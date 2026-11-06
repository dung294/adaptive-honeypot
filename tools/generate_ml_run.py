#!/usr/bin/env python3
"""
ML Run Generator & Bridge Exporter for Adaptive Honeypot.

Công cụ chuyên dụng tạo dataset log theo chuẩn Machine Learning:
- Định dạng JSON Lines (mỗi dòng 1 event JSON hoàn chỉnh).
- KHÔNG tự gán nhãn theo kết quả AI (No predictions in raw logs).
- Gắn run_id, campaign_id, scenario_id định trước.
- Đầy đủ vòng đời session: login -> commands (command + output) -> session_closed.
- Redact toàn bộ mật khẩu, token và thông tin nhạy cảm.
- Tạo run_manifest.json và scenario_manifest.json (Ground Truth độc lập).
- Hỗ trợ đẩy qua mạng Bridge tới máy ML (REST API / File sync).
"""

import os
import sys
import json
import time
import uuid
import argparse
import datetime
from pathlib import Path

# Cấu hình UTF-8 cho console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Thêm thư mục gốc vào PYTHONPATH
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from threat_intel.ml_exporter import (
    MLLogExporter,
    SCENARIOS_CATALOG,
    DEFAULT_DATA_RAW_DIR,
    generate_iso_timestamp
)
from gateway.vfs import VirtualFileSystem
from ai_engine.router import CommandRouter


def run_scenario(
    exporter: MLLogExporter,
    scenario_meta: dict,
    router: CommandRouter,
    source_ip: str,
    source_port: int,
    session_id: str
):
    """Mô phỏng thực thi một kịch bản kiểm thử qua Honeypot Sandbox."""
    sid = scenario_meta["scenario_id"]
    print(f"[*] Đang thực thi kịch bản: {sid} | Nhãn: {scenario_meta['ground_truth_label']}")

    # 1. Xử lý kịch bản brute-force nếu có
    if "failed_attempts" in scenario_meta:
        for u, _ in scenario_meta["failed_attempts"]:
            exporter.emit_login_failed(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=u,
                scenario_id=sid
            )
            time.sleep(0.05)

    # 2. Sự kiện Đăng nhập thành công (login)
    login_user = "root"
    if "successful_login" in scenario_meta:
        login_user = scenario_meta["successful_login"][0]
    exporter.emit_login(
        session_id=session_id,
        source_ip=source_ip,
        source_port=source_port,
        username=login_user,
        scenario_id=sid
    )

    # 3. Thực thi chuỗi lệnh và thu thập output từ Deception Sandbox
    current_user = login_user
    for cmd in scenario_meta.get("commands", []):
        if cmd.startswith("sudo su") or cmd.startswith("sudo -i"):
            current_user = "root"
            output = ""
        else:
            out, _, _ = router.execute(cmd, user=current_user)
            output = out.strip()

        exporter.emit_command(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            username=current_user,
            command=cmd,
            command_output=output,
            scenario_id=sid
        )
        time.sleep(0.05)

    # 4. Sự kiện Kết thúc phiên (BẮT BUỘC có session_closed để máy ML nhận diện đóng session)
    exporter.emit_session_closed(
        session_id=session_id,
        source_ip=source_ip,
        source_port=source_port,
        username=current_user,
        scenario_id=sid
    )


def push_to_ml_bridge(run_dir: Path, bridge_url: str):
    """Gửi toàn bộ events và manifest qua mạng bridge tới máy ML (REST API)."""
    import urllib.request
    import urllib.error

    events_file = run_dir / "events.jsonl"
    run_manifest_file = run_dir / "run_manifest.json"
    scenario_manifest_file = run_dir / "scenario_manifest.json"

    print(f"\n🌐 [BRIDGE SENDER] Đang kết nối tới máy ML tại: {bridge_url} ...")

    # Đọc manifest
    with open(run_manifest_file, "r", encoding="utf-8") as f:
        run_manifest = json.load(f)
    with open(scenario_manifest_file, "r", encoding="utf-8") as f:
        scenario_manifest = json.load(f)

    # Đọc toàn bộ events
    events = []
    with open(events_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))

    payload = {
        "run_manifest": run_manifest,
        "scenario_manifest": scenario_manifest,
        "events": events
    }
    data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    req = urllib.request.Request(
        bridge_url,
        data=data_bytes,
        headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_body = resp.read().decode("utf-8")
            print(f"✅ [BRIDGE SUCCESS] Máy ML đã nhận thành công Run '{run_manifest['run_id']}'! Status: {resp.status}")
            print(f"   Phản hồi: {resp_body[:200]}")
    except Exception as e:
        print(f"⚠️ [BRIDGE WARNING] Không thể kết nối trực tiếp tới REST endpoint của máy ML: {e}")
        print(f"   (Dữ liệu đã được lưu trữ an toàn tại thư mục: {run_dir})")


def main():
    parser = argparse.ArgumentParser(description="Tạo và xuất Run log chuẩn Machine Learning cho Honeypot.")
    parser.add_argument("--run-id", type=str, default=None, help="Mã định danh run (mặc định: run-YYYY-MM-DD-XXXXXX)")
    parser.add_argument("--campaign-id", type=str, default="camp-honeypot-eval-2026", help="Mã campaign kiểm thử")
    parser.add_argument("--role", type=str, choices=["train", "test", "benchmark", "inference"], default="train", help="Vai trò dataset: train hoặc test")
    parser.add_argument("--scenarios", type=str, default="all", help="Danh sách scenario_id (phân tách dấu phẩy hoặc 'all')")
    parser.add_argument("--output-dir", type=str, default=str(DEFAULT_DATA_RAW_DIR), help="Thư mục xuất data/raw")
    parser.add_argument("--bridge-url", type=str, default=None, help="URL REST API của máy ML trên mạng bridge (tùy chọn)")

    args = parser.parse_args()

    # Xác định danh sách scenario cần chạy
    if args.scenarios.strip().lower() == "all":
        scenarios_to_run = list(SCENARIOS_CATALOG.keys())
    else:
        scenarios_to_run = [s.strip() for s in args.scenarios.split(",") if s.strip() in SCENARIOS_CATALOG]

    if not scenarios_to_run:
        print("[!] Không tìm thấy kịch bản hợp lệ nào!")
        sys.exit(1)

    print("=" * 75)
    print("🚀 [ML LOG GENERATOR] KHỞI ĐỘNG CÔNG CỤ TẠO DATASET CHUẨN MACHINE LEARNING")
    print(f"📁 Thư mục xuất: {args.output_dir}")
    print(f"🎯 Dataset Role: {args.role.upper()} (Tách biệt hoàn toàn Train vs Test)")
    print(f"📋 Số lượng kịch bản: {len(scenarios_to_run)}")
    print("=" * 75)

    exporter = MLLogExporter(
        run_id=args.run_id,
        campaign_id=args.campaign_id,
        dataset_role=args.role,
        output_base_dir=Path(args.output_dir)
    )

    vfs = VirtualFileSystem()
    router = CommandRouter(vfs, None)

    base_ip_num = 20
    for idx, sid in enumerate(scenarios_to_run, start=1):
        meta = SCENARIOS_CATALOG[sid]
        sess_id = f"session-{exporter.run_id}-{idx:03d}"
        source_ip = f"192.168.56.{base_ip_num + idx}"
        source_port = 50000 + idx * 73

        run_scenario(
            exporter=exporter,
            scenario_meta=meta,
            router=router,
            source_ip=source_ip,
            source_port=source_port,
            session_id=sess_id
        )

    # Hoàn thành run và tạo manifests
    summary = exporter.finalize_run()

    print("\n" + "=" * 75)
    print(f"🎉 HOÀN THÀNH TẠO RUN THÀNH CÔNG: {summary['run_id']}")
    print(f"📄 Tệp sự kiện:        {summary['events_file']}")
    print(f"📋 Run Manifest:       {summary['run_manifest_file']}")
    print(f"🏷️ Scenario Manifest:  {summary['scenario_manifest_file']}")
    print(f"📊 Tổng số Event:      {summary['total_events']} events")
    print("=" * 75)

    # Đẩy qua mạng bridge nếu có cấu hình
    if args.bridge_url:
        push_to_ml_bridge(Path(summary["run_dir"]), args.bridge_url)


if __name__ == "__main__":
    main()
