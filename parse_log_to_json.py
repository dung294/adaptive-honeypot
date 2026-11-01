#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - BỘ CHUYỂN ĐỔI & ĐỊNH DẠNG LOG JSON DỄ ĐỌC (PRETTY JSON)
=============================================================================
Công dụng:
  - Phân tích cú pháp tệp log thô (events.jsonl).
  - Tái cấu trúc thành định dạng JSON chuẩn (indented 2 spaces, UTF-8).
  - Gom nhóm theo từng phiên tấn công (Session Timeline) với đầy đủ:
    + Thông tin kẻ tấn công (IP, Port, Username, Password thử nghiệm).
    + Thời gian thực tế (Local Time UTC+7).
    + Đánh giá mức độ nguy hiểm & Nhãn MITRE ATT&CK for Enterprise.
    + Chi tiết từng bước gõ lệnh (Lệnh gõ -> Phản hồi Honeypot -> Kỹ thuật MITRE).
  - Xuất ra các tệp JSON trực quan, mở bằng VS Code hoặc Notepad đọc cực kỳ dễ.
"""

import sys
import os
import json
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict

# Đảm bảo UTF-8 cho Windows Terminal
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

VN_TZ = timezone(timedelta(hours=7))

def to_vn_time_str(ts_raw: str) -> str:
    """Chuyển đổi ISO timestamp sang chuỗi giờ Việt Nam (UTC+7) dễ đọc: YYYY-MM-DD HH:MM:SS"""
    if not ts_raw:
        return "N/A"
    try:
        ts_clean = ts_raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_clean)
        dt_vn = dt.astimezone(VN_TZ)
        return dt_vn.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts_raw)[:19].replace("T", " ")

# Bảng đối soát MITRE ATT&CK chuẩn hoá
def extract_mitre_info(ev: dict) -> list:
    """Trích xuất danh sách kỹ thuật MITRE ATT&CK từ event"""
    techniques = []
    
    # 1. Từ mitre_techniques có sẵn
    raw_techs = ev.get("mitre_techniques")
    if isinstance(raw_techs, list):
        for t in raw_techs:
            if isinstance(t, dict):
                tid = t.get("technique_id") or t.get("id")
                tname = t.get("technique_name") or t.get("name")
                tac = t.get("tactic", "Threat Behavior")
                if tid:
                    techniques.append({
                        "technique_id": tid,
                        "technique_name": tname or tid,
                        "tactic": tac
                    })
    
    # 2. Bổ sung từ trạng thái sự kiện
    st = ev.get("event_status")
    cmd = (ev.get("command") or "").strip().lower()
    
    if st == "Auth_Failed" and not any(x["technique_id"] == "T1110" for x in techniques):
        techniques.append({
            "technique_id": "T1110",
            "technique_name": "Brute Force: Password Guessing",
            "tactic": "Credential Access"
        })
    elif st == "Auth_Success" and not any(x["technique_id"] == "T1078.003" for x in techniques):
        techniques.append({
            "technique_id": "T1078.003",
            "technique_name": "Valid Accounts: Local Accounts",
            "tactic": "Initial Access"
        })
    elif st == "Immediate_Exit" and not any(x["technique_id"] == "T1046" for x in techniques):
        techniques.append({
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery / Port Scan",
            "tactic": "Discovery"
        })
    elif st == "Session_Aborted" and not any(x["technique_id"] == "T1070" for x in techniques):
        techniques.append({
            "technique_id": "T1070",
            "technique_name": "Indicator Removal: Abnormal Connection Drop",
            "tactic": "Defense Evasion"
        })

    # Phân tích lệnh nếu chưa có kỹ thuật
    if cmd:
        if any(w in cmd for w in ["wget", "curl", "tftp", "ftp"]):
            if not any(x["technique_id"] == "T1105" for x in techniques):
                techniques.append({
                    "technique_id": "T1105",
                    "technique_name": "Ingress Tool Transfer (Tải payload độc hại)",
                    "tactic": "Command and Control"
                })
        elif "sudo" in cmd:
            if not any("T1548" in x["technique_id"] for x in techniques):
                techniques.append({
                    "technique_id": "T1548.003",
                    "technique_name": "Abuse Elevation Control: Sudo Caching",
                    "tactic": "Privilege Escalation"
                })
        elif any(w in cmd for w in ["crontab", "/etc/cron"]):
            if not any("T1053" in x["technique_id"] for x in techniques):
                techniques.append({
                    "technique_id": "T1053.003",
                    "technique_name": "Scheduled Task/Job: Cron Persistence",
                    "tactic": "Persistence"
                })
        elif any(w in cmd for w in ["whoami", "id"]):
            if not any(x["technique_id"] == "T1033" for x in techniques):
                techniques.append({
                    "technique_id": "T1033",
                    "technique_name": "System Owner/User Discovery",
                    "tactic": "Discovery"
                })
        elif any(w in cmd for w in ["uname", "hostname", "/proc/version"]):
            if not any(x["technique_id"] == "T1082" for x in techniques):
                techniques.append({
                    "technique_id": "T1082",
                    "technique_name": "System Information Discovery",
                    "tactic": "Discovery"
                })
        elif any(w in cmd for w in ["history -c", "rm -rf", "shred"]):
            if not any("T1070" in x["technique_id"] for x in techniques):
                techniques.append({
                    "technique_id": "T1070.003",
                    "technique_name": "Indicator Removal on Host: Clear Command History",
                    "tactic": "Defense Evasion"
                })
        
        # Mặc định shell execution nếu chưa có
        if not techniques:
            techniques.append({
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution"
            })

    return techniques

def determine_scenario(auth_status: str, commands: list, is_aborted: bool) -> str:
    """Xác định kịch bản tấn công bằng ngôn ngữ tiếng Việt dễ hiểu"""
    cmds_str = " ".join(c.lower() for c in commands)
    
    if any(x in cmds_str for x in ["curl", "wget", "malware", ".sh", ".elf", "chmod +x"]):
        return "Tải và kích hoạt mã độc từ máy chủ C2"
    if "sudo" in cmds_str or "su " in cmds_str or "id_rsa" in cmds_str or "/etc/shadow" in cmds_str:
        return "Tìm kiếm thông tin nhạy cảm & Leo thang đặc quyền"
    if any(x in cmds_str for x in ["crontab", "/etc/cron", "rc.local"]):
        return "Tạo cửa sau duy trì chiếm giữ (Persistence)"
    if any(x in cmds_str for x in ["history -c", "rm -rf", "unset histfile"]):
        return "Xóa dấu vết và lịch sử dòng lệnh (Defense Evasion)"
    if any(x in cmds_str for x in ["uname", "whoami", "ifconfig", "ip a", "netstat", "ps aux", "cat /etc/passwd"]):
        return "Khảo sát và trinh sát hệ điều hành (Discovery)"
    if commands:
        return "Tương tác và thăm dò dòng lệnh Linux"
    if auth_status == "Failed":
        return "Tấn công vét cạn mật khẩu (Brute Force SSH)"
    if is_aborted:
        return "Quét cổng dịch vụ & Ngắt kết nối bất thường (Port Scan)"
    return "Kết nối thăm dò ban đầu (Banner Grab)"

def determine_severity(scenario: str, mitre_tactics: list) -> str:
    """Xác định cấp độ nguy hiểm (Critical, High, Medium, Low, Info)"""
    if "C2" in scenario or "Command and Control" in mitre_tactics or "Privilege Escalation" in mitre_tactics:
        return "Critical"
    if "Persistence" in mitre_tactics or "Credential Access" in mitre_tactics or "Leo thang" in scenario:
        return "High"
    if "Defense Evasion" in mitre_tactics or "Tải và kích hoạt" in scenario:
        return "High"
    if "Discovery" in mitre_tactics or "Khảo sát" in scenario:
        return "Medium"
    if "Brute Force" in scenario:
        return "Medium"
    return "Low"

class LogJsonParser:
    def __init__(self, log_path: str = "logs/events.jsonl"):
        self.log_path = Path(log_path)
        self.raw_records = []
        self.sessions = defaultdict(list)
        
    def load_events(self):
        """Đọc và lọc bản ghi từ file jsonl"""
        if not self.log_path.exists():
            raise FileNotFoundError(f"Không tìm thấy file log: {self.log_path}")
            
        seen_keys = set()
        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    k = data.get("event_key") or f"{data.get('timestamp')}:{data.get('session_id')}:{data.get('command')}"
                    if k in seen_keys:
                        continue
                    seen_keys.add(k)
                    self.raw_records.append(data)
                except Exception:
                    continue

    def parse_into_readable_sessions(self) -> list:
        """Gom nhóm sự kiện thành danh sách phiên tấn công dễ đọc"""
        session_map = defaultdict(lambda: {
            "session_id": "",
            "attacker_ip": "127.0.0.1",
            "attacker_port": 0,
            "username": "root",
            "passwords_tried": [],
            "auth_result": "Unknown",
            "timestamps": [],
            "events": [],
            "abnormal_termination": False
        })

        for ev in self.raw_records:
            sid = ev.get("session_id") or "unauthenticated_scan"
            s = session_map[sid]
            s["session_id"] = sid
            if ev.get("source_ip"):
                s["attacker_ip"] = ev["source_ip"]
            if ev.get("source_port"):
                s["attacker_port"] = ev["source_port"]
            if ev.get("username"):
                s["username"] = ev["username"]
            if ev.get("password") and ev["password"] not in s["passwords_tried"]:
                s["passwords_tried"].append(ev["password"])
            if ev.get("timestamp"):
                s["timestamps"].append(ev["timestamp"])
                
            st = ev.get("event_status")
            if st == "Auth_Success":
                s["auth_result"] = "Thành công (Authenticated)"
            elif st == "Auth_Failed":
                if s["auth_result"] != "Thành công (Authenticated)":
                    s["auth_result"] = "Thất bại (Brute Force)"
            elif st == "Immediate_Exit":
                if s["auth_result"] == "Unknown":
                    s["auth_result"] = "Không đăng nhập (Port Scan)"
            elif st == "Session_Aborted":
                s["abnormal_termination"] = True
                
            s["events"].append(ev)

        # Chuyển đổi thành cấu trúc JSON siêu đẹp
        readable_sessions = []
        for sid, s in session_map.items():
            ts_list = sorted(s["timestamps"])
            start_iso = ts_list[0] if ts_list else ""
            end_iso = ts_list[-1] if ts_list else ""
            start_readable = to_vn_time_str(start_iso)
            end_readable = to_vn_time_str(end_iso)
            
            # Tính thời gian phiên
            duration_sec = 0.0
            if start_iso and end_iso:
                try:
                    dt1 = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
                    dt2 = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
                    duration_sec = round(max(0.0, (dt2 - dt1).total_seconds()), 2)
                except Exception:
                    pass

            # Sắp xếp và trích xuất dòng lệnh
            interactions = [e for e in s["events"] if e.get("event_status") == "Interaction"]
            interactions.sort(key=lambda x: x.get("timestamp", ""))

            command_timeline = []
            all_tactics = set()
            all_techniques = set()
            commands_list = []

            for idx, item in enumerate(interactions, 1):
                cmd_text = item.get("command", "")
                commands_list.append(cmd_text)
                mitre_list = extract_mitre_info(item)
                
                mitre_formatted = []
                for m in mitre_list:
                    all_tactics.add(m["tactic"])
                    all_techniques.add(f"{m['technique_id']} - {m['technique_name']}")
                    mitre_formatted.append(f"{m['technique_id']} [{m['tactic']}]: {m['technique_name']}")

                command_timeline.append({
                    "buoc": idx,
                    "thoi_gian": to_vn_time_str(item.get("timestamp", "")),
                    "lenh_hacker_go": cmd_text,
                    "phan_hoi_honeypot": item.get("command_output", ""),
                    "bo_xu_ly": item.get("handler_type", "VFS"),
                    "do_tre_phan_hoi_ms": item.get("latency_ms", 0.0),
                    "ky_thuat_mitre": mitre_formatted
                })

            # Nếu không có lệnh tương tác, thêm nhãn đăng nhập / quét
            if not command_timeline:
                for ev in s["events"]:
                    for m in extract_mitre_info(ev):
                        all_tactics.add(m["tactic"])
                        all_techniques.add(f"{m['technique_id']} - {m['technique_name']}")

            scenario = determine_scenario(
                auth_status="Failed" if "Thất bại" in s["auth_result"] else "Success" if "Thành công" in s["auth_result"] else "Unknown",
                commands=commands_list,
                is_aborted=s["abnormal_termination"]
            )
            severity = determine_severity(scenario, list(all_tactics))

            session_obj = {
                "ma_phien_session_id": sid,
                "thong_tin_ke_tan_cong": {
                    "dia_chi_ip": s["attacker_ip"],
                    "cong_ket_noi": s["attacker_port"],
                    "tai_khoan_su_dung": s["username"],
                    "mat_khau_thu_nghiem": s["passwords_tried"],
                    "ket_qua_dang_nhap": s["auth_result"]
                },
                "thoi_gian_hoat_dong": {
                    "bat_dau": start_readable,
                    "ket_thuc": end_readable,
                    "tong_thoi_luong": f"{duration_sec} giây"
                },
                "danh_gia_nguy_co": {
                    "kich_ban_tan_cong": scenario,
                    "muc_do_nghiem_trong": severity,
                    "tong_so_lenh_thuc_thi": len(command_timeline),
                    "trang_thai_ngat_ket_noi": "Ngắt đột ngột (Abnormal Disconnect)" if s["abnormal_termination"] else "Bình thường (Normal Exit)",
                    "chien_thuat_mitre": sorted(list(all_tactics)),
                    "ky_thuat_mitre": sorted(list(all_techniques))
                },
                "nhat_ky_tung_buoc_command_timeline": command_timeline
            }
            readable_sessions.append(session_obj)

        # Sắp xếp các phiên theo thời gian bắt đầu
        readable_sessions.sort(key=lambda x: x["thoi_gian_hoat_dong"]["bat_dau"], reverse=True)
        return readable_sessions

    def parse_into_readable_events(self) -> list:
        """Chuyển đổi từng sự kiện đơn lẻ thành JSON đẹp, trực quan"""
        readable_events = []
        for idx, ev in enumerate(self.raw_records, 1):
            ts = to_vn_time_str(ev.get("timestamp", ""))
            st = ev.get("event_status", "Event")
            cmd = ev.get("command")
            output = ev.get("command_output")
            mitre_list = extract_mitre_info(ev)
            
            item = {
                "stt": idx,
                "thoi_gian": ts,
                "loai_su_kien": st,
                "session_id": ev.get("session_id", "N/A"),
                "nguon_tan_cong": f"{ev.get('source_ip', '127.0.0.1')}:{ev.get('source_port', 0)}",
                "tai_khoan": ev.get("username", "N/A")
            }
            
            if ev.get("password"):
                item["mat_khau_go"] = ev.get("password")
                
            if cmd is not None:
                item["lenh_thuc_thi"] = cmd
                item["ket_qua_tra_ve"] = output if output is not None else ""
                item["thoi_gian_xu_ly_ms"] = ev.get("latency_ms", 0.0)
                item["bo_xu_ly"] = ev.get("handler_type", "VFS")

            if mitre_list:
                item["mitre_attck"] = [
                    f"{m['technique_id']} [{m['tactic']}]: {m['technique_name']}"
                    for m in mitre_list
                ]
                
            readable_events.append(item)
            
        return readable_events

def main():
    parser = argparse.ArgumentParser(description="Công cụ phân tích và xuất log Honeypot ra JSON đẹp mắt, dễ đọc.")
    parser.add_argument("--input", "-i", default="logs/events.jsonl", help="Đường dẫn file log nguồn")
    parser.add_argument("--output-sessions", "-os", default="logs/readable_attack_sessions.json", help="File JSON phiên tấn công hoàn chỉnh")
    parser.add_argument("--output-sample", "-sm", default="logs/readable_attack_sessions_sample.json", help="File JSON mẫu tuyển chọn (mở siêu nhanh)")
    parser.add_argument("--output-events", "-oe", default="logs/readable_events.json", help="File JSON toàn bộ sự kiện đơn lẻ")
    parser.add_argument("--limit-sample", type=int, default=50, help="Số lượng session mẫu (mặc định: 50)")
    
    args = parser.parse_args()

    print("=" * 80)
    print("✨ [ADAPTIVE HONEYPOT] CHUYỂN ĐỔI LOG SANG ĐỊNH DẠNG JSON ĐẸP MẮT & DỄ ĐỌC")
    print(f"📂 File log nguồn: {args.input}")
    print("=" * 80)

    converter = LogJsonParser(args.input)
    print("\n[*] Đang nạp dữ liệu log thô...")
    converter.load_events()
    print(f"  • Đã tải: {len(converter.raw_records):,} bản ghi sự kiện.")

    print("\n[*] Đang phân tích cú pháp và tái cấu trúc thành JSON phân cấp theo Session...")
    sessions = converter.parse_into_readable_sessions()
    print(f"  • Tổng số phiên tấn công hoàn chỉnh: {len(sessions):,} sessions.")

    # 1. Lưu file JSON Sessions hoàn chỉnh
    out_sess_path = Path(args.output_sessions)
    out_sess_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_sess_path, "w", encoding="utf-8") as f:
        json.dump(sessions, f, ensure_ascii=False, indent=2)
    print(f"✅ ĐÃ XUẤT FILE JSON TẤT CẢ PHIÊN: {out_sess_path} ({len(sessions):,} sessions)")

    # 2. Lưu file JSON Sample (Tuyển chọn các phiên có lệnh và hành vi đặc sắc để mở nhẹ)
    sample_sessions = [s for s in sessions if s["danh_gia_nguy_co"]["tong_so_lenh_thuc_thi"] > 0]
    if len(sample_sessions) < args.limit_sample:
        sample_sessions = sessions[:args.limit_sample]
    else:
        sample_sessions = sample_sessions[:args.limit_sample]

    out_sample_path = Path(args.output_sample)
    with open(out_sample_path, "w", encoding="utf-8") as f:
        json.dump(sample_sessions, f, ensure_ascii=False, indent=2)
    print(f"✅ ĐÃ XUẤT FILE JSON MẪU NHẸ DỄ ĐỌC: {out_sample_path} ({len(sample_sessions)} sessions tiêu biểu)")

    # 3. Lưu file JSON Events đơn lẻ
    print("\n[*] Đang tái cấu trúc từng sự kiện đơn lẻ thành JSON đẹp mắt...")
    events = converter.parse_into_readable_events()
    out_events_path = Path(args.output_events)
    with open(out_events_path, "w", encoding="utf-8") as f:
        json.dump(events, f, ensure_ascii=False, indent=2)
    print(f"✅ ĐÃ XUẤT FILE JSON TỪNG SỰ KIỆN: {out_events_path} ({len(events):,} events)")

    print("\n" + "=" * 80)
    print("🎉 HOÀN THÀNH! BẠN CÓ THỂ MỞ TRỰC TIẾP TRÊN VS CODE ĐỂ ĐỌC DỄ DÀNG:")
    print(f"  1. File mẫu nhẹ nhất để xem ngay:   {out_sample_path}")
    print(f"  2. File toàn bộ phiên tấn công:     {out_sess_path}")
    print(f"  3. File danh sách từng sự kiện:     {out_events_path}")
    print("=" * 80)

if __name__ == "__main__":
    main()
