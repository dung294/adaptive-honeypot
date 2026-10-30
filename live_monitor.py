#!/usr/bin/env python3
"""
Live Log Monitor: Truyền phát và đồng bộ nhật ký sự kiện Honeypot từ VMware về Windows theo thời gian thực (Realtime).
"""

import sys
import io
import json
import time
import paramiko
from pathlib import Path

# Đảm bảo Windows terminal in UTF-8 không lỗi font
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

VM_HOST = "192.168.101.218"
VM_PORT = 22
VM_USER = "nhuthang"
VM_PASS = "123"
REMOTE_LOG = "/home/nhuthang/adaptive-honeypot/logs/events.jsonl"
LOCAL_LOG = Path(__file__).resolve().parent / "logs" / "events.jsonl"
LOCAL_LOG.parent.mkdir(parents=True, exist_ok=True)

def format_event(raw_line: str) -> str:
    """Định dạng bản ghi JSON sự kiện thành dòng hiển thị trực quan."""
    try:
        ev = json.loads(raw_line)
        ts = ev.get("timestamp", "")[:19].replace("T", " ")
        ip = ev.get("source_ip", "")
        port = ev.get("source_port", "")
        user = ev.get("username", "")
        status = ev.get("event_status", "")

        # Sự kiện Xác thực đăng nhập (Auth)
        if "Auth" in status:
            pwd = ev.get("password", "")
            success = ev.get("auth_success", False)
            if success:
                tag = "\033[01;32m[AUTH_SUCCESS]\033[00m"
                msg = f"{tag} \033[01;36m{ip}:{port}\033[00m đăng nhập thành công với User: '\033[01;32m{user}\033[00m' | Pass: '{pwd}'"
            else:
                tag = "\033[01;31m[AUTH_FAILED]\033[00m"
                msg = f"{tag} \033[01;31m{ip}:{port}\033[00m DÒ SAI MẬT KHẨU! User: '{user}' | Pass: '{pwd}' \033[01;33m[MITRE: T1110 Brute Force]\033[00m"
            return f"[{ts}] {msg}"

        # Sự kiện Tương tác dòng lệnh (Interaction)
        else:
            cmd = ev.get("command", "")
            handler = ev.get("handler_type", "VFS")
            lat = ev.get("latency_ms", 0)
            mitre_list = ev.get("mitre_techniques", [])
            mitre_str = ", ".join([m.get("technique_id", "") if isinstance(m, dict) else str(m) for m in mitre_list])
            mitre_tag = f" \033[01;35m[MITRE: {mitre_str}]\033[00m" if mitre_str else ""
            
            return (
                f"[{ts}] \033[01;36m{ip}\033[00m (\033[01;32m{user}\033[00m) "
                f"gõ lệnh: '\033[01;33m{cmd}\033[00m' "
                f"[\033[01;34m{handler}\033[00m | {lat:.2f}ms]{mitre_tag}"
            )
    except Exception:
        return raw_line.strip()

def main():
    print("=" * 75)
    print("📡 [REALTIME HONEYPOT LOG MONITOR] - ĐỒNG BỘ TRỰC TIẾP TỪ VMWARE")
    print(f"🌐 Máy chủ ảo: {VM_HOST}:{VM_PORT} | Người dùng: {VM_USER}")
    print(f"📁 Log máy ảo: {REMOTE_LOG}")
    print(f"💾 Lưu tại máy: {LOCAL_LOG}")
    print("=" * 75)
    print("[*] Đang kết nối tới máy ảo qua SSH...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(VM_HOST, port=VM_PORT, username=VM_USER, password=VM_PASS, timeout=10)
        print("[+] Kết nối thành công! Đang tải toàn bộ log hiện có...")

        # 1. Tải toàn bộ file log hiện tại về máy Windows
        sftp = ssh.open_sftp()
        try:
            sftp.get(REMOTE_LOG, str(LOCAL_LOG))
            print(f"[+] Đã đồng bộ file log hiện tại về: {LOCAL_LOG}")
        except Exception as e:
            print(f"[!] Không thể tải file ban đầu: {e}")
        finally:
            sftp.close()

        # Hiển thị 5 sự kiện gần nhất
        if LOCAL_LOG.exists():
            with open(LOCAL_LOG, "r", encoding="utf-8") as f:
                recent_lines = [l.strip() for l in f if l.strip()][-5:]
            if recent_lines:
                print("\n--- 5 SỰ KIỆN GẦN NHẤT TRƯỚC ĐÓ ---")
                for rl in recent_lines:
                    print(format_event(rl))
                print("-" * 50)

        print("\n🟢 BẮT ĐẦU THEO DÕI REALTIME (Bấm Ctrl+C để dừng)...")
        print("Hacker gõ lệnh gì trên máy ảo sẽ lập tức hiện tại đây:\n")

        # 2. Chạy tail -f trên máy ảo để stream liên tục
        stdin, stdout, stderr = ssh.exec_command(f"tail -n 0 -f {REMOTE_LOG}")

        with open(LOCAL_LOG, "a", encoding="utf-8") as local_f:
            while True:
                line = stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                line_str = line.strip()
                if line_str:
                    # In ra màn hình console Windows dạng đẹp
                    print(format_event(line_str))
                    # Ghi đồng bộ append vào file local
                    local_f.write(line_str + "\n")
                    local_f.flush()

    except KeyboardInterrupt:
        print("\n[*] Đã dừng theo dõi log.")
    except Exception as e:
        print(f"\n[-] [LỖI]: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
