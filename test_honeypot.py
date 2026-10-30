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

def test_wrong_password_rejected():
    host = "127.0.0.1"
    port = 2222
    username = "root"
    wrong_password = "this_is_a_completely_wrong_password_9999"

    print(f"\n=======================================================")
    print(f"[TEST 1] Thử đăng nhập với SAI mật khẩu ({wrong_password})...")
    print(f"=======================================================")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=username, password=wrong_password, timeout=5)
        print("[LỖI] Sai mật khẩu nhưng vẫn được cho vào!")
        client.close()
    except paramiko.AuthenticationException:
        print("[THÀNH CÔNG] Server đã từ chối xác thực (Authentication Failed) do sai mật khẩu!")
    except Exception as e:
        print(f"[TEST 1 Kết quả]: {e}")

def test_attack_simulation():
    host = "127.0.0.1"
    port = 2222
    username = "root"
    # Mật khẩu hợp lệ nằm trong HONEYPOT_ALLOWED_PASSWORDS
    valid_honeypot_password = "supersecretpassword123"

    print(f"\n=======================================================")
    print(f"[TEST 2] Hacker đoán ĐÚNG mật khẩu bẫy ({valid_honeypot_password})...")
    print(f"=======================================================")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=username, password=valid_honeypot_password, timeout=5)
        print("[TEST] -> Khớp mật khẩu bẫy! Được cấp quyền truy cập vào Honeypot ảo.")
        
        channel = client.invoke_shell()
        time.sleep(0.5)
        initial_banner = channel.recv(2048).decode("utf-8", errors="ignore")
        print(f"[TEST] -> Đã nhận Banner giả lập:\n{initial_banner.strip()}\n")

        commands = [
            "uname -a",
            "whoami",
            "pwd",
            "cd /tmp",
            "echo 'MALWARE_PAYLOAD_C2_ACTIVE' > update.sh",
            "ls -la",
            "cat update.sh",
            "exit"
        ]

        for cmd in commands:
            print(f"[TEST] >>> Hacker gõ: {cmd}")
            channel.send(cmd + "\r")
            time.sleep(0.4)
            output = ""
            while channel.recv_ready():
                output += channel.recv(4096).decode("utf-8", errors="ignore")
            print(f"[TEST] <<< Server bẫy phản hồi:\n{output.strip()}\n" + "-"*40)

        client.close()
        print("[TEST] -> Đã đóng phiên Hacker an toàn.\n")

    except Exception as e:
        print(f"[TEST] [LỖI] Không thể kết nối hoặc thực thi: {e}")

def test_admin_control():
    host = "127.0.0.1"
    port = 2222
    username = "admin"
    password = "admin123"

    print(f"\n=======================================================")
    print(f"[TEST 3] Quản trị viên SSH từ Windows vào điều khiển máy chủ...")
    print(f"=======================================================")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=username, password=password, timeout=5)
        print("[TEST] -> Đăng nhập Admin thành công!")
        
        channel = client.invoke_shell()
        time.sleep(0.5)
        banner = channel.recv(2048).decode("utf-8", errors="ignore")
        print(f"[TEST] -> Đã nhận Admin Banner:\n{banner.strip()}\n")

        admin_commands = [
            ":status",
            ":logs 3",
            ":exit"
        ]

        for cmd in admin_commands:
            print(f"[TEST] >>> Admin gõ: {cmd}")
            channel.send(cmd + "\r")
            time.sleep(0.4)
            output = ""
            while channel.recv_ready():
                output += channel.recv(4096).decode("utf-8", errors="ignore")
            print(f"[TEST] <<< Phản hồi Admin Console:\n{output.strip()}\n" + "-"*40)

        client.close()
        print("[TEST] -> Kết thúc kiểm thử Admin Control thành công.")

    except Exception as e:
        print(f"[TEST] [LỖI Admin]: {e}")

if __name__ == "__main__":
    test_wrong_password_rejected()
    test_attack_simulation()
    test_admin_control()
