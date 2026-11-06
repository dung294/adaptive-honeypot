#!/usr/bin/env python3
"""
Live Attacker Tool for Adaptive Honeypot.
Kết nối TCP socket SSH trực tiếp vào cổng 22 của Honeypot (192.168.101.218:22),
thực thi chuỗi tấn công thực tế và kiểm tra phản hồi từ Honeypot Sandbox.
"""

import sys
import time
import socket
import paramiko

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HONEYPOT_HOST = "192.168.101.218"
HONEYPOT_PORT = 22

ATTACK_COMMANDS = [
    "whoami",
    "uname -a",
    "id",
    "cat /etc/os-release",
    "cat /etc/passwd",
    "ps -ef",
    "ip a",
    "netstat -tuln",
    "cd /tmp && ls -la",
    "exit"
]

def launch_live_attack(target_host=HONEYPOT_HOST, target_port=HONEYPOT_PORT):
    print("=" * 70)
    print(f"🔥 [LIVE ATTACK] BẮT ĐẦU TẤN CÔNG THỰC TẾ VÀO HONEYPOT: {target_host}:{target_port}")
    print("=" * 70)

    # 1. Thử dò mật khẩu (Brute Force)
    print("[*] Pha 1: Thử nghiệm Brute Force mật khẩu...")
    for user, pwd in [("admin", "admin123"), ("root", "toor"), ("guest", "guest")]:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(target_host, port=target_port, username=user, password=pwd, timeout=5, allow_agent=False, look_for_keys=False)
            print(f"   [+] Bất ngờ: Đăng nhập được với {user}:{pwd}")
            client.close()
        except paramiko.AuthenticationException:
            print(f"   [-] Từ chối xác thực thành công (Bẫy ghi nhận Auth_Failed): {user}:{pwd}")
        except Exception as e:
            print(f"   [!] Lỗi kết nối: {e}")

    # 2. Đăng nhập thành công và thực thi chuỗi lệnh trinh sát
    print("\n[*] Pha 2: Đăng nhập thành công vào Sandbox và khai thác...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target_host, port=target_port, username="root", password="123", timeout=10, allow_agent=False, look_for_keys=False)
        print("   ✅ [AUTH ACCEPTED] Đã vượt qua hàng rào xác thực và vào Terminal Honeypot!")
        
        channel = client.invoke_shell()
        time.sleep(0.5)
        
        # Nhận banner chào mừng
        if channel.recv_ready():
            banner = channel.recv(2048).decode("utf-8", errors="ignore")
            print(f"   [BANNER NHẬN ĐƯỢC]:\n{banner.strip()[:200]}...")

        # Gửi từng lệnh và đọc phản hồi
        for cmd in ATTACK_COMMANDS:
            print(f"\n   >> [GỬI LỆNH]: {cmd}")
            channel.send(cmd + "\n")
            time.sleep(0.4)
            resp = ""
            while channel.recv_ready():
                resp += channel.recv(4096).decode("utf-8", errors="ignore")
            clean_resp = resp.replace("\r\n", "\n").strip()
            print(f"   << [PHẢN HỒI TỪ HONEYPOT]:\n{clean_resp[:300]}")

        channel.close()
        client.close()
        print("\n✅ [ATTACK COMPLETE] Đã ngắt kết nối SSH. Honeypot đã ghi nhận đầy đủ phiên!")
    except Exception as e:
        print(f"   [!] Thất bại trong phiên tấn công: {e}")

if __name__ == "__main__":
    launch_live_attack()
