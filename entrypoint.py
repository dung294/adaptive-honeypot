#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - UNIFIED MULTI-LAYER ENTRYPOINT
=============================================================================
Khởi động đồng thời 3 thành phần phòng thủ & thu thập CTI trong cùng một hệ thống:
  1. Cổng 80   : Web Decoy Honeypot (Lớp 7 - Hứng tấn công RCE & Lộ Config)
  2. Cổng 2222 : SSH Adaptive Honeypot Gateway (Lớp 4 - Bẫy leo thang đặc quyền)
  3. Cổng 8080 : SOC Live Dashboard & REST Feed API (Đối soát MISP, Cấp feed cho AI)
"""

import sys
import os
import time
import threading
from pathlib import Path

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from config import WEB_HOST, WEB_PORT, SSH_HOST, SSH_PORT, DASHBOARD_HOST, DASHBOARD_PORT
from gateway.ssh_server import SSHGatewayServer
from gateway.web_decoy import app as web_app
from dashboard import app as dashboard_app


def run_web_decoy():
    """Chạy Web Decoy Honeypot (Cổng 80)"""
    try:
        print(f"[*] [THREAD 1] Khởi chạy Web Decoy Honeypot tại http://{WEB_HOST}:{WEB_PORT}")
        # Chạy Flask ở production/threaded mode không reloader
        web_app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"[!] [LỖI WEB DECOY]: {e}")


def run_ssh_gateway():
    """Chạy SSH Adaptive Honeypot Gateway (Cổng 2222)"""
    try:
        print(f"[*] [THREAD 2] Khởi chạy SSH Honeypot Gateway tại {SSH_HOST}:{SSH_PORT}")
        server = SSHGatewayServer(host=SSH_HOST, port=SSH_PORT)
        server.start()
    except Exception as e:
        print(f"[!] [LỖI SSH HONEYPOT]: {e}")


def run_soc_dashboard():
    """Chạy SOC Dashboard & REST Feed API (Cổng 8080)"""
    try:
        print(f"[*] [THREAD 3] Khởi chạy SOC Dashboard & API tại http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
        dashboard_app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"[!] [LỖI DASHBOARD]: {e}")


def main():
    print("=" * 80)
    print("🚀 [ADAPTIVE HONEYPOT] KHỞI ĐỘNG HỆ THỐNG ĐA TẦNG (MULTI-LAYER DECEPTION)")
    print("=" * 80)
    print(f"🌐 1. Web Decoy Lure (Lớp 7)      : http://{WEB_HOST}:{WEB_PORT}")
    print(f"   -> Hứng RCE (/api/ping) & Lộ SSH config (/.env, /config.php)")
    print(f"🔒 2. SSH Honeypot Gateway (Lớp 4): {SSH_HOST}:{SSH_PORT}")
    print(f"   -> Bẫy hacker nhảy từ Web RCE vào gõ lệnh phá hoại")
    print(f"📊 3. SOC Dashboard & API Feed    : http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print(f"   -> Đối soát MISP tức thời, cấp log 'full_session' cho AI Máy 2")
    print("=" * 80)

    # Khởi chạy các luồng độc lập
    t_web = threading.Thread(target=run_web_decoy, name="WebDecoyThread", daemon=True)
    t_ssh = threading.Thread(target=run_ssh_gateway, name="SSHHoneypotThread", daemon=True)
    t_dash = threading.Thread(target=run_soc_dashboard, name="DashboardThread", daemon=True)

    t_web.start()
    t_ssh.start()
    t_dash.start()

    print("[+] Toàn bộ 3 dịch vụ đã kích hoạt thành công. Đang lắng nghe các cuộc tấn công...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Đang dừng hệ thống...")
        sys.exit(0)


if __name__ == "__main__":
    main()
