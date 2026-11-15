#!/usr/bin/env python3
import threading
import time
import socket
import signal
import sys
from gateway.web_decoy import app as web_app
from gateway.ssh_server import SSHGatewayServer
from config import WEB_HOST, WEB_PORT, SSH_HOST, SSH_PORT

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def run_web():
    print(f"[*] Web Decoy đang chạy tại http://{WEB_HOST}:{WEB_PORT}")
    web_app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)

def run_ssh():
    print(f"[*] SSH Honeypot đang chạy tại {SSH_HOST}:{SSH_PORT}")
    server = SSHGatewayServer(host=SSH_HOST, port=SSH_PORT)
    server.start()

def signal_handler(sig, frame):
    print("\n[!] Đang tắt hệ thống Honeypot an toàn...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    local_ip = get_local_ip()
    print("=" * 70)
    print("🚀 KHỞI ĐỘNG HONEYPOT MÁY 2 (WEB DECOY + SSH HONEYPOT DOCKER)")
    print("=" * 70)
    threading.Thread(target=run_web, daemon=True).start()
    threading.Thread(target=run_ssh, daemon=True).start()
    
    print("\n✅ CẢ 2 BẪY ĐÃ SẴN SÀNG:")
    print(f"   🌐 Web Decoy:   http://{local_ip}:{WEB_PORT}")
    print(f"   🔑 SSH Server:  ssh -p {SSH_PORT} ubuntu@{local_ip}")
    print("=" * 70)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Dừng hệ thống Honeypot.")
