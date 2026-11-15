#!/usr/bin/env python3
import threading
import time
from gateway.web_decoy import app as web_app
from gateway.ssh_server import SSHGatewayServer
from config import WEB_HOST, WEB_PORT, SSH_HOST, SSH_PORT

def run_web():
    print(f"[*] Web Decoy đang chạy tại http://{WEB_HOST}:{WEB_PORT}")
    web_app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)

def run_ssh():
    print(f"[*] SSH Honeypot đang chạy tại {SSH_HOST}:{SSH_PORT}")
    server = SSHGatewayServer(host=SSH_HOST, port=SSH_PORT)
    server.start()

if __name__ == "__main__":
    print("=" * 70)
    print("🚀 KHỞI ĐỘNG HONEYPOT MÁY 2 (WEB DECOY + SSH HONEYPOT)")
    print("=" * 70)
    threading.Thread(target=run_web, daemon=True).start()
    threading.Thread(target=run_ssh, daemon=True).start()
    
    print("\n✅ CẢ 2 BẪY ĐÃ SẴN SÀNG:")
    print(f"   🌐 Web Decoy:   http://{WEB_HOST}:{WEB_PORT}")
    print(f"   🔑 SSH Server:  ssh -p {SSH_PORT} ubuntu@<IP_MÁY_2>")
    print("=" * 70)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Dừng hệ thống Honeypot.")
