import sys
import io
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gateway.ssh_server import SSHGatewayServer
from config import SSH_HOST, SSH_PORT

def main():
    print("=" * 70)
    print("🚀 [ADAPTIVE SSH HONEYPOT] KHỞI ĐỘNG HỆ THỐNG PHẢN HỒI AI...")
    print(f"🌐 Giao thức: SSH Terminal (Cổng {SSH_PORT})")
    print("📋 Chế độ: Thu thập log hoạt động thô nguyên bản (Raw Unlabeled Logs)")
    print("=" * 70)

    server = SSHGatewayServer(host=SSH_HOST, port=SSH_PORT)
    try:
        server.start()
    except Exception as e:
        print(f"[FATAL] Không thể khởi động SSH Gateway: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
