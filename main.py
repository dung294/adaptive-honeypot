import sys
import io
import threading
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gateway.ssh_server import SSHGatewayServer
from config import SSH_HOST, SSH_PORT
from threat_intel.web_log_collector import DVWALogCollector

def start_web_collector():
    try:
        collector = DVWALogCollector(container_name="dvwa")
        collector.start_collecting()
    except Exception as e:
        print(f"[!] Web CTI Log Collector notice: {e}")

def main():
    # Khởi động Web CTI Collector trong luồng ngầm để thu thập log từ container DVWA
    web_thread = threading.Thread(target=start_web_collector, daemon=True)
    web_thread.start()
    print("[*] Unified CTI Engine: SSH Gateway + Web DVWA Log Collector Active.")

    server = SSHGatewayServer(host=SSH_HOST, port=SSH_PORT)
    try:
        server.start()
    except Exception as e:
        print(f"[FATAL] Không thể khởi động SSH Gateway: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
