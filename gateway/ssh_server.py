import os
import socket
import threading
import paramiko
from pathlib import Path
from gateway.terminal_session import TerminalSession
from threat_intel.logger import HoneypotLogger
from config import SSH_HOST, SSH_PORT, SSH_BANNER, SERVER_KEY_PATH

class HoneypotSSHInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int, logger: HoneypotLogger):
        self.client_ip = client_ip
        self.client_port = client_port
        self.logger = logger
        self.username = "root"
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        print(f"[*] [AUTH] IP: {self.client_ip}:{self.client_port} | User: '{username}' | Pass: '{password}' -> GRANTED")
        try:
            self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password)
        except Exception:
            pass
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_none(self, username):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def get_or_create_host_key(key_path: Path) -> paramiko.RSAKey:
    """Tự động tạo RSA Host Key nếu chưa tồn tại."""
    if not key_path.exists():
        print(f"[*] Chưa có Host Key. Đang tự động tạo mới tại: {key_path}...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(key_path))
        return key
    return paramiko.RSAKey(filename=str(key_path))

class SSHGatewayServer:
    def __init__(self, host: str = SSH_HOST, port: int = SSH_PORT):
        self.host = host
        self.port = port
        self.logger = HoneypotLogger()
        self.host_key = get_or_create_host_key(SERVER_KEY_PATH)

    def handle_client(self, client_sock, client_addr):
        client_ip, client_port = client_addr
        print(f"[+] [CONNECT] Kết nối mới từ: {client_ip}:{client_port}")
        
        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.local_version = SSH_BANNER
            transport.add_server_key(self.host_key)
            
            server_interface = HoneypotSSHInterface(client_ip, client_port, self.logger)
            transport.start_server(server=server_interface)
            
            channel = transport.accept(20)
            if channel is None:
                print(f"[-] [TIMEOUT] {client_ip} không mở channel.")
                return

            server_interface.event.wait(10)
            if not server_interface.event.is_set():
                print(f"[-] [TIMEOUT] {client_ip} không yêu cầu shell.")
                return

            # Bắt đầu phiên Terminal
            session = TerminalSession(
                channel=channel,
                client_ip=client_ip,
                client_port=client_port,
                username=server_interface.username,
                logger=self.logger
            )
            session.run()

        except Exception as e:
            # print(f"[-] Lỗi phiên: {e}")
            pass
        finally:
            if transport:
                transport.close()
            client_sock.close()
            print(f"[-] [DISCONNECT] Đóng kết nối với: {client_ip}:{client_port}")

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(100)
        
        print("=" * 65)
        print(f"🚀 [NEXT-GEN ADAPTIVE HONEYPOT GATEWAY] ĐANG CHẠY...")
        print(f"🌐 Lắng nghe tại: {self.host}:{self.port}")
        print(f"🛡️  Hybrid Deception: Stateful VFS + Local LLM + Anti-Jailbreak")
        print(f"📊 Sự kiện log được ghi tại: {self.logger.log_path}")
        print("=" * 65)

        try:
            while True:
                client_sock, client_addr = sock.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[!] Dừng Honeypot Gateway.")
        finally:
            sock.close()
