import os
import socket
import threading
import paramiko
import uuid
from pathlib import Path
from gateway.terminal_session import TerminalSession
from threat_intel.logger import HoneypotLogger
from config import (
    SSH_HOST, SSH_PORT, SSH_BANNER, SERVER_KEY_PATH,
    HONEYPOT_ALLOWED_PASSWORDS, HONEYPOT_ALLOWED_USERS
)

class HoneypotSSHInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int, logger: HoneypotLogger):
        self.client_ip = client_ip
        self.client_port = client_port
        self.logger = logger
        self.username = "root"
        self.session_id = str(uuid.uuid4())
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        
        user_ok = ("*" in HONEYPOT_ALLOWED_USERS) or (username in HONEYPOT_ALLOWED_USERS)
        pass_ok = password in HONEYPOT_ALLOWED_PASSWORDS

        if user_ok and pass_ok:
            print(f"[+] [AUTH SUCCESS] IP: {self.client_ip}:{self.client_port} | User: '{username}' | Pass: '{password}' -> CẤP QUYỀN VÀO BẪY ẢO")
            if self.logger:
                self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password, success=True, session_id=self.session_id)
            return paramiko.AUTH_SUCCESSFUL
        else:
            print(f"[-] [AUTH FAILED] IP: {self.client_ip}:{self.client_port} | User: '{username}' | Pass: '{password}' -> TỪ CHỐI (SAI MẬT KHẨU)")
            if self.logger:
                self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password, success=False, session_id=str(uuid.uuid4()))
            return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        # Chặn hoàn toàn đăng nhập không mật khẩu
        return paramiko.AUTH_FAILED

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
            
            server_interface = HoneypotSSHInterface(client_ip, client_port, logger=self.logger)
            transport.start_server(server=server_interface)
            
            channel = transport.accept(20)
            if channel is None:
                self.logger.log_connection(client_ip, client_port, status="Immediate_Exit")
                return

            server_interface.event.wait(10)
            if not server_interface.event.is_set():
                self.logger.log_connection(client_ip, client_port, status="Immediate_Exit")
                return

            # Bắt đầu phiên Terminal Honeypot
            session = TerminalSession(
                channel=channel,
                client_ip=client_ip,
                client_port=client_port,
                username=server_interface.username,
                logger=self.logger,
                session_id=server_interface.session_id
            )
            session.run()

        except Exception:
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
        
        print("=" * 70)
        print("🚀 [NEXT-GEN ADAPTIVE HONEYPOT GATEWAY] ĐANG HOẠT ĐỘNG...")
        print(f"🌐 Lắng nghe tại: {self.host}:{self.port}")
        print(f"🛡️  Kiến trúc Deception: Stateful VFS + LLM + Fast-Path + Tab Completion")
        print(f"🔐 Mật khẩu bẫy chấp nhận: {len(HONEYPOT_ALLOWED_PASSWORDS)} mẫu mật khẩu trong cấu hình")
        print(f"📊 Nhật ký sự kiện lưu tại: {self.logger.log_path}")
        print("=" * 70)

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
