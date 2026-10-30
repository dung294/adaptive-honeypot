import os
import socket
import threading
import paramiko
from pathlib import Path
from gateway.terminal_session import TerminalSession
from threat_intel.logger import HoneypotLogger
from config import (
    SSH_HOST, SSH_PORT, SSH_BANNER, SERVER_KEY_PATH,
    ADMIN_ENABLED, ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_ALLOWED_IPS,
    HONEYPOT_ALLOWED_PASSWORDS, HONEYPOT_ALLOWED_USERS, HONEYPOT_STRICT_AUTH
)

class HoneypotSSHInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int, logger: HoneypotLogger):
        self.client_ip = client_ip
        self.client_port = client_port
        self.logger = logger
        self.username = "root"
        self.is_admin = False
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        
        # 1. Kiểm tra xác thực Quản trị viên (Admin Remote Control điều khiển máy thật)
        if ADMIN_ENABLED and username == ADMIN_USERNAME:
            ip_allowed = (
                "*" in ADMIN_ALLOWED_IPS or
                self.client_ip in ADMIN_ALLOWED_IPS or
                self.client_ip in ("127.0.0.1", "::1", "localhost")
            )
            if ip_allowed and password == ADMIN_PASSWORD:
                self.is_admin = True
                print(f"[👑] [ADMIN AUTH] IP: {self.client_ip}:{self.client_port} | User: '{username}' -> ĐĂNG NHẬP ADMIN THÀNH CÔNG (HOST CONTROL)")
                if self.logger:
                    self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password, success=True, is_admin=True)
                return paramiko.AUTH_SUCCESSFUL
            else:
                print(f"[!] [ADMIN AUTH FAILED] IP: {self.client_ip}:{self.client_port} | User: '{username}' -> Sai pass admin hoặc IP bị chặn.")
                if self.logger:
                    self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password, success=False, is_admin=True)
                return paramiko.AUTH_FAILED

        # 2. Nếu ở chế độ Strict Auth: Khóa toàn bộ tài khoản khác
        if HONEYPOT_STRICT_AUTH:
            print(f"[-] [AUTH REJECTED] IP: {self.client_ip}:{self.client_port} | User: '{username}' (Strict Auth bật)")
            if self.logger:
                self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password, success=False, is_admin=False)
            return paramiko.AUTH_FAILED

        # 3. Xác thực Bẫy Honeypot (KHÔNG PHẢI PASS NÀO CŨNG VÀO ĐƯỢC)
        user_ok = ("*" in HONEYPOT_ALLOWED_USERS) or (username in HONEYPOT_ALLOWED_USERS)
        pass_ok = password in HONEYPOT_ALLOWED_PASSWORDS

        if user_ok and pass_ok:
            self.is_admin = False
            print(f"[+] [HONEYPOT TRAP GRANTED] IP: {self.client_ip}:{self.client_port} | User: '{username}' | Pass: '{password}' -> ĐÚNG PASS BẪY, ĐƯA VÀO VFS+LLM")
            if self.logger:
                self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password, success=True, is_admin=False)
            return paramiko.AUTH_SUCCESSFUL
        else:
            print(f"[-] [HONEYPOT AUTH FAILED] IP: {self.client_ip}:{self.client_port} | User: '{username}' | Pass: '{password}' -> TỪ CHỐI (SAI PASS/USER)")
            if self.logger:
                self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password, success=False, is_admin=False)
            return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        # Tuyệt đối không cho phép đăng nhập nếu không cung cấp password
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
                print(f"[-] [TIMEOUT / REJECTED] {client_ip} không được cấp channel hoặc xác thực thất bại.")
                return

            server_interface.event.wait(10)
            if not server_interface.event.is_set():
                print(f"[-] [TIMEOUT] {client_ip} không yêu cầu shell.")
                return

            # Bắt đầu phiên Terminal (Chế độ Honeypot hoặc Admin Console)
            session = TerminalSession(
                channel=channel,
                client_ip=client_ip,
                client_port=client_port,
                username=server_interface.username,
                logger=self.logger,
                is_admin=server_interface.is_admin
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
        
        print("=" * 70)
        print("🚀 [NEXT-GEN ADAPTIVE HONEYPOT & REMOTE CONTROL GATEWAY]")
        print(f"🌐 Lắng nghe tại: {self.host}:{self.port}")
        print(f"🛡️  Hybrid Deception: Stateful VFS + LLM + Anti-Jailbreak")
        print(f"🔐 Mật khẩu bẫy Honeypot chấp nhận: {len(HONEYPOT_ALLOWED_PASSWORDS)} mật khẩu mẫu trong cấu hình")
        if ADMIN_ENABLED:
            allowed_str = "*" if "*" in ADMIN_ALLOWED_IPS else ", ".join(ADMIN_ALLOWED_IPS)
            print(f"👑 Admin Remote Shell: BẬT | User: '{ADMIN_USERNAME}' | IP Allowed: {allowed_str}")
        else:
            print("👑 Admin Remote Shell: TẮT")
        print(f"📊 File nhật ký sự kiện: {self.logger.log_path}")
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
