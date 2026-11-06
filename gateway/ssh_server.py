import os
import sys
import socket
import threading
import paramiko
import uuid
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
from gateway.terminal_session import TerminalSession
from gateway.admin_proxy import AdminProxySession
from threat_intel.logger import HoneypotLogger
from config import (
    SSH_HOST, SSH_PORT, SSH_BANNER, SERVER_KEY_PATH,
    HONEYPOT_ALLOWED_PASSWORDS, HONEYPOT_ALLOWED_USERS,
    ENABLE_ADMIN_PASSTHROUGH, REAL_SSH_HOST, REAL_SSH_PORT,
    REAL_SSH_USER, REAL_SSH_PASSWORD, ADMIN_AUTHORIZED_KEYS_FILE,
    ADMIN_ALLOWED_USERS, ADMIN_ALLOWED_PASSWORDS
)

class HoneypotSSHInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int, logger: HoneypotLogger):
        self.client_ip = client_ip
        self.client_port = client_port
        self.logger = logger
        self.username = "root"
        self.password = ""
        self.term = "xterm-256color"
        self.term_width = 80
        self.term_height = 24
        self.session_id = str(uuid.uuid4())
        self.is_admin = False
        self.auth_type = "password"
        self.is_exec = False
        self.exec_command = ""
        self.event = threading.Event()
        self.proxy_session = None

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_publickey(self, username, key):
        self.username = username
        self.auth_type = "publickey"

        if ENABLE_ADMIN_PASSTHROUGH and ADMIN_AUTHORIZED_KEYS_FILE.exists():
            try:
                with open(ADMIN_AUTHORIZED_KEYS_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            key_b64 = parts[1]
                            if key.get_base64() == key_b64:
                                self.is_admin = True
                                print(f"[🛡️ AUTH ADMIN] IP: {self.client_ip}:{self.client_port} | User: '{username}' -> XÁC THỰC ADMIN BẰNG SSH KEY HỢP LỆ!")
                                return paramiko.AUTH_SUCCESSFUL
            except Exception as e:
                print(f"[!] Lỗi kiểm tra admin_authorized_keys: {e}")

        print(f"[-] [AUTH KEY REJECT] Key từ IP {self.client_ip}:{self.client_port} không thuộc Admin -> Yêu cầu thử phương thức khác.")
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.auth_type = "password"

        # 1. Kiểm tra xác thực Admin Passthrough (Mật khẩu đặc quyền)
        if ENABLE_ADMIN_PASSTHROUGH:
            is_admin_user = (username in ADMIN_ALLOWED_USERS) or ("*" in ADMIN_ALLOWED_USERS)
            is_admin_pass = (password in ADMIN_ALLOWED_PASSWORDS)
            if is_admin_user and is_admin_pass:
                self.is_admin = True
                print(f"[🛡️ AUTH ADMIN] IP: {self.client_ip}:{self.client_port} | User: '{username}' -> XÁC THỰC ADMIN THÀNH CÔNG (PASSTHROUGH SANG HOST THẬT)")
                return paramiko.AUTH_SUCCESSFUL

        # 2. Kiểm tra xác thực Bẫy Honeypot
        user_ok = ("*" in HONEYPOT_ALLOWED_USERS) or (username in HONEYPOT_ALLOWED_USERS)
        pass_ok = password in HONEYPOT_ALLOWED_PASSWORDS

        if user_ok and pass_ok:
            self.is_admin = False
            print(f"[+] [AUTH SUCCESS] IP: {self.client_ip}:{self.client_port} | User: '{username}' | Pass: '{password}' -> CẤP QUYỀN VÀO BẪY ẢO")
            if self.logger:
                self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password, success=True, session_id=self.session_id)
            return paramiko.AUTH_SUCCESSFUL
        else:
            self.is_admin = False
            print(f"[-] [AUTH FAILED] IP: {self.client_ip}:{self.client_port} | User: '{username}' | Pass: '{password}' -> TỪ CHỐI (SAI MẬT KHẨU)")
            if self.logger:
                self.logger.log_auth_attempt(self.client_ip, self.client_port, username, password, success=False, session_id=str(uuid.uuid4()))
            return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        # Chặn hoàn toàn đăng nhập không mật khẩu
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.term = term or "xterm-256color"
        self.term_width = width or 80
        self.term_height = height or 24
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        self.term_width = width
        self.term_height = height
        if self.proxy_session and self.proxy_session.backend_channel:
            try:
                self.proxy_session.backend_channel.resize_pty(width=width, height=height)
            except Exception:
                pass
        return True

    def check_channel_shell_request(self, channel):
        self.is_exec = False
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.is_exec = True
        self.exec_command = command.decode("utf-8", errors="ignore") if isinstance(command, bytes) else str(command)
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

            # Phân luồng: Admin Passthrough vs Honeypot Sandbox
            if server_interface.is_admin:
                print(f"[🛡️ ROUTING] Đang chuyển tiếp phiên của Admin tới OpenSSH Host ({REAL_SSH_HOST}:{REAL_SSH_PORT})...")
                proxy = AdminProxySession(
                    client_channel=channel,
                    client_ip=client_ip,
                    client_port=client_port,
                    username=REAL_SSH_USER,
                    password=REAL_SSH_PASSWORD,
                    term=server_interface.term,
                    term_width=server_interface.term_width,
                    term_height=server_interface.term_height
                )
                server_interface.proxy_session = proxy
                proxy.run(is_exec=server_interface.is_exec, exec_command=server_interface.exec_command)
            else:
                # Bắt đầu phiên Terminal Honeypot cho Attacker
                session = TerminalSession(
                    channel=channel,
                    client_ip=client_ip,
                    client_port=client_port,
                    username=server_interface.username,
                    password=server_interface.password,
                    term_width=server_interface.term_width,
                    term_height=server_interface.term_height,
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
        print("[*] [NEXT-GEN ADAPTIVE HONEYPOT GATEWAY] ĐANG HOẠT ĐỘNG...")
        print(f"[*] Lắng nghe tại: {self.host}:{self.port}")
        print(f"[+] Kiến trúc Deception: Stateful VFS + LLM + Fast-Path + Tab Completion")
        print(f"[*] Mật khẩu bẫy chấp nhận: {len(HONEYPOT_ALLOWED_PASSWORDS)} mẫu mật khẩu trong cấu hình")
        print(f"[*] Nhật ký sự kiện lưu tại: {self.logger.log_path}")
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
