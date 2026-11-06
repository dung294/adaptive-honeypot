import os
import sys
import socket
import threading
import time
import paramiko
from config import (
    REAL_SSH_HOST, REAL_SSH_PORT, REAL_SSH_USER, REAL_SSH_PASSWORD, REAL_SSH_KEY_PATH
)

class AdminProxySession:
    """
    Transparent SSH Proxy Session dành riêng cho Quản trị viên (Admin).
    Chuyển tiếp (Bridge) toàn bộ lưu lượng Terminal PTY 2 chiều
    từ kết nối ngoài (port 22) vào dịch vụ OpenSSH thật của Host (127.0.0.1:REAL_SSH_PORT).
    """
    def __init__(self, client_channel, client_ip: str, client_port: int,
                 username: str = REAL_SSH_USER, password: str = REAL_SSH_PASSWORD,
                 term: str = "xterm-256color", term_width: int = 80, term_height: int = 24):
        self.client_channel = client_channel
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = username or REAL_SSH_USER
        self.password = password or REAL_SSH_PASSWORD
        self.term = term or "xterm-256color"
        self.term_width = term_width or 80
        self.term_height = term_height or 24
        self.backend_client = None
        self.backend_channel = None
        self.running = False

    def run(self):
        print(f"[🛡️ ADMIN PASSTHROUGH] Đang mở kênh kết nối an toàn tới Host thật ({REAL_SSH_HOST}:{REAL_SSH_PORT})...")
        try:
            self.backend_client = paramiko.SSHClient()
            self.backend_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                "hostname": REAL_SSH_HOST,
                "port": REAL_SSH_PORT,
                "username": self.username,
                "timeout": 10
            }
            if REAL_SSH_KEY_PATH and os.path.exists(REAL_SSH_KEY_PATH):
                connect_kwargs["key_filename"] = REAL_SSH_KEY_PATH
            elif self.password:
                connect_kwargs["password"] = self.password

            self.backend_client.connect(**connect_kwargs)
            
            self.backend_channel = self.backend_client.invoke_shell(
                term=self.term,
                width=self.term_width,
                height=self.term_height
            )
            print(f"[✅ ADMIN PASSTHROUGH] Đã thiết lập kênh cầu nối (Bridge) thành công cho Admin từ {self.client_ip}:{self.client_port}!")

            self.running = True

            # Luồng 1: Client -> Real Host
            def forward_client_to_backend():
                while self.running:
                    try:
                        data = self.client_channel.recv(4096)
                        if not data:
                            break
                        self.backend_channel.sendall(data)
                    except Exception:
                        break
                self.running = False

            # Luồng 2: Real Host -> Client
            def forward_backend_to_client():
                while self.running:
                    try:
                        data = self.backend_channel.recv(4096)
                        if not data:
                            break
                        self.client_channel.sendall(data)
                    except Exception:
                        break
                self.running = False

            t1 = threading.Thread(target=forward_client_to_backend, daemon=True)
            t2 = threading.Thread(target=forward_backend_to_client, daemon=True)
            t1.start()
            t2.start()

            while self.running and not self.client_channel.closed and not self.backend_channel.closed:
                time.sleep(0.3)

        except Exception as e:
            err_msg = f"\r\n\033[31m[!] Lỗi kết nối tới máy chủ SSH thật của Host: {e}\033[0m\r\n"
            try:
                self.client_channel.sendall(err_msg.encode("utf-8"))
            except Exception:
                pass
            print(f"[❌ ADMIN PASSTHROUGH ERROR] {e}")
        finally:
            self.running = False
            try:
                if self.backend_channel:
                    self.backend_channel.close()
            except Exception:
                pass
            try:
                if self.backend_client:
                    self.backend_client.close()
            except Exception:
                pass
            try:
                if self.client_channel:
                    self.client_channel.close()
            except Exception:
                pass
            print(f"[🛡️ ADMIN PASSTHROUGH] Đóng phiên làm việc của Admin từ {self.client_ip}:{self.client_port}.")
