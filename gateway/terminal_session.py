import socket
import uuid
from gateway.vfs import VirtualFileSystem
from ai_engine.router import CommandRouter
from ai_engine.llm_client import LLMClient
from threat_intel.mitre_mapper import MitreMapper
from threat_intel.logger import HoneypotLogger
from config import HOSTNAME, DEFAULT_USER

WELCOME_BANNER = (
    f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\n"
    f" * Documentation:  https://help.ubuntu.com\r\n"
    f" * Management:     https://landscape.canonical.com\r\n"
    f" * Support:        https://ubuntu.com/pro\r\n\r\n"
    f"System information as of Fri Oct 30 20:00:00 UTC 2026\r\n\r\n"
    f"  System load:  0.08               Processes:             102\r\n"
    f"  Usage of /:   18.4% of 38.58GB   Users logged in:       1\r\n"
    f"  Memory usage: 22%                IPv4 address for eth0: 192.168.1.100\r\n\r\n"
    f"Last login: Fri Oct 30 19:30:15 2026 from 192.168.1.1\r\n"
)

class TerminalSession:
    def __init__(self, channel, client_ip: str, client_port: int, username: str, logger: HoneypotLogger):
        self.channel = channel
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = username or DEFAULT_USER
        self.session_id = str(uuid.uuid4())
        self.logger = logger
        
        # Mỗi phiên có 1 cây VFS và 1 Router riêng biệt
        self.vfs = VirtualFileSystem(hostname=HOSTNAME, user=self.username)
        self.llm_client = LLMClient()
        self.router = CommandRouter(self.vfs, self.llm_client)

    def get_prompt(self) -> str:
        symbol = "#" if self.username == "root" else "$"
        cwd = self.vfs.pwd()
        if cwd == f"/home/{self.username}" or (self.username == "root" and cwd == "/root"):
            cwd = "~"
        return f"\033[01;32m{self.username}@{HOSTNAME}\033[00m:\033[01;34m{cwd}\033[00m{symbol} "

    def run(self):
        try:
            self.channel.send(WELCOME_BANNER)
            self.channel.send(self.get_prompt())

            cmd_buffer = ""
            last_was_cr = False
            while True:
                data = self.channel.recv(1024)
                if not data:
                    break

                for byte in data:
                    char = chr(byte)

                    # Enter / Newline
                    if char in ('\r', '\n'):
                        if char == '\n' and last_was_cr:
                            last_was_cr = False
                            continue
                        last_was_cr = (char == '\r')

                        self.channel.send("\r\n")
                        command = cmd_buffer.strip()
                        cmd_buffer = ""

                        if command:
                            stdout, handler, latency = self.router.execute(command, user=self.username)
                            
                            # Nếu hacker gõ exit/logout
                            if stdout == "__EXIT__":
                                self.channel.send("logout\r\n")
                                return

                            # Gửi phản hồi stdout về terminal hacker
                            formatted_stdout = stdout.replace("\n", "\r\n")
                            self.channel.send(formatted_stdout)

                            # Phân tích MITRE & Ghi log
                            mitre_tags = MitreMapper.map_command(command)
                            self.logger.log_interaction(
                                session_id=self.session_id,
                                source_ip=self.client_ip,
                                source_port=self.client_port,
                                username=self.username,
                                command=command,
                                command_output=stdout,
                                handler_type=handler,
                                latency_ms=latency,
                                mitre_matches=mitre_tags
                            )

                        self.channel.send(self.get_prompt())

                    # Backspace / Delete
                    elif byte in (127, 8):
                        last_was_cr = False
                        if len(cmd_buffer) > 0:
                            cmd_buffer = cmd_buffer[:-1]
                            self.channel.send("\b \b")

                    # Ctrl+C
                    elif byte == 3:
                        last_was_cr = False
                        cmd_buffer = ""
                        self.channel.send("^C\r\n")
                        self.channel.send(self.get_prompt())

                    # Ctrl+D
                    elif byte == 4:
                        last_was_cr = False
                        if not cmd_buffer:
                            self.channel.send("exit\r\n")
                            return

                    # Bỏ qua escape sequence (mũi tên lên xuống, v.v.)
                    elif byte == 27:
                        last_was_cr = False
                        pass

                    # Ký tự in được thông thường
                    elif 32 <= byte <= 126:
                        last_was_cr = False
                        cmd_buffer += char
                        self.channel.send(char)

        except Exception as e:
            pass
        finally:
            try:
                self.channel.close()
            except Exception:
                pass
