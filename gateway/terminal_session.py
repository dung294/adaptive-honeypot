import os
import sys
import uuid
import time
from pathlib import Path
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
        
        # Khởi tạo cây tệp ảo VFS và Router cho phiên
        self.vfs = VirtualFileSystem(hostname=HOSTNAME, user=self.username)
        self.llm_client = LLMClient()
        self.router = CommandRouter(self.vfs, self.llm_client)

        # Lịch sử dòng lệnh chuẩn (có sẵn lệnh của admin trước đó để tạo cảm giác thực tế)
        self.history = ["ls -la", "uptime", "cat /var/log/syslog"]
        self.history_idx = len(self.history)

    def get_prompt(self) -> str:
        symbol = "#" if self.username == "root" else "$"
        cwd = self.vfs.pwd()
        user_home = "/root" if self.username == "root" else f"/home/{self.username}"
        if cwd == user_home:
            cwd = "~"
        return f"\033[01;32m{self.username}@{HOSTNAME}\033[00m:\033[01;34m{cwd}\033[00m{symbol} "

    def run(self):
        """Xử lý phiên tương tác dòng lệnh với hacker: hỗ trợ Tab, Mũi tên Lên/Xuống, Backspace, Ctrl+C."""
        try:
            self.channel.send(WELCOME_BANNER)
            self.channel.send(self.get_prompt())

            cmd_buffer = ""
            last_was_cr = False
            escape_mode = False
            escape_buf = ""

            while True:
                data = self.channel.recv(1024)
                if not data:
                    break

                for byte in data:
                    char = chr(byte)

                    # 1. Xử lý Escape Sequence (Phím mũi tên LÊN / XUỐNG / TRÁI / PHẢI)
                    if escape_mode:
                        escape_buf += char
                        # Các chuỗi ANSI CSI thường kết thúc bằng chữ cái A, B, C, D, ~, F, H
                        if char in ('A', 'B', 'C', 'D', '~', 'F', 'H'):
                            escape_mode = False
                            
                            # MŨI TÊN LÊN (UP ARROW) -> Xem lại lệnh trước trong lịch sử
                            if escape_buf.endswith("[A") or escape_buf.endswith("OA"):
                                if self.history and self.history_idx > 0:
                                    self.history_idx -= 1
                                    # Xóa toàn bộ nội dung đang gõ trên màn hình
                                    self.channel.send("\b \b" * len(cmd_buffer))
                                    cmd_buffer = self.history[self.history_idx]
                                    self.channel.send(cmd_buffer)
                                else:
                                    self.channel.send("\x07") # Bell

                            # MŨI TÊN XUỐNG (DOWN ARROW) -> Tiến tới lệnh sau trong lịch sử
                            elif escape_buf.endswith("[B") or escape_buf.endswith("OB"):
                                if self.history and self.history_idx < len(self.history) - 1:
                                    self.history_idx += 1
                                    self.channel.send("\b \b" * len(cmd_buffer))
                                    cmd_buffer = self.history[self.history_idx]
                                    self.channel.send(cmd_buffer)
                                elif self.history_idx == len(self.history) - 1:
                                    self.history_idx = len(self.history)
                                    self.channel.send("\b \b" * len(cmd_buffer))
                                    cmd_buffer = ""
                                else:
                                    self.channel.send("\x07")
                            
                            escape_buf = ""
                        continue

                    # Bắt đầu chuỗi Escape (ESC = 27)
                    if byte == 27:
                        last_was_cr = False
                        escape_mode = True
                        escape_buf = ""
                        continue

                    # 2. Enter / Newline (Thực thi lệnh)
                    if char in ('\r', '\n'):
                        if char == '\n' and last_was_cr:
                            last_was_cr = False
                            continue
                        last_was_cr = (char == '\r')

                        self.channel.send("\r\n")
                        command = cmd_buffer.strip()
                        cmd_buffer = ""

                        if command:
                            # Lưu vào lịch sử lệnh
                            if not self.history or self.history[-1] != command:
                                self.history.append(command)
                            self.history_idx = len(self.history)

                            stdout, handler, latency = self.router.execute(command, user=self.username)
                            
                            # Nếu hacker gõ exit/logout
                            if stdout == "__EXIT__":
                                self.channel.send("logout\r\n")
                                return

                            # Gửi phản hồi stdout về terminal
                            formatted_stdout = stdout.replace("\r\n", "\n").replace("\n", "\r\n")
                            if formatted_stdout and not formatted_stdout.endswith("\r\n"):
                                formatted_stdout += "\r\n"
                            self.channel.send(formatted_stdout)

                            # Phân tích MITRE & Ghi nhật ký sự kiện
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

                    # 3. Tab Autocompletion (phím Tab = byte 9)
                    elif byte == 9:
                        last_was_cr = False
                        cmd_buffer = self.handle_tab_completion(cmd_buffer)

                    # 4. Backspace / Delete
                    elif byte in (127, 8):
                        last_was_cr = False
                        if len(cmd_buffer) > 0:
                            cmd_buffer = cmd_buffer[:-1]
                            self.channel.send("\b \b")

                    # 5. Ctrl+C (Hủy dòng lệnh hiện tại)
                    elif byte == 3:
                        last_was_cr = False
                        cmd_buffer = ""
                        self.history_idx = len(self.history)
                        self.channel.send("^C\r\n")
                        self.channel.send(self.get_prompt())

                    # 6. Ctrl+D (Thoát nếu dòng trống)
                    elif byte == 4:
                        last_was_cr = False
                        if not cmd_buffer:
                            self.channel.send("exit\r\n")
                            return

                    # 7. Ký tự in được thông thường
                    elif 32 <= byte <= 126:
                        last_was_cr = False
                        cmd_buffer += char
                        self.channel.send(char)

        except Exception:
            pass
        finally:
            try:
                self.channel.close()
            except Exception:
                pass

    def handle_tab_completion(self, cmd_buffer: str) -> str:
        """Xử lý Tab Autocomplete giống hệt GNU Bash thật trên Ubuntu."""
        if not cmd_buffer:
            return cmd_buffer

        tokens = cmd_buffer.split()
        ends_with_space = cmd_buffer.endswith(" ")

        # 1. Đang gõ tên lệnh (chưa có dấu cách) -> Gợi ý lệnh Linux
        if not ends_with_space and len(tokens) == 1:
            current_word = tokens[0]
            from ai_engine.router import CommandRouter
            matches = [cmd for cmd in sorted(CommandRouter.KNOWN_LINUX_COMMANDS) if cmd.startswith(current_word)]
            
            if len(matches) == 1:
                match = matches[0]
                remainder = match[len(current_word):] + " "
                self.channel.send(remainder)
                return cmd_buffer + remainder
            elif len(matches) > 1:
                prefix = os.path.commonprefix(matches)
                if len(prefix) > len(current_word):
                    remainder = prefix[len(current_word):]
                    self.channel.send(remainder)
                    return cmd_buffer + remainder
                else:
                    self.channel.send("\r\n" + "  ".join(matches[:24]) + "\r\n")
                    self.channel.send(self.get_prompt() + cmd_buffer)
                    return cmd_buffer
            else:
                self.channel.send("\x07")
                return cmd_buffer

        # 2. Đang gõ đường dẫn tệp / thư mục
        current_word = "" if ends_with_space else tokens[-1]

        if "/" in current_word:
            dir_part, file_prefix = current_word.rsplit("/", 1)
            target_dir = self.vfs.resolve_path(dir_part if dir_part else "/")
        else:
            dir_part = ""
            file_prefix = current_word
            target_dir = self.vfs.cwd

        node = self.vfs._get_node(target_dir)
        if not node or node.get("type") != "dir":
            self.channel.send("\x07")
            return cmd_buffer

        children = node.get("children", {})
        matches = [name for name in sorted(children.keys()) if name.startswith(file_prefix)]
        
        # Ẩn file ẩn nếu không gõ bắt đầu bằng dấu chấm
        if not file_prefix.startswith("."):
            matches = [m for m in matches if not m.startswith(".")]

        if len(matches) == 1:
            match = matches[0]
            is_dir = children[match].get("type") == "dir"
            suffix = "/" if is_dir else " "
            remainder = match[len(file_prefix):] + suffix
            self.channel.send(remainder)
            return cmd_buffer + remainder
        elif len(matches) > 1:
            prefix = os.path.commonprefix(matches)
            if len(prefix) > len(file_prefix):
                remainder = prefix[len(file_prefix):]
                self.channel.send(remainder)
                return cmd_buffer + remainder
            else:
                self.channel.send("\r\n" + "  ".join(matches) + "\r\n")
                self.channel.send(self.get_prompt() + cmd_buffer)
                return cmd_buffer
        else:
            self.channel.send("\x07")
            return cmd_buffer
