import os
import sys
import uuid
import time
from pathlib import Path
from typing import List, Tuple, Optional
from gateway.vfs import VirtualFileSystem
from gateway.nano_editor import NanoEditor
from ai_engine.router import CommandRouter
from ai_engine.llm_client import LLMClient
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
    f"  Memory usage: 22%                IPv4 address for eth0: 192.168.101.218\r\n\r\n"
    f"Last login: Fri Oct 30 19:30:15 2026 from 192.168.1.1\r\n"
)

class TerminalSession:
    """
    Quản lý phiên tương tác SSH PTY siêu chân thực chuẩn Linux Ubuntu 22.04 LTS.
    - Hỗ trợ đầy đủ phím mũi tên, Readline, con trỏ, Tab completion, Ctrl+C/D/L/A/E/U/K.
    - Cơ chế nâng quyền SUDO & SU có mật khẩu ảo, sudoers, auth cache 5 phút, timeout và đếm số lần sai.
    - Hỗ trợ user stack: 'sudo su' nâng lên root, gõ 'exit' hạ xuống user ban đầu thay vì ngắt kết nối SSH.
    - Tích hợp trình soạn thảo TUI tương tác GNU nano trực tiếp qua channel PTY.
    - Đồng bộ lịch sử ~/.bash_history và các file log auth.log, syslog, dpkg.log.
    """

    def __init__(self, channel, client_ip: str, client_port: int, username: str, logger: HoneypotLogger, session_id: str = None, password: str = "123", term_width: int = 80, term_height: int = 24):
        self.channel = channel
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = username or DEFAULT_USER
        self.auth_password = password or "123"
        self.term_width = term_width or 80
        self.term_height = term_height or 24
        self.session_id = session_id or str(uuid.uuid4())
        self.logger = logger
        self.start_time = time.time()
        self.commands_count = 0
        self.normal_exit = False
        
        # User elevation stack: [(previous_user, previous_cwd)]
        self.user_stack: List[Tuple[str, str]] = []
        self.sudo_auth_timestamp: float = 0.0
        self.sudo_auth_timeout: float = 300.0  # 5 phút

        # Khởi tạo cây tệp ảo VFS và Router
        self.vfs = VirtualFileSystem(hostname=HOSTNAME, user=self.username)
        self.llm_client = LLMClient()
        self.router = CommandRouter(self.vfs, self.llm_client)

        # ĐẢM BẢO BẤT KỲ USER ĐĂNG NHẬP NÀO CŨNG TỒN TẠI VÀ CÓ QUYỀN SUDO
        if self.username != "root":
            if self.username not in self.router.state.users:
                self.router.state.users[self.username] = {
                    "uid": 1000,
                    "gid": 1000,
                    "home": f"/home/{self.username}",
                    "shell": "/bin/bash",
                    "password": self.auth_password
                }
                self.vfs.mkdir(f"/home/{self.username}", user="root")
                self.vfs.chown(f"{self.username}:{self.username}", f"/home/{self.username}", user="root")
            else:
                self.router.state.users[self.username]["password"] = self.auth_password

            # Luôn thêm user vào nhóm sudo
            sudo_members = self.router.state.groups.setdefault("sudo", {}).setdefault("members", [])
            if self.username not in sudo_members:
                sudo_members.append(self.username)
            self.router.state.save_state()

        # Đọc lịch sử ~/.bash_history nếu có
        self.history = self._load_user_history()
        self.history_idx = len(self.history)

    def _load_user_history(self) -> List[str]:
        hist_path = "/root/.bash_history" if self.username == "root" else f"/home/{self.username}/.bash_history"
        ok, content = self.vfs.cat(hist_path, user=self.username)
        if ok and content.strip():
            return [l for l in content.splitlines() if l.strip()]
        return ["ls -la", "uptime", "cat /var/log/syslog"]

    def _save_user_history(self):
        try:
            hist_path = "/root/.bash_history" if self.username == "root" else f"/home/{self.username}/.bash_history"
            content = "\n".join(self.history[-200:]) + "\n"
            self.vfs.write_file(hist_path, content, user=self.username)
        except Exception:
            pass

    def get_prompt(self) -> str:
        symbol = "#" if self.username == "root" else "$"
        cwd = self.vfs.pwd()
        user_home = "/root" if self.username == "root" else f"/home/{self.username}"
        if cwd == user_home:
            cwd = "~"
        return f"\033[01;32m{self.username}@{HOSTNAME}\033[00m:\033[01;34m{cwd}\033[00m{symbol} "

    def _read_password(self, prompt: str) -> Optional[str]:
        """Đọc mật khẩu không echo ký tự từ terminal chuẩn Ubuntu"""
        self.channel.send(prompt)
        pwd = ""
        last_was_cr = False
        while True:
            data = self.channel.recv(1024)
            if not data:
                return None
            for byte in data:
                char = chr(byte)
                if byte == 3:  # Ctrl+C
                    self.channel.send("^C\r\n")
                    return None
                elif char in ('\r', '\n'):
                    if char == '\n' and last_was_cr:
                        last_was_cr = False
                        continue
                    last_was_cr = (char == '\r')
                    self.channel.send("\r\n")
                    return pwd
                elif byte in (127, 8):  # Backspace
                    last_was_cr = False
                    if pwd:
                        pwd = pwd[:-1]
                elif 32 <= byte <= 126:
                    last_was_cr = False
                    pwd += char

    def _authenticate_sudo(self) -> bool:
        """Kiểm tra và xác thực quyền sudo theo đúng sudoers và auth cache"""
        if self.username == "root":
            return True

        # Kiểm tra auth cache 5 phút
        now = time.time()
        if (now - self.sudo_auth_timestamp) < self.sudo_auth_timeout:
            return True

        # Đảm bảo user có mặt trong sudoers
        sudo_members = self.router.state.groups.setdefault("sudo", {}).setdefault("members", [])
        if self.username not in sudo_members:
            sudo_members.append(self.username)

        # Thử nhập mật khẩu tối đa 3 lần
        for attempt in range(3):
            entered = self._read_password(f"[sudo] password for {self.username}: ")
            if entered is None:
                return False

            # Chấp nhận mật khẩu đăng nhập, mật khẩu trong state hoặc mặc định 123
            is_valid = (
                entered == self.auth_password or
                self.router.state.verify_password(self.username, entered) or
                entered in ("123", "admin", "password", "root", "ubuntu")
            )

            if is_valid:
                self.sudo_auth_timestamp = time.time()
                # Ghi log auth thành công
                now_str = time.strftime("%b %d %H:%M:%S")
                log_line = f"{now_str} {HOSTNAME} sudo: {self.username} : TTY=pts/0 ; PWD={self.vfs.pwd()} ; USER=root\n"
                self.vfs.write_file("/var/log/auth.log", log_line, append=True, user="root")
                return True
            else:
                if attempt < 2:
                    self.channel.send("Sorry, try again.\r\n")
                else:
                    self.channel.send("sudo: 3 incorrect password attempts\r\n")
                    now_str = time.strftime("%b %d %H:%M:%S")
                    log_line = f"{now_str} {HOSTNAME} sudo: pam_unix(sudo:auth): authentication failure; logname={self.username} uid=1000 euid=0 tty=/dev/pts/0 ruser={self.username} rhost=\n"
                    self.vfs.write_file("/var/log/auth.log", log_line, append=True, user="root")
                    return False

        return False

    def _handle_su(self, command: str) -> bool:
        """Xử lý lệnh su / su - / su <target_user>"""
        tokens = command.split()
        target_user = "root"
        login_shell = False
        
        for t in tokens[1:]:
            if t in ("-", "-l", "--login"):
                login_shell = True
            elif not t.startswith("-"):
                target_user = t

        if target_user not in self.router.state.users:
            self.channel.send(f"su: user {target_user} does not exist or the user entry does not contain all the required fields\r\n")
            return False

        # Nếu đang là root chuyển sang user khác thì không cần mật khẩu
        if self.username != "root":
            entered = self._read_password("Password: ")
            if entered is None:
                return False
            if not self.router.state.verify_password(target_user, entered):
                self.channel.send("su: Authentication failure\r\n")
                now_str = time.strftime("%b %d %H:%M:%S")
                self.vfs.write_file("/var/log/auth.log", f"{now_str} {HOSTNAME} su[1420]: pam_unix(su:auth): authentication failure; logname={self.username} uid=1000 euid=0 tty=pts/0 ruser={self.username} rhost= user={target_user}\n", append=True, user="root")
                return False

        # Chuyển đổi người dùng thành công
        self.user_stack.append((self.username, self.vfs.pwd()))
        self.username = target_user
        if login_shell:
            new_home = "/root" if target_user == "root" else f"/home/{target_user}"
            self.vfs.cwd = new_home

        now_str = time.strftime("%b %d %H:%M:%S")
        self.vfs.write_file("/var/log/auth.log", f"{now_str} {HOSTNAME} su[1420]: Successful su for {target_user} by {self.user_stack[-1][0]}\n", append=True, user="root")
        return True

    def run(self):
        """Vòng lặp PTY tương tác chuẩn GNU Readline"""
        try:
            self.channel.send(WELCOME_BANNER)
            self.channel.send(self.get_prompt())

            cmd_buffer = ""
            cursor_pos = 0
            last_was_cr = False
            escape_mode = False
            escape_buf = ""

            def redraw_line(new_buf: str):
                nonlocal cmd_buffer, cursor_pos
                if cursor_pos > 0:
                    self.channel.send(f"\x1b[{cursor_pos}D")
                self.channel.send("\x1b[K")
                self.channel.send(new_buf)
                cmd_buffer = new_buf
                cursor_pos = len(new_buf)

            while True:
                data = self.channel.recv(1024)
                if not data:
                    break

                for byte in data:
                    char = chr(byte)

                    # 1. Escape Sequences
                    if escape_mode:
                        escape_buf += char
                        if char in ('A', 'B', 'C', 'D', '~', 'F', 'H'):
                            escape_mode = False
                            
                            # UP ARROW
                            if escape_buf.endswith("[A") or escape_buf.endswith("OA"):
                                if self.history and self.history_idx > 0:
                                    self.history_idx -= 1
                                    redraw_line(self.history[self.history_idx])
                                else:
                                    self.channel.send("\x07")

                            # DOWN ARROW
                            elif escape_buf.endswith("[B") or escape_buf.endswith("OB"):
                                if self.history and self.history_idx < len(self.history) - 1:
                                    self.history_idx += 1
                                    redraw_line(self.history[self.history_idx])
                                elif self.history_idx == len(self.history) - 1:
                                    self.history_idx = len(self.history)
                                    redraw_line("")
                                else:
                                    self.channel.send("\x07")

                            # LEFT ARROW
                            elif escape_buf.endswith("[D") or escape_buf.endswith("OD"):
                                if cursor_pos > 0:
                                    cursor_pos -= 1
                                    self.channel.send("\x1b[D")
                                else:
                                    self.channel.send("\x07")

                            # RIGHT ARROW
                            elif escape_buf.endswith("[C") or escape_buf.endswith("OC"):
                                if cursor_pos < len(cmd_buffer):
                                    cursor_pos += 1
                                    self.channel.send("\x1b[C")
                                else:
                                    self.channel.send("\x07")

                            # HOME
                            elif escape_buf.endswith("[H") or escape_buf.endswith("OH") or escape_buf.endswith("[1~") or escape_buf.endswith("[7~"):
                                if cursor_pos > 0:
                                    self.channel.send(f"\x1b[{cursor_pos}D")
                                    cursor_pos = 0

                            # END
                            elif escape_buf.endswith("[F") or escape_buf.endswith("OF") or escape_buf.endswith("[4~") or escape_buf.endswith("[8~"):
                                if cursor_pos < len(cmd_buffer):
                                    diff = len(cmd_buffer) - cursor_pos
                                    self.channel.send(f"\x1b[{diff}C")
                                    cursor_pos = len(cmd_buffer)

                            # DELETE
                            elif escape_buf.endswith("[3~"):
                                if cursor_pos < len(cmd_buffer):
                                    cmd_buffer = cmd_buffer[:cursor_pos] + cmd_buffer[cursor_pos + 1:]
                                    remainder = cmd_buffer[cursor_pos:]
                                    self.channel.send("\x1b[K" + remainder)
                                    if remainder:
                                        self.channel.send(f"\x1b[{len(remainder)}D")
                                else:
                                    self.channel.send("\x07")

                            escape_buf = ""
                        continue

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
                        cursor_pos = 0

                        if command:
                            self.commands_count += 1
                            if not self.history or self.history[-1] != command:
                                self.history.append(command)
                            self.history_idx = len(self.history)

                            # =================================================
                            # A. NÂNG QUYỀN: SUDO SU / SUDO -I / SUDO -S
                            # =================================================
                            cmd_tokens = command.split()
                            if cmd_tokens[0] == "sudo" and len(cmd_tokens) > 1 and cmd_tokens[1] in ("su", "-i", "-s"):
                                if self._authenticate_sudo():
                                    self.user_stack.append((self.username, self.vfs.pwd()))
                                    self.username = "root"
                                    if "-i" in cmd_tokens or "-" in cmd_tokens:
                                        self.vfs.cwd = "/root"
                                self.channel.send(self.get_prompt())
                                continue

                            # =================================================
                            # B. CHUYỂN USER: SU / SU -
                            # =================================================
                            elif cmd_tokens[0] == "su":
                                self._handle_su(command)
                                self.channel.send(self.get_prompt())
                                continue

                            # =================================================
                            # C. TRÌNH SOẠN THẢO NANO: nano <file> / sudo nano <file>
                            # =================================================
                            elif cmd_tokens[0] == "nano" or (cmd_tokens[0] == "sudo" and len(cmd_tokens) > 1 and cmd_tokens[1] == "nano"):
                                is_sudo = (cmd_tokens[0] == "sudo")
                                if is_sudo:
                                    if not self._authenticate_sudo():
                                        self.channel.send(self.get_prompt())
                                        continue
                                    target_file = cmd_tokens[2] if len(cmd_tokens) > 2 else "newfile.txt"
                                    nano_user = "root"
                                else:
                                    target_file = cmd_tokens[1] if len(cmd_tokens) > 1 else "newfile.txt"
                                    nano_user = self.username

                                editor = NanoEditor(
                                    channel=self.channel,
                                    vfs=self.vfs,
                                    file_path=target_file,
                                    user=nano_user,
                                    width=self.term_width,
                                    height=self.term_height
                                )
                                editor.run()

                                self.logger.log_interaction(
                                    session_id=self.session_id,
                                    source_ip=self.client_ip,
                                    source_port=self.client_port,
                                    username=self.username,
                                    command=command,
                                    command_output="[NANO_INTERACTIVE_SESSION]",
                                    handler_type="NANO",
                                    latency_ms=10.0
                                )

                                self.channel.send(self.get_prompt())
                                continue

                            # =================================================
                            # D. SUDO LỆNH THÔNG THƯỜNG (e.g. sudo cat /etc/shadow)
                            # =================================================
                            elif cmd_tokens[0] == "sudo":
                                if not self._authenticate_sudo():
                                    self.channel.send(self.get_prompt())
                                    continue
                                exec_user = "root"
                            else:
                                exec_user = self.username

                            # =================================================
                            # E. XỬ LÝ LỆNH EXIT / LOGOUT VỚI USER STACK
                            # =================================================
                            if command in ("exit", "logout"):
                                if self.user_stack:
                                    self.username, prev_cwd = self.user_stack.pop()
                                    self.vfs.cwd = prev_cwd
                                    self.channel.send("exit\r\n")
                                    self.channel.send(self.get_prompt())
                                    continue
                                else:
                                    self.normal_exit = True
                                    self.channel.send("logout\r\n")
                                    return

                            stdout, handler, latency = self.router.execute(command, user=exec_user, channel=self.channel)

                            is_streamed = stdout.startswith("__STREAMED__")
                            clean_stdout = stdout[len("__STREAMED__"):] if is_streamed else stdout

                            # Ghi log
                            self.logger.log_interaction(
                                session_id=self.session_id,
                                source_ip=self.client_ip,
                                source_port=self.client_port,
                                username=self.username,
                                command=command,
                                command_output="" if clean_stdout == "__EXIT__" else clean_stdout,
                                handler_type=handler,
                                latency_ms=latency
                            )

                            if clean_stdout == "__EXIT__":
                                if self.user_stack:
                                    self.username, prev_cwd = self.user_stack.pop()
                                    self.vfs.cwd = prev_cwd
                                    self.channel.send("exit\r\n")
                                    self.channel.send(self.get_prompt())
                                    continue
                                else:
                                    self.normal_exit = True
                                    self.channel.send("logout\r\n")
                                    return

                            # Gửi stdout về terminal (nếu chưa được phát luồng live)
                            if not is_streamed:
                                formatted_stdout = clean_stdout.replace("\r\n", "\n").replace("\n", "\r\n")
                                if formatted_stdout and not formatted_stdout.endswith("\r\n"):
                                    formatted_stdout += "\r\n"
                                self.channel.send(formatted_stdout)

                        self.channel.send(self.get_prompt())

                    # 3. Tab Autocompletion
                    elif byte == 9:
                        last_was_cr = False
                        cmd_buffer = self.handle_tab_completion(cmd_buffer)
                        cursor_pos = len(cmd_buffer)

                    # 4. Backspace
                    elif byte in (127, 8):
                        last_was_cr = False
                        if cursor_pos > 0:
                            cmd_buffer = cmd_buffer[:cursor_pos - 1] + cmd_buffer[cursor_pos:]
                            cursor_pos -= 1
                            self.channel.send("\b\x1b[K")
                            remainder = cmd_buffer[cursor_pos:]
                            self.channel.send(remainder)
                            if remainder:
                                self.channel.send(f"\x1b[{len(remainder)}D")
                        else:
                            self.channel.send("\x07")

                    # 5. Ctrl+C
                    elif byte == 3:
                        last_was_cr = False
                        cmd_buffer = ""
                        cursor_pos = 0
                        self.history_idx = len(self.history)
                        self.channel.send("^C\r\n")
                        self.channel.send(self.get_prompt())

                    # 6. Ctrl+D (Thoát)
                    elif byte == 4:
                        last_was_cr = False
                        if not cmd_buffer:
                            if self.user_stack:
                                self.username, prev_cwd = self.user_stack.pop()
                                self.vfs.cwd = prev_cwd
                                self.channel.send("exit\r\n")
                                self.channel.send(self.get_prompt())
                                continue
                            else:
                                self.normal_exit = True
                                self.channel.send("exit\r\n")
                                return

                    # 7. Ctrl+A (Home)
                    elif byte == 1:
                        last_was_cr = False
                        if cursor_pos > 0:
                            self.channel.send(f"\x1b[{cursor_pos}D")
                            cursor_pos = 0

                    # 8. Ctrl+E (End)
                    elif byte == 5:
                        last_was_cr = False
                        if cursor_pos < len(cmd_buffer):
                            diff = len(cmd_buffer) - cursor_pos
                            self.channel.send(f"\x1b[{diff}C")
                            cursor_pos = len(cmd_buffer)

                    # 9. Ctrl+U (Clear before cursor)
                    elif byte == 21:
                        last_was_cr = False
                        if cursor_pos > 0:
                            cmd_buffer = cmd_buffer[cursor_pos:]
                            self.channel.send(f"\x1b[{cursor_pos}D\x1b[K" + cmd_buffer)
                            if cmd_buffer:
                                self.channel.send(f"\x1b[{len(cmd_buffer)}D")
                            cursor_pos = 0

                    # 10. Ctrl+K (Clear after cursor)
                    elif byte == 11:
                        last_was_cr = False
                        cmd_buffer = cmd_buffer[:cursor_pos]
                        self.channel.send("\x1b[K")

                    # 11. Ctrl+L (Clear screen)
                    elif byte == 12:
                        last_was_cr = False
                        self.channel.send("\x1b[2J\x1b[H")
                        self.channel.send(self.get_prompt() + cmd_buffer)
                        if cursor_pos < len(cmd_buffer):
                            self.channel.send(f"\x1b[{len(cmd_buffer) - cursor_pos}D")

                    # 12. Printable characters
                    elif 32 <= byte <= 126:
                        last_was_cr = False
                        if cursor_pos == len(cmd_buffer):
                            cmd_buffer += char
                            cursor_pos += 1
                            self.channel.send(char)
                        else:
                            cmd_buffer = cmd_buffer[:cursor_pos] + char + cmd_buffer[cursor_pos:]
                            cursor_pos += 1
                            remainder = cmd_buffer[cursor_pos:]
                            self.channel.send(char + "\x1b[K" + remainder)
                            if remainder:
                                self.channel.send(f"\x1b[{len(remainder)}D")

        except Exception:
            pass
        finally:
            self._save_user_history()
            try:
                duration = time.time() - self.start_time
                reason = "normal" if self.normal_exit else "abrupt_disconnect"
                self.logger.log_session_end(
                    session_id=self.session_id,
                    source_ip=self.client_ip,
                    source_port=self.client_port,
                    username=self.username,
                    duration_sec=duration,
                    commands_count=self.commands_count,
                    reason=reason
                )
            except Exception:
                pass
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
