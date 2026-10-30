import os
import sys
import uuid
import time
import json
import platform
import subprocess
from pathlib import Path
from gateway.vfs import VirtualFileSystem
from ai_engine.router import CommandRouter
from ai_engine.llm_client import LLMClient
from threat_intel.mitre_mapper import MitreMapper
from threat_intel.logger import HoneypotLogger
from config import HOSTNAME, DEFAULT_USER, EVENT_LOG_FILE, QUARANTINE_DIR, LLM_PROVIDER, LLM_MODEL

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
    def __init__(self, channel, client_ip: str, client_port: int, username: str, logger: HoneypotLogger, is_admin: bool = False):
        self.channel = channel
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = username or DEFAULT_USER
        self.session_id = str(uuid.uuid4())
        self.logger = logger
        self.is_admin = is_admin
        
        # Thư mục làm việc thực tế cho Admin
        self.admin_cwd = str(Path.cwd())

        # Nếu là Hacker thì khởi tạo môi trường Honeypot ảo
        if not self.is_admin:
            self.vfs = VirtualFileSystem(hostname=HOSTNAME, user=self.username)
            self.llm_client = LLMClient()
            self.router = CommandRouter(self.vfs, self.llm_client)

    def get_honeypot_prompt(self) -> str:
        symbol = "#" if self.username == "root" else "$"
        cwd = self.vfs.pwd()
        if cwd == f"/home/{self.username}" or (self.username == "root" and cwd == "/root"):
            cwd = "~"
        return f"\033[01;32m{self.username}@{HOSTNAME}\033[00m:\033[01;34m{cwd}\033[00m{symbol} "

    def get_admin_prompt(self) -> str:
        short_cwd = self.admin_cwd
        home_dir = str(Path.home())
        if short_cwd.startswith(home_dir):
            short_cwd = "~" + short_cwd[len(home_dir):]
        return f"\033[01;31m[ADMIN-HOST]\033[00m \033[01;32m{self.username}@{platform.node() or HOSTNAME}\033[00m:\033[01;34m{short_cwd}\033[00m# "

    def run(self):
        if self.is_admin:
            self.run_admin()
        else:
            self.run_honeypot()

    def run_honeypot(self):
        """Xử lý phiên giả lập Honeypot đánh lừa Hacker."""
        try:
            self.channel.send(WELCOME_BANNER)
            self.channel.send(self.get_honeypot_prompt())

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

                        self.channel.send(self.get_honeypot_prompt())

                    # Tab Autocomplete (byte 9)
                    elif byte == 9:
                        last_was_cr = False
                        cmd_buffer = self.handle_tab_completion(cmd_buffer)

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
                        self.channel.send(self.get_honeypot_prompt())

                    # Ctrl+D
                    elif byte == 4:
                        last_was_cr = False
                        if not cmd_buffer:
                            self.channel.send("exit\r\n")
                            return

                    # Bỏ qua escape sequence (mũi tên, v.v.)
                    elif byte == 27:
                        last_was_cr = False
                        pass

                    # Ký tự thông thường
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

    def run_admin(self):
        """Xử lý phiên Quản trị viên (Điều khiển Host OS thực tế từ máy Windows)."""
        banner = (
            "\r\n"
            "\033[01;33m======================================================================\033[00m\r\n"
            "  \033[01;32m👑 NEXT-GEN ADAPTIVE HONEYPOT - ADMIN REMOTE CONTROL SHELL 👑\033[00m\r\n"
            "\033[01;33m======================================================================\033[00m\r\n"
            f"  IP Kết Nối:       \033[01;36m{self.client_ip}:{self.client_port}\033[00m\r\n"
            f"  Hệ Điều Hành Host: \033[01;32m{platform.system()} {platform.release()} ({platform.machine()})\033[00m\r\n"
            f"  Quyền Hạn:        \033[01;31mFULL HOST CONTROL (Thực thi lệnh thật)\033[00m\r\n"
            "\r\n"
            "  \033[01;36mLỆNH QUẢN TRỊ NHANH:\033[00m\r\n"
            "    :help            - Xem danh sách lệnh hỗ trợ\r\n"
            "    :status          - Xem trạng thái máy chủ & honeypot\r\n"
            "    :logs [số]       - Xem các dòng log tấn công mới nhất (vd: :logs 10)\r\n"
            "    :quarantine      - Xem danh sách mẫu mã độc bị cách ly\r\n"
            "    :exit            - Thoát phiên SSH\r\n"
            "    \033[01;32m<lệnh bất kỳ>\033[00m    - Chạy trực tiếp trên Host OS (cmd/powershell/bash)\r\n"
            "\033[01;33m======================================================================\033[00m\r\n\r\n"
        )
        try:
            self.channel.send(banner)
            self.channel.send(self.get_admin_prompt())

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
                            output, should_exit = self.execute_admin_command(command)
                            if should_exit:
                                self.channel.send("Đã đóng phiên Admin. Tạm biệt!\r\n")
                                return

                            if output:
                                formatted_out = output.replace("\r\n", "\n").replace("\n", "\r\n")
                                if not formatted_out.endswith("\r\n"):
                                    formatted_out += "\r\n"
                                self.channel.send(formatted_out)

                        self.channel.send(self.get_admin_prompt())

                    # Tab Autocomplete (byte 9)
                    elif byte == 9:
                        last_was_cr = False
                        cmd_buffer = self.handle_admin_tab_completion(cmd_buffer)

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
                        self.channel.send(self.get_admin_prompt())

                    # Ctrl+D
                    elif byte == 4:
                        last_was_cr = False
                        if not cmd_buffer:
                            self.channel.send("exit\r\n")
                            return

                    # Bỏ qua escape sequence
                    elif byte == 27:
                        last_was_cr = False
                        pass

                    # Ký tự thông thường
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

    def execute_admin_command(self, cmd: str) -> tuple[str, bool]:
        """Thực thi lệnh Admin: hỗ trợ cả lệnh quản trị nội bộ lẫn lệnh Host OS thật."""
        tokens = cmd.split()
        base_cmd = tokens[0].lower()
        norm_cmd = base_cmd.lstrip(":")

        # Thoát
        if norm_cmd in ("exit", "quit", "q"):
            return "", True

        # Trợ giúp
        if norm_cmd in ("help", "h", "?"):
            help_text = (
                "DANH SÁCH LỆNH QUẢN TRỊ ADMIN (Gõ có hoặc không có dấu : đều được):\r\n"
                "  logs [n]         - Xem n sự kiện tấn công / đăng nhập mới nhất (vd: logs 10)\r\n"
                "  status           - Xem cấu hình hệ thống, AI model, số lượng sự kiện\r\n"
                "  quarantine       - Xem các file mẫu mã độc hacker tải lên\r\n"
                "  cd <thư mục>     - Chuyển thư mục làm việc trên máy chủ\r\n"
                "  exit             - Thoát phiên điều khiển\r\n"
                "  <lệnh bất kỳ>    - Chạy trực tiếp trên Terminal thật của máy chủ (ls, ps, docker, top...)\r\n"
            )
            return help_text, False

        # Trạng thái hệ thống
        if norm_cmd in ("status", "stat", "info"):
            num_logs = 0
            if EVENT_LOG_FILE.exists():
                try:
                    with open(EVENT_LOG_FILE, "r", encoding="utf-8") as f:
                        num_logs = sum(1 for _ in f)
                except Exception:
                    pass

            quarantine_files = list(QUARANTINE_DIR.glob("*")) if QUARANTINE_DIR.exists() else []

            status_text = (
                "--- TRẠNG THÁI HỆ THỐNG & HONEYPOT ---\r\n"
                f"  Host OS:        {platform.system()} {platform.release()} ({platform.version()})\r\n"
                f"  Hostname:       {platform.node()}\r\n"
                f"  Python:         {platform.python_version()}\r\n"
                f"  AI Provider:    {LLM_PROVIDER} (Model: {LLM_MODEL})\r\n"
                f"  Tổng Log Ghi:   {num_logs} sự kiện trong {EVENT_LOG_FILE.name}\r\n"
                f"  Tệp Cách Ly:    {len(quarantine_files)} tệp trong {QUARANTINE_DIR.name}/\r\n"
                f"  Thư mục hiện tại: {self.admin_cwd}\r\n"
            )
            return status_text, False

        # Xem log tấn công gần nhất
        if norm_cmd in ("logs", "log"):
            n = 10
            if len(tokens) > 1 and tokens[1].isdigit():
                n = int(tokens[1])

            if not EVENT_LOG_FILE.exists():
                return "Chưa có log tấn công nào được ghi.", False

            try:
                with open(EVENT_LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                
                recent = lines[-n:] if len(lines) >= n else lines
                if not recent:
                    return "File log đang rỗng.", False

                out_lines = [f"=== HIỂN THỊ {len(recent)} SỰ KIỆN TẤN CÔNG GẦN NHẤT ==="]
                for raw in recent:
                    try:
                        ev = json.loads(raw)
                        ts = ev.get("timestamp", "")[:19]
                        ip = ev.get("source_ip", "")
                        user = ev.get("username", "")
                        status = ev.get("event_status", "")
                        if "Auth" in status:
                            pwd = ev.get("password", "")
                            success = ev.get("auth_success", False)
                            tag = "AUTH_OK" if success else "AUTH_FAIL"
                            mitre = ", ".join([m.get("technique_id", "") for m in ev.get("mitre_techniques", [])]) or "None"
                            out_lines.append(f"[{ts}] {ip} | [{tag}] User: '{user}' Pass: '{pwd}' | MITRE: {mitre}")
                        else:
                            cmd_txt = ev.get("command", "")
                            h_type = ev.get("handler_type", "VFS")
                            mitre = ", ".join([m.get("technique_id", "") if isinstance(m, dict) else str(m) for m in ev.get("mitre_techniques", [])]) or "None"
                            out_lines.append(f"[{ts}] {ip} ({user}) -> `{cmd_txt}` [{h_type}] | MITRE: {mitre}")
                    except Exception:
                        out_lines.append(raw.strip())
                return "\r\n".join(out_lines), False
            except Exception as e:
                return f"Lỗi đọc log: {e}", False

        # Xem thư mục cách ly
        if norm_cmd in ("quarantine", "samples"):
            if not QUARANTINE_DIR.exists():
                return "Thư mục cách ly chưa tồn tại.", False
            files = list(QUARANTINE_DIR.glob("*"))
            if not files:
                return "Không có mẫu mã độc nào trong thư mục cách ly.", False
            res = [f"Danh sách tệp cách ly ({len(files)} tệp):"]
            for f in files:
                size_kb = f.stat().st_size / 1024
                mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f.stat().st_mtime))
                res.append(f"  - {f.name:<25} ({size_kb:.2f} KB) - {mtime}")
            return "\r\n".join(res), False

        # Chuyển thư mục làm việc (cd)
        if base_cmd == "cd":
            if len(tokens) == 1 or tokens[1] in ("~", ""):
                target_path = Path.home()
            else:
                target_path = Path(self.admin_cwd) / tokens[1]

            target_path = target_path.resolve()
            if target_path.exists() and target_path.is_dir():
                self.admin_cwd = str(target_path)
                return f"Đã chuyển thư mục làm việc tới: {self.admin_cwd}", False
            else:
                return f"Thư mục không tồn tại: {tokens[1]}", False

        # Thực thi lệnh trực tiếp trên Host OS thật
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                cwd=self.admin_cwd,
                timeout=45
            )
            out = proc.stdout
            err = proc.stderr
            result = ""
            if out:
                result += out
            if err:
                result += err
            if not result:
                result = "[Lệnh thực thi thành công (không có đầu ra)]"
            return result, False
        except subprocess.TimeoutExpired:
            return "[!] Lệnh bị timeout sau 45 giây.", False
        except Exception as e:
            return f"[!] Lỗi thực thi lệnh trên Host OS: {e}", False

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
                    self.channel.send(self.get_honeypot_prompt() + cmd_buffer)
                    return cmd_buffer
            else:
                self.channel.send("\x07")
                return cmd_buffer

        # 2. Đang gõ đối số đường dẫn file/thư mục
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
        
        # Ẩn file ẩn nếu không chủ động gõ dấu chấm
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
                self.channel.send(self.get_honeypot_prompt() + cmd_buffer)
                return cmd_buffer
        else:
            self.channel.send("\x07")
            return cmd_buffer

    def handle_admin_tab_completion(self, cmd_buffer: str) -> str:
        """Xử lý Tab Autocomplete cho Admin Console."""
        if not cmd_buffer:
            return cmd_buffer

        tokens = cmd_buffer.split()
        ends_with_space = cmd_buffer.endswith(" ")

        if not ends_with_space and len(tokens) == 1:
            admin_cmds = ["status", "logs", "quarantine", "help", "exit", "ls", "ps", "cd", "cat", "top", "docker", "systemctl"]
            matches = [c for c in admin_cmds if c.startswith(tokens[0].lower())]
            if len(matches) == 1:
                rem = matches[0][len(tokens[0]):] + " "
                self.channel.send(rem)
                return cmd_buffer + rem

        word = "" if ends_with_space else tokens[-1]
        try:
            cwd_path = Path(self.admin_cwd)
            files = [f.name for f in cwd_path.glob("*") if f.name.startswith(word)]
            if len(files) == 1:
                f_name = files[0]
                is_dir = (cwd_path / f_name).is_dir()
                suffix = "/" if is_dir else " "
                rem = f_name[len(word):] + suffix
                self.channel.send(rem)
                return cmd_buffer + rem
        except Exception:
            pass

        self.channel.send("\x07")
        return cmd_buffer
