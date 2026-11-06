import os
import time
from typing import List, Tuple, Optional

class NanoEditor:
    """
    Trình mô phỏng GNU nano 6.2 hoàn chỉnh chuẩn giao thức ANSI/VT100.
    - Chạy trên Alternate Screen Buffer (\x1b[?1049h), khôi phục sạch sẽ khi thoát (\x1b[?1049l).
    - Quản lý trạng thái modal (Editing, Prompt Save on Exit, Prompt WriteOut, Prompt Search).
    - Thoát dứt khoát 100% khi bấm Ctrl+X.
    - Hỗ trợ đầy đủ phím điều hướng con trỏ, Home, End, PgUp, PgDown, chèn/xóa chữ, Ctrl+K/U/C/O/W/X.
    - Kiểm tra quyền ghi VirtualFileSystem.
    """

    def __init__(self, channel, vfs, file_path: str, user: str = "root", width: int = 80, height: int = 24):
        self.channel = channel
        self.vfs = vfs
        self.raw_path = file_path or "newfile.txt"
        self.resolved_path = vfs.resolve_path(self.raw_path)
        self.user = user
        self.width = max(width if width else 80, 40)
        self.height = max(height if height else 24, 10)
        self.body_height = max(self.height - 4, 4)

        self.lines: List[str] = [""]
        self.cursor_row = 0
        self.cursor_col = 0
        self.scroll_top = 0
        self.scroll_left = 0
        self.modified = False
        self.cut_buffer: Optional[str] = None
        self.status_message = ""
        self.is_writable = True
        self.running = True

        # Modal Prompt State Machine: "edit" | "prompt_save_exit" | "prompt_writeout" | "prompt_search"
        self.mode = "edit"
        self.prompt_input = ""

        self._load_file()

    def _load_file(self):
        node = self.vfs._get_node(self.resolved_path)
        if node:
            if node.get("type") == "dir":
                self.lines = [f"Error: {self.raw_path} is a directory"]
                self.is_writable = False
                self.status_message = f"[ '{self.raw_path}' is a directory ]"
                return

            can_read = self.vfs.check_permission(node, mode="r", user=self.user)
            if not can_read:
                self.lines = ["[ Permission denied ]"]
                self.is_writable = False
                self.status_message = f"[ File '{self.raw_path}' is unwritable / Permission denied ]"
                return

            content = node.get("content", "")
            self.lines = content.split("\n")
            if not self.lines:
                self.lines = [""]
            
            self.is_writable = self.vfs.check_permission(node, mode="w", user=self.user)
            if not self.is_writable:
                self.status_message = f"[ File '{self.raw_path}' is unwritable ]"
            else:
                self.status_message = f"[ Read {len(self.lines)} lines ]"
        else:
            parent_path = os.path.dirname(self.resolved_path)
            parent_node = self.vfs._get_node(parent_path)
            if parent_node and not self.vfs.check_permission(parent_node, mode="w", user=self.user):
                self.is_writable = False
                self.status_message = f"[ Directory unwritable ]"
            else:
                self.status_message = f"[ New File ]"
            self.lines = [""]

    def _render(self):
        """Vẽ lại toàn bộ khung màn hình nano bằng định vị tuyệt đối ANSI"""
        out = []
        out.append("\x1b[?25l")  # Hide cursor during redraw

        # 1. Header (Row 1)
        mod_flag = " [Modified]" if self.modified else ""
        left_txt = "  GNU nano 6.2"
        mid_txt = f"File: {self.raw_path}"
        header_line = left_txt.ljust(20) + mid_txt.center(max(0, self.width - 40)) + mod_flag.rjust(20)
        header_line = header_line[:self.width].ljust(self.width)
        out.append(f"\x1b[1;1H\x1b[7m{header_line}\x1b[0m")

        # 2. Text Area (Rows 2 to body_height + 1)
        for i in range(self.body_height):
            row_idx = self.scroll_top + i
            screen_r = i + 2
            if row_idx < len(self.lines):
                content = self.lines[row_idx]
                disp = content[self.scroll_left:self.scroll_left + self.width]
            else:
                disp = ""
            out.append(f"\x1b[{screen_r};1H{disp}\x1b[K")

        # 3. Status / Prompt Line (Row height - 2)
        status_r = self.height - 2
        if self.mode == "prompt_save_exit":
            prompt_disp = "Save modified buffer? (Answering 'No' will DISCARD changes) [Y/N, ^C Cancel]"
            out.append(f"\x1b[{status_r};1H\x1b[1;37;41m{prompt_disp[:self.width].ljust(self.width)}\x1b[0m")
        elif self.mode == "prompt_writeout":
            prompt_disp = f"File Name to Write: {self.prompt_input}"
            out.append(f"\x1b[{status_r};1H\x1b[7m{prompt_disp[:self.width].ljust(self.width)}\x1b[0m")
        elif self.mode == "prompt_search":
            prompt_disp = f"Search: {self.prompt_input}"
            out.append(f"\x1b[{status_r};1H\x1b[7m{prompt_disp[:self.width].ljust(self.width)}\x1b[0m")
        else:
            disp_status = self.status_message[:self.width]
            out.append(f"\x1b[{status_r};1H{disp_status}\x1b[K")

        # 4. Shortcut Bar (Rows height - 1 and height)
        sc_r1 = self.height - 1
        sc_r2 = self.height
        if self.mode == "prompt_save_exit":
            s1 = "\x1b[7m Y \x1b[0m Yes      \x1b[7m N \x1b[0m No       \x1b[7m^C\x1b[0m Cancel"
            s2 = ""
        elif self.mode == "prompt_writeout":
            s1 = "\x1b[7m^G\x1b[0m Get Help \x1b[7m M-D \x1b[0m DOS Format \x1b[7m M-M \x1b[0m Mac Format \x1b[7m^C\x1b[0m Cancel"
            s2 = "\x1b[7m^T\x1b[0m To Files \x1b[7m M-A \x1b[0m Append     \x1b[7m M-P \x1b[0m Prepend"
        elif self.mode == "prompt_search":
            s1 = "\x1b[7m^G\x1b[0m Get Help \x1b[7m M-C \x1b[0m Case Sens \x1b[7m M-B \x1b[0m Backwards \x1b[7m^C\x1b[0m Cancel"
            s2 = "\x1b[7m^R\x1b[0m Regexp   \x1b[7m M-R \x1b[0m Replace   "
        else:
            s1 = "\x1b[7m^G\x1b[0m Help     \x1b[7m^O\x1b[0m WriteOut \x1b[7m^W\x1b[0m Where Is \x1b[7m^K\x1b[0m Cut      \x1b[7m^T\x1b[0m Execute"
            s2 = "\x1b[7m^X\x1b[0m Exit     \x1b[7m^R\x1b[0m Read File\x1b[7m^\\\x1b[0m Replace  \x1b[7m^U\x1b[0m Paste    \x1b[7m^J\x1b[0m Justify"

        out.append(f"\x1b[{sc_r1};1H{s1}\x1b[K")
        out.append(f"\x1b[{sc_r2};1H{s2}\x1b[K")

        # 5. Position cursor
        if self.mode == "prompt_writeout":
            c_col = len("File Name to Write: ") + len(self.prompt_input) + 1
            out.append(f"\x1b[{status_r};{min(c_col, self.width)}H")
        elif self.mode == "prompt_search":
            c_col = len("Search: ") + len(self.prompt_input) + 1
            out.append(f"\x1b[{status_r};{min(c_col, self.width)}H")
        else:
            scr_r = (self.cursor_row - self.scroll_top) + 2
            scr_c = (self.cursor_col - self.scroll_left) + 1
            out.append(f"\x1b[{scr_r};{scr_c}H")

        out.append("\x1b[?25h")  # Show cursor
        self.channel.send("".join(out))

    def _ensure_cursor_visible(self):
        if self.cursor_row < self.scroll_top:
            self.scroll_top = self.cursor_row
        elif self.cursor_row >= self.scroll_top + self.body_height:
            self.scroll_top = self.cursor_row - self.body_height + 1

        if self.cursor_col < self.scroll_left:
            self.scroll_left = self.cursor_col
        elif self.cursor_col >= self.scroll_left + self.width:
            self.scroll_left = self.cursor_col - self.width + 1

    def _save_file(self) -> bool:
        if not self.is_writable:
            self.status_message = f"[ Error writing {self.raw_path}: Permission denied ]"
            return False

        content = "\n".join(self.lines)
        ok, err = self.vfs.write_file(self.resolved_path, content, user=self.user)
        if ok:
            self.modified = False
            self.status_message = f"[ Wrote {len(self.lines)} lines ]"
            return True
        else:
            self.status_message = f"[ Error writing {self.raw_path}: {err} ]"
            return False

    def run(self):
        """Vòng lặp tương tác chính - Bật Alternate Screen Buffer"""
        # Bật alternate screen buffer + xóa màn hình
        self.channel.send("\x1b[?1049h\x1b[2J\x1b[H")
        self._ensure_cursor_visible()
        self._render()

        escape_mode = False
        escape_buf = ""

        try:
            while self.running:
                data = self.channel.recv(1024)
                if not data:
                    break

                for byte in data:
                    if not self.running:
                        break

                    char = chr(byte)

                    # 1. Escape Sequences (Mũi tên, Delete, Home, End, PgUp, PgDown)
                    if escape_mode:
                        escape_buf += char
                        if char in ('A', 'B', 'C', 'D', '~', 'F', 'H'):
                            escape_mode = False
                            if self.mode == "edit":
                                if escape_buf.endswith("[A") or escape_buf.endswith("OA"):
                                    if self.cursor_row > 0:
                                        self.cursor_row -= 1
                                        self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))
                                elif escape_buf.endswith("[B") or escape_buf.endswith("OB"):
                                    if self.cursor_row < len(self.lines) - 1:
                                        self.cursor_row += 1
                                        self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))
                                elif escape_buf.endswith("[D") or escape_buf.endswith("OD"):
                                    if self.cursor_col > 0:
                                        self.cursor_col -= 1
                                    elif self.cursor_row > 0:
                                        self.cursor_row -= 1
                                        self.cursor_col = len(self.lines[self.cursor_row])
                                elif escape_buf.endswith("[C") or escape_buf.endswith("OC"):
                                    if self.cursor_col < len(self.lines[self.cursor_row]):
                                        self.cursor_col += 1
                                    elif self.cursor_row < len(self.lines) - 1:
                                        self.cursor_row += 1
                                        self.cursor_col = 0
                                elif escape_buf.endswith("[H") or escape_buf.endswith("OH") or escape_buf.endswith("[1~") or escape_buf.endswith("[7~"):
                                    self.cursor_col = 0
                                elif escape_buf.endswith("[F") or escape_buf.endswith("OF") or escape_buf.endswith("[4~") or escape_buf.endswith("[8~"):
                                    self.cursor_col = len(self.lines[self.cursor_row])
                                elif escape_buf.endswith("[5~"):
                                    self.cursor_row = max(0, self.cursor_row - self.body_height)
                                    self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))
                                elif escape_buf.endswith("[6~"):
                                    self.cursor_row = min(len(self.lines) - 1, self.cursor_row + self.body_height)
                                    self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))
                                elif escape_buf.endswith("[3~"):
                                    curr = self.lines[self.cursor_row]
                                    if self.cursor_col < len(curr):
                                        self.lines[self.cursor_row] = curr[:self.cursor_col] + curr[self.cursor_col + 1:]
                                        self.modified = True
                                    elif self.cursor_row < len(self.lines) - 1:
                                        self.lines[self.cursor_row] += self.lines[self.cursor_row + 1]
                                        self.lines.pop(self.cursor_row + 1)
                                        self.modified = True

                            escape_buf = ""
                            self._ensure_cursor_visible()
                            self._render()
                        continue

                    if byte == 27:
                        escape_mode = True
                        escape_buf = ""
                        continue

                    # =========================================================
                    # 2. XỬ LÝ TRẠNG THÁI PROMPT: SAVE ON EXIT
                    # =========================================================
                    if self.mode == "prompt_save_exit":
                        if byte in (ord('y'), ord('Y')):
                            self._save_file()
                            self.running = False
                            break
                        elif byte in (ord('n'), ord('N')):
                            self.running = False
                            break
                        elif byte == 3:  # Ctrl+C
                            self.mode = "edit"
                            self.status_message = "[ Cancelled ]"
                            self._render()
                        continue

                    # =========================================================
                    # 3. XỬ LÝ TRẠNG THÁI PROMPT: WRITEOUT (CTRL+O)
                    # =========================================================
                    if self.mode == "prompt_writeout":
                        if char in ('\r', '\n'):
                            if self.prompt_input.strip():
                                self.raw_path = self.prompt_input.strip()
                                self.resolved_path = self.vfs.resolve_path(self.raw_path)
                            self._save_file()
                            self.mode = "edit"
                            self._render()
                        elif byte in (127, 8):
                            self.prompt_input = self.prompt_input[:-1]
                            self._render()
                        elif byte == 3:  # Ctrl+C
                            self.mode = "edit"
                            self.status_message = "[ Cancelled ]"
                            self._render()
                        elif 32 <= byte <= 126:
                            self.prompt_input += char
                            self._render()
                        continue

                    # =========================================================
                    # 4. XỬ LÝ TRẠNG THÁI PROMPT: SEARCH (CTRL+W)
                    # =========================================================
                    if self.mode == "prompt_search":
                        if char in ('\r', '\n'):
                            term = self.prompt_input
                            self.mode = "edit"
                            if term:
                                found = False
                                for r in range(self.cursor_row, len(self.lines)):
                                    start_c = (self.cursor_col + 1) if r == self.cursor_row else 0
                                    idx = self.lines[r].find(term, start_c)
                                    if idx != -1:
                                        self.cursor_row = r
                                        self.cursor_col = idx
                                        found = True
                                        self.status_message = f"[ Found '{term}' ]"
                                        break
                                if not found:
                                    self.status_message = f"[ '{term}' not found ]"
                            self._ensure_cursor_visible()
                            self._render()
                        elif byte in (127, 8):
                            self.prompt_input = self.prompt_input[:-1]
                            self._render()
                        elif byte == 3:  # Ctrl+C
                            self.mode = "edit"
                            self.status_message = "[ Cancelled ]"
                            self._render()
                        elif 32 <= byte <= 126:
                            self.prompt_input += char
                            self._render()
                        continue

                    # =========================================================
                    # 5. CHẾ ĐỘ SOẠN THẢO THƯỜNG (EDITING MODE)
                    # =========================================================

                    # CTRL+X: Thoát nano
                    if byte == 24:
                        if self.modified:
                            self.mode = "prompt_save_exit"
                            self._render()
                        else:
                            self.running = False
                            break

                    # CTRL+O: Lưu tệp
                    elif byte == 15:
                        self.mode = "prompt_writeout"
                        self.prompt_input = self.raw_path
                        self._render()

                    # CTRL+W: Tìm kiếm
                    elif byte == 23:
                        self.mode = "prompt_search"
                        self.prompt_input = ""
                        self._render()

                    # CTRL+K: Cắt dòng
                    elif byte == 11:
                        self.cut_buffer = self.lines.pop(self.cursor_row)
                        if not self.lines:
                            self.lines = [""]
                        if self.cursor_row >= len(self.lines):
                            self.cursor_row = len(self.lines) - 1
                        self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))
                        self.modified = True
                        self.status_message = "[ Cut 1 line ]"
                        self._ensure_cursor_visible()
                        self._render()

                    # CTRL+U: Dán dòng
                    elif byte == 21:
                        if self.cut_buffer is not None:
                            self.lines.insert(self.cursor_row, self.cut_buffer)
                            self.modified = True
                            self.status_message = "[ Pasted 1 line ]"
                            self._ensure_cursor_visible()
                            self._render()

                    # CTRL+C: Xem vị trí con trỏ
                    elif byte == 3:
                        tot_lines = len(self.lines)
                        tot_chars = sum(len(l) for l in self.lines) + max(0, tot_lines - 1)
                        curr_char = sum(len(self.lines[i]) + 1 for i in range(self.cursor_row)) + self.cursor_col + 1
                        line_pct = int((self.cursor_row + 1) / max(1, tot_lines) * 100)
                        col_len = max(1, len(self.lines[self.cursor_row]))
                        col_pct = int((self.cursor_col + 1) / col_len * 100)
                        self.status_message = f"[ line {self.cursor_row + 1}/{tot_lines} ({line_pct}%), col {self.cursor_col + 1}/{col_len} ({col_pct}%), char {curr_char}/{max(1, tot_chars)} ]"
                        self._render()

                    # Enter: Ngắt dòng
                    elif char in ('\r', '\n'):
                        curr = self.lines[self.cursor_row]
                        left = curr[:self.cursor_col]
                        right = curr[self.cursor_col:]
                        self.lines[self.cursor_row] = left
                        self.lines.insert(self.cursor_row + 1, right)
                        self.cursor_row += 1
                        self.cursor_col = 0
                        self.modified = True
                        self._ensure_cursor_visible()
                        self._render()

                    # Backspace
                    elif byte in (127, 8):
                        if self.cursor_col > 0:
                            curr = self.lines[self.cursor_row]
                            self.lines[self.cursor_row] = curr[:self.cursor_col - 1] + curr[self.cursor_col:]
                            self.cursor_col -= 1
                            self.modified = True
                        elif self.cursor_row > 0:
                            prev_len = len(self.lines[self.cursor_row - 1])
                            self.lines[self.cursor_row - 1] += self.lines[self.cursor_row]
                            self.lines.pop(self.cursor_row)
                            self.cursor_row -= 1
                            self.cursor_col = prev_len
                            self.modified = True

                        self._ensure_cursor_visible()
                        self._render()

                    # Ký tự in được thông thường
                    elif 32 <= byte <= 126:
                        curr = self.lines[self.cursor_row]
                        self.lines[self.cursor_row] = curr[:self.cursor_col] + char + curr[self.cursor_col:]
                        self.cursor_col += 1
                        self.modified = True
                        self._ensure_cursor_visible()
                        self._render()

        finally:
            # Thoát Alternate Screen Buffer: khôi phục nguyên vẹn màn hình shell trước đó
            self.channel.send("\x1b[?1049l\x1b[?25h")
