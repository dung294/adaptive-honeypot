import os
import time
from typing import List, Tuple, Optional

class NanoEditor:
    """
    Trình soạn thảo GNU nano giả lập chạy trực tiếp trên paramiko SSH channel.
    Mô phỏng đầy đủ giao diện Text User Interface (TUI), thanh phím tắt,
    thao tác soạn thảo, di chuyển con trỏ, lưu (Ctrl+O), thoát (Ctrl+X),
    cắt dán (Ctrl+K / Ctrl+U), tìm kiếm (Ctrl+W) và vị trí (Ctrl+C).
    Tích hợp kiểm tra quyền hạn với VFS ảo.
    """

    def __init__(self, channel, vfs, file_path: str, user: str = "root", width: int = 80, height: int = 24):
        self.channel = channel
        self.vfs = vfs
        self.raw_path = file_path
        self.resolved_path = vfs.resolve_path(file_path)
        self.user = user
        self.width = max(width, 60)
        self.height = max(height, 16)
        self.body_height = self.height - 4  # Dành cho header (1), status (1), shortcuts (2)

        self.lines: List[str] = [""]
        self.cursor_row = 0
        self.cursor_col = 0
        self.scroll_top = 0
        self.scroll_left = 0
        self.modified = False
        self.cut_buffer: Optional[str] = None
        self.status_message = ""
        self.is_new_file = False
        self.is_writable = True

        self._load_file()

    def _load_file(self):
        """Đọc tệp từ VFS ảo và kiểm tra quyền"""
        node = self.vfs._get_node(self.resolved_path)
        if node:
            if node.get("type") == "dir":
                self.lines = [f"Error: {self.raw_path} is a directory"]
                self.is_writable = False
                return

            # Kiểm tra quyền đọc
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
            
            # Kiểm tra quyền ghi
            self.is_writable = self.vfs.check_permission(node, mode="w", user=self.user)
            if not self.is_writable:
                self.status_message = f"[ File '{self.raw_path}' is unwritable ]"
            else:
                self.status_message = f"[ Read {len(self.lines)} lines ]"
        else:
            # File mới: kiểm tra quyền ghi vào thư mục cha
            parent_path = os.path.dirname(self.resolved_path)
            parent_node = self.vfs._get_node(parent_path)
            if parent_node and not self.vfs.check_permission(parent_node, mode="w", user=self.user):
                self.is_writable = False
                self.status_message = f"[ Directory unwritable ]"
            else:
                self.is_new_file = True
                self.status_message = f"[ New File ]"
            self.lines = [""]

    def _render(self):
        """Vẽ lại toàn bộ màn hình terminal giống GNU nano"""
        out = []
        out.append("\x1b[H")  # Move to 1,1

        # 1. Title bar (Row 1)
        mod_flag = " [Modified]" if self.modified else ""
        title = f"  GNU nano 6.2".ljust(22) + f"File: {self.raw_path}".center(self.width - 44) + mod_flag.rjust(22)
        title = title[:self.width].ljust(self.width)
        out.append(f"\x1b[7m{title}\x1b[0m\r\n")

        # 2. Text Body (Rows 2 to body_height + 1)
        for i in range(self.body_height):
            line_idx = self.scroll_top + i
            if line_idx < len(self.lines):
                line_content = self.lines[line_idx]
                disp_line = line_content[self.scroll_left:self.scroll_left + self.width]
                out.append(disp_line)
            out.append("\x1b[K\r\n")  # Clear line to end and newline

        # 3. Status Bar (Row height - 2)
        status_disp = self.status_message[:self.width]
        out.append(f"\x1b[K{status_disp}\r\n")

        # 4. Shortcut Bar (Rows height - 1 and height)
        sc1 = "\x1b[7m^G\x1b[0m Help     \x1b[7m^O\x1b[0m WriteOut \x1b[7m^W\x1b[0m Where Is \x1b[7m^K\x1b[0m Cut      \x1b[7m^T\x1b[0m Execute"
        sc2 = "\x1b[7m^X\x1b[0m Exit     \x1b[7m^R\x1b[0m Read File\x1b[7m^\\\x1b[0m Replace  \x1b[7m^U\x1b[0m Paste    \x1b[7m^J\x1b[0m Justify"
        out.append(f"\x1b[K{sc1}\r\n")
        out.append(f"\x1b[K{sc2}")

        # 5. Move cursor to actual position on screen
        screen_row = (self.cursor_row - self.scroll_top) + 2
        screen_col = (self.cursor_col - self.scroll_left) + 1
        out.append(f"\x1b[{screen_row};{screen_col}H")

        self.channel.send("".join(out))

    def _ensure_cursor_visible(self):
        """Tự động cuộn trang khi con trỏ di chuyển ra ngoài viewport"""
        if self.cursor_row < self.scroll_top:
            self.scroll_top = self.cursor_row
        elif self.cursor_row >= self.scroll_top + self.body_height:
            self.scroll_top = self.cursor_row - self.body_height + 1

        if self.cursor_col < self.scroll_left:
            self.scroll_left = self.cursor_col
        elif self.cursor_col >= self.scroll_left + self.width:
            self.scroll_left = self.cursor_col - self.width + 1

    def _save_file(self) -> bool:
        """Lưu nội dung vào VFS ảo"""
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
        """Vòng lặp tương tác chính của trình soạn thảo nano"""
        # Bật màn hình nano, xóa toàn màn hình
        self.channel.send("\x1b[2J\x1b[H")
        self._ensure_cursor_visible()
        self._render()

        escape_mode = False
        escape_buf = ""

        try:
            while True:
                data = self.channel.recv(1024)
                if not data:
                    break

                for byte in data:
                    char = chr(byte)

                    # 1. Xử lý ANSI Escape Sequences (Phím mũi tên, Delete, Home, End, PageUp/Down)
                    if escape_mode:
                        escape_buf += char
                        if char in ('A', 'B', 'C', 'D', '~', 'F', 'H'):
                            escape_mode = False
                            
                            # MŨI TÊN LÊN
                            if escape_buf.endswith("[A") or escape_buf.endswith("OA"):
                                if self.cursor_row > 0:
                                    self.cursor_row -= 1
                                    self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))
                            # MŨI TÊN XUỐNG
                            elif escape_buf.endswith("[B") or escape_buf.endswith("OB"):
                                if self.cursor_row < len(self.lines) - 1:
                                    self.cursor_row += 1
                                    self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))
                            # MŨI TÊN TRÁI
                            elif escape_buf.endswith("[D") or escape_buf.endswith("OD"):
                                if self.cursor_col > 0:
                                    self.cursor_col -= 1
                                elif self.cursor_row > 0:
                                    self.cursor_row -= 1
                                    self.cursor_col = len(self.lines[self.cursor_row])
                            # MŨI TÊN PHẢI
                            elif escape_buf.endswith("[C") or escape_buf.endswith("OC"):
                                if self.cursor_col < len(self.lines[self.cursor_row]):
                                    self.cursor_col += 1
                                elif self.cursor_row < len(self.lines) - 1:
                                    self.cursor_row += 1
                                    self.cursor_col = 0
                            # HOME
                            elif escape_buf.endswith("[H") or escape_buf.endswith("OH") or escape_buf.endswith("[1~") or escape_buf.endswith("[7~"):
                                self.cursor_col = 0
                            # END
                            elif escape_buf.endswith("[F") or escape_buf.endswith("OF") or escape_buf.endswith("[4~") or escape_buf.endswith("[8~"):
                                self.cursor_col = len(self.lines[self.cursor_row])
                            # PAGE UP
                            elif escape_buf.endswith("[5~"):
                                self.cursor_row = max(0, self.cursor_row - self.body_height)
                                self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))
                            # PAGE DOWN
                            elif escape_buf.endswith("[6~"):
                                self.cursor_row = min(len(self.lines) - 1, self.cursor_row + self.body_height)
                                self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))
                            # DELETE KEY
                            elif escape_buf.endswith("[3~"):
                                curr = self.lines[self.cursor_row]
                                if self.cursor_col < len(curr):
                                    self.lines[self.cursor_row] = curr[:self.cursor_col] + curr[self.cursor_col + 1:]
                                    self.modified = True
                                elif self.cursor_row < len(self.lines) - 1:
                                    # Ghép dòng kế tiếp
                                    self.lines[self.cursor_row] += self.lines[self.cursor_row + 1]
                                    self.lines.pop(self.cursor_row + 1)
                                    self.modified = True

                            escape_buf = ""
                            self._ensure_cursor_visible()
                            self._render()
                        continue

                    # Bắt đầu escape sequence (ESC = 27)
                    if byte == 27:
                        escape_mode = True
                        escape_buf = ""
                        continue

                    # 2. Ctrl+X (Exit nano)
                    if byte == 24:
                        if self.modified:
                            # Hỏi lưu file
                            self.status_message = "Save modified buffer? (Answering 'No' will DISCARD changes) [Y/N]"
                            self._render()
                            
                            # Nhận phím xác nhận
                            confirm = self.channel.recv(10)
                            if confirm:
                                key = chr(confirm[0]).upper()
                                if key == 'Y':
                                    self._save_file()
                                    break
                                elif key == 'N':
                                    break
                                else:
                                    self.status_message = "[ Cancelled ]"
                                    self._render()
                                    continue
                        else:
                            break

                    # 3. Ctrl+O (WriteOut / Save)
                    elif byte == 15:
                        self._save_file()
                        self._render()

                    # 4. Ctrl+K (Cut line)
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

                    # 5. Ctrl+U (Paste line)
                    elif byte == 21:
                        if self.cut_buffer is not None:
                            self.lines.insert(self.cursor_row, self.cut_buffer)
                            self.modified = True
                            self.status_message = "[ Pasted 1 line ]"
                            self._ensure_cursor_visible()
                            self._render()

                    # 6. Ctrl+C (Show cursor position info)
                    elif byte == 3:
                        tot_lines = len(self.lines)
                        tot_chars = sum(len(l) for l in self.lines) + max(0, tot_lines - 1)
                        curr_char = sum(len(self.lines[i]) + 1 for i in range(self.cursor_row)) + self.cursor_col + 1
                        line_pct = int((self.cursor_row + 1) / max(1, tot_lines) * 100)
                        col_len = max(1, len(self.lines[self.cursor_row]))
                        col_pct = int((self.cursor_col + 1) / col_len * 100)
                        self.status_message = f"[ line {self.cursor_row + 1}/{tot_lines} ({line_pct}%), col {self.cursor_col + 1}/{col_len} ({col_pct}%), char {curr_char}/{max(1, tot_chars)} ]"
                        self._render()

                    # 7. Ctrl+W (Where Is / Search)
                    elif byte == 23:
                        self.status_message = "Search: "
                        self._render()
                        # Nhận chuỗi tìm kiếm
                        search_term = ""
                        while True:
                            s_data = self.channel.recv(100)
                            if not s_data:
                                break
                            if s_data[0] in (10, 13):
                                break
                            elif s_data[0] == 3:  # Ctrl+C cancel
                                search_term = ""
                                break
                            else:
                                search_term += chr(s_data[0])
                        
                        if search_term:
                            found = False
                            # Tìm từ vị trí hiện tại đến cuối
                            for r in range(self.cursor_row, len(self.lines)):
                                start_col = (self.cursor_col + 1) if r == self.cursor_row else 0
                                idx = self.lines[r].find(search_term, start_col)
                                if idx != -1:
                                    self.cursor_row = r
                                    self.cursor_col = idx
                                    found = True
                                    self.status_message = f"[ Found match ]"
                                    break
                            if not found:
                                self.status_message = f"[ '{search_term}' not found ]"
                        else:
                            self.status_message = "[ Cancelled ]"

                        self._ensure_cursor_visible()
                        self._render()

                    # 8. Enter / Return (Tạo dòng mới)
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

                    # 9. Backspace (byte 127 hoặc byte 8)
                    elif byte in (127, 8):
                        if self.cursor_col > 0:
                            curr = self.lines[self.cursor_row]
                            self.lines[self.cursor_row] = curr[:self.cursor_col - 1] + curr[self.cursor_col:]
                            self.cursor_col -= 1
                            self.modified = True
                        elif self.cursor_row > 0:
                            # Nối lên dòng trên
                            prev_len = len(self.lines[self.cursor_row - 1])
                            self.lines[self.cursor_row - 1] += self.lines[self.cursor_row]
                            self.lines.pop(self.cursor_row)
                            self.cursor_row -= 1
                            self.cursor_col = prev_len
                            self.modified = True

                        self._ensure_cursor_visible()
                        self._render()

                    # 10. Printable characters (32 to 126)
                    elif 32 <= byte <= 126:
                        curr = self.lines[self.cursor_row]
                        self.lines[self.cursor_row] = curr[:self.cursor_col] + char + curr[self.cursor_col:]
                        self.cursor_col += 1
                        self.modified = True
                        self._ensure_cursor_visible()
                        self._render()

        finally:
            # Khôi phục màn hình terminal sạch sẽ khi thoát nano
            self.channel.send("\x1b[2J\x1b[H")
