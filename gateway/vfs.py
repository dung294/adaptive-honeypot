import time
import hashlib
import fnmatch
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from config import QUARANTINE_DIR, HOSTNAME
from gateway.state.system_state import LinuxSystemState

class VirtualFileSystem:
    """
    Virtual File System (VFS) nâng cấp toàn diện:
    - Sử dụng chung LinuxSystemState chia sẻ giữa các session và lưu trữ bền vững (Persistence).
    - Hỗ trợ đầy đủ Unix permissions (read, write, execute) theo owner, group, other.
    - Cung cấp các thao tác hệ thống tệp chuẩn POSIX: ls -la, stat, file, du, df, tree, cp, mv, rm, find.
    """
    def __init__(self, hostname: str = HOSTNAME, user: str = "root"):
        self.state = LinuxSystemState(hostname=hostname)
        self.hostname = hostname
        self.user = user
        self.cwd = self.get_user_home(user)

    def get_user_home(self, user: str) -> str:
        u_info = self.state.users.get(user)
        if u_info:
            return u_info.get("home", "/root" if user == "root" else f"/home/{user}")
        return "/root" if user == "root" else f"/home/{user}"

    def resolve_path(self, path: str) -> str:
        """Chuẩn hóa đường dẫn tương đối / tuyệt đối và hỗ trợ ký tự ~."""
        if not path:
            return self.cwd

        user_home = self.get_user_home(self.user)
        if path == "~":
            path = user_home
        elif path.startswith("~/"):
            path = user_home + path[1:]

        if path.startswith("/"):
            combined = path
        else:
            combined = f"{self.cwd}/{path}"
            
        parts = []
        for segment in combined.split("/"):
            if segment == "" or segment == ".":
                continue
            elif segment == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(segment)
        return "/" + "/".join(parts)

    def _get_node(self, path: str) -> Optional[Dict[str, Any]]:
        norm_path = self.resolve_path(path)
        return self.state.get_node(norm_path)

    def check_permission(self, path: str, mode: str = "r", user: str = None) -> bool:
        """
        Kiểm tra quyền truy cập tệp theo tiêu chuẩn Unix:
        root luôn có quyền đầy đủ (bypass).
        Các user khác kiểm tra theo bit octal 3 chữ số (Owner, Group, Other).
        mode: 'r' (read), 'w' (write), 'x' (execute).
        """
        curr_user = user or self.user
        if curr_user == "root":
            return True

        if isinstance(path, dict):
            node = path
        else:
            norm_path = self.resolve_path(path)
            node = self.state.get_node(norm_path)
            
        if not node:
            return False

        owner = node.get("owner", "root")
        group = node.get("group", "root")
        perm_str = node.get("perm", "644")

        # Đảm bảo perm_str là chuỗi octal 3 ký tự (ví dụ '755', '644')
        if len(perm_str) == 3:
            try:
                owner_val = int(perm_str[0])
                group_val = int(perm_str[1])
                other_val = int(perm_str[2])
            except ValueError:
                owner_val, group_val, other_val = 7, 5, 5
        else:
            owner_val, group_val, other_val = 7, 5, 5

        # Xác định user thuộc nhóm nào
        u_groups = [curr_user]
        for g_name, g_info in self.state.groups.items():
            if curr_user in g_info.get("members", []):
                u_groups.append(g_name)

        target_val = other_val
        if curr_user == owner:
            target_val = owner_val
        elif group in u_groups:
            target_val = group_val

        # Kiểm tra bit
        if mode == "r":
            return bool(target_val & 4)
        elif mode == "w":
            return bool(target_val & 2)
        elif mode == "x":
            return bool(target_val & 1)
        return False

    def pwd(self) -> str:
        return self.cwd

    def cd(self, path: str, user: str = None) -> Tuple[bool, str]:
        target = self.resolve_path(path) if path else self.get_user_home(user or self.user)
        node = self.state.get_node(target)
        if not node:
            return False, f"bash: cd: {path}: No such file or directory"
        if node.get("type") != "dir":
            return False, f"bash: cd: {path}: Not a directory"
        
        # Kiểm tra quyền execute vào thư mục
        if not self.check_permission(target, mode="x", user=user):
            return False, f"bash: cd: {path}: Permission denied"

        self.cwd = target
        return True, ""

    def ls(self, path: str = "", flags: str = "", user: str = None) -> Tuple[bool, str]:
        target = self.resolve_path(path) if path else self.cwd
        node = self.state.get_node(target)
        if not node:
            return False, f"ls: cannot access '{path or self.cwd}': No such file or directory"

        if node.get("type") == "file":
            return True, target.split("/")[-1]

        # Kiểm tra quyền đọc thư mục
        if not self.check_permission(target, mode="r", user=user):
            return False, f"ls: cannot open directory '{path or self.cwd}': Permission denied"

        children = node.get("children", {})
        names = sorted(list(children.keys()))

        if "a" not in flags:
            names = [n for n in names if not n.startswith(".")]

        if not names and "l" not in flags:
            return True, ""

        if "l" in flags:
            entries = []
            if "a" in flags:
                entries.append(("d", "rwxr-xr-x", node.get("owner", "root"), node.get("group", "root"), 4096, node.get("mtime", "Oct 30 12:00"), "."))
                parent_path = "/" + "/".join(target.strip("/").split("/")[:-1])
                parent_node = self.state.get_node(parent_path) or node
                entries.append(("d", "rwxr-xr-x", parent_node.get("owner", "root"), parent_node.get("group", "root"), 4096, parent_node.get("mtime", "Oct 30 12:00"), ".."))

            for name in names:
                item = children[name]
                is_dir = "d" if item.get("type") == "dir" else "-"
                perm = item.get("perm", "644")
                
                # Chuyển octal perm sang chuỗi rwxr-xr-x
                p_str = self._octal_to_rwx(perm)
                owner = item.get("owner", "root")
                group = item.get("group", owner)
                size = len(item.get("content", "")) if item.get("type") == "file" else 4096
                mtime = item.get("mtime", "Oct 30 12:00")
                entries.append((is_dir, p_str, owner, group, size, mtime, name))

            total_blocks = len(entries) * 4
            lines = [f"total {total_blocks}"]
            for is_dir, p_str, owner, group, size, mtime, name in entries:
                lines.append(f"{is_dir}{p_str} 1 {owner} {group} {size:>5} {mtime} {name}")
            return True, "\n".join(lines)

        return True, "  ".join(names)

    def _octal_to_rwx(self, octal_str: str) -> str:
        if len(octal_str) != 3:
            return "rwxr-xr-x"
        mapping = {
            '0': '---', '1': '--x', '2': '-w-', '3': '-wx',
            '4': 'r--', '5': 'r-x', '6': 'rw-', '7': 'rwx'
        }
        return "".join(mapping.get(c, 'r-x') for c in octal_str)

    def cat(self, path: str, user: str = None) -> Tuple[bool, str]:
        target = self.resolve_path(path)
        node = self.state.get_node(target)
        if not node:
            return False, f"cat: {path}: No such file or directory"
        if node.get("type") == "dir":
            return False, f"cat: {path}: Is a directory"
        
        # Kiểm tra quyền đọc
        if not self.check_permission(target, mode="r", user=user):
            return False, f"cat: {path}: Permission denied"

        return True, node.get("content", "")

    def stat(self, path: str) -> Tuple[bool, str]:
        target = self.resolve_path(path)
        node = self.state.get_node(target)
        if not node:
            return False, f"stat: cannot stat '{path}': No such file or directory"
        
        is_dir = node.get("type") == "dir"
        f_type = "directory" if is_dir else "regular file"
        size = 4096 if is_dir else len(node.get("content", ""))
        perm = node.get("perm", "644")
        rwx = self._octal_to_rwx(perm)
        owner = node.get("owner", "root")
        group = node.get("group", "root")
        mtime = node.get("mtime", "2023-10-30 12:00:00.000000000 +0000")
        
        u_info = self.state.users.get(owner, {"uid": 0})
        g_info = self.state.groups.get(group, {"gid": 0})
        
        out = (
            f"  File: {path}\n"
            f"  Size: {size:<15} Blocks: {size//512 + 1:<10} IO Block: 4096   {f_type}\n"
            f"Device: 801h/2049d\tInode: 1234567     Links: 1\n"
            f"Access: (0{perm}/{('-' if not is_dir else 'd') + rwx})  Uid: ( {u_info['uid']:>4}/{owner:>8})   Gid: ( {g_info['gid']:>4}/{group:>8})\n"
            f"Access: {mtime}\n"
            f"Modify: {mtime}\n"
            f"Change: {mtime}\n"
            f" Birth: -"
        )
        return True, out

    def stat_cmd(self, path: str) -> Tuple[bool, str]:
        return self.stat(path)

    def du(self, path: str = ".", human: bool = False, user: str = None) -> Tuple[bool, str]:
        target = self.resolve_path(path)
        node = self.state.get_node(target)
        if not node:
            return False, f"du: cannot access '{path}': No such file or directory"
        
        lines = []
        def _calc(curr_p: str, n: Dict[str, Any]) -> int:
            if n.get("type") != "dir":
                s = n.get("size", len(n.get("content", "")))
                return max(4, (s + 1023) // 1024)
            tot = 4
            for c_name, c_node in sorted(n.get("children", {}).items()):
                sub_p = "/" + c_name if curr_p == "/" else f"{curr_p}/{c_name}"
                tot += _calc(sub_p, c_node)
            disp_size = f"{tot}K" if human else str(tot)
            lines.append(f"{disp_size}\t{curr_p}")
            return tot

        _calc(target, node)
        return True, "\n".join(lines)

    def file_cmd(self, path: str) -> Tuple[bool, str]:
        target = self.resolve_path(path)
        node = self.state.get_node(target)
        if not node:
            return False, f"{path}: cannot open `{path}' (No such file or directory)"
        if node.get("type") == "dir":
            return True, f"{path}: directory"
        content = node.get("content", "")
        if content.startswith("#!/bin/bash") or content.startswith("#!/bin/sh"):
            return True, f"{path}: POSIX shell script, ASCII text executable"
        elif content.startswith("#!/usr/bin/env python") or content.startswith("#!/usr/bin/python"):
            return True, f"{path}: Python script, ASCII text executable"
        elif "[GZIP" in content or "PK" in content:
            return True, f"{path}: gzip compressed data, from Unix"
        elif "\0" in content:
            return True, f"{path}: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV)"
        return True, f"{path}: ASCII text"

    def chmod(self, arg1: str, arg2: str, user: str = None) -> Tuple[bool, str]:
        curr_user = user or self.user
        if arg1.isdigit() or "+" in arg1 or "-" in arg1:
            mode, path = arg1, arg2
        else:
            path, mode = arg1, arg2

        target = self.resolve_path(path)
        node = self.state.get_node(target)
        if not node:
            return False, f"chmod: cannot access '{path}': No such file or directory"
        
        # Chỉ root hoặc owner mới có quyền chmod
        if curr_user != "root" and curr_user != node.get("owner"):
            return False, f"chmod: changing permissions of '{path}': Operation not permitted"

        if mode.isdigit() and len(mode) in (3, 4):
            node["perm"] = mode[-3:]
        elif "+x" in mode:
            node["perm"] = "755"
        elif "-x" in mode:
            node["perm"] = "644"
        elif "+w" in mode:
            node["perm"] = "777" if node.get("type") == "dir" else "666"

        self.state.save_state()
        return True, ""

    def chown(self, arg1: str, arg2: str, user: str = None) -> Tuple[bool, str]:
        curr_user = user or self.user
        if curr_user != "root":
            return False, f"chown: changing ownership: Operation not permitted"

        if ":" in arg1 or "." in arg1 or arg1 in self.state.users:
            ownership, path = arg1, arg2
        else:
            path, ownership = arg1, arg2

        target = self.resolve_path(path)
        node = self.state.get_node(target)
        if not node:
            return False, f"chown: cannot access '{path}': No such file or directory"

        if ":" in ownership:
            new_u, new_g = ownership.split(":", 1)
        elif "." in ownership:
            new_u, new_g = ownership.split(".", 1)
        else:
            new_u, new_g = ownership, ""

        if new_u:
            node["owner"] = new_u
        if new_g:
            node["group"] = new_g

        self.state.save_state()
        return True, ""

    def mkdir(self, path: str, recursive: bool = False, user: str = None) -> Tuple[bool, str]:
        curr_user = user or self.user
        target = self.resolve_path(path)
        
        if recursive:
            parts = [p for p in target.strip("/").split("/") if p]
            curr_p = ""
            for p in parts:
                parent_p = curr_p if curr_p else "/"
                curr_p += "/" + p
                parent_node = self.state.get_node(parent_p)
                if not parent_node or parent_node.get("type") != "dir":
                    return False, f"mkdir: cannot create directory '{path}': No such file or directory"
                if not self.check_permission(parent_p, mode="w", user=curr_user):
                    return False, f"mkdir: cannot create directory '{path}': Permission denied"
                if p not in parent_node.setdefault("children", {}):
                    parent_node["children"][p] = {
                        "type": "dir",
                        "owner": curr_user,
                        "group": curr_user,
                        "perm": "755",
                        "mtime": time.strftime("%b %d %H:%M"),
                        "children": {}
                    }
            self.state.save_state()
            return True, ""

        parent_path = "/" + "/".join(target.strip("/").split("/")[:-1])
        new_name = target.strip("/").split("/")[-1]
        
        parent = self.state.get_node(parent_path)
        if not parent or parent.get("type") != "dir":
            return False, f"mkdir: cannot create directory '{path}': No such file or directory"
        
        if not self.check_permission(parent_path, mode="w", user=curr_user):
            return False, f"mkdir: cannot create directory '{path}': Permission denied"

        if new_name in parent.get("children", {}):
            return False, f"mkdir: cannot create directory '{path}': File exists"
            
        parent.setdefault("children", {})[new_name] = {
            "type": "dir",
            "owner": curr_user,
            "group": curr_user,
            "perm": "755",
            "mtime": time.strftime("%b %d %H:%M"),
            "children": {}
        }
        self.state.save_state()
        return True, ""

    def touch(self, path: str, user: str = None) -> Tuple[bool, str]:
        curr_user = user or self.user
        target = self.resolve_path(path)
        parent_path = "/" + "/".join(target.strip("/").split("/")[:-1])
        new_name = target.strip("/").split("/")[-1]
        
        parent = self.state.get_node(parent_path)
        if not parent or parent.get("type") != "dir":
            return False, f"touch: cannot touch '{path}': No such file or directory"

        if not self.check_permission(parent_path, mode="w", user=curr_user):
            return False, f"touch: cannot touch '{path}': Permission denied"

        children = parent.setdefault("children", {})
        now_str = time.strftime("%b %d %H:%M")
        if new_name not in children:
            children[new_name] = {
                "type": "file",
                "owner": curr_user,
                "group": curr_user,
                "perm": "644",
                "mtime": now_str,
                "content": ""
            }
        else:
            children[new_name]["mtime"] = now_str

        self.state.save_state()
        return True, ""

    def write_file(self, path: str, content: str, append: bool = False, user: str = None) -> Tuple[bool, str]:
        curr_user = user or self.user
        target = self.resolve_path(path)
        parent_path = "/" + "/".join(target.strip("/").split("/")[:-1])
        filename = target.strip("/").split("/")[-1]
        
        parent = self.state.get_node(parent_path)
        if not parent or parent.get("type") != "dir":
            return False, f"bash: {path}: No such file or directory"

        children = parent.setdefault("children", {})
        now_str = time.strftime("%b %d %H:%M")

        if filename in children:
            if not self.check_permission(target, mode="w", user=curr_user):
                return False, f"bash: {path}: Permission denied"
            if append:
                children[filename]["content"] = children[filename].get("content", "") + content
            else:
                children[filename]["content"] = content
            children[filename]["mtime"] = now_str
        else:
            if not self.check_permission(parent_path, mode="w", user=curr_user):
                return False, f"bash: {path}: Permission denied"
            children[filename] = {
                "type": "file",
                "owner": curr_user,
                "group": curr_user,
                "perm": "644",
                "mtime": now_str,
                "content": content
            }

        # Lưu xuống đĩa và sao lưu quarantine nếu là payload
        self.state.save_state()
        final_content = children[filename]["content"]
        if final_content.strip() and len(final_content) < 500000:
            sha256_hash = hashlib.sha256(final_content.encode("utf-8")).hexdigest()
            quarantine_file = QUARANTINE_DIR / f"{sha256_hash[:12]}_{filename}"
            try:
                with open(quarantine_file, "w", encoding="utf-8") as qf:
                    qf.write(final_content)
            except Exception:
                pass

        return True, ""

    def rm(self, path: str, recursive: bool = False, user: str = None) -> Tuple[bool, str]:
        curr_user = user or self.user
        target = self.resolve_path(path)
        if target == "/":
            return False, "rm: it is dangerous to operate recursively on '/'"
            
        parent_path = "/" + "/".join(target.strip("/").split("/")[:-1])
        name = target.strip("/").split("/")[-1]
        
        parent = self.state.get_node(parent_path)
        if not parent or name not in parent.get("children", {}):
            return False, f"rm: cannot remove '{path}': No such file or directory"

        if not self.check_permission(parent_path, mode="w", user=curr_user):
            return False, f"rm: cannot remove '{path}': Permission denied"

        node = parent["children"][name]
        if node.get("type") == "dir" and not recursive:
            return False, f"rm: cannot remove '{path}': Is a directory"
            
        del parent["children"][name]
        self.state.save_state()
        return True, ""

    def cp(self, src: str, dst: str, recursive: bool = False, user: str = None) -> Tuple[bool, str]:
        curr_user = user or self.user
        src_path = self.resolve_path(src)
        dst_path = self.resolve_path(dst)
        
        src_node = self.state.get_node(src_path)
        if not src_node:
            return False, f"cp: cannot stat '{src}': No such file or directory"

        if not self.check_permission(src_path, mode="r", user=curr_user):
            return False, f"cp: cannot open '{src}' for reading: Permission denied"

        if src_node.get("type") == "dir" and not recursive:
            return False, f"cp: -r not specified; omitting directory '{src}'"

        import copy
        cloned_node = copy.deepcopy(src_node)
        cloned_node["owner"] = curr_user
        cloned_node["mtime"] = time.strftime("%b %d %H:%M")

        dst_node = self.state.get_node(dst_path)
        if dst_node and dst_node.get("type") == "dir":
            # Đích là thư mục -> copy vào trong
            dst_parent = dst_node
            dst_name = src_path.strip("/").split("/")[-1]
        else:
            dst_parent_path = "/" + "/".join(dst_path.strip("/").split("/")[:-1])
            dst_name = dst_path.strip("/").split("/")[-1]
            dst_parent = self.state.get_node(dst_parent_path)

        if not dst_parent or dst_parent.get("type") != "dir":
            return False, f"cp: cannot create regular file '{dst}': No such file or directory"

        dst_parent.setdefault("children", {})[dst_name] = cloned_node
        self.state.save_state()
        return True, ""

    def mv(self, src: str, dst: str, user: str = None) -> Tuple[bool, str]:
        ok, err = self.cp(src, dst, recursive=True, user=user)
        if not ok:
            return False, err.replace("cp:", "mv:")
        self.rm(src, recursive=True, user=user)
        return True, ""

    def find(self, start_path: str = ".", name_pattern: str = "", perm_filter: str = "") -> List[str]:
        """Duyệt tìm tệp đệ quy phục vụ lệnh find."""
        norm_start = self.resolve_path(start_path)
        results = []

        def _walk(curr_p: str, node: Dict[str, Any]):
            name = curr_p.strip("/").split("/")[-1] if curr_p != "/" else "/"
            match = True
            if name_pattern:
                match = fnmatch.fnmatch(name, name_pattern)
            if perm_filter and match:
                perm = node.get("perm", "644")
                if "-u=s" in perm_filter or "-4000" in perm_filter:
                    match = perm.startswith("4") or perm.startswith("7") or name in ("passwd", "sudo", "pkexec", "su")
            if match:
                results.append(curr_p)

            if node.get("type") == "dir":
                for child_name, child_node in sorted(node.get("children", {}).items()):
                    sub_p = "/" + child_name if curr_p == "/" else f"{curr_p}/{child_name}"
                    _walk(sub_p, child_node)

        root_node = self.state.get_node(norm_start)
        if root_node:
            _walk(norm_start, root_node)
        return results

    def tree(self, path: str = "") -> str:
        target = self.resolve_path(path) if path else self.cwd
        node = self.state.get_node(target)
        if not node:
            return f"tree: '{path}': No such file or directory\n"
        if node.get("type") != "dir":
            return f"{target} [error opening dir]\n\n0 directories, 1 file\n"

        lines = [target]
        dirs_cnt = [0]
        files_cnt = [0]

        def _build_tree(n: Dict[str, Any], prefix: str = ""):
            children = sorted(list(n.get("children", {}).keys()))
            for i, c_name in enumerate(children):
                is_last = (i == len(children) - 1)
                connector = "└── " if is_last else "├── "
                sub_prefix = "    " if is_last else "│   "
                child = n["children"][c_name]
                lines.append(f"{prefix}{connector}{c_name}")
                if child.get("type") == "dir":
                    dirs_cnt[0] += 1
                    _build_tree(child, prefix + sub_prefix)
                else:
                    files_cnt[0] += 1

        _build_tree(node)
        lines.append(f"\n{dirs_cnt[0]} directories, {files_cnt[0]} files\n")
        return "\n".join(lines)
