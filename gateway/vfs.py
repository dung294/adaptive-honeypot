import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from config import QUARANTINE_DIR

class VirtualFileSystem:
    """
    Virtual File System (VFS) dạng cây quản lý trạng thái tệp tin độc lập cho từng phiên.
    Xử lý deterministic các lệnh file hệ thống để triệt tiêu độ trễ và hiện tượng ảo giác (hallucination).
    """
    def __init__(self, hostname: str = "ubuntu-srv-01", user: str = "root"):
        self.hostname = hostname
        self.user = user
        self.cwd = f"/home/{user}" if user != "root" else "/root"
        
        # Khởi tạo cây thư mục chuẩn Linux
        self.fs = {
            "/": {
                "type": "dir",
                "owner": "root",
                "perm": "755",
                "children": {
                    "bin": {"type": "dir", "owner": "root", "perm": "755", "children": {}},
                    "etc": {
                        "type": "dir", "owner": "root", "perm": "755",
                        "children": {
                            "hostname": {"type": "file", "owner": "root", "perm": "644", "content": f"{self.hostname}\n"},
                            "issue": {"type": "file", "owner": "root", "perm": "644", "content": "Ubuntu 22.04.4 LTS \\n \\l\n"},
                            "os-release": {
                                "type": "file", "owner": "root", "perm": "644",
                                "content": (
                                    'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
                                    'NAME="Ubuntu"\n'
                                    'VERSION_ID="22.04"\n'
                                    'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
                                    'ID=ubuntu\n'
                                    'ID_LIKE=debian\n'
                                )
                            },
                            "passwd": {
                                "type": "file", "owner": "root", "perm": "644",
                                "content": (
                                    "root:x:0:0:root:/root:/bin/bash\n"
                                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                                    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                                    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                                    "sync:x:4:65534:sync:/bin:/bin/sync\n"
                                    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
                                    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
                                    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                                )
                            }
                        }
                    },
                    "home": {
                        "type": "dir", "owner": "root", "perm": "755",
                        "children": {
                            "ubuntu": {"type": "dir", "owner": "ubuntu", "perm": "755", "children": {}}
                        }
                    },
                    "root": {
                        "type": "dir", "owner": "root", "perm": "700",
                        "children": {
                            "notes.txt": {
                                "type": "file", "owner": "root", "perm": "644",
                                "content": "TODO:\n1. Backup MySQL database to 192.168.101.50\n2. Renew SSL certificates for api.internal\n"
                            },
                            "deploy.sh": {
                                "type": "file", "owner": "root", "perm": "755",
                                "content": "#!/bin/bash\necho 'Deploying production stack...'\nsystemctl restart nginx\n"
                            },
                            ".bash_history": {
                                "type": "file", "owner": "root", "perm": "600",
                                "content": "apt update && apt upgrade -y\nufw allow 22/tcp\nsystemctl restart sshd\ncat /var/log/syslog\n"
                            },
                            ".bashrc": {
                                "type": "file", "owner": "root", "perm": "644",
                                "content": "# ~/.bashrc: executed by bash(1) for non-login shells.\nexport PATH=$PATH:/usr/local/bin\n"
                            }
                        }
                    },
                    "proc": {
                        "type": "dir", "owner": "root", "perm": "555",
                        "children": {
                            "cpuinfo": {
                                "type": "file", "owner": "root", "perm": "444",
                                "content": (
                                    "processor\t: 0\n"
                                    "vendor_id\t: GenuineIntel\n"
                                    "model name\t: Intel(R) Xeon(R) CPU @ 2.20GHz\n"
                                    "cpu MHz\t\t: 2199.998\n"
                                    "cache size\t: 46080 KB\n"
                                    "cpu cores\t: 2\n"
                                )
                            },
                            "meminfo": {
                                "type": "file", "owner": "root", "perm": "444",
                                "content": (
                                    "MemTotal:        4016140 kB\n"
                                    "MemFree:         2145320 kB\n"
                                    "MemAvailable:    3250100 kB\n"
                                    "Buffers:          185200 kB\n"
                                    "Cached:          1024500 kB\n"
                                )
                            },
                            "version": {
                                "type": "file", "owner": "root", "perm": "444",
                                "content": "Linux version 5.15.0-88-generic (buildd@lcy02-amd64-010) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #98-Ubuntu SMP\n"
                            }
                        }
                    },
                    "tmp": {"type": "dir", "owner": "root", "perm": "1777", "children": {}},
                    "var": {
                        "type": "dir", "owner": "root", "perm": "755",
                        "children": {
                            "log": {"type": "dir", "owner": "root", "perm": "755", "children": {}}
                        }
                    },
                    "usr": {
                        "type": "dir", "owner": "root", "perm": "755",
                        "children": {
                            "bin": {"type": "dir", "owner": "root", "perm": "755", "children": {}},
                            "lib": {"type": "dir", "owner": "root", "perm": "755", "children": {}}
                        }
                    }
                }
            }
        }

        # Đảm bảo thư mục home của user đăng nhập luôn tồn tại (vd: /home/dung, /home/ubuntu)
        if self.user != "root":
            home_children = self.fs["/"]["children"]["home"]["children"]
            if self.user not in home_children:
                home_children[self.user] = {
                    "type": "dir",
                    "owner": self.user,
                    "perm": "755",
                    "children": {
                        ".bashrc": {
                            "type": "file", "owner": self.user, "perm": "644",
                            "content": "# ~/.bashrc\nexport PATH=$PATH:/usr/local/bin\n"
                        },
                        ".bash_history": {
                            "type": "file", "owner": self.user, "perm": "600",
                            "content": "ls -la\nwhoami\n"
                        },
                        "notes.txt": {
                            "type": "file", "owner": self.user, "perm": "644",
                            "content": "TODO:\n1. Update database credentials in /var/www/.env\n2. Backup server configuration to 192.168.101.50\n"
                        },
                        "backup.sh": {
                            "type": "file", "owner": self.user, "perm": "755",
                            "content": "#!/bin/bash\necho 'Backing up web server...'\ntar -czf /tmp/backup.tar.gz /var/www/html\n"
                        }
                    }
                }

    def resolve_path(self, path: str) -> str:
        """Chuẩn hóa đường dẫn tương đối / tuyệt đối và hỗ trợ ký tự ~."""
        if not path:
            return self.cwd

        user_home = "/root" if self.user == "root" else f"/home/{self.user}"
        if path == "~":
            path = user_home
        elif path.startswith("~/"):
            path = user_home + path[1:]
        """Chuẩn hóa đường dẫn tương đối / tuyệt đối."""
        if not path:
            return self.cwd
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
        if norm_path == "/":
            return self.fs["/"]
        
        current = self.fs["/"]
        for seg in norm_path.strip("/").split("/"):
            if current["type"] != "dir" or seg not in current.get("children", {}):
                return None
            current = current["children"][seg]
        return current

    def pwd(self) -> str:
        return self.cwd

    def cd(self, path: str) -> Tuple[bool, str]:
        target = self.resolve_path(path) if path else ("/root" if self.user == "root" else f"/home/{self.user}")
        node = self._get_node(target)
        if not node:
            return False, f"bash: cd: {path}: No such file or directory"
        if node["type"] != "dir":
            return False, f"bash: cd: {path}: Not a directory"
        self.cwd = target
        return True, ""

    def ls(self, path: str = "", flags: str = "") -> Tuple[bool, str]:
        target = self.resolve_path(path) if path else self.cwd
        node = self._get_node(target)
        if not node:
            return False, f"ls: cannot access '{path or self.cwd}': No such file or directory"
        
        if node["type"] == "file":
            return True, target.split("/")[-1]

        children = node.get("children", {})
        names = sorted(list(children.keys()))
        
        if "a" not in flags:
            names = [n for n in names if not n.startswith(".")]

        if not names and "l" not in flags:
            return True, ""

        if "a" in flags:
            all_names = [".", ".."] + names
        else:
            all_names = names

        if "l" in flags:
            entries = []
            if "a" in flags:
                dir_owner = node.get("owner", "root")
                entries.append(("d", "rwxr-xr-x", dir_owner, 4096, "."))
                entries.append(("d", "rwxr-xr-x", "root", 4096, ".."))
            for name in names:
                item = children[name]
                is_dir = "d" if item["type"] == "dir" else "-"
                owner = item.get("owner", "root")
                size = len(item.get("content", "")) if item["type"] == "file" else 4096
                entries.append((is_dir, "rwxr-xr-x", owner, size, name))

            total_blocks = len(entries) * 4
            lines = [f"total {total_blocks}"]
            for is_dir, perm, owner, size, name in entries:
                lines.append(f"{is_dir}{perm} 1 {owner} {owner} {size:>5} Oct 30 12:00 {name}")
            return True, "\n".join(lines)

        return True, "  ".join(all_names)

    def cat(self, path: str) -> Tuple[bool, str]:
        target = self.resolve_path(path)
        node = self._get_node(target)
        if not node:
            return False, f"cat: {path}: No such file or directory"
        if node["type"] == "dir":
            return False, f"cat: {path}: Is a directory"
        return True, node.get("content", "")

    def mkdir(self, path: str) -> Tuple[bool, str]:
        target = self.resolve_path(path)
        parent_path = "/" + "/".join(target.strip("/").split("/")[:-1])
        new_name = target.strip("/").split("/")[-1]
        
        parent = self._get_node(parent_path)
        if not parent or parent["type"] != "dir":
            return False, f"mkdir: cannot create directory '{path}': No such file or directory"
        if new_name in parent["children"]:
            return False, f"mkdir: cannot create directory '{path}': File exists"
            
        parent["children"][new_name] = {
            "type": "dir",
            "owner": self.user,
            "perm": "755",
            "children": {}
        }
        return True, ""

    def touch(self, path: str) -> Tuple[bool, str]:
        target = self.resolve_path(path)
        parent_path = "/" + "/".join(target.strip("/").split("/")[:-1])
        new_name = target.strip("/").split("/")[-1]
        
        parent = self._get_node(parent_path)
        if not parent or parent["type"] != "dir":
            return False, f"touch: cannot touch '{path}': No such file or directory"
        
        if new_name not in parent["children"]:
            parent["children"][new_name] = {
                "type": "file",
                "owner": self.user,
                "perm": "644",
                "content": ""
            }
        return True, ""

    def write_file(self, path: str, content: str, append: bool = False) -> Tuple[bool, str]:
        target = self.resolve_path(path)
        parent_path = "/" + "/".join(target.strip("/").split("/")[:-1])
        filename = target.strip("/").split("/")[-1]
        
        parent = self._get_node(parent_path)
        if not parent or parent["type"] != "dir":
            return False, f"bash: {path}: No such file or directory"
            
        if filename not in parent["children"]:
            parent["children"][filename] = {
                "type": "file",
                "owner": self.user,
                "perm": "644",
                "content": content
            }
        else:
            if append:
                parent["children"][filename]["content"] += content
            else:
                parent["children"][filename]["content"] = content

        # Tự động cách ly mẫu (Quarantine) và tính mã băm SHA256 cho Threat Intel
        final_content = parent["children"][filename]["content"]
        if final_content.strip():
            sha256_hash = hashlib.sha256(final_content.encode("utf-8")).hexdigest()
            quarantine_file = QUARANTINE_DIR / f"{sha256_hash[:12]}_{filename}"
            try:
                with open(quarantine_file, "w", encoding="utf-8") as qf:
                    qf.write(final_content)
            except Exception:
                pass

        return True, ""

    def rm(self, path: str, recursive: bool = False) -> Tuple[bool, str]:
        target = self.resolve_path(path)
        if target == "/":
            return False, "rm: it is dangerous to operate recursively on '/'"
        parent_path = "/" + "/".join(target.strip("/").split("/")[:-1])
        name = target.strip("/").split("/")[-1]
        
        parent = self._get_node(parent_path)
        if not parent or name not in parent.get("children", {}):
            return False, f"rm: cannot remove '{path}': No such file or directory"
            
        node = parent["children"][name]
        if node["type"] == "dir" and not recursive:
            return False, f"rm: cannot remove '{path}': Is a directory"
            
        del parent["children"][name]
        return True, ""
