import time
import re
from typing import Tuple, Dict, Set
from gateway.vfs import VirtualFileSystem
from ai_engine.guardrails import Guardrails
from ai_engine.llm_client import LLMClient
from config import HOSTNAME

class CommandRouter:
    """
    Bộ điều phối lệnh kết hợp (Hybrid Dispatcher).
    - Bộ lọc từ vựng Linux (Command Whitelist): Nhận diện ngay lệnh không tồn tại trong < 0.05ms (không gọi LLM).
    - 85% lệnh recon/file hệ thống cơ bản: VFS & Fast-Path xử lý tức thì (< 0.1ms).
    - Bộ nhớ đệm RAM Cache: Phản hồi lặp lại cho các lệnh phức tạp trong < 0.1ms.
    - 15% lệnh lạ/phức tạp hợp lệ: Định tuyến sang LLM Client.
    """
    
    # Tập hợp các lệnh chuẩn hợp lệ của Linux Ubuntu 22.04 LTS
    KNOWN_LINUX_COMMANDS: Set[str] = {
        # Shell builtins
        "cd", "echo", "pwd", "history", "clear", "exit", "logout", "help", "export",
        "alias", "unalias", "set", "unset", "source", ".", "type", "builtin", "exec",
        "jobs", "bg", "fg", "disown", "wait", "suspend", "kill", "trap", "test", "[",
        
        # Core utilities
        "ls", "cat", "mkdir", "touch", "rm", "cp", "mv", "ln", "chmod", "chown", "chgrp",
        "head", "tail", "more", "less", "grep", "egrep", "fgrep", "sed", "awk", "find",
        "sort", "uniq", "wc", "tr", "cut", "paste", "tee", "xargs", "diff", "patch",
        "file", "stat", "basename", "dirname", "realpath", "readlink", "du", "df",
        "md5sum", "sha256sum", "sha1sum", "base64", "strings",
        
        # System & Hardware & Process
        "uname", "hostname", "whoami", "id", "groups", "uptime", "w", "who", "last",
        "lastlog", "ps", "top", "htop", "pstree", "free", "vmstat", "iostat", "lsof",
        "killall", "pkill", "pgrep", "dmesg", "service", "systemctl", "journalctl",
        "date", "cal", "sleep", "nohup", "time", "watch", "timeout", "env", "printenv",
        "which", "whereis", "arch", "lscpu", "lsblk", "lspci", "lsusb", "fdisk", "mount", "umount",
        
        # Network & Recon & CTI
        "ifconfig", "ip", "netstat", "ss", "route", "arp", "traceroute", "tracepath",
        "ping", "ping6", "host", "dig", "nslookup", "curl", "wget", "nc", "ncat",
        "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync", "tcpdump", "tshark",
        "iptables", "ip6tables", "ufw", "nmap", "ftp",
        
        # Archive & Compression
        "tar", "gzip", "gunzip", "bzip2", "bunzip2", "zip", "unzip", "xz", "unxz",
        
        # Package managers & Users & Languages
        "apt", "apt-get", "dpkg", "apt-cache", "snap", "sudo", "su", "passwd",
        "useradd", "userdel", "usermod", "groupadd", "groupdel", "crontab", "cron", "at",
        "bash", "sh", "zsh", "dash", "python", "python3", "perl", "php", "ruby", "node",
        "npm", "gcc", "g++", "make", "git", "docker", "docker-compose", "podman", "kubectl",
        "openssl", "gpg"
    }

    def __init__(self, vfs: VirtualFileSystem, llm_client: LLMClient):
        self.vfs = vfs
        self.llm_client = llm_client
        self.cache: Dict[str, str] = {}

    def execute(self, raw_cmd: str, user: str = "root") -> Tuple[str, str, float]:
        start_time = time.perf_counter()
        clean_cmd = raw_cmd.strip()
        
        if not clean_cmd:
            return "", "VFS", 0.05

        # 1. Kiểm tra Guardrails (Anti-Jailbreak)
        is_jailbreak, jailbreak_response = Guardrails.inspect(clean_cmd)
        if is_jailbreak:
            latency = (time.perf_counter() - start_time) * 1000
            return jailbreak_response, "GUARDRAIL_BLOCKED", latency

        # 2. Xử lý sudo: Nếu gõ 'sudo <lệnh>' -> bóc tách lệnh chính
        effective_user = user
        working_cmd = clean_cmd
        tokens = working_cmd.split()
        if tokens[0] == "sudo":
            effective_user = "root"
            if len(tokens) > 1:
                working_cmd = working_cmd[4:].strip()
                tokens = working_cmd.split()
            else:
                return "usage: sudo -h | -K | -k | -V\n", "VFS", (time.perf_counter() - start_time) * 1000

        base_cmd = tokens[0]

        # 3. Xử lý chuỗi lệnh echo redirect (ví dụ: echo 'text' > file.txt)
        if working_cmd.startswith("echo ") and (">" in working_cmd or ">>" in working_cmd):
            append = ">>" in working_cmd
            parts = working_cmd.split(">>" if append else ">")
            content = parts[0].replace("echo", "", 1).strip().strip("'\"") + "\n"
            target_path = parts[1].strip()
            ok, err = self.vfs.write_file(target_path, content, append=append)
            latency = (time.perf_counter() - start_time) * 1000
            return (err + "\n" if err else ""), "VFS", latency

        # 4. FAST-PATH & VFS: Xử lý tức thì (< 0.1ms) không qua mạng
        if base_cmd == "pwd":
            latency = (time.perf_counter() - start_time) * 1000
            return self.vfs.pwd() + "\n", "VFS", latency

        elif base_cmd == "whoami":
            latency = (time.perf_counter() - start_time) * 1000
            return f"{effective_user}\n", "VFS", latency

        elif base_cmd == "id":
            latency = (time.perf_counter() - start_time) * 1000
            out = "uid=0(root) gid=0(root) groups=0(root)\n" if effective_user == "root" else f"uid=1000({effective_user}) gid=1000({effective_user}) groups=1000({effective_user})\n"
            return out, "VFS", latency

        elif base_cmd == "hostname":
            latency = (time.perf_counter() - start_time) * 1000
            return f"{HOSTNAME}\n", "VFS", latency

        elif base_cmd == "uname":
            latency = (time.perf_counter() - start_time) * 1000
            if "-a" in working_cmd or "--all" in working_cmd:
                return f"Linux {HOSTNAME} 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n", "VFS", latency
            elif "-r" in working_cmd:
                return "5.15.0-88-generic\n", "VFS", latency
            elif "-m" in working_cmd or "-p" in working_cmd or "-i" in working_cmd:
                return "x86_64\n", "VFS", latency
            return "Linux\n", "VFS", latency

        elif base_cmd in ("uptime", "w", "who"):
            latency = (time.perf_counter() - start_time) * 1000
            if base_cmd == "uptime":
                return " 12:45:10 up 14 days,  3:22,  1 user,  load average: 0.08, 0.03, 0.01\n", "VFS", latency
            return f"{effective_user}   pts/0        Oct 30 19:30 (192.168.1.1)\n", "VFS", latency

        elif base_cmd == "df":
            latency = (time.perf_counter() - start_time) * 1000
            out = (
                "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
                "/dev/sda1       40439600  7441920  30918080  20% /\n"
                "tmpfs            2008068        0   2008068   0% /dev/shm\n"
                "tmpfs             803232     1044    802188   1% /run\n"
            ) if "-h" not in working_cmd else (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        39G  7.1G   30G  20% /\n"
                "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
                "tmpfs           785M  1.1M  784M   1% /run\n"
            )
            return out, "VFS", latency

        elif base_cmd == "history":
            latency = (time.perf_counter() - start_time) * 1000
            home_history = "/root/.bash_history" if effective_user == "root" else f"/home/{effective_user}/.bash_history"
            ok, content = self.vfs.cat(home_history)
            lines = content.strip().split("\n") if ok and content else ["ls", "uptime"]
            formatted = "\n".join([f"  {i+1}  {line}" for i, line in enumerate(lines)]) + "\n"
            return formatted, "VFS", latency

        elif base_cmd == "clear":
            latency = (time.perf_counter() - start_time) * 1000
            return "\033[2J\033[H", "VFS", latency

        elif base_cmd == "free":
            latency = (time.perf_counter() - start_time) * 1000
            out = (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:            3922         894        2015           1        1012        2750\n"
                "Swap:           2047           0        2047\n"
            )
            return out, "VFS", latency

        elif base_cmd in ("env", "printenv"):
            latency = (time.perf_counter() - start_time) * 1000
            out = (
                f"SHELL=/bin/bash\n"
                f"PWD={self.vfs.pwd()}\n"
                f"LOGNAME={effective_user}\n"
                f"HOME=/root\n" if effective_user == "root" else f"HOME=/home/{effective_user}\n"
                f"USER={effective_user}\n"
                f"HOSTNAME={HOSTNAME}\n"
                f"TERM=xterm-256color\n"
                f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            )
            return out, "VFS", latency

        elif base_cmd == "cd":
            target = tokens[1] if len(tokens) > 1 else ""
            ok, err = self.vfs.cd(target)
            latency = (time.perf_counter() - start_time) * 1000
            return (err + "\n" if err else ""), "VFS", latency

        elif base_cmd == "ls":
            flags = ""
            path = ""
            for t in tokens[1:]:
                if t.startswith("-"):
                    flags += t.lstrip("-")
                else:
                    path = t
            ok, res = self.vfs.ls(path, flags)
            latency = (time.perf_counter() - start_time) * 1000
            return (res + "\n" if res else ""), "VFS", latency

        elif base_cmd == "cat":
            if len(tokens) > 1:
                ok, res = self.vfs.cat(tokens[1])
                latency = (time.perf_counter() - start_time) * 1000
                return (res if ok else res + "\n"), "VFS", latency
            return "", "VFS", 0.1

        elif base_cmd == "mkdir":
            if len(tokens) > 1:
                ok, err = self.vfs.mkdir(tokens[1])
                latency = (time.perf_counter() - start_time) * 1000
                return (err + "\n" if err else ""), "VFS", latency
            return "mkdir: missing operand\n", "VFS", 0.1

        elif base_cmd == "touch":
            if len(tokens) > 1:
                ok, err = self.vfs.touch(tokens[1])
                latency = (time.perf_counter() - start_time) * 1000
                return (err + "\n" if err else ""), "VFS", latency
            return "touch: missing file operand\n", "VFS", 0.1

        elif base_cmd == "rm":
            rec = "-r" in tokens or "-rf" in tokens
            target = [t for t in tokens[1:] if not t.startswith("-")]
            if target:
                ok, err = self.vfs.rm(target[0], recursive=rec)
                latency = (time.perf_counter() - start_time) * 1000
                return (err + "\n" if err else ""), "VFS", latency
            return "rm: missing operand\n", "VFS", 0.1

        elif base_cmd in ["exit", "logout"]:
            latency = (time.perf_counter() - start_time) * 1000
            return "__EXIT__", "VFS", latency

        elif base_cmd == "help":
            latency = (time.perf_counter() - start_time) * 1000
            out = (
                "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\n"
                "These shell commands are defined internally. Type `help' to see this list.\n"
                "Type `help name' to find out more about the function `name'.\n\n"
                "  cd [-L|[-P [-e]] [-@]] [dir]      exit [n]\n"
                "  history [-c] [-d offset] [n]      help [-dms] [pattern ...]\n"
                "  pwd [-LP]                         export [-fn] [name[=value] ...]\n"
            )
            return out, "VFS", latency

        # 5. Xử lý đường dẫn thực thi file (vd: ./exploit.sh, /tmp/payload)
        if base_cmd.startswith("./") or base_cmd.startswith("/"):
            node = self.vfs._get_node(base_cmd)
            if not node:
                latency = (time.perf_counter() - start_time) * 1000
                return f"bash: {base_cmd}: No such file or directory\n", "VFS", latency

        # 6. KIỂM TRA LỆNH KHÔNG TỒN TẠI (TỨC THÌ < 0.05ms)
        # Nếu lệnh KHÔNG thuộc danh mục Linux chuẩn -> báo lỗi ngay, KHÔNG gọi LLM!
        clean_base = base_cmd.split("/")[-1]
        if clean_base not in self.KNOWN_LINUX_COMMANDS and not base_cmd.startswith("./"):
            latency = (time.perf_counter() - start_time) * 1000
            return f"bash: {base_cmd}: command not found\n", "VFS_SYNTAX", latency

        # 7. Kiểm tra Cache RAM cho lệnh LLM hợp lệ
        cache_key = f"{effective_user}:{self.vfs.pwd()}:{working_cmd}"
        if cache_key in self.cache:
            latency = (time.perf_counter() - start_time) * 1000
            return self.cache[cache_key], "CACHE", latency

        # 8. Chỉ các lệnh Linux thật sự hợp lệ mới gọi LLM
        output = self.llm_client.query(working_cmd, cwd=self.vfs.pwd(), user=effective_user)
        latency = (time.perf_counter() - start_time) * 1000
        
        if output:
            self.cache[cache_key] = output
            
        return output, "LLM", latency
