import time
import re
from typing import Tuple, Dict, Set, List
from gateway.vfs import VirtualFileSystem
from ai_engine.guardrails import Guardrails
from ai_engine.llm_client import LLMClient
from config import HOSTNAME

class CommandRouter:
    """
    Bộ điều phối lệnh kết hợp (Hybrid Dispatcher).
    - Bộ lọc từ vựng Linux (Command Whitelist): Nhận diện ngay lệnh không tồn tại trong < 0.05ms (không gọi LLM).
    - Bộ xử lý đường ống Pipeline (|) và chuỗi lệnh (grep, head, tail, wc).
    - Bộ phản hồi giả lập chân thực 100% chuẩn Ubuntu cho hơn 25+ lệnh trinh sát/CTI thông dụng.
    - Bộ nhớ đệm RAM Cache: Phản hồi lặp lại cho các lệnh phức tạp trong < 0.1ms.
    - LLM Client: Đảm nhiệm các lệnh đặc biệt, payload khai thác dị hoặc truy vấn tự nhiên.
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

        # 2. Xử lý đường ống Pipeline (ví dụ: cat /etc/passwd | grep root)
        if "|" in clean_cmd:
            parts = [p.strip() for p in clean_cmd.split("|")]
            if len(parts) > 1:
                # Thực thi lệnh đầu tiên
                out, handler, _ = self._execute_single(parts[0], user=user)
                # Chuyển qua các bộ lọc tiếp theo
                for stage in parts[1:]:
                    s_tokens = stage.split()
                    if not s_tokens:
                        continue
                    scmd = s_tokens[0]
                    lines = out.splitlines()
                    
                    if scmd == "grep":
                        # Hỗ trợ grep [flags] pattern
                        pat = [t for t in s_tokens[1:] if not t.startswith("-")]
                        pattern = pat[0] if pat else ""
                        case_insens = "-i" in s_tokens
                        filtered = []
                        for l in lines:
                            match = (pattern.lower() in l.lower()) if case_insens else (pattern in l)
                            if "-v" in s_tokens:
                                match = not match
                            if match:
                                filtered.append(l)
                        out = "\n".join(filtered) + ("\n" if filtered else "")

                    elif scmd == "head":
                        n = 10
                        if "-n" in s_tokens:
                            try:
                                n = int(s_tokens[s_tokens.index("-n") + 1])
                            except Exception:
                                pass
                        out = "\n".join(lines[:n]) + ("\n" if lines else "")

                    elif scmd == "tail":
                        n = 10
                        if "-n" in s_tokens:
                            try:
                                n = int(s_tokens[s_tokens.index("-n") + 1])
                            except Exception:
                                pass
                        out = "\n".join(lines[-n:]) + ("\n" if lines else "")

                    elif scmd == "wc":
                        if "-l" in s_tokens:
                            out = f"{len(lines)}\n"
                        else:
                            out = f" {len(lines)}  {len(out.split())} {len(out)}\n"

                    elif scmd == "sort":
                        rev = "-r" in s_tokens
                        out = "\n".join(sorted(lines, reverse=rev)) + ("\n" if lines else "")

                    elif scmd == "uniq":
                        seen = set()
                        dedup = []
                        for l in lines:
                            if l not in seen:
                                seen.add(l)
                                dedup.append(l)
                        out = "\n".join(dedup) + ("\n" if dedup else "")

                latency = (time.perf_counter() - start_time) * 1000
                return out, "PIPELINE", latency

        return self._execute_single(clean_cmd, user=user, start_time=start_time)

    def _execute_single(self, cmd: str, user: str = "root", start_time: float = None) -> Tuple[str, str, float]:
        if start_time is None:
            start_time = time.perf_counter()

        clean_cmd = cmd.strip()
        if not clean_cmd:
            return "", "VFS", 0.05

        # Xử lý sudo: Nếu gõ 'sudo <lệnh>' -> bóc tách lệnh chính và nâng quyền root
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

        # Xử lý chuỗi lệnh echo redirect (ví dụ: echo 'text' > file.txt)
        if working_cmd.startswith("echo ") and (">" in working_cmd or ">>" in working_cmd):
            append = ">>" in working_cmd
            parts = working_cmd.split(">>" if append else ">")
            content = parts[0].replace("echo", "", 1).strip().strip("'\"") + "\n"
            target_path = parts[1].strip()
            ok, err = self.vfs.write_file(target_path, content, append=append)
            latency = (time.perf_counter() - start_time) * 1000
            return (err + "\n" if err else ""), "VFS", latency

        # =====================================================================
        # FAST-PATH VFS & CHUẨN HÓA CÁC LỆNH HỆ THỐNG LINUX (< 0.1ms)
        # =====================================================================

        if base_cmd == "pwd":
            latency = (time.perf_counter() - start_time) * 1000
            return self.vfs.pwd() + "\n", "VFS", latency

        elif base_cmd == "whoami":
            latency = (time.perf_counter() - start_time) * 1000
            return f"{effective_user}\n", "VFS", latency

        elif base_cmd == "id":
            latency = (time.perf_counter() - start_time) * 1000
            out = "uid=0(root) gid=0(root) groups=0(root)\n" if effective_user == "root" else f"uid=1000({effective_user}) gid=1000({effective_user}) groups=1000({effective_user}),27(sudo),999(docker)\n"
            return out, "VFS", latency

        elif base_cmd == "groups":
            latency = (time.perf_counter() - start_time) * 1000
            out = "root\n" if effective_user == "root" else f"{effective_user} sudo docker\n"
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

        elif base_cmd == "date":
            latency = (time.perf_counter() - start_time) * 1000
            return time.strftime("%a %b %d %H:%M:%S UTC %Y\n"), "VFS", latency

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

        elif base_cmd == "free":
            latency = (time.perf_counter() - start_time) * 1000
            out = (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:            3922         894        2015           1        1012        2750\n"
                "Swap:           2047           0        2047\n"
            )
            return out, "VFS", latency

        elif base_cmd in ("ps", "top", "htop"):
            latency = (time.perf_counter() - start_time) * 1000
            out = (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root           1  0.0  0.2 168244 11420 ?        Ss   12:00   0:01 /sbin/init\n"
                "root           2  0.0  0.0      0     0 ?        S    12:00   0:00 [kthreadd]\n"
                "root          80  0.0  0.1  28912  6210 ?        Ss   12:00   0:00 /lib/systemd/systemd-journald\n"
                "systemd+     350  0.0  0.2  25800  9800 ?        Ss   12:00   0:00 /lib/systemd/systemd-resolved\n"
                "syslog       410  0.0  0.1 224100  5100 ?        Ssl  12:00   0:00 /usr/sbin/rsyslogd -n -iNONE\n"
                "root         520  0.0  0.1   8540  3200 ?        Ss   12:00   0:00 /usr/sbin/cron -f\n"
                "root         640  0.0  0.2  15820  8400 ?        Ss   12:00   0:00 /usr/sbin/sshd -D [listener]\n"
                "mysql        750  0.1  4.8 1785900 198500 ?      Ssl  12:00   0:15 /usr/sbin/mysqld --daemonize\n"
                "root         820  0.0  0.1  55200  4100 ?        Ss   12:00   0:00 nginx: master process /usr/sbin/nginx\n"
                "www-data     821  0.0  0.1  55800  5800 ?        S    12:00   0:00 nginx: worker process\n"
                f"{effective_user}      1204  0.0  0.1  14200  4210 pts/0    Ss   12:05   0:00 -bash\n"
                f"{effective_user}      1450  0.0  0.1  18900  3210 pts/0    R+   12:10   0:00 ps aux\n"
            )
            return out, "VFS", latency

        elif base_cmd in ("netstat", "ss"):
            latency = (time.perf_counter() - start_time) * 1000
            out = (
                "Active Internet connections (only servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      640/sshd: /usr/sbin\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      820/nginx: master p\n"
                "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      750/mysqld\n"
                "tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      350/systemd-resolve\n"
                "tcp6       0      0 :::22                   :::*                    LISTEN      640/sshd: /usr/sbin\n"
                "tcp6       0      0 :::80                   :::*                    LISTEN      820/nginx: master p\n"
            )
            return out, "VFS", latency

        elif base_cmd in ("ifconfig", "ip"):
            latency = (time.perf_counter() - start_time) * 1000
            if base_cmd == "ifconfig":
                out = (
                    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                    "        inet 192.168.101.218  netmask 255.255.255.0  broadcast 192.168.101.255\n"
                    "        inet6 fe80::20c:29ff:feb8:3a1f  prefixlen 64  scopeid 0x20<link>\n"
                    "        ether 00:0c:29:b8:3a:1f  txqueuelen 1000  (Ethernet)\n"
                    "        RX packets 24523  bytes 31892102 (31.8 MB)\n"
                    "        TX packets 18921  bytes 12982103 (12.9 MB)\n\n"
                    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                    "        inet 127.0.0.1  netmask 255.0.0.0\n"
                    "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
                )
            else:
                out = (
                    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                    "    inet 127.0.0.1/8 scope host lo\n"
                    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
                    "    inet 192.168.101.218/24 brd 192.168.101.255 scope global dynamic eth0\n"
                )
            return out, "VFS", latency

        elif base_cmd in ("systemctl", "service"):
            latency = (time.perf_counter() - start_time) * 1000
            svc = tokens[-1] if len(tokens) > 1 else "ssh"
            if svc in ("ssh", "sshd", "nginx", "mysql", "cron", "rsyslog"):
                out = (
                    f"● {svc}.service - Enterprise {svc.upper()} Daemon\n"
                    f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled; vendor preset: enabled)\n"
                    f"     Active: active (running) since Fri 2026-10-30 12:00:00 UTC; 3h ago\n"
                    f"   Main PID: 640 ({svc})\n"
                    f"      Tasks: 2 (limit: 4580)\n"
                    f"     Memory: 14.8M\n"
                )
                return out, "VFS", latency
            return f"Unit {svc}.service could not be found.\n", "VFS", latency

        elif base_cmd in ("which", "whereis"):
            latency = (time.perf_counter() - start_time) * 1000
            target = tokens[1] if len(tokens) > 1 else ""
            if target in self.KNOWN_LINUX_COMMANDS:
                if base_cmd == "which":
                    return f"/usr/bin/{target}\n", "VFS", latency
                else:
                    return f"{target}: /usr/bin/{target} /usr/share/man/man1/{target}.1.gz\n", "VFS", latency
            return "\n", "VFS", latency

        elif base_cmd == "crontab":
            latency = (time.perf_counter() - start_time) * 1000
            if "-l" in working_cmd:
                if effective_user == "root":
                    return "*/15 * * * * /root/deploy.sh > /dev/null 2>&1\n", "VFS", latency
                return f"no crontab for {effective_user}\n", "VFS", latency
            return "crontab: usage error: file name must be specified for replace\n", "VFS", latency

        elif base_cmd in ("lscpu", "arch"):
            latency = (time.perf_counter() - start_time) * 1000
            if base_cmd == "arch":
                return "x86_64\n", "VFS", latency
            out = (
                "Architecture:            x86_64\n"
                "CPU op-mode(s):        32-bit, 64-bit\n"
                "CPU(s):                  2\n"
                "Vendor ID:               GenuineIntel\n"
                "Model name:            Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
            )
            return out, "VFS", latency

        elif base_cmd == "ping":
            latency = (time.perf_counter() - start_time) * 1000
            dest = [t for t in tokens[1:] if not t.startswith("-")]
            host = dest[0] if dest else "127.0.0.1"
            out = (
                f"PING {host} ({host}) 56(84) bytes of data.\n"
                f"64 bytes from {host}: icmp_seq=1 ttl=118 time=12.4 ms\n"
                f"64 bytes from {host}: icmp_seq=2 ttl=118 time=13.1 ms\n"
                f"64 bytes from {host}: icmp_seq=3 ttl=118 time=12.8 ms\n\n"
                f"--- {host} ping statistics ---\n"
                f"3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
                f"rtt min/avg/max/mdev = 12.412/12.766/13.102/0.282 ms\n"
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

        elif base_cmd == "history":
            latency = (time.perf_counter() - start_time) * 1000
            home_history = "/root/.bash_history" if effective_user == "root" else f"/home/{effective_user}/.bash_history"
            ok, content = self.vfs.cat(home_history)
            lines = content.strip().split("\n") if ok and content else ["ls -la", "uptime", "cat /var/log/syslog"]
            formatted = "\n".join([f"  {i+1}  {line}" for i, line in enumerate(lines)]) + "\n"
            return formatted, "VFS", latency

        elif base_cmd == "clear":
            latency = (time.perf_counter() - start_time) * 1000
            return "\033[2J\033[H", "VFS", latency

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
                ok, res = self.vfs.cat(tokens[1], user=effective_user)
                latency = (time.perf_counter() - start_time) * 1000
                return (res if ok else res + "\n"), "VFS", latency
            return "", "VFS", 0.1

        elif base_cmd == "chmod":
            if len(tokens) >= 3:
                ok, err = self.vfs.chmod(tokens[1], tokens[2])
                latency = (time.perf_counter() - start_time) * 1000
                return (err + "\n" if err else ""), "VFS", latency
            return "chmod: missing operand\n", "VFS", 0.1

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
                "These shell commands are defined internally. Type `help' to see this list.\n\n"
                "  cd [-L|[-P [-e]] [-@]] [dir]      exit [n]\n"
                "  history [-c] [-d offset] [n]      help [-dms] [pattern ...]\n"
                "  pwd [-LP]                         export [-fn] [name[=value] ...]\n"
            )
            return out, "VFS", latency

        # =====================================================================
        # KIỂM TRA ĐƯỜNG DẪN THỰC THI FILE (./script.sh hoặc /tmp/payload)
        # =====================================================================
        if base_cmd.startswith("./") or base_cmd.startswith("/"):
            node = self.vfs._get_node(base_cmd)
            if not node:
                latency = (time.perf_counter() - start_time) * 1000
                return f"bash: {base_cmd}: No such file or directory\n", "VFS", latency

        # =====================================================================
        # LỌC TỪ VỰNG: TỪ CHỐI LỆNH KHÔNG TỒN TẠI TỨC THÌ (< 0.05ms)
        # =====================================================================
        clean_base = base_cmd.split("/")[-1]
        if clean_base not in self.KNOWN_LINUX_COMMANDS and not base_cmd.startswith("./"):
            latency = (time.perf_counter() - start_time) * 1000
            return f"bash: {base_cmd}: command not found\n", "VFS_SYNTAX", latency

        # =====================================================================
        # KIỂM TRA RAM CACHE CHO CÁC LỆNH LLM HỢP LỆ
        # =====================================================================
        cache_key = f"{effective_user}:{self.vfs.pwd()}:{working_cmd}"
        if cache_key in self.cache:
            latency = (time.perf_counter() - start_time) * 1000
            return self.cache[cache_key], "CACHE", latency

        # =====================================================================
        # ĐỊNH TUYẾN SANG LLM CHO CÁC LỆNH PHỨC TẠP / ĐẶC BIỆT
        # =====================================================================
        output = self.llm_client.query(working_cmd, cwd=self.vfs.pwd(), user=effective_user)
        latency = (time.perf_counter() - start_time) * 1000
        
        if output:
            self.cache[cache_key] = output
            
        return output, "LLM", latency
