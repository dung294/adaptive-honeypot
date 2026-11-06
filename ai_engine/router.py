import time
import re
import shlex
import os
import fnmatch
from typing import Tuple, Dict, Set, List, Optional
from gateway.vfs import VirtualFileSystem
from gateway.state.system_state import LinuxSystemState
from gateway.apt_manager import AptManager
from ai_engine.guardrails import Guardrails
from ai_engine.llm_client import LLMClient
from config import HOSTNAME

class CommandRouter:
    """
    Bộ điều phối lệnh kết hợp (Hybrid Dispatcher) có trạng thái (Stateful).
    - Giả lập 100% chuẩn Ubuntu 22.04 LTS cho hơn 34+ lệnh quản trị, file ops, mạng và system diagnostics.
    - Quản lý biến môi trường ($VAR, $?, $USER, $HOME, $PATH).
    - Xử lý chuỗi lệnh: pipeline (|), redirection (>, >>), chained commands (&&, ||, ;).
    - Tích hợp AptManager (apt update, upgrade, install, remove, dpkg).
    - Tích hợp VFS (mkdir, touch, rm, cp, mv, chmod, chown, cat, ls, find, tree, stat, file, du).
    - Lưu mã thoát exit code ($?).
    """

    KNOWN_LINUX_COMMANDS: Set[str] = {
        # Shell builtins
        "cd", "echo", "pwd", "history", "clear", "exit", "logout", "help", "export",
        "alias", "unalias", "set", "unset", "source", ".", "type", "builtin", "exec",
        "jobs", "bg", "fg", "disown", "wait", "suspend", "kill", "trap", "test", "[",
        
        # Core utilities
        "ls", "cat", "mkdir", "touch", "rm", "cp", "mv", "ln", "chmod", "chown", "chgrp",
        "head", "tail", "more", "less", "grep", "egrep", "fgrep", "sed", "awk", "find",
        "sort", "uniq", "wc", "tr", "cut", "paste", "tee", "xargs", "diff", "patch",
        "file", "stat", "basename", "dirname", "realpath", "readlink", "du", "df", "tree",
        "md5sum", "sha256sum", "sha1sum", "base64", "strings", "printf",
        
        # System & Hardware & Process
        "uname", "hostname", "hostnamectl", "lsb_release", "whoami", "id", "groups", "uptime",
        "w", "who", "last", "lastlog", "ps", "top", "htop", "pstree", "free", "vmstat", "iostat",
        "lsof", "kill", "killall", "pkill", "pgrep", "dmesg", "service", "systemctl", "journalctl",
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
        "useradd", "adduser", "userdel", "usermod", "groupadd", "groupdel", "crontab", "cron", "at",
        "bash", "sh", "zsh", "dash", "python", "python3", "perl", "php", "ruby", "node",
        "npm", "gcc", "g++", "make", "git", "docker", "docker-compose", "podman", "kubectl",
        "openssl", "gpg", "nano", "vim", "vi"
    }

    def __init__(self, vfs: VirtualFileSystem, llm_client: LLMClient):
        self.vfs = vfs
        self.llm_client = llm_client
        self.state = LinuxSystemState(hostname=HOSTNAME)
        self.apt_manager = AptManager(self.state, self.vfs)
        self.cache: Dict[str, str] = {}
        
        self.last_exit_code = 0
        self.env_vars: Dict[str, str] = {
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "SHELL": "/bin/bash",
            "HOSTNAME": HOSTNAME
        }

    def get_env(self, key: str, default: str = "", user: str = "ubuntu") -> str:
        if key == "?":
            return str(self.last_exit_code)
        if key == "USER" or key == "LOGNAME":
            return user
        if key == "HOME":
            return "/root" if user == "root" else f"/home/{user}"
        if key == "PWD":
            return self.vfs.pwd()
        if key == "HOSTNAME":
            return HOSTNAME
        return self.env_vars.get(key, default)

    def _expand_env_vars(self, text: str, user: str) -> str:
        """Mở rộng biến môi trường như $VAR, ${VAR}, $?"""
        def replace_var(m):
            var_name = m.group(1) or m.group(2)
            return self.get_env(var_name, default="", user=user)

        pattern = re.compile(r'\$(?:\{([a-zA-Z0-9_?]+)\}|([a-zA-Z0-9_?]+))')
        return pattern.sub(replace_var, text)

    def _expand_wildcards(self, tokens: List[str], user: str = "root") -> List[str]:
        """Mở rộng ký tự đại diện wildcard (*, ?) giống GNU Bash thật."""
        expanded = []
        for token in tokens:
            if token.startswith("-") or "=" in token or not any(c in token for c in ("*", "?")):
                expanded.append(token)
                continue

            if "/" in token:
                dir_part, pattern = token.rsplit("/", 1)
                target_dir = self.vfs.resolve_path(dir_part if dir_part else "/")
            else:
                dir_part = ""
                pattern = token
                target_dir = self.vfs.cwd

            node = self.vfs._get_node(target_dir)
            if not node or node.get("type") != "dir":
                expanded.append(token)
                continue

            children = sorted(list(node.get("children", {}).keys()))
            matched = []
            for name in children:
                if not pattern.startswith(".") and name.startswith("."):
                    continue
                if fnmatch.fnmatch(name, pattern):
                    matched.append(f"{dir_part}/{name}" if dir_part else name)

            if matched:
                expanded.extend(matched)
            else:
                expanded.append(token)

        return expanded

    def execute(self, raw_cmd: str, user: str = "root", channel = None) -> Tuple[str, str, float]:
        """
        Thực thi câu lệnh từ SSH Terminal.
        Hỗ trợ:
          - Chaining: cmd1 && cmd2, cmd1 || cmd2, cmd1 ; cmd2
          - Redirection: >, >>, 2>&1
          - Pipeline: cmd1 | cmd2
        """
        start_time = time.perf_counter()
        clean_cmd = raw_cmd.strip()
        
        if not clean_cmd:
            return "", "VFS", 0.05

        # 1. Guardrails
        is_jailbreak, jailbreak_response = Guardrails.inspect(clean_cmd)
        if is_jailbreak:
            latency = (time.perf_counter() - start_time) * 1000
            self.last_exit_code = 1
            return jailbreak_response, "GUARDRAIL_BLOCKED", latency

        # 2. Xử lý Chained Commands (;, &&, ||)
        if ";" in clean_cmd:
            parts = clean_cmd.split(";")
            total_out = []
            for part in parts:
                p = part.strip()
                if not p:
                    continue
                out, handler, _ = self._execute_pipeline_or_single(p, user=user, channel=channel)
                if out == "__EXIT__":
                    return "__EXIT__", "VFS", 0.1
                total_out.append(out)
            latency = (time.perf_counter() - start_time) * 1000
            return "".join(total_out), "CHAINED", latency

        if "&&" in clean_cmd:
            parts = clean_cmd.split("&&")
            total_out = []
            for part in parts:
                p = part.strip()
                if not p:
                    continue
                out, handler, _ = self._execute_pipeline_or_single(p, user=user, channel=channel)
                if out == "__EXIT__":
                    return "__EXIT__", "VFS", 0.1
                total_out.append(out)
                if self.last_exit_code != 0:
                    break
            latency = (time.perf_counter() - start_time) * 1000
            return "".join(total_out), "CHAINED_AND", latency

        if "||" in clean_cmd:
            parts = clean_cmd.split("||")
            total_out = []
            for part in parts:
                p = part.strip()
                if not p:
                    continue
                out, handler, _ = self._execute_pipeline_or_single(p, user=user, channel=channel)
                if out == "__EXIT__":
                    return "__EXIT__", "VFS", 0.1
                total_out.append(out)
                if self.last_exit_code == 0:
                    break
            latency = (time.perf_counter() - start_time) * 1000
            return "".join(total_out), "CHAINED_OR", latency

        return self._execute_pipeline_or_single(clean_cmd, user=user, start_time=start_time, channel=channel)

    def _execute_pipeline_or_single(self, cmd: str, user: str = "root", start_time: float = None, channel = None) -> Tuple[str, str, float]:
        if start_time is None:
            start_time = time.perf_counter()

        # Xử lý Pipeline (|)
        if "|" in cmd:
            parts = [p.strip() for p in cmd.split("|")]
            if len(parts) > 1:
                out, handler, _ = self._execute_redirection_or_single(parts[0], user=user, channel=channel)
                for stage in parts[1:]:
                    s_tokens = stage.split()
                    if not s_tokens:
                        continue
                    scmd = s_tokens[0]
                    lines = out.splitlines()

                    if scmd in ("grep", "egrep"):
                        flags = [t for t in s_tokens[1:] if t.startswith("-")]
                        pat = [t for t in s_tokens[1:] if not t.startswith("-")]
                        pattern = pat[0].strip("'\"") if pat else ""
                        case_insens = "-i" in flags
                        invert = "-v" in flags
                        line_num = "-n" in flags
                        count_only = "-c" in flags
                        
                        filtered = []
                        matched_count = 0
                        for idx, l in enumerate(lines):
                            match = (pattern.lower() in l.lower()) if case_insens else (pattern in l)
                            if invert:
                                match = not match
                            if match:
                                matched_count += 1
                                if line_num:
                                    filtered.append(f"{idx+1}:{l}")
                                else:
                                    filtered.append(l)

                        if count_only:
                            out = f"{matched_count}\n"
                        else:
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

                    elif scmd == "awk":
                        col_idx = 0
                        for t in s_tokens:
                            if "$1" in t: col_idx = 0
                            elif "$2" in t: col_idx = 1
                            elif "$3" in t: col_idx = 2
                            elif "$9" in t: col_idx = 8
                        cols = []
                        for l in lines:
                            parts = l.split()
                            if len(parts) > col_idx:
                                cols.append(parts[col_idx])
                        out = "\n".join(cols) + ("\n" if cols else "")

                    elif scmd == "xargs":
                        sub_args = s_tokens[1:]
                        if sub_args:
                            joined_args = " ".join(out.split())
                            sub_cmd = f"{' '.join(sub_args)} {joined_args}"
                            out, _, _ = self._execute_redirection_or_single(sub_cmd, user=user, channel=channel)

                latency = (time.perf_counter() - start_time) * 1000
                self.last_exit_code = 0
                return out, "PIPELINE", latency

        return self._execute_redirection_or_single(cmd, user=user, start_time=start_time, channel=channel)

    def _execute_redirection_or_single(self, cmd: str, user: str = "root", start_time: float = None, channel = None) -> Tuple[str, str, float]:
        if start_time is None:
            start_time = time.perf_counter()

        expanded_cmd = self._expand_env_vars(cmd, user=user)

        # Xử lý background process (&)
        is_background = False
        trimmed = expanded_cmd.strip()
        if trimmed.endswith("&") and not trimmed.endswith("&&"):
            is_background = True
            expanded_cmd = trimmed[:-1].strip()

        append = False
        target_file = None
        main_cmd = expanded_cmd

        if ">>" in expanded_cmd:
            parts = expanded_cmd.split(">>", 1)
            main_cmd = parts[0].strip()
            target_file = parts[1].strip().split()[0]
            append = True
        elif ">" in expanded_cmd:
            parts = expanded_cmd.split(">", 1)
            main_cmd = parts[0].strip()
            target_file = parts[1].strip().split()[0]
            append = False

        if target_file:
            target_file = target_file.replace("2>&1", "").strip()

        # Kiểm tra lệnh chạy ngầm (nohup hoặc &)
        is_nohup = main_cmd.startswith("nohup ")
        if is_background or is_nohup:
            actual_cmd = main_cmd[6:].strip() if is_nohup else main_cmd
            pid = self.state.add_process(user=user, cmd=actual_cmd)
            prefix = ""
            if is_nohup:
                prefix = "nohup: ignoring input and appending output to 'nohup.out'\n"
                if not target_file:
                    self.vfs.write_file("nohup.out", f"[{actual_cmd}] running in background\n", append=True, user=user)
            job_id = len(self.state.custom_processes)
            self.last_exit_code = 0
            latency = (time.perf_counter() - start_time) * 1000
            return f"{prefix}[{job_id}] {pid}\n", "VFS_BG", latency

        stdout, handler, latency = self._execute_core(main_cmd, user=user, start_time=start_time, channel=channel)

        if target_file and stdout != "__EXIT__":
            # Loại bỏ marker __STREAMED__ nếu có
            clean_out = stdout[len("__STREAMED__"):] if stdout.startswith("__STREAMED__") else stdout
            ok, err = self.vfs.write_file(target_file, clean_out, append=append, user=user)
            if not ok:
                self.last_exit_code = 1
                return f"bash: {target_file}: {err}\n", "VFS", latency
            self.last_exit_code = 0
            return "", "VFS_REDIRECT", latency

        return stdout, handler, latency

    def _execute_core(self, cmd: str, user: str = "root", start_time: float = None, channel = None) -> Tuple[str, str, float]:
        if start_time is None:
            start_time = time.perf_counter()

        clean_cmd = cmd.strip()
        if not clean_cmd:
            self.last_exit_code = 0
            return "", "VFS", 0.05

        try:
            raw_tokens = shlex.split(clean_cmd)
        except Exception:
            raw_tokens = clean_cmd.split()

        if not raw_tokens:
            self.last_exit_code = 0
            return "", "VFS", 0.05

        if raw_tokens[0] == "export":
            latency = (time.perf_counter() - start_time) * 1000
            for t in raw_tokens[1:]:
                if "=" in t:
                    k, v = t.split("=", 1)
                    self.env_vars[k.strip()] = v.strip().strip("'\"")
            self.last_exit_code = 0
            return "", "VFS", latency

        effective_user = user
        if raw_tokens[0] == "sudo":
            if len(raw_tokens) == 1:
                self.last_exit_code = 1
                return "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]\n", "VFS", (time.perf_counter() - start_time) * 1000
            effective_user = "root"
            raw_tokens = raw_tokens[1:]
            clean_cmd = " ".join(raw_tokens)

        # Mở rộng Wildcard Globbing (*, ?) giống Bash thật
        tokens = self._expand_wildcards(raw_tokens, user=effective_user)
        base_cmd = tokens[0]
        args = tokens[1:]

        # 1. TRÌNH QUẢN LÝ GÓI APT / DPKG
        if base_cmd in ("apt", "apt-get", "apt-cache", "dpkg"):
            out, code = self.apt_manager.handle_apt(tokens, clean_cmd, user=effective_user, channel=channel)
            self.last_exit_code = code
            latency = (time.perf_counter() - start_time) * 1000
            return out, "APT", latency

        # 2. VIRTUAL FILESYSTEM COMMANDS (VFS)
        if base_cmd == "pwd":
            self.last_exit_code = 0
            return self.vfs.pwd() + "\n", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "cd":
            target = args[0] if args else ""
            ok, err = self.vfs.cd(target, user=effective_user)
            self.last_exit_code = 0 if ok else 1
            return (err + "\n" if err else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "ls":
            flags = ""
            paths = []
            for a in args:
                if a.startswith("-"):
                    flags += a.lstrip("-")
                else:
                    paths.append(a)
            path = paths[0] if paths else ""
            ok, res = self.vfs.ls(path, flags=flags, user=effective_user)
            self.last_exit_code = 0 if ok else 2
            return (res + "\n" if res else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "cat":
            if not args:
                self.last_exit_code = 0
                return "", "VFS", (time.perf_counter() - start_time) * 1000
            outputs = []
            err_code = 0
            for target in args:
                if target.startswith("-"):
                    continue
                ok, res = self.vfs.cat(target, user=effective_user)
                if not ok:
                    err_code = 1
                outputs.append(res)
            self.last_exit_code = err_code
            return "\n".join(outputs) + ("\n" if outputs else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd in ("more", "less"):
            if args:
                target = [a for a in args if not a.startswith("-")]
                if target:
                    ok, res = self.vfs.cat(target[0], user=effective_user)
                    self.last_exit_code = 0 if ok else 1
                    return res + "\n", "VFS", (time.perf_counter() - start_time) * 1000
            self.last_exit_code = 0
            return "", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "touch":
            if not args:
                self.last_exit_code = 1
                return "touch: missing file operand\n", "VFS", 0.1
            errs = []
            for target in args:
                if not target.startswith("-"):
                    ok, err = self.vfs.touch(target, user=effective_user)
                    if not ok:
                        errs.append(err)
            self.last_exit_code = 0 if not errs else 1
            return ("\n".join(errs) + "\n" if errs else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "mkdir":
            if not args:
                self.last_exit_code = 1
                return "mkdir: missing operand\n", "VFS", 0.1
            rec = "-p" in args or "--parents" in args
            errs = []
            for target in args:
                if not target.startswith("-"):
                    ok, err = self.vfs.mkdir(target, recursive=rec, user=effective_user)
                    if not ok:
                        errs.append(err)
            self.last_exit_code = 0 if not errs else 1
            return ("\n".join(errs) + "\n" if errs else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "rm":
            if not args:
                self.last_exit_code = 1
                return "rm: missing operand\n", "VFS", 0.1
            rec = "-r" in args or "-rf" in args or "-R" in args or "--recursive" in args
            targets = [a for a in args if not a.startswith("-")]
            if ("/" in targets or "/*" in targets) and "--no-preserve-root" not in args:
                self.last_exit_code = 1
                return "rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe\n", "VFS", 0.1
            errs = []
            for target in targets:
                ok, err = self.vfs.rm(target, recursive=rec, user=effective_user)
                if not ok:
                    errs.append(err)
            self.last_exit_code = 0 if not errs else 1
            return ("\n".join(errs) + "\n" if errs else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "cp":
            clean_args = [a for a in args if not a.startswith("-")]
            if len(clean_args) < 2:
                self.last_exit_code = 1
                return "cp: missing destination file operand\n", "VFS", 0.1
            ok, err = self.vfs.cp(clean_args[0], clean_args[1], user=effective_user)
            self.last_exit_code = 0 if ok else 1
            return (err + "\n" if err else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "mv":
            clean_args = [a for a in args if not a.startswith("-")]
            if len(clean_args) < 2:
                self.last_exit_code = 1
                return "mv: missing destination file operand\n", "VFS", 0.1
            ok, err = self.vfs.mv(clean_args[0], clean_args[1], user=effective_user)
            self.last_exit_code = 0 if ok else 1
            return (err + "\n" if err else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "chmod":
            clean_args = [a for a in args if not a.startswith("-")]
            if len(clean_args) < 2:
                self.last_exit_code = 1
                return "chmod: missing operand\n", "VFS", 0.1
            ok, err = self.vfs.chmod(clean_args[1], clean_args[0], user=effective_user)
            self.last_exit_code = 0 if ok else 1
            return (err + "\n" if err else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "chown":
            clean_args = [a for a in args if not a.startswith("-")]
            if len(clean_args) < 2:
                self.last_exit_code = 1
                return "chown: missing operand\n", "VFS", 0.1
            ok, err = self.vfs.chown(clean_args[1], clean_args[0], user=effective_user)
            self.last_exit_code = 0 if ok else 1
            return (err + "\n" if err else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "find":
            root_dir = "."
            name_pat = None
            type_filter = None
            i = 0
            while i < len(args):
                a = args[i]
                if a == "-name" and i + 1 < len(args):
                    name_pat = args[i+1].strip("'\"")
                    i += 1
                elif a == "-type" and i + 1 < len(args):
                    type_filter = args[i+1]
                    i += 1
                elif not a.startswith("-") and root_dir == ".":
                    root_dir = a
                i += 1
            ok, res = self.vfs.find(root_dir, name_pat=name_pat, type_filter=type_filter, user=effective_user)
            self.last_exit_code = 0 if ok else 1
            return (res + "\n" if res else ""), "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "stat":
            target = [a for a in args if not a.startswith("-")]
            if not target:
                self.last_exit_code = 1
                return "stat: missing operand\n", "VFS", 0.1
            ok, res = self.vfs.stat_cmd(target[0])
            self.last_exit_code = 0 if ok else 1
            return res + "\n", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "file":
            target = [a for a in args if not a.startswith("-")]
            if not target:
                self.last_exit_code = 1
                return "file: missing operand\n", "VFS", 0.1
            ok, res = self.vfs.file_cmd(target[0])
            self.last_exit_code = 0 if ok else 1
            return res + "\n", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "tree":
            target = [a for a in args if not a.startswith("-")]
            root = target[0] if target else "."
            ok, res = self.vfs.tree(root, user=effective_user)
            self.last_exit_code = 0 if ok else 1
            return res + "\n", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "du":
            human = "-h" in args or "--human-readable" in args
            target = [a for a in args if not a.startswith("-")]
            path = target[0] if target else "."
            ok, res = self.vfs.du(path, human=human, user=effective_user)
            self.last_exit_code = 0 if ok else 1
            return res + "\n", "VFS", (time.perf_counter() - start_time) * 1000

        # 3. TEXT & OUTPUT COMMANDS
        elif base_cmd == "echo":
            text = " ".join(args)
            if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
                text = text[1:-1]
            self.last_exit_code = 0
            return text + "\n", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "printf":
            fmt = args[0] if args else ""
            val = args[1:] if len(args) > 1 else []
            try:
                fmt_clean = fmt.replace("\\n", "\n").replace("\\t", "\t")
                if "%s" in fmt_clean and val:
                    res = fmt_clean % tuple(val)
                else:
                    res = fmt_clean
                self.last_exit_code = 0
                return res, "VFS", (time.perf_counter() - start_time) * 1000
            except Exception:
                self.last_exit_code = 0
                return fmt + "\n", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "grep":
            flags = [a for a in args if a.startswith("-")]
            params = [a for a in args if not a.startswith("-")]
            if len(params) >= 2:
                pat = params[0].strip("'\"")
                filepath = params[1]
                ok, content = self.vfs.cat(filepath, user=effective_user)
                if not ok:
                    self.last_exit_code = 2
                    return f"grep: {filepath}: {content}\n", "VFS", 0.1
                lines = content.splitlines()
                case_i = "-i" in flags
                inv = "-v" in flags
                matched = []
                for l in lines:
                    m = (pat.lower() in l.lower()) if case_i else (pat in l)
                    if inv: m = not m
                    if m: matched.append(l)
                self.last_exit_code = 0 if matched else 1
                return ("\n".join(matched) + "\n" if matched else ""), "VFS", 0.1
            self.last_exit_code = 1
            return "usage: grep [options] pattern [file...]\n", "VFS", 0.1

        elif base_cmd == "head":
            n = 10
            target = None
            i = 0
            while i < len(args):
                if args[i] == "-n" and i + 1 < len(args):
                    try: n = int(args[i+1])
                    except: pass
                    i += 1
                elif not args[i].startswith("-"):
                    target = args[i]
                i += 1
            if target:
                ok, content = self.vfs.cat(target, user=effective_user)
                if ok:
                    lines = content.splitlines()[:n]
                    self.last_exit_code = 0
                    return "\n".join(lines) + ("\n" if lines else ""), "VFS", 0.1
                self.last_exit_code = 1
                return f"head: cannot open '{target}': {content}\n", "VFS", 0.1
            self.last_exit_code = 0
            return "", "VFS", 0.1

        elif base_cmd == "tail":
            n = 10
            target = None
            i = 0
            while i < len(args):
                if args[i] == "-n" and i + 1 < len(args):
                    try: n = int(args[i+1])
                    except: pass
                    i += 1
                elif not args[i].startswith("-"):
                    target = args[i]
                i += 1
            if target:
                ok, content = self.vfs.cat(target, user=effective_user)
                if ok:
                    lines = content.splitlines()[-n:]
                    self.last_exit_code = 0
                    return "\n".join(lines) + ("\n" if lines else ""), "VFS", 0.1
                self.last_exit_code = 1
                return f"tail: cannot open '{target}': {content}\n", "VFS", 0.1
            self.last_exit_code = 0
            return "", "VFS", 0.1

        # 4. SYSTEM INFORMATION & RECONNAISSANCE COMMANDS
        elif base_cmd == "whoami":
            self.last_exit_code = 0
            return f"{effective_user}\n", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "id":
            self.last_exit_code = 0
            if effective_user == "root":
                return "uid=0(root) gid=0(root) groups=0(root)\n", "VFS", (time.perf_counter() - start_time) * 1000
            elif effective_user in self.state.users:
                u_info = self.state.users[effective_user]
                uid = u_info["uid"]
                gid = u_info["gid"]
                user_groups = []
                for g_name, g_info in self.state.groups.items():
                    if effective_user in g_info.get("members", []):
                        user_groups.append(f"{g_info['gid']}({g_name})")
                grps_str = ",".join(user_groups) if user_groups else f"{gid}({effective_user})"
                return f"uid={uid}({effective_user}) gid={gid}({effective_user}) groups={grps_str}\n", "VFS", (time.perf_counter() - start_time) * 1000
            return f"uid=1000({effective_user}) gid=1000({effective_user}) groups=1000({effective_user}),4(adm),27(sudo),999(docker)\n", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "groups":
            self.last_exit_code = 0
            if effective_user == "root":
                return "root\n", "VFS", 0.1
            user_groups = [g for g, v in self.state.groups.items() if effective_user in v.get("members", [])]
            return (" ".join(user_groups) + "\n") if user_groups else f"{effective_user}\n", "VFS", 0.1

        elif base_cmd == "hostname":
            self.last_exit_code = 0
            return f"{HOSTNAME}\n", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "hostnamectl":
            self.last_exit_code = 0
            out = (
                f"   Static hostname: {HOSTNAME}\n"
                f"         Icon name: computer-vm\n"
                f"           Chassis: vm\n"
                f"        Machine ID: e41b71d9894e4396a58bc2836262fb29\n"
                f"           Boot ID: 8bf2281a17da45a796e6d76bb87d4681\n"
                f"    Virtualization: vmware\n"
                f"  Operating System: Ubuntu 22.04.4 LTS\n"
                f"            Kernel: Linux 5.15.0-88-generic\n"
                f"      Architecture: x86-64\n"
                f"   Hardware Vendor: VMware, Inc.\n"
                f"    Hardware Model: VMware Virtual Platform\n"
            )
            return out, "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "lsb_release":
            self.last_exit_code = 0
            out = (
                "Distributor ID:\tUbuntu\n"
                "Description:\tUbuntu 22.04.4 LTS\n"
                "Release:\t22.04\n"
                "Codename:\tjammy\n"
            )
            return out, "VFS", 0.1

        elif base_cmd == "uname":
            self.last_exit_code = 0
            if "-a" in args or "--all" in args:
                return f"Linux {HOSTNAME} 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n", "VFS", 0.1
            elif "-r" in args:
                return "5.15.0-88-generic\n", "VFS", 0.1
            elif "-m" in args or "-p" in args or "-i" in args:
                return "x86_64\n", "VFS", 0.1
            elif "-s" in args:
                return "Linux\n", "VFS", 0.1
            elif "-n" in args:
                return f"{HOSTNAME}\n", "VFS", 0.1
            return "Linux\n", "VFS", 0.1

        elif base_cmd in ("uptime", "w", "who"):
            self.last_exit_code = 0
            if base_cmd == "uptime":
                return " 12:45:10 up 14 days,  3:22,  1 user,  load average: 0.08, 0.03, 0.01\n", "VFS", 0.1
            return f"{effective_user}   pts/0        Oct 30 19:30 (192.168.1.1)\n", "VFS", 0.1

        elif base_cmd in ("last", "lastlog"):
            self.last_exit_code = 0
            out = (
                f"{effective_user}   pts/0        192.168.1.1      Fri Oct 30 19:30   still logged in\n"
                f"reboot   system boot  5.15.0-88-generi Fri Oct 16 16:08   still running\n\n"
                f"wtmp begins Fri Oct 16 16:08:02 2026\n"
            )
            return out, "VFS", 0.1

        elif base_cmd == "date":
            self.last_exit_code = 0
            return time.strftime("%a %b %d %H:%M:%S UTC %Y\n"), "VFS", 0.1

        elif base_cmd == "df":
            self.last_exit_code = 0
            if "-h" in args or "--human-readable" in args:
                out = (
                    "Filesystem      Size  Used Avail Use% Mounted on\n"
                    "/dev/sda1        39G  7.1G   30G  20% /\n"
                    "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
                    "tmpfs           785M  1.1M  784M   1% /run\n"
                    "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
                    "/dev/sda15      105M  6.1M   99M   6% /boot/efi\n"
                )
            else:
                out = (
                    "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
                    "/dev/sda1       40439600  7441920  30918080  20% /\n"
                    "tmpfs            2008068        0   2008068   0% /dev/shm\n"
                    "tmpfs             803232     1044    802188   1% /run\n"
                    "tmpfs               5120        0      5120   0% /run/lock\n"
                    "/dev/sda15        106858     6216    100642   6% /boot/efi\n"
                )
            return out, "VFS", 0.1

        elif base_cmd == "free":
            self.last_exit_code = 0
            if "-h" in args or "--human" in args:
                out = (
                    "               total        used        free      shared  buff/cache   available\n"
                    "Mem:           3.8Gi       890Mi       2.0Gi       1.0Mi       990Mi       2.7Gi\n"
                    "Swap:          2.0Gi          0B       2.0Gi\n"
                )
            elif "-m" in args:
                out = (
                    "               total        used        free      shared  buff/cache   available\n"
                    "Mem:            3922         894        2015           1        1012        2750\n"
                    "Swap:           2047           0        2047\n"
                )
            else:
                out = (
                    "               total        used        free      shared  buff/cache   available\n"
                    "Mem:         4016136      915456     2063360        1024     1037320     2816000\n"
                    "Swap:        2097148           0     2097148\n"
                )
            return out, "VFS", 0.1

        elif base_cmd in ("ps", "top"):
            self.last_exit_code = 0
            ps_lines = [
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
                "root           1  0.0  0.2 168244 11420 ?        Ss   12:00   0:01 /sbin/init",
                "root           2  0.0  0.0      0     0 ?        S    12:00   0:00 [kthreadd]",
                "root          80  0.0  0.1  28912  6210 ?        Ss   12:00   0:00 /lib/systemd/systemd-journald",
                "systemd+     350  0.0  0.2  25800  9800 ?        Ss   12:00   0:00 /lib/systemd/systemd-resolved",
                "syslog       410  0.0  0.1 224100  5100 ?        Ssl  12:00   0:00 /usr/sbin/rsyslogd -n -iNONE",
                "root         520  0.0  0.1   8540  3200 ?        Ss   12:00   0:00 /usr/sbin/cron -f",
                "root         640  0.0  0.2  15820  8400 ?        Ss   12:00   0:00 /usr/sbin/sshd -D [listener]",
                "mysql        750  0.1  4.8 1785900 198500 ?      Ssl  12:00   0:15 /usr/sbin/mysqld --daemonize",
                "root         820  0.0  0.1  55200  4100 ?        Ss   12:00   0:00 nginx: master process /usr/sbin/nginx",
                "www-data     821  0.0  0.1  55800  5800 ?        S    12:00   0:00 nginx: worker process",
                f"{effective_user:<12} 1204  0.0  0.1  14200  4210 pts/0    Ss   12:05   0:00 -bash"
            ]
            for cp in self.state.custom_processes:
                cu = cp.get("user", effective_user)[:12]
                c_pid = cp.get("pid", 1500)
                c_cpu = cp.get("cpu", "0.0")
                c_mem = cp.get("mem", "0.1")
                c_vsz = cp.get("vsz", 18500)
                c_rss = cp.get("rss", 4200)
                c_tty = cp.get("tty", "?")
                c_stat = cp.get("stat", "Sl")
                c_start = cp.get("start", "12:10")
                c_time = cp.get("time", "0:00")
                c_cmd = cp.get("cmd", "")
                ps_lines.append(f"{cu:<12} {c_pid:>5}  {c_cpu}  {c_mem} {c_vsz:>7} {c_rss:>5} {c_tty:<8} {c_stat:<4} {c_start:<7} {c_time} {c_cmd}")
            ps_lines.append(f"{effective_user:<12} 1450  0.0  0.1  18900  3210 pts/0    R+   12:10   0:00 ps aux")
            return "\n".join(ps_lines) + "\n", "VFS", 0.1

        elif base_cmd in ("kill", "killall", "pkill"):
            if not args:
                self.last_exit_code = 1
                return f"{base_cmd}: usage: {base_cmd} [-s sigspec | -n signum | -sigspec] pid | jobspec ... or {base_cmd} -l [sigspec]\n", "VFS", 0.1
            targets = [a for a in args if not a.startswith("-")]
            if not targets:
                self.last_exit_code = 0
                return "", "VFS", 0.1
            any_err = False
            err_msg = []
            for t in targets:
                ok = self.state.kill_process(t)
                if not ok:
                    if t in ("1", "2", "80", "350", "410", "520", "640", "750", "820", "821"):
                        if effective_user != "root":
                            err_msg.append(f"bash: {base_cmd}: ({t}) - Operation not permitted\n")
                            any_err = True
                    else:
                        err_msg.append(f"bash: {base_cmd}: ({t}) - No such process\n")
                        any_err = True
            if any_err:
                self.last_exit_code = 1
                return "".join(err_msg), "VFS", 0.1
            self.last_exit_code = 0
            return "", "VFS", 0.1

        elif base_cmd == "htop":
            self.last_exit_code = 0
            out = (
                "  1  [|||||||||                                 18.2%]   Tasks: 42, 114 thr; 1 running\n"
                "  2  [||||||                                    12.0%]   Load average: 0.08 0.03 0.01 \n"
                "  Mem[||||||||||||||||||||||||             894M/3.83G]   Uptime: 14 days, 03:22:15\n"
                "  Swp[                                         0K/2.00G]\n\n"
                "  PID USER      PRI  NI  VIRT   RES   SHR S CPU% MEM%   TIME+  Command\n"
                "  750 mysql      20   0 1744M  193M 24512 S  0.1  4.8  0:15.22 /usr/sbin/mysqld\n"
                "  820 root       20   0 55200  4100  3100 S  0.0  0.1  0:00.08 nginx: master process\n"
                "  640 root       20   0 15820  8400  6200 S  0.0  0.2  0:00.32 /usr/sbin/sshd -D\n"
                "  520 root       20   0  8540  3200  2800 S  0.0  0.1  0:00.02 /usr/sbin/cron -f\n"
            )
            return out, "VFS", 0.1

        elif base_cmd in ("systemctl", "service"):
            self.last_exit_code = 0
            svc = args[-1] if args else "ssh"
            action = args[0] if len(args) > 1 and args[0] in ("start", "stop", "restart", "status") else "status"
            
            if svc in self.state.services:
                s_meta = self.state.services[svc]
                if action in ("stop", "restart", "start") and effective_user != "root":
                    self.last_exit_code = 1
                    return f"Failed to {action} {svc}.service: Interactive authentication required.\n", "VFS", 0.1
                
                if action == "stop":
                    s_meta["active"] = "inactive"
                    s_meta["sub"] = "dead"
                    return "", "VFS", 0.1
                elif action in ("start", "restart"):
                    s_meta["active"] = "active"
                    s_meta["sub"] = "running"
                    return "", "VFS", 0.1

                out = (
                    f"● {svc}.service - {s_meta.get('desc', 'Service')}\n"
                    f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled; vendor preset: enabled)\n"
                    f"     Active: {s_meta.get('active', 'active')} ({s_meta.get('sub', 'running')}) since Fri 2026-10-30 12:00:00 UTC; 3h ago\n"
                    f"   Main PID: {s_meta.get('pid', 640)} ({svc})\n"
                    f"      Tasks: 2 (limit: 4580)\n"
                    f"     Memory: 14.8M\n"
                )
                return out, "VFS", 0.1
            return f"Unit {svc}.service could not be found.\n", "VFS", 0.1

        elif base_cmd == "journalctl":
            self.last_exit_code = 0
            out = (
                "-- Journal begins at Fri 2026-10-16 16:08:00 UTC, ends at Fri 2026-10-30 20:00:00 UTC. --\n"
                "Oct 30 12:00:01 ubuntu-srv-01 CRON[520]: (root) CMD (/root/deploy.sh > /dev/null 2>&1)\n"
                "Oct 30 12:00:05 ubuntu-srv-01 systemd[1]: Started Daily apt upgrade and clean activities.\n"
                "Oct 30 19:30:12 ubuntu-srv-01 sshd[1200]: Accepted password for ubuntu from 192.168.1.1 port 52410 ssh2\n"
                "Oct 30 19:30:12 ubuntu-srv-01 systemd[1]: Started Session 1 of User ubuntu.\n"
            )
            return out, "VFS", 0.1

        elif base_cmd == "dmesg":
            self.last_exit_code = 0
            out = (
                "[    0.000000] Linux version 5.15.0-88-generic (buildd@lcy02-amd64-001) (gcc version 11.4.0)\n"
                "[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-5.15.0-88-generic root=/dev/sda1 ro quiet splash\n"
                "[    0.000000] KERNEL supported cpus: Intel GenuineIntel, AMD AuthenticAMD\n"
                "[    1.240510] systemd[1]: Inserted module 'autofs4'\n"
                "[    2.152341] eth0: Intel(R) 82545EM Gigabit Ethernet Controller\n"
                "[    3.041289] EXT4-fs (sda1): mounted filesystem with ordered data mode. Opts: (null)\n"
            )
            return out, "VFS", 0.1

        elif base_cmd in ("netstat", "ss"):
            self.last_exit_code = 0
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
            return out, "VFS", 0.1

        elif base_cmd in ("ifconfig", "ip"):
            self.last_exit_code = 0
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
            return out, "VFS", 0.1

        elif base_cmd == "ping":
            self.last_exit_code = 0
            dest = [a for a in args if not a.startswith("-")]
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
            return out, "VFS", 0.1

        elif base_cmd in ("lscpu", "arch"):
            self.last_exit_code = 0
            if base_cmd == "arch":
                return "x86_64\n", "VFS", 0.1
            out = (
                "Architecture:            x86_64\n"
                "CPU op-mode(s):        32-bit, 64-bit\n"
                "CPU(s):                  2\n"
                "Vendor ID:               GenuineIntel\n"
                "Model name:            Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
            )
            return out, "VFS", 0.1

        elif base_cmd in ("env", "printenv"):
            self.last_exit_code = 0
            home_dir = "/root" if effective_user == "root" else f"/home/{effective_user}"
            lines = [
                f"SHELL=/bin/bash",
                f"PWD={self.vfs.pwd()}",
                f"LOGNAME={effective_user}",
                f"HOME={home_dir}",
                f"USER={effective_user}",
                f"HOSTNAME={HOSTNAME}",
                f"TERM={self.env_vars.get('TERM', 'xterm-256color')}",
                f"PATH={self.env_vars.get('PATH', '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')}"
            ]
            for k, v in self.env_vars.items():
                if k not in ("SHELL", "PWD", "LOGNAME", "HOME", "USER", "HOSTNAME", "TERM", "PATH"):
                    lines.append(f"{k}={v}")
            return "\n".join(lines) + "\n", "VFS", 0.1

        elif base_cmd == "history":
            self.last_exit_code = 0
            home_history = "/root/.bash_history" if effective_user == "root" else f"/home/{effective_user}/.bash_history"
            ok, content = self.vfs.cat(home_history, user=effective_user)
            lines = content.strip().split("\n") if ok and content else ["ls -la", "uptime", "cat /var/log/syslog"]
            formatted = "\n".join([f"  {i+1}  {line}" for i, line in enumerate(lines)]) + "\n"
            return formatted, "VFS", 0.1

        elif base_cmd == "clear":
            self.last_exit_code = 0
            return "\033[2J\033[H", "VFS", 0.1

        elif base_cmd in ("which", "whereis"):
            self.last_exit_code = 0
            target = args[0] if args else ""
            if target in self.KNOWN_LINUX_COMMANDS or target in self.state.packages:
                if base_cmd == "which":
                    return f"/usr/bin/{target}\n", "VFS", 0.1
                else:
                    return f"{target}: /usr/bin/{target} /usr/share/man/man1/{target}.1.gz\n", "VFS", 0.1
            self.last_exit_code = 1
            return "\n", "VFS", 0.1

        elif base_cmd == "crontab":
            self.last_exit_code = 0
            if "-l" in args:
                content = self.state.crontabs.get(effective_user)
                if content:
                    return content, "VFS", 0.1
                return f"no crontab for {effective_user}\n", "VFS", 0.1
            elif "-r" in args:
                if effective_user in self.state.crontabs:
                    del self.state.crontabs[effective_user]
                    self.state.save_state()
                return "", "VFS", 0.1
            elif "-e" in args:
                return f"crontab: no crontab for {effective_user} - using an empty one\n", "VFS", 0.1
            non_flags = [a for a in args if not a.startswith("-")]
            if non_flags:
                cron_target = non_flags[0]
                ok, content = self.vfs.cat(cron_target, user=effective_user)
                if ok:
                    self.state.crontabs[effective_user] = content
                    self.state.save_state()
                    return "", "VFS", 0.1
                else:
                    self.last_exit_code = 1
                    return f"crontab: {content}\n", "VFS", 0.1
            return "crontab: usage error: file name must be specified for replace\n", "VFS", 0.1

        # 5. USER & AUTH MANAGEMENT
        elif base_cmd in ("useradd", "adduser"):
            if effective_user != "root":
                self.last_exit_code = 1
                return f"{base_cmd}: Permission denied.\n", "VFS", 0.1
            new_user = [a for a in args if not a.startswith("-")]
            if new_user:
                u_name = new_user[-1]
                self.state.users[u_name] = {
                    "uid": 1000 + len(self.state.users),
                    "gid": 1000 + len(self.state.users),
                    "home": f"/home/{u_name}",
                    "shell": "/bin/bash",
                    "password": "123"
                }
                self.vfs.mkdir(f"/home/{u_name}", user="root")
                self.vfs.write_file("/etc/passwd", f"{u_name}:x:1002:1002::/home/{u_name}:/bin/bash\n", append=True, user="root")
                self.state.save()
                self.last_exit_code = 0
                return "", "VFS", 0.1
            self.last_exit_code = 1
            return f"usage: {base_cmd} [options] LOGIN\n", "VFS", 0.1

        elif base_cmd == "passwd":
            target = args[0] if args else effective_user
            if target != effective_user and effective_user != "root":
                self.last_exit_code = 1
                return "passwd: You may not view or modify password information for others.\n", "VFS", 0.1
            self.last_exit_code = 0
            return f"passwd: password updated successfully for {target}\n", "VFS", 0.1

        # 6. ARCHIVE & MISC UTILITIES
        elif base_cmd == "tar":
            self.last_exit_code = 0
            flags = args[0] if args else ""
            if "c" in flags and "f" in flags and len(args) >= 2:
                archive_name = args[1]
                self.vfs.write_file(archive_name, "[GZIP_TAR_ARCHIVE_BINARY_DATA]\n", user=effective_user)
                if "v" in flags:
                    targets = args[2:] if len(args) > 2 else ["/etc/passwd"]
                    return "\n".join(targets) + "\n", "VFS", 0.1
                return "", "VFS", 0.1
            return "", "VFS", 0.1

        elif base_cmd == "zip":
            self.last_exit_code = 0
            targets = [a for a in args if not a.startswith("-")]
            if targets:
                zip_file = targets[0]
                self.vfs.write_file(zip_file, "[PK_ZIP_BINARY_DATA]\n", user=effective_user)
                out = "\n".join([f"  adding: {t} (deflated 60%)" for t in targets[1:]]) + "\n" if len(targets) > 1 else f"  adding: data (stored 0%)\n"
                return out, "VFS", 0.1
            return "zip error: Nothing to do!\n", "VFS", 0.1

        elif base_cmd == "base64":
            import base64
            if "-d" in args or "--decode" in args:
                payload = [a for a in args if not a.startswith("-")]
                if payload:
                    try:
                        self.last_exit_code = 0
                        return base64.b64decode(payload[0]).decode("utf-8", errors="replace") + "\n", "VFS", 0.1
                    except Exception:
                        self.last_exit_code = 1
                        return "base64: invalid input\n", "VFS", 0.1
            self.last_exit_code = 0
            return "", "VFS", 0.1

        elif base_cmd in ("md5sum", "sha256sum", "sha1sum"):
            import hashlib
            target = [a for a in args if not a.startswith("-")]
            if target:
                ok, content = self.vfs.cat(target[0], user=effective_user)
                if ok:
                    h = hashlib.sha256(content.encode()).hexdigest() if "sha256" in base_cmd else hashlib.md5(content.encode()).hexdigest()
                    self.last_exit_code = 0
                    return f"{h}  {target[0]}\n", "VFS", 0.1
                self.last_exit_code = 1
                return f"{base_cmd}: {target[0]}: {content}\n", "VFS", 0.1
            self.last_exit_code = 0
            return "", "VFS", 0.1

        elif base_cmd in ("exit", "logout"):
            self.last_exit_code = 0
            return "__EXIT__", "VFS", (time.perf_counter() - start_time) * 1000

        elif base_cmd == "help":
            self.last_exit_code = 0
            out = (
                "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\n"
                "These shell commands are defined internally. Type `help' to see this list.\n\n"
                "  cd [-L|[-P [-e]] [-@]] [dir]      exit [n]\n"
                "  history [-c] [-d offset] [n]      help [-dms] [pattern ...]\n"
                "  pwd [-LP]                         export [-fn] [name[=value] ...]\n"
            )
            return out, "VFS", 0.1

        # 7. EXECUTION PATHS (./script.sh hoặc /tmp/payload)
        if base_cmd.startswith("./") or base_cmd.startswith("/"):
            node = self.vfs._get_node(base_cmd)
            if not node:
                self.last_exit_code = 127
                return f"bash: {base_cmd}: No such file or directory\n", "VFS", 0.1
            if not self.vfs.check_permission(node, effective_user, "x"):
                self.last_exit_code = 126
                return f"bash: {base_cmd}: Permission denied\n", "VFS", 0.1
            self.last_exit_code = 0
            return "", "VFS", 0.1

        # 8. LỌC TỪ VỰNG: COMMAND NOT FOUND
        clean_base = base_cmd.split("/")[-1]
        if clean_base not in self.KNOWN_LINUX_COMMANDS and clean_base not in self.state.packages and not base_cmd.startswith("./"):
            self.last_exit_code = 127
            return f"bash: {base_cmd}: command not found\n", "VFS_SYNTAX", (time.perf_counter() - start_time) * 1000

        # 9. RAM CACHE CHO LLM
        cache_key = f"{effective_user}:{self.vfs.pwd()}:{clean_cmd}"
        if cache_key in self.cache:
            self.last_exit_code = 0
            return self.cache[cache_key], "CACHE", (time.perf_counter() - start_time) * 1000

        # 10. LLM FALLBACK FOR UNCOMMON COMMANDS
        output = self.llm_client.query(clean_cmd, cwd=self.vfs.pwd(), user=effective_user)
        latency = (time.perf_counter() - start_time) * 1000
        if output:
            self.cache[cache_key] = output
        self.last_exit_code = 0
        return output, "LLM", latency
