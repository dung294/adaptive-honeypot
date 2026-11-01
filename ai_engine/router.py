import time
import re
from typing import Tuple
from gateway.vfs import VirtualFileSystem
from ai_engine.guardrails import Guardrails
from ai_engine.llm_client import LLMClient

class CommandRouter:
    """
    Bộ điều phối lệnh kết hợp (Hybrid Dispatcher).
    - 80% lệnh file hệ thống cơ bản: VFS xử lý tức thì (<5ms), đảm bảo tính nhất quán.
    - 20% lệnh phức tạp/lạ: Chuyển giao cho LLM Client xử lý.
    """
    def __init__(self, vfs: VirtualFileSystem, llm_client: LLMClient):
        self.vfs = vfs
        self.llm_client = llm_client

    def execute(self, raw_cmd: str, user: str = "root") -> Tuple[str, str, float]:
        start_time = time.perf_counter()
        clean_cmd = raw_cmd.strip()
        
        if not clean_cmd:
            return "", "VFS", 0.1

        # 1. Kiểm tra Guardrails (Anti-Jailbreak)
        is_jailbreak, jailbreak_response = Guardrails.inspect(clean_cmd)
        if is_jailbreak:
            latency = (time.perf_counter() - start_time) * 1000
            return jailbreak_response, "GUARDRAIL_BLOCKED", latency

        # 2. Xử lý chuỗi lệnh echo redirect (ví dụ: echo 'text' > file.txt)
        if clean_cmd.startswith("echo ") and (">" in clean_cmd or ">>" in clean_cmd):
            append = ">>" in clean_cmd
            parts = clean_cmd.split(">>" if append else ">")
            content = parts[0].replace("echo", "", 1).strip().strip("'\"") + "\n"
            target_path = parts[1].strip()
            ok, err = self.vfs.write_file(target_path, content, append=append)
            latency = (time.perf_counter() - start_time) * 1000
            return (err + "\n" if err else ""), "VFS", latency

        tokens = clean_cmd.split()
        base_cmd = tokens[0]

        # 3. Lệnh VFS xử lý trực tiếp
        if base_cmd == "pwd":
            latency = (time.perf_counter() - start_time) * 1000
            return self.vfs.pwd() + "\n", "VFS", latency

        elif base_cmd == "whoami":
            latency = (time.perf_counter() - start_time) * 1000
            return f"{user}\n", "VFS", latency

        elif base_cmd == "id":
            latency = (time.perf_counter() - start_time) * 1000
            out = "uid=0(root) gid=0(root) groups=0(root)\n" if user == "root" else f"uid=1000({user}) gid=1000({user}) groups=1000({user})\n"
            return out, "VFS", latency

        elif base_cmd == "history":
            latency = (time.perf_counter() - start_time) * 1000
            ok, content = self.vfs.cat("/root/.bash_history")
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
            return "", "VFS", 0.5

        elif base_cmd == "mkdir":
            if len(tokens) > 1:
                ok, err = self.vfs.mkdir(tokens[1])
                latency = (time.perf_counter() - start_time) * 1000
                return (err + "\n" if err else ""), "VFS", latency
            return "mkdir: missing operand\n", "VFS", 0.5

        elif base_cmd == "touch":
            if len(tokens) > 1:
                ok, err = self.vfs.touch(tokens[1])
                latency = (time.perf_counter() - start_time) * 1000
                return (err + "\n" if err else ""), "VFS", latency
            return "touch: missing file operand\n", "VFS", 0.5

        elif base_cmd == "rm":
            rec = "-r" in tokens or "-rf" in tokens
            target = [t for t in tokens[1:] if not t.startswith("-")]
            if target:
                ok, err = self.vfs.rm(target[0], recursive=rec)
                latency = (time.perf_counter() - start_time) * 1000
                return (err + "\n" if err else ""), "VFS", latency
            return "rm: missing operand\n", "VFS", 0.5

        elif base_cmd == "chmod":
            target = tokens[-1] if len(tokens) > 1 else ""
            mode = tokens[1] if len(tokens) > 2 else "+x"
            ok, err = self.vfs.chmod(target, mode)
            latency = (time.perf_counter() - start_time) * 1000
            return (err + "\n" if err else ""), "VFS", latency

        elif base_cmd == "wget":
            url_tokens = [t for t in tokens[1:] if not t.startswith("-")]
            target_url = url_tokens[0] if url_tokens else "http://malware.c2/payload.sh"
            filename = target_url.split("/")[-1] or "downloaded_file"
            simulated_payload = f"#!/bin/bash\n# Captured remote payload from {target_url}\n# Dropped at: {time.time()}\necho 'Malware payload simulated'\n"
            self.vfs.write_file(filename, simulated_payload)
            latency = (time.perf_counter() - start_time) * 1000
            out = (
                f"--2026-11-01 16:50:00--  {target_url}\n"
                f"Resolving c2 host... 185.220.101.5\n"
                f"Connecting to 185.220.101.5:80... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: {len(simulated_payload)} [text/x-sh]\n"
                f"Saving to: '{filename}'\n\n"
                f"{filename}        100%[===================>]  {len(simulated_payload)}  --.-KB/s    in 0.001s\n\n"
                f"2026-11-01 16:50:00 - '{filename}' saved [{len(simulated_payload)}/{len(simulated_payload)}]\n"
            )
            return out, "DECEPTION_DOWNLOAD", latency

        elif clean_cmd.startswith("sudo -l"):
            latency = (time.perf_counter() - start_time) * 1000
            out = (
                f"Matching Defaults entries for {user} on {self.vfs.hostname}:\n"
                f"    env_reset, mail_badpass\n\n"
                f"User {user} may run the following commands on {self.vfs.hostname}:\n"
                f"    (ALL : ALL) NOPASSWD: /usr/bin/find\n"
            )
            return out, "VFS_PRIV_ESC_BAIT", latency

        elif clean_cmd in ["sudo su", "sudo -i", "sudo bash", "sudo sh", "su"] or "sudo find" in clean_cmd:
            latency = (time.perf_counter() - start_time) * 1000
            self.vfs.user = "root"
            self.vfs.cwd = "/root"
            return "__ESCALATE_ROOT__", "VFS_PRIV_ESC", latency

        elif base_cmd in ["exit", "logout"]:
            latency = (time.perf_counter() - start_time) * 1000
            return "__EXIT__", "VFS", latency

        # 4. Các lệnh phức tạp / động -> Định tuyến sang LLM
        output = self.llm_client.query(clean_cmd, cwd=self.vfs.pwd(), user=user)
        latency = (time.perf_counter() - start_time) * 1000
        return output, "LLM", latency
