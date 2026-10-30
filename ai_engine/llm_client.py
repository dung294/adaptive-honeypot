import json
import time
import requests
from typing import Optional
from config import OLLAMA_API_URL, LLM_MODEL, LLM_TIMEOUT_SECONDS, HOSTNAME

SYSTEM_PROMPT = f"""You are a low-level Linux kernel and GNU bash terminal running on Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-88-generic x86_64).
Hostname: {HOSTNAME}
Your role is to simulate authentic command stdout and stderr.

CRITICAL RULES:
1. Output ONLY the raw terminal output (stdout/stderr).
2. NEVER explain, apologize, or act like an AI assistant.
3. NEVER write greetings like "Hello" or "Sure!".
4. If a command doesn't exist, output: "bash: <cmd>: command not found"
5. If command succeeded with no output, output nothing.
"""

class LLMClient:
    def __init__(self, api_url: str = OLLAMA_API_URL, model: str = LLM_MODEL):
        self.api_url = api_url
        self.model = model

    def query(self, command: str, cwd: str = "/root", user: str = "root") -> Optional[str]:
        """Gửi prompt sang Ollama Local LLM."""
        payload = {
            "model": self.model,
            "prompt": f"Current directory: {cwd}\nCurrent user: {user}\nCommand executed: {command}\nOutput:\n",
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Nhiệt độ thấp để output chuẩn xác, không bịa đặt
                "stop": ["\nroot@", "\nubuntu@", f"\n{user}@"]
            }
        }
        try:
            # timeout=(connect_timeout, read_timeout)
            resp = requests.post(self.api_url, json=payload, timeout=(0.8, LLM_TIMEOUT_SECONDS))
            if resp.status_code == 200:
                data = resp.json()
                raw_response = data.get("response", "").strip("\r\n")
                return raw_response + "\n" if raw_response else ""
        except Exception:
            # Fallback khi Ollama chưa bật hoặc offline
            return self._heuristic_fallback(command, cwd, user)
        return self._heuristic_fallback(command, cwd, user)

    def _heuristic_fallback(self, command: str, cwd: str, user: str) -> str:
        """Bộ sinh phản hồi dự phòng thông minh khi Ollama chưa khởi động."""
        cmd = command.strip().split()[0] if command.strip() else ""
        
        if cmd == "uname":
            if "-a" in command:
                return f"Linux {HOSTNAME} 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
            return "Linux\n"
        elif cmd == "id":
            return "uid=0(root) gid=0(root) groups=0(root)\n" if user == "root" else f"uid=1000({user}) gid=1000({user}) groups=1000({user}),4(adm),27(sudo)\n"
        elif cmd == "whoami":
            return f"{user}\n"
        elif cmd == "uptime":
            return " 20:50:12 up 14 days,  3:22,  1 user,  load average: 0.08, 0.03, 0.01\n"
        elif cmd == "hostname":
            return f"{HOSTNAME}\n"
        elif cmd == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:02 systemd\n"
                "  482 ?        00:00:00 systemd-journal\n"
                "  812 ?        00:00:00 sshd\n"
                " 1420 pts/0    00:00:00 bash\n"
                " 1489 pts/0    00:00:00 ps\n"
            )
        elif cmd in ["ifconfig", "ip"]:
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n"
                "        ether 02:42:ac:11:00:02  txqueuelen 1000  (Ethernet)\n"
            )
        elif cmd == "python3" or cmd == "python":
            if "-c" in command:
                return "Command executed successfully.\n"
            return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n"
        elif cmd in ["curl", "wget"]:
            return f"--2026-10-30 20:50:15--  {command.split()[-1]}\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 4096 (4.0K)\nSaving to: 'output'\n\n100%[===================>] 4.00K  --.-KB/s    in 0.001s\n"
        else:
            return f"bash: {cmd}: command not found\n"
