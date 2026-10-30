import json
import time
import requests
from typing import Optional, Dict, Any
from config import (
    LLM_PROVIDER,
    LLM_API_KEY,
    LLM_BASE_URL,
    OLLAMA_API_URL,
    LLM_MODEL,
    LLM_TIMEOUT_SECONDS,
    HOSTNAME
)

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
    """
    Client gọi LLM đa nền tảng linh hoạt (Multi-Provider LLM Client).
    Hỗ trợ:
      - Local: Ollama, vLLM, LM Studio, Heuristic Fallback
      - Cloud APIs: OpenAI, Groq (siêu nhanh), DeepSeek, Google Gemini, Anthropic Claude, OpenRouter
    """
    def __init__(
        self,
        provider: str = LLM_PROVIDER,
        model: str = LLM_MODEL,
        api_key: str = LLM_API_KEY,
        base_url: str = LLM_BASE_URL,
        timeout: float = LLM_TIMEOUT_SECONDS
    ):
        self.provider = (provider or "ollama").lower()
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.endpoint = self._resolve_endpoint()

    def _resolve_endpoint(self) -> str:
        """Tự động phân giải URL API theo provider đã chọn."""
        if self.base_url:
            return self.base_url

        if self.provider == "ollama":
            return OLLAMA_API_URL
        elif self.provider == "openai":
            return "https://api.openai.com/v1/chat/completions"
        elif self.provider == "groq":
            return "https://api.groq.com/openai/v1/chat/completions"
        elif self.provider == "deepseek":
            return "https://api.deepseek.com/chat/completions"
        elif self.provider == "openrouter":
            return "https://openrouter.ai/api/v1/chat/completions"
        elif self.provider == "gemini":
            # Endpoint chuẩn OpenAI compatibility chính thức của Google Gemini
            return "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        elif self.provider == "anthropic":
            return "https://api.anthropic.com/v1/messages"
        elif self.provider == "custom":
            return self.base_url or "http://localhost:8000/v1/chat/completions"
        return OLLAMA_API_URL

    def query(self, command: str, cwd: str = "/root", user: str = "root") -> Optional[str]:
        """Định tuyến truy vấn tới đúng provider AI đã cấu hình."""
        if self.provider == "heuristic":
            return self._heuristic_fallback(command, cwd, user)

        prompt_body = f"Current directory: {cwd}\nCurrent user: {user}\nCommand executed: {command}\nOutput:\n"

        try:
            if self.provider == "ollama":
                res = self._call_ollama(prompt_body, user)
            elif self.provider == "anthropic":
                res = self._call_anthropic(prompt_body, user)
            else:
                # Tất cả các provider dùng chuẩn OpenAI (openai, groq, deepseek, gemini, openrouter, custom)
                res = self._call_openai_compatible(prompt_body, user)

            if res is not None:
                cleaned = res.rstrip("\r\n")
                return (cleaned + "\n") if cleaned else ""
        except Exception:
            # Fallback an toàn khi mạng gặp lỗi, API hết hạn, rate-limit 429...
            return self._heuristic_fallback(command, cwd, user)

        return self._heuristic_fallback(command, cwd, user)

    def _call_ollama(self, prompt: str, user: str) -> Optional[str]:
        """Gọi Ollama native endpoint."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "stop": ["\nroot@", "\nubuntu@", f"\n{user}@"]
            }
        }
        resp = requests.post(self.endpoint, json=payload, timeout=(0.8, self.timeout))
        if resp.status_code == 200:
            return resp.json().get("response", "")
        return None

    def _call_openai_compatible(self, prompt: str, user: str) -> Optional[str]:
        """Gọi bất kỳ API nào theo chuẩn OpenAI Chat Completions (OpenAI, Groq, DeepSeek, Gemini, OpenRouter...)."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": 512,
            "stop": ["\nroot@", "\nubuntu@", f"\n{user}@"]
        }
        resp = requests.post(self.endpoint, json=payload, headers=headers, timeout=(1.0, self.timeout))
        if resp.status_code == 200:
            data = resp.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
        return None

    def _call_anthropic(self, prompt: str, user: str) -> Optional[str]:
        """Gọi Anthropic Claude Messages API."""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": self.model or "claude-3-5-haiku-20241022",
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 512,
            "temperature": 0.1,
            "stop_sequences": ["\nroot@", "\nubuntu@", f"\n{user}@"]
        }
        resp = requests.post(self.endpoint, json=payload, headers=headers, timeout=(1.0, self.timeout))
        if resp.status_code == 200:
            data = resp.json()
            content = data.get("content", [])
            if content and isinstance(content, list):
                return content[0].get("text", "")
        return None

    def _heuristic_fallback(self, command: str, cwd: str, user: str) -> str:
        """Bộ sinh phản hồi dự phòng thông minh khi LLM offline hoặc gặp lỗi."""
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
