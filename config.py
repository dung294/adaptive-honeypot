import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

QUARANTINE_DIR = BASE_DIR / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# Cấu hình SSH Gateway
SSH_HOST = "0.0.0.0"
SSH_PORT = 2222
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
SERVER_KEY_PATH = BASE_DIR / "server.key"

# Cấu hình Persona Hệ thống
HOSTNAME = "ubuntu-srv-01"
DEFAULT_USER = "root"
PROMPT_TEMPLATE = "{user}@{hostname}:{cwd}# "

# Cấu hình AI / LLM Engine
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5-coder:7b")
LLM_TIMEOUT_SECONDS = 5.0

# Đường dẫn lưu log sự kiện (JSON Lines)
EVENT_LOG_FILE = LOGS_DIR / "events.jsonl"
