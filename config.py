import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Tự động nạp cấu hình từ file .env (nếu có)
ENV_PATH = BASE_DIR / ".env"
if ENV_PATH.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=ENV_PATH)
    except Exception:
        try:
            with open(ENV_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

QUARANTINE_DIR = BASE_DIR / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# Cấu hình SSH Gateway Honeypot
SSH_HOST = os.getenv("SSH_HOST", "0.0.0.0")
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
SSH_BANNER = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
SERVER_KEY_PATH = BASE_DIR / "server.key"

# Cấu hình Xác thực Bẫy Honeypot
# Chỉ các mật khẩu nằm trong danh sách này mới được mở cửa vào môi trường bẫy ảo
# Hacker nhập sai pass sẽ bị từ chối (Permission denied) và hệ thống tự động ghi log dò pass (MITRE T1110)
HONEYPOT_ALLOWED_PASSWORDS = [
    p.strip() for p in os.getenv(
        "HONEYPOT_ALLOWED_PASSWORDS",
        "123,123456,root,password,admin,ubuntu,toor,supersecretpassword123"
    ).split(",") if p.strip()
]

# Danh sách username được phép ('*' = cho phép bất kỳ username nào đoán trúng pass)
HONEYPOT_ALLOWED_USERS = [
    u.strip() for u in os.getenv("HONEYPOT_ALLOWED_USERS", "*").split(",") if u.strip()
]

# Cấu hình Persona Hệ thống ảo
HOSTNAME = os.getenv("HOSTNAME", "ubuntu-srv-01")
DEFAULT_USER = os.getenv("DEFAULT_USER", "root")

# Cấu hình AI / LLM Engine đa nền tảng
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "custom").lower()
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://hhtechapi.net/v1")
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-3.8-flash")
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "8.0"))

# Đường dẫn lưu log sự kiện CTI (JSON Lines)
EVENT_LOG_FILE = LOGS_DIR / "events.jsonl"
