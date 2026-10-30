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
        # Fallback đọc file .env thủ công khi chưa cài thư viện dotenv
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

# Cấu hình SSH Gateway
SSH_HOST = os.getenv("SSH_HOST", "0.0.0.0")
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
SSH_BANNER = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
SERVER_KEY_PATH = BASE_DIR / "server.key"

# Cấu hình Quản trị viên (Admin Remote Control từ máy Windows)
ADMIN_ENABLED = os.getenv("ADMIN_ENABLED", "true").lower() in ("true", "1", "yes")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Danh sách IP được phép làm admin: '*' cho phép tất cả, hoặc danh sách phân cách bởi dấu phẩy (ví dụ: '192.168.1.5, 10.0.0.2')
ADMIN_ALLOWED_IPS = [ip.strip() for ip in os.getenv("ADMIN_ALLOWED_IPS", "*").split(",") if ip.strip()]

# Cấu hình Honeypot Auth:
# - False (Mặc định): Chế độ Bẫy (Deception). Hacker nhập user/pass bất kỳ đều cho vào bẫy ảo VFS+LLM để thu thập mẫu.
# - True: Chỉ người dùng có user/pass hợp lệ mới được vào.
HONEYPOT_STRICT_AUTH = os.getenv("HONEYPOT_STRICT_AUTH", "false").lower() in ("true", "1", "yes")

# Cấu hình Persona Hệ thống ảo (Dành cho Hacker bị lừa vào bẫy)
HOSTNAME = os.getenv("HOSTNAME", "ubuntu-srv-01")
DEFAULT_USER = os.getenv("DEFAULT_USER", "root")
PROMPT_TEMPLATE = "{user}@{hostname}:{cwd}# "

# Cấu hình AI / LLM Engine đa nền tảng
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower()
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "")
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5-coder:7b")
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "5.0"))

# Đường dẫn lưu log sự kiện (JSON Lines)
EVENT_LOG_FILE = LOGS_DIR / "events.jsonl"
