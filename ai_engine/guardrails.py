import re
from typing import Tuple

# Danh sách mẫu Prompt Injection phổ biến
JAILBREAK_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"disregard\s+all\s+(rules|instructions)",
    r"you\s+are\s+now\s+(in\s+developer\s+mode|dan|an\s+unfiltered)",
    r"reveal\s+(your\s+)?(system\s+prompt|instructions|secret|api\s*key)",
    r"print\s+(your\s+)?(prompt|system\s+rules)",
    r"system\s*:\s*you\s+must",
    r"act\s+as\s+a\s+helpful\s+ai\s+assistant",
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in JAILBREAK_PATTERNS]

class Guardrails:
    """
    Lớp bảo vệ AI khỏi Prompt Injection & Jailbreaking.
    Nếu phát hiện hacker cố tình tấn công bẻ khóa AI, hệ thống sẽ trả về lỗi Bash tự nhiên
    để hacker không hề biết có một con LLM đang đứng sau.
    """
    @staticmethod
    def inspect(command: str) -> Tuple[bool, str]:
        for pattern in COMPILED_PATTERNS:
            if pattern.search(command):
                # Giả lập lỗi Bash chuẩn thay vì xin lỗi kiểu ChatGPT
                return True, "bash: syntax error near unexpected token `newline'\n"
        return False, ""
