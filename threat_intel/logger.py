import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any, List
from config import EVENT_LOG_FILE

class HoneypotLogger:
    """
    Ghi nhật ký sự kiện có cấu trúc chuẩn JSON Lines.
    Đầu ra tương thích với hệ thống phân tích CTI, Elasticsearch, SQLite và Neo4j.
    """
    def __init__(self, log_path: Path = EVENT_LOG_FILE):
        self.log_path = log_path

    def _write_event(self, event_record: Dict[str, Any]):
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_record, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def log_connection(self, source_ip: str, source_port: int, status: str = "Connected"):
        """Ghi nhận sự kiện kết nối socket SSH thô (hỗ trợ phát hiện port scan, kết nối rồi thoát ngay)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session_id = str(uuid.uuid4())
        event_record = {
            "event_key": f"{now}:{session_id}:Connection",
            "timestamp": now,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "session_id": session_id,
            "event_status": status,
            "message": f"SSH Raw Connection {status}",
            "mitre_techniques": [{
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "tactic": "Discovery"
            }] if status == "Immediate_Exit" else [],
            "ingested_at": now
        }
        self._write_event(event_record)
        return event_record

    def log_auth_attempt(
        self,
        source_ip: str,
        source_port: int,
        username: str,
        password: str,
        success: bool,
        session_id: str = None,
        is_admin: bool = False
    ):
        """Ghi nhận lại toàn bộ nỗ lực đăng nhập (thành công hoặc dò mật khẩu thất bại)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not session_id:
            session_id = str(uuid.uuid4())
        event_key = f"{now}:{session_id}:Auth"
        
        mitre_matches = []
        if not success:
            mitre_matches = [{
                "technique_id": "T1110",
                "technique_name": "Brute Force / Password Guessing",
                "tactic": "Credential Access"
            }]

        event_record = {
            "event_key": event_key,
            "timestamp": now,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "session_id": session_id,
            "username": username,
            "password": password,
            "auth_success": success,
            "is_admin": is_admin,
            "event_status": "Auth_Success" if success else "Auth_Failed",
            "message": f"SSH Auth {'Thành công' if success else 'Thất bại'} cho user '{username}'",
            "mitre_techniques": mitre_matches,
            "ingested_at": now
        }

        self._write_event(event_record)
        return event_record

    def log_interaction(
        self,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: str,
        command: str,
        command_output: str,
        handler_type: str,
        latency_ms: float,
        mitre_matches: List[Dict[str, str]]
    ):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        event_key = f"{now}:{session_id}:Interaction"
        
        event_record = {
            "event_key": event_key,
            "timestamp": now,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "session_id": session_id,
            "username": username,
            "event_status": "Interaction",
            "message": "SSH Terminal Session Interaction",
            "command": command,
            "command_output": command_output.rstrip("\r\n"),
            
            # Các trường nâng cao độc quyền của nhóm
            "handler_type": handler_type,
            "latency_ms": round(latency_ms, 2),
            "mitre_techniques": mitre_matches,
            "ebpf_monitored": False, # Sẽ bật khi deploy trên Linux có eBPF
            
            "ingested_at": now
        }

        self._write_event(event_record)
        return event_record

    def log_session_end(
        self,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: str,
        duration_sec: float,
        commands_count: int,
        reason: str = "normal"
    ):
        """Ghi nhận đóng phiên (hỗ trợ phân biệt thoát tự nhiên vs ngắt đột ngột / timeout)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        is_abrupt = (reason != "normal")
        event_record = {
            "event_key": f"{now}:{session_id}:Session_End",
            "timestamp": now,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "session_id": session_id,
            "username": username,
            "event_status": "Session_Aborted" if is_abrupt else "Session_End",
            "message": f"SSH Session Closed ({reason})",
            "duration_seconds": round(duration_sec, 2),
            "commands_count": commands_count,
            "abnormal_termination": is_abrupt,
            "mitre_techniques": [],
            "ingested_at": now
        }
        self._write_event(event_record)
        return event_record
