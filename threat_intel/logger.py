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

        # Ghi append vào file JSONL
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_record, ensure_ascii=False) + "\n")
            
        return event_record
