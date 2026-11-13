import json
import uuid
import datetime
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List, Optional
from config import EVENT_LOG_FILE, LOGS_DIR, ENABLE_THREAT_LABELING
from threat_intel.mitre_mapper import MitreMapper
from threat_intel.ml_exporter import MLLogExporter
from threat_intel.misp_comparator import misp_comparator

SESSIONS_LOG_FILE = LOGS_DIR / "sessions.json"
UNLABELED_SESSIONS_FILE = LOGS_DIR / "unlabeled_sessions.jsonl"

class HoneypotLogger:
    """
    Standard Operational & AI-driven CTI Logger for Adaptive SSH Honeypot.
    Cơ chế gán nhãn MITRE ATT&CK thời gian thực 1:1:
    Mỗi khi một log sự kiện (kết nối, xác thực, lệnh thực thi) vừa sinh ra,
    AI Engine lập tức phân tích và gắn nhãn MITRE ATT&CK (Tactic, Technique ID,
    Severity, Macro-Class) trực tiếp vào chính bản ghi đó.
    """
    def __init__(self, log_path: Path = EVENT_LOG_FILE, sessions_path: Path = SESSIONS_LOG_FILE):
        self.log_path = log_path
        self.sessions_path = sessions_path
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        try:
            self.ml_exporter = MLLogExporter(dataset_role="benchmark")
        except Exception:
            self.ml_exporter = None

    def _write_event(self, event_record: Dict[str, Any]):
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_record, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _get_or_create_session(self, session_id: str, source_ip: str, source_port: int, username: str = "") -> Dict[str, Any]:
        if session_id not in self.active_sessions:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.active_sessions[session_id] = {
                "session_id": session_id,
                "source_ip": source_ip,
                "source_port": source_port,
                "username": username,
                "passwords_tried": [],
                "auth_status": "Unknown",
                "start_time": now,
                "end_time": now,
                "duration_seconds": 0.0,
                "command_count": 0,
                "status": "Active",
                "commands": []
            }
        sess = self.active_sessions[session_id]
        if source_ip and not sess["source_ip"]:
            sess["source_ip"] = source_ip
        if source_port and not sess["source_port"]:
            sess["source_port"] = source_port
        if username and not sess["username"]:
            sess["username"] = username
        return sess

    def _flush_session_to_json(self, session_id: str):
        """
        Lưu hoặc cập nhật session vào tệp logs/sessions.json chuẩn indent=2
        và logs/unlabeled_sessions.jsonl phục vụ mô hình AI Machine Learning & đối soát MISP.
        """
        if session_id not in self.active_sessions:
            return
        
        sess_data = self.active_sessions.pop(session_id)

        # 1. Trích xuất danh sách lệnh sạch
        commands_list = []
        for c in sess_data.get("commands", []):
            if isinstance(c, dict) and "command" in c:
                cmd_str = str(c["command"]).strip()
                if cmd_str:
                    commands_list.append(cmd_str)
            elif isinstance(c, str):
                cmd_str = c.strip()
                if cmd_str:
                    commands_list.append(cmd_str)

        # Nếu phiên kết thúc bình thường và lệnh cuối chưa có exit
        if sess_data.get("status") == "Closed" and commands_list and commands_list[-1] != "exit":
            commands_list.append("exit")

        # 2. Xây dựng chuỗi full_session cách nhau bởi " ; " và kết thúc bằng " ;" (chuẩn file train parquet)
        full_session = " ; ".join(commands_list) + " ;" if commands_list else ""

        # 3. Chuẩn hóa first_timestamp: "YYYY-MM-DD HH:MM:SS"
        start_raw = sess_data.get("start_time", "")
        try:
            dt = datetime.datetime.fromisoformat(start_raw.replace("Z", "+00:00"))
            first_ts = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            first_ts = start_raw

        last_pass = sess_data["passwords_tried"][-1] if sess_data.get("passwords_tried") else "123456"

        # 4. Bản ghi log CHƯA GÁN NHÃN (Raw Unlabeled Log)
        unlabeled_session = {
            "session_id": sess_data["session_id"],
            "attacker_ip": sess_data["source_ip"],
            "attacker_port": sess_data["source_port"],
            "timestamp": sess_data["start_time"],
            "first_timestamp": first_ts,
            "auth": {
                "username": sess_data["username"] or "root",
                "password": last_pass
            },
            "commands": commands_list,
            "full_session": full_session
        }

        # Lưu bản ghi chưa gán nhãn vào stream file logs/unlabeled_sessions.jsonl
        try:
            with open(UNLABELED_SESSIONS_FILE, "a", encoding="utf-8") as uf:
                uf.write(json.dumps(unlabeled_session, ensure_ascii=False) + "\n")
        except Exception:
            pass

        # 5. Tự động đối soát với MISP IoC Database
        misp_result = None
        try:
            misp_result = misp_comparator.compare_session(unlabeled_session)
        except Exception:
            pass

        # 6. Bản ghi lưu vào sessions.json (đầy đủ để Dashboard đọc & kiểm tra)
        export_sess = {
            "session_id": sess_data["session_id"],
            "attacker_ip": sess_data["source_ip"],
            "attacker_port": sess_data["source_port"],
            "timestamp": sess_data["start_time"],
            "first_timestamp": first_ts,
            "auth": {
                "username": sess_data["username"] or "root",
                "password": last_pass
            },
            "commands": commands_list,
            "full_session": full_session,
            "source_ip": sess_data["source_ip"],
            "source_port": sess_data["source_port"],
            "username": sess_data["username"],
            "passwords_tried": sess_data["passwords_tried"],
            "auth_status": sess_data["auth_status"],
            "start_time": sess_data["start_time"],
            "end_time": sess_data["end_time"],
            "duration_seconds": sess_data["duration_seconds"],
            "command_count": len(commands_list),
            "status": sess_data["status"],
            "misp_intel": misp_result,
            "command_timeline": sess_data["commands"]
        }

        try:
            sessions_list = []
            if self.sessions_path.exists():
                try:
                    with open(self.sessions_path, "r", encoding="utf-8") as f:
                        sessions_list = json.load(f)
                except Exception:
                    sessions_list = []

            sessions_list = [s for s in sessions_list if s.get("session_id") != session_id]
            sessions_list.insert(0, export_sess)

            with open(self.sessions_path, "w", encoding="utf-8") as f:
                json.dump(sessions_list, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def log_connection(self, source_ip: str, source_port: int, status: str = "Connected"):
        """Ghi nhận sự kiện kết nối SSH và gán nhãn MITRE thời gian thực 1:1."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session_id = str(uuid.uuid4())

        mitre_info = MitreMapper.map_connection(status)

        event_record = {
            "timestamp": now,
            "session_id": session_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "event_type": "Connection",
            "event_status": status,
            "message": f"SSH connection {status}",
            "macro_class": mitre_info["macro_class"],
            "mitre_framework": mitre_info["framework"],
            "mitre_tactic": mitre_info["tactic_name"],
            "mitre_tactic_id": mitre_info["tactic_id"],
            "mitre_technique_id": mitre_info["technique_id"],
            "mitre_technique_name": mitre_info["technique_name"],
            "subtechnique_id": mitre_info["subtechnique_id"],
            "severity": mitre_info["severity"],
            "scenario": mitre_info["scenario"],
            "ai_labeling": {
                "assigned_by": "Adaptive-AI-Engine",
                "mode": "REALTIME_1_TO_1",
                "timestamp": now,
                "confidence": 1.0
            },
            "mitre_matches": [
                {
                    "id": mitre_info["technique_id"],
                    "name": mitre_info["technique_name"],
                    "tactic": mitre_info["tactic_name"]
                }
            ]
        }

        self._write_event(event_record)

        if status == "Immediate_Exit":
            sess = self._get_or_create_session(session_id, source_ip, source_port)
            sess["status"] = "Immediate_Exit"
            sess["end_time"] = now
            self._flush_session_to_json(session_id)

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
        """Ghi nhận sự kiện xác thực SSH và gán nhãn MITRE 1:1 trực tiếp bởi AI."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not session_id:
            session_id = str(uuid.uuid4())

        mitre_info = MitreMapper.map_auth(success, username, password)

        safe_user = urllib.parse.quote(username, safe="")
        safe_pass = urllib.parse.quote(password, safe="")

        event_record = {
            "timestamp": now,
            "session_id": session_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "event_type": "Authentication",
            "username": username,
            "password": password,
            "encoded_username": safe_user,
            "encoded_password": safe_pass,
            "auth_success": success,
            "is_admin": is_admin,
            "event_status": "Auth_Success" if success else "Auth_Failed",
            "message": f"SSH login {'successful' if success else 'failed'} for user '{username}'",
            "macro_class": mitre_info["macro_class"],
            "mitre_framework": mitre_info["framework"],
            "mitre_tactic": mitre_info["tactic_name"],
            "mitre_tactic_id": mitre_info["tactic_id"],
            "mitre_technique_id": mitre_info["technique_id"],
            "mitre_technique_name": mitre_info["technique_name"],
            "subtechnique_id": mitre_info["subtechnique_id"],
            "severity": mitre_info["severity"],
            "scenario": mitre_info["scenario"],
            "ai_labeling": {
                "assigned_by": "Adaptive-AI-Engine",
                "mode": "REALTIME_1_TO_1",
                "timestamp": now,
                "confidence": 1.0
            },
            "mitre_matches": [
                {
                    "id": mitre_info["technique_id"],
                    "name": mitre_info["technique_name"],
                    "tactic": mitre_info["tactic_name"]
                }
            ]
        }

        self._write_event(event_record)

        sess = self._get_or_create_session(session_id, source_ip, source_port, username)
        if password and password not in sess["passwords_tried"]:
            sess["passwords_tried"].append(password)
        sess["auth_status"] = "Success" if success else "Failed"
        sess["end_time"] = now

        if not success:
            sess["status"] = "Auth_Failed"
            self._flush_session_to_json(session_id)

        if self.ml_exporter:
            try:
                if success:
                    self.ml_exporter.emit_login(session_id, source_ip, source_port, username)
                else:
                    self.ml_exporter.emit_login_failed(session_id, source_ip, source_port, username)
            except Exception:
                pass

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
        mitre_matches: Optional[Any] = None
    ):
        """
        Ghi nhận lệnh được thực thi và gán nhãn MITRE ATT&CK thời gian thực 1:1.
        Vừa sinh ra log thì AI đã hoàn thành gắn nhãn đó ngay lập tức trong sự kiện.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        clean_output = command_output.rstrip("\r\n") if command_output else ""

        # Gán nhãn trực tiếp bằng AI MitreMapper 1:1 ngay lúc lệnh được thực thi
        mitre_info = MitreMapper.map_command(command)

        event_record = {
            "timestamp": now,
            "session_id": session_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "event_type": "Command",
            "username": username,
            "event_status": "Interaction",
            "command": command,
            "command_output": clean_output,
            "handler_type": handler_type,
            "latency_ms": round(latency_ms, 2),
            "macro_class": mitre_info["macro_class"],
            "mitre_framework": mitre_info["framework"],
            "mitre_tactic": mitre_info["tactic_name"],
            "mitre_tactic_id": mitre_info["tactic_id"],
            "mitre_technique_id": mitre_info["technique_id"],
            "mitre_technique_name": mitre_info["technique_name"],
            "subtechnique_id": mitre_info["subtechnique_id"],
            "severity": mitre_info["severity"],
            "scenario": mitre_info["scenario"],
            "ai_labeling": {
                "assigned_by": f"Adaptive-AI-{handler_type}",
                "mode": "REALTIME_1_TO_1",
                "timestamp": now,
                "confidence": 1.0
            },
            "mitre_matches": [
                {
                    "id": mitre_info["technique_id"],
                    "name": mitre_info["technique_name"],
                    "tactic": mitre_info["tactic_name"]
                }
            ]
        }

        self._write_event(event_record)

        # Cập nhật hồ sơ phiên với đầy đủ thông tin nhãn MITRE 1:1 của AI
        sess = self._get_or_create_session(session_id, source_ip, source_port, username)
        sess["end_time"] = now
        sess["command_count"] += 1
        sess["commands"].append({
            "step": len(sess["commands"]) + 1,
            "timestamp": now,
            "command": command,
            "output": clean_output,
            "handler_type": handler_type,
            "latency_ms": round(latency_ms, 2),
            "macro_class": mitre_info["macro_class"],
            "mitre_tactic": mitre_info["tactic_name"],
            "mitre_technique_id": mitre_info["technique_id"],
            "mitre_technique_name": mitre_info["technique_name"],
            "severity": mitre_info["severity"],
            "ai_verified": True
        })

        if self.ml_exporter:
            try:
                self.ml_exporter.emit_command(session_id, source_ip, source_port, username, command, clean_output)
            except Exception:
                pass

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
        """Ghi nhận kết thúc phiên SSH và lưu hồ sơ phiên sạch."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        event_record = {
            "timestamp": now,
            "session_id": session_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "event_type": "Session_End",
            "username": username,
            "event_status": "Closed",
            "duration_seconds": round(duration_sec, 2),
            "commands_count": commands_count,
            "reason": reason,
            "message": f"SSH session closed ({reason})"
        }
        self._write_event(event_record)

        sess = self._get_or_create_session(session_id, source_ip, source_port, username)
        sess["end_time"] = now
        sess["duration_seconds"] = round(duration_sec, 2)
        sess["status"] = "Closed"
        self._flush_session_to_json(session_id)

        if self.ml_exporter:
            try:
                self.ml_exporter.emit_session_closed(session_id, source_ip, source_port, username)
                self.ml_exporter.finalize_run()
            except Exception:
                pass

        return event_record
