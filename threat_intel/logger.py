import json
import uuid
import datetime
import urllib.parse
import queue
import threading
import requests
from pathlib import Path
from typing import Dict, Any, List, Optional
from config import EVENT_LOG_FILE, LOGS_DIR, LOG_FORWARD_ENABLED, LOG_FORWARD_URL
from threat_intel.ml_exporter import MLLogExporter

try:
    from forwarder import HoneypotForwarder
    forwarder = HoneypotForwarder()
except Exception:
    forwarder = None

SESSIONS_LOG_FILE = LOGS_DIR / "sessions.json"

class HoneypotLogger:
    """
    Standard Operational Logger for Adaptive SSH Honeypot.
    Ghi nhận log sự kiện thô nguyên bản (Raw Event Logs) phục vụ giám sát hoạt động,
    hoàn toàn không gán nhãn MITRE hay gán nhãn bài toán Học máy (Unlabeled Logs).
    Tích hợp bộ chuyển tiếp bất đồng bộ (Asynchronous Log Forwarder) bắn log thời gian thực sang Máy 2 (Port 8000).
    """
    def __init__(self, log_path: Path = EVENT_LOG_FILE, sessions_path: Path = SESSIONS_LOG_FILE):
        self.log_path = log_path
        self.sessions_path = sessions_path
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        try:
            self.ml_exporter = MLLogExporter(dataset_role="benchmark")
        except Exception:
            self.ml_exporter = None

        # Khởi tạo hàng đợi ngầm chuyển tiếp log sang Máy 2
        self.log_forward_enabled = LOG_FORWARD_ENABLED
        self.log_forward_url = LOG_FORWARD_URL
        self.forward_queue: Optional[queue.Queue] = None
        if self.log_forward_enabled and self.log_forward_url:
            self.forward_queue = queue.Queue(maxsize=10000)
            self.forward_thread = threading.Thread(target=self._log_forwarder_worker, daemon=True)
            self.forward_thread.start()

    def _log_forwarder_worker(self):
        """Worker thread ngầm bắn log sang API tiếp nhận của Máy 2 (Port 8000)."""
        while True:
            try:
                record = self.forward_queue.get()
                if record is None:
                    break
                try:
                    requests.post(self.log_forward_url, json=record, timeout=3.0)
                except Exception:
                    # Rớt mạng hoặc Máy 2 chưa bật thì bỏ qua an toàn, không làm treo hệ thống
                    pass
                finally:
                    self.forward_queue.task_done()
            except Exception:
                pass

    def _write_event(self, event_record: Dict[str, Any]):
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_record, ensure_ascii=False) + "\n")
        except Exception:
            pass

        # Đẩy sự kiện vào hàng đợi ngầm để bắn sang Máy 2
        if self.log_forward_enabled and self.forward_queue:
            try:
                self.forward_queue.put_nowait(event_record)
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
        """Lưu hoặc cập nhật session vào tệp logs/sessions.json chuẩn indent=2"""
        if session_id not in self.active_sessions:
            return
        
        sess_data = self.active_sessions.pop(session_id)

        export_sess = {
            "session_id": sess_data["session_id"],
            "source_ip": sess_data["source_ip"],
            "source_port": sess_data["source_port"],
            "username": sess_data["username"],
            "passwords_tried": sess_data["passwords_tried"],
            "auth_status": sess_data["auth_status"],
            "start_time": sess_data["start_time"],
            "end_time": sess_data["end_time"],
            "duration_seconds": sess_data["duration_seconds"],
            "command_count": sess_data["command_count"],
            "status": sess_data["status"],
            "commands": sess_data["commands"]
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

        # Bắn log SSH Honeypot (Commands, Session) sang Máy 1
        if forwarder:
            try:
                commands_list = [c["command"] for c in sess_data.get("commands", []) if isinstance(c, dict) and "command" in c]
                if not commands_list:
                    commands_list = [str(c) for c in sess_data.get("commands", [])]
                if commands_list:
                    forwarder.send_ssh_attack(
                        attacker_ip=sess_data.get("source_ip", "127.0.0.1"),
                        commands=commands_list,
                        username=sess_data.get("username", "root")
                    )
            except Exception as e:
                print(f"[!] Forward SSH log lỗi: {e}")

    def log_connection(self, source_ip: str, source_port: int, status: str = "Connected"):
        """Ghi nhận sự kiện kết nối socket SSH thông thường."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session_id = str(uuid.uuid4())
        
        event_record = {
            "timestamp": now,
            "session_id": session_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "event_type": "Connection",
            "event_status": status,
            "message": f"SSH connection {status}"
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
        """Ghi nhận sự kiện xác thực SSH thông thường."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not session_id:
            session_id = str(uuid.uuid4())

        event_record = {
            "timestamp": now,
            "session_id": session_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "event_type": "Authentication",
            "username": username,
            "password": password,
            "auth_success": success,
            "is_admin": is_admin,
            "event_status": "Auth_Success" if success else "Auth_Failed",
            "message": f"SSH login {'successful' if success else 'failed'} for user '{username}'"
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
        """Ghi nhận lệnh được thực thi và phản hồi của AI Honeypot (không gán nhãn)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        clean_output = command_output.rstrip("\r\n") if command_output else ""

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
            "latency_ms": round(latency_ms, 2)
        }
        self._write_event(event_record)

        # Cập nhật session
        sess = self._get_or_create_session(session_id, source_ip, source_port, username)
        sess["end_time"] = now
        sess["command_count"] += 1
        sess["commands"].append({
            "step": len(sess["commands"]) + 1,
            "timestamp": now,
            "command": command,
            "output": clean_output,
            "handler_type": handler_type,
            "latency_ms": round(latency_ms, 2)
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
        """Ghi nhận kết thúc phiên SSH thông thường."""
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
