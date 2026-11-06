import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from config import EVENT_LOG_FILE, LOGS_DIR
from threat_intel.mitre_mapper import MitreMapper

SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SESSIONS_LOG_FILE = LOGS_DIR / "sessions.json"

class HoneypotLogger:
    """
    Production-grade CTI Logger for Adaptive Honeypot.
    Outputs 100% MITRE ATT&CK for Enterprise labeled events and sessions in real time.
    """
    def __init__(self, log_path: Path = EVENT_LOG_FILE, sessions_path: Path = SESSIONS_LOG_FILE):
        self.log_path = log_path
        self.sessions_path = sessions_path
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

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
                "attacker": {
                    "ip": source_ip,
                    "port": source_port,
                    "username": username,
                    "passwords_tried": [],
                    "auth_status": "Unknown"
                },
                "duration": {
                    "start_time": now,
                    "end_time": now,
                    "duration_seconds": 0.0
                },
                "threat_analysis": {
                    "scenario": "Initial Connection Probe",
                    "highest_severity": "Low",
                    "command_count": 0,
                    "termination": "Active",
                    "mitre_tactics": set(),
                    "mitre_techniques": set()
                },
                "timeline": []
            }
        sess = self.active_sessions[session_id]
        if source_ip and not sess["attacker"]["ip"]: sess["attacker"]["ip"] = source_ip
        if source_port and not sess["attacker"]["port"]: sess["attacker"]["port"] = source_port
        if username and not sess["attacker"]["username"]: sess["attacker"]["username"] = username
        return sess

    def _update_session_severity(self, session: Dict[str, Any], severity: str):
        current_sev = session["threat_analysis"]["highest_severity"]
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(current_sev, 0):
            session["threat_analysis"]["highest_severity"] = severity

    def _flush_session_to_json(self, session_id: str):
        """Lưu hoặc cập nhật session vào tệp logs/sessions.json chuẩn indent=2"""
        if session_id not in self.active_sessions:
            return
        
        sess_data = self.active_sessions.pop(session_id)
        
        # Format set thành sorted list
        export_sess = {
            "session_id": sess_data["session_id"],
            "attacker": sess_data["attacker"],
            "duration": sess_data["duration"],
            "threat_analysis": {
                "scenario": sess_data["threat_analysis"]["scenario"],
                "highest_severity": sess_data["threat_analysis"]["highest_severity"],
                "command_count": sess_data["threat_analysis"]["command_count"],
                "termination": sess_data["threat_analysis"]["termination"],
                "mitre_tactics": sorted(list(sess_data["threat_analysis"]["mitre_tactics"])),
                "mitre_techniques": sorted(list(sess_data["threat_analysis"]["mitre_techniques"]))
            },
            "timeline": sess_data["timeline"]
        }

        try:
            sessions_list = []
            if self.sessions_path.exists():
                try:
                    with open(self.sessions_path, "r", encoding="utf-8") as f:
                        sessions_list = json.load(f)
                except Exception:
                    sessions_list = []

            # Tránh trùng session_id nếu đã tồn tại
            sessions_list = [s for s in sessions_list if s.get("session_id") != session_id]
            sessions_list.insert(0, export_sess)

            with open(self.sessions_path, "w", encoding="utf-8") as f:
                json.dump(sessions_list, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def log_connection(self, source_ip: str, source_port: int, status: str = "Connected"):
        """Ghi nhận sự kiện kết nối socket SSH thô (hỗ trợ phát hiện port scan / banner grab)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session_id = str(uuid.uuid4())
        
        mitre_block = MitreMapper.map_connection(status)

        event_record = {
            "event_key": f"{now}:{session_id}:Connection",
            "timestamp": now,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": "SSH",
            "session_id": session_id,
            "event_status": status,
            "message": f"SSH Raw Connection {status}",
            "macro_class": mitre_block.get("macro_class", "Port Scan & Connection Probe"),
            "mitre_attack": mitre_block,
            "mitre_tactic": mitre_block["tactic_name"],
            "mitre_technique_id": mitre_block["technique_id"],
            "mitre_technique_name": mitre_block["technique_name"],
            "scenario": mitre_block["scenario"],
            "severity": mitre_block["severity"],
            "mitre_techniques": [{
                "technique_id": mitre_block["technique_id"],
                "technique_name": mitre_block["technique_name"],
                "tactic": mitre_block["tactic_name"]
            }],
            "ingested_at": now
        }
        self._write_event(event_record)

        if status == "Immediate_Exit":
            sess = self._get_or_create_session(session_id, source_ip, source_port)
            sess["threat_analysis"]["termination"] = "Immediate_Exit"
            sess["threat_analysis"]["scenario"] = "Port Scan & Connection Probe"
            sess["threat_analysis"]["mitre_tactics"].add(f"{mitre_block['tactic_id']} - {mitre_block['tactic_name']}")
            sess["threat_analysis"]["mitre_techniques"].add(f"{mitre_block['technique_id']} - {mitre_block['technique_name']}")
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
        """Ghi nhận lại toàn bộ nỗ lực đăng nhập (thành công hoặc dò mật khẩu thất bại)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not session_id:
            session_id = str(uuid.uuid4())
        event_key = f"{now}:{session_id}:Auth"
        
        mitre_block = MitreMapper.map_auth(success, username, password)

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
            "message": f"SSH Auth {'Success' if success else 'Failed'} for user '{username}'",
            "macro_class": mitre_block.get("macro_class", "SSH Password Guessing"),
            "mitre_attack": mitre_block,
            "mitre_tactic": mitre_block["tactic_name"],
            "mitre_technique_id": mitre_block["technique_id"],
            "mitre_technique_name": mitre_block["technique_name"],
            "scenario": mitre_block["scenario"],
            "severity": mitre_block["severity"],
            "mitre_techniques": [{
                "technique_id": mitre_block["technique_id"],
                "technique_name": mitre_block["technique_name"],
                "tactic": mitre_block["tactic_name"]
            }],
            "ingested_at": now
        }

        self._write_event(event_record)

        # Cập nhật session bộ nhớ
        sess = self._get_or_create_session(session_id, source_ip, source_port, username)
        if password and password not in sess["attacker"]["passwords_tried"]:
            sess["attacker"]["passwords_tried"].append(password)
        sess["attacker"]["auth_status"] = "Success" if success else "Failed"
        sess["duration"]["end_time"] = now
        sess["threat_analysis"]["mitre_tactics"].add(f"{mitre_block['tactic_id']} - {mitre_block['tactic_name']}")
        sess["threat_analysis"]["mitre_techniques"].add(f"{mitre_block['technique_id']} - {mitre_block['technique_name']}")
        self._update_session_severity(sess, mitre_block["severity"])

        if not success:
            sess["threat_analysis"]["scenario"] = "SSH Password Guessing (Brute Force)"
            self._flush_session_to_json(session_id)

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
        """Ghi nhận chi tiết từng câu lệnh tương tác và phản hồi của Honeypot."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        event_key = f"{now}:{session_id}:Interaction"
        
        # Tự động gán nhãn MITRE chuẩn xác bằng MitreMapper
        mitre_block = MitreMapper.map_command(command)

        clean_output = command_output.rstrip("\r\n") if command_output else ""

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
            "command_output": clean_output,
            "handler_type": handler_type,
            "latency_ms": round(latency_ms, 2),
            "macro_class": mitre_block.get("macro_class", "Command Execution & Scripting"),
            "mitre_attack": mitre_block,
            "mitre_tactic": mitre_block["tactic_name"],
            "mitre_technique_id": mitre_block["technique_id"],
            "mitre_technique_name": mitre_block["technique_name"],
            "scenario": mitre_block["scenario"],
            "severity": mitre_block["severity"],
            "mitre_techniques": [{
                "technique_id": mitre_block["technique_id"],
                "technique_name": mitre_block["technique_name"],
                "tactic": mitre_block["tactic_name"]
            }],
            "ebpf_monitored": False,
            "ingested_at": now
        }

        self._write_event(event_record)

        # Cập nhật timeline cho session
        sess = self._get_or_create_session(session_id, source_ip, source_port, username)
        sess["duration"]["end_time"] = now
        sess["threat_analysis"]["command_count"] += 1
        sess["threat_analysis"]["mitre_tactics"].add(f"{mitre_block['tactic_id']} - {mitre_block['tactic_name']}")
        sess["threat_analysis"]["mitre_techniques"].add(f"{mitre_block['technique_id']} - {mitre_block['technique_name']}")
        self._update_session_severity(sess, mitre_block["severity"])

        # Timeline item
        sess["timeline"].append({
            "step": len(sess["timeline"]) + 1,
            "timestamp": now,
            "command": command,
            "output": clean_output,
            "handler": handler_type,
            "latency_ms": round(latency_ms, 2),
            "mitre_technique": f"{mitre_block['technique_id']} [{mitre_block['tactic_name']}]: {mitre_block['technique_name']}"
        })

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
        """Ghi nhận đóng phiên (phân biệt ngắt bất thường vs đóng phiên bình thường)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        is_abrupt = (reason != "normal")
        
        if is_abrupt:
            mitre_block = {
                "tactic_id": "TA0005",
                "tactic_name": "Defense Evasion",
                "technique_id": "T1070",
                "technique_name": "Indicator Removal: Abnormal Session Drop",
                "subtechnique_id": None,
                "scenario": "Indicator Removal: Abnormal Session Drop",
                "severity": "Medium"
            }
        else:
            mitre_block = {
                "tactic_id": "TA0002",
                "tactic_name": "Execution",
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Normal Terminal Exit",
                "subtechnique_id": None,
                "scenario": "Normal Terminal Shell Exit",
                "severity": "Info"
            }

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
            "mitre_attack": mitre_block,
            "mitre_tactic": mitre_block["tactic_name"],
            "mitre_technique_id": mitre_block["technique_id"],
            "mitre_technique_name": mitre_block["technique_name"],
            "scenario": mitre_block["scenario"],
            "severity": mitre_block["severity"],
            "mitre_techniques": [{
                "technique_id": mitre_block["technique_id"],
                "technique_name": mitre_block["technique_name"],
                "tactic": mitre_block["tactic_name"]
            }],
            "ingested_at": now
        }
        self._write_event(event_record)

        # Cập nhật và lưu vào sessions.json
        sess = self._get_or_create_session(session_id, source_ip, source_port, username)
        sess["duration"]["end_time"] = now
        sess["duration"]["duration_seconds"] = round(duration_sec, 2)
        sess["threat_analysis"]["termination"] = "Abnormal_Drop" if is_abrupt else "Normal_Exit"
        sess["threat_analysis"]["mitre_tactics"].add(f"{mitre_block['tactic_id']} - {mitre_block['tactic_name']}")
        sess["threat_analysis"]["mitre_techniques"].add(f"{mitre_block['technique_id']} - {mitre_block['technique_name']}")

        # Xác định scenario chung của session
        cmds = [item["command"].lower() for item in sess["timeline"]]
        cmds_str = " ".join(cmds)
        if any(x in cmds_str for x in ["curl", "wget", "malware", ".sh", ".elf"]):
            sess["threat_analysis"]["scenario"] = "C2 Ingress Tool Transfer & Malware Staging"
        elif "sudo" in cmds_str or "su " in cmds_str or "id_rsa" in cmds_str or "/etc/shadow" in cmds_str:
            sess["threat_analysis"]["scenario"] = "Privilege Escalation & Sensitive Credential Access"
        elif any(x in cmds_str for x in ["crontab", "/etc/cron"]):
            sess["threat_analysis"]["scenario"] = "Persistence via Scheduled Jobs (Cron)"
        elif any(x in cmds_str for x in ["history -c", "rm -rf"]):
            sess["threat_analysis"]["scenario"] = "Defense Evasion & History Deletion"
        elif any(x in cmds_str for x in ["uname", "whoami", "ip a", "netstat", "ps aux", "passwd"]):
            sess["threat_analysis"]["scenario"] = "System & Network Environment Discovery"
        elif sess["timeline"]:
            sess["threat_analysis"]["scenario"] = "Interactive Shell Exploration"

        self._flush_session_to_json(session_id)

        return event_record
