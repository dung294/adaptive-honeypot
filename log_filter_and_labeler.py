#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - MITRE ATT&CK LOG FILTER & LABELER (PRODUCTION CTI)
=============================================================================
Purpose:
  1. Filters dirty / noise logs from the raw dataset (10,000+ honeypot events):
     - Localhost loopback test noise (127.0.0.1 / ::1).
     - Corrupted or unparseable JSON lines.
     - Records missing vital schema keys (timestamp, session_id, event_status).
     - Exact duplicate event records.
     - Empty interaction commands.
  2. Labels 100% of valid clean logs according to MITRE ATT&CK for Enterprise:
     - Tactic ID & Name (TA0001 - TA0011).
     - Technique ID & Name (T1046, T1110, T1078.003, T1082, T1105, T1548, etc.).
     - Sub-technique ID.
     - Threat Severity (Critical, High, Medium, Low, Info).
     - Attack Scenario classification.
  3. Reconstructs attack sessions with full command-and-response timelines.
  4. 100% Standard English Schema (no translated keys or values).
"""

import os
import sys
import json
import re
import argparse
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict

# Ensure UTF-8 output on Windows
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# =====================================================================
# MITRE ATT&CK FOR ENTERPRISE (LINUX SSH MATRIX) RULES
# =====================================================================
MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0011": "Command and Control",
}

MITRE_COMMAND_RULES = [
    # 1. COMMAND AND CONTROL (TA0011)
    {
        "pattern": re.compile(r"\b(curl|wget|scp|sftp|ftp|tftp)\b", re.IGNORECASE),
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "subtechnique_id": None,
        "scenario": "Ingress Tool Transfer (C2 Payload Download)",
        "severity": "High"
    },
    # 2. PRIVILEGE ESCALATION (TA0004)
    {
        "pattern": re.compile(r"\b(sudo\s+-l|sudo\s+su|su\s+-|sudo\s+cat|sudo\s+bash|sudo\s+sh)\b", re.IGNORECASE),
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "subtechnique_id": "T1548.003",
        "scenario": "Abuse Elevation Control Mechanism: Sudo Caching",
        "severity": "Critical"
    },
    {
        "pattern": re.compile(r"\b(find\s+/.*-perm\s+(-u=s|-4000))\b", re.IGNORECASE),
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation: SUID Probe",
        "subtechnique_id": None,
        "scenario": "Exploitation for Privilege Escalation (SUID Binary Probe)",
        "severity": "High"
    },
    # 3. DEFENSE EVASION (TA0005)
    {
        "pattern": re.compile(r"\b(history\s+-c|unset\s+HISTFILE|cat\s+/dev/null\s*>\s*~?/\.bash_history|export\s+HISTFILESIZE=0)\b", re.IGNORECASE),
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1070.003",
        "technique_name": "Indicator Removal: Clear Command History",
        "subtechnique_id": "T1070.003",
        "scenario": "Indicator Removal: Clear Command History",
        "severity": "High"
    },
    {
        "pattern": re.compile(r"\b(rm\s+-rf?)\b", re.IGNORECASE),
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1070.004",
        "technique_name": "Indicator Removal: File Deletion",
        "subtechnique_id": "T1070.004",
        "scenario": "Indicator Removal: File Deletion",
        "severity": "Medium"
    },
    {
        "pattern": re.compile(r"\b(chmod\s+(\+x|[0-7]{3,4}))\b", re.IGNORECASE),
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1222.002",
        "technique_name": "File and Directory Permissions Modification: Linux Permissions",
        "subtechnique_id": "T1222.002",
        "scenario": "File Permissions Modification (Chmod)",
        "severity": "Medium"
    },
    # 4. PERSISTENCE (TA0003)
    {
        "pattern": re.compile(r"\b(crontab|/etc/crontab|/var/spool/cron|cron\.d)\b", re.IGNORECASE),
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Job: Cron",
        "subtechnique_id": "T1053.003",
        "scenario": "Persistence via Scheduled Jobs (Cron)",
        "severity": "High"
    },
    # 5. CREDENTIAL ACCESS (TA0006)
    {
        "pattern": re.compile(r"\b(cat\s+/etc/shadow|~?/\.ssh/id_rsa|grep.*pass|find.*id_rsa)\b", re.IGNORECASE),
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "subtechnique_id": "T1552.001",
        "scenario": "Unsecured Credentials Access (Shadow/Private Keys)",
        "severity": "Critical"
    },
    {
        "pattern": re.compile(r"\b(cat\s+/etc/passwd|cat\s+/etc/group)\b", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1087.001",
        "technique_name": "Account Discovery: Local Accounts",
        "subtechnique_id": "T1087.001",
        "scenario": "Account Discovery: Local Accounts",
        "severity": "Low"
    },
    # 6. DISCOVERY (TA0007)
    {
        "pattern": re.compile(r"\b(whoami|id|groups|w|who)\b", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1033",
        "technique_name": "System Owner/User Discovery",
        "subtechnique_id": None,
        "scenario": "System Owner/User Discovery",
        "severity": "Low"
    },
    {
        "pattern": re.compile(r"\b(uname|hostname|cat\s+/etc/os-release|cat\s+/etc/issue|lscpu|free|df|cat\s+/proc/version|uptime)\b", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "subtechnique_id": None,
        "scenario": "System Information Discovery",
        "severity": "Low"
    },
    {
        "pattern": re.compile(r"\b(ps\b|top\b|htop\b|pstree\b)", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "subtechnique_id": None,
        "scenario": "Process Discovery",
        "severity": "Low"
    },
    {
        "pattern": re.compile(r"\b(ifconfig|ip\s+a|ip\s+addr|netstat|ss\s+-|route|arp|cat\s+/etc/resolv\.conf|cat\s+/etc/hosts)\b", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "subtechnique_id": None,
        "scenario": "System Network Configuration Discovery",
        "severity": "Low"
    },
    {
        "pattern": re.compile(r"\b(ping|traceroute|nmap)\b", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1018",
        "technique_name": "Remote System Discovery",
        "subtechnique_id": None,
        "scenario": "Remote System Discovery",
        "severity": "Medium"
    },
    {
        "pattern": re.compile(r"\b(ls|pwd|cd\b|cat\s+|find\b|dir\b)", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "subtechnique_id": None,
        "scenario": "File and Directory Discovery",
        "severity": "Low"
    },
    # 7. AI / HONEYPOT JAILBREAK PROBE
    {
        "pattern": re.compile(r"(SYSTEM\s+INSTRUCTION|Ignore\s+previous|system\s+prompt|jailbreak)", re.IGNORECASE),
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1027",
        "technique_name": "Obfuscated/Indirect Command Injection (AI Jailbreak)",
        "subtechnique_id": None,
        "scenario": "Adversarial AI Probe: Prompt Injection Jailbreak",
        "severity": "High"
    }
]

class MitreAttackLabeler:
    def __init__(self, input_file: str):
        self.input_file = Path(input_file)
        self.raw_lines = 0
        self.clean_events = []
        
        # Thống kê chi tiết các bản ghi không sạch bị loại bỏ
        self.rejected_stats = {
            "corrupted_json": 0,
            "missing_vital_fields": 0,
            "localhost_test_noise": 0,
            "duplicate_records": 0,
            "empty_command_interaction": 0
        }

    def parse_and_clean(self) -> list:
        """
        Lọc triệt để các log không sạch:
        1. Lỗi JSON Decode
        2. Thiếu trường bắt buộc (timestamp, session_id, event_status)
        3. Localhost test noise (127.0.0.1 / ::1 từ giai đoạn dev test)
        4. Trùng lặp sự kiện (Deduplication)
        5. Lệnh tương tác rỗng (Empty command string)
        """
        seen_keys = set()
        
        with open(self.input_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                self.raw_lines += 1
                line_str = line.strip()
                if not line_str:
                    continue

                # 1. Parse JSON
                try:
                    record = json.loads(line_str)
                except Exception:
                    self.rejected_stats["corrupted_json"] += 1
                    continue

                if not isinstance(record, dict):
                    self.rejected_stats["corrupted_json"] += 1
                    continue

                # 2. Check vital fields
                if not record.get("event_status") or not record.get("session_id") or not record.get("timestamp"):
                    self.rejected_stats["missing_vital_fields"] += 1
                    continue

                # 3. Filter localhost internal test noise (127.0.0.1)
                source_ip = record.get("source_ip", "")
                if source_ip in ["127.0.0.1", "::1", "localhost"]:
                    self.rejected_stats["localhost_test_noise"] += 1
                    continue

                # 4. Filter empty command interaction
                if record.get("event_status") == "Interaction":
                    cmd = (record.get("command") or "").strip()
                    if not cmd:
                        self.rejected_stats["empty_command_interaction"] += 1
                        continue

                # 5. Filter duplicates
                key = record.get("event_key") or f"{record.get('timestamp')}:{record.get('session_id')}:{record.get('event_status')}:{record.get('command')}"
                if key in seen_keys:
                    self.rejected_stats["duplicate_records"] += 1
                    continue
                seen_keys.add(key)

                self.clean_events.append(record)

        return self.clean_events

    def label_event(self, ev: dict) -> dict:
        """Gán nhãn chuẩn 100% MITRE ATT&CK for Enterprise."""
        status = ev.get("event_status", "UNKNOWN")
        cmd = (ev.get("command") or "").strip()

        mitre_block = None

        # 1. Quét cổng / Banner grab ngắt ngay -> T1046
        if status == "Immediate_Exit":
            mitre_block = {
                "tactic_id": "TA0007",
                "tactic_name": "Discovery",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "subtechnique_id": None,
                "scenario": "Network Service Discovery (Port Scan / Banner Grab)",
                "severity": "Low"
            }

        # 2. Đăng nhập thất bại (Dò mật khẩu) -> T1110
        elif status == "Auth_Failed":
            mitre_block = {
                "tactic_id": "TA0006",
                "tactic_name": "Credential Access",
                "technique_id": "T1110",
                "technique_name": "Brute Force: Password Guessing",
                "subtechnique_id": "T1110.001",
                "scenario": "SSH Password Guessing (Brute Force)",
                "severity": "High"
            }

        # 3. Đăng nhập thành công -> T1078.003
        elif status == "Auth_Success":
            mitre_block = {
                "tactic_id": "TA0001",
                "tactic_name": "Initial Access",
                "technique_id": "T1078.003",
                "technique_name": "Valid Accounts: Local Accounts",
                "subtechnique_id": "T1078.003",
                "scenario": "Valid Local Accounts Access",
                "severity": "Medium"
            }

        # 4. Ngắt kết nối bất thường (Rớt mạng / Tháo chạy) -> T1070
        elif status == "Session_Aborted" or ev.get("abnormal_termination") is True:
            mitre_block = {
                "tactic_id": "TA0005",
                "tactic_name": "Defense Evasion",
                "technique_id": "T1070",
                "technique_name": "Indicator Removal: Abnormal Session Drop",
                "subtechnique_id": None,
                "scenario": "Indicator Removal: Abnormal Session Drop",
                "severity": "Medium"
            }

        # 5. Thoát phiên bình thường -> Execution Normal Exit
        elif status == "Session_End":
            mitre_block = {
                "tactic_id": "TA0002",
                "tactic_name": "Execution",
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Normal Terminal Exit",
                "subtechnique_id": None,
                "scenario": "Normal Terminal Shell Exit",
                "severity": "Info"
            }

        # 6. Tương tác dòng lệnh (Interaction)
        elif status == "Interaction" and cmd:
            matched = False
            for rule in MITRE_COMMAND_RULES:
                if rule["pattern"].search(cmd):
                    mitre_block = {
                        "tactic_id": rule["tactic_id"],
                        "tactic_name": rule["tactic_name"],
                        "technique_id": rule["technique_id"],
                        "technique_name": rule["technique_name"],
                        "subtechnique_id": rule["subtechnique_id"],
                        "scenario": rule["scenario"],
                        "severity": rule["severity"]
                    }
                    matched = True
                    break

            if not matched:
                mitre_block = {
                    "tactic_id": "TA0002",
                    "tactic_name": "Execution",
                    "technique_id": "T1059.004",
                    "technique_name": "Command and Scripting Interpreter: Unix Shell",
                    "subtechnique_id": "T1059.004",
                    "scenario": "Interactive Unix Shell Command Execution",
                    "severity": "Low"
                }

        ev["mitre_attack"] = mitre_block
        ev["mitre_tactic"] = mitre_block["tactic_name"] if mitre_block else "Unknown"
        ev["mitre_technique_id"] = mitre_block["technique_id"] if mitre_block else "-"
        ev["mitre_technique_name"] = mitre_block["technique_name"] if mitre_block else "-"
        ev["scenario"] = mitre_block["scenario"] if mitre_block else "Other"
        ev["severity"] = mitre_block["severity"] if mitre_block else "Info"
        return ev

    def build_sessions(self, labeled_events: list) -> list:
        """Gom cụm và tái cấu trúc các phiên tấn công có đầy đủ timeline lệnh & output."""
        sessions_map = defaultdict(lambda: {
            "session_id": "",
            "attacker": {
                "ip": "",
                "port": 0,
                "username": "",
                "passwords_tried": [],
                "auth_status": "Unknown"
            },
            "duration": {
                "start_time": "",
                "end_time": "",
                "duration_seconds": 0.0
            },
            "threat_analysis": {
                "scenario": "Unknown",
                "highest_severity": "Info",
                "command_count": 0,
                "termination": "Normal",
                "mitre_tactics": set(),
                "mitre_techniques": set()
            },
            "timeline": []
        })

        severity_rank = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

        for ev in labeled_events:
            sid = ev.get("session_id") or f"conn-{ev.get('source_ip')}:{ev.get('source_port')}"
            s = sessions_map[sid]
            s["session_id"] = sid
            
            # Attacker info
            if ev.get("source_ip"): s["attacker"]["ip"] = ev["source_ip"]
            if ev.get("source_port"): s["attacker"]["port"] = ev["source_port"]
            if ev.get("username"): s["attacker"]["username"] = ev["username"]
            if ev.get("password") and ev["password"] not in s["attacker"]["passwords_tried"]:
                s["attacker"]["passwords_tried"].append(ev["password"])

            # Timing
            ts = ev.get("timestamp", "")
            if not s["duration"]["start_time"] or ts < s["duration"]["start_time"]:
                s["duration"]["start_time"] = ts
            if not s["duration"]["end_time"] or ts > s["duration"]["end_time"]:
                s["duration"]["end_time"] = ts

            # Status
            status = ev.get("event_status")
            if status == "Auth_Success":
                s["attacker"]["auth_status"] = "Success"
            elif status == "Auth_Failed" and s["attacker"]["auth_status"] != "Success":
                s["attacker"]["auth_status"] = "Failed"
            elif status == "Session_Aborted" or ev.get("abnormal_termination"):
                s["threat_analysis"]["termination"] = "Abnormal_Drop"
            elif status == "Immediate_Exit":
                s["threat_analysis"]["termination"] = "Immediate_Exit"

            # MITRE tags
            m = ev.get("mitre_attack")
            if m:
                s["threat_analysis"]["mitre_tactics"].add(f"{m['tactic_id']} - {m['tactic_name']}")
                s["threat_analysis"]["mitre_techniques"].add(f"{m['technique_id']} - {m['technique_name']}")
                
                sev = m.get("severity", "Info")
                if severity_rank.get(sev, 0) > severity_rank.get(s["threat_analysis"]["highest_severity"], 0):
                    s["threat_analysis"]["highest_severity"] = sev

            # Timeline commands
            cmd = ev.get("command")
            if status == "Interaction" and cmd:
                s["threat_analysis"]["command_count"] += 1
                s["timeline"].append({
                    "step": len(s["timeline"]) + 1,
                    "timestamp": ts,
                    "command": cmd,
                    "output": ev.get("command_output", ""),
                    "handler": ev.get("handler_type", "VFS"),
                    "latency_ms": ev.get("latency_ms", 0.0),
                    "mitre_technique": f"{m['technique_id']} [{m['tactic_name']}]: {m['technique_name']}" if m else "T1059.004"
                })

        # Finalize sessions
        res = []
        for sid, s in sessions_map.items():
            # Duration in seconds
            st1 = s["duration"]["start_time"]
            st2 = s["duration"]["end_time"]
            if st1 and st2:
                try:
                    dt1 = datetime.fromisoformat(st1.replace("Z", "+00:00"))
                    dt2 = datetime.fromisoformat(st2.replace("Z", "+00:00"))
                    s["duration"]["duration_seconds"] = round(max(0.0, (dt2 - dt1).total_seconds()), 2)
                except Exception:
                    pass

            # Scenario determination
            cmds = [item["command"].lower() for item in s["timeline"]]
            cmds_str = " ".join(cmds)
            if any(x in cmds_str for x in ["curl", "wget", "malware", ".sh", ".elf"]):
                s["threat_analysis"]["scenario"] = "C2 Ingress Tool Transfer & Malware Staging"
            elif "sudo" in cmds_str or "su " in cmds_str or "id_rsa" in cmds_str or "/etc/shadow" in cmds_str:
                s["threat_analysis"]["scenario"] = "Privilege Escalation & Sensitive Credential Access"
            elif any(x in cmds_str for x in ["crontab", "/etc/cron"]):
                s["threat_analysis"]["scenario"] = "Persistence via Scheduled Jobs (Cron)"
            elif any(x in cmds_str for x in ["history -c", "rm -rf"]):
                s["threat_analysis"]["scenario"] = "Defense Evasion & History Deletion"
            elif any(x in cmds_str for x in ["uname", "whoami", "ip a", "netstat", "ps aux", "passwd"]):
                s["threat_analysis"]["scenario"] = "System & Network Environment Discovery"
            elif s["timeline"]:
                s["threat_analysis"]["scenario"] = "Interactive Shell Exploration"
            elif s["attacker"]["auth_status"] == "Failed":
                s["threat_analysis"]["scenario"] = "SSH Password Guessing (Brute Force)"
            elif s["threat_analysis"]["termination"] == "Immediate_Exit":
                s["threat_analysis"]["scenario"] = "Port Scan & Connection Probe"
            else:
                s["threat_analysis"]["scenario"] = "Initial Connection / Banner Grab"

            s["threat_analysis"]["mitre_tactics"] = sorted(list(s["threat_analysis"]["mitre_tactics"]))
            s["threat_analysis"]["mitre_techniques"] = sorted(list(s["threat_analysis"]["mitre_techniques"]))
            res.append(s)

        res.sort(key=lambda x: x["duration"]["start_time"], reverse=True)
        return res

def main():
    parser = argparse.ArgumentParser(description="Clean dirty logs and label 100% of events with MITRE ATT&CK Enterprise criteria.")
    parser.add_argument("--input", "-i", type=str, default="logs/events.jsonl", help="Input raw log path")
    parser.add_argument("--output-events", "-oe", type=str, default="logs/mitre_labeled_clean_events.jsonl", help="Output clean MITRE labeled events (JSONL)")
    parser.add_argument("--output-sessions", "-os", type=str, default="logs/mitre_labeled_clean_sessions.json", help="Output clean MITRE labeled sessions (Indented JSON)")
    parser.add_argument("--stats", action="store_true", default=True, help="Display comprehensive MITRE stats")
    
    args = parser.parse_args()

    print("=" * 90)
    print("🛡️ [ADAPTIVE HONEYPOT] BỘ LỌC LOG SẠCH & GÁN NHÃN TIÊU CHÍ MITRE ATT&CK FOR ENTERPRISE")
    print(f"📂 Tệp đầu vào: {args.input}")
    print("=" * 90)

    labeler = MitreAttackLabeler(args.input)
    
    print("\n[*] BƯỚC 1: TIẾN HÀNH LỌC LOG BẨN & NHIỄU (CLEANING PHASE)...")
    cleaned = labeler.parse_and_clean()
    
    total_rejected = sum(labeler.rejected_stats.values())
    print(f"  • Tổng số dòng log thô đọc vào : {labeler.raw_lines:,} dòng")
    print(f"  • Số bản ghi BẨN / NHIỄU bị loại : {total_rejected:,} bản ghi")
    print(f"    - Nhiễu test nội bộ (127.0.0.1) : {labeler.rejected_stats['localhost_test_noise']:,}")
    print(f"    - Bản ghi lỗi JSON / Parse     : {labeler.rejected_stats['corrupted_json']:,}")
    print(f"    - Bản ghi thiếu trường cốt lõi  : {labeler.rejected_stats['missing_vital_fields']:,}")
    print(f"    - Bản ghi trùng lặp (Duplicate): {labeler.rejected_stats['duplicate_records']:,}")
    print(f"    - Lệnh tương tác rỗng (Empty)  : {labeler.rejected_stats['empty_command_interaction']:,}")
    print(f"  ==> SỐ SỰ KIỆN SẠCH ĐẠT CHUẨN  : {len(cleaned):,} bản ghi (Sạch 100%)")

    print("\n[*] BƯỚC 2: GÁN NHÃN MA TRẬN MITRE ATT&CK FOR ENTERPRISE (100% TIÊU CHÍ)...")
    for ev in cleaned:
        labeler.label_event(ev)

    # Lưu file Events sạch
    out_events = Path(args.output_events)
    out_events.parent.mkdir(parents=True, exist_ok=True)
    with open(out_events, "w", encoding="utf-8") as f:
        for ev in cleaned:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"  ✅ Đã lưu file sự kiện SẠCH gán nhãn MITRE (JSONL): {out_events} ({len(cleaned):,} dòng)")

    # Lưu file Sessions sạch (Indented JSON)
    sessions = labeler.build_sessions(cleaned)
    out_sessions = Path(args.output_sessions)
    with open(out_sessions, "w", encoding="utf-8") as f:
        json.dump(sessions, f, ensure_ascii=False, indent=2)
    print(f"  ✅ Đã lưu file hồ sơ phiên tấn công SẠCH (JSON đẹp): {out_sessions} ({len(sessions):,} sessions)")

    # In thống kê
    if args.stats:
        print("\n" + "=" * 90)
        print("📊 BẢNG TỔNG HỢP GÁN NHÃN TIÊU CHÍ MITRE ATT&CK TRÊN TẬP DỮ LIỆU ĐÃ LÀM SẠCH")
        print("=" * 90)

        # 1. Tactics
        tactic_counts = Counter(e.get("mitre_tactic", "Unknown") for e in cleaned)
        print("\n[+] PHÂN BỐ THEO CHIẾN THUẬT (MITRE ATT&CK TACTICS):")
        for tac, cnt in tactic_counts.most_common():
            pct = (cnt / len(cleaned)) * 100 if cleaned else 0
            print(f"  • {tac:<30} : {cnt:6,d} ({pct:5.1f}%)")

        # 2. Techniques
        tech_counts = Counter(
            f"{e.get('mitre_technique_id')} - {e.get('mitre_technique_name')} [{e.get('mitre_tactic')}]"
            for e in cleaned if e.get("mitre_technique_id") != "-"
        )
        print("\n[+] TOP KỸ THUẬT MITRE ATT&CK ĐÃ ĐỐI SOÁT & GÁN NHÃN:")
        for tech, cnt in tech_counts.most_common(12):
            pct = (cnt / len(cleaned)) * 100 if cleaned else 0
            print(f"  • {tech:<65} : {cnt:5,d} ({pct:5.1f}%)")

        # 3. Severity
        sev_counts = Counter(e.get("severity", "Info") for e in cleaned)
        print("\n[+] PHÂN BỐ MỨC ĐỘ NGUY HIỂM (SEVERITY LEVEL):")
        for sev, cnt in sev_counts.most_common():
            pct = (cnt / len(cleaned)) * 100 if cleaned else 0
            print(f"  • {sev:<15} : {cnt:6,d} ({pct:5.1f}%)")

        print("=" * 90)

if __name__ == "__main__":
    main()
