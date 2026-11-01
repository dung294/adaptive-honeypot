#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - RAW JSONL TO PRETTY-PRINTED JSON LOG PARSER
=============================================================================
Parses raw honeypot events (events.jsonl) into standard, clean, indented JSON.
Retains 100% standard English technical schema (no translated keys/values).
"""

import sys
import os
import json
import argparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# MITRE ATT&CK extraction
def extract_mitre_info(ev: dict) -> list:
    techniques = []
    
    # 1. From existing mitre_techniques field
    raw_techs = ev.get("mitre_techniques")
    if isinstance(raw_techs, list):
        for t in raw_techs:
            if isinstance(t, dict):
                tid = t.get("technique_id") or t.get("id")
                tname = t.get("technique_name") or t.get("name")
                tac = t.get("tactic", "Threat Behavior")
                if tid:
                    techniques.append({
                        "technique_id": tid,
                        "technique_name": tname or tid,
                        "tactic": tac
                    })
    
    st = ev.get("event_status")
    cmd = (ev.get("command") or "").strip().lower()
    
    if st == "Auth_Failed" and not any(x["technique_id"] == "T1110" for x in techniques):
        techniques.append({
            "technique_id": "T1110",
            "technique_name": "Brute Force: Password Guessing",
            "tactic": "Credential Access"
        })
    elif st == "Auth_Success" and not any(x["technique_id"] == "T1078.003" for x in techniques):
        techniques.append({
            "technique_id": "T1078.003",
            "technique_name": "Valid Accounts: Local Accounts",
            "tactic": "Initial Access"
        })
    elif st == "Immediate_Exit" and not any(x["technique_id"] == "T1046" for x in techniques):
        techniques.append({
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery: Port Scan",
            "tactic": "Discovery"
        })
    elif st == "Session_Aborted" and not any(x["technique_id"] == "T1070" for x in techniques):
        techniques.append({
            "technique_id": "T1070",
            "technique_name": "Indicator Removal: Abnormal Connection Drop",
            "tactic": "Defense Evasion"
        })

    if cmd:
        if any(w in cmd for w in ["wget", "curl", "tftp", "ftp"]):
            if not any(x["technique_id"] == "T1105" for x in techniques):
                techniques.append({
                    "technique_id": "T1105",
                    "technique_name": "Ingress Tool Transfer",
                    "tactic": "Command and Control"
                })
        elif "sudo" in cmd:
            if not any("T1548" in x["technique_id"] for x in techniques):
                techniques.append({
                    "technique_id": "T1548.003",
                    "technique_name": "Abuse Elevation Control: Sudo Caching",
                    "tactic": "Privilege Escalation"
                })
        elif any(w in cmd for w in ["crontab", "/etc/cron"]):
            if not any("T1053" in x["technique_id"] for x in techniques):
                techniques.append({
                    "technique_id": "T1053.003",
                    "technique_name": "Scheduled Task/Job: Cron Persistence",
                    "tactic": "Persistence"
                })
        elif any(w in cmd for w in ["whoami", "id"]):
            if not any(x["technique_id"] == "T1033" for x in techniques):
                techniques.append({
                    "technique_id": "T1033",
                    "technique_name": "System Owner/User Discovery",
                    "tactic": "Discovery"
                })
        elif any(w in cmd for w in ["uname", "hostname", "/proc/version"]):
            if not any(x["technique_id"] == "T1082" for x in techniques):
                techniques.append({
                    "technique_id": "T1082",
                    "technique_name": "System Information Discovery",
                    "tactic": "Discovery"
                })
        elif any(w in cmd for w in ["history -c", "rm -rf", "shred"]):
            if not any("T1070" in x["technique_id"] for x in techniques):
                techniques.append({
                    "technique_id": "T1070.003",
                    "technique_name": "Indicator Removal on Host: Clear History",
                    "tactic": "Defense Evasion"
                })
        
        if not techniques:
            techniques.append({
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution"
            })

    return techniques

def determine_scenario(auth_status: str, commands: list, is_aborted: bool) -> str:
    cmds_str = " ".join(c.lower() for c in commands)
    if any(x in cmds_str for x in ["curl", "wget", "malware", ".sh", ".elf", "chmod +x"]):
        return "C2 Ingress Tool Transfer & Malware Staging"
    if "sudo" in cmds_str or "su " in cmds_str or "id_rsa" in cmds_str or "/etc/shadow" in cmds_str:
        return "Privilege Escalation & Sensitive Credential Access"
    if any(x in cmds_str for x in ["crontab", "/etc/cron", "rc.local"]):
        return "Persistence via Scheduled Jobs"
    if any(x in cmds_str for x in ["history -c", "rm -rf", "unset histfile"]):
        return "Defense Evasion & History Tampering"
    if any(x in cmds_str for x in ["uname", "whoami", "ifconfig", "ip a", "netstat", "ps aux", "cat /etc/passwd"]):
        return "System & Network Environment Discovery"
    if commands:
        return "Interactive Shell Reconnaissance"
    if auth_status == "Failed":
        return "SSH Password Guessing / Brute Force"
    if is_aborted:
        return "Port Scan & Connection Probe"
    return "Initial Connection / Banner Grab"

def determine_severity(scenario: str, mitre_tactics: list) -> str:
    if "C2" in scenario or "Command and Control" in mitre_tactics or "Privilege Escalation" in mitre_tactics:
        return "Critical"
    if "Persistence" in mitre_tactics or "Credential Access" in mitre_tactics or "Privilege Escalation" in scenario:
        return "High"
    if "Defense Evasion" in mitre_tactics or "Malware Staging" in scenario:
        return "High"
    if "Discovery" in mitre_tactics or "Discovery" in scenario:
        return "Medium"
    if "Brute Force" in scenario:
        return "Medium"
    return "Low"

class LogJsonParser:
    def __init__(self, log_path: str = "logs/events.jsonl"):
        self.log_path = Path(log_path)
        self.raw_records = []
        
    def load_events(self):
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")
            
        seen_keys = set()
        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    k = data.get("event_key") or f"{data.get('timestamp')}:{data.get('session_id')}:{data.get('command')}"
                    if k in seen_keys:
                        continue
                    seen_keys.add(k)
                    self.raw_records.append(data)
                except Exception:
                    continue

    def parse_into_readable_sessions(self) -> list:
        session_map = defaultdict(lambda: {
            "session_id": "",
            "ip": "127.0.0.1",
            "port": 0,
            "username": "root",
            "passwords_tried": [],
            "auth_status": "Unknown",
            "timestamps": [],
            "events": [],
            "abnormal_termination": False
        })

        for ev in self.raw_records:
            sid = ev.get("session_id") or "unauthenticated_scan"
            s = session_map[sid]
            s["session_id"] = sid
            if ev.get("source_ip"):
                s["ip"] = ev["source_ip"]
            if ev.get("source_port"):
                s["port"] = ev["source_port"]
            if ev.get("username"):
                s["username"] = ev["username"]
            if ev.get("password") and ev["password"] not in s["passwords_tried"]:
                s["passwords_tried"].append(ev["password"])
            if ev.get("timestamp"):
                s["timestamps"].append(ev["timestamp"])
                
            st = ev.get("event_status")
            if st == "Auth_Success":
                s["auth_status"] = "Success"
            elif st == "Auth_Failed":
                if s["auth_status"] != "Success":
                    s["auth_status"] = "Failed"
            elif st == "Immediate_Exit":
                if s["auth_status"] == "Unknown":
                    s["auth_status"] = "None"
            elif st == "Session_Aborted":
                s["abnormal_termination"] = True
                
            s["events"].append(ev)

        readable_sessions = []
        for sid, s in session_map.items():
            ts_list = sorted(s["timestamps"])
            start_iso = ts_list[0] if ts_list else ""
            end_iso = ts_list[-1] if ts_list else ""
            
            duration_sec = 0.0
            if start_iso and end_iso:
                try:
                    dt1 = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
                    dt2 = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
                    duration_sec = round(max(0.0, (dt2 - dt1).total_seconds()), 2)
                except Exception:
                    pass

            interactions = [e for e in s["events"] if e.get("event_status") == "Interaction"]
            interactions.sort(key=lambda x: x.get("timestamp", ""))

            command_timeline = []
            all_tactics = set()
            all_techniques = set()
            commands_list = []

            for idx, item in enumerate(interactions, 1):
                cmd_text = item.get("command", "")
                commands_list.append(cmd_text)
                mitre_list = extract_mitre_info(item)
                
                for m in mitre_list:
                    all_tactics.add(m["tactic"])
                    all_techniques.add(f"{m['technique_id']} - {m['technique_name']}")

                command_timeline.append({
                    "step": idx,
                    "timestamp": item.get("timestamp", ""),
                    "command": cmd_text,
                    "output": item.get("command_output", ""),
                    "handler": item.get("handler_type", "VFS"),
                    "latency_ms": item.get("latency_ms", 0.0),
                    "mitre_attack": mitre_list
                })

            if not command_timeline:
                for ev in s["events"]:
                    for m in extract_mitre_info(ev):
                        all_tactics.add(m["tactic"])
                        all_techniques.add(f"{m['technique_id']} - {m['technique_name']}")

            scenario = determine_scenario(
                auth_status=s["auth_status"],
                commands=commands_list,
                is_aborted=s["abnormal_termination"]
            )
            severity = determine_severity(scenario, list(all_tactics))

            session_obj = {
                "session_id": sid,
                "attacker": {
                    "ip": s["ip"],
                    "port": s["port"],
                    "username": s["username"],
                    "passwords_tried": s["passwords_tried"],
                    "auth_status": s["auth_status"]
                },
                "duration": {
                    "start_time": start_iso,
                    "end_time": end_iso,
                    "duration_seconds": duration_sec
                },
                "threat_analysis": {
                    "scenario": scenario,
                    "severity": severity,
                    "command_count": len(command_timeline),
                    "connection_status": "Abnormal_Disconnect" if s["abnormal_termination"] else "Normal_Exit",
                    "mitre_tactics": sorted(list(all_tactics)),
                    "mitre_techniques": sorted(list(all_techniques))
                },
                "timeline": command_timeline
            }
            readable_sessions.append(session_obj)

        readable_sessions.sort(key=lambda x: x["duration"]["start_time"], reverse=True)
        return readable_sessions

    def parse_into_readable_events(self) -> list:
        readable_events = []
        for idx, ev in enumerate(self.raw_records, 1):
            st = ev.get("event_status", "Event")
            cmd = ev.get("command")
            output = ev.get("command_output")
            mitre_list = extract_mitre_info(ev)
            
            item = {
                "index": idx,
                "timestamp": ev.get("timestamp", ""),
                "event_type": st,
                "session_id": ev.get("session_id", "N/A"),
                "source_ip": ev.get("source_ip", "127.0.0.1"),
                "source_port": ev.get("source_port", 0),
                "username": ev.get("username", "N/A")
            }
            
            if ev.get("password"):
                item["password"] = ev.get("password")
                
            if cmd is not None:
                item["command"] = cmd
                item["output"] = output if output is not None else ""
                item["handler"] = ev.get("handler_type", "VFS")
                item["latency_ms"] = ev.get("latency_ms", 0.0)

            if mitre_list:
                item["mitre_attack"] = mitre_list
                
            readable_events.append(item)
            
        return readable_events

def main():
    parser = argparse.ArgumentParser(description="Parse raw honeypot logs into clean, readable JSON format.")
    parser.add_argument("--input", "-i", default="logs/events.jsonl", help="Input log path")
    parser.add_argument("--output-sessions", "-os", default="logs/readable_attack_sessions.json", help="Full sessions JSON")
    parser.add_argument("--output-sample", "-sm", default="logs/readable_attack_sessions_sample.json", help="Sample sessions JSON")
    parser.add_argument("--output-events", "-oe", default="logs/readable_events.json", help="Clean individual events JSON")
    parser.add_argument("--limit-sample", type=int, default=50, help="Number of sample sessions (default: 50)")
    
    args = parser.parse_args()

    print("=" * 80)
    print("PARSING HONEYPOT LOGS INTO PRETTY-PRINTED STANDARD JSON")
    print(f"Source file: {args.input}")
    print("=" * 80)

    converter = LogJsonParser(args.input)
    converter.load_events()
    print(f"Loaded: {len(converter.raw_records):,} raw events.")

    sessions = converter.parse_into_readable_sessions()
    print(f"Parsed: {len(sessions):,} sessions.")

    # 1. Full Sessions JSON
    out_sess_path = Path(args.output_sessions)
    out_sess_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_sess_path, "w", encoding="utf-8") as f:
        json.dump(sessions, f, ensure_ascii=False, indent=2)
    print(f"[OK] Saved full sessions JSON: {out_sess_path} ({len(sessions):,} sessions)")

    # 2. Sample Sessions JSON
    sample_sessions = [s for s in sessions if s["threat_analysis"]["command_count"] > 0]
    if len(sample_sessions) < args.limit_sample:
        sample_sessions = sessions[:args.limit_sample]
    else:
        sample_sessions = sample_sessions[:args.limit_sample]

    out_sample_path = Path(args.output_sample)
    with open(out_sample_path, "w", encoding="utf-8") as f:
        json.dump(sample_sessions, f, ensure_ascii=False, indent=2)
    print(f"[OK] Saved sample sessions JSON: {out_sample_path} ({len(sample_sessions)} sessions)")

    # 3. Individual Events JSON
    events = converter.parse_into_readable_events()
    out_events_path = Path(args.output_events)
    with open(out_events_path, "w", encoding="utf-8") as f:
        json.dump(events, f, ensure_ascii=False, indent=2)
    print(f"[OK] Saved individual events JSON: {out_events_path} ({len(events):,} events)")
    print("=" * 80)

if __name__ == "__main__":
    main()
