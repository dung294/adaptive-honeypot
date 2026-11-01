import os
import sys
import json
import re
import argparse
import datetime
from pathlib import Path
from collections import Counter, defaultdict

# Ensure UTF-8 output on Windows
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# =====================================================================
# MA TRẬN PHÂN LOẠI CHUẨN MITRE ATT&CK FOR ENTERPRISE (LINUX SSH)
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

# Quy tắc gán nhãn MITRE ATT&CK chuyên sâu theo Regex và trạng thái sự kiện
MITRE_RULES = [
    # 1. COMMAND AND CONTROL (TA0011)
    {
        "pattern": re.compile(r"\b(curl|wget|scp|sftp|ftp|tftp)\b", re.IGNORECASE),
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "subtechnique_id": None,
        "scenario_name": "Ý định tải file bằng lệnh giả lập an toàn",
        "severity": "High"
    },
    # 2. PRIVILEGE ESCALATION (TA0004)
    {
        "pattern": re.compile(r"\b(sudo\s+-l|sudo\s+su|su\s+-|sudo\s+cat)\b", re.IGNORECASE),
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "subtechnique_id": "T1548.003",
        "scenario_name": "Thăm dò leo thang đặc quyền",
        "severity": "Critical"
    },
    {
        "pattern": re.compile(r"\b(find\s+/.*-perm\s+(-u=s|-4000))\b", re.IGNORECASE),
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation (SUID Probe)",
        "subtechnique_id": None,
        "scenario_name": "Thăm dò leo thang đặc quyền (Tìm binary SUID)",
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
        "scenario_name": "Xóa dấu vết phòng thủ (Clear Bash History)",
        "severity": "High"
    },
    {
        "pattern": re.compile(r"\b(rm\s+-rf?)\b", re.IGNORECASE),
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1070.004",
        "technique_name": "Indicator Removal: File Deletion",
        "subtechnique_id": "T1070.004",
        "scenario_name": "Xóa dấu vết phòng thủ (File Deletion)",
        "severity": "Medium"
    },
    {
        "pattern": re.compile(r"\b(chmod\s+(\+x|[0-7]{3,4}))\b", re.IGNORECASE),
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1222.002",
        "technique_name": "File and Directory Permissions Modification: Linux Permissions",
        "subtechnique_id": "T1222.002",
        "scenario_name": "Thay đổi quyền tệp tin (Chmod)",
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
        "scenario_name": "Cài cắm duy trì (Persistence via Cron)",
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
        "scenario_name": "Săn lùng Credential trong hệ thống",
        "severity": "Critical"
    },
    {
        "pattern": re.compile(r"\b(cat\s+/etc/passwd|cat\s+/etc/group)\b", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1087.001",
        "technique_name": "Account Discovery: Local Accounts",
        "subtechnique_id": "T1087.001",
        "scenario_name": "Khảo sát tài khoản người dùng cục bộ",
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
        "scenario_name": "Trinh sát danh tính tài khoản",
        "severity": "Low"
    },
    {
        "pattern": re.compile(r"\b(uname|hostname|cat\s+/etc/os-release|cat\s+/etc/issue|lscpu|free|df|cat\s+/proc/version|uptime)\b", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "subtechnique_id": None,
        "scenario_name": "Đăng nhập thành công rồi khảo sát hệ thống",
        "severity": "Low"
    },
    {
        "pattern": re.compile(r"\b(ps\b|top\b|htop\b|pstree\b)", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "subtechnique_id": None,
        "scenario_name": "Khảo sát tiến trình hệ thống",
        "severity": "Low"
    },
    {
        "pattern": re.compile(r"\b(ifconfig|ip\s+a|ip\s+addr|netstat|ss\s+-|route|arp|cat\s+/etc/resolv\.conf|cat\s+/etc/hosts)\b", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "subtechnique_id": None,
        "scenario_name": "Khảo sát cấu hình mạng nội bộ",
        "severity": "Low"
    },
    {
        "pattern": re.compile(r"\b(ping|traceroute|nmap)\b", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1018",
        "technique_name": "Remote System Discovery",
        "subtechnique_id": None,
        "scenario_name": "Dò quét máy chủ mạng lân cận",
        "severity": "Medium"
    },
    {
        "pattern": re.compile(r"\b(ls|pwd|cd\b|cat\s+|find\b|dir\b)", re.IGNORECASE),
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "subtechnique_id": None,
        "scenario_name": "Khảo sát file/thư mục",
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
        "scenario_name": "Thăm dò Honeypot / AI Prompt Injection",
        "severity": "High"
    }
]

class MitreAttackLabeler:
    def __init__(self, input_file: str):
        self.input_file = Path(input_file)
        self.raw_lines = 0
        self.clean_events = []
        self.sessions = {}

    def parse_and_clean(self):
        """Lọc dữ liệu sạch: loại bỏ bản ghi lỗi, dòng trống và trùng lặp."""
        seen_keys = set()
        
        with open(self.input_file, "r", encoding="utf-8") as f:
            for line in f:
                self.raw_lines += 1
                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    record = json.loads(line_str)
                except Exception:
                    continue

                if not isinstance(record, dict) or "event_status" not in record:
                    continue

                # Deduplication
                key = record.get("event_key") or f"{record.get('timestamp')}:{record.get('session_id')}:{record.get('event_status')}:{record.get('command')}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                # Format local time
                ts = record.get("timestamp", "")
                try:
                    dt = datetime.datetime.fromisoformat(ts)
                    record["formatted_time"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    record["formatted_time"] = ts[:19].replace("T", " ")

                self.clean_events.append(record)

        return self.clean_events

    def label_event(self, ev: dict) -> dict:
        """Gán nhãn chi tiết theo chuẩn ma trận MITRE ATT&CK for Enterprise."""
        status = ev.get("event_status", "UNKNOWN")
        cmd = ev.get("command", "")

        mitre_block = None

        # 1. Quét cổng / Banner grab ngắt ngay -> T1046
        if status == "Immediate_Exit":
            mitre_block = {
                "tactic_id": "TA0007",
                "tactic_name": "Discovery",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "subtechnique_id": None,
                "scenario_group": "Kết nối rồi thoát",
                "severity": "Low",
                "confidence": "High",
                "full_label": "[TA0007:Discovery] T1046 - Network Service Discovery"
            }

        # 2. Đăng nhập thất bại (Dò mật khẩu) -> T1110
        elif status == "Auth_Failed":
            mitre_block = {
                "tactic_id": "TA0006",
                "tactic_name": "Credential Access",
                "technique_id": "T1110",
                "technique_name": "Brute Force: Password Guessing",
                "subtechnique_id": "T1110.001",
                "scenario_group": "Đăng nhập thất bại nhiều lần",
                "severity": "High",
                "confidence": "High",
                "full_label": "[TA0006:Credential Access] T1110 - Brute Force: Password Guessing"
            }

        # 3. Đăng nhập thành công -> T1078.003
        elif status == "Auth_Success":
            mitre_block = {
                "tactic_id": "TA0001",
                "tactic_name": "Initial Access",
                "technique_id": "T1078.003",
                "technique_name": "Valid Accounts: Local Accounts",
                "subtechnique_id": "T1078.003",
                "scenario_group": "Đăng nhập thành công",
                "severity": "Medium",
                "confidence": "High",
                "full_label": "[TA0001:Initial Access] T1078.003 - Valid Accounts: Local Accounts"
            }

        # 4. Ngắt kết nối bất thường (Rớt mạng / Tháo chạy) -> T1070
        elif status == "Session_Aborted" or ev.get("abnormal_termination") is True:
            mitre_block = {
                "tactic_id": "TA0005",
                "tactic_name": "Defense Evasion",
                "technique_id": "T1070",
                "technique_name": "Indicator Removal: Abnormal Session Drop",
                "subtechnique_id": None,
                "scenario_group": "Session bị ngắt hoặc thiếu End",
                "severity": "Medium",
                "confidence": "High",
                "full_label": "[TA0005:Defense Evasion] T1070 - Abnormal Session Drop"
            }

        # 5. Thoát phiên bình thường -> Execution Normal Exit
        elif status == "Session_End":
            mitre_block = {
                "tactic_id": "TA0002",
                "tactic_name": "Execution",
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Normal Terminal Exit",
                "subtechnique_id": None,
                "scenario_group": "Đóng phiên bình thường",
                "severity": "Info",
                "confidence": "High",
                "full_label": "[TA0002:Execution] T1059.004 - Normal Terminal Exit"
            }

        # 6. Tương tác dòng lệnh (Interaction)
        elif status == "Interaction" and cmd:
            matched = False
            for rule in MITRE_RULES:
                if rule["pattern"].search(cmd):
                    mitre_block = {
                        "tactic_id": rule["tactic_id"],
                        "tactic_name": rule["tactic_name"],
                        "technique_id": rule["technique_id"],
                        "technique_name": rule["technique_name"],
                        "subtechnique_id": rule["subtechnique_id"],
                        "scenario_group": rule["scenario_name"],
                        "severity": rule["severity"],
                        "confidence": "High",
                        "full_label": f"[{rule['tactic_id']}:{rule['tactic_name']}] {rule['technique_id']} - {rule['technique_name']}"
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
                    "scenario_group": "Tương tác lệnh hệ điều hành",
                    "severity": "Low",
                    "confidence": "Medium",
                    "full_label": "[TA0002:Execution] T1059.004 - Command and Scripting Interpreter: Unix Shell"
                }

        ev["mitre_attack"] = mitre_block
        ev["mitre_tactic"] = mitre_block["tactic_name"] if mitre_block else "Unknown"
        ev["mitre_technique_id"] = mitre_block["technique_id"] if mitre_block else "-"
        ev["mitre_technique_name"] = mitre_block["technique_name"] if mitre_block else "-"
        ev["scenario_group"] = mitre_block["scenario_group"] if mitre_block else "Khác"
        ev["severity"] = mitre_block["severity"] if mitre_block else "Info"
        return ev

    def build_sessions(self, labeled_events: list) -> list:
        """Gom cụm và gán nhãn MITRE ATT&CK ở cấp độ phiên tấn công (Attack Session)."""
        sessions_map = defaultdict(lambda: {
            "session_id": "",
            "source_ip": "",
            "source_port": 0,
            "username": "",
            "start_time": "",
            "end_time": "",
            "duration_seconds": 0.0,
            "auth_status": "Unknown",
            "commands": [],
            "command_count": 0,
            "mitre_tactics_observed": set(),
            "mitre_techniques_observed": set(),
            "highest_severity": "Info",
            "scenario_tags": set(),
            "termination": "Normal"
        })

        severity_rank = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

        for ev in labeled_events:
            sid = ev.get("session_id") or f"conn-{ev.get('source_ip')}:{ev.get('source_port')}"
            s = sessions_map[sid]
            s["session_id"] = sid
            s["source_ip"] = s["source_ip"] or ev.get("source_ip", "")
            s["source_port"] = s["source_port"] or ev.get("source_port", 0)
            s["username"] = s["username"] or ev.get("username", "")

            ts = ev.get("timestamp", "")
            if not s["start_time"] or ts < s["start_time"]: s["start_time"] = ts
            if not s["end_time"] or ts > s["end_time"]: s["end_time"] = ts

            status = ev.get("event_status")
            if status == "Auth_Success":
                s["auth_status"] = "Success"
            elif status == "Auth_Failed" and s["auth_status"] != "Success":
                s["auth_status"] = "Failed"
            elif status == "Session_Aborted" or ev.get("abnormal_termination"):
                s["termination"] = "Abnormal_Drop"
            elif status == "Immediate_Exit":
                s["termination"] = "Immediate_Exit"

            cmd = ev.get("command")
            if cmd:
                s["commands"].append(cmd)
                s["command_count"] += 1

            m = ev.get("mitre_attack")
            if m:
                s["mitre_tactics_observed"].add(f"{m['tactic_id']} - {m['tactic_name']}")
                s["mitre_techniques_observed"].add(f"{m['technique_id']} - {m['technique_name']}")
                s["scenario_tags"].add(m["scenario_group"])
                
                sev = m.get("severity", "Info")
                if severity_rank.get(sev, 0) > severity_rank.get(s["highest_severity"], 0):
                    s["highest_severity"] = sev

        # Chuyển đổi set thành list cho JSON
        res = []
        for sid, s in sessions_map.items():
            s["mitre_tactics_observed"] = sorted(list(s["mitre_tactics_observed"]))
            s["mitre_techniques_observed"] = sorted(list(s["mitre_techniques_observed"]))
            s["scenario_tags"] = sorted(list(s["scenario_tags"]))
            res.append(s)

        res.sort(key=lambda x: x["start_time"])
        return res

def main():
    parser = argparse.ArgumentParser(description="Công cụ lọc log sạch & gán nhãn chuẩn MITRE ATT&CK for Enterprise.")
    parser.add_argument("--input", "-i", type=str, default="logs/events.jsonl", help="Tệp log đầu vào (mặc định: logs/events.jsonl)")
    parser.add_argument("--output-events", "-oe", type=str, default="logs/mitre_labeled_events.jsonl", help="Tệp xuất events đã gán nhãn MITRE")
    parser.add_argument("--output-sessions", "-os", type=str, default="logs/mitre_labeled_sessions.json", help="Tệp xuất sessions đã gán nhãn MITRE")
    parser.add_argument("--tactic", "-ta", type=str, default=None, help="Lọc riêng theo Chiến thuật MITRE (ví dụ: Discovery, Credential Access, Command and Control)")
    parser.add_argument("--technique", "-te", type=str, default=None, help="Lọc riêng theo Mã Kỹ thuật MITRE (ví dụ: T1082, T1110, T1105, T1053.003)")
    parser.add_argument("--scenario", "-s", type=str, default=None, help="Lọc theo nhóm kịch bản (ví dụ: 'tải file', 'ngắt', 'khảo sát')")
    parser.add_argument("--stats", action="store_true", default=True, help="Hiển thị bảng thống kê MITRE chi tiết")
    
    args = parser.parse_args()

    print("=" * 90)
    print("🛡️ [ADAPTIVE HONEYPOT] BỘ LỌC LOG SẠCH & GÁN NHÃN TIÊU CHÍ MITRE ATT&CK ENTERPRISE")
    print(f"📂 Tệp đầu vào: {args.input}")
    print("=" * 90)

    labeler = MitreAttackLabeler(args.input)
    
    print("\n[*] Bước 1: Đang lọc sạch log (loại bỏ trùng lặp, lỗi cú pháp)...")
    cleaned = labeler.parse_and_clean()
    print(f"  • Tổng số dòng đọc vào   : {labeler.raw_lines:,} dòng")
    print(f"  • Số sự kiện SẠCH hợp lệ : {len(cleaned):,} sự kiện (100% Valid)")

    print("\n[*] Bước 2: Đang đối soát và gán nhãn Ma trận MITRE ATT&CK for Enterprise...")
    for ev in cleaned:
        labeler.label_event(ev)

    # Bộ lọc nếu có chỉ định
    filtered = cleaned
    if args.tactic:
        filtered = [e for e in filtered if args.tactic.lower() in e.get("mitre_tactic", "").lower()]
        print(f"  🔍 Đã lọc theo Tactic '{args.tactic}': {len(filtered):,} sự kiện")
    if args.technique:
        filtered = [e for e in filtered if args.technique.lower() in e.get("mitre_technique_id", "").lower()]
        print(f"  🔍 Đã lọc theo Technique '{args.technique}': {len(filtered):,} sự kiện")
    if args.scenario:
        filtered = [e for e in filtered if args.scenario.lower() in e.get("scenario_group", "").lower()]
        print(f"  🔍 Đã lọc theo Kịch bản '{args.scenario}': {len(filtered):,} sự kiện")

    # Lưu file Events
    out_events = Path(args.output_events)
    out_events.parent.mkdir(parents=True, exist_ok=True)
    with open(out_events, "w", encoding="utf-8") as f:
        for ev in filtered:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"\n✅ Đã lưu file sự kiện gán nhãn MITRE: {out_events} ({len(filtered):,} dòng)")

    # Lưu file Sessions
    sessions = labeler.build_sessions(filtered)
    out_sessions = Path(args.output_sessions)
    with open(out_sessions, "w", encoding="utf-8") as f:
        json.dump(sessions, f, ensure_ascii=False, indent=2)
    print(f"✅ Đã lưu hồ sơ các phiên tấn công: {out_sessions} ({len(sessions):,} sessions)")

    # In thống kê
    if args.stats:
        print("\n" + "=" * 90)
        print("📊 BẢNG TỔNG HỢP CHIẾN THUẬT & KỸ THUẬT MITRE ATT&CK TRÊN TẬP LOG ĐÃ LÀM SẠCH")
        print("=" * 90)

        # 1. Thống kê theo MITRE Tactics
        tactic_counts = Counter(e.get("mitre_tactic", "Unknown") for e in filtered)
        print("\n[+] PHÂN BỐ THEO CHIẾN THUẬT (MITRE ATT&CK TACTICS):")
        for tac, cnt in tactic_counts.most_common():
            pct = (cnt / len(filtered)) * 100 if filtered else 0
            print(f"  • {tac:<30} : {cnt:6,d} ({pct:5.1f}%)")

        # 2. Thống kê theo MITRE Techniques
        tech_counts = Counter(
            f"{e.get('mitre_technique_id')} - {e.get('mitre_technique_name')} [{e.get('mitre_tactic')}]"
            for e in filtered if e.get("mitre_technique_id") != "-"
        )
        print("\n[+] TOP KỸ THUẬT MITRE ATT&CK XUẤT HIỆN NHIỀU NHẤT:")
        for tech, cnt in tech_counts.most_common(12):
            pct = (cnt / len(filtered)) * 100 if filtered else 0
            print(f"  • {tech:<65} : {cnt:5,d} ({pct:5.1f}%)")

        # 3. Thống kê theo Mức độ nghiêm trọng (Severity)
        sev_counts = Counter(e.get("severity", "Info") for e in filtered)
        print("\n[+] PHÂN BỐ THEO MỨC ĐỘ NGUY CƠ (SEVERITY LEVEL):")
        for sev, cnt in sev_counts.most_common():
            pct = (cnt / len(filtered)) * 100 if filtered else 0
            print(f"  • {sev:<15} : {cnt:6,d} ({pct:5.1f}%)")

        print("=" * 90)

if __name__ == "__main__":
    main()
