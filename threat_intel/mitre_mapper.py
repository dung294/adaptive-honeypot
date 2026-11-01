import re
from typing import Dict, Any

class MitreMapper:
    """
    Real-time MITRE ATT&CK for Enterprise classifier for Linux SSH Honeypot.
    Categorizes events into exact Tactics, Techniques, Sub-techniques, Scenarios and Severity.
    """
    RULES = [
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

    @classmethod
    def map_command(cls, command: str) -> Dict[str, Any]:
        """
        Đối soát lệnh với Ma trận MITRE ATT&CK for Enterprise.
        Luôn trả về đối tượng MITRE hoàn chỉnh (không bao giờ để trống).
        """
        cmd = (command or "").strip()
        for rule in cls.RULES:
            if rule["pattern"].search(cmd):
                return {
                    "tactic_id": rule["tactic_id"],
                    "tactic_name": rule["tactic_name"],
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "subtechnique_id": rule["subtechnique_id"],
                    "scenario": rule["scenario"],
                    "severity": rule["severity"]
                }
        
        # Mặc định shell execution nếu không khớp mẫu đặc thù
        return {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.004",
            "technique_name": "Command and Scripting Interpreter: Unix Shell",
            "subtechnique_id": "T1059.004",
            "scenario": "Interactive Unix Shell Command Execution",
            "severity": "Low"
        }
