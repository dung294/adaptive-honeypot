#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - TWO-TIER DETECTION & MITRE ATT&CK / ATLAS CLASSIFIER
=============================================================================
Kiến trúc nhận diện 2 tầng (Two-Tier Detection Pipeline):
  - Tầng 1: Phân loại hành vi vĩ mô (Macro-Classes) cho mô hình Học máy (Machine Learning)
    bao gồm 14 nhóm chuẩn mực, bảo đảm tính tổng quát hóa (Generalization).
  - Tầng 2: Ánh xạ bằng chứng lệnh (Evidence-based Rule Mapping) ra kỹ thuật chi tiết
    thuộc Ma trận MITRE ATT&CK for Enterprise (hoặc MITRE ATLAS cho tấn công AI).
"""

import re
from typing import Dict, Any, Optional

class MitreMapper:
    """
    Two-Tier CTI Classifier for Host-based Linux SSH Honeypot.
    Outputs both Macro-Class (Tier 1 for ML) and Precise MITRE Technique (Tier 2 for CTI).
    """
    RULES = [
        # =================================================================
        # 1. ADVERSARIAL AI / PROMPT INJECTION (MITRE ATLAS)
        # =================================================================
        {
            "pattern": re.compile(r"(SYSTEM\s+INSTRUCTION|Ignore\s+previous|system\s+prompt|jailbreak|DAN\s+mode|prompt\s+leak)", re.IGNORECASE),
            "macro_class": "Adversarial AI / Jailbreak Probe",
            "framework": "MITRE ATLAS",
            "tactic_id": "AML.TA0005",
            "tactic_name": "Execution",
            "technique_id": "AML.T0054",
            "technique_name": "LLM Jailbreak / Adversarial Prompt Injection",
            "subtechnique_id": "AML.T0054.001",
            "scenario": "Adversarial AI Jailbreak Probe (LLM Deception Test)",
            "severity": "High"
        },

        # =================================================================
        # 2. COMMAND AND CONTROL (REVERSE SHELL / TUNNELING)
        # =================================================================
        {
            "pattern": re.compile(r"\b(nc\s+.*-e\s+(/bin/sh|/bin/bash)|bash\s+-i\s+>&?\s*/dev/tcp/|socat\s+exec|python.*pty\.spawn.*connect)\b", re.IGNORECASE),
            "macro_class": "Command and Control (Reverse Shell / Tunnel)",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0011",
            "tactic_name": "Command and Control",
            "technique_id": "T1059.004",
            "technique_name": "Command and Scripting Interpreter: Unix Shell Reverse Connection",
            "subtechnique_id": "T1059.004",
            "scenario": "Interactive Reverse Shell Execution (C2 Channel)",
            "severity": "Critical"
        },
        {
            "pattern": re.compile(r"\bssh\s+.*(-R|-L|-D)\s+\d+\b", re.IGNORECASE),
            "macro_class": "Command and Control (Reverse Shell / Tunnel)",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0011",
            "tactic_name": "Command and Control",
            "technique_id": "T1572",
            "technique_name": "Protocol Tunneling: SSH Port Forwarding",
            "subtechnique_id": None,
            "scenario": "Encrypted SSH Port Forwarding / Tunneling",
            "severity": "High"
        },

        # =================================================================
        # 3. LATERAL MOVEMENT (LAN PIVOT & REMOTE SERVICES)
        # =================================================================
        {
            "pattern": re.compile(r"\b(ssh|scp|rsync)\s+.*(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b", re.IGNORECASE),
            "macro_class": "Lateral Movement",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0008",
            "tactic_name": "Lateral Movement",
            "technique_id": "T1021.004",
            "technique_name": "Remote Services: SSH",
            "subtechnique_id": "T1021.004",
            "scenario": "Lateral Movement Attempt via Internal SSH/SCP",
            "severity": "High"
        },
        {
            "pattern": re.compile(r"\b(nmap|arp-scan)\s+.*(10\.\d+|172\.(1[6-9]|2\d|3[01])|192\.168\.)\b", re.IGNORECASE),
            "macro_class": "Lateral Movement",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0007",
            "tactic_name": "Discovery",
            "technique_id": "T1018",
            "technique_name": "Remote System Discovery: Internal Subnet Scan",
            "subtechnique_id": None,
            "scenario": "Internal Subnet Reconnaissance for Lateral Movement",
            "severity": "Medium"
        },

        # =================================================================
        # 4. PERSISTENCE & BACKDOOR SETUP
        # =================================================================
        {
            "pattern": re.compile(r"\b(useradd|adduser)\b", re.IGNORECASE),
            "macro_class": "Persistence & Backdoor Setup",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0003",
            "tactic_name": "Persistence",
            "technique_id": "T1136.001",
            "technique_name": "Create Account: Local Account",
            "subtechnique_id": "T1136.001",
            "scenario": "Backdoor Local Account Creation",
            "severity": "Critical"
        },
        {
            "pattern": re.compile(r"(sudoers|echo.*>>\s*/etc/sudoers)", re.IGNORECASE),
            "macro_class": "Persistence & Backdoor Setup",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0003",
            "tactic_name": "Persistence",
            "technique_id": "T1098",
            "technique_name": "Account Manipulation: Sudoers Modification",
            "subtechnique_id": None,
            "scenario": "Persistence via Sudoers Privilege Manipulation",
            "severity": "Critical"
        },
        {
            "pattern": re.compile(r"\b(crontab|/etc/crontab|/var/spool/cron|cron\.d)\b", re.IGNORECASE),
            "macro_class": "Persistence & Backdoor Setup",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0003",
            "tactic_name": "Persistence",
            "technique_id": "T1053.003",
            "technique_name": "Scheduled Task/Job: Cron",
            "subtechnique_id": "T1053.003",
            "scenario": "Persistence via Scheduled Jobs (Cron)",
            "severity": "High"
        },
        {
            "pattern": re.compile(r"(authorized_keys|\.ssh/authorized_keys)", re.IGNORECASE),
            "macro_class": "Persistence & Backdoor Setup",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0003",
            "tactic_name": "Persistence",
            "technique_id": "T1098.004",
            "technique_name": "Account Manipulation: SSH Authorized Keys",
            "subtechnique_id": "T1098.004",
            "scenario": "SSH Authorized Keys Backdoor Insertion",
            "severity": "Critical"
        },
        {
            "pattern": re.compile(r"(\.bashrc|/etc/profile|/etc/rc\.local)", re.IGNORECASE),
            "macro_class": "Persistence & Backdoor Setup",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0003",
            "tactic_name": "Persistence",
            "technique_id": "T1546.004",
            "technique_name": "Event Triggered Execution: Unix Shell Configuration Modification",
            "subtechnique_id": "T1546.004",
            "scenario": "Persistence via Shell Startup Configuration",
            "severity": "High"
        },
        {
            "pattern": re.compile(r"(systemctl\s+enable|/etc/systemd/system)", re.IGNORECASE),
            "macro_class": "Persistence & Backdoor Setup",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0003",
            "tactic_name": "Persistence",
            "technique_id": "T1543.002",
            "technique_name": "Create or Modify System Process: Systemd Service",
            "subtechnique_id": "T1543.002",
            "scenario": "Persistence via Malicious Systemd Service",
            "severity": "High"
        },

        # =================================================================
        # 5. PRIVILEGE ESCALATION ATTEMPT & GTFOBINS
        # =================================================================
        {
            "pattern": re.compile(r"\b(sudo\s+-l|sudo\s+su|su\s+-|sudo\s+cat|sudo\s+bash|sudo\s+sh)\b", re.IGNORECASE),
            "macro_class": "Privilege Escalation Attempt",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1548.003",
            "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
            "subtechnique_id": "T1548.003",
            "scenario": "Sudo Privilege Verification & Elevation Attempt",
            "severity": "Critical"
        },
        {
            "pattern": re.compile(r"\b(sudo\s+(find|nmap|vim|vi|awk|python\d?|gdb|less|more|man|tar|zip|env|perl|ruby))\b", re.IGNORECASE),
            "macro_class": "Privilege Escalation Attempt",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1548.003",
            "technique_name": "Abuse Elevation Control Mechanism: GTFOBins Sudo Escape",
            "subtechnique_id": "T1548.003",
            "scenario": "GTFOBins Exploitation for Root Shell Escape",
            "severity": "Critical"
        },
        {
            "pattern": re.compile(r"\b(find\s+/.*-perm\s+(-u=s|-4000))\b", re.IGNORECASE),
            "macro_class": "Privilege Escalation Attempt",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation: SUID Probe",
            "subtechnique_id": None,
            "scenario": "SUID Binary Enumeration for Privilege Escalation",
            "severity": "High"
        },

        # =================================================================
        # 6. COMMAND EXECUTION & SCRIPTING
        # =================================================================
        {
            "pattern": re.compile(r"(\bbash\s+-c|\bsh\s+-c|\bpython\d?\s+-c|\bperl\s+-e|\bruby\s+-e|\bphp\s+-r)", re.IGNORECASE),
            "macro_class": "Command Execution & Scripting",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.004",
            "technique_name": "Command and Scripting Interpreter: Shell / Inline Script",
            "subtechnique_id": "T1059.004",
            "scenario": "Inline Script Interpreter Execution",
            "severity": "High"
        },
        {
            "pattern": re.compile(r"(base64\s+-d\s*\|\s*(sh|bash)|echo.*base64)", re.IGNORECASE),
            "macro_class": "Command Execution & Scripting",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information: Deobfuscate/Decode Execution",
            "subtechnique_id": "T1027",
            "scenario": "Base64 Deobfuscated Command Execution",
            "severity": "High"
        },
        {
            "pattern": re.compile(r"(\bcurl|\bwget).*\|\s*(bash|sh|python)", re.IGNORECASE),
            "macro_class": "Command Execution & Scripting",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.004",
            "technique_name": "Command and Scripting Interpreter: Pipe to Shell",
            "subtechnique_id": "T1059.004",
            "scenario": "Direct Network Pipe into Shell Interpreter",
            "severity": "Critical"
        },

        # =================================================================
        # 7. C2 INGRESS & MALWARE STAGING
        # =================================================================
        {
            "pattern": re.compile(r"\b(curl|wget|ftp|tftp|sftp)\b", re.IGNORECASE),
            "macro_class": "C2 Ingress & Malware Staging",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0011",
            "tactic_name": "Command and Control",
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "subtechnique_id": None,
            "scenario": "Remote File Download / Ingress Tool Transfer",
            "severity": "High"
        },

        # =================================================================
        # 8. COLLECTION & EXFILTRATION
        # =================================================================
        {
            "pattern": re.compile(r"\b(tar\s+-[a-z]*c[a-z]*|gzip\b|zip\s+-[a-z]*r|7z\s+a)\b", re.IGNORECASE),
            "macro_class": "Collection & Exfiltration",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0009",
            "tactic_name": "Collection",
            "technique_id": "T1560.001",
            "technique_name": "Archive Collected Data: Archive via Utility",
            "subtechnique_id": "T1560.001",
            "scenario": "Data Archiving & Compression for Exfiltration",
            "severity": "High"
        },
        {
            "pattern": re.compile(r"(\bcat\s+.*>\s*/tmp/|\bmysqldump\b)", re.IGNORECASE),
            "macro_class": "Collection & Exfiltration",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0009",
            "tactic_name": "Collection",
            "technique_id": "T1005",
            "technique_name": "Data from Local System: Staging in Temp",
            "subtechnique_id": None,
            "scenario": "Sensitive Data Staging for Exfiltration",
            "severity": "Medium"
        },
        {
            "pattern": re.compile(r"\bcurl\s+.*(-F|--data|--upload-file)\b", re.IGNORECASE),
            "macro_class": "Collection & Exfiltration",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0010",
            "tactic_name": "Exfiltration",
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol: HTTP Post Exfil",
            "subtechnique_id": "T1048.003",
            "scenario": "Outbound HTTP File Exfiltration",
            "severity": "Critical"
        },

        # =================================================================
        # 9. CREDENTIAL ACCESS & HARVESTING
        # =================================================================
        {
            "pattern": re.compile(r"(id_rsa|id_ed25519|id_ecdsa|\.ssh/id_)", re.IGNORECASE),
            "macro_class": "Credential Access & Harvesting",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1552.004",
            "technique_name": "Unsecured Credentials: Private Keys",
            "subtechnique_id": "T1552.004",
            "scenario": "SSH Private Key Theft Attempt",
            "severity": "Critical"
        },
        {
            "pattern": re.compile(r"\b(cat\s+/etc/shadow|grep.*-i\s+(pass|secret|token|api_key)|notes\.txt)\b", re.IGNORECASE),
            "macro_class": "Credential Access & Harvesting",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1552.001",
            "technique_name": "Unsecured Credentials: Credentials In Files",
            "subtechnique_id": "T1552.001",
            "scenario": "Credentials Extraction from System / Decoy Files",
            "severity": "Critical"
        },
        {
            "pattern": re.compile(r"(\.bash_history|history\b.*grep)", re.IGNORECASE),
            "macro_class": "Credential Access & Harvesting",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1552.003",
            "technique_name": "Unsecured Credentials: Bash History",
            "subtechnique_id": "T1552.003",
            "scenario": "Harvesting Credentials from Command History",
            "severity": "Medium"
        },
        {
            "pattern": re.compile(r"\b(env\b|printenv\b)", re.IGNORECASE),
            "macro_class": "Credential Access & Harvesting",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1552",
            "technique_name": "Unsecured Credentials: Environment Variables",
            "subtechnique_id": None,
            "scenario": "Harvesting Secrets from Environment Variables",
            "severity": "Low"
        },

        # =================================================================
        # 10. DEFENSE EVASION & ANTI-FORENSICS
        # =================================================================
        {
            "pattern": re.compile(r"\b(history\s+-c|unset\s+HISTFILE|cat\s+/dev/null\s*>\s*~?/\.bash_history|export\s+HISTFILESIZE=0)\b", re.IGNORECASE),
            "macro_class": "Defense Evasion & Anti-Forensics",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0005",
            "tactic_name": "Defense Evasion",
            "technique_id": "T1070.003",
            "technique_name": "Indicator Removal: Clear Command History",
            "subtechnique_id": "T1070.003",
            "scenario": "Clear Shell Command History",
            "severity": "High"
        },
        {
            "pattern": re.compile(r"\b(rm\s+-rf?\s+(/var/log|.*\.log))\b", re.IGNORECASE),
            "macro_class": "Defense Evasion & Anti-Forensics",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0005",
            "tactic_name": "Defense Evasion",
            "technique_id": "T1070.002",
            "technique_name": "Indicator Removal: Clear Linux System Logs",
            "subtechnique_id": "T1070.002",
            "scenario": "Tampering & Deleting Linux Security Logs",
            "severity": "High"
        },
        {
            "pattern": re.compile(r"\b(chmod\s+(\+x|[0-7]{3,4}))\b", re.IGNORECASE),
            "macro_class": "Defense Evasion & Anti-Forensics",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0005",
            "tactic_name": "Defense Evasion",
            "technique_id": "T1222.002",
            "technique_name": "File and Directory Permissions Modification: Linux Permissions",
            "subtechnique_id": "T1222.002",
            "scenario": "File Permissions Modification (Chmod)",
            "severity": "Medium"
        },
        {
            "pattern": re.compile(r"\b(rm\s+-rf?)\b", re.IGNORECASE),
            "macro_class": "Defense Evasion & Anti-Forensics",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0005",
            "tactic_name": "Defense Evasion",
            "technique_id": "T1070.004",
            "technique_name": "Indicator Removal: File Deletion",
            "subtechnique_id": "T1070.004",
            "scenario": "Tool Cleanup & File Deletion",
            "severity": "Medium"
        },

        # =================================================================
        # 11. IMPACT & SABOTAGE (SAFE EMULATION) & CRYPTOMINING
        # =================================================================
        {
            "pattern": re.compile(r"\b(xmrig|minerd|minexmr|cryptonight|stratum\+tcp|xmr_miner|\.?/?xmr\b|nohup\s+\./xmr)\b", re.IGNORECASE),
            "macro_class": "Resource Hijacking & Cryptomining",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1496",
            "technique_name": "Resource Hijacking: Cryptomining",
            "subtechnique_id": None,
            "scenario": "Deploying & Executing Cryptomining Malware",
            "severity": "Critical"
        },
        {
            "pattern": re.compile(r"\b(kill\s+-9|killall|pkill)\b", re.IGNORECASE),
            "macro_class": "Impact & Sabotage",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1489",
            "technique_name": "Service Stop",
            "subtechnique_id": None,
            "scenario": "Terminating System Processes / Denial of Service",
            "severity": "High"
        },
        {
            "pattern": re.compile(r"(:\(\)\{\s*:\|:&\s*\};:|rm\s+-rf\s+(/var/www|/home|/root))", re.IGNORECASE),
            "macro_class": "Impact & Sabotage",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1485",
            "technique_name": "Data Destruction / Fork Bomb",
            "subtechnique_id": None,
            "scenario": "Simulated Destructive Action / Resource Exhaustion",
            "severity": "Critical"
        },

        # =================================================================
        # 12. SYSTEM & NETWORK DISCOVERY
        # =================================================================
        {
            "pattern": re.compile(r"\b(whoami|id|groups|w|who)\b", re.IGNORECASE),
            "macro_class": "System & Network Discovery",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0007",
            "tactic_name": "Discovery",
            "technique_id": "T1033",
            "technique_name": "System Owner/User Discovery",
            "subtechnique_id": None,
            "scenario": "System Owner/User Discovery",
            "severity": "Low"
        },
        {
            "pattern": re.compile(r"\b(cat\s+/etc/passwd|cat\s+/etc/group)\b", re.IGNORECASE),
            "macro_class": "System & Network Discovery",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0007",
            "tactic_name": "Discovery",
            "technique_id": "T1087.001",
            "technique_name": "Account Discovery: Local Accounts",
            "subtechnique_id": "T1087.001",
            "scenario": "Local Accounts Enumeration",
            "severity": "Low"
        },
        {
            "pattern": re.compile(r"\b(uname|hostname|cat\s+/etc/os-release|cat\s+/etc/issue|lscpu|free|df|cat\s+/proc/version|uptime)\b", re.IGNORECASE),
            "macro_class": "System & Network Discovery",
            "framework": "MITRE ATT&CK for Enterprise",
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
            "macro_class": "System & Network Discovery",
            "framework": "MITRE ATT&CK for Enterprise",
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
            "macro_class": "System & Network Discovery",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0007",
            "tactic_name": "Discovery",
            "technique_id": "T1016",
            "technique_name": "System Network Configuration Discovery",
            "subtechnique_id": None,
            "scenario": "System Network Configuration Discovery",
            "severity": "Low"
        },
        {
            "pattern": re.compile(r"\b(ping|traceroute)\b", re.IGNORECASE),
            "macro_class": "System & Network Discovery",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0007",
            "tactic_name": "Discovery",
            "technique_id": "T1018",
            "technique_name": "Remote System Discovery: ICMP Ping",
            "subtechnique_id": None,
            "scenario": "Remote Host Reachability Discovery",
            "severity": "Low"
        },
        {
            "pattern": re.compile(r"\b(ls|pwd|cd\b|find\b|dir\b)", re.IGNORECASE),
            "macro_class": "System & Network Discovery",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0007",
            "tactic_name": "Discovery",
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "subtechnique_id": None,
            "scenario": "File and Directory Discovery",
            "severity": "Low"
        }
    ]

    @classmethod
    def map_command(cls, command: str) -> Dict[str, Any]:
        """
        Two-Tier Mapping: Maps raw shell command to Macro-Class (Tier 1) and MITRE Technique (Tier 2).
        """
        cmd = (command or "").strip()
        for rule in cls.RULES:
            if rule["pattern"].search(cmd):
                return {
                    "macro_class": rule["macro_class"],
                    "framework": rule["framework"],
                    "tactic_id": rule["tactic_id"],
                    "tactic_name": rule["tactic_name"],
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "subtechnique_id": rule["subtechnique_id"],
                    "scenario": rule["scenario"],
                    "severity": rule["severity"],
                    "command_evidence": cmd
                }
        
        # Mặc định shell execution thông thường nếu không khớp mẫu đặc thù
        return {
            "macro_class": "Command Execution & Scripting",
            "framework": "MITRE ATT&CK for Enterprise",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.004",
            "technique_name": "Command and Scripting Interpreter: Unix Shell",
            "subtechnique_id": "T1059.004",
            "scenario": "Interactive Unix Shell Command Execution",
            "severity": "Low",
            "command_evidence": cmd
        }

    @classmethod
    def map_auth(cls, success: bool, user: str, password: str) -> Dict[str, Any]:
        """Maps authentication attempt to Tier 1 and Tier 2."""
        if success:
            return {
                "macro_class": "Benign Activity" if user in ["root", "admin"] else "Initial Access via Valid Accounts",
                "framework": "MITRE ATT&CK for Enterprise",
                "tactic_id": "TA0001",
                "tactic_name": "Initial Access",
                "technique_id": "T1078.003",
                "technique_name": "Valid Accounts: Local Accounts",
                "subtechnique_id": "T1078.003",
                "scenario": f"Valid Local Account Access for user '{user}'",
                "severity": "Medium" if user == "root" else "Low",
                "command_evidence": f"SSH Auth Success: user={user}"
            }
        else:
            return {
                "macro_class": "SSH Password Guessing",
                "framework": "MITRE ATT&CK for Enterprise",
                "tactic_id": "TA0006",
                "tactic_name": "Credential Access",
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing",
                "subtechnique_id": "T1110.001",
                "scenario": f"SSH Password Guessing Attempt for user '{user}'",
                "severity": "High",
                "command_evidence": f"SSH Auth Failed: user={user} pass={password}"
            }

    @classmethod
    def map_connection(cls, status: str) -> Dict[str, Any]:
        """Maps raw socket connection / port scan to Tier 1 and Tier 2."""
        if status == "Immediate_Exit":
            return {
                "macro_class": "Port Scan & Connection Probe",
                "framework": "MITRE ATT&CK for Enterprise",
                "tactic_id": "TA0007",
                "tactic_name": "Discovery",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "subtechnique_id": None,
                "scenario": "Network Service Discovery: Port Scan & Banner Grab",
                "severity": "Low",
                "command_evidence": "TCP Socket Connect & Immediate Disconnect"
            }
        else:
            return {
                "macro_class": "Port Scan & Connection Probe",
                "framework": "MITRE ATT&CK for Enterprise",
                "tactic_id": "TA0007",
                "tactic_name": "Discovery",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "subtechnique_id": None,
                "scenario": "Initial Raw Connection Handshake",
                "severity": "Info",
                "command_evidence": "TCP Socket Connect"
            }


# Alias for backward and cross-module compatibility
MitreMapper.classify = MitreMapper.map_command
