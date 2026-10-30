import re
from typing import List, Dict

class MitreMapper:
    """
    Module tự động đối sánh lệnh với ma trận MITRE ATT&CK for Enterprise.
    Giúp tự động phân loại chiến thuật (Tactics) và kỹ thuật (Techniques).
    """
    RULES = [
        (r"\b(uname|hostname|cat\s+/etc/os-release|cat\s+/etc/issue)\b", "T1082", "System Information Discovery", "Discovery"),
        (r"\b(whoami|id|groups)\b", "T1033", "System Owner/User Discovery", "Discovery"),
        (r"\b(cat\s+/etc/passwd|cat\s+/etc/shadow)\b", "T1087.001", "Local Account Discovery", "Discovery"),
        (r"\b(ps|top|htop|pstree)\b", "T1057", "Process Discovery", "Discovery"),
        (r"\b(ifconfig|ip\s+addr|ip\s+a|netstat|ss|route|arp)\b", "T1016", "System Network Configuration Discovery", "Discovery"),
        (r"\b(curl|wget|scp|sftp|ftp|tftp)\b", "T1105", "Ingress Tool Transfer", "Command and Control"),
        (r"\b(chmod\s+(\+x|[0-7]{3,4}))\b", "T1222.002", "Linux File and Directory Permissions Modification", "Defense Evasion"),
        (r"\b(python3?|perl|bash|sh|zsh|php)\b", "T1059.004", "Unix Shell", "Execution"),
        (r"\b(crontab|/etc/cron)\b", "T1053.003", "Cron", "Persistence"),
        (r"\b(rm\s+-rf?|history\s+-c)\b", "T1070.004", "File Deletion / Indicator Removal", "Defense Evasion"),
    ]

    @classmethod
    def map_command(cls, command: str) -> List[Dict[str, str]]:
        matches = []
        for pattern, tech_id, tech_name, tactic in cls.RULES:
            if re.search(pattern, command, re.IGNORECASE):
                matches.append({
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic": tactic
                })
        return matches
