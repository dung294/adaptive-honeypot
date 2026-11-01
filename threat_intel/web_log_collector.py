#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - WEB CTI LOG COLLECTOR (DVWA / HTTP INGESTOR)
=============================================================================
Tự động thu thập luồng log từ Web DVWA (cổng 80), phân tích payload tấn công
(SQLi, Command Injection, LFI/RFI, Webshell Upload, XSS, Brute Force)
và gán nhãn MITRE ATT&CK đẩy thẳng vào logs/events.jsonl & logs/sessions.json!
"""

import sys
import os
import re
import json
import time
import urllib.parse
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from threat_intel.logger import HoneypotLogger

# Regex phân tích Apache Combined / Common Log Format
APACHE_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s*(?P<proto>[^"]*)"\s+(?P<status>\d+)\s+(?P<bytes>\S+)'
)

class WebAttackClassifier:
    """Phân loại kỹ thuật tấn công Web theo chuẩn MITRE ATT&CK for Enterprise."""
    
    @staticmethod
    def classify(method: str, uri: str, user_agent: str = "") -> dict:
        decoded_uri = urllib.parse.unquote_plus(uri)

        # 1. COMMAND INJECTION (T1059.004 - Execution)
        if any(x in decoded_uri for x in [";", "|", "`", "$(", "&&"]) and any(c in decoded_uri.lower() for c in ["whoami", "id", "uname", "cat ", "/etc/passwd", "ls", "nc ", "bash", "sh ", "curl", "wget"]):
            return {
                "tactic_id": "TA0002",
                "tactic_name": "Execution",
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell",
                "subtechnique_id": "T1059.004",
                "scenario": "Web OS Command Injection",
                "severity": "Critical"
            }

        # 2. SQL INJECTION (T1190 - Initial Access)
        if any(x in decoded_uri.lower() for x in ["' or '1'='1", "' or 1=1", "union select", "information_schema", "order by", "select * from", "schema()", "version()", "load_file", "into outfile", "sleep(", "benchmark("]):
            return {
                "tactic_id": "TA0001",
                "tactic_name": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application: SQL Injection",
                "subtechnique_id": None,
                "scenario": "SQL Injection (SQLi Data Extraction)",
                "severity": "Critical"
            }

        # 3. FILE INCLUSION / LFI / RFI (T1552.001 - Credential Access)
        if any(x in decoded_uri.lower() for x in ["../", "..\\", "/etc/passwd", "/etc/shadow", "php://filter", "php://input", "data://text/plain", "file://"]):
            return {
                "tactic_id": "TA0006",
                "tactic_name": "Credential Access",
                "technique_id": "T1552.001",
                "technique_name": "Unsecured Credentials: Local File Inclusion (LFI)",
                "subtechnique_id": "T1552.001",
                "scenario": "Local File Inclusion (LFI Path Traversal)",
                "severity": "High"
            }

        # 4. WEBSHELL / MALICIOUS UPLOAD (T1505.003 - Persistence)
        if "upload" in decoded_uri.lower() and (method == "POST" or any(ext in decoded_uri.lower() for ext in [".php", ".phtml", ".phar", ".sh"])):
            return {
                "tactic_id": "TA0003",
                "tactic_name": "Persistence",
                "technique_id": "T1505.003",
                "technique_name": "Server Software Component: Web Shell",
                "subtechnique_id": "T1505.003",
                "scenario": "Malicious Web Shell Upload Attempt",
                "severity": "Critical"
            }

        # 5. CROSS-SITE SCRIPTING / XSS (T1059.007 - Execution)
        if any(x in decoded_uri.lower() for x in ["<script>", "alert(", "onerror=", "onload=", "javascript:", "document.cookie"]):
            return {
                "tactic_id": "TA0002",
                "tactic_name": "Execution",
                "technique_id": "T1059.007",
                "technique_name": "Command and Scripting Interpreter: JavaScript (XSS)",
                "subtechnique_id": "T1059.007",
                "scenario": "Cross-Site Scripting (XSS Probe)",
                "severity": "Medium"
            }

        # 6. BRUTE FORCE LOGIN (T1110.001 - Credential Access)
        if "login.php" in decoded_uri.lower() and method == "POST":
            return {
                "tactic_id": "TA0006",
                "tactic_name": "Credential Access",
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing (HTTP Login)",
                "subtechnique_id": "T1110.001",
                "scenario": "Web HTTP Authentication Brute Force",
                "severity": "High"
            }

        # 7. WEB SCANNER / SCAN PROBE (T1046 - Discovery)
        if any(s in user_agent.lower() for s in ["sqlmap", "nikto", "burp", "zap", "dirbuster", "gobuster", "nmap", "wpscan"]):
            return {
                "tactic_id": "TA0007",
                "tactic_name": "Discovery",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery: Automated Vulnerability Scanner",
                "subtechnique_id": None,
                "scenario": "Automated Web Vulnerability Scan",
                "severity": "Medium"
            }

        # Mặc định duyệt web / trinh sát thông thường
        return {
            "tactic_id": "TA0007",
            "tactic_name": "Discovery",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery: HTTP Reconnaissance",
            "subtechnique_id": None,
            "scenario": "Web HTTP Service Interaction",
            "severity": "Low"
        }

class DVWALogCollector:
    def __init__(self, container_name: str = "dvwa"):
        self.container_name = container_name
        self.logger = HoneypotLogger()

    def process_log_line(self, line: str):
        line = line.strip()
        if not line or "internal dummy connection" in line:
            return

        match = APACHE_LOG_REGEX.search(line)
        if not match:
            return

        ip = match.group("ip")
        method = match.group("method")
        uri = match.group("uri")
        status = int(match.group("status"))

        # Bỏ qua tài nguyên tĩnh (css, js, png, ico) để tránh nhiễu
        if any(uri.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".gif", ".ico", ".woff", ".svg"]):
            return

        decoded_uri = urllib.parse.unquote_plus(uri)
        mitre_block = WebAttackClassifier.classify(method, uri)

        now = datetime.now(timezone.utc).isoformat()
        session_id = f"web-{ip.replace('.', '_')}"

        event_record = {
            "event_key": f"{now}:{session_id}:HTTP_{method}",
            "timestamp": now,
            "source_ip": ip,
            "source_port": 80,
            "protocol": "HTTP",
            "session_id": session_id,
            "username": "web_guest",
            "event_status": "Web_Interaction",
            "message": f"DVWA HTTP {method} [{status}] -> {decoded_uri}",
            "command": f"{method} {decoded_uri}",
            "command_output": f"HTTP Status {status}",
            "handler_type": "WEB_DVWA",
            "latency_ms": 1.5,
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

        # Ghi trực tiếp vào logs/events.jsonl
        self.logger._write_event(event_record)

        # Cập nhật vào sessions.json
        sess = self.logger._get_or_create_session(session_id, ip, 80, "web_attacker")
        sess["duration"]["end_time"] = now
        sess["threat_analysis"]["command_count"] += 1
        sess["threat_analysis"]["mitre_tactics"].add(f"{mitre_block['tactic_id']} - {mitre_block['tactic_name']}")
        sess["threat_analysis"]["mitre_techniques"].add(f"{mitre_block['technique_id']} - {mitre_block['technique_name']}")
        self.logger._update_session_severity(sess, mitre_block["severity"])
        
        if mitre_block["severity"] in ["High", "Critical"]:
            sess["threat_analysis"]["scenario"] = mitre_block["scenario"]

        sess["timeline"].append({
            "step": len(sess["timeline"]) + 1,
            "timestamp": now,
            "command": f"{method} {decoded_uri}",
            "output": f"HTTP {status} Response",
            "handler": "WEB_DVWA",
            "latency_ms": 1.5,
            "mitre_technique": f"{mitre_block['technique_id']} [{mitre_block['tactic_name']}]: {mitre_block['technique_name']}"
        })

        self.logger._flush_session_to_json(session_id)
        print(f"[+] [WEB CTI] {ip} -> {method} {decoded_uri[:60]} [{mitre_block['technique_id']} {mitre_block['scenario']}]")

    def start_collecting(self):
        """Lắng nghe luồng apache access.log liên tục từ container DVWA"""
        print(f"[*] Đang kết nối luồng Apache Access Log từ container '{self.container_name}'...")
        proc = subprocess.Popen(
            ["docker", "exec", "-i", self.container_name, "tail", "-F", "-n", "0", "/var/log/apache2/access.log"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            errors="replace"
        )
        try:
            for line in iter(proc.stdout.readline, ""):
                if line:
                    self.process_log_line(line)
        except Exception as e:
            print(f"[!] Web Log Collector encountered error: {e}")
        finally:
            proc.terminate()

if __name__ == "__main__":
    collector = DVWALogCollector()
    collector.start_collecting()
