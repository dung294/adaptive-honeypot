#!/usr/bin/env python3
# ==============================================================================
# app.py - CỔNG BẪY QUẢN TRỊ MẠNG NỘI BỘ (WEB DECOY GATEWAY)
# Đề tài: Hệ thống Honeypot thông minh kết hợp AI, MITRE ATT&CK & CTI
# ==============================================================================
import os
import sys
import time
import uuid
import sqlite3
import threading
import requests
from datetime import datetime
from pathlib import Path
from flask import Flask, request, render_template, redirect, url_for, session, Response

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "decoy-secret-key-2026-honeypot-dmz")

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "web_decoy.db"

# Địa chỉ API tiếp nhận log của Máy 1 (SOC & AI Pipeline)
PIPELINE_URL = os.getenv("PIPELINE_URL", "http://192.168.2.76:8000/api/analyze")

# Khởi tạo CSDL nếu chưa có
if not DB_PATH.exists():
    from database import init_db
    init_db()

# ==============================================================================
# HÀM BẮN LOG BẰNG BACKGROUND THREAD (KHÔNG LÀM CHẬM WEB CỦA NGƯỜI DÙNG)
# ==============================================================================
def forward_to_soc(attacker_ip: str, url: str, method: str, content: str = ""):
    """
    Gửi gói tin HTTP POST JSON chứa thông tin tấn công sang Máy 1 (Port 8000).
    Chạy trên background thread (non-blocking) để web luôn phản hồi mượt mà (< 10ms).
    """
    def _worker():
        payload = {
            "session_id": f"web-{uuid.uuid4().hex[:12]}",
            "attacker_ip": attacker_ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "method": method.upper(),
            "url": url,
            "content": content or ""
        }
        try:
            headers = {"Content-Type": "application/json"}
            res = requests.post(PIPELINE_URL, json=payload, headers=headers, timeout=3)
            if res.status_code == 200:
                print(f"[+] [SOC FORWARD OK] Đã bắn log sang Máy 1: {method} {url} | Attacker: {attacker_ip}")
            else:
                print(f"[-] [SOC FORWARD WARN] Máy 1 phản hồi HTTP {res.status_code}")
        except Exception as e:
            print(f"[!] [SOC FORWARD FAIL] Không thể kết nối tới Máy 1 ({PIPELINE_URL}): {e}")

    threading.Thread(target=_worker, daemon=True).start()

def get_client_ip():
    """Lấy IP thực của Hacker, hỗ trợ trường hợp đứng sau Proxy / NAT"""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

# ==============================================================================
# SIMULATOR CHO COMMAND INJECTION (RCE)
# ==============================================================================
ENV_LEAK_CONTENT = """# ==============================================================================
# ENTERPRISE GATEWAY PRODUCTION CONFIGURATION - HIGH PRIVILEGE ENVIRONMENT
# ==============================================================================
APP_ENV=production
DEBUG=false
DB_CONNECTION=sqlite:///app/web_decoy.db

# [CRITICAL SECURITY NOTICE]
# OpenSSH Maintenance Gateway for SysAdmins:
SSH_HOST=0.0.0.0
SSH_PORT=2222
SSH_USER=admin
SSH_PASSWORD=P@ssw0rd2026!
"""

PASSWD_CONTENT = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
admin:x:1000:1000:Administrator,,,:/home/admin:/bin/bash
secops:x:1001:1001:SOC Analyst,,,:/home/secops:/bin/bash
devops:x:1002:1002:CI/CD Automation,,,:/home/devops:/bin/bash
"""

def simulate_rce_cmd(cmd: str) -> str:
    c = cmd.strip()
    c_lower = c.lower()

    if c_lower in ("whoami", "id -un"):
        return "www-data\n"
    if c_lower == "id":
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    if "uname" in c_lower:
        return "Linux edge-gw-01 5.15.0-89-generic #99-Ubuntu SMP x86_64 GNU/Linux\n"
    if "cat .env" in c_lower or "cat /app/.env" in c_lower or "cat config" in c_lower:
        return ENV_LEAK_CONTENT
    if "cat /etc/passwd" in c_lower:
        return PASSWD_CONTENT
    if c_lower in ("ls", "ls -l", "ls -la", "dir"):
        return "-rw-r--r-- 1 root root  420 Nov 15 17:30 .env\n-rw-r--r-- 1 root root 8192 Nov 15 17:30 app.py\n-rw-r--r-- 1 root root 2048 Nov 15 17:30 database.py\n-rw-r--r-- 1 root root 12288 Nov 15 17:30 web_decoy.db\ndrwxr-xr-x 2 root root 4096 Nov 15 17:30 templates/\n"
    if c_lower.startswith("ping"):
        return "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms\n"
    if c_lower.startswith("wget ") or c_lower.startswith("curl "):
        filename = c.split()[-1].split("/")[-1] or "payload.sh"
        return f"--2026-11-15 17:30:12-- {c.split()[-1]}\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 4120 [application/x-sh]\nSaving to: '{filename}'\n\n2026-11-15 17:30:12 (12.4 MB/s) - '{filename}' saved [4120/4120]\n"
    
    return f"{c.split()[0]}: command executed successfully.\n"

# ==============================================================================
# CÁC ROUTE CỦA WEB DECOY
# ==============================================================================

@app.route("/")
def index():
    """Trang chủ hiển thị Cổng chẩn đoán mạng & Tài liệu kỹ thuật"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, title, description FROM documents;")
    docs = cursor.fetchall()
    
    users_list = []
    current_user = session.get("user")
    if current_user:
        cursor.execute("SELECT id, username, password, email, role, note FROM users;")
        users_list = cursor.fetchall()
    conn.close()

    return render_template("index.html", documents=docs, user=current_user, users_list=users_list)

# ------------------------------------------------------------------------------
# 1. LỖ HỔNG COMMAND INJECTION (RCE) TẠI /api/ping
# ------------------------------------------------------------------------------
@app.route("/api/ping", methods=["GET", "POST"])
@app.route("/ping", methods=["GET", "POST"])
def ping_api():
    client_ip = get_client_ip()
    raw_host = request.args.get("host") or (request.form.get("host") if request.form else "")
    host = raw_host.strip() if raw_host else "127.0.0.1"

    # Nhận diện hành vi Command Injection
    is_injection = any(sep in host for sep in [";", "&&", "|", "`", "$(", "$", "\n"])
    if is_injection:
        # BẮN LOG SANG MÁY 1 (T1059 / T1190)
        forward_to_soc(
            attacker_ip=client_ip,
            url=request.url,
            method=request.method,
            content=host
        )

    # Giả lập kết quả thực thi
    lines = [
        f"PING {host.split(';')[0].split('&')[0].split('|')[0].strip()} (127.0.0.1) 56(84) bytes of data.",
        "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms",
        "64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.041 ms\n"
    ]
    if is_injection:
        sub_cmds = [c.strip() for c in host.replace("&&", ";").replace("|", ";").split(";") if c.strip() and c.strip() != "127.0.0.1"]
        for sc in sub_cmds:
            lines.append(simulate_rce_cmd(sc))
    
    lines.append("--- ping statistics ---")
    lines.append("2 packets transmitted, 2 received, 0% packet loss, time 1002ms")
    plain_output = "\n".join(lines)

    # Nếu truy cập bằng trình duyệt thông thường, hiển thị trên giao diện HTML
    accept = request.headers.get("Accept", "")
    user_agent = request.headers.get("User-Agent", "").lower()
    if "text/html" in accept and "curl" not in user_agent and not request.path.endswith("/api/ping"):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, filename, title, description FROM documents;")
        docs = cursor.fetchall()
        conn.close()
        return render_template("index.html", host=host, ping_output=plain_output, documents=docs, user=session.get("user"))

    return Response(plain_output, mimetype="text/plain")

# ------------------------------------------------------------------------------
# 2. LỖ HỔNG SQL INJECTION (SQLi) TẠI /login
# ------------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    client_ip = get_client_ip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    raw_body = f"username={username}&password={password}"

    # Nhận diện dấu hiệu SQL Injection (' OR '1'='1, UNION, --, /*)
    sqli_indicators = ["'", "\"", "--", "/*", " or ", " OR ", " union ", " UNION ", "sleep(", "benchmark("]
    is_sqli = any(pat in username or pat in password for pat in sqli_indicators)
    if is_sqli:
        # BẮN LOG SANG MÁY 1 (T1190)
        forward_to_soc(
            attacker_ip=client_ip,
            url=request.url,
            method=request.method,
            content=raw_body
        )

    # Thực thi câu truy vấn CỐ TÌNH NỐI CHUỖI (Vulnerable to SQLi)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT id, username, password, email, role, note FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        user_row = cursor.fetchone()

        # Hỗ trợ bypass SQLi linh hoạt kể cả khi không có comment --
        if not user_row and is_sqli and any(p in username.lower() for p in ["'1'='1", "1=1", "''='", "or true"]):
            cursor.execute("SELECT id, username, password, email, role, note FROM users WHERE role='SuperAdmin' LIMIT 1;")
            user_row = cursor.fetchone()

        conn.close()

        if user_row:
            # Bypass hoặc đăng nhập thành công!
            session["user"] = {
                "id": user_row[0],
                "username": user_row[1],
                "email": user_row[3],
                "role": user_row[4],
                "note": user_row[5]
            }
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Tài khoản hoặc mật khẩu không chính xác! (Invalid Credentials)")

    except sqlite3.OperationalError as e:
        conn.close()
        # Trả về lỗi SQL chân thực để hacker khai thác Error-based / Boolean-based SQLi
        return render_template("login.html", error=f"Database Query Syntax Error: {str(e)} (Query: {query})")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

# ------------------------------------------------------------------------------
# 3. LỖ HỔNG PATH TRAVERSAL (LFI) TẠI /view
# ------------------------------------------------------------------------------
@app.route("/view")
def view_document():
    client_ip = get_client_ip()
    file_param = request.args.get("file", "").strip()

    # Nhận diện hành vi Path Traversal / LFI
    is_lfi = any(pattern in file_param for pattern in ["../", "..\\", "/etc/passwd", ".env", "win.ini", "boot.ini"])
    if is_lfi:
        # BẮN LOG SANG MÁY 1 (T1083 / T1190)
        forward_to_soc(
            attacker_ip=client_ip,
            url=request.url,
            method=request.method,
            content=file_param
        )

    # Giả lập trả về file nhạy cảm
    if "passwd" in file_param:
        content = PASSWD_CONTENT
    elif ".env" in file_param or "config" in file_param:
        content = ENV_LEAK_CONTENT
    elif file_param == "ssh_policy.txt":
        content = "=== QUY ĐỊNH BẢO MẬT DỊCH VỤ SSH ===\n- Port dịch vụ: 2222\n- Tài khoản root bị vô hiệu hóa đăng nhập từ xa.\n- Tài khoản bảo trì được ủy quyền: 'admin'\n- Mật khẩu quản trị cấp cao định kỳ: P@ssw0rd2026!\n"
    elif file_param == "network_topology.txt":
        content = "=== SƠ ĐỒ HẠ TẦNG MẠNG NỘI BỘ ===\n- Cổng tiếp nhận Web DMZ: Port 80 (edge-gw-01)\n- Cổng SSH Gateway Honeypot: Port 2222\n- SOC Core Machine 1 Ingestion: http://172.18.0.5:8000/api/analyze\n"
    else:
        content = f"--- [TÀI LIỆU NỘI BỘ: {file_param}] ---\nTài liệu đã được lưu trữ an toàn trong kho lưu trữ điện tử. Mọi yêu cầu truy xuất đều được lưu vết phục vụ công tác thanh tra An toàn thông tin."

    # Nếu truy cập bằng curl, trả về text thuần
    user_agent = request.headers.get("User-Agent", "").lower()
    if "curl" in user_agent:
        return Response(content, mimetype="text/plain")

    # Render vào template
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, title, description FROM documents;")
    docs = cursor.fetchall()
    conn.close()

    return render_template("index.html", documents=docs, current_file=file_param, file_content=content, user=session.get("user"))

if __name__ == "__main__":
    port = int(os.getenv("PORT", 80))
    print(f"[*] Cổng bẫy Web Decoy đang khởi chạy tại http://0.0.0.0:{port}")
    print(f"[*] Log sẽ được tự động bắn về Máy 1: {PIPELINE_URL}")
    app.run(host="0.0.0.0", port=port, debug=False)
