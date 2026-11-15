#!/usr/bin/env python3
# ==============================================================================
# web_decoy.py - CỬA HÀNG ĐIỆN TỬ TECHSHOP (E-COMMERCE HONEYPOT WEB)
# Tích hợp lỗ hổng SQL Injection, Path Traversal (LFI) & Command Injection (RCE)
# Tự động bắn log JSON sang Máy 1 (Port 8000: /api/analyze)
# ==============================================================================
import os
import sys
import uuid
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, request, render_template, redirect, url_for, session, Response

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
app.secret_key = os.getenv("SECRET_KEY", "techshop-decoy-ecommerce-secret-key-2026")

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
from forwarder import HoneypotForwarder
from gateway.shop_db import init_shop_db, ensure_schema, DB_PATH

forwarder = HoneypotForwarder()

def get_db():
    try:
        return sqlite3.connect(DB_PATH)
    except Exception:
        conn = sqlite3.connect(":memory:")
        return conn

# Đảm bảo CSDL luôn đầy đủ cột mới nhất
try:
    ensure_schema()
except Exception:
    pass

def get_client_ip():
    """Lấy IP thực của Hacker (hỗ trợ reverse proxy / NAT)"""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

# ==============================================================================
# MẪU NỘI DUNG RÒ RỈ CHO RCE VÀ LFI (LEAK SSH CREDENTIALS ĐỂ PIVOT PORT 2222)
# ==============================================================================
ENV_LEAK = """# ==============================================================================
# TECHSHOP E-COMMERCE PRODUCTION ENVIRONMENT CONFIGURATION
# ==============================================================================
APP_ENV=production
DEBUG=false
DB_CONNECTION=sqlite:///app/gateway/shop.db

# [CRITICAL SECURITY NOTICE]
# Remote Maintenance OpenSSH Gateway for DevOps & System Admins:
SSH_HOST=0.0.0.0
SSH_PORT=2222
SSH_USER=ubuntu
SSH_PASSWORD=supersecretpassword123
ADMIN_USER=admin
ADMIN_PASSWORD=P@ssw0rd2026!
"""

PASSWD_LEAK = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu User,,,:/home/ubuntu:/bin/bash
admin:x:1001:1001:System Administrator,,,:/home/admin:/bin/bash
kho_hang:x:1002:1002:Warehouse Manager,,,:/home/kho_hang:/bin/bash
"""

def simulate_rce_cmd(cmd: str) -> str:
    c = cmd.strip()
    c_lower = c.lower()

    if c_lower in ("whoami", "id -un"):
        return "www-data\n"
    if c_lower == "id":
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    if "uname" in c_lower:
        return "Linux honeypot-srv 5.15.0-89-generic #99-Ubuntu x86_64 GNU/Linux\n"
    if "cat .env" in c_lower or "cat /app/.env" in c_lower or "cat config" in c_lower:
        return ENV_LEAK
    if "cat /etc/passwd" in c_lower:
        return PASSWD_LEAK
    if c_lower in ("ls", "ls -l", "ls -la", "dir"):
        return "-rw-r--r-- 1 root root  420 Nov 15 17:30 .env\n-rw-r--r-- 1 root root 8192 Nov 15 17:30 app.py\n-rw-r--r-- 1 root root 16384 Nov 15 17:30 shop.db\ndrwxr-xr-x 2 root root 4096 Nov 15 17:30 templates/\n"
    if c_lower.startswith("wget ") or c_lower.startswith("curl "):
        filename = c.split()[-1].split("/")[-1] or "payload.sh"
        return f"--2026-11-15 17:30:12-- {c.split()[-1]}\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nSaving to: '{filename}'\n"
    return f"{c.split()[0]}: command executed successfully.\n"

# ==============================================================================
# CÁC ROUTE CỦA WEB TECHSHOP
# ==============================================================================

@app.route("/")
def index():
    """Trang chủ hiển thị danh mục sản phẩm thời trang Coolmate"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, category, price, old_price, description, badge, colors, icon FROM products;")
        products = cursor.fetchall()
        cursor.execute("SELECT id, invoice_code, customer_name, total_amount, file_path FROM invoices;")
        invoices = cursor.fetchall()
        conn.close()
    except Exception:
        init_shop_db()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, category, price, old_price, description, badge, colors, icon FROM products;")
        products = cursor.fetchall()
        cursor.execute("SELECT id, invoice_code, customer_name, total_amount, file_path FROM invoices;")
        invoices = cursor.fetchall()
        conn.close()

    return render_template("shop_index.html", products=products, invoices=invoices, user=session.get("user"))

# ------------------------------------------------------------------------------
# 1. LỖ HỔNG SQL INJECTION (SQLi) TẠI TÌM KIẾM SẢN PHẨM /search
# ------------------------------------------------------------------------------
@app.route("/search")
def search():
    client_ip = get_client_ip()
    q = request.args.get("q", "").strip()

    # Nhận diện hành vi SQL Injection
    sqli_keywords = ["'", "\"", "--", "/*", " or ", " OR ", " union ", " UNION ", "select", "SELECT"]
    is_sqli = any(kw in q for kw in sqli_keywords)

    if is_sqli:
        # BẮN LOG TẤN CÔNG WEB SANG MÁY 1 (T1190)
        forwarder.send_web_attack(attacker_ip=client_ip, url=request.url, method=request.method, content=q)

    conn = get_db()
    cursor = conn.cursor()
    
    # Câu truy vấn CỐ TÌNH NỐI CHUỖI KHÔNG AN TOÀN (Vulnerable to SQLi)
    query = f"SELECT id, name, category, price, old_price, description, badge, colors, icon FROM products WHERE name LIKE '%{q}%'"
    
    sqli_exposed = False
    try:
        cursor.execute(query)
        products = cursor.fetchall()
    except sqlite3.OperationalError:
        products = []
        sqli_exposed = True

    cursor.execute("SELECT id, invoice_code, customer_name, total_amount, file_path FROM invoices;")
    invoices = cursor.fetchall()
    conn.close()

    return render_template("shop_index.html", products=products, invoices=invoices, query=q, sqli_exposed=sqli_exposed, user=session.get("user"))

# ------------------------------------------------------------------------------
# 2. LỖ HỔNG PATH TRAVERSAL (LFI) TẠI TRA CỨU HÓA ĐƠN /invoice HOẶC /view
# ------------------------------------------------------------------------------
@app.route("/invoice")
@app.route("/view")
def view_invoice():
    client_ip = get_client_ip()
    file_param = request.args.get("file", "").strip()

    # Nhận diện LFI
    is_lfi = any(pattern in file_param for pattern in ["../", "..\\", "/etc/passwd", ".env", "win.ini"])
    if is_lfi:
        # BẮN LOG TẤN CÔNG SANG MÁY 1 (T1083 / T1190)
        forwarder.send_web_attack(attacker_ip=client_ip, url=request.url, method=request.method, content=file_param)

    if "passwd" in file_param:
        content = PASSWD_LEAK
    elif ".env" in file_param or "config" in file_param:
        content = ENV_LEAK
    elif file_param == "invoice_001.pdf":
        content = "=== HÓA ĐƠN ĐIỆN TỬ GTGT (VAT INVOICE: INV-2026-001) ===\nKhách hàng: Nguyễn Văn An\nSản phẩm: Laptop Dell XPS 15 9530 (1x) - 34.990.000 đ\nThuế VAT (10%): 3.499.000 đ\nTổng thanh toán: 38.489.000 đ\nTrạng thái: Đã thanh toán qua VNPAY-QR\n"
    elif file_param == "invoice_002.pdf":
        content = "=== HÓA ĐƠN ĐIỆN TỬ GTGT (VAT INVOICE: INV-2026-002) ===\nKhách hàng: Phạm Quốc Bảo\nSản phẩm: iPhone 15 Pro Max 256GB (1x) - 29.490.000 đ\nTổng thanh toán: 32.439.000 đ\nTrạng thái: Đã xuất kho giao vận\n"
    else:
        content = f"--- [HỆ THỐNG LƯU TRỮ HÓA ĐƠN: {file_param}] ---\nChứng từ điện tử đã được xác thực chữ ký số an toàn bởi CACS Gateway."

    if "curl" in request.headers.get("User-Agent", "").lower():
        return Response(content, mimetype="text/plain")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, category, price, old_price, description, badge, colors, icon FROM products;")
    products = cursor.fetchall()
    cursor.execute("SELECT id, invoice_code, customer_name, total_amount, file_path FROM invoices;")
    invoices = cursor.fetchall()
    conn.close()

    return render_template("shop_index.html", products=products, invoices=invoices, current_file=file_param, file_content=content, user=session.get("user"))

# ------------------------------------------------------------------------------
# 3. LỖ HỔNG COMMAND INJECTION (RCE) TẠI KIỂM TRA MẠNG KHO VẬN /admin/diagnostics
# ------------------------------------------------------------------------------
@app.route("/admin/diagnostics", methods=["GET", "POST"])
@app.route("/api/ping", methods=["GET", "POST"])
@app.route("/ping", methods=["GET", "POST"])
def ping_diagnostics():
    client_ip = get_client_ip()
    raw_host = request.args.get("host") or (request.form.get("host") if request.form else "")
    host = raw_host.strip() if raw_host else "127.0.0.1"

    is_injection = any(sep in host for sep in [";", "&&", "|", "`", "$(", "$", "\n"])
    if is_injection:
        # BẮN LOG TẤN CÔNG WEB RCE SANG MÁY 1 (T1059 / T1190)
        forwarder.send_web_attack(attacker_ip=client_ip, url=request.url, method=request.method, content=host)

    lines = [
        f"PING {host.split(';')[0].split('&')[0].split('|')[0].strip()} (127.0.0.1) 56(84) bytes of data.",
        "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms\n"
    ]
    if is_injection:
        sub_cmds = [c.strip() for c in host.replace("&&", ";").replace("|", ";").split(";") if c.strip() and c.strip() != "127.0.0.1"]
        for sc in sub_cmds:
            lines.append(simulate_rce_cmd(sc))

    plain_output = "\n".join(lines)

    # Hiển thị trên template nếu người dùng truy cập bằng trình duyệt
    accept = request.headers.get("Accept", "")
    user_agent = request.headers.get("User-Agent", "").lower()
    if "text/html" in accept and "curl" not in user_agent and not request.path.startswith("/api"):
        return render_template("shop_diagnostics.html", host=host, ping_output=plain_output)

    return Response(plain_output, mimetype="text/plain")

# ------------------------------------------------------------------------------
# 4. LỖ HỔNG SQL INJECTION (SQLi) TẠI TRANG ĐĂNG NHẬP NHÂN VIÊN /login
# ------------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("shop_login.html")

    client_ip = get_client_ip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    raw_body = f"username={username}&password={password}"

    # Nhận diện SQLi
    sqli_indicators = ["'", "\"", "--", "/*", " or ", " OR ", " union ", " UNION "]
    if any(pat in username or pat in password for pat in sqli_indicators):
        forwarder.send_web_attack(attacker_ip=client_ip, url=request.url, method=request.method, content=raw_body)

    conn = get_db()
    cursor = conn.cursor()
    # Nối chuỗi SQL không an toàn
    query = f"SELECT id, username, password, fullname, email, role, note FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        user_row = cursor.fetchone()
        
        # Nếu nhập payload SQLi kinh điển (' OR '1'='1) dù có hay không có comment -- vẫn bypass thành công
        if not user_row and is_sqli and any(p in username.lower() for p in ["'1'='1", "1=1", "''='", "or true"]):
            cursor.execute("SELECT id, username, password, fullname, email, role, note FROM users WHERE role='SuperAdmin' LIMIT 1;")
            user_row = cursor.fetchone()

        conn.close()

        if user_row:
            session["user"] = {
                "id": user_row[0],
                "username": user_row[1],
                "fullname": user_row[3],
                "email": user_row[4],
                "role": user_row[5],
                "note": user_row[6]
            }
            return redirect(url_for("admin_dashboard"))
        else:
            return render_template("shop_login.html", error="Tài khoản hoặc mật khẩu không chính xác! (Invalid Credentials)")

    except sqlite3.OperationalError as e:
        conn.close()
        return render_template("shop_login.html", error=f"Database Query Error: {str(e)} (Query: {query})")

@app.route("/admin/dashboard")
def admin_dashboard():
    """Bảng quản trị sau khi login thành công (hiển thị danh sách user và leak SSH credentials)"""
    current_user = session.get("user")
    if not current_user:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, fullname, email, role, note FROM users;")
    users_list = cursor.fetchall()
    conn.close()

    return render_template("shop_admin.html", user=current_user, users_list=users_list)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
