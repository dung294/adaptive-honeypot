# ==============================================================================
# database.py - KHỞI TẠO CSDL SQLITE CHỨA TÀI KHOẢN MẪU & GHI CHÚ BẪY
# ==============================================================================
import sqlite3
import os
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "web_decoy.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Bảng users (Mục tiêu của SQL Injection)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        note TEXT NOT NULL
    );
    """)

    # Bảng documents (Mục tiêu của Path Traversal / LFI)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL
    );
    """)

    # Xóa dữ liệu cũ nếu có và nạp dữ liệu mẫu
    cursor.execute("DELETE FROM users;")
    cursor.execute("DELETE FROM documents;")

    # Tài khoản bẫy: Hacker dump được mật khẩu SSH 'P@ssw0rd2026!' để pivot sang Port 2222
    users_data = [
        ("admin", "P@ssw0rd2026!", "admin@corp-internal.local", "SuperAdmin", "SSH Gateway Access: Port 2222 (Root Passthrough)"),
        ("secops", "S3cOps#2026Secure", "secops@corp-internal.local", "Security Analyst", "SOC Incident Handling & Monitoring"),
        ("devops", "Dev0ps_Pipeline_Key!9", "devops@corp-internal.local", "DevOps Engineer", "CI/CD Deployment Runner"),
        ("helpdesk", "Support@123", "helpdesk@corp-internal.local", "IT Support", "Standard Domain User")
    ]
    cursor.executemany("INSERT INTO users (username, password, email, role, note) VALUES (?, ?, ?, ?, ?);", users_data)

    docs_data = [
        ("network_topology.txt", "Sơ đồ kiến trúc mạng nội bộ", "Mô tả phân vùng mạng DMZ, Internal LAN và Honeypot Sensor"),
        ("ssh_policy.txt", "Quy định bảo mật SSH Server", "Cổng dịch vụ SSH quản trị: 2222 - Xác thực bằng mật khẩu mạnh"),
        ("incident_response_playbook.pdf", "Quy trình ứng cứu sự cố", "Hướng dẫn cách ly máy chủ khi phát hiện tấn công L7 và RCE")
    ]
    cursor.executemany("INSERT INTO documents (filename, title, description) VALUES (?, ?, ?);", docs_data)

    conn.commit()
    conn.close()
    print(f"[*] Đã khởi tạo CSDL thành công tại: {DB_PATH}")

if __name__ == "__main__":
    init_db()
