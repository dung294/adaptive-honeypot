#!/usr/bin/env python3
"""
Script kết nối điều khiển Honeypot / Máy chủ từ xa từ môi trường Windows.
Hỗ trợ dòng lệnh hoặc nhập tương tác.
"""

import sys
import io
import time
import argparse
import getpass
import paramiko

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

def interactive_shell(chan):
    """Xử lý nhập/xuất tương tác cho terminal."""
    import threading

    def receive_loop():
        try:
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                sys.stdout.write(data.decode("utf-8", errors="replace"))
                sys.stdout.flush()
        except Exception:
            pass

    t = threading.Thread(target=receive_loop, daemon=True)
    t.start()

    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            chan.send(line)
            if line.strip() in (":exit", "exit", "quit"):
                time.sleep(0.5)
                break
    except KeyboardInterrupt:
        chan.send("\x03")
    finally:
        chan.close()

def main():
    parser = argparse.ArgumentParser(description="Admin Client điều khiển Honeypot từ Windows")
    parser.add_argument("--host", default="", help="Địa chỉ IP của máy chủ Honeypot")
    parser.add_argument("--port", type=int, default=0, help="Cổng SSH (mặc định 2222)")
    parser.add_argument("--user", default="", help="Tên tài khoản Admin (mặc định admin)")
    parser.add_argument("--password", default="", help="Mật khẩu Admin")
    args = parser.parse_args()

    host = args.host
    if not host:
        host = input("Nhập IP máy chủ [127.0.0.1]: ").strip() or "127.0.0.1"

    port = args.port
    if not port:
        port_str = input("Nhập cổng SSH [2222]: ").strip()
        port = int(port_str) if port_str else 2222

    user = args.user
    if not user:
        user = input("Nhập tên tài khoản [admin]: ").strip() or "admin"

    password = args.password
    if not password:
        password = getpass.getpass(f"Nhập mật khẩu cho '{user}': ").strip()

    print(f"\n[*] Đang kết nối tới {user}@{host}:{port} ...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(hostname=host, port=port, username=user, password=password, timeout=10)
        print("[+] Kết nối SSH thành công!\n")
        
        channel = client.invoke_shell(term="xterm", width=120, height=30)
        time.sleep(0.3)
        
        interactive_shell(channel)
        
    except paramiko.AuthenticationException:
        print("\n[-] [LỖI] Sai tên đăng nhập hoặc mật khẩu!")
    except Exception as e:
        print(f"\n[-] [LỖI] Không thể kết nối: {e}")
    finally:
        client.close()
        print("\n[*] Đã ngắt kết nối.")

if __name__ == "__main__":
    main()
