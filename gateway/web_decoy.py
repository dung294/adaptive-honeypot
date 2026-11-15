#!/usr/bin/env python3
from flask import Flask, request, Response
import os
import sys
import html
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from forwarder import HoneypotForwarder

app = Flask(__name__)
forwarder = HoneypotForwarder()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Diagnostics & Ping Utility</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 40px 20px; }}
        .container {{ max-width: 740px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }}
        h2 {{ margin-top: 0; color: #58a6ff; font-size: 20px; display: flex; align-items: center; gap: 8px; }}
        p {{ color: #8b949e; font-size: 14px; margin-bottom: 20px; }}
        form {{ display: flex; gap: 10px; margin-bottom: 15px; }}
        input[type="text"] {{ flex: 1; padding: 10px 14px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #58a6ff; font-family: monospace; font-size: 14px; }}
        input[type="text"]:focus {{ outline: none; border-color: #58a6ff; }}
        button {{ padding: 10px 20px; background: #238636; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 14px; }}
        button:hover {{ background: #2ea043; }}
        pre {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; color: #3fb950; overflow-x: auto; font-family: monospace; font-size: 13px; line-height: 1.5; }}
        .footer {{ margin-top: 24px; font-size: 12px; color: #484f58; text-align: center; border-top: 1px solid #21262d; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>🛠️ Network Diagnostics Portal v2.4</h2>
        <p>Execute ICMP ping tests to diagnose network latency and server connectivity.</p>
        <form method="GET" action="/ping">
            <input type="text" name="host" value="{host_val}" placeholder="127.0.0.1" autofocus required>
            <button type="submit">Ping Host</button>
        </form>
        {output_section}
        <div class="footer">Internal Diagnostics Gateway • Kernel: Linux 5.15.0-89-generic</div>
    </div>
</body>
</html>
"""

def simulate_rce_cmd(cmd):
    c = cmd.lower().strip()
    if c == "whoami": return "www-data\n"
    if c == "id": return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    if "uname" in c: return "Linux honeypot-srv 5.15.0-89-generic #99-Ubuntu x86_64 GNU/Linux\n"
    if "cat /etc/passwd" in c:
        return "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n"
    if "cat .env" in c or "cat config" in c:
        return "# Database & Server Config\nSSH_PORT=2222\nSSH_USER=ubuntu\nSSH_PASSWORD=supersecretpassword123\n"
    if c.startswith("wget ") or c.startswith("curl "):
        return f"--2026-11-15-- {c.split()[-1]}\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nSaving to: '{c.split('/')[-1]}'\n"
    return f"{cmd.split()[0]}: command executed successfully.\n"

@app.route("/")
@app.route("/ping", methods=["GET", "POST"])
@app.route("/api/ping", methods=["GET", "POST"])
def ping_rce():
    client_ip = request.remote_addr or "127.0.0.1"
    raw_host = request.args.get("host") or (request.form.get("host") if request.form else "")
    host = raw_host if raw_host else "127.0.0.1"
    
    # Bắn log sang Máy 1 phân tích AI nếu phát hiện payload command injection
    if any(sep in host for sep in [";", "&&", "|", "`", "$("]):
        forwarder.send_web_attack(attacker_ip=client_ip, url=request.url, method=request.method, content=host)

    # Giả lập kết quả ping và command execution
    lines = [f"PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.", "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.035 ms\n"]
    if any(sep in host for sep in [";", "&&", "|"]):
        sub_cmds = [c.strip() for c in host.replace("&&", ";").replace("|", ";").split(";") if c.strip() and c.strip() != "127.0.0.1"]
        for sc in sub_cmds:
            lines.append(simulate_rce_cmd(sc))
    
    plain_output = "\n".join(lines)

    # Nếu người dùng truy cập bằng trình duyệt thông thường, hiển thị giao diện đẹp
    accept = request.headers.get("Accept", "")
    user_agent = request.headers.get("User-Agent", "").lower()
    if "text/html" in accept and "curl" not in user_agent and not request.path.startswith("/api"):
        output_section = f"<pre><code>{html.escape(plain_output)}</code></pre>" if raw_host or request.path == "/ping" else ""
        rendered = HTML_TEMPLATE.format(host_val=html.escape(raw_host or "127.0.0.1"), output_section=output_section)
        return Response(rendered, mimetype="text/html")

    return Response(plain_output, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
