#!/usr/bin/env python3
from flask import Flask, request, Response
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from forwarder import HoneypotForwarder

app = Flask(__name__)
forwarder = HoneypotForwarder()

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
    host = request.args.get("host") or (request.form.get("host") if request.form else "") or "127.0.0.1"
    
    # Bắn log sang Máy 1 phân tích AI
    if any(sep in host for sep in [";", "&&", "|", "`", "$("]):
        forwarder.send_web_attack(attacker_ip=client_ip, url=request.url, method=request.method, content=host)

    # Trả về kết quả RCE chân thực cho Hacker xem
    lines = [f"PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.", "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.035 ms\n"]
    if any(sep in host for sep in [";", "&&", "|"]):
        sub_cmds = [c.strip() for c in host.replace("&&", ";").replace("|", ";").split(";") if c.strip() and c.strip() != "127.0.0.1"]
        for sc in sub_cmds:
            lines.append(simulate_rce_cmd(sc))
    
    return Response("\n".join(lines), mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
