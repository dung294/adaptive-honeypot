# ==============================================================================
# forwarder.py - MODULE BẮN LOG TỪ HONEYPOT MÁY 2 SANG PIPELINE AI MÁY 1
# ==============================================================================
import os
import time
import requests

# Địa chỉ IP của Máy 1 (Lấy từ banner trên SOC Dashboard Máy 1)
DEFAULT_PIPELINE_URL = os.getenv("PIPELINE_URL", "http://192.168.2.76:8000/api/analyze")

class HoneypotForwarder:
    def __init__(self, pipeline_url=None):
        self.pipeline_url = pipeline_url or DEFAULT_PIPELINE_URL

    def send_web_attack(self, attacker_ip: str, url: str, method: str = "GET", content: str = ""):
        """Bắn log Web Decoy (RCE, SQLi, LFI) sang Máy 1"""
        payload = {
            "session_id": f"web-{int(time.time())}",
            "attacker_ip": attacker_ip,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "method": method.upper(),
            "url": url,
            "content": content
        }
        try:
            res = requests.post(self.pipeline_url, json=payload, timeout=3)
            return res.status_code == 200, res.json()
        except Exception as e:
            return False, str(e)

    def send_ssh_attack(self, attacker_ip: str, commands: list, username: str = "root"):
        """Bắn log SSH Honeypot (Commands, Session) sang Máy 1"""
        payload = {
            "session_id": f"ssh-{int(time.time())}",
            "attacker_ip": attacker_ip,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "auth": {
                "username": username,
                "password": "N/A"
            },
            "commands": commands if isinstance(commands, list) else [commands]
        }
        try:
            res = requests.post(self.pipeline_url, json=payload, timeout=3)
            return res.status_code == 200, res.json()
        except Exception as e:
            return False, str(e)
