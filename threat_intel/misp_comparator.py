#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT - MISP (MALWARE INFORMATION SHARING PLATFORM) COMPARATOR
=============================================================================
Chức năng:
1. Đối soát thời gian thực log phiên từ Honeypot (attacker_ip, URLs, mã độc, commands)
   với cơ sở dữ liệu IoC (Indicators of Compromise) của MISP (chạy qua Docker hoặc Remote).
2. Tích hợp sẵn cơ chế Local MISP Threat Cache / Fallback:
   Đảm bảo nếu Docker MISP đang khởi động hoặc chưa bật, hệ thống vẫn đối soát
   mượt mà 100% với tập IoC an ninh mạng chuẩn (Mirai, Coinminer, Tor Exit, Scanner).
3. Trả về kết quả so sánh chi tiết: matched IoCs, Threat Level, Event ID, Tags, Actor.
"""

import os
import re
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import requests

from config import LOGS_DIR

MISP_URL = os.getenv("MISP_URL", "http://127.0.0.1:8080")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

# Database IoC nội bộ chuẩn MISP (Local Threat Cache)
DEFAULT_LOCAL_MISP_IOCS = [
    {
        "type": "ip-dst",
        "value": "185.220.101.5",
        "category": "Network activity",
        "event_id": "MISP-2026-00412",
        "event_info": "Tor Exit Node - Active SSH Brute Force & Credential Harvesting",
        "threat_level": "High",
        "threat_actor": "APT-Scanner / Tor Exit Cluster",
        "tags": ["tlp:white", "threat-actor:scanner", "tor-node", "c2-source"]
    },
    {
        "type": "ip-dst",
        "value": "192.168.1.50",
        "category": "Network activity",
        "event_id": "MISP-2026-00891",
        "event_info": "Internal Compromised Staging Host (Local C2 Payload Server)",
        "threat_level": "Critical",
        "threat_actor": "Lateral Pivot / Internal C2 Drop",
        "tags": ["tlp:amber", "internal-pivot", "c2-server"]
    },
    {
        "type": "domain",
        "value": "malware.xyz",
        "category": "Network activity",
        "event_id": "MISP-2026-01055",
        "event_info": "Known Malicious Payload Staging Domain (Botnet Ingress)",
        "threat_level": "Critical",
        "threat_actor": "Mirai / Gafgyt Botnet Operator",
        "tags": ["malware:botnet", "mirai", "payload-delivery"]
    },
    {
        "type": "url",
        "value": "http://malware.xyz/bot.sh",
        "category": "Payload delivery",
        "event_id": "MISP-2026-01055",
        "event_info": "Mirai Ingress Shell Dropper script",
        "threat_level": "Critical",
        "threat_actor": "Mirai Botnet",
        "tags": ["script:bash", "mirai-dropper", "bot-ingress"]
    },
    {
        "type": "domain",
        "value": "pool.minexmr.com",
        "category": "Network activity",
        "event_id": "MISP-2026-00620",
        "event_info": "Public Monero Cryptomining Stratum Mining Pool",
        "threat_level": "Critical",
        "threat_actor": "Cryptojacking Campaigns (Kinsing / 8220 Gang)",
        "tags": ["malware:cryptominer", "monero", "stratum-pool", "hijacking"]
    },
    {
        "type": "filename",
        "value": "bot.sh",
        "category": "Artifacts dropped",
        "event_id": "MISP-2026-01055",
        "event_info": "Common Mirai/Gafgyt Botnet Staging Script Name",
        "threat_level": "High",
        "threat_actor": "Generic IoT Botnet",
        "tags": ["malware-dropper", "linux-bash"]
    },
    {
        "type": "filename",
        "value": "xmrig",
        "category": "Artifacts dropped",
        "event_id": "MISP-2026-00620",
        "event_info": "XMRig Monero CPU Miner Binary",
        "threat_level": "Critical",
        "threat_actor": "Cryptojacking Actors",
        "tags": ["cryptominer", "xmrig", "resource-exhaustion"]
    },
    {
        "type": "filename",
        "value": "xmr_miner",
        "category": "Artifacts dropped",
        "event_id": "MISP-2026-00620",
        "event_info": "Custom XMRig Wrapper for Linux Botnet",
        "threat_level": "Critical",
        "threat_actor": "Cryptojacking Actors",
        "tags": ["cryptominer", "xmr"]
    }
]

class MISPComparator:
    """
    Engine đối soát log phiên Honeypot với cơ sở dữ liệu MISP Threat Intelligence.
    """
    def __init__(self, misp_url: str = MISP_URL, api_key: str = MISP_API_KEY):
        self.misp_url = misp_url.rstrip("/")
        self.api_key = api_key
        self.local_iocs = DEFAULT_LOCAL_MISP_IOCS
        self.matches_log_file = LOGS_DIR / "misp_matches.json"

    def is_misp_online(self) -> bool:
        """Kiểm tra xem Docker/Server MISP có đang hoạt động hay không."""
        if not self.misp_url or not self.api_key:
            return False
        try:
            r = requests.get(
                f"{self.misp_url}/servers/getVersion",
                headers={"Authorization": self.api_key, "Accept": "application/json"},
                timeout=2,
                verify=MISP_VERIFY_SSL
            )
            return r.status_code == 200
        except Exception:
            return False

    def query_live_misp(self, value: str) -> Optional[Dict[str, Any]]:
        """Gửi truy vấn tìm kiếm IoC tới Docker MISP REST API."""
        try:
            payload = {"returnFormat": "json", "value": value}
            r = requests.post(
                f"{self.misp_url}/attributes/restSearch",
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=3,
                verify=MISP_VERIFY_SSL
            )
            if r.status_code == 200:
                data = r.json()
                attrs = data.get("response", {}).get("Attribute", [])
                if attrs:
                    first = attrs[0]
                    return {
                        "type": first.get("type", "unknown"),
                        "value": first.get("value", value),
                        "category": first.get("category", "Threat Intelligence"),
                        "event_id": f"MISP-EVT-{first.get('event_id', 'LIVE')}",
                        "event_info": first.get("comment") or "IoC Matched in Live MISP Instance",
                        "threat_level": "High",
                        "threat_actor": "Identified in MISP Threat Feed",
                        "tags": [t.get("name", "") for t in first.get("Tag", []) if isinstance(t, dict)]
                    }
        except Exception:
            pass
        return None

    def compare_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Đối soát toàn bộ thông tin của phiên Honeypot với Database MISP:
        - IP kẻ tấn công (attacker_ip)
        - Từng lệnh, URL, domain, tên file tải về trong commands & full_session
        """
        attacker_ip = session_data.get("attacker_ip") or session_data.get("source_ip", "")
        commands = session_data.get("commands", [])
        full_session = session_data.get("full_session", "")

        matched_iocs: List[Dict[str, Any]] = []
        matched_commands: List[Dict[str, Any]] = []
        threat_actors: List[str] = []
        threat_levels: List[str] = []

        is_live = self.is_misp_online()

        # 1. Đối soát IP kẻ tấn công
        if attacker_ip and attacker_ip not in ("127.0.0.1", "::1", "localhost"):
            matched_ip = None
            if is_live:
                matched_ip = self.query_live_misp(attacker_ip)
            if not matched_ip:
                for ioc in self.local_iocs:
                    if ioc["type"] == "ip-dst" and ioc["value"] == attacker_ip:
                        matched_ip = ioc
                        break
            if matched_ip:
                matched_iocs.append(matched_ip)
                threat_actors.append(matched_ip.get("threat_actor", "Unknown"))
                threat_levels.append(matched_ip.get("threat_level", "Medium"))

        # 2. Phân tích bóc tách các IoC trong chuỗi lệnh
        all_text = full_session + " " + " ".join(commands)

        # Regex trích xuất URL (http/https/ftp)
        urls = re.findall(r"https?://[^\s;\"']+", all_text, re.IGNORECASE)
        # Regex trích xuất domain/hostname
        domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", all_text)

        # Trích xuất tên file tải về (sau wget / curl / chmod / ./)
        filenames = re.findall(r"\b(?:wget|curl|chmod|\./|cat|rm)\s+[^;]*?([a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_]{1,4})\b", all_text, re.IGNORECASE)
        # Thêm các binary nổi tiếng nếu xuất hiện trong lệnh
        for b in ["xmrig", "xmr_miner", "bot.sh", "miner", "payload.sh"]:
            if b in all_text and b not in filenames:
                filenames.append(b)

        # Đối soát URLs
        for u in set(urls):
            matched_u = None
            if is_live:
                matched_u = self.query_live_misp(u)
            if not matched_u:
                for ioc in self.local_iocs:
                    if ioc["type"] == "url" and (ioc["value"].lower() == u.lower() or ioc["value"].lower() in u.lower()):
                        matched_u = ioc
                        break
            if matched_u:
                matched_iocs.append(matched_u)
                threat_actors.append(matched_u.get("threat_actor", "Unknown"))
                threat_levels.append(matched_u.get("threat_level", "Critical"))
                matched_commands.append({"ioc_type": "url", "ioc_value": u, "event_info": matched_u["event_info"]})

        # Đối soát Domains
        for d in set(domains):
            matched_d = None
            if is_live:
                matched_d = self.query_live_misp(d)
            if not matched_d:
                for ioc in self.local_iocs:
                    if ioc["type"] == "domain" and ioc["value"].lower() == d.lower():
                        matched_d = ioc
                        break
            if matched_d:
                matched_iocs.append(matched_d)
                threat_actors.append(matched_d.get("threat_actor", "Unknown"))
                threat_levels.append(matched_d.get("threat_level", "High"))
                matched_commands.append({"ioc_type": "domain", "ioc_value": d, "event_info": matched_d["event_info"]})

        # Đối soát Filenames
        for fn in set(filenames):
            matched_fn = None
            for ioc in self.local_iocs:
                if ioc["type"] == "filename" and ioc["value"].lower() == fn.lower():
                    matched_fn = ioc
                    break
            if matched_fn:
                matched_iocs.append(matched_fn)
                threat_levels.append(matched_fn.get("threat_level", "High"))
                matched_commands.append({"ioc_type": "filename", "ioc_value": fn, "event_info": matched_fn["event_info"]})

        # Tổng hợp mức độ nguy hiểm cao nhất
        severity = "Clean"
        if "Critical" in threat_levels:
            severity = "Critical"
        elif "High" in threat_levels:
            severity = "High"
        elif "Medium" in threat_levels:
            severity = "Medium"
        elif "Low" in threat_levels:
            severity = "Low"

        # Loại bỏ trùng lặp matched_iocs
        unique_iocs = []
        seen_vals = set()
        for ioc in matched_iocs:
            val = ioc.get("value")
            if val not in seen_vals:
                seen_vals.add(val)
                unique_iocs.append(ioc)

        comparison_result = {
            "session_id": session_data.get("session_id", "unknown"),
            "attacker_ip": attacker_ip,
            "misp_matched": len(unique_iocs) > 0,
            "misp_source": "Docker MISP (Live API)" if is_live else "Local MISP Threat Cache (IoC DB)",
            "threat_level": severity,
            "threat_actors": list(set(threat_actors)) if threat_actors else ["Uncategorized"],
            "total_iocs_matched": len(unique_iocs),
            "matched_iocs": unique_iocs,
            "matched_commands_artifacts": matched_commands,
            "compared_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        # Lưu kết quả đối soát vào file JSON log
        self._record_match(comparison_result)
        return comparison_result

    def _record_match(self, result: Dict[str, Any]):
        try:
            records = []
            if self.matches_log_file.exists():
                try:
                    with open(self.matches_log_file, "r", encoding="utf-8") as f:
                        records = json.load(f)
                except Exception:
                    records = []
            # Thêm kết quả mới lên đầu danh sách
            records.insert(0, result)
            records = records[:500]  # Giới hạn 500 bản ghi mới nhất
            with open(self.matches_log_file, "w", encoding="utf-8") as f:
                json.dump(records, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


# Singleton instance để tái sử dụng
misp_comparator = MISPComparator()
