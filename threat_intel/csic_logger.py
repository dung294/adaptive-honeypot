#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
CSIC 2010 HTTP DATASET COMPATIBLE LOGGER
=============================================================================
Thu thập và ghi log toàn bộ lưu lượng HTTP (Lớp 7) chuẩn 100% theo schema
của bộ dữ liệu quốc tế CSIC 2010 (csic_database.csv):
  ['Unnamed: 0', 'Method', 'User-Agent', 'Pragma', 'Cache-Control', 'Accept',
   'Accept-encoding', 'Accept-charset', 'language', 'host', 'cookie',
   'content-type', 'connection', 'lenght', 'content', 'classification', 'URL']

Hỗ trợ cung cấp cả log thô (Unlabeled - chưa gán nhãn classification)
cho mô hình AI Máy 2 suy luận, lẫn log đã gán nhãn để làm benchmark WAF.
"""

import os
import csv
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

CSIC_CSV_FILE = LOGS_DIR / "csic_http_requests.csv"
CSIC_JSONL_FILE = LOGS_DIR / "csic_http_requests.jsonl"
CSIC_UNLABELED_JSONL = LOGS_DIR / "csic_unlabeled_http.jsonl"

# Các cột chuẩn tuyệt đối theo csic_database.csv
CSIC_COLUMNS = [
    'Unnamed: 0',
    'Method',
    'User-Agent',
    'Pragma',
    'Cache-Control',
    'Accept',
    'Accept-encoding',
    'Accept-charset',
    'language',
    'host',
    'cookie',
    'content-type',
    'connection',
    'lenght',
    'content',
    'classification',
    'URL'
]

# Regex nhận diện các dấu hiệu bất thường (Anomalous Web Request)
ANOMALY_PATTERNS = [
    # Command Injection / RCE
    r';|&&|\|\||\||`|\$\(',
    r'\b(whoami|uname|id|cat\s+|wget|curl|chmod|rm\s+|bash|sh|nc)\b',
    # Path Traversal / LFI
    r'\.\./|\.\.\\|/etc/passwd|/etc/shadow|\.env|config\.php',
    # SQL Injection
    r"('|--|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bWHERE\b|\bOR\s+1=1|\bOR\s+'1'='1)",
    # XSS
    r'<script|javascript:|onerror=|onload=|alert\('
]
ANOMALY_REGEX = re.compile('|'.join(ANOMALY_PATTERNS), re.IGNORECASE)


class CSICLogger:
    """Bộ ghi log HTTP chuẩn CSIC 2010"""

    def __init__(self):
        self._ensure_csv_header()

    def _ensure_csv_header(self):
        """Khởi tạo header CSV nếu file chưa tồn tại"""
        if not CSIC_CSV_FILE.exists() or CSIC_CSV_FILE.stat().st_size == 0:
            try:
                with open(CSIC_CSV_FILE, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=CSIC_COLUMNS)
                    writer.writeheader()
            except Exception as e:
                print(f"[!] Lỗi khởi tạo {CSIC_CSV_FILE.name}: {e}")

    def is_anomalous_request(self, raw_url: str, body: str) -> bool:
        """Tự động kiểm tra xem request có chứa payload tấn công hay không"""
        target_text = f"{raw_url} {body}"
        return bool(ANOMALY_REGEX.search(target_text))

    def log_flask_request(self, flask_req, is_anomalous: Optional[bool] = None) -> Dict[str, Any]:
        """
        Trích xuất và lưu request từ Flask thành định dạng chuẩn csic_database.csv.
        """
        method = flask_req.method or "GET"
        headers = flask_req.headers

        # Trích xuất body / content
        body_str = ""
        try:
            body_str = flask_req.get_data(as_text=True) or ""
        except Exception:
            body_str = ""

        # Xây dựng trường URL chuẩn format: "http://host/path?query HTTP/1.1"
        scheme = flask_req.scheme or "http"
        host_header = headers.get("Host") or flask_req.host or "localhost:80"
        path_and_query = flask_req.full_path if flask_req.query_string else flask_req.path
        if path_and_query.endswith("?"):
            path_and_query = path_and_query[:-1]
        protocol = flask_req.environ.get("SERVER_PROTOCOL", "HTTP/1.1")
        full_url_field = f"{scheme}://{host_header}{path_and_query} {protocol}"

        # Kiểm tra bất thường nếu chưa gán nhãn
        if is_anomalous is None:
            is_anomalous = self.is_anomalous_request(full_url_field, body_str)

        # Tính toán giá trị trường 'lenght' (Đúng typo chuẩn của dataset gốc: 'lenght')
        content_len_hdr = headers.get("Content-Length")
        if content_len_hdr:
            lenght_val = f"Content-Length: {content_len_hdr}"
        elif body_str:
            lenght_val = f"Content-Length: {len(body_str.encode('utf-8'))}"
        else:
            lenght_val = ""

        # Connection header
        conn_hdr = headers.get("Connection", "close")
        if conn_hdr and not conn_hdr.lower().startswith("connection:"):
            conn_val = f"Connection: {conn_hdr}"
        else:
            conn_val = conn_hdr or "close"

        classification_val = 1 if is_anomalous else 0
        unnamed_val = "Anomalous" if is_anomalous else "Normal"

        record = {
            'Unnamed: 0': unnamed_val,
            'Method': method,
            'User-Agent': headers.get("User-Agent", ""),
            'Pragma': headers.get("Pragma", "no-cache"),
            'Cache-Control': headers.get("Cache-Control", "no-cache"),
            'Accept': headers.get("Accept", "*/*"),
            'Accept-encoding': headers.get("Accept-Encoding", ""),
            'Accept-charset': headers.get("Accept-Charset", ""),
            'language': headers.get("Accept-Language", "en"),
            'host': host_header,
            'cookie': headers.get("Cookie", ""),
            'content-type': headers.get("Content-Type", ""),
            'connection': conn_val,
            'lenght': lenght_val,
            'content': body_str if body_str else "",
            'classification': classification_val,
            'URL': full_url_field
        }

        # Bản ghi Unlabeled (Chưa gán nhãn dành cho AI Machine Learning dự đoán)
        unlabeled_record = {
            'Method': record['Method'],
            'User-Agent': record['User-Agent'],
            'Pragma': record['Pragma'],
            'Cache-Control': record['Cache-Control'],
            'Accept': record['Accept'],
            'Accept-encoding': record['Accept-encoding'],
            'Accept-charset': record['Accept-charset'],
            'language': record['language'],
            'host': record['host'],
            'cookie': record['cookie'],
            'content-type': record['content-type'],
            'connection': record['connection'],
            'lenght': record['lenght'],
            'content': record['content'],
            'URL': record['URL']
        }

        # 1. Ghi vào file CSV chuẩn
        try:
            self._ensure_csv_header()
            with open(CSIC_CSV_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSIC_COLUMNS)
                writer.writerow(record)
        except Exception as e:
            print(f"[!] Lỗi ghi {CSIC_CSV_FILE.name}: {e}")

        # 2. Ghi vào file JSONL
        try:
            with open(CSIC_JSONL_FILE, "a", encoding="utf-8") as jf:
                jf.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass

        # 3. Ghi vào file Unlabeled JSONL (cho AI Máy 2)
        try:
            with open(CSIC_UNLABELED_JSONL, "a", encoding="utf-8") as ujf:
                ujf.write(json.dumps(unlabeled_record, ensure_ascii=False) + "\n")
        except Exception:
            pass

        return {
            "record": record,
            "unlabeled": unlabeled_record
        }


# Singleton instance toàn cục
csic_logger = CSICLogger()
