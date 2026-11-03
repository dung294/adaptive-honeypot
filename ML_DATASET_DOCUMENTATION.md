# BÁO CÁO MÔ TẢ TẬP DỮ LIỆU LOG HONEYPOT (ML BENCHMARK BATCH)
**Phục vụ:** Nghiên cứu và Huấn luyện / Đánh giá mô hình Machine Learning phát hiện & phân loại tấn công mạng  
**Hệ thống thu thập:** Adaptive Honeypot Deception Engine v2.1.0 (Stateful VFS SSH + Dockerized Web DVWA)  
**Thời điểm xuất:** 2026-11-03T04:08:18.092596+00:00  
**Batch ID:** `BATCH-20261102-BENCHMARK-01`

---

## 1. Tổng quan Tập Dữ liệu (Dataset Overview)
- **Định dạng dữ liệu:** JSON Lines (`.jsonl`) nguyên bản (Raw Event Stream), mỗi dòng là một sự kiện độc lập.
- **Tổng số sự kiện (Events):** `10,000` sự kiện.
- **Tổng số phiên (Sessions):** `1,793` phiên hoàn chỉnh có thể xâu chuỗi qua `session_id`.
- **Số lượng IP duy nhất (Unique Attacker IPs):** `1,622` IP (bao gồm dải ISP Việt Nam, Cloud quốc tế, Tor/Proxy và mạng nội bộ).
- **Phân bổ Nhãn Nhị phân (Binary Classification):**
  - **Malicious (Tấn công - Nhãn 1):** `9,781` sự kiện
  - **Benign (Bình thường / Hợp lệ - Nhãn 0):** `219` sự kiện
- **Phân bổ Giao thức:**
  - `HTTP` (Web DVWA Port 80): `4,010` sự kiện
  - `SSH` (Honeypot Terminal Port 2222): `5,990` sự kiện

---

## 2. Thông tin Các Lần Chạy (Run Metadata - `run_id`)
Mỗi sự kiện đều chứa trường `run_id` tương ứng với từng đợt thực nghiệm có chủ đích:

| Run ID | Chiến dịch liên kết (`campaign_id`) | Bề mặt mục tiêu | Tỷ trọng |
| :--- | :--- | :--- | :--- |
| `RUN-20261102-BATCH01-BOTNET` | `CAMP-2026-BOTNET-AUTO` | SSH & HTTP Scanner | 35% |
| `RUN-20261102-BATCH02-WEBPEN` | `CAMP-2026-WEB-PENTEST` | Web DVWA (Port 80) | 35% |
| `RUN-20261102-BATCH03-HUMANAPT`| `CAMP-2026-HUMAN-APT` | SSH Interactive (Port 2222) | 20% |
| `RUN-20261102-BATCH04-INSIDER` | `CAMP-2026-LATERAL-INSIDER` | LAN Pivot (SSH/Web) | 10% |

---

## 3. Danh mục Kịch bản Thử nghiệm & Nhãn Ground Truth (`scenario_id`)

Dưới đây là chi tiết từng kịch bản thử nghiệm đã biết (`scenario_id`) làm cơ sở để đánh giá độ chính xác (Accuracy, Precision, Recall, F1-Score, Macro/Micro-AUC) của mô hình:

| Scenario ID | Tên Kịch bản & Hành vi | MITRE Tactic | Kỹ thuật MITRE ATT&CK | Phân loại Đa lớp (`attack_category`) |
| :--- | :--- | :--- | :--- | :--- |
| `SCN-SSH-BRUTE` | Dò quét mật khẩu SSH từ điển | Credential Access | `T1110.001` Password Guessing | `Brute-Force` |
| `SCN-SSH-SYSRECON` | Điều tra cấu hình hệ điều hành & phần cứng | Discovery | `T1082` System Information Discovery | `Discovery` |
| `SCN-SSH-NETRECON` | Quét cổng, socket, ARP bảng và tiến trình | Discovery | `T1049` Network Connections Discovery| `Discovery` |
| `SCN-SSH-GTFOBINS` | Leo thang đặc quyền qua GTFOBins & Sudo | Privilege Escalation | `T1548.003` Sudo Caching Abuse | `Privilege-Escalation` |
| `SCN-SSH-C2STAGE` | Tải payload đào coin / botnet qua curl/wget | Command & Control | `T1105` Ingress Tool Transfer | `C2-Malware` |
| `SCN-SSH-DEFENSE-EVASION`| Xóa lịch sử bash, ngắt socket đột ngột | Defense Evasion | `T1070.003` Clear Command History | `Defense-Evasion` |
| `SCN-WEB-SQLI-ADVANCED` | Khai thác SQLi Boolean/Blind/UNION | Initial Access | `T1190` SQL Injection | `Web-Exploit-SQLi` |
| `SCN-WEB-CMDi-CHAIN` | OS Command Injection chuỗi lệnh OS | Execution | `T1059.004` Unix Shell Injection | `Web-Exploit-CMDi` |
| `SCN-WEB-LFI-WRAPPER` | Duyệt thư mục & khai thác LFI wrapper | Credential Access | `T1552.001` Local File Inclusion | `Web-Exploit-LFI` |
| `SCN-WEB-XSS-EXFIL` | Tiêm mã độc XSS đánh cắp phiên | Execution | `T1059.007` JavaScript Execution | `Web-Exploit-XSS` |
| `SCN-WEB-WEBSHELL-UPLOAD`| Upload Webshell (`.phtml`, `.php5`) | Persistence | `T1505.003` Web Shell Component | `Web-Exploit-Upload` |
| `SCN-WEB-SCANNER-SWEEP` | Quét tự động Nikto, SQLMap, Nuclei | Discovery | `T1046` Network Service Discovery | `Web-Scanner` |
| `SCN-WEB-BENIGN-TRAFFIC`| Truy cập trang web quản trị thông thường | Normal Operation | Normal Operation | `Benign` |

---

## 4. Cấu trúc Schema Bản ghi Sự kiện (JSONL Record Schema)

Mỗi sự kiện nguyên bản trong tệp `logs/ml_benchmark_batch_raw.jsonl` có cấu trúc chuẩn như sau:

```json
{
  "run_id": "RUN-20261102-BATCH02-WEBPEN",
  "campaign_id": "CAMP-2026-WEB-PENTEST",
  "scenario_id": "SCN-WEB-SQLI-ADVANCED",
  "honeypot": {
    "sensor_name": "Adaptive-Honeypot-Deception-Engine",
    "sensor_version": "2.1.0-Release",
    "node_id": "sensor-hcm-edge-web-01",
    "emulated_service": "Apache/2.4.52 (Ubuntu) PHP/8.1.2 DVWA-2.0",
    "internal_port": 80,
    "runtime_environment": "Docker Containerized Low-Interaction Trap"
  },
  "session_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "sequence_number": 1,
  "timestamp": "2026-10-20T04:12:35.812Z",
  "source_ip": "113.160.45.18",
  "source_port": 49152,
  "protocol": "HTTP",
  "event_status": "Web_Request",
  "method": "GET",
  "uri": "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2C+password+FROM+users+--+-&Submit=Submit",
  "http_status_code": 200,
  "bytes_transferred": 2840,
  "user_agent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
  "raw_event_payload": "GET /vulnerabilities/sqli/?id=1%27... HTTP/1.1 -> 200 (2840 bytes)",
  "ground_truth": {
    "binary_label": 1,
    "attack_class": "Malicious",
    "attack_category": "Web-Exploit-SQLi",
    "mitre_tactic": "Initial Access",
    "mitre_technique": "T1190 - Exploit Public-Facing Application: SQL Injection",
    "confidence": "High"
  }
}
```

---

## 5. Khuyến nghị Kỹ thuật Đặc trưng & Huấn luyện Mô hình ML cho Luận văn

1. **Gom phiên theo `session_id`:**
   - Dùng `sequence_number` và `timestamp` để tính toán khoảng cách thời gian giữa các lệnh ($\Delta t$), xác định tốc độ gõ phím của botnet vs con người.
2. **Kỹ thuật trích xuất đặc trưng (Feature Extraction):**
   - **Xử lý chuỗi lệnh / URI:** TF-IDF n-grams (ký tự và từ ngữ), Byte-pair Encoding (BPE), hoặc nhúng câu qua MiniLM/SecBERT.
   - **Thống kê phiên:** Tỷ lệ mã trạng thái HTTP (200, 404, 500), số lượng lệnh nhập vào, độ trễ phản hồi (`latency_ms`), số lần xác thực thất bại.
3. **Bài toán Học máy phù hợp:**
   - **Binary Classification (Phát hiện tấn công):** Phân biệt `Benign` (0) vs `Malicious` (1) sử dụng Random Forest, XGBoost, LightGBM hoặc SVM.
   - **Multi-Class Classification (Phân loại hình thái):** Phân loại 10+ nhóm hành vi trong trường `attack_category` hoặc phân loại `mitre_tactic`.
   - **Sequence / Behavioral Modeling:** Áp dụng LSTM, GRU, hoặc Graph Neural Network (GNN) để dự báo bước đi tiếp theo của kẻ tấn công trong chuỗi kill-chain.
