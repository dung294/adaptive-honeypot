# TÀI LIỆU MÔ TẢ TẬP DỮ LIỆU ĐÁNH GIÁ MÔ HÌNH HỌC MÁY (OOD TESTSET)
**Hệ thống:** Adaptive Honeypot & Deception Engine - Two-Tier Linux SSH Surface  
**Mã tập dữ liệu (Dataset ID):** `DATASET-OOD-ML-HONEYPOT-SSH-2026`  
**Mã lô (Batch ID):** `BATCH-20261102-HOST-SSH-02`  
**Thời điểm tạo:** `2026-11-06T12:56:48.728534+00:00`  
**Mục đích:** Đánh giá khả năng phát hiện (Detection) và phân loại hành vi tấn công mạng (Classification) của các mô hình Machine Learning / Deep Learning trên các đợt chạy (Runs) và chiến dịch (Campaigns) độc lập với dữ liệu huấn luyện.

---

## 1. Phương pháp thu thập và Bản quyền dữ liệu (Data Provenance)
- **Hình thức thu thập:** Dữ liệu sự kiện gốc (Raw event stream) được ghi nhận tuần tự qua cổng SSH Gateway (Port 2222) của hệ thống Adaptive Honeypot.
- **Tính nguyên bản:** 100% dữ liệu sự kiện thô, giữ nguyên quan hệ nhân quả (causality sequences), timestamp chính xác đến mili-giây, không tổng hợp hay gộp cụm trước khi cung cấp.
- **Phương pháp gán nhãn Ground Truth (Design-time Oracle):**
  Nhãn được gán theo cơ chế **Kiến trúc nhận diện 2 tầng (Two-Tier Architecture)**:
  - **Tầng 1 (ML Macro-Class):** 14 nhóm hành vi chuẩn mực phục vụ huấn luyện mô hình học máy, triệt tiêu mất cân bằng lớp và tối ưu hóa tính tổng quát (Generalizability).
  - **Tầng 2 (MITRE ATT&CK for Enterprise / MITRE ATLAS):** Ánh xạ chính xác Tactic ID, Technique ID và Command Evidence chi tiết phục vụ chuyên gia SOC.
- **Phạm vi bề mặt:** 100% bề mặt Host-based SSH Honeypot (đã loại bỏ Web HTTP theo yêu cầu thiết kế hệ thống tập trung).

---

## 2. Thống kê tổng quan (Dataset Statistics)
- **Tổng số bản ghi sự kiện (Events):** 10,000
- **Tổng số phiên kết nối (Sessions):** 1,567
- **Số địa chỉ IP nguồn duy nhất:** 1,304
- **Tỷ lệ phân loại nhị phân (Binary Labels):**
  - **Độc hại (Malicious - 1):** 9,845 bản ghi
  - **Lành tính (Benign - 0):** 155 bản ghi

### Phân bổ 14 nhóm hành vi vĩ mô (Tier 1 Macro-Classes):
| Nhóm hành vi vĩ mô (Macro-Class) | Số lượng sự kiện | Tỷ lệ (%) |
| :--- | :---: | :---: |
| `Initial Access via Valid Accounts` | 1,202 | 12.02% |
| `System & Network Discovery` | 1,551 | 15.51% |
| `Privilege Escalation Attempt` | 776 | 7.76% |
| `Persistence & Backdoor Setup` | 793 | 7.93% |
| `Defense Evasion & Anti-Forensics` | 1,046 | 10.46% |
| `Credential Access & Harvesting` | 889 | 8.89% |
| `Lateral Movement` | 521 | 5.21% |
| `Collection & Exfiltration` | 512 | 5.12% |
| `Command and Control (Reverse Shell / Tunnel)` | 302 | 3.02% |
| `SSH Password Guessing` | 1,502 | 15.02% |
| `C2 Ingress & Malware Staging` | 486 | 4.86% |
| `Impact & Sabotage` | 94 | 0.94% |
| `Port Scan & Connection Probe` | 94 | 0.94% |
| `Adversarial AI / Jailbreak Probe` | 77 | 0.77% |
| `Benign Activity` | 155 | 1.55% |

---

## 3. Danh mục 4 đợt chạy (Runs) & Chiến dịch thử nghiệm
Dữ liệu được tổ chức thành 4 Runs với mục tiêu kiểm thử độ bền vững (OOD Robustness) của mô hình:

| Mã đợt chạy (Run ID) | Chiến dịch (Campaign ID) | Trọng số phiên | Phiên thực tế | Sự kiện thực tế | Số sự kiện/phiên TB |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `RUN-20261102-BATCH01-BOTNET` | `CAMP-2026-BOTNET-SSH` | 0.35 | 527 (33.6%) | 2,244 (22.4%) | 4.26 |
| `RUN-20261102-BATCH02-HUMANAPT` | `CAMP-2026-HUMAN-APT` | 0.35 | 523 (33.4%) | 4,991 (49.9%) | 9.54 |
| `RUN-20261102-BATCH03-INSIDER` | `CAMP-2026-LATERAL-INSIDER` | 0.2 | 353 (22.5%) | 2,275 (22.8%) | 6.44 |
| `RUN-20261102-BATCH04-ADVAI` | `CAMP-2026-ADV-AI-REDTEAM` | 0.1 | 164 (10.5%) | 490 (4.9%) | 2.99 |

### Chi tiết các chiến dịch (Campaigns):
#### `CAMP-2026-BOTNET-SSH`: Automated Botnet SSH Commodity Sweeps
- **Đối tượng tấn công giả lập:** Automated Botnet / Script Kiddie
- **Bề mặt mục tiêu:** SSH Gateway (Port 2222)
- **Mô tả kịch bản:** Chiến dịch botnet tự động quét diện rộng, dò mật khẩu mặc định và tải malware đào coin (XMRig/Mirai/Mozi).

#### `CAMP-2026-HUMAN-APT`: Targeted Hands-On-Keyboard Linux Intrusion
- **Đối tượng tấn công giả lập:** Advanced Persistent Threat (APT) / Hands-on Operator
- **Bề mặt mục tiêu:** SSH Gateway (Port 2222)
- **Mô tả kịch bản:** Kẻ tấn công có chủ đích điều khiển shell trực tiếp, khảo sát hệ thống, leo thang đặc quyền GTFOBins, thiết lập persistence và C2 reverse shell.

#### `CAMP-2026-LATERAL-INSIDER`: Internal Lateral Pivot & Reconnaissance
- **Đối tượng tấn công giả lập:** Malicious Insider / Lateral Pivot
- **Bề mặt mục tiêu:** SSH Gateway (Port 2222)
- **Mô tả kịch bản:** Khai thác máy trạm nội bộ, trích xuất chứng thư /etc/shadow và SSH keys, quét subnet LAN và SSH sang máy chủ khác, nén dữ liệu và tuồn ra ngoài.

#### `CAMP-2026-ADV-AI-REDTEAM`: Adversarial AI Jailbreak & Host Sabotage
- **Đối tượng tấn công giả lập:** Adversarial AI Researcher / Saboteur
- **Bề mặt mục tiêu:** SSH Gateway (Port 2222)
- **Mô tả kịch bản:** Thử nghiệm Red Team nhắm vào tầng phòng thủ AI (Prompt Injection / DAN mode) kết hợp phá hoại tiến trình hệ thống (Service Kill / Fork bomb).


---

## 4. Hướng dẫn sử dụng cho Huấn luyện & Đánh giá ML (Benchmarking Guidelines)
1. **Chia tập dữ liệu (Data Splitting):**
   - Khuyến nghị chia tập theo **`run_id`** (ví dụ: Huấn luyện trên `RUN-BATCH01` và `RUN-BATCH02`, kiểm thử OOD trên `RUN-BATCH03` và `RUN-BATCH04`).
   - Tuyệt đối không chia ngẫu nhiên từng dòng đơn lẻ (Random Row Split) để tránh hiện tượng rò rỉ dữ liệu giữa các bước trong cùng một phiên (`session_id`).
2. **Trường mục tiêu (Target Features):**
   - `ground_truth.binary_label` (0 hoặc 1) cho bài toán Binary Classification.
   - `macro_class` cho bài toán Multi-class Classification (14 lớp hành vi vĩ mô).
3. **Trích xuất đặc trưng (Feature Engineering):**
   - Phân tích cú pháp lệnh trong trường `command` hoặc `raw_event_payload` (TF-IDF, Byte-Pair Encoding, n-gram).
   - Tần suất gõ lệnh, độ trễ phản hồi (`latency_ms`), thời lượng phiên (`duration_seconds`).
