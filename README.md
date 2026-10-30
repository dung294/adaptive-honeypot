# 🛡️ Next-Gen Adaptive Honeypot (Nền Tảng Bẫy Mạng Thích Ứng AI)

> **Mục tiêu**: Nghiên cứu & phát triển hệ thống Honeypot SSH thế hệ mới sử dụng kiến trúc Deception hỗn hợp (**Stateful VFS + Fast-Path Cache + Cloud LLM**) nhằm đánh lừa kẻ tấn công, kéo dài thời gian lưu trú và tự động thu thập nhật ký tình báo đe dọa (CTI) gắn nhãn theo ma trận **MITRE ATT&CK for Enterprise**.

---

## 🌟 1. Cơ Chế Hoạt Động & Điểm Nổi Bật

### 🎯 Trải nghiệm Terminal chân thực 100% (GNU Readline Emulation)
* **Điều hướng con trỏ linh hoạt**: Hỗ trợ đầy đủ phím mũi tên **Trái (`←`) / Phải (`→`)**, phím **Home**, **End** và chèn/xóa ký tự ở bất kỳ vị trí nào giữa dòng lệnh giống hệt terminal Ubuntu thật.
* **Lịch sử lệnh (History)**: Dùng phím mũi tên **Lên (`↑`) / Xuống (`↓`)** để xem lại và thực thi các câu lệnh trước đó.
* **Phím Tab Autocomplete**: Tự động gợi ý và hoàn thiện tên lệnh Linux (`unam` $\rightarrow$ `uname`) và đường dẫn tệp/thư mục ảo (`cat no` $\rightarrow$ `cat notes.txt`).
* **Lọc lệnh lỗi tức thì (< 0.05ms)**: Danh sách từ vựng lệnh Linux chuẩn giúp hệ thống trả về ngay `bash: <cmd>: command not found` khi kẻ tấn công gõ sai lệnh (`hello`, `asdf`), triệt tiêu độ trễ của AI.

### 🧠 Bộ Điều Phối Hybrid Deception (Router & AI Engine)
```
[ Hacker / Botnet SSH ]
         │ (Cổng 2222)
         ▼
[ Paramiko SSH Gateway ] ─── Auth Failed ──► [ MITRE T1110: Brute Force ]
         │ (Auth Success)
         ▼
[ Stateful Terminal Session ]
         │
         ▼
  [ Command Router ]
   ├── 1. Lệnh không hợp lệ? ──────► bash: command not found (< 0.05ms)
   ├── 2. Lệnh Linux cơ bản / VFS? ─► Fast-Path VFS & Pipeline (< 0.1ms)
   └── 3. Lệnh lạ / Khai thác sâu? ─► Cloud LLM (Gemini 3.8 Flash qua HHTech API)
         │
         ▼
[ Threat Intel Logger ] ────────► logs/events.jsonl (Chuẩn JSON Lines + MITRE Tags)
```

1. **Stateful VFS (Hệ thống tệp ảo có trạng thái)**:
   * Giữ trạng thái độc lập cho từng phiên: tạo file (`echo 'data' > test.sh`), chuyển thư mục (`cd /tmp`), phân quyền (`chmod +x`), xóa file (`rm`), xem file (`cat`).
   * Cung cấp sẵn các file mồi nhử (Decoys): `notes.txt`, `backup.sh`, `/etc/passwd`, `/etc/crontab`...
   * Phân quyền thực tế: User thường không đọc được `/etc/shadow`, chỉ khi gõ `sudo cat /etc/shadow` mới đọc được mã băm mật khẩu.
2. **Đường ống lệnh (Pipeline `|`)**:
   * Hỗ trợ kết hợp: `cat /etc/passwd | grep root`, `ps aux | grep ssh`, `history | tail -n 5`.
3. **Cloud LLM (Gemini 3.8 Flash)**:
   * Ứng biến sinh phản hồi thông minh cho các câu lệnh dị, script khai thác phức tạp mà Fast-Path chưa định nghĩa.
4. **Tình báo đe dọa (CTI & MITRE ATT&CK)**:
   * Tự động phân tích và gắn nhãn kỹ thuật tấn công: `T1110` (Brute Force), `T1082` (System Info Discovery), `T1083` (File Discovery), `T1105` (Tool Download), `T1053` (Cron Persistence), `T1548` (Privilege Escalation)...
   * Lưu trữ nhật ký chuẩn JSON Lines tại `logs/events.jsonl` có liên kết `session_id`.

---

## 📂 2. Cấu Trúc Dự Án

```text
adaptive-honeypot/
├── gateway/                    # Cổng tiếp nhận SSH & Phiên tương tác
│   ├── vfs.py                  # Cây thư mục ảo (Virtual File System)
│   ├── terminal_session.py     # Xử lý Terminal, GNU Readline, Tab, phím mũi tên
│   └── ssh_server.py           # SSH Server (Paramiko) lắng nghe cổng 2222
├── ai_engine/                  # Điều phối phản hồi thông minh
│   ├── router.py               # Bộ định tuyến Hybrid (Whitelist + VFS + Pipeline + LLM)
│   ├── llm_client.py           # Client kết nối Cloud LLM (HHTech / Gemini)
│   └── guardrails.py           # Bộ lọc an toàn chống Prompt Injection
├── threat_intel/               # Module phân tích & Tình báo đe dọa
│   ├── mitre_mapper.py         # Đối sánh lệnh với ma trận MITRE ATT&CK
│   └── logger.py               # Ghi nhật ký sự kiện có cấu trúc chuẩn JSON Lines
├── logs/                       # Thư mục lưu trữ log (events.jsonl)
├── quarantine/                 # Thư mục cách ly an toàn tệp tải lên
├── config.py                   # Nạp cấu hình hệ thống
├── main.py                     # Điểm khởi động chính của Honeypot Gateway
├── live_monitor.py             # Công cụ giám sát nhật ký trực tiếp từ xa
├── requirements.txt            # Danh sách thư viện Python cần thiết
├── Dockerfile                  # Đóng gói container Docker
└── docker-compose.yml          # Triển khai nhanh bằng Docker Compose
```

---

## 🚀 3. Hướng Dẫn Cài Đặt & Vận Hành

### Bước 1: Chuẩn bị môi trường
Yêu cầu: Python 3.10 trở lên trên Ubuntu / Linux (máy thật, VPS hoặc máy ảo VMware).

```bash
# Clone mã nguồn
git clone https://github.com/dung294/adaptive-honeypot.git
cd adaptive-honeypot

# Cài đặt các thư viện phụ thuộc
pip install -r requirements.txt
```

### Bước 2: Cấu hình hệ thống (`.env`)
Tạo hoặc kiểm tra file `.env` tại thư mục gốc:
```env
# Cổng SSH của Honeypot (Cổng 22 mặc định của OS giữ nguyên cho quản trị)
SSH_HOST=0.0.0.0
SSH_PORT=2222

# Danh sách mật khẩu bẫy chấp nhận cho đăng nhập thành công
HONEYPOT_ALLOWED_PASSWORDS=123,123456,root,password,admin,ubuntu,toor

# Cấu hình AI Engine (Gemini qua HHTech API)
LLM_PROVIDER=custom
LLM_BASE_URL=https://hhtechapi.net/v1
LLM_API_KEY=sk-372528de2e1f44d098a5fa7d
LLM_MODEL=gemini-3.8-flash
LLM_TIMEOUT_SECONDS=8.0
```

### Bước 3: Khởi động Honeypot Gateway

* **Cách 1: Khởi động trực tiếp (xem trực tiếp log trên màn hình terminal):**
  ```bash
  python3 main.py
  ```

* **Cách 2: Chạy ngầm dạng Daemon (chạy liên tục kể cả khi đóng SSH / tắt terminal):**
  ```bash
  nohup python3 main.py </dev/null >honeypot.log 2>&1 &
  ```

* **Kiểm tra trạng thái dịch vụ:**
  ```bash
  ss -tulpn | grep 2222
  ```

* **Dừng Honeypot Gateway khi cần:**
  ```bash
  pkill -f main.py
  ```

---

## 🧪 4. Hướng Dẫn Kiểm Thử & Tương Tác

### 1. Đăng nhập thử vào Honeypot từ máy Client / Hacker:
Từ bất kỳ máy nào cùng mạng LAN, mở terminal và gõ:
```bash
ssh root@<IP_CUA_HONEYPOT> -p 2222
```
*Nhập mật khẩu bẫy:* `123` (hoặc `admin`, `ubuntu`, `toor`).

### 2. Các lệnh tương tác thử nghiệm:
* **Khảo sát hệ thống**: `uname -a`, `whoami`, `id`, `hostname`, `uptime`, `cat /etc/os-release`.
* **Khảo sát file**: `ls -la`, `pwd`, `cat /root/notes.txt`, `cat /etc/passwd`.
* **Thử leo thang đặc quyền**: `sudo -l`, `cat /etc/shadow`, `sudo cat /etc/shadow`.
* **Thử gõ phím đặc biệt**: Dùng phím **Mũi tên Trái/Phải** để sửa chữ giữa dòng, phím **Mũi tên Lên/Xuống** để gọi lại lịch sử lệnh, phím **Tab** để hoàn thành lệnh.
* **Thoát phiên**: Gõ `exit` hoặc `logout`.

### 3. Giám sát log thời gian thực:
Trên máy quản trị, chạy file giám sát để xem toàn bộ thao tác của kẻ tấn công theo thời gian thực:
```bash
python live_monitor.py
```

---

## 📊 5. Công Cụ Mô Phỏng Tấn Công & Sinh Dữ Liệu Lab (CTI Generator)

Dự án có sẵn công cụ đa luồng [`attack_lab_generator.py`](file:///c:/Users/luunh/OneDrive/Desktop/adaptive-honeypot/attack_lab_generator.py) phục vụ nghiên cứu & tạo dữ liệu mẫu lớn:
* Hỗ trợ **13 kịch bản tấn công thực tế** theo chuẩn MITRE ATT&CK:
  1. *Kết nối rồi ngắt ngay (Port scan / Banner grab - T1046)*
  2. *Dò mật khẩu thất bại nhiều lần (Brute-force - T1110)*
  3. *Đăng nhập thành công và trinh sát OS (T1082 / T1033)*
  4. *Khảo sát cây thư mục và file nhạy cảm (T1083)*
  5. *Tương tác gõ lệnh với khoảng nghỉ jitter ngẫu nhiên mô phỏng người thật*
  6. *Ý định tải payload giả lập an toàn bằng curl/wget (T1105)*
  7. *Ngắt kết nối đột ngột (Socket drop / thiếu End)*
  8. *Thăm dò leo thang đặc quyền (T1548 / T1068)*
  9. *Xóa dấu vết anti-forensics (T1070)*
  10. *Cài cắm persistence crontab (T1053)*
  11. *Quét mạng nội bộ & dịch chuyển ngang (T1016 / T1049)*
  12. *Săn lùng SSH key & credentials (T1552)*
  13. *Thăm dò Honeypot / Prompt injection*

* **Cách chạy sinh 10,000 sự kiện log thực tế:**
  ```bash
  python attack_lab_generator.py 10000
  ```
*(Dữ liệu sinh ra sẽ tự động được ghi nhận tại `logs/events.jsonl` và tự động kéo về máy cục bộ).*
