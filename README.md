# 🛡️ Nền Tảng Honeypot Thích Ứng (Next-Gen Adaptive Deception Platform)

> **Đề tài**: Nghiên cứu và phát triển nền tảng Honeypot thích ứng sử dụng Hybrid LLM kết hợp eBPF nhằm phát hiện và phân tích tự động các tác tử tấn công mạng.

---

## 1. Điểm Nổi Bật Của Hệ Thống

* **Trải nghiệm Terminal chân thực 100%**:
  * **Phím Tab Autocomplete**: Tự động gợi ý và điền tên lệnh (`unam` $\rightarrow$ `uname`) và đường dẫn tệp/thư mục (`cat no` $\rightarrow$ `cat notes.txt`) giống hệt GNU Bash trên Ubuntu.
  * **Phím Mũi tên Lên / Xuống (History)**: Cho phép hacker lướt lại lịch sử lệnh mượt mà.
  * **Bộ lọc từ vựng siêu tốc (< 0.05ms)**: Nhận diện ngay các lệnh sai/gõ nhầm (`hello`, `asdf`, `lss`) và báo lỗi `command not found` tức thì, triệt tiêu hoàn toàn độ trễ 5s của AI.
* **Cơ chế bẫy Hybrid (Stateful VFS + Fast-Path + Dynamic LLM)**:
  * **VFS độc lập từng phiên**: Hacker có thể tạo file, sửa file (`echo ... > file`), đổi quyền (`chmod +x`), xóa file (`rm`), chuyển thư mục (`cd`) với trạng thái nhất quán.
  * **Tệp mồi nhử (Decoy Files)**: Cung cấp sẵn các file gợi ý (`notes.txt`, `backup.sh`, `/etc/hosts`, `/etc/crontab`) kích thích hacker tiếp tục khám phá.
  * **Mô phỏng chân thực hơn 25+ lệnh CTI/Recon**: `ps aux`, `netstat -tlpn`, `ifconfig`, `ip a`, `df -h`, `free`, `systemctl status ssh`, `crontab -l`, `which curl`...
  * **Hỗ trợ đường ống lệnh (Pipeline `|`)**: Cho phép thực thi kết hợp như `cat /etc/passwd | grep root`, `history | tail -n 5`.
  * **Phân quyền người dùng**: Người dùng thường không thể xem `/etc/shadow`, chỉ khi dùng `sudo cat /etc/shadow` mới hiển thị mã băm mật khẩu.
  * **Tích hợp Cloud LLM (Gemini 3.8 Flash / HHTech API)**: Tự động ứng biến sinh phản hồi cho các câu lệnh dị, script khai thác phức tạp.
* **Tình báo đe dọa (CTI & MITRE ATT&CK)**:
  * Tự động gắn nhãn kỹ thuật tấn công theo ma trận MITRE ATT&CK (T1110 - Brute Force, T1059.004 - Unix Shell, T1082 - System Discovery...).
  * Ghi nhật ký chuẩn JSON Lines tại `logs/events.jsonl`.
  * Tự động cô lập mã độc hacker tải lên vào thư mục `quarantine/`.

---

## 2. Cấu Trúc Mã Nguồn

```text
adaptive-honeypot/
├── gateway/                    # Cổng bẫy SSH & Xử lý tương tác
│   ├── vfs.py                  # Cây thư mục ảo (Virtual File System)
│   ├── terminal_session.py     # Xử lý Terminal SSH, Tab completion, phím mũi tên
│   └── ssh_server.py           # Paramiko SSH Server bắt kết nối cổng 2222
├── ai_engine/                  # Bộ điều phối phản hồi & Trí tuệ nhân tạo
│   ├── router.py               # Hybrid Dispatcher (Whitelist + VFS + Pipeline + LLM)
│   ├── llm_client.py           # Client kết nối Cloud API (HHTech / Gemini / OpenAI)
│   └── guardrails.py           # Phòng thủ chống bẻ khóa AI (Anti-Prompt Injection)
├── threat_intel/               # Module phân tích & Tình báo đe dọa
│   ├── mitre_mapper.py         # Tự động gắn mã kỹ thuật MITRE ATT&CK
│   └── logger.py               # Ghi nhật ký sự kiện có cấu trúc chuẩn JSON Lines
├── logs/                       # Nhật ký sự kiện thời gian thực (events.jsonl)
├── quarantine/                 # Thư mục cách ly mẫu mã độc
├── .env                        # File cấu hình biến môi trường
├── config.py                   # Nạp cấu hình tập trung
├── main.py                     # File khởi động chính của Honeypot Gateway
├── test_honeypot.py            # Kịch bản kiểm thử tự động
└── requirements.txt            # Thư viện phụ thuộc
```

---

## 3. Hướng Dẫn Cài Đặt & Khởi Chạy

### Cách 1: Chạy trực tiếp trên Linux / Ubuntu (Máy ảo VMware / VPS)

#### Bước 1: Cài đặt thư viện cần thiết
```bash
cd /home/nhuthang/adaptive-honeypot
pip3 install -r requirements.txt
```

#### Bước 2: Kiểm tra cấu hình file `.env`
Mở file `.env` để xem các tùy chọn:
```env
# Port SSH của Honeypot (Mặc định 2222)
SSH_HOST=0.0.0.0
SSH_PORT=2222

# Mật khẩu bẫy được cấp phép vào honeypot
HONEYPOT_ALLOWED_PASSWORDS=123,123456,root,password,admin,ubuntu,toor

# Cấu hình AI Engine (Đã tích hợp sẵn HHTech API / Gemini 3.8 Flash)
LLM_PROVIDER=custom
LLM_BASE_URL=https://hhtechapi.net/v1
LLM_API_KEY=sk-372528de2e1f44d098a5fa7d
LLM_MODEL=gemini-3.8-flash
LLM_TIMEOUT_SECONDS=8.0
```

#### Bước 3: Khởi động Honeypot Gateway

* **Chạy trực tiếp (xem log trên màn hình terminal):**
  ```bash
  python3 main.py
  ```

* **Hoặc chạy nền liên tục (chạy ngầm kể cả khi tắt terminal):**
  ```bash
  nohup python3 main.py > honeypot.log 2>&1 &
  ```

---

### Cách 2: Chạy bằng Docker Compose

Nếu trên máy chủ đã cài Docker:
```bash
docker compose up -d --build
```
Dịch vụ sẽ tự động đóng gói và lắng nghe tại cổng `2222`.

---

## 4. Hướng Dẫn Kiểm Thử (Đóng Vai Hacker)

Mở một cửa sổ Terminal khác từ máy Windows hoặc máy khác trong mạng:

### 1. Thử nghiệm dò mật khẩu (Brute Force):
```bash
ssh dung@192.168.101.218 -p 2222
```
* **Nhập mật khẩu SAI** (ví dụ: `wrongpass999`):
  $\rightarrow$ Server từ chối ngay (`Permission denied, please try again.`) và tự động ghi log cảnh báo mã **MITRE T1110**.
* **Nhập mật khẩu ĐÚNG** (nhập `123` hoặc `123456`):
  $\rightarrow$ Được cấp quyền vào bẫy ảo Ubuntu 22.04 LTS.

---

### 2. Thử nghiệm các tính năng vừa nâng cấp:

1. **Thử phím TAB (Tab Autocomplete)**:
   * Gõ `cat no` rồi bấm **`Tab`** $\rightarrow$ Tự động điền `cat notes.txt `.
   * Gõ `unam` rồi bấm **`Tab`** $\rightarrow$ Tự động điền `uname `.
   * Gõ `cd /t` rồi bấm **`Tab`** $\rightarrow$ Tự động điền `cd /tmp/`.

2. **Thử phím Mũi Tên Lên / Xuống (History)**:
   * Bấm phím **Mũi tên Lên** $(\uparrow)$ $\rightarrow$ Hiển thị lại các lệnh vừa gõ hoặc lệnh lịch sử có sẵn của quản trị viên (`ls -la`, `uptime`, `cat /var/log/syslog`).

3. **Thử lệnh sai tức thì (Zero-Latency for Invalid Commands)**:
   * Gõ `hello` hoặc `asdf` $\rightarrow$ Kết quả `bash: hello: command not found` trả về ngay trong **0.01ms** (không bị khựng 5s).

4. **Thử các lệnh trinh sát hệ thống chân thực**:
   ```bash
   ps aux                   # Xem danh sách tiến trình chân thực (nginx, mysql, systemd)
   netstat -tlpn            # Xem các cổng mạng đang mở (22, 80, 3306)
   ifconfig                 # Xem thông tin card mạng eth0 và lo
   df -h                    # Xem dung lượng ổ đĩa
   free -m                  # Xem bộ nhớ RAM
   uptime                   # Xem thời gian hoạt động của máy chủ
   cat /etc/os-release      # Xem phiên bản hệ điều hành Ubuntu 22.04.4 LTS
   cat /etc/hosts           # Xem cấu hình domain và IP nội bộ
   which curl               # Kiểm tra đường dẫn binary (/usr/bin/curl)
   systemctl status ssh     # Xem trạng thái service SSH đang chạy
   crontab -l               # Xem tác vụ định kỳ
   ```

5. **Thử đường ống lệnh (Pipeline `|`)**:
   ```bash
   cat /etc/passwd | grep root
   ps aux | grep nginx
   ```

6. **Thử phân quyền tệp tin nhạy cảm**:
   ```bash
   cat /etc/shadow          # Bị từ chối: Permission denied
   sudo cat /etc/shadow     # Được xem mã băm mật khẩu
   ```

7. **Thử tải mã độc lên máy (Quarantine Test)**:
   ```bash
   cd /tmp
   echo 'MALWARE_PAYLOAD_C2_REV_SHELL' > evil.sh
   chmod +x evil.sh
   ls -la
   cat evil.sh
   ```
   *(Tệp `evil.sh` sẽ được tự động cách ly vào thư mục `quarantine/` trên máy chủ).*

---

## 5. Xem Dữ Liệu Log Sự Kiện (Threat Intelligence)

Tất cả hành vi của kẻ tấn công được lưu dưới dạng JSON Lines tại `logs/events.jsonl`:

```bash
# Xem 5 sự kiện tấn công mới nhất
tail -n 5 logs/events.jsonl
```

Mỗi bản ghi log bao gồm đầy đủ thông tin phục vụ phân tích CTI:
* `timestamp`: Thời gian diễn ra sự kiện.
* `source_ip`, `source_port`: Địa chỉ IP và Port của kẻ tấn công.
* `username`, `password`: Tài khoản và mật khẩu kẻ tấn công đã dùng.
* `command`, `command_output`: Lệnh hacker gõ và kết quả hệ thống trả về.
* `handler_type`: Thành phần xử lý (`VFS`, `CACHE`, `PIPELINE` hay `LLM`).
* `latency_ms`: Độ trễ phản hồi tính bằng mili-giây.
* `mitre_techniques`: Danh sách mã kỹ thuật đối sánh với ma trận MITRE ATT&CK.
