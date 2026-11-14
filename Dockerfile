# Sử dụng Python 3.11 slim nhẹ, bảo mật và tương thích tốt
FROM python:3.11-slim

# Thiết lập thư mục làm việc
WORKDIR /app

# Cài đặt các gói thư viện hệ thống cần thiết
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    curl \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Cài đặt các gói phụ thuộc Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép toàn bộ mã nguồn
COPY . .

# Tạo các thư mục lưu trữ log và quarantine
RUN mkdir -p logs quarantine

# Mở các cổng dịch vụ:
# 80   : Web Decoy Lure (Lớp 7 - RCE & Lộ file cấu hình)
# 2222 : SSH Adaptive Honeypot Gateway (Lớp 4 - Pivot bẫy ảo)
# 8080 : SOC Dashboard & REST Feed API
EXPOSE 80 2222 8080

# Biến môi trường
ENV PYTHONUNBUFFERED=1 \
    WEB_PORT=80 \
    SSH_PORT=2222 \
    DASHBOARD_PORT=8080

# Khởi chạy đồng bộ 3 dịch vụ qua entrypoint
CMD ["python", "entrypoint.py"]
