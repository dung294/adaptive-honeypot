# Sử dụng Python 3.10 slim nhẹ và an toàn
FROM python:3.10-slim

# Thiết lập thư mục làm việc
WORKDIR /app

# Cài đặt các gói phụ thuộc hệ thống cần thiết cho cryptography và network
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Cài đặt dependencies Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy mã nguồn dự án
COPY . .

# Mở cổng SSH Honeypot
EXPOSE 2222

# Biến môi trường
ENV PYTHONUNBUFFERED=1
ENV SSH_PORT=2222

# Khởi chạy Honeypot Gateway
CMD ["python", "main.py"]
