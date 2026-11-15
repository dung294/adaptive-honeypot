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

# Mở cổng Web Decoy và SSH Honeypot
EXPOSE 80 2222

# Biến môi trường
ENV PYTHONUNBUFFERED=1
ENV SSH_PORT=2222
ENV WEB_PORT=80
ENV PIPELINE_URL=http://192.168.2.175:8000/api/analyze

# Khởi chạy đồng thời Web Decoy và SSH Honeypot
CMD ["python", "run_all.py"]
