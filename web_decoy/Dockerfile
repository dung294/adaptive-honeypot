# Sử dụng Python 3.10 slim nhẹ và bảo mật
FROM python:3.10-slim

# Thiết lập thư mục làm việc trong container
WORKDIR /app

# Cài đặt gói hệ thống cơ bản
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Cài đặt dependencies Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép mã nguồn ứng dụng
COPY . .

# Khởi tạo CSDL SQLite mẫu ban đầu
RUN python database.py

# Mở cổng 80 cho Web Decoy
EXPOSE 80

# Biến môi trường
ENV PYTHONUNBUFFERED=1
ENV PORT=80
ENV PIPELINE_URL=http://172.18.0.5:8000/api/analyze

# Khởi chạy ứng dụng Flask
CMD ["python", "app.py"]
