@echo off
chcp 65001 > nul
title Kết Nối Điều Khiển Honeypot Từ Windows

echo ======================================================================
echo    KẾT NỐI ĐIỀU KHIỂN HỆ THỐNG / HONEYPOT TỪ MÁY WINDOWS
echo ======================================================================
echo.

set /p SERVER_IP="Nhập IP máy chủ (Enter để dùng 127.0.0.1): "
if "%SERVER_IP%"=="" set SERVER_IP=127.0.0.1

set /p SERVER_PORT="Nhập Port SSH (Enter để dùng 2222): "
if "%SERVER_PORT%"=="" set SERVER_PORT=2222

set /p USERNAME="Nhập User Admin (Enter để dùng admin): "
if "%USERNAME%"=="" set USERNAME=admin

echo.
echo [*] Đang kết nối tới: %USERNAME%@%SERVER_IP%:%SERVER_PORT% ...
echo [*] Lưu ý: Nhập mật khẩu Admin (mặc định trong .env là admin123).
echo.

ssh %USERNAME%@%SERVER_IP% -p %SERVER_PORT%

echo.
echo [*] Phiên kết nối đã kết thúc.
pause
