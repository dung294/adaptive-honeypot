#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ADAPTIVE HONEYPOT & DECEPTION LAB - COMPREHENSIVE SYSTEM REPORT GENERATOR
=============================================================================
Xuất tài liệu PDF chi tiết, trực quan, chuyên nghiệp về kiến trúc hệ thống,
dữ liệu log, CTI MITRE ATT&CK, mô hình ML và hạ tầng triển khai.
"""

import os
import sys
import io
import shutil
from pathlib import Path
from playwright.sync_api import sync_playwright

if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    except Exception:
        pass

WORKSPACE_DIR = Path("C:/Users/luunh/OneDrive/Desktop/adaptive-honeypot")
ARTIFACT_DIR = Path("C:/Users/luunh/.gemini/antigravity/brain/b56f25d5-9336-4946-8eff-f0b94ac2a909")
OUTPUT_PDF_WORKSPACE = WORKSPACE_DIR / "Bao_Cao_Tong_Quan_He_Thong_Honeypot.pdf"
OUTPUT_PDF_ARTIFACT = ARTIFACT_DIR / "Bao_Cao_Tong_Quan_He_Thong_Honeypot.pdf"

html_content = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>Báo Cáo Tổng Quan Hệ Thống Adaptive Honeypot & Cyber Deception Platform</title>
<style>
  @page {
    size: A4;
    margin: 18mm 15mm 18mm 15mm;
    @bottom-right {
      content: "Trang " counter(page) " / " counter(pages);
      font-size: 8.5pt;
      color: #64748b;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    @bottom-left {
      content: "Adaptive Honeypot & Deception Lab | Academic & CTI Report";
      font-size: 8.5pt;
      color: #64748b;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
  }

  * { box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
    color: #0f172a;
    line-height: 1.55;
    font-size: 9.8pt;
    background: #ffffff;
    margin: 0;
    padding: 0;
  }

  /* Header Cover Box */
  .cover-card {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0369a1 100%);
    color: #ffffff;
    border-radius: 10px;
    padding: 24px 28px;
    margin-bottom: 22px;
    box-shadow: 0 4px 12px rgba(15, 23, 42, 0.15);
  }
  .cover-badge {
    display: inline-block;
    background: rgba(56, 189, 248, 0.2);
    border: 1px solid rgba(56, 189, 248, 0.4);
    color: #38bdf8;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 8pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 10px;
  }
  .cover-title {
    font-size: 20pt;
    font-weight: 800;
    line-height: 1.25;
    margin: 0 0 8px 0;
    letter-spacing: -0.4px;
    color: #f8fafc;
  }
  .cover-subtitle {
    font-size: 10.5pt;
    color: #cbd5e1;
    margin: 0 0 14px 0;
    font-weight: 400;
  }
  .cover-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    font-size: 8.5pt;
    color: #94a3b8;
    border-top: 1px solid rgba(255, 255, 255, 0.15);
    padding-top: 10px;
  }
  .cover-meta span strong { color: #f1f5f9; }

  /* Section Headings */
  h1 {
    font-size: 13pt;
    font-weight: 800;
    color: #0f172a;
    border-left: 4.5px solid #0284c7;
    padding-left: 10px;
    margin: 20px 0 10px 0;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    page-break-after: avoid;
  }
  h2 {
    font-size: 11pt;
    font-weight: 700;
    color: #0369a1;
    margin: 14px 0 6px 0;
    page-break-after: avoid;
  }
  h3 {
    font-size: 10pt;
    font-weight: 600;
    color: #334155;
    margin: 10px 0 4px 0;
  }

  p { margin: 0 0 8px 0; text-align: justify; }

  /* Callout Boxes */
  .callout {
    background: #f8fafc;
    border-left: 3.5px solid #0284c7;
    border-radius: 0 6px 6px 0;
    padding: 10px 14px;
    margin: 10px 0;
    font-size: 9.3pt;
  }
  .callout-success {
    background: #f0fdf4;
    border-left-color: #16a34a;
    color: #166534;
  }
  .callout-warning {
    background: #fffbeb;
    border-left-color: #d97706;
    color: #92400e;
  }

  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0 14px 0;
    font-size: 8.8pt;
    page-break-inside: avoid;
  }
  th {
    background: #0f172a;
    color: #ffffff;
    font-weight: 700;
    padding: 7px 9px;
    text-align: left;
    border: 1px solid #1e293b;
    font-size: 8.5pt;
    letter-spacing: 0.2px;
  }
  td {
    padding: 6px 9px;
    border: 1px solid #e2e8f0;
    vertical-align: middle;
  }
  tr:nth-child(even) { background: #f8fafc; }
  tr:hover { background: #f1f5f9; }

  /* Status Badges */
  .status-pill {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 10px;
    font-size: 7.5pt;
    font-weight: 700;
  }
  .status-active { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
  .status-high { background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }
  .status-info { background: #e0f2fe; color: #0369a1; border: 1px solid #7dd3fc; }

  /* Code Block */
  pre {
    background: #0f172a;
    color: #e2e8f0;
    padding: 10px 12px;
    border-radius: 6px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8pt;
    line-height: 1.45;
    overflow-x: auto;
    margin: 8px 0 12px 0;
  }
  code {
    font-family: 'Consolas', monospace;
    font-size: 8.5pt;
    background: #f1f5f9;
    color: #0f172a;
    padding: 1px 4px;
    border-radius: 3px;
    border: 1px solid #e2e8f0;
  }
  pre code {
    background: none;
    border: none;
    color: inherit;
    padding: 0;
  }

  /* Grid Layout */
  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin: 10px 0;
  }
  .card-box {
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 10px 12px;
    background: #ffffff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  }
  .card-box h3 { margin-top: 0; color: #0284c7; }

  .page-break { page-break-before: always; }
</style>
</head>
<body>

  <!-- COVER HEADER -->
  <div class="cover-card">
    <div class="cover-badge">BÁO CÁO KỸ THUẬT & KIẾN TRÚC TOÀN DIỆN (SYSTEM STATUS REPORT)</div>
    <h1 class="cover-title">HỆ THỐNG ADAPTIVE HONEYPOT & CYBER DECEPTION LAB</h1>
    <p class="cover-subtitle">Kiến trúc Đa Bề Mặt (Dual-Surface), Lõi Thu Thập CTI Thời Gian Thực Chuẩn MITRE ATT&CK, Trí Tuệ Nhân Tạo Lừa Dối Thích Ứng & Tập Dữ Liệu Benchmark Huấn Luyện Machine Learning</p>
    <div class="cover-meta">
      <span><strong>Hệ điều hành Honeypot:</strong> Ubuntu 22.04 LTS (Jammy)</span>
      <span><strong>Máy ảo triển khai:</strong> 192.168.101.218</span>
      <span><strong>Phiên bản cốt lõi:</strong> v2.1.0-Release</span>
      <span><strong>Nhánh Git:</strong> dev (github.com/dung294/adaptive-honeypot)</span>
    </div>
  </div>

  <!-- PHẦN 1: TỔNG QUAN HỆ THỐNG -->
  <h1>1. TỔNG QUAN KIẾN TRÚC HỆ THỐNG</h1>
  <p>
    Hệ thống <strong>Adaptive Honeypot & Cyber Deception Platform</strong> là giải pháp bẫy phòng thủ mạng chủ động thế hệ mới, tích hợp hai bề mặt tấn công độc lập (SSH và Web HTTP), kết hợp động cơ trí tuệ nhân tạo thích ứng (AI-driven dynamic interaction) và đường ống xử lý dữ liệu đe dọa (Cyber Threat Intelligence - CTI) theo chuẩn quốc tế <strong>MITRE ATT&CK for Enterprise Matrix</strong>.
  </p>

  <div class="callout">
    <strong>Mục đích ứng dụng cốt lõi:</strong>
    Phát hiện sớm kẻ tấn công, thu thập toàn bộ chuỗi hành vi xâm nhập nhiều giai đoạn (Cyber Kill Chain), gán nhãn Ground Truth chính xác 100% không qua phỏng đoán, và cung cấp tập dữ liệu nhật ký bảo mật chất lượng cao cho việc huấn luyện, đánh giá mô hình Học máy (Machine Learning / Deep Learning) trong phát hiện tấn công mạng.
  </div>

  <div class="grid-2">
    <div class="card-box">
      <h3>🌐 Bề Mặt 1: SSH Gateway (Port 2222)</h3>
      <p>Lắng nghe tại <code>0.0.0.0:2222</code> bằng Python Asyncio + Paramiko. Cung cấp môi trường Stateful VFS Sandbox, hỗ trợ Tab-completion, duy trì trạng thái filesystem ảo và giả lập đầy đủ lệnh leo thang đặc quyền GTFOBins, tải payload C2 mà không gây hại cho máy chủ thật.</p>
    </div>
    <div class="card-box">
      <h3>🌐 Bề Mặt 2: Web DVWA Target (Port 80)</h3>
      <p>Lắng nghe tại <code>0.0.0.0:80</code> qua Docker Container <code>vulnerables/web-dvwa</code>. Giả lập ứng dụng Apache/PHP/MySQL với đầy đủ các lỗ hổng OWASP Top 10 (SQLi, Command Injection, LFI/RFI, Webshell Upload, XSS, Brute-force Login).</p>
    </div>
  </div>

  <!-- PHẦN 2: THÀNH PHẦN HỆ THỐNG HIỆN HỮU -->
  <h1>2. CÁC THÀNH PHẦN VÀ TIỂU HỆ THỐNG ĐÃ XÂY DỰNG</h1>

  <table>
    <thead>
      <tr>
        <th style="width: 18%;">Module / Tệp tin</th>
        <th style="width: 28%;">Chức năng kỹ thuật</th>
        <th style="width: 38%;">Đặc tả chi tiết & Công nghệ</th>
        <th style="width: 16%;">Trạng thái</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>gateway/ssh_server.py</code></td>
        <td>Cổng bẫy SSH tương tác</td>
        <td>Xử lý bắt tay SSH, kiểm soát xác thực từ điển, khởi tạo kênh Shell ảo có quản lý trạng thái phiên độc lập.</td>
        <td><span class="status-pill status-active">Đang chạy</span></td>
      </tr>
      <tr>
        <td><code>gateway/vfs.py</code></td>
        <td>Hệ thống tệp ảo (Stateful VFS)</td>
        <td>Cấu trúc cây thư mục ảo Linux (<code>/root, /etc, /tmp, /var/log</code>), bẫy mồi nhử (Decoy files: <code>notes.txt, .bash_history</code>).</td>
        <td><span class="status-pill status-active">Hoạt động</span></td>
      </tr>
      <tr>
        <td><code>threat_intel/logger.py</code></td>
        <td>Lõi ghi nhật ký CTI tập trung</td>
        <td>Ghi nhận song song sự kiện thô vào <code>logs/events.jsonl</code> và tổng hợp phiên vào <code>logs/sessions.json</code> kèm MITRE ATT&CK.</td>
        <td><span class="status-pill status-active">Hoạt động</span></td>
      </tr>
      <tr>
        <td><code>threat_intel/mitre_mapper.py</code></td>
        <td>Bộ phân loại MITRE ATT&CK</td>
        <td>Ánh xạ tức thời các lệnh Linux terminal vào 14 Tactics và hơn 30 Techniques (T1046, T1110, T1082, T1548.003, T1105, T1070).</td>
        <td><span class="status-pill status-active">Hoạt động</span></td>
      </tr>
      <tr>
        <td><code>threat_intel/web_log_collector.py</code></td>
        <td>Thu thập log Web Container</td>
        <td>Tiến trình nền kết nối Apache Access Log từ container DVWA, URL-decode payload và tự động phân loại kỹ thuật Web exploit.</td>
        <td><span class="status-pill status-active">Đang stream</span></td>
      </tr>
      <tr>
        <td><code>ai_engine/response_engine.py</code></td>
        <td>Động cơ sinh phản hồi AI</td>
        <td>Cơ chế định tuyến 3 tầng: Fast-Path VFS Rules &rarr; LLM/LoRA Model &rarr; DPO Feedback & Graph Search Fallback.</td>
        <td><span class="status-pill status-active">Hoạt động</span></td>
      </tr>
      <tr>
        <td><code>simulate_lab_traffic.py</code></td>
        <td>Mô phỏng & Sinh 10k log</td>
        <td>Hỗ trợ cả chế độ Live Attack vào VM và sinh dữ liệu 10,000 logs đa dạng cao (0% trùng lặp, 4,920+ IP, MITRE labeled).</td>
        <td><span class="status-pill status-active">Hoàn thiện</span></td>
      </tr>
      <tr>
        <td><code>generate_ml_benchmark_batch.py</code></td>
        <td>Bộ sinh Benchmark Học Máy</td>
        <td>Tạo batch log gốc chuyên biệt cho ML/DL với đầy đủ <code>run_id, campaign_id, scenario_id, ground_truth</code> và <code>manifest.json</code>.</td>
        <td><span class="status-pill status-active">Hoàn thiện</span></td>
      </tr>
      <tr>
        <td><code>sync_to_vm.py</code></td>
        <td>Tự động hóa đồng bộ</td>
        <td>Đồng bộ mã nguồn, dữ liệu, cấu hình qua SFTP/SSH sang máy ảo VMware chỉ bằng một câu lệnh.</td>
        <td><span class="status-pill status-active">Hoạt động</span></td>
      </tr>
    </tbody>
  </table>

  <!-- PAGE BREAK -->
  <div class="page-break"></div>

  <!-- PHẦN 3: BỘ DỮ LIỆU ĐANG CÓ -->
  <h1>3. KHO DỮ LIỆU NHẬT KÝ & BENCHMARK MACHINE LEARNING HIỆN TẠI</h1>
  <p>
    Hệ thống đã thu thập và sinh ra các tập dữ liệu có cấu trúc hoàn chỉnh tại thư mục <code>logs/</code> để phục vụ nghiên cứu thực nghiệm và đánh giá mô hình học máy:
  </p>

  <table>
    <thead>
      <tr>
        <th>Tên tệp tin</th>
        <th>Dung lượng</th>
        <th>Số bản ghi</th>
        <th>Đặc điểm cấu trúc</th>
        <th>Mục đích sử dụng</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>logs/events.jsonl</code></td>
        <td>12.7 MB</td>
        <td>10,000 sự kiện</td>
        <td>Raw JSONL, 50% Web + 50% SSH, 4,920 IP độc lập, 0.00% duplicate, gán nhãn MITRE ATT&CK.</td>
        <td>Nhật ký CTI tổng thể, huấn luyện chung, phát hiện xâm nhập cấp độ sự kiện.</td>
      </tr>
      <tr>
        <td><code>logs/sessions.json</code></td>
        <td>7.6 MB</td>
        <td>5,898 phiên</td>
        <td>JSON cây phân cấp có timeline từng bước, start/end time, duration, command count, scenario.</td>
        <td>Phân tích chuỗi hành vi kẻ tấn công, mô hình hóa Markov / GNN theo phiên.</td>
      </tr>
      <tr>
        <td><code>logs/ml_benchmark_batch_raw.jsonl</code></td>
        <td>10.3 MB</td>
        <td>10,000 sự kiện</td>
        <td>Log gốc có <code>run_id</code>, <code>campaign_id</code>, <code>scenario_id</code>, <code>ground_truth</code> nhị phân và đa lớp.</td>
        <td>Bộ kiểm thử Out-Of-Distribution (OOD Testset) chuẩn mực cho Luận văn Machine Learning.</td>
      </tr>
      <tr>
        <td><code>logs/ml_benchmark_manifest.json</code></td>
        <td>6.5 KB</td>
        <td>1,793 phiên</td>
        <td>Siêu dữ liệu chi tiết thống kê 4 Runs, 4 Campaigns, 13 Scenarios, tỷ lệ session và event thực tế.</td>
        <td>Đối soát khoa học, khai báo phân bổ dữ liệu cho người chấm / hội đồng phản biện.</td>
      </tr>
    </tbody>
  </table>

  <h2>Thống Kê Phân Bổ 4 Chiến Dịch & Kịch Bản Trong Bộ Dữ Liệu ML Benchmark:</h2>
  <table>
    <thead>
      <tr>
        <th>Run ID</th>
        <th>Chiến dịch (Campaign)</th>
        <th>Hồ sơ kẻ tấn công (Threat Profile)</th>
        <th>Số Phiên (Sessions)</th>
        <th>Tỷ lệ Phiên</th>
        <th>Số Sự kiện (Events)</th>
        <th>Tỷ lệ Sự kiện</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>RUN-...-BATCH01-BOTNET</code></td>
        <td><code>CAMP-2026-BOTNET-AUTO</code></td>
        <td>Botnet quét diện rộng, dò pass SSH, tải miner qua curl/wget, quét Nikto.</td>
        <td>584 phiên</td>
        <td>32.57%</td>
        <td>2,637</td>
        <td>26.37%</td>
      </tr>
      <tr>
        <td><code>RUN-...-BATCH02-WEBPEN</code></td>
        <td><code>CAMP-2026-WEB-PENTEST</code></td>
        <td>Khai thác ứng dụng Web: SQLi Blind/UNION, CMDi, LFI, XSS, Upload Webshell.</td>
        <td>670 phiên</td>
        <td>37.37%</td>
        <td>2,663</td>
        <td>26.63%</td>
      </tr>
      <tr>
        <td><code>RUN-...-BATCH03-HUMANAPT</code></td>
        <td><code>CAMP-2026-HUMAN-APT</code></td>
        <td>Kẻ tấn công con người tương tác shell, leo thang GTFOBins (find, vim, nmap), xóa log.</td>
        <td>377 phiên</td>
        <td>21.03%</td>
        <td>3,987</td>
        <td>39.87%</td>
      </tr>
      <tr>
        <td><code>RUN-...-BATCH04-INSIDER</code></td>
        <td><code>CAMP-2026-LATERAL-INSIDER</code></td>
        <td>Nội bộ LAN 10.0.1.x quét ARP, tiến trình mạng và lưu lượng duyệt thông thường (Benign).</td>
        <td>162 phiên</td>
        <td>9.04%</td>
        <td>713</td>
        <td>7.13%</td>
      </tr>
      <tr style="font-weight: 700; background: #e2e8f0;">
        <td colspan="3">TỔNG CỘNG TẬP DỮ LIỆU</td>
        <td>1,793 phiên</td>
        <td>100.0%</td>
        <td>10,000</td>
        <td>100.0%</td>
      </tr>
    </tbody>
  </table>

  <!-- PHẦN 4: GIẢI TRÌNH KHOA HỌC DÀNH CHO LUẬN VĂN -->
  <h1>4. CƠ SỞ KHOA HỌC & GIẢI TRÌNH PHƯƠNG PHÁP LUẬN (DATA PROVENANCE)</h1>
  <p>
    Tài liệu giải trình chi tiết tại <code>DATA_PROVENANCE_AND_VERIFICATION.md</code> trả lời 5 vấn đề cốt lõi thường được giáo viên hướng dẫn và hội đồng bảo vệ luận văn kiểm tra:
  </p>

  <div class="callout callout-success">
    <strong>1. Bản chất dữ liệu (Data Nature):</strong> Dữ liệu được tạo bằng phương pháp <em>Controlled Semi-Synthetic Testbed Simulation</em> dựa trên máy ảo và container thực tế. Phương pháp này tuân thủ chuẩn mực của các bộ benchmark kinh điển như <strong>CIC-IDS2017</strong> và <strong>UNSW-NB15</strong> nhằm đảm bảo tính tái lập (reproducibility) và loại trừ hoàn toàn nhãn nhiễu (noisy labels) của lưu lượng Internet tự nhiên.
  </div>

  <div class="callout callout-success">
    <strong>2. Cơ chế gán nhãn Ground Truth (Oracle Labeling):</strong> Nhãn được gán tiền nghiệm theo thiết kế (Deterministic Design-time Oracle), dựa trực tiếp trên kỹ thuật MITRE ATT&CK for Enterprise của từng payload, <em>hoàn toàn không phải do mô hình AI tự phỏng đoán</em>.
  </div>

  <div class="callout callout-success">
    <strong>3. Độ mịn của Scenario (Granularity):</strong> Trong một phiên tấn công xâm nhập tương tác (APT Kill Chain), kẻ tấn công thực hiện tuần tự nhiều bước (Khảo sát &rarr; Leo thang GTFOBins &rarr; Tải C2 &rarr; Xóa log). Do đó, <code>scenario_id</code> được gán chính xác ở cấp độ <strong>Từng sự kiện (Event-level Action)</strong> để phục vụ nhận diện hành vi theo bước.
  </div>

  <div class="callout callout-success">
    <strong>4. Trọng số Weight vs Số Event:</strong> Trường <code>session_sampling_weight</code> trong manifest là xác suất chọn Phiên (Session), khớp gần như tuyệt đối với tỷ lệ phiên thực tế (~35%, 35%, 20%, 10%). Tỷ lệ sự kiện lệch là do phiên APT của con người tương tác sâu có trung bình 10.58 lệnh/phiên, trong khi phiên botnet chỉ có 4.5 lệnh/phiên.
  </div>

  <!-- PAGE BREAK -->
  <div class="page-break"></div>

  <!-- PHẦN 5: TRẠNG THÁI RUNTIME HIỆN TẠI -->
  <h1>5. TRẠNG THÁI VẬN HÀNH THỰC TẾ TRÊN MÁY ẢO LAB (192.168.101.218)</h1>
  <p>
    Hệ thống đang được kích hoạt và chạy nền ổn định trên máy ảo Ubuntu 22.04 LTS:
  </p>

  <table>
    <thead>
      <tr>
        <th>Thành phần dịch vụ</th>
        <th>Địa chỉ & Cổng mạng</th>
        <th>Tiến trình / Container ID</th>
        <th>Trạng thái kiểm tra</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Adaptive SSH Gateway</strong></td>
        <td><code>0.0.0.0:2222</code></td>
        <td><code>python3 -u main.py</code> (PID 2763)</td>
        <td><span class="status-pill status-active">ĐANG LẮNG NGHE</span> (Stateful VFS sẵn sàng nhận kết nối)</td>
      </tr>
      <tr>
        <td><strong>Web Target DVWA</strong></td>
        <td><code>0.0.0.0:80</code></td>
        <td>Docker Container <code>dvwa</code> (Image: <code>vulnerables/web-dvwa</code>)</td>
        <td><span class="status-pill status-active">ĐANG CHẠY</span> (Phản hồi HTTP 200 OK)</td>
      </tr>
      <tr>
        <td><strong>Web CTI Log Streamer</strong></td>
        <td>Internal Tail Process</td>
        <td>Thread nền trong <code>main.py</code> đọc Apache Access Log</td>
        <td><span class="status-pill status-active">ĐANG STREAM</span> (Đẩy log thẳng vào <code>events.jsonl</code>)</td>
      </tr>
      <tr>
        <td><strong>Tiến trình xung đột (Cũ)</strong></td>
        <td>Port 2222 (trước đây)</td>
        <td>Container <code>beelzebub</code></td>
        <td><span class="status-pill status-info">ĐÃ TẮT & DISABLE</span> (Không chiếm dụng cổng 2222)</td>
      </tr>
    </tbody>
  </table>

  <h2>Mẫu Bản Ghi Sự Kiện Thời Gian Thực (Live Ingestion Log Record):</h2>
  <pre><code>{
  "event_key": "2026-11-06T11:42:05.186389+00:00:web-192_168_101_195:HTTP_GET",
  "timestamp": "2026-11-06T11:42:05.186389+00:00",
  "source_ip": "192.168.101.195",
  "source_port": 80,
  "protocol": "HTTP",
  "session_id": "web-192_168_101_195",
  "username": "web_guest",
  "event_status": "Web_Interaction",
  "message": "DVWA HTTP GET [200] -> /login.php",
  "command": "GET /login.php",
  "command_output": "HTTP Status 200",
  "handler_type": "WEB_DVWA",
  "latency_ms": 1.5,
  "mitre_attack": {
    "tactic_id": "TA0007",
    "tactic_name": "Discovery",
    "technique_id": "T1046",
    "technique_name": "Network Service Discovery: HTTP Reconnaissance",
    "severity": "Low"
  }
}</code></pre>

  <!-- PHẦN 6: HƯỚNG DẪN THỰC THI & SỬ DỤNG -->
  <h1>6. HƯỚNG DẪN VẬN HÀNH, KIỂM THỬ & SỬ DỤNG CHO LUẬN VĂN</h1>

  <h3>1. Kiểm thử nhanh tự động từ máy thật Windows:</h3>
  <pre><code># Bắn 20 requests kiểm thử ngẫu nhiên vào cả Web (Port 80) và SSH (Port 2222)
python simulate_lab_traffic.py --live --live-count 20</code></pre>

  <h3>2. Tự kết nối thủ công vào SSH Honeypot để kiểm tra bẫy tương tác:</h3>
  <pre><code># Kết nối từ Terminal / PowerShell / PuTTY
ssh root@192.168.101.218 -p 2222
# Mật khẩu hợp lệ: 123 (hoặc root, admin)
# Thử các lệnh: whoami, uname -a, sudo -l, sudo find . -exec /bin/sh \;, history -c, exit</code></pre>

  <h3>3. Kiểm tra web qua trình duyệt:</h3>
  <pre><code>Truy cập: http://192.168.101.218/
Đăng nhập: admin / password -> Chọn Security Low -> Thử SQLi hoặc Command Injection</code></pre>

  <h3>4. Theo dõi log thời gian thực trên máy ảo:</h3>
  <pre><code>ssh nhuthang@192.168.101.218
tail -f /home/nhuthang/adaptive-honeypot/logs/events.jsonl</code></pre>

  <!-- TÀI LIỆU VÀ MÃ NGUỒN LIÊN QUAN -->
  <h1>7. DANH MỤC TÀI LIỆU HỌC THUẬT & REPOSITORY</h1>
  <ul>
    <li><strong>GitHub Repository:</strong> <code>https://github.com/dung294/adaptive-honeypot</code> (Nhánh hoạt động: <code>dev</code>).</li>
    <li><strong>Tài liệu kỹ thuật tổng hợp:</strong> <code>DOCUMENTATION.md</code>, <code>DOCUMENTATION.docx</code>, <code>DOCUMENTATION.pdf</code> (Hơn 30 trang mô tả chi tiết 4 điểm mới và 4 thuật toán).</li>
    <li><strong>Tài liệu giải trình nguồn gốc dữ liệu:</strong> <code>DATA_PROVENANCE_AND_VERIFICATION.md</code> (Giải trình khoa học cho giáo viên và người chấm luận văn).</li>
    <li><strong>Tài liệu hướng dẫn huấn luyện Machine Learning:</strong> <code>ML_DATASET_DOCUMENTATION.md</code> (Hướng dẫn trích xuất đặc trưng, n-grams, tính $\Delta t$ và phân tách Train/Test OOD).</li>
  </ul>

</body>
</html>
"""

def generate_pdf():
    print("=" * 80)
    print("📄 [PDF GENERATOR] ĐANG XUẤT BÁO CÁO TOÀN DIỆN VỀ HỆ THỐNG SANG PDF...")
    print("=" * 80)

    temp_html = WORKSPACE_DIR / "temp_system_report.html"
    with open(temp_html, "w", encoding="utf-8") as f:
        f.write(html_content)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(temp_html.as_uri(), wait_until="networkidle")
        
        # In PDF chuẩn A4
        page.pdf(
            path=str(OUTPUT_PDF_WORKSPACE),
            format="A4",
            print_background=True,
            margin={"top": "16mm", "bottom": "16mm", "left": "14mm", "right": "14mm"}
        )
        browser.close()

    if temp_html.exists():
        temp_html.unlink()

    # Sao chép vào thư mục Artifacts của Antigravity
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(OUTPUT_PDF_WORKSPACE, OUTPUT_PDF_ARTIFACT)

    print(f"✅ Đã tạo thành công PDF tại Workspace: {OUTPUT_PDF_WORKSPACE}")
    print(f"✅ Đã tạo bản sao vào Artifact Dir:     {OUTPUT_PDF_ARTIFACT}")
    print("=" * 80)

if __name__ == "__main__":
    generate_pdf()
