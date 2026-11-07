# -*- coding: utf-8 -*-
"""
Script tạo tài liệu PDF toàn diện về Kiến trúc Adaptive Honeypot và Quy trình Huấn luyện Machine Learning.
Hỗ trợ đầy đủ tiếng Việt có dấu qua font Arial Unicode của Windows.
"""

import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Đăng ký font tiếng Việt từ Windows Fonts
FONT_DIR = "C:/Windows/Fonts"
pdfmetrics.registerFont(TTFont("Arial", os.path.join(FONT_DIR, "arial.ttf")))
pdfmetrics.registerFont(TTFont("Arial-Bold", os.path.join(FONT_DIR, "arialbd.ttf")))
pdfmetrics.registerFont(TTFont("Arial-Italic", os.path.join(FONT_DIR, "ariali.ttf")))
pdfmetrics.registerFont(TTFont("Arial-BoldItalic", os.path.join(FONT_DIR, "arialbi.ttf")))


class NumberedCanvas(canvas.Canvas):
    """Canvas đánh số trang dạng: Trang X / Y và Header đẹp mắt."""
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super(NumberedCanvas, self).showPage()
        super(NumberedCanvas, self).save()

    def draw_header_footer(self, page_count):
        if self._pageNumber > 1:
            # Header
            self.saveState()
            self.setFont("Arial", 8)
            self.setFillColor(colors.HexColor("#4B5563"))
            self.drawString(54, 805, "HỆ THỐNG ADAPTIVE HONEYPOT & QUY TRÌNH HUẤN LUYỆN MACHINE LEARNING")
            self.setStrokeColor(colors.HexColor("#E5E7EB"))
            self.setLineWidth(0.5)
            self.line(54, 798, 541, 798)
            
            # Footer
            self.line(54, 45, 541, 45)
            self.drawString(54, 32, "Tài liệu kỹ thuật nội bộ | Dự án Nghiên cứu An toàn thông tin")
            page_text = f"Trang {self._pageNumber} / {page_count}"
            self.drawRightString(541, 32, page_text)
            self.restoreState()


def create_pdf(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Định nghĩa các style văn bản tiếng Việt
    title_style = ParagraphStyle(
        "CoverTitle",
        fontName="Arial-Bold",
        fontSize=22,
        leading=28,
        textColor=colors.HexColor("#0F172A"),
        alignment=1, # Center
        spaceAfter=10
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        fontName="Arial",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#2563EB"),
        alignment=1,
        spaceAfter=20
    )
    meta_style = ParagraphStyle(
        "CoverMeta",
        fontName="Arial-Italic",
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#64748B"),
        alignment=1
    )
    h1_style = ParagraphStyle(
        "Heading1_Custom",
        fontName="Arial-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        "Heading2_Custom",
        fontName="Arial-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0284C7"),
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        "Body_Custom",
        fontName="Arial",
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#1F2937"),
        spaceAfter=6
    )
    bullet_style = ParagraphStyle(
        "Bullet_Custom",
        fontName="Arial",
        fontSize=9,
        leading=13.5,
        textColor=colors.HexColor("#374151"),
        leftIndent=15,
        spaceAfter=4
    )
    code_style = ParagraphStyle(
        "Code_Custom",
        fontName="Arial",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A")
    )
    callout_style = ParagraphStyle(
        "Callout_Custom",
        fontName="Arial",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1E3A8A")
    )

    story = []

    # ==========================================
    # TRANG BÌA & TIÊU ĐỀ
    # ==========================================
    story.append(Spacer(1, 20))
    story.append(Paragraph("BÁO CÁO KỸ THUẬT TOÀN DIỆN", subtitle_style))
    story.append(Paragraph("HỆ THỐNG ADAPTIVE HONEYPOT &amp; QUY TRÌNH HUẤN LUYỆN MACHINE LEARNING", title_style))
    story.append(Paragraph("Kiến trúc Cổng bẫy Cổng 22, Xử lý Lệnh rối, Phân định Nhiệm vụ &amp; Pipeline Đào tạo AI", meta_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=15))

    # ==========================================
    # CHƯƠNG 1: PHÂN ĐỊNH NHIỆM VỤ TỪNG MÁY
    # ==========================================
    story.append(Paragraph("1. KIẾN TRÚC HỆ THỐNG VÀ PHÂN ĐỊNH NHIỆM VỤ", h1_style))
    story.append(Paragraph(
        "Mô hình nghiên cứu được phân định thành hai thực thể độc lập: <b>Máy Honeypot</b> (Cảm biến thu thập dữ liệu) "
        "và <b>Máy Machine Learning</b> (Bộ não phân tích và suy luận cảnh báo). Sự tách biệt này bảo đảm tính khách quan, "
        "không để kết quả dự đoán của AI can thiệp vào quá trình thu thập log sự kiện thô ban đầu.",
        body_style
    ))

    # Bảng phân nhiệm
    roles_data = [
        [
            Paragraph("<b>Thành phần</b>", body_style),
            Paragraph("<b>Máy Honeypot (Máy của bạn)</b>", body_style),
            Paragraph("<b>Máy Machine Learning (Máy đối tác)</b>", body_style)
        ],
        [
            Paragraph("<b>Vai trò</b>", body_style),
            Paragraph("Cảm biến bẫy mồi nhử &amp; Bộ sinh nhật ký thô nguyên bản (Sensor &amp; Data Generator)", body_style),
            Paragraph("Bộ não phân tích, huấn luyện mô hình học máy &amp; cảnh báo (Analytics &amp; Inference Engine)", body_style)
        ],
        [
            Paragraph("<b>Cổng &amp; Giao tiếp</b>", body_style),
            Paragraph("• Lắng nghe Cổng 22 (SSH tiêu chuẩn)<br/>• Passthrough Admin sang Host (Cổng 22022)<br/>• Đẩy JSONL qua mạng Bridge", body_style),
            Paragraph("• Tiếp nhận file JSONL và Manifests<br/>• Xuất kết quả phân tích lên Dashboard bảo mật", body_style)
        ],
        [
            Paragraph("<b>Nhiệm vụ cốt lõi</b>", body_style),
            Paragraph("1. Tiếp nhận kết nối và giam giữ kẻ tấn công vào Deception Sandbox.<br/>2. Ghi nhận toàn bộ sự kiện theo chuẩn JSON Lines.<br/>3. Redact thông tin nhạy cảm (mật khẩu, secret, token).<br/>4. Đóng gói định danh đợt chạy và Ground Truth độc lập.", body_style),
            Paragraph("1. Kiểm định Schema và gom cụm sự kiện theo session_id.<br/>2. Huấn luyện mô hình phân loại dựa trên Ground Truth.<br/>3. Suy luận (inference) nhãn hành vi của các phiên mới.<br/>4. Ánh xạ kỹ thuật MITRE ATT&amp;CK và sinh mức cảnh báo.", body_style)
        ],
        [
            Paragraph("<b>Điều cấm kỵ</b>", body_style),
            Paragraph("❌ <b>Không tự huấn luyện model.</b><br/>❌ <b>Không tự gán nhãn AI / Prediction vào log thô.</b>", body_style),
            Paragraph("❌ <b>Không dùng prediction để làm Ground Truth train.</b><br/>❌ <b>Không dùng cùng 1 log vừa train vừa test.</b>", body_style)
        ]
    ]

    t_roles = Table(roles_data, colWidths=[80, 200, 207])
    t_roles.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EFF6FF")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_roles)
    story.append(Spacer(1, 10))

    # ==========================================
    # CHƯƠNG 2: ĐỊNH DẠNG DỮ LIỆU & MANIFEST
    # ==========================================
    story.append(Paragraph("2. ĐỊNH DẠNG DỮ LIỆU LOG VÀ QUY CHUẨN KẾT NỐI ML", h1_style))
    story.append(Paragraph(
        "Dữ liệu được chuẩn hóa theo chuẩn công nghiệp <b>JSON Lines (JSONL)</b>, trong đó mỗi dòng là một JSON object "
        "hoàn chỉnh, chứa đầy đủ ngữ cảnh để máy ML dễ dàng gom cụm phiên và truy vết.",
        body_style
    ))

    # Box giải thích 3 file
    files_box = [
        [Paragraph(
            "<b>CẤU TRÚC 3 TỆP GỬI SANG MÁY MACHINE LEARNING:</b><br/>"
            "• <b>events.jsonl (Tệp Log duy nhất):</b> Chứa toàn bộ 5.145 log sự kiện thô nguyên bản của 735 phiên SSH. "
            "Ghi nhận tuần tự vòng đời: <i>login/login_failed</i> &rarr; các lệnh <i>command</i> (kèm output thật từ VFS) &rarr; <i>session_closed</i>.<br/>"
            "• <b>run_manifest.json (Siêu dữ liệu đợt chạy):</b> Khai báo run_id, campaign_id, engine version, timestamp UTC, và dataset_role ('train' hoặc 'test').<br/>"
            "• <b>scenario_manifest.json (Đáp án Ground Truth):</b> Bảng đáp án chuẩn độc lập ánh xạ 7 kịch bản tấn công sang chiến thuật và kỹ thuật MITRE ATT&amp;CK.",
            callout_style
        )]
    ]
    t_box = Table(files_box, colWidths=[487])
    t_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#3B82F6")),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_box)
    story.append(Spacer(1, 10))

    # Ví dụ Event JSON
    story.append(Paragraph("<b>Mẫu một Event thực thi lệnh chuẩn JSON Lines:</b>", h2_style))
    sample_json = (
        "{\n"
        "  \"event_id\": \"evt-run-2026-11-06-train-5000-00002\",\n"
        "  \"timestamp\": \"2026-11-06T16:42:34.338Z\",\n"
        "  \"session_id\": \"session-run-2026-11-06-train-5000-001\",\n"
        "  \"protocol\": \"ssh\",\n"
        "  \"event_status\": \"command\",\n"
        "  \"username\": \"root\",\n"
        "  \"command\": \"whoami\",\n"
        "  \"command_output\": \"root\",\n"
        "  \"source_ip\": \"192.168.101.195\",\n"
        "  \"source_port\": 52341,\n"
        "  \"scenario_id\": \"ssh-discovery-001\",\n"
        "  \"raw_event\": \"[root@192.168.101.195] $ whoami -> root\"\n"
        "}"
    )
    t_code = Table([[Paragraph(f"<pre>{sample_json}</pre>", code_style)]], colWidths=[487])
    t_code.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#94A3B8")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_code)
    story.append(Spacer(1, 12))

    # ==========================================
    # CHƯƠNG 3: XỬ LÝ CÂU LỆNH RỐI (OBFUSCATION)
    # ==========================================
    story.append(Paragraph("3. XỬ LÝ CÂU LỆNH RỐI VÀ KỸ THUẬT LẨN TRÁNH", h1_style))
    story.append(Paragraph(
        "Kẻ tấn công thường sử dụng các kỹ thuật làm rối câu lệnh (Command Obfuscation) nhằm né tránh các hệ thống phát hiện "
        "dựa trên chữ ký từ khóa thông thường. Shell Linux (Bash) vẫn có thể thực thi được các lệnh này nhờ cơ chế phân tích cú pháp linh hoạt.",
        body_style
    ))

    obfuscation_data = [
        [
            Paragraph("<b>Kỹ thuật làm rối</b>", body_style),
            Paragraph("<b>Ví dụ lệnh thực tế</b>", body_style),
            Paragraph("<b>Cơ chế Linux thực thi &amp; Cách bắt bài</b>", body_style)
        ],
        [
            Paragraph("<b>Quote Removal</b><br/>(Gỡ bỏ dấu nháy)", body_style),
            Paragraph("<code>c\"\"a''t /et'c'/pas\"\"swd</code>", code_style),
            Paragraph("Bash tự động nối chuỗi rỗng liền nhau thành <code>cat /etc/passwd</code>. Honeypot bắt được bản chất qua <b>command_output</b>.", body_style)
        ],
        [
            Paragraph("<b>String Reverse</b><br/>(Đảo ngược chuỗi)", body_style),
            Paragraph("<code>echo \"imaohw\" | rev | bash</code>", code_style),
            Paragraph("Lệnh <code>rev</code> đảo ngược chữ thành <code>whoami</code> và pipe vào Bash. AI phát hiện qua chuỗi tiến trình thực thi.", body_style)
        ],
        [
            Paragraph("<b>Base64 Encoding</b><br/>(Mã hóa chuỗi)", body_style),
            Paragraph("<code>echo \"Y3Vyb...\" | base64 -d | sh</code>", code_style),
            Paragraph("Giải mã trực tiếp trong RAM (Fileless). Tiền xử lý ML sẽ decode Base64 để bóc tách lệnh gốc.", body_style)
        ],
        [
            Paragraph("<b>Globbing / Wildcards</b><br/>(Ký tự đại diện)", body_style),
            Paragraph("<code>/???/c?t /???/p?sswd</code>", code_style),
            Paragraph("Dấu <code>?</code> khớp 1 ký tự bất kỳ &rarr; khớp <code>/bin/cat /etc/passwd</code>. Hệ thống VFS ghi nhận tệp bị đọc.", body_style)
        ]
    ]

    t_obf = Table(obfuscation_data, colWidths=[110, 160, 217])
    t_obf.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EFF6FF")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_obf)
    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "<b>Ba tầng phòng thủ đối phó lệnh rối:</b><br/>"
        "1. <b>Tầng Honeypot:</b> Bắt bằng <code>command_output</code> thật (lệnh có thể rối, nhưng dữ liệu hệ thống trả về không thể giấu).<br/>"
        "2. <b>Tầng Chuẩn hóa (ML Pipeline):</b> Gỡ dấu nháy rỗng, decode chuỗi Base64 trước khi lọc từ khóa.<br/>"
        "3. <b>Tầng Nhận diện AI (High Entropy):</b> Model ML trích xuất đặc trưng Character n-grams và độ hỗn loạn ký tự để ánh xạ ngay vào kỹ thuật lẩn tránh <b>MITRE ATT&amp;CK T1027 (Obfuscated Files or Information)</b>.",
        bullet_style
    ))
    story.append(Spacer(1, 12))

    # ==========================================
    # CHƯƠNG 4: QUY TRÌNH XÂY DỰNG & TRAIN AI
    # ==========================================
    story.append(Paragraph("4. QUY TRÌNH XÂY DỰNG VÀ HUẤN LUYỆN MÔ HÌNH AI", h1_style))
    story.append(Paragraph(
        "Quá trình xây dựng mô hình trí tuệ nhân tạo phân loại hành vi tấn công mạng gồm 6 giai đoạn chuẩn mực, "
        "kết hợp chặt chẽ giữa toán học tối ưu và xử lý ngôn ngữ tự nhiên (NLP):",
        body_style
    ))

    # Bảng 6 giai đoạn
    ai_stages = [
        [Paragraph("<b>Giai đoạn</b>", body_style), Paragraph("<b>Mô tả chi tiết và Áp dụng vào hệ thống</b>", body_style)],
        [
            Paragraph("<b>1. Xác định bài toán</b>", body_style),
            Paragraph("Bài toán phân loại phiên SSH đa lớp (Multi-class Classification). Input: Chuỗi lệnh và sự kiện trong phiên; Output: Nhãn hành vi (Discovery, BruteForce, PrivEsc,...) và độ tin cậy.", body_style)
        ],
        [
            Paragraph("<b>2. Chuẩn bị dữ liệu</b>", body_style),
            Paragraph("Sử dụng bộ dữ liệu 5.145 log sự kiện thật từ Honeypot (735 sessions). Chia tập độc lập: <b>80% Train Set</b> (để học) và <b>20% Test Set</b> (để đánh giá khách quan).", body_style)
        ],
        [
            Paragraph("<b>3. Tiền xử lý &amp; Trích xuất đặc trưng</b>", body_style),
            Paragraph("Gom cụm các sự kiện theo <code>session_id</code>. Chuyển đổi văn bản câu lệnh thành vector số học bằng TF-IDF, n-gram ký tự hoặc Tokenizer Embeddings.", body_style)
        ],
        [
            Paragraph("<b>4. Vòng lặp huấn luyện (Training Loop)</b>", body_style),
            Paragraph("Thực thi qua nhiều Epoch (vòng lặp):<br/>"
                      "• <b>Forward Pass:</b> Mô hình dự đoán thử dựa trên trọng số hiện tại.<br/>"
                      "• <b>Loss Calculation:</b> Đo lường sai lệch giữa kết quả dự đoán và Ground Truth bằng hàm Cross-Entropy Loss.<br/>"
                      "• <b>Backpropagation:</b> Tính toán Gradient đạo hàm để tìm ra tham số gây sai sót.<br/>"
                      "• <b>Optimizer (Adam/SGD):</b> Điều chỉnh ma trận trọng số weights để giảm sai số.", body_style)
        ],
        [
            Paragraph("<b>5. Đánh giá mô hình</b>", body_style),
            Paragraph("Đánh giá trên Test Set qua 4 chỉ số vàng: <b>Accuracy</b> (Độ chính xác tổng quan), <b>Precision</b> (Tỉ lệ đoán đúng khi báo động), <b>Recall</b> (Tỉ lệ phát hiện, tránh bỏ sót cuộc tấn công), và <b>F1-Score</b>.", body_style)
        ],
        [
            Paragraph("<b>6. Triển khai (Inference)</b>", body_style),
            Paragraph("Xuất file mô hình đã đóng băng trọng số (<code>.pt</code>, <code>.onnx</code>, <code>.joblib</code>). Khi nhận log phiên mới từ Honeypot, bộ suy luận chạy phân loại và gửi cảnh báo lên Dashboard.", body_style)
        ]
    ]

    t_ai = Table(ai_stages, colWidths=[120, 367])
    t_ai.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EFF6FF")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_ai)
    story.append(Spacer(1, 10))

    # So sánh thuật toán
    story.append(Paragraph("<b>Các dòng thuật toán AI phù hợp cho bài toán:</b>", h2_style))
    algo_data = [
        [Paragraph("<b>Dòng thuật toán</b>", body_style), Paragraph("<b>Mô hình tiêu biểu</b>", body_style), Paragraph("<b>Đặc điểm &amp; Đánh giá</b>", body_style)],
        [
            Paragraph("<b>Machine Learning Cổ điển</b>", body_style),
            Paragraph("Random Forest, XGBoost, SVM", body_style),
            Paragraph("Huấn luyện siêu tốc trong vài giây, không đòi hỏi GPU, tính giải thích cao, cực kỳ thích hợp làm mô hình cơ sở (Baseline).", body_style)
        ],
        [
            Paragraph("<b>Deep Learning (Chuỗi)</b>", body_style),
            Paragraph("BiLSTM, 1D-CNN", body_style),
            Paragraph("Học rất tốt sự phụ thuộc thời gian và thứ tự trước sau của các lệnh thực thi trong phiên.", body_style)
        ],
        [
            Paragraph("<b>Transformer / LLM</b>", body_style),
            Paragraph("SecBERT, RoBERTa, Fine-tuned LLM", body_style),
            Paragraph("Hiểu sâu ngữ cảnh và câu lệnh bị làm rối phức tạp, mang lại điểm nhấn công nghệ cao nhất khi báo cáo đồ án.", body_style)
        ]
    ]
    t_algo = Table(algo_data, colWidths=[120, 140, 227])
    t_algo.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_algo)
    story.append(Spacer(1, 12))

    # ==========================================
    # CHƯƠNG 5: TRẠNG THÁI HỆ THỐNG HIỆN TẠI
    # ==========================================
    story.append(Paragraph("5. TRẠNG THÁI VẬN HÀNH VÀ BỘ DỮ LIỆU ĐÃ ĐÓNG GÓI", h1_style))
    story.append(Paragraph(
        "Hệ thống Adaptive Honeypot hiện đã hoàn thiện và sẵn sàng cho giai đoạn huấn luyện mô hình học máy:",
        body_style
    ))
    story.append(Paragraph("• <b>Bộ dữ liệu 5.145 sự kiện thực tế:</b> Đã đóng gói tại <code>HONEYPOT_ML_TRAIN_5000_LOGS.zip</code> gồm 735 sessions SSH, 0 trùng lặp, đầy đủ Ground Truth MITRE ATT&amp;CK.", bullet_style))
    story.append(Paragraph("• <b>Cổng Gateway SSH 22:</b> Đang hoạt động trên máy ảo VMware (<code>192.168.101.218:22</code>), tài khoản quản trị Host <code>nhuthang</code> đã cập nhật mật khẩu <code>123</code>.", bullet_style))
    story.append(Paragraph("• <b>Công cụ tấn công thực tế:</b> Script <code>tools/attack_honeypot_live.py</code> đã kiểm thử thành công kết nối TCP socket SSH trực tiếp vào Cổng 22.", bullet_style))
    story.append(Paragraph("• <b>Mã nguồn &amp; Kiểm thử:</b> Vượt qua 17/17 test tự động, đã đồng bộ lên GitHub nhánh <code>dev</code>.", bullet_style))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceAfter=10))
    story.append(Paragraph("<i>Báo cáo được khởi tạo tự động từ hệ thống Adaptive Honeypot Security Framework.</i>", meta_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Tạo thành công tệp PDF tại: {output_path}")


if __name__ == "__main__":
    import shutil
    out_local = "Tai_Lieu_Kien_Truc_Honeypot_Va_Huan_Luyen_AI.pdf"
    create_pdf(out_local)

    # Copy to Desktop
    desktop_path = Path("C:/Users/luunh/OneDrive/Desktop/Tai_Lieu_Kien_Truc_Honeypot_Va_Huan_Luyen_AI.pdf")
    shutil.copy2(out_local, desktop_path)
    print(f"[+] Đã copy sang Desktop: {desktop_path}")

    # Copy to Brain Artifacts directory
    artifact_path = Path("C:/Users/luunh/.gemini/antigravity/brain/b56f25d5-9336-4946-8eff-f0b94ac2a909/Tai_Lieu_Kien_Truc_Honeypot_Va_Huan_Luyen_AI.pdf")
    try:
        shutil.copy2(out_local, artifact_path)
        print(f"[+] Đã copy sang Artifacts: {artifact_path}")
    except Exception as e:
        print(f"[!] Không copy được sang Artifacts: {e}")
