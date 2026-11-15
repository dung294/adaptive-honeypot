# ==============================================================================
# shop_db.py - CƠ SỞ DỮ LIỆU CỬA HÀNG THỜI TRANG NAM COOLMATE (SQLITE)
# ==============================================================================
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "shop.db"

def init_shop_db():
    try:
        conn = sqlite3.connect(DB_PATH)
    except Exception:
        return
    cursor = conn.cursor()

    # Tái tạo schema mới nhất (tránh lỗi mismatch schema cũ)
    cursor.execute("DROP TABLE IF EXISTS users;")
    cursor.execute("DROP TABLE IF EXISTS products;")
    cursor.execute("DROP TABLE IF EXISTS invoices;")

    # Bảng người dùng & quản trị (Mục tiêu của SQL Injection)
    cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        fullname TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        note TEXT NOT NULL
    );
    """)

    # Bảng sản phẩm thời trang Coolmate
    cursor.execute("""
    CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        price INTEGER NOT NULL,
        old_price INTEGER NOT NULL,
        description TEXT NOT NULL,
        badge TEXT NOT NULL,
        colors TEXT NOT NULL,
        icon TEXT NOT NULL
    );
    """)

    # Bảng hóa đơn điện tử VAT (Mục tiêu của Path Traversal / LFI)
    cursor.execute("""
    CREATE TABLE invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_code TEXT NOT NULL,
        customer_name TEXT NOT NULL,
        total_amount INTEGER NOT NULL,
        file_path TEXT NOT NULL
    );
    """)

    # Tài khoản bẫy: Hacker khai thác SQLi sẽ dump được mật khẩu SSH 'P@ssw0rd2026!'
    users_data = [
        ("admin", "P@ssw0rd2026!", "Coolmate Administrator", "admin@coolmate.me", "SuperAdmin", "SSH Gateway Server: Port 2222 (Root shell access)"),
        ("kho_coolmate", "KhoHang#2026", "Quản Lý Kho Hàng Hà Nội", "kho.hn@coolmate.me", "WarehouseManager", "Hệ thống quản lý tồn kho và giao vận GHN"),
        ("cskh", "CSKH@Coolmate2026", "Hỗ Trợ Khách Hàng 24/7", "cskh@coolmate.me", "Helpdesk", "Phụ trách chăm sóc khách hàng và đổi trả 60 ngày"),
        ("ketoan", "KeToan@123", "Kế Toán Trưởng", "ketoan@coolmate.me", "Accountant", "Phụ trách xuất hóa đơn điện tử VAT")
    ]
    cursor.executemany("INSERT INTO users (username, password, fullname, email, role, note) VALUES (?, ?, ?, ?, ?, ?);", users_data)

    # Danh mục sản phẩm thời trang nam Coolmate thực tế
    products_data = [
        ("Áo Polo Nam Cafe Khử Mùi & Thấm Hút Tốt (Dáng Regular Fit)", "Áo Polo", 299000, 399000, "Sợi cà phê tái chế thân thiện môi trường, khử mùi tự nhiên, chống tia UV vượt trội.", "Bán chạy", "Đen, Xanh Navy, Trắng, Rêu", "bi-person-badge"),
        ("Áo Thun Nam Cotton Compact Siêu Mát Mịn 220GSM", "Áo Thun", 189000, 249000, "100% Cotton Compact cao cấp, không bai dão, co giãn 4 chiều mềm mại cả ngày.", "Hot", "Trắng, Đen, Xám Melange, Xanh Than", "bi-toggles"),
        ("Quần Shorts Nam Thể Thao Daily Pants 7 inch (Co Giãn Thoải Mái)", "Quần", 199000, 269000, "Chất liệu Quick-Dry mau khô, túi có khóa zip tiện dụng mang chìa khóa, điện thoại.", "Yêu thích", "Đen, Xám Chì, Xanh Navy", "bi-slash-square"),
        ("Quần Lót Nam Trunk Modal Thân Thiện Môi Trường (Combo 3 Chiếc)", "Đồ Lót", 249000, 329000, "Sợi gỗ sồi Modal mềm mại, kháng khuẩn tự nhiên, cạp lưng êm không hằn vết.", "Khuyên dùng", "Đen, Xanh, Xám", "bi-box-seam"),
        ("Áo Khoác Gió Nam Thể Thao Daily Jacket Chống Nước & Cản Gió", "Áo Khoác", 399000, 499000, "Vải trượt nước công nghệ DWR, siêu nhẹ có thể gấp gọn trong lòng bàn tay.", "Mới", "Đen, Rêu, Xanh Đậm", "bi-shield-check"),
        ("Áo Sơ Mi Nam Dài Tay Vải Sợi Tre Bamboo Chống Nhăn", "Sơ Mi", 349000, 429000, "Sợi tre tự nhiên thoáng mát, chống nhăn tự nhiên không cần ủi là sau khi giặt.", "Thanh lịch", "Trắng, Xanh Nhạt, Kẻ Sọc", "bi-file-person"),
        ("Quần Dài Kaki Nam Dáng Slimfit Co Giãn 4 Chiều Công Sở", "Quần", 359000, 449000, "Thiết kế hiện đại, tôn dáng, đường may chuẩn chỉ từng milimet, phù hợp đi làm.", "Cao cấp", "Đen, Be, Xanh Navy", "bi-border-middle"),
        ("Combo 4 Đôi Vớ Cổ Trung Kháng Khuẩn Khử Mùi Bạc Nano", "Phụ Kiện", 99000, 139000, "Công nghệ phân tử Bạc Nano khử mùi chân, đệm gót êm ái chống tuột gót.", "Tiết kiệm", "Trắng, Đen, Xám", "bi-layers")
    ]
    cursor.executemany("INSERT INTO products (name, category, price, old_price, description, badge, colors, icon) VALUES (?, ?, ?, ?, ?, ?, ?, ?);", products_data)

    # Hóa đơn VAT mẫu
    invoices_data = [
        ("COOLMATE-VAT-2026-001", "Trần Quốc Hưng", 598000, "invoice_001.pdf"),
        ("COOLMATE-VAT-2026-002", "Lê Bảo Anh", 1146000, "invoice_002.pdf"),
        ("COOLMATE-VAT-2026-003", "Nguyễn Tuấn Kiệt", 349000, "invoice_003.pdf")
    ]
    cursor.executemany("INSERT INTO invoices (invoice_code, customer_name, total_amount, file_path) VALUES (?, ?, ?, ?);", invoices_data)

    conn.commit()
    conn.close()
    print("[*] Đã khởi tạo CSDL Coolmate Shop thành công.")

if __name__ == "__main__":
    init_shop_db()
