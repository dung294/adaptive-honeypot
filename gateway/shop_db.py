# ==============================================================================
# shop_db.py - CƠ SỞ DỮ LIỆU CỬA HÀNG ĐIỆN TỬ TECHSHOP (SQLITE)
# Phục vụ kịch bản Web Decoy: E-Commerce Store với SQLi, LFI & RCE
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

    # Bảng người dùng & quản trị (Mục tiêu của SQL Injection)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        fullname TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        note TEXT NOT NULL
    );
    """)

    # Bảng sản phẩm công nghệ
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        price INTEGER NOT NULL,
        old_price INTEGER NOT NULL,
        description TEXT NOT NULL,
        badge TEXT NOT NULL,
        icon TEXT NOT NULL
    );
    """)

    # Bảng hóa đơn điện tử (Mục tiêu của Path Traversal / LFI)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_code TEXT NOT NULL,
        customer_name TEXT NOT NULL,
        total_amount INTEGER NOT NULL,
        file_path TEXT NOT NULL
    );
    """)

    # Xóa dữ liệu cũ nếu có
    cursor.execute("DELETE FROM users;")
    cursor.execute("DELETE FROM products;")
    cursor.execute("DELETE FROM invoices;")

    # Tài khoản bẫy: Hacker khai thác SQLi sẽ dump được mật khẩu SSH 'P@ssw0rd2026!'
    users_data = [
        ("admin", "P@ssw0rd2026!", "Trần Quản Trị", "admin@techshop.vn", "SuperAdmin", "SSH Gateway Server: Port 2222 (Root shell access)"),
        ("kho_hang", "KhoHang#2026", "Lê Văn Kho", "kho@techshop.vn", "WarehouseManager", "Hệ thống quản lý tồn kho chi nhánh 1"),
        ("ketoan", "KeToan@123", "Nguyễn Thị Thu", "ketoan@techshop.vn", "Accountant", "Phụ trách xuất hóa đơn điện tử GTGT"),
        ("support", "Support@888", "Hoàng Chăm Sóc", "cskh@techshop.vn", "Helpdesk", "Hỗ trợ khách hàng trực tuyến")
    ]
    cursor.executemany("INSERT INTO users (username, password, fullname, email, role, note) VALUES (?, ?, ?, ?, ?, ?);", users_data)

    # 8 sản phẩm công nghệ thực tế
    products_data = [
        ("Laptop Dell XPS 15 9530 (i7-13700H, RTX 4050, 3.5K OLED)", "Laptop", 34990000, 39990000, "Màn hình OLED 3.5K cảm ứng, vỏ nhôm nguyên khối siêu mỏng nhẹ, pin 86Wh.", "Bán chạy", "bi-laptop"),
        ("Apple MacBook Pro 14 M3 Pro (18GB / 512GB SSD - Space Black)", "Laptop", 45990000, 49990000, "Chip M3 Pro mạnh mẽ, màn hình Liquid Retina XDR 120Hz, thời lượng pin 18h.", "Mới", "bi-laptop"),
        ("Điện thoại Apple iPhone 15 Pro Max 256GB - Titan Tự Nhiên", "Điện thoại", 29490000, 34990000, "Khung viền Titan chuẩn hàng không vũ trụ, chip A17 Pro chơi game đỉnh cao.", "Hot", "bi-phone"),
        ("Điện thoại Samsung Galaxy S24 Ultra 5G (12GB / 256GB)", "Điện thoại", 26990000, 31990000, "Tích hợp quyền năng Galaxy AI, camera 200MP, bút S-Pen tích hợp.", "Giảm sâu", "bi-phone"),
        ("Bàn phím cơ không dây Akko 3098B Plus Multi-modes (TTC Demon)", "Phụ kiện", 1690000, 2190000, "Kết nối 3 chế độ (Type-C, 2.4GHz, Bluetooth 5.0), LED RGB 16.8 triệu màu.", "Khuyên dùng", "bi-keyboard"),
        ("Chuột không dây Gaming Logitech G502 X PLUS LIGHTSPEED", "Phụ kiện", 2890000, 3490000, "Cảm biến HERO 25K siêu chính xác, switch quang-cơ học LIGHTFORCE độ bền 70 triệu lượt bấm.", "Ưa chuộng", "bi-mouse"),
        ("Màn hình Gaming LG UltraGear 27GR75Q 27 inch 2K 165Hz IPS", "Màn hình", 5890000, 7290000, "Độ phân giải QHD 2K, tần số quét 165Hz, chuẩn màu sRGB 99%, hỗ trợ G-Sync.", "Giá sốc", "bi-display"),
        ("Tai nghe chụp tai chống ồn Sony WH-1000XM5 Hi-Res Audio", "Âm thanh", 6790000, 8490000, "Chống ồn thông minh hàng đầu với bộ xử lý V1, âm thanh Hi-Res LDAC không dây đỉnh cao.", "Cao cấp", "bi-headphones")
    ]
    cursor.executemany("INSERT INTO products (name, category, price, old_price, description, badge, icon) VALUES (?, ?, ?, ?, ?, ?, ?);", products_data)

    # Hóa đơn mẫu
    invoices_data = [
        ("INV-2026-001", "Nguyễn Văn An", 34990000, "invoice_001.pdf"),
        ("INV-2026-002", "Phạm Quốc Bảo", 29490000, "invoice_002.pdf"),
        ("INV-2026-003", "Trần Minh Quân", 1690000, "invoice_003.pdf")
    ]
    cursor.executemany("INSERT INTO invoices (invoice_code, customer_name, total_amount, file_path) VALUES (?, ?, ?, ?);", invoices_data)

    conn.commit()
    conn.close()
    print(f"[*] Đã khởi tạo CSDL Cửa hàng TechShop tại: {DB_PATH}")

if __name__ == "__main__":
    init_shop_db()
