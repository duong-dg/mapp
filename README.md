# Sunny Travel Online v2.0 — bản nền tảng thử nghiệm

Đây là **bản khởi đầu kỹ thuật**, chưa phải bản thay thế hoàn chỉnh cho v1.9.8 và **chưa được phép triển khai production với dữ liệu thật**.

## Chạy thử trên máy tính

Cài Python 3.11+, sau đó trong thư mục dự án:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn server:app --host 127.0.0.1 --port 8000
```

Truy cập `http://127.0.0.1:8000` và tạo tài khoản quản trị viên đầu tiên (mật khẩu ít nhất 12 ký tự).

## Đã có trong bản nền tảng

- Backend FastAPI và SQLite, dữ liệu trên máy chủ thay vì localStorage.
- Đăng nhập session HttpOnly, PBKDF2 password hash; vai trò admin/manager/accountant/seller và kiểm tra quyền tại API.
- Danh mục đại lý, loại vé; bảng dữ liệu giá vốn và giá bán đại lý theo thời gian; API thêm giá vốn/giá bán không cho trùng khoảng hiệu lực.
- Tạo booking với giá vốn tự lấy theo ngày, giá đại lý tự lấy theo ngày, giá khách lẻ nhập thủ công; booking lưu snapshot giá.
- Ghi nhận thanh toán, chặn thanh toán vượt dư nợ; báo cáo tổng quan; tạo nhân viên và audit cơ bản.
- Cấu trúc dữ liệu ban đầu cho chiến dịch Zalo OA-ready (chưa có giao diện hoặc tích hợp OA).

## Chưa hoàn thiện — bắt buộc trước khi đưa lên hosting

- Chưa chuyển toàn bộ tính năng v1.9.8 (Sổ quỹ, công nợ nhà cung cấp, chi phí, VAT, xuất Excel, import/hợp nhất, thanh toán hàng loạt, Zalo, báo cáo nâng cao, sửa/hủy booking...).
- Chưa có công cụ **di chuyển và đối soát dữ liệu JSON v1.9.8**. Không nhập dữ liệu thật trực tiếp vào bản nền tảng.
- Chưa có quản lý sửa/xóa người dùng, reset mật khẩu, khóa tài khoản, 2FA, rate limiting, CSRF/origin hardening, quản trị session, sao lưu tự động, giám sát, kiểm thử tải, quy trình migration/rollback.
- SQLite chỉ thích hợp bản thử nghiệm/nhóm nhỏ; trước production nên cân nhắc PostgreSQL, migrations Alembic, HTTPS reverse proxy, backup/restore và staging.
- Backend API quản lý giá vốn/bảng giá đã có nhưng giao diện khai báo chưa xây dựng.
- Chưa có giao diện responsive hoàn chỉnh, kiểm thử nghiệp vụ end-to-end và kiểm thử bảo mật độc lập.

## Bảo mật và triển khai

Chỉ chạy localhost để thử nghiệm. Không mở port 8000 ra Internet, không triển khai trực tiếp lên hosting công khai. Khi có HTTPS, cấu hình `SUNNY_HTTPS=1`. File `sunny.sqlite3` chứa dữ liệu, không đưa vào thư mục public. Cần dùng reverse proxy, TLS, cơ chế CSRF/rate-limit và hệ thống sao lưu trước khi production.
