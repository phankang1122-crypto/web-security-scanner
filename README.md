# Web Security Scanner

Ứng dụng Node.js quét liên kết trong website và thực hiện kiểm tra HTTP thụ động.

## Chức năng
- Crawl tối đa 80 trang HTML cùng origin.
- Thu thập tối đa 250 URL liên kết/tài nguyên và kiểm tra HTTP status.
- Báo cáo 404, 410, 403, 5xx, timeout/DNS/TLS.
- Kiểm tra các security headers phổ biến trên trang HTML cùng origin.
- Xuất CSV.

## Chạy local
Yêu cầu Node.js 20+.

```bash
npm install
npm start
```
Mở `http://localhost:3000`.

## Deploy
Đưa toàn bộ thư mục lên GitHub. Tạo Web Service trên Render, kết nối repository, Build Command `npm install`, Start Command `npm start`. Chọn Node runtime.

## Giới hạn quan trọng
- Chỉ sử dụng với website bạn sở hữu hoặc có văn bản cho phép kiểm tra.
- Đây là kiểm tra thụ động, không khai thác SQL injection/XSS, không brute force, không dò cổng.
- Crawl tối đa 80 trang và 250 URL mỗi lần; không thể cam kết tìm thấy mọi link (ví dụ link được tạo bằng JavaScript, đăng nhập, sitemap lớn).
- Link ngoài website được kiểm tra HTTP nhưng không crawl sâu.
- 403 có thể là chính sách truy cập hợp lệ; không đồng nghĩa lỗ hổng.
- Thiếu security header là cảnh báo cấu hình, không tự động đồng nghĩa website bị xâm nhập.
- Có bảo vệ SSRF cơ bản: chặn IP private/reserved, kiểm tra DNS và từng redirect. Không nên mở scanner công khai không có xác thực/rate limit. Bản production cần thêm hàng đợi, giới hạn tốc độ, xác thực người dùng, logging và kiểm soát egress ở hạ tầng.
