# Cách chạy demo CLI

Yêu cầu: Node.js ≥ 14.

```bash
# 1. Cài deps (không có package ngoài nên có thể bỏ qua bước này nếu không dùng npm)
npm init -y  # tuỳ chọn

# 2. Tạo sẵn thư mục input (nếu chưa có)
mkdir input

# 3. Chạy demo với file mẫu (nếu đường dẫn không tồn tại, chương trình sẽ tự sinh file mẫu)
node src/index.js              # mặc định: dùng thư mục ./input và key mặc định
node src/index.js path/to/file # chỉ định file đơn lẻ

# 4. Tuỳ chọn truyền key hex 128‑bit (32 hex)
node src/index.js path/to/file 00112233445566778899aabbccddeeff
```

Sau khi chạy, kết quả:

- Mỗi file đầu vào sẽ có một thư mục con trong `output/` chứa:
  - `encrypted.bin`: dữ liệu đã mã hóa (IV + ciphertext, CBC + PKCS#7).
  - `decrypted.txt`: dữ liệu sau khi giải mã.
- Console log:
  - Kích thước gốc / kích thước sau mã hóa (in‑memory & on‑disk).
  - Thời gian `Encryption core` và `Decryption core` (CBC, không tính IV/padding).
  - Kiểm tra toàn vẹn: `Integrity check: PASS/FAIL`.
