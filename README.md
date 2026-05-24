# LAN Encrypted File Transfer (FastAPI WebSocket + PyCryptodome)

## 1) Mô tả chung
Ứng dụng gồm:
- Backend `app.py`: FastAPI chạy WebSocket endpoint `/ws` trên `host=0.0.0.0`.
- `crypto_utils.py`: tách hàm AES-CBC, RSA-2048 (PKCS#1 v1.5), ký/verify RSA+SHA-512, và hash SHA-512.
- Frontend: `index.html`, `style.css`, `script.js`.

Luồng bắt buộc:
- **Handshake**: Sender gửi `Hello!` → Receiver trả `Ready!`
- **Trao đổi khóa**: Receiver tạo RSA-2048 gửi public key cho Sender.
- **Ký metadata**: Sender ký metadata `{filename, timestamp}` bằng RSA/SHA-512.
- **Mã hóa session key**: Sender mã hóa AES session key bằng RSA PKCS#1 v1.5.
- **Mã hóa file AES-CBC** + **hash SHA-512(IV || ciphertext || expiration)**
- Receiver: verify hash + verify chữ ký + kiểm tra `now <= exp` (24h), rồi ACK/NACK.

> Lưu ý kỹ thuật: Cách trình bày UI chỉ mô tả theo yêu cầu. Việc crypto thực thi trên backend để đảm bảo đúng thuật toán/padding.

## 2) Cài đặt thư viện
Mở terminal ở thư mục dự án `d:/BTL_ATBM`:
```bash
pip install -r requirements.txt
```

## 3) Chạy trên 2 máy LAN
### Máy Receiver (nơi sẽ nhận và lưu file)
1. Chạy backend:
```bash
python app.py
```
Backend sẽ listen trên `http://0.0.0.0:8000` (WebSocket dùng đường dẫn `/ws`).

2. Firewall: cần cho phép inbound TCP cổng **8000**.

### Máy Sender (máy gửi)
1. Mở `index.html` bằng trình duyệt.
2. Ở chế độ **Sender**, nhập WS URL trỏ tới IP của Receiver:
- Ví dụ (Receiver IP = 192.168.1.10):
  - `ws://192.168.1.10:8000/ws`
3. Chọn file `email.txt` (text/plain), set expiration (mặc định có nút auto: now+24h nếu bạn nhập `auto`).
4. Bấm **Connect** → **Send encrypted package**.

## 4) Tìm IP trên Windows 11
Trên mỗi máy:
- Mở CMD và chạy:
```cmd
ipconfig
```
- Lấy dòng **IPv4 Address** của card đang dùng Wi-Fi (ví dụ `192.168.x.x`).

## 5) Kiểm tra kết quả
- Receiver sẽ lưu file dưới tên: `email.txt` (ngay trong thư mục chạy backend).
- Console/Terminal UI hiển thị log theo thời gian thực:
  - `[+] ... Handshake/Keys/Encrypt/Hash/Validate/ACK|NACK`

## 6) File Explanation (hàm + luồng chi tiết)
### `crypto_utils.py`
- `generate_iv(block_size=16) -> bytes`
  - Tạo IV ngẫu nhiên cho AES-CBC.
- `aes_encrypt_cbc(aes_key, iv, plaintext) -> bytes`
  - AES mode CBC, dùng PKCS#7 padding.
- `aes_decrypt_cbc(aes_key, iv, ciphertext) -> bytes`
  - Giải mã + unpad.
- `rsa_generate_keypair_2048()`
  - Tạo keypair RSA 2048 bit.
- `rsa_encrypt_pkcs1_v1_5(public_key, message) -> bytes`
  - RSA encryption với padding PKCS#1 v1.5.
- `rsa_decrypt_pkcs1_v1_5(private_key, ciphertext) -> bytes`
  - Decrypt PKCS#1 v1.5.
- `rsa_sign_sha512(message, private_key) -> bytes`
  - Tính SHA-512(message) rồi sign bằng RSA PKCS#1 v1.5.
- `rsa_verify_sha512(message, signature, public_key) -> bool`
  - Verify chữ ký.
- `sha512_hex(iv, ciphertext, exp_iso) -> str`
  - Tính hash theo yêu cầu: SHA-512(IV || ciphertext || expiration).
- `b64e/b64d`: base64 encode/decode phục vụ JSON.

### `app.py` (backend WebSocket `/ws`)
WebSocket xử lý 1 phiên theo kết nối:
1. **Handshake**
   - Nhận message đầu:
     - Sender: nhận `Hello!` và trả `Ready!`
     - Receiver: trả `Ready!` ngay.
2. **Receiver tạo RSA keypair**
   - Tạo RSA-2048, lưu private/public theo kết nối.
   - Gửi `{type:"public_key", public_key_pem: ...}` cho Sender.
3. **Sender (trên cùng backend) gửi plaintext payload**
   - UI Sender chỉ gửi `{filename, plaintext_b64, exp}`.
   - Backend tạo session AES key, tạo metadata `{filename, timestamp}` từ exp,
     sau đó ký metadata, encrypt session key bằng RSA public key của receiver,
     encrypt file AES-CBC và tính hash SHA-512(IV||cipher||exp).
   - Backend đóng gói thành packet JSON và gửi cho Receiver.
4. **Receiver verify & giải mã**
   - Kiểm tra timeout: `now > exp_dt` ⇒ NACK.
   - Verify chữ ký RSA/SHA-512 trên metadata bytes.
   - Compute lại hash SHA-512 và so sánh với `hash` trong packet.
   - Nếu OK: decrypt AES-CBC và lưu thành `email.txt`.
   - Gửi `ACK` hoặc `NACK`.

## 7) Ghi chú về an toàn
- Bài lab theo yêu cầu thuật toán/hàm cụ thể.
- Trong thực tế sản phẩm, nên dùng TLS và cơ chế key exchange chuẩn hơn (hybrid + AEAD), nhưng ở đây tuân thủ đề bài.

