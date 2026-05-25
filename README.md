# LAN Encrypted File Transfer (FastAPI WebSocket + Crypto Spec)

## 1) Yêu cầu
- Python 3.10+
- Wi-Fi/LAN cùng mạng (cùng subnet)
- Mở firewall inbound cho port backend

## 2) Cài đặt
```bash
pip install -r requirements.txt
```

## 3) Cấu trúc
- `app.py` : FastAPI + WebSocket endpoint `/ws`
- `crypto_utils.py` : AES-CBC/RSA PKCS#1 v1.5 + SHA-512 (signature + integrity)
- `keys/`
  - `sender_private_key.pem` (Sender auto tạo lần chạy đầu)
  - `sender_public_key.pem` (Sender ghi ra để Receiver verify)
- `artifacts/` : lưu ciphertext raw bytes + packet.json + file giải mã

## 4) Chạy Receiver (máy 1)
```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```
Mở port inbound **8000** trong Windows Firewall.

## 5) Lấy IP Receiver (Windows 11)
Trên máy Receiver:
- Mở `cmd` chạy:
  ```bash
  ipconfig
  ```
- Lấy **IPv4 Address** của card Wi-Fi (ví dụ: `192.168.1.10`).

## 6) Copy public key từ Sender sang Receiver (bắt buộc)
- Khởi chạy Sender *ít nhất 1 lần* để auto tạo key:
  - Trong repo sẽ tạo `keys/sender_public_key.pem`
- Copy file **`keys/sender_public_key.pem`** sang thư mục `keys/` trên máy Receiver.

## 7) Chạy Sender (máy 2)
- Mở file `index.html` bằng trình duyệt trên máy Sender (khuyến nghị Chrome/Edge).
- Set WS URL:
  - `ws://<receiver-ip>:8000/ws`

## 8) Test bình thường
- Chọn Mode = **Sender** ở máy Sender, nhấn **Connect**
- Chọn Mode = **Receiver** ở máy Sender? (không cần) 
  - Receiver đã chạy bằng uvicorn ở máy 1.
- Quay lại Sender, nhấn **Send**
- Receiver sẽ lưu file giải mã vào `artifacts/email.txt` và trả `ACK`.

## 9) Test integrity (tamper 1 byte)
- Trên UI (Sender): tick checkbox **Tamper 1 byte**
- Nhấn **Send**
- Kỳ vọng Receiver trả:
  - `NACK` reason: **`Hash Mismatch`**

## 10) Receiver offline: dán “bản mã” từ packet.json vào các ô
Sender sẽ ghi packet đúng protocol vào `artifacts/packet.json`. Receiver offline chỉ cần mở file này và copy:

**“Bản mã”** nghĩa là dữ liệu đã được mã hóa/bọc theo crypto spec (khác với “plaintext”). Cụ thể:
- **Bản mã IV (Base64)**  ← `packet.json.iv` (IV cho AES-CBC)
- **Bản mã AES-Cipher (Base64)** ← `packet.json.cipher` (ciphertext của file đã AES-CBC encrypt)
- **Bản mã AES Key (RSA Wrap - enc_session_key, Base64)** ← `packet.json.enc_session_key` (AES key đã bị RSA bọc/khóa bằng public key receiver)
- **Bản mã HASH (hex)** ← `packet.json.hash` (SHA-512(IV || ciphertext || exp)) để kiểm integrity)
- **Bản mã SIG (Base64)** ← `packet.json.sig` (chữ ký RSA trên metadata = filename + exp)
- **Hạn exp (ISO-8601 UTC...)** ← `packet.json.exp` (hạn timeout để chống replay)
- **Filename** ← `packet.json.filename` (mặc định `email.txt`)


Sau đó:
- dán keys: `receiver_private_key.pem` + `sender_public_key.pem`
- bấm **Decrypt & Verify (Offline)**.



## 10) Ghi chú về artifacts/ (sửa 1 byte để tự test)
Khi Sender mã hóa xong sẽ ghi:
- `artifacts/aes_cipher.bin` (ciphertext raw)
- `artifacts/aes_iv.bin` (IV raw)
- `artifacts/packet.json` (packet gửi thực tế)

Để thử “đổi 1 byte” thủ công:
- Mở `aes_cipher.bin` bằng editor hex,
- đổi 1 byte ngẫu nhiên,
- run lại Send trong UI với tamper mode để đảm bảo hash mismatch.

