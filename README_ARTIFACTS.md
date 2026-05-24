# README - Artifacts & Key Files

Thư mục dự án:
- `keys/`: lưu key RSA sinh ra theo từng lần gửi (có ghi đè/xóa key cũ).
- `artifacts/`: lưu dữ liệu sau khi mã hóa để bạn có thể "giả lập hacker" sửa 1 ký tự trước khi receiver verify.

Cách test giả lập xâm nhập (theo flow code):
1) Bên Sender gửi file bình thường.
2) Backend sẽ ghi ra trong `artifacts/` các file:
   - `latest_ciphertext.bin` (AES-CBC ciphertext)
   - `latest_iv.bin` (IV)
   - `latest_hash.txt` (SHA-512 hex: IV || ciphertext || exp)
   - `latest_exp.txt` (ISO-8601 expiration)
   - `latest_signature.bin` (RSA signature metadata)
   - `latest_enc_session_key.bin` (AES session key encrypted bằng RSA)
   - `latest_packet.json` (packet JSON đang gửi)
3) Trên Receiver, trước khi verify/decrypt, bạn có thể bật chế độ sửa 1 byte trong `latest_ciphertext.bin` bằng cách đặt biến môi trường:
   - `TAMPER_CIPHERTEXT=1`

Khi `TAMPER_CIPHERTEXT=1`, backend receiver sẽ tự động sửa 1 byte của ciphertext đã ghi ra để mô phỏng hacker thay đổi.

> Lưu ý: Hiện tại bản code trong repository đang ở trạng thái prototype; để có behavior tamper nêu trên, vui lòng chạy bản code đã được mình cập nhật ở bước tiếp theo.
