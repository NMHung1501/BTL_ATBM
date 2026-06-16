# Luồng bảo mật tự động trong CipherChat (Commercial Version)

Khi ứng dụng được chuyển sang mô hình thương mại hóa (tự động 100%), người dùng không cần phải copy/paste khóa (key) hay thực hiện giải mã thủ công nữa. Mọi quy trình mật mã phức tạp đều được đưa xuống chạy ngầm (background) ở tốc độ mili-giây.

Dưới đây là chi tiết về cách hệ thống tự động duy trì tính bảo mật, toàn vẹn và xác thực đằng sau giao diện mượt mà:

## 1. Khởi tạo và phân phối khóa tự động (Auto Key Exchange)
* **Khi người dùng tham gia phòng chat (nhập tên):** Hệ thống tạo kết nối WebSocket an toàn (Handshake).
* **Tự động sinh khóa:** Máy chủ ngay lập tức tự sinh ra một cặp khóa bất đối xứng **RSA-2048** (Gồm Private Key và Public Key) riêng biệt cho người dùng đó và lưu trữ an toàn trong bộ nhớ. 
* Người dùng không bao giờ phải nhìn thấy hay quản lý các chuỗi khóa dài dòng, hệ thống tự động ánh xạ cặp khóa này với tên hiển thị (username) của họ.

## 2. Quy trình xử lý ngầm khi "GỬI" tin nhắn (Bên A)
Ngay khi người gửi (A) nhập nội dung và nhấn "Send", hệ thống lập tức thực hiện chuỗi hành động mật mã học sau trước khi dữ liệu rời đi:
1. **Sinh khóa phiên (Session Key):** Tự động sinh ra một khóa **AES-256 (32 bytes)** và Vector khởi tạo **IV (16 bytes)** ngẫu nhiên chỉ dùng một lần (One-time use) cho riêng tin nhắn này.
2. **Mã hóa nội dung (Confidentiality):** Dùng khóa AES vừa sinh để mã hóa bản rõ (nội dung chat) thành Bản mã (Ciphertext) - đây chính là thao tác khóa "Hòm niêm phong".
3. **Băm và Ký số (Integrity & Authentication):**
   - Hệ thống tự động băm bản rõ nội dung email/tin nhắn bằng thuật toán **SHA-512** ra một chuỗi mã băm.
   - Sử dụng **Private Key của A** để mã hóa (Ký số) lên đoạn mã băm này. Bước này chứng minh chắc chắn "chính A là người tạo ra nội dung này" (Chống chối bỏ).
4. **Bọc khóa bí mật (Key Encapsulation):** 
   - Với mỗi người nhận (B, C...) trong phòng, hệ thống tự động lấy **Public Key của người nhận đó** để mã hóa khóa AES. 
   - Điều này đảm bảo: Dù tất cả đều nhận được cục dữ liệu giống nhau qua đường truyền WiFi, nhưng chỉ có "chìa khóa được bọc lại bằng ổ khóa của B" thì B mới mở được.
5. **Gắn thẻ thời hạn:** Gắn nhãn thời gian `exp_iso` là 24 giờ kể từ thời điểm gửi. Đóng gói toàn bộ (Bản mã, Khóa AES đã mã hóa, Chữ ký số, Thời hạn) thành một gói tin JSON và phát đi.

## 3. Quy trình xử lý ngầm khi "NHẬN" tin nhắn (Bên B)
Khi gói tin bay đến máy người nhận (B), giao diện chat vẫn chưa hiển thị gì cả. Phía sau, hệ thống đang làm việc như một trạm kiểm soát an ninh nghiêm ngặt:
1. **Mở khóa phiên:** Hệ thống tự lấy **Private Key của B** (được lưu ngầm trong phiên) để giải mã "chìa khóa bọc lại", thu được khóa **AES-256** ban đầu của tin nhắn. *(Lưu ý: Nếu Hacker nghe lén được gói tin, do không có Private Key của B, khóa AES sẽ vĩnh viễn không mở được).*
2. **Giải mã hòm thư:** Dùng khóa AES vừa thu được để giải mã Bản mã (Ciphertext) để lấy lại Bản rõ (văn bản gốc của tin nhắn).
3. **Kiểm tra tính toàn vẹn (Integrity Check):** 
   - Hệ thống tự động băm Bản rõ vừa giải mã được bằng **SHA-512** để tạo ra một mã băm thực tế tại máy B.
4. **Xác minh chữ ký số (Verification):** 
   - Hệ thống tự lấy **Public Key của A** (người gửi) để giải mã chữ ký số đính kèm trong gói tin. 
   - Thao tác này trả về một mã băm nguyên bản của A. Hệ thống đem mã băm nguyên bản này so sánh với mã băm thực tế tính ở bước 3. **Chỉ khi 2 chuỗi băm khớp nhau 100%**, hệ thống mới tin tưởng tuyệt đối rằng nội dung không bị sửa đổi dọc đường (Toàn vẹn) và chắc chắn là A gửi (Xác thực).
5. **Kiểm tra thời gian (Timeout Check):** Kiểm tra mốc `exp_iso`. Nếu thời gian hiện tại vượt quá 24h kể từ lúc gửi, gói tin lập tức bị từ chối và tiêu hủy (Hủy không cho đọc).

## 4. Kết quả phản hồi lên giao diện (UI)
* **Hợp lệ (✅):** Nếu TẤT CẢ các chốt chặn an ninh (giải mã AES thành công + chữ ký RSA hợp lệ + Hash khớp + thời hạn hợp lệ) đều vượt qua, hệ thống mới bắn tín hiệu cho giao diện hiển thị tin nhắn lên màn hình kèm theo một tiếng thông báo (Ting). Người dùng có thể click vào biểu tượng Ổ khóa nhỏ ở góc tin nhắn để xem các thông số bảo mật này.
* **Không hợp lệ (❌):** Nếu bất kỳ khâu nào thất bại (ví dụ: bị Hacker sửa 1 byte làm lệch Hash, chữ ký số sai, tin nhắn đã quá hạn), hệ thống sẽ ngầm quăng lỗi (NACK) và từ chối hiển thị nội dung ra giao diện. Gói tin độc hại bị tiêu diệt ngay tại bộ nhớ mà người dùng B không hề bị làm phiền. Máy chủ sẽ trả thông báo lỗi ngược lại cho người gửi A.

**Tóm lại:** 
Mọi quy trình mã hóa bảo mật từ lúc nhấn "Send" đến khi hiện ra bên máy người nhận diễn ra trong khoảng thời gian rất nhỏ (dưới 100 mili-giây). Tính năng này mang lại trải nghiệm tiện lợi "nhắn tới đâu hiện tới đó" của các ứng dụng nhắn tin thương mại (như Zalo, Telegram, WhatsApp) mà vẫn đảm bảo tiêu chuẩn bảo mật mật mã học cực kỳ khắt khe đằng sau lớp giao diện.
