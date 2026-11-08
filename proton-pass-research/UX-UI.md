# UX/UI — Proton Pass Web App

Nguồn: [hướng dẫn web app](https://proton.me/support/use-pass-web), [trang sản phẩm](https://proton.me/pass) và [ảnh tham chiếu](images/). Đây là phân tích ảnh Proton công bố, không phải khảo sát trực tiếp giao diện đang chạy; màu sắc, tỷ lệ và kích thước dưới đây chỉ là ước lượng, không phải design token chính thức.

## UX — Cấu trúc và luồng thao tác

- Desktop dùng ba khu vực: sidebar chọn vault/Trash/Pass Monitor, cột giữa liệt kê item trong vault, panel phải hiển thị chi tiết item đang chọn. [Ảnh tổng quan](images/02-three-pane-overview.jpg).
- Thanh trên cùng có tìm kiếm và nút **Create item**; menu tạo item xuất hiện khi bấm nút này. [Ảnh menu](images/03-create-item-button.jpg).
- Chọn item trong danh sách để đọc chi tiết; bấm **Edit** để sửa; menu ba chấm cung cấp **Move to trash** và **Move to another vault**. [Ảnh sửa](images/05-edit-item.png), [menu xóa](images/07-delete-menu.png), [chuyển vault](images/08-move-item.png).
- Form tạo login nhóm các trường Title, Username, Password, 2FA secret key (TOTP), Websites, Note và Add more; chọn vault đích trong form. [Ảnh form](images/04-new-login-form.png).
- Panel chi tiết đặt các hành động ở gần tiêu đề item; mật khẩu được che mặc định, có nút xem. Metadata Last autofill, Last modified và Created nằm trong nhóm riêng. [Ảnh tổng quan](images/02-three-pane-overview.jpg).
- Lịch sử item: từ chi tiết mở **View item history**, chọn mốc Created/Modified, xem phiên bản cũ và khôi phục bằng **Restore** (tính năng tài khoản trả phí theo hướng dẫn Proton). [Ảnh tổng quan](images/10-item-history-overview.png), [timeline](images/11-item-history-timeline.png), [mốc lịch sử](images/12-item-history-entry.png), [so sánh](images/13-item-history-compare.png).
- Pass Monitor là màn hình riêng: nhóm Dark Web Monitoring, Password Health, Account protection và nội dung hướng dẫn; card trạng thái giúp nhận diện rủi ro. [Ảnh](images/09-pass-monitor.png).

## UI — Phong cách thị giác quan sát được

| Thành phần | Quan sát từ ảnh |
|---|---|
| Theme | Các ảnh tham chiếu dùng dark theme; **không kết luận đây là theme duy nhất hoặc mặc định**. |
| Nền và panel | Navy/tím đậm, sidebar và card lệch sắc độ nhẹ; đường viền mảnh, ít bóng đổ. |
| Accent | Tím/lavender xuất hiện ở nhiều màn hình (tổng quan, menu tạo item, lịch sử), nhưng **không phải màu nhấn duy nhất**: nút Edit màu kem ở ảnh sửa item, màu xanh mint ở ảnh menu xóa của một item khác ("Company card"). Không đủ bằng chứng để quy màu nhấn theo loại item, trạng thái hay phiên bản ứng dụng. |
| Chữ | Sans-serif; tiêu đề sáng và đậm hơn, nhãn/metadata nhỏ và trầm hơn. Không xác định font cụ thể từ ảnh. |
| Icon | Nét mảnh, icon của trường đặt cạnh nhãn; icon item thường nằm trong nền hình tròn. |
| Form | Trường nằm trong nhóm/card bo góc; label nhỏ, nút hành động chính bo tròn. |
| Trạng thái | Đỏ/hồng cho cảnh báo nghiêm trọng như Vulnerable; vàng/cam cho weak/reused passwords; xanh teal cho trạng thái an toàn trong Pass Monitor. |
| Lựa chọn | Vault và item được chọn có nền tím khác biệt; sidebar có dấu nhấn ở cạnh trái. |
| Chú thích trong ảnh | Một số ảnh (vd tạo login, khôi phục phiên bản) có khung đỏ quanh nút hoặc khu vực — đây là chú thích hướng dẫn do Proton thêm vào, không phải thành phần giao diện thật; không mô tả chúng như một phần UI. |

Bố cục trong ảnh desktop có sidebar hẹp, danh sách item ở giữa và chi tiết rộng hơn ở phải. Không đủ bằng chứng để ấn định tỷ lệ cột, breakpoint responsive, mã màu hex, bán kính bo góc hay hành vi hover/focus. Không dùng giá trị ước lượng như thông số triển khai.

## Ảnh tham chiếu tại local

| Ảnh | Nội dung |
|---|---|
| [01-app-switcher.jpg](images/01-app-switcher.jpg) | App switcher |
| [02-three-pane-overview.jpg](images/02-three-pane-overview.jpg) | Bố cục ba khu vực |
| [03-create-item-button.jpg](images/03-create-item-button.jpg) | Nút/menu tạo item |
| [04-new-login-form.png](images/04-new-login-form.png) | Form tạo login |
| [05-edit-item.png](images/05-edit-item.png) | Sửa item |
| [06-share-item.png](images/06-share-item.png) | Chia sẻ |
| [07-delete-menu.png](images/07-delete-menu.png) | Menu chuyển vào Trash |
| [08-move-item.png](images/08-move-item.png) | Chuyển vault |
| [09-pass-monitor.png](images/09-pass-monitor.png) | Pass Monitor |
| [10-item-history-overview.png](images/10-item-history-overview.png) | Tổng quan lịch sử |
| [11-item-history-timeline.png](images/11-item-history-timeline.png) | Timeline |
| [12-item-history-entry.png](images/12-item-history-entry.png) | Mốc thay đổi |
| [13-item-history-compare.png](images/13-item-history-compare.png) | Xem/khôi phục phiên bản |
