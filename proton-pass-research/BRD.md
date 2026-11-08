# Business Requirements Document — Proton Pass Web App (pass.proton.me)

**Nguồn tham khảo:**
- https://pass.proton.me/ (app, SPA — không crawl được DOM render)
- https://proton.me/support/use-pass-web (hướng dẫn sử dụng)
- https://proton.me/pass (trang tính năng & pricing)
- [Mã nguồn web app](https://github.com/ProtonMail/WebClients/blob/main/applications/pass/package.json)

**Tài liệu UX/UI và ảnh tham chiếu:** [UX-UI.md](UX-UI.md). Ảnh do Proton công bố; chưa khảo sát trực tiếp giao diện đang chạy.

---

## Yêu cầu chức năng

### 1.1 Quản lý Vault (không gian lưu trữ)
| Mã | Yêu cầu |
|---|---|
| F-01 | Người dùng tạo nhiều vault để phân loại item (vd: Personal, Work) |
| F-02 | Sidebar hiển thị danh sách vault kèm số lượng item mỗi vault |
| F-03 | Mục "All items" gộp xem toàn bộ vault |
| F-04 | Vault có Trash riêng (xem mục 1.4) |
| F-05 | Chia sẻ vault với người khác qua email hoặc link bảo mật (có xác nhận trước khi share) — Plus/Business |

### 1.2 Quản lý Item (CRUD)
| Mã | Yêu cầu |
|---|---|
| F-10 | Tạo item mới qua nút "Create item" cạnh thanh search, chọn loại: Login, Credit card, Note, Identity (suy ra từ form) |
| F-11 | Form tạo Login gồm: Title, Username, Password (có nút generate/regenerate), 2FA secret key (TOTP), Websites (nhiều URL, nút "+ Add"), Note, custom fields ("+ Add more") |
| F-12 | Sửa item: chọn item → nút Edit → cập nhật field → lưu |
| F-13 | Xóa item: menu 3 chấm → "Move to trash" → xác nhận → xóa vĩnh viễn sau đó |
| F-14 | Di chuyển item giữa các vault: menu 3 chấm → "Move to another vault" → chọn vault đích |
| F-15 | Panel chi tiết hiển thị: Username, Password (ẩn bằng dấu chấm, có icon reveal/eye), Websites (hiển thị dạng link), metadata (Last autofill, Last modified, Created) |
| F-16 | Trạng thái "Vulnerable" gắn nhãn cảnh báo (màu đỏ/hồng) ngay trên dòng Password khi mật khẩu yếu/bị lộ |

### 1.3 Danh sách & Tìm kiếm
| Mã | Yêu cầu |
|---|---|
| F-20 | Thanh search toàn cục ở top bar giữa trang |
| F-21 | Filter nhanh trong danh sách: "All (n)", "Recent" |
| F-22 | Chế độ "Multiple select" để thao tác hàng loạt |
| F-23 | Danh sách item nhóm theo thời gian (vd label "Today") |

### 1.4 Trash
| Mã | Yêu cầu |
|---|---|
| F-30 | Item bị xóa chuyển vào Trash (không xóa vĩnh viễn ngay) |
| F-31 | Trash truy cập từ sidebar |

### 1.5 Lịch sử Item (Item History) — gói trả phí
| Mã | Yêu cầu |
|---|---|
| F-40 | Xem thông tin version hiện tại: current version, last autofill, created, modified |
| F-41 | Nút "View item history" (pill button nổi bật) mở timeline đầy đủ |
| F-42 | Timeline liệt kê từng lần Created/Modified theo mốc thời gian |
| F-43 | Click vào 1 mốc → xem snapshot giá trị tại thời điểm đó |
| F-44 | So sánh (tab qua lại) giữa version cũ và version hiện tại |
| F-45 | Nút "Restore" khôi phục version cũ thành current |

### 1.6 Pass Monitor (Giám sát bảo mật)
| Mã | Yêu cầu |
|---|---|
| F-50 | Mục riêng "Pass Monitor" trong sidebar |
| F-51 | Dark Web Monitoring: cảnh báo khi credential xuất hiện trong rò rỉ dữ liệu bên thứ 3 (trạng thái good/bad rõ ràng — xanh/teal khi an toàn) |
| F-52 | Password Health: phát hiện "Weak passwords" và "Reused passwords" (đếm số lượng, cảnh báo màu vàng/cam) |
| F-53 | Inactive 2FA: liệt kê tài khoản chưa bật 2FA dù hỗ trợ |
| F-54 | Excluded items: item được loại trừ khỏi giám sát |
| F-55 | Account protection: toggle bật/tắt bảo vệ nâng cao |
| F-56 | Khu vực "Want to learn more?" với 3 card giáo dục người dùng |

### 1.7 Bảo mật & Mã hóa
| Mã | Yêu cầu |
|---|---|
| F-60 | End-to-end, zero-knowledge encryption cho toàn bộ dữ liệu (password, passkey, credit card) |
| F-61 | Hỗ trợ Passkey (đăng nhập không mật khẩu, chống phishing) |
| F-62 | Built-in 2FA authenticator (lưu & autofill mã 2FA) — Plus/Business |
| F-63 | Emergency Access — Plus/Business |
| F-64 | Advanced account protection — Plus/Business |

### 1.8 Email Alias
| Mã | Yêu cầu |
|---|---|
| F-70 | Tạo hide-my-email alias để ẩn địa chỉ email thật (Free: tối đa 10, Plus: unlimited) |
| F-71 | Forward email từ alias về inbox thật |
| F-72 | Custom domain cho alias — Plus |
| F-73 | Additional mailbox cho alias — Plus |
| F-74 | Gửi email trực tiếp từ alias — Plus |

### 1.9 Chia sẻ & Cộng tác
| Mã | Yêu cầu |
|---|---|
| F-80 | Share item/vault qua email hoặc secure link |
| F-81 | Secure vault sharing — Plus/Business |
| F-82 | File attachment đính kèm vào credential — Plus |
| F-83 | SSO (Single Sign-On) cho doanh nghiệp — Business |
| F-84 | Activity log & compliance reporting — Business |
| F-85 | Policy enforcement (giới hạn chia sẻ ra ngoài tổ chức) — Business |

### 1.10 Đa nền tảng & Import/Export
| Mã | Yêu cầu |
|---|---|
| F-90 | Đồng bộ không giới hạn thiết bị (web, mobile iOS/Android, desktop Windows/macOS/Linux, extension Chrome/Firefox/Edge/Safari/Brave) |
| F-91 | Import password từ browser hoặc password manager khác qua file CSV |
| F-92 | Command line interface (CLI) — Plus |
| F-93 | App switcher (icon 4 ô vuông) chuyển nhanh giữa các app Proton (Mail, Calendar, VPN, Drive, Meet) |

### 1.11 Phân hạng gói (Pricing tiers — ảnh hưởng tính năng khả dụng)
| Gói | Giá | Khác biệt chính |
|---|---|---|
| Free | $0 | Unlimited login/note/card, unlimited devices, password generator, 10 alias, weak/reused password alert, passkey, import |
| Pass Plus | $2.99/tháng (billed yearly) | + Unlimited alias, built-in 2FA, vault/link sharing, Dark Web Monitoring, file attachment, Emergency Access, custom domain, CLI |
| Proton Unlimited | $9.99/tháng | Pass Plus + Mail + Calendar + VPN + Drive + Meet |
| Business | (riêng trang business) | + SSO, compliance/activity log, policy enforcement |

---

## Công nghệ web (tham chiếu triển khai hiện tại)

Theo [`applications/pass/package.json`](https://github.com/ProtonMail/WebClients/blob/main/applications/pass/package.json) trong monorepo ProtonMail/WebClients:

| Lớp | Công nghệ được khai báo |
|---|---|
| Giao diện và định tuyến | React, React DOM, React Router DOM |
| Quản lý trạng thái | Redux Toolkit, React Redux, Redux Saga |
| Ngôn ngữ và build | TypeScript, Webpack, `@proton/pack` (`proton-pack`) |
| Thành phần giao diện | `@proton/components`, `@proton/atoms`, `@proton/icons`, `@proton/styles` |
| Lưu trữ phía trình duyệt | `idb` (IndexedDB) |
| Quốc tế hóa | `ttag`, `@proton/i18n` |
| Thư viện mã hóa trong devDependencies | `@protontech/crypto` |
| Kiểm thử và lint | Jest, Testing Library React, oxlint |

HTML tại https://pass.proton.me/ chứa `<div class="app-root"></div>` và bundle JavaScript có `webpackChunkproton_pass`: dấu hiệu ứng dụng SPA dùng Webpack. Các dependency trong manifest không tự chứng minh chi tiết triển khai offline hoặc luồng mã hóa runtime.
