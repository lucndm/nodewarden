# Độ phủ endpoint của client Bitwarden chính thức trên NodeWarden

Ngày đo: 2026-11-09. Client: `bitwarden/clients` @ `2ff80e5`. NodeWarden: `origin/main` @ `060500c`.

## Kết luận

NodeWarden có route cho **96 / 388** đường dẫn mà client chính thức gọi. Phần lõi của vault cá nhân (đăng nhập, sync, item, folder, Send, thiết bị, 2FA cơ bản) đã có. Phần thiếu lớn nhất là organizations: NodeWarden làm org bằng đường dẫn riêng cho web vault của mình, nên 120 đường dẫn org chính thức rơi vào catch-all 501 ở `src/router-authenticated.ts`.

| Trạng thái | Số đường dẫn |
|---|---|
| có route | 96 |
| 501 | 135 |
| không có route | 149 |
| không dò được | 8 |

| Nhóm | Có route | 501 | Không có route |
|---|---|---|---|
| 1. Organizations: phía member | 0 | 5 | 0 |
| 1b. Organizations: admin console | 23 | 60 | 0 |
| 2. Tài khoản | 11 | 10 | 30 |
| 3. Tính năng client mới | 1 | 0 | 4 |
| 4. Vault, 2FA và phần còn lại | 59 | 5 | 10 |
| 5. Ngoài phạm vi (trả phí hoặc doanh nghiệp) | 2 | 55 | 105 |

## Cách đo

1. Lấy mọi lời gọi `apiService.send(method, path, request, authed, hasResponse)` trong `libs/`, `apps/`, `bitwarden_license/` (bỏ spec, test, stories), cộng thêm vài endpoint gọi trực tiếp: `/connect/token`, `/events/collect`, `/notifications/hub`.
2. Thay mỗi tham số đường dẫn bằng một UUID, rồi gọi thẳng `handlePublicRoute` và `handleAuthenticatedRoute` với một `env` giả. Mỗi binding (D1, R2, Durable Object) ném lỗi đánh dấu ngay khi bị chạm tới. Router trả `null` nghĩa là không có route; handler chạm tới binding nghĩa là có route; 501 là catch-all hoặc cố ý từ chối.
3. Kiểu request và response lấy từ chính lời gọi `send`: kiểu của tham số request trong hàm bao quanh, và `new XResponse(...)` ngay sau đó.

## Giới hạn

- Phép đo chỉ cho biết **có route hay không**, chưa kiểm tra hình dạng request/response. Việc kiểm tra hợp đồng do Bruno collection trong `api-tests/` đảm nhận.
- Có dương tính giả khi một segment cố định khớp nhầm route `/:id`. Ví dụ `PUT /organizations/{id}/users/enable-pam` khớp `users/:membershipId`.
- Có âm tính giả khi route của NodeWarden đòi kiểu tham số khác. Ví dụ `PUT /organizations/{id}/policies/{type}` cần `type` là số, nên bị đếm là 501.
- Đường dẫn dựng hoàn toàn từ biến (chủ yếu là billing) không dò được.
- Một số mục là quyết định có chủ đích: đổi KDF và các luồng cần gửi email trả 501, còn `/accounts/password-hint` đã bị gỡ ngày 2026-10-16.
- **Thiếu mọi lời gọi do Rust SDK thực hiện.** Tạo, sửa, chuyển thư mục, chia sẻ, đưa vào thùng rác, khôi phục và xóa cipher chỉ đi qua `@bitwarden/sdk-internal`; TypeScript không có đường thay thế. Phần bổ sung "Endpoint do Rust SDK gọi" ở cuối báo cáo liệt kê chúng.
- `GET /sync` bị sót vì client dựng đường dẫn trong một biến.

## Endpoint do Rust SDK gọi (bổ sung ngày 2026-11-09)

Nguồn: `@bitwarden/sdk-internal` 0.2.0-main.1214, đúng bản mà `clients` khai báo, publish lúc 2026-11-06 14:28 UTC. Mã nguồn đọc ở `bitwarden/sdk-internal` commit `5b7fbb41`, commit cuối trên `main` trước giờ publish.

Cách lấy: với mỗi hàm trong client API sinh tự động (`crates/bitwarden-api-api/src/apis/`) lấy method và đường dẫn, rồi giữ những hàm được gọi trong code không phải test của `bitwarden-vault`, `bitwarden-send`, `bitwarden-sync` và `bitwarden-importers`. Cách khớp theo tên hàm nên có thể thừa vài mục, nhưng không sót lời gọi trực tiếp. Sau đó dò router như ở trên.

| Trạng thái | Endpoint |
|---|---|
| có route (31) | `POST /ciphers`, `POST /ciphers/create`, `GET`/`PUT`/`DELETE /ciphers/{id}`, `PUT /ciphers/{id}/partial`, `/share`, `/collections_v2`, `/delete`, `/restore`, `PUT /ciphers/move`, `/delete`, `/restore`, `DELETE /ciphers`, `POST /ciphers/{id}/attachment/v2`, `GET`/`DELETE /ciphers/{id}/attachment/{attachmentId}`, `POST /ciphers/import`, `GET /sync`, `POST /folders`, `GET`/`PUT /folders/{id}`, `POST /sends`, `GET`/`PUT`/`DELETE /sends/{id}`, `PUT /sends/{id}/remove-password`, `GET /sends/{id}/file/{fileId}`, `POST /sends/file/v2`, `POST /sends/access`, `POST /sends/access/file/{fileId}` |
| không có route (18) | `PUT /ciphers/share` (chia sẻ hàng loạt), `POST /ciphers/bulk-collections`, `POST /ciphers/import-organization`, `GET /ciphers/{id}/attachment/{attachmentId}/renew`, `GET /ciphers/organization-details`, `/assigned`, `/logins`, và các biến thể admin: `POST /ciphers/admin`, `PUT`/`DELETE /ciphers/{id}/admin`, `PUT /ciphers/{id}/collections-admin`, `/delete-admin`, `/restore-admin`, `PUT /ciphers/delete-admin`, `/restore-admin`, `DELETE /ciphers/admin`, `GET`/`DELETE /ciphers/{id}/attachment/{attachmentId}/admin` |

Các biến thể admin và `organization-details` thuộc admin console của organization (nhóm 1b). SDK còn gọi các endpoint ngoài vault, như emergency access, xoay khóa và invite link của organization; các nhóm tương ứng ghi lại chúng.

## 1. Organizations: phía member

| Trạng thái | Method | Đường dẫn | Request | Response | Nguồn trong clients |
|---|---|---|---|---|---|
| 501 | GET | `/organizations/{id}/keys` | — | OrganizationKeysResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:282` |
| 501 | POST | `/organizations/{id}/keys` | OrganizationKeysRequest | OrganizationKeysResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:290` |
| 501 | POST | `/organizations/{id}/leave` | — | — | `libs/common/src/admin-console/services/organization/organization-api.service.ts:205` |
| 501 | POST | `/organizations/{organizationId}/users/{id}/accept` | OrganizationUserAcceptRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:154` |
| 501 | POST | `/organizations/{organizationId}/users/{id}/accept-init` | OrganizationUserAcceptInitRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:140` |

## 1b. Organizations: admin console

| Trạng thái | Method | Đường dẫn | Request | Response | Nguồn trong clients |
|---|---|---|---|---|---|
| 501 | DELETE | `/organizations/{id}` | SecretVerificationRequest | — | `libs/common/src/admin-console/services/organization/organization-api.service.ts:210` |
| 501 | GET | `/organizations/{id}` | — | OrganizationResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:41` |
| 501 | PUT | `/organizations/{id}` | OrganizationUpdateRequest | OrganizationResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:133` |
| 501 | POST | `/organizations/{id}/api-key` | OrganizationApiKeyRequest | ApiKeyResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:248` |
| 501 | PUT | `/organizations/{id}/collection-management` | OrganizationCollectionManagementUpdateRequest | OrganizationResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:346` |
| 501 | POST | `/organizations/{id}/reinstate` | — | — | `libs/common/src/admin-console/services/organization/organization-api.service.ts:201` |
| 501 | POST | `/organizations/{id}/rotate-api-key` | OrganizationApiKeyRequest | ApiKeyResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:271` |
| 501 | POST | `/organizations/{id}/seat` | SeatRequest | PaymentResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:179` |
| 501 | GET | `/organizations/{id}/sso` | — | OrganizationSsoResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:302` |
| 501 | POST | `/organizations/{id}/sso` | OrganizationSsoRequest | OrganizationSsoResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:307` |
| 501 | POST | `/organizations/{id}/storage` | StorageRequest | PaymentResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:190` |
| 501 | POST | `/organizations/{id}/subscribe-secrets-manager` | SecretsManagerSubscribeRequest | ProfileOrganizationResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:332` |
| 501 | POST | `/organizations/{id}/upgrade` | OrganizationUpgradeRequest | PaymentResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:140` |
| 501 | GET | `/organizations/{identifier}/auto-enroll-status` | — | OrganizationAutoEnrollStatusResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:89` |
| 501 | GET | `/organizations/{organizationId}/audit/items{toQueryString(range)}` | ? | ? | `bitwarden_license/bit-web/src/app/pam/access-audit/default-audit-api.service.ts` |
| 501 | GET | `/organizations/{organizationId}/audit{toQueryString(filter)}` | ? | ? | `bitwarden_license/bit-web/src/app/pam/access-audit/default-audit-api.service.ts` |
| 501 | GET | `/organizations/{organizationId}/auth-requests` | — | ListResponse | `bitwarden_license/bit-common/src/admin-console/auth-requests/organization-auth-request-api.service.ts:16` |
| 501 | POST | `/organizations/{organizationId}/auth-requests` | OrganizationAuthRequestUpdateRequest[] | — | `bitwarden_license/bit-common/src/admin-console/auth-requests/organization-auth-request-api.service.ts:43` |
| 501 | POST | `/organizations/{organizationId}/auth-requests/{requestId}` | AdminAuthRequestUpdateRequest | — | `bitwarden_license/bit-common/src/admin-console/auth-requests/organization-auth-request-api.service.ts:67` |
| 501 | POST | `/organizations/{organizationId}/auth-requests/deny` | BulkDenyAuthRequestsRequest | — | `bitwarden_license/bit-common/src/admin-console/auth-requests/organization-auth-request-api.service.ts:30` |
| 501 | POST | `/organizations/{organizationId}/cancel` | SubscriptionCancellationRequest | — | `libs/common/src/billing/services/billing-api.service.ts:25` |
| 501 | DELETE | `/organizations/{organizationId}/collections` | CollectionBulkDeleteRequest | — | `libs/common/src/services/api.service.ts:554` |
| 501 | DELETE | `/organizations/{organizationId}/collections/{id}` | — | — | `libs/common/src/services/api.service.ts:544` |
| 501 | PUT | `/organizations/{organizationId}/collections/{id}` | UpdateCollectionRequest | CollectionAccessDetailsResponse | `libs/common/src/services/api.service.ts:533` |
| 501 | GET | `/organizations/{organizationId}/collections/{id}/details` | — | CollectionAccessDetailsResponse | `libs/common/src/services/api.service.ts:448` |
| 501 | GET | `/organizations/{organizationId}/collections/{id}/users` | — | SelectionReadOnlyResponse | `libs/common/src/services/api.service.ts:504` |
| 501 | GET | `/organizations/{organizationId}/collections/access` | — | ListResponse | `libs/common/src/services/api.service.ts:490` |
| 501 | POST | `/organizations/{organizationId}/collections/bulk-access` | request | — | `libs/admin-console/src/common/collections/services/default-collection-admin.service.ts:120` |
| 501 | GET | `/organizations/{organizationId}/collections/details` | — | ListResponse | `libs/common/src/services/api.service.ts:477` |
| 501 | POST | `/organizations/{organizationId}/delete-recover-token` | OrganizationVerifyDeleteRecoverRequest | — | `libs/common/src/admin-console/services/organization/organization-api.service.ts:218` |
| 501 | GET | `/organizations/{organizationId}/export` | undefined | OrganizationExportResponse | `libs/tools/export-vault-core/src/services/api/default-vault-export-api.service.ts:15` |
| 501 | DELETE | `/organizations/{organizationId}/groups/{id}/user/{organizationUserId}` | — | — | `libs/common/src/services/api.service.ts:577` |
| 501 | GET | `/organizations/{organizationId}/groups/{id}/users` | — | (có body) | `libs/common/src/services/api.service.ts:566` |
| 501 | POST | `/organizations/{organizationId}/import` | ImportDirectoryRequest | — | `libs/common/src/admin-console/services/organization/organization-api.service.ts:238` |
| 501 | GET | `/organizations/{organizationId}/policies/{type}` | — | PolicyResponse | `libs/common/src/admin-console/services/policy/policy-api.service.ts:28` |
| 501 | PUT | `/organizations/{organizationId}/policies/{type}` | SavePolicyRequest | PolicyResponse | `libs/common/src/admin-console/services/policy/policy-api.service.ts:138` |
| 501 | GET | `/organizations/{organizationId}/policies/master-password` | — | PolicyResponse | `libs/common/src/admin-console/services/policy/policy-api.service.ts:90` |
| 501 | GET | `/organizations/{organizationId}/policies/token` | — | ListResponse | `libs/common/src/admin-console/services/policy/policy-api.service.ts:55` |
| 501 | GET | `/organizations/{organizationId}/two-factor` | — | ListResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:51` |
| 501 | DELETE | `/organizations/{organizationId}/two-factor/duo` | TwoFactorOrganizationDuoDeleteRequest | — | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:173` |
| 501 | PUT | `/organizations/{organizationId}/two-factor/duo` | TwoFactorDuoUpdateRequest | TwoFactorOrganizationDuoUpdateResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:159` |
| 501 | POST | `/organizations/{organizationId}/two-factor/get-duo` | SecretVerificationRequest | TwoFactorOrganizationDuoResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:136` |
| 501 | DELETE | `/organizations/{organizationId}/users` | OrganizationUserBulkRequest | ListResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:299` |
| 501 | GET | `/organizations/{organizationId}/users/{id}` | — | OrganizationUserDetailsResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:45` |
| 501 | POST | `/organizations/{organizationId}/users/{id}/auto-confirm` | OrganizationUserConfirmRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:182` |
| 501 | DELETE | `/organizations/{organizationId}/users/{id}/delete-account` | — | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:372` |
| 501 | PUT | `/organizations/{organizationId}/users/{id}/recover-account` | OrganizationUserResetPasswordRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:276` |
| 501 | GET | `/organizations/{organizationId}/users/{id}/reset-password-details` | — | OrganizationUserResetPasswordDetailsResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:98` |
| 501 | PUT | `/organizations/{organizationId}/users/{id}/restore/vnext` | OrganizationUserRestoreRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:348` |
| 501 | PUT | `/organizations/{organizationId}/users/{id}/revoke` | — | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:310` |
| 501 | PUT | `/organizations/{organizationId}/users/{userId}/reset-password-enrollment` | OrganizationUserResetPasswordEnrollmentRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:262` |
| 501 | GET | `/organizations/{organizationId}/users/mini-details` | — | ListResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:84` |
| 501 | GET | `/organizations/{organizationId}/users/pending-auto-confirm` | ? | ? | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts` |
| 501 | DELETE | `/organizations/{orgId}/groups` | OrganizationGroupBulkRequest | (có body) | `apps/web/src/app/admin-console/organizations/core/services/group/group-api.service.ts:87` |
| 501 | GET | `/organizations/{orgId}/groups/{groupId}/details` | — | GroupDetailsResponse | `apps/web/src/app/admin-console/organizations/core/services/group/group-api.service.ts:27` |
| 501 | GET | `/organizations/{orgId}/groups/details` | — | ListResponse | `apps/web/src/app/admin-console/organizations/core/services/group/group-api.service.ts:53` |
| 501 | POST | `/organizations/create-without-payment` | OrganizationNoPaymentMethodCreateRequest | OrganizationResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:109` |
| 501 | POST | `/organizations/invite-link/policies` | ? | ? | `libs/common/src/admin-console/services/policy/policy-api.service.ts` |
| 501 | POST | `/organizations/invite-link/status` | ? | ? | `libs/organization-invite-link/src/services/default-organization-invite-link-api.service.ts` |
| 501 | POST | `/organizations/invite-link/validate-email-domain` | OrganizationInviteLinkValidateEmailDomainRequest | OrganizationInviteLinkValidateEmailDomainResponse | `libs/organization-invite-link/src/services/default-organization-invite-link-api.service.ts:14` |
| có route | POST | `/organizations` | OrganizationCreateRequest | OrganizationResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:100` |
| có route | GET | `/organizations/{organizationId}/collections` | — | ListResponse | `libs/common/src/services/api.service.ts:464` |
| có route | POST | `/organizations/{organizationId}/collections` | CreateCollectionRequest | CollectionAccessDetailsResponse | `libs/common/src/services/api.service.ts:518` |
| có route | POST | `/organizations/{organizationId}/groups` | GroupRequest | GroupResponse | `apps/web/src/app/admin-console/organizations/core/services/group/group-api.service.ts:113` |
| có route | PUT | `/organizations/{organizationId}/groups/{id}` | GroupRequest | GroupResponse | `apps/web/src/app/admin-console/organizations/core/services/group/group-api.service.ts:128` |
| có route | GET | `/organizations/{organizationId}/policies` | — | ListResponse | `libs/common/src/admin-console/services/policy/policy-api.service.ts:39` |
| có route | GET | `/organizations/{organizationId}/users` | — | ListResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:71` |
| có route | DELETE | `/organizations/{organizationId}/users/{id}` | — | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:286` |
| có route | PUT | `/organizations/{organizationId}/users/{id}` | OrganizationUserUpdateRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:248` |
| có route | POST | `/organizations/{organizationId}/users/{id}/confirm` | OrganizationUserConfirmRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:168` |
| có route | POST | `/organizations/{organizationId}/users/account-recovery-details` | OrganizationUserBulkRequest | ListResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:112` |
| có route | POST | `/organizations/{organizationId}/users/bulk-auto-confirm` | ? | ? | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts` |
| có route | POST | `/organizations/{organizationId}/users/confirm` | OrganizationUserBulkConfirmRequest | ListResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:210` |
| có route | DELETE | `/organizations/{organizationId}/users/delete-account` | OrganizationUserBulkRequest | ListResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:385` |
| có route | PUT | `/organizations/{organizationId}/users/enable-pam` | OrganizationUserBulkRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:234` |
| có route | PUT | `/organizations/{organizationId}/users/enable-secrets-manager` | OrganizationUserBulkRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:224` |
| có route | POST | `/organizations/{organizationId}/users/invite` | OrganizationUserInviteRequest | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:126` |
| có route | POST | `/organizations/{organizationId}/users/public-keys` | ? | ? | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts` |
| có route | PUT | `/organizations/{organizationId}/users/restore` | OrganizationUserBulkRestoreRequest | ListResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:361` |
| có route | PUT | `/organizations/{organizationId}/users/revoke` | OrganizationUserBulkRequest | ListResponse | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:323` |
| có route | PUT | `/organizations/{organizationId}/users/revoke-self` | — | — | `libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts:334` |
| có route | GET | `/organizations/{orgId}/groups` | — | ListResponse | `apps/web/src/app/admin-console/organizations/core/services/group/group-api.service.ts:39` |
| có route | DELETE | `/organizations/{orgId}/groups/{groupId}` | — | — | `apps/web/src/app/admin-console/organizations/core/services/group/group-api.service.ts:77` |

## 2. Tài khoản

| Trạng thái | Method | Đường dẫn | Request | Response | Nguồn trong clients |
|---|---|---|---|---|---|
| 501 | POST | `/accounts/email-token` | ? | ? | `libs/common/src/auth/services/change-email/default-change-email.service.ts` |
| 501 | POST | `/accounts/register/finish` | RegisterFinishRequest | (có body) | `libs/common/src/auth/services/account-api.service.ts:91` |
| 501 | POST | `/accounts/register/send-verification-email` | RegisterSendVerificationEmailRequest | (có body) | `libs/common/src/auth/services/account-api.service.ts:42` |
| 501 | POST | `/accounts/register/verification-email-clicked` | RegisterVerificationEmailClickedRequest | — | `libs/common/src/auth/services/account-api.service.ts:71` |
| 501 | POST | `/accounts/request-otp` | — | — | `libs/common/src/auth/services/user-verification/user-verification-api.service.ts:14` |
| 501 | POST | `/accounts/resend-new-device-otp` | ? | ? | `libs/auth/src/angular/new-device-verification/new-device-verification.component.ts` |
| 501 | POST | `/accounts/set-password` | SetPasswordRequest | — | `libs/common/src/auth/services/master-password/master-password-api.service.implementation.ts:17` |
| 501 | POST | `/accounts/verify-email` | — | — | `libs/common/src/services/api.service.ts:307` |
| 501 | POST | `/accounts/verify-email-token` | VerifyEmailRequest | — | `libs/common/src/services/api.service.ts:311` |
| 501 | POST | `/accounts/verify-otp` | VerifyOTPRequest | — | `libs/common/src/auth/services/user-verification/user-verification-api.service.ts:11` |
| có route | POST | `/accounts/api-key` | SecretVerificationRequest | ApiKeyResponse | `libs/common/src/services/api.service.ts:331` |
| có route | POST | `/accounts/keys` | KeysRequest | — | `libs/common/src/services/api.service.ts:303` |
| có route | POST | `/accounts/password` | PasswordRequest | — | `libs/common/src/auth/services/master-password/master-password-api.service.implementation.ts:34` |
| có route | POST | `/accounts/prelogin/password` | PasswordPreloginRequest | PasswordPreloginResponse | `libs/common/src/auth/password-prelogin/password-prelogin-api.service.ts:17` |
| có route | GET | `/accounts/profile` | — | ProfileResponse | `libs/common/src/services/api.service.ts:257` |
| có route | PUT | `/accounts/profile` | UpdateProfileRequest | ProfileResponse | `libs/common/src/services/api.service.ts:267` |
| có route | GET | `/accounts/revision-date` | ? | ? | `libs/common/src/services/api.service.ts` |
| có route | POST | `/accounts/rotate-api-key` | SecretVerificationRequest | ApiKeyResponse | `libs/common/src/services/api.service.ts:339` |
| có route | POST | `/accounts/verify-devices` | SetVerifyDevicesRequest | (có body) | `libs/common/src/auth/services/account-api.service.ts:109` |
| có route | POST | `/accounts/verify-password` | SecretVerificationRequest | (có body) | `libs/common/src/auth/services/user-verification/user-verification-api.service.ts:19` |
| có route | GET | `/accounts/webauthn/assertion-options` | — | CredentialAssertionOptionsResponse | `libs/common/src/auth/services/webauthn-login/webauthn-login-api.service.ts:17` |
| không có route | DELETE | `/accounts` | verificationRequest | — | `libs/common/src/auth/services/account-api.service.ts:28` |
| không có route | PUT | `/accounts/avatar` | UpdateAvatarRequest | ProfileResponse | `libs/common/src/services/api.service.ts:272` |
| không có route | POST | `/accounts/delete-recover` | DeleteRecoverRequest | — | `libs/common/src/services/api.service.ts:315` |
| không có route | POST | `/accounts/delete-recover-token` | VerifyDeleteRecoverRequest | — | `libs/common/src/services/api.service.ts:319` |
| không có route | POST | `/accounts/email` | ? | ? | `libs/common/src/auth/services/change-email/default-change-email.service.ts` |
| không có route | GET | `/accounts/key-connector/confirmation-details/{encodeURIComponent(orgSsoIdentifier)}` | — | KeyConnectorConfirmationDetailsResponse | `libs/common/src/key-management/key-connector/services/default-key-connector-api.service.ts:11` |
| không có route | POST | `/accounts/key-management/rotate-user-account-keys` | RotateUserAccountKeysRequest | — | `apps/web/src/app/key-management/key-rotation/user-key-rotation-api.service.ts:12` |
| không có route | POST | `/accounts/password-hint` | PasswordHintRequest | — | `libs/common/src/services/api.service.ts:290` |
| không có route | POST | `/accounts/security-stamp` | SecretVerificationRequest | — | `libs/common/src/services/api.service.ts:281` |
| không có route | POST | `/accounts/set-key-connector-key` | SetKeyConnectorKeyRequest | — | `libs/common/src/services/api.service.ts:277` |
| không có route | DELETE | `/accounts/sso/{organizationId}` | — | — | `libs/common/src/services/api.service.ts:323` |
| không có route | GET | `/accounts/sso/user-identifier` | — | ApiKeyResponse | `libs/common/src/services/api.service.ts:327` |
| không có route | PUT | `/accounts/update-tde-offboarding-password` | UpdateTdeOffboardingPasswordRequest | — | `libs/common/src/auth/services/master-password/master-password-api.service.implementation.ts:70` |
| không có route | PUT | `/accounts/update-temp-password` | UpdateTempPasswordRequest | — | `libs/common/src/auth/services/master-password/master-password-api.service.implementation.ts:51` |
| không có route | DELETE | `/emergency-access/{id}` | — | — | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:53` |
| không có route | GET | `/emergency-access/{id}` | — | EmergencyAccessGranteeDetailsResponse | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:33` |
| không có route | PUT | `/emergency-access/{id}` | EmergencyAccessUpdateRequest | — | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:49` |
| không có route | POST | `/emergency-access/{id}/accept` | EmergencyAccessAcceptRequest | — | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:65` |
| không có route | POST | `/emergency-access/{id}/approve` | — | — | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:89` |
| không có route | POST | `/emergency-access/{id}/confirm` | EmergencyAccessConfirmRequest | — | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:75` |
| không có route | POST | `/emergency-access/{id}/initiate` | — | — | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:85` |
| không có route | POST | `/emergency-access/{id}/password` | EmergencyAccessPasswordRequest | (có body) | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:111` |
| không có route | GET | `/emergency-access/{id}/policies` | — | ListResponse | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:38` |
| không có route | POST | `/emergency-access/{id}/reinvite` | — | — | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:61` |
| không có route | POST | `/emergency-access/{id}/reject` | — | — | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:93` |
| không có route | POST | `/emergency-access/{id}/takeover` | — | EmergencyAccessTakeoverResponse | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:97` |
| không có route | GET | `/emergency-access/granted` | — | ListResponse | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:28` |
| không có route | POST | `/emergency-access/invite` | EmergencyAccessInviteRequest | — | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:57` |
| không có route | GET | `/emergency-access/trusted` | — | ListResponse | `apps/web/src/app/auth/emergency-access/services/emergency-access-api.service.ts:23` |
| không có route | GET | `/users/{id}/public-key` | — | UserKeyResponse | `libs/common/src/services/api.service.ts:1049` |

## 3. Tính năng client mới

| Trạng thái | Method | Đường dẫn | Request | Response | Nguồn trong clients |
|---|---|---|---|---|---|
| có route | POST | `/notifications/hub/negotiate` | ? | ? | `NOTIF` |
| không có route | POST | `/events/collect` | ? | ? | `EVENTS` |
| không có route | GET | `/notifications` | — | ListResponse | `libs/common/src/vault/notifications/services/default-end-user-notification.service.ts:143` |
| không có route | DELETE | `/notifications/{notificationId}/delete` | — | — | `libs/common/src/vault/notifications/services/default-end-user-notification.service.ts:74` |
| không có route | PATCH | `/notifications/{notificationId}/read` | — | — | `libs/common/src/vault/notifications/services/default-end-user-notification.service.ts:63` |

## 4. Vault, 2FA và phần còn lại

| Trạng thái | Method | Đường dẫn | Request | Response | Nguồn trong clients |
|---|---|---|---|---|---|
| 501 | DELETE | `/two-factor/email` | TwoFactorEmailDeleteRequest | — | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:122` |
| 501 | PUT | `/two-factor/email` | TwoFactorEmailUpdateRequest | TwoFactorEmailUpdateResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:117` |
| 501 | POST | `/two-factor/get-email` | SecretVerificationRequest | TwoFactorEmailResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:96` |
| 501 | POST | `/two-factor/send-email` | TwoFactorEmailSetupRequest | — | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:107` |
| 501 | POST | `/two-factor/send-email-login` | TwoFactorEmailLoginRequest | — | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:111` |
| có route | POST | `/auth-requests/` | AuthRequest | AuthRequestResponse | `libs/auth/src/common/services/auth-request/auth-request-api.service.ts:67` |
| có route | GET | `/auth-requests/{id}` | ? | ? | `api.service` |
| có route | PUT | `/auth-requests/{id}` | ? | ? | `api.service` |
| có route | GET | `/auth-requests/{id}/response` | ? | ? | `auth-request-api` |
| có route | POST | `/auth-requests/admin-request` | AuthRequest | AuthRequestResponse | `libs/auth/src/common/services/auth-request/auth-request-api.service.ts:47` |
| có route | GET | `/auth-requests/pending` | ? | ? | `auth-request-api` |
| có route | DELETE | `/ciphers/{id}` | — | — | `libs/common/src/services/api.service.ts:368` |
| có route | GET | `/ciphers/{id}` | — | CipherResponse | `libs/common/src/services/api.service.ts:353` |
| có route | POST | `/ciphers/{id}/attachment/{attachmentId}` | data | — | `libs/common/src/services/api.service.ts:439` |
| có route | GET | `/ciphers/{id}/details` | — | CipherResponse | `libs/common/src/services/api.service.ts:358` |
| có route | PUT | `/ciphers/archive` | request | ListResponse | `libs/common/src/vault/services/default-cipher-archive.service.ts:66` |
| có route | POST | `/ciphers/import` | ImportCiphersRequest | — | `libs/importer/src/services/import-api.service.ts:11` |
| có route | PUT | `/ciphers/unarchive` | request | ListResponse | `libs/common/src/vault/services/default-cipher-archive.service.ts:80` |
| có route | GET | `/collections` | — | ListResponse | `libs/common/src/services/api.service.ts:459` |
| có route | GET | `/config` | — | ServerConfigResponse | `libs/common/src/platform/services/config/config-api.service.ts:14` |
| có route | POST | `/connect/token` | ? | ? | `IDENTITY` |
| có route | GET | `/devices` | — | ListResponse | `libs/common/src/auth/services/devices-api.service.implementation.ts:49` |
| có route | POST | `/devices/{deviceId}/deactivate` | — | — | `libs/common/src/auth/services/devices-api.service.implementation.ts:119` |
| có route | PUT | `/devices/{deviceIdentifier}/keys` | request | DeviceResponse | `libs/common/src/auth/services/devices-api.service.implementation.ts:65` |
| có route | POST | `/devices/{deviceIdentifier}/retrieve-keys` | — | ProtectedDeviceResponse | `libs/common/src/auth/services/devices-api.service.implementation.ts:94` |
| có route | POST | `/devices/identifier/{await this.appIdService.getAppId()}/web-push-auth` | ? | ? | `libs/common/src/platform/server-notifications/internal/web-push-notifications-api.service.ts` |
| có route | GET | `/devices/identifier/{deviceIdentifier}` | — | DeviceResponse | `libs/common/src/auth/services/devices-api.service.implementation.ts:38` |
| có route | GET | `/devices/knowndevice` | — | (có body) | `libs/common/src/auth/services/devices-api.service.implementation.ts:18` |
| có route | POST | `/devices/lost-trust` | — | — | `libs/common/src/auth/services/devices-api.service.implementation.ts:105` |
| có route | POST | `/devices/untrust` | UntrustDevicesRequestModel | — | `libs/common/src/auth/services/devices-api.service.implementation.ts:123` |
| có route | POST | `/devices/update-trust` | UpdateDevicesTrustRequest | — | `libs/common/src/auth/services/devices-api.service.implementation.ts:80` |
| có route | POST | `/folders` | FolderRequest | FolderResponse | `libs/common/src/vault/services/folder/folder-api.service.ts:54` |
| có route | DELETE | `/folders/{id}` | — | — | `libs/common/src/vault/services/folder/folder-api.service.ts:64` |
| có route | GET | `/folders/{id}` | — | FolderResponse | `libs/common/src/vault/services/folder/folder-api.service.ts:49` |
| có route | PUT | `/folders/{id}` | FolderRequest | FolderResponse | `libs/common/src/vault/services/folder/folder-api.service.ts:59` |
| có route | GET | `/sends` | — | ListResponse | `libs/common/src/tools/send/services/send-api.service.ts:77` |
| có route | POST | `/sends` | SendRequest | SendResponse | `libs/common/src/tools/send/services/send-api.service.ts:139` |
| có route | DELETE | `/sends/{id}` | — | — | `libs/common/src/tools/send/services/send-api.service.ts:93` |
| có route | GET | `/sends/{id}` | — | SendResponse | `libs/common/src/tools/send/services/send-api.service.ts:36` |
| có route | PUT | `/sends/{id}` | SendRequest | SendResponse | `libs/common/src/tools/send/services/send-api.service.ts:167` |
| có route | PUT | `/sends/{id}/remove-password` | — | SendResponse | `libs/common/src/tools/send/services/send-api.service.ts:82` |
| có route | GET | `/sends/{sendId}/file/{fileId}` | — | SendFileUploadDataResponse | `libs/common/src/tools/send/services/send-api.service.ts:152` |
| có route | POST | `/sends/{sendId}/file/{fileId}` | FormData | — | `libs/common/src/tools/send/services/send-api.service.ts:163` |
| có route | POST | `/sends/access` | — | SendAccessResponse | `libs/common/src/tools/send/services/send-api.service.ts:44` |
| có route | POST | `/sends/access/file/{send.file.id}` | — | SendFileDownloadDataResponse | `libs/common/src/tools/send/services/send-api.service.ts:64` |
| có route | POST | `/sends/file/v2` | SendRequest | SendFileUploadDataResponse | `libs/common/src/tools/send/services/send-api.service.ts:144` |
| có route | GET | `/two-factor` | — | ListResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:44` |
| có route | DELETE | `/two-factor/authenticator` | TwoFactorAuthenticatorDeleteRequest | — | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:90` |
| có route | PUT | `/two-factor/authenticator` | TwoFactorAuthenticatorUpdateRequest | TwoFactorAuthenticatorUpdateResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:79` |
| có route | POST | `/two-factor/get-authenticator` | SecretVerificationRequest | TwoFactorAuthenticatorResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:66` |
| có route | POST | `/two-factor/get-recover` | SecretVerificationRequest | TwoFactorRecoverResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:282` |
| có route | POST | `/two-factor/get-webauthn` | SecretVerificationRequest | TwoFactorWebAuthnResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:211` |
| có route | POST | `/two-factor/get-webauthn-challenge` | TwoFactorWebAuthnChallengeRequest | TwoFactorWebAuthnChallengeResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:224` |
| có route | POST | `/two-factor/get-yubikey` | SecretVerificationRequest | TwoFactorYubiKeyResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:185` |
| có route | DELETE | `/two-factor/webauthn` | TwoFactorWebAuthnDeleteRequest | TwoFactorWebAuthnDeleteResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:265` |
| có route | PUT | `/two-factor/webauthn` | any | TwoFactorWebAuthnUpdateResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:258` |
| có route | DELETE | `/two-factor/yubikey` | TwoFactorYubiKeyDeleteRequest | — | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:203` |
| có route | PUT | `/two-factor/yubikey` | TwoFactorYubiKeyUpdateRequest | TwoFactorYubiKeyUpdateResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:198` |
| có route | GET | `/webauthn` | — | ListResponse | `apps/web/src/app/auth/core/services/webauthn-login/webauthn-login-admin-api.service.ts:49` |
| có route | POST | `/webauthn` | SaveCredentialRequest | ListResponse | `apps/web/src/app/auth/core/services/webauthn-login/webauthn-login-admin-api.service.ts:44` |
| có route | PUT | `/webauthn` | EnableCredentialEncryptionRequest | (có body) | `apps/web/src/app/auth/core/services/webauthn-login/webauthn-login-admin-api.service.ts:61` |
| có route | POST | `/webauthn/{credentialId}/delete` | SecretVerificationRequest | (có body) | `apps/web/src/app/auth/core/services/webauthn-login/webauthn-login-admin-api.service.ts:57` |
| có route | POST | `/webauthn/assertion-options` | SecretVerificationRequest | CredentialAssertionOptionsResponse | `apps/web/src/app/auth/core/services/webauthn-login/webauthn-login-admin-api.service.ts:33` |
| có route | POST | `/webauthn/attestation-options` | SecretVerificationRequest | WebauthnLoginCredentialCreateOptionsResponse | `apps/web/src/app/auth/core/services/webauthn-login/webauthn-login-admin-api.service.ts:20` |
| không có route | GET | `/ciphers/{id}/admin` | — | CipherResponse | `libs/common/src/services/api.service.ts:363` |
| không có route | POST | `/ciphers/{id}/attachment/{attachmentId}/share` | FormData | — | `libs/common/src/services/api.service.ts:404` |
| không có route | POST | `/ciphers/import-organization` | ImportOrganizationCiphersRequest | — | `libs/importer/src/services/import-api.service.ts:18` |
| không có route | DELETE | `/folders` | FolderBulkDeleteRequest | — | `libs/common/src/vault/services/folder/folder-api.service.ts:39` |
| không có route | DELETE | `/folders/all` | — | — | `libs/common/src/vault/services/folder/folder-api.service.ts:44` |
| không có route | GET | `/hibp/breach` | — | BreachAccountResponse | `libs/common/src/dirt/services/hibp-api.service.ts:9` |
| không có route | DELETE | `/two-factor/duo` | TwoFactorDuoDeleteRequest | — | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:152` |
| không có route | PUT | `/two-factor/duo` | TwoFactorDuoUpdateRequest | TwoFactorDuoUpdateResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:147` |
| không có route | POST | `/two-factor/get-duo` | SecretVerificationRequest | TwoFactorDuoResponse | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:128` |
| không có route | DELETE | `/two-factor/webauthn/all` | TwoFactorWebAuthnDeleteAllRequest | — | `libs/common/src/auth/two-factor/services/default-two-factor-api.service.ts:276` |

## 5. Ngoài phạm vi (trả phí hoặc doanh nghiệp)

| Trạng thái | Method | Đường dẫn | Request | Response | Nguồn trong clients |
|---|---|---|---|---|---|
| 501 | GET | `/organizations/{id}/billing` | — | BillingResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:46` |
| 501 | GET | `/organizations/{id}/billing/history` | — | BillingHistoryResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:57` |
| 501 | GET | `/organizations/{id}/billing/invoices{queryString}` | — | BillingInvoiceResponse | `libs/common/src/billing/services/organization/organization-billing-api.service.ts:29` |
| 501 | POST | `/organizations/{id}/billing/setup-business-unit` | request | (có body) | `libs/common/src/billing/services/organization/organization-billing-api.service.ts:63` |
| 501 | GET | `/organizations/{id}/billing/transactions{queryParams}` | — | BillingTransactionResponse | `libs/common/src/billing/services/organization/organization-billing-api.service.ts:44` |
| 501 | GET | `/organizations/{id}/license` | — | OrganizationAutoEnrollStatusResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:79` |
| 501 | POST | `/organizations/{id}/sm-subscription` | OrganizationSmSubscriptionUpdateRequest | ProfileOrganizationResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:168` |
| 501 | GET | `/organizations/{id}/subscription` | — | OrganizationSubscriptionResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:68` |
| 501 | POST | `/organizations/{id}/subscription` | OrganizationSubscriptionUpdateRequest | ProfileOrganizationResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:154` |
| 501 | GET | `/organizations/{organizationId}/access-policies/people/potential-grantees` | — | ListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:245` |
| 501 | GET | `/organizations/{organizationId}/access-policies/projects/potential-grantees` | — | ListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:269` |
| 501 | GET | `/organizations/{organizationId}/access-policies/service-accounts/potential-grantees` | — | ListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:257` |
| 501 | POST | `/organizations/{organizationId}/billing/change-frequency` | ChangePlanFrequencyRequest | — | `libs/common/src/billing/services/organization/organization-billing-api.service.ts:78` |
| 501 | POST | `/organizations/{organizationId}/billing/restart-subscription` | OrganizationCreateRequest | — | `libs/common/src/billing/services/billing-api.service.ts:126` |
| 501 | POST | `/organizations/{organizationId}/billing/subscription/plan-change/preview` | OrganizationPlanChangePreviewRequest | InvoicePreviewResponse | `apps/web/src/app/billing/clients/invoice-preview.client.ts:112` |
| 501 | GET | `/organizations/{organizationId}/billing/subscription/preview` | — | SubscriptionPreviewResponse | `apps/web/src/app/billing/clients/subscription-preview.client.ts:31` |
| 501 | PUT | `/organizations/{organizationId}/billing/subscription/privileged-controls` | UpdatePrivilegedControlsSubscriptionRequest | — | `apps/web/src/app/billing/clients/organization-billing.client.ts:113` |
| 501 | POST | `/organizations/{organizationId}/billing/subscription/restart/preview` | OrganizationRestartPreviewRequest | InvoicePreviewResponse | `apps/web/src/app/billing/clients/invoice-preview.client.ts:133` |
| 501 | GET | `/organizations/{organizationId}/billing/vnext/annual-upgrade-offer` | — | (có body) | `apps/web/src/app/billing/clients/organization-billing.client.ts:89` |
| 501 | POST | `/organizations/{organizationId}/billing/vnext/annual-upgrade-offer/redeem` | — | — | `apps/web/src/app/billing/clients/organization-billing.client.ts:100` |
| 501 | GET | `/organizations/{organizationId}/billing/vnext/churn-mitigation-offer` | — | (có body) | `apps/web/src/app/billing/clients/organization-billing.client.ts:66` |
| 501 | POST | `/organizations/{organizationId}/billing/vnext/churn-mitigation-offer/redeem` | — | — | `apps/web/src/app/billing/clients/organization-billing.client.ts:77` |
| 501 | GET | `/organizations/{organizationId}/billing/vnext/metadata` | — | OrganizationBillingMetadataResponse | `libs/common/src/billing/services/billing-api.service.ts:54` |
| 501 | GET | `/organizations/{organizationId}/billing/vnext/self-host/metadata` | — | OrganizationBillingMetadataResponse | `libs/common/src/billing/services/billing-api.service.ts:68` |
| 501 | GET | `/organizations/{organizationId}/billing/vnext/warnings` | — | OrganizationWarningsResponse | `apps/web/src/app/billing/clients/organization-billing.client.ts:52` |
| 501 | GET | `/organizations/{organizationId}/projects` | — | ListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/projects/project.service.ts:77` |
| 501 | POST | `/organizations/{organizationId}/projects` | request | ProjectResponse | `bitwarden_license/bit-web/src/app/secrets-manager/projects/project.service.ts:90` |
| 501 | GET | `/organizations/{organizationId}/secrets` | — | SecretWithProjectsListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:68` |
| 501 | POST | `/organizations/{organizationId}/secrets` | request | SecretResponse | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:103` |
| 501 | GET | `/organizations/{organizationId}/service-accounts` | — | ListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/service-accounts/service-account.service.ts:71` |
| 501 | POST | `/organizations/{organizationId}/service-accounts` | request | ServiceAccountResponse | `bitwarden_license/bit-web/src/app/secrets-manager/service-accounts/service-account.service.ts:123` |
| 501 | GET | `/organizations/{organizationId}/sm-counts` | — | OrganizationCountsResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/counts/count.service.ts:16` |
| 501 | GET | `/organizations/{orgId}/domain` | — | OrganizationDomainResponse | `libs/common/src/admin-console/services/organization-domain/org-domain-api.service.ts:18` |
| 501 | POST | `/organizations/{orgId}/domain` | OrganizationDomainRequest | OrganizationDomainResponse | `libs/common/src/admin-console/services/organization-domain/org-domain-api.service.ts:58` |
| 501 | DELETE | `/organizations/{orgId}/domain/{orgDomainId}` | — | — | `libs/common/src/admin-console/services/organization-domain/org-domain-api.service.ts:90` |
| 501 | GET | `/organizations/{orgId}/domain/{orgDomainId}` | — | OrganizationDomainResponse | `libs/common/src/admin-console/services/organization-domain/org-domain-api.service.ts:39` |
| 501 | POST | `/organizations/{orgId}/domain/{orgDomainId}/verify` | — | OrganizationDomainResponse | `libs/common/src/admin-console/services/organization-domain/org-domain-api.service.ts:74` |
| 501 | GET | `/organizations/{orgId}/integrations` | — | (có body) | `bitwarden_license/bit-common/src/dirt/organization-integrations/services/organization-integration-api.service.ts:14` |
| 501 | POST | `/organizations/{orgId}/integrations` | OrganizationIntegrationRequest | (có body) | `bitwarden_license/bit-common/src/dirt/organization-integrations/services/organization-integration-api.service.ts:31` |
| 501 | DELETE | `/organizations/{orgId}/integrations/{integrationId}` | — | — | `bitwarden_license/bit-common/src/dirt/organization-integrations/services/organization-integration-api.service.ts:60` |
| 501 | PUT | `/organizations/{orgId}/integrations/{integrationId}` | OrganizationIntegrationRequest | (có body) | `bitwarden_license/bit-common/src/dirt/organization-integrations/services/organization-integration-api.service.ts:46` |
| 501 | GET | `/organizations/{orgId}/integrations/{integrationId}/configurations` | — | (có body) | `bitwarden_license/bit-common/src/dirt/organization-integrations/services/organization-integration-configuration-api.service.ts:18` |
| 501 | POST | `/organizations/{orgId}/integrations/{integrationId}/configurations` | OrganizationIntegrationConfigurationRequest | (có body) | `bitwarden_license/bit-common/src/dirt/organization-integrations/services/organization-integration-configuration-api.service.ts:33` |
| 501 | DELETE | `/organizations/{orgId}/integrations/{integrationId}/configurations/{configurationId}` | — | — | `bitwarden_license/bit-common/src/dirt/organization-integrations/services/organization-integration-configuration-api.service.ts:64` |
| 501 | PUT | `/organizations/{orgId}/integrations/{integrationId}/configurations/{configurationId}` | OrganizationIntegrationConfigurationRequest | (có body) | `bitwarden_license/bit-common/src/dirt/organization-integrations/services/organization-integration-configuration-api.service.ts:49` |
| 501 | POST | `/organizations/billing/subscription/purchase/preview` | OrganizationPurchasePreviewRequest | InvoicePreviewResponse | `apps/web/src/app/billing/clients/invoice-preview.client.ts:91` |
| 501 | POST | `/organizations/connections/` | OrganizationConnectionRequest | OrganizationConnectionResponse | `libs/common/src/services/api.service.ts:635` |
| 501 | DELETE | `/organizations/connections/{id}` | — | — | `libs/common/src/services/api.service.ts:655` |
| 501 | GET | `/organizations/connections/{id}/{type}` | — | OrganizationConnectionResponse | `libs/common/src/services/api.service.ts:627` |
| 501 | PUT | `/organizations/connections/{organizationConnectionId}` | OrganizationConnectionRequest | OrganizationConnectionResponse | `libs/common/src/services/api.service.ts:644` |
| 501 | GET | `/organizations/connections/enabled` | — | OrganizationConnectionResponse | `libs/common/src/services/api.service.ts:618` |
| 501 | POST | `/organizations/domain/sso/verified` | ? | ? | `libs/common/src/admin-console/services/organization-domain/org-domain-api.service.ts` |
| 501 | POST | `/organizations/licenses/self-hosted` | FormData | OrganizationResponse | `libs/common/src/admin-console/services/organization/organization-api.service.ts:122` |
| 501 | POST | `/organizations/licenses/self-hosted/{id}` | FormData | — | `libs/common/src/admin-console/services/organization/organization-api.service.ts:228` |
| 501 | POST | `/organizations/licenses/self-hosted/{id}/sync/` | — | — | `libs/common/src/admin-console/services/organization/organization-api.service.ts:319` |
| có route | GET | `/settings/domains` | — | DomainsResponse | `libs/common/src/services/api.service.ts:596` |
| có route | PUT | `/settings/domains` | UpdateDomainsRequest | DomainsResponse | `libs/common/src/services/api.service.ts:601` |
| không có route | GET | `/account/billing/subscription/preview` | — | SubscriptionPreviewResponse | `apps/web/src/app/billing/clients/subscription-preview.client.ts:16` |
| không có route | GET | `/account/billing/subscription/purchase/preview` | — | InvoicePreviewResponse | `apps/web/src/app/billing/clients/invoice-preview.client.ts:55` |
| không có route | GET | `/account/billing/subscription/upgrade/preview` | — | InvoicePreviewResponse | `apps/web/src/app/billing/clients/invoice-preview.client.ts:76` |
| không có route | POST | `/account/billing/vnext/premium/checkout` | PremiumCheckoutSessionRequest | PremiumCheckoutSessionResponse | `libs/common/src/billing/services/billing-api.service.ts:41` |
| không có route | GET | `/accounts/billing/history` | — | BillingHistoryResponse | `libs/common/src/services/api.service.ts:346` |
| không có route | GET | `/accounts/billing/invoices{queryString}` | — | BillingInvoiceResponse | `libs/common/src/billing/services/account/account-billing-api.service.ts:27` |
| không có route | GET | `/accounts/billing/transactions{queryParams}` | — | BillingTransactionResponse | `libs/common/src/billing/services/account/account-billing-api.service.ts:39` |
| không có route | POST | `/accounts/cancel` | SubscriptionCancellationRequest | — | `libs/common/src/billing/services/billing-api.service.ts:35` |
| không có route | POST | `/accounts/license` | FormData | — | `libs/common/src/services/api.service.ts:299` |
| không có route | POST | `/accounts/premium` | FormData | PaymentResponse | `libs/common/src/services/api.service.ts:294` |
| không có route | GET | `/accounts/subscription` | — | SubscriptionResponse | `libs/common/src/services/api.service.ts:262` |
| không có route | POST | `/bitpay-invoice` | BitPayInvoiceRequest | (có body) | `libs/common/src/services/api.service.ts:1056` |
| không có route | GET | `/organization/sponsorship/{sponsoredOrgId}/sync-status` | — | OrganizationSponsorshipSyncStatusResponse | `libs/common/src/services/api.service.ts:1262` |
| không có route | POST | `/organization/sponsorship/{sponsoringOrgId}/families-for-enterprise/resend-self` | — | — | `libs/common/src/billing/services/organization/organization-sponsorship-api.service.ts:43` |
| không có route | POST | `/organization/sponsorship/redeem` | OrganizationSponsorshipRedeemRequest | — | `libs/common/src/services/api.service.ts:1301` |
| không có route | DELETE | `/organization/sponsorship/sponsored/{sponsoringOrgId}` | — | — | `libs/common/src/services/api.service.ts:1273` |
| không có route | POST | `/organization/sponsorship/validate-token` | — | PreValidateSponsorshipResponse | `libs/common/src/services/api.service.ts:1285` |
| không có route | GET | `/plans` | — | ListResponse | `libs/common/src/billing/services/billing-api.service.ts:80` |
| không có route | GET | `/plans/premium` | — | PremiumPlanResponse | `libs/common/src/billing/services/billing-api.service.ts:85` |
| không có route | GET | `/projects/{projectId}` | — | ProjectResponse | `bitwarden_license/bit-web/src/app/secrets-manager/projects/project.service.ts:59` |
| không có route | GET | `/projects/{projectId}/access-policies/people` | — | ProjectPeopleAccessPoliciesResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:93` |
| không có route | PUT | `/projects/{projectId}/access-policies/people` | request | ProjectPeopleAccessPoliciesResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:110` |
| không có route | GET | `/projects/{projectId}/access-policies/service-accounts` | — | ProjectServiceAccountsAccessPoliciesResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:196` |
| không có route | PUT | `/projects/{projectId}/access-policies/service-accounts` | request | ProjectServiceAccountsAccessPoliciesResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:214` |
| không có route | GET | `/projects/{projectId}/secrets` | — | SecretWithProjectsListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:81` |
| không có route | GET | `/projects/{projectId}/sm-counts` | — | ProjectCountsResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/counts/count.service.ts:27` |
| không có route | PUT | `/projects/{projectView.id}` | request | ProjectResponse | `bitwarden_license/bit-web/src/app/secrets-manager/projects/project.service.ts:105` |
| không có route | POST | `/projects/delete` | projectIds | (có body) | `bitwarden_license/bit-web/src/app/secrets-manager/projects/project.service.ts:111` |
| không có route | DELETE | `/providers/{id}` | — | — | `libs/common/src/provider/services/provider-api.service.ts:50` |
| không có route | GET | `/providers/{id}` | — | ProviderResponse | `libs/common/src/provider/services/provider-api.service.ts:27` |
| không có route | PUT | `/providers/{id}` | ProviderUpdateRequest | ProviderResponse | `libs/common/src/provider/services/provider-api.service.ts:32` |
| không có route | POST | `/providers/{id}/setup` | ProviderSetupRequest | ProviderResponse | `libs/common/src/provider/services/provider-api.service.ts:16` |
| không có route | GET | `/providers/{providerId}/billing/invoices` | — | InvoicesResponse | `libs/common/src/billing/services/billing-api.service.ts:101` |
| không có route | GET | `/providers/{providerId}/billing/invoices/{invoiceId}` | — | InvoicesResponse | `libs/common/src/billing/services/billing-api.service.ts:90` |
| không có route | GET | `/providers/{providerId}/billing/subscription` | — | ProviderSubscriptionResponse | `libs/common/src/billing/services/billing-api.service.ts:112` |
| không có route | GET | `/providers/{providerId}/billing/vnext/warnings` | — | ProviderWarningsResponse | `bitwarden_license/bit-web/src/app/billing/providers/warnings/services/provider-warnings.service.ts:131` |
| không có route | POST | `/providers/{providerId}/clients` | CreateProviderOrganizationRequest | — | `libs/common/src/provider/services/provider-api.service.ts:114` |
| không có route | PUT | `/providers/{providerId}/clients/{organizationId}` | UpdateProviderOrganizationRequest | — | `libs/common/src/provider/services/provider-api.service.ts:101` |
| không có route | GET | `/providers/{providerId}/clients/addable` | — | AddableOrganizationResponse | `libs/common/src/provider/services/provider-api.service.ts:69` |
| không có route | POST | `/providers/{providerId}/clients/existing` | request | — | `libs/common/src/provider/services/provider-api.service.ts:87` |
| không có route | POST | `/providers/{providerId}/delete-recover-token` | ProviderVerifyRecoverDeleteRequest | — | `libs/common/src/provider/services/provider-api.service.ts:40` |
| không có route | GET | `/providers/{providerId}/organizations` | — | ListResponse | `libs/common/src/provider/services/provider-api.service.ts:56` |
| không có route | POST | `/providers/{providerId}/organizations` | ProviderOrganizationCreateRequest | ProviderOrganizationResponse | `libs/common/src/services/api.service.ts:808` |
| không có route | DELETE | `/providers/{providerId}/organizations/{id}` | — | — | `libs/common/src/services/api.service.ts:819` |
| không có route | POST | `/providers/{providerId}/organizations/add` | ProviderAddOrganizationRequest | — | `libs/common/src/services/api.service.ts:795` |
| không có route | DELETE | `/providers/{providerId}/users` | ProviderUserBulkRequest | ListResponse | `libs/common/src/services/api.service.ts:718` |
| không có route | GET | `/providers/{providerId}/users` | — | ListResponse | `libs/common/src/services/api.service.ts:663` |
| không có route | DELETE | `/providers/{providerId}/users/{id}` | — | — | `libs/common/src/services/api.service.ts:773` |
| không có route | GET | `/providers/{providerId}/users/{id}` | — | ProviderUserResponse | `libs/common/src/services/api.service.ts:668` |
| không có route | PUT | `/providers/{providerId}/users/{id}` | ProviderUserUpdateRequest | — | `libs/common/src/services/api.service.ts:769` |
| không có route | POST | `/providers/{providerId}/users/{id}/accept` | ProviderUserAcceptRequest | — | `libs/common/src/services/api.service.ts:727` |
| không có route | POST | `/providers/{providerId}/users/{id}/confirm` | ProviderUserConfirmRequest | — | `libs/common/src/services/api.service.ts:741` |
| không có route | POST | `/providers/{providerId}/users/{id}/reinvite` | — | — | `libs/common/src/services/api.service.ts:677` |
| không có route | POST | `/providers/{providerId}/users/confirm` | ProviderUserBulkConfirmRequest | ListResponse | `libs/common/src/services/api.service.ts:704` |
| không có route | POST | `/providers/{providerId}/users/invite` | ProviderUserInviteRequest | — | `libs/common/src/services/api.service.ts:673` |
| không có route | POST | `/providers/{providerId}/users/public-keys` | ProviderUserBulkRequest | ListResponse | `libs/common/src/services/api.service.ts:754` |
| không có route | POST | `/providers/{providerId}/users/reinvite` | ProviderUserBulkRequest | ListResponse | `libs/common/src/services/api.service.ts:690` |
| không có route | GET | `/reports/member-access/{orgId}` | — | MemberAccessResponse | `bitwarden_license/bit-web/src/app/dirt/reports/member-access-report/services/member-access-report-api.service.ts:11` |
| không có route | GET | `/reports/member-cipher-details/{orgId}` | — | (có body) | `bitwarden_license/bit-common/src/dirt/reports/risk-insights/services/api/member-cipher-details-api.service.ts:18` |
| không có route | POST | `/reports/organizations/{organizationId.toString()}` | request.data | SaveRiskInsightsReportResponse | `bitwarden_license/bit-common/src/dirt/reports/risk-insights/services/api/risk-insights-api.service.ts:49` |
| không có route | PATCH | `/reports/organizations/{organizationId.toString()}/data/summary/{reportId.toString()}` | ? | ? | `bitwarden_license/bit-common/src/dirt/reports/risk-insights/services/api/risk-insights-api.service.ts` |
| không có route | POST | `/reports/organizations/{orgId.toString()}` | AccessReportCreateRequest | (có body) | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts:40` |
| không có route | GET | `/reports/organizations/{orgId.toString()}/data/application/{reportId.toString()}` | — | GetRiskInsightsApplicationDataResponse | `bitwarden_license/bit-common/src/dirt/reports/risk-insights/services/api/risk-insights-api.service.ts:98` |
| không có route | PATCH | `/reports/organizations/{orgId.toString()}/data/application/{reportId.toString()}` | ? | ? | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts` |
| không có route | GET | `/reports/organizations/{orgId.toString()}/data/summary` | — | (có body) | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts:104` |
| không có route | PATCH | `/reports/organizations/{orgId.toString()}/data/summary/{reportId.toString()}` | ? | ? | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts` |
| không có route | GET | `/reports/organizations/{orgId.toString()}/latest` | — | (có body) | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts:26` |
| không có route | DELETE | `/reports/organizations/{orgId}/{reportId}` | — | — | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts:140` |
| không có route | PATCH | `/reports/organizations/{orgId}/{reportId}` | AccessReportSettingsUpdateRequest | (có body) | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts:187` |
| không có route | POST | `/reports/organizations/{orgId}/{reportId}/file` | FormData | — | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts:156` |
| không có route | GET | `/reports/organizations/{orgId}/{reportId}/file/download` | — | (có body) | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts:171` |
| không có route | GET | `/reports/organizations/{orgId}/{reportId}/file/renew` | — | (có body) | `bitwarden_license/bit-common/src/dirt/access-intelligence/services/implementations/api/default-access-intelligence-api.service.ts:129` |
| không có route | GET | `/reports/passkey-directory` | ? | ? | `libs/common/src/dirt/services/default-passkey-directory-api.service.ts` |
| không có route | DELETE | `/reports/password-health-report-application/` | PasswordHealthReportApplicationDropRequest | (có body) | `bitwarden_license/bit-common/src/dirt/reports/risk-insights/services/api/critical-apps-api.service.ts:42` |
| không có route | POST | `/reports/password-health-report-applications/` | PasswordHealthReportApplicationsRequest[] | (có body) | `bitwarden_license/bit-common/src/dirt/reports/risk-insights/services/api/critical-apps-api.service.ts:18` |
| không có route | GET | `/reports/password-health-report-applications/{orgId.toString()}` | — | (có body) | `bitwarden_license/bit-common/src/dirt/reports/risk-insights/services/api/critical-apps-api.service.ts:30` |
| không có route | POST | `/request-access/request-sm-access` | RequestSMAccessRequest | — | `apps/web/src/app/secrets-manager/secrets-manager-landing/sm-landing-api.service.ts:14` |
| không có route | GET | `/secrets/{organizationId}/trash` | — | SecretWithProjectsListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:155` |
| không có route | POST | `/secrets/{organizationId}/trash/empty` | string[] | (có body) | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:167` |
| không có route | POST | `/secrets/{organizationId}/trash/restore` | string[] | (có body) | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:179` |
| không có route | GET | `/secrets/{secretId}` | — | SecretResponse | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:61` |
| không có route | GET | `/secrets/{secretId}/access-policies` | — | SecretAccessPoliciesResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:232` |
| không có route | GET | `/secrets/{secretId}/versions` | — | SecretVersionListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret-version.service.ts:54` |
| không có route | PUT | `/secrets/{secretId}/versions/restore` | { versionId } | SecretResponse | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:130` |
| không có route | PUT | `/secrets/{secretView.id}` | request | SecretResponse | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:125` |
| không có route | POST | `/secrets/delete` | secretIds | (có body) | `bitwarden_license/bit-web/src/app/secrets-manager/secrets/secret.service.ts:142` |
| không có route | GET | `/service-accounts/{serviceAccountId}` | — | ServiceAccountResponse | `bitwarden_license/bit-web/src/app/secrets-manager/service-accounts/service-account.service.ts:87` |
| không có route | PUT | `/service-accounts/{serviceAccountId}` | request | ServiceAccountResponse | `bitwarden_license/bit-web/src/app/secrets-manager/service-accounts/service-account.service.ts:105` |
| không có route | GET | `/service-accounts/{serviceAccountId}/access-policies/people` | — | ServiceAccountPeopleAccessPoliciesResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:126` |
| không có route | PUT | `/service-accounts/{serviceAccountId}/access-policies/people` | request | ServiceAccountPeopleAccessPoliciesResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:143` |
| không có route | GET | `/service-accounts/{serviceAccountId}/access-tokens` | — | ListResponse | `bitwarden_license/bit-web/src/app/secrets-manager/service-accounts/access/access.service.ts:51` |
| không có route | POST | `/service-accounts/{serviceAccountId}/access-tokens` | request | AccessTokenCreationResponse | `bitwarden_license/bit-web/src/app/secrets-manager/service-accounts/access/access.service.ts:92` |
| không có route | POST | `/service-accounts/{serviceAccountId}/access-tokens/revoke` | request | — | `bitwarden_license/bit-web/src/app/secrets-manager/service-accounts/access/access.service.ts:109` |
| không có route | GET | `/service-accounts/{serviceAccountId}/granted-policies` | — | ServiceAccountGrantedPoliciesPermissionDetailsResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:160` |
| không có route | PUT | `/service-accounts/{serviceAccountId}/granted-policies` | request | ServiceAccountGrantedPoliciesPermissionDetailsResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/access-policies/access-policy.service.ts:178` |
| không có route | GET | `/service-accounts/{serviceAccountId}/sm-counts` | — | ServiceAccountCountsResponse | `bitwarden_license/bit-web/src/app/secrets-manager/shared/counts/count.service.ts:38` |
| không có route | POST | `/service-accounts/delete` | ids | (có body) | `bitwarden_license/bit-web/src/app/secrets-manager/service-accounts/service-account.service.ts:142` |
| không có route | POST | `/setup-payment` | — | (có body) | `libs/common/src/services/api.service.ts:1061` |
| không có route | GET | `/sm/{organizationId}/export` | — | SecretsManagerExportResponse | `bitwarden_license/bit-web/src/app/secrets-manager/settings/services/sm-porting-api.service.ts:59` |
| không có route | POST | `/sm/{organizationId}/import` | requestBody | ErrorResponse | `bitwarden_license/bit-web/src/app/secrets-manager/settings/services/sm-porting-api.service.ts:81` |
| không có route | GET | `/tasks` | — | ListResponse | `libs/common/src/vault/tasks/services/default-task.service.ts:104` |
| không có route | POST | `/tasks/{organizationId}/bulk-create` | { tasks } | (có body) | `bitwarden_license/bit-web/src/app/vault/services/default-admin-task.service.ts:46` |
| không có route | GET | `/tasks/{orgId.toString()}/metrics` | — | (có body) | `bitwarden_license/bit-common/src/dirt/reports/risk-insights/services/api/security-tasks-api.service.ts:22` |
| không có route | PATCH | `/tasks/{taskId}/complete` | — | — | `libs/common/src/vault/tasks/services/default-task.service.ts:94` |
| không có route | GET | `/tasks/organization` | — | ListResponse | `bitwarden_license/bit-common/src/dirt/reports/risk-insights/services/api/security-tasks-api.service.ts:46` |
| không dò được | DELETE | `{basePath}{hostPath}{sponsoringOrganizationId}` | ? | ? | `libs/common/src/billing/services/organization/organization-sponsorship-api.service.ts` |
| không dò được | DELETE | `{basePath}{hostPath}{sponsoringOrganizationId}/{encodeURIComponent(sponsoredFriendlyName)}/revoke` | ? | ? | `libs/common/src/billing/services/organization/organization-sponsorship-api.service.ts` |
| không dò được | POST | `{getPath()}` | ? | ? | `apps/web/src/app/billing/services/stripe.service.ts` |
| không dò được | GET | `{path}` | ? | ? | `apps/web/src/app/billing/clients/account-billing.client.ts` |
| không dò được | POST | `{path}` | ? | ? | `apps/web/src/app/billing/clients/account-billing.client.ts` |
| không dò được | PUT | `{path}` | ? | ? | `apps/web/src/app/billing/clients/account-billing.client.ts` |
| không dò được | GET | `{uri}` | ? | ? | `libs/common/src/admin-console/services/organization/organization-api.service.ts` |
| không dò được | POST | `{url}` | ? | ? | `libs/common/src/billing/services/organization/organization-sponsorship-api.service.ts` |

## Câu hỏi còn mở

- Endpoint accept chính thức bắt buộc có invite token, vốn đến từ link email. NodeWarden không gửi email. Cách cấp token (link mời do admin tự gửi, hay một cơ chế khác) sẽ chốt ở phase cài đặt; Bruno collection chỉ ghi lại hợp đồng.
