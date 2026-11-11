# Vault, Send, two-step login and device endpoints: current state

Status: the routes recorded here answer since 2026-11-10; Duo is refused with 501 by decision.

## Outcome

Know how NodeWarden answers the personal vault, Send, two-step login, device
and auth request endpoints of the official clients. This covers group 4 of
`plans/reports/api-coverage-261109-2003-official-clients-endpoint-coverage.md`,
plus the vault calls that the Rust SDK makes and the report first missed (see
its section "Endpoint do Rust SDK gọi").

## How the state was recorded

Five Bruno folders, run with `npm run test:api -- <folder>` on 2026-11-09
against `origin/main` at `060500c`. The whole collection then ran in one pass:
171 requests, 116 passing, 53 failing, 2 skipped, the failures matching the
folders run one by one.

| Folder | Requests | Passing | Failing |
|---|---|---|---|
| `40-vault-ciphers` | 23 | 22 | 1 |
| `41-vault-folders-sync` | 13 | 11 | 2 |
| `42-vault-sends` | 12 | 12 | 0 |
| `43-two-factor` | 15 | 9 | 6 |
| `44-devices-auth-requests` | 16 | 15 | 1 |

Two rules from the client shape these tests:

- `apiService.send` treats 200, 201 and 204 as success when it reads no body, so deletes may answer 204.
- `BaseResponse.getResponseProperty` reads a property in either case (`data` or `Data`), so the tests read both.

## State per area

### Personal vault items (`40-vault-ciphers`)

The SDK reads an item with `type`, `creationDate` and `revisionDate` required.
Create, read, details, change, the stale-copy refusal (400 when
`lastKnownRevisionDate` is old), favorite and folder through `/partial`, bulk
move, archive and unarchive, trash and restore (one and bulk), attachment
upload v2, import, and delete (one and bulk) all work as the clients expect.

- [x] `PUT /ciphers/share` (2026-11-10): each item goes through the single share; a malformed request changes nothing; answers a list of the shared items.
- Not recorded here, for group 1b: the `admin` variants and `organization-details`.
- [x] `POST /ciphers/import-organization` (2026-11-11, Bruno `40/24`): as vaultwarden `post_org_import` (confirmed member, write rights on an existing collection, owner or admin for a new one), and an item left without a collection is refused, since a shared item always sits in one.
- Not recorded: `POST /ciphers/bulk-collections`, attachment `renew` and attachment `share`, all without a route.

### Folders, sync, config (`41-vault-folders-sync`)

Config, folder create, read, rename and delete, sync with and without
domains, equivalent domains and the collection list work as expected.

- [x] `DELETE /folders` (bulk, body `{ ids }`) and `DELETE /folders/all` (2026-11-10): the same delete as `POST /folders/delete`, tags removed from the items.

### Sends (`42-vault-sends`)

Everything recorded works: text and file Sends, list, read, change, remove
password, renew the file upload, the `send_access` token the SDK requests
(`client_id=send`, `scope=api.send.access`, `send_id`), public access with
that token, and delete. A deletion date 31 days or more ahead is refused, as
on the official server.

### Two-step login (`43-two-factor`)

Provider list, recovery code, and the refusal of a wrong authenticator code
work. Email two-step login answers 501 on purpose (no email delivery).

- [ ] `POST /two-factor/get-authenticator` answers flat (`{ Enabled, Key, UserVerificationToken }`). Current clients read `Authenticator` nested (`TwoFactorAuthenticatorResponse`), so the official web vault finds no key to show.
- [ ] `POST /two-factor/get-yubikey` and `/get-webauthn` answer flat and without `UserVerificationToken`; clients read `YubiKey` and `WebAuthn` nested and send the token back on every change.
- [ ] `POST /two-factor/get-webauthn-challenge` needs that token, so it fails after `get-webauthn`.
- [x] `DELETE /two-factor/webauthn/all` (2026-11-10): the same check and removal as turning WebAuthn off.
- [x] Duo (`get-duo`, `PUT`/`DELETE /two-factor/duo`): 501 (decided 2026-11-10); vaultwarden supports it.

No request turns a provider on: that needs a real code and belongs in a
browser test.

### Devices, auth requests, login passkeys (`44-devices-auth-requests`)

Known device (headers `X-Device-Identifier`, `X-Request-Email`), device list
and lookup, the whole login-with-device flow (request, pending list, read,
approve, the new device reading the approval and wrapped key, a wrong access
code refused), the admin approval request route, login passkey list,
creation options, unknown passkey delete, and device removal work.

- `POST /webauthn/assertion-options` answers 404 "No account passkeys registered" when the account has none; the web vault asks only for a passkey it lists, so this is recorded as expected.
- [x] `GET /hibp/breach` (2026-11-10): the same check and cache as `GET /api/security/email-breaches`, the account's own address only (decided); another address gets 400, a provider failure 503.
