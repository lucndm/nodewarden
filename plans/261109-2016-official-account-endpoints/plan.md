# Account endpoints of the official clients: current state

Status: state recorded, no implementation planned in this phase.

## Outcome

Know what every account endpoint of the official Bitwarden clients needs and
how NodeWarden answers it today, so the implementation phase starts from
evidence. This covers group 2 of
`plans/reports/api-coverage-261109-2003-official-clients-endpoint-coverage.md`.

## How the state was recorded

Four Bruno folders, run with `npm run test:api -- <folder>` against a
throwaway Worker. Each request names the client code it comes from and the
vaultwarden handler it follows. A request expects the official behavior,
except where NodeWarden decided otherwise; those tests are named
"NodeWarden refuses on purpose" and expect the decided answer.

Run on 2026-11-09, NodeWarden `origin/main` at `060500c`. The whole
collection: 85 requests, 44 passing, 39 failing, 2 skipped; the failures per
folder match the folders run one by one.

| Folder | Requests | Passing | Failing |
|---|---|---|---|
| `20-account-profile` | 14 | 13 | 1; 14/14 on 2026-11-10 |
| `21-account-lifecycle` | 16 | 8 | 8; 16/16 on 2026-11-10 |
| `22-account-email-flows` | 13 | 10 | 3; 13/13 on 2026-11-10 |
| `23-emergency-access` | 18 | 0 | 17 (1 skipped); 18 pass, 1 skipped on 2026-11-10 |

Rerun of `23-emergency-access` on `origin/main` at `101016c`, after NodeWarden's
own emergency access was merged: 19 requests, 6 passing, 12 failing, 1
skipped (the folder gained one request that creates a grant in NodeWarden's
shape).

## State per endpoint

Paths are the official ones, under `/api` unless marked identity.

### Works as the official client expects

- `GET /accounts/profile`: every field `ProfileResponse` reads is there.
- `GET /accounts/revision-date`: a bare number of milliseconds.
- `POST /accounts/keys`: refused with 400 once the key pair exists.
- `POST /accounts/api-key` and `/accounts/rotate-api-key`: `apiKey` and `revisionDate`; a wrong password gets 400; rotation changes the key.
- `POST /accounts/verify-password`: 200, and 400 for a wrong password.
- `POST /accounts/password`: accepts the current `PasswordRequest` shape (`authenticationData`, `unlockData`); the new password logs in.
- identity `POST /accounts/prelogin/password`: KDF settings and `salt: null`. A null salt makes the client use the email, which holds only while the flag `pm-27060-password-prelogin-from-sdk` is off; `/api/config` keeps it off, and a request checks that.
- identity `GET /accounts/webauthn/assertion-options`: `options.challenge` and `token`.

### Differs from the official client

- [x] Emergency access, whole path, on 2026-11-10: `23-emergency-access` passes 18 requests; `03` is skipped because the official invite in `01` succeeds.
  - An account cannot name itself (400), as in vaultwarden.
  - `:id/accept` does not check the token: NodeWarden sends no email, so it issues none. The grant has to be addressed to the caller's account, which is what the token proves in vaultwarden.
  - `:id/reject` serves two callers: the grantor turns a recovery down (back to confirmed, the wait reset), and the grantee declines an invitation (the grant is gone).
  - A refused step answers 404 where vaultwarden answers 400; the client treats both as an error.

- [x] `PUT /accounts/profile` (2026-11-10): reads `name` (at most 50 characters, as upstream) and `masterPasswordHint`, and changes only what the body carries.

### No route (404)

- [ ] `GET /users/:id/public-key`: needed to confirm organization members and emergency contacts from an official client.
- [x] `PUT /accounts/avatar` (2026-11-10): stored in `users.avatar_color`, `#rrggbb` or null, read back in the profile. Not in the backup export, like `user_key_id`.
- [x] `POST /accounts/security-stamp` (2026-11-10): needs the master password, replaces the stamp and drops the refresh tokens; the old access token answers 401.
- [x] `POST /accounts/key-management/rotate-user-account-keys`: 501, like a KDF change (decided 2026-11-10).
- [x] `GET /accounts/sso/user-identifier` and `DELETE /accounts/sso/:organizationId`: 501 (decided 2026-11-10). The official clients link SSO per organization; NodeWarden links one provider for the server on `/api/settings/sso`.
### Refused on purpose (501), as decided

- `POST /accounts/set-password`: SSO links existing accounts, so every account has a master password.
- No email delivery: identity `register/send-verification-email`, `register/verification-email-clicked`, `register/finish`; `email-token`, `verify-email`, `verify-email-token`, `request-otp`, `verify-otp`, `resend-new-device-otp`.
- The server does mail emergency access invitations, emergency access notices and organization invitations since 2026-11-11; the routes listed here stay 501.
- `POST /accounts/verify-devices`: refused with 400 rather than 501, pointing to TOTP or WebAuthn, for the same reason.
- `POST /accounts/password-hint`: removed on 2026-10-16; the request checks that no hint is disclosed.

### Sign-up stays in NodeWarden's web vault (decided 2026-11-11)

- Identity `register/send-verification-email`, `register/verification-email-clicked` and `register/finish` stay 501, so no official client can create an account. Accounts are created in NodeWarden's web vault, which asks for an invite code; `RegisterFinishRequest` has no field for one.
- This holds even though official sign-up does not strictly need mail: with mail off, vaultwarden answers `register/send-verification-email` with the registration token directly. Serving that path would open sign-up past the invite codes.
- An account made in the web vault signs in from every official client as usual.

### The decision does not reach these paths

- [x] `DELETE /accounts`: 501, the same answer as the other deletion paths (2026-11-10).
- [x] `POST /accounts/email`: 501 like `email-token` (2026-11-10).
- [x] `POST /accounts/delete-recover` and `/delete-recover-token`: 501 on the public router, before the login check (2026-11-10).

### Not recorded, out of scope

- `GET /accounts/key-connector/confirmation-details/:orgSsoIdentifier` and `POST /accounts/set-key-connector-key`: Key Connector, an enterprise feature NodeWarden does not have.
- `PUT /accounts/update-tde-offboarding-password`: trusted device encryption, enterprise.
- `PUT /accounts/update-temp-password`: the forced reset after an admin recovers an account, which needs organization account recovery. Checked on 2026-11-11: the clients call it only from `ChangePasswordComponent` when the reason is `ForceSetPasswordReason.AdminForcePasswordReset` (`changePasswordForAccountRecovery`), which comes from `ForcePasswordReset: true` in the token or profile. NodeWarden and vaultwarden always send `false`, and vaultwarden serves no such route. Emergency access takeover sets the new password through `/emergency-access/:id/password`, not here. A weak master password under an organization policy goes through `POST /accounts/password`.

## Open questions

- The organization invite still needs an answer for the token the official server emails; emergency access settled on not checking it (2026-11-10).
