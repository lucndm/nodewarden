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
| `20-account-profile` | 14 | 13 | 1 |
| `21-account-lifecycle` | 16 | 8 | 8 |
| `22-account-email-flows` | 13 | 10 | 3 |
| `23-emergency-access` | 18 | 0 | 17 (1 skipped) |

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

- [ ] `PUT /accounts/profile`: the handler reads only `masterPasswordHint`. The name is ignored, and the official body (`name` only) clears the master password hint.

### No route (404)

- [ ] `GET /users/:id/public-key`: needed to confirm organization members and emergency contacts from an official client.
- [ ] `PUT /accounts/avatar`.
- [ ] `POST /accounts/security-stamp` ("log out of all sessions"); the old token keeps working.
- [ ] `POST /accounts/key-management/rotate-user-account-keys` (rotate the account encryption key).
- [ ] `GET /accounts/sso/user-identifier` and `DELETE /accounts/sso/:organizationId`: NodeWarden links SSO on its own routes (`/api/settings/sso`, `/api/settings/sso/link`). The expected answer is not decided; the tests only record that no route exists.
- [ ] Emergency access. On `060500c` none of the 15 endpoints existed. On `101016c` NodeWarden has its own emergency access; against the official client:
  - works: `trusted`, `granted`, `GET :id`, `DELETE :id`, `:id/accept`;
  - `invite` is refused with 400 "Encrypted user key is required.": NodeWarden takes the grantor's wrapped key at invite time (`encryptedUserKey`), the official client sends it later with `confirm`;
  - `:id/accept` accepts any token, because NodeWarden's grantee accepts inside the web vault;
  - no route: `PUT :id`, `:id/reinvite`, `:id/confirm`, `:id/policies`;
  - after `accept` the grant stays accepted and nothing moves it to confirmed, so `:id/initiate`, `:id/approve`, `:id/takeover` and `:id/password` answer 404 "Emergency access not valid." This holds for NodeWarden's own web vault too, which calls no confirm route.

### Refused on purpose (501), as decided

- `POST /accounts/set-password`: SSO links existing accounts, so every account has a master password.
- No email delivery: identity `register/send-verification-email`, `register/verification-email-clicked`, `register/finish`; `email-token`, `verify-email`, `verify-email-token`, `request-otp`, `verify-otp`, `resend-new-device-otp`.
- `POST /accounts/verify-devices`: refused with 400 rather than 501, pointing to TOTP or WebAuthn, for the same reason.
- `POST /accounts/password-hint`: removed on 2026-10-16; the request checks that no hint is disclosed.

### The decision does not reach these paths

- [ ] `DELETE /accounts`: NodeWarden refuses `POST /accounts/delete`, `/delete-account` and `/delete-vault` with 501, but the official client deletes with `DELETE /accounts`, which has no route (404).
- [ ] `POST /accounts/email`: mail-backed like `email-token`, but 404 instead of 501.
- [ ] `POST /accounts/delete-recover` and `/delete-recover-token`: mail-backed, sent without a token, so they end in 401 instead of 501.

### Not recorded, out of scope

- `GET /accounts/key-connector/confirmation-details/:orgSsoIdentifier` and `POST /accounts/set-key-connector-key`: Key Connector, an enterprise feature NodeWarden does not have.
- `PUT /accounts/update-tde-offboarding-password`: trusted device encryption, enterprise.
- `PUT /accounts/update-temp-password`: the forced reset after an admin recovers an account, which needs organization account recovery.

## Open questions

- Official sign-up does not actually need email: vaultwarden answers `register/send-verification-email` with the registration token directly when mail is off. NodeWarden treats it as mail-backed and refuses, which blocks sign-up from every official client. Should official sign-up stay blocked, given NodeWarden registers with invite codes and `RegisterFinishRequest` has no invite code field?
- Emergency access and the organization invite both need a token that the official server emails. One answer for both would keep the two flows consistent.
- Expected answers for the SSO link endpoints.
