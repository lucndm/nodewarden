# Emergency access, whole path, in NodeWarden's web vault

Status: done on 2026-11-10. The UI check walks both grant types to the end (84 steps).

## Outcome

A person can finish emergency access in NodeWarden's own web vault, without
an official client: view a vault after a view grant is approved, take an
account over after a takeover grant is approved, and the grantor can turn a
recovery down. Findings 1-4 of
`plans/reports/ui-review-261110-1706-web-vault-vs-session-endpoints.md`.

## Constraints

- The server never sees a key it could open: the grantor's vault key is
  unwrapped in the grantee's browser with the grantee's private key.
- The web vault derives master keys with PBKDF2 only (kdf 0), like its own
  password change. A grantor on another KDF gets a clear refusal, not a
  broken password.
- New password rules match the web vault's own password change: at least 12
  characters, typed twice, confirmed before it is sent.
- Every new text exists in all 10 locales.

## Non-goals

- Editing the grantor's items from the view (read only, as upstream).
- Holding the takeover to the grantor's organization master password policy
  (the web vault's own password change does not either).
- Argon2 in the web vault.

## Work

1. Server
   - `:id/password` stores the new password through `hashPasswordServer`, as
     the password change does; today it stores the client hash as is.
   - Both grant lists carry `recoveryInitiatedDate`, so the grantee sees when
     access opens.
2. Web vault library
   - API: `view`, `takeover`, `password`; server errors go through
     `translateServerError`.
   - Crypto: open the grantor's key with the account's private key; build the
     takeover password (PBKDF2, the grantor's salt and iterations).
3. Web vault UI (`EmergencyAccessSettings.tsx`)
   - Grantor: approve for both types at status 3; reject at status 3 and 4.
   - Grantee: type, wait and the date access opens; start the wait for both
     types; "view vault" (type 0) and "take over" (type 1) at status 4.
   - Refuse inviting the account's own address before sending.
4. Tests: unit for the server change; webapp crypto round trip (wrap, open,
   take over, unlock with the new password); UI check walks invite, accept,
   confirm, start, approve, view and takeover; Bruno and unit suites stay
   green.
5. `ROADMAP.md`: say what the web vault does.

## Acceptance

- The UI check walks both grant types to the end in the web vault.
- After a takeover, the grantor's account opens with the new password and the
  vault key is unchanged.
- No request of the Bruno suite goes from pass to fail.
