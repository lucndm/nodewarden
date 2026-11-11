# Change Email Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> In this repository each task is implemented by an omp worker through the
> `delegate-omp` flow (Claude writes the task spec and reviews the diff). The
> tasks ship as one pull request.

Status: planned 2026-11-11, not started.

**Goal:** A user changes their account email from the official clients or from NodeWarden's web vault: a code sent to the new address proves they own it, and the old address is told afterwards.

**Architecture:**
- `POST /accounts/email-token` checks the master password, stores a short-lived code for the new address (hashed), and mails it.
- `POST /accounts/email` checks the password and the code, then switches the email, the server password verifier and the wrapped user key in one save. It then ends every session, as a password change does, and mails the old address.
- NodeWarden's web vault gets a two-step form that derives the new master key with the new email as salt, using the same helpers as its password change.

**Tech Stack:** Workers + D1, `sendMail` and templates from #60, Preact web vault, `node:test` with `tsx`.

**Spec:** the decisions below, made with the owner on 2026-11-11.

## Decisions (the spec)

- **Both client paths.** Official clients (web vault, desktop, extension: Settings → My account → Change email), and a new form in NodeWarden's web vault, in the same pull request.
- **Wire format** (`clients` `libs/common/src/auth/models/request/email*.request.ts`). Both client variants send:
  - `email-token`: `{ masterPasswordHash, newEmail }`;
  - `email`: `{ masterPasswordHash, newEmail, newMasterPasswordHash, token, key }`.
  - `key` is the user key wrapped with the master key derived from the new email. The KDF does not change.
- **The code.** 6 digits, valid 15 minutes, at most 5 wrong tries. It is stored only as HMAC-SHA256(`JWT_SECRET`, `${userId}:${code}`).
- **Mail.** Without mail configured, both routes keep answering 501 `Email delivery is not supported by this server.`, as today. A change is never allowed without a delivered code.
- **After the change:**
  - a new security stamp;
  - all refresh tokens deleted;
  - trusted two-step tokens deleted;
  - the user cache invalidated;
  - an audit event;
  - a best-effort mail to the old address (owner decision 2026-11-11).
- **The server password verifier** is `auth.hashPasswordServer(newMasterPasswordHash)`. The current verifier format does not salt with the email.
- **Out of scope:** email verification, email two-step login, deletion by mail. They stay 501.

## Global Constraints

- **Email.** New emails are trimmed and lowercased. One address only: reuse the single-address check from `src/services/mail.ts` by exporting it as `isSingleEmailAddress(value: string): boolean`.
- **Errors.** 400 with these exact messages:
  - `Invalid password`
  - `Email already in use`
  - `The new email is the current email`
  - `No email change pending`
  - `Email change mismatch`
  - `Token mismatch`
  - `Too many wrong codes; ask for a new one`
  - `The code has expired; ask for a new one`
  - `key is not a valid encrypted string`
- **Codes not delivered.** When `sendMail` returns `false` (budget or failure), the stored request is deleted and the answer is 429 `The code could not be sent; try again later`.
- **New table**, created through `ensureStorageSchema` like the others (`CREATE TABLE IF NOT EXISTS`). No change to existing tables. D1 Time Travel covers rollback.
  ```sql
  email_change_requests (
    user_id TEXT PRIMARY KEY,
    new_email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
  )
  ```
- **Web vault strings.** New keys go into all 10 files in `webapp/src/lib/i18n/locales/`, because `t()` has no English fallback. Translate them; English text is acceptable only where no translation can be made.
- **Code style.** Comments, test names and server strings in English, in the voice of the surrounding files. No plan IDs in code.

## Review Focus

1. **The new email belongs to someone else** at request time, or is taken between the code and the change: 400 `Email already in use` both times, and nothing changes. Owned by Task 2.
2. **Guessing the code:** after 5 wrong codes the request is gone, so a new code must be asked for; an expired code is refused. Owned by Task 2.
3. **The old email is not a key anywhere after the change:**
   - login works with the new email and the same password; the old email fails;
   - pending emergency access invitations addressed to the new email show up, through the rule from #61;
   - the account's organization memberships and emergency grants stay (they key on user id).
   - Owned by Task 2, with a login test.
4. **A request for another account's pending change:** the request is keyed by the authenticated user id, so it never crosses accounts. Owned by Task 2.
5. **The web vault derives the key with the wrong salt or KDF:** the test decrypts the new `key` with the master key derived from the new email, and expects the same user key. Owned by Task 4.

---

### Task 1: Storage and mail templates

**Files:**
- Modify: `src/services/storage-schema.ts` (the table)
- Create: `src/services/storage-email-change-repo.ts`
- Modify: `src/services/storage.ts` (wrappers)
- Modify: `src/services/mail.ts`:
  - add `'email_change_code' | 'email_changed'` to `MailKind`;
  - export `isSingleEmailAddress`.
- Modify: `src/services/mail-templates.ts`
- Test: `scripts/email-change-storage.test.ts`; `scripts/mail-templates.test.ts` (new cases). Add `test:email-change` running both new email-change test files, and append it to `test:unit`.

**Interfaces:**
- Produces (repo functions, mirrored on `StorageService` with the db argument dropped):
  ```ts
  putEmailChangeRequest(db, input: { userId: string; newEmail: string; codeHash: string; expiresAt: number }): Promise<void>   // replaces any pending one, attempts = 0
  getEmailChangeRequest(db, userId: string): Promise<{ userId: string; newEmail: string; codeHash: string; expiresAt: number; attempts: number } | null>
  recordEmailChangeAttempt(db, userId: string): Promise<number>   // returns attempts after increment
  deleteEmailChangeRequest(db, userId: string): Promise<void>
  ```
- Produces (templates, same return shape as the others):
  ```ts
  emailChangeCodeMail(input: { code: string; vaultUrl: string | null })
  // subject: 'Your email change code'
  // text includes the code, "15 minutes", and that the mail can be ignored if they did not ask for it
  emailChangedNoticeMail(input: { newEmail: string; vaultUrl: string | null })
  // subject: 'The email of your vault account was changed'
  // text includes the new email, and "If you did not do this, sign in and change your master password, or contact the server's administrator."
  ```

- [ ] **Step 1:** Write the failing tests:
  - `a pending change replaces the one before it`;
  - `attempts count up`;
  - `deleting removes the request`;
  - `the code mail carries the code and its lifetime`;
  - `the notice names the new email` (the HTML part escapes it).
- [ ] **Step 2:** Run `npm run test:email-change` and `npm run test:mail-templates`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run both again. Expected: PASS.

### Task 2: The two routes

**Files:**
- Modify: `src/handlers/accounts.ts`. Add `handleEmailToken(request, env, userId)` and `handleChangeEmail(request, env, userId)` beside `handleChangePassword`, and reuse its steps after the save.
- Modify: `src/router-authenticated.ts`.
  - Remove the four `/accounts/email-token` and `/accounts/email` entries from `mailBackedAccountPaths` (around line 230).
  - Route `POST` to the new handlers before that set.
  - When `!isMailConfigured(env)`, the handlers answer the same 501 as before.
- Test: `scripts/account-email-change.test.ts`, included in `test:email-change`.

**Interfaces:**
- Consumes Task 1, `sendMail`, `isMailConfigured`, `mailVaultUrl`, `AuthService` (`verifyPassword`, `hashPasswordServer`, `invalidateUserCache`), `isValidEncString`, and the post-save steps of `handleChangePassword` (look there for the exact calls and the audit event shape; use event name `account.email.change`, metadata `{ oldEmail, newEmail, ... }`).
- Code generation: `crypto.getRandomValues`, zero-padded to 6 digits.
- Compare the code by HMAC hash in constant time. Use the repo's existing constant-time helper if there is one; otherwise compare equal-length hex strings without an early exit.
- Order in `handleChangeEmail`:
  1. password;
  2. pending request exists;
  3. `newEmail` matches it;
  4. not expired (delete it when expired);
  5. attempts < 5;
  6. code (on mismatch, `recordEmailChangeAttempt`; at 5, delete the request);
  7. `key` is valid and `newMasterPasswordHash` is present;
  8. the email is still free;
  9. save, delete the request, run the post-save steps, then mail the old address.

- [ ] **Step 1:** Write the failing tests (recording `EMAIL` binding, `MAIL_FROM`, `MAIL_VAULT_URL`; a user created the way `scripts/account-lifecycle.test.ts` creates one):
  - `without mail both routes answer 501`.
  - `asking for a code mails it to the new address`: the recorded `to` is the new address; the code in the text has 6 digits; the stored hash is not the code.
  - `a wrong password gets no code`: 400 `Invalid password`; nothing mailed.
  - `an address in use gets no code`: 400 `Email already in use`.
  - `the right code changes the email`: 200; login with the new email and the same client hash succeeds through the identity token route the existing tests use; login with the old email fails; `securityStamp` changed; refresh tokens gone; a mail went to the old address naming the new one.
  - `a wrong code counts, and the fifth ends the request`: four wrong → 400 `Token mismatch`; the fifth → 400 `Too many wrong codes; ask for a new one`; then the right code → 400 `No email change pending`.
  - `an expired code is refused` (set `expiresAt` in the past through the repo).
  - `a code that was not delivered is not kept`: a binding that throws → 429; `getEmailChangeRequest` is null.
  - `an invitation to the new address shows up after the change`: an emergency access invite to the new address made before the change appears in `GET /api/emergency-access/granted` after it.
- [ ] **Step 2:** Run `npm run test:email-change`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run it again. Expected: PASS.

### Task 3: The account plan and README

**Files:**
- `plans/261109-2016-official-account-endpoints/plan.md`: move `POST /accounts/email-token` and `POST /accounts/email` out of the 501 lists into a `[x]` line dated 2026-11-11, and say mail must be configured.
- `README.md`: one line in "Outbound mail" saying email change uses it.

- [ ] **Step 1:** Edit both. No test.

### Task 4: NodeWarden web vault form

**Files:**
- Modify: `webapp/src/lib/api/auth.ts`. Add, next to `changeMasterPassword` and reusing its helpers:
  ```ts
  requestEmailChangeCode(authedFetch, args: { email: string; password: string; currentIterations: number; newEmail: string }): Promise<void>
  changeEmail(authedFetch, args: { email: string; password: string; currentIterations: number; profileKey: string; newEmail: string; code: string }): Promise<void>
  ```
  `changeEmail` does the following:
  - derives the current login hash as `changeMasterPassword` does;
  - unlocks the user key from `profileKey`;
  - derives the new master key with `newEmail.trim().toLowerCase()` as salt and the same KDF settings;
  - computes the new login hash and wraps the same user key with the new master key;
  - POSTs `{ masterPasswordHash, newEmail, newMasterPasswordHash, token: code, key }`.

  It supports exactly the KDF types `changeMasterPassword` supports and throws the same way for others. Both functions throw `Error` with the server message on failure.
- Modify: the settings component that holds the password change (`webapp/src/components/SettingsPage.tsx`, or the hook `useAccountSecurityActions.ts`). Add a "Change email" section:
  - **step 1:** new email and master password, then "Send code" → `requestEmailChangeCode`;
  - **step 2:** the code input, then "Change email" → `changeEmail`;
  - **on success:** a notice that the email changed and every session ends, then sign out the way the password change does.
- Modify: all 10 locale files, adding keys for the labels, buttons, the success notice and the generic failure.
- Test: `scripts/change-email-webapp.test.ts` (pattern: `scripts/emergency-access-webapp.test.ts`); add `test:change-email-webapp` to `test:unit`.
  - `the new key opens with the master key of the new email`: build a profile from a known password, email and iterations; capture the POST body from a fake `authedFetch`; decrypt `key` with the master key derived from the new email; expect the original user key bytes.
  - `the hashes differ for the old and new email`.
  - `the request goes to /api/accounts/email with the code as token`.

- [ ] **Step 1:** Write the failing tests.
- [ ] **Step 2:** Run `npm run test:change-email-webapp`. Expected: FAIL.
- [ ] **Step 3:** Implement the functions, the section and the strings.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Run `npx tsc --noEmit -p webapp/tsconfig.json` and `npm run build`. Expected: clean.

### Final verification (Claude)

- `npm run test:unit`, both `tsc`, and `build`: clean.
- `npm run test:api`: every request keeps the same status. Mail is not configured locally, so the email routes stay 501.
- `npm run test:local-ui`: all checks pass.
- After deploy, on a second, disposable account (never the owner's main account):
  - change its email in NodeWarden's web vault;
  - the code mail arrives at the new address and the notice at the old one;
  - sign in with the new email works;
  - Workers Logs show no `mail.send_failed`.

## Rollback

Revert the pull request. The routes return to 501. The extra table is harmless and can stay.
