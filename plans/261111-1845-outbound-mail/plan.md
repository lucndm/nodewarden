# Outbound Mail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> In this repository each task is implemented by an omp worker through the
> `delegate-omp` flow (Claude writes the task spec and reviews the diff). The
> tasks ship as one pull request.

Status: planned 2026-11-11, not started.

**Goal:** NodeWarden mails the people who need to act: the grantor when emergency access recovery moves, and whoever is invited to an organization or as an emergency contact.

**Architecture:**
- A small mail service (`src/services/mail.ts`) wraps the Cloudflare Email Service Workers binding.
  - It sends only when both the binding and the sender address are configured.
  - It is best effort: it never throws, and it never changes the answer of the request that triggered it.
- Message text comes from pure template functions (`src/services/mail-templates.ts`).
- Three call sites use it:
  - the emergency access invite and reinvite handlers;
  - the existing emergency access notifier, which today only posts to Telegram;
  - the organization invite handler.

**Tech Stack:** Cloudflare Workers `send_email` binding (`env.EMAIL.send({ to, from, subject, text, html })`), D1 rate limits (`RateLimitService.consumeStrictBudgetWithWindow`), `node:test` with `tsx`.

**Spec:** the decisions below. They were made with the owner on 2026-11-11, and this plan carries them.

## Decisions (the spec)

- **Sending domain.** `pass.minhluc.info` was onboarded to Cloudflare Email Sending on 2026-11-11 (`docker-compose` commit `5dbd10b`, resource `cloudflare_email_sending_subdomain.nodewarden`). The apex `minhluc.info` is PurelyMail and must not be used.
- **Sender.** `no-reply@pass.minhluc.info`, display name `NodeWarden`.
- **Plan.** Workers Paid: 3,000 mails a month included. New accounts start with a low daily quota.
- **First mails:**
  - (a) the grantor, when a grantee starts a recovery, when it is approved by the wait running out, and when the account is taken over (the three kinds `sendEmergencyAccessNotice` already knows);
  - (b) the grantee of an emergency access invite or reinvite;
  - (c) the member invited to an organization.
- **Unchanged.** Every mail-backed route that answers 501 today stays 501: registration, email two-step login, new-device OTP, email change, account deletion by mail. Sign-up stays in the web vault (account plan, decided 2026-11-11).
- **Mail is optional.** Without the binding or `MAIL_FROM`, the server behaves exactly as today.

## Global Constraints

- **New config, in `wrangler.toml` only.**
  - A `[[send_email]]` binding with `name = "EMAIL"`. No `destination_address`, so it can mail any recipient.
  - `[vars]` with `MAIL_FROM = "no-reply@pass.minhluc.info"` and `MAIL_VAULT_URL = "https://pass.minhluc.info"`.
  - `keep_vars = true` stays.
  - `wrangler.kv.toml` is not changed.
- **`Env`.** It gains `EMAIL?: MailBinding`, `MAIL_FROM?: string` and `MAIL_VAULT_URL?: string`. `MailBinding` is a local interface: the installed workers types may not have the new `send()` shape.
- **What a mail carries.** Never a key, a password, a hash, a token or an encrypted string. Only names and emails already shown in the vault, the wait in days, and `MAIL_VAULT_URL`.
- **Language.** All mail text is English, plain and short.
- **Budgets.**
  - Per recipient and kind: 1 mail per 900 s.
  - Global: 100 mails per 3600 s (key `mail:all`), to protect the daily quota.
- **Logging.** One line per failure, `console.warn('mail.send_failed', JSON.stringify({ kind, reason }))`. `reason` is the error `code` or `name`, never the address or the body.
- **Code style.** Comments and test names in English, in the voice of the surrounding files. No plan or finding IDs in code.

## Review Focus

1. **A failing or over-quota binding** (throws, rejects with `E_RATE_LIMIT_EXCEEDED`, or hangs): the invite or recovery request still answers exactly as today. Owned by Task 1 (`sendMail never throws`) and Tasks 3–5 (`the request succeeds when the mail binding fails`).
2. **Names or organization names with HTML, or a CR/LF in the subject:** escaped in the HTML part, and stripped from the subject so no header can be injected. Owned by Task 2.
3. **Reinvite pressed repeatedly:** one mail per recipient per kind per 15 minutes. Owned by Task 3.
4. **A recipient who cannot be resolved:** the grantor was deleted before the cron approval, the grantee has no account yet, the organization invite email has no account.
   - Emergency access invites still mail the address given.
   - Organization invites only mail accounts that exist, because the handler already skips the others.
   - Recovery notices skip a missing grantor silently.
   - Owned by Tasks 3–5.
5. **Mail not configured** (another fork, local dev, Bruno, `test:local-ui`): no binding or no `MAIL_FROM` means no send and no error, and every existing suite passes unchanged. Owned by Task 1, and checked in the final verification.

---

### Task 1: Mail service and configuration

**Files:**
- Create: `src/services/mail.ts`
- Modify: `src/types/index.ts` (`Env`), `wrangler.toml`
- Test: `scripts/mail.test.ts`; add `test:mail` to `package.json` and append it to `test:unit`

**Interfaces:**
- Produces:
  ```ts
  export interface MailBinding {
    send(message: { to: string; from: { email: string; name: string }; subject: string; text: string; html: string }): Promise<{ messageId: string }>;
  }
  export type MailKind = 'emergency_access_invite' | 'emergency_access_recovery' | 'organization_invite';
  export interface OutboundMail { kind: MailKind; to: string; subject: string; text: string; html: string }
  export function isMailConfigured(env: Env): boolean;          // EMAIL present and MAIL_FROM non-empty
  export function mailVaultUrl(env: Env): string | null;         // MAIL_VAULT_URL if it parses as https URL, else null
  export async function sendMail(env: Env, mail: OutboundMail): Promise<boolean>; // true when handed to the binding
  ```
- `sendMail` does the following:
  - returns `false` without a call when the mail is not configured, or when `to` does not look like one address (no whitespace, exactly one `@`);
  - consumes `mail:${kind}:${to.toLowerCase()}` (1 per 900 s), then `mail:all` (100 per 3600 s);
  - calls `env.EMAIL.send` with `from: { email: MAIL_FROM, name: 'NodeWarden' }`;
  - catches everything and logs per Global Constraints.

- [ ] **Step 1: Write the failing tests** in `scripts/mail.test.ts`. Use a fake binding that records `send` calls, and a fake that throws `Object.assign(new Error('quota'), { code: 'E_RATE_LIMIT_EXCEEDED' })`:
  - `mail is not sent when the binding or the sender is missing`: three env variants → `sendMail` resolves `false`, and the fake has 0 calls.
  - `a configured server hands the mail to the binding`: resolves `true`; one call with `from.email === 'no-reply@pass.minhluc.info'`, `from.name === 'NodeWarden'`, and the given `to`, `subject`, `text` and `html`.
  - `sendMail never throws`: the throwing fake → resolves `false`; `console.warn` called once with a string containing `mail.send_failed` and `E_RATE_LIMIT_EXCEEDED`, and not containing the recipient address.
  - `one mail per recipient and kind per quarter hour`: the same kind and `to` twice → 1 call; a different kind → 2 calls.
  - `an address that is not one address is not mailed`: `'a@b.c, d@e.f'` and `'nobody'` → `false`, 0 calls.
  - `mailVaultUrl accepts only an https URL`: `'https://pass.minhluc.info'` → the same string without a trailing slash; `'javascript:alert(1)'`, `'http://x'` and `undefined` → `null`.

  Env: `MemoryD1` or `sqliteD1` like `scripts/emergency-access-notice.test.ts`, so `RateLimitService` works.

- [ ] **Step 2: Run** `npm run test:mail`. Expected: FAIL, module not found.
- [ ] **Step 3: Implement** `src/services/mail.ts` and the `Env` fields. Add to `wrangler.toml`:
  ```toml
  [vars]
  MAIL_FROM = "no-reply@pass.minhluc.info"
  MAIL_VAULT_URL = "https://pass.minhluc.info"

  [[send_email]]
  name = "EMAIL"
  ```
- [ ] **Step 4: Run** `npm run test:mail`. Expected: PASS, 6/6.
- [ ] **Step 5: Run** `npx tsc --noEmit -p tsconfig.json`. Expected: no `error TS`.

### Task 2: Mail templates

**Files:**
- Create: `src/services/mail-templates.ts`
- Test: `scripts/mail-templates.test.ts`; add `test:mail-templates` to `test:unit`

**Interfaces:**
- Produces (each returns `{ subject: string; text: string; html: string }`):
  ```ts
  emergencyAccessInviteMail(input: { grantorName: string | null; grantorEmail: string; accessType: 'view' | 'takeover'; waitTimeDays: number; vaultUrl: string | null })
  emergencyAccessRecoveryMail(input: { kind: 'recovery_started' | 'recovery_approved' | 'account_taken_over'; granteeName: string | null; granteeEmail: string; waitTimeDays: number; vaultUrl: string | null })
  organizationInviteMail(input: { organizationName: string; inviterEmail: string; vaultUrl: string | null })
  ```
- The subject has CR, LF and other control characters removed, and is cut to 200 characters. The HTML escapes `& < > " '` in every inserted value. With `vaultUrl` null, the "Sign in at …" line is left out of both parts.
- Fixed copy for the subjects:
  - `You were named an emergency contact`
  - `Emergency access to your vault was requested`
  - `Emergency access to your vault was granted`
  - `Your account was taken over through emergency access`
  - `You were invited to ${organizationName}`
- The `recovery_started` body must say that access is granted automatically after `${waitTimeDays} days` unless the grantor rejects it, and that signing in to the vault is where to reject it.

- [ ] **Step 1: Write the failing tests:**
  - `each mail names the person and links the vault`: the text and html contain the grantor or grantee email and `https://pass.minhluc.info`.
  - `the recovery notice says how long the owner has to refuse`: `recovery_started` with `waitTimeDays: 7` → the text contains `7 days` and `reject`.
  - `inserted values are escaped in html`: organization name `<b>x</b>&"'` → the html contains `&lt;b&gt;x&lt;/b&gt;&amp;&quot;&#39;` and not `<b>x`.
  - `a subject cannot carry a header`: organization name `"Acme\r\nBcc: a@b.c"` → the subject has no `\r` or `\n`.
  - `no vault url, no sign-in line`: `vaultUrl: null` → the text does not contain `Sign in at`.
- [ ] **Step 2: Run** `npm run test:mail-templates`. Expected: FAIL.
- [ ] **Step 3: Implement** the three functions and one private `escapeHtml`.
- [ ] **Step 4: Run** it again. Expected: PASS, 5/5.

### Task 3: Emergency access invite and reinvite mail

**Files:**
- Modify: `src/handlers/emergency-access.ts` (`handleInviteEmergencyAccess` around line 167; `handleReinviteEmergencyAccess` around line 457)
- Test: add to `scripts/emergency-access.test.ts`, using its `fixture()` plus a recording `EMAIL` binding and `MAIL_FROM` / `MAIL_VAULT_URL`.

**Interfaces:**
- Consumes: `sendMail`, `isMailConfigured`, `mailVaultUrl` (Task 1); `emergencyAccessInviteMail` (Task 2); `storage.getUserById` for the grantor's name and email.
- The mail goes to the invited address (`row.email`), after the grant is stored and before the response, with `await`. A failure cannot fail the request, because `sendMail` never throws. `accessType` is `'takeover'` for type 1, `'view'` for type 0.

- [ ] **Step 1: Write the failing tests:**
  - `an invitation is mailed to the person invited`: invite `grantee@example.test` → 200; one `send` with `to === 'grantee@example.test'`; the subject is `You were named an emergency contact`.
  - `an invitation to an address without an account is still mailed`.
  - `a reinvite mails again, but not twice in a quarter hour`: invite, then reinvite → 1 call (same kind and recipient within 900 s).
  - `the request succeeds when the mail binding fails`: a throwing binding → the invite still answers 200 and the grant exists.
  - `nothing is mailed when mail is not configured`: no `EMAIL` → 200, and no error.
- [ ] **Step 2: Run** `npm run test:emergency-access`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement** a local `mailEmergencyAccessInvite(env, row, grantor)` used by both handlers.
- [ ] **Step 4: Run** `npm run test:emergency-access`. Expected: PASS, with the existing tests unchanged.

### Task 4: Mail the grantor when recovery moves

**Files:**
- Modify: `src/services/emergency-access-notifier.ts`
- Test: add to `scripts/emergency-access-notice.test.ts`

**Interfaces:**
- Consumes: Tasks 1–2; `StorageService(env.DB).getUserById` for the grantor (recipient) and the grantee (named in the mail).
- `sendEmergencyAccessNotice(env, host, notice)` keeps its signature and its Telegram behavior. The mail part runs whether or not Telegram is configured, so the early `return` on a missing Telegram config must no longer skip it. The function still never throws. The cron call in `src/index.ts:136` therefore mails too, with no change there.
- `kind` in `sendMail` is `'emergency_access_recovery'`. The per-recipient budget key includes the notice kind (`mail:emergency_access_recovery:${notice.kind}:${email}`), so a "started" and an "approved" on the same day both arrive. Extend `OutboundMail` with an optional `budgetKey?: string` that, when set, replaces `${kind}` in the budget identifier.

- [ ] **Step 1: Write the failing tests:**
  - `the grantor is mailed when a recovery starts`: notice `recovery_started` for a stored grantor and grantee → one `send` to the grantor's email; the subject is `Emergency access to your vault was requested`; the text contains the grantee email and the wait.
  - `the mail goes out without Telegram configured`: no `TELEGRAM_*` → still one `send`.
  - `a grantor who no longer exists is not mailed`: unknown `grantorId` → 0 calls, no throw.
  - `started and approved are both delivered`: two kinds in a row → 2 calls.
  - `the mail carries nothing that opens the vault`: the stored grantor has `key`, `privateKey` and `masterPasswordHash` set → none of those values appears in the text or html.
- [ ] **Step 2: Run** `npm run test:emergency-access` (it runs `emergency-access-notice.test.ts`). Expected: the new tests FAIL.
- [ ] **Step 3: Implement** it.
- [ ] **Step 4: Run** it again. Expected: PASS, and the existing notice tests pass unchanged.

### Task 5: Organization invite mail

**Files:**
- Modify: `src/handlers/organizations.ts` (`handleInviteOrganizationUser` around line 151)
- Test: create `scripts/organization-invite-mail.test.ts` using `scripts/organization-fixture.ts`; add `test:organization-invite-mail` to `package.json` and append it to `test:unit`.

**Interfaces:**
- Consumes: Tasks 1–2. The organization name comes from `storage.getOrganizationsForUser(userId)`, finding `orgId`. The inviter email comes from `storage.getUserById(userId)`.
- One mail per newly added membership, sent after `addOrganizationUser`. Emails that have no account, or that are already members, are skipped as today and get no mail.

- [ ] **Step 1: Write the failing tests:**
  - `each new member is mailed`: invite two existing accounts → 2 `send` calls; the subject is `You were invited to <org name>`.
  - `an address without an account and an existing member get no mail`.
  - `the request succeeds when the mail binding fails`.
- [ ] **Step 2: Run** `npm run test:organization-invite-mail`. Expected: FAIL.
- [ ] **Step 3: Implement** it.
- [ ] **Step 4: Run** it. Expected: PASS.

### Task 6: Documentation and full verification

**Files:**
- Modify: `README.md`. Add a short "Outbound mail" section: what is mailed, the binding and the two vars, that it is optional, and that the 501 mail routes are unchanged. Link this plan.
- Modify: `plans/261109-2016-official-account-endpoints/plan.md`. Under the 501 section, one line: the server now mails invites and recovery notices, and the routes listed there remain 501.

- [ ] **Step 1: Run**, all expected clean:
  - `npm run test:unit`: all suites, 0 fail;
  - `npx tsc --noEmit -p tsconfig.json`: no `error TS`;
  - `npx tsc --noEmit -p webapp/tsconfig.json`: no `error TS`;
  - `npm run build`: succeeds.
- [ ] **Step 2: Claude runs:**
  - `npm run test:api`: same status for every request as on `main` (mail is not configured locally);
  - `npm run test:local-ui`: all checks pass.
- [ ] **Step 3: After merge and deploy, Claude checks production:**
  - The Workers Builds deploy succeeds with the `send_email` binding. If it fails for a missing permission, add the Email Sending permission to the `nodewarden-deploy` token in `docker-compose/infrastructure/cloudflare-token/main.tf`.
  - The owner invites their own second address as an emergency contact. The mail arrives from `no-reply@pass.minhluc.info`, and its headers show `spf=pass`, `dkim=pass` and `dmarc=pass`.
  - Workers Logs show no `mail.send_failed`.

## Rollback

Remove the `[[send_email]]` block, or `MAIL_FROM`, from `wrangler.toml` and deploy. The server returns to sending no mail, with no other change. The Email Sending subdomain can stay onboarded, at no cost.
