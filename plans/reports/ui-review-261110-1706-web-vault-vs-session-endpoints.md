# Web vault UX against the endpoints changed on 2026-11-09/10

Scope: what a person sees in NodeWarden's own web vault (`webapp/`) for each
feature whose server side changed in #26, #29, #35, #38, #39, #40 and #41.
Method: read the components and API wrappers on `main` at `f44d95c`; the UI
check (`npm run test:local-ui`, 57 steps) passed on every PR.

## Outcome (2026-11-10)

Findings 1-4 are fixed by `plans/261110-1745-emergency-access-web-vault/`.
Fixing them showed one more, worse than finding 1: `SettingsPage` rendered
the emergency access settings without the session, so the grantor's
"Hand over the key" always failed and no grant could reach "confirmed" in the
web vault. Finding 5 stays as accepted.

## Findings, most severe first

### 1. Emergency access stops at "approved" in the web vault (high)

`webapp/src/lib/api/emergency-access.ts` has no wrapper for `:id/view`,
`:id/takeover`, `:id/password` or `:id/policies`, and no component calls them.

- A view grant (type 0) cannot start: the grantee's "start wait" button shows
  only for `type === 1` (`EmergencyAccessSettings.tsx:302`), and the grantor's
  "approve" button only for `type === 1` (`:244`). The server allows both for
  type 0.
- A takeover grant reaches status 4 and nothing more happens: the grantee has
  no way to set the new master password.

The server path works end to end (Bruno `23-emergency-access`, the unit flow
tests), so the official web vault completes it. NodeWarden's own web vault
does not.

`ROADMAP.md:390` says "Đã làm phần View + Takeover (2026-11-09) — bảng, route,
UI, có test". The UI part is not true.

### 2. The grantor cannot turn a recovery down (medium)

#38 added the grantor's `reject` for status 3 and 4. The web vault shows the
grantor only "approve" (type 1) and "withdraw". Withdraw deletes the grant, so
stopping an unwanted recovery costs a new invite, a new accept and a new
confirm.

### 3. The grantee sees too little (medium)

The "received" list shows the grantor and the status only
(`EmergencyAccessSettings.tsx:279-282`): not the type, not the wait, and not
when access opens after "start wait". The grantee cannot tell what they were
given or how long is left.

### 4. Error messages (low)

- Invite shows the server message as is (`:180`), in English in every locale;
  for example "You can not set yourself as an emergency contact." A check
  against the account's own email before sending would give a localized
  message.
- Accept, reject, approve, initiate and withdraw show a generic "failed"
  message and drop the server's reason.

### 5. Avatar color is not shown (low)

#39 stores `avatarColor` and returns it in the profile; only the official
clients read it. The web vault keeps its own avatar. Acceptable unless the
web vault should match the official clients.

## Checked, no change needed

- Organization accept-before-confirm (#29): "Accepted" label, give-key button
  only for accepted members, owner-only for admins; covered by the UI check.
- Two-step login setup (#35): the web vault reads the nested shapes and still
  sends the master password; covered by the UI check.
- `POST /accounts/security-stamp` (#39): the web vault already has "Remove all
  devices and sign out" on its own route (`useAccountSecurityActions.ts:561`).
- Notification center and event upload (#40): no web vault surface; only the
  browser extension calls them.
- 501 answers (#39, #41: key rotation, organization SSO, account deletion,
  change email, delete-recover): no web vault surface. The official clients
  still show these menu items and report a generic error when the server
  refuses; that is the accepted cost of the decisions.

## Open questions

- Should NodeWarden's web vault complete emergency access (finding 1), or is
  the official web vault the intended client for view and takeover? Either
  way `ROADMAP.md:390` needs correcting.
- Fix findings 2-4 in the same PR as 1, or separately?
