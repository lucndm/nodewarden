# UX review of the changes merged in #42–#56

Scope: what a person sees, in NodeWarden's web vault (`webapp/`) and in the
official clients, for each change merged on 2026-11-10/11 (#42–#56).
Method:
- read the web vault components and the official client code paths the
  changes serve;
- read 24 hours, then 7 days, of production Worker events (status ≥ 400),
  with a one-hour read-only token deleted after use;
- every PR passed `test:unit`, Bruno and `test:local-ui`.

## Outcome (2026-11-11)

Findings 1 and 2 are fixed in the same pull request as this report: the hub
accepts up to a minute of clock skew, a refused ticket answers 503 with
`Retry-After` and logs the user agent, and the import refusal names the
"Import to" field once. Findings 3 and 4 stay as accepted.

## Findings, most severe first

### 1. Live sync failed in a burst after a deploy (medium)

- **What happened.** On 2026-11-11 at 10:15:25–10:15:26 (UTC+7), shortly after
  #51 deployed, at least 200 `POST /notifications/hub/negotiate` calls answered
  500 within about two seconds. The query caps at 200 events, so there may
  have been more.
  - Each 500 is the Worker's `issueWebSocketConnectionToken` throwing after
    the Durable Object answered `/internal/ws-token` with 400.
  - Every request came from one Mac browser.
  - There were none in the 7 days before and none since.
- **Cause of the 400.** The Durable Object refuses a ticket whose
  `expiresAt > Date.now() + TTL` by its own clock
  (`src/durable/notifications-hub.ts:228`). The Worker sets
  `expiresAt = Date.now() + TTL` by the Worker's clock
  (`src/handlers/notifications.ts:29`). The check has no tolerance, so if the
  object's clock is even 1 ms behind the Worker's, a valid ticket is refused.
  A Durable Object moving or restarting at deploy time is a plausible moment
  for such a skew. This is inferred from the code and the timing; the clock
  values were not observed.
- **Effect.** The tab gets no live updates until a reconnect succeeds. Items
  changed elsewhere appear only on the next manual or periodic sync.
- **Not explained.** The rate. The web vault backs off 1 s, 2 s … 10 s per
  failure (`App.tsx:1913`), and only restarts its effect when `accessToken`,
  the keys, `phase` or `vaultInitialDecryptDone` change (`App.tsx:2082`). Two
  hundred calls in two seconds means many tabs, an effect restarting in a
  loop, or another client on that Mac.
- **Fix.**
  - Let the object accept a small skew, e.g. a minute past the TTL, or let it
    set the expiry itself.
  - Answer a refused ticket with 503, not an unhandled 500.
  - To find the looping client, log the user agent of a refused negotiate
    once.

### 2. Importing a plain file into an organization fails without a collection (medium)

- The official web vault's import form leaves "Import to" (collection) empty
  by default (`import.component.ts:268`, `targetSelector: [null]`). A CSV or a
  personal export carries no collections, so every item arrives unassigned.
- #50 refuses that import whole:
  `Cipher 1: a shared item must be placed in at least one collection`
  (`src/handlers/import.ts:451`).
- The official server would import the items unassigned.
- The message names neither the form field nor the remedy.
- **Fix.** Keep the refusal; it protects the rule that an organization item
  always sits in a collection. Reword it so the person knows what to do, for
  example "Choose a collection under 'Import to' before importing into an
  organization", and send it once, not per item.

### 3. Removing the filtered collection can be refused (low, accepted)

- In the official "Assign to collections" dialog, opened from a collection
  filter, deselecting that collection sends a removal. If those items are in
  no other collection, #55 answers 400:
  `A shared item must stay in at least one collection`.
- The official server would leave them unassigned.
- The message is clear, and this is the trade-off chosen for #55.

### 4. Plain collection names are repaired only by an owner or admin (low)

- #51 seals old plain collection names when an owner or admin opens the web
  vault.
- A member who uses only a mobile app depends on that visit; until then the
  Android app cannot sync that organization.
- There is one organization today, owned by the person who already opened the
  web vault, and production shows the repair ran (`PUT …/collections/…` 200
  at 10:15:46).
- Worth remembering if more organizations are created on an older web vault.

## Checked, no change needed

- **SSO screen (#56).** The 401 is gone; the identifier is typed by hand, as
  chosen.
- **Live sync on the official clients (#47).** Production shows
  `ws-token/consume` 200 and hub connections from the apps.
- **Device removal (#46).** It answers without waiting for the push relay, and
  no slow requests were seen.
- **Android sync (#48, #51, #52).** The user confirmed sync works. The contract
  test now checks both required fields and encrypted fields.
- **Bulk "Assign to collections" (#55).** The web vault has no bulk assign
  (one collection per item from the editor), so it has no surface there.
- **Import into an organization (#50).** NodeWarden's web vault imports into
  the personal vault only, so it has no surface there.
- **Web vault collection creation after #51.** Its only collection-creating
  path, the move into an organization (`organization-migration.ts:381`),
  already seals names, so nothing in the web vault breaks on the new refusal.
- **Emergency access in the web vault (#42).** It covers the findings of the
  previous review and is checked by `test:local-ui`.
- **Two-step login (#43).** Duo answers 501 and HIBP checks only the account's
  own email, as decided. The official clients show a generic error for Duo.
- **Organization accept and account rename from official clients (#44).**
  The web vault shows "Accepted" for the owner to give the key; the account
  name is not shown in the web vault.
- **Error noise in production.** The rest of the 24-hour errors are icon
  lookups (404) for internal or unreachable hosts and anonymous probes of
  `/graphql`, `/api` and `/.well-known/security.txt` (401). Neither affects a
  person.

## Open questions

- Fix finding 1, and find the looping client, before the next endpoint group?
- Reword the import refusal (finding 2)?
