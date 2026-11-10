# Push hub, notification center and events: current state

Status: done on 2026-11-10; all 7 requests of `30-client-notifications` pass.

## Outcome

Know how NodeWarden answers the newer official client features outside the
vault: the push hub, the end-user notification center and the event upload.
This covers group 3 of
`plans/reports/api-coverage-261109-2003-official-clients-endpoint-coverage.md`.

## How the state was recorded

Bruno folder `api-tests/30-client-notifications`, run with
`npm run test:api -- 30-client-notifications` on 2026-11-09 against
`origin/main` at `060500c`: 7 requests, 3 passing, 4 failing.

The hub is a WebSocket speaking SignalR with MessagePack, which Bruno cannot
drive; only its HTTP side is recorded here. `npm run test:notifications-security`
covers the hub itself.

## State per endpoint

### Works as the official client expects

- `GET /notifications/hub`: the official client connects straight over WebSocket (`skipNegotiation: true`, MessagePack, token in `access_token`); a plain GET gets 426 "Expected websocket", so the route is there.
  - Correction, 2026-11-10: the route was there, but every official connection got 401. The hub refused a token in the URL (#349), and the official client skips negotiate, so it never had the one-time `id` either; production logs showed 52 such 401s between 15:57 and 22:10. Since 2026-11-10 the hub accepts `access_token` in the query, as vaultwarden does (decided), with query strings redacted from Worker logs and traces (#46) and the token dropped before the Durable Object.
- `POST /notifications/hub/negotiate`: answers 200. The official client never calls it.
- Organizations answer `useEvents: false`, so official clients never record or upload events.

### No route (404)

- [x] `GET /api/notifications?pageSize=50` (2026-11-10: an empty list): the browser extension fetches it when its notification state is empty and shows it with the at-risk password tasks. NodeWarden has no such notifications, so an empty `ListResponse` would be enough. vaultwarden has no route either.
- [x] `PATCH /api/notifications/:id/read` and `DELETE /api/notifications/:id/delete` (2026-11-10: 404 "Notification not found."): no body, no response body read. The tests tell a missing route from a missing notification by the error message: the router's no-route answer is the generic `Not found`.
- [x] `POST /events/collect` (2026-11-10: 200, the events are dropped): the client treats anything but 200 as a failure and keeps the events to retry. vaultwarden answers 200 even when organization events are off. Harmless while `useEvents` stays false.
