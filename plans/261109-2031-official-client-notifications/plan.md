# Push hub, notification center and events: current state

Status: state recorded, no implementation planned in this phase.

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
- `POST /notifications/hub/negotiate`: answers 200. The official client never calls it.
- Organizations answer `useEvents: false`, so official clients never record or upload events.

### No route (404)

- [ ] `GET /api/notifications?pageSize=50`: the browser extension fetches it when its notification state is empty and shows it with the at-risk password tasks. NodeWarden has no such notifications, so an empty `ListResponse` would be enough. vaultwarden has no route either.
- [ ] `PATCH /api/notifications/:id/read` and `DELETE /api/notifications/:id/delete`: no body, no response body read. The tests tell a missing route from a missing notification by the error message: the router's no-route answer is the generic `Not found`.
- [ ] `POST /events/collect`: the client treats anything but 200 as a failure and keeps the events to retry. vaultwarden answers 200 even when organization events are off. Harmless while `useEvents` stays false.

## Open questions

- Should `GET /api/notifications` answer an empty list, so the extension stops logging a failed fetch, or wait until NodeWarden has notifications to show?
