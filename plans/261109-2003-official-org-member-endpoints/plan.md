# Organization endpoints for members on the official paths

Status: done on 2026-11-10; all 11 requests of `10-organization-member` pass. The accept token is not checked (decided 2026-11-10, as for emergency access): NodeWarden sends no email and issues none, and the membership in the path has to be the caller's.

## Outcome

An official Bitwarden client (web, extension, desktop, CLI) can act as an
organization member against NodeWarden: read the organization keys, accept an
invitation, and leave. Today NodeWarden serves these on routes of its own and
answers the official paths with the 501 catch-all in
`src/router-authenticated.ts`.

This phase only records what each endpoint needs. Implementation is the next
phase.

## Contract

The executable contract is `api-tests/10-organization-member/`. Run it with
`npm run test:api`. It boots a throwaway Worker, builds the accounts and the
organization in `api-tests/00-setup/`, and runs the requests. Every request
names the client code it comes from and the vaultwarden behavior it follows.

Run on 2026-11-09: setup 13/13 passing; the 10 contract requests fail with
501 as expected; the accept-with-token request is skipped (no token source yet).

## Checklist

### GET `/api/organizations/:orgId/keys`

- [x] Contract: client `OrganizationApiService.getKeys`, response `OrganizationKeysResponse`; callers read only `publicKey`.
- [x] Bruno: a confirmed member gets 200 with the organization's `publicKey` and no `privateKey` (`01`).
- [x] Bruno: an invited, unconfirmed account gets 404 (`02`).
- [x] Route and handler.
- [x] `01` and `02` pass.

### POST `/api/organizations/:orgId/keys`

- [x] Contract: body `OrganizationKeysRequest` (`publicKey`, `encryptedPrivateKey`), response `OrganizationKeysResponse`. The only official caller is the self-hosted license upload.
- [x] Bruno: refused with 400 once the key pair exists (`03`); a plain member gets 404 (`04`).
- [x] Route and handler. Every NodeWarden organization gets its key pair at creation, so the handler mostly refuses.
- [x] `03` and `04` pass.

### POST `/api/organizations/:orgId/users/:membershipId/accept`

- [x] Contract: body `OrganizationUserAcceptRequest` (`token` required, `resetPasswordKey` only under account recovery auto-enrollment); no response body read. The client gets `organizationId`, `organizationUserId`, `email` and `token` from the invite link.
- [x] Bruno: an account the invitation was not sent to is refused with 404 (`05`).
- [x] Bruno: the invitee accepts with a token from the link (`06`), run by default.
- [x] Decided: no token is issued or checked; the membership has to be the caller's.
- [x] Route: `POST /organizations/:orgId/users/:membershipId/accept` runs the same accept as `/organizations/:orgId/accept`, for the caller's own membership only.
- [x] `05` and `06` pass.

### POST `/api/organizations/:orgId/leave`

- [x] Contract: no body, no response body read. Callers: the web vault filter and the CLI key-connector conversion.
- [x] Bruno: the last owner gets 400 (`07`); an unconfirmed account gets 400 (`08`); a confirmed member gets 200 (`09`), no longer sees the organization (`10`), and the organization is marked `keyRotationRequired` (`11`).
- [x] Route and handler, reusing `removeOrganizationUser` so leaving records the needed key rotation the same way as a removal.
- [x] `07` to `11` pass.

### Out of this phase

- [ ] POST `/organizations/:orgId/users/:membershipId/accept-init`: used only when an invite also creates the organization (`initOrganization` in the invite link), which NodeWarden does not do. Recorded so it is not mistaken for a gap.

## Acceptance criteria

- `npm run test:api -- 10-organization-member` passes with no skipped request.
- `npm run test:unit` and the existing organization checks still pass.
- An official client, unmodified, can read the keys, accept with an invite link and leave against a local Worker.

## Open questions

- Error status for an account that is not allowed to see the organization: the contract follows NodeWarden's existing 404; vaultwarden answers 400. The official server was not checked.

## References

- Coverage of every official client endpoint: `plans/reports/api-coverage-261109-2003-official-clients-endpoint-coverage.md`.
- vaultwarden `src/api/core/organizations.rs`: `leave_organization`, `get_organization_keys`, `post_org_keys`, `accept_invite`.
