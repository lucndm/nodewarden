# Organization endpoints for members on the official paths

Status: contract written, implementation not started.

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
- [ ] Route and handler.
- [ ] `01` and `02` pass.

### POST `/api/organizations/:orgId/keys`

- [x] Contract: body `OrganizationKeysRequest` (`publicKey`, `encryptedPrivateKey`), response `OrganizationKeysResponse`. The only official caller is the self-hosted license upload.
- [x] Bruno: refused with 400 once the key pair exists (`03`); a plain member gets 404 (`04`).
- [ ] Route and handler. Every NodeWarden organization gets its key pair at creation, so the handler mostly refuses.
- [ ] `03` and `04` pass.

### POST `/api/organizations/:orgId/users/:membershipId/accept`

- [x] Contract: body `OrganizationUserAcceptRequest` (`token` required, `resetPasswordKey` only under account recovery auto-enrollment); no response body read. The client gets `organizationId`, `organizationUserId`, `email` and `token` from the invite link.
- [x] Bruno: a forged token is refused with 400 (`05`).
- [x] Bruno: the success path (`06`) is written and skipped until a token can be supplied with `--env-var inviteToken=...`.
- [ ] Decide how NodeWarden issues the invite token and the link, since it sends no email (see open questions).
- [ ] Have `00-setup` capture the token from the invite response, so `06` runs by default.
- [ ] Route and handler: verify the token's signature, expiry, email, organization and membership, then move the membership to accepted, as the NodeWarden route `/organizations/:orgId/accept` already does.
- [ ] `05` and `06` pass.

### POST `/api/organizations/:orgId/leave`

- [x] Contract: no body, no response body read. Callers: the web vault filter and the CLI key-connector conversion.
- [x] Bruno: the last owner gets 400 (`07`); an unconfirmed account gets 400 (`08`); a confirmed member gets 200 (`09`), no longer sees the organization (`10`), and the organization is marked `keyRotationRequired` (`11`).
- [ ] Route and handler, reusing `removeOrganizationUser` so leaving records the needed key rotation the same way as a removal.
- [ ] `07` to `11` pass.

### Out of this phase

- [ ] POST `/organizations/:orgId/users/:membershipId/accept-init`: used only when an invite also creates the organization (`initOrganization` in the invite link), which NodeWarden does not do. Recorded so it is not mistaken for a gap.

## Acceptance criteria

- `npm run test:api -- 10-organization-member` passes with no skipped request.
- `npm run test:unit` and the existing organization checks still pass.
- An official client, unmodified, can read the keys, accept with an invite link and leave against a local Worker.

## Open questions

- Invite token: sign one at invite time and return a Bitwarden-format invite link for the admin to pass on, as vaultwarden signs its claims, or something else? The contract only fixes that a forged token fails and a valid one succeeds.
- Error status for an account that is not allowed to see the organization: the contract follows NodeWarden's existing 404; vaultwarden answers 400. The official server was not checked.

## References

- Coverage of every official client endpoint: `plans/reports/api-coverage-261109-2003-official-clients-endpoint-coverage.md`.
- vaultwarden `src/api/core/organizations.rs`: `leave_organization`, `get_organization_keys`, `post_org_keys`, `accept_invite`.
