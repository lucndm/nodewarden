# Organization admin console endpoints: current state

Status: state recorded. Not a compatibility target (decided 2026-11-09).

## Decisions (2026-11-09)

- The admin console that matters is NodeWarden's own web vault. The official
  web vault's admin console is not a target, so folders 51 to 55 are a record
  of the gap, not a backlog.
- `POST /ciphers/create` with `collectionIds` beside `cipher` is handled on
  its own, because it breaks plain members of every official client: branch
  `fix/cipher-create-collection-ids`.
- A member must accept an invitation before an admin confirms them: branch
  `feature/confirm-requires-accept`. NodeWarden's web vault invites without
  confirming, shows "Accepted" once the member answers, and offers the key
  only then.

## Outcome

Know how NodeWarden answers the admin console of the official web vault:
members, collections, groups, policies, organization settings and the admin
vault. This covers group 1b of
`plans/reports/api-coverage-261109-2003-official-clients-endpoint-coverage.md`
and the SDK admin cipher calls in its section "Endpoint do Rust SDK gọi".

## How the state was recorded

`api-tests/50-org-admin-setup` builds a second organization with NodeWarden's
own routes (owner, a confirmed member, an invited account, one collection),
so these folders do not depend on what `10-organization-member` does to the
first one. Run a folder with it, for example
`npm run test:api -- 50-org-admin-setup 52-org-collections`.

Run on 2026-11-09 against `origin/main` at `060500c`. The whole collection:
236 requests, 131 passing, 103 failing, 2 skipped; the failures per folder
match the folders run one by one.

| Folder | Requests | Passing | Failing |
|---|---|---|---|
| `51-org-members` | 16 | 2 | 14 |
| `52-org-collections` | 10 | 1 | 9 |
| `53-org-groups` | 9 | 3 | 6 |
| `54-org-policies-settings` | 10 | 2 | 8 |
| `55-org-vault-admin` | 14 | 1 | 13 |

NodeWarden runs organizations from its own web vault on routes of its own
(`/organizations/:id/users` to invite, `/users/public-key`, `/accept`,
`/rotate-key`, `/policies/<number>` with a flat body). Anything else under
`/organizations/:id/` reaches the 501 catch-all in `src/router-authenticated.ts`.
A fixed segment such as `/users/invite` also matches the `/users/:membershipId`
route and gets 404 "member not found"; the coverage report counted those as
routed, and these tests show they are not.

## State per area

### Members (`51-org-members`)

Works: `GET users` (but see the missing fields), `PUT users/:id` (role and
collection access), `DELETE users/:id`.

- [ ] `GET users`: each member lacks `name`, `twoFactorEnabled`, `hasMasterPassword`, `resetPasswordEnrolled` and `groups`, which the members page reads.
- [ ] 501: `GET users/:id`, `GET users/mini-details`, `POST users/:id/reinvite`, `PUT users/:id/revoke`, `PUT users/:id/restore/vnext`, `DELETE users` (bulk).
- [ ] 404 through the `/users/:membershipId` route: `POST users/invite`, `POST users/public-keys` (NodeWarden has `users/public-key` with `userIds`), `POST users/confirm` (bulk), `PUT users/revoke` and `PUT users/restore` (bulk), `PUT users/revoke-self`.

### Collections (`52-org-collections`)

Works: list and create. The create answer lacks `groups` and `users`.

- [ ] 501: `GET collections/details`, `GET collections/:id/details`, `GET collections/:id/users`, `PUT collections/:id`, `POST collections/bulk-access`, `GET collections/access`, `DELETE collections/:id`, `DELETE collections` (bulk).
- NodeWarden has no route at all, of its own or official, to rename or delete a collection; access is changed per member through `PUT users/:id`.

### Groups (`53-org-groups`)

Works: create (201, which the client accepts), list, delete.

- [ ] `PUT groups/:id` ignores `name`, and both create and update read the members from `members`, while the official `GroupRequest` sends `users`: a group made in the official web vault has no members.
- [ ] 501: `GET groups/details`, `GET groups/:id/details`, `GET groups/:id/users`, `DELETE groups/:id/user/:membershipId`, `DELETE groups` (bulk).

### Policies and organization settings (`54-org-policies-settings`)

Works: `GET policies`. NodeWarden refuses on purpose a policy it does not
enforce (only Send controls, type 21, is stored).

- [ ] `PUT policies/21`: the official body is `{ policy: { enabled, data }, metadata }`; NodeWarden reads `enabled` at the top level and answers 400.
- [ ] 501: `GET policies/:type`, `GET policies/master-password`, `GET organizations/:id`, `PUT organizations/:id`, `PUT organizations/:id/collection-management`, `GET organizations/:id/export`, `DELETE organizations/:id`.

### Admin console vault (`55-org-vault-admin`)

- [ ] `POST /ciphers/create`: the SDK sends `{ cipher, collectionIds }`; NodeWarden reads `collectionIds` from inside `cipher` and refuses with "A shared item must be placed in at least one collection". **An official client cannot create an organization item.** The folder then creates one in NodeWarden's shape so the next requests have an item.
- [ ] No route (404): `GET /ciphers/organization-details`, `/organization-details/assigned`, `GET /ciphers/:id/admin`, `POST /ciphers/admin`, `PUT /ciphers/:id/admin`, `/collections-admin`, `/delete-admin`, `/restore-admin`, `PUT /ciphers/delete-admin`, `/restore-admin`, `DELETE /ciphers/:id/admin`, `DELETE /ciphers/admin`.

### Not recorded, out of scope

Paid or enterprise features NodeWarden does not offer: billing (`cancel`,
`reinstate`, `seat`, `storage`, `upgrade`, `subscribe-secrets-manager`,
`create-without-payment`), Secrets Manager and PAM access (`enable-secrets-manager`,
`enable-pam`), directory import (`import`), organization SSO configuration
(`sso`), organization Duo (`two-factor/*`), the organization API key
(`api-key`, `rotate-api-key`), device approval by admins (`auth-requests`),
account recovery (`reset-password-enrollment`, `recover-account`,
`reset-password-details`, `account-recovery-details`), auto-confirm
(`auto-confirm`, `bulk-auto-confirm`, `pending-auto-confirm`,
`auto-enroll-status`), invite links (`invite-link/*`), the event log
(`audit`), `delete-recover-token` and `policies/token`.

## Open questions

None left from this group: the three questions it raised were decided on
2026-11-09 (see Decisions).
