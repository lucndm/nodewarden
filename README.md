<p align="center">
  <img src="./NodeWarden.svg" alt="NodeWarden Logo" />
</p>

<p align="center">
  Bitwarden-compatible server running on Cloudflare Workers
</p>

<p align="center">
  <a href="https://workers.cloudflare.com/"><img src="https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white" alt="Powered by Cloudflare" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-LGPL--3.0-2ea44f" alt="License: LGPL-3.0" /></a>
  <a href="https://github.com/shuaiplus/NodeWarden/releases/latest"><img src="https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag" alt="Latest Release" /></a>

</p>

<p align="center">
  <a href="https://t.me/NodeWarden_News">Telegram Channel</a> |
  <a href="https://t.me/NodeWarden_Official">Telegram Group</a>
</p>

<p align="center">
  <a href="./README_ZH.md">中文</a> |
  <a href="./CONTRIBUTING.md">Contributing</a> |
  <a href="https://nodewarden.app">Official wiki</a>
</p>

> **Disclaimer**  
> This project is for learning and discussion purposes only. Please back up your vault regularly.  
> This project is not affiliated with Bitwarden. Please do not report NodeWarden issues to the official Bitwarden team.

---

## Feature comparison with the official Bitwarden server

| Feature | Bitwarden Free | NodeWarden | Notes |
|---|---|---|---|
| Web vault | ✅ | ✅ | **Original Web Vault UI** |
| TOTP | ❌ | ✅ | Includes `steam://` support |
| **PWA / offline** | ❌ | ✅ | **Installable, offline** |
| **Passkey login** | ✅ | ✅ | **passwordless auth** |
| API keys | ✅ | ✅ | CLI keys; create and rotate |
| Login 2FA | ✅ | ✅ | TOTP, YubiKey, Passkey |
| 2FA recovery codes | ✅ | ✅ | One-time 2FA disable codes |
| Real-time push sync | ✅ | ✅ | All device sync |
| Attachments / Send | ✅ | ✅ | Cloudflare R2 or KV |
| Import / export | ✅ | ✅ | Bitwarden JSON / CSV / **ZIP** |
| **Cloud backup center** | ❌ | ✅ | **Scheduled WebDAV / S3 incrementals** |
| Device management | ✅ | ✅ | **Remove devices; trust controls** |
| Login requests | ✅ | ✅ | **Cross-device login approval/unlock** |
| **Multi-user** | ✅ | ✅ | Invite-code registration |
| Domain rules | ✅ | ✅ | Equivalent domains, global exclusions |
| Fill-assist | ✅ | ✅ | `POST /fill-assist`|
| Organizations / collections / roles | ✅ | ❌ | Not implemented |
| SSO (OIDC) | ✅ | ✅ | Zitadel OIDC; account link required, no SCIM / directory sync |

---

## Web Vault usage metrics

Select **Sort → Most used** to rank items by successful copies of their current login password in the NodeWarden Web Vault. Login details show the copy count and last-copied time. Username, TOTP, password-history copies, views and reveals do not count; official extension/app autofill and successful website logins are not measured.

Counters start at zero when this feature is enabled and are stored per item in this instance’s D1 database, not sent to a third-party analytics service. Failed tracking shows a warning without undoing the copy; offline or failed requests are not queued. The schema upgrades automatically, cloud backups retain the counters, and older backups restore with zero counts. Permanent item deletion removes its metrics.

## Web Vault design

The Web Vault follows Proton Pass’s layout and visual language. The desktop vault is a three-pane layout: one navigation rail combining vault filters (all items, favorites, archive, trash, duplicates, item types and tags) with app links, an item list, and a detail pane. Item actions sit next to the item title, and the detail pane ends with a metadata group showing last copied, last edited, created and password-updated times above the password history entry point.

Login and autofill fields remain in separate cards without visible group headings; screen readers retain the group names.

Searching from a filtered list switches to All Items so matches across the active vault are visible. Create and edit show the title and main fields first, then Notes; Type and Tags follow in a metadata card. Creating an item focuses its title.

The colour system uses a violet interaction colour across both light and dark themes, with a navy-violet dark background, hairline borders and flat surfaces instead of heavy shadows. The filter rail marks the selected entry with a left edge marker, and the selected item in the list keeps a tinted fill.

## Tested clients

- ✅ Windows desktop
- ✅ Mobile app
- ✅ Browser extension
- ✅ Linux desktop
- ⚠️ macOS desktop not fully verified yet

---

## Visual quick deploy

1. Fork the NodeWarden repository to your GitHub account
2. Open [Cloudflare Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create)
3. Choose **Continue with GitHub** and select your fork
4. Set **build command** to `npm run build` and **deploy command** to `npm run deploy`
   - For KV mode, change the deploy command to `npm run deploy:kv`
5. After deployment finishes, open the generated Workers URL

- The default Workers hostname may be unreachable on some networks. To use a custom domain, add it in [Workers settings](https://dash.cloudflare.com/?to=/:account/workers/services/view/nodewarden/production/settings).

- If the site reports a missing `JWT_SECRET`, add it as a **Secret** in Workers settings. In production use a random string of at least 32 characters; do not use temporary or example values.

- To hide the Web Vault, add a text variable named `HIDE_WEB_VAULT` with the value `1` under **Workers settings → Variables and Secrets**. While enabled, server-hosted frontend pages and static assets return `404 Not Found`, while the login, sync, attachment, icon, notification, and other server endpoints used by Bitwarden clients remain available; an already installed or cached PWA can continue using its local frontend. Delete the variable (or change it to anything other than `1`) to restore the server-hosted Web Vault.

- In this flow you hand code to Cloudflare to build and deploy. `wrangler.toml` or `wrangler.kv.toml` in the repo defines binding names; the Worker initializes the D1 schema on first request—no manual SQL upload.


> [!TIP] 
> Default R2 vs optional KV:
>   | Storage | Card required | Max single attachment / Send file | Free tier |
>   |---|---|---|---|
>   | R2 | Yes | 100 MB (soft limit, adjustable) | 10 GB |
>   | KV | No | 25 MiB (Cloudflare limit) | 1 GB |


## Telegram security alerts (optional)

NodeWarden can post security events to a Telegram chat you choose. The feature is off by default and needs two Worker secrets.

Two events are reported:

- **New client** — a successful sign-in from a client identifier the account has never used before, including the very first login.
- **Login lockout** — the existing login lockout was triggered: 10 failed attempts, 2-minute lock, counted separately per client source, grant type, and account subject.

A new client is often just a new phone or a new browser, and a lockout is often a typo or a client retrying. These alerts are a heads-up channel: they do not detect geolocation and they are not proof of an attack.

> [!NOTE]
> Web SSO signs in with a freshly generated client identifier every time, so a successful web SSO login is reported as a new client (subject to the cooldown below).

**What a message contains**

- the hostname the request was served on (your Worker or custom domain)
- the event kind
- the account ID, first 8 characters only, or `unknown` when no account could be resolved
- the authentication method, taken from a fixed enum: `password`, `webauthn`, `client_credentials`, `authorization_code`, or `sso_oidc` — anything else is reported as `unknown`
- the time in UTC

Email addresses, IP addresses, user agents, device names, credentials, and tokens are never included.

**How often you are notified**

- At most one message per account and event kind per 15-minute window. Alerts that could not be resolved to an account share a single bucket.
- At most 10 messages per 15-minute window for the whole instance.
- The window is fixed, so two messages can arrive slightly closer together than 15 minutes apart.
- Once a budget is used up, further events are dropped — there is no queue and no retry.

Delivery is best effort with a 5-second timeout, and a failed send is never retried, so a message can be lost and the event then stays unreported for the rest of the window. These alerts do not detect every attack, and they are not a WAF or DDoS alerting system.

**Setup**

1. Create a bot with [@BotFather](https://t.me/BotFather): send `/newbot` and copy the token it returns. Treat the token like a password — never paste it into the Telegram chat, the repository, or an issue.
2. Open your bot in Telegram and send `/start` in the private chat that should receive the alerts. A bot can only post into chats that have started it.
3. Read the chat ID from the Bot API without leaving the token in your shell history:

   ```bash
   read -rsp "Bot token: " TG_TOKEN; echo
   curl -s "https://api.telegram.org/bot${TG_TOKEN}/getUpdates" | jq -r '.result[-1].message.chat.id'
   unset TG_TOKEN
   ```

   The printed value is the chat ID (negative for groups and channels). Without `jq`, the same response is JSON and the number sits under `result[].message.chat.id`. The chat ID on its own is not a credential — it cannot post anything — but it names the chat that receives your alerts, so keep it out of chat messages and the repository as well. On Windows, read the token with `Read-Host -MaskInput` and call the same endpoint from PowerShell.

4. Store both values as Worker secrets:

   ```bash
   npx wrangler secret put TELEGRAM_BOT_TOKEN
   npx wrangler secret put TELEGRAM_CHAT_ID
   ```

   Each command prompts for the value and stores it as a Cloudflare Secret; nothing is written to `wrangler.toml` or to the repository. If you have no local Wrangler credentials, add both under **Workers → Settings → Variables and Secrets** and mark them as **Secret** rather than plain-text variables.

Dashboard text variables are preserved during deployment (`keep_vars = true` in both Wrangler configurations). Prefer Secrets for both Telegram values. If `TELEGRAM_CHAT_ID` is supplied as an encrypted GitHub Actions repository secret, this fork’s deploy workflow installs it as a Worker Secret before deployment; the bot token stays in Cloudflare.

5. Both secrets must be present in the running Worker, and the Worker must run a version containing the alert code. With one secret or none, nothing is sent. This fork deploys pushes to `main` through `.github/workflows/deploy.yml`; wait for the **Deploy worker** step to succeed. Worker secrets stay in Cloudflare and must not be copied into GitHub or `wrangler.toml`.

If no message arrives, check that the chat ID belongs to the chat where you sent `/start`, that both secrets are still listed under **Variables and Secrets**, and remember the cooldown — a second event of the same kind for the same account inside the same 15-minute window is intentionally silent.

To verify delivery after deployment, sign in successfully from a fresh browser profile or an incognito window, using your normal authentication method. An existing client or a vault unlock does not trigger a new-client alert. Web SSO creates a fresh client identifier, so a successful SSO sign-in can also exercise this path. Do not deliberately lock out your production account. Check Telegram for the message; a successful deployment alone does not prove delivery.


## FAQ

- **After forking the repository, why can't I see my repository when connecting GitHub to Cloudflare, or why do I get a 404 after selecting it?**  
  This is usually related to how the GitHub fork is identified or how Cloudflare handles repository authorization and synchronization. If the fork keeps a repository name, description, or other information that is very similar to the upstream project, it may be more likely to trigger related restrictions or issues. It is recommended to rename the repository to something different from the upstream project when creating the fork, and change the repository description as well. For example, you can rename it to `2233warden`. If you have already created the fork, you can rename the repository and update its description in the GitHub repository settings, then try connecting it to Cloudflare again.

- **I deleted my deployment and redeployed it. Why does registration require an invite code again?**  
  Deleting the Worker or redeploying it does not automatically delete the persistent data that was already created. The users, invite codes, and related configuration stored in the D1 database and KV namespace are still there, so the newly deployed Worker continues to read the existing data and enforce the invite-code requirement.  
  If you want to start completely from scratch, you need to delete the corresponding **D1 database and KV namespace** as well.

- **I configured `JWT_SECRET`, but the page still says it is missing. Why?**  
  Make sure `JWT_SECRET` is configured under **Workers → Settings → Variables and Secrets**, specifically as a **Runtime variable or Secret**, rather than under **Build variables**.  
  Build-time variables are only available during the build process. They are not available to the Worker at runtime, so the build may succeed while the application still reports that `JWT_SECRET` is missing.

- **Why does `JWT_SECRET` seem to disappear after an upgrade or redeployment?**  
  It is recommended to store `JWT_SECRET` as a **Secret** rather than as a plain-text variable. `JWT_SECRET` is a sensitive runtime credential and should not be committed to the repository.  
  If your deployment process recreates or overwrites the Worker variable configuration, ordinary variables may be affected. Secrets are more appropriate for sensitive configuration that needs to remain available across multiple deployments. If the application still reports that `JWT_SECRET` is missing after a redeployment, check **Variables and Secrets** for the current Worker and make sure the Secret is still configured.

---

## How to update

- Manual: open your fork on GitHub; when the sync banner appears, click **Sync fork** → **Update branch**




## CLI deploy

```powershell
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

npm install
npx wrangler login

# Default: R2 mode
npm run deploy

# Optional: KV mode
npm run deploy:kv

# Local development
npm run dev
npm run dev:kv
```

---


## License

LGPL-3.0 License

---

## Credits

- [Bitwarden](https://bitwarden.com/) - Original design and clients
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - Server implementation reference
- [Cloudflare Workers](https://workers.cloudflare.com/) - Serverless platform

---

## Contributors

<a href="https://github.com/shuaiplus/nodewarden/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=shuaiplus/nodewarden" alt="NodeWarden contributors" />
</a>

## Star History

<a href="https://www.star-history.com/?repos=shuaiplus%2FNodeWarden&type=timeline&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=shuaiplus/NodeWarden&type=timeline&theme=dark&legend=top-left&sealed_token=ck0AMqR8EFMjJ6tMbnGDHT5QwMpO85IUuN7i8e82zRRNPtjoLsAAFwVzxmSZwaid97wLUwy56EEiVE9M-OY0cf16bQKBrU9GaauFoOFXGq-vMqcOyk0tIc4b3o1ZGfDw9IH8o6NUxC125TJkjKSLn9fxhFUUeNr1f1El0UcAUcjsMPl_LX80qQrlvQqp" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left&sealed_token=ck0AMqR8EFMjJ6tMbnGDHT5QwMpO85IUuN7i8e82zRRNPtjoLsAAFwVzxmSZwaid97wLUwy56EEiVE9M-OY0cf16bQKBrU9GaauFoOFXGq-vMqcOyk0tIc4b3o1ZGfDw9IH8o6NUxC125TJkjKSLn9fxhFUUeNr1f1El0UcAUcjsMPl_LX80qQrlvQqp" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left&sealed_token=ck0AMqR8EFMjJ6tMbnGDHT5QwMpO85IUuN7i8e82zRRNPtjoLsAAFwVzxmSZwaid97wLUwy56EEiVE9M-OY0cf16bQKBrU9GaauFoOFXGq-vMqcOyk0tIc4b3o1ZGfDw9IH8o6NUxC125TJkjKSLn9fxhFUUeNr1f1El0UcAUcjsMPl_LX80qQrlvQqp" />
 </picture>
</a>