<p align="center">
  <img src="./NodeWarden.svg" alt="NodeWarden Logo" />
</p>

<p align="center">
  运行在 Cloudflare Workers 上的 Bitwarden 兼容服务端
</p>

<p align="center">
  <a href="https://workers.cloudflare.com/"><img src="https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white" alt="Powered by Cloudflare" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-LGPL--3.0-2ea44f" alt="License: LGPL-3.0" /></a>
  <a href="https://github.com/shuaiplus/NodeWarden/releases/latest"><img src="https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag" alt="Latest Release" /></a>

</p>

<p align="center">
  <a href="https://t.me/NodeWarden_News">Telegram 频道</a> |
  <a href="https://t.me/NodeWarden_Official">Telegram 群组</a>
</p>

<p align="center">
  <a href="./README.md">English</a> |
  <a href="./CONTRIBUTING.md">贡献指南</a> |
  <a href="https://nodewarden.app">官方wiki</a>
</p>

> **免责声明**  
> 本项目仅供学习与交流使用，请定期备份你的密码库。  
> 本项目与 Bitwarden 官方无关，请不要向 Bitwarden 官方反馈 NodeWarden 的问题。

---

## 与 Bitwarden 官方服务端能力对比

| 能力 | Bitwarden免费版 | NodeWarden | 说明 |
|---|---|---|---|
| 网页密码库 | ✅ | ✅ | **原创Web Vault界面** |
| TOTP | ❌ | ✅ | 包括 `steam://` 支持 |
| **PWA / 离线使用** | ❌ | ✅ | **可安装、离线使用、App快捷方式** |
| **Passkey 登录** | ✅ | ✅ | **支持WebAuthn/FIDO2无密码登录** |
| API 密钥 | ✅ | ✅ | 供bitwarden cli使用，支持获取和轮换 |
| 登录 2FA | ✅ | ✅ | 支持 TOTP、YubiKey、Passkey |
| 2FA 恢复码 | ✅ | ✅ | 一次性恢复码用于禁用 2FA |
| 实时推送同步 | ✅ | ✅ | 网页端、浏览器扩展、电脑端和手机端实时同步 |
| 附件 / Send| ✅ | ✅ | Cloudflare R2 或 KV |
| 导入 / 导出 | ✅ | ✅ | 支持 Bitwarden JSON / CSV / **ZIP 导入（包括附件）** |
| **云端备份中心** | ❌ | ✅ | **支持 WebDAV / S3 定时增量备份** |
| 设备管理 | ✅ | ✅ | **删除设备、撤销信任、永久信任** |
| 登录请求 | ✅ | ✅ | **多端免密登录审批、跨设备解锁请求** |
| **多用户使用** | ✅ | ✅ | 支持邀请码注册 |
| 域名规则 | ✅ | ✅ | 自定义等效域名、全局域名排除 |
| Fill-assist | ✅ | ✅ | `POST /fill-assist` 辅助客户端自动填充；不能绕过保险库解锁 |
| 组织 / 集合 / 成员权限 | ✅ | ❌ | 未实现 |
| SSO（OIDC 单点登录） | ✅ | ✅ | 支持 Zitadel OIDC；需先绑定账号，暂无 SCIM / 企业目录同步 |

---

## 网页保险库使用统计

选择 **排序 → 最常使用**，按在 NodeWarden 网页保险库中成功复制当前登录密码的次数排序。登录条目详情显示复制次数及最后复制时间。复制用户名、TOTP、历史密码，或查看、显示密码均不计数；不统计官方扩展或应用自动填充，也不代表网站登录成功。

启用后从零开始计数，按条目保存在本实例的 D1 数据库，不发送至第三方分析服务。统计失败会提示，但不影响已完成的复制；离线或失败请求不会排队补报。数据库自动升级，云端备份保留统计，旧备份恢复为零次；永久删除条目时删除其统计。

## 网页密码库设计

网页密码库沿用 Proton Pass 的布局与视觉语言。桌面端为三栏结构：左侧合并应用导航与筛选项（全部条目、收藏、归档、回收站、重复项和条目类型）的导航栏、中间条目列表、右侧详情面板。条目操作按钮与条目标题并排，详情面板末尾是元数据分组，依次展示最后复制、最后编辑、创建时间与密码更新时间，下方是密码历史入口。

登录凭据与网站分别显示在带标题的卡片中；屏幕阅读器仍可读取分组名称。

桌面端搜索与创建按钮共用工作区顶栏；移动端在列表内搜索，并保留悬浮创建按钮。桌面端标签筛选与管理位于排序和同步按钮旁；移动端保留紧凑的标签筛选和标签管理侧栏。搜索会切换到“全部条目”。列表提供最近 30 天筛选、多选，以及按最近修改排序时的日期标记。编辑登录条目时，保存/取消位于顶部，网站字段单独分组；可按已保存的生成器设置直接生成密码，覆盖原密码前须确认。卡片、银行账户和历史密码默认隐藏，需逐项显示。将正常条目移入回收站可以恢复；仅回收站中的条目会被永久删除。标签用于整理条目，不是独立保险库。

密码健康检查仅在手动启动后运行。检查前风险数量未知；未完成的泄露查询标记为“未检查”，而非安全。报告仅保留在浏览器内存中，应用内导航可继续查看，刷新、密码库变更或锁定/退出后清除。电子邮件泄露监测会明确提示停用或失败状态；不会推断网站是否支持双重身份验证。

配色在浅色与深色主题下统一使用紫色交互色，深色主题为深紫蓝背景；界面使用细边框与扁平面板，不使用厚重阴影。筛选栏用左侧标记标出当前选中项，列表中的选中条目保留淡紫底色。

功能差距清单及 P0–P6 阶段计划参见 [NodeWarden × Proton Pass 路线图](ROADMAP.md)；路线图并不表示这些功能已实现。

## 已测试客户端

- ✅ Windows 桌面端
- ✅ 手机 App
- ✅ 浏览器扩展
- ✅ Linux 桌面端
- ⚠️ macOS 桌面端尚未完整验证

---

## 可视化快速部署

1. Fork NodeWarden 仓库到自己的 GitHub 账号
2. 进入 [Cloudflare Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create)
3. 选择 Continue with GitHub 并选择你的仓库
4. 构建命令填 `npm run build`，部署命令填 `npm run deploy`
- 如果你打算用 KV 模式，把部署命令改成 `npm run deploy:kv`
5. 等部署完成后，打开生成的 Workers 域名

- Workers 默认域名在部分网络环境不可直连。如需自定义域名，到 [Workers 设置](https://dash.cloudflare.com/?to=/:account/workers/services/view/nodewarden/production/settings)里添加。

- 页面提示缺少 `JWT_SECRET` 时，到 Workers 设置里添加 Secret。正式环境至少使用 32 个字符以上的随机字符串，不要使用临时值或示例值。

- 如需隐藏 Web Vault，在 Workers 的“设置 → 变量和机密”中添加文本变量 `HIDE_WEB_VAULT`，值设为 `1`。启用后，服务器上的前端页面和静态资源统一返回 `404 Not Found`，Bitwarden 客户端所需的登录、同步、附件、图标、通知等服务端接口仍可使用；已经安装或缓存的 PWA 可以继续使用本地前端。删除该变量（或将值改为非 `1`）即可恢复服务器上的 Web Vault。

- 这套流程里，用户实际做的是把代码交给 Cloudflare 构建并部署。代码里的 `wrangler.toml` 或 `wrangler.kv.toml` 决定绑定名，Worker 第一次处理请求时会自动初始化 D1 schema，不需要用户上传 SQL。


> [!TIP] 
> 默认R2与可选KV的区别：
>   | 储存 | 是否需绑卡 | 单个附件/Send文件上限 | 免费额度 |
>   |---|---|---|---|
>   | R2 | 需要 | 100 MB（软限制可更改） | 10 GB |
>   | KV | 不需要 | 25 MiB（Cloudflare限制） | 1 GB |


## Telegram 安全告警（可选）

NodeWarden 可以把安全事件推送到你指定的 Telegram 聊天。该功能默认关闭，需要配置两个 Worker Secret。

会推送两类事件：

- **新客户端**：某账号使用此前从未出现过的客户端标识成功登录，包含首次登录。
- **登录锁定**：触发了现有的登录锁定机制——10 次失败、锁定 2 分钟，按客户端来源、grant 类型和账号主体分别计数。

新客户端常常只是换了手机或浏览器；锁定也常常只是输错密码或客户端重试。这类告警只是一个提醒：它不做地理位置判断，也不代表真的遭到攻击。

> [!NOTE]
> Web SSO 每次登录都会生成新的客户端标识，因此每次成功的 Web SSO 登录都会被当作新客户端推送（仍受下面的冷却窗口限制）。

**消息包含哪些内容**
- 请求所访问的主机名（你的 Worker 或自定义域名）
- 事件类型
- 账号 ID 的前 8 位字符；无法解析到账号时为 `unknown`
- 认证方式，取自固定枚举：`password`、`webauthn`、`client_credentials`、`authorization_code`、`sso_oidc`，其余情况记为 `unknown`
- UTC 时间

消息中不包含邮箱、IP 地址、User-Agent、设备名称、凭据或令牌。

**推送频率**

- 每个账号、每种事件在 15 分钟窗口内最多一条；无法解析到账号的告警共用一个计数桶。
- 整个实例在 15 分钟窗口内最多 10 条。
- 窗口按固定时长切分，因此两条消息的间隔可能略小于 15 分钟。
- 额度用完后，后续事件会被丢弃：没有队列，也不会重试。

推送为尽力而为，超时 5 秒，失败不重试，所以某条消息可能丢失，该事件在当前窗口内也不会再补发。这类告警无法覆盖所有攻击，也不是 WAF 或 DDoS 告警系统。

**配置步骤**

1. 用 [@BotFather](https://t.me/BotFather) 创建机器人：发送 `/newbot` 并复制返回的 token。请把 token 当作密码保管：不要贴到 Telegram 聊天、代码仓库或 issue 里。
2. 打开你的机器人，在希望接收告警的私聊中发送 `/start`。只有和机器人对话过的聊天才能收到消息。
3. 通过 Bot API 获取 chat ID，同时避免把 token 留在 shell 历史里：

   ```bash
   read -rsp "Bot token: " TG_TOKEN; echo
   curl -s "https://api.telegram.org/bot${TG_TOKEN}/getUpdates" | jq -r '.result[-1].message.chat.id'
   unset TG_TOKEN
   ```

   打印出来的就是 chat ID（群组和频道为负数）。没有 `jq` 时，同一响应是 JSON，数值位于 `result[].message.chat.id`。chat ID 本身不是凭据，单凭它发不出任何消息；它只是指明告警要发到哪个会话，同样不要贴到聊天或仓库里。Windows 下可以用 `Read-Host -MaskInput` 读取 token 后在 PowerShell 里请求同一接口。

4. 把两个值保存为 Worker Secret：

   ```bash
   npx wrangler secret put TELEGRAM_BOT_TOKEN
   npx wrangler secret put TELEGRAM_CHAT_ID
   ```

   命令会提示输入并保存为 Cloudflare Secret，`wrangler.toml` 和仓库里都不会留下内容。如果本地没有 Wrangler 凭据，就到 **Workers → Settings → Variables and Secrets** 里把两个值都添加为 **Secret**（不要用明文变量）。

两个 Wrangler 配置均设置 `keep_vars = true`，部署时保留 Dashboard 文本变量。Telegram 两个值仍建议使用 Secret。若把 `TELEGRAM_CHAT_ID` 保存为 GitHub Actions 加密仓库 Secret，此 fork 的部署流程会先将它写入 Worker Secret；机器人 token 仍保存在 Cloudflare。

5. 运行中的 Worker 必须同时具备两个 Secret，并运行包含告警代码的版本；只配一个或不配都不会推送。此 fork 通过 `.github/workflows/deploy.yml` 自动部署推送到 `main` 的代码，请等待 **Deploy worker** 步骤成功。Secret 保存在 Cloudflare，不要复制到 GitHub 或 `wrangler.toml`。

如果没收到消息，请检查 chat ID 是否属于你发送 `/start` 的那个聊天、两个 Secret 是否仍在 **Variables and Secrets** 中，并注意冷却窗口：同一账号、同一事件类型在同一个 15 分钟窗口内的第二次事件会被有意静默。

部署后可用全新浏览器配置或无痕窗口，通过正常认证方式成功登录来验证推送。已有客户端重新登录或解锁保险库不会触发新客户端告警；Web SSO 会生成新客户端标识，也可以用成功的 SSO 登录验证。不要故意锁定生产账号。请确认 Telegram 实际收到消息；部署成功本身不能证明推送已送达。


## 常见问题：
- **Fork 完仓库后，在 Cloudflare 连接 GitHub 账户时看不到自己的仓库，或者选择仓库后返回 404？**  
  这通常与 GitHub Fork 仓库的识别或 Cloudflare 对仓库的授权/同步有关。如果 Fork 后仓库名称、描述等信息与上游项目高度一致，可能更容易触发相关限制或异常。建议在 Fork 时就将仓库名称修改为与上游不同的名称，并同时修改仓库描述，例如改为 `2233warden`。如果已经完成 Fork，也可以直接在 GitHub 仓库设置中修改名称和描述，然后重新尝试在 Cloudflare 中连接。

- **我删掉部署后重新部署，为什么注册又开始要求邀请码了？**  
  因为删除 Worker 或重新部署并不会自动删除已经创建的持久化数据。D1 数据库和 KV 命名空间中的用户、邀请码及相关配置仍然存在，因此重新部署后仍会读取原来的数据，并继续要求邀请码。  
  如果希望完全重新开始，需要同时删除对应的 **D1 数据库和 KV 命名空间**。

- **我配置了 `JWT_SECRET`，为什么页面仍然提示缺少？**  
  请将 `JWT_SECRET` 配置在 Cloudflare Workers 的 **Settings → Variables and Secrets** 中，并确保它属于 **Runtime variables and secrets**，而不是 **Build variables**。  
  Build 阶段的变量只在项目构建过程中可用，Worker 实际运行时无法通过运行时环境读取，因此即使构建能够正常完成，页面仍可能提示 `JWT_SECRET` 缺失。

- **为什么升级或重新部署后，`JWT_SECRET` 好像消失了？**  
  建议将 `JWT_SECRET` 配置为 **Secret**，而不是普通的明文变量。`JWT_SECRET` 属于敏感的运行时凭据，也不应该出现在代码仓库中。  
  如果部署流程会重新生成或覆盖 Worker 的变量配置，普通变量可能受到影响；使用 Secret 更适合保存这类需要在多次部署之间持续存在的敏感配置。重新部署后如果仍提示缺失，请检查当前 Worker 的 **Variables and Secrets** 中是否仍存在该 Secret。

---

## 更新方法：
- 手动：打开你 Fork 的 GitHub 仓库，看到顶部同步提示后，点击 `Sync fork` ➜ `Update branch`




## CLI 部署

```powershell
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

npm install
npx wrangler login

# 默认：R2 模式
npm run deploy

# 可选：KV 模式
npm run deploy:kv

# 本地开发
npm run dev
npm run dev:kv
```

---


## 开源协议

LGPL-3.0 License

---

## 致谢

- [Bitwarden](https://bitwarden.com/) - 原始设计与客户端
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - 服务端实现参考
- [Cloudflare Workers](https://workers.cloudflare.com/) - 无服务器平台

---

## 贡献者

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
