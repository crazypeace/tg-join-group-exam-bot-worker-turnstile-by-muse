# Telegram 入群验证系统（Cloudflare Workers，无 KV）

入群自动禁言 → 私发验证链接（仅新成员可见）→ Telegram 登录确认身份 →
Turnstile 人机验证 → 自动解禁。封禁与解禁拆成两个 Worker，全程无状态。

> **部署说明**：本项目使用 Cloudflare `cf` CLI + `cloudflare.config.ts`
> 部署（`cf` CLI 文档：https://developers.cloudflare.com/cf/）。
> 公开变量写在各自的 `cloudflare.config.ts` 里，机密一律用
> `cf workers secrets update` 设置，**不要**写进配置文件或提交到 git。

## 架构

```
新成员入群
   │  Telegram webhook
   ▼
worker-a (封禁端)
   │ 1. chat_id 不在白名单 → bot 直接退群
   │ 2. 白名单群组 → restrictChatMember 禁言新成员
   │ 3. sendMessage + ephemeral_message_parameters 发验证链接
   │    （Bot API 10.2+ 的 ephemeral 消息，仅该成员和 bot 可见）
   ▼  https://worker-b/v?token=<HMAC签名>
worker-b (解禁端)
   │ 1. 验签链接 → Telegram OIDC 登录（确认登录账号 == 被禁言账号）
   │ 2. Turnstile 人机验证（服务端 siteverify）
   │ 3. restrictChatMember 恢复发言权限（解禁）
```

**无状态实现**：`token / OAuth state / 会话 token` 都是 HMAC-SHA256
签名的自包含 token（`base64url(JSON).base64url(HMAC)`），两个 worker 共用
同一个 `SIGNING_SECRET`。Turnstile token 天然一次性，防重放。
- **sess 绑定 IP**：`/auth/callback` 签发会话 token 时把当时的
  `CF-Connecting-IP` 写进签名里，`/api/verify` 提交时比对，不一致直接拒绝。
  这能挡掉"把 sess 转发给异地第三方代过验证"的朴素攻击。副作用：如果用户
  在登录和过验证之间切换了网络（WiFi→蜂窝），会触发 `ip_mismatch`，
  重新打开验证链接即可（链接有效期内）。
- **Turnstile hostname 校验**：`siteverify` 返回的 `hostname` 必须等于
  worker-b 自己的域名，否则拒绝，防别处解出的同 sitekey token 被拿来冒充。

## 一、准备工作

### 1. 创建 Bot（@BotFather）

1. `/newbot` 建 bot，拿到 **token**。
2. 记下 bot 的 **username** 和数字 **id**（token 里冒号前面的部分）。

### 2. 配置 Telegram Login（给 worker-b 用）

1. 打开 **@BotFather** 的 mini app（在聊天附件菜单里启动），选中你的 bot →
   **Login Widget**。如果 bot 还在旧版 widget，点
   **Switch to OpenID Connect Login** 并确认切换。
2. 配置下面两项（注意新版界面已经不叫 Allowed URLs 了）：
   - **Trusted Origins**：填 `https://tg-verify-b.<你的子域名>.workers.dev`
     （只填 origin，不要带路径、不要末尾斜杠）；
   - **Redirect URIs**：填 `https://tg-verify-b.<你的子域名>.workers.dev/auth/callback`
     （完整的回调地址；我们走的是服务端 OIDC authorization code 流程，这个必填）。
   两项都要求 HTTPS。
3. 记下 **Client ID**（一般就是 bot 的数字 id）和 **Client Secret**
  （注意：不是 bot token，是另一串独立的值）。

> 不配这一步，第 1 步的"使用 Telegram 登录"按钮会跳转失败。

### 3. 创建 Turnstile Widget

用 `cf` CLI 直接创建：

```bash
cf turnstile widgets create --body '{
  "name": "tg-verify-b 入群验证",
  "domains": ["tg-verify-b.<你的子域名>.workers.dev"],
  "mode": "managed"
}'
```

注意：

- `mode` 是 API 必填项，但 CLI 没有暴露对应的 flag，必须用 `--body` 传原始
  JSON；可选 `managed`（推荐，必要时才弹人机验证）、`non-interactive`、`invisible`。
- 返回的 JSON 里有 **Site key**（公开，填进 worker-b 的 `TURNSTILE_SITE_KEY`）
  和 **Secret key**（保密，**只在创建时返回一次**，立刻保存好，再用
  `cf workers secrets update TURNSTILE_SECRET_KEY --worker <worker-b名> --type secret_text`
  写入 worker-b）。
- 也可以在 Cloudflare Dashboard → Turnstile 里手动建，效果一样。

### 4. 生成随机密钥

```bash
openssl rand -hex 32   # -> SIGNING_SECRET（两个 worker 用同一个值）
openssl rand -hex 32   # -> WEBHOOK_SECRET_TOKEN（worker-a 用）
```

## 二、部署

```bash
# 安装 cf CLI（https://developers.cloudflare.com/cf/）后登录
cf auth login
```

### worker-a

```bash
cd worker-a
# 先改 cloudflare.config.ts 的 env: WORKER_B_URL / WHITELIST_CHAT_IDS
# 以下命令会交互式要求输入值（不会回显），不要写进文件
cf workers secrets update BOT_TOKEN --worker tg-verify-a --type secret_text
cf workers secrets update SIGNING_SECRET --worker tg-verify-a --type secret_text
cf workers secrets update WEBHOOK_SECRET_TOKEN --worker tg-verify-a --type secret_text
cf deploy
```

### worker-b

```bash
cd worker-b
# 先改 cloudflare.config.ts 的 env:
# WHITELIST_CHAT_IDS / TG_CLIENT_ID / TURNSTILE_SITE_KEY
cf workers secrets update BOT_TOKEN --worker tg-verify-b --type secret_text
cf workers secrets update SIGNING_SECRET --worker tg-verify-b --type secret_text   # 必须和 worker-a 相同
cf workers secrets update TG_CLIENT_SECRET --worker tg-verify-b --type secret_text
cf workers secrets update TURNSTILE_SECRET_KEY --worker tg-verify-b --type secret_text
cf deploy
```

### 设置 Telegram webhook（指向 worker-a）

> `WEBHOOK_SECRET_TOKEN` 是一个随机字符串（`openssl rand -hex 32` 生成），
> 设置 webhook 的 `secret_token` 必须和它完全一致。如果要更换，先执行
> `cf workers secrets update WEBHOOK_SECRET_TOKEN --worker tg-verify-a`
> （会交互式要求输入），再把**同一个值**填进下面的 `secret_token`。

```bash
curl -X POST "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://tg-verify-a.<你的子域名>.workers.dev/",
    "secret_token": "<WEBHOOK_SECRET_TOKEN>",
    "allowed_updates": ["message", "my_chat_member"]
  }'
```

`secret_token` 会让 Telegram 每次推送带上
`X-Telegram-Bot-Api-Secret-Token` 头，worker-a 会校验它，防伪造推送。

## 三、群组配置

1. 把 bot 拉进工作群组，设为**管理员**，勾选权限：
   - **封禁用户**（Ban users / can_restrict_members）——禁言/解禁必需；
   - 如果客户端里有**"发送欢迎消息"**（can_send_welcome_messages）也勾上，
     这是 Bot API 10.3 给 bot 发 ephemeral 消息用的管理权限。
2. 把群组的 `chat_id` 加进两边 `cloudflare.config.ts` 的 `WHITELIST_CHAT_IDS`
   （逗号分隔，重新 `cf deploy` 生效）。
   - 取 chat_id 方法：把 bot 拉进群后看 worker 日志，
     或用 @userinfobot / @getmyid_bot 查。

## 四、测试流程

1. 用一个小号加入群组 → 应被立即禁言（发不了言），并收到一条**仅自己可见**
   的验证消息（群里其他人看不到）。
2. 点链接 → 第 1 步用**被禁言的那个号**完成 Telegram 登录。
   - 故意用另一个号登录 → 应提示"账号不一致"，无法继续。
3. 第 2 步完成 Turnstile → 页面提示成功，群里自动解除禁言。
4. 异常测试：把 bot 拉进一个**不在白名单**的群 → bot 应自动退群。

## 五、注意事项与限制

- **无 KV 的取舍**：不存任何服务端状态。链接伪造靠 HMAC 签名防；
  Turnstile token 只能校验一次，天然防重放；链接默认 30 分钟过期
  （`VERIFY_TTL_SECONDS`）。
- **验证链接过期后**：被禁言的用户不会自动解禁，需要**退群重进**拿新链接
  （或管理员手动解禁）。
- **ephemeral 消息不保证送达**：按官方文档，如果用户当时离线可能收不到。
  用户上线后一般能在群里看到这条仅自己可见的消息。
- **禁言是永久的**（直到验证通过）：`restrictChatMember` 没有设 `until_date`。
  想加安全阀的话可以在 worker-a 里给禁言加 `until_date`。
- **解禁后的权限**在 worker-b 顶部 `UNMUTE_PERMISSIONS` 定义：
  恢复全部发言权限，改群资料/邀请/置顶/管理话题保持关闭，按需改。
- **白名单变更**：改 `WHITELIST_CHAT_IDS` 后两边都要重新 `cf deploy`。
- 两个 worker 的 `SIGNING_SECRET` 必须相同，否则 worker-b 验签失败。
- 机器人账号入群会被跳过（做不了人机验证）；已是管理员的入群者调
  `restrictChatMember` 会失败，worker-a 只记日志不阻断。
