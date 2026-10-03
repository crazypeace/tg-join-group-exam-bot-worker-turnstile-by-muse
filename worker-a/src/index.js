// worker-a: Telegram 入群验证 —— 封禁端
//
// 职责:
//   1. 接收 Telegram webhook 推送的 update
//   2. 新成员加入白名单群组 -> 调用 restrictChatMember 禁言,
//      再用 ephemeral message(仅该成员可见)发送指向 worker-b 的人机验证链接
//   3. 收到任何群组消息发现 chat_id 不在白名单 -> bot 主动退群
//
// 无状态设计:不使用 KV。验证链接是 HMAC-SHA256 签名的 token,
// 由 worker-b 验签,两个 worker 共用同一个 SIGNING_SECRET。

const DEFAULT_VERIFY_TTL = 1800; // 验证链接默认有效期(秒),可用 VERIFY_TTL_SECONDS 覆盖

// 禁言权限:全部关闭
const MUTE_PERMISSIONS = {
  can_send_messages: false,
  can_send_audios: false,
  can_send_documents: false,
  can_send_photos: false,
  can_send_videos: false,
  can_send_video_notes: false,
  can_send_voice_notes: false,
  can_send_polls: false,
  can_send_other_messages: false,
  can_add_web_page_previews: false,
  can_change_info: false,
  can_invite_users: false,
  can_pin_messages: false,
  can_manage_topics: false,
};

const te = new TextEncoder();
const td = new TextDecoder();

/* ---------------- base64url ---------------- */
function b64urlEncode(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ---------------- 签名 token ---------------- */
async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    te.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

// token = base64url(JSON) + "." + base64url(HMAC_SHA256(secret, base64url(JSON)))
async function signToken(payload, secret) {
  const body = b64urlEncode(te.encode(JSON.stringify(payload)));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, te.encode(body));
  return body + "." + b64urlEncode(sig);
}

/* ---------------- 工具 ---------------- */
function parseWhitelist(raw) {
  return new Set(
    (raw || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map(Number)
      .filter((n) => Number.isFinite(n))
  );
}

async function tgApi(env, method, params) {
  const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  const data = await res.json().catch(() => ({}));
  if (!data.ok) {
    throw new Error(
      `Telegram API ${method} failed: ${data.error_code || "?"} ${data.description || "unknown"}`
    );
  }
  return data.result;
}

// 从 update 里提取相关的 chat(用于白名单检查)
function extractChat(update) {
  const m =
    update.message ||
    update.edited_message ||
    update.channel_post ||
    update.edited_channel_post;
  if (m && m.chat) return m.chat;
  if (update.my_chat_member && update.my_chat_member.chat) return update.my_chat_member.chat;
  if (update.chat_member && update.chat_member.chat) return update.chat_member.chat;
  if (update.chat_join_request && update.chat_join_request.chat)
    return update.chat_join_request.chat;
  if (update.callback_query && update.callback_query.message && update.callback_query.message.chat)
    return update.callback_query.message.chat;
  return null;
}

function isGroupChat(chat) {
  return chat && (chat.type === "group" || chat.type === "supergroup");
}

/* ---------------- 新成员处理 ---------------- */
async function handleNewMember(env, chat, member) {
  if (member.is_bot) return; // 跳过机器人账号,它们做不了人机验证

  if (!env.WORKER_B_URL) throw new Error("WORKER_B_URL 未配置,无法签发验证链接");
  if (!env.SIGNING_SECRET) throw new Error("SIGNING_SECRET 未配置");

  const ttl = parseInt(env.VERIFY_TTL_SECONDS || "", 10) || DEFAULT_VERIFY_TTL;

  // 1) 先禁言
  await tgApi(env, "restrictChatMember", {
    chat_id: chat.id,
    user_id: member.id,
    permissions: MUTE_PERMISSIONS,
  });

  // 2) 签发验证链接并发 ephemeral 消息(仅该成员可见)
  const payload = {
    u: member.id, // user_id
    c: chat.id, // chat_id
    exp: Math.floor(Date.now() / 1000) + ttl,
    n: crypto.randomUUID(), // 随机 nonce,让每次签发的 token 都不同
  };
  const token = await signToken(payload, env.SIGNING_SECRET);
  const verifyUrl = `${env.WORKER_B_URL.replace(/\/+$/, "")}/v?token=${token}`;

  const name = escHtml(member.first_name || "新成员");
  const minutes = Math.round(ttl / 60);
  const text =
    `👋 你好,${name}!\n\n` +
    `欢迎加入本群。为防范广告机器人,入群需要完成一次<b>人机验证</b>。\n\n` +
    `你已被暂时禁言,请在 <b>${minutes} 分钟</b>内点击下面的链接完成验证,通过后会自动解除禁言:\n\n` +
    `👉 <a href="${escHtml(verifyUrl)}">点击进行人机验证</a>\n\n` +
    `<i>这条消息仅你可见,请勿转发给他人。</i>`;

  await tgApi(env, "sendMessage", {
    chat_id: chat.id,
    text,
    parse_mode: "HTML",
    // Bot API 10.2+ ephemeral 消息:仅 receiver_user_id 指定的用户(和 bot)可见
    ephemeral_message_parameters: { receiver_user_id: member.id },
  });
}

/* ---------------- 入口 ---------------- */
export default {
  async fetch(request, env, ctx) {
    if (request.method === "GET") {
      return new Response("tg-verify-a ok", { status: 200 });
    }
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // webhook 鉴权:必须携带 setWebhook 时设置的 secret_token
    const secretHeader = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
    if (!env.WEBHOOK_SECRET_TOKEN || secretHeader !== env.WEBHOOK_SECRET_TOKEN) {
      return new Response("Forbidden", { status: 403 });
    }

    let update;
    try {
      update = await request.json();
    } catch {
      return new Response("Bad Request", { status: 400 });
    }

    const whitelist = parseWhitelist(env.WHITELIST_CHAT_IDS);

    try {
      const chat = extractChat(update);

      // 异常处理:非白名单群组 -> bot 直接退群
      if (isGroupChat(chat) && !whitelist.has(chat.id)) {
        await tgApi(env, "leaveChat", { chat_id: chat.id });
        return Response.json({ ok: true });
      }

      // 正常流程:白名单群组有新成员加入 -> 逐个禁言 + 发验证链接
      const msg = update.message;
      if (
        msg &&
        isGroupChat(msg.chat) &&
        whitelist.has(msg.chat.id) &&
        Array.isArray(msg.new_chat_members)
      ) {
        for (const member of msg.new_chat_members) {
          try {
            await handleNewMember(env, msg.chat, member);
          } catch (e) {
            // 单个成员处理失败不影响其他人,记日志即可
            // (常见原因:bot 不是管理员 / 对方是管理员无法被禁言)
            console.error(`handle new member ${member && member.id} failed:`, e.message);
          }
        }
      }
    } catch (e) {
      console.error("update handling failed:", e.message);
    }

    // 始终返回 200,避免 Telegram 反复重试
    return Response.json({ ok: true });
  },
};
