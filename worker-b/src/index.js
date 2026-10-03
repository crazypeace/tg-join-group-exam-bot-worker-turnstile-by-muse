// worker-b: Telegram 入群验证 —— 解禁端
//
// 流程:
//   GET  /v?token=...        校验 worker-a 签发的链接 -> 渲染第 1 步:Telegram 登录页
//   GET  /auth/callback      Telegram OIDC 回调 -> 换 id_token 并验签,
//                            确认登录账号 == 被禁言账号 -> 渲染第 2 步:Turnstile 页
//   POST /api/verify         校验 Turnstile + 会话 token -> 调用 restrictChatMember 解禁
//
// 无状态设计:不使用 KV。链接 token / OAuth state / 会话 token 全部是
// HMAC-SHA256 签名的自包含 token,防伪造;Turnstile token 天然一次性,防重放。

const LINK_GRACE_SECONDS = 900; // OAuth state 有效期(秒)
const SESS_TTL_SECONDS = 900; // Turnstile 会话 token 有效期(秒)

// 解禁权限:恢复全部发言权限,管理类权限保持关闭
const UNMUTE_PERMISSIONS = {
  can_send_messages: true,
  can_send_audios: true,
  can_send_documents: true,
  can_send_photos: true,
  can_send_videos: true,
  can_send_video_notes: true,
  can_send_voice_notes: true,
  can_send_polls: true,
  can_send_other_messages: true,
  can_add_web_page_previews: true,
  can_change_info: false,
  can_invite_users: false,
  can_pin_messages: false,
  can_manage_topics: false,
};

const te = new TextEncoder();
const td = new TextDecoder();

/* ---------------- base64url / html ---------------- */
function b64urlEncode(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  str = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
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

async function signRaw(body, secret) {
  const bodyB64 = b64urlEncode(te.encode(body));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, te.encode(bodyB64));
  return bodyB64 + "." + b64urlEncode(sig);
}

async function signToken(payload, secret) {
  return signRaw(JSON.stringify(payload), secret);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// 验签通过返回原始 body 字符串,失败返回 null
async function verifyRaw(token, secret) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [bodyB64, sigB64] = parts;
  let sig;
  try {
    sig = b64urlDecode(sigB64);
  } catch {
    return null;
  }
  const key = await hmacKey(secret);
  const expected = await crypto.subtle.sign("HMAC", key, te.encode(bodyB64));
  if (!timingSafeEqual(new Uint8Array(expected), sig)) return null;
  try {
    return td.decode(b64urlDecode(bodyB64));
  } catch {
    return null;
  }
}

// 验签通过返回 payload(JSON),失败返回 null(调用方再检查 exp 等字段)
async function verifyToken(token, secret) {
  const raw = await verifyRaw(token, secret);
  if (raw === null) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// PKCE verifier:由随机 nonce 经 HMAC 确定性派生(32 字节 -> 恰好 43 字符),
// 不需要放进 state,回调时用同样的 nonce 重新算出来即可
async function pkceVerifier(nonce, secret) {
  const key = await hmacKey(secret);
  const mac = await crypto.subtle.sign("HMAC", key, te.encode("tg-pkce-v1:" + nonce));
  return b64urlEncode(mac);
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

// 取用户真实出口 IP(Cloudflare 边缘传入)
function clientIp(request) {
  return (request.headers.get("CF-Connecting-IP") || "").trim() || null;
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

function randomString(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return b64urlEncode(arr).slice(0, len);
}

async function sha256B64url(str) {
  const d = await crypto.subtle.digest("SHA-256", te.encode(str));
  return b64urlEncode(d);
}

/* ---------------- Telegram OIDC id_token 校验 ---------------- */
let jwksCache = null; // { keys, fetchedAt } —— isolate 内尽力缓存

async function getJwks() {
  const now = Date.now();
  if (jwksCache && now - jwksCache.fetchedAt < 3600_000) return jwksCache.keys;
  const res = await fetch("https://oauth.telegram.org/.well-known/jwks.json");
  if (!res.ok) throw new Error("fetch JWKS failed");
  const jwks = await res.json();
  jwksCache = { keys: jwks.keys || [], fetchedAt: now };
  return jwksCache.keys;
}

// 校验 id_token 的 RS256 签名 + iss/aud/exp,返回 claims
async function verifyIdToken(idToken, clientId) {
  const parts = String(idToken).split(".");
  if (parts.length !== 3) throw new Error("bad id_token format");
  const [hB64, pB64, sB64] = parts;
  const header = JSON.parse(td.decode(b64urlDecode(hB64)));
  const payload = JSON.parse(td.decode(b64urlDecode(pB64)));
  const sig = b64urlDecode(sB64);

  const keys = await getJwks();
  const jwk = header.kid ? keys.find((k) => k.kid === header.kid) : keys[0];
  if (!jwk) throw new Error("no matching JWKS key");
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    sig,
    te.encode(`${hB64}.${pB64}`)
  );
  if (!ok) throw new Error("bad id_token signature");

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== "https://oauth.telegram.org") throw new Error("bad iss");
  if (String(payload.aud) !== String(clientId)) throw new Error("bad aud");
  if (typeof payload.exp !== "number" || payload.exp <= now)
    throw new Error("id_token expired");
  if (payload.iat && payload.iat > now + 300) throw new Error("bad iat");
  return payload;
}

/* ---------------- 页面 ---------------- */
const CSS = `
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;
       background:#f2f4f7;margin:0;padding:24px 12px;color:#222}
  .card{max-width:520px;margin:40px auto;background:#fff;border-radius:14px;
        padding:28px 24px;box-shadow:0 4px 24px rgba(0,0,0,.08)}
  h1{font-size:20px;margin:0 0 16px}
  p,li{font-size:15px;line-height:1.7}
  code{background:#f0f2f5;padding:2px 6px;border-radius:6px;font-size:13px}
  .btn{display:inline-block;margin-top:18px;background:#2aabee;color:#fff;text-decoration:none;
       padding:12px 28px;border-radius:10px;font-size:16px;font-weight:600}
  .btn:hover{background:#1d9bd8}
  .note{color:#888;font-size:13px;margin-top:16px}
  .err{color:#c0392b}
  .ok{color:#1e8e3e;font-weight:600}
  .cf-turnstile{margin:16px 0}
  #msg{margin-top:12px;font-size:15px;min-height:24px}
`;

function page(title, inner) {
  return new Response(
    `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">` +
      `<meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<title>${escHtml(title)}</title><style>${CSS}</style></head>` +
      `<body><div class="card">${inner}</div></body></html>`,
    { headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
}

function errorPage(msg) {
  return page(
    "验证失败",
    `<h1 class="err">❌ 验证失败</h1><p>${escHtml(msg)}</p>` +
      `<p class="note">如果是链接过期,请退群后重新加入以获取新的验证链接。</p>`
  );
}

/* ---------------- 路由处理 ---------------- */

// 第 1 步:校验验证链接 -> 渲染 Telegram 登录页
async function handleVerifyPage(request, env, url) {
  const now = Math.floor(Date.now() / 1000);
  const link = await verifyToken(url.searchParams.get("token"), env.SIGNING_SECRET);
  if (
    !link ||
    typeof link.u !== "number" ||
    typeof link.c !== "number" ||
    typeof link.exp !== "number" ||
    link.exp <= now
  ) {
    return errorPage("验证链接无效或已过期。");
  }

  // 白名单复核:链接里的群组必须仍在白名单里
  if (!parseWhitelist(env.WHITELIST_CHAT_IDS).has(link.c)) {
    return errorPage("该群组不在验证服务范围内。");
  }

  // 生成 OAuth state:Telegram /auth 要求 state 不超过 256 字符,
  // 因此 state 只带最少字段(u.c.exp.nonce 点分紧凑格式,签名后约 120 字符);
  // PKCE verifier 由 nonce 经 HMAC 确定性派生,不进 state,回调时重新算出
  const oauthNonce = randomString(16);
  const verifier = await pkceVerifier(oauthNonce, env.SIGNING_SECRET);
  const challenge = await sha256B64url(verifier);
  const state = await signRaw(
    `${link.u}.${link.c}.${now + LINK_GRACE_SECONDS}.${oauthNonce}`,
    env.SIGNING_SECRET
  );

  const origin = new URL(request.url).origin;
  const redirectUri = `${origin}/auth/callback`;
  const authUrl =
    "https://oauth.telegram.org/auth" +
    `?client_id=${encodeURIComponent(env.TG_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent("openid profile")}` +
    `&state=${encodeURIComponent(state)}` +
    `&code_challenge=${encodeURIComponent(challenge)}` +
    `&code_challenge_method=S256`;

  // 尽力获取群名称,失败就显示 chat_id
  let chatTitle = `群组 ${link.c}`;
  try {
    const ch = await tgApi(env, "getChat", { chat_id: link.c });
    if (ch && ch.title) chatTitle = ch.title;
  } catch (e) {
    console.error("getChat failed:", e.message);
  }

  const ttlMin = Math.round((parseInt(env.VERIFY_TTL_SECONDS || "", 10) || 1800) / 60);
  return page(
    "入群验证",
    `<h1>🔐 入群验证</h1>` +
      `<p>你正在为群组 <b>${escHtml(chatTitle)}</b> 进行入群验证。</p>` +
      `<p>你的 Telegram ID: <code>${link.u}</code>（当前已被禁言）</p>` +
      `<ol>` +
      `<li>点击下方按钮,使用<b>被禁言的那个 Telegram 账号</b>完成登录；</li>` +
      `<li>登录成功后,再完成一次人机验证；</li>` +
      `<li>全部通过后,系统会自动解除你的禁言。</li>` +
      `</ol>` +
      `<a class="btn" href="${escHtml(authUrl)}">使用 Telegram 登录</a>` +
      `<p class="note">验证链接 ${ttlMin} 分钟内有效,请勿分享给他人。<br>` +
      `登录的账号必须与被禁言的账号一致,否则无法通过验证。</p>`
  );
}

// Telegram OIDC 回调:换 id_token -> 验签 -> 确认身份一致 -> 渲染 Turnstile 页
async function handleCallback(request, env, url) {
  const now = Math.floor(Date.now() / 1000);
  const origin = new URL(request.url).origin;

  if (url.searchParams.get("error")) {
    return errorPage("你在 Telegram 侧拒绝了登录授权,验证已取消。");
  }
  const code = url.searchParams.get("code");
  const stateRaw = await verifyRaw(url.searchParams.get("state"), env.SIGNING_SECRET);
  let st = null;
  if (stateRaw) {
    const sp = stateRaw.split(".");
    if (sp.length === 4) {
      const u = Number(sp[0]);
      const c = Number(sp[1]);
      const exp = Number(sp[2]);
      if (Number.isFinite(u) && Number.isFinite(c) && Number.isFinite(exp)) {
        st = { u, c, exp, n: sp[3] };
      }
    }
  }
  if (!code || !st || st.exp <= now || !/^[A-Za-z0-9_-]{16}$/.test(st.n)) {
    return errorPage("登录会话无效或已过期,请重新打开验证链接。");
  }
  // 重新派生 PKCE verifier(与签发 state 时一致)
  const verifier = await pkceVerifier(st.n, env.SIGNING_SECRET);

  // 用 authorization code 换 id_token(服务端到服务端,带 client_secret)
  let tokenJson;
  try {
    const tokenRes = await fetch("https://oauth.telegram.org/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Basic " + btoa(`${env.TG_CLIENT_ID}:${env.TG_CLIENT_SECRET}`),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: `${origin}/auth/callback`,
        client_id: env.TG_CLIENT_ID,
        code_verifier: verifier,
      }),
    });
    tokenJson = await tokenRes.json().catch(() => ({}));
    if (!tokenRes.ok || !tokenJson.id_token) {
      throw new Error(tokenJson.error_description || tokenJson.error || `http ${tokenRes.status}`);
    }
  } catch (e) {
    console.error("OIDC token exchange failed:", e.message);
    return errorPage("Telegram 登录失败,请返回重新登录。");
  }

  // 校验 id_token 签名与声明
  let claims;
  try {
    claims = await verifyIdToken(tokenJson.id_token, env.TG_CLIENT_ID);
  } catch (e) {
    console.error("id_token verification failed:", e.message);
    return errorPage("Telegram 身份校验失败,请返回重新登录。");
  }

  // 关键检查:登录的 Telegram 账号必须 == 被禁言的账号
  const loginUserId = Number(claims.id);
  if (!Number.isFinite(loginUserId) || loginUserId !== st.u) {
    return errorPage(
      `登录的 Telegram 账号(ID ${Number.isFinite(loginUserId) ? loginUserId : "未知"})与被禁言的账号(ID ${st.u})不一致。` +
        `请使用被禁言的那个账号重新登录。`
    );
  }

  // 签发 Turnstile 会话 token,进入第 2 步
  const sess = await signToken(
    {
      u: st.u,
      c: st.c,
      tg: loginUserId, // 已确认身份的 Telegram ID
      ip: clientIp(request), // 绑定签发时的出口 IP,防 sess 被转发给异地第三方
      exp: now + SESS_TTL_SECONDS,
      n: crypto.randomUUID(),
    },
    env.SIGNING_SECRET
  );

  return page(
    "人机验证",
    `<h1>🤖 人机验证</h1>` +
      `<p>Telegram 身份已确认(ID: <code>${loginUserId}</code>)。<br>` +
      `请完成下方验证,通过后将自动解除禁言:</p>` +
      `<div class="cf-turnstile" data-sitekey="${escHtml(env.TURNSTILE_SITE_KEY)}" ` +
      `data-callback="onTsOk" data-error-callback="onTsErr"></div>` +
      `<p id="msg"></p>` +
      `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` +
      `<script>
        var SESS = ${JSON.stringify(sess)};
        var ERRMSG = {
          bad_session: '会话无效或已过期，请重新打开验证链接',
          missing_turnstile: '未获取到验证结果，请重试',
          ip_mismatch: '网络环境发生变化（IP 已变更），请重新打开验证链接',
          turnstile_failed: '人机验证未通过，请重试',
          turnstile_error: '验证服务异常，请稍后重试',
          turnstile_hostname_mismatch: '验证环境异常，请重新打开验证链接',
          unmute_failed: '解禁失败，请联系群管理员',
          chat_not_allowed: '该群组不在验证服务范围内'
        };
        function setMsg(html){ document.getElementById('msg').innerHTML = html; }
        async function onTsOk(token){
          setMsg('验证中,请稍候…');
          try{
            var r = await fetch('/api/verify',{
              method:'POST',
              headers:{'Content-Type':'application/json'},
              body: JSON.stringify({ sess: SESS, turnstile: token })
            });
            var j = await r.json();
            if(j && j.ok){
              setMsg('<span class="ok">✅ 验证通过,禁言已解除,欢迎回来！</span>');
            }else{
              var em = (j && j.error && ERRMSG[j.error]) || ((j && j.error) || '未知错误');
              setMsg('❌ 验证失败(' + em + '),请刷新页面重试。');
              if(window.turnstile) turnstile.reset();
            }
          }catch(e){
            setMsg('❌ 网络错误,请刷新页面重试。');
            if(window.turnstile) turnstile.reset();
          }
        }
        function onTsErr(){ setMsg('❌ 验证组件加载失败,请刷新页面重试。'); }
      </script>`
  );
}

// POST /api/verify:校验 Turnstile + 会话 token -> 解禁
async function handleApiVerify(request, env) {
  const now = Math.floor(Date.now() / 1000);

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "bad_request" }, { status: 400 });
  }

  const sess = await verifyToken(body && body.sess, env.SIGNING_SECRET);
  if (
    !sess ||
    typeof sess.u !== "number" ||
    typeof sess.c !== "number" ||
    typeof sess.tg !== "number" ||
    sess.tg !== sess.u || // 会话里记录的已验证身份必须与目标一致
    typeof sess.exp !== "number" ||
    sess.exp <= now
  ) {
    return Response.json({ ok: false, error: "bad_session" }, { status: 400 });
  }
  if (typeof body.turnstile !== "string" || !body.turnstile) {
    return Response.json({ ok: false, error: "missing_turnstile" }, { status: 400 });
  }

  // IP 绑定:提交 Turnstile 的出口 IP 必须与签发 sess 时一致,
  // 否则视为 sess 被转发给了第三方,直接拒绝(用户重开验证链接即可恢复)
  const curIp = clientIp(request);
  if (sess.ip && curIp && sess.ip !== curIp) {
    return Response.json({ ok: false, error: "ip_mismatch" });
  }

  // 白名单复核
  if (!parseWhitelist(env.WHITELIST_CHAT_IDS).has(sess.c)) {
    return Response.json({ ok: false, error: "chat_not_allowed" }, { status: 403 });
  }

  // 服务端校验 Turnstile(单次有效,天然防重放)
  let vj;
  try {
    const form = new URLSearchParams({
      secret: env.TURNSTILE_SECRET_KEY,
      response: body.turnstile,
    });
    const ip = request.headers.get("CF-Connecting-IP");
    if (ip) form.set("remoteip", ip);
    const vr = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form,
    });
    vj = await vr.json().catch(() => ({}));
  } catch (e) {
    console.error("turnstile siteverify failed:", e.message);
    return Response.json({ ok: false, error: "turnstile_error" });
  }
  if (!vj.success) {
    return Response.json({
      ok: false,
      error: "turnstile_failed",
      codes: vj["error-codes"] || [],
    });
  }

  // hostname 校验:token 必须是在本 worker-b 域名下解出的,
  // 防止有人拿着别处解出的同 sitekey token 来冒充
  const expectedHost = new URL(request.url).host;
  if (!vj.hostname || vj.hostname !== expectedHost) {
    console.error(`turnstile hostname mismatch: got ${vj.hostname}, want ${expectedHost}`);
    return Response.json({ ok: false, error: "turnstile_hostname_mismatch" });
  }

  // 解禁
  try {
    await tgApi(env, "restrictChatMember", {
      chat_id: sess.c,
      user_id: sess.u,
      permissions: UNMUTE_PERMISSIONS,
    });
  } catch (e) {
    console.error("unmute failed:", e.message);
    return Response.json({ ok: false, error: "unmute_failed" });
  }

  return Response.json({ ok: true });
}

/* ---------------- 入口 ---------------- */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/verify" && request.method === "POST") {
      return handleApiVerify(request, env);
    }
    if (url.pathname === "/auth/callback") {
      return handleCallback(request, env, url);
    }
    if (url.pathname === "/v") {
      return handleVerifyPage(request, env, url);
    }
    if (url.pathname === "/" && request.method === "GET") {
      return page(
        "Telegram 入群验证",
        `<h1>🤖 Telegram 入群验证服务</h1>` +
          `<p>这是入群验证的解禁端(worker-b)。验证链接由群管理 bot 在你入群时私发,</p>` +
          `<p>请直接点击群里的验证链接完成验证,无需在此操作。</p>`
      );
    }
    return new Response("Not Found", { status: 404 });
  },
};
