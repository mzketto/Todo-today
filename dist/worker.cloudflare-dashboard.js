/**
 * 今日待办 · 单文件版（供 Cloudflare 网页控制台直接粘贴部署）
 *
 * ⚠️ 这是自动生成的文件，请勿手动修改。
 *    源码在 src/ 与 public/，改完执行：npm run build:dashboard
 *
 * 生成时间：2026-10-16T06:19:57.579Z
 * 内联静态资源：/app.js, /icon.svg, /index.html, /manifest.webmanifest, /style.css
 *
 * 部署要点：
 *   D1 绑定名必须是 DB
 *   R2 绑定名必须是 BACKUPS（可选，用于原生云备份）
 *   变量：APP_NAME / ALLOW_REGISTRATION
 *   密钥：BACKUP_S3_SECRET_KEY / BACKUP_WEBDAV_PASSWORD（可选）
 */

/* ================================================================ *
 * src/lib/crypto.js
 * ================================================================ */

/**
 * 加密工具：全部基于 WebCrypto，Workers 运行时原生可用，无需额外依赖。
 *  - PBKDF2-SHA256 派生口令哈希（10 万次迭代 + 16 字节随机盐）
 *  - 定长比较，避免时序侧信道
 *  - 随机 ID / Token
 */

const encoder = new TextEncoder();

const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEY_BYTES = 32;

function toHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function fromHex(hex) {
  const clean = String(hex || '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

/** 生成随机 hex 串，len 为字节数（输出长度为 2*len） */
function randomHex(len = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return toHex(bytes);
}

function newId(prefix = '') {
  return `${prefix}${Date.now().toString(36)}${randomHex(6)}`;
}

/** 派生口令哈希，salt 为空时自动生成 */
async function hashPassword(password, saltHex = null) {
  const salt = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(String(password)),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    PBKDF2_KEY_BYTES * 8,
  );
  return { hash: toHex(new Uint8Array(bits)), salt: toHex(salt) };
}

/** 定长比较（hex 字符串） */
function safeEqualHex(a, b) {
  const x = String(a || '');
  const y = String(b || '');
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

async function verifyPassword(password, hashHex, saltHex) {
  if (!hashHex || !saltHex) return false;
  const { hash } = await hashPassword(password, saltHex);
  return safeEqualHex(hash, hashHex);
}

/* ---------- S3 SigV4 需要的哈希原语 ---------- */

async function sha256Hex(data) {
  const buf = typeof data === 'string' ? encoder.encode(data) : data;
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return toHex(new Uint8Array(digest));
}

async function hmacSha256(keyBytes, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const msg = typeof message === 'string' ? encoder.encode(message) : message;
  const sig = await crypto.subtle.sign('HMAC', key, msg);
  return new Uint8Array(sig);
}

/** Basic Auth 头，UTF-8 安全（先转 Latin-1 再 btoa） */
function basicAuthHeader(username, password) {
  const bytes = encoder.encode(`${username}:${password}`);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return `Basic ${btoa(binary)}`;
}

/* ================================================================ *
 * src/lib/http.js
 * ================================================================ */

/**
 * HTTP 小工具：统一 JSON 响应、Cookie 读写。
 */

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
};

function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    status: init.status || 200,
    headers: { ...JSON_HEADERS, ...(init.headers || {}) },
  });
}

/** 成功响应：{ ok: true, ...data } */
function ok(data = null) {
  return json(data === null ? { ok: true } : { ok: true, ...data });
}

/** 失败响应：{ ok: false, error } */
function fail(message, status = 400) {
  return json({ ok: false, error: message }, { status });
}

async function readJson(request) {
  try {
    const data = await request.json();
    return data && typeof data === 'object' && !Array.isArray(data) ? data : {};
  } catch {
    return {};
  }
}

function parseCookies(request) {
  const raw = request.headers.get('cookie') || '';
  const out = {};
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    const key = part.slice(0, i).trim();
    if (!key) continue;
    const value = part.slice(i + 1).trim();
    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }
  return out;
}

function serializeCookie(name, value, opts = {}) {
  let str = `${name}=${encodeURIComponent(value)}`;
  if (opts.maxAge != null) str += `; Max-Age=${Math.floor(opts.maxAge)}`;
  if (opts.path) str += `; Path=${opts.path}`;
  if (opts.httpOnly) str += '; HttpOnly';
  if (opts.secure) str += '; Secure';
  if (opts.sameSite) str += `; SameSite=${opts.sameSite}`;
  return str;
}

/** 仅本机 http 才不加 Secure，其余一律加，防止 Cookie 被明文传输。 */
function isSecureRequest(request) {
  try {
    const url = new URL(request.url);
    if (url.protocol !== 'https:') return false;
    return !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  } catch {
    return true;
  }
}

/* ================================================================ *
 * src/lib/assets.js
 * ================================================================ */

/**
 * 静态资源内联表 —— 为「不用命令行、只在 Cloudflare 网页控制台部署」准备。
 *
 * 两种部署方式：
 *
 *  1. wrangler / Workers Builds 部署（推荐）
 *     public/ 目录由 `assets` 配置托管，env.ASSETS 生效，
 *     此文件保持 INLINE_ASSETS = null，完全不会被用到。
 *
 *  2. 纯网页控制台部署（单文件粘贴）
 *     网页编辑器不支持配置 `assets`，也不支持上传静态文件。
 *     因此 scripts/build-dashboard.mjs 会把 public/ 下的文件
 *     以 base64 打进 dist/worker.cloudflare-dashboard.js，
 *     由 Worker 自己返回这些资源。
 */

/* BUILD_MARKER:INLINE_ASSETS_B64 —— 打包脚本会替换下面这一行 */
const INLINE_ASSETS_B64 = {
  "/app.js": {
    type: "text/javascript; charset=utf-8",
    body:
      "LyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAqIOS7iuaXpeW+" +
      "heWKniDCtyDliY3nq6/pgLvovpHvvIjpm7bkvp3otZbvvIzml6DmnoTlu7rvvIkKICoKICogIC0g6buY6K6k6LWw55yf5a6e5ZCO" +
      "56uvIC9hcGkvKgogKiAgLSDoi6Xmo4DmtYvliLDlkI7nq6/kuI3lj6/nlKjvvIjkvovlpoLnm7TmjqXmiZPlvIDpnZnmgIHmlofk" +
      "u7bpooTop4jvvInvvIzoh6rliqjpmY3nuqfkuLoKICogICAg44CM5ryU56S65qih5byP44CN77yM55SoIGxvY2FsU3RvcmFnZSDm" +
      "qKHmi5/lrozmlbTlkI7nq6/vvIzmlrnkvr/mnKzlnLDmn6XnnIvnlYzpnaLjgIIKICogPT09PT09PT09PT09PT09PT09PT09PT09" +
      "PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCgooKCkgPT4gewogICd1c2Ugc3RyaWN0JzsKCiAgY29uc3Qg" +
      "QVBJX0JBU0UgPSAnL2FwaSc7CiAgY29uc3QgQVBQX1ZFUlNJT04gPSAnMS4wLjAnOwogIGNvbnN0IFVSTF9QQVJBTVMgPSBuZXcg" +
      "VVJMU2VhcmNoUGFyYW1zKGxvY2F0aW9uLnNlYXJjaCk7CiAgLyoqID9kZW1vPTEg55u05o6l6L+b5YWl5ryU56S65qih5byP5bm2" +
      "54GM5YWl56S65L6L5pWw5o2u77yM55So5LqO5peg5ZCO56uv5pe26aKE6KeI55WM6Z2iICovCiAgY29uc3QgRk9SQ0VfREVNTyA9" +
      "IFVSTF9QQVJBTVMuZ2V0KCdkZW1vJykgPT09ICcxJzsKCiAgLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiBET00g5byV55SoCiAgICogLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgY29uc3QgJCA9IChpZCkgPT4gZG9jdW1l" +
      "bnQuZ2V0RWxlbWVudEJ5SWQoaWQpOwoKICBjb25zdCBlbCA9IHsKICAgIGJvb3Q6ICQoJ2Jvb3QnKSwKICAgIGF1dGhWaWV3OiAk" +
      "KCdhdXRoLXZpZXcnKSwKICAgIG1haW5WaWV3OiAkKCdtYWluLXZpZXcnKSwKICAgIGF1dGhGb3JtOiAkKCdhdXRoLWZvcm0nKSwK" +
      "ICAgIGF1dGhVc2VybmFtZTogJCgnYXV0aC11c2VybmFtZScpLAogICAgYXV0aFBhc3N3b3JkOiAkKCdhdXRoLXBhc3N3b3JkJyks" +
      "CiAgICBhdXRoRXJyb3I6ICQoJ2F1dGgtZXJyb3InKSwKICAgIGF1dGhTdWJtaXQ6ICQoJ2F1dGgtc3VibWl0JyksCiAgICBhdXRo" +
      "U3VibWl0TGFiZWw6ICQoJ2F1dGgtc3VibWl0LWxhYmVsJyksCiAgICB0b2dnbGVQYXNzd29yZDogJCgndG9nZ2xlLXBhc3N3b3Jk" +
      "JyksCiAgICB0YWJzOiBBcnJheS5mcm9tKGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy50YWInKSksCgogICAgcGFnZVRpdGxl" +
      "OiAkKCdwYWdlLXRpdGxlJyksCiAgICBwYWdlRGF0ZTogJCgncGFnZS1kYXRlJyksCiAgICB0aGVtZVRvZ2dsZTogJCgndGhlbWUt" +
      "dG9nZ2xlJyksCiAgICB1c2VyTWVudTogJCgndXNlci1tZW51JyksCiAgICB1c2VySW5pdGlhbDogJCgndXNlci1pbml0aWFsJyks" +
      "CiAgICBkZW1vQmFubmVyOiAkKCdkZW1vLWJhbm5lcicpLAogICAgZGVtb0Jhbm5lckNsb3NlOiAkKCdkZW1vLWJhbm5lci1jbG9z" +
      "ZScpLAoKICAgIHByZXZEYXk6ICQoJ3ByZXYtZGF5JyksCiAgICBuZXh0RGF5OiAkKCduZXh0LWRheScpLAogICAgZGF0ZVBpbGw6" +
      "ICQoJ2RhdGUtcGlsbCcpLAogICAgZGF0ZVBpbGxUZXh0OiAkKCdkYXRlLXBpbGwtdGV4dCcpLAoKICAgIGFkZEZvcm06ICQoJ2Fk" +
      "ZC1mb3JtJyksCiAgICBhZGRJbnB1dDogJCgnYWRkLWlucHV0JyksCiAgICBhZGRIaW50OiAkKCdhZGQtaGludCcpLAogICAgY29t" +
      "cG9zZXJEYXRlOiAkKCdjb21wb3Nlci1kYXRlJyksCiAgICBjb21wb3NlckRhdGVUZXh0OiAkKCdjb21wb3Nlci1kYXRlLXRleHQn" +
      "KSwKCiAgICAvLyDml6XmnJ/pgInmi6nlvLnlsYIKICAgIGRhdGVQb3A6ICQoJ2RhdGUtcG9wJyksCiAgICBwb3BZZWFyOiAkKCdw" +
      "b3AteWVhcicpLAogICAgcG9wTW9udGg6ICQoJ3BvcC1tb250aCcpLAogICAgcG9wR3JpZDogJCgncG9wLWdyaWQnKSwKCiAgICAv" +
      "LyDkvqfmoI8KICAgIHNpZGViYXI6ICQoJ3NpZGViYXInKSwKICAgIHNpZGVNYXNrOiAkKCdzaWRlLW1hc2snKSwKICAgIHNpZGVU" +
      "b2dnbGU6ICQoJ3NpZGUtdG9nZ2xlJyksCiAgICBzZWFyY2hJbnB1dDogJCgnc2VhcmNoLWlucHV0JyksCiAgICBzZWFyY2hDbGVh" +
      "cjogJCgnc2VhcmNoLWNsZWFyJyksCiAgICBzdGF0RGF5czogJCgnc3RhdC1kYXlzJyksCiAgICBzdGF0VG90YWw6ICQoJ3N0YXQt" +
      "dG90YWwnKSwKICAgIHN0YXREb25lOiAkKCdzdGF0LWRvbmUnKSwKICAgIGNhbFRpdGxlOiAkKCdjYWwtdGl0bGUnKSwKICAgIGNh" +
      "bFByZXY6ICQoJ2NhbC1wcmV2JyksCiAgICBjYWxOZXh0OiAkKCdjYWwtbmV4dCcpLAogICAgY2FsZW5kYXI6ICQoJ2NhbGVuZGFy" +
      "JyksCiAgICB0YWdzQmxvY2s6ICQoJ3RhZ3MtYmxvY2snKSwKICAgIHRhZ3NMaXN0OiAkKCd0YWdzLWxpc3QnKSwKICAgIHRpbWVs" +
      "aW5lQmxvY2s6ICQoJ3RpbWVsaW5lLWJsb2NrJyksCiAgICB0aW1lbGluZUxpc3Q6ICQoJ3RpbWVsaW5lLWxpc3QnKSwKCiAgICAv" +
      "LyDljaHniYfmtYEKICAgIGZlZWQ6ICQoJ2ZlZWQnKSwKICAgIHNlYXJjaEJhbm5lcjogJCgnc2VhcmNoLWJhbm5lcicpLAogICAg" +
      "c2VhcmNoQmFubmVyVGV4dDogJCgnc2VhcmNoLWJhbm5lci10ZXh0JyksCiAgICBzZWFyY2hFeGl0OiAkKCdzZWFyY2gtZXhpdCcp" +
      "LAogICAgZW1wdHlTdGF0ZTogJCgnZW1wdHktc3RhdGUnKSwKICAgIGVtcHR5VGl0bGU6ICQoJ2VtcHR5LXRpdGxlJyksCiAgICBl" +
      "bXB0eVN1YjogJCgnZW1wdHktc3ViJyksCiAgICByZW1haW5pbmdDb3VudDogJCgncmVtYWluaW5nLWNvdW50JyksCiAgICByZW1h" +
      "aW5pbmdMYWJlbDogJCgncmVtYWluaW5nLWxhYmVsJyksCiAgICBjYXJyeW92ZXJCdG46ICQoJ2NhcnJ5b3Zlci1idG4nKSwKICAg" +
      "IGNsZWFyRG9uZUJ0bjogJCgnY2xlYXItZG9uZS1idG4nKSwKCiAgICBkcmF3ZXJNYXNrOiAkKCdkcmF3ZXItbWFzaycpLAogICAg" +
      "ZHJhd2VyQ2xvc2U6ICQoJ2RyYXdlci1jbG9zZScpLAogICAgYWNjb3VudE5hbWU6ICQoJ2FjY291bnQtbmFtZScpLAogICAgbG9n" +
      "b3V0QnRuOiAkKCdsb2dvdXQtYnRuJyksCgogICAgcHdkQ3VycmVudDogJCgncHdkLWN1cnJlbnQnKSwKICAgIHB3ZE5ldzogJCgn" +
      "cHdkLW5ldycpLAogICAgcHdkU3VibWl0OiAkKCdwd2Qtc3VibWl0JyksCgogICAgYmFja3VwUHJvdmlkZXI6ICQoJ2JhY2t1cC1w" +
      "cm92aWRlcicpLAogICAgYmFja3VwRW5hYmxlZDogJCgnYmFja3VwLWVuYWJsZWQnKSwKICAgIGJhY2t1cEF1dG86ICQoJ2JhY2t1" +
      "cC1hdXRvJyksCiAgICBiYWNrdXBQYW5lbHM6IEFycmF5LmZyb20oZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnByb3ZpZGVy" +
      "LXBhbmVsJykpLAogICAgcjJLZXk6ICQoJ3IyLWtleScpLAogICAgczNFbmRwb2ludDogJCgnczMtZW5kcG9pbnQnKSwKICAgIHMz" +
      "UmVnaW9uOiAkKCdzMy1yZWdpb24nKSwKICAgIHMzQnVja2V0OiAkKCdzMy1idWNrZXQnKSwKICAgIHMzQWtpZDogJCgnczMtYWtp" +
      "ZCcpLAogICAgczNTZWNyZXQ6ICQoJ3MzLXNlY3JldCcpLAogICAgczNQcmVmaXg6ICQoJ3MzLXByZWZpeCcpLAogICAgczNGaWxl" +
      "OiAkKCdzMy1maWxlJyksCiAgICBzM1BhdGhTdHlsZTogJCgnczMtcGF0aHN0eWxlJyksCiAgICBkYXZVcmw6ICQoJ2Rhdi11cmwn" +
      "KSwKICAgIGRhdlVzZXI6ICQoJ2Rhdi11c2VyJyksCiAgICBkYXZQYXNzOiAkKCdkYXYtcGFzcycpLAogICAgZGF2RmlsZTogJCgn" +
      "ZGF2LWZpbGUnKSwKICAgIGJhY2t1cFRlc3Q6ICQoJ2JhY2t1cC10ZXN0JyksCiAgICBiYWNrdXBTYXZlOiAkKCdiYWNrdXAtc2F2" +
      "ZScpLAogICAgYmFja3VwUnVuOiAkKCdiYWNrdXAtcnVuJyksCiAgICBiYWNrdXBSZXN0b3JlOiAkKCdiYWNrdXAtcmVzdG9yZScp" +
      "LAogICAgYmFja3VwU3RhdHVzOiAkKCdiYWNrdXAtc3RhdHVzJyksCiAgICBiYWNrdXBTdGFtcDogJCgnYmFja3VwLXN0YW1wJyks" +
      "CiAgICBiYWNrdXBTdGFtcEhpbnQ6ICQoJ2JhY2t1cC1zdGFtcC1oaW50JyksCiAgICBiYWNrdXBJbnRlcnZhbDogJCgnYmFja3Vw" +
      "LWludGVydmFsJyksCiAgICBiYWNrdXBJbnRlcnZhbEZpZWxkOiAkKCdiYWNrdXAtaW50ZXJ2YWwtZmllbGQnKSwKICAgIGJhY2t1" +
      "cEludGVydmFsSGludDogJCgnYmFja3VwLWludGVydmFsLWhpbnQnKSwKICAgIGJhY2t1cFNjaGVkdWxlZDogJCgnYmFja3VwLXNj" +
      "aGVkdWxlZCcpLAogICAgYmFja3VwUGVyaW9kOiAkKCdiYWNrdXAtcGVyaW9kJyksCiAgICBiYWNrdXBQZXJpb2RGaWVsZDogJCgn" +
      "YmFja3VwLXBlcmlvZC1maWVsZCcpLAogICAgYmFja3VwQ3JvbkhpbnQ6ICQoJ2JhY2t1cC1jcm9uLWhpbnQnKSwKICAgIGxhc3RC" +
      "YWNrdXBMaW5lOiAkKCdsYXN0LWJhY2t1cC1saW5lJyksCgogICAgZXhwb3J0QnRuOiAkKCdleHBvcnQtYnRuJyksCiAgICBpbXBv" +
      "cnRCdG46ICQoJ2ltcG9ydC1idG4nKSwKICAgIGltcG9ydEZpbGU6ICQoJ2ltcG9ydC1maWxlJyksCiAgICBhYm91dFZlcnNpb246" +
      "ICQoJ2Fib3V0LXZlcnNpb24nKSwKCiAgICB0b2FzdEhvc3Q6ICQoJ3RvYXN0LWhvc3QnKSwKICB9OwoKICAvKiAtLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKgogICAqIOW6lOeUqOeKtuaA" +
      "gQogICAqIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAq" +
      "LwogIGNvbnN0IHN0YXRlID0gewogICAgdXNlcjogbnVsbCwKICAgIGRhdGU6IHRvZGF5U3RyKCksCiAgICB0b2RvczogW10sCiAg" +
      "ICByZW1haW5pbmc6IDAsCiAgICB0b3RhbDogMCwKICAgIC8vIOaciOinhuWbvu+8mumdnuepuuaXtuWNoeeJh+a1geWxleekuuaV" +
      "tOaciOS7u+WKoQogICAgbW9udGg6IG51bGwsCiAgICBtb250aFRvZG9zOiBbXSwKICAgIGF1dGhNb2RlOiAnbG9naW4nLAogICAg" +
      "ZGVtbzogZmFsc2UsCiAgICBhcGlDb25maXJtZWQ6IGZhbHNlLAogICAgYnVzeTogZmFsc2UsCiAgICAvLyDkvqfmoI8KICAgIHN0" +
      "YXRzOiBbXSwgICAgICAgICAgICAvLyBbeyBkYXRlLCByZW1haW5pbmcsIHRvdGFsIH1dIOaMieaXpeacn+WAkuW6jwogICAgdGFn" +
      "czogW10sICAgICAgICAgICAgIC8vIFt7IG5hbWUsIGNvdW50IH1dCiAgICBjYWw6ICgoKSA9PiB7IGNvbnN0IGQgPSBuZXcgRGF0" +
      "ZSgpOyByZXR1cm4geyB5OiBkLmdldEZ1bGxZZWFyKCksIG06IGQuZ2V0TW9udGgoKSB9OyB9KSgpLAogICAgc2VhcmNoOiB7IHE6" +
      "ICcnLCBhY3RpdmU6IGZhbHNlLCBsb2FkaW5nOiBmYWxzZSwgcmVzdWx0czogW10gfSwKICAgIGNyb246IG51bGwsICAgICAgICAg" +
      "ICAvLyDlrprml7bku7vliqHvvIhDcm9u77yJ5b+D6Lez54q25oCBCiAgfTsKCiAgY29uc3QgVEFHX1JFID0gLyMoW15ccyNdezEs" +
      "MjR9KS9nOwoKICAvKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0gKgogICAqIOWuouaIt+err+e8k+WtmO+8mueCueWHu+aXpeacny/mnIjku73lhYjnp5LlvIDnvJPlrZjvvIzlho3lkI7l" +
      "j7DmoKHmlrDvvIzlubbpooTlj5bnm7jpgrvml6XmnJ8KICAgKiDvvIhzdGFsZS13aGlsZS1yZXZhbGlkYXRl77yM5raI6Zmk44CM" +
      "54K55LiA5LiL562J5LiA5LiL44CN55qE572R57uc5b6A6L+U5oSf77yJCiAgICogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgY29uc3QgZGF5Q2FjaGUgPSBuZXcgTWFwKCk7ICAg" +
      "ICAgLy8gZGF0ZSAtPiB7IHRvZG9zLCByZW1haW5pbmcsIHRvdGFsIH0KICBjb25zdCBtb250aENhY2hlID0gbmV3IE1hcCgpOyAg" +
      "ICAvLyBtb250aCAtPiB0b2Rvc1tdCiAgY29uc3QgcHJlZmV0Y2hpbmcgPSBuZXcgU2V0KCk7ICAgLy8g5q2j5Zyo6aKE5Y+W55qE" +
      "5pel5pyf77yM6Ziy6YeN5aSN6K+35rGCCiAgY29uc3QgREFZX0NBQ0hFX01BWCA9IDkwOwogIGNvbnN0IE1PTlRIX0NBQ0hFX01B" +
      "WCA9IDI0OwoKICBmdW5jdGlvbiBjYWNoZVNldERheShkYXRlLCB0b2RvcywgcmVtYWluaW5nLCB0b3RhbCkgewogICAgaWYgKGRh" +
      "eUNhY2hlLnNpemUgPj0gREFZX0NBQ0hFX01BWCkgZGF5Q2FjaGUuZGVsZXRlKGRheUNhY2hlLmtleXMoKS5uZXh0KCkudmFsdWUp" +
      "OwogICAgZGF5Q2FjaGUuc2V0KGRhdGUsIHsgdG9kb3MsIHJlbWFpbmluZywgdG90YWwgfSk7CiAgfQoKICBmdW5jdGlvbiBjYWNo" +
      "ZUNsZWFyQWxsKCkgewogICAgZGF5Q2FjaGUuY2xlYXIoKTsKICAgIG1vbnRoQ2FjaGUuY2xlYXIoKTsKICAgIHByZWZldGNoaW5n" +
      "LmNsZWFyKCk7CiAgfQoKICBmdW5jdGlvbiBwcmVmZXRjaERheShkYXRlKSB7CiAgICBpZiAoZGF5Q2FjaGUuaGFzKGRhdGUpIHx8" +
      "IHByZWZldGNoaW5nLmhhcyhkYXRlKSkgcmV0dXJuOwogICAgcHJlZmV0Y2hpbmcuYWRkKGRhdGUpOwogICAgYXBpKGAvdG9kb3M/" +
      "ZGF0ZT0ke2VuY29kZVVSSUNvbXBvbmVudChkYXRlKX1gKQogICAgICAudGhlbigoZCkgPT4gewogICAgICAgIGNvbnN0IHRvZG9z" +
      "ID0gZC50b2RvcyB8fCBbXTsKICAgICAgICBjYWNoZVNldERheShkYXRlLCB0b2RvcywgZC5yZW1haW5pbmcgPz8gdG9kb3MuZmls" +
      "dGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGgsIGQudG90YWwgPz8gdG9kb3MubGVuZ3RoKTsKICAgICAgfSkKICAgICAgLmNhdGNo" +
      "KCgpID0+IHsgLyog6aKE5Y+W5aSx6LSl6Z2Z6buY5b+955WlICovIH0pCiAgICAgIC5maW5hbGx5KCgpID0+IHByZWZldGNoaW5n" +
      "LmRlbGV0ZShkYXRlKSk7CiAgfQoKICAvKiog5YaZ5pON5L2c5oiQ5Yqf5ZCO77yM5oqK5b2T5YmN5Y2V5pel6KeG5Zu+54q25oCB" +
      "5ZCM5q2l5Zue57yT5a2YICovCiAgZnVuY3Rpb24gc3luY0RheUNhY2hlKCkgewogICAgaWYgKHN0YXRlLm1vbnRoIHx8IHN0YXRl" +
      "LnNlYXJjaC5hY3RpdmUpIHJldHVybjsKICAgIGNhY2hlU2V0RGF5KHN0YXRlLmRhdGUsIHN0YXRlLnRvZG9zLCBzdGF0ZS5yZW1h" +
      "aW5pbmcsIHN0YXRlLnRvdGFsKTsKICB9CgogIC8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqCiAgICog5bel5YW35Ye95pWwCiAgICogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgZnVuY3Rpb24gcGFkKG4pIHsgcmV0dXJuIFN0cmlu" +
      "ZyhuKS5wYWRTdGFydCgyLCAnMCcpOyB9CgogIGZ1bmN0aW9uIHRvZGF5U3RyKCkgewogICAgY29uc3QgZCA9IG5ldyBEYXRlKCk7" +
      "CiAgICByZXR1cm4gYCR7ZC5nZXRGdWxsWWVhcigpfS0ke3BhZChkLmdldE1vbnRoKCkgKyAxKX0tJHtwYWQoZC5nZXREYXRlKCkp" +
      "fWA7CiAgfQoKICBmdW5jdGlvbiBzaGlmdERhdGUoZGF0ZVN0ciwgZGVsdGEpIHsKICAgIGNvbnN0IFt5LCBtLCBkXSA9IGRhdGVT" +
      "dHIuc3BsaXQoJy0nKS5tYXAoTnVtYmVyKTsKICAgIGNvbnN0IGR0ID0gbmV3IERhdGUoeSwgbSAtIDEsIGQpOwogICAgZHQuc2V0" +
      "RGF0ZShkdC5nZXREYXRlKCkgKyBkZWx0YSk7CiAgICByZXR1cm4gYCR7ZHQuZ2V0RnVsbFllYXIoKX0tJHtwYWQoZHQuZ2V0TW9u" +
      "dGgoKSArIDEpfS0ke3BhZChkdC5nZXREYXRlKCkpfWA7CiAgfQoKICAvKiog5pyI5Lu95bmz56e777yaJzIwMjUtMTAnICsgKC0x" +
      "KSDihpIgJzIwMjUtMDknICovCiAgZnVuY3Rpb24gc2hpZnRNb250aFN0cihtb250aFN0ciwgZGVsdGEpIHsKICAgIGNvbnN0IFt5" +
      "LCBtXSA9IG1vbnRoU3RyLnNwbGl0KCctJykubWFwKE51bWJlcik7CiAgICBjb25zdCB6ZXJvID0geSAqIDEyICsgKG0gLSAxKSAr" +
      "IGRlbHRhOwogICAgcmV0dXJuIGAke01hdGguZmxvb3IoemVybyAvIDEyKX0tJHtwYWQoKHplcm8gJSAxMikgKyAxKX1gOwogIH0K" +
      "CiAgY29uc3QgV0VFS0RBWVMgPSBbJ+WRqOaXpScsICflkajkuIAnLCAn5ZGo5LqMJywgJ+WRqOS4iScsICflkajlm5snLCAn5ZGo" +
      "5LqUJywgJ+WRqOWFrSddOwoKICBmdW5jdGlvbiBodW1hbkRhdGUoZGF0ZVN0cikgewogICAgY29uc3QgdG9kYXkgPSB0b2RheVN0" +
      "cigpOwogICAgaWYgKGRhdGVTdHIgPT09IHRvZGF5KSByZXR1cm4geyB0aXRsZTogJ+S7iuWkqScsIHN1YjogYCR7ZGF0ZVN0cn0g" +
      "wrcgJHtXRUVLREFZU1t3ZWVrZGF5T2YoZGF0ZVN0cildfWAgfTsKICAgIGlmIChkYXRlU3RyID09PSBzaGlmdERhdGUodG9kYXks" +
      "IC0xKSkgcmV0dXJuIHsgdGl0bGU6ICfmmKjlpKknLCBzdWI6IGAke2RhdGVTdHJ9IMK3ICR7V0VFS0RBWVNbd2Vla2RheU9mKGRh" +
      "dGVTdHIpXX1gIH07CiAgICBpZiAoZGF0ZVN0ciA9PT0gc2hpZnREYXRlKHRvZGF5LCAxKSkgcmV0dXJuIHsgdGl0bGU6ICfmmI7l" +
      "pKknLCBzdWI6IGAke2RhdGVTdHJ9IMK3ICR7V0VFS0RBWVNbd2Vla2RheU9mKGRhdGVTdHIpXX1gIH07CiAgICBjb25zdCBbeSwg" +
      "bSwgZF0gPSBkYXRlU3RyLnNwbGl0KCctJykubWFwKE51bWJlcik7CiAgICByZXR1cm4geyB0aXRsZTogYCR7bX0g5pyIICR7ZH0g" +
      "5pelYCwgc3ViOiBgJHt5fS0ke3BhZChtKX0tJHtwYWQoZCl9IMK3ICR7V0VFS0RBWVNbd2Vla2RheU9mKGRhdGVTdHIpXX1gIH07" +
      "CiAgfQoKICBmdW5jdGlvbiB3ZWVrZGF5T2YoZGF0ZVN0cikgewogICAgY29uc3QgW3ksIG0sIGRdID0gZGF0ZVN0ci5zcGxpdCgn" +
      "LScpLm1hcChOdW1iZXIpOwogICAgcmV0dXJuIG5ldyBEYXRlKHksIG0gLSAxLCBkKS5nZXREYXkoKTsKICB9CgogIGZ1bmN0aW9u" +
      "IHRvYXN0KG1lc3NhZ2UsIGtpbmQgPSAnJywgZHVyYXRpb24gPSAyNDAwKSB7CiAgICBjb25zdCB0ZXh0ID0gU3RyaW5nKG1lc3Nh" +
      "Z2UgPz8gJycpOwogICAgY29uc3QgbG9uZyA9IHRleHQubGVuZ3RoID4gNTY7ICAgLy8g6ZW/5paH5qGI5pS555So5Y2h54mH5qC3" +
      "5byP5bm25aSa5YGc55WZ5LiA5Lya5YS/CiAgICBjb25zdCBub2RlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAg" +
      "ICBub2RlLmNsYXNzTmFtZSA9IGB0b2FzdCAke2tpbmR9JHtsb25nID8gJyBsb25nJyA6ICcnfWA7CiAgICBub2RlLnRleHRDb250" +
      "ZW50ID0gdGV4dDsKICAgIGVsLnRvYXN0SG9zdC5hcHBlbmRDaGlsZChub2RlKTsKICAgIHNldFRpbWVvdXQoKCkgPT4gewogICAg" +
      "ICBub2RlLmNsYXNzTGlzdC5hZGQoJ2xlYXZpbmcnKTsKICAgICAgc2V0VGltZW91dCgoKSA9PiBub2RlLnJlbW92ZSgpLCAyNDAp" +
      "OwogICAgfSwgbG9uZyA/IE1hdGgubWF4KGR1cmF0aW9uLCA3MDAwKSA6IGR1cmF0aW9uKTsKICB9CgogIGZ1bmN0aW9uIHNldFN0" +
      "YXR1cyhub2RlLCB0ZXh0LCBraW5kID0gJ2J1c3knKSB7CiAgICBpZiAoIXRleHQpIHsgbm9kZS5oaWRkZW4gPSB0cnVlOyBub2Rl" +
      "LnRleHRDb250ZW50ID0gJyc7IHJldHVybjsgfQogICAgbm9kZS5oaWRkZW4gPSBmYWxzZTsKICAgIG5vZGUuY2xhc3NOYW1lID0g" +
      "YHN0YXR1cy1saW5lICR7a2luZH1gOwogICAgbm9kZS50ZXh0Q29udGVudCA9IHRleHQ7CiAgfQoKICAvKiogaWZyYW1lIOmHjCB3" +
      "aW5kb3cuY29uZmlybSDlj6/og73ooqvmi6bmiKrvvIzmlLnnlKjjgIzlho3ngrnkuIDmrKHnoa7orqTjgI0gKi8KICBmdW5jdGlv" +
      "biBhcm1lZENsaWNrKGJ1dHRvbiwgbGFiZWwsIGFjdGlvbikgewogICAgaWYgKGJ1dHRvbi5kYXRhc2V0LmFybWVkID09PSAnMScp" +
      "IHsKICAgICAgZGVsZXRlIGJ1dHRvbi5kYXRhc2V0LmFybWVkOwogICAgICBidXR0b24udGV4dENvbnRlbnQgPSBidXR0b24uZGF0" +
      "YXNldC5vcmlnaW5hbCB8fCBsYWJlbDsKICAgICAgcmV0dXJuIGFjdGlvbigpOwogICAgfQogICAgYnV0dG9uLmRhdGFzZXQub3Jp" +
      "Z2luYWwgPSBidXR0b24uZGF0YXNldC5vcmlnaW5hbCB8fCBidXR0b24udGV4dENvbnRlbnQ7CiAgICBidXR0b24uZGF0YXNldC5h" +
      "cm1lZCA9ICcxJzsKICAgIGJ1dHRvbi50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgc2V0VGltZW91dCgoKSA9PiB7CiAgICAgIGlm" +
      "IChidXR0b24uZGF0YXNldC5hcm1lZCA9PT0gJzEnKSB7CiAgICAgICAgZGVsZXRlIGJ1dHRvbi5kYXRhc2V0LmFybWVkOwogICAg" +
      "ICAgIGJ1dHRvbi50ZXh0Q29udGVudCA9IGJ1dHRvbi5kYXRhc2V0Lm9yaWdpbmFsOwogICAgICB9CiAgICB9LCAzMjAwKTsKICAg" +
      "IHJldHVybiB1bmRlZmluZWQ7CiAgfQoKICAvKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0gKgogICAqIOa8lOekuuaooeW8j++8mueUqCBsb2NhbFN0b3JhZ2Ug5qih5ouf5ZCO56uvCiAg" +
      "ICogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAg" +
      "Y29uc3QgREVNT19LRVkgPSAndG9kby10b2RheTpkZW1vOnYxJzsKCiAgZnVuY3Rpb24gZGVtb1JlYWQoKSB7CiAgICB0cnkgewog" +
      "ICAgICBjb25zdCByYXcgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShERU1PX0tFWSk7CiAgICAgIGlmIChyYXcpIHJldHVybiBKU09O" +
      "LnBhcnNlKHJhdyk7CiAgICB9IGNhdGNoIHsgLyogaWdub3JlICovIH0KICAgIHJldHVybiB7IHVzZXI6IG51bGwsIHRvZG9zOiBb" +
      "XSwgYmFja3VwOiBudWxsIH07CiAgfQoKICBmdW5jdGlvbiBkZW1vV3JpdGUoZGF0YSkgewogICAgdHJ5IHsgbG9jYWxTdG9yYWdl" +
      "LnNldEl0ZW0oREVNT19LRVksIEpTT04uc3RyaW5naWZ5KGRhdGEpKTsgfSBjYXRjaCB7IC8qIGlnbm9yZSAqLyB9CiAgfQoKICBm" +
      "dW5jdGlvbiBkZW1vSWQoKSB7CiAgICByZXR1cm4gYGRfJHtEYXRlLm5vdygpLnRvU3RyaW5nKDM2KX0ke01hdGgucmFuZG9tKCku" +
      "dG9TdHJpbmcoMzYpLnNsaWNlKDIsIDgpfWA7CiAgfQoKICBmdW5jdGlvbiBkZW1vQ291bnQodG9kb3MsIGRhdGUpIHsKICAgIGNv" +
      "bnN0IGxpc3QgPSB0b2Rvcy5maWx0ZXIoKHQpID0+IHQuZGF0ZSA9PT0gZGF0ZSk7CiAgICByZXR1cm4geyByZW1haW5pbmc6IGxp" +
      "c3QuZmlsdGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGgsIHRvdGFsOiBsaXN0Lmxlbmd0aCB9OwogIH0KCiAgZnVuY3Rpb24gZGVt" +
      "b0xpc3QodG9kb3MsIGRhdGUpIHsKICAgIHJldHVybiB0b2RvcwogICAgICAuZmlsdGVyKCh0KSA9PiB0LmRhdGUgPT09IGRhdGUp" +
      "CiAgICAgIC5zb3J0KChhLCBiKSA9PiBOdW1iZXIoYS5kb25lKSAtIE51bWJlcihiLmRvbmUpIHx8IGEub3JkZXIgLSBiLm9yZGVy" +
      "IHx8IGEuY3JlYXRlZEF0IC0gYi5jcmVhdGVkQXQpOwogIH0KCiAgZnVuY3Rpb24gZGVtb0FwaShwYXRoLCB7IG1ldGhvZCA9ICdH" +
      "RVQnLCBib2R5IH0gPSB7fSkgewogICAgY29uc3QgZGIgPSBkZW1vUmVhZCgpOwogICAgY29uc3QgW3Jhd1BhdGgsIHF1ZXJ5XSA9" +
      "IHBhdGguc3BsaXQoJz8nKTsKICAgIGNvbnN0IHBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMocXVlcnkgfHwgJycpOwogICAg" +
      "Y29uc3Qgc2VnID0gcmF3UGF0aC5zcGxpdCgnLycpLmZpbHRlcihCb29sZWFuKTsgLy8gWydhdXRoJywnbWUnXSBldGMuCiAgICBj" +
      "b25zdCBqc29uUmVzID0gKGRhdGEsIHN0YXR1cyA9IDIwMCkgPT4gKHsgLi4uZGF0YSwgX19zdGF0dXM6IHN0YXR1cyB9KTsKCiAg" +
      "ICAvKiAtLS0gYXV0aCAtLS0gKi8KICAgIGlmIChzZWdbMF0gPT09ICdhdXRoJykgewogICAgICBpZiAoc2VnWzFdID09PSAnbWUn" +
      "KSByZXR1cm4geyBvazogdHJ1ZSwgdXNlcjogZGIudXNlciB9OwogICAgICBpZiAoc2VnWzFdID09PSAnbG9naW4nIHx8IHNlZ1sx" +
      "XSA9PT0gJ3JlZ2lzdGVyJykgewogICAgICAgIGNvbnN0IG5hbWUgPSBTdHJpbmcoYm9keT8udXNlcm5hbWUgfHwgJycpLnRyaW0o" +
      "KTsKICAgICAgICBjb25zdCBwYXNzID0gU3RyaW5nKGJvZHk/LnBhc3N3b3JkIHx8ICcnKTsKICAgICAgICBpZiAobmFtZS5sZW5n" +
      "dGggPCAyKSB0aHJvdyBuZXcgQXBpRXJyb3IoJ+eUqOaIt+WQjeiHs+WwkSAyIOS9jScpOwogICAgICAgIGlmIChwYXNzLmxlbmd0" +
      "aCA8IDYpIHRocm93IG5ldyBBcGlFcnJvcign5a+G56CB6Iez5bCRIDYg5L2NJyk7CiAgICAgICAgZGIudXNlciA9IHsgaWQ6ICdk" +
      "ZW1vLXVzZXInLCB1c2VybmFtZTogbmFtZSwgY3JlYXRlZEF0OiBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxMDAwKSB9OwogICAg" +
      "ICAgIGRlbW9Xcml0ZShkYik7CiAgICAgICAgcmV0dXJuIHsgb2s6IHRydWUsIHVzZXI6IGRiLnVzZXIgfTsKICAgICAgfQogICAg" +
      "ICBpZiAoc2VnWzFdID09PSAnbG9nb3V0JykgewogICAgICAgIGRiLnVzZXIgPSBudWxsOwogICAgICAgIGRlbW9Xcml0ZShkYik7" +
      "CiAgICAgICAgcmV0dXJuIHsgb2s6IHRydWUgfTsKICAgICAgfQogICAgICBpZiAoc2VnWzFdID09PSAncGFzc3dvcmQnKSByZXR1" +
      "cm4geyBvazogdHJ1ZSwgbWVzc2FnZTogJ+a8lOekuuaooeW8j+S4i+S4jeS8muecn+eahOaUueWvhueggScgfTsKICAgIH0KCiAg" +
      "ICBpZiAoIWRiLnVzZXIpIHRocm93IG5ldyBBcGlFcnJvcign6K+35YWI55m75b2VJywgNDAxKTsKCiAgICAvKiAtLS0g5pCc57Si" +
      "IC8g5qCH562+IC0tLSAqLwogICAgaWYgKHNlZ1swXSA9PT0gJ3NlYXJjaCcgJiYgbWV0aG9kID09PSAnR0VUJykgewogICAgICBj" +
      "b25zdCBxID0gKHBhcmFtcy5nZXQoJ3EnKSB8fCAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgICAgIGNvbnN0IGxpc3QgPSBk" +
      "Yi50b2RvcwogICAgICAgIC5maWx0ZXIoKHQpID0+IHQudGl0bGUudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhxKSkKICAgICAgICAu" +
      "c29ydCgoYSwgYikgPT4gKGEuZGF0ZSA8IGIuZGF0ZSA/IDEgOiBhLmRhdGUgPiBiLmRhdGUgPyAtMSA6IGIuY3JlYXRlZEF0IC0g" +
      "YS5jcmVhdGVkQXQpKQogICAgICAgIC5zbGljZSgwLCA1MCk7CiAgICAgIHJldHVybiB7IG9rOiB0cnVlLCBxLCB0b2RvczogbGlz" +
      "dCB9OwogICAgfQoKICAgIGlmIChzZWdbMF0gPT09ICd0YWdzJyAmJiBtZXRob2QgPT09ICdHRVQnKSB7CiAgICAgIGNvbnN0IGNv" +
      "dW50ZXIgPSBuZXcgTWFwKCk7CiAgICAgIGRiLnRvZG9zLmZvckVhY2goKHQpID0+IHsKICAgICAgICBjb25zdCB0YWdzID0gU3Ry" +
      "aW5nKHQudGl0bGUgfHwgJycpLm1hdGNoKC8jKFteXHMjXXsxLDI0fSkvZykgfHwgW107CiAgICAgICAgdGFncy5mb3JFYWNoKChy" +
      "YXcpID0+IHsKICAgICAgICAgIGNvbnN0IG5hbWUgPSByYXcuc2xpY2UoMSk7CiAgICAgICAgICBjb3VudGVyLnNldChuYW1lLCAo" +
      "Y291bnRlci5nZXQobmFtZSkgfHwgMCkgKyAxKTsKICAgICAgICB9KTsKICAgICAgfSk7CiAgICAgIGNvbnN0IHRhZ3MgPSBBcnJh" +
      "eS5mcm9tKGNvdW50ZXIsIChbbmFtZSwgY291bnRdKSA9PiAoeyBuYW1lLCBjb3VudCB9KSkKICAgICAgICAuc29ydCgoYSwgYikg" +
      "PT4gYi5jb3VudCAtIGEuY291bnQgfHwgYS5uYW1lLmxvY2FsZUNvbXBhcmUoYi5uYW1lLCAnemgtSGFucy1DTicpKQogICAgICAg" +
      "IC5zbGljZSgwLCAzMCk7CiAgICAgIHJldHVybiB7IG9rOiB0cnVlLCB0YWdzIH07CiAgICB9CgogICAgLyogLS0tIHRvZG9zIC0t" +
      "LSAqLwogICAgaWYgKHNlZ1swXSA9PT0gJ3RvZG9zJykgewogICAgICBjb25zdCBkYXRlID0gcGFyYW1zLmdldCgnZGF0ZScpIHx8" +
      "IHN0YXRlLmRhdGU7CgogICAgICAvLyDmlbTmnIjop4blm74KICAgICAgY29uc3QgbW9udGggPSBwYXJhbXMuZ2V0KCdtb250aCcp" +
      "OwogICAgICBpZiAoIXNlZ1sxXSAmJiBtZXRob2QgPT09ICdHRVQnICYmIG1vbnRoKSB7CiAgICAgICAgaWYgKCEvXlxkezR9LSg/" +
      "OjBbMS05XXwxWzAtMl0pJC8udGVzdChtb250aCkpIHRocm93IG5ldyBBcGlFcnJvcign5pyI5Lu95qC85byP5LiN5q2j56Gu77yM" +
      "5bqU5Li6IFlZWVktTU0nKTsKICAgICAgICBjb25zdCBsaXN0ID0gZGIudG9kb3MKICAgICAgICAgIC5maWx0ZXIoKHQpID0+IHQu" +
      "ZGF0ZS5zdGFydHNXaXRoKGAke21vbnRofS1gKSkKICAgICAgICAgIC5zb3J0KChhLCBiKSA9PiAoYS5kYXRlIDwgYi5kYXRlID8g" +
      "MSA6IGEuZGF0ZSA+IGIuZGF0ZSA/IC0xIDogTnVtYmVyKGEuZG9uZSkgLSBOdW1iZXIoYi5kb25lKSB8fCBhLm9yZGVyIC0gYi5v" +
      "cmRlcikpOwogICAgICAgIHJldHVybiB7IG9rOiB0cnVlLCBtb250aCwgdG9kb3M6IGxpc3QsIHJlbWFpbmluZzogbGlzdC5maWx0" +
      "ZXIoKHQpID0+ICF0LmRvbmUpLmxlbmd0aCwgdG90YWw6IGxpc3QubGVuZ3RoIH07CiAgICAgIH0KCiAgICAgIGlmICghc2VnWzFd" +
      "ICYmIG1ldGhvZCA9PT0gJ0dFVCcpIHsKICAgICAgICByZXR1cm4geyBvazogdHJ1ZSwgZGF0ZSwgdG9kb3M6IGRlbW9MaXN0KGRi" +
      "LnRvZG9zLCBkYXRlKSwgLi4uZGVtb0NvdW50KGRiLnRvZG9zLCBkYXRlKSB9OwogICAgICB9CgogICAgICBpZiAoIXNlZ1sxXSAm" +
      "JiBtZXRob2QgPT09ICdQT1NUJykgewogICAgICAgIGNvbnN0IHRpdGxlID0gU3RyaW5nKGJvZHk/LnRpdGxlIHx8ICcnKS5yZXBs" +
      "YWNlKC9ccysvZywgJyAnKS50cmltKCk7CiAgICAgICAgaWYgKCF0aXRsZSkgdGhyb3cgbmV3IEFwaUVycm9yKCfku7vliqHlhoXl" +
      "rrnkuI3og73kuLrnqbonKTsKICAgICAgICBjb25zdCBkYXkgPSBib2R5Py5kYXRlIHx8IGRhdGU7CiAgICAgICAgY29uc3QgbWlu" +
      "T3JkZXIgPSBNYXRoLm1pbigwLCAuLi5kYi50b2Rvcy5maWx0ZXIoKHQpID0+IHQuZGF0ZSA9PT0gZGF5KS5tYXAoKHQpID0+IHQu" +
      "b3JkZXIpKTsKICAgICAgICBjb25zdCB0b2RvID0gewogICAgICAgICAgaWQ6IGRlbW9JZCgpLCB0aXRsZSwgZG9uZTogZmFsc2Us" +
      "IGRhdGU6IGRheSwKICAgICAgICAgIG9yZGVyOiBtaW5PcmRlciAtIDEsIGNyZWF0ZWRBdDogTWF0aC5mbG9vcihEYXRlLm5vdygp" +
      "IC8gMTAwMCksCiAgICAgICAgfTsKICAgICAgICBkYi50b2Rvcy5wdXNoKHRvZG8pOwogICAgICAgIGRlbW9Xcml0ZShkYik7CiAg" +
      "ICAgICAgcmV0dXJuIHsgb2s6IHRydWUsIHRvZG8sIC4uLmRlbW9Db3VudChkYi50b2RvcywgZGF5KSwgX19zdGF0dXM6IDIwMSB9" +
      "OwogICAgICB9CgogICAgICBpZiAoc2VnWzFdID09PSAnYmF0Y2gnICYmIG1ldGhvZCA9PT0gJ1BPU1QnKSB7CiAgICAgICAgY29u" +
      "c3QgZGF5ID0gYm9keT8uZGF0ZSB8fCBkYXRlOwogICAgICAgIGlmIChib2R5Py5hY3Rpb24gPT09ICdjbGVhci1jb21wbGV0ZWQn" +
      "KSB7CiAgICAgICAgICBjb25zdCBiZWZvcmUgPSBkYi50b2Rvcy5sZW5ndGg7CiAgICAgICAgICBpZiAoYm9keT8ubW9udGgpIHsK" +
      "ICAgICAgICAgICAgaWYgKCEvXlxkezR9LSg/OjBbMS05XXwxWzAtMl0pJC8udGVzdChib2R5Lm1vbnRoKSkgdGhyb3cgbmV3IEFw" +
      "aUVycm9yKCfmnIjku73moLzlvI/kuI3mraPnoa7vvIzlupTkuLogWVlZWS1NTScpOwogICAgICAgICAgICBkYi50b2RvcyA9IGRi" +
      "LnRvZG9zLmZpbHRlcigodCkgPT4gISh0LmRhdGUuc3RhcnRzV2l0aChgJHtib2R5Lm1vbnRofS1gKSAmJiB0LmRvbmUpKTsKICAg" +
      "ICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIGRiLnRvZG9zID0gZGIudG9kb3MuZmlsdGVyKCh0KSA9PiAhKHQuZGF0ZSA9PT0g" +
      "ZGF5ICYmIHQuZG9uZSkpOwogICAgICAgICAgfQogICAgICAgICAgZGVtb1dyaXRlKGRiKTsKICAgICAgICAgIHJldHVybiB7IG9r" +
      "OiB0cnVlLCByZW1vdmVkOiBiZWZvcmUgLSBkYi50b2Rvcy5sZW5ndGgsIC4uLmRlbW9Db3VudChkYi50b2RvcywgZGF5KSB9Owog" +
      "ICAgICAgIH0KICAgICAgICBpZiAoYm9keT8uYWN0aW9uID09PSAndG9nZ2xlLWFsbCcpIHsKICAgICAgICAgIGRiLnRvZG9zLmZv" +
      "ckVhY2goKHQpID0+IHsgaWYgKHQuZGF0ZSA9PT0gZGF5KSB0LmRvbmUgPSAhIWJvZHkuZG9uZTsgfSk7CiAgICAgICAgICBkZW1v" +
      "V3JpdGUoZGIpOwogICAgICAgICAgcmV0dXJuIHsgb2s6IHRydWUsIC4uLmRlbW9Db3VudChkYi50b2RvcywgZGF5KSB9OwogICAg" +
      "ICAgIH0KICAgICAgICBpZiAoYm9keT8uYWN0aW9uID09PSAnY2Fycnktb3ZlcicpIHsKICAgICAgICAgIGxldCBtb3ZlZCA9IDA7" +
      "CiAgICAgICAgICBjb25zdCBwZW5kaW5nID0gYm9keT8uZnJvbQogICAgICAgICAgICA/IGRiLnRvZG9zLmZpbHRlcigodCkgPT4g" +
      "dC5kYXRlID09PSBib2R5LmZyb20gJiYgIXQuZG9uZSkKICAgICAgICAgICAgOiBkYi50b2Rvcy5maWx0ZXIoKHQpID0+IHQuZGF0" +
      "ZSA8IGRheSAmJiAhdC5kb25lKTsKICAgICAgICAgIGxldCBvcmRlciA9IE1hdGgubWluKDAsIC4uLmRiLnRvZG9zLmZpbHRlcigo" +
      "dCkgPT4gdC5kYXRlID09PSBkYXkpLm1hcCgodCkgPT4gdC5vcmRlcikpIC0gMTsKICAgICAgICAgIHBlbmRpbmcuZm9yRWFjaCgo" +
      "dCkgPT4geyB0LmRhdGUgPSBkYXk7IHQub3JkZXIgPSBvcmRlci0tOyBtb3ZlZCArPSAxOyB9KTsKICAgICAgICAgIGRlbW9Xcml0" +
      "ZShkYik7CiAgICAgICAgICByZXR1cm4geyBvazogdHJ1ZSwgbW92ZWQsIHRvZG9zOiBkZW1vTGlzdChkYi50b2RvcywgZGF5KSwg" +
      "Li4uZGVtb0NvdW50KGRiLnRvZG9zLCBkYXkpIH07CiAgICAgICAgfQogICAgICAgIHJldHVybiB7IG9rOiB0cnVlIH07CiAgICAg" +
      "IH0KCiAgICAgIGlmIChzZWdbMV0gPT09ICdzdGF0cycpIHsKICAgICAgICBjb25zdCBtYXAgPSBuZXcgTWFwKCk7CiAgICAgICAg" +
      "ZGIudG9kb3MuZm9yRWFjaCgodCkgPT4gewogICAgICAgICAgY29uc3QgY3VyID0gbWFwLmdldCh0LmRhdGUpIHx8IHsgZGF0ZTog" +
      "dC5kYXRlLCByZW1haW5pbmc6IDAsIHRvdGFsOiAwIH07CiAgICAgICAgICBjdXIudG90YWwgKz0gMTsKICAgICAgICAgIGlmICgh" +
      "dC5kb25lKSBjdXIucmVtYWluaW5nICs9IDE7CiAgICAgICAgICBtYXAuc2V0KHQuZGF0ZSwgY3VyKTsKICAgICAgICB9KTsKICAg" +
      "ICAgICByZXR1cm4geyBvazogdHJ1ZSwgc3RhdHM6IEFycmF5LmZyb20obWFwLnZhbHVlcygpKS5zb3J0KChhLCBiKSA9PiAoYS5k" +
      "YXRlIDwgYi5kYXRlID8gMSA6IC0xKSkgfTsKICAgICAgfQoKICAgICAgY29uc3QgaWQgPSBzZWdbMV07CiAgICAgIGNvbnN0IGlu" +
      "ZGV4ID0gZGIudG9kb3MuZmluZEluZGV4KCh0KSA9PiB0LmlkID09PSBpZCk7CiAgICAgIGlmIChpbmRleCA9PT0gLTEpIHRocm93" +
      "IG5ldyBBcGlFcnJvcign5Lu75Yqh5LiN5a2Y5ZyoJywgNDA0KTsKCiAgICAgIGlmIChtZXRob2QgPT09ICdQQVRDSCcpIHsKICAg" +
      "ICAgICBjb25zdCB0ID0gZGIudG9kb3NbaW5kZXhdOwogICAgICAgIGlmICgndGl0bGUnIGluIChib2R5IHx8IHt9KSkgewogICAg" +
      "ICAgICAgY29uc3QgdGl0bGUgPSBTdHJpbmcoYm9keS50aXRsZSkucmVwbGFjZSgvXHMrL2csICcgJykudHJpbSgpOwogICAgICAg" +
      "ICAgaWYgKCF0aXRsZSkgdGhyb3cgbmV3IEFwaUVycm9yKCfku7vliqHlhoXlrrnkuI3og73kuLrnqbonKTsKICAgICAgICAgIHQu" +
      "dGl0bGUgPSB0aXRsZTsKICAgICAgICB9CiAgICAgICAgaWYgKCdkb25lJyBpbiAoYm9keSB8fCB7fSkpIHQuZG9uZSA9ICEhYm9k" +
      "eS5kb25lOwogICAgICAgIGlmICgnZGF0ZScgaW4gKGJvZHkgfHwge30pKSB0LmRhdGUgPSBib2R5LmRhdGU7CiAgICAgICAgZGVt" +
      "b1dyaXRlKGRiKTsKICAgICAgICByZXR1cm4geyBvazogdHJ1ZSwgdG9kbzogdCwgLi4uZGVtb0NvdW50KGRiLnRvZG9zLCB0LmRh" +
      "dGUpIH07CiAgICAgIH0KCiAgICAgIGlmIChtZXRob2QgPT09ICdERUxFVEUnKSB7CiAgICAgICAgY29uc3QgW3JlbW92ZWRdID0g" +
      "ZGIudG9kb3Muc3BsaWNlKGluZGV4LCAxKTsKICAgICAgICBkZW1vV3JpdGUoZGIpOwogICAgICAgIHJldHVybiB7IG9rOiB0cnVl" +
      "LCBpZDogcmVtb3ZlZC5pZCwgLi4uZGVtb0NvdW50KGRiLnRvZG9zLCByZW1vdmVkLmRhdGUpIH07CiAgICAgIH0KICAgIH0KCiAg" +
      "ICAvKiAtLS0gYmFja3VwIC0tLSAqLwogICAgaWYgKHNlZ1swXSA9PT0gJ2JhY2t1cCcpIHsKICAgICAgaWYgKHNlZ1sxXSA9PT0g" +
      "J2NvbmZpZycgJiYgbWV0aG9kID09PSAnR0VUJykgewogICAgICAgIHJldHVybiB7CiAgICAgICAgICBvazogdHJ1ZSwKICAgICAg" +
      "ICAgIGNvbmZpZzogZGIuYmFja3VwIHx8IHsKICAgICAgICAgICAgcHJvdmlkZXI6ICdub25lJywgZW5hYmxlZDogZmFsc2UsIGF1" +
      "dG86IGZhbHNlLCBzdGFtcDogdHJ1ZSwKICAgICAgICAgICAgaW50ZXJ2YWxNaW46IDEsIHNjaGVkdWxlZDogZmFsc2UsIHNjaGVk" +
      "dWxlTWluOiA2MCwgdHo6ICcnLAogICAgICAgICAgICBmaWxlOiAndG9kby10b2RheS5iYWNrdXAuanNvbicsCiAgICAgICAgICAg" +
      "IGhhc1IyQmluZGluZzogZmFsc2UsCiAgICAgICAgICAgIHMzOiB7IGVuZHBvaW50OiAnJywgcmVnaW9uOiAnYXV0bycsIGJ1Y2tl" +
      "dDogJycsIGFjY2Vzc0tleUlkOiAnJywgaGFzU2VjcmV0S2V5OiBmYWxzZSwgcHJlZml4OiAnJywgcGF0aFN0eWxlOiBmYWxzZSB9" +
      "LAogICAgICAgICAgICB3ZWJkYXY6IHsgdXJsOiAnJywgdXNlcm5hbWU6ICcnLCBoYXNQYXNzd29yZDogZmFsc2UsIGZpbGU6ICcn" +
      "IH0sCiAgICAgICAgICB9LAogICAgICAgICAgbGFzdEJhY2t1cDogbnVsbCwKICAgICAgICAgIGNyb246IHsgbGFzdFJ1bjogbnVs" +
      "bCwgaGVhbHRoeTogZmFsc2UsIGludGVydmFsU2Vjb25kczogMzAwIH0sCiAgICAgICAgfTsKICAgICAgfQogICAgICBpZiAoc2Vn" +
      "WzFdID09PSAnY29uZmlnJyAmJiBtZXRob2QgPT09ICdQVVQnKSB7CiAgICAgICAgZGIuYmFja3VwID0geyAuLi5ib2R5LCBoYXNS" +
      "MkJpbmRpbmc6IGZhbHNlIH07CiAgICAgICAgZGVtb1dyaXRlKGRiKTsKICAgICAgICByZXR1cm4geyBvazogdHJ1ZSwgY29uZmln" +
      "OiBkYi5iYWNrdXAgfTsKICAgICAgfQogICAgICBpZiAoc2VnWzFdID09PSAndGVzdCcpIHJldHVybiB7IG9rOiB0cnVlLCBtZXNz" +
      "YWdlOiAn5ryU56S65qih5byP77ya5pyq55yf5q2j6L+e5o6l5LqR5a2Y5YKoJyB9OwogICAgICBpZiAoc2VnWzFdID09PSAncnVu" +
      "JykgcmV0dXJuIHsgb2s6IHRydWUsIG1lc3NhZ2U6ICfmvJTnpLrmqKHlvI/vvJrmnKrnnJ/mraPkuIrkvKAnIH07CiAgICAgIGlm" +
      "IChzZWdbMV0gPT09ICdyZXN0b3JlJykgcmV0dXJuIHsgb2s6IHRydWUsIG1lc3NhZ2U6ICfmvJTnpLrmqKHlvI/vvJrmnKrnnJ/m" +
      "raPkuIvovb0nIH07CiAgICB9CgogICAgdGhyb3cgbmV3IEFwaUVycm9yKGDmvJTnpLrmqKHlvI/mmoLkuI3mlK/mjIHvvJoke21l" +
      "dGhvZH0gJHtwYXRofWAsIDQwNCk7CiAgfQoKICBjbGFzcyBBcGlFcnJvciBleHRlbmRzIEVycm9yIHsKICAgIGNvbnN0cnVjdG9y" +
      "KG1lc3NhZ2UsIHN0YXR1cyA9IDQwMCkgeyBzdXBlcihtZXNzYWdlKTsgdGhpcy5zdGF0dXMgPSBzdGF0dXM7IH0KICB9CgogIC8q" +
      "IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqCiAgICog" +
      "6K+35rGC5bCB6KOF77ya55yf5a6e5ZCO56uv5LyY5YWI77yM5b+F6KaB5pe26ZmN57qn5ryU56S65qih5byPCiAgICogLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgYXN5bmMgZnVu" +
      "Y3Rpb24gYXBpKHBhdGgsIHsgbWV0aG9kID0gJ0dFVCcsIGJvZHkgfSA9IHt9KSB7CiAgICBpZiAoc3RhdGUuZGVtbykgcmV0dXJu" +
      "IGRlbW9BcGkocGF0aCwgeyBtZXRob2QsIGJvZHkgfSk7CgogICAgbGV0IHJlczsKICAgIHRyeSB7CiAgICAgIHJlcyA9IGF3YWl0" +
      "IGZldGNoKEFQSV9CQVNFICsgcGF0aCwgewogICAgICAgIG1ldGhvZCwKICAgICAgICBjcmVkZW50aWFsczogJ3NhbWUtb3JpZ2lu" +
      "JywKICAgICAgICBoZWFkZXJzOiBib2R5ICE9PSB1bmRlZmluZWQgPyB7ICdjb250ZW50LXR5cGUnOiAnYXBwbGljYXRpb24vanNv" +
      "bicgfSA6IHVuZGVmaW5lZCwKICAgICAgICBib2R5OiBib2R5ICE9PSB1bmRlZmluZWQgPyBKU09OLnN0cmluZ2lmeShib2R5KSA6" +
      "IHVuZGVmaW5lZCwKICAgICAgfSk7CiAgICB9IGNhdGNoIChuZXR3b3JrRXJyb3IpIHsKICAgICAgaWYgKCFzdGF0ZS5hcGlDb25m" +
      "aXJtZWQpIHJldHVybiBmYWxsYmFja1RvRGVtbyhwYXRoLCBtZXRob2QsIGJvZHkpOwogICAgICB0aHJvdyBuZXcgRXJyb3IoJ+e9" +
      "kee7nOW8guW4uO+8jOivt+ajgOafpei/nuaOpeWQjumHjeivlScpOwogICAgfQoKICAgIGNvbnN0IGNvbnRlbnRUeXBlID0gcmVz" +
      "LmhlYWRlcnMuZ2V0KCdjb250ZW50LXR5cGUnKSB8fCAnJzsKICAgIGlmICghY29udGVudFR5cGUuaW5jbHVkZXMoJ2FwcGxpY2F0" +
      "aW9uL2pzb24nKSkgewogICAgICAvLyDpnZnmgIHmiZjnrqEgLyDlkI7nq6/mnKrpg6jnvbIg4oCU4oCUIOiHquWKqOi/m+WFpea8" +
      "lOekuuaooeW8jwogICAgICBpZiAoIXN0YXRlLmFwaUNvbmZpcm1lZCkgcmV0dXJuIGZhbGxiYWNrVG9EZW1vKHBhdGgsIG1ldGhv" +
      "ZCwgYm9keSk7CiAgICAgIHRocm93IG5ldyBFcnJvcihg5pyN5Yqh6L+U5Zue5LqG6Z2e6aKE5pyf5YaF5a65ICgke3Jlcy5zdGF0" +
      "dXN9KWApOwogICAgfQoKICAgIHN0YXRlLmFwaUNvbmZpcm1lZCA9IHRydWU7CiAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpz" +
      "b24oKS5jYXRjaCgoKSA9PiAoe30pKTsKICAgIGlmICghcmVzLm9rIHx8IGRhdGEub2sgPT09IGZhbHNlKSB7CiAgICAgIHRocm93" +
      "IG5ldyBBcGlFcnJvcihkYXRhLmVycm9yIHx8IGDor7fmsYLlpLHotKUgKCR7cmVzLnN0YXR1c30pYCwgcmVzLnN0YXR1cyk7CiAg" +
      "ICB9CiAgICByZXR1cm4gZGF0YTsKICB9CgogIGZ1bmN0aW9uIGZhbGxiYWNrVG9EZW1vKHBhdGgsIG1ldGhvZCwgYm9keSkgewog" +
      "ICAgZW5hYmxlRGVtb01vZGUoKTsKICAgIHJldHVybiBkZW1vQXBpKHBhdGgsIHsgbWV0aG9kLCBib2R5IH0pOwogIH0KCiAgZnVu" +
      "Y3Rpb24gZW5hYmxlRGVtb01vZGUoKSB7CiAgICBpZiAoc3RhdGUuZGVtbykgcmV0dXJuOwogICAgc3RhdGUuZGVtbyA9IHRydWU7" +
      "CiAgICBlbC5kZW1vQmFubmVyLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgZWwuYWJvdXRWZXJzaW9uLnRleHRDb250" +
      "ZW50ID0gYOWJjeerryB2JHtBUFBfVkVSU0lPTn0gwrcg5ryU56S65qih5byPYDsKICAgIHRvYXN0KCfmnKrmo4DmtYvliLDlkI7n" +
      "q6/mnI3liqHvvIzlt7LliIfmjaLliLDmvJTnpLrmqKHlvI8nLCAnJywgMzIwMCk7CiAgfQoKICAvKiog5ryU56S655So55qE56S6" +
      "5L6L5pWw5o2u77yM5LuF5ZyoID9kZW1vPTEg6aaW5qyh6L+b5YWl5pe254GM5LiA5qyhICovCiAgZnVuY3Rpb24gc2VlZERlbW9E" +
      "YXRhKCkgewogICAgY29uc3QgZGIgPSBkZW1vUmVhZCgpOwogICAgaWYgKGRiLnVzZXIpIHJldHVybjsKICAgIGNvbnN0IHRvZGF5" +
      "ID0gdG9kYXlTdHIoKTsKICAgIGNvbnN0IGRheSA9IChkZWx0YSkgPT4gc2hpZnREYXRlKHRvZGF5LCBkZWx0YSk7CiAgICAvLyBb" +
      "5qCH6aKYLCDmmK/lkKblrozmiJAsIOaXpeacn+WBj+enu10KICAgIGNvbnN0IHNhbXBsZXMgPSBbCiAgICAgIFsn5oqK5a2j5bqm" +
      "5rGH5oql55qE5o+Q57qy5YaZ5a6MICPlt6XkvZwnLCBmYWxzZSwgMF0sCiAgICAgIFsn5Zue5aSN5a6i5oi355qE6YKu5Lu2ICPl" +
      "t6XkvZwnLCB0cnVlLCAwXSwKICAgICAgWyfpooTnuqblkajkupTnmoTkvZPmo4AgI+eUn+a0uycsIGZhbHNlLCAwXSwKICAgICAg" +
      "WyfmmZrkuIogOCDngrnljrvlgaXouqvmiL8gI+eUn+a0uycsIGZhbHNlLCAtMV0sCiAgICAgIFsn6K+75a6M44CK5Y2h54mH56yU" +
      "6K6w5YaZ5L2c5rOV44CL56ys5LiJ56ugICPpmIXor7snLCBmYWxzZSwgLTFdLAogICAgICBbJ+e7memYs+WPsOeahOe7v+iQnea1" +
      "h+awtCAj55Sf5rS7JywgdHJ1ZSwgLTJdLAogICAgICBbJ+aVtOeQhuS4i+S4gOatpeeahOaXheihjOa4heWNlSAj55Sf5rS7Jywg" +
      "ZmFsc2UsIC00XSwKICAgICAgWydyZXZpZXcg5ZCM5LqL55qE5pa55qGI5paH5qGjICPlt6XkvZwnLCB0cnVlLCAtNV0sCiAgICBd" +
      "OwogICAgZGIudXNlciA9IHsgaWQ6ICdkZW1vLXVzZXInLCB1c2VybmFtZTogJ2RlbW8nLCBjcmVhdGVkQXQ6IE1hdGguZmxvb3Io" +
      "RGF0ZS5ub3coKSAvIDEwMDApIH07CiAgICBkYi50b2RvcyA9IHNhbXBsZXMubWFwKChbdGl0bGUsIGRvbmUsIGRlbHRhXSwgaSkg" +
      "PT4gKHsKICAgICAgaWQ6IGRlbW9JZCgpLAogICAgICB0aXRsZSwKICAgICAgZG9uZSwKICAgICAgZGF0ZTogZGF5KGRlbHRhKSwK" +
      "ICAgICAgb3JkZXI6IGksCiAgICAgIGNyZWF0ZWRBdDogTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCkgKyBpLAogICAgfSkp" +
      "OwogICAgZGVtb1dyaXRlKGRiKTsKICB9CgogIC8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqCiAgICog6KeG5Zu+5YiH5o2iCiAgICogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgZnVuY3Rpb24gc2hvd0F1dGgoKSB7CiAgICBlbC5i" +
      "b290LmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgZWwuYXV0aFZpZXcuY2xhc3NMaXN0LnJlbW92ZSgnaGlkZGVuJyk7CiAg" +
      "ICBlbC5tYWluVmlldy5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgIGVsLmF1dGhVc2VybmFtZS5mb2N1cyh7IHByZXZlbnRT" +
      "Y3JvbGw6IHRydWUgfSk7CiAgfQoKICBhc3luYyBmdW5jdGlvbiBzaG93TWFpbigpIHsKICAgIGVsLmJvb3QuY2xhc3NMaXN0LmFk" +
      "ZCgnaGlkZGVuJyk7CiAgICBlbC5hdXRoVmlldy5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgIGVsLm1haW5WaWV3LmNsYXNz" +
      "TGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgZWwudXNlckluaXRpYWwudGV4dENvbnRlbnQgPSAoc3RhdGUudXNlcj8udXNlcm5h" +
      "bWUgfHwgJ1UnKS5zbGljZSgwLCAxKS50b1VwcGVyQ2FzZSgpOwogICAgZWwuYWNjb3VudE5hbWUudGV4dENvbnRlbnQgPSBzdGF0" +
      "ZS51c2VyPy51c2VybmFtZSB8fCAnLSc7CiAgICBhd2FpdCByZWZyZXNoKCk7ICAgICAgICAgIC8vIOS4u+WIl+ihqOS8mOWFiOa4" +
      "suafkwogICAgbG9hZFNpZGViYXJEYXRhKCk7ICAgICAgICAvLyDkvqfmoI/kuI7lpIfku73phY3nva7lubbooYzliqDovb3vvIzk" +
      "uI3pmLvloZ7pppblsY8KICAgIGxvYWRCYWNrdXBDb25maWcoKTsKICAgIGVsLmFkZElucHV0LmZvY3VzKHsgcHJldmVudFNjcm9s" +
      "bDogdHJ1ZSB9KTsKICAgIC8vID9wYW5lbD1zZXR0aW5ncyDnlKjkuo7nm7TmjqXmiZPlvIDorr7nva7mir3lsYnvvIjmvJTnpLov" +
      "5oiq5Zu+55So77yJCiAgICBpZiAoVVJMX1BBUkFNUy5nZXQoJ3BhbmVsJykgPT09ICdzZXR0aW5ncycpIG9wZW5EcmF3ZXIoKTsK" +
      "ICAgIC8vID9wYW5lbD1zaWRlYmFyIOeUqOS6juebtOaOpeWxleW8gOenu+WKqOerr+S+p+agj++8iOaIquWbvueUqO+8iQogICAg" +
      "aWYgKFVSTF9QQVJBTVMuZ2V0KCdwYW5lbCcpID09PSAnc2lkZWJhcicpIG9wZW5TaWRlYmFyKCk7CiAgICAvLyA/cT14eHgg55u0" +
      "5o6l6L+b5YWl5pCc57Si54q25oCB77yI5ryU56S6L+aIquWbvueUqO+8iQogICAgY29uc3QgcSA9IFVSTF9QQVJBTVMuZ2V0KCdx" +
      "Jyk7CiAgICBpZiAocSkgc3RhcnRTZWFyY2gocSk7CiAgICAvLyA/bW9udGg9WVlZWS1NTSDnm7TmjqXov5vlhaXmlbTmnIjop4bl" +
      "m77vvIjmvJTnpLov5oiq5Zu+55So77yJCiAgICBjb25zdCBtdiA9IFVSTF9QQVJBTVMuZ2V0KCdtb250aCcpOwogICAgaWYgKG12" +
      "ICYmIC9eXGR7NH0tXGR7Mn0kLy50ZXN0KG12KSkgb3Blbk1vbnRoKG12KTsKICB9CgogIC8qIC0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqCiAgICog6K6k6K+BCiAgICogLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgZnVuY3Rpb24gc2V0" +
      "QXV0aE1vZGUobW9kZSkgewogICAgc3RhdGUuYXV0aE1vZGUgPSBtb2RlOwogICAgZWwudGFicy5mb3JFYWNoKCh0KSA9PiB0LmNs" +
      "YXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsIHQuZGF0YXNldC5tb2RlID09PSBtb2RlKSk7CiAgICBlbC5hdXRoU3VibWl0TGFiZWwu" +
      "dGV4dENvbnRlbnQgPSBtb2RlID09PSAnbG9naW4nID8gJ+eZu+W9lScgOiAn5Yib5bu66LSm5Y+3JzsKICAgIGVsLmF1dGhQYXNz" +
      "d29yZC5zZXRBdHRyaWJ1dGUoJ2F1dG9jb21wbGV0ZScsIG1vZGUgPT09ICdsb2dpbicgPyAnY3VycmVudC1wYXNzd29yZCcgOiAn" +
      "bmV3LXBhc3N3b3JkJyk7CiAgICBlbC5hdXRoRXJyb3IuaGlkZGVuID0gdHJ1ZTsKICAgIGVsLmF1dGhQYXNzd29yZC52YWx1ZSA9" +
      "ICcnOwogIH0KCiAgZnVuY3Rpb24gc2hvd0F1dGhFcnJvcihtZXNzYWdlKSB7CiAgICBlbC5hdXRoRXJyb3IudGV4dENvbnRlbnQg" +
      "PSBtZXNzYWdlOwogICAgZWwuYXV0aEVycm9yLmhpZGRlbiA9IGZhbHNlOwogIH0KCiAgZWwudGFicy5mb3JFYWNoKCh0YWIpID0+" +
      "IHRhYi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHNldEF1dGhNb2RlKHRhYi5kYXRhc2V0Lm1vZGUpKSk7CgogIGVs" +
      "LnRvZ2dsZVBhc3N3b3JkLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgY29uc3QgaXNQYXNzd29yZCA9IGVs" +
      "LmF1dGhQYXNzd29yZC50eXBlID09PSAncGFzc3dvcmQnOwogICAgZWwuYXV0aFBhc3N3b3JkLnR5cGUgPSBpc1Bhc3N3b3JkID8g" +
      "J3RleHQnIDogJ3Bhc3N3b3JkJzsKICAgIGVsLnRvZ2dsZVBhc3N3b3JkLnRleHRDb250ZW50ID0gaXNQYXNzd29yZCA/ICfwn5mI" +
      "JyA6ICfwn5GBJzsKICB9KTsKCiAgZWwuYXV0aEZvcm0uYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgYXN5bmMgKGV2ZW50KSA9" +
      "PiB7CiAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpOwogICAgY29uc3QgdXNlcm5hbWUgPSBlbC5hdXRoVXNlcm5hbWUudmFsdWUu" +
      "dHJpbSgpOwogICAgY29uc3QgcGFzc3dvcmQgPSBlbC5hdXRoUGFzc3dvcmQudmFsdWU7CgogICAgaWYgKCF1c2VybmFtZSkgcmV0" +
      "dXJuIHNob3dBdXRoRXJyb3IoJ+ivt+i+k+WFpeeUqOaIt+WQjScpOwogICAgaWYgKHBhc3N3b3JkLmxlbmd0aCA8IDYpIHJldHVy" +
      "biBzaG93QXV0aEVycm9yKCflr4bnoIHoh7PlsJEgNiDkvY0nKTsKCiAgICBlbC5hdXRoU3VibWl0LmRpc2FibGVkID0gdHJ1ZTsK" +
      "ICAgIGVsLmF1dGhTdWJtaXRMYWJlbC50ZXh0Q29udGVudCA9IHN0YXRlLmF1dGhNb2RlID09PSAnbG9naW4nID8gJ+eZu+W9leS4" +
      "reKApicgOiAn5Yib5bu65Lit4oCmJzsKICAgIGVsLmF1dGhFcnJvci5oaWRkZW4gPSB0cnVlOwoKICAgIHRyeSB7CiAgICAgIGNv" +
      "bnN0IGRhdGEgPSBhd2FpdCBhcGkoYC9hdXRoLyR7c3RhdGUuYXV0aE1vZGV9YCwgeyBtZXRob2Q6ICdQT1NUJywgYm9keTogeyB1" +
      "c2VybmFtZSwgcGFzc3dvcmQgfSB9KTsKICAgICAgLy8g5o2i6LSm5Y+35b+F6aG75YWI5riF56m65LiK5LiA5Liq6LSm5Y+355qE" +
      "5LiA5YiH55eV6L+577yM6YG/5YWN5pWw5o2u5Liy5Yiw5paw6LSm5Y+3CiAgICAgIHJlc2V0VXNlclN0YXRlKCk7CiAgICAgIHN0" +
      "YXRlLnVzZXIgPSBkYXRhLnVzZXI7CiAgICAgIGVsLmF1dGhQYXNzd29yZC52YWx1ZSA9ICcnOwogICAgICBhd2FpdCBzaG93TWFp" +
      "bigpOwogICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgIHNob3dBdXRoRXJyb3IoZXJyLm1lc3NhZ2UgfHwgJ+aTjeS9nOWksei0pScp" +
      "OwogICAgfSBmaW5hbGx5IHsKICAgICAgZWwuYXV0aFN1Ym1pdC5kaXNhYmxlZCA9IGZhbHNlOwogICAgICBlbC5hdXRoU3VibWl0" +
      "TGFiZWwudGV4dENvbnRlbnQgPSBzdGF0ZS5hdXRoTW9kZSA9PT0gJ2xvZ2luJyA/ICfnmbvlvZUnIDogJ+WIm+W7uui0puWPtyc7" +
      "CiAgICB9CiAgfSk7CgogIC8qKgogICAqIOa4heepuuaJgOacieS4juOAjOW9k+WJjeeUqOaIt+OAjee7keWumueahOWJjeerr+eK" +
      "tuaAge+8mgogICAqIOWGheWtmOe8k+WtmOOAgeWIl+ihqOOAgeS+p+agj+e7n+iuoeOAgeagh+etvuOAgeaQnOe0ouaAgeOAgea8" +
      "lOekuuaVsOaNruetieOAggogICAqIOeZu+W9leOAgemAgOWHuuOAgeS8muivneWkseaViO+8iDQwMe+8ieaXtumDveW/hemhu+iw" +
      "g+eUqO+8jOS/neivgei0puWPt+mXtOmbtuaui+eVmeOAggogICAqLwogIGZ1bmN0aW9uIHJlc2V0VXNlclN0YXRlKCkgewogICAg" +
      "Y2FjaGVDbGVhckFsbCgpOyAgICAgICAgICAvLyDljZXml6UgLyDmlbTmnIjnvJPlrZgKICAgIHN0YXRlLnRvZG9zID0gW107CiAg" +
      "ICBzdGF0ZS5tb250aFRvZG9zID0gW107CiAgICBzdGF0ZS5tb250aCA9IG51bGw7CiAgICBzdGF0ZS5yZW1haW5pbmcgPSAwOwog" +
      "ICAgc3RhdGUudG90YWwgPSAwOwogICAgc3RhdGUuc3RhdHMgPSBbXTsKICAgIHN0YXRlLnRhZ3MgPSBbXTsKICAgIGV4aXRTZWFy" +
      "Y2goKTsgICAgICAgICAgICAgLy8g5riF5o6J5pCc57Si5YWz6ZSu5a2X5LiO57uT5p6cCiAgICBjbG9zZURhdGVQb3AoKTsKICAg" +
      "IGNsb3NlRHJhd2VyKCk7CiAgICAvLyDmuIXnqbrlt7LmuLLmn5PnmoQgRE9N77yM6YG/5YWN5pen6LSm5Y+35YaF5a655LiA6Zeq" +
      "6ICM6L+HCiAgICBlbC5mZWVkLmlubmVySFRNTCA9ICcnOwogICAgZWwudGFnc0xpc3QuaW5uZXJIVE1MID0gJyc7CiAgICBlbC50" +
      "aW1lbGluZUxpc3QuaW5uZXJIVE1MID0gJyc7CiAgICBlbC5zZWFyY2hJbnB1dC52YWx1ZSA9ICcnOwogICAgZWwuc2VhcmNoQ2xl" +
      "YXI/LmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgZWwuc3RhdERheXMudGV4dENvbnRlbnQgPSAnMCc7CiAgICBlbC5zdGF0" +
      "VG90YWwudGV4dENvbnRlbnQgPSAnMCc7CiAgICBlbC5zdGF0RG9uZS50ZXh0Q29udGVudCA9ICcwJzsKICAgIGVsLnJlbWFpbmlu" +
      "Z0NvdW50LnRleHRDb250ZW50ID0gJzAnOwogICAgZWwuZW1wdHlTdGF0ZT8uY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgfQoK" +
      "ICAvKiog5Lya6K+d5aSx5pWI77yINDAx77yJ57uf5LiA5aSE55CG77ya5riF56m65b2T5YmN55So5oi355qE5omA5pyJ5q6L55WZ" +
      "54q25oCB5bm25Zue5Yiw55m75b2V6aG1ICovCiAgZnVuY3Rpb24gaGFuZGxlU2Vzc2lvbkxvc3QoKSB7CiAgICByZXNldFVzZXJT" +
      "dGF0ZSgpOwogICAgc3RhdGUudXNlciA9IG51bGw7CiAgICBzaG93QXV0aCgpOwogICAgdG9hc3QoJ+eZu+W9leeKtuaAgeW3suWk" +
      "seaViO+8jOivt+mHjeaWsOeZu+W9lScpOwogIH0KCiAgZWwubG9nb3V0QnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgYXN5" +
      "bmMgKCkgPT4gewogICAgdHJ5IHsgYXdhaXQgYXBpKCcvYXV0aC9sb2dvdXQnLCB7IG1ldGhvZDogJ1BPU1QnIH0pOyB9IGNhdGNo" +
      "IHsgLyogaWdub3JlICovIH0KICAgIHJlc2V0VXNlclN0YXRlKCk7CiAgICBzdGF0ZS51c2VyID0gbnVsbDsKICAgIHNob3dBdXRo" +
      "KCk7CiAgICB0b2FzdCgn5bey6YCA5Ye655m75b2VJyk7CiAgfSk7CgogIGVsLnB3ZFN1Ym1pdC5hZGRFdmVudExpc3RlbmVyKCdj" +
      "bGljaycsIGFzeW5jICgpID0+IHsKICAgIGNvbnN0IGN1cnJlbnRQYXNzd29yZCA9IGVsLnB3ZEN1cnJlbnQudmFsdWU7CiAgICBj" +
      "b25zdCBuZXdQYXNzd29yZCA9IGVsLnB3ZE5ldy52YWx1ZTsKICAgIGlmIChuZXdQYXNzd29yZC5sZW5ndGggPCA2KSByZXR1cm4g" +
      "dG9hc3QoJ+aWsOWvhueggeiHs+WwkSA2IOS9jScsICdlcnInKTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBh" +
      "cGkoJy9hdXRoL3Bhc3N3b3JkJywgeyBtZXRob2Q6ICdQT1NUJywgYm9keTogeyBjdXJyZW50UGFzc3dvcmQsIG5ld1Bhc3N3b3Jk" +
      "IH0gfSk7CiAgICAgIHRvYXN0KGRhdGEubWVzc2FnZSB8fCAn5a+G56CB5bey5pu05pawJywgJ29rJyk7CiAgICAgIGVsLnB3ZEN1" +
      "cnJlbnQudmFsdWUgPSAnJzsKICAgICAgZWwucHdkTmV3LnZhbHVlID0gJyc7CiAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgdG9h" +
      "c3QoZXJyLm1lc3NhZ2UsICdlcnInKTsKICAgIH0KICB9KTsKCiAgLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDml6XmnJ8KICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KICBmdW5jdGlvbiByZW5kZXJEYXRlKCkgewog" +
      "ICAgY29uc3QgeyB0aXRsZSwgc3ViIH0gPSBodW1hbkRhdGUoc3RhdGUuZGF0ZSk7CiAgICBlbC5wYWdlVGl0bGUudGV4dENvbnRl" +
      "bnQgPSB0aXRsZTsKICAgIGVsLnBhZ2VEYXRlLnRleHRDb250ZW50ID0gc3ViOwogICAgZWwuZGF0ZVBpbGxUZXh0LnRleHRDb250" +
      "ZW50ID0gYCR7c3RhdGUuZGF0ZX0gJHtXRUVLREFZU1t3ZWVrZGF5T2Yoc3RhdGUuZGF0ZSldfWA7CiAgICBlbC5jb21wb3NlckRh" +
      "dGVUZXh0LnRleHRDb250ZW50ID0gdGl0bGUgPT09ICfku4rlpKknID8gJ+S7iuWkqScgOiBgJHtzdGF0ZS5kYXRlLnNsaWNlKDUp" +
      "fSAke1dFRUtEQVlTW3dlZWtkYXlPZihzdGF0ZS5kYXRlKV19YDsKICAgIGNvbnN0IGlzVG9kYXkgPSBzdGF0ZS5kYXRlID09PSB0" +
      "b2RheVN0cigpOwogICAgZWwuY2FycnlvdmVyQnRuLnN0eWxlLnZpc2liaWxpdHkgPSBpc1RvZGF5ID8gJ3Zpc2libGUnIDogJ2hp" +
      "ZGRlbic7CiAgICAvLyDml6Xljobop4blm77ot5/pmo/miYDpgInml6XmnJ8KICAgIGNvbnN0IFt5LCBtXSA9IHN0YXRlLmRhdGUu" +
      "c3BsaXQoJy0nKS5tYXAoTnVtYmVyKTsKICAgIGlmIChzdGF0ZS5jYWwueSAhPT0geSB8fCBzdGF0ZS5jYWwubSAhPT0gbSAtIDEp" +
      "IHsKICAgICAgc3RhdGUuY2FsID0geyB5LCBtOiBtIC0gMSB9OwogICAgICByZW5kZXJDYWxlbmRhcigpOwogICAgfSBlbHNlIHsK" +
      "ICAgICAgcmVuZGVyQ2FsZW5kYXIoKTsgICAvLyDph43mlrDmoIfkuq7pgInkuK3ml6UKICAgIH0KICB9CgogIGVsLnByZXZEYXku" +
      "YWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBpZiAoc3RhdGUubW9udGgpIHsgb3Blbk1vbnRoKHNoaWZ0TW9u" +
      "dGhTdHIoc3RhdGUubW9udGgsIC0xKSwgeyBjbG9zZVNpZGU6IGZhbHNlIH0pOyByZXR1cm47IH0KICAgIGdvdG9EYXRlKHNoaWZ0" +
      "RGF0ZShzdGF0ZS5kYXRlLCAtMSkpOwogIH0pOwogIGVsLm5leHREYXkuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7" +
      "CiAgICBpZiAoc3RhdGUubW9udGgpIHsgb3Blbk1vbnRoKHNoaWZ0TW9udGhTdHIoc3RhdGUubW9udGgsIDEpLCB7IGNsb3NlU2lk" +
      "ZTogZmFsc2UgfSk7IHJldHVybjsgfQogICAgZ290b0RhdGUoc2hpZnREYXRlKHN0YXRlLmRhdGUsIDEpKTsKICB9KTsKICAvKiAt" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0g6Ieq5a6a5LmJ5pel5pyf6YCJ5oup5by55bGCIC0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwog" +
      "IGNvbnN0IHBvcCA9IHsKICAgIG9wZW46IGZhbHNlLAogICAgdmlld1k6IDAsIHZpZXdNOiAwLCAgICAgIC8vIOW8ueWxguato+Wc" +
      "qOa1j+iniOeahOW5tCAvIOaciCgwLTExKQogICAgdmFsdWU6ICcnLCAgICAgICAgICAgICAgIC8vIOW9k+WJjemAieS4rSBZWVlZ" +
      "LU1NLURECiAgICBvcmlnaW46ICcnLCAgICAgICAgICAgICAgLy8g5omT5byA5pe255qE5Y6f5YC877yI44CM5riF56m644CN5oGi" +
      "5aSN55So77yJCiAgICBhbmNob3I6IG51bGwsCiAgICBvblBpY2s6IG51bGwsCiAgfTsKCiAgZnVuY3Rpb24gY2xvc2VEYXRlUG9w" +
      "KCkgewogICAgcG9wLm9wZW4gPSBmYWxzZTsKICAgIGVsLmRhdGVQb3AuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICBkb2N1" +
      "bWVudC5yZW1vdmVFdmVudExpc3RlbmVyKCdwb2ludGVyZG93bicsIHBvcC5vbk91dHNpZGUsIHRydWUpOwogICAgZG9jdW1lbnQu" +
      "cmVtb3ZlRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIHBvcC5vbktleWRvd24sIHRydWUpOwogICAgd2luZG93LnJlbW92ZUV2ZW50" +
      "TGlzdGVuZXIoJ3Njcm9sbCcsIGNsb3NlRGF0ZVBvcCwgdHJ1ZSk7CiAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcigncmVz" +
      "aXplJywgY2xvc2VEYXRlUG9wKTsKICB9CiAgcG9wLm9uT3V0c2lkZSA9IChlKSA9PiB7CiAgICBpZiAoIWVsLmRhdGVQb3AuY29u" +
      "dGFpbnMoZS50YXJnZXQpICYmIGUudGFyZ2V0ICE9PSBwb3AuYW5jaG9yICYmICFwb3AuYW5jaG9yPy5jb250YWlucyhlLnRhcmdl" +
      "dCkpIGNsb3NlRGF0ZVBvcCgpOwogIH07CiAgcG9wLm9uS2V5ZG93biA9IChlKSA9PiB7IGlmIChlLmtleSA9PT0gJ0VzY2FwZScp" +
      "IGNsb3NlRGF0ZVBvcCgpOyB9OwoKICBmdW5jdGlvbiBwb3NpdGlvbkRhdGVQb3AoKSB7CiAgICBjb25zdCByID0gcG9wLmFuY2hv" +
      "ci5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICAgIGNvbnN0IHBvcEVsID0gZWwuZGF0ZVBvcDsKICAgIGNvbnN0IHB3ID0gcG9w" +
      "RWwub2Zmc2V0V2lkdGg7CiAgICBjb25zdCBwaCA9IHBvcEVsLm9mZnNldEhlaWdodDsKICAgIGxldCBsZWZ0ID0gci5sZWZ0ICsg" +
      "ci53aWR0aCAvIDIgLSBwdyAvIDI7CiAgICBsZWZ0ID0gTWF0aC5tYXgoMTAsIE1hdGgubWluKGxlZnQsIHdpbmRvdy5pbm5lcldp" +
      "ZHRoIC0gcHcgLSAxMCkpOwogICAgbGV0IHRvcCA9IHIuYm90dG9tICsgODsKICAgIGlmICh0b3AgKyBwaCA+IHdpbmRvdy5pbm5l" +
      "ckhlaWdodCAtIDEwKSB0b3AgPSByLnRvcCAtIHBoIC0gODsKICAgIHBvcEVsLnN0eWxlLmxlZnQgPSBgJHtNYXRoLnJvdW5kKGxl" +
      "ZnQpfXB4YDsKICAgIHBvcEVsLnN0eWxlLnRvcCA9IGAke01hdGgucm91bmQoTWF0aC5tYXgoMTAsIHRvcCkpfXB4YDsKICB9Cgog" +
      "IGZ1bmN0aW9uIHJlbmRlckRhdGVQb3AoKSB7CiAgICAvLyDmoIfpopjnmoTkuKTkuKrovpPlhaXmoYblj6/miYvliqjloavlhpnl" +
      "ubQv5pyI77yb5q2j5Zyo6L6T5YWl5pe25LiN5Zue5YaZ77yM6YG/5YWN5omT5patCiAgICBpZiAoZG9jdW1lbnQuYWN0aXZlRWxl" +
      "bWVudCAhPT0gZWwucG9wWWVhcikgZWwucG9wWWVhci52YWx1ZSA9IFN0cmluZyhwb3Audmlld1kpOwogICAgaWYgKGRvY3VtZW50" +
      "LmFjdGl2ZUVsZW1lbnQgIT09IGVsLnBvcE1vbnRoKSBlbC5wb3BNb250aC52YWx1ZSA9IFN0cmluZyhwb3Audmlld00gKyAxKTsK" +
      "ICAgIGVsLnBvcEdyaWQuaW5uZXJIVE1MID0gJyc7CiAgICBjb25zdCB0b2RheSA9IHRvZGF5U3RyKCk7CiAgICBmb3IgKGNvbnN0" +
      "IG5hbWUgb2YgWyfml6UnLCAn5LiAJywgJ+S6jCcsICfkuIknLCAn5ZubJywgJ+S6lCcsICflha0nXSkgewogICAgICBlbC5wb3BH" +
      "cmlkLmFwcGVuZENoaWxkKE9iamVjdC5hc3NpZ24oZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpLCB7IGNsYXNzTmFtZTog" +
      "J2NhbC1kb3cnLCB0ZXh0Q29udGVudDogbmFtZSB9KSk7CiAgICB9CiAgICBjb25zdCBmaXJzdCA9IG5ldyBEYXRlKHBvcC52aWV3" +
      "WSwgcG9wLnZpZXdNLCAxKTsKICAgIGNvbnN0IHN0YXJ0ID0gbmV3IERhdGUoZmlyc3QpOwogICAgc3RhcnQuc2V0RGF0ZSgxIC0g" +
      "Zmlyc3QuZ2V0RGF5KCkpOyAgIC8vIOihpem9kOmmluWRqO+8jOWQq+ebuOmCu+aciAogICAgZm9yIChsZXQgaSA9IDA7IGkgPCA0" +
      "MjsgaSArPSAxKSB7CiAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZShzdGFydCk7CiAgICAgIGQuc2V0RGF0ZShzdGFydC5nZXREYXRl" +
      "KCkgKyBpKTsKICAgICAgY29uc3QgZGF0ZVN0ciA9IGAke2QuZ2V0RnVsbFllYXIoKX0tJHtwYWQoZC5nZXRNb250aCgpICsgMSl9" +
      "LSR7cGFkKGQuZ2V0RGF0ZSgpKX1gOwogICAgICBjb25zdCBvdXRzaWRlID0gZC5nZXRNb250aCgpICE9PSBwb3Audmlld007CiAg" +
      "ICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAgICBidG4udHlwZSA9ICdidXR0b24n" +
      "OwogICAgICBidG4uY2xhc3NOYW1lID0gJ2NhbC1kYXknCiAgICAgICAgKyAob3V0c2lkZSA/ICcgaXMtb3V0c2lkZScgOiAnJykK" +
      "ICAgICAgICArIChkYXRlU3RyID09PSB0b2RheSA/ICcgaXMtdG9kYXknIDogJycpCiAgICAgICAgKyAoZGF0ZVN0ciA9PT0gcG9w" +
      "LnZhbHVlID8gJyBpcy1zZWxlY3RlZCcgOiAnJyk7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9IFN0cmluZyhkLmdldERhdGUoKSk7" +
      "CiAgICAgIGJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICAgICBwb3AudmFsdWUgPSBkYXRlU3RyOwog" +
      "ICAgICAgIC8vIOeCueWIsOebuOmCu+aciOeahOaXpeacn+aXtu+8jOinhuWbvui3n+edgOe/u+i/h+WOuwogICAgICAgIHBvcC52" +
      "aWV3WSA9IGQuZ2V0RnVsbFllYXIoKTsKICAgICAgICBwb3Audmlld00gPSBkLmdldE1vbnRoKCk7CiAgICAgICAgcmVuZGVyRGF0" +
      "ZVBvcCgpOwogICAgICAgIHBvc2l0aW9uRGF0ZVBvcCgpOwogICAgICAgIHBvcC5vblBpY2s/Lihwb3AudmFsdWUpOwogICAgICB9" +
      "KTsKICAgICAgZWwucG9wR3JpZC5hcHBlbmRDaGlsZChidG4pOwogICAgfQogIH0KCiAgZnVuY3Rpb24gb3BlbkRhdGVQb3AoYW5j" +
      "aG9yLCB2YWx1ZSwgb25QaWNrKSB7CiAgICBwb3AuYW5jaG9yID0gYW5jaG9yOwogICAgcG9wLnZhbHVlID0gdmFsdWU7CiAgICBw" +
      "b3Aub3JpZ2luID0gdmFsdWU7CiAgICBwb3Aub25QaWNrID0gb25QaWNrOwogICAgcG9wLm9wZW4gPSB0cnVlOwogICAgY29uc3Qg" +
      "W3ksIG1dID0gdmFsdWUuc3BsaXQoJy0nKS5tYXAoTnVtYmVyKTsKICAgIHBvcC52aWV3WSA9IHk7CiAgICBwb3Audmlld00gPSBt" +
      "IC0gMTsKCiAgICBlbC5kYXRlUG9wLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgcmVuZGVyRGF0ZVBvcCgpOwogICAg" +
      "cG9zaXRpb25EYXRlUG9wKCk7CgogICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigncG9pbnRlcmRvd24nLCBwb3Aub25PdXRz" +
      "aWRlLCB0cnVlKTsKICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCBwb3Aub25LZXlkb3duLCB0cnVlKTsK" +
      "ICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdzY3JvbGwnLCBjbG9zZURhdGVQb3AsIHRydWUpOwogICAgd2luZG93LmFkZEV2" +
      "ZW50TGlzdGVuZXIoJ3Jlc2l6ZScsIGNsb3NlRGF0ZVBvcCk7CiAgfQoKICAvLyDmoIfpopjlubQv5pyI5Y+v5omL5Yqo5aGr5YaZ" +
      "77ya5Zue6L2m5oiW5aSx54Sm5ZCO6Lez6L2s77yM6Z2e5rOV6L6T5YWl6Ieq5Yqo6L+Y5Y6fCiAgZnVuY3Rpb24gYXBwbHlQb3BJ" +
      "bnB1dChpbnB1dCwgdG9WaWV3KSB7CiAgICBjb25zdCByYXcgPSBpbnB1dC52YWx1ZS50cmltKCk7CiAgICBjb25zdCBuID0gTnVt" +
      "YmVyKHJhdyk7CiAgICBpZiAoL15cZCskLy50ZXN0KHJhdykgJiYgbiA+PSAoaW5wdXQgPT09IGVsLnBvcFllYXIgPyAxIDogMSkg" +
      "JiYgbiA8PSAoaW5wdXQgPT09IGVsLnBvcFllYXIgPyA5OTk5IDogMTIpKSB7CiAgICAgIHRvVmlldyhuKTsKICAgIH0KICAgIHJl" +
      "bmRlckRhdGVQb3AoKTsgICAvLyDpnZ7ms5XovpPlhaXml7bku4Xov5jljp/mmL7npLoKICB9CiAgZWwucG9wWWVhci5hZGRFdmVu" +
      "dExpc3RlbmVyKCdmb2N1cycsICgpID0+IGVsLnBvcFllYXIuc2VsZWN0KCkpOwogIGVsLnBvcE1vbnRoLmFkZEV2ZW50TGlzdGVu" +
      "ZXIoJ2ZvY3VzJywgKCkgPT4gZWwucG9wTW9udGguc2VsZWN0KCkpOwogIGVsLnBvcFllYXIuYWRkRXZlbnRMaXN0ZW5lcignY2hh" +
      "bmdlJywgKCkgPT4gYXBwbHlQb3BJbnB1dChlbC5wb3BZZWFyLCAobikgPT4geyBwb3Audmlld1kgPSBuOyB9KSk7CiAgZWwucG9w" +
      "TW9udGguYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgKCkgPT4gYXBwbHlQb3BJbnB1dChlbC5wb3BNb250aCwgKG4pID0+IHsg" +
      "cG9wLnZpZXdNID0gbiAtIDE7IH0pKTsKICBmb3IgKGNvbnN0IGlucCBvZiBbZWwucG9wWWVhciwgZWwucG9wTW9udGhdKSB7CiAg" +
      "ICBpbnAuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIChlKSA9PiB7IGlmIChlLmtleSA9PT0gJ0VudGVyJykgaW5wLmJsdXIo" +
      "KTsgfSk7CiAgfQoKICAkKCdwb3AtcHJldi15ZWFyJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7IHBvcC52aWV3" +
      "WSAtPSAxOyByZW5kZXJEYXRlUG9wKCk7IH0pOwogICQoJ3BvcC1uZXh0LXllYXInKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycs" +
      "ICgpID0+IHsgcG9wLnZpZXdZICs9IDE7IHJlbmRlckRhdGVQb3AoKTsgfSk7CiAgJCgncG9wLXByZXYtbW9udGgnKS5hZGRFdmVu" +
      "dExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgIGNvbnN0IGQgPSBuZXcgRGF0ZShwb3Audmlld1ksIHBvcC52aWV3TSAtIDEs" +
      "IDEpOwogICAgcG9wLnZpZXdZID0gZC5nZXRGdWxsWWVhcigpOyBwb3Audmlld00gPSBkLmdldE1vbnRoKCk7IHJlbmRlckRhdGVQ" +
      "b3AoKTsKICB9KTsKICAkKCdwb3AtbmV4dC1tb250aCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgY29u" +
      "c3QgZCA9IG5ldyBEYXRlKHBvcC52aWV3WSwgcG9wLnZpZXdNICsgMSwgMSk7CiAgICBwb3Audmlld1kgPSBkLmdldEZ1bGxZZWFy" +
      "KCk7IHBvcC52aWV3TSA9IGQuZ2V0TW9udGgoKTsgcmVuZGVyRGF0ZVBvcCgpOwogIH0pOwogICQoJ3BvcC10b2RheScpLmFkZEV2" +
      "ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgcG9wLnZhbHVlID0gdG9kYXlTdHIoKTsKICAgIGNvbnN0IFt5LCBtXSA9" +
      "IHBvcC52YWx1ZS5zcGxpdCgnLScpLm1hcChOdW1iZXIpOwogICAgcG9wLnZpZXdZID0geTsgcG9wLnZpZXdNID0gbSAtIDE7CiAg" +
      "ICByZW5kZXJEYXRlUG9wKCk7CiAgICBwb3Aub25QaWNrPy4ocG9wLnZhbHVlKTsKICAgIGNsb3NlRGF0ZVBvcCgpOwogIH0pOwog" +
      "ICQoJ3BvcC1jbGVhcicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgcG9wLnZhbHVlID0gcG9wLm9yaWdp" +
      "bjsKICAgIHBvcC5vblBpY2s/Lihwb3AudmFsdWUpOwogICAgY2xvc2VEYXRlUG9wKCk7CiAgfSk7CiAgJCgncG9wLW9rJykuYWRk" +
      "RXZlbnRMaXN0ZW5lcignY2xpY2snLCBjbG9zZURhdGVQb3ApOwoKICBlbC5kYXRlUGlsbC5hZGRFdmVudExpc3RlbmVyKCdjbGlj" +
      "aycsICgpID0+IHsKICAgIGlmIChwb3Aub3BlbikgeyBjbG9zZURhdGVQb3AoKTsgcmV0dXJuOyB9CiAgICBvcGVuRGF0ZVBvcChl" +
      "bC5kYXRlUGlsbCwgc3RhdGUuZGF0ZSwgKGQpID0+IGdvdG9EYXRlKGQpKTsKICB9KTsKICBlbC5jb21wb3NlckRhdGUuYWRkRXZl" +
      "bnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBpZiAocG9wLm9wZW4pIHsgY2xvc2VEYXRlUG9wKCk7IHJldHVybjsgfQog" +
      "ICAgb3BlbkRhdGVQb3AoZWwuY29tcG9zZXJEYXRlLCBzdGF0ZS5kYXRlLCAoZCkgPT4gZ290b0RhdGUoZCkpOwogIH0pOwoKICBh" +
      "c3luYyBmdW5jdGlvbiBnb3RvRGF0ZShkYXRlKSB7CiAgICBpZiAoc3RhdGUuc2VhcmNoLmFjdGl2ZSB8fCBlbC5zZWFyY2hJbnB1" +
      "dC52YWx1ZSkgZXhpdFNlYXJjaCgpOwogICAgc3RhdGUubW9udGggPSBudWxsOwogICAgc3RhdGUuZGF0ZSA9IGRhdGU7CiAgICBy" +
      "ZW5kZXJEYXRlKCk7CiAgICBjbG9zZVNpZGViYXIoKTsKICAgIGF3YWl0IHJlZnJlc2goKTsKICB9CgogIC8qIC0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLSDmnIjop4blm74gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCgogIC8qKiDov5vl" +
      "haXmlbTmnIjop4blm77vvJrlsZXnpLror6XmnIjmiYDmnInku7vliqHvvIzmjInml6XmnJ/lgJLluo/liIbnu4QgKi8KICBhc3lu" +
      "YyBmdW5jdGlvbiBvcGVuTW9udGgobW9udGgsIHsgY2xvc2VTaWRlID0gdHJ1ZSB9ID0ge30pIHsKICAgIGlmIChzdGF0ZS5zZWFy" +
      "Y2guYWN0aXZlIHx8IGVsLnNlYXJjaElucHV0LnZhbHVlKSBleGl0U2VhcmNoKCk7CiAgICBzdGF0ZS5tb250aCA9IG1vbnRoOwoK" +
      "ICAgIC8vIOWQjOatpeaXpeWOhuS4juOAjOW9k+WJjeaXpeacn+OAjeS4iuS4i+aWh++8iGNvbXBvc2VyIOW9kuWxnuaXpeacn+iQ" +
      "veWcqOivpeaciOWGhe+8iQogICAgY29uc3QgW3ksIG1dID0gbW9udGguc3BsaXQoJy0nKS5tYXAoTnVtYmVyKTsKICAgIHN0YXRl" +
      "LmNhbCA9IHsgeSwgbTogbSAtIDEgfTsKICAgIGlmICghc3RhdGUuZGF0ZS5zdGFydHNXaXRoKGAke21vbnRofS1gKSkgewogICAg" +
      "ICBzdGF0ZS5kYXRlID0gc3RhdGUuc3RhdHMuZmluZCgocykgPT4gcy5kYXRlLnN0YXJ0c1dpdGgoYCR7bW9udGh9LWApKT8uZGF0" +
      "ZSB8fCBgJHttb250aH0tMDFgOwogICAgfQoKICAgIHJlbmRlck1vbnRoSGVhZGVyKCk7CiAgICByZW5kZXJDYWxlbmRhcigpOwog" +
      "ICAgY2xvc2VTaWRlICYmIGNsb3NlU2lkZWJhcigpOwogICAgYXdhaXQgcmVmcmVzaE1vbnRoKCk7CiAgfQoKICBmdW5jdGlvbiBl" +
      "eGl0TW9udGgoKSB7CiAgICBzdGF0ZS5tb250aCA9IG51bGw7CiAgICByZW5kZXJEYXRlKCk7CiAgICByZW5kZXJMaXN0KCk7CiAg" +
      "ICBlbC5hZGRJbnB1dC5mb2N1cyh7IHByZXZlbnRTY3JvbGw6IHRydWUgfSk7CiAgfQoKICAvKiog5pyI6KeG5Zu+55qE6aG26YOo" +
      "5qCH6aKY5LiO5pel5pyf5p2hICovCiAgZnVuY3Rpb24gcmVuZGVyTW9udGhIZWFkZXIoKSB7CiAgICBjb25zdCBbeSwgbV0gPSBz" +
      "dGF0ZS5tb250aC5zcGxpdCgnLScpLm1hcChOdW1iZXIpOwogICAgZWwucGFnZVRpdGxlLnRleHRDb250ZW50ID0gYCR7eX0g5bm0" +
      "ICR7bX0g5pyIYDsKICAgIGVsLnBhZ2VEYXRlLnRleHRDb250ZW50ID0gJ+aVtOaciOinhuWbviDCtyDmjInml6XmnJ/lgJLluo8n" +
      "OwogICAgZWwuZGF0ZVBpbGxUZXh0LnRleHRDb250ZW50ID0gYCR7c3RhdGUubW9udGh9IOWFqOaciGA7CiAgICAvLyBjb21wb3Nl" +
      "ciDlvZLlsZ7ml6XmnJ/kv53mjIHlnKjlvZPmnIjvvIzmlrDmt7vliqDnmoTku7vliqHkvJrokL3ov5vlvZPliY3mn6XnnIvnmoTm" +
      "nIjku70KICAgIGVsLmNvbXBvc2VyRGF0ZVRleHQudGV4dENvbnRlbnQgPSBgJHtzdGF0ZS5kYXRlLnNsaWNlKDUpfSAke1dFRUtE" +
      "QVlTW3dlZWtkYXlPZihzdGF0ZS5kYXRlKV19YDsKICAgIGVsLmNhcnJ5b3ZlckJ0bi5zdHlsZS52aXNpYmlsaXR5ID0gJ2hpZGRl" +
      "bic7CiAgfQoKICAvKiog5bqU55So5pW05pyI5pWw5o2u5Yiw6KeG5Zu+77yIcmVmcmVzaE1vbnRoIOS4k+eUqO+8iSAqLwogIGZ1" +
      "bmN0aW9uIGFwcGx5TW9udGhEYXRhKG1vbnRoLCB0b2RvcykgewogICAgaWYgKHN0YXRlLm1vbnRoICE9PSBtb250aCkgcmV0dXJu" +
      "OyAgIC8vIOeUqOaIt+W3suWIh+i1sAogICAgc3RhdGUubW9udGhUb2RvcyA9IHRvZG9zOwogICAgY29uc3QgdW5kb25lID0gdG9k" +
      "b3MuZmlsdGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGg7CiAgICBzdGF0ZS5yZW1haW5pbmcgPSB1bmRvbmU7CiAgICBzdGF0ZS50" +
      "b3RhbCA9IHRvZG9zLmxlbmd0aDsKICAgIGVsLnJlbWFpbmluZ0NvdW50LnRleHRDb250ZW50ID0gU3RyaW5nKHVuZG9uZSk7CiAg" +
      "ICBlbC5yZW1haW5pbmdMYWJlbC50ZXh0Q29udGVudCA9IHVuZG9uZSA9PT0gMAogICAgICA/ICh0b2Rvcy5sZW5ndGggPyAn5pys" +
      "5pyI5YWo6YOo5a6M5oiQIPCfjoknIDogJ+mhueW+heWujOaIkCcpCiAgICAgIDogJ+mhueW+heWujOaIkCc7CiAgICBlbC5jbGVh" +
      "ckRvbmVCdG4uZGlzYWJsZWQgPSAhdG9kb3Muc29tZSgodCkgPT4gdC5kb25lKTsKICAgIHJlbmRlckxpc3QoKTsKICB9CgogIGFz" +
      "eW5jIGZ1bmN0aW9uIHJlZnJlc2hNb250aCgpIHsKICAgIGNvbnN0IG1vbnRoID0gc3RhdGUubW9udGg7CiAgICBpZiAoIW1vbnRo" +
      "KSByZXR1cm47CgogICAgLy8gMSkg5pyJ57yT5a2Y77ya56uL5Y2z5riy5p+TCiAgICBjb25zdCBjYWNoZWQgPSBtb250aENhY2hl" +
      "LmdldChtb250aCk7CiAgICBpZiAoY2FjaGVkICYmIHN0YXRlLm1vbnRoID09PSBtb250aCkgYXBwbHlNb250aERhdGEobW9udGgs" +
      "IGNhY2hlZCk7CgogICAgLy8gMikg5ZCO5Y+w5qCh5paw77yI5pWw5o2u5rKh5Y+Y5bCx5LiN6YeN57uY77yJCiAgICB0cnkgewog" +
      "ICAgICBjb25zdCBkYXRhID0gYXdhaXQgYXBpKGAvdG9kb3M/bW9udGg9JHtlbmNvZGVVUklDb21wb25lbnQobW9udGgpfWApOwog" +
      "ICAgICBpZiAoc3RhdGUubW9udGggIT09IG1vbnRoKSByZXR1cm47ICAgLy8g55So5oi35bey5YiH6LWwCiAgICAgIGNvbnN0IHRv" +
      "ZG9zID0gZGF0YS50b2RvcyB8fCBbXTsKICAgICAgY29uc3QgdW5jaGFuZ2VkID0gY2FjaGVkICYmIEpTT04uc3RyaW5naWZ5KGNh" +
      "Y2hlZCkgPT09IEpTT04uc3RyaW5naWZ5KHRvZG9zKTsKICAgICAgaWYgKHVuY2hhbmdlZCkgcmV0dXJuOwogICAgICBpZiAobW9u" +
      "dGhDYWNoZS5zaXplID49IE1PTlRIX0NBQ0hFX01BWCkgbW9udGhDYWNoZS5kZWxldGUobW9udGhDYWNoZS5rZXlzKCkubmV4dCgp" +
      "LnZhbHVlKTsKICAgICAgbW9udGhDYWNoZS5zZXQobW9udGgsIHRvZG9zKTsKICAgICAgYXBwbHlNb250aERhdGEobW9udGgsIHRv" +
      "ZG9zKTsKCiAgICAgIC8vIDMpIOaVtOaciOaVsOaNrumhuuaJi+eBjOi/m+WNleaXpee8k+WtmO+8mueCueivpeaciOS7u+S9leS4" +
      "gOWkqemDveenkuW8gAogICAgICBjb25zdCBieURhdGUgPSBuZXcgTWFwKCk7CiAgICAgIGZvciAoY29uc3QgdCBvZiB0b2Rvcykg" +
      "ewogICAgICAgIGlmICghYnlEYXRlLmhhcyh0LmRhdGUpKSBieURhdGUuc2V0KHQuZGF0ZSwgW10pOwogICAgICAgIGJ5RGF0ZS5n" +
      "ZXQodC5kYXRlKS5wdXNoKHQpOwogICAgICB9CiAgICAgIGZvciAoY29uc3QgW2QsIGxpc3RdIG9mIGJ5RGF0ZSkgewogICAgICAg" +
      "IGlmICghZGF5Q2FjaGUuaGFzKGQpKSB7CiAgICAgICAgICBjYWNoZVNldERheShkLCBsaXN0LCBsaXN0LmZpbHRlcigodCkgPT4g" +
      "IXQuZG9uZSkubGVuZ3RoLCBsaXN0Lmxlbmd0aCk7CiAgICAgICAgfQogICAgICB9CiAgICB9IGNhdGNoIChlcnIpIHsKICAgICAg" +
      "aWYgKGVyci5zdGF0dXMgPT09IDQwMSkgeyBoYW5kbGVTZXNzaW9uTG9zdCgpOyByZXR1cm47IH0KICAgICAgaWYgKCFjYWNoZWQp" +
      "IHRvYXN0KGVyci5tZXNzYWdlLCAnZXJyJyk7CiAgICB9CiAgfQoKICAvKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKgogICAqIOWNoeeJh+a1gea4suafkwogICAqIC0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwogIGZ1bmN0aW9uIHJlbmRl" +
      "ckxpc3QoKSB7CiAgICBlbC5mZWVkLmlubmVySFRNTCA9ICcnOwoKICAgIGlmIChzdGF0ZS5zZWFyY2guYWN0aXZlKSB7CiAgICAg" +
      "IGVsLnNlYXJjaEJhbm5lci5jbGFzc0xpc3QucmVtb3ZlKCdoaWRkZW4nKTsKICAgICAgZWwuc2VhcmNoQmFubmVyVGV4dC50ZXh0" +
      "Q29udGVudCA9IHN0YXRlLnNlYXJjaC5sb2FkaW5nCiAgICAgICAgPyBg5q2j5Zyo5pCc57Si44CMJHtzdGF0ZS5zZWFyY2gucX3j" +
      "gI3igKZgCiAgICAgICAgOiBg5pCc57Si44CMJHtzdGF0ZS5zZWFyY2gucX3jgI3vvJoke3N0YXRlLnNlYXJjaC5yZXN1bHRzLmxl" +
      "bmd0aH0g5p2h57uT5p6cYDsKICAgICAgZWwuc2VhcmNoRXhpdC50ZXh0Q29udGVudCA9ICfpgIDlh7rmkJzntKInOwogICAgICBy" +
      "ZW5kZXJTZWFyY2hSZXN1bHRzKCk7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBpZiAoc3RhdGUubW9udGgpIHsKICAgICAgZWwu" +
      "c2VhcmNoQmFubmVyLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgICBjb25zdCBbeSwgbV0gPSBzdGF0ZS5tb250aC5z" +
      "cGxpdCgnLScpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCB1bmRvbmUgPSBzdGF0ZS5tb250aFRvZG9zLmZpbHRlcigodCkgPT4g" +
      "IXQuZG9uZSkubGVuZ3RoOwogICAgICBlbC5zZWFyY2hCYW5uZXJUZXh0LnRleHRDb250ZW50ID0gYCR7eX0g5bm0ICR7bX0g5pyI" +
      "IMK3IOWFsSAke3N0YXRlLm1vbnRoVG9kb3MubGVuZ3RofSDmnaEgwrcgJHt1bmRvbmV9IOmhueacquWujOaIkGA7CiAgICAgIGVs" +
      "LnNlYXJjaEV4aXQudGV4dENvbnRlbnQgPSAn6L+U5Zue5Y2V5pelJzsKICAgICAgcmVuZGVyTW9udGhSZXN1bHRzKCk7CiAgICAg" +
      "IHJldHVybjsKICAgIH0KCiAgICBlbC5zZWFyY2hCYW5uZXIuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICByZW5kZXJEYXlM" +
      "aXN0KCk7CiAgfQoKICAvKiog5b2T5YmN5pel5pyf55qE5b6F5Yqe5Y2h54mHICovCiAgZnVuY3Rpb24gcmVuZGVyRGF5TGlzdCgp" +
      "IHsKICAgIGlmICghc3RhdGUudG9kb3MubGVuZ3RoKSB7CiAgICAgIGVsLmVtcHR5U3RhdGUuY2xhc3NMaXN0LnJlbW92ZSgnaGlk" +
      "ZGVuJyk7CiAgICAgIGVsLmVtcHR5VGl0bGUudGV4dENvbnRlbnQgPSAn6L+Z6YeM6L+Y5rKh5pyJ5a6J5o6SJzsKICAgICAgZWwu" +
      "ZW1wdHlTdWIudGV4dENvbnRlbnQgPSAn5Zyo5LiK6Z2i55qE6L6T5YWl5qGG5pWy5LiL56ys5LiA5Lu25LqL5ZCnJzsKICAgIH0g" +
      "ZWxzZSB7CiAgICAgIGVsLmVtcHR5U3RhdGUuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICAgIGNvbnN0IGZyYWdtZW50ID0g" +
      "ZG9jdW1lbnQuY3JlYXRlRG9jdW1lbnRGcmFnbWVudCgpOwogICAgICBzdGF0ZS50b2Rvcy5mb3JFYWNoKCh0b2RvKSA9PiBmcmFn" +
      "bWVudC5hcHBlbmRDaGlsZChyZW5kZXJJdGVtKHRvZG8sIHsgc2hvd0RhdGU6IGZhbHNlIH0pKSk7CiAgICAgIGVsLmZlZWQuYXBw" +
      "ZW5kQ2hpbGQoZnJhZ21lbnQpOwogICAgfQogICAgZWwucmVtYWluaW5nQ291bnQudGV4dENvbnRlbnQgPSBTdHJpbmcoc3RhdGUu" +
      "cmVtYWluaW5nKTsKICAgIGVsLnJlbWFpbmluZ0xhYmVsLnRleHRDb250ZW50ID0gc3RhdGUucmVtYWluaW5nID09PSAwCiAgICAg" +
      "ID8gKHN0YXRlLnRvdGFsID8gJ+WFqOmDqOWujOaIkCDwn46JJyA6ICfpobnlvoXlrozmiJAnKQogICAgICA6ICfpobnlvoXlrozm" +
      "iJAnOwogICAgZWwuY2xlYXJEb25lQnRuLmRpc2FibGVkID0gIXN0YXRlLnRvZG9zLnNvbWUoKHQpID0+IHQuZG9uZSk7CiAgfQoK" +
      "ICAvKiog5pCc57Si57uT5p6c77ya5oyJ5pel5pyf5YiG57uE5bGV56S6ICovCiAgZnVuY3Rpb24gcmVuZGVyU2VhcmNoUmVzdWx0" +
      "cygpIHsKICAgIGlmICghc3RhdGUuc2VhcmNoLnJlc3VsdHMubGVuZ3RoKSB7CiAgICAgIGVsLmVtcHR5U3RhdGUuY2xhc3NMaXN0" +
      "LnJlbW92ZSgnaGlkZGVuJyk7CiAgICAgIGVsLmVtcHR5VGl0bGUudGV4dENvbnRlbnQgPSBzdGF0ZS5zZWFyY2gubG9hZGluZyA/" +
      "ICfmraPlnKjmkJzntKLigKYnIDogJ+ayoeacieaJvuWIsOWMuemFjeeahOS7u+WKoSc7CiAgICAgIGVsLmVtcHR5U3ViLnRleHRD" +
      "b250ZW50ID0gc3RhdGUuc2VhcmNoLmxvYWRpbmcgPyAnJyA6ICfmjaLkuKrlhbPplK7or43or5Xor5XvvIwj5qCH562+IOS5n+WP" +
      "r+S7peebtOaOpeaQnCc7CiAgICAgIHJldHVybjsKICAgIH0KICAgIGVsLmVtcHR5U3RhdGUuY2xhc3NMaXN0LmFkZCgnaGlkZGVu" +
      "Jyk7CiAgICByZW5kZXJHcm91cGVkQnlEYXRlKHN0YXRlLnNlYXJjaC5yZXN1bHRzKTsKICB9CgogIC8qKiDmnIjop4blm77vvJrm" +
      "lbTmnIjku7vliqHmjInml6XmnJ/liIbnu4TvvIjml6XmnJ/lgJLluo/vvInlsZXnpLogKi8KICBmdW5jdGlvbiByZW5kZXJNb250" +
      "aFJlc3VsdHMoKSB7CiAgICBpZiAoIXN0YXRlLm1vbnRoVG9kb3MubGVuZ3RoKSB7CiAgICAgIGVsLmVtcHR5U3RhdGUuY2xhc3NM" +
      "aXN0LnJlbW92ZSgnaGlkZGVuJyk7CiAgICAgIGVsLmVtcHR5VGl0bGUudGV4dENvbnRlbnQgPSAn6L+Z5Liq5pyI6L+Y5rKh5pyJ" +
      "5Lu75YqhJzsKICAgICAgZWwuZW1wdHlTdWIudGV4dENvbnRlbnQgPSAn5Zyo5pel5Y6G5oiW5pe26Ze057q/6YCJ5LiA5aSp77yM" +
      "5pWy5LiL56ys5LiA5Lu25LqL5ZCnJzsKICAgICAgcmV0dXJuOwogICAgfQogICAgZWwuZW1wdHlTdGF0ZS5jbGFzc0xpc3QuYWRk" +
      "KCdoaWRkZW4nKTsKICAgIHJlbmRlckdyb3VwZWRCeURhdGUoc3RhdGUubW9udGhUb2Rvcyk7CiAgfQoKICAvKiog6YCa55So77ya" +
      "5oyJ5pel5pyf5YiG57uE5riy5p+T5Y2h54mH5rWB77yM57uE5aS05pi+56S644CMeCDmnIggeCDml6Ugwrcg5Ymp5L2ZIC8g5YWx" +
      "IE7jgI0gKi8KICBmdW5jdGlvbiByZW5kZXJHcm91cGVkQnlEYXRlKGxpc3QpIHsKICAgIGNvbnN0IGdyb3VwcyA9IG5ldyBNYXAo" +
      "KTsKICAgIGZvciAoY29uc3QgdG9kbyBvZiBsaXN0KSB7CiAgICAgIGlmICghZ3JvdXBzLmhhcyh0b2RvLmRhdGUpKSBncm91cHMu" +
      "c2V0KHRvZG8uZGF0ZSwgW10pOwogICAgICBncm91cHMuZ2V0KHRvZG8uZGF0ZSkucHVzaCh0b2RvKTsKICAgIH0KCiAgICBjb25z" +
      "dCBmcmFnbWVudCA9IGRvY3VtZW50LmNyZWF0ZURvY3VtZW50RnJhZ21lbnQoKTsKICAgIGZvciAoY29uc3QgW2RhdGUsIGl0ZW1z" +
      "XSBvZiBncm91cHMpIHsKICAgICAgY29uc3QgaGVhZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICBoZWFk" +
      "LmNsYXNzTmFtZSA9ICdmZWVkLWRhdGUtaGVhZCc7CiAgICAgIGNvbnN0IHsgdGl0bGUgfSA9IGh1bWFuRGF0ZShkYXRlKTsKICAg" +
      "ICAgaGVhZC5hcHBlbmQoCiAgICAgICAgT2JqZWN0LmFzc2lnbihkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzcGFuJyksIHsgdGV4" +
      "dENvbnRlbnQ6IHRpdGxlIH0pLAogICAgICAgIE9iamVjdC5hc3NpZ24oZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc21hbGwnKSwg" +
      "eyB0ZXh0Q29udGVudDogZGF0ZSB9KSwKICAgICAgICBPYmplY3QuYXNzaWduKGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NwYW4n" +
      "KSwgewogICAgICAgICAgY2xhc3NOYW1lOiAnZmVlZC1kYXRlLWNvdW50JywKICAgICAgICAgIHRleHRDb250ZW50OiBgJHtpdGVt" +
      "cy5maWx0ZXIoKHQpID0+ICF0LmRvbmUpLmxlbmd0aH0g6aG55pyq5a6M5oiQIC8g5YWxICR7aXRlbXMubGVuZ3RofWAsCiAgICAg" +
      "ICAgfSksCiAgICAgICk7CiAgICAgIGZyYWdtZW50LmFwcGVuZENoaWxkKGhlYWQpOwogICAgICBpdGVtcy5mb3JFYWNoKCh0b2Rv" +
      "KSA9PiBmcmFnbWVudC5hcHBlbmRDaGlsZChyZW5kZXJJdGVtKHRvZG8sIHsgc2hvd0RhdGU6IGZhbHNlIH0pKSk7CiAgICB9CiAg" +
      "ICBlbC5mZWVkLmFwcGVuZENoaWxkKGZyYWdtZW50KTsKICB9CgogIGNvbnN0IENIRUNLX1NWRyA9ICc8c3ZnIHZpZXdCb3g9IjAg" +
      "MCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMy40IiBzdHJva2UtbGluZWNh" +
      "cD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik0yMCA2TDkgMTdsLTUtNSIvPjwvc3ZnPic7CiAgY29u" +
      "c3QgVFJBU0hfU1ZHID0gJzxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIg" +
      "c3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik0z" +
      "IDZoMThNOCA2VjRhMSAxIDAgMCAxIDEtMWg2YTEgMSAwIDAgMSAxIDF2Mk0xOSA2bC0xIDE0YTIgMiAwIDAgMS0yIDJIOGEyIDIg" +
      "MCAwIDEtMi0yTDUgNk0xMCAxMXY2TTE0IDExdjYiLz48L3N2Zz4nOwogIGNvbnN0IFBFTkNJTF9TVkcgPSAnPHN2ZyB2aWV3Qm94" +
      "PSIwIDAgMjQgMjQiIGZpbGw9Im5vbmUiIHN0cm9rZT0iY3VycmVudENvbG9yIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5l" +
      "Y2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBhdGggZD0iTTE3IDNhMi44NSAyLjgzIDAgMSAxIDQgNEw3LjUg" +
      "MjAuNSAyIDIybDEuNS01LjVaIi8+PC9zdmc+JzsKCiAgZnVuY3Rpb24gZm9ybWF0VGltZSh1bml4KSB7CiAgICBjb25zdCBkID0g" +
      "bmV3IERhdGUoKE51bWJlcih1bml4KSB8fCAwKSAqIDEwMDApOwogICAgcmV0dXJuIGAke3BhZChkLmdldEhvdXJzKCkpfToke3Bh" +
      "ZChkLmdldE1pbnV0ZXMoKSl9YDsKICB9CgogIGZ1bmN0aW9uIHJlbmRlckl0ZW0odG9kbywgeyBzaG93RGF0ZSA9IGZhbHNlIH0g" +
      "PSB7fSkgewogICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2FydGljbGUnKTsKICAgIGNhcmQuY2xhc3NO" +
      "YW1lID0gYG1lbW8ke3RvZG8uZG9uZSA/ICcgZG9uZScgOiAnJ31gOwogICAgY2FyZC5kYXRhc2V0LmlkID0gdG9kby5pZDsKCiAg" +
      "ICAvKiBtZXRhIOihjO+8muaXtumXtCArIOaTjeS9nCAqLwogICAgY29uc3QgbWV0YSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQo" +
      "J2RpdicpOwogICAgbWV0YS5jbGFzc05hbWUgPSAnbWVtby1tZXRhJzsKCiAgICBjb25zdCB0aW1lID0gZG9jdW1lbnQuY3JlYXRl" +
      "RWxlbWVudCgnc3BhbicpOwogICAgdGltZS5jbGFzc05hbWUgPSAnbWVtby10aW1lJzsKICAgIGNvbnN0IGNyZWF0ZWQgPSBuZXcg" +
      "RGF0ZSgoTnVtYmVyKHRvZG8uY3JlYXRlZEF0KSB8fCAwKSAqIDEwMDApOwogICAgY29uc3QgZGF0ZVRleHQgPSBzaG93RGF0ZQog" +
      "ICAgICA/IGAke2NyZWF0ZWQuZ2V0RnVsbFllYXIoKX0vJHtwYWQoY3JlYXRlZC5nZXRNb250aCgpICsgMSl9LyR7cGFkKGNyZWF0" +
      "ZWQuZ2V0RGF0ZSgpKX0gYAogICAgICA6ICcnOwogICAgdGltZS50ZXh0Q29udGVudCA9IGAke2RhdGVUZXh0fSR7Zm9ybWF0VGlt" +
      "ZSh0b2RvLmNyZWF0ZWRBdCl9YDsKCiAgICBjb25zdCBhY3RzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpOwogICAg" +
      "YWN0cy5jbGFzc05hbWUgPSAnbWVtby1hY3RzJzsKCiAgICBjb25zdCBlZGl0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYnV0" +
      "dG9uJyk7CiAgICBlZGl0LnR5cGUgPSAnYnV0dG9uJzsKICAgIGVkaXQuc2V0QXR0cmlidXRlKCdhcmlhLWxhYmVsJywgJ+e8lui+" +
      "keS7u+WKoScpOwogICAgZWRpdC5pbm5lckhUTUwgPSBQRU5DSUxfU1ZHOwoKICAgIGNvbnN0IGRlbCA9IGRvY3VtZW50LmNyZWF0" +
      "ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAgZGVsLnR5cGUgPSAnYnV0dG9uJzsKICAgIGRlbC5jbGFzc05hbWUgPSAnbWVtby1kZWwn" +
      "OwogICAgZGVsLnNldEF0dHJpYnV0ZSgnYXJpYS1sYWJlbCcsICfliKDpmaTku7vliqEnKTsKICAgIGRlbC5pbm5lckhUTUwgPSBU" +
      "UkFTSF9TVkc7CiAgICBkZWwuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBkZWxldGVUb2RvKHRvZG8sIGNhcmQpKTsK" +
      "CiAgICBhY3RzLmFwcGVuZChlZGl0LCBkZWwpOwogICAgbWV0YS5hcHBlbmQodGltZSwgYWN0cyk7CgogICAgLyogYm9kee+8muWL" +
      "vumAiSArIOWGheWuuSAqLwogICAgY29uc3QgYm9keSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgYm9keS5j" +
      "bGFzc05hbWUgPSAnbWVtby1ib2R5JzsKCiAgICBjb25zdCBjaGVjayA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2J1dHRvbicp" +
      "OwogICAgY2hlY2sudHlwZSA9ICdidXR0b24nOwogICAgY2hlY2suY2xhc3NOYW1lID0gJ2NoZWNrJzsKICAgIGNoZWNrLnNldEF0" +
      "dHJpYnV0ZSgnYXJpYS1sYWJlbCcsIHRvZG8uZG9uZSA/ICfmoIforrDkuLrmnKrlrozmiJAnIDogJ+agh+iusOS4uuW3suWujOaI" +
      "kCcpOwogICAgY2hlY2suc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcodG9kby5kb25lKSk7CiAgICBjaGVjay5p" +
      "bm5lckhUTUwgPSBDSEVDS19TVkc7CiAgICBjaGVjay5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHRvZ2dsZVRvZG8o" +
      "dG9kbykpOwoKICAgIGNvbnN0IHRleHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIHRleHQuY2xhc3NOYW1l" +
      "ID0gJ21lbW8tdGV4dCc7CiAgICB0ZXh0LnRpdGxlID0gJ+mVv+aMieaIluWPjOWHu+WPr+e8lui+kSc7CiAgICByZW5kZXJUaXRs" +
      "ZVdpdGhUYWdzKHRleHQsIHRvZG8udGl0bGUpOwogICAgY29uc3QgZWRpdEFwaSA9IGJpbmRFZGl0KGNhcmQsIHRleHQsIHRvZG8p" +
      "OwogICAgZWRpdC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IGVkaXRBcGkuZW50ZXJFZGl0KCkpOwoKICAgIGJvZHku" +
      "YXBwZW5kKGNoZWNrLCB0ZXh0KTsKICAgIGNhcmQuYXBwZW5kKG1ldGEsIGJvZHkpOwogICAgcmV0dXJuIGNhcmQ7CiAgfQoKICAv" +
      "Kiog5oqK5qCH6aKY6YeM55qEICPmoIfnrb4g5riy5p+T5oiQ5Y+v54K55Ye755qE5b6954mH77yI5YW25L2Z5L+d5oyB57qv5paH" +
      "5pys77yM6ZiyIFhTU++8iSAqLwogIGZ1bmN0aW9uIHJlbmRlclRpdGxlV2l0aFRhZ3MoY29udGFpbmVyLCB0aXRsZSkgewogICAg" +
      "Y29uc3QgcmUgPSBuZXcgUmVnRXhwKFRBR19SRS5zb3VyY2UsICdnJyk7CiAgICBsZXQgbGFzdCA9IDA7CiAgICBsZXQgbWF0Y2g7" +
      "CiAgICB3aGlsZSAoKG1hdGNoID0gcmUuZXhlYyh0aXRsZSkpKSB7CiAgICAgIGlmIChtYXRjaC5pbmRleCA+IGxhc3QpIHsKICAg" +
      "ICAgICBjb250YWluZXIuYXBwZW5kQ2hpbGQoZG9jdW1lbnQuY3JlYXRlVGV4dE5vZGUodGl0bGUuc2xpY2UobGFzdCwgbWF0Y2gu" +
      "aW5kZXgpKSk7CiAgICAgIH0KICAgICAgY29uc3QgY2hpcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAg" +
      "ICBjaGlwLnR5cGUgPSAnYnV0dG9uJzsKICAgICAgY2hpcC5jbGFzc05hbWUgPSAndGFnLWNoaXAnOwogICAgICBjaGlwLnRleHRD" +
      "b250ZW50ID0gYCMke21hdGNoWzFdfWA7CiAgICAgIGNoaXAudGl0bGUgPSBg5p+l55yLICMke21hdGNoWzFdfSDnmoTlhajpg6jk" +
      "u7vliqFgOwogICAgICBjaGlwLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gc3RhcnRTZWFyY2goYCMke21hdGNoWzFd" +
      "fWApKTsKICAgICAgY29udGFpbmVyLmFwcGVuZENoaWxkKGNoaXApOwogICAgICBsYXN0ID0gbWF0Y2guaW5kZXggKyBtYXRjaFsw" +
      "XS5sZW5ndGg7CiAgICB9CiAgICBpZiAobGFzdCA8IHRpdGxlLmxlbmd0aCkgewogICAgICBjb250YWluZXIuYXBwZW5kQ2hpbGQo" +
      "ZG9jdW1lbnQuY3JlYXRlVGV4dE5vZGUodGl0bGUuc2xpY2UobGFzdCkpKTsKICAgIH0KICB9CgogIC8qKiDplb/mjIkgLyDlj4zl" +
      "h7sgLyDpk4XnrJTov5vlhaXooYzlhoXnvJbovpEgKi8KICBmdW5jdGlvbiBiaW5kRWRpdChjYXJkLCBub2RlLCB0b2RvKSB7CiAg" +
      "ICBsZXQgdGltZXIgPSBudWxsOwoKICAgIGNvbnN0IHN0YXJ0ID0gKCkgPT4gewogICAgICB0aW1lciA9IHNldFRpbWVvdXQoKCkg" +
      "PT4geyB0aW1lciA9IG51bGw7IGVudGVyRWRpdCgpOyB9LCA1MjApOwogICAgfTsKICAgIGNvbnN0IGNhbmNlbCA9ICgpID0+IHsg" +
      "aWYgKHRpbWVyKSB7IGNsZWFyVGltZW91dCh0aW1lcik7IHRpbWVyID0gbnVsbDsgfSB9OwoKICAgIG5vZGUuYWRkRXZlbnRMaXN0" +
      "ZW5lcigndG91Y2hzdGFydCcsIHN0YXJ0LCB7IHBhc3NpdmU6IHRydWUgfSk7CiAgICBub2RlLmFkZEV2ZW50TGlzdGVuZXIoJ3Rv" +
      "dWNoZW5kJywgY2FuY2VsKTsKICAgIG5vZGUuYWRkRXZlbnRMaXN0ZW5lcigndG91Y2htb3ZlJywgY2FuY2VsKTsKICAgIG5vZGUu" +
      "YWRkRXZlbnRMaXN0ZW5lcignbW91c2Vkb3duJywgc3RhcnQpOwogICAgbm9kZS5hZGRFdmVudExpc3RlbmVyKCdtb3VzZXVwJywg" +
      "Y2FuY2VsKTsKICAgIG5vZGUuYWRkRXZlbnRMaXN0ZW5lcignbW91c2VsZWF2ZScsIGNhbmNlbCk7CiAgICBub2RlLmFkZEV2ZW50" +
      "TGlzdGVuZXIoJ2RibGNsaWNrJywgKGUpID0+IHsgZS5wcmV2ZW50RGVmYXVsdCgpOyBlbnRlckVkaXQoKTsgfSk7CgogICAgZnVu" +
      "Y3Rpb24gZW50ZXJFZGl0KCkgewogICAgICBpZiAobm9kZS5pc0NvbnRlbnRFZGl0YWJsZSkgcmV0dXJuOwogICAgICBjb25zdCBv" +
      "cmlnaW5hbCA9IHRvZG8udGl0bGU7CiAgICAgIC8vIOWFiOaLjeW5s+aIkOe6r+aWh+acrOWGjee8lui+ke+8iOWOu+aOieagh+et" +
      "vuW+veeJh++8iQogICAgICBub2RlLnRleHRDb250ZW50ID0gb3JpZ2luYWw7CiAgICAgIG5vZGUuY29udGVudEVkaXRhYmxlID0g" +
      "J3RydWUnOwogICAgICBub2RlLmZvY3VzKCk7CiAgICAgIGRvY3VtZW50LmdldFNlbGVjdGlvbigpPy5zZWxlY3RBbGxDaGlsZHJl" +
      "bihub2RlKTsKCiAgICAgIGNvbnN0IGZpbmlzaCA9IGFzeW5jIChzYXZlKSA9PiB7CiAgICAgICAgbm9kZS5jb250ZW50RWRpdGFi" +
      "bGUgPSAnZmFsc2UnOwogICAgICAgIGNvbnN0IG5leHQgPSBub2RlLnRleHRDb250ZW50LnJlcGxhY2UoL1xzKy9nLCAnICcpLnRy" +
      "aW0oKTsKCiAgICAgICAgaWYgKCFzYXZlIHx8ICFuZXh0IHx8IG5leHQgPT09IG9yaWdpbmFsKSB7CiAgICAgICAgICBub2RlLnRl" +
      "eHRDb250ZW50ID0gJyc7CiAgICAgICAgICByZW5kZXJUaXRsZVdpdGhUYWdzKG5vZGUsIG9yaWdpbmFsKTsKICAgICAgICAgIHJl" +
      "dHVybjsKICAgICAgICB9CiAgICAgICAgbm9kZS50ZXh0Q29udGVudCA9IG5leHQ7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNv" +
      "bnN0IGRhdGEgPSBhd2FpdCBhcGkoYC90b2Rvcy8ke2VuY29kZVVSSUNvbXBvbmVudCh0b2RvLmlkKX1gLCB7IG1ldGhvZDogJ1BB" +
      "VENIJywgYm9keTogeyB0aXRsZTogbmV4dCB9IH0pOwogICAgICAgICAgT2JqZWN0LmFzc2lnbih0b2RvLCB7IHRpdGxlOiBuZXh0" +
      "IH0pOwogICAgICAgICAgdXBkYXRlQ291bnRzKGRhdGEpOwogICAgICAgICAgc3luY0RheUNhY2hlKCk7CiAgICAgICAgICBzY2hl" +
      "ZHVsZVNpZGViYXJSZWZyZXNoKCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICB0b2FzdChlcnIubWVzc2FnZSwg" +
      "J2VycicpOwogICAgICAgIH0gZmluYWxseSB7CiAgICAgICAgICBub2RlLnRleHRDb250ZW50ID0gJyc7CiAgICAgICAgICByZW5k" +
      "ZXJUaXRsZVdpdGhUYWdzKG5vZGUsIHRvZG8udGl0bGUpOwogICAgICAgIH0KICAgICAgfTsKCiAgICAgIGNvbnN0IG9uS2V5ID0g" +
      "KGUpID0+IHsKICAgICAgICBpZiAoZS5rZXkgPT09ICdFbnRlcicpIHsgZS5wcmV2ZW50RGVmYXVsdCgpOyBub2RlLmJsdXIoKTsg" +
      "fQogICAgICAgIGlmIChlLmtleSA9PT0gJ0VzY2FwZScpIHsgbm9kZS50ZXh0Q29udGVudCA9IG9yaWdpbmFsOyBub2RlLmJsdXIo" +
      "KTsgfQogICAgICB9OwogICAgICBjb25zdCBvbkJsdXIgPSAoKSA9PiB7CiAgICAgICAgbm9kZS5yZW1vdmVFdmVudExpc3RlbmVy" +
      "KCdrZXlkb3duJywgb25LZXkpOwogICAgICAgIG5vZGUucmVtb3ZlRXZlbnRMaXN0ZW5lcignYmx1cicsIG9uQmx1cik7CiAgICAg" +
      "ICAgZmluaXNoKG5vZGUudGV4dENvbnRlbnQudHJpbSgpICE9PSBvcmlnaW5hbCk7CiAgICAgIH07CgogICAgICBub2RlLmFkZEV2" +
      "ZW50TGlzdGVuZXIoJ2tleWRvd24nLCBvbktleSk7CiAgICAgIG5vZGUuYWRkRXZlbnRMaXN0ZW5lcignYmx1cicsIG9uQmx1cik7" +
      "CiAgICB9CgogICAgcmV0dXJuIHsgZW50ZXJFZGl0IH07CiAgfQoKICBmdW5jdGlvbiB1cGRhdGVDb3VudHMoZGF0YSkgewogICAg" +
      "aWYgKHR5cGVvZiBkYXRhPy5yZW1haW5pbmcgPT09ICdudW1iZXInKSBzdGF0ZS5yZW1haW5pbmcgPSBkYXRhLnJlbWFpbmluZzsK" +
      "ICAgIGlmICh0eXBlb2YgZGF0YT8udG90YWwgPT09ICdudW1iZXInKSBzdGF0ZS50b3RhbCA9IGRhdGEudG90YWw7CiAgICBlbC5y" +
      "ZW1haW5pbmdDb3VudC50ZXh0Q29udGVudCA9IFN0cmluZyhzdGF0ZS5yZW1haW5pbmcpOwogICAgZWwucmVtYWluaW5nTGFiZWwu" +
      "dGV4dENvbnRlbnQgPSBzdGF0ZS5yZW1haW5pbmcgPT09IDAKICAgICAgPyAoc3RhdGUudG90YWwgPyAn5YWo6YOo5a6M5oiQIPCf" +
      "joknIDogJ+mhueW+heWujOaIkCcpCiAgICAgIDogJ+mhueW+heWujOaIkCc7CiAgICBlbC5jbGVhckRvbmVCdG4uZGlzYWJsZWQg" +
      "PSAhc3RhdGUudG9kb3Muc29tZSgodCkgPT4gdC5kb25lKTsKICB9CgogIGFzeW5jIGZ1bmN0aW9uIHJlZnJlc2goKSB7CiAgICBj" +
      "b25zdCBkYXRlID0gc3RhdGUuZGF0ZTsKICAgIGNvbnN0IGNhY2hlZCA9IGRheUNhY2hlLmdldChkYXRlKTsKCiAgICAvLyAxKSDm" +
      "nInnvJPlrZjvvJrnq4vljbPmuLLmn5PvvIznlKjmiLfpm7bnrYnlvoUKICAgIGlmIChjYWNoZWQgJiYgc3RhdGUuZGF0ZSA9PT0g" +
      "ZGF0ZSAmJiAhc3RhdGUubW9udGggJiYgIXN0YXRlLnNlYXJjaC5hY3RpdmUpIHsKICAgICAgc3RhdGUudG9kb3MgPSBjYWNoZWQu" +
      "dG9kb3M7CiAgICAgIHN0YXRlLnJlbWFpbmluZyA9IGNhY2hlZC5yZW1haW5pbmc7CiAgICAgIHN0YXRlLnRvdGFsID0gY2FjaGVk" +
      "LnRvdGFsOwogICAgICByZW5kZXJMaXN0KCk7CiAgICB9CgogICAgLy8gMikg5ZCO5Y+w6K+35rGC5pyA5paw5pWw5o2u77yI5pyJ" +
      "57yT5a2Y5pe25pWw5o2u5rKh5Y+Y5bCx5LiN6YeN57uY77yM6YG/5YWN6Zeq54OB77yJCiAgICB0cnkgewogICAgICBjb25zdCBk" +
      "YXRhID0gYXdhaXQgYXBpKGAvdG9kb3M/ZGF0ZT0ke2VuY29kZVVSSUNvbXBvbmVudChkYXRlKX1gKTsKICAgICAgY29uc3QgdG9k" +
      "b3MgPSBkYXRhLnRvZG9zIHx8IFtdOwogICAgICBjb25zdCByZW1haW5pbmcgPSBkYXRhLnJlbWFpbmluZyA/PyB0b2Rvcy5maWx0" +
      "ZXIoKHQpID0+ICF0LmRvbmUpLmxlbmd0aDsKICAgICAgY29uc3QgdG90YWwgPSBkYXRhLnRvdGFsID8/IHRvZG9zLmxlbmd0aDsK" +
      "ICAgICAgY29uc3QgdW5jaGFuZ2VkID0gY2FjaGVkCiAgICAgICAgJiYgY2FjaGVkLnJlbWFpbmluZyA9PT0gcmVtYWluaW5nCiAg" +
      "ICAgICAgJiYgY2FjaGVkLnRvdGFsID09PSB0b3RhbAogICAgICAgICYmIEpTT04uc3RyaW5naWZ5KGNhY2hlZC50b2RvcykgPT09" +
      "IEpTT04uc3RyaW5naWZ5KHRvZG9zKTsKICAgICAgaWYgKCF1bmNoYW5nZWQpIGNhY2hlU2V0RGF5KGRhdGUsIHRvZG9zLCByZW1h" +
      "aW5pbmcsIHRvdGFsKTsKCiAgICAgIGlmIChzdGF0ZS5kYXRlICE9PSBkYXRlIHx8IHN0YXRlLm1vbnRoIHx8IHN0YXRlLnNlYXJj" +
      "aC5hY3RpdmUpIHJldHVybjsgICAvLyDnlKjmiLflt7LliIfotbAKICAgICAgaWYgKHVuY2hhbmdlZCkgcmV0dXJuOyAgICAgICAg" +
      "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIOeUu+mdouW3suaYr+acgOaWsAogICAgICBzdGF0" +
      "ZS50b2RvcyA9IHRvZG9zOwogICAgICBzdGF0ZS5yZW1haW5pbmcgPSByZW1haW5pbmc7CiAgICAgIHN0YXRlLnRvdGFsID0gdG90" +
      "YWw7CiAgICAgIHJlbmRlckxpc3QoKTsKCiAgICAgIC8vIDMpIOmhuuaJi+mihOWPluWJjeS4gOWkqS/lkI7kuIDlpKnvvIzlt6bl" +
      "j7PliIfmjaLml6XmnJ/ml7bnp5LlvIAKICAgICAgcHJlZmV0Y2hEYXkoc2hpZnREYXRlKGRhdGUsIC0xKSk7CiAgICAgIHByZWZl" +
      "dGNoRGF5KHNoaWZ0RGF0ZShkYXRlLCAxKSk7CiAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgaWYgKGVyci5zdGF0dXMgPT09IDQw" +
      "MSkgeyBoYW5kbGVTZXNzaW9uTG9zdCgpOyByZXR1cm47IH0KICAgICAgaWYgKCFjYWNoZWQpIHRvYXN0KGVyci5tZXNzYWdlLCAn" +
      "ZXJyJyk7ICAgLy8g5bey5pyJ57yT5a2Y5YaF5a655Zyo5bGV56S65pe26Z2Z6buYCiAgICB9CiAgfQoKICAvKiAtLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKgogICAqIOS+p+agj++8mue7" +
      "n+iuoSAvIOaXpeWOhiAvIOagh+etviAvIOaXtumXtOe6vwogICAqIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwogIGxldCBzaWRlYmFyVGltZXIgPSBudWxsOwogIC8qKiDmlbDmja7l" +
      "j5jmm7TlkI7pnZnpu5jliLfmlrDkvqfmoI/vvIjpmLLmipbvvIzpgb/lhY3popHnuYHor7fmsYLvvIkgKi8KICBmdW5jdGlvbiBz" +
      "Y2hlZHVsZVNpZGViYXJSZWZyZXNoKCkgewogICAgY2xlYXJUaW1lb3V0KHNpZGViYXJUaW1lcik7CiAgICBzaWRlYmFyVGltZXIg" +
      "PSBzZXRUaW1lb3V0KGxvYWRTaWRlYmFyRGF0YSwgOTAwKTsKICB9CgogIGFzeW5jIGZ1bmN0aW9uIGxvYWRTaWRlYmFyRGF0YSgp" +
      "IHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IFtzdGF0c1JlcywgdGFnc1Jlc10gPSBhd2FpdCBQcm9taXNlLmFsbChbCiAgICAgICAg" +
      "YXBpKCcvdG9kb3Mvc3RhdHM/ZGF5cz0zNjUnKSwKICAgICAgICBhcGkoJy90YWdzJyksCiAgICAgIF0pOwogICAgICBzdGF0ZS5z" +
      "dGF0cyA9IHN0YXRzUmVzLnN0YXRzIHx8IFtdOwogICAgICBzdGF0ZS50YWdzID0gdGFnc1Jlcy50YWdzIHx8IFtdOwogICAgfSBj" +
      "YXRjaCB7IC8qIOmdmem7mOWksei0pe+8jOS4jeW9seWTjeS4u+a1geeoiyAqLyB9CiAgICByZW5kZXJTdGF0cygpOwogICAgcmVu" +
      "ZGVyQ2FsZW5kYXIoKTsKICAgIHJlbmRlclRhZ3MoKTsKICAgIHJlbmRlclRpbWVsaW5lKCk7CiAgfQoKICBmdW5jdGlvbiByZW5k" +
      "ZXJTdGF0cygpIHsKICAgIGxldCB0b3RhbCA9IDA7CiAgICBsZXQgcmVtYWluaW5nID0gMDsKICAgIGZvciAoY29uc3QgcyBvZiBz" +
      "dGF0ZS5zdGF0cykgeyB0b3RhbCArPSBzLnRvdGFsOyByZW1haW5pbmcgKz0gcy5yZW1haW5pbmc7IH0KICAgIGVsLnN0YXREYXlz" +
      "LnRleHRDb250ZW50ID0gU3RyaW5nKHN0YXRlLnN0YXRzLmxlbmd0aCk7CiAgICBlbC5zdGF0VG90YWwudGV4dENvbnRlbnQgPSBT" +
      "dHJpbmcodG90YWwpOwogICAgZWwuc3RhdERvbmUudGV4dENvbnRlbnQgPSBTdHJpbmcodG90YWwgLSByZW1haW5pbmcpOwogIH0K" +
      "CiAgZnVuY3Rpb24gcmVuZGVyQ2FsZW5kYXIoKSB7CiAgICBjb25zdCB7IHksIG0gfSA9IHN0YXRlLmNhbDsKICAgIGVsLmNhbFRp" +
      "dGxlLnRleHRDb250ZW50ID0gYCR7eX0g5bm0ICR7bSArIDF9IOaciGA7CiAgICBlbC5jYWxUaXRsZS50aXRsZSA9IGDmn6XnnIsg" +
      "JHt5fSDlubQgJHttICsgMX0g5pyI5YWo6YOo5Lu75YqhYDsKICAgIGVsLmNhbGVuZGFyLmlubmVySFRNTCA9ICcnOwoKICAgIGNv" +
      "bnN0IGJ5RGF0ZSA9IG5ldyBNYXAoc3RhdGUuc3RhdHMubWFwKChzKSA9PiBbcy5kYXRlLCBzXSkpOwogICAgY29uc3QgdG9kYXkg" +
      "PSB0b2RheVN0cigpOwogICAgZm9yIChjb25zdCBuYW1lIG9mIFsn5pelJywgJ+S4gCcsICfkuownLCAn5LiJJywgJ+WbmycsICfk" +
      "upQnLCAn5YWtJ10pIHsKICAgICAgZWwuY2FsZW5kYXIuYXBwZW5kQ2hpbGQoT2JqZWN0LmFzc2lnbihkb2N1bWVudC5jcmVhdGVF" +
      "bGVtZW50KCdzcGFuJyksIHsgY2xhc3NOYW1lOiAnY2FsLWRvdycsIHRleHRDb250ZW50OiBuYW1lIH0pKTsKICAgIH0KCiAgICBj" +
      "b25zdCBmaXJzdERvdyA9IG5ldyBEYXRlKHksIG0sIDEpLmdldERheSgpOwogICAgY29uc3QgZGF5c0luTW9udGggPSBuZXcgRGF0" +
      "ZSh5LCBtICsgMSwgMCkuZ2V0RGF0ZSgpOwogICAgZm9yIChsZXQgaSA9IDA7IGkgPCBmaXJzdERvdzsgaSArPSAxKSB7CiAgICAg" +
      "IGVsLmNhbGVuZGFyLmFwcGVuZENoaWxkKE9iamVjdC5hc3NpZ24oZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpLCB7IGNs" +
      "YXNzTmFtZTogJ2NhbC1ibGFuaycgfSkpOwogICAgfQogICAgZm9yIChsZXQgZCA9IDE7IGQgPD0gZGF5c0luTW9udGg7IGQgKz0g" +
      "MSkgewogICAgICBjb25zdCBkYXRlU3RyID0gYCR7eX0tJHtwYWQobSArIDEpfS0ke3BhZChkKX1gOwogICAgICBjb25zdCBpbmZv" +
      "ID0gYnlEYXRlLmdldChkYXRlU3RyKTsKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYnV0dG9uJyk7" +
      "CiAgICAgIGJ0bi50eXBlID0gJ2J1dHRvbic7CiAgICAgIGJ0bi5jbGFzc05hbWUgPSAnY2FsLWRheScKICAgICAgICArIChpbmZv" +
      "ID8gJyBoYXMtdGFza3MnIDogJycpCiAgICAgICAgKyAoZGF0ZVN0ciA9PT0gdG9kYXkgPyAnIGlzLXRvZGF5JyA6ICcnKQogICAg" +
      "ICAgICsgKGRhdGVTdHIgPT09IHN0YXRlLmRhdGUgPyAnIGlzLXNlbGVjdGVkJyA6ICcnKTsKICAgICAgYnRuLnRleHRDb250ZW50" +
      "ID0gU3RyaW5nKGQpOwogICAgICBpZiAoaW5mbykgewogICAgICAgIGJ0bi50aXRsZSA9IGAke2RhdGVTdHJ9IMK3ICR7aW5mby5y" +
      "ZW1haW5pbmd9IOmhueacquWujOaIkCAvIOWFsSAke2luZm8udG90YWx9YDsKICAgICAgICBidG4uYXBwZW5kQ2hpbGQoT2JqZWN0" +
      "LmFzc2lnbihkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzcGFuJyksIHsgY2xhc3NOYW1lOiAnZG90JyB9KSk7CiAgICAgIH0KICAg" +
      "ICAgYnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gZ290b0RhdGUoZGF0ZVN0cikpOwogICAgICBlbC5jYWxlbmRh" +
      "ci5hcHBlbmRDaGlsZChidG4pOwogICAgfQogIH0KCiAgZWwuY2FsUHJldi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+" +
      "IHNoaWZ0TW9udGgoLTEpKTsKICBlbC5jYWxOZXh0LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gc2hpZnRNb250aCgx" +
      "KSk7CiAgLy8g54K55Ye75pel5Y6G5qCH6aKYIOKGkiDmn6XnnIvor6XmnIjlhajpg6jku7vliqHnmoTmlbTmnIjop4blm74KICBl" +
      "bC5jYWxUaXRsZS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IG9wZW5Nb250aChgJHtzdGF0ZS5jYWwueX0tJHtwYWQo" +
      "c3RhdGUuY2FsLm0gKyAxKX1gKSk7CiAgZnVuY3Rpb24gc2hpZnRNb250aChkZWx0YSkgewogICAgY29uc3QgZCA9IG5ldyBEYXRl" +
      "KHN0YXRlLmNhbC55LCBzdGF0ZS5jYWwubSArIGRlbHRhLCAxKTsKICAgIHN0YXRlLmNhbCA9IHsgeTogZC5nZXRGdWxsWWVhcigp" +
      "LCBtOiBkLmdldE1vbnRoKCkgfTsKICAgIHJlbmRlckNhbGVuZGFyKCk7CiAgfQoKICBmdW5jdGlvbiByZW5kZXJUYWdzKCkgewog" +
      "ICAgZWwudGFnc0Jsb2NrLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicsICFzdGF0ZS50YWdzLmxlbmd0aCk7CiAgICBlbC50YWdz" +
      "TGlzdC5pbm5lckhUTUwgPSAnJzsKICAgIHN0YXRlLnRhZ3MuZm9yRWFjaCgoeyBuYW1lLCBjb3VudCB9KSA9PiB7CiAgICAgIGNv" +
      "bnN0IHJvdyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAgICByb3cudHlwZSA9ICdidXR0b24nOwogICAg" +
      "ICByb3cuY2xhc3NOYW1lID0gJ3RhZy1yb3cnOwogICAgICByb3cudGl0bGUgPSBg5p+l55yLICMke25hbWV9IOeahOWFqOmDqOS7" +
      "u+WKoWA7CiAgICAgIHJvdy5hcHBlbmQoCiAgICAgICAgT2JqZWN0LmFzc2lnbihkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzcGFu" +
      "JyksIHsgY2xhc3NOYW1lOiAndGFnLWhhc2gnLCB0ZXh0Q29udGVudDogJyMnIH0pLAogICAgICAgIE9iamVjdC5hc3NpZ24oZG9j" +
      "dW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpLCB7IHRleHRDb250ZW50OiBuYW1lIH0pLAogICAgICAgIE9iamVjdC5hc3NpZ24o" +
      "ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYicpLCB7IHRleHRDb250ZW50OiBTdHJpbmcoY291bnQpIH0pLAogICAgICApOwogICAg" +
      "ICByb3cuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzdGFydFNlYXJjaChgIyR7bmFtZX1gKSk7CiAgICAgIGVsLnRh" +
      "Z3NMaXN0LmFwcGVuZENoaWxkKHJvdyk7CiAgICB9KTsKICB9CgogIGZ1bmN0aW9uIHJlbmRlclRpbWVsaW5lKCkgewogICAgZWwu" +
      "dGltZWxpbmVCbG9jay5jbGFzc0xpc3QudG9nZ2xlKCdoaWRkZW4nLCAhc3RhdGUuc3RhdHMubGVuZ3RoKTsKICAgIGVsLnRpbWVs" +
      "aW5lTGlzdC5pbm5lckhUTUwgPSAnJzsKCiAgICAvLyBzdGF0cyDlt7LmjInml6XmnJ/lgJLluo/vvJrmjIkg5bm0IOKGkiDmnIgg" +
      "6IGa5ZCI77yM6K6w5b2V5q+P5pyIL+avj+W5tOacgOi/keS4gOS4quacieS7u+WKoeeahOaXpeacnwogICAgY29uc3QgeWVhcnMg" +
      "PSBuZXcgTWFwKCk7CiAgICBmb3IgKGNvbnN0IHMgb2Ygc3RhdGUuc3RhdHMpIHsKICAgICAgY29uc3QgW3ksIG1dID0gcy5kYXRl" +
      "LnNwbGl0KCctJykubWFwKE51bWJlcik7CiAgICAgIGlmICgheWVhcnMuaGFzKHkpKSB5ZWFycy5zZXQoeSwgeyBjb3VudDogMCwg" +
      "bGF0ZXN0OiBzLmRhdGUsIG1vbnRoczogbmV3IE1hcCgpIH0pOwogICAgICBjb25zdCB5ZWFyID0geWVhcnMuZ2V0KHkpOwogICAg" +
      "ICB5ZWFyLmNvdW50ICs9IHMudG90YWw7CiAgICAgIGlmICgheWVhci5tb250aHMuaGFzKG0pKSB5ZWFyLm1vbnRocy5zZXQobSwg" +
      "eyBjb3VudDogMCwgbGF0ZXN0OiBzLmRhdGUgfSk7CiAgICAgIHllYXIubW9udGhzLmdldChtKS5jb3VudCArPSBzLnRvdGFsOwog" +
      "ICAgfQoKICAgIGZvciAoY29uc3QgW3ksIHllYXJdIG9mIHllYXJzKSB7CiAgICAgIGNvbnN0IGxhdGVzdE1vbnRoID0gQXJyYXku" +
      "ZnJvbSh5ZWFyLm1vbnRocy5rZXlzKCkpWzBdOwogICAgICBjb25zdCB5ZWFyUm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgn" +
      "ZGl2Jyk7CiAgICAgIHllYXJSb3cuY2xhc3NOYW1lID0gJ3RsLXllYXInOwogICAgICB5ZWFyUm93LnRpdGxlID0gYOafpeeciyAk" +
      "e3l9IOW5tCAke2xhdGVzdE1vbnRofSDmnIjlj4rmm7Tml6nnmoTku7vliqFgOwogICAgICB5ZWFyUm93LmFwcGVuZCgKICAgICAg" +
      "ICBPYmplY3QuYXNzaWduKGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NwYW4nKSwgeyB0ZXh0Q29udGVudDogU3RyaW5nKHkpIH0p" +
      "LAogICAgICAgIE9iamVjdC5hc3NpZ24oZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc21hbGwnKSwgeyB0ZXh0Q29udGVudDogYCR7" +
      "eWVhci5jb3VudH0g5p2hYCB9KSwKICAgICAgKTsKICAgICAgLy8g54K55Ye75bm05Lu9IOKGkiDmiZPlvIDor6XlubTmnIDov5Hm" +
      "nInku7vliqHnmoTmnIjku73nmoTmlbTmnIjop4blm74KICAgICAgeWVhclJvdy5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgp" +
      "ID0+IG9wZW5Nb250aChgJHt5fS0ke3BhZChsYXRlc3RNb250aCl9YCkpOwogICAgICBlbC50aW1lbGluZUxpc3QuYXBwZW5kQ2hp" +
      "bGQoeWVhclJvdyk7CgogICAgICBjb25zdCBtb250aHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgbW9u" +
      "dGhzLmNsYXNzTmFtZSA9ICd0bC1tb250aHMnOwogICAgICBmb3IgKGNvbnN0IFttLCBpbmZvXSBvZiBBcnJheS5mcm9tKHllYXIu" +
      "bW9udGhzKS5zb3J0KChhLCBiKSA9PiBiWzBdIC0gYVswXSkpIHsKICAgICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5jcmVhdGVF" +
      "bGVtZW50KCdidXR0b24nKTsKICAgICAgICBidG4udHlwZSA9ICdidXR0b24nOwogICAgICAgIGJ0bi5jbGFzc05hbWUgPSAndGwt" +
      "bW9udGgnOwogICAgICAgIGJ0bi50aXRsZSA9IGDmn6XnnIsgJHt5fSDlubQgJHttfSDmnIjlhajpg6ggJHtpbmZvLmNvdW50fSDm" +
      "naHku7vliqFgOwogICAgICAgIGJ0bi5hcHBlbmQoCiAgICAgICAgICBkb2N1bWVudC5jcmVhdGVUZXh0Tm9kZShgJHttfSDmnIhg" +
      "KSwKICAgICAgICAgIE9iamVjdC5hc3NpZ24oZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYicpLCB7IHRleHRDb250ZW50OiBTdHJp" +
      "bmcoaW5mby5jb3VudCkgfSksCiAgICAgICAgKTsKICAgICAgICAvLyDngrnlh7vmnIjku70g4oaSIOaVtOaciOinhuWbvu+8iOiv" +
      "peaciOaJgOacieS7u+WKoeaMieaXpeacn+WIhue7hOWxleekuu+8iQogICAgICAgIGJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGlj" +
      "aycsICgpID0+IG9wZW5Nb250aChgJHt5fS0ke3BhZChtKX1gKSk7CiAgICAgICAgbW9udGhzLmFwcGVuZENoaWxkKGJ0bik7CiAg" +
      "ICAgIH0KICAgICAgZWwudGltZWxpbmVMaXN0LmFwcGVuZENoaWxkKG1vbnRocyk7CiAgICB9CiAgfQoKICAvKiAtLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0g5L6n5qCP5byA5ZCI77yI56e75Yqo56uv5oq95bGJ77yJIC0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLSAqLwogIGZ1bmN0aW9uIG9wZW5TaWRlYmFyKCkgewogICAgZG9jdW1lbnQuYm9keS5jbGFzc0xpc3QuYWRkKCdz" +
      "aWRlLW9wZW4nKTsKICAgIGVsLnNpZGVNYXNrLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogIH0KICBmdW5jdGlvbiBjbG9z" +
      "ZVNpZGViYXIoKSB7CiAgICBkb2N1bWVudC5ib2R5LmNsYXNzTGlzdC5yZW1vdmUoJ3NpZGUtb3BlbicpOwogICAgZWwuc2lkZU1h" +
      "c2suY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgfQogIGVsLnNpZGVUb2dnbGUuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBv" +
      "cGVuU2lkZWJhcik7CiAgZWwuc2lkZU1hc2suYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBjbG9zZVNpZGViYXIpOwogIHdpbmRv" +
      "dy5hZGRFdmVudExpc3RlbmVyKCdyZXNpemUnLCAoKSA9PiB7IGlmICh3aW5kb3cuaW5uZXJXaWR0aCA+PSA5ODApIGNsb3NlU2lk" +
      "ZWJhcigpOyB9KTsKCiAgLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tICoKICAgKiDmkJzntKIKICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KICBsZXQgc2VhcmNoVGltZXIgPSBudWxsOwoKICBlbC5zZWFyY2hJbnB1dC5hZGRFdmVu" +
      "dExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHsKICAgIGNvbnN0IHEgPSBlbC5zZWFyY2hJbnB1dC52YWx1ZS50cmltKCk7CiAgICBl" +
      "bC5zZWFyY2hDbGVhci5jbGFzc0xpc3QudG9nZ2xlKCdoaWRkZW4nLCAhcSk7CiAgICBjbGVhclRpbWVvdXQoc2VhcmNoVGltZXIp" +
      "OwogICAgaWYgKCFxKSB7IGV4aXRTZWFyY2goKTsgcmV0dXJuOyB9CiAgICBzZWFyY2hUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4g" +
      "cnVuU2VhcmNoKHEpLCAyNjApOwogIH0pOwoKICBlbC5zZWFyY2hJbnB1dC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUp" +
      "ID0+IHsKICAgIGlmIChlLmtleSA9PT0gJ0VzY2FwZScpIHsgZXhpdFNlYXJjaCgpOyBlbC5zZWFyY2hJbnB1dC5ibHVyKCk7IH0K" +
      "ICB9KTsKCiAgZWwuc2VhcmNoQ2xlYXIuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7IGV4aXRTZWFyY2goKTsgZWwu" +
      "YWRkSW5wdXQuZm9jdXMoeyBwcmV2ZW50U2Nyb2xsOiB0cnVlIH0pOyB9KTsKICBlbC5zZWFyY2hFeGl0LmFkZEV2ZW50TGlzdGVu" +
      "ZXIoJ2NsaWNrJywgKCkgPT4gewogICAgaWYgKHN0YXRlLm1vbnRoKSB7IGV4aXRNb250aCgpOyByZXR1cm47IH0KICAgIGV4aXRT" +
      "ZWFyY2goKTsKICAgIGVsLmFkZElucHV0LmZvY3VzKHsgcHJldmVudFNjcm9sbDogdHJ1ZSB9KTsKICB9KTsKCiAgYXN5bmMgZnVu" +
      "Y3Rpb24gcnVuU2VhcmNoKHEpIHsKICAgIHN0YXRlLnNlYXJjaCA9IHsgcSwgYWN0aXZlOiB0cnVlLCBsb2FkaW5nOiB0cnVlLCBy" +
      "ZXN1bHRzOiBbXSB9OwogICAgcmVuZGVyTGlzdCgpOwogICAgdHJ5IHsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGFwaShgL3Nl" +
      "YXJjaD9xPSR7ZW5jb2RlVVJJQ29tcG9uZW50KHEpfWApOwogICAgICBpZiAoc3RhdGUuc2VhcmNoLmFjdGl2ZSAmJiBzdGF0ZS5z" +
      "ZWFyY2gucSA9PT0gcSkgewogICAgICAgIHN0YXRlLnNlYXJjaC5yZXN1bHRzID0gZGF0YS50b2RvcyB8fCBbXTsKICAgICAgfQog" +
      "ICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgIGlmIChlcnIuc3RhdHVzID09PSA0MDEpIHsgaGFuZGxlU2Vzc2lvbkxvc3QoKTsgcmV0" +
      "dXJuOyB9CiAgICAgIHRvYXN0KGVyci5tZXNzYWdlLCAnZXJyJyk7CiAgICB9IGZpbmFsbHkgewogICAgICBpZiAoc3RhdGUuc2Vh" +
      "cmNoLmFjdGl2ZSAmJiBzdGF0ZS5zZWFyY2gucSA9PT0gcSkgewogICAgICAgIHN0YXRlLnNlYXJjaC5sb2FkaW5nID0gZmFsc2U7" +
      "CiAgICAgICAgcmVuZGVyTGlzdCgpOwogICAgICB9CiAgICB9CiAgfQoKICBmdW5jdGlvbiBzdGFydFNlYXJjaChxKSB7CiAgICBl" +
      "bC5zZWFyY2hJbnB1dC52YWx1ZSA9IHE7CiAgICBlbC5zZWFyY2hDbGVhci5jbGFzc0xpc3QucmVtb3ZlKCdoaWRkZW4nKTsKICAg" +
      "IGNsZWFyVGltZW91dChzZWFyY2hUaW1lcik7CiAgICBydW5TZWFyY2gocSk7CiAgICBjbG9zZVNpZGViYXIoKTsKICB9CgogIGZ1" +
      "bmN0aW9uIGV4aXRTZWFyY2goKSB7CiAgICBjbGVhclRpbWVvdXQoc2VhcmNoVGltZXIpOwogICAgY29uc3QgaGFkID0gc3RhdGUu" +
      "c2VhcmNoLmFjdGl2ZSB8fCBlbC5zZWFyY2hJbnB1dC52YWx1ZTsKICAgIHN0YXRlLnNlYXJjaCA9IHsgcTogJycsIGFjdGl2ZTog" +
      "ZmFsc2UsIGxvYWRpbmc6IGZhbHNlLCByZXN1bHRzOiBbXSB9OwogICAgZWwuc2VhcmNoSW5wdXQudmFsdWUgPSAnJzsKICAgIGVs" +
      "LnNlYXJjaENsZWFyLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgaWYgKGhhZCkgcmVuZGVyTGlzdCgpOwogIH0KCiAgLyog" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDl" +
      "op4gLyDmlLkgLyDliKAKICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0gKi8KICBlbC5hZGRGb3JtLmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIGFzeW5jIChldmVudCkgPT4gewog" +
      "ICAgZXZlbnQucHJldmVudERlZmF1bHQoKTsKICAgIGlmIChzdGF0ZS5idXN5KSByZXR1cm47CgogICAgY29uc3QgdGl0bGUgPSBl" +
      "bC5hZGRJbnB1dC52YWx1ZS5yZXBsYWNlKC9ccysvZywgJyAnKS50cmltKCk7CiAgICBpZiAoIXRpdGxlKSB7CiAgICAgIC8vIOep" +
      "uueZveS7u+WKoeS4jea3u+WKoAogICAgICBlbC5hZGRIaW50LnRleHRDb250ZW50ID0gJ+S7u+WKoeWGheWuueS4jeiDveS4uuep" +
      "uic7CiAgICAgIGVsLmFkZEhpbnQuaGlkZGVuID0gZmFsc2U7CiAgICAgIGVsLmFkZEZvcm0uY2xhc3NMaXN0LmFkZCgnc2hha2Un" +
      "KTsKICAgICAgc2V0VGltZW91dCgoKSA9PiBlbC5hZGRGb3JtLmNsYXNzTGlzdC5yZW1vdmUoJ3NoYWtlJyksIDM2MCk7CiAgICAg" +
      "IGVsLmFkZElucHV0LmZvY3VzKCk7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBlbC5hZGRIaW50LmhpZGRlbiA9IHRydWU7CiAg" +
      "ICBpZiAoc3RhdGUuc2VhcmNoLmFjdGl2ZSkgZXhpdFNlYXJjaCgpOyAgIC8vIOaQnOe0oueKtuaAgeS4i+a3u+WKoOS7u+WKoe+8" +
      "jOWFiOWbnuWIsOaXpeacn+inhuWbvgogICAgc3RhdGUuYnVzeSA9IHRydWU7CiAgICBjb25zdCBidG4gPSBlbC5hZGRCdG4gfHwg" +
      "ZWwuYWRkRm9ybS5xdWVyeVNlbGVjdG9yKCdidXR0b25bdHlwZT1zdWJtaXRdJyk7CiAgICBpZiAoYnRuKSBidG4uZGlzYWJsZWQg" +
      "PSB0cnVlOwoKICAgIC8vIOaciOinhuWbvu+8muS4jeWBmuaXpeinhuWbvueahOS5kOinguaPkuWFpe+8jOaIkOWKn+WQjuWIt+aW" +
      "sOaVtOaciOaVsOaNrgogICAgaWYgKHN0YXRlLm1vbnRoKSB7CiAgICAgIGVsLmFkZElucHV0LnZhbHVlID0gJyc7CiAgICAgIHRy" +
      "eSB7CiAgICAgICAgYXdhaXQgYXBpKCcvdG9kb3MnLCB7IG1ldGhvZDogJ1BPU1QnLCBib2R5OiB7IHRpdGxlLCBkYXRlOiBzdGF0" +
      "ZS5kYXRlIH0gfSk7CiAgICAgICAgYXdhaXQgcmVmcmVzaE1vbnRoKCk7CiAgICAgICAgc2NoZWR1bGVTaWRlYmFyUmVmcmVzaCgp" +
      "OwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBpZiAoZXJyLnN0YXR1cyA9PT0gNDAxKSB7IGhhbmRsZVNlc3Npb25Mb3N0" +
      "KCk7IHJldHVybjsgfQogICAgICAgIHRvYXN0KGVyci5tZXNzYWdlLCAnZXJyJyk7CiAgICAgICAgZWwuYWRkSW5wdXQudmFsdWUg" +
      "PSB0aXRsZTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBzdGF0ZS5idXN5ID0gZmFsc2U7CiAgICAgICAgaWYgKGJ0bikgYnRu" +
      "LmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgZWwuYWRkSW5wdXQuZm9jdXMoeyBwcmV2ZW50U2Nyb2xsOiB0cnVlIH0pOwogICAg" +
      "ICB9CiAgICAgIHJldHVybjsKICAgIH0KCiAgICAvLyDkuZDop4Lmj5LlhaUKICAgIGNvbnN0IHRlbXBJZCA9IGB0bXBfJHtEYXRl" +
      "Lm5vdygpfWA7CiAgICBjb25zdCBvcHRpbWlzdGljID0geyBpZDogdGVtcElkLCB0aXRsZSwgZG9uZTogZmFsc2UsIGRhdGU6IHN0" +
      "YXRlLmRhdGUsIG9yZGVyOiAtSW5maW5pdHksIGNyZWF0ZWRBdDogRGF0ZS5ub3coKSAvIDEwMDAgfTsKICAgIHN0YXRlLnRvZG9z" +
      "LnVuc2hpZnQob3B0aW1pc3RpYyk7CiAgICBzdGF0ZS50b3RhbCArPSAxOwogICAgc3RhdGUucmVtYWluaW5nICs9IDE7CiAgICBy" +
      "ZW5kZXJMaXN0KCk7CiAgICBlbC5hZGRJbnB1dC52YWx1ZSA9ICcnOwoKICAgIHRyeSB7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2Fp" +
      "dCBhcGkoJy90b2RvcycsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IHsgdGl0bGUsIGRhdGU6IHN0YXRlLmRhdGUgfSB9KTsKICAg" +
      "ICAgY29uc3QgaW5kZXggPSBzdGF0ZS50b2Rvcy5maW5kSW5kZXgoKHQpID0+IHQuaWQgPT09IHRlbXBJZCk7CiAgICAgIGlmIChp" +
      "bmRleCAhPT0gLTEpIHN0YXRlLnRvZG9zW2luZGV4XSA9IGRhdGEudG9kbzsKICAgICAgc3RhdGUudG9kb3Muc29ydCgoYSwgYikg" +
      "PT4gTnVtYmVyKGEuZG9uZSkgLSBOdW1iZXIoYi5kb25lKSB8fCBhLm9yZGVyIC0gYi5vcmRlcik7CiAgICAgIHN0YXRlLnJlbWFp" +
      "bmluZyA9IGRhdGEucmVtYWluaW5nOwogICAgICBzdGF0ZS50b3RhbCA9IGRhdGEudG90YWw7CiAgICAgIHJlbmRlckxpc3QoKTsK" +
      "ICAgICAgc3luY0RheUNhY2hlKCk7CiAgICAgIHNjaGVkdWxlU2lkZWJhclJlZnJlc2goKTsKICAgIH0gY2F0Y2ggKGVycikgewog" +
      "ICAgICBzdGF0ZS50b2RvcyA9IHN0YXRlLnRvZG9zLmZpbHRlcigodCkgPT4gdC5pZCAhPT0gdGVtcElkKTsKICAgICAgc3RhdGUu" +
      "dG90YWwgPSBNYXRoLm1heCgwLCBzdGF0ZS50b3RhbCAtIDEpOwogICAgICBzdGF0ZS5yZW1haW5pbmcgPSBzdGF0ZS50b2Rvcy5m" +
      "aWx0ZXIoKHQpID0+ICF0LmRvbmUpLmxlbmd0aDsKICAgICAgcmVuZGVyTGlzdCgpOwogICAgICBpZiAoZXJyLnN0YXR1cyA9PT0g" +
      "NDAxKSB7IGhhbmRsZVNlc3Npb25Mb3N0KCk7IHJldHVybjsgfQogICAgICB0b2FzdChlcnIubWVzc2FnZSwgJ2VycicpOwogICAg" +
      "ICBlbC5hZGRJbnB1dC52YWx1ZSA9IHRpdGxlOwogICAgfSBmaW5hbGx5IHsKICAgICAgc3RhdGUuYnVzeSA9IGZhbHNlOwogICAg" +
      "ICBpZiAoYnRuKSBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgZWwuYWRkSW5wdXQuZm9jdXMoeyBwcmV2ZW50U2Nyb2xsOiB0" +
      "cnVlIH0pOwogICAgfQogIH0pOwoKICBlbC5hZGRJbnB1dC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHsgZWwuYWRk" +
      "SGludC5oaWRkZW4gPSB0cnVlOyB9KTsKCiAgYXN5bmMgZnVuY3Rpb24gdG9nZ2xlVG9kbyh0b2RvKSB7CiAgICBjb25zdCBuZXh0" +
      "ID0gIXRvZG8uZG9uZTsKICAgIHRvZG8uZG9uZSA9IG5leHQ7CiAgICAvLyDlt7LlrozmiJDnmoTmsonliLDlupXpg6gKICAgIHN0" +
      "YXRlLnRvZG9zLnNvcnQoKGEsIGIpID0+IE51bWJlcihhLmRvbmUpIC0gTnVtYmVyKGIuZG9uZSkgfHwgYS5vcmRlciAtIGIub3Jk" +
      "ZXIpOwogICAgc3RhdGUucmVtYWluaW5nID0gc3RhdGUudG9kb3MuZmlsdGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGg7CiAgICBy" +
      "ZW5kZXJMaXN0KCk7CgogICAgdHJ5IHsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGFwaShgL3RvZG9zLyR7ZW5jb2RlVVJJQ29t" +
      "cG9uZW50KHRvZG8uaWQpfWAsIHsgbWV0aG9kOiAnUEFUQ0gnLCBib2R5OiB7IGRvbmU6IG5leHQgfSB9KTsKICAgICAgaWYgKHN0" +
      "YXRlLm1vbnRoKSB7IGF3YWl0IHJlZnJlc2hNb250aCgpOyB9CiAgICAgIGVsc2UgeyB1cGRhdGVDb3VudHMoZGF0YSk7IHN5bmNE" +
      "YXlDYWNoZSgpOyB9CiAgICAgIHNjaGVkdWxlU2lkZWJhclJlZnJlc2goKTsKICAgIH0gY2F0Y2ggKGVycikgewogICAgICB0b2Rv" +
      "LmRvbmUgPSAhbmV4dDsKICAgICAgaWYgKHN0YXRlLm1vbnRoKSB7IHJlbmRlckxpc3QoKTsgfSBlbHNlIHsKICAgICAgICBzdGF0" +
      "ZS50b2Rvcy5zb3J0KChhLCBiKSA9PiBOdW1iZXIoYS5kb25lKSAtIE51bWJlcihiLmRvbmUpIHx8IGEub3JkZXIgLSBiLm9yZGVy" +
      "KTsKICAgICAgICBzdGF0ZS5yZW1haW5pbmcgPSBzdGF0ZS50b2Rvcy5maWx0ZXIoKHQpID0+ICF0LmRvbmUpLmxlbmd0aDsKICAg" +
      "ICAgICByZW5kZXJMaXN0KCk7CiAgICAgIH0KICAgICAgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnInKTsKICAgIH0KICB9CgogIGFz" +
      "eW5jIGZ1bmN0aW9uIGRlbGV0ZVRvZG8odG9kbywgbGkpIHsKICAgIGxpLmNsYXNzTGlzdC5hZGQoJ3JlbW92aW5nJyk7CiAgICBj" +
      "b25zdCBiYWNrdXAgPSBzdGF0ZS5tb250aCA/IHN0YXRlLm1vbnRoVG9kb3Muc2xpY2UoKSA6IHN0YXRlLnRvZG9zLnNsaWNlKCk7" +
      "CiAgICBpZiAoc3RhdGUubW9udGgpIHsKICAgICAgc3RhdGUubW9udGhUb2RvcyA9IHN0YXRlLm1vbnRoVG9kb3MuZmlsdGVyKCh0" +
      "KSA9PiB0LmlkICE9PSB0b2RvLmlkKTsKICAgIH0gZWxzZSB7CiAgICAgIHN0YXRlLnRvZG9zID0gc3RhdGUudG9kb3MuZmlsdGVy" +
      "KCh0KSA9PiB0LmlkICE9PSB0b2RvLmlkKTsKICAgICAgc3RhdGUucmVtYWluaW5nID0gc3RhdGUudG9kb3MuZmlsdGVyKCh0KSA9" +
      "PiAhdC5kb25lKS5sZW5ndGg7CiAgICAgIHN0YXRlLnRvdGFsID0gc3RhdGUudG9kb3MubGVuZ3RoOwogICAgfQoKICAgIHNldFRp" +
      "bWVvdXQocmVuZGVyTGlzdCwgMTgwKTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBhcGkoYC90b2Rvcy8ke2Vu" +
      "Y29kZVVSSUNvbXBvbmVudCh0b2RvLmlkKX0/ZGF0ZT0ke2VuY29kZVVSSUNvbXBvbmVudChzdGF0ZS5kYXRlKX1gLCB7IG1ldGhv" +
      "ZDogJ0RFTEVURScgfSk7CiAgICAgIGlmIChzdGF0ZS5tb250aCkgeyBhd2FpdCByZWZyZXNoTW9udGgoKTsgfQogICAgICBlbHNl" +
      "IHsgdXBkYXRlQ291bnRzKGRhdGEpOyBzeW5jRGF5Q2FjaGUoKTsgfQogICAgICBzY2hlZHVsZVNpZGViYXJSZWZyZXNoKCk7CiAg" +
      "ICB9IGNhdGNoIChlcnIpIHsKICAgICAgaWYgKHN0YXRlLm1vbnRoKSB7CiAgICAgICAgc3RhdGUubW9udGhUb2RvcyA9IGJhY2t1" +
      "cDsKICAgICAgfSBlbHNlIHsKICAgICAgICBzdGF0ZS50b2RvcyA9IGJhY2t1cDsKICAgICAgICBzdGF0ZS5yZW1haW5pbmcgPSBi" +
      "YWNrdXAuZmlsdGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGg7CiAgICAgICAgc3RhdGUudG90YWwgPSBiYWNrdXAubGVuZ3RoOwog" +
      "ICAgICB9CiAgICAgIHJlbmRlckxpc3QoKTsKICAgICAgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnInKTsKICAgIH0KICB9CgogIGVs" +
      "LmNsZWFyRG9uZUJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgIGNvbnN0IGhhc0RvbmUgPSBzdGF0ZS5t" +
      "b250aAogICAgICA/IHN0YXRlLm1vbnRoVG9kb3Muc29tZSgodCkgPT4gdC5kb25lKQogICAgICA6IHN0YXRlLnRvZG9zLnNvbWUo" +
      "KHQpID0+IHQuZG9uZSk7CiAgICBpZiAoIWhhc0RvbmUpIHJldHVybjsKCiAgICBhcm1lZENsaWNrKGVsLmNsZWFyRG9uZUJ0biwg" +
      "J+ehruiupOa4hemZpO+8nycsIGFzeW5jICgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBib2R5ID0gc3RhdGUubW9u" +
      "dGgKICAgICAgICAgID8geyBhY3Rpb246ICdjbGVhci1jb21wbGV0ZWQnLCBtb250aDogc3RhdGUubW9udGggfQogICAgICAgICAg" +
      "OiB7IGFjdGlvbjogJ2NsZWFyLWNvbXBsZXRlZCcsIGRhdGU6IHN0YXRlLmRhdGUgfTsKICAgICAgICBjb25zdCBkYXRhID0gYXdh" +
      "aXQgYXBpKCcvdG9kb3MvYmF0Y2gnLCB7IG1ldGhvZDogJ1BPU1QnLCBib2R5IH0pOwogICAgICAgIHNjaGVkdWxlU2lkZWJhclJl" +
      "ZnJlc2goKTsKICAgICAgICBpZiAoc3RhdGUubW9udGgpIHsKICAgICAgICAgIGF3YWl0IHJlZnJlc2hNb250aCgpOwogICAgICAg" +
      "ICAgdG9hc3QoYOW3sua4hemZpOacrOaciCAke2RhdGEucmVtb3ZlZCB8fCAwfSDpobnlt7LlrozmiJDku7vliqFgLCAnb2snKTsK" +
      "ICAgICAgICB9IGVsc2UgewogICAgICAgICAgYXdhaXQgcmVmcmVzaCgpOwogICAgICAgICAgc3luY0RheUNhY2hlKCk7CiAgICAg" +
      "ICAgICB0b2FzdCgn5bey5riF6Zmk5a6M5oiQ55qE5Lu75YqhJywgJ29rJyk7CiAgICAgICAgfQogICAgICB9IGNhdGNoIChlcnIp" +
      "IHsgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnInKTsgfQogICAgfSk7CiAgfSk7CgogIGVsLmNhcnJ5b3ZlckJ0bi5hZGRFdmVudExp" +
      "c3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBhcGkoJy90b2Rv" +
      "cy9iYXRjaCcsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IHsgYWN0aW9uOiAnY2Fycnktb3ZlcicsIGRhdGU6IHN0YXRlLmRhdGUg" +
      "fSB9KTsKICAgICAgY2FjaGVDbGVhckFsbCgpOyAgIC8vIOmhuuW7tuS8muaUueWKqOWkmuS4quaXpeacn+eahOaVsOaNru+8jOeb" +
      "tOaOpea4heepuue8k+WtmOacgOeos+WmpQogICAgICBhd2FpdCByZWZyZXNoKCk7CiAgICAgIHNjaGVkdWxlU2lkZWJhclJlZnJl" +
      "c2goKTsKICAgICAgdG9hc3QoZGF0YS5tb3ZlZCA/IGDlt7Lpobrlu7YgJHtkYXRhLm1vdmVkfSDpobnmnKrlrozmiJDku7vliqFg" +
      "IDogJ+ayoeaciemcgOimgemhuuW7tueahOS7u+WKoScsIGRhdGEubW92ZWQgPyAnb2snIDogJycpOwogICAgfSBjYXRjaCAoZXJy" +
      "KSB7IHRvYXN0KGVyci5tZXNzYWdlLCAnZXJyJyk7IH0KICB9KTsKCiAgLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDkuLvpopgKICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KICBjb25zdCBUSEVNRV9LRVkgPSAndG9k" +
      "by10b2RheTp0aGVtZSc7CiAgZnVuY3Rpb24gYXBwbHlUaGVtZSh0aGVtZSkgewogICAgaWYgKHRoZW1lID09PSAnbGlnaHQnIHx8" +
      "IHRoZW1lID09PSAnZGFyaycpIHsKICAgICAgZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50LnNldEF0dHJpYnV0ZSgnZGF0YS10aGVt" +
      "ZScsIHRoZW1lKTsKICAgIH0gZWxzZSB7CiAgICAgIGRvY3VtZW50LmRvY3VtZW50RWxlbWVudC5yZW1vdmVBdHRyaWJ1dGUoJ2Rh" +
      "dGEtdGhlbWUnKTsKICAgIH0KICAgIGVsLnRoZW1lVG9nZ2xlLnRleHRDb250ZW50ID0gdGhlbWUgPT09ICdkYXJrJyA/ICfimIDv" +
      "uI8nIDogdGhlbWUgPT09ICdsaWdodCcgPyAn8J+MmScgOiAn8J+Mkyc7CiAgfQogIGVsLnRoZW1lVG9nZ2xlLmFkZEV2ZW50TGlz" +
      "dGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgY29uc3Qgb3JkZXIgPSBbJ2F1dG8nLCAnbGlnaHQnLCAnZGFyayddOwogICAgY29u" +
      "c3QgY3VycmVudCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKFRIRU1FX0tFWSkgfHwgJ2F1dG8nOwogICAgY29uc3QgbmV4dCA9IG9y" +
      "ZGVyWyhvcmRlci5pbmRleE9mKGN1cnJlbnQpICsgMSkgJSBvcmRlci5sZW5ndGhdOwogICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0o" +
      "VEhFTUVfS0VZLCBuZXh0KTsKICAgIGFwcGx5VGhlbWUobmV4dCA9PT0gJ2F1dG8nID8gbnVsbCA6IG5leHQpOwogIH0pOwogIGFw" +
      "cGx5VGhlbWUobG9jYWxTdG9yYWdlLmdldEl0ZW0oVEhFTUVfS0VZKSB8fCBudWxsKTsKCiAgLyogLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDorr7nva7mir3lsYkKICAgKiAt" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KICBmdW5j" +
      "dGlvbiBvcGVuRHJhd2VyKCkgewogICAgZWwuZHJhd2VyTWFzay5jbGFzc0xpc3QucmVtb3ZlKCdoaWRkZW4nKTsKICAgIGRvY3Vt" +
      "ZW50LmJvZHkuc3R5bGUub3ZlcmZsb3cgPSAnaGlkZGVuJzsKICB9CiAgZnVuY3Rpb24gY2xvc2VEcmF3ZXIoKSB7CiAgICBlbC5k" +
      "cmF3ZXJNYXNrLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgZG9jdW1lbnQuYm9keS5zdHlsZS5vdmVyZmxvdyA9ICcnOwog" +
      "IH0KICBlbC51c2VyTWVudS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIG9wZW5EcmF3ZXIpOwogIGVsLmRyYXdlckNsb3NlLmFk" +
      "ZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgY2xvc2VEcmF3ZXIpOwogIGVsLmRyYXdlck1hc2suYWRkRXZlbnRMaXN0ZW5lcignY2xp" +
      "Y2snLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IGVsLmRyYXdlck1hc2spIGNsb3NlRHJhd2VyKCk7IH0pOwogIGRvY3VtZW50" +
      "LmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCAoZSkgPT4gewogICAgaWYgKGUua2V5ID09PSAnRXNjYXBlJykgeyBjbG9zZURy" +
      "YXdlcigpOyBjbG9zZVNpZGViYXIoKTsgfQogIH0pOwogIGVsLmRlbW9CYW5uZXJDbG9zZS5hZGRFdmVudExpc3RlbmVyKCdjbGlj" +
      "aycsICgpID0+IGVsLmRlbW9CYW5uZXIuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJykpOwoKICAvKiAtLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0g5LqR5aSH5Lu9IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwogIGZ1bmN0aW9uIHN5bmNQcm92" +
      "aWRlclBhbmVscygpIHsKICAgIGNvbnN0IHByb3ZpZGVyID0gZWwuYmFja3VwUHJvdmlkZXIudmFsdWU7CiAgICBlbC5iYWNrdXBQ" +
      "YW5lbHMuZm9yRWFjaCgocGFuZWwpID0+IHsKICAgICAgcGFuZWwuaGlkZGVuID0gcGFuZWwuZGF0YXNldC5wcm92aWRlciAhPT0g" +
      "cHJvdmlkZXI7CiAgICB9KTsKICAgIGNvbnN0IG9uID0gZWwuYmFja3VwRW5hYmxlZC5jaGVja2VkICYmIHByb3ZpZGVyICE9PSAn" +
      "bm9uZSc7CiAgICBlbC5iYWNrdXBFbmFibGVkLmRpc2FibGVkID0gcHJvdmlkZXIgPT09ICdub25lJzsKICAgIGVsLmJhY2t1cEF1" +
      "dG8uZGlzYWJsZWQgPSAhb247CiAgICBlbC5iYWNrdXBTY2hlZHVsZWQuZGlzYWJsZWQgPSAhb247CiAgICBbZWwuYmFja3VwVGVz" +
      "dCwgZWwuYmFja3VwUnVuLCBlbC5iYWNrdXBSZXN0b3JlXS5mb3JFYWNoKChiKSA9PiB7IGIuZGlzYWJsZWQgPSBwcm92aWRlciA9" +
      "PT0gJ25vbmUnOyB9KTsKICAgIGlmICghb24pIHsgZWwuYmFja3VwQXV0by5jaGVja2VkID0gZmFsc2U7IGVsLmJhY2t1cFNjaGVk" +
      "dWxlZC5jaGVja2VkID0gZmFsc2U7IH0KCiAgICAvLyDpopHnjofnm7jlhbPmjqfku7blj6rlnKjlr7nlupTlvIDlhbPmiZPlvIDm" +
      "l7blh7rnjrAKICAgIGVsLmJhY2t1cEludGVydmFsRmllbGQuY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZGVuJywgIShvbiAmJiBlbC5i" +
      "YWNrdXBBdXRvLmNoZWNrZWQpKTsKICAgIGVsLmJhY2t1cFBlcmlvZEZpZWxkLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicsICEo" +
      "b24gJiYgZWwuYmFja3VwU2NoZWR1bGVkLmNoZWNrZWQpKTsKCiAgICB1cGRhdGVTdGFtcEhpbnQoKTsKICAgIHVwZGF0ZUZyZXF1" +
      "ZW5jeUhpbnRzKCk7CiAgfQoKICAvKiog5a6J5YWo5Zyw57uZIHNlbGVjdCDotYvlgLzvvJrphY3nva7ph4znmoTlgLzkuI3lnKjp" +
      "gInpobnliJfooajph4zml7bkuLTml7booaXkuIDkuKrpgInpobkgKi8KICBmdW5jdGlvbiBzZXRTZWxlY3RWYWx1ZShzZWxlY3Qs" +
      "IHZhbHVlKSB7CiAgICBjb25zdCB2ID0gU3RyaW5nKHZhbHVlKTsKICAgIGlmICghQXJyYXkuZnJvbShzZWxlY3Qub3B0aW9ucyku" +
      "c29tZSgobykgPT4gby52YWx1ZSA9PT0gdikpIHsKICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnb3B0" +
      "aW9uJyk7CiAgICAgIG9wdC52YWx1ZSA9IHY7CiAgICAgIG9wdC50ZXh0Q29udGVudCA9IGAke2h1bWFuTWludXRlcyh2KX3vvIjo" +
      "h6rlrprkuYnvvIlgOwogICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgIH0KICAgIHNlbGVjdC52YWx1ZSA9IHY7CiAg" +
      "fQoKICAvKiog5oqK44CM5YiG6ZKf44CN57+76K+R5oiQ5Lq66K+dICovCiAgZnVuY3Rpb24gaHVtYW5NaW51dGVzKG1pbikgewog" +
      "ICAgY29uc3QgbiA9IE51bWJlcihtaW4pOwogICAgaWYgKG4gPT09IDApIHJldHVybiAn5LiN6ZmQ5Yi2JzsKICAgIGlmIChuIDwg" +
      "NjApIHJldHVybiBgJHtufSDliIbpkp9gOwogICAgaWYgKG4gPT09IDYwKSByZXR1cm4gJzEg5bCP5pe2JzsKICAgIGlmIChuIDwg" +
      "MTQ0MCkgcmV0dXJuIGAke24gLyA2MH0g5bCP5pe2YDsKICAgIGlmIChuID09PSAxNDQwKSByZXR1cm4gJzI0IOWwj+aXtic7CiAg" +
      "ICByZXR1cm4gYCR7TWF0aC5yb3VuZChuIC8gMTQ0MCl9IOWkqWA7CiAgfQoKICAvKiog6aKR546HIC8g5a6a5pe25aSH5Lu955qE" +
      "6K+05piOICsgQ3JvbiDmmK/lkKbnnJ/nmoTlnKjot5HnmoTor4rmlq0gKi8KICBmdW5jdGlvbiB1cGRhdGVGcmVxdWVuY3lIaW50" +
      "cygpIHsKICAgIGNvbnN0IGV2ZXJ5ID0gaHVtYW5NaW51dGVzKGVsLmJhY2t1cEludGVydmFsLnZhbHVlKTsKICAgIGVsLmJhY2t1" +
      "cEludGVydmFsSGludC50ZXh0Q29udGVudCA9IE51bWJlcihlbC5iYWNrdXBJbnRlcnZhbC52YWx1ZSkgPT09IDAKICAgICAgPyAn" +
      "5q+P5qyh5pWw5o2u5Y+Y5pu06YO95Lya5aSH5Lu95LiA5qyh77yM5Y6G5Y+y5paH5Lu25aKe6ZW/5pyA5b+r44CCJwogICAgICA6" +
      "IGDot53kuIrmrKHlpIfku73kuI3otrMgJHtldmVyeX3ml7bkuI3kvJrph43lpI3lpIfku73vvIjmr4/mlLnkuIDmrKHku7vliqHp" +
      "g73kvJrmo4Dmn6XvvInjgIJgOwoKICAgIGlmICghZWwuYmFja3VwU2NoZWR1bGVkLmNoZWNrZWQpIHsKICAgICAgZWwuYmFja3Vw" +
      "Q3JvbkhpbnQudGV4dENvbnRlbnQgPSAn5omT5byA5ZCO55SxIENsb3VkZmxhcmUg5a6a5pe26Kem5Y+R77yI5q+PIDUg5YiG6ZKf" +
      "5qOA5p+l5LiA5qyh77yJ77yM5LiN6ZyA6KaB5L2g5omT5byA6aG16Z2i44CCJzsKICAgICAgcmV0dXJuOwogICAgfQogICAgY29u" +
      "c3QgcGVyaW9kID0gaHVtYW5NaW51dGVzKGVsLmJhY2t1cFBlcmlvZC52YWx1ZSk7CiAgICBjb25zdCBzdGF0dXMgPSBzdGF0ZS5j" +
      "cm9uIHx8IHt9OwogICAgbGV0IHRleHQgPSBg5LqR56uv5q+PIDUg5YiG6ZKf5qOA5p+l5LiA5qyh77yM5Yiw54K55bCx5aSH5Lu9" +
      "77yM57qm5q+PICR7cGVyaW9kfeS4gOasoeOAgmA7CiAgICBpZiAoc3RhdHVzLmxhc3RSdW4pIHsKICAgICAgY29uc3QgYWdvID0g" +
      "TWF0aC5tYXgoMCwgTWF0aC5yb3VuZChEYXRlLm5vdygpIC8gMTAwMCAtIHN0YXR1cy5sYXN0UnVuKSk7CiAgICAgIGNvbnN0IGFn" +
      "b1RleHQgPSBhZ28gPCA5MCA/IGAke2Fnb30g56eS5YmNYCA6IGAke01hdGgucm91bmQoYWdvIC8gNjApfSDliIbpkp/liY1gOwog" +
      "ICAgICB0ZXh0ICs9IHN0YXR1cy5oZWFsdGh5CiAgICAgICAgPyBgIOWumuaXtuS7u+WKoei/kOihjOato+W4uO+8iOS4iuasoeaj" +
      "gOafpSAke2Fnb1RleHR977yJ44CCYAogICAgICAgIDogYCDimqDvuI8g5LiK5qyh5qOA5p+l5pivICR7YWdvVGV4dH3vvIzlrprm" +
      "l7bku7vliqHlj6/og73msqHlnKjot5HvvJrpnIDlnKggV29ya2VyIOeahCBUcmlnZ2VycyDph4zmt7vliqAgQ3JvbuOAjCovNSAq" +
      "ICogKiAq44CN44CCYDsKICAgIH0gZWxzZSB7CiAgICAgIHRleHQgKz0gJyDimqDvuI8g6L+Y5rKh5pS25Yiw6L+H5a6a5pe25Lu7" +
      "5Yqh55qE5b+D6Lez77ya6K+356Gu6K6k5bey5ZyoIFdvcmtlciDnmoQgVHJpZ2dlcnMg4oaSIENyb24gVHJpZ2dlcnMg6YeM5re7" +
      "5Yqg44CMKi81ICogKiAqICrjgI3jgIInOwogICAgfQogICAgZWwuYmFja3VwQ3JvbkhpbnQudGV4dENvbnRlbnQgPSB0ZXh0Owog" +
      "IH0KCiAgLyoqIOacrOWcsOaXtumXtOeahOaXtumXtOaIs+ekuuS+i++8jOS4juWQjuerryBmaWxlU3RhbXAg5qC85byP5LiA6Ie0" +
      "77yaWVlZWU1NREQtSEhtbXNzICovCiAgZnVuY3Rpb24gbG9jYWxTdGFtcChkID0gbmV3IERhdGUoKSkgewogICAgY29uc3QgcCA9" +
      "IChuKSA9PiBTdHJpbmcobikucGFkU3RhcnQoMiwgJzAnKTsKICAgIHJldHVybiBgJHtkLmdldEZ1bGxZZWFyKCl9JHtwKGQuZ2V0" +
      "TW9udGgoKSArIDEpfSR7cChkLmdldERhdGUoKSl9LSR7cChkLmdldEhvdXJzKCkpfSR7cChkLmdldE1pbnV0ZXMoKSl9JHtwKGQu" +
      "Z2V0U2Vjb25kcygpKX1gOwogIH0KCiAgLyoqIOS4juWQjuerryBzdGFtcEtleSDkuIDoh7TnmoTlkb3lkI3op4TliJnvvJrml7bp" +
      "l7TmiLPmj5LlnKjmianlsZXlkI3kuYvliY0gKi8KICBmdW5jdGlvbiBzdGFtcE5hbWUoYmFzZSwgc3RhbXApIHsKICAgIGNvbnN0" +
      "IG5hbWUgPSBTdHJpbmcoYmFzZSB8fCAndG9kby10b2RheS5iYWNrdXAuanNvbicpOwogICAgY29uc3QgZG90ID0gbmFtZS5sYXN0" +
      "SW5kZXhPZignLicpOwogICAgcmV0dXJuIGRvdCA+IDAgPyBgJHtuYW1lLnNsaWNlKDAsIGRvdCl9LiR7c3RhbXB9JHtuYW1lLnNs" +
      "aWNlKGRvdCl9YCA6IGAke25hbWV9LiR7c3RhbXB9YDsKICB9CgogIC8qKiDlvZPliY3phY3nva7kuIvlrp7pmYXkvJrlhpnlhaXn" +
      "moTlm7rlrprmlofku7blkI3vvIjkuI7lkI7nq68gb2JqZWN0S2V5T2Yg5a+55bqU77yJICovCiAgZnVuY3Rpb24gY3VycmVudEJh" +
      "Y2t1cEJhc2UoKSB7CiAgICBjb25zdCBwcm92aWRlciA9IGVsLmJhY2t1cFByb3ZpZGVyLnZhbHVlOwogICAgaWYgKHByb3ZpZGVy" +
      "ID09PSAncjInKSByZXR1cm4gZWwucjJLZXkudmFsdWUudHJpbSgpIHx8ICd0b2RvLXRvZGF5LmJhY2t1cC5qc29uJzsKICAgIGlm" +
      "IChwcm92aWRlciA9PT0gJ3dlYmRhdicpIHJldHVybiBlbC5kYXZGaWxlLnZhbHVlLnRyaW0oKSB8fCAndG9kby10b2RheS5iYWNr" +
      "dXAuanNvbic7CiAgICBjb25zdCBwcmVmaXggPSBlbC5zM1ByZWZpeC52YWx1ZS50cmltKCkucmVwbGFjZSgvXlwvKy8sICcnKTsK" +
      "ICAgIHJldHVybiBgJHtwcmVmaXh9JHtlbC5zM0ZpbGUudmFsdWUudHJpbSgpIHx8ICd0b2RvLXRvZGF5LmJhY2t1cC5qc29uJ31g" +
      "OwogIH0KCiAgZnVuY3Rpb24gdXBkYXRlU3RhbXBIaW50KCkgewogICAgY29uc3QgcHJvdmlkZXIgPSBlbC5iYWNrdXBQcm92aWRl" +
      "ci52YWx1ZTsKICAgIGlmIChwcm92aWRlciA9PT0gJ25vbmUnKSB7CiAgICAgIGVsLmJhY2t1cFN0YW1wSGludC50ZXh0Q29udGVu" +
      "dCA9ICfpgInmi6nlpIfku73mlrnlvI/lkI7vvIzov5nph4zkvJrmmL7npLrlrp7pmYXlhpnlhaXkupHnq6/nmoTmlofku7blkI3j" +
      "gIInOwogICAgICByZXR1cm47CiAgICB9CiAgICBjb25zdCBiYXNlID0gY3VycmVudEJhY2t1cEJhc2UoKTsKICAgIGlmICghZWwu" +
      "YmFja3VwU3RhbXApIHJldHVybjsKICAgIGlmICghZWwuYmFja3VwU3RhbXAuY2hlY2tlZCkgewogICAgICBlbC5iYWNrdXBTdGFt" +
      "cEhpbnQudGV4dENvbnRlbnQgPSBg5q+P5qyh5aSH5Lu96YO95Lya6KaG55uW5ZCM5LiA5Liq5paH5Lu277yaJHtiYXNlfWA7CiAg" +
      "ICAgIHJldHVybjsKICAgIH0KICAgIGVsLmJhY2t1cFN0YW1wSGludC50ZXh0Q29udGVudCA9CiAgICAgIGDmr4/mrKHlpIfku73l" +
      "hpnlhaUgJHtzdGFtcE5hbWUoYmFzZSwgbG9jYWxTdGFtcCgpKX3vvIzlubblkIzml7bliLfmlrDlm7rlrprlkI3lv6vnhacgJHti" +
      "YXNlfe+8iOOAjOS7juS6keerr+aBouWkjeOAjeivu+eahOaYr+i/meS7ve+8ieOAgmA7CiAgfQoKICBlbC5iYWNrdXBQcm92aWRl" +
      "ci5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCBzeW5jUHJvdmlkZXJQYW5lbHMpOwogIGVsLmJhY2t1cEVuYWJsZWQuYWRkRXZl" +
      "bnRMaXN0ZW5lcignY2hhbmdlJywgc3luY1Byb3ZpZGVyUGFuZWxzKTsKICBlbC5iYWNrdXBTdGFtcC5hZGRFdmVudExpc3RlbmVy" +
      "KCdjaGFuZ2UnLCB1cGRhdGVTdGFtcEhpbnQpOwogIGVsLmJhY2t1cEF1dG8uYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgc3lu" +
      "Y1Byb3ZpZGVyUGFuZWxzKTsKICBlbC5iYWNrdXBTY2hlZHVsZWQuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgc3luY1Byb3Zp" +
      "ZGVyUGFuZWxzKTsKICBlbC5iYWNrdXBJbnRlcnZhbC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCB1cGRhdGVGcmVxdWVuY3lI" +
      "aW50cyk7CiAgZWwuYmFja3VwUGVyaW9kLmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsIHVwZGF0ZUZyZXF1ZW5jeUhpbnRzKTsK" +
      "ICBbZWwucjJLZXksIGVsLnMzRmlsZSwgZWwuczNQcmVmaXgsIGVsLmRhdkZpbGVdLmZvckVhY2goKGlucHV0KSA9PiB7CiAgICBp" +
      "bnB1dC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsIHVwZGF0ZVN0YW1wSGludCk7CiAgfSk7CgogIGFzeW5jIGZ1bmN0aW9uIGxv" +
      "YWRCYWNrdXBDb25maWcoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBkYXRhID0gYXdhaXQgYXBpKCcvYmFja3VwL2NvbmZpZycp" +
      "OwogICAgICBzdGF0ZS5jcm9uID0gZGF0YS5jcm9uIHx8IG51bGw7CiAgICAgIGZpbGxCYWNrdXBGb3JtKGRhdGEuY29uZmlnIHx8" +
      "IHt9KTsKICAgICAgaWYgKGRhdGEubGFzdEJhY2t1cCkgewogICAgICAgIGVsLmxhc3RCYWNrdXBMaW5lLnRleHRDb250ZW50ID0g" +
      "YOS4iuasoeWkh+S7ve+8miR7bmV3IERhdGUoZGF0YS5sYXN0QmFja3VwICogMTAwMCkudG9Mb2NhbGVTdHJpbmcoKX1gOwogICAg" +
      "ICB9IGVsc2UgewogICAgICAgIGVsLmxhc3RCYWNrdXBMaW5lLnRleHRDb250ZW50ID0gJ+WwmuacquWkh+S7vei/h+OAgic7CiAg" +
      "ICAgIH0KICAgIH0gY2F0Y2ggKGVycikgewogICAgICBzZXRTdGF0dXMoZWwuYmFja3VwU3RhdHVzLCBg6K+75Y+W5aSH5Lu96YWN" +
      "572u5aSx6LSl77yaJHtlcnIubWVzc2FnZX1gLCAnZXJyJyk7CiAgICB9CiAgfQoKICBmdW5jdGlvbiBmaWxsQmFja3VwRm9ybShj" +
      "b25maWcpIHsKICAgIGVsLmJhY2t1cFByb3ZpZGVyLnZhbHVlID0gY29uZmlnLnByb3ZpZGVyIHx8ICdub25lJzsKICAgIGVsLmJh" +
      "Y2t1cEVuYWJsZWQuY2hlY2tlZCA9ICEhY29uZmlnLmVuYWJsZWQ7CiAgICBlbC5iYWNrdXBBdXRvLmNoZWNrZWQgPSAhIWNvbmZp" +
      "Zy5hdXRvOwogICAgZWwuYmFja3VwU3RhbXAuY2hlY2tlZCA9IGNvbmZpZy5zdGFtcCAhPT0gZmFsc2U7ICAgLy8g6buY6K6k5byA" +
      "5ZCvCiAgICBzZXRTZWxlY3RWYWx1ZShlbC5iYWNrdXBJbnRlcnZhbCwgY29uZmlnLmludGVydmFsTWluID8/IDEpOwogICAgZWwu" +
      "YmFja3VwU2NoZWR1bGVkLmNoZWNrZWQgPSAhIWNvbmZpZy5zY2hlZHVsZWQ7CiAgICBzZXRTZWxlY3RWYWx1ZShlbC5iYWNrdXBQ" +
      "ZXJpb2QsIGNvbmZpZy5zY2hlZHVsZU1pbiA/PyA2MCk7CgogICAgZWwucjJLZXkudmFsdWUgPSBjb25maWcucjI/LmtleSB8fCAn" +
      "JzsKICAgIGlmIChjb25maWcuaGFzUjJCaW5kaW5nID09PSBmYWxzZSkgewogICAgICBlbC5yMktleS5wbGFjZWhvbGRlciA9ICfm" +
      "nKrmo4DmtYvliLAgUjIg57uR5a6aIEJBQ0tVUFMnOwogICAgfQoKICAgIGNvbnN0IHMzID0gY29uZmlnLnMzIHx8IHt9OwogICAg" +
      "ZWwuczNFbmRwb2ludC52YWx1ZSA9IHMzLmVuZHBvaW50IHx8ICcnOwogICAgZWwuczNSZWdpb24udmFsdWUgPSBzMy5yZWdpb24g" +
      "fHwgJ2F1dG8nOwogICAgZWwuczNCdWNrZXQudmFsdWUgPSBzMy5idWNrZXQgfHwgJyc7CiAgICBlbC5zM0FraWQudmFsdWUgPSBz" +
      "My5hY2Nlc3NLZXlJZCB8fCAnJzsKICAgIGVsLnMzU2VjcmV0LnZhbHVlID0gJyc7CiAgICBlbC5zM1NlY3JldC5wbGFjZWhvbGRl" +
      "ciA9IHMzLmhhc1NlY3JldEtleQogICAgICA/IChzMy5zZWNyZXRGcm9tRW52ID8gJ+W3suWcqOeOr+Wig+WPmOmHj+S4remFjee9" +
      "ru+8iOeVmeepuuWNs+S9v+eUqO+8iScgOiAn5bey5L+d5a2Y77yM55WZ56m66KGo56S65LiN5L+u5pS5JykKICAgICAgOiAn55WZ" +
      "56m66KGo56S65LiN5L+u5pS5JzsKICAgIGVsLnMzUHJlZml4LnZhbHVlID0gczMucHJlZml4IHx8ICcnOwogICAgZWwuczNGaWxl" +
      "LnZhbHVlID0gY29uZmlnLmZpbGUgJiYgY29uZmlnLnByb3ZpZGVyID09PSAnczMnID8gY29uZmlnLmZpbGUgOiAoY29uZmlnLmZp" +
      "bGUgfHwgJycpOwogICAgZWwuczNQYXRoU3R5bGUuY2hlY2tlZCA9ICEhczMucGF0aFN0eWxlOwoKICAgIGNvbnN0IGRhdiA9IGNv" +
      "bmZpZy53ZWJkYXYgfHwge307CiAgICBlbC5kYXZVcmwudmFsdWUgPSBkYXYudXJsIHx8ICcnOwogICAgZWwuZGF2VXNlci52YWx1" +
      "ZSA9IGRhdi51c2VybmFtZSB8fCAnJzsKICAgIGVsLmRhdlBhc3MudmFsdWUgPSAnJzsKICAgIGVsLmRhdlBhc3MucGxhY2Vob2xk" +
      "ZXIgPSBkYXYuaGFzUGFzc3dvcmQKICAgICAgPyAoZGF2LnBhc3N3b3JkRnJvbUVudiA/ICflt7LlnKjnjq/looPlj5jph4/kuK3p" +
      "hY3nva7vvIjnlZnnqbrljbPkvb/nlKjvvIknIDogJ+W3suS/neWtmO+8jOeVmeepuuihqOekuuS4jeS/ruaUuScpCiAgICAgIDog" +
      "J+eVmeepuuihqOekuuS4jeS/ruaUuSc7CiAgICBlbC5kYXZGaWxlLnZhbHVlID0gZGF2LmZpbGUgfHwgJyc7CgogICAgc3luY1By" +
      "b3ZpZGVyUGFuZWxzKCk7CiAgfQoKICBmdW5jdGlvbiBjb2xsZWN0QmFja3VwRm9ybSgpIHsKICAgIGNvbnN0IHByb3ZpZGVyID0g" +
      "ZWwuYmFja3VwUHJvdmlkZXIudmFsdWU7CiAgICByZXR1cm4gewogICAgICBwcm92aWRlciwKICAgICAgZW5hYmxlZDogZWwuYmFj" +
      "a3VwRW5hYmxlZC5jaGVja2VkICYmIHByb3ZpZGVyICE9PSAnbm9uZScsCiAgICAgIGF1dG86IGVsLmJhY2t1cEF1dG8uY2hlY2tl" +
      "ZCAmJiBlbC5iYWNrdXBFbmFibGVkLmNoZWNrZWQgJiYgcHJvdmlkZXIgIT09ICdub25lJywKICAgICAgaW50ZXJ2YWxNaW46IE51" +
      "bWJlcihlbC5iYWNrdXBJbnRlcnZhbC52YWx1ZSkgfHwgMCwKICAgICAgc2NoZWR1bGVkOiBlbC5iYWNrdXBTY2hlZHVsZWQuY2hl" +
      "Y2tlZCAmJiBlbC5iYWNrdXBFbmFibGVkLmNoZWNrZWQgJiYgcHJvdmlkZXIgIT09ICdub25lJywKICAgICAgc2NoZWR1bGVNaW46" +
      "IE51bWJlcihlbC5iYWNrdXBQZXJpb2QudmFsdWUpIHx8IDYwLAogICAgICBzdGFtcDogZWwuYmFja3VwU3RhbXAuY2hlY2tlZCwK" +
      "ICAgICAgLy8g5YmN56uv55u05o6l5oqK5rWP6KeI5Zmo5pe25Yy65oql57uZ5ZCO56uv77yM5a6a5pe25aSH5Lu95ou85paH5Lu2" +
      "5ZCN5pe255SoCiAgICAgIHR6OiBJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmUgfHwgJycs" +
      "CiAgICAgIGZpbGU6IHByb3ZpZGVyID09PSAnd2ViZGF2JwogICAgICAgID8gKGVsLmRhdkZpbGUudmFsdWUudHJpbSgpIHx8ICd0" +
      "b2RvLXRvZGF5LmJhY2t1cC5qc29uJykKICAgICAgICA6IChlbC5zM0ZpbGUudmFsdWUudHJpbSgpIHx8ICd0b2RvLXRvZGF5LmJh" +
      "Y2t1cC5qc29uJyksCiAgICAgIHIyOiB7IGtleTogZWwucjJLZXkudmFsdWUudHJpbSgpIH0sCiAgICAgIHMzOiB7CiAgICAgICAg" +
      "ZW5kcG9pbnQ6IGVsLnMzRW5kcG9pbnQudmFsdWUudHJpbSgpLAogICAgICAgIHJlZ2lvbjogZWwuczNSZWdpb24udmFsdWUudHJp" +
      "bSgpIHx8ICdhdXRvJywKICAgICAgICBidWNrZXQ6IGVsLnMzQnVja2V0LnZhbHVlLnRyaW0oKSwKICAgICAgICBhY2Nlc3NLZXlJ" +
      "ZDogZWwuczNBa2lkLnZhbHVlLnRyaW0oKSwKICAgICAgICBzZWNyZXRBY2Nlc3NLZXk6IGVsLnMzU2VjcmV0LnZhbHVlLnRyaW0o" +
      "KSwKICAgICAgICBwcmVmaXg6IGVsLnMzUHJlZml4LnZhbHVlLnRyaW0oKSwKICAgICAgICBwYXRoU3R5bGU6IGVsLnMzUGF0aFN0" +
      "eWxlLmNoZWNrZWQsCiAgICAgIH0sCiAgICAgIHdlYmRhdjogewogICAgICAgIHVybDogZWwuZGF2VXJsLnZhbHVlLnRyaW0oKSwK" +
      "ICAgICAgICB1c2VybmFtZTogZWwuZGF2VXNlci52YWx1ZS50cmltKCksCiAgICAgICAgcGFzc3dvcmQ6IGVsLmRhdlBhc3MudmFs" +
      "dWUudHJpbSgpLAogICAgICAgIGZpbGU6IGVsLmRhdkZpbGUudmFsdWUudHJpbSgpLAogICAgICB9LAogICAgfTsKICB9CgogIGVs" +
      "LmJhY2t1cFNhdmUuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3luYyAoKSA9PiB7CiAgICBzZXRTdGF0dXMoZWwuYmFja3Vw" +
      "U3RhdHVzLCAn5L+d5a2Y5Lit4oCmJywgJ2J1c3knKTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBhcGkoJy9i" +
      "YWNrdXAvY29uZmlnJywgeyBtZXRob2Q6ICdQVVQnLCBib2R5OiBjb2xsZWN0QmFja3VwRm9ybSgpIH0pOwogICAgICBmaWxsQmFj" +
      "a3VwRm9ybShkYXRhLmNvbmZpZyB8fCB7fSk7CiAgICAgIHNldFN0YXR1cyhlbC5iYWNrdXBTdGF0dXMsICfphY3nva7lt7Lkv53l" +
      "rZgnLCAnb2snKTsKICAgICAgdG9hc3QoJ+Wkh+S7vemFjee9ruW3suS/neWtmCcsICdvaycpOwogICAgfSBjYXRjaCAoZXJyKSB7" +
      "CiAgICAgIHNldFN0YXR1cyhlbC5iYWNrdXBTdGF0dXMsIGDkv53lrZjlpLHotKXvvJoke2Vyci5tZXNzYWdlfWAsICdlcnInKTsK" +
      "ICAgIH0KICB9KTsKCiAgZWwuYmFja3VwVGVzdC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICAgIHNl" +
      "dFN0YXR1cyhlbC5iYWNrdXBTdGF0dXMsICfmraPlnKjmtYvor5Xov57mjqXigKYnLCAnYnVzeScpOwogICAgdHJ5IHsKICAgICAg" +
      "Y29uc3QgZGF0YSA9IGF3YWl0IGFwaSgnL2JhY2t1cC90ZXN0JywgeyBtZXRob2Q6ICdQT1NUJywgYm9keTogY29sbGVjdEJhY2t1" +
      "cEZvcm0oKSB9KTsKICAgICAgc2V0U3RhdHVzKGVsLmJhY2t1cFN0YXR1cywgZGF0YS5tZXNzYWdlIHx8ICfov57mjqXmraPluLgn" +
      "LCAnb2snKTsKICAgIH0gY2F0Y2ggKGVycikgewogICAgICBzZXRTdGF0dXMoZWwuYmFja3VwU3RhdHVzLCBg6L+e5o6l5aSx6LSl" +
      "77yaJHtlcnIubWVzc2FnZX1gLCAnZXJyJyk7CiAgICB9CiAgfSk7CgogIGVsLmJhY2t1cFJ1bi5hZGRFdmVudExpc3RlbmVyKCdj" +
      "bGljaycsIGFzeW5jICgpID0+IHsKICAgIHNldFN0YXR1cyhlbC5iYWNrdXBTdGF0dXMsICfmraPlnKjlpIfku73igKYnLCAnYnVz" +
      "eScpOwogICAgdHJ5IHsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGFwaSgnL2JhY2t1cC9ydW4nLCB7IG1ldGhvZDogJ1BPU1Qn" +
      "IH0pOwogICAgICBjb25zdCByID0gZGF0YS5yZXN1bHQgfHwge307CiAgICAgIGNvbnN0IGRldGFpbCA9IHIua2V5ICYmIHIua2V5" +
      "ICE9PSByLmxhdGVzdEtleQogICAgICAgID8gYOWFsSAke3IudG90YWwgPz8gJy0nfSDmnaHku7vliqHvvIwke2Zvcm1hdEJ5dGVz" +
      "KHIuc2l6ZSl9IOKGkiAke3Iua2V5fWAKICAgICAgICA6IGDlhbEgJHtyLnRvdGFsID8/ICctJ30g5p2h5Lu75Yqh77yMJHtmb3Jt" +
      "YXRCeXRlcyhyLnNpemUpfSDihpIgJHtyLmtleSB8fCByLmxhdGVzdEtleSB8fCAnJ31gOwogICAgICBzZXRTdGF0dXMoZWwuYmFj" +
      "a3VwU3RhdHVzLCBg5aSH5Lu95oiQ5Yqf77yaJHtkZXRhaWx9YCwgJ29rJyk7CiAgICAgIGVsLmxhc3RCYWNrdXBMaW5lLnRleHRD" +
      "b250ZW50ID0gYOS4iuasoeWkh+S7ve+8miR7bmV3IERhdGUoKS50b0xvY2FsZVN0cmluZygpfWA7CiAgICAgIHRvYXN0KCflt7Ll" +
      "pIfku73liLDkupHnq68nLCAnb2snKTsKICAgIH0gY2F0Y2ggKGVycikgewogICAgICBzZXRTdGF0dXMoZWwuYmFja3VwU3RhdHVz" +
      "LCBg5aSH5Lu95aSx6LSl77yaJHtlcnIubWVzc2FnZX1gLCAnZXJyJyk7CiAgICB9CiAgfSk7CgogIGVsLmJhY2t1cFJlc3RvcmUu" +
      "YWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBhcm1lZENsaWNrKGVsLmJhY2t1cFJlc3RvcmUsICfnoa7orqTo" +
      "pobnm5bvvJ8nLCBhc3luYyAoKSA9PiB7CiAgICAgIHNldFN0YXR1cyhlbC5iYWNrdXBTdGF0dXMsICfmraPlnKjku47kupHnq6/m" +
      "gaLlpI3igKYnLCAnYnVzeScpOwogICAgICB0cnkgewogICAgICBjb25zdCBkYXRhID0gYXdhaXQgYXBpKCcvYmFja3VwL3Jlc3Rv" +
      "cmUnLCB7IG1ldGhvZDogJ1BPU1QnLCBib2R5OiB7IG1vZGU6ICdyZXBsYWNlJyB9IH0pOwogICAgICBzZXRTdGF0dXMoZWwuYmFj" +
      "a3VwU3RhdHVzLCBgJHtkYXRhLm1lc3NhZ2V977yI5paw5aKeICR7ZGF0YS5yZXN1bHQ/Lmluc2VydGVkID8/IDB9IOadoe+8iWAs" +
      "ICdvaycpOwogICAgICBjYWNoZUNsZWFyQWxsKCk7ICAgLy8g5LqR56uv5pWw5o2u5pW05L2T5pu/5o2i77yM57yT5a2Y5YWo6YOo" +
      "5aSx5pWICiAgICAgIGF3YWl0IHJlZnJlc2goKTsKICAgICAgc2NoZWR1bGVTaWRlYmFyUmVmcmVzaCgpOwogICAgICB9IGNhdGNo" +
      "IChlcnIpIHsKICAgICAgICBzZXRTdGF0dXMoZWwuYmFja3VwU3RhdHVzLCBg5oGi5aSN5aSx6LSl77yaJHtlcnIubWVzc2FnZX1g" +
      "LCAnZXJyJyk7CiAgICAgIH0KICAgIH0pOwogIH0pOwoKICBmdW5jdGlvbiBmb3JtYXRCeXRlcyhuKSB7CiAgICBjb25zdCBudW0g" +
      "PSBOdW1iZXIobikgfHwgMDsKICAgIGlmIChudW0gPCAxMDI0KSByZXR1cm4gYCR7bnVtfSBCYDsKICAgIGlmIChudW0gPCAxMDI0" +
      "ICogMTAyNCkgcmV0dXJuIGAkeyhudW0gLyAxMDI0KS50b0ZpeGVkKDEpfSBLQmA7CiAgICByZXR1cm4gYCR7KG51bSAvIDEwMjQg" +
      "LyAxMDI0KS50b0ZpeGVkKDIpfSBNQmA7CiAgfQoKICAvKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0g5a+85YWl5a+8" +
      "5Ye6IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwogIGVsLmV4cG9ydEJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGlj" +
      "aycsIGFzeW5jICgpID0+IHsKICAgIHRyeSB7CiAgICAgIGlmIChzdGF0ZS5kZW1vKSB7CiAgICAgICAgY29uc3QgZGIgPSBkZW1v" +
      "UmVhZCgpOwogICAgICAgIGRvd25sb2FkSnNvbih7IGFwcDogJ3RvZG8tdG9kYXknLCB2ZXJzaW9uOiAxLCBleHBvcnRlZEF0OiBu" +
      "ZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksIHRvZG9zOiBkYi50b2RvcyB9KTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAg" +
      "Y29uc3QgcmVzID0gYXdhaXQgZmV0Y2goYCR7QVBJX0JBU0V9L2V4cG9ydGAsIHsgY3JlZGVudGlhbHM6ICdzYW1lLW9yaWdpbicg" +
      "fSk7CiAgICAgIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoYOWvvOWHuuWksei0pSAoJHtyZXMuc3RhdHVzfSlgKTsKICAg" +
      "ICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgIGRvd25sb2FkQmxvYihibG9iLCBgdG9kby10b2RheS0ke3Rv" +
      "ZGF5U3RyKCl9Lmpzb25gKTsKICAgICAgdG9hc3QoJ+W3suWvvOWHuiBKU09OJywgJ29rJyk7CiAgICB9IGNhdGNoIChlcnIpIHsK" +
      "ICAgICAgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnInKTsKICAgIH0KICB9KTsKCiAgZWwuaW1wb3J0QnRuLmFkZEV2ZW50TGlzdGVu" +
      "ZXIoJ2NsaWNrJywgKCkgPT4gZWwuaW1wb3J0RmlsZS5jbGljaygpKTsKCiAgZWwuaW1wb3J0RmlsZS5hZGRFdmVudExpc3RlbmVy" +
      "KCdjaGFuZ2UnLCBhc3luYyAoKSA9PiB7CiAgICBjb25zdCBmaWxlID0gZWwuaW1wb3J0RmlsZS5maWxlcz8uWzBdOwogICAgZWwu" +
      "aW1wb3J0RmlsZS52YWx1ZSA9ICcnOwogICAgaWYgKCFmaWxlKSByZXR1cm47CgogICAgdHJ5IHsKICAgICAgY29uc3QgdGV4dCA9" +
      "IGF3YWl0IGZpbGUudGV4dCgpOwogICAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5wYXJzZSh0ZXh0KTsKICAgICAgaWYgKCFBcnJh" +
      "eS5pc0FycmF5KHBheWxvYWQ/LnRvZG9zKSkgdGhyb3cgbmV3IEVycm9yKCfmlofku7bmoLzlvI/kuI3mraPnoa7vvJrnvLrlsJEg" +
      "dG9kb3Mg5pWw57uEJyk7CgogICAgICBpZiAoc3RhdGUuZGVtbykgewogICAgICAgIGNvbnN0IGRiID0gZGVtb1JlYWQoKTsKICAg" +
      "ICAgICBkYi50b2RvcyA9IHBheWxvYWQudG9kb3MubWFwKCh0LCBpKSA9PiAoewogICAgICAgICAgaWQ6IGRlbW9JZCgpLCB0aXRs" +
      "ZTogU3RyaW5nKHQudGl0bGUgfHwgJycpLnRyaW0oKSwgZG9uZTogISF0LmRvbmUsCiAgICAgICAgICBkYXRlOiB0LmRhdGUgfHwg" +
      "dG9kYXlTdHIoKSwgb3JkZXI6IGksIGNyZWF0ZWRBdDogTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCksCiAgICAgICAgfSkp" +
      "LmZpbHRlcigodCkgPT4gdC50aXRsZSk7CiAgICAgICAgZGVtb1dyaXRlKGRiKTsKICAgICAgICBjYWNoZUNsZWFyQWxsKCk7CiAg" +
      "ICAgICAgYXdhaXQgcmVmcmVzaCgpOwogICAgICAgIHRvYXN0KGDlr7zlhaXlrozmiJDvvJoke2RiLnRvZG9zLmxlbmd0aH0g5p2h" +
      "YCwgJ29rJyk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBkYXRhID0gYXdhaXQgYXBpKCcvaW1wb3J0Jywg" +
      "eyBtZXRob2Q6ICdQT1NUJywgYm9keTogeyBwYXlsb2FkLCBtb2RlOiAncmVwbGFjZScgfSB9KTsKICAgICAgY2FjaGVDbGVhckFs" +
      "bCgpOyAgIC8vIOWvvOWFpeaVtOS9k+abv+aNouaVsOaNru+8jOe8k+WtmOWFqOmDqOWkseaViAogICAgICBhd2FpdCByZWZyZXNo" +
      "KCk7CiAgICAgIHNjaGVkdWxlU2lkZWJhclJlZnJlc2goKTsKICAgICAgdG9hc3QoZGF0YS5tZXNzYWdlIHx8ICflr7zlhaXlrozm" +
      "iJAnLCAnb2snKTsKICAgIH0gY2F0Y2ggKGVycikgewogICAgICB0b2FzdChg5a+85YWl5aSx6LSl77yaJHtlcnIubWVzc2FnZX1g" +
      "LCAnZXJyJyk7CiAgICB9CiAgfSk7CgogIGZ1bmN0aW9uIGRvd25sb2FkSnNvbihvYmopIHsKICAgIGRvd25sb2FkQmxvYihuZXcg" +
      "QmxvYihbSlNPTi5zdHJpbmdpZnkob2JqLCBudWxsLCAyKV0sIHsgdHlwZTogJ2FwcGxpY2F0aW9uL2pzb24nIH0pLCBgdG9kby10" +
      "b2RheS0ke3RvZGF5U3RyKCl9Lmpzb25gKTsKICB9CgogIGZ1bmN0aW9uIGRvd25sb2FkQmxvYihibG9iLCBmaWxlbmFtZSkgewog" +
      "ICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgIGNvbnN0IGEgPSBkb2N1bWVudC5jcmVhdGVFbGVt" +
      "ZW50KCdhJyk7CiAgICBhLmhyZWYgPSB1cmw7CiAgICBhLmRvd25sb2FkID0gZmlsZW5hbWU7CiAgICBkb2N1bWVudC5ib2R5LmFw" +
      "cGVuZENoaWxkKGEpOwogICAgYS5jbGljaygpOwogICAgYS5yZW1vdmUoKTsKICAgIHNldFRpbWVvdXQoKCkgPT4gVVJMLnJldm9r" +
      "ZU9iamVjdFVSTCh1cmwpLCAxMDAwKTsKICB9CgogIC8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqCiAgICog5ZCv5YqoCiAgICogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgZWwuYWJvdXRWZXJzaW9uLnRleHRDb250ZW50ID0gYOWJ" +
      "jeerryB2JHtBUFBfVkVSU0lPTn1gOwoKICAvLyDlv6vmjbfplK7vvJovIOiBmueEpuaWsOWinui+k+WFpeahhu+8m0N0cmwvQ21k" +
      "K0sg6IGa54Sm5pCc57Si77ybRXNjIOWFs+aKveWxiS/kvqfmoI8KICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3du" +
      "JywgKGUpID0+IHsKICAgIGNvbnN0IGluRmllbGQgPSAvXihJTlBVVHxURVhUQVJFQXxTRUxFQ1QpJC8udGVzdChkb2N1bWVudC5h" +
      "Y3RpdmVFbGVtZW50Py50YWdOYW1lIHx8ICcnKQogICAgICB8fCBkb2N1bWVudC5hY3RpdmVFbGVtZW50Py5pc0NvbnRlbnRFZGl0" +
      "YWJsZTsKCiAgICBpZiAoKGUuY3RybEtleSB8fCBlLm1ldGFLZXkpICYmIGUua2V5LnRvTG93ZXJDYXNlKCkgPT09ICdrJykgewog" +
      "ICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGVsLnNlYXJjaElucHV0LmZvY3VzKCk7CiAgICAgIGVsLnNlYXJjaElucHV0" +
      "LnNlbGVjdCgpOwogICAgICByZXR1cm47CiAgICB9CiAgICBpZiAoZS5rZXkgPT09ICcvJyAmJiAhaW5GaWVsZCkgewogICAgICBl" +
      "LnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGVsLmFkZElucHV0LmZvY3VzKCk7CiAgICB9CiAgfSk7CgogIC8qKiDmjqLmtYvlkI7n" +
      "q6/mmK/lkKblhYHorrjms6jlhozvvJvkuI3lhYHorrjml7bpmpDol4/jgIzms6jlhozjgI3moIfnrb7pobUgKi8KICBhc3luYyBm" +
      "dW5jdGlvbiBzeW5jUmVnaXN0cmF0aW9uVGFiKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgaGVhbHRoID0gYXdhaXQgYXBpKCcv" +
      "aGVhbHRoJyk7CiAgICAgIGlmIChoZWFsdGggJiYgaGVhbHRoLnJlZ2lzdHJhdGlvbiA9PT0gZmFsc2UpIHsKICAgICAgICBjb25z" +
      "dCByZWdUYWIgPSBlbC50YWJzLmZpbmQoKHQpID0+IHQuZGF0YXNldC5tb2RlID09PSAncmVnaXN0ZXInKTsKICAgICAgICByZWdU" +
      "YWI/LmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICAgIGlmIChzdGF0ZS5hdXRoTW9kZSA9PT0gJ3JlZ2lzdGVyJykgc2V0" +
      "QXV0aE1vZGUoJ2xvZ2luJyk7CiAgICAgIH0KICAgIH0gY2F0Y2ggeyAvKiDmjqLmtYvlpLHotKXlsLHmjInpu5jorqTmmL7npLog" +
      "Ki8gfQogIH0KCiAgKGFzeW5jIGZ1bmN0aW9uIGJvb3QoKSB7CiAgICByZW5kZXJEYXRlKCk7CgogICAgaWYgKEZPUkNFX0RFTU8p" +
      "IHsKICAgICAgc3RhdGUuZGVtbyA9IHRydWU7CiAgICAgIHNlZWREZW1vRGF0YSgpOwogICAgICBlbC5kZW1vQmFubmVyLmNsYXNz" +
      "TGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgICBlbC5hYm91dFZlcnNpb24udGV4dENvbnRlbnQgPSBg5YmN56uvIHYke0FQUF9W" +
      "RVJTSU9OfSDCtyDmvJTnpLrmqKHlvI9gOwogICAgICBzdGF0ZS51c2VyID0gZGVtb1JlYWQoKS51c2VyOwogICAgICBhd2FpdCBz" +
      "aG93TWFpbigpOwogICAgICByZXR1cm47CiAgICB9CgogICAgYXdhaXQgc3luY1JlZ2lzdHJhdGlvblRhYigpOwogICAgdHJ5IHsK" +
      "ICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGFwaSgnL2F1dGgvbWUnKTsKICAgICAgc3RhdGUudXNlciA9IGRhdGEudXNlcjsKICAg" +
      "ICAgaWYgKHN0YXRlLnVzZXIpIGF3YWl0IHNob3dNYWluKCk7CiAgICAgIGVsc2Ugc2hvd0F1dGgoKTsKICAgIH0gY2F0Y2ggewog" +
      "ICAgICBzaG93QXV0aCgpOwogICAgfQogIH0pKCk7Cn0pKCk7Cg=="
  },
  "/icon.svg": {
    type: "image/svg+xml",
    body:
      "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxOTIgMTkyIiB3aWR0aD0iMTkyIiBo" +
      "ZWlnaHQ9IjE5MiI+CiAgPGRlZnM+CiAgICA8bGluZWFyR3JhZGllbnQgaWQ9ImciIHgxPSIwIiB5MT0iMCIgeDI9IjEiIHkyPSIx" +
      "Ij4KICAgICAgPHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSIjNmQ2ZGYwIi8+CiAgICAgIDxzdG9wIG9mZnNldD0iMSIgc3Rv" +
      "cC1jb2xvcj0iIzQ0NDRiOCIvPgogICAgPC9saW5lYXJHcmFkaWVudD4KICA8L2RlZnM+CiAgPHJlY3Qgd2lkdGg9IjE5MiIgaGVp" +
      "Z2h0PSIxOTIiIHJ4PSI0NCIgZmlsbD0idXJsKCNnKSIvPgogIDxwYXRoIGQ9Ik01NiA5OGwyNiAyNiA1NC01OCIgZmlsbD0ibm9u" +
      "ZSIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utd2lkdGg9IjE2IgogICAgICAgIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxp" +
      "bmVqb2luPSJyb3VuZCIvPgo8L3N2Zz4K"
  },
  "/index.html": {
    type: "text/html; charset=utf-8",
    body:
      "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9InpoLUNOIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9InV0Zi04IiAvPgo8bWV0YSBu" +
      "YW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHZpZXdwb3J0LWZpdD1j" +
      "b3ZlciwgbWF4aW11bS1zY2FsZT0xIiAvPgo8bWV0YSBuYW1lPSJ0aGVtZS1jb2xvciIgY29udGVudD0iIzViNWJkNiIgbWVkaWE9" +
      "IihwcmVmZXJzLWNvbG9yLXNjaGVtZTogbGlnaHQpIiAvPgo8bWV0YSBuYW1lPSJ0aGVtZS1jb2xvciIgY29udGVudD0iIzE0MTQy" +
      "OCIgbWVkaWE9IihwcmVmZXJzLWNvbG9yLXNjaGVtZTogZGFyaykiIC8+CjxtZXRhIG5hbWU9ImRlc2NyaXB0aW9uIiBjb250ZW50" +
      "PSLku4rml6XlvoXlip4gwrcg5p6B566A55qE5q+P5pel5riF5Y2V77yM5LqR56uv5ZCM5q2l77yM5pSv5oyB5LqR5aSH5Lu9IiAv" +
      "Pgo8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC1jYXBhYmxlIiBjb250ZW50PSJ5ZXMiIC8+CjxtZXRhIG5hbWU9ImFw" +
      "cGxlLW1vYmlsZS13ZWItYXBwLXRpdGxlIiBjb250ZW50PSLku4rml6XlvoXlip4iIC8+Cjx0aXRsZT7ku4rml6XlvoXlip48L3Rp" +
      "dGxlPgo8bGluayByZWw9Im1hbmlmZXN0IiBocmVmPSIuL21hbmlmZXN0LndlYm1hbmlmZXN0IiAvPgo8bGluayByZWw9Imljb24i" +
      "IGhyZWY9Ii4vaWNvbi5zdmciIHR5cGU9ImltYWdlL3N2Zyt4bWwiIC8+CjxsaW5rIHJlbD0iYXBwbGUtdG91Y2gtaWNvbiIgaHJl" +
      "Zj0iLi9pY29uLnN2ZyIgLz4KPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSIuL3N0eWxlLmNzcyIgLz4KPC9oZWFkPgo8Ym9k" +
      "eT4KCjwhLS0gPT09PT09PT09PT09PT09PT09PT09PT09PT09PSDliqDovb3kuK0gPT09PT09PT09PT09PT09PT09PT09PT09PT09" +
      "PSAtLT4KPGRpdiBpZD0iYm9vdCIgY2xhc3M9ImJvb3QiPgogIDxkaXYgY2xhc3M9InNwaW5uZXIiIGFyaWEtaGlkZGVuPSJ0cnVl" +
      "Ij48L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09PT09PT09PT09PT09PT09PT09PT09PT0g55m75b2VIC8g5rOo5YaMID09PT09PT09" +
      "PT09PT09PT09PT09PT09PT09PT0gLS0+CjxzZWN0aW9uIGlkPSJhdXRoLXZpZXciIGNsYXNzPSJ2aWV3IGF1dGgtdmlldyBoaWRk" +
      "ZW4iPgogIDxkaXYgY2xhc3M9ImF1dGgtY2FyZCI+CiAgICA8ZGl2IGNsYXNzPSJicmFuZCI+CiAgICAgIDxkaXYgY2xhc3M9ImJy" +
      "YW5kLW1hcmsiIGFyaWEtaGlkZGVuPSJ0cnVlIj4KICAgICAgICA8c3ZnIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIg" +
      "c3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMi4yIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5l" +
      "am9pbj0icm91bmQiPgogICAgICAgICAgPHBhdGggZD0iTTkgMTFsMyAzTDIyIDQiIC8+CiAgICAgICAgICA8cGF0aCBkPSJNMjEg" +
      "MTJ2N2EyIDIgMCAwIDEtMiAySDVhMiAyIDAgMCAxLTItMlY1YTIgMiAwIDAgMSAyLTJoMTEiIC8+CiAgICAgICAgPC9zdmc+CiAg" +
      "ICAgIDwvZGl2PgogICAgICA8aDE+5LuK5pel5b6F5YqePC9oMT4KICAgICAgPHAgY2xhc3M9ImJyYW5kLXN1YiI+5q+P5aSp5Y+q" +
      "5YWz5b+D5LuK5aSp55qE5riF5Y2VPC9wPgogICAgPC9kaXY+CgogICAgPGRpdiBjbGFzcz0idGFicyIgcm9sZT0idGFibGlzdCI+" +
      "CiAgICAgIDxidXR0b24gY2xhc3M9InRhYiBhY3RpdmUiIGRhdGEtbW9kZT0ibG9naW4iIHJvbGU9InRhYiI+55m75b2VPC9idXR0" +
      "b24+CiAgICAgIDxidXR0b24gY2xhc3M9InRhYiIgZGF0YS1tb2RlPSJyZWdpc3RlciIgcm9sZT0idGFiIj7ms6jlhow8L2J1dHRv" +
      "bj4KICAgIDwvZGl2PgoKICAgIDxmb3JtIGlkPSJhdXRoLWZvcm0iIGF1dG9jb21wbGV0ZT0ib24iIG5vdmFsaWRhdGU+CiAgICAg" +
      "IDxsYWJlbCBjbGFzcz0iZmllbGQiPgogICAgICAgIDxzcGFuPueUqOaIt+WQjTwvc3Bhbj4KICAgICAgICA8aW5wdXQgaWQ9ImF1" +
      "dGgtdXNlcm5hbWUiIHR5cGU9InRleHQiIG5hbWU9InVzZXJuYW1lIiBhdXRvY29tcGxldGU9InVzZXJuYW1lIgogICAgICAgICAg" +
      "ICAgICBwbGFjZWhvbGRlcj0iMi0yMCDkvY3vvIzkuK3oi7Hmlocv5pWw5a2XL18gLiAtIiByZXF1aXJlZCBtYXhsZW5ndGg9IjIw" +
      "IiAvPgogICAgICA8L2xhYmVsPgoKICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCI+CiAgICAgICAgPHNwYW4+5a+G56CBPC9zcGFu" +
      "PgogICAgICAgIDxkaXYgY2xhc3M9ImlucHV0LXdpdGgtYWN0aW9uIj4KICAgICAgICAgIDxpbnB1dCBpZD0iYXV0aC1wYXNzd29y" +
      "ZCIgdHlwZT0icGFzc3dvcmQiIG5hbWU9InBhc3N3b3JkIgogICAgICAgICAgICAgICAgIGF1dG9jb21wbGV0ZT0iY3VycmVudC1w" +
      "YXNzd29yZCIgcGxhY2Vob2xkZXI9IuiHs+WwkSA2IOS9jSIgcmVxdWlyZWQgbWlubGVuZ3RoPSI2IiBtYXhsZW5ndGg9IjEyOCIg" +
      "Lz4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBpZD0idG9nZ2xlLXBhc3N3b3JkIiBjbGFzcz0iZ2hvc3QtaWNvbiIg" +
      "YXJpYS1sYWJlbD0i5pi+56S65a+G56CBIj7wn5GBPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvbGFiZWw+CgogICAg" +
      "ICA8cCBpZD0iYXV0aC1lcnJvciIgY2xhc3M9ImZvcm0tZXJyb3IiIHJvbGU9ImFsZXJ0IiBoaWRkZW4+PC9wPgoKICAgICAgPGJ1" +
      "dHRvbiB0eXBlPSJzdWJtaXQiIGlkPSJhdXRoLXN1Ym1pdCIgY2xhc3M9ImJ0biBwcmltYXJ5IGJsb2NrIj4KICAgICAgICA8c3Bh" +
      "biBpZD0iYXV0aC1zdWJtaXQtbGFiZWwiPueZu+W9lTwvc3Bhbj4KICAgICAgPC9idXR0b24+CiAgICA8L2Zvcm0+CgogICAgPHAg" +
      "Y2xhc3M9ImF1dGgtZm9vdCI+CiAgICAgIOaVsOaNruWtmOWCqOWcqCBDbG91ZGZsYXJlIEQx77yM5Y+v6Ieq55Sx6YWN572uIFIy" +
      "IC8gUzMgLyBXZWJEQVYg5LqR5aSH5Lu944CCCiAgICA8L3A+CiAgPC9kaXY+Cjwvc2VjdGlvbj4KCjwhLS0gPT09PT09PT09PT09" +
      "PT09PT09PT09PT09PT09PSDkuLvnlYzpnaIgPT09PT09PT09PT09PT09PT09PT09PT09PT09PSAtLT4KPHNlY3Rpb24gaWQ9Im1h" +
      "aW4tdmlldyIgY2xhc3M9InZpZXcgbWFpbi12aWV3IGhpZGRlbiI+CiAgPGRpdiBjbGFzcz0ic2hlbGwiPgoKICAgIDwhLS0g5L6n" +
      "5qCP77ya5qGM6Z2i5bi46am777yM56e75Yqo56uv5oq95bGJIC0tPgogICAgPGFzaWRlIGlkPSJzaWRlYmFyIiBjbGFzcz0ic2lk" +
      "ZWJhciIgYXJpYS1sYWJlbD0i5a+86Iiq5L6n5qCPIj4KICAgICAgPGRpdiBjbGFzcz0ic2lkZS1zZWFyY2giPgogICAgICAgIDxz" +
      "dmcgY2xhc3M9InNpZGUtc2VhcmNoLWljb24iIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50" +
      "Q29sb3IiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBhcmlhLWhpZGRlbj0idHJ1ZSI+CiAgICAgICAg" +
      "ICA8Y2lyY2xlIGN4PSIxMSIgY3k9IjExIiByPSI3IiAvPjxwYXRoIGQ9Ik0yMSAyMWwtNC4zLTQuMyIgLz4KICAgICAgICA8L3N2" +
      "Zz4KICAgICAgICA8aW5wdXQgaWQ9InNlYXJjaC1pbnB1dCIgdHlwZT0ic2VhcmNoIiBwbGFjZWhvbGRlcj0i5pCc57Si5Lu75Yqh" +
      "77yM5pSv5oyBICPmoIfnrb4iCiAgICAgICAgICAgICAgIGF1dG9jb21wbGV0ZT0ib2ZmIiBlbnRlcmtleWhpbnQ9InNlYXJjaCIg" +
      "YXJpYS1sYWJlbD0i5pCc57Si5Lu75YqhIiAvPgogICAgICAgIDxidXR0b24gaWQ9InNlYXJjaC1jbGVhciIgY2xhc3M9InNpZGUt" +
      "c2VhcmNoLWNsZWFyIGhpZGRlbiIgYXJpYS1sYWJlbD0i5riF6Zmk5pCc57SiIj7inJU8L2J1dHRvbj4KICAgICAgPC9kaXY+Cgog" +
      "ICAgICA8ZGl2IGNsYXNzPSJzaWRlLXN0YXRzIj4KICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0Ij48YiBpZD0ic3RhdC1kYXlzIj4w" +
      "PC9iPjxzcGFuPuiusOW9leWkqeaVsDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0Ij48YiBpZD0ic3RhdC10" +
      "b3RhbCI+MDwvYj48c3Bhbj7lhajpg6jku7vliqE8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0ic3RhdCI+PGIgaWQ9" +
      "InN0YXQtZG9uZSI+MDwvYj48c3Bhbj7lt7LlrozmiJA8L3NwYW4+PC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPHNlY3Rpb24g" +
      "Y2xhc3M9InNpZGUtYmxvY2siPgogICAgICAgIDxoZWFkZXIgY2xhc3M9InNpZGUtaGVhZCI+CiAgICAgICAgICA8c3BhbiBpZD0i" +
      "Y2FsLXRpdGxlIj7igJQ8L3NwYW4+CiAgICAgICAgICA8c3BhbiBjbGFzcz0ic2lkZS1oZWFkLWJ0bnMiPgogICAgICAgICAgICA8" +
      "YnV0dG9uIGlkPSJjYWwtcHJldiIgY2xhc3M9Im1pbmktYnRuIiBhcmlhLWxhYmVsPSLkuIrkuKrmnIgiPuKAuTwvYnV0dG9uPgog" +
      "ICAgICAgICAgICA8YnV0dG9uIGlkPSJjYWwtbmV4dCIgY2xhc3M9Im1pbmktYnRuIiBhcmlhLWxhYmVsPSLkuIvkuKrmnIgiPuKA" +
      "ujwvYnV0dG9uPgogICAgICAgICAgPC9zcGFuPgogICAgICAgIDwvaGVhZGVyPgogICAgICAgIDxkaXYgaWQ9ImNhbGVuZGFyIiBj" +
      "bGFzcz0iY2FsZW5kYXIiPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CgogICAgICA8c2VjdGlvbiBjbGFzcz0ic2lkZS1ibG9jayBo" +
      "aWRkZW4iIGlkPSJ0YWdzLWJsb2NrIj4KICAgICAgICA8aGVhZGVyIGNsYXNzPSJzaWRlLWhlYWQiPjxzcGFuPuagh+etvjwvc3Bh" +
      "bj48L2hlYWRlcj4KICAgICAgICA8ZGl2IGlkPSJ0YWdzLWxpc3QiIGNsYXNzPSJ0YWdzLWxpc3QiPjwvZGl2PgogICAgICA8L3Nl" +
      "Y3Rpb24+CgogICAgICA8c2VjdGlvbiBjbGFzcz0ic2lkZS1ibG9jayBoaWRkZW4iIGlkPSJ0aW1lbGluZS1ibG9jayI+CiAgICAg" +
      "ICAgPGhlYWRlciBjbGFzcz0ic2lkZS1oZWFkIj48c3Bhbj7ml7bpl7Tnur88L3NwYW4+PC9oZWFkZXI+CiAgICAgICAgPGRpdiBp" +
      "ZD0idGltZWxpbmUtbGlzdCIgY2xhc3M9InRpbWVsaW5lIj48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgPC9hc2lkZT4KICAg" +
      "IDxkaXYgaWQ9InNpZGUtbWFzayIgY2xhc3M9InNpZGUtbWFzayBoaWRkZW4iIGFyaWEtaGlkZGVuPSJ0cnVlIj48L2Rpdj4KCiAg" +
      "ICA8IS0tIOS4u+agjyAtLT4KICAgIDxtYWluIGNsYXNzPSJjb250ZW50Ij4KCiAgICAgIDxoZWFkZXIgY2xhc3M9InRvcGJhciI+" +
      "CiAgICAgICAgPGRpdiBjbGFzcz0idG9wYmFyLW1haW4iPgogICAgICAgICAgPGJ1dHRvbiBpZD0ic2lkZS10b2dnbGUiIGNsYXNz" +
      "PSJpY29uLWJ0biBzaWRlLXRvZ2dsZSIgYXJpYS1sYWJlbD0i5omT5byA5L6n5qCPIj7imLA8L2J1dHRvbj4KICAgICAgICAgIDxk" +
      "aXY+CiAgICAgICAgICAgIDxoMSBjbGFzcz0idG9wYmFyLXRpdGxlIiBpZD0icGFnZS10aXRsZSI+5LuK5aSpPC9oMT4KICAgICAg" +
      "ICAgICAgPHAgY2xhc3M9InRvcGJhci1zdWIiIGlkPSJwYWdlLWRhdGUiPjwvcD4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwv" +
      "ZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InRvcGJhci1hY3Rpb25zIj4KICAgICAgICAgIDxidXR0b24gaWQ9InRoZW1lLXRvZ2ds" +
      "ZSIgY2xhc3M9Imljb24tYnRuIiBhcmlhLWxhYmVsPSLliIfmjaLkuLvpopgiIHRpdGxlPSLliIfmjaLkuLvpopgiPvCfjJM8L2J1" +
      "dHRvbj4KICAgICAgICAgIDxidXR0b24gaWQ9InVzZXItbWVudSIgY2xhc3M9InVzZXItY2hpcCIgYXJpYS1sYWJlbD0i6LSm5Y+3" +
      "Ij4KICAgICAgICAgICAgPHNwYW4gaWQ9InVzZXItaW5pdGlhbCI+VTwvc3Bhbj4KICAgICAgICAgIDwvYnV0dG9uPgogICAgICAg" +
      "IDwvZGl2PgogICAgICA8L2hlYWRlcj4KCiAgICAgIDxkaXYgaWQ9ImRlbW8tYmFubmVyIiBjbGFzcz0iZGVtby1iYW5uZXIgaGlk" +
      "ZGVuIj4KICAgICAgICA8c3Ryb25nPua8lOekuuaooeW8jzwvc3Ryb25nPgogICAgICAgIDxzcGFuPuW9k+WJjeS4uua8lOekuuao" +
      "oeW8j++8jOaVsOaNruS7heS/neWtmOWcqOacrOacuua1j+iniOWZqOOAgjwvc3Bhbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1" +
      "dHRvbiIgaWQ9ImRlbW8tYmFubmVyLWNsb3NlIiBjbGFzcz0iaWNvbi1idG4gc21hbGwiIGFyaWEtbGFiZWw9IuWFs+mXrSI+4pyV" +
      "PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPCEtLSDml6XmnJ/liIfmjaIgLS0+CiAgICAgIDxuYXYgY2xhc3M9ImRhdGVi" +
      "YXIiPgogICAgICAgIDxidXR0b24gY2xhc3M9Imljb24tYnRuIiBpZD0icHJldi1kYXkiIGFyaWEtbGFiZWw9IuWJjeS4gOWkqSI+" +
      "4oC5PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJkYXRlLXBpbGwiIGlkPSJkYXRlLXBpbGwi" +
      "IGFyaWEtaGFzcG9wdXA9ImRpYWxvZyI+CiAgICAgICAgICA8c3BhbiBpZD0iZGF0ZS1waWxsLXRleHQiPuS7iuWkqTwvc3Bhbj4K" +
      "ICAgICAgICA8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJpY29uLWJ0biIgaWQ9Im5leHQtZGF5IiBhcmlhLWxhYmVs" +
      "PSLlkI7kuIDlpKkiPuKAujwvYnV0dG9uPgogICAgICA8L25hdj4KCiAgICAgIDwhLS0g57yW6L6R5Zmo5Y2h54mH77yI5paw5aKe" +
      "5Lu75Yqh77yJIC0tPgogICAgICA8Zm9ybSBpZD0iYWRkLWZvcm0iIGNsYXNzPSJjb21wb3NlciIgYXV0b2NvbXBsZXRlPSJvZmYi" +
      "PgogICAgICAgIDxpbnB1dCBpZD0iYWRkLWlucHV0IiB0eXBlPSJ0ZXh0IiBwbGFjZWhvbGRlcj0i5re75Yqg5LiA5Lu26KaB5YGa" +
      "55qE5LqL4oCm77yI5Y+v55SoICPmoIfnrb7vvIkiCiAgICAgICAgICAgICAgIG1heGxlbmd0aD0iNTAwIiBlbnRlcmtleWhpbnQ9" +
      "ImRvbmUiIGFyaWEtbGFiZWw9IuaWsOWinuS7u+WKoSIgLz4KICAgICAgICA8ZGl2IGNsYXNzPSJjb21wb3Nlci1mb290Ij4KICAg" +
      "ICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iY29tcG9zZXItZGF0ZSIgaWQ9ImNvbXBvc2VyLWRhdGUiIGFyaWEt" +
      "aGFzcG9wdXA9ImRpYWxvZyIgdGl0bGU9IuS7u+WKoeW9kuWxnuaXpeacnyI+CiAgICAgICAgICAgIDxzcGFuIGlkPSJjb21wb3Nl" +
      "ci1kYXRlLXRleHQiPuS7iuWkqTwvc3Bhbj4KICAgICAgICAgIDwvYnV0dG9uPgogICAgICAgICAgPHNwYW4gY2xhc3M9ImNvbXBv" +
      "c2VyLXNwYWNlciI+PC9zcGFuPgogICAgICAgICAgPHAgaWQ9ImFkZC1oaW50IiBjbGFzcz0iYWRkLWhpbnQiIHJvbGU9ImFsZXJ0" +
      "IiBoaWRkZW4+PC9wPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJzdWJtaXQiIGlkPSJhZGQtYnRuIiBjbGFzcz0iYnRuIHByaW1h" +
      "cnkgc21hbGwiPua3u+WKoDwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICA8L2Zvcm0+CgogICAgICA8IS0tIOWNoeeJh+a1" +
      "gSAtLT4KICAgICAgPGRpdiBjbGFzcz0iZmVlZC13cmFwIj4KICAgICAgICA8ZGl2IGlkPSJzZWFyY2gtYmFubmVyIiBjbGFzcz0i" +
      "c2VhcmNoLWJhbm5lciBoaWRkZW4iPgogICAgICAgICAgPHNwYW4gaWQ9InNlYXJjaC1iYW5uZXItdGV4dCI+PC9zcGFuPgogICAg" +
      "ICAgICAgPGJ1dHRvbiBpZD0ic2VhcmNoLWV4aXQiIGNsYXNzPSJidG4gc3VidGxlIHNtYWxsIj7pgIDlh7rmkJzntKI8L2J1dHRv" +
      "bj4KICAgICAgICA8L2Rpdj4KCiAgICAgICAgPGRpdiBpZD0iZmVlZCIgY2xhc3M9ImZlZWQiPjwvZGl2PgoKICAgICAgICA8ZGl2" +
      "IGlkPSJlbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIGhpZGRlbiI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJlbXB0eS1h" +
      "cnQiIGFyaWEtaGlkZGVuPSJ0cnVlIj7wn4ykPC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0iZW1wdHktdGl0bGUiIGlkPSJlbXB0" +
      "eS10aXRsZSI+5LuK5aSp6L+Y5rKh5pyJ5a6J5o6SPC9wPgogICAgICAgICAgPHAgY2xhc3M9ImVtcHR5LXN1YiIgaWQ9ImVtcHR5" +
      "LXN1YiI+5Zyo5LiK6Z2i6L6T5YWl5qGG5pWy5LiL56ys5LiA5Lu25LqL5ZCnPC9wPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rp" +
      "dj4KCiAgICAgIDwhLS0g5bqV6YOo57uf6K6hIC0tPgogICAgICA8Zm9vdGVyIGNsYXNzPSJmb290ZXIiPgogICAgICAgIDxkaXYg" +
      "Y2xhc3M9ImZvb3Rlci1zdGF0Ij4KICAgICAgICAgIDxzcGFuIGlkPSJyZW1haW5pbmctY291bnQiPjA8L3NwYW4+CiAgICAgICAg" +
      "ICA8c3BhbiBpZD0icmVtYWluaW5nLWxhYmVsIj7pobnlvoXlrozmiJA8L3NwYW4+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRp" +
      "diBjbGFzcz0iZm9vdGVyLWFjdGlvbnMiPgogICAgICAgICAgPGJ1dHRvbiBpZD0iY2FycnlvdmVyLWJ0biIgY2xhc3M9ImJ0biBz" +
      "dWJ0bGUgc21hbGwiIHRpdGxlPSLmiorku6XlvoDmnKrlrozmiJDnmoTku7vliqHmjKrliLDku4rlpKkiPumhuuW7tuacquWujOaI" +
      "kDwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiBpZD0iY2xlYXItZG9uZS1idG4iIGNsYXNzPSJidG4gc3VidGxlIHNtYWxsIiB0" +
      "aXRsZT0i5Yig6Zmk5omA5pyJ5bey5a6M5oiQ5Lu75YqhIj7muIXpmaTlt7LlrozmiJA8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4K" +
      "ICAgICAgPC9mb290ZXI+CiAgICA8L21haW4+CiAgPC9kaXY+Cjwvc2VjdGlvbj4KCjwhLS0gPT09PT09PT09PT09PT09PT09PT09" +
      "PT09PT09PSDorr7nva7mir3lsYkgPT09PT09PT09PT09PT09PT09PT09PT09PT09PSAtLT4KPGRpdiBpZD0iZHJhd2VyLW1hc2si" +
      "IGNsYXNzPSJkcmF3ZXItbWFzayBoaWRkZW4iPgogIDxhc2lkZSBpZD0iZHJhd2VyIiBjbGFzcz0iZHJhd2VyIiByb2xlPSJkaWFs" +
      "b2ciIGFyaWEtbW9kYWw9InRydWUiIGFyaWEtbGFiZWw9Iuiuvue9riI+CiAgICA8aGVhZGVyIGNsYXNzPSJkcmF3ZXItaGVhZCI+" +
      "CiAgICAgIDxoMj7orr7nva48L2gyPgogICAgICA8YnV0dG9uIGlkPSJkcmF3ZXItY2xvc2UiIGNsYXNzPSJpY29uLWJ0biIgYXJp" +
      "YS1sYWJlbD0i5YWz6ZetIj7inJU8L2J1dHRvbj4KICAgIDwvaGVhZGVyPgoKICAgIDxkaXYgY2xhc3M9ImRyYXdlci1ib2R5Ij4K" +
      "CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJjYXJkIGFjY291bnQtY2FyZCI+CiAgICAgICAgPGRpdiBjbGFzcz0icm93LWJldHdlZW4i" +
      "PgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPHAgY2xhc3M9ImNhcmQtbGFiZWwiPuW9k+WJjei0puWPtzwvcD4KICAgICAg" +
      "ICAgICAgPHAgY2xhc3M9ImFjY291bnQtbmFtZSIgaWQ9ImFjY291bnQtbmFtZSI+LTwvcD4KICAgICAgICAgIDwvZGl2PgogICAg" +
      "ICAgICAgPGJ1dHRvbiBpZD0ibG9nb3V0LWJ0biIgY2xhc3M9ImJ0biBzdWJ0bGUgc21hbGwiPumAgOWHuueZu+W9lTwvYnV0dG9u" +
      "PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImRpdmlkZXIiPjwvZGl2PgogICAgICAgIDxkZXRhaWxzIGNsYXNz" +
      "PSJjb2xsYXBzZSI+CiAgICAgICAgICA8c3VtbWFyeT7kv67mlLnlr4bnoIE8L3N1bW1hcnk+CiAgICAgICAgICA8ZGl2IGNsYXNz" +
      "PSJjb2xsYXBzZS1ib2R5Ij4KICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCI+PHNwYW4+5b2T5YmN5a+G56CBPC9zcGFu" +
      "PgogICAgICAgICAgICAgIDxpbnB1dCBpZD0icHdkLWN1cnJlbnQiIHR5cGU9InBhc3N3b3JkIiBhdXRvY29tcGxldGU9ImN1cnJl" +
      "bnQtcGFzc3dvcmQiIC8+PC9sYWJlbD4KICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCI+PHNwYW4+5paw5a+G56CBPC9z" +
      "cGFuPgogICAgICAgICAgICAgIDxpbnB1dCBpZD0icHdkLW5ldyIgdHlwZT0icGFzc3dvcmQiIGF1dG9jb21wbGV0ZT0ibmV3LXBh" +
      "c3N3b3JkIiBwbGFjZWhvbGRlcj0i6Iez5bCRIDYg5L2NIiAvPjwvbGFiZWw+CiAgICAgICAgICAgIDxidXR0b24gaWQ9InB3ZC1z" +
      "dWJtaXQiIGNsYXNzPSJidG4gc3VidGxlIGJsb2NrIHNtYWxsIj7mm7TmlrDlr4bnoIE8L2J1dHRvbj4KICAgICAgICAgIDwvZGl2" +
      "PgogICAgICAgIDwvZGV0YWlscz4KICAgICAgPC9zZWN0aW9uPgoKICAgICAgPHNlY3Rpb24gY2xhc3M9ImNhcmQiPgogICAgICAg" +
      "IDxwIGNsYXNzPSJjYXJkLWxhYmVsIj7kupHlpIfku708L3A+CiAgICAgICAgPHAgY2xhc3M9ImNhcmQtZGVzYyI+CiAgICAgICAg" +
      "ICDmiormuIXljZXoh6rliqjmiJbmiYvliqjlkIzmraXliLDkupHnq6/lrZjlgqjjgILmlK/mjIEgQ2xvdWRmbGFyZSBSMuOAgeS7" +
      "u+aEjyBTMyDlhbzlrrnlr7nosaHlrZjlgqjvvIwKICAgICAgICAgIOS7peWPiiBOZXh0Y2xvdWQgLyDlnZrmnpzkupEgLyDnvqTm" +
      "mZbnrYkgV2ViREFWIOacjeWKoeOAggogICAgICAgIDwvcD4KCiAgICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCI+CiAgICAgICAg" +
      "ICA8c3Bhbj7lpIfku73mlrnlvI88L3NwYW4+CiAgICAgICAgICA8c2VsZWN0IGlkPSJiYWNrdXAtcHJvdmlkZXIiPgogICAgICAg" +
      "ICAgICA8b3B0aW9uIHZhbHVlPSJub25lIj7kuI3lkK/nlKg8L29wdGlvbj4KICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0icjIi" +
      "PkNsb3VkZmxhcmUgUjLvvIjljp/nlJ/nu5HlrprvvIk8L29wdGlvbj4KICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iczMiPlMz" +
      "IOWFvOWuueWvueixoeWtmOWCqDwvb3B0aW9uPgogICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJ3ZWJkYXYiPldlYkRBVjwvb3B0" +
      "aW9uPgogICAgICAgICAgPC9zZWxlY3Q+CiAgICAgICAgPC9sYWJlbD4KCiAgICAgICAgPGRpdiBjbGFzcz0ic3dpdGNoLXJvdyI+" +
      "CiAgICAgICAgICA8bGFiZWwgY2xhc3M9InN3aXRjaCI+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJjaGVja2JveCIgaWQ9ImJh" +
      "Y2t1cC1lbmFibGVkIiAvPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ic2xpZGVyIj48L3NwYW4+CiAgICAgICAgICAgIDxzcGFu" +
      "IGNsYXNzPSJzd2l0Y2gtdGV4dCI+5ZCv55So5LqR5aSH5Lu9PC9zcGFuPgogICAgICAgICAgPC9sYWJlbD4KICAgICAgICAgIDxs" +
      "YWJlbCBjbGFzcz0ic3dpdGNoIj4KICAgICAgICAgICAgPGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0iYmFja3VwLWF1dG8iIC8+" +
      "CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJzbGlkZXIiPjwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InN3aXRjaC10" +
      "ZXh0Ij7lj5jmm7TlkI7oh6rliqjlpIfku708L3NwYW4+CiAgICAgICAgICA8L2xhYmVsPgogICAgICAgIDwvZGl2PgoKICAgICAg" +
      "ICA8bGFiZWwgY2xhc3M9ImZpZWxkIGhpZGRlbiIgaWQ9ImJhY2t1cC1pbnRlcnZhbC1maWVsZCI+CiAgICAgICAgICA8c3Bhbj7m" +
      "nIDnn63lpIfku73pl7TpmpQ8L3NwYW4+CiAgICAgICAgICA8c2VsZWN0IGlkPSJiYWNrdXAtaW50ZXJ2YWwiPgogICAgICAgICAg" +
      "ICA8b3B0aW9uIHZhbHVlPSIwIj7mr4/mrKHlj5jmm7Tpg73lpIfku73vvIjkuI3pmZDliLbvvIk8L29wdGlvbj4KICAgICAgICAg" +
      "ICAgPG9wdGlvbiB2YWx1ZT0iMSI+MSDliIbpkp88L29wdGlvbj4KICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iNSI+NSDliIbp" +
      "kp88L29wdGlvbj4KICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iMTUiPjE1IOWIhumSnzwvb3B0aW9uPgogICAgICAgICAgICA8" +
      "b3B0aW9uIHZhbHVlPSIzMCI+MzAg5YiG6ZKfPC9vcHRpb24+CiAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IjYwIj4xIOWwj+aX" +
      "tjwvb3B0aW9uPgogICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIzNjAiPjYg5bCP5pe2PC9vcHRpb24+CiAgICAgICAgICAgIDxv" +
      "cHRpb24gdmFsdWU9IjE0NDAiPjI0IOWwj+aXtjwvb3B0aW9uPgogICAgICAgICAgPC9zZWxlY3Q+CiAgICAgICAgPC9sYWJlbD4K" +
      "ICAgICAgICA8cCBjbGFzcz0iaGludCIgaWQ9ImJhY2t1cC1pbnRlcnZhbC1oaW50Ij48L3A+CgogICAgICAgIDxkaXYgY2xhc3M9" +
      "InN3aXRjaC1yb3ciPgogICAgICAgICAgPGxhYmVsIGNsYXNzPSJzd2l0Y2giPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0iY2hl" +
      "Y2tib3giIGlkPSJiYWNrdXAtc2NoZWR1bGVkIiAvPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ic2xpZGVyIj48L3NwYW4+CiAg" +
      "ICAgICAgICAgIDxzcGFuIGNsYXNzPSJzd2l0Y2gtdGV4dCI+5a6a5pe25aSH5Lu977yI5LiN5pON5L2c5Lmf5Lya5aSH5Lu977yJ" +
      "PC9zcGFuPgogICAgICAgICAgPC9sYWJlbD4KICAgICAgICA8L2Rpdj4KCiAgICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCBoaWRk" +
      "ZW4iIGlkPSJiYWNrdXAtcGVyaW9kLWZpZWxkIj4KICAgICAgICAgIDxzcGFuPuWumuaXtuWkh+S7veWRqOacnzwvc3Bhbj4KICAg" +
      "ICAgICAgIDxzZWxlY3QgaWQ9ImJhY2t1cC1wZXJpb2QiPgogICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI1Ij7mr48gNSDliIbp" +
      "kp88L29wdGlvbj4KICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iMTUiPuavjyAxNSDliIbpkp88L29wdGlvbj4KICAgICAgICAg" +
      "ICAgPG9wdGlvbiB2YWx1ZT0iMzAiPuavjyAzMCDliIbpkp88L29wdGlvbj4KICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iNjAi" +
      "Puavj+Wwj+aXtjwvb3B0aW9uPgogICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIzNjAiPuavjyA2IOWwj+aXtjwvb3B0aW9uPgog" +
      "ICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI3MjAiPuavjyAxMiDlsI/ml7Y8L29wdGlvbj4KICAgICAgICAgICAgPG9wdGlvbiB2" +
      "YWx1ZT0iMTQ0MCI+5q+P5aSpPC9vcHRpb24+CiAgICAgICAgICA8L3NlbGVjdD4KICAgICAgICA8L2xhYmVsPgogICAgICAgIDxw" +
      "IGNsYXNzPSJoaW50IiBpZD0iYmFja3VwLWNyb24taGludCI+PC9wPgoKICAgICAgICA8ZGl2IGNsYXNzPSJzd2l0Y2gtcm93Ij4K" +
      "ICAgICAgICAgIDxsYWJlbCBjbGFzcz0ic3dpdGNoIj4KICAgICAgICAgICAgPGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0iYmFj" +
      "a3VwLXN0YW1wIiAvPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ic2xpZGVyIj48L3NwYW4+CiAgICAgICAgICAgIDxzcGFuIGNs" +
      "YXNzPSJzd2l0Y2gtdGV4dCI+5paH5Lu25ZCN5bim5pe26Ze05oiz77yI5L+d55WZ5Y6G5Y+y54mI5pys77yJPC9zcGFuPgogICAg" +
      "ICAgICAgPC9sYWJlbD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8cCBjbGFzcz0iaGludCIgaWQ9ImJhY2t1cC1zdGFtcC1oaW50" +
      "Ij48L3A+CgogICAgICAgIDwhLS0gUjIgLS0+CiAgICAgICAgPGRpdiBjbGFzcz0icHJvdmlkZXItcGFuZWwiIGRhdGEtcHJvdmlk" +
      "ZXI9InIyIiBoaWRkZW4+CiAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZpZWxkIj48c3Bhbj7lr7nosaHplK7lkI08L3NwYW4+CiAg" +
      "ICAgICAgICAgIDxpbnB1dCBpZD0icjIta2V5IiB0eXBlPSJ0ZXh0IiBwbGFjZWhvbGRlcj0idG9kby10b2RheS5iYWNrdXAuanNv" +
      "biIgLz48L2xhYmVsPgogICAgICAgICAgPHAgY2xhc3M9ImhpbnQiPumcgOimgeWcqCB3cmFuZ2xlci5qc29uYyDkuK3lkK/nlKgg" +
      "PGNvZGU+cjJfYnVja2V0czwvY29kZT4g57uR5a6aIDxjb2RlPkJBQ0tVUFM8L2NvZGU+77yM5peg6ZyA5Lu75L2V5a+G6ZKl44CC" +
      "PC9wPgogICAgICAgIDwvZGl2PgoKICAgICAgICA8IS0tIFMzIC0tPgogICAgICAgIDxkaXYgY2xhc3M9InByb3ZpZGVyLXBhbmVs" +
      "IiBkYXRhLXByb3ZpZGVyPSJzMyIgaGlkZGVuPgogICAgICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCI+PHNwYW4+RW5kcG9pbnQg" +
      "5pyN5Yqh5Zyw5Z2APC9zcGFuPgogICAgICAgICAgICA8aW5wdXQgaWQ9InMzLWVuZHBvaW50IiB0eXBlPSJ1cmwiIHBsYWNlaG9s" +
      "ZGVyPSJodHRwczovLzxhY2NvdW50aWQ+LnIyLmNsb3VkZmxhcmVzdG9yYWdlLmNvbSIgLz48L2xhYmVsPgogICAgICAgICAgPGRp" +
      "diBjbGFzcz0iZ3JpZC0yIj4KICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCI+PHNwYW4+UmVnaW9uPC9zcGFuPgogICAg" +
      "ICAgICAgICAgIDxpbnB1dCBpZD0iczMtcmVnaW9uIiB0eXBlPSJ0ZXh0IiBwbGFjZWhvbGRlcj0iYXV0byAvIHVzLWVhc3QtMSIg" +
      "Lz48L2xhYmVsPgogICAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZpZWxkIj48c3Bhbj5CdWNrZXQ8L3NwYW4+CiAgICAgICAgICAg" +
      "ICAgPGlucHV0IGlkPSJzMy1idWNrZXQiIHR5cGU9InRleHQiIHBsYWNlaG9sZGVyPSJ0b2RvLWJhY2t1cHMiIC8+PC9sYWJlbD4K" +
      "ICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCI+PHNwYW4+QWNjZXNzIEtleSBJRDwvc3Bhbj4K" +
      "ICAgICAgICAgICAgPGlucHV0IGlkPSJzMy1ha2lkIiB0eXBlPSJ0ZXh0IiBwbGFjZWhvbGRlcj0iQUtJQS4uLiIgYXV0b2NvbXBs" +
      "ZXRlPSJvZmYiIC8+PC9sYWJlbD4KICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZmllbGQiPjxzcGFuPlNlY3JldCBBY2Nlc3MgS2V5" +
      "PC9zcGFuPgogICAgICAgICAgICA8aW5wdXQgaWQ9InMzLXNlY3JldCIgdHlwZT0icGFzc3dvcmQiIHBsYWNlaG9sZGVyPSLnlZnn" +
      "qbrooajnpLrkuI3kv67mlLkiIGF1dG9jb21wbGV0ZT0ibmV3LXBhc3N3b3JkIiAvPjwvbGFiZWw+CiAgICAgICAgICA8ZGl2IGNs" +
      "YXNzPSJncmlkLTIiPgogICAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZpZWxkIj48c3Bhbj7ot6/lvoTliY3nvIA8L3NwYW4+CiAg" +
      "ICAgICAgICAgICAgPGlucHV0IGlkPSJzMy1wcmVmaXgiIHR5cGU9InRleHQiIHBsYWNlaG9sZGVyPSJ0b2RvLyIgLz48L2xhYmVs" +
      "PgogICAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZpZWxkIj48c3Bhbj7mlofku7blkI08L3NwYW4+CiAgICAgICAgICAgICAgPGlu" +
      "cHV0IGlkPSJzMy1maWxlIiB0eXBlPSJ0ZXh0IiBwbGFjZWhvbGRlcj0idG9kby10b2RheS5iYWNrdXAuanNvbiIgLz48L2xhYmVs" +
      "PgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8bGFiZWwgY2xhc3M9InN3aXRjaCBjb21wYWN0Ij4KICAgICAgICAgICAgPGlu" +
      "cHV0IHR5cGU9ImNoZWNrYm94IiBpZD0iczMtcGF0aHN0eWxlIiAvPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ic2xpZGVyIj48" +
      "L3NwYW4+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJzd2l0Y2gtdGV4dCI+5L2/55SoIFBhdGgtU3R5bGUg5a+75Z2A77yITWlu" +
      "SU8g562J6Ieq5bu65pyN5Yqh5bi455So77yJPC9zcGFuPgogICAgICAgICAgPC9sYWJlbD4KICAgICAgICA8L2Rpdj4KCiAgICAg" +
      "ICAgPCEtLSBXZWJEQVYgLS0+CiAgICAgICAgPGRpdiBjbGFzcz0icHJvdmlkZXItcGFuZWwiIGRhdGEtcHJvdmlkZXI9IndlYmRh" +
      "diIgaGlkZGVuPgogICAgICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCI+PHNwYW4+V2ViREFWIOebruW9leWcsOWdgDwvc3Bhbj4K" +
      "ICAgICAgICAgICAgPGlucHV0IGlkPSJkYXYtdXJsIiB0eXBlPSJ1cmwiIHBsYWNlaG9sZGVyPSJodHRwczovL2Rhdi5qaWFuZ3Vv" +
      "eXVuLmNvbS9kYXYv5oiR55qE5Z2a5p6c5LqRL3RvZG8iIC8+PC9sYWJlbD4KICAgICAgICAgIDxkaXYgY2xhc3M9ImdyaWQtMiI+" +
      "CiAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZmllbGQiPjxzcGFuPueUqOaIt+WQjTwvc3Bhbj4KICAgICAgICAgICAgICA8aW5w" +
      "dXQgaWQ9ImRhdi11c2VyIiB0eXBlPSJ0ZXh0IiBhdXRvY29tcGxldGU9Im9mZiIgLz48L2xhYmVsPgogICAgICAgICAgICA8bGFi" +
      "ZWwgY2xhc3M9ImZpZWxkIj48c3Bhbj7lr4bnoIEgLyDlupTnlKjlr4bnoIE8L3NwYW4+CiAgICAgICAgICAgICAgPGlucHV0IGlk" +
      "PSJkYXYtcGFzcyIgdHlwZT0icGFzc3dvcmQiIHBsYWNlaG9sZGVyPSLnlZnnqbrooajnpLrkuI3kv67mlLkiIGF1dG9jb21wbGV0" +
      "ZT0ibmV3LXBhc3N3b3JkIiAvPjwvbGFiZWw+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZmllbGQi" +
      "PjxzcGFuPuaWh+S7tuWQjTwvc3Bhbj4KICAgICAgICAgICAgPGlucHV0IGlkPSJkYXYtZmlsZSIgdHlwZT0idGV4dCIgcGxhY2Vo" +
      "b2xkZXI9InRvZG8tdG9kYXkuYmFja3VwLmpzb24iIC8+PC9sYWJlbD4KICAgICAgICA8L2Rpdj4KCiAgICAgICAgPGRpdiBjbGFz" +
      "cz0iYnRuLXJvdyI+CiAgICAgICAgICA8YnV0dG9uIGlkPSJiYWNrdXAtdGVzdCIgY2xhc3M9ImJ0biBzdWJ0bGUgc21hbGwiPua1" +
      "i+ivlei/nuaOpTwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiBpZD0iYmFja3VwLXNhdmUiIGNsYXNzPSJidG4gc3VidGxlIHNt" +
      "YWxsIj7kv53lrZjphY3nva48L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJidG4tcm93Ij4KICAg" +
      "ICAgICAgIDxidXR0b24gaWQ9ImJhY2t1cC1ydW4iIGNsYXNzPSJidG4gcHJpbWFyeSBzbWFsbCI+56uL5Y2z5aSH5Lu9PC9idXR0" +
      "b24+CiAgICAgICAgICA8YnV0dG9uIGlkPSJiYWNrdXAtcmVzdG9yZSIgY2xhc3M9ImJ0biBzdWJ0bGUgc21hbGwiPuS7juS6keer" +
      "r+aBouWkjTwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxwIGlkPSJiYWNrdXAtc3RhdHVzIiBjbGFzcz0ic3RhdHVz" +
      "LWxpbmUiIGhpZGRlbj48L3A+CiAgICAgICAgPHAgY2xhc3M9ImhpbnQiIGlkPSJsYXN0LWJhY2t1cC1saW5lIj48L3A+CiAgICAg" +
      "ICAgPHAgY2xhc3M9ImhpbnQiPuWvhumSpeS5n+WPr+S7peaUvuWcqCBXb3JrZXIg546v5aKD5Y+Y6YeP6YeM77yaPGNvZGU+QkFD" +
      "S1VQX1MzX1NFQ1JFVF9LRVk8L2NvZGU+44CBPGNvZGU+QkFDS1VQX1dFQkRBVl9QQVNTV09SRDwvY29kZT7jgII8L3A+CiAgICAg" +
      "IDwvc2VjdGlvbj4KCiAgICAgIDxzZWN0aW9uIGNsYXNzPSJjYXJkIj4KICAgICAgICA8cCBjbGFzcz0iY2FyZC1sYWJlbCI+5pys" +
      "5Zyw5pWw5o2uPC9wPgogICAgICAgIDxwIGNsYXNzPSJjYXJkLWRlc2MiPuWvvOWHuuS4uiBKU09OIOaWh+S7tuWtmOaho++8jOaI" +
      "luS7juaWh+S7tuaBouWkjeOAgjwvcD4KICAgICAgICA8ZGl2IGNsYXNzPSJidG4tcm93Ij4KICAgICAgICAgIDxidXR0b24gaWQ9" +
      "ImV4cG9ydC1idG4iIGNsYXNzPSJidG4gc3VidGxlIHNtYWxsIj7lr7zlh7ogSlNPTjwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRv" +
      "biBpZD0iaW1wb3J0LWJ0biIgY2xhc3M9ImJ0biBzdWJ0bGUgc21hbGwiPuWvvOWFpSBKU09OPC9idXR0b24+CiAgICAgICAgPC9k" +
      "aXY+CiAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJpbXBvcnQtZmlsZSIgYWNjZXB0PSJhcHBsaWNhdGlvbi9qc29uLC5q" +
      "c29uIiBoaWRkZW4gLz4KICAgICAgPC9zZWN0aW9uPgoKICAgICAgPHNlY3Rpb24gY2xhc3M9ImNhcmQgYWJvdXQtY2FyZCI+CiAg" +
      "ICAgICAgPHAgY2xhc3M9ImNhcmQtbGFiZWwiPuWFs+S6jjwvcD4KICAgICAgICA8cCBjbGFzcz0iY2FyZC1kZXNjIj4KICAgICAg" +
      "ICAgIENsb3VkZmxhcmUgV29ya2VycyDml6DmnI3liqHlmajpg6jnvbIgwrcg5pWw5o2u5a2Y5LqOIEQxIMK3IOWPo+S7pOS7pSBQ" +
      "QktERjItU0hBMjU2IOa0vueUn+WtmOWCqOOAggogICAgICAgIDwvcD4KICAgICAgICA8cCBjbGFzcz0iaGludCIgaWQ9ImFib3V0" +
      "LXZlcnNpb24iPjwvcD4KICAgICAgPC9zZWN0aW9uPgogICAgPC9kaXY+CiAgPC9hc2lkZT4KPC9kaXY+Cgo8IS0tID09PT09PT09" +
      "PT09PT09PT09PT09PT09PT09PT0g5pel5pyf6YCJ5oup5by55bGCID09PT09PT09PT09PT09PT09PT09PT09PT09PT0gLS0+Cjxk" +
      "aXYgaWQ9ImRhdGUtcG9wIiBjbGFzcz0iZGF0ZS1wb3AgaGlkZGVuIiByb2xlPSJkaWFsb2ciIGFyaWEtbW9kYWw9ImZhbHNlIiBh" +
      "cmlhLWxhYmVsPSLpgInmi6nml6XmnJ8iPgogIDxkaXYgY2xhc3M9ImRhdGUtcG9wLWhlYWQiPgogICAgPGJ1dHRvbiB0eXBlPSJi" +
      "dXR0b24iIGNsYXNzPSJtaW5pLWJ0biIgaWQ9InBvcC1wcmV2LXllYXIiIGFyaWEtbGFiZWw9IuS4iuS4gOW5tCIgdGl0bGU9IuS4" +
      "iuS4gOW5tCI+wqs8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ibWluaS1idG4iIGlkPSJwb3AtcHJl" +
      "di1tb250aCIgYXJpYS1sYWJlbD0i5LiK5Liq5pyIIiB0aXRsZT0i5LiK5Liq5pyIIj7igLk8L2J1dHRvbj4KICAgIDxzcGFuIGNs" +
      "YXNzPSJkYXRlLXBvcC10aXRsZSI+CiAgICAgIDxpbnB1dCBpZD0icG9wLXllYXIiIGNsYXNzPSJkYXRlLXBvcC1pbnB1dCIgdHlw" +
      "ZT0idGV4dCIgaW5wdXRtb2RlPSJudW1lcmljIiBtYXhsZW5ndGg9IjQiIGFyaWEtbGFiZWw9IuW5tOS7vSIgLz4g5bm0CiAgICAg" +
      "IDxpbnB1dCBpZD0icG9wLW1vbnRoIiBjbGFzcz0iZGF0ZS1wb3AtaW5wdXQgZGF0ZS1wb3AtaW5wdXQtbW9udGgiIHR5cGU9InRl" +
      "eHQiIGlucHV0bW9kZT0ibnVtZXJpYyIgbWF4bGVuZ3RoPSIyIiBhcmlhLWxhYmVsPSLmnIjku70iIC8+IOaciAogICAgPC9zcGFu" +
      "PgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJtaW5pLWJ0biIgaWQ9InBvcC1uZXh0LW1vbnRoIiBhcmlhLWxhYmVs" +
      "PSLkuIvkuKrmnIgiIHRpdGxlPSLkuIvkuKrmnIgiPuKAujwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNz" +
      "PSJtaW5pLWJ0biIgaWQ9InBvcC1uZXh0LXllYXIiIGFyaWEtbGFiZWw9IuS4i+S4gOW5tCIgdGl0bGU9IuS4i+S4gOW5tCI+wrs8" +
      "L2J1dHRvbj4KICA8L2Rpdj4KICA8ZGl2IGlkPSJwb3AtZ3JpZCIgY2xhc3M9ImNhbGVuZGFyIHBvcC1ncmlkIj48L2Rpdj4KICA8" +
      "ZGl2IGNsYXNzPSJkYXRlLXBvcC1mb290Ij4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBpZD0icG9wLWNsZWFyIiBjbGFzcz0i" +
      "YnRuIHN1YnRsZSBzbWFsbCIgdGl0bGU9IuaBouWkjeS4uuWOn+aXpeacnyI+5riF56m6PC9idXR0b24+CiAgICA8c3BhbiBjbGFz" +
      "cz0iZGF0ZS1wb3AtZ2FwIj48L3NwYW4+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgaWQ9InBvcC10b2RheSIgY2xhc3M9ImJ0" +
      "biBzdWJ0bGUgc21hbGwiPuS7iuWkqTwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJwb3Atb2siIGNsYXNz" +
      "PSJidG4gcHJpbWFyeSBzbWFsbCI+56Gu5a6aPC9idXR0b24+CiAgPC9kaXY+CjwvZGl2PgoKPGRpdiBpZD0idG9hc3QtaG9zdCIg" +
      "Y2xhc3M9InRvYXN0LWhvc3QiIGFyaWEtbGl2ZT0icG9saXRlIj48L2Rpdj4KCjxzY3JpcHQgc3JjPSIuL2FwcC5qcyI+PC9zY3Jp" +
      "cHQ+CjwvYm9keT4KPC9odG1sPgo="
  },
  "/manifest.webmanifest": {
    type: "application/manifest+json; charset=utf-8",
    body:
      "ewogICJuYW1lIjogIuS7iuaXpeW+heWKniIsCiAgInNob3J0X25hbWUiOiAi5b6F5YqeIiwKICAiZGVzY3JpcHRpb24iOiAi5p6B" +
      "566A55qE5q+P5pel5b6F5Yqe5riF5Y2V77yM5LqR56uv5ZCM5q2l77yM5pSv5oyBIFIyIC8gUzMgLyBXZWJEQVYg5LqR5aSH5Lu9" +
      "44CCIiwKICAic3RhcnRfdXJsIjogIi4vaW5kZXguaHRtbCIsCiAgInNjb3BlIjogIi4vIiwKICAiZGlzcGxheSI6ICJzdGFuZGFs" +
      "b25lIiwKICAib3JpZW50YXRpb24iOiAicG9ydHJhaXQiLAogICJiYWNrZ3JvdW5kX2NvbG9yIjogIiNmNWY2ZmIiLAogICJ0aGVt" +
      "ZV9jb2xvciI6ICIjNWI1YmQ2IiwKICAibGFuZyI6ICJ6aC1DTiIsCiAgImljb25zIjogWwogICAgewogICAgICAic3JjIjogIi4v" +
      "aWNvbi5zdmciLAogICAgICAic2l6ZXMiOiAiYW55IiwKICAgICAgInR5cGUiOiAiaW1hZ2Uvc3ZnK3htbCIsCiAgICAgICJwdXJw" +
      "b3NlIjogImFueSBtYXNrYWJsZSIKICAgIH0KICBdCn0K"
  },
  "/style.css": {
    type: "text/css; charset=utf-8",
    body:
      "LyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIOS7iuaXpeW+" +
      "heWKniDCtyDmoLflvI/ooajvvIjnp7vliqjnq6/kvJjlhYjvvIzmlK/mjIHmtYXoibIv5rex6Imy77yJCiAgID09PT09PT09PT09" +
      "PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwoKOnJvb3QgewogIC0tYnJhbmQ6ICM1" +
      "YjViZDY7CiAgLS1icmFuZC1zdHJvbmc6ICM0YTRhYzQ7CiAgLS1icmFuZC1zb2Z0OiByZ2JhKDkxLCA5MSwgMjE0LCAwLjEyKTsK" +
      "ICAtLWRhbmdlcjogI2RjNGE0YTsKICAtLXN1Y2Nlc3M6ICMyZmEyNmE7CgogIC0tYmc6ICNmNWY2ZmI7CiAgLS1iZy1ncmFkOiBy" +
      "YWRpYWwtZ3JhZGllbnQoMTIwMHB4IDYwMHB4IGF0IDUwJSAtMTAlLCAjZTZlN2ZmIDAlLCAjZjVmNmZiIDU1JSk7CiAgLS1zdXJm" +
      "YWNlOiAjZmZmZmZmOwogIC0tc3VyZmFjZS0yOiAjZjdmOGZjOwogIC0tYm9yZGVyOiAjZTVlN2YwOwogIC0tdGV4dDogIzFjMWQy" +
      "OTsKICAtLXRleHQtbXV0ZWQ6ICM2YjZmODU7CiAgLS10ZXh0LWZhaW50OiAjOWFhMGI1OwogIC0tc2hhZG93LXNtOiAwIDFweCAy" +
      "cHggcmdiYSgyNCwgMjYsIDQ4LCAwLjA2KTsKICAtLXNoYWRvdy1tZDogMCA2cHggMjBweCByZ2JhKDI0LCAyNiwgNDgsIDAuMDkp" +
      "OwogIC0tc2hhZG93LWxnOiAwIDIwcHggNTBweCByZ2JhKDI0LCAyNiwgNDgsIDAuMTYpOwogIC0tcmFkaXVzOiAxNnB4OwogIC0t" +
      "cmFkaXVzLXNtOiAxMHB4OwogIC0tcmFkaXVzLXBpbGw6IDk5OXB4OwogIC0tc2FmZS1ib3R0b206IGVudihzYWZlLWFyZWEtaW5z" +
      "ZXQtYm90dG9tLCAwcHgpOwp9CgpAbWVkaWEgKHByZWZlcnMtY29sb3Itc2NoZW1lOiBkYXJrKSB7CiAgOnJvb3Q6bm90KFtkYXRh" +
      "LXRoZW1lPSdsaWdodCddKSB7CiAgICAtLWJyYW5kOiAjOGI4YmY1OwogICAgLS1icmFuZC1zdHJvbmc6ICNhMGEwZmY7CiAgICAt" +
      "LWJyYW5kLXNvZnQ6IHJnYmEoMTM5LCAxMzksIDI0NSwgMC4xNik7CiAgICAtLWRhbmdlcjogI2ZmODA4MDsKICAgIC0tc3VjY2Vz" +
      "czogIzRmZDM5YTsKICAgIC0tYmc6ICMwZjEwMTg7CiAgICAtLWJnLWdyYWQ6IHJhZGlhbC1ncmFkaWVudCgxMjAwcHggNjAwcHgg" +
      "YXQgNTAlIC0xMCUsICMxYzFkMzMgMCUsICMwZjEwMTggNTUlKTsKICAgIC0tc3VyZmFjZTogIzE5MWEyNjsKICAgIC0tc3VyZmFj" +
      "ZS0yOiAjMjAyMjJmOwogICAgLS1ib3JkZXI6ICMyYjJkM2Q7CiAgICAtLXRleHQ6ICNlZWYwZjg7CiAgICAtLXRleHQtbXV0ZWQ6" +
      "ICNhMmE3YmQ7CiAgICAtLXRleHQtZmFpbnQ6ICM3NjdiOTI7CiAgICAtLXNoYWRvdy1zbTogMCAxcHggMnB4IHJnYmEoMCwgMCwg" +
      "MCwgMC40KTsKICAgIC0tc2hhZG93LW1kOiAwIDZweCAyMnB4IHJnYmEoMCwgMCwgMCwgMC40NSk7CiAgICAtLXNoYWRvdy1sZzog" +
      "MCAyMHB4IDUwcHggcmdiYSgwLCAwLCAwLCAwLjYpOwogIH0KfQoKOnJvb3RbZGF0YS10aGVtZT0nZGFyayddIHsKICAtLWJyYW5k" +
      "OiAjOGI4YmY1OwogIC0tYnJhbmQtc3Ryb25nOiAjYTBhMGZmOwogIC0tYnJhbmQtc29mdDogcmdiYSgxMzksIDEzOSwgMjQ1LCAw" +
      "LjE2KTsKICAtLWRhbmdlcjogI2ZmODA4MDsKICAtLXN1Y2Nlc3M6ICM0ZmQzOWE7CiAgLS1iZzogIzBmMTAxODsKICAtLWJnLWdy" +
      "YWQ6IHJhZGlhbC1ncmFkaWVudCgxMjAwcHggNjAwcHggYXQgNTAlIC0xMCUsICMxYzFkMzMgMCUsICMwZjEwMTggNTUlKTsKICAt" +
      "LXN1cmZhY2U6ICMxOTFhMjY7CiAgLS1zdXJmYWNlLTI6ICMyMDIyMmY7CiAgLS1ib3JkZXI6ICMyYjJkM2Q7CiAgLS10ZXh0OiAj" +
      "ZWVmMGY4OwogIC0tdGV4dC1tdXRlZDogI2EyYTdiZDsKICAtLXRleHQtZmFpbnQ6ICM3NjdiOTI7CiAgLS1zaGFkb3ctc206IDAg" +
      "MXB4IDJweCByZ2JhKDAsIDAsIDAsIDAuNCk7CiAgLS1zaGFkb3ctbWQ6IDAgNnB4IDIycHggcmdiYSgwLCAwLCAwLCAwLjQ1KTsK" +
      "ICAtLXNoYWRvdy1sZzogMCAyMHB4IDUwcHggcmdiYSgwLCAwLCAwLCAwLjYpOwp9CgoqIHsgYm94LXNpemluZzogYm9yZGVyLWJv" +
      "eDsgfQoKaHRtbCwgYm9keSB7CiAgbWFyZ2luOiAwOwogIHBhZGRpbmc6IDA7CiAgbWluLWhlaWdodDogMTAwJTsKfQoKYm9keSB7" +
      "CiAgZm9udC1mYW1pbHk6IC1hcHBsZS1zeXN0ZW0sIEJsaW5rTWFjU3lzdGVtRm9udCwgJ1NlZ29lIFVJJywgJ1BpbmdGYW5nIFND" +
      "JywKICAgICdIaXJhZ2lubyBTYW5zIEdCJywgJ01pY3Jvc29mdCBZYUhlaScsICdIZWx2ZXRpY2EgTmV1ZScsIEFyaWFsLCBzYW5z" +
      "LXNlcmlmOwogIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICBiYWNrZ3JvdW5kLWltYWdlOiB2YXIoLS1iZy1ncmFkKTsKICBiYWNr" +
      "Z3JvdW5kLWF0dGFjaG1lbnQ6IGZpeGVkOwogIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAtd2Via2l0LWZvbnQtc21vb3RoaW5nOiBh" +
      "bnRpYWxpYXNlZDsKICAtd2Via2l0LXRhcC1oaWdobGlnaHQtY29sb3I6IHRyYW5zcGFyZW50OwogIGZvbnQtc2l6ZTogMTVweDsK" +
      "ICBsaW5lLWhlaWdodDogMS41NTsKfQoKLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmUgIWltcG9ydGFudDsgfQoKYnV0dG9uLCBpbnB1" +
      "dCwgc2VsZWN0LCB0ZXh0YXJlYSB7IGZvbnQ6IGluaGVyaXQ7IGNvbG9yOiBpbmhlcml0OyB9CgovKiAtLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tIOWQr+WKqOaAgSAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KLmJvb3Qgewog" +
      "IHBvc2l0aW9uOiBmaXhlZDsKICBpbnNldDogMDsKICBkaXNwbGF5OiBncmlkOwogIHBsYWNlLWl0ZW1zOiBjZW50ZXI7CiAgYmFj" +
      "a2dyb3VuZDogdmFyKC0tYmcpOwogIGJhY2tncm91bmQtaW1hZ2U6IHZhcigtLWJnLWdyYWQpOwogIHotaW5kZXg6IDYwOwp9Ci5z" +
      "cGlubmVyIHsKICB3aWR0aDogMzBweDsgaGVpZ2h0OiAzMHB4OwogIGJvcmRlcjogM3B4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAg" +
      "Ym9yZGVyLXRvcC1jb2xvcjogdmFyKC0tYnJhbmQpOwogIGJvcmRlci1yYWRpdXM6IDUwJTsKICBhbmltYXRpb246IHNwaW4gMC44" +
      "cyBsaW5lYXIgaW5maW5pdGU7Cn0KQGtleWZyYW1lcyBzcGluIHsgdG8geyB0cmFuc2Zvcm06IHJvdGF0ZSgzNjBkZWcpOyB9IH0K" +
      "Ci8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0g6YCa55SoIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0gKi8KLnZpZXcgeyBhbmltYXRpb246IGZhZGUtdXAgMC4zNXMgY3ViaWMtYmV6aWVyKDAuMiwgMC44LCAwLjIsIDEpOyB9" +
      "CkBrZXlmcmFtZXMgZmFkZS11cCB7CiAgZnJvbSB7IG9wYWNpdHk6IDA7IHRyYW5zZm9ybTogdHJhbnNsYXRlWSg4cHgpOyB9CiAg" +
      "dG8geyBvcGFjaXR5OiAxOyB0cmFuc2Zvcm06IG5vbmU7IH0KfQoKLmJ0biB7CiAgZGlzcGxheTogaW5saW5lLWZsZXg7CiAgYWxp" +
      "Z24taXRlbXM6IGNlbnRlcjsKICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICBnYXA6IDZweDsKICBib3JkZXI6IDFweCBzb2xp" +
      "ZCB0cmFuc3BhcmVudDsKICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMtc20pOwogIHBhZGRpbmc6IDExcHggMTZweDsKICBm" +
      "b250LXdlaWdodDogNjAwOwogIGN1cnNvcjogcG9pbnRlcjsKICB0cmFuc2l0aW9uOiB0cmFuc2Zvcm0gMC4xMnMgZWFzZSwgYmFj" +
      "a2dyb3VuZCAwLjE4cyBlYXNlLCBvcGFjaXR5IDAuMThzIGVhc2UsIGJveC1zaGFkb3cgMC4xOHMgZWFzZTsKICB1c2VyLXNlbGVj" +
      "dDogbm9uZTsKICB3aGl0ZS1zcGFjZTogbm93cmFwOwp9Ci5idG46YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk3KTsgfQou" +
      "YnRuOmRpc2FibGVkIHsgb3BhY2l0eTogMC41OyBjdXJzb3I6IG5vdC1hbGxvd2VkOyB0cmFuc2Zvcm06IG5vbmU7IH0KCi5idG4u" +
      "cHJpbWFyeSB7CiAgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDE2MGRlZywgdmFyKC0tYnJhbmQpLCB2YXIoLS1icmFuZC1z" +
      "dHJvbmcpKTsKICBjb2xvcjogI2ZmZjsKICBib3gtc2hhZG93OiAwIDRweCAxNHB4IHZhcigtLWJyYW5kLXNvZnQpOwp9Ci5idG4u" +
      "cHJpbWFyeTpob3Zlcjpub3QoOmRpc2FibGVkKSB7IGJveC1zaGFkb3c6IDAgNnB4IDIwcHggdmFyKC0tYnJhbmQtc29mdCk7IH0K" +
      "Ci5idG4uc3VidGxlIHsKICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogIGJvcmRlci1jb2xvcjogdmFyKC0tYm9yZGVy" +
      "KTsKICBjb2xvcjogdmFyKC0tdGV4dC1tdXRlZCk7Cn0KLmJ0bi5zdWJ0bGU6aG92ZXI6bm90KDpkaXNhYmxlZCkgeyBjb2xvcjog" +
      "dmFyKC0tdGV4dCk7IGJvcmRlci1jb2xvcjogdmFyKC0tYnJhbmQpOyB9CgouYnRuLmJsb2NrIHsgd2lkdGg6IDEwMCU7IH0KLmJ0" +
      "bi5zbWFsbCB7IHBhZGRpbmc6IDhweCAxMnB4OyBmb250LXNpemU6IDEzLjVweDsgfQoKLmljb24tYnRuIHsKICB3aWR0aDogMzhw" +
      "eDsgaGVpZ2h0OiAzOHB4OwogIGRpc3BsYXk6IGdyaWQ7IHBsYWNlLWl0ZW1zOiBjZW50ZXI7CiAgYm9yZGVyOiBub25lOwogIGJv" +
      "cmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cy1waWxsKTsKICBiYWNrZ3JvdW5kOiB0cmFuc3BhcmVudDsKICBjb2xvcjogdmFyKC0t" +
      "dGV4dC1tdXRlZCk7CiAgY3Vyc29yOiBwb2ludGVyOwogIGZvbnQtc2l6ZTogMTdweDsKICB0cmFuc2l0aW9uOiBiYWNrZ3JvdW5k" +
      "IDAuMTZzIGVhc2UsIGNvbG9yIDAuMTZzIGVhc2U7Cn0KLmljb24tYnRuOmhvdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFj" +
      "ZS0yKTsgY29sb3I6IHZhcigtLXRleHQpOyB9Ci5pY29uLWJ0bi5zbWFsbCB7IHdpZHRoOiAyOHB4OyBoZWlnaHQ6IDI4cHg7IGZv" +
      "bnQtc2l6ZTogMTNweDsgfQoKLmZpZWxkIHsgZGlzcGxheTogYmxvY2s7IG1hcmdpbi1ib3R0b206IDE0cHg7IH0KLmZpZWxkID4g" +
      "c3BhbiB7CiAgZGlzcGxheTogYmxvY2s7CiAgZm9udC1zaXplOiAxMi41cHg7CiAgZm9udC13ZWlnaHQ6IDYwMDsKICBjb2xvcjog" +
      "dmFyKC0tdGV4dC1tdXRlZCk7CiAgbWFyZ2luLWJvdHRvbTogNnB4OwogIGxldHRlci1zcGFjaW5nOiAwLjAyZW07Cn0KLmZpZWxk" +
      "IGlucHV0LCAuZmllbGQgc2VsZWN0IHsKICB3aWR0aDogMTAwJTsKICBwYWRkaW5nOiAxMXB4IDEzcHg7CiAgYm9yZGVyOiAxcHgg" +
      "c29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMtc20pOwogIGJhY2tncm91bmQ6IHZhcigt" +
      "LXN1cmZhY2UpOwogIG91dGxpbmU6IG5vbmU7CiAgdHJhbnNpdGlvbjogYm9yZGVyLWNvbG9yIDAuMTZzIGVhc2UsIGJveC1zaGFk" +
      "b3cgMC4xNnMgZWFzZTsKICBtaW4taGVpZ2h0OiA0NHB4Owp9Ci5maWVsZCBpbnB1dDpmb2N1cywgLmZpZWxkIHNlbGVjdDpmb2N1" +
      "cyB7CiAgYm9yZGVyLWNvbG9yOiB2YXIoLS1icmFuZCk7CiAgYm94LXNoYWRvdzogMCAwIDAgM3B4IHZhcigtLWJyYW5kLXNvZnQp" +
      "Owp9CgouaW5wdXQtd2l0aC1hY3Rpb24geyBwb3NpdGlvbjogcmVsYXRpdmU7IH0KLmlucHV0LXdpdGgtYWN0aW9uIGlucHV0IHsg" +
      "cGFkZGluZy1yaWdodDogNDRweDsgfQouaW5wdXQtd2l0aC1hY3Rpb24gLmdob3N0LWljb24gewogIHBvc2l0aW9uOiBhYnNvbHV0" +
      "ZTsgcmlnaHQ6IDZweDsgdG9wOiA1MCU7CiAgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKC01MCUpOwogIGJvcmRlcjogbm9uZTsgYmFj" +
      "a2dyb3VuZDogdHJhbnNwYXJlbnQ7IGN1cnNvcjogcG9pbnRlcjsKICB3aWR0aDogMzRweDsgaGVpZ2h0OiAzNHB4OyBib3JkZXIt" +
      "cmFkaXVzOiA1MCU7CiAgZGlzcGxheTogZ3JpZDsgcGxhY2UtaXRlbXM6IGNlbnRlcjsKICBvcGFjaXR5OiAwLjY7Cn0KLmlucHV0" +
      "LXdpdGgtYWN0aW9uIC5naG9zdC1pY29uOmhvdmVyIHsgb3BhY2l0eTogMTsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsg" +
      "fQoKLmdyaWQtMiB7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMWZyIDFmcjsgZ2FwOiAwIDEycHg7IH0K" +
      "QG1lZGlhIChtYXgtd2lkdGg6IDQwMHB4KSB7IC5ncmlkLTIgeyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmcjsgfSB9CgouZGl2" +
      "aWRlciB7IGhlaWdodDogMXB4OyBiYWNrZ3JvdW5kOiB2YXIoLS1ib3JkZXIpOyBtYXJnaW46IDE0cHggMDsgfQoKLmhpbnQgeyBm" +
      "b250LXNpemU6IDEycHg7IGNvbG9yOiB2YXIoLS10ZXh0LWZhaW50KTsgbWFyZ2luOiA4cHggMCAwOyBsaW5lLWhlaWdodDogMS42" +
      "OyB9Ci5oaW50IGNvZGUgewogIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0t" +
      "Ym9yZGVyKTsKICBib3JkZXItcmFkaXVzOiA1cHg7CiAgcGFkZGluZzogMXB4IDVweDsKICBmb250LXNpemU6IDExLjVweDsKICBm" +
      "b250LWZhbWlseTogdWktbW9ub3NwYWNlLCBTRk1vbm8tUmVndWxhciwgTWVubG8sIENvbnNvbGFzLCBtb25vc3BhY2U7Cn0KCi8q" +
      "IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0g55m75b2V6aG1IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLSAqLwouYXV0aC12aWV3IHsKICBtaW4taGVpZ2h0OiAxMDBkdmg7CiAgZGlzcGxheTogZ3JpZDsKICBwbGFjZS1pdGVtczog" +
      "Y2VudGVyOwogIHBhZGRpbmc6IDI0cHggMThweCBjYWxjKDI0cHggKyB2YXIoLS1zYWZlLWJvdHRvbSkpOwp9Ci5hdXRoLWNhcmQg" +
      "ewogIHdpZHRoOiAxMDAlOwogIG1heC13aWR0aDogNDAwcHg7CiAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgYm9yZGVy" +
      "OiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOiAyMnB4OwogIHBhZGRpbmc6IDMwcHggMjRweCAyNHB4" +
      "OwogIGJveC1zaGFkb3c6IHZhcigtLXNoYWRvdy1sZyk7Cn0KLmJyYW5kIHsgdGV4dC1hbGlnbjogY2VudGVyOyBtYXJnaW4tYm90" +
      "dG9tOiAyMnB4OyB9Ci5icmFuZC1tYXJrIHsKICB3aWR0aDogNTRweDsgaGVpZ2h0OiA1NHB4OwogIG1hcmdpbjogMCBhdXRvIDE0" +
      "cHg7CiAgYm9yZGVyLXJhZGl1czogMTdweDsKICBkaXNwbGF5OiBncmlkOyBwbGFjZS1pdGVtczogY2VudGVyOwogIGJhY2tncm91" +
      "bmQ6IGxpbmVhci1ncmFkaWVudCgxNjBkZWcsIHZhcigtLWJyYW5kKSwgdmFyKC0tYnJhbmQtc3Ryb25nKSk7CiAgY29sb3I6ICNm" +
      "ZmY7CiAgYm94LXNoYWRvdzogMCA4cHggMjJweCB2YXIoLS1icmFuZC1zb2Z0KTsKfQouYnJhbmQtbWFyayBzdmcgeyB3aWR0aDog" +
      "MjdweDsgaGVpZ2h0OiAyN3B4OyB9Ci5icmFuZCBoMSB7IG1hcmdpbjogMDsgZm9udC1zaXplOiAyMnB4OyBmb250LXdlaWdodDog" +
      "NzAwOyBsZXR0ZXItc3BhY2luZzogLTAuMDFlbTsgfQouYnJhbmQtc3ViIHsgbWFyZ2luOiA2cHggMCAwOyBmb250LXNpemU6IDEz" +
      "cHg7IGNvbG9yOiB2YXIoLS10ZXh0LW11dGVkKTsgfQoKLnRhYnMgewogIGRpc3BsYXk6IGZsZXg7CiAgZ2FwOiA0cHg7CiAgYmFj" +
      "a2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMtcGlsbCk7CiAgcGFkZGluZzog" +
      "NHB4OwogIG1hcmdpbi1ib3R0b206IDIwcHg7Cn0KLnRhYiB7CiAgZmxleDogMTsKICBib3JkZXI6IG5vbmU7CiAgYmFja2dyb3Vu" +
      "ZDogdHJhbnNwYXJlbnQ7CiAgcGFkZGluZzogOXB4IDA7CiAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXBpbGwpOwogIGZv" +
      "bnQtd2VpZ2h0OiA2MDA7CiAgZm9udC1zaXplOiAxNHB4OwogIGNvbG9yOiB2YXIoLS10ZXh0LW11dGVkKTsKICBjdXJzb3I6IHBv" +
      "aW50ZXI7CiAgdHJhbnNpdGlvbjogYWxsIDAuMThzIGVhc2U7Cn0KLnRhYi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJm" +
      "YWNlKTsgY29sb3I6IHZhcigtLXRleHQpOyBib3gtc2hhZG93OiB2YXIoLS1zaGFkb3ctc20pOyB9CgouZm9ybS1lcnJvciB7CiAg" +
      "YmFja2dyb3VuZDogcmdiYSgyMjAsIDc0LCA3NCwgMC4xKTsKICBjb2xvcjogdmFyKC0tZGFuZ2VyKTsKICBib3JkZXItcmFkaXVz" +
      "OiB2YXIoLS1yYWRpdXMtc20pOwogIHBhZGRpbmc6IDlweCAxMnB4OwogIGZvbnQtc2l6ZTogMTNweDsKICBsaW5lLWhlaWdodDog" +
      "MS42NTsKICBtYXJnaW46IDAgMCAxNHB4OwogIHdvcmQtYnJlYWs6IGJyZWFrLXdvcmQ7Cn0KLmF1dGgtZm9vdCB7CiAgbWFyZ2lu" +
      "OiAxOHB4IDAgMDsKICBmb250LXNpemU6IDExLjVweDsKICBjb2xvcjogdmFyKC0tdGV4dC1mYWludCk7CiAgdGV4dC1hbGlnbjog" +
      "Y2VudGVyOwogIGxpbmUtaGVpZ2h0OiAxLjc7Cn0KCi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0g5Li755WM" +
      "6Z2iIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwovKiDluIPlsYDpqqjmnrbvvJrnp7vliqjnq6/ljZXliJcg" +
      "KyDkvqfmoI/mir3lsYnvvJviiaU5ODBweCDlj4zmoI/vvIjkvqfmoI/luLjpqbvvvIkgKi8KLnNoZWxsIHsgbWluLWhlaWdodDog" +
      "MTAwZHZoOyB9CgouY29udGVudCB7CiAgbWF4LXdpZHRoOiA3MDBweDsKICBtYXJnaW46IDAgYXV0bzsKICBwYWRkaW5nOiAwIDE2" +
      "cHggY2FsYygxOHB4ICsgdmFyKC0tc2FmZS1ib3R0b20pKTsKICBtaW4taGVpZ2h0OiAxMDBkdmg7CiAgZGlzcGxheTogZmxleDsK" +
      "ICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwp9CgoudG9wYmFyIHsKICBkaXNwbGF5OiBmbGV4OwogIGFsaWduLWl0ZW1zOiBjZW50" +
      "ZXI7CiAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogIGdhcDogMTJweDsKICBwYWRkaW5nOiAxOHB4IDJweCAxMHB4" +
      "Owp9Ci50b3BiYXItbWFpbiB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogNHB4OyBtaW4td2lkdGg6" +
      "IDA7IH0KLnRvcGJhci10aXRsZSB7IG1hcmdpbjogMDsgZm9udC1zaXplOiAyNXB4OyBmb250LXdlaWdodDogNzAwOyBsZXR0ZXIt" +
      "c3BhY2luZzogLTAuMDJlbTsgfQoudG9wYmFyLXN1YiB7IG1hcmdpbjogM3B4IDAgMDsgZm9udC1zaXplOiAxM3B4OyBjb2xvcjog" +
      "dmFyKC0tdGV4dC1tdXRlZCk7IH0KLnRvcGJhci1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsg" +
      "Z2FwOiA2cHg7IH0KLnNpZGUtdG9nZ2xlIHsgZGlzcGxheTogaW5saW5lLWdyaWQ7IH0KCi51c2VyLWNoaXAgewogIHdpZHRoOiAz" +
      "OHB4OyBoZWlnaHQ6IDM4cHg7CiAgYm9yZGVyLXJhZGl1czogNTAlOwogIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7" +
      "CiAgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDE2MGRlZywgdmFyKC0tYnJhbmQpLCB2YXIoLS1icmFuZC1zdHJvbmcpKTsK" +
      "ICBjb2xvcjogI2ZmZjsKICBmb250LXdlaWdodDogNzAwOwogIGZvbnQtc2l6ZTogMTVweDsKICBjdXJzb3I6IHBvaW50ZXI7CiAg" +
      "ZGlzcGxheTogZ3JpZDsgcGxhY2UtaXRlbXM6IGNlbnRlcjsKICBib3gtc2hhZG93OiB2YXIoLS1zaGFkb3ctc20pOwp9CgouZGVt" +
      "by1iYW5uZXIgewogIGRpc3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBnYXA6IDEwcHg7CiAgYmFja2dyb3Vu" +
      "ZDogcmdiYSgyNDAsIDE3MCwgNDAsIDAuMTQpOwogIGJvcmRlcjogMXB4IHNvbGlkIHJnYmEoMjQwLCAxNzAsIDQwLCAwLjM0KTsK" +
      "ICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXNtKTsKICBwYWRkaW5nOiA5cHggMTJw" +
      "eDsKICBmb250LXNpemU6IDEyLjVweDsKICBtYXJnaW4tYm90dG9tOiAxMnB4Owp9Ci5kZW1vLWJhbm5lciBzcGFuIHsgZmxleDog" +
      "MTsgY29sb3I6IHZhcigtLXRleHQtbXV0ZWQpOyB9CgovKiDkvqfmoI/vvIjnp7vliqjnq6/kuLrmir3lsYnvvIkgKi8KLnNpZGVi" +
      "YXIgewogIHBvc2l0aW9uOiBmaXhlZDsKICB0b3A6IDA7IGxlZnQ6IDA7IGJvdHRvbTogMDsKICB6LWluZGV4OiA0NTsKICB3aWR0" +
      "aDogbWluKDMwNHB4LCA4NnZ3KTsKICBwYWRkaW5nOiAxNnB4IDE0cHggY2FsYygyMHB4ICsgdmFyKC0tc2FmZS1ib3R0b20pKTsK" +
      "ICBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7CiAgb3ZlcmZsb3cteTogYXV0bzsKICAtd2Via2l0LW92ZXJmbG93LXNjcm9sbGluZzog" +
      "dG91Y2g7CiAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC0xMDUlKTsKICB0cmFuc2l0aW9uOiB0cmFuc2Zvcm0gMC4yNnMgY3ViaWMt" +
      "YmV6aWVyKDAuMiwgMC44LCAwLjIsIDEpOwogIHZpc2liaWxpdHk6IGhpZGRlbjsKfQpib2R5LnNpZGUtb3BlbiAuc2lkZWJhciB7" +
      "CiAgdHJhbnNmb3JtOiBub25lOwogIHZpc2liaWxpdHk6IHZpc2libGU7CiAgYm94LXNoYWRvdzogdmFyKC0tc2hhZG93LWxnKTsK" +
      "fQouc2lkZS1tYXNrIHsKICBwb3NpdGlvbjogZml4ZWQ7IGluc2V0OiAwOwogIHotaW5kZXg6IDQ0OwogIGJhY2tncm91bmQ6IHJn" +
      "YmEoMTQsIDE1LCAyNSwgMC40Mik7CiAgYmFja2Ryb3AtZmlsdGVyOiBibHVyKDJweCk7CiAgLXdlYmtpdC1iYWNrZHJvcC1maWx0" +
      "ZXI6IGJsdXIoMnB4KTsKICBhbmltYXRpb246IGZhZGUtaW4gMC4yMnMgZWFzZTsKfQoKLnNpZGUtc2VhcmNoIHsgcG9zaXRpb246" +
      "IHJlbGF0aXZlOyBtYXJnaW4tYm90dG9tOiAxNHB4OyB9Ci5zaWRlLXNlYXJjaC1pY29uIHsKICBwb3NpdGlvbjogYWJzb2x1dGU7" +
      "IGxlZnQ6IDExcHg7IHRvcDogNTAlOwogIHRyYW5zZm9ybTogdHJhbnNsYXRlWSgtNTAlKTsKICB3aWR0aDogMTVweDsgaGVpZ2h0" +
      "OiAxNXB4OwogIGNvbG9yOiB2YXIoLS10ZXh0LWZhaW50KTsKICBwb2ludGVyLWV2ZW50czogbm9uZTsKfQouc2lkZS1zZWFyY2gg" +
      "aW5wdXQgewogIHdpZHRoOiAxMDAlOwogIHBhZGRpbmc6IDEwcHggMzRweCAxMHB4IDMzcHg7CiAgYm9yZGVyOiAxcHggc29saWQg" +
      "dmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMtcGlsbCk7CiAgYmFja2dyb3VuZDogdmFyKC0tc3Vy" +
      "ZmFjZSk7CiAgb3V0bGluZTogbm9uZTsKICBmb250LXNpemU6IDEzLjVweDsKICBtaW4taGVpZ2h0OiA0MHB4OwogIHRyYW5zaXRp" +
      "b246IGJvcmRlci1jb2xvciAwLjE2cyBlYXNlLCBib3gtc2hhZG93IDAuMTZzIGVhc2U7CiAgLXdlYmtpdC1hcHBlYXJhbmNlOiBu" +
      "b25lOwogIGFwcGVhcmFuY2U6IG5vbmU7Cn0KLnNpZGUtc2VhcmNoIGlucHV0Ojotd2Via2l0LXNlYXJjaC1jYW5jZWwtYnV0dG9u" +
      "IHsgZGlzcGxheTogbm9uZTsgfQouc2lkZS1zZWFyY2ggaW5wdXQ6Zm9jdXMgewogIGJvcmRlci1jb2xvcjogdmFyKC0tYnJhbmQp" +
      "OwogIGJveC1zaGFkb3c6IDAgMCAwIDNweCB2YXIoLS1icmFuZC1zb2Z0KTsKfQouc2lkZS1zZWFyY2gtY2xlYXIgewogIHBvc2l0" +
      "aW9uOiBhYnNvbHV0ZTsgcmlnaHQ6IDdweDsgdG9wOiA1MCU7CiAgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKC01MCUpOwogIHdpZHRo" +
      "OiAyNHB4OyBoZWlnaHQ6IDI0cHg7CiAgYm9yZGVyOiBub25lOyBib3JkZXItcmFkaXVzOiA1MCU7CiAgYmFja2dyb3VuZDogdmFy" +
      "KC0tc3VyZmFjZS0yKTsKICBjb2xvcjogdmFyKC0tdGV4dC1tdXRlZCk7CiAgZm9udC1zaXplOiAxMXB4OwogIGN1cnNvcjogcG9p" +
      "bnRlcjsKICBkaXNwbGF5OiBncmlkOyBwbGFjZS1pdGVtczogY2VudGVyOwp9Cgouc2lkZS1zdGF0cyB7CiAgZGlzcGxheTogZ3Jp" +
      "ZDsKICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IHJlcGVhdCgzLCAxZnIpOwogIHRleHQtYWxpZ246IGNlbnRlcjsKICBiYWNrZ3Jv" +
      "dW5kOiB2YXIoLS1zdXJmYWNlKTsKICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6IHZh" +
      "cigtLXJhZGl1cyk7CiAgcGFkZGluZzogMTNweCAwIDExcHg7CiAgbWFyZ2luLWJvdHRvbTogMThweDsKICBib3gtc2hhZG93OiB2" +
      "YXIoLS1zaGFkb3ctc20pOwp9Ci5zdGF0IGIgeyBkaXNwbGF5OiBibG9jazsgZm9udC1zaXplOiAyMXB4OyBmb250LXdlaWdodDog" +
      "NzAwOyBjb2xvcjogdmFyKC0tYnJhbmQpOyBsaW5lLWhlaWdodDogMS4yOyB9Ci5zdGF0IHNwYW4geyBmb250LXNpemU6IDExcHg7" +
      "IGNvbG9yOiB2YXIoLS10ZXh0LWZhaW50KTsgbGV0dGVyLXNwYWNpbmc6IDAuMDRlbTsgfQoKLnNpZGUtYmxvY2sgeyBtYXJnaW4t" +
      "Ym90dG9tOiAyMHB4OyB9Ci5zaWRlLWhlYWQgewogIGRpc3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBqdXN0" +
      "aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgZm9udC1zaXplOiAxMy41cHg7CiAgZm9udC13ZWlnaHQ6IDcwMDsKICBtYXJn" +
      "aW4tYm90dG9tOiA5cHg7Cn0KLnNpZGUtaGVhZC1idG5zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAycHg7IH0KLm1pbmktYnRuIHsK" +
      "ICB3aWR0aDogMjZweDsgaGVpZ2h0OiAyNnB4OwogIGJvcmRlcjogbm9uZTsKICBib3JkZXItcmFkaXVzOiA4cHg7CiAgYmFja2dy" +
      "b3VuZDogdHJhbnNwYXJlbnQ7CiAgY29sb3I6IHZhcigtLXRleHQtbXV0ZWQpOwogIGZvbnQtc2l6ZTogMTVweDsKICBjdXJzb3I6" +
      "IHBvaW50ZXI7CiAgZGlzcGxheTogZ3JpZDsgcGxhY2UtaXRlbXM6IGNlbnRlcjsKICB0cmFuc2l0aW9uOiBiYWNrZ3JvdW5kIDAu" +
      "MTVzIGVhc2UsIGNvbG9yIDAuMTVzIGVhc2U7Cn0KLm1pbmktYnRuOmhvdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0y" +
      "KTsgY29sb3I6IHZhcigtLXRleHQpOyB9CgovKiDml6XljoYgKi8KLmNhbGVuZGFyIHsKICBkaXNwbGF5OiBncmlkOwogIGdyaWQt" +
      "dGVtcGxhdGUtY29sdW1uczogcmVwZWF0KDcsIDFmcik7CiAgZ2FwOiAycHg7Cn0KLmNhbC1kb3cgewogIGZvbnQtc2l6ZTogMTAu" +
      "NXB4OwogIGNvbG9yOiB2YXIoLS10ZXh0LWZhaW50KTsKICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgcGFkZGluZzogM3B4IDAgNXB4" +
      "Owp9Ci5jYWwtZGF5IHsKICBwb3NpdGlvbjogcmVsYXRpdmU7CiAgaGVpZ2h0OiAzNnB4OwogIGJvcmRlcjogbm9uZTsKICBib3Jk" +
      "ZXItcmFkaXVzOiA5cHg7CiAgYmFja2dyb3VuZDogdHJhbnNwYXJlbnQ7CiAgY29sb3I6IHZhcigtLXRleHQtbXV0ZWQpOwogIGZv" +
      "bnQtc2l6ZTogMTIuNXB4OwogIGN1cnNvcjogcG9pbnRlcjsKICBwYWRkaW5nOiAwOwogIHRyYW5zaXRpb246IGJhY2tncm91bmQg" +
      "MC4xNHMgZWFzZSwgY29sb3IgMC4xNHMgZWFzZTsKfQouY2FsLWRheTpob3ZlciB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2Ut" +
      "Mik7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQouY2FsLWRheS5oYXMtdGFza3MgeyBjb2xvcjogdmFyKC0tdGV4dCk7IGZvbnQtd2Vp" +
      "Z2h0OiA2MDA7IH0KLmNhbC1kYXkgLmRvdCB7CiAgcG9zaXRpb246IGFic29sdXRlOwogIGJvdHRvbTogNHB4OyBsZWZ0OiA1MCU7" +
      "CiAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogIHdpZHRoOiA0cHg7IGhlaWdodDogNHB4OwogIGJvcmRlci1yYWRpdXM6" +
      "IDUwJTsKICBiYWNrZ3JvdW5kOiB2YXIoLS1icmFuZCk7CiAgb3BhY2l0eTogMC44Owp9Ci5jYWwtZGF5LmlzLXRvZGF5IHsgYm94" +
      "LXNoYWRvdzogaW5zZXQgMCAwIDAgMS41cHggdmFyKC0tYnJhbmQpOyB9Ci5jYWwtZGF5LmlzLXNlbGVjdGVkIHsKICBiYWNrZ3Jv" +
      "dW5kOiBsaW5lYXItZ3JhZGllbnQoMTYwZGVnLCB2YXIoLS1icmFuZCksIHZhcigtLWJyYW5kLXN0cm9uZykpOwogIGNvbG9yOiAj" +
      "ZmZmOwogIGJveC1zaGFkb3c6IG5vbmU7Cn0KLmNhbC1kYXkuaXMtc2VsZWN0ZWQgLmRvdCB7IGJhY2tncm91bmQ6ICNmZmY7IH0K" +
      "LmNhbC1ibGFuayB7IGhlaWdodDogMzZweDsgfQoKLyog5qCH562+ICovCi50YWdzLWxpc3QgeyBkaXNwbGF5OiBmbGV4OyBmbGV4" +
      "LXdyYXA6IHdyYXA7IGdhcDogNnB4OyB9Ci50YWctcm93IHsKICBkaXNwbGF5OiBpbmxpbmUtZmxleDsKICBhbGlnbi1pdGVtczog" +
      "Y2VudGVyOwogIGdhcDogNHB4OwogIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgYmFja2dyb3VuZDogdmFyKC0t" +
      "c3VyZmFjZSk7CiAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXBpbGwpOwogIHBhZGRpbmc6IDVweCAxMXB4OwogIGZvbnQt" +
      "c2l6ZTogMTIuNXB4OwogIGNvbG9yOiB2YXIoLS10ZXh0LW11dGVkKTsKICBjdXJzb3I6IHBvaW50ZXI7CiAgdHJhbnNpdGlvbjog" +
      "Ym9yZGVyLWNvbG9yIDAuMTVzIGVhc2UsIGNvbG9yIDAuMTVzIGVhc2U7Cn0KLnRhZy1yb3c6aG92ZXIgeyBib3JkZXItY29sb3I6" +
      "IHZhcigtLWJyYW5kKTsgY29sb3I6IHZhcigtLXRleHQpOyB9Ci50YWctcm93IC50YWctaGFzaCB7IGNvbG9yOiB2YXIoLS1icmFu" +
      "ZCk7IGZvbnQtd2VpZ2h0OiA3MDA7IH0KLnRhZy1yb3cgYiB7IGZvbnQtd2VpZ2h0OiA2MDA7IGNvbG9yOiB2YXIoLS10ZXh0LWZh" +
      "aW50KTsgZm9udC1zaXplOiAxMS41cHg7IH0KCi8qIOaXtumXtOe6vyAqLwoudGltZWxpbmUgeyBmb250LXNpemU6IDEzcHg7IH0K" +
      "LnRsLXllYXIgewogIGRpc3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNl" +
      "LWJldHdlZW47CiAgcGFkZGluZzogNnB4IDhweDsKICBmb250LXdlaWdodDogNzAwOwogIGJvcmRlci1yYWRpdXM6IDlweDsKICBj" +
      "dXJzb3I6IHBvaW50ZXI7CiAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAwLjE1cyBlYXNlOwp9Ci50bC15ZWFyOmhvdmVyIHsgYmFj" +
      "a2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgfQoudGwteWVhciBzbWFsbCB7IGNvbG9yOiB2YXIoLS10ZXh0LWZhaW50KTsgZm9u" +
      "dC13ZWlnaHQ6IDUwMDsgfQovKiDml6XljobmoIfpopjlj6/ngrnlh7sg4oaSIOafpeeci+aVtOaciCAqLwojY2FsLXRpdGxlIHsK" +
      "ICBjdXJzb3I6IHBvaW50ZXI7CiAgYm9yZGVyLXJhZGl1czogNnB4OwogIHBhZGRpbmc6IDFweCA0cHg7CiAgbWFyZ2luOiAtMXB4" +
      "IC00cHg7CiAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAwLjE1cyBlYXNlLCBjb2xvciAwLjE1cyBlYXNlOwp9CiNjYWwtdGl0bGU6" +
      "aG92ZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBjb2xvcjogdmFyKC0tYnJhbmQpOyB9Ci50bC1tb250aHMgeyBk" +
      "aXNwbGF5OiBmbGV4OyBmbGV4LXdyYXA6IHdyYXA7IGdhcDogNXB4OyBwYWRkaW5nOiAycHggNHB4IDEwcHggMTBweDsgfQoudGwt" +
      "bW9udGggewogIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAg" +
      "Ym9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXBpbGwpOwogIHBhZGRpbmc6IDRweCAxMHB4OwogIGZvbnQtc2l6ZTogMTJweDsK" +
      "ICBjb2xvcjogdmFyKC0tdGV4dC1tdXRlZCk7CiAgY3Vyc29yOiBwb2ludGVyOwogIHRyYW5zaXRpb246IGFsbCAwLjE1cyBlYXNl" +
      "Owp9Ci50bC1tb250aDpob3ZlciB7IGJvcmRlci1jb2xvcjogdmFyKC0tYnJhbmQpOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KLnRs" +
      "LW1vbnRoIGIgeyBjb2xvcjogdmFyKC0tYnJhbmQpOyBmb250LXdlaWdodDogNjAwOyBtYXJnaW4tbGVmdDogM3B4OyB9CgovKiDm" +
      "l6XmnJ/mnaEgKi8KLmRhdGViYXIgewogIGRpc3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBqdXN0aWZ5LWNv" +
      "bnRlbnQ6IGNlbnRlcjsKICBnYXA6IDZweDsKICBtYXJnaW4tYm90dG9tOiAxNHB4Owp9Ci5kYXRlLXBpbGwgewogIHBvc2l0aW9u" +
      "OiByZWxhdGl2ZTsKICBkaXNwbGF5OiBpbmxpbmUtZmxleDsKICBhbGlnbi1pdGVtczogY2VudGVyOwogIGp1c3RpZnktY29udGVu" +
      "dDogY2VudGVyOwogIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7" +
      "CiAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXBpbGwpOwogIHBhZGRpbmc6IDlweCAyMHB4OwogIG1pbi13aWR0aDogMTY4" +
      "cHg7CiAgdGV4dC1hbGlnbjogY2VudGVyOwogIGZvbnQtd2VpZ2h0OiA2MDA7CiAgZm9udC1zaXplOiAxNC41cHg7CiAgY3Vyc29y" +
      "OiBwb2ludGVyOwogIGJveC1zaGFkb3c6IHZhcigtLXNoYWRvdy1zbSk7CiAgdHJhbnNpdGlvbjogYm9yZGVyLWNvbG9yIDAuMTZz" +
      "IGVhc2U7CiAgdXNlci1zZWxlY3Q6IG5vbmU7CiAgY29sb3I6IHZhcigtLXRleHQpOwp9Ci5kYXRlLXBpbGw6aG92ZXIgeyBib3Jk" +
      "ZXItY29sb3I6IHZhcigtLWJyYW5kKTsgfQoKLyog57yW6L6R5Zmo5Y2h54mHICovCi5jb21wb3NlciB7CiAgYmFja2dyb3VuZDog" +
      "dmFyKC0tc3VyZmFjZSk7CiAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOiB2YXIoLS1y" +
      "YWRpdXMpOwogIHBhZGRpbmc6IDEycHggMTRweCAxMHB4OwogIGJveC1zaGFkb3c6IHZhcigtLXNoYWRvdy1zbSk7CiAgbWFyZ2lu" +
      "LWJvdHRvbTogMTZweDsKICB0cmFuc2l0aW9uOiBib3JkZXItY29sb3IgMC4xNnMgZWFzZSwgYm94LXNoYWRvdyAwLjE2cyBlYXNl" +
      "Owp9Ci5jb21wb3Nlcjpmb2N1cy13aXRoaW4gewogIGJvcmRlci1jb2xvcjogdmFyKC0tYnJhbmQpOwogIGJveC1zaGFkb3c6IDAg" +
      "MCAwIDNweCB2YXIoLS1icmFuZC1zb2Z0KTsKfQouY29tcG9zZXIgaW5wdXRbdHlwZT0ndGV4dCddIHsKICB3aWR0aDogMTAwJTsK" +
      "ICBib3JkZXI6IG5vbmU7CiAgb3V0bGluZTogbm9uZTsKICBiYWNrZ3JvdW5kOiB0cmFuc3BhcmVudDsKICBtaW4taGVpZ2h0OiA0" +
      "MnB4OwogIGZvbnQtc2l6ZTogMTVweDsKICBwYWRkaW5nOiAwOwp9Ci5jb21wb3NlciBpbnB1dFt0eXBlPSd0ZXh0J106OnBsYWNl" +
      "aG9sZGVyIHsgY29sb3I6IHZhcigtLXRleHQtZmFpbnQpOyB9Ci5jb21wb3Nlci1mb290IHsKICBkaXNwbGF5OiBmbGV4OwogIGFs" +
      "aWduLWl0ZW1zOiBjZW50ZXI7CiAgZ2FwOiA4cHg7CiAgbWFyZ2luLXRvcDogNHB4Owp9Ci5jb21wb3Nlci1zcGFjZXIgeyBmbGV4" +
      "OiAxOyB9Ci5jb21wb3Nlci1kYXRlIHsKICBwb3NpdGlvbjogcmVsYXRpdmU7CiAgZGlzcGxheTogaW5saW5lLWZsZXg7CiAgYWxp" +
      "Z24taXRlbXM6IGNlbnRlcjsKICBnYXA6IDRweDsKICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJhY2tncm91" +
      "bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXBpbGwpOwogIHBhZGRpbmc6IDVweCAx" +
      "MnB4OwogIGZvbnQtc2l6ZTogMTJweDsKICBjb2xvcjogdmFyKC0tdGV4dC1tdXRlZCk7CiAgY3Vyc29yOiBwb2ludGVyOwogIHVz" +
      "ZXItc2VsZWN0OiBub25lOwogIHRyYW5zaXRpb246IGJvcmRlci1jb2xvciAwLjE2cyBlYXNlLCBjb2xvciAwLjE2cyBlYXNlOwp9" +
      "Ci5jb21wb3Nlci1kYXRlOmhvdmVyIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1icmFuZCk7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQou" +
      "YWRkLWhpbnQgewogIGNvbG9yOiB2YXIoLS1kYW5nZXIpOwogIGZvbnQtc2l6ZTogMTIuNXB4OwogIG1hcmdpbjogMDsKICBtaW4t" +
      "d2lkdGg6IDA7CiAgZmxleDogMTsKICB0ZXh0LWFsaWduOiByaWdodDsKfQouY29tcG9zZXIuc2hha2UgeyBhbmltYXRpb246IHNo" +
      "YWtlIDAuMzRzOyB9CkBrZXlmcmFtZXMgc2hha2UgewogIDAlLCAxMDAlIHsgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKDApOyB9CiAg" +
      "MjUlIHsgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01cHgpOyB9CiAgNzUlIHsgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKDVweCk7IH0K" +
      "fQoKLyog5Y2h54mH5rWBICovCi5mZWVkLXdyYXAgeyBmbGV4OiAxOyB9Ci5mZWVkIHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJl" +
      "Y3Rpb246IGNvbHVtbjsgZ2FwOiAxMHB4OyB9Cgouc2VhcmNoLWJhbm5lciB7CiAgZGlzcGxheTogZmxleDsKICBhbGlnbi1pdGVt" +
      "czogY2VudGVyOwogIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICBnYXA6IDEwcHg7CiAgYmFja2dyb3VuZDogdmFy" +
      "KC0tYnJhbmQtc29mdCk7CiAgYm9yZGVyOiAxcHggc29saWQgY29sb3ItbWl4KGluIHNyZ2IsIHZhcigtLWJyYW5kKSAyNiUsIHRy" +
      "YW5zcGFyZW50KTsKICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMtc20pOwogIHBhZGRpbmc6IDhweCA4cHggOHB4IDEzcHg7" +
      "CiAgZm9udC1zaXplOiAxM3B4OwogIGNvbG9yOiB2YXIoLS10ZXh0KTsKICBtYXJnaW4tYm90dG9tOiAxMnB4Owp9Ci5zZWFyY2gt" +
      "YmFubmVyIHNwYW4geyBtaW4td2lkdGg6IDA7IHdvcmQtYnJlYWs6IGJyZWFrLWFsbDsgfQoKLmZlZWQtZGF0ZS1oZWFkIHsKICBk" +
      "aXNwbGF5OiBmbGV4OwogIGFsaWduLWl0ZW1zOiBiYXNlbGluZTsKICBnYXA6IDhweDsKICBtYXJnaW46IDE0cHggMnB4IDJweDsK" +
      "ICBmb250LXNpemU6IDEzcHg7CiAgZm9udC13ZWlnaHQ6IDcwMDsKfQouZmVlZC1kYXRlLWhlYWQ6Zmlyc3QtY2hpbGQgeyBtYXJn" +
      "aW4tdG9wOiAycHg7IH0KLmZlZWQtZGF0ZS1oZWFkIHNtYWxsIHsgY29sb3I6IHZhcigtLXRleHQtZmFpbnQpOyBmb250LXdlaWdo" +
      "dDogNTAwOyB9Ci5mZWVkLWRhdGUtaGVhZCAuZmVlZC1kYXRlLWNvdW50IHsgbWFyZ2luLWxlZnQ6IGF1dG87IGZvbnQtc2l6ZTog" +
      "MTJweDsgY29sb3I6IHZhcigtLXRleHQtZmFpbnQpOyBmb250LXdlaWdodDogNTAwOyB9CgovKiBtZW1vIOWNoeeJhyAqLwoubWVt" +
      "byB7CiAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3Jk" +
      "ZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogIHBhZGRpbmc6IDlweCAxMnB4IDExcHg7CiAgYm94LXNoYWRvdzogdmFyKC0tc2hh" +
      "ZG93LXNtKTsKICBhbmltYXRpb246IGl0ZW0taW4gMC4yNnMgY3ViaWMtYmV6aWVyKDAuMiwgMC44LCAwLjIsIDEpOwogIHRyYW5z" +
      "aXRpb246IGJvcmRlci1jb2xvciAwLjE2cyBlYXNlLCBvcGFjaXR5IDAuMnMgZWFzZSwgdHJhbnNmb3JtIDAuMnMgZWFzZTsKfQpA" +
      "a2V5ZnJhbWVzIGl0ZW0taW4gewogIGZyb20geyBvcGFjaXR5OiAwOyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVkoLTZweCkgc2NhbGUo" +
      "MC45ODUpOyB9CiAgdG8geyBvcGFjaXR5OiAxOyB0cmFuc2Zvcm06IG5vbmU7IH0KfQoubWVtbzpob3ZlciB7IGJvcmRlci1jb2xv" +
      "cjogdmFyKC0tYnJhbmQpOyB9Ci5tZW1vLnJlbW92aW5nIHsgb3BhY2l0eTogMDsgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKDIwcHgp" +
      "OyB9CgoubWVtby1tZXRhIHsKICBkaXNwbGF5OiBmbGV4OwogIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgZ2FwOiA4cHg7CiAgZm9u" +
      "dC1zaXplOiAxMS41cHg7CiAgY29sb3I6IHZhcigtLXRleHQtZmFpbnQpOwogIGZvbnQtdmFyaWFudC1udW1lcmljOiB0YWJ1bGFy" +
      "LW51bXM7Cn0KLm1lbW8tbWV0YSAubWVtby10aW1lIHsgbWluLXdpZHRoOiAwOyBvdmVyZmxvdzogaGlkZGVuOyB0ZXh0LW92ZXJm" +
      "bG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQoubWVtby1hY3RzIHsKICBkaXNwbGF5OiBmbGV4OwogIGdhcDog" +
      "MnB4OwogIG1hcmdpbi1sZWZ0OiBhdXRvOwogIG9wYWNpdHk6IDAuNDU7CiAgdHJhbnNpdGlvbjogb3BhY2l0eSAwLjE1cyBlYXNl" +
      "Owp9Ci5tZW1vOmhvdmVyIC5tZW1vLWFjdHMsIC5tZW1vOmZvY3VzLXdpdGhpbiAubWVtby1hY3RzIHsgb3BhY2l0eTogMTsgfQou" +
      "bWVtby1hY3RzIGJ1dHRvbiB7CiAgd2lkdGg6IDI2cHg7IGhlaWdodDogMjZweDsKICBib3JkZXI6IG5vbmU7CiAgYm9yZGVyLXJh" +
      "ZGl1czogN3B4OwogIGJhY2tncm91bmQ6IHRyYW5zcGFyZW50OwogIGNvbG9yOiB2YXIoLS10ZXh0LWZhaW50KTsKICBjdXJzb3I6" +
      "IHBvaW50ZXI7CiAgZGlzcGxheTogZ3JpZDsgcGxhY2UtaXRlbXM6IGNlbnRlcjsKICBwYWRkaW5nOiAwOwogIHRyYW5zaXRpb246" +
      "IGFsbCAwLjE1cyBlYXNlOwp9Ci5tZW1vLWFjdHMgYnV0dG9uIHN2ZyB7IHdpZHRoOiAxM3B4OyBoZWlnaHQ6IDEzcHg7IH0KLm1l" +
      "bW8tYWN0cyBidXR0b246aG92ZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0K" +
      "Lm1lbW8tYWN0cyAubWVtby1kZWw6aG92ZXIgeyBiYWNrZ3JvdW5kOiByZ2JhKDIyMCwgNzQsIDc0LCAwLjEyKTsgY29sb3I6IHZh" +
      "cigtLWRhbmdlcik7IH0KCi5tZW1vLWJvZHkgewogIGRpc3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGZsZXgtc3RhcnQ7CiAg" +
      "Z2FwOiAxMHB4OwogIG1hcmdpbi10b3A6IDVweDsKfQoKLmNoZWNrIHsKICBmbGV4OiBub25lOwogIHdpZHRoOiAyMnB4OyBoZWln" +
      "aHQ6IDIycHg7CiAgbWFyZ2luLXRvcDogMXB4OwogIGJvcmRlci1yYWRpdXM6IDUwJTsKICBib3JkZXI6IDJweCBzb2xpZCB2YXIo" +
      "LS1ib3JkZXIpOwogIGJhY2tncm91bmQ6IHRyYW5zcGFyZW50OwogIGN1cnNvcjogcG9pbnRlcjsKICBkaXNwbGF5OiBncmlkOyBw" +
      "bGFjZS1pdGVtczogY2VudGVyOwogIHRyYW5zaXRpb246IGFsbCAwLjE4cyBjdWJpYy1iZXppZXIoMC4yLCAwLjgsIDAuMiwgMSk7" +
      "CiAgcGFkZGluZzogMDsKfQouY2hlY2s6aG92ZXIgeyBib3JkZXItY29sb3I6IHZhcigtLWJyYW5kKTsgfQouY2hlY2sgc3ZnIHsg" +
      "d2lkdGg6IDEycHg7IGhlaWdodDogMTJweDsgb3BhY2l0eTogMDsgdHJhbnNmb3JtOiBzY2FsZSgwLjQpOyB0cmFuc2l0aW9uOiBh" +
      "bGwgMC4xOHMgZWFzZTsgY29sb3I6ICNmZmY7IH0KLm1lbW8uZG9uZSAuY2hlY2sgewogIGJhY2tncm91bmQ6IGxpbmVhci1ncmFk" +
      "aWVudCgxNjBkZWcsIHZhcigtLWJyYW5kKSwgdmFyKC0tYnJhbmQtc3Ryb25nKSk7CiAgYm9yZGVyLWNvbG9yOiB0cmFuc3BhcmVu" +
      "dDsKfQoubWVtby5kb25lIC5jaGVjayBzdmcgeyBvcGFjaXR5OiAxOyB0cmFuc2Zvcm06IHNjYWxlKDEpOyB9CgoubWVtby10ZXh0" +
      "IHsKICBmbGV4OiAxOwogIG1pbi13aWR0aDogMDsKICB3b3JkLWJyZWFrOiBicmVhay13b3JkOwogIHBhZGRpbmctdG9wOiAxcHg7" +
      "CiAgdHJhbnNpdGlvbjogY29sb3IgMC4ycyBlYXNlOwogIG91dGxpbmU6IG5vbmU7CiAgYm9yZGVyLXJhZGl1czogNHB4OwogIGxp" +
      "bmUtaGVpZ2h0OiAxLjY7Cn0KLm1lbW8tdGV4dDpmb2N1cyB7IGJveC1zaGFkb3c6IDAgMCAwIDNweCB2YXIoLS1icmFuZC1zb2Z0" +
      "KTsgfQoubWVtby5kb25lIC5tZW1vLXRleHQgewogIGNvbG9yOiB2YXIoLS10ZXh0LWZhaW50KTsKICB0ZXh0LWRlY29yYXRpb246" +
      "IGxpbmUtdGhyb3VnaDsKICB0ZXh0LWRlY29yYXRpb24tdGhpY2tuZXNzOiAxLjVweDsKfQoKLyog5qCH6aKY6YeM55qEICPmoIfn" +
      "rb4gKi8KLnRhZy1jaGlwIHsKICBkaXNwbGF5OiBpbmxpbmUtYmxvY2s7CiAgYm9yZGVyOiBub25lOwogIGJhY2tncm91bmQ6IHZh" +
      "cigtLWJyYW5kLXNvZnQpOwogIGNvbG9yOiB2YXIoLS1icmFuZC1zdHJvbmcpOwogIGJvcmRlci1yYWRpdXM6IDZweDsKICBwYWRk" +
      "aW5nOiAwIDZweDsKICBtYXJnaW46IDAgMXB4OwogIGZvbnQtc2l6ZTogMC45MmVtOwogIGZvbnQtd2VpZ2h0OiA2MDA7CiAgbGlu" +
      "ZS1oZWlnaHQ6IDEuNjsKICBjdXJzb3I6IHBvaW50ZXI7CiAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAwLjE1cyBlYXNlLCB0cmFu" +
      "c2Zvcm0gMC4xMnMgZWFzZTsKfQoudGFnLWNoaXA6aG92ZXIgeyBiYWNrZ3JvdW5kOiBjb2xvci1taXgoaW4gc3JnYiwgdmFyKC0t" +
      "YnJhbmQpIDIyJSwgdHJhbnNwYXJlbnQpOyB9Ci50YWctY2hpcDphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTYpOyB9Cgov" +
      "KiDnqbrnirbmgIEgKi8KLmVtcHR5LXN0YXRlIHsgdGV4dC1hbGlnbjogY2VudGVyOyBwYWRkaW5nOiA1NHB4IDIwcHg7IH0KLmVt" +
      "cHR5LWFydCB7IGZvbnQtc2l6ZTogNDJweDsgbWFyZ2luLWJvdHRvbTogMTBweDsgb3BhY2l0eTogMC45OyB9Ci5lbXB0eS10aXRs" +
      "ZSB7IG1hcmdpbjogMDsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxNXB4OyB9Ci5lbXB0eS1zdWIgeyBtYXJnaW46IDVw" +
      "eCAwIDA7IGZvbnQtc2l6ZTogMTNweDsgY29sb3I6IHZhcigtLXRleHQtZmFpbnQpOyB9CgovKiDlupXpg6jnu5/orqEgKi8KLmZv" +
      "b3RlciB7CiAgcG9zaXRpb246IHN0aWNreTsKICBib3R0b206IDA7CiAgbWFyZ2luLXRvcDogMTRweDsKICBwYWRkaW5nOiAxMHB4" +
      "IDJweCBjYWxjKDEwcHggKyB2YXIoLS1zYWZlLWJvdHRvbSkpOwogIGJhY2tncm91bmQ6IGNvbG9yLW1peChpbiBzcmdiLCB2YXIo" +
      "LS1iZykgODYlLCB0cmFuc3BhcmVudCk7CiAgYmFja2Ryb3AtZmlsdGVyOiBzYXR1cmF0ZSgxNzAlKSBibHVyKDE0cHgpOwogIC13" +
      "ZWJraXQtYmFja2Ryb3AtZmlsdGVyOiBzYXR1cmF0ZSgxNzAlKSBibHVyKDE0cHgpOwogIGJvcmRlci10b3A6IDFweCBzb2xpZCB2" +
      "YXIoLS1ib3JkZXIpOwogIGRpc3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBqdXN0aWZ5LWNvbnRlbnQ6IHNw" +
      "YWNlLWJldHdlZW47CiAgZ2FwOiAxMnB4OwogIHotaW5kZXg6IDIwOwp9Ci5mb290ZXItc3RhdCB7IGRpc3BsYXk6IGZsZXg7IGFs" +
      "aWduLWl0ZW1zOiBiYXNlbGluZTsgZ2FwOiA1cHg7IGZvbnQtc2l6ZTogMTMuNXB4OyBjb2xvcjogdmFyKC0tdGV4dC1tdXRlZCk7" +
      "IH0KLmZvb3Rlci1zdGF0ICNyZW1haW5pbmctY291bnQgeyBmb250LXNpemU6IDE5cHg7IGZvbnQtd2VpZ2h0OiA3MDA7IGNvbG9y" +
      "OiB2YXIoLS1icmFuZCk7IH0KLmZvb3Rlci1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiA4cHg7IH0KQG1lZGlhIChtYXgt" +
      "d2lkdGg6IDQwMHB4KSB7CiAgLmZvb3Rlci1hY3Rpb25zIC5idG4geyBwYWRkaW5nOiA3cHggOXB4OyBmb250LXNpemU6IDEyLjVw" +
      "eDsgfQp9CgovKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIOaXpeacn+mAieaLqeW8ueWxgiAtLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCi5kYXRlLXBvcCB7CiAgcG9zaXRpb246IGZpeGVkOwogIHotaW5kZXg6IDU1Owog" +
      "IHdpZHRoOiAzMDJweDsKICBtYXgtd2lkdGg6IGNhbGMoMTAwdncgLSAyMHB4KTsKICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNl" +
      "KTsKICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgYm94" +
      "LXNoYWRvdzogdmFyKC0tc2hhZG93LWxnKTsKICBwYWRkaW5nOiAxMHB4IDEycHggMTJweDsKICBhbmltYXRpb246IHBvcC1pbiAw" +
      "LjE2cyBjdWJpYy1iZXppZXIoMC4yLCAwLjgsIDAuMiwgMSk7Cn0KQGtleWZyYW1lcyBwb3AtaW4gewogIGZyb20geyBvcGFjaXR5" +
      "OiAwOyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVkoNnB4KSBzY2FsZSgwLjk3KTsgfQogIHRvIHsgb3BhY2l0eTogMTsgdHJhbnNmb3Jt" +
      "OiBub25lOyB9Cn0KLmRhdGUtcG9wLWhlYWQgewogIGRpc3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBnYXA6" +
      "IDJweDsKICBtYXJnaW4tYm90dG9tOiA0cHg7Cn0KLmRhdGUtcG9wLXRpdGxlIHsKICBmbGV4OiAxOwogIGRpc3BsYXk6IGZsZXg7" +
      "CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICBnYXA6IDJweDsKICBmb250LXdlaWdo" +
      "dDogNzAwOwogIGZvbnQtc2l6ZTogMTQuNXB4OwogIGxldHRlci1zcGFjaW5nOiAwLjAyZW07Cn0KLmRhdGUtcG9wLWlucHV0IHsK" +
      "ICB3aWR0aDogNTJweDsKICBib3JkZXI6IG5vbmU7CiAgYm9yZGVyLWJvdHRvbTogMS41cHggc29saWQgdHJhbnNwYXJlbnQ7CiAg" +
      "YmFja2dyb3VuZDogdHJhbnNwYXJlbnQ7CiAgdGV4dC1hbGlnbjogY2VudGVyOwogIGZvbnQtd2VpZ2h0OiA3MDA7CiAgZm9udC1z" +
      "aXplOiAxNC41cHg7CiAgY29sb3I6IHZhcigtLXRleHQpOwogIHBhZGRpbmc6IDFweCAycHg7CiAgYm9yZGVyLXJhZGl1czogNnB4" +
      "IDZweCAwIDA7CiAgb3V0bGluZTogbm9uZTsKICBmb250LXZhcmlhbnQtbnVtZXJpYzogdGFidWxhci1udW1zOwogIHRyYW5zaXRp" +
      "b246IGJvcmRlci1jb2xvciAwLjE1cyBlYXNlLCBiYWNrZ3JvdW5kIDAuMTVzIGVhc2U7Cn0KLmRhdGUtcG9wLWlucHV0LW1vbnRo" +
      "IHsgd2lkdGg6IDM0cHg7IH0KLmRhdGUtcG9wLWlucHV0OmhvdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgfQou" +
      "ZGF0ZS1wb3AtaW5wdXQ6Zm9jdXMgeyBib3JkZXItYm90dG9tLWNvbG9yOiB2YXIoLS1icmFuZCk7IGJhY2tncm91bmQ6IHZhcigt" +
      "LXN1cmZhY2UtMik7IH0KLmRhdGUtcG9wIC5taW5pLWJ0biB7IHdpZHRoOiAzMHB4OyBoZWlnaHQ6IDMwcHg7IGZvbnQtc2l6ZTog" +
      "MTRweDsgfQoucG9wLWdyaWQgeyBnYXA6IDFweDsgfQoucG9wLWdyaWQgLmNhbC1kYXkgeyBoZWlnaHQ6IDM2cHg7IH0KLnBvcC1n" +
      "cmlkIC5jYWwtZGF5LmlzLW91dHNpZGUgeyBjb2xvcjogdmFyKC0tdGV4dC1mYWludCk7IG9wYWNpdHk6IDAuNTU7IH0KLmRhdGUt" +
      "cG9wLWZvb3QgewogIGRpc3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBnYXA6IDhweDsKICBtYXJnaW4tdG9w" +
      "OiA4cHg7CiAgcGFkZGluZy10b3A6IDEwcHg7CiAgYm9yZGVyLXRvcDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Cn0KLmRhdGUt" +
      "cG9wLWdhcCB7IGZsZXg6IDE7IH0KQG1lZGlhIChtYXgtd2lkdGg6IDUyMHB4KSB7CiAgLmRhdGUtcG9wIHsKICAgIGxlZnQ6IDUw" +
      "JSAhaW1wb3J0YW50OwogICAgcmlnaHQ6IGF1dG8gIWltcG9ydGFudDsKICAgIGJvdHRvbTogY2FsYygxNnB4ICsgdmFyKC0tc2Fm" +
      "ZS1ib3R0b20pKSAhaW1wb3J0YW50OwogICAgdG9wOiBhdXRvICFpbXBvcnRhbnQ7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgo" +
      "LTUwJSk7CiAgICBhbmltYXRpb246IHBvcC1pbi1ib3R0b20gMC4xNnMgY3ViaWMtYmV6aWVyKDAuMiwgMC44LCAwLjIsIDEpOwog" +
      "IH0KICBAa2V5ZnJhbWVzIHBvcC1pbi1ib3R0b20gewogICAgZnJvbSB7IG9wYWNpdHk6IDA7IHRyYW5zZm9ybTogdHJhbnNsYXRl" +
      "WCgtNTAlKSB0cmFuc2xhdGVZKDEwcHgpOyB9CiAgICB0byB7IG9wYWNpdHk6IDE7IHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAl" +
      "KTsgfQogIH0KfQoKLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSDmir3lsYkgLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLSAqLwouZHJhd2VyLW1hc2sgewogIHBvc2l0aW9uOiBmaXhlZDsKICBpbnNldDogMDsKICBiYWNrZ3Jv" +
      "dW5kOiByZ2JhKDE0LCAxNSwgMjUsIDAuNDIpOwogIGJhY2tkcm9wLWZpbHRlcjogYmx1cigzcHgpOwogIC13ZWJraXQtYmFja2Ry" +
      "b3AtZmlsdGVyOiBibHVyKDNweCk7CiAgei1pbmRleDogNDA7CiAgZGlzcGxheTogZmxleDsKICBqdXN0aWZ5LWNvbnRlbnQ6IGZs" +
      "ZXgtZW5kOwogIGFuaW1hdGlvbjogZmFkZS1pbiAwLjIycyBlYXNlOwp9CkBrZXlmcmFtZXMgZmFkZS1pbiB7IGZyb20geyBvcGFj" +
      "aXR5OiAwOyB9IHRvIHsgb3BhY2l0eTogMTsgfSB9CgouZHJhd2VyIHsKICB3aWR0aDogbWluKDQ0MHB4LCAxMDAlKTsKICBoZWln" +
      "aHQ6IDEwMCU7CiAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogIGRpc3BsYXk6IGZsZXg7CiAgZmxleC1kaXJlY3Rpb246IGNvbHVt" +
      "bjsKICBib3gtc2hhZG93OiB2YXIoLS1zaGFkb3ctbGcpOwogIGFuaW1hdGlvbjogc2xpZGUtaW4gMC4yOHMgY3ViaWMtYmV6aWVy" +
      "KDAuMiwgMC44LCAwLjIsIDEpOwp9CkBrZXlmcmFtZXMgc2xpZGUtaW4geyBmcm9tIHsgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKDI0" +
      "cHgpOyBvcGFjaXR5OiAwLjQ7IH0gdG8geyB0cmFuc2Zvcm06IG5vbmU7IG9wYWNpdHk6IDE7IH0gfQoKLmRyYXdlci1oZWFkIHsK" +
      "ICBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgcGFk" +
      "ZGluZzogMTZweCAxNnB4IDEycHg7CiAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgcG9zaXRpb246" +
      "IHN0aWNreTsgdG9wOiAwOwogIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICB6LWluZGV4OiAyOwp9Ci5kcmF3ZXItaGVhZCBoMiB7" +
      "IG1hcmdpbjogMDsgZm9udC1zaXplOiAxOHB4OyBmb250LXdlaWdodDogNzAwOyB9Ci5kcmF3ZXItYm9keSB7IG92ZXJmbG93LXk6" +
      "IGF1dG87IHBhZGRpbmc6IDE0cHggMTZweCBjYWxjKDI4cHggKyB2YXIoLS1zYWZlLWJvdHRvbSkpOyAtd2Via2l0LW92ZXJmbG93" +
      "LXNjcm9sbGluZzogdG91Y2g7IH0KCi5jYXJkIHsKICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICBib3JkZXI6IDFweCBz" +
      "b2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgcGFkZGluZzogMTVweCAxNXB4IDE2" +
      "cHg7CiAgbWFyZ2luLWJvdHRvbTogMTJweDsKICBib3gtc2hhZG93OiB2YXIoLS1zaGFkb3ctc20pOwp9Ci5jYXJkLWxhYmVsIHsK" +
      "ICBtYXJnaW46IDAgMCA0cHg7CiAgZm9udC1zaXplOiAxMnB4OyBmb250LXdlaWdodDogNzAwOwogIGNvbG9yOiB2YXIoLS10ZXh0" +
      "LWZhaW50KTsKICB0ZXh0LXRyYW5zZm9ybTogdXBwZXJjYXNlOwogIGxldHRlci1zcGFjaW5nOiAwLjA3ZW07Cn0KLmNhcmQtZGVz" +
      "YyB7IG1hcmdpbjogMCAwIDE0cHg7IGZvbnQtc2l6ZTogMTNweDsgY29sb3I6IHZhcigtLXRleHQtbXV0ZWQpOyBsaW5lLWhlaWdo" +
      "dDogMS42NTsgfQoKLnJvdy1iZXR3ZWVuIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsganVzdGlmeS1jb250" +
      "ZW50OiBzcGFjZS1iZXR3ZWVuOyBnYXA6IDEycHg7IH0KLmFjY291bnQtbmFtZSB7IG1hcmdpbjogMnB4IDAgMDsgZm9udC13ZWln" +
      "aHQ6IDYwMDsgZm9udC1zaXplOiAxNXB4OyB9CgouY29sbGFwc2Ugc3VtbWFyeSB7CiAgY3Vyc29yOiBwb2ludGVyOwogIGZvbnQt" +
      "c2l6ZTogMTMuNXB4OwogIGZvbnQtd2VpZ2h0OiA2MDA7CiAgY29sb3I6IHZhcigtLXRleHQtbXV0ZWQpOwogIGxpc3Qtc3R5bGU6" +
      "IG5vbmU7CiAgcGFkZGluZzogNHB4IDA7Cn0KLmNvbGxhcHNlIHN1bW1hcnk6Oi13ZWJraXQtZGV0YWlscy1tYXJrZXIgeyBkaXNw" +
      "bGF5OiBub25lOyB9Ci5jb2xsYXBzZSBzdW1tYXJ5OjpiZWZvcmUgeyBjb250ZW50OiAn4pa4ICc7IGRpc3BsYXk6IGlubGluZS1i" +
      "bG9jazsgdHJhbnNpdGlvbjogdHJhbnNmb3JtIDAuMThzIGVhc2U7IH0KLmNvbGxhcHNlW29wZW5dIHN1bW1hcnk6OmJlZm9yZSB7" +
      "IGNvbnRlbnQ6ICfilr4gJzsgfQouY29sbGFwc2UtYm9keSB7IHBhZGRpbmctdG9wOiAxMnB4OyB9Cgouc3dpdGNoLXJvdyB7IGRp" +
      "c3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMTBweDsgbWFyZ2luOiA0cHggMCAxNHB4OyB9Ci5zd2l0" +
      "Y2ggewogIGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMTBweDsKICBjdXJzb3I6IHBvaW50ZXI7CiAg" +
      "Zm9udC1zaXplOiAxMy41cHg7CiAgdXNlci1zZWxlY3Q6IG5vbmU7Cn0KLnN3aXRjaCBpbnB1dCB7IHBvc2l0aW9uOiBhYnNvbHV0" +
      "ZTsgb3BhY2l0eTogMDsgd2lkdGg6IDA7IGhlaWdodDogMDsgfQouc3dpdGNoIC5zbGlkZXIgewogIHBvc2l0aW9uOiByZWxhdGl2" +
      "ZTsKICBmbGV4OiBub25lOwogIHdpZHRoOiA0NHB4OyBoZWlnaHQ6IDI2cHg7CiAgYmFja2dyb3VuZDogdmFyKC0tYm9yZGVyKTsK" +
      "ICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMtcGlsbCk7CiAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAwLjJzIGVhc2U7Cn0K" +
      "LnN3aXRjaCAuc2xpZGVyOjphZnRlciB7CiAgY29udGVudDogJyc7CiAgcG9zaXRpb246IGFic29sdXRlOwogIHRvcDogM3B4OyBs" +
      "ZWZ0OiAzcHg7CiAgd2lkdGg6IDIwcHg7IGhlaWdodDogMjBweDsKICBiYWNrZ3JvdW5kOiAjZmZmOwogIGJvcmRlci1yYWRpdXM6" +
      "IDUwJTsKICBib3gtc2hhZG93OiB2YXIoLS1zaGFkb3ctc20pOwogIHRyYW5zaXRpb246IHRyYW5zZm9ybSAwLjJzIGN1YmljLWJl" +
      "emllcigwLjMsIDEuNCwgMC41LCAxKTsKfQouc3dpdGNoIGlucHV0OmNoZWNrZWQgKyAuc2xpZGVyIHsgYmFja2dyb3VuZDogdmFy" +
      "KC0tYnJhbmQpOyB9Ci5zd2l0Y2ggaW5wdXQ6Y2hlY2tlZCArIC5zbGlkZXI6OmFmdGVyIHsgdHJhbnNmb3JtOiB0cmFuc2xhdGVY" +
      "KDE4cHgpOyB9Ci5zd2l0Y2gtdGV4dCB7IGNvbG9yOiB2YXIoLS10ZXh0LW11dGVkKTsgfQouc3dpdGNoLmNvbXBhY3QgeyBtYXJn" +
      "aW4tdG9wOiAycHg7IH0KLnN3aXRjaC5jb21wYWN0IC5zd2l0Y2gtdGV4dCB7IGZvbnQtc2l6ZTogMTIuNXB4OyBsaW5lLWhlaWdo" +
      "dDogMS41OyB9CgoucHJvdmlkZXItcGFuZWwgewogIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgYm9yZGVyOiAxcHgg" +
      "ZGFzaGVkIHZhcigtLWJvcmRlcik7CiAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXNtKTsKICBwYWRkaW5nOiAxNHB4IDEz" +
      "cHggNHB4OwogIG1hcmdpbi1ib3R0b206IDE0cHg7CiAgYW5pbWF0aW9uOiBmYWRlLXVwIDAuMjRzIGVhc2U7Cn0KCi5idG4tcm93" +
      "IHsgZGlzcGxheTogZmxleDsgZ2FwOiA4cHg7IG1hcmdpbi1ib3R0b206IDhweDsgfQouYnRuLXJvdyAuYnRuIHsgZmxleDogMTsg" +
      "fQoKLnN0YXR1cy1saW5lIHsKICBmb250LXNpemU6IDEyLjVweDsKICBwYWRkaW5nOiA4cHggMTFweDsKICBib3JkZXItcmFkaXVz" +
      "OiB2YXIoLS1yYWRpdXMtc20pOwogIG1hcmdpbjogOHB4IDAgMDsKICB3b3JkLWJyZWFrOiBicmVhay13b3JkOwp9Ci5zdGF0dXMt" +
      "bGluZS5vayB7IGJhY2tncm91bmQ6IHJnYmEoNDcsIDE2MiwgMTA2LCAwLjEyKTsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9Ci5z" +
      "dGF0dXMtbGluZS5lcnIgeyBiYWNrZ3JvdW5kOiByZ2JhKDIyMCwgNzQsIDc0LCAwLjEyKTsgY29sb3I6IHZhcigtLWRhbmdlcik7" +
      "IH0KLnN0YXR1cy1saW5lLmJ1c3kgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBjb2xvcjogdmFyKC0tdGV4dC1tdXRl" +
      "ZCk7IH0KCi5hYm91dC1jYXJkIC5jYXJkLWRlc2MgeyBtYXJnaW4tYm90dG9tOiA2cHg7IH0KCi8qIC0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0gVG9hc3QgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwoudG9hc3QtaG9zdCB7" +
      "CiAgcG9zaXRpb246IGZpeGVkOwogIGxlZnQ6IDUwJTsKICBib3R0b206IGNhbGMoODRweCArIHZhcigtLXNhZmUtYm90dG9tKSk7" +
      "CiAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogIGRpc3BsYXk6IGZsZXg7CiAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsK" +
      "ICBhbGlnbi1pdGVtczogY2VudGVyOwogIGdhcDogOHB4OwogIHotaW5kZXg6IDcwOwogIHBvaW50ZXItZXZlbnRzOiBub25lOwog" +
      "IHdpZHRoOiBtaW4oOTJ2dywgNDYwcHgpOwp9Ci50b2FzdCB7CiAgYmFja2dyb3VuZDogIzFmMjEzMDsKICBjb2xvcjogI2ZmZjsK" +
      "ICBwYWRkaW5nOiAxMHB4IDE2cHg7CiAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXBpbGwpOwogIGZvbnQtc2l6ZTogMTMu" +
      "NXB4OwogIGJveC1zaGFkb3c6IHZhcigtLXNoYWRvdy1tZCk7CiAgYW5pbWF0aW9uOiB0b2FzdC1pbiAwLjI0cyBjdWJpYy1iZXpp" +
      "ZXIoMC4yLCAwLjgsIDAuMiwgMSk7CiAgbWF4LXdpZHRoOiAxMDAlOwogIHRleHQtYWxpZ246IGNlbnRlcjsKfQoudG9hc3QuZXJy" +
      "IHsgYmFja2dyb3VuZDogI2IzMzgzYTsgfQoudG9hc3Qub2sgeyBiYWNrZ3JvdW5kOiAjMWY3YTUzOyB9Ci8qIOmVv+aWh+ahiO+8" +
      "iOWmguWQjuerr+i/lOWbnueahOaOkuafpeaMh+W8le+8ieeUqOWNoeeJh+agt+W8j++8jOiDtuWbiuW9ouS8muaSkeW+l+W+iOaA" +
      "qiAqLwoudG9hc3QubG9uZyB7CiAgYm9yZGVyLXJhZGl1czogMTRweDsKICBwYWRkaW5nOiAxMnB4IDE2cHg7CiAgdGV4dC1hbGln" +
      "bjogbGVmdDsKICBsaW5lLWhlaWdodDogMS42NTsKICB3b3JkLWJyZWFrOiBicmVhay13b3JkOwp9Ci50b2FzdC5sZWF2aW5nIHsg" +
      "YW5pbWF0aW9uOiB0b2FzdC1vdXQgMC4yMnMgZWFzZSBmb3J3YXJkczsgfQpAa2V5ZnJhbWVzIHRvYXN0LWluIHsgZnJvbSB7IG9w" +
      "YWNpdHk6IDA7IHRyYW5zZm9ybTogdHJhbnNsYXRlWSgxMHB4KSBzY2FsZSgwLjk2KTsgfSB0byB7IG9wYWNpdHk6IDE7IHRyYW5z" +
      "Zm9ybTogbm9uZTsgfSB9CkBrZXlmcmFtZXMgdG9hc3Qtb3V0IHsgdG8geyBvcGFjaXR5OiAwOyB0cmFuc2Zvcm06IHRyYW5zbGF0" +
      "ZVkoNnB4KSBzY2FsZSgwLjk3KTsgfSB9CgovKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIOahjOmdouerr+W4" +
      "g+WxgCAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCkBtZWRpYSAobWluLXdpZHRoOiA5ODBweCkgewogIC5z" +
      "aGVsbCB7CiAgICBkaXNwbGF5OiBncmlkOwogICAgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAyNjhweCBtaW5tYXgoMCwgMWZyKTsK" +
      "ICAgIG1heC13aWR0aDogMTE4MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBhbGlnbi1pdGVtczogc3RhcnQ7CiAgfQogIC5z" +
      "aWRlYmFyIHsKICAgIHBvc2l0aW9uOiBzdGlja3k7CiAgICB0b3A6IDA7CiAgICBoZWlnaHQ6IDEwMGR2aDsKICAgIHdpZHRoOiBh" +
      "dXRvOwogICAgdHJhbnNmb3JtOiBub25lOwogICAgdmlzaWJpbGl0eTogdmlzaWJsZTsKICAgIGJhY2tncm91bmQ6IHRyYW5zcGFy" +
      "ZW50OwogICAgYm9yZGVyLXJpZ2h0OiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJveC1zaGFkb3c6IG5vbmU7CiAgICBw" +
      "YWRkaW5nOiAyMnB4IDE2cHggMjBweDsKICB9CiAgLnNpZGUtbWFzayB7IGRpc3BsYXk6IG5vbmUgIWltcG9ydGFudDsgfQogIC5z" +
      "aWRlLXRvZ2dsZSB7IGRpc3BsYXk6IG5vbmU7IH0KICAvKiBncmlkIOmhueS4iueahCBtYXJnaW46YXV0byDkvJrmlL7lvIPmi4nk" +
      "vLjjgIHmjIkgZml0LWNvbnRlbnQg5pS257yp77yM5b+F6aG75pi+5byP57uZ5a69ICovCiAgLmNvbnRlbnQgewogICAgd2lkdGg6" +
      "IDEwMCU7CiAgICBtYXgtd2lkdGg6IDc2MHB4OwogICAgcGFkZGluZzogMCAyOHB4IGNhbGMoMThweCArIHZhcigtLXNhZmUtYm90" +
      "dG9tKSk7CiAgfQogIC50b3BiYXIgeyBwYWRkaW5nLXRvcDogMzBweDsgfQogIC50b3BiYXItdGl0bGUgeyBmb250LXNpemU6IDI4" +
      "cHg7IH0KfQoKQG1lZGlhIChtYXgtd2lkdGg6IDk3OXB4KSB7CiAgLm1haW4tdmlldyB7IG1heC13aWR0aDogNzAwcHg7IG1hcmdp" +
      "bjogMCBhdXRvOyB9Cn0KCkBtZWRpYSAocHJlZmVycy1yZWR1Y2VkLW1vdGlvbjogcmVkdWNlKSB7CiAgKiwgKjo6YmVmb3JlLCAq" +
      "OjphZnRlciB7IGFuaW1hdGlvbi1kdXJhdGlvbjogMC4wMDFtcyAhaW1wb3J0YW50OyB0cmFuc2l0aW9uLWR1cmF0aW9uOiAwLjAw" +
      "MW1zICFpbXBvcnRhbnQ7IH0KfQo="
  },
};

/** base64 -> UTF-8 字符串（atob 只处理 Latin-1，中文必须再走一次 TextDecoder） */
function decodeBase64Utf8(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/**
 * 形如 `{ '/index.html': { body: '...', type: 'text/html; charset=utf-8' } }`
 * @type {Record<string, {body: string, type: string}>|null}
 */
const INLINE_ASSETS = INLINE_ASSETS_B64
  ? Object.fromEntries(
      Object.entries(INLINE_ASSETS_B64).map(([path, entry]) => [
        path,
        { body: decodeBase64Utf8(entry.body), type: entry.type },
      ]),
    )
  : null;

/* ================================================================ *
 * src/lib/auth.js
 * ================================================================ */

/**
 * 账号与登录态。
 *  - 口令使用 PBKDF2-SHA256 派生，绝不明文落库
 *  - 登录成功后签发随机 token，写入 HttpOnly Cookie，同时在 D1 的 sessions 表留痕
 */

const SESSION_COOKIE = 'todo_sid';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 天
const USERNAME_RE = /^[A-Za-z0-9_\u4e00-\u9fa5.\-]{2,20}$/;

class HttpError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function publicUser(row) {
  return { id: row.id, username: row.username, createdAt: row.created_at };
}

/* ------------------------------ 注册 / 登录 ------------------------------ */

async function register(env, { username, password }) {
  const name = String(username || '').trim();
  const pass = String(password || '');

  if (!USERNAME_RE.test(name)) {
    throw new HttpError('用户名需为 2-20 位中英文、数字、下划线、点或短横线');
  }
  if (pass.length < 6) throw new HttpError('密码至少 6 位');
  if (pass.length > 128) throw new HttpError('密码太长');

  if (String(env.ALLOW_REGISTRATION ?? 'true').toLowerCase() === 'false') {
    throw new HttpError('本站已关闭注册', 403);
  }

  const exists = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(name).first();
  if (exists) throw new HttpError('该用户名已被注册', 409);

  const { hash, salt } = await hashPassword(pass);
  const id = newId('u_');
  const ts = nowSeconds();

  await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO users (id, username, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)',
    ).bind(id, name, hash, salt, ts),
    env.DB.prepare(
      'INSERT INTO settings (user_id, backup_json, last_backup, updated_at) VALUES (?, NULL, NULL, ?)',
    ).bind(id, ts),
  ]);

  return { id, username: name, createdAt: ts };
}

async function login(env, { username, password }) {
  const name = String(username || '').trim();
  const row = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(name).first();
  if (!row) throw new HttpError('用户名或密码不正确', 401);

  const valid = await verifyPassword(String(password || ''), row.password_hash, row.salt);
  if (!valid) throw new HttpError('用户名或密码不正确', 401);

  return publicUser(row);
}

/* -------------------------------- 会话 -------------------------------- */

async function createSession(env, userId) {
  const token = randomHex(32);
  const ts = nowSeconds();
  await env.DB.prepare(
    'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
  )
    .bind(token, userId, ts, ts + SESSION_TTL_SECONDS)
    .run();
  return token;
}

function sessionCookie(request, token) {
  return serializeCookie(SESSION_COOKIE, token, {
    maxAge: token ? SESSION_TTL_SECONDS : 0,
    path: '/',
    httpOnly: true,
    secure: isSecureRequest(request),
    sameSite: 'Lax',
  });
}

async function destroySession(env, token) {
  if (!token) return;
  await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
}

/** 顺带清理过期会话（低频调用即可，失败不影响主流程） */
async function purgeExpiredSessions(env) {
  try {
    await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(nowSeconds()).run();
  } catch {
    /* ignore */
  }
}

/** 读取当前登录用户，未登录返回 null */
async function getSessionUser(request, env) {
  const token = parseCookies(request)[SESSION_COOKIE];
  if (!token) return null;

  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.created_at, s.token, s.expires_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token = ? AND s.expires_at > ?`,
  )
    .bind(token, nowSeconds())
    .first();

  if (!row) return null;
  return { id: row.id, username: row.username, createdAt: row.created_at, token: row.token };
}

/** 要求登录，否则抛 401 */
async function requireUser(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) throw new HttpError('请先登录', 401);
  return user;
}

/** 修改密码 */
async function changePassword(env, user, { currentPassword, newPassword }) {
  if (String(newPassword || '').length < 6) throw new HttpError('新密码至少 6 位');

  const row = await env.DB.prepare('SELECT password_hash, salt FROM users WHERE id = ?')
    .bind(user.id)
    .first();
  if (!row) throw new HttpError('用户不存在', 404);

  const valid = await verifyPassword(String(currentPassword || ''), row.password_hash, row.salt);
  if (!valid) throw new HttpError('当前密码不正确', 401);

  const { hash, salt } = await hashPassword(String(newPassword));
  await env.DB.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?')
    .bind(hash, salt, user.id)
    .run();

  // 改密后注销其它设备上的会话，仅保留当前这一个
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?')
    .bind(user.id, user.token)
    .run();
}

/* ================================================================ *
 * src/lib/todos.js
 * ================================================================ */

/**
 * 待办事项数据访问层。
 * 排序规则：未完成在前、已完成沉底；同组内按 sort_order、创建时间。
 */

const MAX_TITLE = 500;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const MONTH_RE = /^\d{4}-(?:0[1-9]|1[0-2])$/;
/** 标题里的 #标签（1-24 个非空白字符，不含 #） */
const TAG_RE = /#([^\s#]{1,24})/g;

function normalizeTitle(raw) {
  const title = String(raw ?? '').replace(/\s+/g, ' ').trim();
  if (!title) throw new HttpError('任务内容不能为空');
  if (title.length > MAX_TITLE) throw new HttpError(`任务内容不能超过 ${MAX_TITLE} 字`);
  return title;
}

function normalizeDate(raw, fallback = null) {
  const value = String(raw || '').trim();
  if (!value) {
    if (fallback) return fallback;
    throw new HttpError('日期格式不正确，应为 YYYY-MM-DD');
  }
  if (!DATE_RE.test(value)) throw new HttpError('日期格式不正确，应为 YYYY-MM-DD');
  const d = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) throw new HttpError('日期无效');
  return value;
}

/** 校验月份参数（YYYY-MM），供整月视图使用 */
function normalizeMonth(raw, fallback = null) {
  const value = String(raw || '').trim();
  if (!value) {
    if (fallback) return fallback;
    throw new HttpError('月份格式不正确，应为 YYYY-MM');
  }
  if (!MONTH_RE.test(value)) throw new HttpError('月份格式不正确，应为 YYYY-MM');
  return value;
}

function toDto(row) {
  return {
    id: row.id,
    title: row.title,
    done: !!row.done,
    date: row.todo_date,
    order: row.sort_order,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function listTodos(env, userId, date) {
  const day = normalizeDate(date);
  const { results } = await env.DB.prepare(
    `SELECT * FROM todos
      WHERE user_id = ? AND todo_date = ?
      ORDER BY done ASC, sort_order ASC, created_at ASC`,
  )
    .bind(userId, day)
    .all();
  return (results || []).map(toDto);
}

/** 一次性取回所有日期，用于本地缓存/导出场景 */
async function listAllTodos(env, userId) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM todos WHERE user_id = ? ORDER BY todo_date DESC, sort_order ASC, created_at ASC`,
  )
    .bind(userId)
    .all();
  return (results || []).map(toDto);
}

/**
 * 取回某个整月的待办（按日期倒序、组内未完成在前），供「月视图」使用。
 * 上限 500 条，个人应用足够；超出时提示用户缩小范围。
 */
async function listByMonth(env, userId, rawMonth) {
  const month = normalizeMonth(rawMonth);
  const { results } = await env.DB.prepare(
    `SELECT * FROM todos
      WHERE user_id = ? AND todo_date >= ? AND todo_date < ?
      ORDER BY todo_date DESC, done ASC, sort_order ASC, created_at ASC
      LIMIT 501`,
  )
    .bind(userId, `${month}-01`, nextMonthStart(month))
    .all();

  const rows = results || [];
  if (rows.length > 500) {
    throw new HttpError('该月任务超过 500 条，请按日期缩小范围查看', 413);
  }
  return { month, todos: rows.map(toDto) };
}

/** 月份 +1 的起点日期（如 2025-10 → 2025-11-01），用于范围查询 */
function nextMonthStart(month) {
  const [y, m] = month.split('-').map(Number);
  const date = m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, '0')}-01`;
  return date;
}

async function countByDate(env, userId, date) {
  const day = normalizeDate(date);
  const row = await env.DB.prepare(
    `SELECT
        SUM(CASE WHEN done = 0 THEN 1 ELSE 0 END) AS remaining,
        COUNT(*) AS total
       FROM todos WHERE user_id = ? AND todo_date = ?`,
  )
    .bind(userId, day)
    .first();
  return {
    remaining: Number(row?.remaining || 0),
    total: Number(row?.total || 0),
  };
}

async function createTodo(env, userId, { title, date }) {
  const text = normalizeTitle(title);
  const day = normalizeDate(date);
  const ts = nowSeconds();

  const minRow = await env.DB.prepare(
    'SELECT MIN(sort_order) AS min_order FROM todos WHERE user_id = ? AND todo_date = ?',
  )
    .bind(userId, day)
    .first();

  // 新任务排在最上面
  const order = (Number(minRow?.min_order ?? 0) || 0) - 1;

  const id = newId('t_');
  await env.DB.prepare(
    `INSERT INTO todos (id, user_id, title, done, todo_date, sort_order, created_at, updated_at)
     VALUES (?, ?, ?, 0, ?, ?, ?, ?)`,
  )
    .bind(id, userId, text, day, order, ts, ts)
    .run();

  return {
    id,
    title: text,
    done: false,
    date: day,
    order,
    createdAt: ts,
    updatedAt: ts,
  };
}

async function updateTodo(env, userId, id, patch = {}) {
  const row = await env.DB.prepare('SELECT * FROM todos WHERE id = ? AND user_id = ?')
    .bind(id, userId)
    .first();
  if (!row) throw new HttpError('任务不存在或无权访问', 404);

  const sets = [];
  const values = [];

  if ('title' in patch) {
    sets.push('title = ?');
    values.push(normalizeTitle(patch.title));
  }
  if ('done' in patch) {
    sets.push('done = ?');
    values.push(patch.done ? 1 : 0);
  }
  if ('date' in patch) {
    sets.push('todo_date = ?');
    values.push(normalizeDate(patch.date));
  }
  if ('order' in patch) {
    const n = Number(patch.order);
    sets.push('sort_order = ?');
    values.push(Number.isFinite(n) ? n : 0);
  }

  if (!sets.length) return toDto(row);

  sets.push('updated_at = ?');
  values.push(nowSeconds());
  values.push(id, userId);

  await env.DB.prepare(`UPDATE todos SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`)
    .bind(...values)
    .run();

  const fresh = await env.DB.prepare('SELECT * FROM todos WHERE id = ?').bind(id).first();
  return toDto(fresh);
}

async function deleteTodo(env, userId, id) {
  const res = await env.DB.prepare('DELETE FROM todos WHERE id = ? AND user_id = ?')
    .bind(id, userId)
    .run();
  const changed = res?.meta?.changes ?? 0;
  if (!changed) throw new HttpError('任务不存在或已删除', 404);
  return { id };
}

/** 批量重排：body.ids 为按目标顺序排列的任务 id */
async function reorderTodos(env, userId, date, ids) {
  const day = normalizeDate(date);
  if (!Array.isArray(ids) || !ids.length) return { updated: 0 };

  const ts = nowSeconds();
  const stmts = ids.map((id, index) =>
    env.DB.prepare(
      'UPDATE todos SET sort_order = ?, updated_at = ? WHERE id = ? AND user_id = ? AND todo_date = ?',
    ).bind(index, ts, String(id), userId, day),
  );
  await env.DB.batch(stmts);
  return { updated: ids.length };
}

async function clearCompleted(env, userId, date) {
  const day = normalizeDate(date);
  const res = await env.DB.prepare(
    'DELETE FROM todos WHERE user_id = ? AND todo_date = ? AND done = 1',
  )
    .bind(userId, day)
    .run();
  return { removed: res?.meta?.changes ?? 0 };
}

/** 清除整个月份的已完成任务（月视图用） */
async function clearCompletedMonth(env, userId, rawMonth) {
  const month = normalizeMonth(rawMonth);
  const res = await env.DB.prepare(
    'DELETE FROM todos WHERE user_id = ? AND todo_date >= ? AND todo_date < ? AND done = 1',
  )
    .bind(userId, `${month}-01`, nextMonthStart(month))
    .run();
  return { removed: res?.meta?.changes ?? 0 };
}

async function toggleAll(env, userId, date, done) {
  const day = normalizeDate(date);
  const res = await env.DB.prepare(
    'UPDATE todos SET done = ?, updated_at = ? WHERE user_id = ? AND todo_date = ?',
  )
    .bind(done ? 1 : 0, nowSeconds(), userId, day)
    .run();
  return { updated: res?.meta?.changes ?? 0 };
}

/**
 * 把某天之前（含指定来源日期）所有未完成的任务顺延到目标日期。
 * 默认：把「今天之前」全部未完成项搬到今天。
 */
async function carryOver(env, userId, { from = null, to }) {
  const target = normalizeDate(to);
  const ts = nowSeconds();

  let rows;
  if (from) {
    const source = normalizeDate(from);
    const res = await env.DB.prepare(
      'SELECT * FROM todos WHERE user_id = ? AND todo_date = ? AND done = 0 ORDER BY sort_order ASC',
    )
      .bind(userId, source)
      .all();
    rows = res.results || [];
  } else {
    const res = await env.DB.prepare(
      'SELECT * FROM todos WHERE user_id = ? AND todo_date < ? AND done = 0 ORDER BY todo_date ASC, sort_order ASC',
    )
      .bind(userId, target)
      .all();
    rows = res.results || [];
  }

  if (!rows.length) return { moved: 0 };

  const minRow = await env.DB.prepare(
    'SELECT MIN(sort_order) AS min_order FROM todos WHERE user_id = ? AND todo_date = ?',
  )
    .bind(userId, target)
    .first();
  let order = (Number(minRow?.min_order ?? 0) || 0) - 1;

  const stmts = rows.map((row) => {
    const nextOrder = order;
    order -= 1;
    return env.DB.prepare(
      'UPDATE todos SET todo_date = ?, sort_order = ?, updated_at = ? WHERE id = ? AND user_id = ?',
    ).bind(target, nextOrder, ts, row.id, userId);
  });

  await env.DB.batch(stmts);
  return { moved: rows.length };
}

/** 全文搜索（LIKE，转义 %/_），按日期倒序，供前端搜索框使用 */
async function searchTodos(env, userId, rawQuery, limit = 50) {
  const q = String(rawQuery ?? '').trim().slice(0, 100);
  if (!q) return [];

  const like = `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
  const { results } = await env.DB.prepare(
    `SELECT * FROM todos
      WHERE user_id = ? AND title LIKE ? ESCAPE '\\'
      ORDER BY todo_date DESC, created_at DESC
      LIMIT ?`,
  )
    .bind(userId, like, Math.max(1, Math.min(100, Number(limit) || 50)))
    .all();
  return (results || []).map(toDto);
}

/** 提取标题里的 #标签 并按出现次数排序（个人应用量级，直接扫标题） */
async function listTags(env, userId, limit = 30) {
  const { results } = await env.DB.prepare('SELECT title FROM todos WHERE user_id = ?')
    .bind(userId)
    .all();

  const counter = new Map();
  for (const row of results || []) {
    const tags = String(row.title || '').match(TAG_RE);
    if (!tags) continue;
    for (const raw of tags) {
      const name = raw.slice(1);
      counter.set(name, (counter.get(name) || 0) + 1);
    }
  }

  return Array.from(counter, ([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'zh-Hans-CN'))
    .slice(0, Math.max(1, Math.min(100, Number(limit) || 30)));
}

/** 统计每个日期的待办数量，用于日历角标 */
async function statsByDate(env, userId, days = 30) {
  const { results } = await env.DB.prepare(
    `SELECT todo_date AS date,
            SUM(CASE WHEN done = 0 THEN 1 ELSE 0 END) AS remaining,
            COUNT(*) AS total
       FROM todos
      WHERE user_id = ?
      GROUP BY todo_date
      ORDER BY todo_date DESC
      LIMIT ?`,
  )
    .bind(userId, Math.max(1, Math.min(365, Number(days) || 30)))
    .all();
  return (results || []).map((r) => ({
    date: r.date,
    remaining: Number(r.remaining || 0),
    total: Number(r.total || 0),
  }));
}

/* ================================================================ *
 * src/lib/backup.js
 * ================================================================ */

/**
 * 云备份模块 —— 支持三种后端，可自由配置：
 *
 *   1. r2      Cloudflare R2 原生绑定（workers 里的 BACKUPS 绑定，无需任何密钥）
 *   2. s3      任意 S3 兼容对象存储（AWS S3 / R2 的 S3 接口 / MinIO / 阿里云 OSS / 七牛 / B2 ...）
 *              签名在 Worker 内用 WebCrypto 手写 AWS SigV4，无需 aws-sdk
 *   3. webdav  任意 WebDAV 服务（Nextcloud / 坚果云 / 群晖 / Box / 阿里云盘 WebDAV 网关 ...）
 *
 * 密钥读取优先级：页面配置 > Worker 环境变量（密钥/变量）
 *   BACKUP_S3_SECRET_KEY       S3 私钥
 *   BACKUP_WEBDAV_PASSWORD     WebDAV 密码
 *
 * 文件名：默认在扩展名前附加时间戳保留历史版本，例如
 *   todo-today.backup.json  →  todo-today.backup.20261015-215730.json
 * 同时始终刷新一份固定名的最新快照（todo-today.backup.json），
 * 「从云端恢复 / 测试连接」读的就是它，因此无论开不开时间戳都不受影响。
 */

const BACKUP_VERSION = 1;
const DEFAULT_FILE = 'todo-today.backup.json';

const EMPTY_CONFIG = {
  provider: 'none',   // none | r2 | s3 | webdav
  enabled: false,
  auto: false,        // 数据变更后自动备份
  intervalMin: 1,     // 变更触发备份的最短间隔（分钟），0 = 不限流
  scheduled: false,   // 定时备份（Cron 触发，不依赖操作）
  scheduleMin: 60,    // 定时备份周期（分钟）
  stamp: true,        // 文件名附加时间戳，保留历史版本
  tz: '',             // 用户时区（用于文件名时间戳，Cron 触发时没有请求上下文）
  file: DEFAULT_FILE,
  r2: { key: '' },
  s3: {
    endpoint: '',
    region: 'auto',
    bucket: '',
    accessKeyId: '',
    secretAccessKey: '',
    prefix: '',
    pathStyle: false,
  },
  webdav: { url: '', username: '', password: '', file: '' },
};

/** 变更触发备份的默认最短间隔（分钟） */
const DEFAULT_INTERVAL_MIN = 1;
/** 定时备份的最小周期（分钟）——Cron 每 5 分钟唤醒一次 */
const MIN_SCHEDULE_MIN = 5;
/** Cron 心跳超过这个秒数没更新，就认为定时任务没跑起来 */
const CRON_HEALTHY_SECONDS = 900;
const MAX_INTERVAL_MIN = 10080;          // 最多 7 天
const CRON_HEARTBEAT_ROW = '__cron__';   // 借用 settings 表存 Cron 心跳，避免改表结构

/* ============================== 文件名 / 时间戳 ============================== */

function tzParts(date, timeZone) {
  const options = {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  };
  const formatter = (tz) => new Intl.DateTimeFormat('en-US', { ...options, timeZone: tz });
  try {
    return formatter(timeZone || 'UTC').formatToParts(date);
  } catch {
    // 时区字符串非法（或运行环境不支持）→ 退回 UTC，绝不因此让备份失败
    return formatter('UTC').formatToParts(date);
  }
}

/**
 * 生成文件名用的时间戳：YYYYMMDD-HHmmss
 * 默认按 UTC；传入 IANA 时区（如 request.cf.timezone = 'Asia/Shanghai'）则按该时区，
 * 这样文件名里的时间与用户本地时钟一致。
 */
function fileStamp(date = new Date(), timeZone = 'UTC') {
  const parts = tzParts(date, timeZone);
  const get = (type) => parts.find((p) => p.type === type)?.value || '';
  return `${get('year')}${get('month')}${get('day')}-${get('hour')}${get('minute')}${get('second')}`;
}

/**
 * 把时间戳插到文件名的扩展名之前（对象键里的目录、前缀保持不变）：
 *   todo-today.backup.json        → todo-today.backup.20261015-215730.json
 *   todo/todo-today.backup.json   → todo/todo-today.backup.20261015-215730.json
 *   dump                          → dump.20261015-215730
 */
function stampKey(key, stamp) {
  const s = String(key || DEFAULT_FILE);
  const slash = s.lastIndexOf('/');
  const dir = slash >= 0 ? s.slice(0, slash + 1) : '';
  const name = (slash >= 0 ? s.slice(slash + 1) : s) || DEFAULT_FILE;
  const dot = name.lastIndexOf('.');
  if (dot > 0) return `${dir}${name.slice(0, dot)}.${stamp}${name.slice(dot)}`;
  return `${dir}${name}.${stamp}`;
}

/* ============================== 配置读写 ============================== */

function pickString(value, fallback = '') {
  return typeof value === 'string' ? value.trim() : fallback;
}

/** 把「分钟数」输入夹到合法范围；非数字则回退到兜底值 */
function pickMinutes(value, fallback, min) {
  const n = Math.round(Number(value));
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, min), MAX_INTERVAL_MIN);
}

/** 归一化 + 合并旧的加密字段（前端留空 = 不修改） */
function normalizeConfig(input = {}, previous = {}) {
  const provider = ['none', 'r2', 's3', 'webdav'].includes(input.provider)
    ? input.provider
    : 'none';

  const prevS3 = previous.s3 || {};
  const prevDav = previous.webdav || {};
  const prevR2 = previous.r2 || {};

  const s3Secret = pickString(input.s3?.secretAccessKey);
  const davPass = pickString(input.webdav?.password);

  return {
    provider,
    enabled: !!input.enabled && provider !== 'none',
    auto: !!input.auto,
    // 备份频率：变更触发的最短间隔 / 定时备份周期（都可自行设置）
    intervalMin: pickMinutes(input.intervalMin, previous.intervalMin ?? DEFAULT_INTERVAL_MIN, 0),
    scheduled: !!input.scheduled,
    scheduleMin: pickMinutes(input.scheduleMin, previous.scheduleMin ?? 60, MIN_SCHEDULE_MIN),
    // 默认开启：未显式关闭就附加时间戳
    stamp: input.stamp === undefined ? previous.stamp !== false : !!input.stamp,
    tz: pickString(input.tz) || pickString(previous.tz) || '',
    file: pickString(input.file) || DEFAULT_FILE,
    r2: {
      key: pickString(input.r2?.key) || prevR2.key || '',
    },
    s3: {
      endpoint: pickString(input.s3?.endpoint).replace(/\/+$/, ''),
      region: pickString(input.s3?.region) || 'auto',
      bucket: pickString(input.s3?.bucket),
      accessKeyId: pickString(input.s3?.accessKeyId),
      // 留空则沿用旧值（前端不回显真实私钥）
      secretAccessKey: s3Secret || prevS3.secretAccessKey || '',
      prefix: pickString(input.s3?.prefix).replace(/^\/+/, ''),
      pathStyle: !!input.s3?.pathStyle,
    },
    webdav: {
      url: pickString(input.webdav?.url).replace(/\/+$/, ''),
      username: pickString(input.webdav?.username),
      password: davPass || prevDav.password || '',
      file: pickString(input.webdav?.file) || '',
    },
  };
}

/** 返回给前端时抹掉真实密钥，只告知「是否已配置」 */
function maskConfig(config = EMPTY_CONFIG, env = {}) {
  const s3Secret = config.s3?.secretAccessKey || env.BACKUP_S3_SECRET_KEY || '';
  const davPass = config.webdav?.password || env.BACKUP_WEBDAV_PASSWORD || '';
  return {
    provider: config.provider || 'none',
    enabled: !!config.enabled,
    auto: !!config.auto,
    intervalMin: config.intervalMin ?? DEFAULT_INTERVAL_MIN,
    scheduled: !!config.scheduled,
    scheduleMin: config.scheduleMin ?? 60,
    stamp: config.stamp !== false,
    tz: config.tz || '',
    file: config.file || DEFAULT_FILE,
    r2: { key: config.r2?.key || '' },
    hasR2Binding: !!env.BACKUPS,
    s3: {
      endpoint: config.s3?.endpoint || '',
      region: config.s3?.region || 'auto',
      bucket: config.s3?.bucket || '',
      accessKeyId: config.s3?.accessKeyId || '',
      secretAccessKey: '',                    // 永不回显
      hasSecretKey: !!s3Secret,
      secretFromEnv: !config.s3?.secretAccessKey && !!env.BACKUP_S3_SECRET_KEY,
      prefix: config.s3?.prefix || '',
      pathStyle: !!config.s3?.pathStyle,
    },
    webdav: {
      url: config.webdav?.url || '',
      username: config.webdav?.username || '',
      password: '',                            // 永不回显
      hasPassword: !!davPass,
      passwordFromEnv: !config.webdav?.password && !!env.BACKUP_WEBDAV_PASSWORD,
      file: config.webdav?.file || '',
    },
  };
}

async function readConfig(env, userId) {
  const row = await env.DB.prepare('SELECT backup_json, last_backup FROM settings WHERE user_id = ?')
    .bind(userId)
    .first();
  let config = { ...EMPTY_CONFIG };
  if (row?.backup_json) {
    try {
      config = normalizeConfig(JSON.parse(row.backup_json), {});
    } catch {
      config = { ...EMPTY_CONFIG };
    }
  }
  return { config, lastBackup: row?.last_backup || null };
}

async function writeConfig(env, userId, config) {
  const ts = nowSeconds();
  const payload = JSON.stringify(config);
  await env.DB.prepare(
    `INSERT INTO settings (user_id, backup_json, last_backup, updated_at)
     VALUES (?, ?, NULL, ?)
     ON CONFLICT(user_id) DO UPDATE SET backup_json = excluded.backup_json, updated_at = excluded.updated_at`,
  )
    .bind(userId, payload, ts)
    .run();
  return config;
}

/* ============================== 备份载荷 ============================== */

async function buildPayload(env, user) {
  const todos = await listAllTodos(env, user.id);
  return {
    app: 'todo-today',
    version: BACKUP_VERSION,
    exportedAt: new Date().toISOString(),
    user: { username: user.username },
    stats: {
      total: todos.length,
      remaining: todos.filter((t) => !t.done).length,
    },
    todos,
  };
}

async function applyPayload(env, user, payload, { mode = 'merge' } = {}) {
  if (!payload || !Array.isArray(payload.todos)) {
    throw new HttpError('备份内容格式不正确：缺少 todos 数组');
  }

  const ts = nowSeconds();
  const cleaned = [];
  for (const item of payload.todos) {
    const title = String(item?.title ?? '').replace(/\s+/g, ' ').trim();
    const date = String(item?.date ?? '').trim();
    if (!title || !/^\d{4}-\d{2}-\d{2}$/.test(date)) continue;
    cleaned.push({
      title: title.slice(0, 500),
      done: item.done ? 1 : 0,
      date,
      order: Number.isFinite(Number(item.order)) ? Number(item.order) : 0,
      createdAt: Number(item.createdAt) || ts,
    });
  }

  if (mode === 'replace') {
    await env.DB.prepare('DELETE FROM todos WHERE user_id = ?').bind(user.id).run();
  }

  let inserted = 0;
  let skipped = 0;

  if (mode !== 'replace') {
    // 合并模式：同一天 + 同标题 + 同完成状态视为重复，跳过
    const { results } = await env.DB.prepare(
      'SELECT title, done, todo_date FROM todos WHERE user_id = ?',
    )
      .bind(user.id)
      .all();
    const seen = new Set((results || []).map((r) => `${r.todo_date}|${r.done}|${r.title}`));

    const stmts = [];
    for (const t of cleaned) {
      if (seen.has(`${t.date}|${t.done}|${t.title}`)) {
        skipped += 1;
        continue;
      }
      seen.add(`${t.date}|${t.done}|${t.title}`);
      stmts.push(
        env.DB.prepare(
          `INSERT INTO todos (id, user_id, title, done, todo_date, sort_order, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        ).bind(`t_${crypto.randomUUID().replace(/-/g, '')}`, user.id, t.title, t.done, t.date, t.order, t.createdAt, ts),
      );
      inserted += 1;
    }
    if (stmts.length) await env.DB.batch(stmts);
  } else {
    const stmts = cleaned.map((t) =>
      env.DB.prepare(
        `INSERT INTO todos (id, user_id, title, done, todo_date, sort_order, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(`t_${crypto.randomUUID().replace(/-/g, '')}`, user.id, t.title, t.done, t.date, t.order, t.createdAt, ts),
    );
    if (stmts.length) await env.DB.batch(stmts);
    inserted = stmts.length;
  }

  return { inserted, skipped, total: cleaned.length, mode };
}

/* ============================== S3 SigV4 ============================== */

function rfc3986Encode(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function encodeObjectKey(key) {
  return String(key)
    .split('/')
    .map((seg) => rfc3986Encode(seg))
    .filter((seg) => seg.length > 0)
    .join('/');
}

/** 2015-08-30T12:36:00.000Z -> 20150830T123600Z */
function toAmzDate(date) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

/** 头值规范化：去掉首尾空白，内部连续空白压成一个空格 */
function normalizeHeaderValue(value) {
  return String(value).trim().replace(/\s+/g, ' ');
}

/** 规范化查询串：按键名（其次键值）排序，RFC3986 编码 */
function canonicalQueryString(searchParams) {
  const pairs = [];
  for (const [k, v] of searchParams.entries()) {
    pairs.push([rfc3986Encode(k), rfc3986Encode(v)]);
  }
  pairs.sort((a, b) => {
    if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
    if (a[1] !== b[1]) return a[1] < b[1] ? -1 : 1;
    return 0;
  });
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
}

/**
 * 通用 AWS Signature Version 4 签名（header-based）。
 *
 * 独立出来是为了能被测试直接调用：用 AWS 官方 aws-sig-v4-test-suite 的
 * 测试向量做回归验证。生产代码 path 由 s3Fetch 调用。
 *
 * @returns {Promise<{authorization:string, headers:object, canonicalRequest:string, stringToSign:string}>}
 */
async function signRequest({
  method = 'GET',
  url,
  headers = {},
  body = '',
  accessKeyId,
  secretAccessKey,
  region = 'us-east-1',
  service = 's3',
  date = new Date(),
  addContentSha256 = true,
}) {
  const u = new URL(url);
  const amzDate = toAmzDate(date);
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256Hex(body ?? '');

  // 1) 收集并规范化待签名头
  const H = {};
  for (const [k, v] of Object.entries(headers)) {
    H[String(k).toLowerCase()] = normalizeHeaderValue(v);
  }
  if (!H.host) H.host = u.host;
  if (!H['x-amz-date']) H['x-amz-date'] = amzDate;
  // 使用 SigV4 + S3 时必须有它，值就是负载的 SHA256
  if (addContentSha256 && !H['x-amz-content-sha256']) H['x-amz-content-sha256'] = payloadHash;

  const names = Object.keys(H).sort();
  const canonicalHeaders = names.map((n) => `${n}:${H[n]}\n`).join('');
  const signedHeaders = names.join(';');

  // 2) 规范化请求
  const canonicalRequest = [
    String(method).toUpperCase(),
    u.pathname || '/',
    canonicalQueryString(u.searchParams),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  // 3) 待签字符串
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join('\n');

  // 4) 派生签名密钥（HMAC 链）
  const enc = new TextEncoder();
  const kDate = await hmacSha256(enc.encode(`AWS4${secretAccessKey}`), dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, 'aws4_request');
  const signature = toHex(await hmacSha256(kSigning, stringToSign));

  // 5) 组装 Authorization
  const authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    authorization,
    headers: { ...H, authorization },
    canonicalRequest,
    stringToSign,
    payloadHash,
    amzDate,
  };
}

/** 把 s3 配置（含 env 兜底）解析成完整参数 */
function resolveS3(env, config) {
  const s3 = config.s3 || {};
  const secretAccessKey = s3.secretAccessKey || env.BACKUP_S3_SECRET_KEY || '';
  if (!s3.endpoint) throw new HttpError('S3 备份缺少 endpoint（服务地址）');
  if (!s3.bucket) throw new HttpError('S3 备份缺少 bucket');
  if (!s3.accessKeyId) throw new HttpError('S3 备份缺少 Access Key ID');
  if (!secretAccessKey) {
    throw new HttpError('S3 备份缺少 Secret Access Key（可在设置里填写，或配置 Worker 密钥 BACKUP_S3_SECRET_KEY）');
  }
  return {
    endpoint: s3.endpoint,
    region: s3.region || 'auto',
    bucket: s3.bucket,
    accessKeyId: s3.accessKeyId,
    secretAccessKey,
    pathStyle: !!s3.pathStyle,
  };
}

function objectKeyOf(config, provider) {
  if (provider === 'webdav') return config.webdav?.file || config.file || DEFAULT_FILE;
  if (provider === 'r2') return config.r2?.key || config.file || DEFAULT_FILE;
  const prefix = (config.s3?.prefix || '').replace(/^\/+/, '');
  const file = config.file || DEFAULT_FILE;
  return `${prefix}${file}`;
}

/**
 * 用 AWS SigV4 发起一次 S3 请求。
 * @returns {Promise<Response>}
 */
async function s3Fetch(env, config, {
  method = 'GET',
  key,
  body = null,
  contentType = null,
  extraHeaders = {},
  date = new Date(),
}) {
  const s3 = resolveS3(env, config);
  const u = new URL(s3.endpoint);
  const port = u.port ? `:${u.port}` : '';
  const host = s3.pathStyle ? `${u.hostname}${port}` : `${s3.bucket}.${u.hostname}${port}`;
  const basePath = u.pathname.replace(/\/+$/, '');
  const canonicalUri = `${basePath}${s3.pathStyle ? `/${rfc3986Encode(s3.bucket)}` : ''}/${encodeObjectKey(key)}`;
  const requestUrl = `${u.protocol}//${host}${canonicalUri}`;

  const payload = body == null ? '' : body;
  const headers = { ...extraHeaders };
  if (contentType) headers['content-type'] = contentType;

  const { headers: signed } = await signRequest({
    method,
    url: requestUrl,
    headers,
    body: payload,
    accessKeyId: s3.accessKeyId,
    secretAccessKey: s3.secretAccessKey,
    region: s3.region,
    service: 's3',
    date,
  });

  return fetch(requestUrl, {
    method,
    headers: signed,
    body: method === 'GET' || method === 'HEAD' ? undefined : payload,
  });
}

/* ============================== 三种后端 ============================== */

async function putObject(env, config, key, text) {
  const provider = config.provider;

  if (provider === 'r2') {
    if (!env.BACKUPS) {
      throw new HttpError('未绑定 R2 存储桶：请在 wrangler.jsonc 中启用 r2_buckets（BACKUPS），并部署');
    }
    await env.BACKUPS.put(key, text, {
      httpMetadata: { contentType: 'application/json; charset=utf-8' },
    });
    return { provider, key, skipped: false };
  }

  if (provider === 's3') {
    const res = await s3Fetch(env, config, {
      method: 'PUT',
      key,
      body: text,
      contentType: 'application/json; charset=utf-8',
    });
    if (!res.ok) {
      const detail = await safeText(res);
      throw new HttpError(`S3 上传失败 (${res.status})：${detail}`);
    }
    return { provider, key, skipped: false };
  }

  if (provider === 'webdav') {
    const dav = config.webdav || {};
    if (!dav.url) throw new HttpError('WebDAV 备份缺少地址');
    if (!dav.username) throw new HttpError('WebDAV 备份缺少用户名');
    const password = dav.password || env.BACKUP_WEBDAV_PASSWORD || '';
    if (!password) {
      throw new HttpError('WebDAV 备份缺少密码（可在设置里填写，或配置 Worker 密钥 BACKUP_WEBDAV_PASSWORD）');
    }
    const target = `${dav.url.replace(/\/+$/, '')}/${key.split('/').map(encodeURIComponent).join('/')}`;
    const res = await fetch(target, {
      method: 'PUT',
      headers: {
        Authorization: basicAuthHeader(dav.username, password),
        'Content-Type': 'application/json; charset=utf-8',
      },
      body: text,
    });
    if (!res.ok) {
      const detail = await safeText(res);
      throw new HttpError(`WebDAV 上传失败 (${res.status})：${detail}`);
    }
    return { provider, key, skipped: false };
  }

  throw new HttpError('未配置备份方式');
}

async function getObject(env, config, key) {
  const provider = config.provider;

  if (provider === 'r2') {
    if (!env.BACKUPS) throw new HttpError('未绑定 R2 存储桶');
    const obj = await env.BACKUPS.get(key);
    if (!obj) throw new HttpError('云端还没有备份文件', 404);
    return await obj.text();
  }

  if (provider === 's3') {
    const res = await s3Fetch(env, config, { method: 'GET', key });
    if (res.status === 404) throw new HttpError('云端还没有备份文件', 404);
    if (!res.ok) throw new HttpError(`S3 读取失败 (${res.status})：${await safeText(res)}`);
    return await res.text();
  }

  if (provider === 'webdav') {
    const dav = config.webdav || {};
    const password = dav.password || env.BACKUP_WEBDAV_PASSWORD || '';
    const target = `${dav.url.replace(/\/+$/, '')}/${key.split('/').map(encodeURIComponent).join('/')}`;
    const res = await fetch(target, {
      method: 'GET',
      headers: { Authorization: basicAuthHeader(dav.username, password) },
    });
    if (res.status === 404) throw new HttpError('云端还没有备份文件', 404);
    if (!res.ok) throw new HttpError(`WebDAV 读取失败 (${res.status})：${await safeText(res)}`);
    return await res.text();
  }

  throw new HttpError('未配置备份方式');
}

async function headObject(env, config, key) {
  const provider = config.provider;

  if (provider === 'r2') {
    if (!env.BACKUPS) throw new HttpError('未绑定 R2 存储桶');
    const head = await env.BACKUPS.head(key);
    return { ok: true, exists: !!head, size: head?.size ?? 0, uploaded: head?.uploaded?.toISOString?.() || null };
  }

  if (provider === 's3') {
    const res = await s3Fetch(env, config, { method: 'HEAD', key });
    if (res.ok) {
      return { ok: true, exists: true, size: Number(res.headers.get('content-length') || 0) };
    }
    if (res.status === 404) return { ok: true, exists: false };
    throw new HttpError(`S3 连通性检查失败 (${res.status})：${await safeText(res)}`);
  }

  if (provider === 'webdav') {
    const dav = config.webdav || {};
    const password = dav.password || env.BACKUP_WEBDAV_PASSWORD || '';
    const target = `${dav.url.replace(/\/+$/, '')}/${key.split('/').map(encodeURIComponent).join('/')}`;
    const res = await fetch(target, {
      method: 'HEAD',
      headers: { Authorization: basicAuthHeader(dav.username, password) },
    });
    if (res.ok) return { ok: true, exists: true, size: Number(res.headers.get('content-length') || 0) };
    if (res.status === 404 || res.status === 405) return { ok: true, exists: false };
    throw new HttpError(`WebDAV 连通性检查失败 (${res.status})：${await safeText(res)}`);
  }

  throw new HttpError('未配置备份方式');
}

async function safeText(res) {
  try {
    const t = await res.text();
    return t.slice(0, 300) || res.statusText || '无详细信息';
  } catch {
    return res.statusText || '无详细信息';
  }
}

/* ============================== 对外入口 ============================== */

async function runBackup(env, user, config, { timeZone = 'UTC', now = new Date() } = {}) {
  if (!config || config.provider === 'none') throw new HttpError('未配置备份方式');

  const latestKey = objectKeyOf(config, config.provider);
  const payload = await buildPayload(env, user);
  const text = JSON.stringify(payload, null, 2);

  // 1) 固定名「最新快照」先写：「从云端恢复 / 测试连接」读的就是它，保证这两条路永不失效
  const result = await putObject(env, config, latestKey, text);
  const keys = [latestKey];

  // 2) 带时间戳的历史版本（可在设置里关闭）
  let historyKey = null;
  if (config.stamp !== false) {
    historyKey = stampKey(latestKey, fileStamp(now, timeZone));
    try {
      await putObject(env, config, historyKey, text);
      keys.push(historyKey);
    } catch (err) {
      throw new HttpError(
        `历史版本写入失败（最新快照已更新）：${err?.message || err}`,
        err instanceof HttpError ? err.status : 502,
      );
    }
  }

  await env.DB.prepare('UPDATE settings SET last_backup = ?, updated_at = ? WHERE user_id = ?')
    .bind(nowSeconds(), nowSeconds(), user.id)
    .run();

  return {
    ...result,
    key: historyKey || latestKey,   // 本次实际写入的（带时间戳的）文件名
    latestKey,                      // 固定名快照
    historyKey,
    keys,
    stamped: !!historyKey,
    size: new TextEncoder().encode(text).length,
    total: payload.stats.total,
    remaining: payload.stats.remaining,
    at: payload.exportedAt,
  };
}

async function testConnection(env, config) {
  if (!config || config.provider === 'none') throw new HttpError('未配置备份方式');
  const key = objectKeyOf(config, config.provider);
  const info = await headObject(env, config, key);
  return { provider: config.provider, key, ...info };
}

async function restoreBackup(env, user, config, mode = 'merge') {
  if (!config || config.provider === 'none') throw new HttpError('未配置备份方式');
  const key = objectKeyOf(config, config.provider);
  const text = await getObject(env, config, key);

  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new HttpError('云端备份文件不是合法 JSON');
  }

  const result = await applyPayload(env, user, payload, { mode });
  return { ...result, exportedAt: payload.exportedAt || null, key };
}

/**
 * 数据变更后的自动备份。节流窗口由用户在设置里自行配置（config.intervalMin 分钟，0 = 不限流）。
 * 用 ctx.waitUntil 调用，不阻塞用户请求。
 */
async function maybeAutoBackup(env, user, { timeZone = '' } = {}) {
  try {
    const { config, lastBackup } = await readConfig(env, user.id);
    if (!config.enabled || !config.auto || config.provider === 'none') return;

    const intervalSec = Math.max(0, config.intervalMin ?? DEFAULT_INTERVAL_MIN) * 60;
    if (intervalSec > 0 && lastBackup && nowSeconds() - lastBackup < intervalSec) return;

    const result = await runBackup(env, user, config, { timeZone: timeZone || config.tz });
    console.log(`[auto-backup] user=${user.id} provider=${config.provider} key=${result.key} ok`);
  } catch (err) {
    console.error(`[auto-backup] 失败：${err?.message || err}`);
  }
}

/* ============================== 定时备份（Cron） ============================== */

/**
 * 记住用户的时区，供「定时备份」拼文件名用
 * （Cron 触发时没有请求上下文，拿不到 request.cf.timezone）。
 * 只在时区变化时写库，返回最新的 config。
 */
async function rememberTimeZone(env, userId, config, timeZone) {
  const tz = pickString(timeZone);
  if (!tz || config.tz === tz) return config;
  const next = { ...config, tz };
  await writeConfig(env, userId, next);
  return next;
}

/** 记录一次 Cron 心跳（借用 settings 表，backup_json 保持 NULL 以免被当成用户配置） */
async function touchCronHeartbeat(env, at = nowSeconds()) {
  await env.DB.prepare(
    `INSERT INTO settings (user_id, backup_json, last_backup, updated_at)
     VALUES (?, NULL, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET last_backup = excluded.last_backup, updated_at = excluded.updated_at`,
  )
    .bind(CRON_HEARTBEAT_ROW, at, at)
    .run();
  return at;
}

/** 查询 Cron 是否真的在跑（设置页用它提示「定时任务未生效」） */
async function readCronStatus(env) {
  try {
    const row = await env.DB.prepare('SELECT last_backup FROM settings WHERE user_id = ?')
      .bind(CRON_HEARTBEAT_ROW)
      .first();
    const lastRun = row?.last_backup || null;
    return {
      lastRun,
      healthy: !!lastRun && nowSeconds() - lastRun < CRON_HEALTHY_SECONDS,
      intervalSeconds: MIN_SCHEDULE_MIN * 60,
    };
  } catch {
    return { lastRun: null, healthy: false, intervalSeconds: MIN_SCHEDULE_MIN * 60 };
  }
}

/** 取当前时间戳（Cron 的 event.scheduledTime，缺省用当前时间） */
function cronNow(event) {
  const ms = Number(event?.scheduledTime);
  return Number.isFinite(ms) && ms > 0 ? Math.floor(ms / 1000) : nowSeconds();
}

/**
 * Cron 定时备份：每 5 分钟被唤醒一次，只给「到点」的用户做备份。
 * 周期由用户自己配置（config.scheduleMin 分钟，最小 MIN_SCHEDULE_MIN）。
 * @returns {Promise<{checked:number,due:number,ok:number,failed:Array}>}
 */
async function runScheduledBackups(env, { now = nowSeconds() } = {}) {
  await touchCronHeartbeat(env, now);

  const { results } = await env.DB.prepare(
    `SELECT s.user_id AS user_id, s.backup_json AS backup_json,
            s.last_backup AS last_backup, u.username AS username
       FROM settings s
       JOIN users u ON u.id = s.user_id
      WHERE s.backup_json IS NOT NULL`,
  ).all();

  const report = { checked: (results || []).length, due: 0, ok: 0, failed: [] };

  for (const row of results || []) {
    let config;
    try {
      config = normalizeConfig(JSON.parse(row.backup_json), {});
    } catch {
      continue;   // 配置坏了就跳过，别让一个用户拖垮整轮
    }
    if (!config.enabled || !config.scheduled || config.provider === 'none') continue;

    const periodSec = Math.max(MIN_SCHEDULE_MIN, config.scheduleMin || 60) * 60;
    if (row.last_backup && now - row.last_backup < periodSec) continue;

    report.due += 1;
    try {
      const result = await runBackup(
        env,
        { id: row.user_id, username: row.username || 'user' },
        config,
        { timeZone: config.tz, now: new Date(now * 1000) },
      );
      report.ok += 1;
      console.log(`[cron-backup] user=${row.user_id} key=${result.key} ok`);
    } catch (err) {
      report.failed.push({ user: row.user_id, error: err?.message || String(err) });
      console.error(`[cron-backup] user=${row.user_id} 失败：${err?.message || err}`);
    }
  }

  return report;
}

/* ================================================================ *
 * 命名空间（等价于原文件的 import * as xxx）
 * ================================================================ */

const auth = {
  SESSION_COOKIE,
  HttpError,
  nowSeconds,
  register,
  login,
  createSession,
  sessionCookie,
  destroySession,
  purgeExpiredSessions,
  getSessionUser,
  requireUser,
  changePassword,
};

const todos = {
  DATE_RE,
  MONTH_RE,
  normalizeDate,
  normalizeMonth,
  listTodos,
  listAllTodos,
  listByMonth,
  countByDate,
  createTodo,
  updateTodo,
  deleteTodo,
  reorderTodos,
  clearCompleted,
  clearCompletedMonth,
  toggleAll,
  carryOver,
  searchTodos,
  listTags,
  statsByDate,
};

const backup = {
  BACKUP_VERSION,
  DEFAULT_FILE,
  DEFAULT_INTERVAL_MIN,
  MIN_SCHEDULE_MIN,
  CRON_HEALTHY_SECONDS,
  fileStamp,
  stampKey,
  normalizeConfig,
  maskConfig,
  readConfig,
  writeConfig,
  buildPayload,
  applyPayload,
  signRequest,
  s3Fetch,
  runBackup,
  testConnection,
  restoreBackup,
  maybeAutoBackup,
  rememberTimeZone,
  touchCronHeartbeat,
  readCronStatus,
  cronNow,
  runScheduledBackups,
};

/* ================================================================ *
 * src/index.js（入口，export default 由 Cloudflare 识别）
 * ================================================================ */

/**
 * 今日待办 · Cloudflare Worker 入口
 *
 * 路由策略：
 *   /api/*  -> 由本 Worker 处理
 *   其它    -> 交给静态资源绑定 ASSETS（public/ 目录）
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith('/api/')) {
      return serveStatic(request, env);
    }

    try {
      return await route(request, env, ctx, url);
    } catch (err) {
      const status = err instanceof auth.HttpError ? err.status : 500;
      if (status >= 500) console.error('[api-error]', err?.stack || err);
      return fail(explainError(err, status), status);
    }
  },

  /**
   * 定时备份：由 Cron Trigger 唤起（默认每 5 分钟一次），
   * 只对「配置了定时备份且已到周期」的用户真正执行上传。
   */
  async scheduled(event, env, ctx) {
    const task = (async () => {
      try {
        const report = await backup.runScheduledBackups(env, { now: backup.cronNow(event) });
        console.log('[cron] 完成', JSON.stringify(report));
        return report;
      } catch (err) {
        console.error('[cron] 失败', err?.stack || err);
        return null;
      }
    })();
    if (ctx?.waitUntil) ctx.waitUntil(task);
    return task;   // 也直接返回，便于本地调用 / 测试拿到结果
  },
};

const REQUIRED_TABLES = ['users', 'sessions', 'todos', 'settings'];

/**
 * 把底层报错翻译成「能照着做」的提示。
 * 最常见的一类是 D1 建好了但没执行过 schema.sql，原始报文只有
 * "D1_ERROR: no such table: users: SQLITE_ERROR"，对使用者毫无指向性。
 */
function explainError(err, status) {
  const raw = String(err?.message || err || '');
  if (status < 500) return raw || '请求有误';

  if (/no such table/i.test(raw)) {
    const table = raw.match(/no such table:\s*([^\s:]+)/i)?.[1] || '数据表';
    return `数据库尚未初始化（缺少 ${table}）。请在 Cloudflare 控制台进入 D1 → 选择该数据库 → Console，粘贴执行项目里的 schema.sql；`
      + '或在本地执行 npm run db:remote。执行完访问 /api/health?check=1 可确认。';
  }
  if (/no such column/i.test(raw)) {
    return '数据库表结构过旧（缺少字段）。请重新执行一遍 schema.sql 升级表结构，再访问 /api/health?check=1 确认。';
  }
  if (/UNIQUE constraint failed/i.test(raw)) {
    return '该记录已存在（唯一约束冲突）。';
  }
  if (/network connection lost|internal error|storage.*(error|failure)/i.test(raw)) {
    return '数据库暂时不可用，请稍后重试。';
  }
  return raw || '服务器内部错误';
}

/** 连库核对必需的数据表是否都已建好，供 /api/health?check=1 使用 */
async function inspectSchema(env) {
  try {
    const { results } = await env.DB
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all();
    const existing = new Set((results || []).map((r) => r.name));
    const tables = REQUIRED_TABLES.filter((t) => existing.has(t));
    const missing = REQUIRED_TABLES.filter((t) => !existing.has(t));
    return {
      ok: missing.length === 0,
      tables,
      missing,
      hint: missing.length
        ? '缺少数据表：在 Cloudflare 控制台进入该 D1 数据库 → Console，执行 schema.sql 后重试'
        : '数据表齐全',
    };
  } catch (err) {
    return {
      ok: false,
      error: String(err?.message || err),
      hint: '无法读取数据库结构：请确认 Worker 的绑定名称是 DB，且指向的是正确的数据库',
    };
  }
}

/**
 * 静态资源：
 *  1. 有 ASSETS 绑定时交给它（wrangler / Workers Builds 部署）
 *  2. 否则回落到内联资源表（单文件粘贴到网页控制台的部署方式）
 */
async function serveStatic(request, env) {
  if (env.ASSETS) return env.ASSETS.fetch(request);

  if (INLINE_ASSETS) {
    const { pathname } = new URL(request.url);
    const path = pathname === '/' ? '/index.html' : pathname;
    const asset = INLINE_ASSETS[path];
    if (asset) {
      return new Response(request.method === 'HEAD' ? null : asset.body, {
        status: 200,
        headers: {
          'content-type': asset.type,
          'cache-control': path === '/index.html'
            ? 'no-cache'
            : 'public, max-age=3600',
        },
      });
    }
  }

  return new Response('Not Found', { status: 404 });
}

/* ============================== 路由 ============================== */

async function route(request, env, ctx, url) {
  const path = url.pathname.replace(/\/+$/, '') || '/api';
  const method = request.method.toUpperCase();

  // 数据库绑定体检
  if (!env.DB && path !== '/api/health') {
    return fail('未绑定 D1 数据库：请先创建数据库并在 wrangler.jsonc 中配置 d1_databases', 503);
  }

  /* ---------- 健康检查 ---------- */
  // /api/health          只报绑定情况，不碰数据库
  // /api/health?check=1  额外连库核对数据表是否已建好（部署后自查用）
  if (path === '/api/health' && method === 'GET') {
    const payload = {
      app: env.APP_NAME || '今日待办',
      time: new Date().toISOString(),
      db: !!env.DB,
      r2: !!env.BACKUPS,
      registration: String(env.ALLOW_REGISTRATION ?? 'true').toLowerCase() !== 'false',
    };
    if (url.searchParams.get('check') === '1' && env.DB) {
      payload.schema = await inspectSchema(env);
    }
    return ok(payload);
  }

  /* ---------- 认证 ---------- */
  if (path === '/api/auth/register' && method === 'POST') {
    const body = await readJson(request);
    const user = await auth.register(env, body);
    const token = await auth.createSession(env, user.id);
    ctx.waitUntil(auth.purgeExpiredSessions(env));
    return json({ ok: true, user }, { headers: { 'set-cookie': auth.sessionCookie(request, token) } });
  }

  if (path === '/api/auth/login' && method === 'POST') {
    const body = await readJson(request);
    const user = await auth.login(env, body);
    const token = await auth.createSession(env, user.id);
    ctx.waitUntil(auth.purgeExpiredSessions(env));
    return json({ ok: true, user }, { headers: { 'set-cookie': auth.sessionCookie(request, token) } });
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    const token = (await auth.getSessionUser(request, env))?.token;
    await auth.destroySession(env, token);
    return json({ ok: true }, { headers: { 'set-cookie': auth.sessionCookie(request, '') } });
  }

  if (path === '/api/auth/me' && method === 'GET') {
    const user = await auth.getSessionUser(request, env);
    return ok({ user: user ? { id: user.id, username: user.username, createdAt: user.createdAt } : null });
  }

  if (path === '/api/auth/password' && method === 'POST') {
    const user = await auth.requireUser(request, env);
    const body = await readJson(request);
    await auth.changePassword(env, user, body);
    return ok({ message: '密码已更新，其它设备需重新登录' });
  }

  /* ---------- 待办 ---------- */
  if (path === '/api/todos' && method === 'GET') {
    const user = await auth.requireUser(request, env);

    // 整月视图：/api/todos?month=YYYY-MM
    if (url.searchParams.get('month')) {
      const { month, todos: list } = await todos.listByMonth(env, user.id, url.searchParams.get('month'));
      const remaining = list.filter((t) => !t.done).length;
      return ok({ month, todos: list, remaining, total: list.length });
    }

    const date = todos.normalizeDate(url.searchParams.get('date'));
    const list = await todos.listTodos(env, user.id, date);
    const stat = await todos.countByDate(env, user.id, date);
    return ok({ date, todos: list, ...stat });
  }

  if (path === '/api/todos' && method === 'POST') {
    const user = await auth.requireUser(request, env);
    const body = await readJson(request);
    const todo = await todos.createTodo(env, user.id, body);
    const stat = await todos.countByDate(env, user.id, todo.date);
    scheduleAutoBackup(ctx, env, user, request.cf?.timezone);
    return json({ ok: true, todo, ...stat }, { status: 201 });
  }

  if (path === '/api/todos/batch' && method === 'POST') {
    const user = await auth.requireUser(request, env);
    const body = await readJson(request);
    // 按月操作时（如 clear-completed + month）可以不带 date
    const date = todos.normalizeDate(body.date, '1970-01-01');

    if (body.action === 'clear-completed') {
      // 支持按月清除：{ action: 'clear-completed', month: 'YYYY-MM' }
      if (body.month) {
        const res = await todos.clearCompletedMonth(env, user.id, body.month);
        scheduleAutoBackup(ctx, env, user, request.cf?.timezone);
        return ok(res);
      }
      const res = await todos.clearCompleted(env, user.id, date);
      const stat = await todos.countByDate(env, user.id, date);
      scheduleAutoBackup(ctx, env, user, request.cf?.timezone);
      return ok({ ...res, ...stat });
    }

    if (body.action === 'toggle-all') {
      const res = await todos.toggleAll(env, user.id, date, !!body.done);
      const stat = await todos.countByDate(env, user.id, date);
      scheduleAutoBackup(ctx, env, user, request.cf?.timezone);
      return ok({ ...res, ...stat });
    }

    if (body.action === 'reorder') {
      const res = await todos.reorderTodos(env, user.id, date, body.ids);
      scheduleAutoBackup(ctx, env, user, request.cf?.timezone);
      return ok(res);
    }

    if (body.action === 'carry-over') {
      const res = await todos.carryOver(env, user.id, { from: body.from || null, to: date });
      const list = await todos.listTodos(env, user.id, date);
      const stat = await todos.countByDate(env, user.id, date);
      scheduleAutoBackup(ctx, env, user, request.cf?.timezone);
      return ok({ ...res, todos: list, ...stat });
    }

    return fail('未知的批量操作');
  }

  if (path === '/api/todos/stats' && method === 'GET') {
    const user = await auth.requireUser(request, env);
    const days = url.searchParams.get('days');
    const stats = await todos.statsByDate(env, user.id, days);
    return ok({ stats });
  }

  /* ---------- 搜索 / 标签 ---------- */
  if (path === '/api/search' && method === 'GET') {
    const user = await auth.requireUser(request, env);
    const q = url.searchParams.get('q') || '';
    return ok({ q, todos: await todos.searchTodos(env, user.id, q) });
  }

  if (path === '/api/tags' && method === 'GET') {
    const user = await auth.requireUser(request, env);
    const limit = url.searchParams.get('limit');
    return ok({ tags: await todos.listTags(env, user.id, limit) });
  }

  const todoMatch = path.match(/^\/api\/todos\/([^/]+)$/);
  if (todoMatch) {
    const id = decodeURIComponent(todoMatch[1]);
    const user = await auth.requireUser(request, env);

    if (method === 'PATCH') {
      const body = await readJson(request);
      const todo = await todos.updateTodo(env, user.id, id, body);
      const stat = await todos.countByDate(env, user.id, todo.date);
      scheduleAutoBackup(ctx, env, user, request.cf?.timezone);
      return ok({ todo, ...stat });
    }

    if (method === 'DELETE') {
      const res = await todos.deleteTodo(env, user.id, id);
      const date = url.searchParams.get('date');
      let stat = { remaining: 0, total: 0 };
      if (date && todos.DATE_RE.test(date)) stat = await todos.countByDate(env, user.id, date);
      scheduleAutoBackup(ctx, env, user, request.cf?.timezone);
      return ok({ ...res, ...stat });
    }
  }

  /* ---------- 备份 ---------- */
  if (path === '/api/backup/config' && method === 'GET') {
    const user = await auth.requireUser(request, env);
    const { config, lastBackup } = await backup.readConfig(env, user.id);
    // 顺手记住用户时区：定时备份（Cron）没有请求上下文，拼文件名时要用
    const fresh = await backup.rememberTimeZone(env, user.id, config, request.cf?.timezone);
    return ok({
      config: backup.maskConfig(fresh, env),
      lastBackup,
      cron: await backup.readCronStatus(env),
    });
  }

  if (path === '/api/backup/config' && method === 'PUT') {
    const user = await auth.requireUser(request, env);
    const body = await readJson(request);
    const { config: previous } = await backup.readConfig(env, user.id);
    const merged = backup.normalizeConfig(
      { ...body, tz: body.tz || request.cf?.timezone },
      previous,
    );
    await backup.writeConfig(env, user.id, merged);
    return ok({ config: backup.maskConfig(merged, env) });
  }

  if (path === '/api/backup/test' && method === 'POST') {
    const user = await auth.requireUser(request, env);
    const body = await readJson(request);
    const { config: previous } = await backup.readConfig(env, user.id);
    const candidate = backup.normalizeConfig({ ...body, enabled: true }, previous);
    const info = await backup.testConnection(env, candidate);
    return ok({
      message: info.exists ? '连接成功，云端已有备份文件' : '连接成功，云端暂无备份文件',
      info,
    });
  }

  if (path === '/api/backup/run' && method === 'POST') {
    const user = await auth.requireUser(request, env);
    const { config } = await backup.readConfig(env, user.id);
    const result = await backup.runBackup(env, user, config, {
      timeZone: request.cf?.timezone || config.tz,
    });
    return ok({ message: '已备份到云端', result });
  }

  if (path === '/api/backup/restore' && method === 'POST') {
    const user = await auth.requireUser(request, env);
    const body = await readJson(request);
    const { config } = await backup.readConfig(env, user.id);
    const mode = body.mode === 'replace' ? 'replace' : 'merge';
    const result = await backup.restoreBackup(env, user, config, mode);
    return ok({
      message: mode === 'replace' ? '已用云端备份覆盖本地数据' : '已合并云端备份',
      result,
    });
  }

  /* ---------- 本地导入 / 导出 ---------- */
  if (path === '/api/export' && method === 'GET') {
    const user = await auth.requireUser(request, env);
    const payload = await backup.buildPayload(env, user);
    // 文件名带时间戳，同一天多次导出不会互相覆盖
    const filename = `todo-today-${backup.fileStamp(new Date(), request.cf?.timezone)}.json`;
    return new Response(JSON.stringify(payload, null, 2), {
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'content-disposition': `attachment; filename="${filename}"`,
        'cache-control': 'no-store',
      },
    });
  }

  if (path === '/api/import' && method === 'POST') {
    const user = await auth.requireUser(request, env);
    const body = await readJson(request);
    const payload = body.payload || body;
    const mode = body.mode === 'replace' ? 'replace' : 'merge';
    const result = await backup.applyPayload(env, user, payload, { mode });
    scheduleAutoBackup(ctx, env, user, request.cf?.timezone);
    return ok({ message: `导入完成：新增 ${result.inserted} 条`, result });
  }

  return fail(`接口不存在：${method} ${path}`, 404);
}

/** 数据变更后触发自动备份（节流由 maybeAutoBackup 内部处理）
 *  timeZone 用于备份文件名的时间戳，取用户请求里的 Cloudflare 时区信息 */
function scheduleAutoBackup(ctx, env, user, timeZone) {
  if (!ctx?.waitUntil) return;
  ctx.waitUntil(backup.maybeAutoBackup(env, user, { timeZone }));
}
