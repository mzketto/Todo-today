/**
 * 今日待办 · 单文件版（供 Cloudflare 网页控制台直接粘贴部署）
 *
 * ⚠️ 这是自动生成的文件，请勿手动修改。
 *    源码在 src/ 与 public/，改完执行：npm run build:dashboard
 *
 * 生成时间：2026-10-15T16:14:38.854Z
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
      "KSwKCiAgICAvLyDml6XmnJ/pgInmi6nlvLnlsYIKICAgIGRhdGVQb3A6ICQoJ2RhdGUtcG9wJyksCiAgICBwb3BUaXRsZTogJCgn" +
      "cG9wLXRpdGxlJyksCiAgICBwb3BHcmlkOiAkKCdwb3AtZ3JpZCcpLAoKICAgIC8vIOS+p+agjwogICAgc2lkZWJhcjogJCgnc2lk" +
      "ZWJhcicpLAogICAgc2lkZU1hc2s6ICQoJ3NpZGUtbWFzaycpLAogICAgc2lkZVRvZ2dsZTogJCgnc2lkZS10b2dnbGUnKSwKICAg" +
      "IHNlYXJjaElucHV0OiAkKCdzZWFyY2gtaW5wdXQnKSwKICAgIHNlYXJjaENsZWFyOiAkKCdzZWFyY2gtY2xlYXInKSwKICAgIHN0" +
      "YXREYXlzOiAkKCdzdGF0LWRheXMnKSwKICAgIHN0YXRUb3RhbDogJCgnc3RhdC10b3RhbCcpLAogICAgc3RhdERvbmU6ICQoJ3N0" +
      "YXQtZG9uZScpLAogICAgY2FsVGl0bGU6ICQoJ2NhbC10aXRsZScpLAogICAgY2FsUHJldjogJCgnY2FsLXByZXYnKSwKICAgIGNh" +
      "bE5leHQ6ICQoJ2NhbC1uZXh0JyksCiAgICBjYWxlbmRhcjogJCgnY2FsZW5kYXInKSwKICAgIHRhZ3NCbG9jazogJCgndGFncy1i" +
      "bG9jaycpLAogICAgdGFnc0xpc3Q6ICQoJ3RhZ3MtbGlzdCcpLAogICAgdGltZWxpbmVCbG9jazogJCgndGltZWxpbmUtYmxvY2sn" +
      "KSwKICAgIHRpbWVsaW5lTGlzdDogJCgndGltZWxpbmUtbGlzdCcpLAoKICAgIC8vIOWNoeeJh+a1gQogICAgZmVlZDogJCgnZmVl" +
      "ZCcpLAogICAgc2VhcmNoQmFubmVyOiAkKCdzZWFyY2gtYmFubmVyJyksCiAgICBzZWFyY2hCYW5uZXJUZXh0OiAkKCdzZWFyY2gt" +
      "YmFubmVyLXRleHQnKSwKICAgIHNlYXJjaEV4aXQ6ICQoJ3NlYXJjaC1leGl0JyksCiAgICBlbXB0eVN0YXRlOiAkKCdlbXB0eS1z" +
      "dGF0ZScpLAogICAgZW1wdHlUaXRsZTogJCgnZW1wdHktdGl0bGUnKSwKICAgIGVtcHR5U3ViOiAkKCdlbXB0eS1zdWInKSwKICAg" +
      "IHJlbWFpbmluZ0NvdW50OiAkKCdyZW1haW5pbmctY291bnQnKSwKICAgIHJlbWFpbmluZ0xhYmVsOiAkKCdyZW1haW5pbmctbGFi" +
      "ZWwnKSwKICAgIGNhcnJ5b3ZlckJ0bjogJCgnY2FycnlvdmVyLWJ0bicpLAogICAgY2xlYXJEb25lQnRuOiAkKCdjbGVhci1kb25l" +
      "LWJ0bicpLAoKICAgIGRyYXdlck1hc2s6ICQoJ2RyYXdlci1tYXNrJyksCiAgICBkcmF3ZXJDbG9zZTogJCgnZHJhd2VyLWNsb3Nl" +
      "JyksCiAgICBhY2NvdW50TmFtZTogJCgnYWNjb3VudC1uYW1lJyksCiAgICBsb2dvdXRCdG46ICQoJ2xvZ291dC1idG4nKSwKCiAg" +
      "ICBwd2RDdXJyZW50OiAkKCdwd2QtY3VycmVudCcpLAogICAgcHdkTmV3OiAkKCdwd2QtbmV3JyksCiAgICBwd2RTdWJtaXQ6ICQo" +
      "J3B3ZC1zdWJtaXQnKSwKCiAgICBiYWNrdXBQcm92aWRlcjogJCgnYmFja3VwLXByb3ZpZGVyJyksCiAgICBiYWNrdXBFbmFibGVk" +
      "OiAkKCdiYWNrdXAtZW5hYmxlZCcpLAogICAgYmFja3VwQXV0bzogJCgnYmFja3VwLWF1dG8nKSwKICAgIGJhY2t1cFBhbmVsczog" +
      "QXJyYXkuZnJvbShkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcucHJvdmlkZXItcGFuZWwnKSksCiAgICByMktleTogJCgncjIt" +
      "a2V5JyksCiAgICBzM0VuZHBvaW50OiAkKCdzMy1lbmRwb2ludCcpLAogICAgczNSZWdpb246ICQoJ3MzLXJlZ2lvbicpLAogICAg" +
      "czNCdWNrZXQ6ICQoJ3MzLWJ1Y2tldCcpLAogICAgczNBa2lkOiAkKCdzMy1ha2lkJyksCiAgICBzM1NlY3JldDogJCgnczMtc2Vj" +
      "cmV0JyksCiAgICBzM1ByZWZpeDogJCgnczMtcHJlZml4JyksCiAgICBzM0ZpbGU6ICQoJ3MzLWZpbGUnKSwKICAgIHMzUGF0aFN0" +
      "eWxlOiAkKCdzMy1wYXRoc3R5bGUnKSwKICAgIGRhdlVybDogJCgnZGF2LXVybCcpLAogICAgZGF2VXNlcjogJCgnZGF2LXVzZXIn" +
      "KSwKICAgIGRhdlBhc3M6ICQoJ2Rhdi1wYXNzJyksCiAgICBkYXZGaWxlOiAkKCdkYXYtZmlsZScpLAogICAgYmFja3VwVGVzdDog" +
      "JCgnYmFja3VwLXRlc3QnKSwKICAgIGJhY2t1cFNhdmU6ICQoJ2JhY2t1cC1zYXZlJyksCiAgICBiYWNrdXBSdW46ICQoJ2JhY2t1" +
      "cC1ydW4nKSwKICAgIGJhY2t1cFJlc3RvcmU6ICQoJ2JhY2t1cC1yZXN0b3JlJyksCiAgICBiYWNrdXBTdGF0dXM6ICQoJ2JhY2t1" +
      "cC1zdGF0dXMnKSwKICAgIGJhY2t1cFN0YW1wOiAkKCdiYWNrdXAtc3RhbXAnKSwKICAgIGJhY2t1cFN0YW1wSGludDogJCgnYmFj" +
      "a3VwLXN0YW1wLWhpbnQnKSwKICAgIGJhY2t1cEludGVydmFsOiAkKCdiYWNrdXAtaW50ZXJ2YWwnKSwKICAgIGJhY2t1cEludGVy" +
      "dmFsRmllbGQ6ICQoJ2JhY2t1cC1pbnRlcnZhbC1maWVsZCcpLAogICAgYmFja3VwSW50ZXJ2YWxIaW50OiAkKCdiYWNrdXAtaW50" +
      "ZXJ2YWwtaGludCcpLAogICAgYmFja3VwU2NoZWR1bGVkOiAkKCdiYWNrdXAtc2NoZWR1bGVkJyksCiAgICBiYWNrdXBQZXJpb2Q6" +
      "ICQoJ2JhY2t1cC1wZXJpb2QnKSwKICAgIGJhY2t1cFBlcmlvZEZpZWxkOiAkKCdiYWNrdXAtcGVyaW9kLWZpZWxkJyksCiAgICBi" +
      "YWNrdXBDcm9uSGludDogJCgnYmFja3VwLWNyb24taGludCcpLAogICAgbGFzdEJhY2t1cExpbmU6ICQoJ2xhc3QtYmFja3VwLWxp" +
      "bmUnKSwKCiAgICBleHBvcnRCdG46ICQoJ2V4cG9ydC1idG4nKSwKICAgIGltcG9ydEJ0bjogJCgnaW1wb3J0LWJ0bicpLAogICAg" +
      "aW1wb3J0RmlsZTogJCgnaW1wb3J0LWZpbGUnKSwKICAgIGFib3V0VmVyc2lvbjogJCgnYWJvdXQtdmVyc2lvbicpLAoKICAgIHRv" +
      "YXN0SG9zdDogJCgndG9hc3QtaG9zdCcpLAogIH07CgogIC8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqCiAgICog5bqU55So54q25oCBCiAgICogLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgY29uc3Qgc3RhdGUgPSB7CiAgICB1c2Vy" +
      "OiBudWxsLAogICAgZGF0ZTogdG9kYXlTdHIoKSwKICAgIHRvZG9zOiBbXSwKICAgIHJlbWFpbmluZzogMCwKICAgIHRvdGFsOiAw" +
      "LAogICAgLy8g5pyI6KeG5Zu+77ya6Z2e56m65pe25Y2h54mH5rWB5bGV56S65pW05pyI5Lu75YqhCiAgICBtb250aDogbnVsbCwK" +
      "ICAgIG1vbnRoVG9kb3M6IFtdLAogICAgYXV0aE1vZGU6ICdsb2dpbicsCiAgICBkZW1vOiBmYWxzZSwKICAgIGFwaUNvbmZpcm1l" +
      "ZDogZmFsc2UsCiAgICBidXN5OiBmYWxzZSwKICAgIC8vIOS+p+agjwogICAgc3RhdHM6IFtdLCAgICAgICAgICAgIC8vIFt7IGRh" +
      "dGUsIHJlbWFpbmluZywgdG90YWwgfV0g5oyJ5pel5pyf5YCS5bqPCiAgICB0YWdzOiBbXSwgICAgICAgICAgICAgLy8gW3sgbmFt" +
      "ZSwgY291bnQgfV0KICAgIGNhbDogKCgpID0+IHsgY29uc3QgZCA9IG5ldyBEYXRlKCk7IHJldHVybiB7IHk6IGQuZ2V0RnVsbFll" +
      "YXIoKSwgbTogZC5nZXRNb250aCgpIH07IH0pKCksCiAgICBzZWFyY2g6IHsgcTogJycsIGFjdGl2ZTogZmFsc2UsIGxvYWRpbmc6" +
      "IGZhbHNlLCByZXN1bHRzOiBbXSB9LAogICAgY3JvbjogbnVsbCwgICAgICAgICAgIC8vIOWumuaXtuS7u+WKoe+8iENyb27vvInl" +
      "v4Pot7PnirbmgIEKICB9OwoKICBjb25zdCBUQUdfUkUgPSAvIyhbXlxzI117MSwyNH0pL2c7CgogIC8qIC0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqCiAgICog5a6i5oi356uv57yT5a2Y" +
      "77ya54K55Ye75pel5pyfL+aciOS7veWFiOenkuW8gOe8k+WtmO+8jOWGjeWQjuWPsOagoeaWsO+8jOW5tumihOWPluebuOmCu+aX" +
      "peacnwogICAqIO+8iHN0YWxlLXdoaWxlLXJldmFsaWRhdGXvvIzmtojpmaTjgIzngrnkuIDkuIvnrYnkuIDkuIvjgI3nmoTnvZHn" +
      "u5zlvoDov5TmhJ/vvIkKICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0gKi8KICBjb25zdCBkYXlDYWNoZSA9IG5ldyBNYXAoKTsgICAgICAvLyBkYXRlIC0+IHsgdG9kb3MsIHJlbWFp" +
      "bmluZywgdG90YWwgfQogIGNvbnN0IG1vbnRoQ2FjaGUgPSBuZXcgTWFwKCk7ICAgIC8vIG1vbnRoIC0+IHRvZG9zW10KICBjb25z" +
      "dCBwcmVmZXRjaGluZyA9IG5ldyBTZXQoKTsgICAvLyDmraPlnKjpooTlj5bnmoTml6XmnJ/vvIzpmLLph43lpI3or7fmsYIKICBj" +
      "b25zdCBEQVlfQ0FDSEVfTUFYID0gOTA7CiAgY29uc3QgTU9OVEhfQ0FDSEVfTUFYID0gMjQ7CgogIGZ1bmN0aW9uIGNhY2hlU2V0" +
      "RGF5KGRhdGUsIHRvZG9zLCByZW1haW5pbmcsIHRvdGFsKSB7CiAgICBpZiAoZGF5Q2FjaGUuc2l6ZSA+PSBEQVlfQ0FDSEVfTUFY" +
      "KSBkYXlDYWNoZS5kZWxldGUoZGF5Q2FjaGUua2V5cygpLm5leHQoKS52YWx1ZSk7CiAgICBkYXlDYWNoZS5zZXQoZGF0ZSwgeyB0" +
      "b2RvcywgcmVtYWluaW5nLCB0b3RhbCB9KTsKICB9CgogIGZ1bmN0aW9uIGNhY2hlQ2xlYXJBbGwoKSB7CiAgICBkYXlDYWNoZS5j" +
      "bGVhcigpOwogICAgbW9udGhDYWNoZS5jbGVhcigpOwogICAgcHJlZmV0Y2hpbmcuY2xlYXIoKTsKICB9CgogIGZ1bmN0aW9uIHBy" +
      "ZWZldGNoRGF5KGRhdGUpIHsKICAgIGlmIChkYXlDYWNoZS5oYXMoZGF0ZSkgfHwgcHJlZmV0Y2hpbmcuaGFzKGRhdGUpKSByZXR1" +
      "cm47CiAgICBwcmVmZXRjaGluZy5hZGQoZGF0ZSk7CiAgICBhcGkoYC90b2Rvcz9kYXRlPSR7ZW5jb2RlVVJJQ29tcG9uZW50KGRh" +
      "dGUpfWApCiAgICAgIC50aGVuKChkKSA9PiB7CiAgICAgICAgY29uc3QgdG9kb3MgPSBkLnRvZG9zIHx8IFtdOwogICAgICAgIGNh" +
      "Y2hlU2V0RGF5KGRhdGUsIHRvZG9zLCBkLnJlbWFpbmluZyA/PyB0b2Rvcy5maWx0ZXIoKHQpID0+ICF0LmRvbmUpLmxlbmd0aCwg" +
      "ZC50b3RhbCA/PyB0b2Rvcy5sZW5ndGgpOwogICAgICB9KQogICAgICAuY2F0Y2goKCkgPT4geyAvKiDpooTlj5blpLHotKXpnZnp" +
      "u5jlv73nlaUgKi8gfSkKICAgICAgLmZpbmFsbHkoKCkgPT4gcHJlZmV0Y2hpbmcuZGVsZXRlKGRhdGUpKTsKICB9CgogIC8qKiDl" +
      "hpnmk43kvZzmiJDlip/lkI7vvIzmiorlvZPliY3ljZXml6Xop4blm77nirbmgIHlkIzmraXlm57nvJPlrZggKi8KICBmdW5jdGlv" +
      "biBzeW5jRGF5Q2FjaGUoKSB7CiAgICBpZiAoc3RhdGUubW9udGggfHwgc3RhdGUuc2VhcmNoLmFjdGl2ZSkgcmV0dXJuOwogICAg" +
      "Y2FjaGVTZXREYXkoc3RhdGUuZGF0ZSwgc3RhdGUudG9kb3MsIHN0YXRlLnJlbWFpbmluZywgc3RhdGUudG90YWwpOwogIH0KCiAg" +
      "LyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAg" +
      "KiDlt6Xlhbflh73mlbAKICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0gKi8KICBmdW5jdGlvbiBwYWQobikgeyByZXR1cm4gU3RyaW5nKG4pLnBhZFN0YXJ0KDIsICcwJyk7IH0KCiAg" +
      "ZnVuY3Rpb24gdG9kYXlTdHIoKSB7CiAgICBjb25zdCBkID0gbmV3IERhdGUoKTsKICAgIHJldHVybiBgJHtkLmdldEZ1bGxZZWFy" +
      "KCl9LSR7cGFkKGQuZ2V0TW9udGgoKSArIDEpfS0ke3BhZChkLmdldERhdGUoKSl9YDsKICB9CgogIGZ1bmN0aW9uIHNoaWZ0RGF0" +
      "ZShkYXRlU3RyLCBkZWx0YSkgewogICAgY29uc3QgW3ksIG0sIGRdID0gZGF0ZVN0ci5zcGxpdCgnLScpLm1hcChOdW1iZXIpOwog" +
      "ICAgY29uc3QgZHQgPSBuZXcgRGF0ZSh5LCBtIC0gMSwgZCk7CiAgICBkdC5zZXREYXRlKGR0LmdldERhdGUoKSArIGRlbHRhKTsK" +
      "ICAgIHJldHVybiBgJHtkdC5nZXRGdWxsWWVhcigpfS0ke3BhZChkdC5nZXRNb250aCgpICsgMSl9LSR7cGFkKGR0LmdldERhdGUo" +
      "KSl9YDsKICB9CgogIC8qKiDmnIjku73lubPnp7vvvJonMjAyNS0xMCcgKyAoLTEpIOKGkiAnMjAyNS0wOScgKi8KICBmdW5jdGlv" +
      "biBzaGlmdE1vbnRoU3RyKG1vbnRoU3RyLCBkZWx0YSkgewogICAgY29uc3QgW3ksIG1dID0gbW9udGhTdHIuc3BsaXQoJy0nKS5t" +
      "YXAoTnVtYmVyKTsKICAgIGNvbnN0IHplcm8gPSB5ICogMTIgKyAobSAtIDEpICsgZGVsdGE7CiAgICByZXR1cm4gYCR7TWF0aC5m" +
      "bG9vcih6ZXJvIC8gMTIpfS0ke3BhZCgoemVybyAlIDEyKSArIDEpfWA7CiAgfQoKICBjb25zdCBXRUVLREFZUyA9IFsn5ZGo5pel" +
      "JywgJ+WRqOS4gCcsICflkajkuownLCAn5ZGo5LiJJywgJ+WRqOWbmycsICflkajkupQnLCAn5ZGo5YWtJ107CgogIGZ1bmN0aW9u" +
      "IGh1bWFuRGF0ZShkYXRlU3RyKSB7CiAgICBjb25zdCB0b2RheSA9IHRvZGF5U3RyKCk7CiAgICBpZiAoZGF0ZVN0ciA9PT0gdG9k" +
      "YXkpIHJldHVybiB7IHRpdGxlOiAn5LuK5aSpJywgc3ViOiBgJHtkYXRlU3RyfSDCtyAke1dFRUtEQVlTW3dlZWtkYXlPZihkYXRl" +
      "U3RyKV19YCB9OwogICAgaWYgKGRhdGVTdHIgPT09IHNoaWZ0RGF0ZSh0b2RheSwgLTEpKSByZXR1cm4geyB0aXRsZTogJ+aYqOWk" +
      "qScsIHN1YjogYCR7ZGF0ZVN0cn0gwrcgJHtXRUVLREFZU1t3ZWVrZGF5T2YoZGF0ZVN0cildfWAgfTsKICAgIGlmIChkYXRlU3Ry" +
      "ID09PSBzaGlmdERhdGUodG9kYXksIDEpKSByZXR1cm4geyB0aXRsZTogJ+aYjuWkqScsIHN1YjogYCR7ZGF0ZVN0cn0gwrcgJHtX" +
      "RUVLREFZU1t3ZWVrZGF5T2YoZGF0ZVN0cildfWAgfTsKICAgIGNvbnN0IFt5LCBtLCBkXSA9IGRhdGVTdHIuc3BsaXQoJy0nKS5t" +
      "YXAoTnVtYmVyKTsKICAgIHJldHVybiB7IHRpdGxlOiBgJHttfSDmnIggJHtkfSDml6VgLCBzdWI6IGAke3l9LSR7cGFkKG0pfS0k" +
      "e3BhZChkKX0gwrcgJHtXRUVLREFZU1t3ZWVrZGF5T2YoZGF0ZVN0cildfWAgfTsKICB9CgogIGZ1bmN0aW9uIHdlZWtkYXlPZihk" +
      "YXRlU3RyKSB7CiAgICBjb25zdCBbeSwgbSwgZF0gPSBkYXRlU3RyLnNwbGl0KCctJykubWFwKE51bWJlcik7CiAgICByZXR1cm4g" +
      "bmV3IERhdGUoeSwgbSAtIDEsIGQpLmdldERheSgpOwogIH0KCiAgZnVuY3Rpb24gdG9hc3QobWVzc2FnZSwga2luZCA9ICcnLCBk" +
      "dXJhdGlvbiA9IDI0MDApIHsKICAgIGNvbnN0IHRleHQgPSBTdHJpbmcobWVzc2FnZSA/PyAnJyk7CiAgICBjb25zdCBsb25nID0g" +
      "dGV4dC5sZW5ndGggPiA1NjsgICAvLyDplb/mlofmoYjmlLnnlKjljaHniYfmoLflvI/lubblpJrlgZznlZnkuIDkvJrlhL8KICAg" +
      "IGNvbnN0IG5vZGUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIG5vZGUuY2xhc3NOYW1lID0gYHRvYXN0ICR7" +
      "a2luZH0ke2xvbmcgPyAnIGxvbmcnIDogJyd9YDsKICAgIG5vZGUudGV4dENvbnRlbnQgPSB0ZXh0OwogICAgZWwudG9hc3RIb3N0" +
      "LmFwcGVuZENoaWxkKG5vZGUpOwogICAgc2V0VGltZW91dCgoKSA9PiB7CiAgICAgIG5vZGUuY2xhc3NMaXN0LmFkZCgnbGVhdmlu" +
      "ZycpOwogICAgICBzZXRUaW1lb3V0KCgpID0+IG5vZGUucmVtb3ZlKCksIDI0MCk7CiAgICB9LCBsb25nID8gTWF0aC5tYXgoZHVy" +
      "YXRpb24sIDcwMDApIDogZHVyYXRpb24pOwogIH0KCiAgZnVuY3Rpb24gc2V0U3RhdHVzKG5vZGUsIHRleHQsIGtpbmQgPSAnYnVz" +
      "eScpIHsKICAgIGlmICghdGV4dCkgeyBub2RlLmhpZGRlbiA9IHRydWU7IG5vZGUudGV4dENvbnRlbnQgPSAnJzsgcmV0dXJuOyB9" +
      "CiAgICBub2RlLmhpZGRlbiA9IGZhbHNlOwogICAgbm9kZS5jbGFzc05hbWUgPSBgc3RhdHVzLWxpbmUgJHtraW5kfWA7CiAgICBu" +
      "b2RlLnRleHRDb250ZW50ID0gdGV4dDsKICB9CgogIC8qKiBpZnJhbWUg6YeMIHdpbmRvdy5jb25maXJtIOWPr+iDveiiq+aLpuaI" +
      "qu+8jOaUueeUqOOAjOWGjeeCueS4gOasoeehruiupOOAjSAqLwogIGZ1bmN0aW9uIGFybWVkQ2xpY2soYnV0dG9uLCBsYWJlbCwg" +
      "YWN0aW9uKSB7CiAgICBpZiAoYnV0dG9uLmRhdGFzZXQuYXJtZWQgPT09ICcxJykgewogICAgICBkZWxldGUgYnV0dG9uLmRhdGFz" +
      "ZXQuYXJtZWQ7CiAgICAgIGJ1dHRvbi50ZXh0Q29udGVudCA9IGJ1dHRvbi5kYXRhc2V0Lm9yaWdpbmFsIHx8IGxhYmVsOwogICAg" +
      "ICByZXR1cm4gYWN0aW9uKCk7CiAgICB9CiAgICBidXR0b24uZGF0YXNldC5vcmlnaW5hbCA9IGJ1dHRvbi5kYXRhc2V0Lm9yaWdp" +
      "bmFsIHx8IGJ1dHRvbi50ZXh0Q29udGVudDsKICAgIGJ1dHRvbi5kYXRhc2V0LmFybWVkID0gJzEnOwogICAgYnV0dG9uLnRleHRD" +
      "b250ZW50ID0gbGFiZWw7CiAgICBzZXRUaW1lb3V0KCgpID0+IHsKICAgICAgaWYgKGJ1dHRvbi5kYXRhc2V0LmFybWVkID09PSAn" +
      "MScpIHsKICAgICAgICBkZWxldGUgYnV0dG9uLmRhdGFzZXQuYXJtZWQ7CiAgICAgICAgYnV0dG9uLnRleHRDb250ZW50ID0gYnV0" +
      "dG9uLmRhdGFzZXQub3JpZ2luYWw7CiAgICAgIH0KICAgIH0sIDMyMDApOwogICAgcmV0dXJuIHVuZGVmaW5lZDsKICB9CgogIC8q" +
      "IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqCiAgICog" +
      "5ryU56S65qih5byP77ya55SoIGxvY2FsU3RvcmFnZSDmqKHmi5/lkI7nq68KICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KICBjb25zdCBERU1PX0tFWSA9ICd0b2RvLXRvZGF5" +
      "OmRlbW86djEnOwoKICBmdW5jdGlvbiBkZW1vUmVhZCgpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHJhdyA9IGxvY2FsU3RvcmFn" +
      "ZS5nZXRJdGVtKERFTU9fS0VZKTsKICAgICAgaWYgKHJhdykgcmV0dXJuIEpTT04ucGFyc2UocmF3KTsKICAgIH0gY2F0Y2ggeyAv" +
      "KiBpZ25vcmUgKi8gfQogICAgcmV0dXJuIHsgdXNlcjogbnVsbCwgdG9kb3M6IFtdLCBiYWNrdXA6IG51bGwgfTsKICB9CgogIGZ1" +
      "bmN0aW9uIGRlbW9Xcml0ZShkYXRhKSB7CiAgICB0cnkgeyBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShERU1PX0tFWSwgSlNPTi5zdHJp" +
      "bmdpZnkoZGF0YSkpOyB9IGNhdGNoIHsgLyogaWdub3JlICovIH0KICB9CgogIGZ1bmN0aW9uIGRlbW9JZCgpIHsKICAgIHJldHVy" +
      "biBgZF8ke0RhdGUubm93KCkudG9TdHJpbmcoMzYpfSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgOCl9YDsK" +
      "ICB9CgogIGZ1bmN0aW9uIGRlbW9Db3VudCh0b2RvcywgZGF0ZSkgewogICAgY29uc3QgbGlzdCA9IHRvZG9zLmZpbHRlcigodCkg" +
      "PT4gdC5kYXRlID09PSBkYXRlKTsKICAgIHJldHVybiB7IHJlbWFpbmluZzogbGlzdC5maWx0ZXIoKHQpID0+ICF0LmRvbmUpLmxl" +
      "bmd0aCwgdG90YWw6IGxpc3QubGVuZ3RoIH07CiAgfQoKICBmdW5jdGlvbiBkZW1vTGlzdCh0b2RvcywgZGF0ZSkgewogICAgcmV0" +
      "dXJuIHRvZG9zCiAgICAgIC5maWx0ZXIoKHQpID0+IHQuZGF0ZSA9PT0gZGF0ZSkKICAgICAgLnNvcnQoKGEsIGIpID0+IE51bWJl" +
      "cihhLmRvbmUpIC0gTnVtYmVyKGIuZG9uZSkgfHwgYS5vcmRlciAtIGIub3JkZXIgfHwgYS5jcmVhdGVkQXQgLSBiLmNyZWF0ZWRB" +
      "dCk7CiAgfQoKICBmdW5jdGlvbiBkZW1vQXBpKHBhdGgsIHsgbWV0aG9kID0gJ0dFVCcsIGJvZHkgfSA9IHt9KSB7CiAgICBjb25z" +
      "dCBkYiA9IGRlbW9SZWFkKCk7CiAgICBjb25zdCBbcmF3UGF0aCwgcXVlcnldID0gcGF0aC5zcGxpdCgnPycpOwogICAgY29uc3Qg" +
      "cGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyhxdWVyeSB8fCAnJyk7CiAgICBjb25zdCBzZWcgPSByYXdQYXRoLnNwbGl0KCcv" +
      "JykuZmlsdGVyKEJvb2xlYW4pOyAvLyBbJ2F1dGgnLCdtZSddIGV0Yy4KICAgIGNvbnN0IGpzb25SZXMgPSAoZGF0YSwgc3RhdHVz" +
      "ID0gMjAwKSA9PiAoeyAuLi5kYXRhLCBfX3N0YXR1czogc3RhdHVzIH0pOwoKICAgIC8qIC0tLSBhdXRoIC0tLSAqLwogICAgaWYg" +
      "KHNlZ1swXSA9PT0gJ2F1dGgnKSB7CiAgICAgIGlmIChzZWdbMV0gPT09ICdtZScpIHJldHVybiB7IG9rOiB0cnVlLCB1c2VyOiBk" +
      "Yi51c2VyIH07CiAgICAgIGlmIChzZWdbMV0gPT09ICdsb2dpbicgfHwgc2VnWzFdID09PSAncmVnaXN0ZXInKSB7CiAgICAgICAg" +
      "Y29uc3QgbmFtZSA9IFN0cmluZyhib2R5Py51c2VybmFtZSB8fCAnJykudHJpbSgpOwogICAgICAgIGNvbnN0IHBhc3MgPSBTdHJp" +
      "bmcoYm9keT8ucGFzc3dvcmQgfHwgJycpOwogICAgICAgIGlmIChuYW1lLmxlbmd0aCA8IDIpIHRocm93IG5ldyBBcGlFcnJvcign" +
      "55So5oi35ZCN6Iez5bCRIDIg5L2NJyk7CiAgICAgICAgaWYgKHBhc3MubGVuZ3RoIDwgNikgdGhyb3cgbmV3IEFwaUVycm9yKCfl" +
      "r4bnoIHoh7PlsJEgNiDkvY0nKTsKICAgICAgICBkYi51c2VyID0geyBpZDogJ2RlbW8tdXNlcicsIHVzZXJuYW1lOiBuYW1lLCBj" +
      "cmVhdGVkQXQ6IE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDEwMDApIH07CiAgICAgICAgZGVtb1dyaXRlKGRiKTsKICAgICAgICBy" +
      "ZXR1cm4geyBvazogdHJ1ZSwgdXNlcjogZGIudXNlciB9OwogICAgICB9CiAgICAgIGlmIChzZWdbMV0gPT09ICdsb2dvdXQnKSB7" +
      "CiAgICAgICAgZGIudXNlciA9IG51bGw7CiAgICAgICAgZGVtb1dyaXRlKGRiKTsKICAgICAgICByZXR1cm4geyBvazogdHJ1ZSB9" +
      "OwogICAgICB9CiAgICAgIGlmIChzZWdbMV0gPT09ICdwYXNzd29yZCcpIHJldHVybiB7IG9rOiB0cnVlLCBtZXNzYWdlOiAn5ryU" +
      "56S65qih5byP5LiL5LiN5Lya55yf55qE5pS55a+G56CBJyB9OwogICAgfQoKICAgIGlmICghZGIudXNlcikgdGhyb3cgbmV3IEFw" +
      "aUVycm9yKCfor7flhYjnmbvlvZUnLCA0MDEpOwoKICAgIC8qIC0tLSDmkJzntKIgLyDmoIfnrb4gLS0tICovCiAgICBpZiAoc2Vn" +
      "WzBdID09PSAnc2VhcmNoJyAmJiBtZXRob2QgPT09ICdHRVQnKSB7CiAgICAgIGNvbnN0IHEgPSAocGFyYW1zLmdldCgncScpIHx8" +
      "ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTsKICAgICAgY29uc3QgbGlzdCA9IGRiLnRvZG9zCiAgICAgICAgLmZpbHRlcigodCkg" +
      "PT4gdC50aXRsZS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKHEpKQogICAgICAgIC5zb3J0KChhLCBiKSA9PiAoYS5kYXRlIDwgYi5k" +
      "YXRlID8gMSA6IGEuZGF0ZSA+IGIuZGF0ZSA/IC0xIDogYi5jcmVhdGVkQXQgLSBhLmNyZWF0ZWRBdCkpCiAgICAgICAgLnNsaWNl" +
      "KDAsIDUwKTsKICAgICAgcmV0dXJuIHsgb2s6IHRydWUsIHEsIHRvZG9zOiBsaXN0IH07CiAgICB9CgogICAgaWYgKHNlZ1swXSA9" +
      "PT0gJ3RhZ3MnICYmIG1ldGhvZCA9PT0gJ0dFVCcpIHsKICAgICAgY29uc3QgY291bnRlciA9IG5ldyBNYXAoKTsKICAgICAgZGIu" +
      "dG9kb3MuZm9yRWFjaCgodCkgPT4gewogICAgICAgIGNvbnN0IHRhZ3MgPSBTdHJpbmcodC50aXRsZSB8fCAnJykubWF0Y2goLyMo" +
      "W15ccyNdezEsMjR9KS9nKSB8fCBbXTsKICAgICAgICB0YWdzLmZvckVhY2goKHJhdykgPT4gewogICAgICAgICAgY29uc3QgbmFt" +
      "ZSA9IHJhdy5zbGljZSgxKTsKICAgICAgICAgIGNvdW50ZXIuc2V0KG5hbWUsIChjb3VudGVyLmdldChuYW1lKSB8fCAwKSArIDEp" +
      "OwogICAgICAgIH0pOwogICAgICB9KTsKICAgICAgY29uc3QgdGFncyA9IEFycmF5LmZyb20oY291bnRlciwgKFtuYW1lLCBjb3Vu" +
      "dF0pID0+ICh7IG5hbWUsIGNvdW50IH0pKQogICAgICAgIC5zb3J0KChhLCBiKSA9PiBiLmNvdW50IC0gYS5jb3VudCB8fCBhLm5h" +
      "bWUubG9jYWxlQ29tcGFyZShiLm5hbWUsICd6aC1IYW5zLUNOJykpCiAgICAgICAgLnNsaWNlKDAsIDMwKTsKICAgICAgcmV0dXJu" +
      "IHsgb2s6IHRydWUsIHRhZ3MgfTsKICAgIH0KCiAgICAvKiAtLS0gdG9kb3MgLS0tICovCiAgICBpZiAoc2VnWzBdID09PSAndG9k" +
      "b3MnKSB7CiAgICAgIGNvbnN0IGRhdGUgPSBwYXJhbXMuZ2V0KCdkYXRlJykgfHwgc3RhdGUuZGF0ZTsKCiAgICAgIC8vIOaVtOac" +
      "iOinhuWbvgogICAgICBjb25zdCBtb250aCA9IHBhcmFtcy5nZXQoJ21vbnRoJyk7CiAgICAgIGlmICghc2VnWzFdICYmIG1ldGhv" +
      "ZCA9PT0gJ0dFVCcgJiYgbW9udGgpIHsKICAgICAgICBpZiAoIS9eXGR7NH0tKD86MFsxLTldfDFbMC0yXSkkLy50ZXN0KG1vbnRo" +
      "KSkgdGhyb3cgbmV3IEFwaUVycm9yKCfmnIjku73moLzlvI/kuI3mraPnoa7vvIzlupTkuLogWVlZWS1NTScpOwogICAgICAgIGNv" +
      "bnN0IGxpc3QgPSBkYi50b2RvcwogICAgICAgICAgLmZpbHRlcigodCkgPT4gdC5kYXRlLnN0YXJ0c1dpdGgoYCR7bW9udGh9LWAp" +
      "KQogICAgICAgICAgLnNvcnQoKGEsIGIpID0+IChhLmRhdGUgPCBiLmRhdGUgPyAxIDogYS5kYXRlID4gYi5kYXRlID8gLTEgOiBO" +
      "dW1iZXIoYS5kb25lKSAtIE51bWJlcihiLmRvbmUpIHx8IGEub3JkZXIgLSBiLm9yZGVyKSk7CiAgICAgICAgcmV0dXJuIHsgb2s6" +
      "IHRydWUsIG1vbnRoLCB0b2RvczogbGlzdCwgcmVtYWluaW5nOiBsaXN0LmZpbHRlcigodCkgPT4gIXQuZG9uZSkubGVuZ3RoLCB0" +
      "b3RhbDogbGlzdC5sZW5ndGggfTsKICAgICAgfQoKICAgICAgaWYgKCFzZWdbMV0gJiYgbWV0aG9kID09PSAnR0VUJykgewogICAg" +
      "ICAgIHJldHVybiB7IG9rOiB0cnVlLCBkYXRlLCB0b2RvczogZGVtb0xpc3QoZGIudG9kb3MsIGRhdGUpLCAuLi5kZW1vQ291bnQo" +
      "ZGIudG9kb3MsIGRhdGUpIH07CiAgICAgIH0KCiAgICAgIGlmICghc2VnWzFdICYmIG1ldGhvZCA9PT0gJ1BPU1QnKSB7CiAgICAg" +
      "ICAgY29uc3QgdGl0bGUgPSBTdHJpbmcoYm9keT8udGl0bGUgfHwgJycpLnJlcGxhY2UoL1xzKy9nLCAnICcpLnRyaW0oKTsKICAg" +
      "ICAgICBpZiAoIXRpdGxlKSB0aHJvdyBuZXcgQXBpRXJyb3IoJ+S7u+WKoeWGheWuueS4jeiDveS4uuepuicpOwogICAgICAgIGNv" +
      "bnN0IGRheSA9IGJvZHk/LmRhdGUgfHwgZGF0ZTsKICAgICAgICBjb25zdCBtaW5PcmRlciA9IE1hdGgubWluKDAsIC4uLmRiLnRv" +
      "ZG9zLmZpbHRlcigodCkgPT4gdC5kYXRlID09PSBkYXkpLm1hcCgodCkgPT4gdC5vcmRlcikpOwogICAgICAgIGNvbnN0IHRvZG8g" +
      "PSB7CiAgICAgICAgICBpZDogZGVtb0lkKCksIHRpdGxlLCBkb25lOiBmYWxzZSwgZGF0ZTogZGF5LAogICAgICAgICAgb3JkZXI6" +
      "IG1pbk9yZGVyIC0gMSwgY3JlYXRlZEF0OiBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxMDAwKSwKICAgICAgICB9OwogICAgICAg" +
      "IGRiLnRvZG9zLnB1c2godG9kbyk7CiAgICAgICAgZGVtb1dyaXRlKGRiKTsKICAgICAgICByZXR1cm4geyBvazogdHJ1ZSwgdG9k" +
      "bywgLi4uZGVtb0NvdW50KGRiLnRvZG9zLCBkYXkpLCBfX3N0YXR1czogMjAxIH07CiAgICAgIH0KCiAgICAgIGlmIChzZWdbMV0g" +
      "PT09ICdiYXRjaCcgJiYgbWV0aG9kID09PSAnUE9TVCcpIHsKICAgICAgICBjb25zdCBkYXkgPSBib2R5Py5kYXRlIHx8IGRhdGU7" +
      "CiAgICAgICAgaWYgKGJvZHk/LmFjdGlvbiA9PT0gJ2NsZWFyLWNvbXBsZXRlZCcpIHsKICAgICAgICAgIGNvbnN0IGJlZm9yZSA9" +
      "IGRiLnRvZG9zLmxlbmd0aDsKICAgICAgICAgIGlmIChib2R5Py5tb250aCkgewogICAgICAgICAgICBpZiAoIS9eXGR7NH0tKD86" +
      "MFsxLTldfDFbMC0yXSkkLy50ZXN0KGJvZHkubW9udGgpKSB0aHJvdyBuZXcgQXBpRXJyb3IoJ+aciOS7veagvOW8j+S4jeato+eh" +
      "ru+8jOW6lOS4uiBZWVlZLU1NJyk7CiAgICAgICAgICAgIGRiLnRvZG9zID0gZGIudG9kb3MuZmlsdGVyKCh0KSA9PiAhKHQuZGF0" +
      "ZS5zdGFydHNXaXRoKGAke2JvZHkubW9udGh9LWApICYmIHQuZG9uZSkpOwogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAg" +
      "ZGIudG9kb3MgPSBkYi50b2Rvcy5maWx0ZXIoKHQpID0+ICEodC5kYXRlID09PSBkYXkgJiYgdC5kb25lKSk7CiAgICAgICAgICB9" +
      "CiAgICAgICAgICBkZW1vV3JpdGUoZGIpOwogICAgICAgICAgcmV0dXJuIHsgb2s6IHRydWUsIHJlbW92ZWQ6IGJlZm9yZSAtIGRi" +
      "LnRvZG9zLmxlbmd0aCwgLi4uZGVtb0NvdW50KGRiLnRvZG9zLCBkYXkpIH07CiAgICAgICAgfQogICAgICAgIGlmIChib2R5Py5h" +
      "Y3Rpb24gPT09ICd0b2dnbGUtYWxsJykgewogICAgICAgICAgZGIudG9kb3MuZm9yRWFjaCgodCkgPT4geyBpZiAodC5kYXRlID09" +
      "PSBkYXkpIHQuZG9uZSA9ICEhYm9keS5kb25lOyB9KTsKICAgICAgICAgIGRlbW9Xcml0ZShkYik7CiAgICAgICAgICByZXR1cm4g" +
      "eyBvazogdHJ1ZSwgLi4uZGVtb0NvdW50KGRiLnRvZG9zLCBkYXkpIH07CiAgICAgICAgfQogICAgICAgIGlmIChib2R5Py5hY3Rp" +
      "b24gPT09ICdjYXJyeS1vdmVyJykgewogICAgICAgICAgbGV0IG1vdmVkID0gMDsKICAgICAgICAgIGNvbnN0IHBlbmRpbmcgPSBi" +
      "b2R5Py5mcm9tCiAgICAgICAgICAgID8gZGIudG9kb3MuZmlsdGVyKCh0KSA9PiB0LmRhdGUgPT09IGJvZHkuZnJvbSAmJiAhdC5k" +
      "b25lKQogICAgICAgICAgICA6IGRiLnRvZG9zLmZpbHRlcigodCkgPT4gdC5kYXRlIDwgZGF5ICYmICF0LmRvbmUpOwogICAgICAg" +
      "ICAgbGV0IG9yZGVyID0gTWF0aC5taW4oMCwgLi4uZGIudG9kb3MuZmlsdGVyKCh0KSA9PiB0LmRhdGUgPT09IGRheSkubWFwKCh0" +
      "KSA9PiB0Lm9yZGVyKSkgLSAxOwogICAgICAgICAgcGVuZGluZy5mb3JFYWNoKCh0KSA9PiB7IHQuZGF0ZSA9IGRheTsgdC5vcmRl" +
      "ciA9IG9yZGVyLS07IG1vdmVkICs9IDE7IH0pOwogICAgICAgICAgZGVtb1dyaXRlKGRiKTsKICAgICAgICAgIHJldHVybiB7IG9r" +
      "OiB0cnVlLCBtb3ZlZCwgdG9kb3M6IGRlbW9MaXN0KGRiLnRvZG9zLCBkYXkpLCAuLi5kZW1vQ291bnQoZGIudG9kb3MsIGRheSkg" +
      "fTsKICAgICAgICB9CiAgICAgICAgcmV0dXJuIHsgb2s6IHRydWUgfTsKICAgICAgfQoKICAgICAgaWYgKHNlZ1sxXSA9PT0gJ3N0" +
      "YXRzJykgewogICAgICAgIGNvbnN0IG1hcCA9IG5ldyBNYXAoKTsKICAgICAgICBkYi50b2Rvcy5mb3JFYWNoKCh0KSA9PiB7CiAg" +
      "ICAgICAgICBjb25zdCBjdXIgPSBtYXAuZ2V0KHQuZGF0ZSkgfHwgeyBkYXRlOiB0LmRhdGUsIHJlbWFpbmluZzogMCwgdG90YWw6" +
      "IDAgfTsKICAgICAgICAgIGN1ci50b3RhbCArPSAxOwogICAgICAgICAgaWYgKCF0LmRvbmUpIGN1ci5yZW1haW5pbmcgKz0gMTsK" +
      "ICAgICAgICAgIG1hcC5zZXQodC5kYXRlLCBjdXIpOwogICAgICAgIH0pOwogICAgICAgIHJldHVybiB7IG9rOiB0cnVlLCBzdGF0" +
      "czogQXJyYXkuZnJvbShtYXAudmFsdWVzKCkpLnNvcnQoKGEsIGIpID0+IChhLmRhdGUgPCBiLmRhdGUgPyAxIDogLTEpKSB9Owog" +
      "ICAgICB9CgogICAgICBjb25zdCBpZCA9IHNlZ1sxXTsKICAgICAgY29uc3QgaW5kZXggPSBkYi50b2Rvcy5maW5kSW5kZXgoKHQp" +
      "ID0+IHQuaWQgPT09IGlkKTsKICAgICAgaWYgKGluZGV4ID09PSAtMSkgdGhyb3cgbmV3IEFwaUVycm9yKCfku7vliqHkuI3lrZjl" +
      "nKgnLCA0MDQpOwoKICAgICAgaWYgKG1ldGhvZCA9PT0gJ1BBVENIJykgewogICAgICAgIGNvbnN0IHQgPSBkYi50b2Rvc1tpbmRl" +
      "eF07CiAgICAgICAgaWYgKCd0aXRsZScgaW4gKGJvZHkgfHwge30pKSB7CiAgICAgICAgICBjb25zdCB0aXRsZSA9IFN0cmluZyhi" +
      "b2R5LnRpdGxlKS5yZXBsYWNlKC9ccysvZywgJyAnKS50cmltKCk7CiAgICAgICAgICBpZiAoIXRpdGxlKSB0aHJvdyBuZXcgQXBp" +
      "RXJyb3IoJ+S7u+WKoeWGheWuueS4jeiDveS4uuepuicpOwogICAgICAgICAgdC50aXRsZSA9IHRpdGxlOwogICAgICAgIH0KICAg" +
      "ICAgICBpZiAoJ2RvbmUnIGluIChib2R5IHx8IHt9KSkgdC5kb25lID0gISFib2R5LmRvbmU7CiAgICAgICAgaWYgKCdkYXRlJyBp" +
      "biAoYm9keSB8fCB7fSkpIHQuZGF0ZSA9IGJvZHkuZGF0ZTsKICAgICAgICBkZW1vV3JpdGUoZGIpOwogICAgICAgIHJldHVybiB7" +
      "IG9rOiB0cnVlLCB0b2RvOiB0LCAuLi5kZW1vQ291bnQoZGIudG9kb3MsIHQuZGF0ZSkgfTsKICAgICAgfQoKICAgICAgaWYgKG1l" +
      "dGhvZCA9PT0gJ0RFTEVURScpIHsKICAgICAgICBjb25zdCBbcmVtb3ZlZF0gPSBkYi50b2Rvcy5zcGxpY2UoaW5kZXgsIDEpOwog" +
      "ICAgICAgIGRlbW9Xcml0ZShkYik7CiAgICAgICAgcmV0dXJuIHsgb2s6IHRydWUsIGlkOiByZW1vdmVkLmlkLCAuLi5kZW1vQ291" +
      "bnQoZGIudG9kb3MsIHJlbW92ZWQuZGF0ZSkgfTsKICAgICAgfQogICAgfQoKICAgIC8qIC0tLSBiYWNrdXAgLS0tICovCiAgICBp" +
      "ZiAoc2VnWzBdID09PSAnYmFja3VwJykgewogICAgICBpZiAoc2VnWzFdID09PSAnY29uZmlnJyAmJiBtZXRob2QgPT09ICdHRVQn" +
      "KSB7CiAgICAgICAgcmV0dXJuIHsKICAgICAgICAgIG9rOiB0cnVlLAogICAgICAgICAgY29uZmlnOiBkYi5iYWNrdXAgfHwgewog" +
      "ICAgICAgICAgICBwcm92aWRlcjogJ25vbmUnLCBlbmFibGVkOiBmYWxzZSwgYXV0bzogZmFsc2UsIHN0YW1wOiB0cnVlLAogICAg" +
      "ICAgICAgICBpbnRlcnZhbE1pbjogMSwgc2NoZWR1bGVkOiBmYWxzZSwgc2NoZWR1bGVNaW46IDYwLCB0ejogJycsCiAgICAgICAg" +
      "ICAgIGZpbGU6ICd0b2RvLXRvZGF5LmJhY2t1cC5qc29uJywKICAgICAgICAgICAgaGFzUjJCaW5kaW5nOiBmYWxzZSwKICAgICAg" +
      "ICAgICAgczM6IHsgZW5kcG9pbnQ6ICcnLCByZWdpb246ICdhdXRvJywgYnVja2V0OiAnJywgYWNjZXNzS2V5SWQ6ICcnLCBoYXNT" +
      "ZWNyZXRLZXk6IGZhbHNlLCBwcmVmaXg6ICcnLCBwYXRoU3R5bGU6IGZhbHNlIH0sCiAgICAgICAgICAgIHdlYmRhdjogeyB1cmw6" +
      "ICcnLCB1c2VybmFtZTogJycsIGhhc1Bhc3N3b3JkOiBmYWxzZSwgZmlsZTogJycgfSwKICAgICAgICAgIH0sCiAgICAgICAgICBs" +
      "YXN0QmFja3VwOiBudWxsLAogICAgICAgICAgY3JvbjogeyBsYXN0UnVuOiBudWxsLCBoZWFsdGh5OiBmYWxzZSwgaW50ZXJ2YWxT" +
      "ZWNvbmRzOiAzMDAgfSwKICAgICAgICB9OwogICAgICB9CiAgICAgIGlmIChzZWdbMV0gPT09ICdjb25maWcnICYmIG1ldGhvZCA9" +
      "PT0gJ1BVVCcpIHsKICAgICAgICBkYi5iYWNrdXAgPSB7IC4uLmJvZHksIGhhc1IyQmluZGluZzogZmFsc2UgfTsKICAgICAgICBk" +
      "ZW1vV3JpdGUoZGIpOwogICAgICAgIHJldHVybiB7IG9rOiB0cnVlLCBjb25maWc6IGRiLmJhY2t1cCB9OwogICAgICB9CiAgICAg" +
      "IGlmIChzZWdbMV0gPT09ICd0ZXN0JykgcmV0dXJuIHsgb2s6IHRydWUsIG1lc3NhZ2U6ICfmvJTnpLrmqKHlvI/vvJrmnKrnnJ/m" +
      "raPov57mjqXkupHlrZjlgqgnIH07CiAgICAgIGlmIChzZWdbMV0gPT09ICdydW4nKSByZXR1cm4geyBvazogdHJ1ZSwgbWVzc2Fn" +
      "ZTogJ+a8lOekuuaooeW8j++8muacquecn+ato+S4iuS8oCcgfTsKICAgICAgaWYgKHNlZ1sxXSA9PT0gJ3Jlc3RvcmUnKSByZXR1" +
      "cm4geyBvazogdHJ1ZSwgbWVzc2FnZTogJ+a8lOekuuaooeW8j++8muacquecn+ato+S4i+i9vScgfTsKICAgIH0KCiAgICB0aHJv" +
      "dyBuZXcgQXBpRXJyb3IoYOa8lOekuuaooeW8j+aaguS4jeaUr+aMge+8miR7bWV0aG9kfSAke3BhdGh9YCwgNDA0KTsKICB9Cgog" +
      "IGNsYXNzIEFwaUVycm9yIGV4dGVuZHMgRXJyb3IgewogICAgY29uc3RydWN0b3IobWVzc2FnZSwgc3RhdHVzID0gNDAwKSB7IHN1" +
      "cGVyKG1lc3NhZ2UpOyB0aGlzLnN0YXR1cyA9IHN0YXR1czsgfQogIH0KCiAgLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDor7fmsYLlsIHoo4XvvJrnnJ/lrp7lkI7nq6/k" +
      "vJjlhYjvvIzlv4XopoHml7bpmY3nuqfmvJTnpLrmqKHlvI8KICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KICBhc3luYyBmdW5jdGlvbiBhcGkocGF0aCwgeyBtZXRob2QgPSAn" +
      "R0VUJywgYm9keSB9ID0ge30pIHsKICAgIGlmIChzdGF0ZS5kZW1vKSByZXR1cm4gZGVtb0FwaShwYXRoLCB7IG1ldGhvZCwgYm9k" +
      "eSB9KTsKCiAgICBsZXQgcmVzOwogICAgdHJ5IHsKICAgICAgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyBwYXRoLCB7CiAg" +
      "ICAgICAgbWV0aG9kLAogICAgICAgIGNyZWRlbnRpYWxzOiAnc2FtZS1vcmlnaW4nLAogICAgICAgIGhlYWRlcnM6IGJvZHkgIT09" +
      "IHVuZGVmaW5lZCA/IHsgJ2NvbnRlbnQtdHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9IDogdW5kZWZpbmVkLAogICAgICAgIGJv" +
      "ZHk6IGJvZHkgIT09IHVuZGVmaW5lZCA/IEpTT04uc3RyaW5naWZ5KGJvZHkpIDogdW5kZWZpbmVkLAogICAgICB9KTsKICAgIH0g" +
      "Y2F0Y2ggKG5ldHdvcmtFcnJvcikgewogICAgICBpZiAoIXN0YXRlLmFwaUNvbmZpcm1lZCkgcmV0dXJuIGZhbGxiYWNrVG9EZW1v" +
      "KHBhdGgsIG1ldGhvZCwgYm9keSk7CiAgICAgIHRocm93IG5ldyBFcnJvcign572R57uc5byC5bi477yM6K+35qOA5p+l6L+e5o6l" +
      "5ZCO6YeN6K+VJyk7CiAgICB9CgogICAgY29uc3QgY29udGVudFR5cGUgPSByZXMuaGVhZGVycy5nZXQoJ2NvbnRlbnQtdHlwZScp" +
      "IHx8ICcnOwogICAgaWYgKCFjb250ZW50VHlwZS5pbmNsdWRlcygnYXBwbGljYXRpb24vanNvbicpKSB7CiAgICAgIC8vIOmdmeaA" +
      "geaJmOeuoSAvIOWQjuerr+acqumDqOe9siDigJTigJQg6Ieq5Yqo6L+b5YWl5ryU56S65qih5byPCiAgICAgIGlmICghc3RhdGUu" +
      "YXBpQ29uZmlybWVkKSByZXR1cm4gZmFsbGJhY2tUb0RlbW8ocGF0aCwgbWV0aG9kLCBib2R5KTsKICAgICAgdGhyb3cgbmV3IEVy" +
      "cm9yKGDmnI3liqHov5Tlm57kuobpnZ7pooTmnJ/lhoXlrrkgKCR7cmVzLnN0YXR1c30pYCk7CiAgICB9CgogICAgc3RhdGUuYXBp" +
      "Q29uZmlybWVkID0gdHJ1ZTsKICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAg" +
      "aWYgKCFyZXMub2sgfHwgZGF0YS5vayA9PT0gZmFsc2UpIHsKICAgICAgdGhyb3cgbmV3IEFwaUVycm9yKGRhdGEuZXJyb3IgfHwg" +
      "YOivt+axguWksei0pSAoJHtyZXMuc3RhdHVzfSlgLCByZXMuc3RhdHVzKTsKICAgIH0KICAgIHJldHVybiBkYXRhOwogIH0KCiAg" +
      "ZnVuY3Rpb24gZmFsbGJhY2tUb0RlbW8ocGF0aCwgbWV0aG9kLCBib2R5KSB7CiAgICBlbmFibGVEZW1vTW9kZSgpOwogICAgcmV0" +
      "dXJuIGRlbW9BcGkocGF0aCwgeyBtZXRob2QsIGJvZHkgfSk7CiAgfQoKICBmdW5jdGlvbiBlbmFibGVEZW1vTW9kZSgpIHsKICAg" +
      "IGlmIChzdGF0ZS5kZW1vKSByZXR1cm47CiAgICBzdGF0ZS5kZW1vID0gdHJ1ZTsKICAgIGVsLmRlbW9CYW5uZXIuY2xhc3NMaXN0" +
      "LnJlbW92ZSgnaGlkZGVuJyk7CiAgICBlbC5hYm91dFZlcnNpb24udGV4dENvbnRlbnQgPSBg5YmN56uvIHYke0FQUF9WRVJTSU9O" +
      "fSDCtyDmvJTnpLrmqKHlvI9gOwogICAgdG9hc3QoJ+acquajgOa1i+WIsOWQjuerr+acjeWKoe+8jOW3suWIh+aNouWIsOa8lOek" +
      "uuaooeW8jycsICcnLCAzMjAwKTsKICB9CgogIC8qKiDmvJTnpLrnlKjnmoTnpLrkvovmlbDmja7vvIzku4XlnKggP2RlbW89MSDp" +
      "ppbmrKHov5vlhaXml7bngYzkuIDmrKEgKi8KICBmdW5jdGlvbiBzZWVkRGVtb0RhdGEoKSB7CiAgICBjb25zdCBkYiA9IGRlbW9S" +
      "ZWFkKCk7CiAgICBpZiAoZGIudXNlcikgcmV0dXJuOwogICAgY29uc3QgdG9kYXkgPSB0b2RheVN0cigpOwogICAgY29uc3QgZGF5" +
      "ID0gKGRlbHRhKSA9PiBzaGlmdERhdGUodG9kYXksIGRlbHRhKTsKICAgIC8vIFvmoIfpopgsIOaYr+WQpuWujOaIkCwg5pel5pyf" +
      "5YGP56e7XQogICAgY29uc3Qgc2FtcGxlcyA9IFsKICAgICAgWyfmiorlraPluqbmsYfmiqXnmoTmj5DnurLlhpnlrowgI+W3peS9" +
      "nCcsIGZhbHNlLCAwXSwKICAgICAgWyflm57lpI3lrqLmiLfnmoTpgq7ku7YgI+W3peS9nCcsIHRydWUsIDBdLAogICAgICBbJ+mi" +
      "hOe6puWRqOS6lOeahOS9k+ajgCAj55Sf5rS7JywgZmFsc2UsIDBdLAogICAgICBbJ+aZmuS4iiA4IOeCueWOu+WBpei6q+aIvyAj" +
      "55Sf5rS7JywgZmFsc2UsIC0xXSwKICAgICAgWyfor7vlrozjgIrljaHniYfnrJTorrDlhpnkvZzms5XjgIvnrKzkuInnq6AgI+mY" +
      "heivuycsIGZhbHNlLCAtMV0sCiAgICAgIFsn57uZ6Ziz5Y+w55qE57u/6JCd5rWH5rC0ICPnlJ/mtLsnLCB0cnVlLCAtMl0sCiAg" +
      "ICAgIFsn5pW055CG5LiL5LiA5q2l55qE5peF6KGM5riF5Y2VICPnlJ/mtLsnLCBmYWxzZSwgLTRdLAogICAgICBbJ3JldmlldyDl" +
      "kIzkuovnmoTmlrnmoYjmlofmoaMgI+W3peS9nCcsIHRydWUsIC01XSwKICAgIF07CiAgICBkYi51c2VyID0geyBpZDogJ2RlbW8t" +
      "dXNlcicsIHVzZXJuYW1lOiAnZGVtbycsIGNyZWF0ZWRBdDogTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCkgfTsKICAgIGRi" +
      "LnRvZG9zID0gc2FtcGxlcy5tYXAoKFt0aXRsZSwgZG9uZSwgZGVsdGFdLCBpKSA9PiAoewogICAgICBpZDogZGVtb0lkKCksCiAg" +
      "ICAgIHRpdGxlLAogICAgICBkb25lLAogICAgICBkYXRlOiBkYXkoZGVsdGEpLAogICAgICBvcmRlcjogaSwKICAgICAgY3JlYXRl" +
      "ZEF0OiBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxMDAwKSArIGksCiAgICB9KSk7CiAgICBkZW1vV3JpdGUoZGIpOwogIH0KCiAg" +
      "LyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAg" +
      "KiDop4blm77liIfmjaIKICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0gKi8KICBmdW5jdGlvbiBzaG93QXV0aCgpIHsKICAgIGVsLmJvb3QuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7" +
      "CiAgICBlbC5hdXRoVmlldy5jbGFzc0xpc3QucmVtb3ZlKCdoaWRkZW4nKTsKICAgIGVsLm1haW5WaWV3LmNsYXNzTGlzdC5hZGQo" +
      "J2hpZGRlbicpOwogICAgZWwuYXV0aFVzZXJuYW1lLmZvY3VzKHsgcHJldmVudFNjcm9sbDogdHJ1ZSB9KTsKICB9CgogIGFzeW5j" +
      "IGZ1bmN0aW9uIHNob3dNYWluKCkgewogICAgZWwuYm9vdC5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgIGVsLmF1dGhWaWV3" +
      "LmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgZWwubWFpblZpZXcuY2xhc3NMaXN0LnJlbW92ZSgnaGlkZGVuJyk7CiAgICBl" +
      "bC51c2VySW5pdGlhbC50ZXh0Q29udGVudCA9IChzdGF0ZS51c2VyPy51c2VybmFtZSB8fCAnVScpLnNsaWNlKDAsIDEpLnRvVXBw" +
      "ZXJDYXNlKCk7CiAgICBlbC5hY2NvdW50TmFtZS50ZXh0Q29udGVudCA9IHN0YXRlLnVzZXI/LnVzZXJuYW1lIHx8ICctJzsKICAg" +
      "IGF3YWl0IHJlZnJlc2goKTsgICAgICAgICAgLy8g5Li75YiX6KGo5LyY5YWI5riy5p+TCiAgICBsb2FkU2lkZWJhckRhdGEoKTsg" +
      "ICAgICAgIC8vIOS+p+agj+S4juWkh+S7vemFjee9ruW5tuihjOWKoOi9ve+8jOS4jemYu+WhnummluWxjwogICAgbG9hZEJhY2t1" +
      "cENvbmZpZygpOwogICAgZWwuYWRkSW5wdXQuZm9jdXMoeyBwcmV2ZW50U2Nyb2xsOiB0cnVlIH0pOwogICAgLy8gP3BhbmVsPXNl" +
      "dHRpbmdzIOeUqOS6juebtOaOpeaJk+W8gOiuvue9ruaKveWxie+8iOa8lOekui/miKrlm77nlKjvvIkKICAgIGlmIChVUkxfUEFS" +
      "QU1TLmdldCgncGFuZWwnKSA9PT0gJ3NldHRpbmdzJykgb3BlbkRyYXdlcigpOwogICAgLy8gP3BhbmVsPXNpZGViYXIg55So5LqO" +
      "55u05o6l5bGV5byA56e75Yqo56uv5L6n5qCP77yI5oiq5Zu+55So77yJCiAgICBpZiAoVVJMX1BBUkFNUy5nZXQoJ3BhbmVsJykg" +
      "PT09ICdzaWRlYmFyJykgb3BlblNpZGViYXIoKTsKICAgIC8vID9xPXh4eCDnm7TmjqXov5vlhaXmkJzntKLnirbmgIHvvIjmvJTn" +
      "pLov5oiq5Zu+55So77yJCiAgICBjb25zdCBxID0gVVJMX1BBUkFNUy5nZXQoJ3EnKTsKICAgIGlmIChxKSBzdGFydFNlYXJjaChx" +
      "KTsKICAgIC8vID9tb250aD1ZWVlZLU1NIOebtOaOpei/m+WFpeaVtOaciOinhuWbvu+8iOa8lOekui/miKrlm77nlKjvvIkKICAg" +
      "IGNvbnN0IG12ID0gVVJMX1BBUkFNUy5nZXQoJ21vbnRoJyk7CiAgICBpZiAobXYgJiYgL15cZHs0fS1cZHsyfSQvLnRlc3QobXYp" +
      "KSBvcGVuTW9udGgobXYpOwogIH0KCiAgLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDorqTor4EKICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KICBmdW5jdGlvbiBzZXRBdXRoTW9kZShtb2RlKSB7CiAgICBzdGF0ZS5h" +
      "dXRoTW9kZSA9IG1vZGU7CiAgICBlbC50YWJzLmZvckVhY2goKHQpID0+IHQuY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgdC5k" +
      "YXRhc2V0Lm1vZGUgPT09IG1vZGUpKTsKICAgIGVsLmF1dGhTdWJtaXRMYWJlbC50ZXh0Q29udGVudCA9IG1vZGUgPT09ICdsb2dp" +
      "bicgPyAn55m75b2VJyA6ICfliJvlu7rotKblj7cnOwogICAgZWwuYXV0aFBhc3N3b3JkLnNldEF0dHJpYnV0ZSgnYXV0b2NvbXBs" +
      "ZXRlJywgbW9kZSA9PT0gJ2xvZ2luJyA/ICdjdXJyZW50LXBhc3N3b3JkJyA6ICduZXctcGFzc3dvcmQnKTsKICAgIGVsLmF1dGhF" +
      "cnJvci5oaWRkZW4gPSB0cnVlOwogICAgZWwuYXV0aFBhc3N3b3JkLnZhbHVlID0gJyc7CiAgfQoKICBmdW5jdGlvbiBzaG93QXV0" +
      "aEVycm9yKG1lc3NhZ2UpIHsKICAgIGVsLmF1dGhFcnJvci50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICBlbC5hdXRoRXJyb3Iu" +
      "aGlkZGVuID0gZmFsc2U7CiAgfQoKICBlbC50YWJzLmZvckVhY2goKHRhYikgPT4gdGFiLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNr" +
      "JywgKCkgPT4gc2V0QXV0aE1vZGUodGFiLmRhdGFzZXQubW9kZSkpKTsKCiAgZWwudG9nZ2xlUGFzc3dvcmQuYWRkRXZlbnRMaXN0" +
      "ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBjb25zdCBpc1Bhc3N3b3JkID0gZWwuYXV0aFBhc3N3b3JkLnR5cGUgPT09ICdwYXNz" +
      "d29yZCc7CiAgICBlbC5hdXRoUGFzc3dvcmQudHlwZSA9IGlzUGFzc3dvcmQgPyAndGV4dCcgOiAncGFzc3dvcmQnOwogICAgZWwu" +
      "dG9nZ2xlUGFzc3dvcmQudGV4dENvbnRlbnQgPSBpc1Bhc3N3b3JkID8gJ/CfmYgnIDogJ/CfkYEnOwogIH0pOwoKICBlbC5hdXRo" +
      "Rm9ybS5hZGRFdmVudExpc3RlbmVyKCdzdWJtaXQnLCBhc3luYyAoZXZlbnQpID0+IHsKICAgIGV2ZW50LnByZXZlbnREZWZhdWx0" +
      "KCk7CiAgICBjb25zdCB1c2VybmFtZSA9IGVsLmF1dGhVc2VybmFtZS52YWx1ZS50cmltKCk7CiAgICBjb25zdCBwYXNzd29yZCA9" +
      "IGVsLmF1dGhQYXNzd29yZC52YWx1ZTsKCiAgICBpZiAoIXVzZXJuYW1lKSByZXR1cm4gc2hvd0F1dGhFcnJvcign6K+36L6T5YWl" +
      "55So5oi35ZCNJyk7CiAgICBpZiAocGFzc3dvcmQubGVuZ3RoIDwgNikgcmV0dXJuIHNob3dBdXRoRXJyb3IoJ+WvhueggeiHs+Ww" +
      "kSA2IOS9jScpOwoKICAgIGVsLmF1dGhTdWJtaXQuZGlzYWJsZWQgPSB0cnVlOwogICAgZWwuYXV0aFN1Ym1pdExhYmVsLnRleHRD" +
      "b250ZW50ID0gc3RhdGUuYXV0aE1vZGUgPT09ICdsb2dpbicgPyAn55m75b2V5Lit4oCmJyA6ICfliJvlu7rkuK3igKYnOwogICAg" +
      "ZWwuYXV0aEVycm9yLmhpZGRlbiA9IHRydWU7CgogICAgdHJ5IHsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGFwaShgL2F1dGgv" +
      "JHtzdGF0ZS5hdXRoTW9kZX1gLCB7IG1ldGhvZDogJ1BPU1QnLCBib2R5OiB7IHVzZXJuYW1lLCBwYXNzd29yZCB9IH0pOwogICAg" +
      "ICBzdGF0ZS51c2VyID0gZGF0YS51c2VyOwogICAgICBlbC5hdXRoUGFzc3dvcmQudmFsdWUgPSAnJzsKICAgICAgYXdhaXQgc2hv" +
      "d01haW4oKTsKICAgIH0gY2F0Y2ggKGVycikgewogICAgICBzaG93QXV0aEVycm9yKGVyci5tZXNzYWdlIHx8ICfmk43kvZzlpLHo" +
      "tKUnKTsKICAgIH0gZmluYWxseSB7CiAgICAgIGVsLmF1dGhTdWJtaXQuZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgZWwuYXV0aFN1" +
      "Ym1pdExhYmVsLnRleHRDb250ZW50ID0gc3RhdGUuYXV0aE1vZGUgPT09ICdsb2dpbicgPyAn55m75b2VJyA6ICfliJvlu7rotKbl" +
      "j7cnOwogICAgfQogIH0pOwoKICBlbC5sb2dvdXRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3luYyAoKSA9PiB7CiAg" +
      "ICB0cnkgeyBhd2FpdCBhcGkoJy9hdXRoL2xvZ291dCcsIHsgbWV0aG9kOiAnUE9TVCcgfSk7IH0gY2F0Y2ggeyAvKiBpZ25vcmUg" +
      "Ki8gfQogICAgc3RhdGUudXNlciA9IG51bGw7CiAgICBzdGF0ZS50b2RvcyA9IFtdOwogICAgY2FjaGVDbGVhckFsbCgpOwogICAg" +
      "Y2xvc2VEcmF3ZXIoKTsKICAgIHNob3dBdXRoKCk7CiAgICB0b2FzdCgn5bey6YCA5Ye655m75b2VJyk7CiAgfSk7CgogIGVsLnB3" +
      "ZFN1Ym1pdC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICAgIGNvbnN0IGN1cnJlbnRQYXNzd29yZCA9" +
      "IGVsLnB3ZEN1cnJlbnQudmFsdWU7CiAgICBjb25zdCBuZXdQYXNzd29yZCA9IGVsLnB3ZE5ldy52YWx1ZTsKICAgIGlmIChuZXdQ" +
      "YXNzd29yZC5sZW5ndGggPCA2KSByZXR1cm4gdG9hc3QoJ+aWsOWvhueggeiHs+WwkSA2IOS9jScsICdlcnInKTsKICAgIHRyeSB7" +
      "CiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBhcGkoJy9hdXRoL3Bhc3N3b3JkJywgeyBtZXRob2Q6ICdQT1NUJywgYm9keTogeyBj" +
      "dXJyZW50UGFzc3dvcmQsIG5ld1Bhc3N3b3JkIH0gfSk7CiAgICAgIHRvYXN0KGRhdGEubWVzc2FnZSB8fCAn5a+G56CB5bey5pu0" +
      "5pawJywgJ29rJyk7CiAgICAgIGVsLnB3ZEN1cnJlbnQudmFsdWUgPSAnJzsKICAgICAgZWwucHdkTmV3LnZhbHVlID0gJyc7CiAg" +
      "ICB9IGNhdGNoIChlcnIpIHsKICAgICAgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnInKTsKICAgIH0KICB9KTsKCiAgLyogLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDml6XmnJ8K" +
      "ICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8K" +
      "ICBmdW5jdGlvbiByZW5kZXJEYXRlKCkgewogICAgY29uc3QgeyB0aXRsZSwgc3ViIH0gPSBodW1hbkRhdGUoc3RhdGUuZGF0ZSk7" +
      "CiAgICBlbC5wYWdlVGl0bGUudGV4dENvbnRlbnQgPSB0aXRsZTsKICAgIGVsLnBhZ2VEYXRlLnRleHRDb250ZW50ID0gc3ViOwog" +
      "ICAgZWwuZGF0ZVBpbGxUZXh0LnRleHRDb250ZW50ID0gYCR7c3RhdGUuZGF0ZX0gJHtXRUVLREFZU1t3ZWVrZGF5T2Yoc3RhdGUu" +
      "ZGF0ZSldfWA7CiAgICBlbC5jb21wb3NlckRhdGVUZXh0LnRleHRDb250ZW50ID0gdGl0bGUgPT09ICfku4rlpKknID8gJ+S7iuWk" +
      "qScgOiBgJHtzdGF0ZS5kYXRlLnNsaWNlKDUpfSAke1dFRUtEQVlTW3dlZWtkYXlPZihzdGF0ZS5kYXRlKV19YDsKICAgIGNvbnN0" +
      "IGlzVG9kYXkgPSBzdGF0ZS5kYXRlID09PSB0b2RheVN0cigpOwogICAgZWwuY2FycnlvdmVyQnRuLnN0eWxlLnZpc2liaWxpdHkg" +
      "PSBpc1RvZGF5ID8gJ3Zpc2libGUnIDogJ2hpZGRlbic7CiAgICAvLyDml6Xljobop4blm77ot5/pmo/miYDpgInml6XmnJ8KICAg" +
      "IGNvbnN0IFt5LCBtXSA9IHN0YXRlLmRhdGUuc3BsaXQoJy0nKS5tYXAoTnVtYmVyKTsKICAgIGlmIChzdGF0ZS5jYWwueSAhPT0g" +
      "eSB8fCBzdGF0ZS5jYWwubSAhPT0gbSAtIDEpIHsKICAgICAgc3RhdGUuY2FsID0geyB5LCBtOiBtIC0gMSB9OwogICAgICByZW5k" +
      "ZXJDYWxlbmRhcigpOwogICAgfSBlbHNlIHsKICAgICAgcmVuZGVyQ2FsZW5kYXIoKTsgICAvLyDph43mlrDmoIfkuq7pgInkuK3m" +
      "l6UKICAgIH0KICB9CgogIGVsLnByZXZEYXkuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBpZiAoc3RhdGUu" +
      "bW9udGgpIHsgb3Blbk1vbnRoKHNoaWZ0TW9udGhTdHIoc3RhdGUubW9udGgsIC0xKSwgeyBjbG9zZVNpZGU6IGZhbHNlIH0pOyBy" +
      "ZXR1cm47IH0KICAgIGdvdG9EYXRlKHNoaWZ0RGF0ZShzdGF0ZS5kYXRlLCAtMSkpOwogIH0pOwogIGVsLm5leHREYXkuYWRkRXZl" +
      "bnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBpZiAoc3RhdGUubW9udGgpIHsgb3Blbk1vbnRoKHNoaWZ0TW9udGhTdHIo" +
      "c3RhdGUubW9udGgsIDEpLCB7IGNsb3NlU2lkZTogZmFsc2UgfSk7IHJldHVybjsgfQogICAgZ290b0RhdGUoc2hpZnREYXRlKHN0" +
      "YXRlLmRhdGUsIDEpKTsKICB9KTsKICAvKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0g6Ieq5a6a5LmJ5pel5pyf6YCJ5oup5by55bGC" +
      "IC0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwogIGNvbnN0IHBvcCA9IHsKICAgIG9wZW46IGZhbHNlLAogICAgdmlld1k6IDAsIHZp" +
      "ZXdNOiAwLCAgICAgIC8vIOW8ueWxguato+WcqOa1j+iniOeahOW5tCAvIOaciCgwLTExKQogICAgdmFsdWU6ICcnLCAgICAgICAg" +
      "ICAgICAgIC8vIOW9k+WJjemAieS4rSBZWVlZLU1NLURECiAgICBvcmlnaW46ICcnLCAgICAgICAgICAgICAgLy8g5omT5byA5pe2" +
      "55qE5Y6f5YC877yI44CM5riF56m644CN5oGi5aSN55So77yJCiAgICBhbmNob3I6IG51bGwsCiAgICBvblBpY2s6IG51bGwsCiAg" +
      "fTsKCiAgZnVuY3Rpb24gY2xvc2VEYXRlUG9wKCkgewogICAgcG9wLm9wZW4gPSBmYWxzZTsKICAgIGVsLmRhdGVQb3AuY2xhc3NM" +
      "aXN0LmFkZCgnaGlkZGVuJyk7CiAgICBkb2N1bWVudC5yZW1vdmVFdmVudExpc3RlbmVyKCdwb2ludGVyZG93bicsIHBvcC5vbk91" +
      "dHNpZGUsIHRydWUpOwogICAgZG9jdW1lbnQucmVtb3ZlRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIHBvcC5vbktleWRvd24sIHRy" +
      "dWUpOwogICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ3Njcm9sbCcsIGNsb3NlRGF0ZVBvcCwgdHJ1ZSk7CiAgICB3aW5k" +
      "b3cucmVtb3ZlRXZlbnRMaXN0ZW5lcigncmVzaXplJywgY2xvc2VEYXRlUG9wKTsKICB9CiAgcG9wLm9uT3V0c2lkZSA9IChlKSA9" +
      "PiB7CiAgICBpZiAoIWVsLmRhdGVQb3AuY29udGFpbnMoZS50YXJnZXQpICYmIGUudGFyZ2V0ICE9PSBwb3AuYW5jaG9yICYmICFw" +
      "b3AuYW5jaG9yPy5jb250YWlucyhlLnRhcmdldCkpIGNsb3NlRGF0ZVBvcCgpOwogIH07CiAgcG9wLm9uS2V5ZG93biA9IChlKSA9" +
      "PiB7IGlmIChlLmtleSA9PT0gJ0VzY2FwZScpIGNsb3NlRGF0ZVBvcCgpOyB9OwoKICBmdW5jdGlvbiBwb3NpdGlvbkRhdGVQb3Ao" +
      "KSB7CiAgICBjb25zdCByID0gcG9wLmFuY2hvci5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICAgIGNvbnN0IHBvcEVsID0gZWwu" +
      "ZGF0ZVBvcDsKICAgIGNvbnN0IHB3ID0gcG9wRWwub2Zmc2V0V2lkdGg7CiAgICBjb25zdCBwaCA9IHBvcEVsLm9mZnNldEhlaWdo" +
      "dDsKICAgIGxldCBsZWZ0ID0gci5sZWZ0ICsgci53aWR0aCAvIDIgLSBwdyAvIDI7CiAgICBsZWZ0ID0gTWF0aC5tYXgoMTAsIE1h" +
      "dGgubWluKGxlZnQsIHdpbmRvdy5pbm5lcldpZHRoIC0gcHcgLSAxMCkpOwogICAgbGV0IHRvcCA9IHIuYm90dG9tICsgODsKICAg" +
      "IGlmICh0b3AgKyBwaCA+IHdpbmRvdy5pbm5lckhlaWdodCAtIDEwKSB0b3AgPSByLnRvcCAtIHBoIC0gODsKICAgIHBvcEVsLnN0" +
      "eWxlLmxlZnQgPSBgJHtNYXRoLnJvdW5kKGxlZnQpfXB4YDsKICAgIHBvcEVsLnN0eWxlLnRvcCA9IGAke01hdGgucm91bmQoTWF0" +
      "aC5tYXgoMTAsIHRvcCkpfXB4YDsKICB9CgogIGZ1bmN0aW9uIHJlbmRlckRhdGVQb3AoKSB7CiAgICBlbC5wb3BUaXRsZS50ZXh0" +
      "Q29udGVudCA9IGAke3BvcC52aWV3WX0g5bm0ICR7cG9wLnZpZXdNICsgMX0g5pyIYDsKICAgIGVsLnBvcEdyaWQuaW5uZXJIVE1M" +
      "ID0gJyc7CiAgICBjb25zdCB0b2RheSA9IHRvZGF5U3RyKCk7CiAgICBmb3IgKGNvbnN0IG5hbWUgb2YgWyfml6UnLCAn5LiAJywg" +
      "J+S6jCcsICfkuIknLCAn5ZubJywgJ+S6lCcsICflha0nXSkgewogICAgICBlbC5wb3BHcmlkLmFwcGVuZENoaWxkKE9iamVjdC5h" +
      "c3NpZ24oZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpLCB7IGNsYXNzTmFtZTogJ2NhbC1kb3cnLCB0ZXh0Q29udGVudDog" +
      "bmFtZSB9KSk7CiAgICB9CiAgICBjb25zdCBmaXJzdCA9IG5ldyBEYXRlKHBvcC52aWV3WSwgcG9wLnZpZXdNLCAxKTsKICAgIGNv" +
      "bnN0IHN0YXJ0ID0gbmV3IERhdGUoZmlyc3QpOwogICAgc3RhcnQuc2V0RGF0ZSgxIC0gZmlyc3QuZ2V0RGF5KCkpOyAgIC8vIOih" +
      "pem9kOmmluWRqO+8jOWQq+ebuOmCu+aciAogICAgZm9yIChsZXQgaSA9IDA7IGkgPCA0MjsgaSArPSAxKSB7CiAgICAgIGNvbnN0" +
      "IGQgPSBuZXcgRGF0ZShzdGFydCk7CiAgICAgIGQuc2V0RGF0ZShzdGFydC5nZXREYXRlKCkgKyBpKTsKICAgICAgY29uc3QgZGF0" +
      "ZVN0ciA9IGAke2QuZ2V0RnVsbFllYXIoKX0tJHtwYWQoZC5nZXRNb250aCgpICsgMSl9LSR7cGFkKGQuZ2V0RGF0ZSgpKX1gOwog" +
      "ICAgICBjb25zdCBvdXRzaWRlID0gZC5nZXRNb250aCgpICE9PSBwb3Audmlld007CiAgICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50" +
      "LmNyZWF0ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAgICBidG4udHlwZSA9ICdidXR0b24nOwogICAgICBidG4uY2xhc3NOYW1lID0g" +
      "J2NhbC1kYXknCiAgICAgICAgKyAob3V0c2lkZSA/ICcgaXMtb3V0c2lkZScgOiAnJykKICAgICAgICArIChkYXRlU3RyID09PSB0" +
      "b2RheSA/ICcgaXMtdG9kYXknIDogJycpCiAgICAgICAgKyAoZGF0ZVN0ciA9PT0gcG9wLnZhbHVlID8gJyBpcy1zZWxlY3RlZCcg" +
      "OiAnJyk7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9IFN0cmluZyhkLmdldERhdGUoKSk7CiAgICAgIGJ0bi5hZGRFdmVudExpc3Rl" +
      "bmVyKCdjbGljaycsICgpID0+IHsKICAgICAgICBwb3AudmFsdWUgPSBkYXRlU3RyOwogICAgICAgIC8vIOeCueWIsOebuOmCu+ac" +
      "iOeahOaXpeacn+aXtu+8jOinhuWbvui3n+edgOe/u+i/h+WOuwogICAgICAgIHBvcC52aWV3WSA9IGQuZ2V0RnVsbFllYXIoKTsK" +
      "ICAgICAgICBwb3Audmlld00gPSBkLmdldE1vbnRoKCk7CiAgICAgICAgcmVuZGVyRGF0ZVBvcCgpOwogICAgICAgIHBvc2l0aW9u" +
      "RGF0ZVBvcCgpOwogICAgICAgIHBvcC5vblBpY2s/Lihwb3AudmFsdWUpOwogICAgICB9KTsKICAgICAgZWwucG9wR3JpZC5hcHBl" +
      "bmRDaGlsZChidG4pOwogICAgfQogIH0KCiAgZnVuY3Rpb24gb3BlbkRhdGVQb3AoYW5jaG9yLCB2YWx1ZSwgb25QaWNrKSB7CiAg" +
      "ICBwb3AuYW5jaG9yID0gYW5jaG9yOwogICAgcG9wLnZhbHVlID0gdmFsdWU7CiAgICBwb3Aub3JpZ2luID0gdmFsdWU7CiAgICBw" +
      "b3Aub25QaWNrID0gb25QaWNrOwogICAgcG9wLm9wZW4gPSB0cnVlOwogICAgY29uc3QgW3ksIG1dID0gdmFsdWUuc3BsaXQoJy0n" +
      "KS5tYXAoTnVtYmVyKTsKICAgIHBvcC52aWV3WSA9IHk7CiAgICBwb3Audmlld00gPSBtIC0gMTsKCiAgICBlbC5kYXRlUG9wLmNs" +
      "YXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgcmVuZGVyRGF0ZVBvcCgpOwogICAgcG9zaXRpb25EYXRlUG9wKCk7CgogICAg" +
      "ZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigncG9pbnRlcmRvd24nLCBwb3Aub25PdXRzaWRlLCB0cnVlKTsKICAgIGRvY3VtZW50" +
      "LmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCBwb3Aub25LZXlkb3duLCB0cnVlKTsKICAgIHdpbmRvdy5hZGRFdmVudExpc3Rl" +
      "bmVyKCdzY3JvbGwnLCBjbG9zZURhdGVQb3AsIHRydWUpOwogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ3Jlc2l6ZScsIGNs" +
      "b3NlRGF0ZVBvcCk7CiAgfQoKICAkKCdwb3AtcHJldi15ZWFyJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7IHBv" +
      "cC52aWV3WSAtPSAxOyByZW5kZXJEYXRlUG9wKCk7IH0pOwogICQoJ3BvcC1uZXh0LXllYXInKS5hZGRFdmVudExpc3RlbmVyKCdj" +
      "bGljaycsICgpID0+IHsgcG9wLnZpZXdZICs9IDE7IHJlbmRlckRhdGVQb3AoKTsgfSk7CiAgJCgncG9wLXByZXYtbW9udGgnKS5h" +
      "ZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgIGNvbnN0IGQgPSBuZXcgRGF0ZShwb3Audmlld1ksIHBvcC52aWV3" +
      "TSAtIDEsIDEpOwogICAgcG9wLnZpZXdZID0gZC5nZXRGdWxsWWVhcigpOyBwb3Audmlld00gPSBkLmdldE1vbnRoKCk7IHJlbmRl" +
      "ckRhdGVQb3AoKTsKICB9KTsKICAkKCdwb3AtbmV4dC1tb250aCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewog" +
      "ICAgY29uc3QgZCA9IG5ldyBEYXRlKHBvcC52aWV3WSwgcG9wLnZpZXdNICsgMSwgMSk7CiAgICBwb3Audmlld1kgPSBkLmdldEZ1" +
      "bGxZZWFyKCk7IHBvcC52aWV3TSA9IGQuZ2V0TW9udGgoKTsgcmVuZGVyRGF0ZVBvcCgpOwogIH0pOwogICQoJ3BvcC10b2RheScp" +
      "LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgcG9wLnZhbHVlID0gdG9kYXlTdHIoKTsKICAgIGNvbnN0IFt5" +
      "LCBtXSA9IHBvcC52YWx1ZS5zcGxpdCgnLScpLm1hcChOdW1iZXIpOwogICAgcG9wLnZpZXdZID0geTsgcG9wLnZpZXdNID0gbSAt" +
      "IDE7CiAgICByZW5kZXJEYXRlUG9wKCk7CiAgICBwb3Aub25QaWNrPy4ocG9wLnZhbHVlKTsKICAgIGNsb3NlRGF0ZVBvcCgpOwog" +
      "IH0pOwogICQoJ3BvcC1jbGVhcicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgcG9wLnZhbHVlID0gcG9w" +
      "Lm9yaWdpbjsKICAgIHBvcC5vblBpY2s/Lihwb3AudmFsdWUpOwogICAgY2xvc2VEYXRlUG9wKCk7CiAgfSk7CiAgJCgncG9wLW9r" +
      "JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBjbG9zZURhdGVQb3ApOwoKICBlbC5kYXRlUGlsbC5hZGRFdmVudExpc3RlbmVy" +
      "KCdjbGljaycsICgpID0+IHsKICAgIGlmIChwb3Aub3BlbikgeyBjbG9zZURhdGVQb3AoKTsgcmV0dXJuOyB9CiAgICBvcGVuRGF0" +
      "ZVBvcChlbC5kYXRlUGlsbCwgc3RhdGUuZGF0ZSwgKGQpID0+IGdvdG9EYXRlKGQpKTsKICB9KTsKICBlbC5jb21wb3NlckRhdGUu" +
      "YWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBpZiAocG9wLm9wZW4pIHsgY2xvc2VEYXRlUG9wKCk7IHJldHVy" +
      "bjsgfQogICAgb3BlbkRhdGVQb3AoZWwuY29tcG9zZXJEYXRlLCBzdGF0ZS5kYXRlLCAoZCkgPT4gZ290b0RhdGUoZCkpOwogIH0p" +
      "OwoKICBhc3luYyBmdW5jdGlvbiBnb3RvRGF0ZShkYXRlKSB7CiAgICBpZiAoc3RhdGUuc2VhcmNoLmFjdGl2ZSB8fCBlbC5zZWFy" +
      "Y2hJbnB1dC52YWx1ZSkgZXhpdFNlYXJjaCgpOwogICAgc3RhdGUubW9udGggPSBudWxsOwogICAgc3RhdGUuZGF0ZSA9IGRhdGU7" +
      "CiAgICByZW5kZXJEYXRlKCk7CiAgICBjbG9zZVNpZGViYXIoKTsKICAgIGF3YWl0IHJlZnJlc2goKTsKICB9CgogIC8qIC0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSDmnIjop4blm74gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCgogIC8q" +
      "KiDov5vlhaXmlbTmnIjop4blm77vvJrlsZXnpLror6XmnIjmiYDmnInku7vliqHvvIzmjInml6XmnJ/lgJLluo/liIbnu4QgKi8K" +
      "ICBhc3luYyBmdW5jdGlvbiBvcGVuTW9udGgobW9udGgsIHsgY2xvc2VTaWRlID0gdHJ1ZSB9ID0ge30pIHsKICAgIGlmIChzdGF0" +
      "ZS5zZWFyY2guYWN0aXZlIHx8IGVsLnNlYXJjaElucHV0LnZhbHVlKSBleGl0U2VhcmNoKCk7CiAgICBzdGF0ZS5tb250aCA9IG1v" +
      "bnRoOwoKICAgIC8vIOWQjOatpeaXpeWOhuS4juOAjOW9k+WJjeaXpeacn+OAjeS4iuS4i+aWh++8iGNvbXBvc2VyIOW9kuWxnuaX" +
      "peacn+iQveWcqOivpeaciOWGhe+8iQogICAgY29uc3QgW3ksIG1dID0gbW9udGguc3BsaXQoJy0nKS5tYXAoTnVtYmVyKTsKICAg" +
      "IHN0YXRlLmNhbCA9IHsgeSwgbTogbSAtIDEgfTsKICAgIGlmICghc3RhdGUuZGF0ZS5zdGFydHNXaXRoKGAke21vbnRofS1gKSkg" +
      "ewogICAgICBzdGF0ZS5kYXRlID0gc3RhdGUuc3RhdHMuZmluZCgocykgPT4gcy5kYXRlLnN0YXJ0c1dpdGgoYCR7bW9udGh9LWAp" +
      "KT8uZGF0ZSB8fCBgJHttb250aH0tMDFgOwogICAgfQoKICAgIHJlbmRlck1vbnRoSGVhZGVyKCk7CiAgICByZW5kZXJDYWxlbmRh" +
      "cigpOwogICAgY2xvc2VTaWRlICYmIGNsb3NlU2lkZWJhcigpOwogICAgYXdhaXQgcmVmcmVzaE1vbnRoKCk7CiAgfQoKICBmdW5j" +
      "dGlvbiBleGl0TW9udGgoKSB7CiAgICBzdGF0ZS5tb250aCA9IG51bGw7CiAgICByZW5kZXJEYXRlKCk7CiAgICByZW5kZXJMaXN0" +
      "KCk7CiAgICBlbC5hZGRJbnB1dC5mb2N1cyh7IHByZXZlbnRTY3JvbGw6IHRydWUgfSk7CiAgfQoKICAvKiog5pyI6KeG5Zu+55qE" +
      "6aG26YOo5qCH6aKY5LiO5pel5pyf5p2hICovCiAgZnVuY3Rpb24gcmVuZGVyTW9udGhIZWFkZXIoKSB7CiAgICBjb25zdCBbeSwg" +
      "bV0gPSBzdGF0ZS5tb250aC5zcGxpdCgnLScpLm1hcChOdW1iZXIpOwogICAgZWwucGFnZVRpdGxlLnRleHRDb250ZW50ID0gYCR7" +
      "eX0g5bm0ICR7bX0g5pyIYDsKICAgIGVsLnBhZ2VEYXRlLnRleHRDb250ZW50ID0gJ+aVtOaciOinhuWbviDCtyDmjInml6XmnJ/l" +
      "gJLluo8nOwogICAgZWwuZGF0ZVBpbGxUZXh0LnRleHRDb250ZW50ID0gYCR7c3RhdGUubW9udGh9IOWFqOaciGA7CiAgICAvLyBj" +
      "b21wb3NlciDlvZLlsZ7ml6XmnJ/kv53mjIHlnKjlvZPmnIjvvIzmlrDmt7vliqDnmoTku7vliqHkvJrokL3ov5vlvZPliY3mn6Xn" +
      "nIvnmoTmnIjku70KICAgIGVsLmNvbXBvc2VyRGF0ZVRleHQudGV4dENvbnRlbnQgPSBgJHtzdGF0ZS5kYXRlLnNsaWNlKDUpfSAk" +
      "e1dFRUtEQVlTW3dlZWtkYXlPZihzdGF0ZS5kYXRlKV19YDsKICAgIGVsLmNhcnJ5b3ZlckJ0bi5zdHlsZS52aXNpYmlsaXR5ID0g" +
      "J2hpZGRlbic7CiAgfQoKICAvKiog5bqU55So5pW05pyI5pWw5o2u5Yiw6KeG5Zu+77yIcmVmcmVzaE1vbnRoIOS4k+eUqO+8iSAq" +
      "LwogIGZ1bmN0aW9uIGFwcGx5TW9udGhEYXRhKG1vbnRoLCB0b2RvcykgewogICAgaWYgKHN0YXRlLm1vbnRoICE9PSBtb250aCkg" +
      "cmV0dXJuOyAgIC8vIOeUqOaIt+W3suWIh+i1sAogICAgc3RhdGUubW9udGhUb2RvcyA9IHRvZG9zOwogICAgY29uc3QgdW5kb25l" +
      "ID0gdG9kb3MuZmlsdGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGg7CiAgICBzdGF0ZS5yZW1haW5pbmcgPSB1bmRvbmU7CiAgICBz" +
      "dGF0ZS50b3RhbCA9IHRvZG9zLmxlbmd0aDsKICAgIGVsLnJlbWFpbmluZ0NvdW50LnRleHRDb250ZW50ID0gU3RyaW5nKHVuZG9u" +
      "ZSk7CiAgICBlbC5yZW1haW5pbmdMYWJlbC50ZXh0Q29udGVudCA9IHVuZG9uZSA9PT0gMAogICAgICA/ICh0b2Rvcy5sZW5ndGgg" +
      "PyAn5pys5pyI5YWo6YOo5a6M5oiQIPCfjoknIDogJ+mhueW+heWujOaIkCcpCiAgICAgIDogJ+mhueW+heWujOaIkCc7CiAgICBl" +
      "bC5jbGVhckRvbmVCdG4uZGlzYWJsZWQgPSAhdG9kb3Muc29tZSgodCkgPT4gdC5kb25lKTsKICAgIHJlbmRlckxpc3QoKTsKICB9" +
      "CgogIGFzeW5jIGZ1bmN0aW9uIHJlZnJlc2hNb250aCgpIHsKICAgIGNvbnN0IG1vbnRoID0gc3RhdGUubW9udGg7CiAgICBpZiAo" +
      "IW1vbnRoKSByZXR1cm47CgogICAgLy8gMSkg5pyJ57yT5a2Y77ya56uL5Y2z5riy5p+TCiAgICBjb25zdCBjYWNoZWQgPSBtb250" +
      "aENhY2hlLmdldChtb250aCk7CiAgICBpZiAoY2FjaGVkICYmIHN0YXRlLm1vbnRoID09PSBtb250aCkgYXBwbHlNb250aERhdGEo" +
      "bW9udGgsIGNhY2hlZCk7CgogICAgLy8gMikg5ZCO5Y+w5qCh5paw77yI5pWw5o2u5rKh5Y+Y5bCx5LiN6YeN57uY77yJCiAgICB0" +
      "cnkgewogICAgICBjb25zdCBkYXRhID0gYXdhaXQgYXBpKGAvdG9kb3M/bW9udGg9JHtlbmNvZGVVUklDb21wb25lbnQobW9udGgp" +
      "fWApOwogICAgICBpZiAoc3RhdGUubW9udGggIT09IG1vbnRoKSByZXR1cm47ICAgLy8g55So5oi35bey5YiH6LWwCiAgICAgIGNv" +
      "bnN0IHRvZG9zID0gZGF0YS50b2RvcyB8fCBbXTsKICAgICAgY29uc3QgdW5jaGFuZ2VkID0gY2FjaGVkICYmIEpTT04uc3RyaW5n" +
      "aWZ5KGNhY2hlZCkgPT09IEpTT04uc3RyaW5naWZ5KHRvZG9zKTsKICAgICAgaWYgKHVuY2hhbmdlZCkgcmV0dXJuOwogICAgICBp" +
      "ZiAobW9udGhDYWNoZS5zaXplID49IE1PTlRIX0NBQ0hFX01BWCkgbW9udGhDYWNoZS5kZWxldGUobW9udGhDYWNoZS5rZXlzKCku" +
      "bmV4dCgpLnZhbHVlKTsKICAgICAgbW9udGhDYWNoZS5zZXQobW9udGgsIHRvZG9zKTsKICAgICAgYXBwbHlNb250aERhdGEobW9u" +
      "dGgsIHRvZG9zKTsKCiAgICAgIC8vIDMpIOaVtOaciOaVsOaNrumhuuaJi+eBjOi/m+WNleaXpee8k+WtmO+8mueCueivpeaciOS7" +
      "u+S9leS4gOWkqemDveenkuW8gAogICAgICBjb25zdCBieURhdGUgPSBuZXcgTWFwKCk7CiAgICAgIGZvciAoY29uc3QgdCBvZiB0" +
      "b2RvcykgewogICAgICAgIGlmICghYnlEYXRlLmhhcyh0LmRhdGUpKSBieURhdGUuc2V0KHQuZGF0ZSwgW10pOwogICAgICAgIGJ5" +
      "RGF0ZS5nZXQodC5kYXRlKS5wdXNoKHQpOwogICAgICB9CiAgICAgIGZvciAoY29uc3QgW2QsIGxpc3RdIG9mIGJ5RGF0ZSkgewog" +
      "ICAgICAgIGlmICghZGF5Q2FjaGUuaGFzKGQpKSB7CiAgICAgICAgICBjYWNoZVNldERheShkLCBsaXN0LCBsaXN0LmZpbHRlcigo" +
      "dCkgPT4gIXQuZG9uZSkubGVuZ3RoLCBsaXN0Lmxlbmd0aCk7CiAgICAgICAgfQogICAgICB9CiAgICB9IGNhdGNoIChlcnIpIHsK" +
      "ICAgICAgaWYgKGVyci5zdGF0dXMgPT09IDQwMSkgeyBzdGF0ZS51c2VyID0gbnVsbDsgc2hvd0F1dGgoKTsgcmV0dXJuOyB9CiAg" +
      "ICAgIGlmICghY2FjaGVkKSB0b2FzdChlcnIubWVzc2FnZSwgJ2VycicpOwogICAgfQogIH0KCiAgLyogLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDljaHniYfmtYHmuLLmn5MK" +
      "ICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8K" +
      "ICBmdW5jdGlvbiByZW5kZXJMaXN0KCkgewogICAgZWwuZmVlZC5pbm5lckhUTUwgPSAnJzsKCiAgICBpZiAoc3RhdGUuc2VhcmNo" +
      "LmFjdGl2ZSkgewogICAgICBlbC5zZWFyY2hCYW5uZXIuY2xhc3NMaXN0LnJlbW92ZSgnaGlkZGVuJyk7CiAgICAgIGVsLnNlYXJj" +
      "aEJhbm5lclRleHQudGV4dENvbnRlbnQgPSBzdGF0ZS5zZWFyY2gubG9hZGluZwogICAgICAgID8gYOato+WcqOaQnOe0ouOAjCR7" +
      "c3RhdGUuc2VhcmNoLnF944CN4oCmYAogICAgICAgIDogYOaQnOe0ouOAjCR7c3RhdGUuc2VhcmNoLnF944CN77yaJHtzdGF0ZS5z" +
      "ZWFyY2gucmVzdWx0cy5sZW5ndGh9IOadoee7k+aenGA7CiAgICAgIGVsLnNlYXJjaEV4aXQudGV4dENvbnRlbnQgPSAn6YCA5Ye6" +
      "5pCc57SiJzsKICAgICAgcmVuZGVyU2VhcmNoUmVzdWx0cygpOwogICAgICByZXR1cm47CiAgICB9CgogICAgaWYgKHN0YXRlLm1v" +
      "bnRoKSB7CiAgICAgIGVsLnNlYXJjaEJhbm5lci5jbGFzc0xpc3QucmVtb3ZlKCdoaWRkZW4nKTsKICAgICAgY29uc3QgW3ksIG1d" +
      "ID0gc3RhdGUubW9udGguc3BsaXQoJy0nKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgdW5kb25lID0gc3RhdGUubW9udGhUb2Rv" +
      "cy5maWx0ZXIoKHQpID0+ICF0LmRvbmUpLmxlbmd0aDsKICAgICAgZWwuc2VhcmNoQmFubmVyVGV4dC50ZXh0Q29udGVudCA9IGAk" +
      "e3l9IOW5tCAke219IOaciCDCtyDlhbEgJHtzdGF0ZS5tb250aFRvZG9zLmxlbmd0aH0g5p2hIMK3ICR7dW5kb25lfSDpobnmnKrl" +
      "rozmiJBgOwogICAgICBlbC5zZWFyY2hFeGl0LnRleHRDb250ZW50ID0gJ+i/lOWbnuWNleaXpSc7CiAgICAgIHJlbmRlck1vbnRo" +
      "UmVzdWx0cygpOwogICAgICByZXR1cm47CiAgICB9CgogICAgZWwuc2VhcmNoQmFubmVyLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicp" +
      "OwogICAgcmVuZGVyRGF5TGlzdCgpOwogIH0KCiAgLyoqIOW9k+WJjeaXpeacn+eahOW+heWKnuWNoeeJhyAqLwogIGZ1bmN0aW9u" +
      "IHJlbmRlckRheUxpc3QoKSB7CiAgICBpZiAoIXN0YXRlLnRvZG9zLmxlbmd0aCkgewogICAgICBlbC5lbXB0eVN0YXRlLmNsYXNz" +
      "TGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgICBlbC5lbXB0eVRpdGxlLnRleHRDb250ZW50ID0gJ+i/memHjOi/mOayoeacieWu" +
      "ieaOkic7CiAgICAgIGVsLmVtcHR5U3ViLnRleHRDb250ZW50ID0gJ+WcqOS4iumdoueahOi+k+WFpeahhuaVsuS4i+esrOS4gOS7" +
      "tuS6i+WQpyc7CiAgICB9IGVsc2UgewogICAgICBlbC5lbXB0eVN0YXRlLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICBj" +
      "b25zdCBmcmFnbWVudCA9IGRvY3VtZW50LmNyZWF0ZURvY3VtZW50RnJhZ21lbnQoKTsKICAgICAgc3RhdGUudG9kb3MuZm9yRWFj" +
      "aCgodG9kbykgPT4gZnJhZ21lbnQuYXBwZW5kQ2hpbGQocmVuZGVySXRlbSh0b2RvLCB7IHNob3dEYXRlOiBmYWxzZSB9KSkpOwog" +
      "ICAgICBlbC5mZWVkLmFwcGVuZENoaWxkKGZyYWdtZW50KTsKICAgIH0KICAgIGVsLnJlbWFpbmluZ0NvdW50LnRleHRDb250ZW50" +
      "ID0gU3RyaW5nKHN0YXRlLnJlbWFpbmluZyk7CiAgICBlbC5yZW1haW5pbmdMYWJlbC50ZXh0Q29udGVudCA9IHN0YXRlLnJlbWFp" +
      "bmluZyA9PT0gMAogICAgICA/IChzdGF0ZS50b3RhbCA/ICflhajpg6jlrozmiJAg8J+OiScgOiAn6aG55b6F5a6M5oiQJykKICAg" +
      "ICAgOiAn6aG55b6F5a6M5oiQJzsKICAgIGVsLmNsZWFyRG9uZUJ0bi5kaXNhYmxlZCA9ICFzdGF0ZS50b2Rvcy5zb21lKCh0KSA9" +
      "PiB0LmRvbmUpOwogIH0KCiAgLyoqIOaQnOe0oue7k+aenO+8muaMieaXpeacn+WIhue7hOWxleekuiAqLwogIGZ1bmN0aW9uIHJl" +
      "bmRlclNlYXJjaFJlc3VsdHMoKSB7CiAgICBpZiAoIXN0YXRlLnNlYXJjaC5yZXN1bHRzLmxlbmd0aCkgewogICAgICBlbC5lbXB0" +
      "eVN0YXRlLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgICBlbC5lbXB0eVRpdGxlLnRleHRDb250ZW50ID0gc3RhdGUu" +
      "c2VhcmNoLmxvYWRpbmcgPyAn5q2j5Zyo5pCc57Si4oCmJyA6ICfmsqHmnInmib7liLDljLnphY3nmoTku7vliqEnOwogICAgICBl" +
      "bC5lbXB0eVN1Yi50ZXh0Q29udGVudCA9IHN0YXRlLnNlYXJjaC5sb2FkaW5nID8gJycgOiAn5o2i5Liq5YWz6ZSu6K+N6K+V6K+V" +
      "77yMI+agh+etviDkuZ/lj6/ku6Xnm7TmjqXmkJwnOwogICAgICByZXR1cm47CiAgICB9CiAgICBlbC5lbXB0eVN0YXRlLmNsYXNz" +
      "TGlzdC5hZGQoJ2hpZGRlbicpOwogICAgcmVuZGVyR3JvdXBlZEJ5RGF0ZShzdGF0ZS5zZWFyY2gucmVzdWx0cyk7CiAgfQoKICAv" +
      "Kiog5pyI6KeG5Zu+77ya5pW05pyI5Lu75Yqh5oyJ5pel5pyf5YiG57uE77yI5pel5pyf5YCS5bqP77yJ5bGV56S6ICovCiAgZnVu" +
      "Y3Rpb24gcmVuZGVyTW9udGhSZXN1bHRzKCkgewogICAgaWYgKCFzdGF0ZS5tb250aFRvZG9zLmxlbmd0aCkgewogICAgICBlbC5l" +
      "bXB0eVN0YXRlLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgICBlbC5lbXB0eVRpdGxlLnRleHRDb250ZW50ID0gJ+i/" +
      "meS4quaciOi/mOayoeacieS7u+WKoSc7CiAgICAgIGVsLmVtcHR5U3ViLnRleHRDb250ZW50ID0gJ+WcqOaXpeWOhuaIluaXtumX" +
      "tOe6v+mAieS4gOWkqe+8jOaVsuS4i+esrOS4gOS7tuS6i+WQpyc7CiAgICAgIHJldHVybjsKICAgIH0KICAgIGVsLmVtcHR5U3Rh" +
      "dGUuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICByZW5kZXJHcm91cGVkQnlEYXRlKHN0YXRlLm1vbnRoVG9kb3MpOwogIH0K" +
      "CiAgLyoqIOmAmueUqO+8muaMieaXpeacn+WIhue7hOa4suafk+WNoeeJh+a1ge+8jOe7hOWktOaYvuekuuOAjHgg5pyIIHgg5pel" +
      "IMK3IOWJqeS9mSAvIOWFsSBO44CNICovCiAgZnVuY3Rpb24gcmVuZGVyR3JvdXBlZEJ5RGF0ZShsaXN0KSB7CiAgICBjb25zdCBn" +
      "cm91cHMgPSBuZXcgTWFwKCk7CiAgICBmb3IgKGNvbnN0IHRvZG8gb2YgbGlzdCkgewogICAgICBpZiAoIWdyb3Vwcy5oYXModG9k" +
      "by5kYXRlKSkgZ3JvdXBzLnNldCh0b2RvLmRhdGUsIFtdKTsKICAgICAgZ3JvdXBzLmdldCh0b2RvLmRhdGUpLnB1c2godG9kbyk7" +
      "CiAgICB9CgogICAgY29uc3QgZnJhZ21lbnQgPSBkb2N1bWVudC5jcmVhdGVEb2N1bWVudEZyYWdtZW50KCk7CiAgICBmb3IgKGNv" +
      "bnN0IFtkYXRlLCBpdGVtc10gb2YgZ3JvdXBzKSB7CiAgICAgIGNvbnN0IGhlYWQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdk" +
      "aXYnKTsKICAgICAgaGVhZC5jbGFzc05hbWUgPSAnZmVlZC1kYXRlLWhlYWQnOwogICAgICBjb25zdCB7IHRpdGxlIH0gPSBodW1h" +
      "bkRhdGUoZGF0ZSk7CiAgICAgIGhlYWQuYXBwZW5kKAogICAgICAgIE9iamVjdC5hc3NpZ24oZG9jdW1lbnQuY3JlYXRlRWxlbWVu" +
      "dCgnc3BhbicpLCB7IHRleHRDb250ZW50OiB0aXRsZSB9KSwKICAgICAgICBPYmplY3QuYXNzaWduKGRvY3VtZW50LmNyZWF0ZUVs" +
      "ZW1lbnQoJ3NtYWxsJyksIHsgdGV4dENvbnRlbnQ6IGRhdGUgfSksCiAgICAgICAgT2JqZWN0LmFzc2lnbihkb2N1bWVudC5jcmVh" +
      "dGVFbGVtZW50KCdzcGFuJyksIHsKICAgICAgICAgIGNsYXNzTmFtZTogJ2ZlZWQtZGF0ZS1jb3VudCcsCiAgICAgICAgICB0ZXh0" +
      "Q29udGVudDogYCR7aXRlbXMuZmlsdGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGh9IOmhueacquWujOaIkCAvIOWFsSAke2l0ZW1z" +
      "Lmxlbmd0aH1gLAogICAgICAgIH0pLAogICAgICApOwogICAgICBmcmFnbWVudC5hcHBlbmRDaGlsZChoZWFkKTsKICAgICAgaXRl" +
      "bXMuZm9yRWFjaCgodG9kbykgPT4gZnJhZ21lbnQuYXBwZW5kQ2hpbGQocmVuZGVySXRlbSh0b2RvLCB7IHNob3dEYXRlOiBmYWxz" +
      "ZSB9KSkpOwogICAgfQogICAgZWwuZmVlZC5hcHBlbmRDaGlsZChmcmFnbWVudCk7CiAgfQoKICBjb25zdCBDSEVDS19TVkcgPSAn" +
      "PHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIGZpbGw9Im5vbmUiIHN0cm9rZT0iY3VycmVudENvbG9yIiBzdHJva2Utd2lkdGg9IjMu" +
      "NCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMjAgNkw5IDE3bC01LTUi" +
      "Lz48L3N2Zz4nOwogIGNvbnN0IFRSQVNIX1NWRyA9ICc8c3ZnIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tl" +
      "PSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJv" +
      "dW5kIj48cGF0aCBkPSJNMyA2aDE4TTggNlY0YTEgMSAwIDAgMSAxLTFoNmExIDEgMCAwIDEgMSAxdjJNMTkgNmwtMSAxNGEyIDIg" +
      "MCAwIDEtMiAySDhhMiAyIDAgMCAxLTItMkw1IDZNMTAgMTF2Nk0xNCAxMXY2Ii8+PC9zdmc+JzsKICBjb25zdCBQRU5DSUxfU1ZH" +
      "ID0gJzxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRo" +
      "PSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik0xNyAzYTIuODUgMi44" +
      "MyAwIDEgMSA0IDRMNy41IDIwLjUgMiAyMmwxLjUtNS41WiIvPjwvc3ZnPic7CgogIGZ1bmN0aW9uIGZvcm1hdFRpbWUodW5peCkg" +
      "ewogICAgY29uc3QgZCA9IG5ldyBEYXRlKChOdW1iZXIodW5peCkgfHwgMCkgKiAxMDAwKTsKICAgIHJldHVybiBgJHtwYWQoZC5n" +
      "ZXRIb3VycygpKX06JHtwYWQoZC5nZXRNaW51dGVzKCkpfWA7CiAgfQoKICBmdW5jdGlvbiByZW5kZXJJdGVtKHRvZG8sIHsgc2hv" +
      "d0RhdGUgPSBmYWxzZSB9ID0ge30pIHsKICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhcnRpY2xlJyk7" +
      "CiAgICBjYXJkLmNsYXNzTmFtZSA9IGBtZW1vJHt0b2RvLmRvbmUgPyAnIGRvbmUnIDogJyd9YDsKICAgIGNhcmQuZGF0YXNldC5p" +
      "ZCA9IHRvZG8uaWQ7CgogICAgLyogbWV0YSDooYzvvJrml7bpl7QgKyDmk43kvZwgKi8KICAgIGNvbnN0IG1ldGEgPSBkb2N1bWVu" +
      "dC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIG1ldGEuY2xhc3NOYW1lID0gJ21lbW8tbWV0YSc7CgogICAgY29uc3QgdGltZSA9" +
      "IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NwYW4nKTsKICAgIHRpbWUuY2xhc3NOYW1lID0gJ21lbW8tdGltZSc7CiAgICBjb25z" +
      "dCBjcmVhdGVkID0gbmV3IERhdGUoKE51bWJlcih0b2RvLmNyZWF0ZWRBdCkgfHwgMCkgKiAxMDAwKTsKICAgIGNvbnN0IGRhdGVU" +
      "ZXh0ID0gc2hvd0RhdGUKICAgICAgPyBgJHtjcmVhdGVkLmdldEZ1bGxZZWFyKCl9LyR7cGFkKGNyZWF0ZWQuZ2V0TW9udGgoKSAr" +
      "IDEpfS8ke3BhZChjcmVhdGVkLmdldERhdGUoKSl9IGAKICAgICAgOiAnJzsKICAgIHRpbWUudGV4dENvbnRlbnQgPSBgJHtkYXRl" +
      "VGV4dH0ke2Zvcm1hdFRpbWUodG9kby5jcmVhdGVkQXQpfWA7CgogICAgY29uc3QgYWN0cyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1l" +
      "bnQoJ3NwYW4nKTsKICAgIGFjdHMuY2xhc3NOYW1lID0gJ21lbW8tYWN0cyc7CgogICAgY29uc3QgZWRpdCA9IGRvY3VtZW50LmNy" +
      "ZWF0ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAgZWRpdC50eXBlID0gJ2J1dHRvbic7CiAgICBlZGl0LnNldEF0dHJpYnV0ZSgnYXJp" +
      "YS1sYWJlbCcsICfnvJbovpHku7vliqEnKTsKICAgIGVkaXQuaW5uZXJIVE1MID0gUEVOQ0lMX1NWRzsKCiAgICBjb25zdCBkZWwg" +
      "PSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdidXR0b24nKTsKICAgIGRlbC50eXBlID0gJ2J1dHRvbic7CiAgICBkZWwuY2xhc3NO" +
      "YW1lID0gJ21lbW8tZGVsJzsKICAgIGRlbC5zZXRBdHRyaWJ1dGUoJ2FyaWEtbGFiZWwnLCAn5Yig6Zmk5Lu75YqhJyk7CiAgICBk" +
      "ZWwuaW5uZXJIVE1MID0gVFJBU0hfU1ZHOwogICAgZGVsLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gZGVsZXRlVG9k" +
      "byh0b2RvLCBjYXJkKSk7CgogICAgYWN0cy5hcHBlbmQoZWRpdCwgZGVsKTsKICAgIG1ldGEuYXBwZW5kKHRpbWUsIGFjdHMpOwoK" +
      "ICAgIC8qIGJvZHnvvJrli77pgIkgKyDlhoXlrrkgKi8KICAgIGNvbnN0IGJvZHkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdk" +
      "aXYnKTsKICAgIGJvZHkuY2xhc3NOYW1lID0gJ21lbW8tYm9keSc7CgogICAgY29uc3QgY2hlY2sgPSBkb2N1bWVudC5jcmVhdGVF" +
      "bGVtZW50KCdidXR0b24nKTsKICAgIGNoZWNrLnR5cGUgPSAnYnV0dG9uJzsKICAgIGNoZWNrLmNsYXNzTmFtZSA9ICdjaGVjayc7" +
      "CiAgICBjaGVjay5zZXRBdHRyaWJ1dGUoJ2FyaWEtbGFiZWwnLCB0b2RvLmRvbmUgPyAn5qCH6K6w5Li65pyq5a6M5oiQJyA6ICfm" +
      "oIforrDkuLrlt7LlrozmiJAnKTsKICAgIGNoZWNrLnNldEF0dHJpYnV0ZSgnYXJpYS1wcmVzc2VkJywgU3RyaW5nKHRvZG8uZG9u" +
      "ZSkpOwogICAgY2hlY2suaW5uZXJIVE1MID0gQ0hFQ0tfU1ZHOwogICAgY2hlY2suYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAo" +
      "KSA9PiB0b2dnbGVUb2RvKHRvZG8pKTsKCiAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAg" +
      "ICB0ZXh0LmNsYXNzTmFtZSA9ICdtZW1vLXRleHQnOwogICAgdGV4dC50aXRsZSA9ICfplb/mjInmiJblj4zlh7vlj6/nvJbovpEn" +
      "OwogICAgcmVuZGVyVGl0bGVXaXRoVGFncyh0ZXh0LCB0b2RvLnRpdGxlKTsKICAgIGNvbnN0IGVkaXRBcGkgPSBiaW5kRWRpdChj" +
      "YXJkLCB0ZXh0LCB0b2RvKTsKICAgIGVkaXQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBlZGl0QXBpLmVudGVyRWRp" +
      "dCgpKTsKCiAgICBib2R5LmFwcGVuZChjaGVjaywgdGV4dCk7CiAgICBjYXJkLmFwcGVuZChtZXRhLCBib2R5KTsKICAgIHJldHVy" +
      "biBjYXJkOwogIH0KCiAgLyoqIOaKiuagh+mimOmHjOeahCAj5qCH562+IOa4suafk+aIkOWPr+eCueWHu+eahOW+veeJh++8iOWF" +
      "tuS9meS/neaMgee6r+aWh+acrO+8jOmYsiBYU1PvvIkgKi8KICBmdW5jdGlvbiByZW5kZXJUaXRsZVdpdGhUYWdzKGNvbnRhaW5l" +
      "ciwgdGl0bGUpIHsKICAgIGNvbnN0IHJlID0gbmV3IFJlZ0V4cChUQUdfUkUuc291cmNlLCAnZycpOwogICAgbGV0IGxhc3QgPSAw" +
      "OwogICAgbGV0IG1hdGNoOwogICAgd2hpbGUgKChtYXRjaCA9IHJlLmV4ZWModGl0bGUpKSkgewogICAgICBpZiAobWF0Y2guaW5k" +
      "ZXggPiBsYXN0KSB7CiAgICAgICAgY29udGFpbmVyLmFwcGVuZENoaWxkKGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKHRpdGxlLnNs" +
      "aWNlKGxhc3QsIG1hdGNoLmluZGV4KSkpOwogICAgICB9CiAgICAgIGNvbnN0IGNoaXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50" +
      "KCdidXR0b24nKTsKICAgICAgY2hpcC50eXBlID0gJ2J1dHRvbic7CiAgICAgIGNoaXAuY2xhc3NOYW1lID0gJ3RhZy1jaGlwJzsK" +
      "ICAgICAgY2hpcC50ZXh0Q29udGVudCA9IGAjJHttYXRjaFsxXX1gOwogICAgICBjaGlwLnRpdGxlID0gYOafpeeciyAjJHttYXRj" +
      "aFsxXX0g55qE5YWo6YOo5Lu75YqhYDsKICAgICAgY2hpcC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHN0YXJ0U2Vh" +
      "cmNoKGAjJHttYXRjaFsxXX1gKSk7CiAgICAgIGNvbnRhaW5lci5hcHBlbmRDaGlsZChjaGlwKTsKICAgICAgbGFzdCA9IG1hdGNo" +
      "LmluZGV4ICsgbWF0Y2hbMF0ubGVuZ3RoOwogICAgfQogICAgaWYgKGxhc3QgPCB0aXRsZS5sZW5ndGgpIHsKICAgICAgY29udGFp" +
      "bmVyLmFwcGVuZENoaWxkKGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKHRpdGxlLnNsaWNlKGxhc3QpKSk7CiAgICB9CiAgfQoKICAv" +
      "Kiog6ZW/5oyJIC8g5Y+M5Ye7IC8g6ZOF56yU6L+b5YWl6KGM5YaF57yW6L6RICovCiAgZnVuY3Rpb24gYmluZEVkaXQoY2FyZCwg" +
      "bm9kZSwgdG9kbykgewogICAgbGV0IHRpbWVyID0gbnVsbDsKCiAgICBjb25zdCBzdGFydCA9ICgpID0+IHsKICAgICAgdGltZXIg" +
      "PSBzZXRUaW1lb3V0KCgpID0+IHsgdGltZXIgPSBudWxsOyBlbnRlckVkaXQoKTsgfSwgNTIwKTsKICAgIH07CiAgICBjb25zdCBj" +
      "YW5jZWwgPSAoKSA9PiB7IGlmICh0aW1lcikgeyBjbGVhclRpbWVvdXQodGltZXIpOyB0aW1lciA9IG51bGw7IH0gfTsKCiAgICBu" +
      "b2RlLmFkZEV2ZW50TGlzdGVuZXIoJ3RvdWNoc3RhcnQnLCBzdGFydCwgeyBwYXNzaXZlOiB0cnVlIH0pOwogICAgbm9kZS5hZGRF" +
      "dmVudExpc3RlbmVyKCd0b3VjaGVuZCcsIGNhbmNlbCk7CiAgICBub2RlLmFkZEV2ZW50TGlzdGVuZXIoJ3RvdWNobW92ZScsIGNh" +
      "bmNlbCk7CiAgICBub2RlLmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNlZG93bicsIHN0YXJ0KTsKICAgIG5vZGUuYWRkRXZlbnRMaXN0" +
      "ZW5lcignbW91c2V1cCcsIGNhbmNlbCk7CiAgICBub2RlLmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNlbGVhdmUnLCBjYW5jZWwpOwog" +
      "ICAgbm9kZS5hZGRFdmVudExpc3RlbmVyKCdkYmxjbGljaycsIChlKSA9PiB7IGUucHJldmVudERlZmF1bHQoKTsgZW50ZXJFZGl0" +
      "KCk7IH0pOwoKICAgIGZ1bmN0aW9uIGVudGVyRWRpdCgpIHsKICAgICAgaWYgKG5vZGUuaXNDb250ZW50RWRpdGFibGUpIHJldHVy" +
      "bjsKICAgICAgY29uc3Qgb3JpZ2luYWwgPSB0b2RvLnRpdGxlOwogICAgICAvLyDlhYjmi43lubPmiJDnuq/mlofmnKzlho3nvJbo" +
      "vpHvvIjljrvmjonmoIfnrb7lvr3niYfvvIkKICAgICAgbm9kZS50ZXh0Q29udGVudCA9IG9yaWdpbmFsOwogICAgICBub2RlLmNv" +
      "bnRlbnRFZGl0YWJsZSA9ICd0cnVlJzsKICAgICAgbm9kZS5mb2N1cygpOwogICAgICBkb2N1bWVudC5nZXRTZWxlY3Rpb24oKT8u" +
      "c2VsZWN0QWxsQ2hpbGRyZW4obm9kZSk7CgogICAgICBjb25zdCBmaW5pc2ggPSBhc3luYyAoc2F2ZSkgPT4gewogICAgICAgIG5v" +
      "ZGUuY29udGVudEVkaXRhYmxlID0gJ2ZhbHNlJzsKICAgICAgICBjb25zdCBuZXh0ID0gbm9kZS50ZXh0Q29udGVudC5yZXBsYWNl" +
      "KC9ccysvZywgJyAnKS50cmltKCk7CgogICAgICAgIGlmICghc2F2ZSB8fCAhbmV4dCB8fCBuZXh0ID09PSBvcmlnaW5hbCkgewog" +
      "ICAgICAgICAgbm9kZS50ZXh0Q29udGVudCA9ICcnOwogICAgICAgICAgcmVuZGVyVGl0bGVXaXRoVGFncyhub2RlLCBvcmlnaW5h" +
      "bCk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIG5vZGUudGV4dENvbnRlbnQgPSBuZXh0OwogICAgICAgIHRy" +
      "eSB7CiAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgYXBpKGAvdG9kb3MvJHtlbmNvZGVVUklDb21wb25lbnQodG9kby5pZCl9" +
      "YCwgeyBtZXRob2Q6ICdQQVRDSCcsIGJvZHk6IHsgdGl0bGU6IG5leHQgfSB9KTsKICAgICAgICAgIE9iamVjdC5hc3NpZ24odG9k" +
      "bywgeyB0aXRsZTogbmV4dCB9KTsKICAgICAgICAgIHVwZGF0ZUNvdW50cyhkYXRhKTsKICAgICAgICAgIHN5bmNEYXlDYWNoZSgp" +
      "OwogICAgICAgICAgc2NoZWR1bGVTaWRlYmFyUmVmcmVzaCgpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgdG9h" +
      "c3QoZXJyLm1lc3NhZ2UsICdlcnInKTsKICAgICAgICB9IGZpbmFsbHkgewogICAgICAgICAgbm9kZS50ZXh0Q29udGVudCA9ICcn" +
      "OwogICAgICAgICAgcmVuZGVyVGl0bGVXaXRoVGFncyhub2RlLCB0b2RvLnRpdGxlKTsKICAgICAgICB9CiAgICAgIH07CgogICAg" +
      "ICBjb25zdCBvbktleSA9IChlKSA9PiB7CiAgICAgICAgaWYgKGUua2V5ID09PSAnRW50ZXInKSB7IGUucHJldmVudERlZmF1bHQo" +
      "KTsgbm9kZS5ibHVyKCk7IH0KICAgICAgICBpZiAoZS5rZXkgPT09ICdFc2NhcGUnKSB7IG5vZGUudGV4dENvbnRlbnQgPSBvcmln" +
      "aW5hbDsgbm9kZS5ibHVyKCk7IH0KICAgICAgfTsKICAgICAgY29uc3Qgb25CbHVyID0gKCkgPT4gewogICAgICAgIG5vZGUucmVt" +
      "b3ZlRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIG9uS2V5KTsKICAgICAgICBub2RlLnJlbW92ZUV2ZW50TGlzdGVuZXIoJ2JsdXIn" +
      "LCBvbkJsdXIpOwogICAgICAgIGZpbmlzaChub2RlLnRleHRDb250ZW50LnRyaW0oKSAhPT0gb3JpZ2luYWwpOwogICAgICB9OwoK" +
      "ICAgICAgbm9kZS5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgb25LZXkpOwogICAgICBub2RlLmFkZEV2ZW50TGlzdGVuZXIo" +
      "J2JsdXInLCBvbkJsdXIpOwogICAgfQoKICAgIHJldHVybiB7IGVudGVyRWRpdCB9OwogIH0KCiAgZnVuY3Rpb24gdXBkYXRlQ291" +
      "bnRzKGRhdGEpIHsKICAgIGlmICh0eXBlb2YgZGF0YT8ucmVtYWluaW5nID09PSAnbnVtYmVyJykgc3RhdGUucmVtYWluaW5nID0g" +
      "ZGF0YS5yZW1haW5pbmc7CiAgICBpZiAodHlwZW9mIGRhdGE/LnRvdGFsID09PSAnbnVtYmVyJykgc3RhdGUudG90YWwgPSBkYXRh" +
      "LnRvdGFsOwogICAgZWwucmVtYWluaW5nQ291bnQudGV4dENvbnRlbnQgPSBTdHJpbmcoc3RhdGUucmVtYWluaW5nKTsKICAgIGVs" +
      "LnJlbWFpbmluZ0xhYmVsLnRleHRDb250ZW50ID0gc3RhdGUucmVtYWluaW5nID09PSAwCiAgICAgID8gKHN0YXRlLnRvdGFsID8g" +
      "J+WFqOmDqOWujOaIkCDwn46JJyA6ICfpobnlvoXlrozmiJAnKQogICAgICA6ICfpobnlvoXlrozmiJAnOwogICAgZWwuY2xlYXJE" +
      "b25lQnRuLmRpc2FibGVkID0gIXN0YXRlLnRvZG9zLnNvbWUoKHQpID0+IHQuZG9uZSk7CiAgfQoKICBhc3luYyBmdW5jdGlvbiBy" +
      "ZWZyZXNoKCkgewogICAgY29uc3QgZGF0ZSA9IHN0YXRlLmRhdGU7CiAgICBjb25zdCBjYWNoZWQgPSBkYXlDYWNoZS5nZXQoZGF0" +
      "ZSk7CgogICAgLy8gMSkg5pyJ57yT5a2Y77ya56uL5Y2z5riy5p+T77yM55So5oi36Zu2562J5b6FCiAgICBpZiAoY2FjaGVkICYm" +
      "IHN0YXRlLmRhdGUgPT09IGRhdGUgJiYgIXN0YXRlLm1vbnRoICYmICFzdGF0ZS5zZWFyY2guYWN0aXZlKSB7CiAgICAgIHN0YXRl" +
      "LnRvZG9zID0gY2FjaGVkLnRvZG9zOwogICAgICBzdGF0ZS5yZW1haW5pbmcgPSBjYWNoZWQucmVtYWluaW5nOwogICAgICBzdGF0" +
      "ZS50b3RhbCA9IGNhY2hlZC50b3RhbDsKICAgICAgcmVuZGVyTGlzdCgpOwogICAgfQoKICAgIC8vIDIpIOWQjuWPsOivt+axguac" +
      "gOaWsOaVsOaNru+8iOaciee8k+WtmOaXtuaVsOaNruayoeWPmOWwseS4jemHjee7mO+8jOmBv+WFjemXqueDge+8iQogICAgdHJ5" +
      "IHsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGFwaShgL3RvZG9zP2RhdGU9JHtlbmNvZGVVUklDb21wb25lbnQoZGF0ZSl9YCk7" +
      "CiAgICAgIGNvbnN0IHRvZG9zID0gZGF0YS50b2RvcyB8fCBbXTsKICAgICAgY29uc3QgcmVtYWluaW5nID0gZGF0YS5yZW1haW5p" +
      "bmcgPz8gdG9kb3MuZmlsdGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGg7CiAgICAgIGNvbnN0IHRvdGFsID0gZGF0YS50b3RhbCA/" +
      "PyB0b2Rvcy5sZW5ndGg7CiAgICAgIGNvbnN0IHVuY2hhbmdlZCA9IGNhY2hlZAogICAgICAgICYmIGNhY2hlZC5yZW1haW5pbmcg" +
      "PT09IHJlbWFpbmluZwogICAgICAgICYmIGNhY2hlZC50b3RhbCA9PT0gdG90YWwKICAgICAgICAmJiBKU09OLnN0cmluZ2lmeShj" +
      "YWNoZWQudG9kb3MpID09PSBKU09OLnN0cmluZ2lmeSh0b2Rvcyk7CiAgICAgIGlmICghdW5jaGFuZ2VkKSBjYWNoZVNldERheShk" +
      "YXRlLCB0b2RvcywgcmVtYWluaW5nLCB0b3RhbCk7CgogICAgICBpZiAoc3RhdGUuZGF0ZSAhPT0gZGF0ZSB8fCBzdGF0ZS5tb250" +
      "aCB8fCBzdGF0ZS5zZWFyY2guYWN0aXZlKSByZXR1cm47ICAgLy8g55So5oi35bey5YiH6LWwCiAgICAgIGlmICh1bmNoYW5nZWQp" +
      "IHJldHVybjsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyDnlLvpnaLlt7LmmK/m" +
      "nIDmlrAKICAgICAgc3RhdGUudG9kb3MgPSB0b2RvczsKICAgICAgc3RhdGUucmVtYWluaW5nID0gcmVtYWluaW5nOwogICAgICBz" +
      "dGF0ZS50b3RhbCA9IHRvdGFsOwogICAgICByZW5kZXJMaXN0KCk7CgogICAgICAvLyAzKSDpobrmiYvpooTlj5bliY3kuIDlpKkv" +
      "5ZCO5LiA5aSp77yM5bem5Y+z5YiH5o2i5pel5pyf5pe256eS5byACiAgICAgIHByZWZldGNoRGF5KHNoaWZ0RGF0ZShkYXRlLCAt" +
      "MSkpOwogICAgICBwcmVmZXRjaERheShzaGlmdERhdGUoZGF0ZSwgMSkpOwogICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgIGlmIChl" +
      "cnIuc3RhdHVzID09PSA0MDEpIHsgc3RhdGUudXNlciA9IG51bGw7IHNob3dBdXRoKCk7IHJldHVybjsgfQogICAgICBpZiAoIWNh" +
      "Y2hlZCkgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnInKTsgICAvLyDlt7LmnInnvJPlrZjlhoXlrrnlnKjlsZXnpLrml7bpnZnpu5gK" +
      "ICAgIH0KICB9CgogIC8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLSAqCiAgICog5L6n5qCP77ya57uf6K6hIC8g5pel5Y6GIC8g5qCH562+IC8g5pe26Ze057q/CiAgICogLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgbGV0IHNpZGViYXJU" +
      "aW1lciA9IG51bGw7CiAgLyoqIOaVsOaNruWPmOabtOWQjumdmem7mOWIt+aWsOS+p+agj++8iOmYsuaKlu+8jOmBv+WFjemikee5" +
      "geivt+axgu+8iSAqLwogIGZ1bmN0aW9uIHNjaGVkdWxlU2lkZWJhclJlZnJlc2goKSB7CiAgICBjbGVhclRpbWVvdXQoc2lkZWJh" +
      "clRpbWVyKTsKICAgIHNpZGViYXJUaW1lciA9IHNldFRpbWVvdXQobG9hZFNpZGViYXJEYXRhLCA5MDApOwogIH0KCiAgYXN5bmMg" +
      "ZnVuY3Rpb24gbG9hZFNpZGViYXJEYXRhKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgW3N0YXRzUmVzLCB0YWdzUmVzXSA9IGF3" +
      "YWl0IFByb21pc2UuYWxsKFsKICAgICAgICBhcGkoJy90b2Rvcy9zdGF0cz9kYXlzPTM2NScpLAogICAgICAgIGFwaSgnL3RhZ3Mn" +
      "KSwKICAgICAgXSk7CiAgICAgIHN0YXRlLnN0YXRzID0gc3RhdHNSZXMuc3RhdHMgfHwgW107CiAgICAgIHN0YXRlLnRhZ3MgPSB0" +
      "YWdzUmVzLnRhZ3MgfHwgW107CiAgICB9IGNhdGNoIHsgLyog6Z2Z6buY5aSx6LSl77yM5LiN5b2x5ZON5Li75rWB56iLICovIH0K" +
      "ICAgIHJlbmRlclN0YXRzKCk7CiAgICByZW5kZXJDYWxlbmRhcigpOwogICAgcmVuZGVyVGFncygpOwogICAgcmVuZGVyVGltZWxp" +
      "bmUoKTsKICB9CgogIGZ1bmN0aW9uIHJlbmRlclN0YXRzKCkgewogICAgbGV0IHRvdGFsID0gMDsKICAgIGxldCByZW1haW5pbmcg" +
      "PSAwOwogICAgZm9yIChjb25zdCBzIG9mIHN0YXRlLnN0YXRzKSB7IHRvdGFsICs9IHMudG90YWw7IHJlbWFpbmluZyArPSBzLnJl" +
      "bWFpbmluZzsgfQogICAgZWwuc3RhdERheXMudGV4dENvbnRlbnQgPSBTdHJpbmcoc3RhdGUuc3RhdHMubGVuZ3RoKTsKICAgIGVs" +
      "LnN0YXRUb3RhbC50ZXh0Q29udGVudCA9IFN0cmluZyh0b3RhbCk7CiAgICBlbC5zdGF0RG9uZS50ZXh0Q29udGVudCA9IFN0cmlu" +
      "Zyh0b3RhbCAtIHJlbWFpbmluZyk7CiAgfQoKICBmdW5jdGlvbiByZW5kZXJDYWxlbmRhcigpIHsKICAgIGNvbnN0IHsgeSwgbSB9" +
      "ID0gc3RhdGUuY2FsOwogICAgZWwuY2FsVGl0bGUudGV4dENvbnRlbnQgPSBgJHt5fSDlubQgJHttICsgMX0g5pyIYDsKICAgIGVs" +
      "LmNhbFRpdGxlLnRpdGxlID0gYOafpeeciyAke3l9IOW5tCAke20gKyAxfSDmnIjlhajpg6jku7vliqFgOwogICAgZWwuY2FsZW5k" +
      "YXIuaW5uZXJIVE1MID0gJyc7CgogICAgY29uc3QgYnlEYXRlID0gbmV3IE1hcChzdGF0ZS5zdGF0cy5tYXAoKHMpID0+IFtzLmRh" +
      "dGUsIHNdKSk7CiAgICBjb25zdCB0b2RheSA9IHRvZGF5U3RyKCk7CiAgICBmb3IgKGNvbnN0IG5hbWUgb2YgWyfml6UnLCAn5LiA" +
      "JywgJ+S6jCcsICfkuIknLCAn5ZubJywgJ+S6lCcsICflha0nXSkgewogICAgICBlbC5jYWxlbmRhci5hcHBlbmRDaGlsZChPYmpl" +
      "Y3QuYXNzaWduKGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NwYW4nKSwgeyBjbGFzc05hbWU6ICdjYWwtZG93JywgdGV4dENvbnRl" +
      "bnQ6IG5hbWUgfSkpOwogICAgfQoKICAgIGNvbnN0IGZpcnN0RG93ID0gbmV3IERhdGUoeSwgbSwgMSkuZ2V0RGF5KCk7CiAgICBj" +
      "b25zdCBkYXlzSW5Nb250aCA9IG5ldyBEYXRlKHksIG0gKyAxLCAwKS5nZXREYXRlKCk7CiAgICBmb3IgKGxldCBpID0gMDsgaSA8" +
      "IGZpcnN0RG93OyBpICs9IDEpIHsKICAgICAgZWwuY2FsZW5kYXIuYXBwZW5kQ2hpbGQoT2JqZWN0LmFzc2lnbihkb2N1bWVudC5j" +
      "cmVhdGVFbGVtZW50KCdzcGFuJyksIHsgY2xhc3NOYW1lOiAnY2FsLWJsYW5rJyB9KSk7CiAgICB9CiAgICBmb3IgKGxldCBkID0g" +
      "MTsgZCA8PSBkYXlzSW5Nb250aDsgZCArPSAxKSB7CiAgICAgIGNvbnN0IGRhdGVTdHIgPSBgJHt5fS0ke3BhZChtICsgMSl9LSR7" +
      "cGFkKGQpfWA7CiAgICAgIGNvbnN0IGluZm8gPSBieURhdGUuZ2V0KGRhdGVTdHIpOwogICAgICBjb25zdCBidG4gPSBkb2N1bWVu" +
      "dC5jcmVhdGVFbGVtZW50KCdidXR0b24nKTsKICAgICAgYnRuLnR5cGUgPSAnYnV0dG9uJzsKICAgICAgYnRuLmNsYXNzTmFtZSA9" +
      "ICdjYWwtZGF5JwogICAgICAgICsgKGluZm8gPyAnIGhhcy10YXNrcycgOiAnJykKICAgICAgICArIChkYXRlU3RyID09PSB0b2Rh" +
      "eSA/ICcgaXMtdG9kYXknIDogJycpCiAgICAgICAgKyAoZGF0ZVN0ciA9PT0gc3RhdGUuZGF0ZSA/ICcgaXMtc2VsZWN0ZWQnIDog" +
      "JycpOwogICAgICBidG4udGV4dENvbnRlbnQgPSBTdHJpbmcoZCk7CiAgICAgIGlmIChpbmZvKSB7CiAgICAgICAgYnRuLnRpdGxl" +
      "ID0gYCR7ZGF0ZVN0cn0gwrcgJHtpbmZvLnJlbWFpbmluZ30g6aG55pyq5a6M5oiQIC8g5YWxICR7aW5mby50b3RhbH1gOwogICAg" +
      "ICAgIGJ0bi5hcHBlbmRDaGlsZChPYmplY3QuYXNzaWduKGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NwYW4nKSwgeyBjbGFzc05h" +
      "bWU6ICdkb3QnIH0pKTsKICAgICAgfQogICAgICBidG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBnb3RvRGF0ZShk" +
      "YXRlU3RyKSk7CiAgICAgIGVsLmNhbGVuZGFyLmFwcGVuZENoaWxkKGJ0bik7CiAgICB9CiAgfQoKICBlbC5jYWxQcmV2LmFkZEV2" +
      "ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gc2hpZnRNb250aCgtMSkpOwogIGVsLmNhbE5leHQuYWRkRXZlbnRMaXN0ZW5lcign" +
      "Y2xpY2snLCAoKSA9PiBzaGlmdE1vbnRoKDEpKTsKICAvLyDngrnlh7vml6XljobmoIfpopgg4oaSIOafpeeci+ivpeaciOWFqOmD" +
      "qOS7u+WKoeeahOaVtOaciOinhuWbvgogIGVsLmNhbFRpdGxlLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gb3Blbk1v" +
      "bnRoKGAke3N0YXRlLmNhbC55fS0ke3BhZChzdGF0ZS5jYWwubSArIDEpfWApKTsKICBmdW5jdGlvbiBzaGlmdE1vbnRoKGRlbHRh" +
      "KSB7CiAgICBjb25zdCBkID0gbmV3IERhdGUoc3RhdGUuY2FsLnksIHN0YXRlLmNhbC5tICsgZGVsdGEsIDEpOwogICAgc3RhdGUu" +
      "Y2FsID0geyB5OiBkLmdldEZ1bGxZZWFyKCksIG06IGQuZ2V0TW9udGgoKSB9OwogICAgcmVuZGVyQ2FsZW5kYXIoKTsKICB9Cgog" +
      "IGZ1bmN0aW9uIHJlbmRlclRhZ3MoKSB7CiAgICBlbC50YWdzQmxvY2suY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZGVuJywgIXN0YXRl" +
      "LnRhZ3MubGVuZ3RoKTsKICAgIGVsLnRhZ3NMaXN0LmlubmVySFRNTCA9ICcnOwogICAgc3RhdGUudGFncy5mb3JFYWNoKCh7IG5h" +
      "bWUsIGNvdW50IH0pID0+IHsKICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYnV0dG9uJyk7CiAgICAg" +
      "IHJvdy50eXBlID0gJ2J1dHRvbic7CiAgICAgIHJvdy5jbGFzc05hbWUgPSAndGFnLXJvdyc7CiAgICAgIHJvdy50aXRsZSA9IGDm" +
      "n6XnnIsgIyR7bmFtZX0g55qE5YWo6YOo5Lu75YqhYDsKICAgICAgcm93LmFwcGVuZCgKICAgICAgICBPYmplY3QuYXNzaWduKGRv" +
      "Y3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NwYW4nKSwgeyBjbGFzc05hbWU6ICd0YWctaGFzaCcsIHRleHRDb250ZW50OiAnIycgfSks" +
      "CiAgICAgICAgT2JqZWN0LmFzc2lnbihkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzcGFuJyksIHsgdGV4dENvbnRlbnQ6IG5hbWUg" +
      "fSksCiAgICAgICAgT2JqZWN0LmFzc2lnbihkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdiJyksIHsgdGV4dENvbnRlbnQ6IFN0cmlu" +
      "Zyhjb3VudCkgfSksCiAgICAgICk7CiAgICAgIHJvdy5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHN0YXJ0U2VhcmNo" +
      "KGAjJHtuYW1lfWApKTsKICAgICAgZWwudGFnc0xpc3QuYXBwZW5kQ2hpbGQocm93KTsKICAgIH0pOwogIH0KCiAgZnVuY3Rpb24g" +
      "cmVuZGVyVGltZWxpbmUoKSB7CiAgICBlbC50aW1lbGluZUJsb2NrLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicsICFzdGF0ZS5z" +
      "dGF0cy5sZW5ndGgpOwogICAgZWwudGltZWxpbmVMaXN0LmlubmVySFRNTCA9ICcnOwoKICAgIC8vIHN0YXRzIOW3suaMieaXpeac" +
      "n+WAkuW6j++8muaMiSDlubQg4oaSIOaciCDogZrlkIjvvIzorrDlvZXmr4/mnIgv5q+P5bm05pyA6L+R5LiA5Liq5pyJ5Lu75Yqh" +
      "55qE5pel5pyfCiAgICBjb25zdCB5ZWFycyA9IG5ldyBNYXAoKTsKICAgIGZvciAoY29uc3QgcyBvZiBzdGF0ZS5zdGF0cykgewog" +
      "ICAgICBjb25zdCBbeSwgbV0gPSBzLmRhdGUuc3BsaXQoJy0nKS5tYXAoTnVtYmVyKTsKICAgICAgaWYgKCF5ZWFycy5oYXMoeSkp" +
      "IHllYXJzLnNldCh5LCB7IGNvdW50OiAwLCBsYXRlc3Q6IHMuZGF0ZSwgbW9udGhzOiBuZXcgTWFwKCkgfSk7CiAgICAgIGNvbnN0" +
      "IHllYXIgPSB5ZWFycy5nZXQoeSk7CiAgICAgIHllYXIuY291bnQgKz0gcy50b3RhbDsKICAgICAgaWYgKCF5ZWFyLm1vbnRocy5o" +
      "YXMobSkpIHllYXIubW9udGhzLnNldChtLCB7IGNvdW50OiAwLCBsYXRlc3Q6IHMuZGF0ZSB9KTsKICAgICAgeWVhci5tb250aHMu" +
      "Z2V0KG0pLmNvdW50ICs9IHMudG90YWw7CiAgICB9CgogICAgZm9yIChjb25zdCBbeSwgeWVhcl0gb2YgeWVhcnMpIHsKICAgICAg" +
      "Y29uc3QgbGF0ZXN0TW9udGggPSBBcnJheS5mcm9tKHllYXIubW9udGhzLmtleXMoKSlbMF07CiAgICAgIGNvbnN0IHllYXJSb3cg" +
      "PSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgeWVhclJvdy5jbGFzc05hbWUgPSAndGwteWVhcic7CiAgICAg" +
      "IHllYXJSb3cudGl0bGUgPSBg5p+l55yLICR7eX0g5bm0ICR7bGF0ZXN0TW9udGh9IOaciOWPiuabtOaXqeeahOS7u+WKoWA7CiAg" +
      "ICAgIHllYXJSb3cuYXBwZW5kKAogICAgICAgIE9iamVjdC5hc3NpZ24oZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpLCB7" +
      "IHRleHRDb250ZW50OiBTdHJpbmcoeSkgfSksCiAgICAgICAgT2JqZWN0LmFzc2lnbihkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdz" +
      "bWFsbCcpLCB7IHRleHRDb250ZW50OiBgJHt5ZWFyLmNvdW50fSDmnaFgIH0pLAogICAgICApOwogICAgICAvLyDngrnlh7vlubTk" +
      "u70g4oaSIOaJk+W8gOivpeW5tOacgOi/keacieS7u+WKoeeahOaciOS7veeahOaVtOaciOinhuWbvgogICAgICB5ZWFyUm93LmFk" +
      "ZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gb3Blbk1vbnRoKGAke3l9LSR7cGFkKGxhdGVzdE1vbnRoKX1gKSk7CiAgICAg" +
      "IGVsLnRpbWVsaW5lTGlzdC5hcHBlbmRDaGlsZCh5ZWFyUm93KTsKCiAgICAgIGNvbnN0IG1vbnRocyA9IGRvY3VtZW50LmNyZWF0" +
      "ZUVsZW1lbnQoJ2RpdicpOwogICAgICBtb250aHMuY2xhc3NOYW1lID0gJ3RsLW1vbnRocyc7CiAgICAgIGZvciAoY29uc3QgW20s" +
      "IGluZm9dIG9mIEFycmF5LmZyb20oeWVhci5tb250aHMpLnNvcnQoKGEsIGIpID0+IGJbMF0gLSBhWzBdKSkgewogICAgICAgIGNv" +
      "bnN0IGJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAgICAgIGJ0bi50eXBlID0gJ2J1dHRvbic7CiAg" +
      "ICAgICAgYnRuLmNsYXNzTmFtZSA9ICd0bC1tb250aCc7CiAgICAgICAgYnRuLnRpdGxlID0gYOafpeeciyAke3l9IOW5tCAke219" +
      "IOaciOWFqOmDqCAke2luZm8uY291bnR9IOadoeS7u+WKoWA7CiAgICAgICAgYnRuLmFwcGVuZCgKICAgICAgICAgIGRvY3VtZW50" +
      "LmNyZWF0ZVRleHROb2RlKGAke219IOaciGApLAogICAgICAgICAgT2JqZWN0LmFzc2lnbihkb2N1bWVudC5jcmVhdGVFbGVtZW50" +
      "KCdiJyksIHsgdGV4dENvbnRlbnQ6IFN0cmluZyhpbmZvLmNvdW50KSB9KSwKICAgICAgICApOwogICAgICAgIC8vIOeCueWHu+ac" +
      "iOS7vSDihpIg5pW05pyI6KeG5Zu+77yI6K+l5pyI5omA5pyJ5Lu75Yqh5oyJ5pel5pyf5YiG57uE5bGV56S677yJCiAgICAgICAg" +
      "YnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gb3Blbk1vbnRoKGAke3l9LSR7cGFkKG0pfWApKTsKICAgICAgICBt" +
      "b250aHMuYXBwZW5kQ2hpbGQoYnRuKTsKICAgICAgfQogICAgICBlbC50aW1lbGluZUxpc3QuYXBwZW5kQ2hpbGQobW9udGhzKTsK" +
      "ICAgIH0KICB9CgogIC8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSDkvqfmoI/lvIDlkIjvvIjnp7vliqjnq6/mir3l" +
      "sYnvvIkgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgZnVuY3Rpb24gb3BlblNpZGViYXIoKSB7CiAgICBkb2N1" +
      "bWVudC5ib2R5LmNsYXNzTGlzdC5hZGQoJ3NpZGUtb3BlbicpOwogICAgZWwuc2lkZU1hc2suY2xhc3NMaXN0LnJlbW92ZSgnaGlk" +
      "ZGVuJyk7CiAgfQogIGZ1bmN0aW9uIGNsb3NlU2lkZWJhcigpIHsKICAgIGRvY3VtZW50LmJvZHkuY2xhc3NMaXN0LnJlbW92ZSgn" +
      "c2lkZS1vcGVuJyk7CiAgICBlbC5zaWRlTWFzay5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICB9CiAgZWwuc2lkZVRvZ2dsZS5h" +
      "ZGRFdmVudExpc3RlbmVyKCdjbGljaycsIG9wZW5TaWRlYmFyKTsKICBlbC5zaWRlTWFzay5hZGRFdmVudExpc3RlbmVyKCdjbGlj" +
      "aycsIGNsb3NlU2lkZWJhcik7CiAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ3Jlc2l6ZScsICgpID0+IHsgaWYgKHdpbmRvdy5p" +
      "bm5lcldpZHRoID49IDk4MCkgY2xvc2VTaWRlYmFyKCk7IH0pOwoKICAvKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKgogICAqIOaQnOe0ogogICAqIC0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwogIGxldCBzZWFyY2hUaW1lciA9IG51bGw7" +
      "CgogIGVsLnNlYXJjaElucHV0LmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgKCkgPT4gewogICAgY29uc3QgcSA9IGVsLnNlYXJj" +
      "aElucHV0LnZhbHVlLnRyaW0oKTsKICAgIGVsLnNlYXJjaENsZWFyLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicsICFxKTsKICAg" +
      "IGNsZWFyVGltZW91dChzZWFyY2hUaW1lcik7CiAgICBpZiAoIXEpIHsgZXhpdFNlYXJjaCgpOyByZXR1cm47IH0KICAgIHNlYXJj" +
      "aFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiBydW5TZWFyY2gocSksIDI2MCk7CiAgfSk7CgogIGVsLnNlYXJjaElucHV0LmFkZEV2" +
      "ZW50TGlzdGVuZXIoJ2tleWRvd24nLCAoZSkgPT4gewogICAgaWYgKGUua2V5ID09PSAnRXNjYXBlJykgeyBleGl0U2VhcmNoKCk7" +
      "IGVsLnNlYXJjaElucHV0LmJsdXIoKTsgfQogIH0pOwoKICBlbC5zZWFyY2hDbGVhci5hZGRFdmVudExpc3RlbmVyKCdjbGljaycs" +
      "ICgpID0+IHsgZXhpdFNlYXJjaCgpOyBlbC5hZGRJbnB1dC5mb2N1cyh7IHByZXZlbnRTY3JvbGw6IHRydWUgfSk7IH0pOwogIGVs" +
      "LnNlYXJjaEV4aXQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBpZiAoc3RhdGUubW9udGgpIHsgZXhpdE1v" +
      "bnRoKCk7IHJldHVybjsgfQogICAgZXhpdFNlYXJjaCgpOwogICAgZWwuYWRkSW5wdXQuZm9jdXMoeyBwcmV2ZW50U2Nyb2xsOiB0" +
      "cnVlIH0pOwogIH0pOwoKICBhc3luYyBmdW5jdGlvbiBydW5TZWFyY2gocSkgewogICAgc3RhdGUuc2VhcmNoID0geyBxLCBhY3Rp" +
      "dmU6IHRydWUsIGxvYWRpbmc6IHRydWUsIHJlc3VsdHM6IFtdIH07CiAgICByZW5kZXJMaXN0KCk7CiAgICB0cnkgewogICAgICBj" +
      "b25zdCBkYXRhID0gYXdhaXQgYXBpKGAvc2VhcmNoP3E9JHtlbmNvZGVVUklDb21wb25lbnQocSl9YCk7CiAgICAgIGlmIChzdGF0" +
      "ZS5zZWFyY2guYWN0aXZlICYmIHN0YXRlLnNlYXJjaC5xID09PSBxKSB7CiAgICAgICAgc3RhdGUuc2VhcmNoLnJlc3VsdHMgPSBk" +
      "YXRhLnRvZG9zIHx8IFtdOwogICAgICB9CiAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgaWYgKGVyci5zdGF0dXMgPT09IDQwMSkg" +
      "eyBzdGF0ZS51c2VyID0gbnVsbDsgc2hvd0F1dGgoKTsgcmV0dXJuOyB9CiAgICAgIHRvYXN0KGVyci5tZXNzYWdlLCAnZXJyJyk7" +
      "CiAgICB9IGZpbmFsbHkgewogICAgICBpZiAoc3RhdGUuc2VhcmNoLmFjdGl2ZSAmJiBzdGF0ZS5zZWFyY2gucSA9PT0gcSkgewog" +
      "ICAgICAgIHN0YXRlLnNlYXJjaC5sb2FkaW5nID0gZmFsc2U7CiAgICAgICAgcmVuZGVyTGlzdCgpOwogICAgICB9CiAgICB9CiAg" +
      "fQoKICBmdW5jdGlvbiBzdGFydFNlYXJjaChxKSB7CiAgICBlbC5zZWFyY2hJbnB1dC52YWx1ZSA9IHE7CiAgICBlbC5zZWFyY2hD" +
      "bGVhci5jbGFzc0xpc3QucmVtb3ZlKCdoaWRkZW4nKTsKICAgIGNsZWFyVGltZW91dChzZWFyY2hUaW1lcik7CiAgICBydW5TZWFy" +
      "Y2gocSk7CiAgICBjbG9zZVNpZGViYXIoKTsKICB9CgogIGZ1bmN0aW9uIGV4aXRTZWFyY2goKSB7CiAgICBjbGVhclRpbWVvdXQo" +
      "c2VhcmNoVGltZXIpOwogICAgY29uc3QgaGFkID0gc3RhdGUuc2VhcmNoLmFjdGl2ZSB8fCBlbC5zZWFyY2hJbnB1dC52YWx1ZTsK" +
      "ICAgIHN0YXRlLnNlYXJjaCA9IHsgcTogJycsIGFjdGl2ZTogZmFsc2UsIGxvYWRpbmc6IGZhbHNlLCByZXN1bHRzOiBbXSB9Owog" +
      "ICAgZWwuc2VhcmNoSW5wdXQudmFsdWUgPSAnJzsKICAgIGVsLnNlYXJjaENsZWFyLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwog" +
      "ICAgaWYgKGhhZCkgcmVuZGVyTGlzdCgpOwogIH0KCiAgLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDlop4gLyDmlLkgLyDliKAKICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KICBlbC5hZGRGb3JtLmFkZEV2ZW50TGlz" +
      "dGVuZXIoJ3N1Ym1pdCcsIGFzeW5jIChldmVudCkgPT4gewogICAgZXZlbnQucHJldmVudERlZmF1bHQoKTsKICAgIGlmIChzdGF0" +
      "ZS5idXN5KSByZXR1cm47CgogICAgY29uc3QgdGl0bGUgPSBlbC5hZGRJbnB1dC52YWx1ZS5yZXBsYWNlKC9ccysvZywgJyAnKS50" +
      "cmltKCk7CiAgICBpZiAoIXRpdGxlKSB7CiAgICAgIC8vIOepuueZveS7u+WKoeS4jea3u+WKoAogICAgICBlbC5hZGRIaW50LnRl" +
      "eHRDb250ZW50ID0gJ+S7u+WKoeWGheWuueS4jeiDveS4uuepuic7CiAgICAgIGVsLmFkZEhpbnQuaGlkZGVuID0gZmFsc2U7CiAg" +
      "ICAgIGVsLmFkZEZvcm0uY2xhc3NMaXN0LmFkZCgnc2hha2UnKTsKICAgICAgc2V0VGltZW91dCgoKSA9PiBlbC5hZGRGb3JtLmNs" +
      "YXNzTGlzdC5yZW1vdmUoJ3NoYWtlJyksIDM2MCk7CiAgICAgIGVsLmFkZElucHV0LmZvY3VzKCk7CiAgICAgIHJldHVybjsKICAg" +
      "IH0KCiAgICBlbC5hZGRIaW50LmhpZGRlbiA9IHRydWU7CiAgICBpZiAoc3RhdGUuc2VhcmNoLmFjdGl2ZSkgZXhpdFNlYXJjaCgp" +
      "OyAgIC8vIOaQnOe0oueKtuaAgeS4i+a3u+WKoOS7u+WKoe+8jOWFiOWbnuWIsOaXpeacn+inhuWbvgogICAgc3RhdGUuYnVzeSA9" +
      "IHRydWU7CiAgICBjb25zdCBidG4gPSBlbC5hZGRCdG4gfHwgZWwuYWRkRm9ybS5xdWVyeVNlbGVjdG9yKCdidXR0b25bdHlwZT1z" +
      "dWJtaXRdJyk7CiAgICBpZiAoYnRuKSBidG4uZGlzYWJsZWQgPSB0cnVlOwoKICAgIC8vIOaciOinhuWbvu+8muS4jeWBmuaXpein" +
      "huWbvueahOS5kOinguaPkuWFpe+8jOaIkOWKn+WQjuWIt+aWsOaVtOaciOaVsOaNrgogICAgaWYgKHN0YXRlLm1vbnRoKSB7CiAg" +
      "ICAgIGVsLmFkZElucHV0LnZhbHVlID0gJyc7CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpKCcvdG9kb3MnLCB7IG1ldGhv" +
      "ZDogJ1BPU1QnLCBib2R5OiB7IHRpdGxlLCBkYXRlOiBzdGF0ZS5kYXRlIH0gfSk7CiAgICAgICAgYXdhaXQgcmVmcmVzaE1vbnRo" +
      "KCk7CiAgICAgICAgc2NoZWR1bGVTaWRlYmFyUmVmcmVzaCgpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBpZiAoZXJy" +
      "LnN0YXR1cyA9PT0gNDAxKSB7IHNob3dBdXRoKCk7IHJldHVybjsgfQogICAgICAgIHRvYXN0KGVyci5tZXNzYWdlLCAnZXJyJyk7" +
      "CiAgICAgICAgZWwuYWRkSW5wdXQudmFsdWUgPSB0aXRsZTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBzdGF0ZS5idXN5ID0g" +
      "ZmFsc2U7CiAgICAgICAgaWYgKGJ0bikgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgZWwuYWRkSW5wdXQuZm9jdXMoeyBw" +
      "cmV2ZW50U2Nyb2xsOiB0cnVlIH0pOwogICAgICB9CiAgICAgIHJldHVybjsKICAgIH0KCiAgICAvLyDkuZDop4Lmj5LlhaUKICAg" +
      "IGNvbnN0IHRlbXBJZCA9IGB0bXBfJHtEYXRlLm5vdygpfWA7CiAgICBjb25zdCBvcHRpbWlzdGljID0geyBpZDogdGVtcElkLCB0" +
      "aXRsZSwgZG9uZTogZmFsc2UsIGRhdGU6IHN0YXRlLmRhdGUsIG9yZGVyOiAtSW5maW5pdHksIGNyZWF0ZWRBdDogRGF0ZS5ub3co" +
      "KSAvIDEwMDAgfTsKICAgIHN0YXRlLnRvZG9zLnVuc2hpZnQob3B0aW1pc3RpYyk7CiAgICBzdGF0ZS50b3RhbCArPSAxOwogICAg" +
      "c3RhdGUucmVtYWluaW5nICs9IDE7CiAgICByZW5kZXJMaXN0KCk7CiAgICBlbC5hZGRJbnB1dC52YWx1ZSA9ICcnOwoKICAgIHRy" +
      "eSB7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBhcGkoJy90b2RvcycsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IHsgdGl0bGUs" +
      "IGRhdGU6IHN0YXRlLmRhdGUgfSB9KTsKICAgICAgY29uc3QgaW5kZXggPSBzdGF0ZS50b2Rvcy5maW5kSW5kZXgoKHQpID0+IHQu" +
      "aWQgPT09IHRlbXBJZCk7CiAgICAgIGlmIChpbmRleCAhPT0gLTEpIHN0YXRlLnRvZG9zW2luZGV4XSA9IGRhdGEudG9kbzsKICAg" +
      "ICAgc3RhdGUudG9kb3Muc29ydCgoYSwgYikgPT4gTnVtYmVyKGEuZG9uZSkgLSBOdW1iZXIoYi5kb25lKSB8fCBhLm9yZGVyIC0g" +
      "Yi5vcmRlcik7CiAgICAgIHN0YXRlLnJlbWFpbmluZyA9IGRhdGEucmVtYWluaW5nOwogICAgICBzdGF0ZS50b3RhbCA9IGRhdGEu" +
      "dG90YWw7CiAgICAgIHJlbmRlckxpc3QoKTsKICAgICAgc3luY0RheUNhY2hlKCk7CiAgICAgIHNjaGVkdWxlU2lkZWJhclJlZnJl" +
      "c2goKTsKICAgIH0gY2F0Y2ggKGVycikgewogICAgICBzdGF0ZS50b2RvcyA9IHN0YXRlLnRvZG9zLmZpbHRlcigodCkgPT4gdC5p" +
      "ZCAhPT0gdGVtcElkKTsKICAgICAgc3RhdGUudG90YWwgPSBNYXRoLm1heCgwLCBzdGF0ZS50b3RhbCAtIDEpOwogICAgICBzdGF0" +
      "ZS5yZW1haW5pbmcgPSBzdGF0ZS50b2Rvcy5maWx0ZXIoKHQpID0+ICF0LmRvbmUpLmxlbmd0aDsKICAgICAgcmVuZGVyTGlzdCgp" +
      "OwogICAgICBpZiAoZXJyLnN0YXR1cyA9PT0gNDAxKSB7IHNob3dBdXRoKCk7IHJldHVybjsgfQogICAgICB0b2FzdChlcnIubWVz" +
      "c2FnZSwgJ2VycicpOwogICAgICBlbC5hZGRJbnB1dC52YWx1ZSA9IHRpdGxlOwogICAgfSBmaW5hbGx5IHsKICAgICAgc3RhdGUu" +
      "YnVzeSA9IGZhbHNlOwogICAgICBpZiAoYnRuKSBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgZWwuYWRkSW5wdXQuZm9jdXMo" +
      "eyBwcmV2ZW50U2Nyb2xsOiB0cnVlIH0pOwogICAgfQogIH0pOwoKICBlbC5hZGRJbnB1dC5hZGRFdmVudExpc3RlbmVyKCdpbnB1" +
      "dCcsICgpID0+IHsgZWwuYWRkSGludC5oaWRkZW4gPSB0cnVlOyB9KTsKCiAgYXN5bmMgZnVuY3Rpb24gdG9nZ2xlVG9kbyh0b2Rv" +
      "KSB7CiAgICBjb25zdCBuZXh0ID0gIXRvZG8uZG9uZTsKICAgIHRvZG8uZG9uZSA9IG5leHQ7CiAgICAvLyDlt7LlrozmiJDnmoTm" +
      "sonliLDlupXpg6gKICAgIHN0YXRlLnRvZG9zLnNvcnQoKGEsIGIpID0+IE51bWJlcihhLmRvbmUpIC0gTnVtYmVyKGIuZG9uZSkg" +
      "fHwgYS5vcmRlciAtIGIub3JkZXIpOwogICAgc3RhdGUucmVtYWluaW5nID0gc3RhdGUudG9kb3MuZmlsdGVyKCh0KSA9PiAhdC5k" +
      "b25lKS5sZW5ndGg7CiAgICByZW5kZXJMaXN0KCk7CgogICAgdHJ5IHsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGFwaShgL3Rv" +
      "ZG9zLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHRvZG8uaWQpfWAsIHsgbWV0aG9kOiAnUEFUQ0gnLCBib2R5OiB7IGRvbmU6IG5leHQg" +
      "fSB9KTsKICAgICAgaWYgKHN0YXRlLm1vbnRoKSB7IGF3YWl0IHJlZnJlc2hNb250aCgpOyB9CiAgICAgIGVsc2UgeyB1cGRhdGVD" +
      "b3VudHMoZGF0YSk7IHN5bmNEYXlDYWNoZSgpOyB9CiAgICAgIHNjaGVkdWxlU2lkZWJhclJlZnJlc2goKTsKICAgIH0gY2F0Y2gg" +
      "KGVycikgewogICAgICB0b2RvLmRvbmUgPSAhbmV4dDsKICAgICAgaWYgKHN0YXRlLm1vbnRoKSB7IHJlbmRlckxpc3QoKTsgfSBl" +
      "bHNlIHsKICAgICAgICBzdGF0ZS50b2Rvcy5zb3J0KChhLCBiKSA9PiBOdW1iZXIoYS5kb25lKSAtIE51bWJlcihiLmRvbmUpIHx8" +
      "IGEub3JkZXIgLSBiLm9yZGVyKTsKICAgICAgICBzdGF0ZS5yZW1haW5pbmcgPSBzdGF0ZS50b2Rvcy5maWx0ZXIoKHQpID0+ICF0" +
      "LmRvbmUpLmxlbmd0aDsKICAgICAgICByZW5kZXJMaXN0KCk7CiAgICAgIH0KICAgICAgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnIn" +
      "KTsKICAgIH0KICB9CgogIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVRvZG8odG9kbywgbGkpIHsKICAgIGxpLmNsYXNzTGlzdC5hZGQo" +
      "J3JlbW92aW5nJyk7CiAgICBjb25zdCBiYWNrdXAgPSBzdGF0ZS5tb250aCA/IHN0YXRlLm1vbnRoVG9kb3Muc2xpY2UoKSA6IHN0" +
      "YXRlLnRvZG9zLnNsaWNlKCk7CiAgICBpZiAoc3RhdGUubW9udGgpIHsKICAgICAgc3RhdGUubW9udGhUb2RvcyA9IHN0YXRlLm1v" +
      "bnRoVG9kb3MuZmlsdGVyKCh0KSA9PiB0LmlkICE9PSB0b2RvLmlkKTsKICAgIH0gZWxzZSB7CiAgICAgIHN0YXRlLnRvZG9zID0g" +
      "c3RhdGUudG9kb3MuZmlsdGVyKCh0KSA9PiB0LmlkICE9PSB0b2RvLmlkKTsKICAgICAgc3RhdGUucmVtYWluaW5nID0gc3RhdGUu" +
      "dG9kb3MuZmlsdGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGg7CiAgICAgIHN0YXRlLnRvdGFsID0gc3RhdGUudG9kb3MubGVuZ3Ro" +
      "OwogICAgfQoKICAgIHNldFRpbWVvdXQocmVuZGVyTGlzdCwgMTgwKTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2Fp" +
      "dCBhcGkoYC90b2Rvcy8ke2VuY29kZVVSSUNvbXBvbmVudCh0b2RvLmlkKX0/ZGF0ZT0ke2VuY29kZVVSSUNvbXBvbmVudChzdGF0" +
      "ZS5kYXRlKX1gLCB7IG1ldGhvZDogJ0RFTEVURScgfSk7CiAgICAgIGlmIChzdGF0ZS5tb250aCkgeyBhd2FpdCByZWZyZXNoTW9u" +
      "dGgoKTsgfQogICAgICBlbHNlIHsgdXBkYXRlQ291bnRzKGRhdGEpOyBzeW5jRGF5Q2FjaGUoKTsgfQogICAgICBzY2hlZHVsZVNp" +
      "ZGViYXJSZWZyZXNoKCk7CiAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgaWYgKHN0YXRlLm1vbnRoKSB7CiAgICAgICAgc3RhdGUu" +
      "bW9udGhUb2RvcyA9IGJhY2t1cDsKICAgICAgfSBlbHNlIHsKICAgICAgICBzdGF0ZS50b2RvcyA9IGJhY2t1cDsKICAgICAgICBz" +
      "dGF0ZS5yZW1haW5pbmcgPSBiYWNrdXAuZmlsdGVyKCh0KSA9PiAhdC5kb25lKS5sZW5ndGg7CiAgICAgICAgc3RhdGUudG90YWwg" +
      "PSBiYWNrdXAubGVuZ3RoOwogICAgICB9CiAgICAgIHJlbmRlckxpc3QoKTsKICAgICAgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnIn" +
      "KTsKICAgIH0KICB9CgogIGVsLmNsZWFyRG9uZUJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgIGNvbnN0" +
      "IGhhc0RvbmUgPSBzdGF0ZS5tb250aAogICAgICA/IHN0YXRlLm1vbnRoVG9kb3Muc29tZSgodCkgPT4gdC5kb25lKQogICAgICA6" +
      "IHN0YXRlLnRvZG9zLnNvbWUoKHQpID0+IHQuZG9uZSk7CiAgICBpZiAoIWhhc0RvbmUpIHJldHVybjsKCiAgICBhcm1lZENsaWNr" +
      "KGVsLmNsZWFyRG9uZUJ0biwgJ+ehruiupOa4hemZpO+8nycsIGFzeW5jICgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25z" +
      "dCBib2R5ID0gc3RhdGUubW9udGgKICAgICAgICAgID8geyBhY3Rpb246ICdjbGVhci1jb21wbGV0ZWQnLCBtb250aDogc3RhdGUu" +
      "bW9udGggfQogICAgICAgICAgOiB7IGFjdGlvbjogJ2NsZWFyLWNvbXBsZXRlZCcsIGRhdGU6IHN0YXRlLmRhdGUgfTsKICAgICAg" +
      "ICBjb25zdCBkYXRhID0gYXdhaXQgYXBpKCcvdG9kb3MvYmF0Y2gnLCB7IG1ldGhvZDogJ1BPU1QnLCBib2R5IH0pOwogICAgICAg" +
      "IHNjaGVkdWxlU2lkZWJhclJlZnJlc2goKTsKICAgICAgICBpZiAoc3RhdGUubW9udGgpIHsKICAgICAgICAgIGF3YWl0IHJlZnJl" +
      "c2hNb250aCgpOwogICAgICAgICAgdG9hc3QoYOW3sua4hemZpOacrOaciCAke2RhdGEucmVtb3ZlZCB8fCAwfSDpobnlt7Llrozm" +
      "iJDku7vliqFgLCAnb2snKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgYXdhaXQgcmVmcmVzaCgpOwogICAgICAgICAgc3lu" +
      "Y0RheUNhY2hlKCk7CiAgICAgICAgICB0b2FzdCgn5bey5riF6Zmk5a6M5oiQ55qE5Lu75YqhJywgJ29rJyk7CiAgICAgICAgfQog" +
      "ICAgICB9IGNhdGNoIChlcnIpIHsgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnInKTsgfQogICAgfSk7CiAgfSk7CgogIGVsLmNhcnJ5" +
      "b3ZlckJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGRhdGEg" +
      "PSBhd2FpdCBhcGkoJy90b2Rvcy9iYXRjaCcsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IHsgYWN0aW9uOiAnY2Fycnktb3Zlcics" +
      "IGRhdGU6IHN0YXRlLmRhdGUgfSB9KTsKICAgICAgY2FjaGVDbGVhckFsbCgpOyAgIC8vIOmhuuW7tuS8muaUueWKqOWkmuS4quaX" +
      "peacn+eahOaVsOaNru+8jOebtOaOpea4heepuue8k+WtmOacgOeos+WmpQogICAgICBhd2FpdCByZWZyZXNoKCk7CiAgICAgIHNj" +
      "aGVkdWxlU2lkZWJhclJlZnJlc2goKTsKICAgICAgdG9hc3QoZGF0YS5tb3ZlZCA/IGDlt7Lpobrlu7YgJHtkYXRhLm1vdmVkfSDp" +
      "obnmnKrlrozmiJDku7vliqFgIDogJ+ayoeaciemcgOimgemhuuW7tueahOS7u+WKoScsIGRhdGEubW92ZWQgPyAnb2snIDogJycp" +
      "OwogICAgfSBjYXRjaCAoZXJyKSB7IHRvYXN0KGVyci5tZXNzYWdlLCAnZXJyJyk7IH0KICB9KTsKCiAgLyogLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDkuLvpopgKICAgKiAt" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi8KICBjb25z" +
      "dCBUSEVNRV9LRVkgPSAndG9kby10b2RheTp0aGVtZSc7CiAgZnVuY3Rpb24gYXBwbHlUaGVtZSh0aGVtZSkgewogICAgaWYgKHRo" +
      "ZW1lID09PSAnbGlnaHQnIHx8IHRoZW1lID09PSAnZGFyaycpIHsKICAgICAgZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50LnNldEF0" +
      "dHJpYnV0ZSgnZGF0YS10aGVtZScsIHRoZW1lKTsKICAgIH0gZWxzZSB7CiAgICAgIGRvY3VtZW50LmRvY3VtZW50RWxlbWVudC5y" +
      "ZW1vdmVBdHRyaWJ1dGUoJ2RhdGEtdGhlbWUnKTsKICAgIH0KICAgIGVsLnRoZW1lVG9nZ2xlLnRleHRDb250ZW50ID0gdGhlbWUg" +
      "PT09ICdkYXJrJyA/ICfimIDvuI8nIDogdGhlbWUgPT09ICdsaWdodCcgPyAn8J+MmScgOiAn8J+Mkyc7CiAgfQogIGVsLnRoZW1l" +
      "VG9nZ2xlLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgY29uc3Qgb3JkZXIgPSBbJ2F1dG8nLCAnbGlnaHQn" +
      "LCAnZGFyayddOwogICAgY29uc3QgY3VycmVudCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKFRIRU1FX0tFWSkgfHwgJ2F1dG8nOwog" +
      "ICAgY29uc3QgbmV4dCA9IG9yZGVyWyhvcmRlci5pbmRleE9mKGN1cnJlbnQpICsgMSkgJSBvcmRlci5sZW5ndGhdOwogICAgbG9j" +
      "YWxTdG9yYWdlLnNldEl0ZW0oVEhFTUVfS0VZLCBuZXh0KTsKICAgIGFwcGx5VGhlbWUobmV4dCA9PT0gJ2F1dG8nID8gbnVsbCA6" +
      "IG5leHQpOwogIH0pOwogIGFwcGx5VGhlbWUobG9jYWxTdG9yYWdlLmdldEl0ZW0oVEhFTUVfS0VZKSB8fCBudWxsKTsKCiAgLyog" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoKICAgKiDo" +
      "rr7nva7mir3lsYkKICAgKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0gKi8KICBmdW5jdGlvbiBvcGVuRHJhd2VyKCkgewogICAgZWwuZHJhd2VyTWFzay5jbGFzc0xpc3QucmVtb3ZlKCdo" +
      "aWRkZW4nKTsKICAgIGRvY3VtZW50LmJvZHkuc3R5bGUub3ZlcmZsb3cgPSAnaGlkZGVuJzsKICB9CiAgZnVuY3Rpb24gY2xvc2VE" +
      "cmF3ZXIoKSB7CiAgICBlbC5kcmF3ZXJNYXNrLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgZG9jdW1lbnQuYm9keS5zdHls" +
      "ZS5vdmVyZmxvdyA9ICcnOwogIH0KICBlbC51c2VyTWVudS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIG9wZW5EcmF3ZXIpOwog" +
      "IGVsLmRyYXdlckNsb3NlLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgY2xvc2VEcmF3ZXIpOwogIGVsLmRyYXdlck1hc2suYWRk" +
      "RXZlbnRMaXN0ZW5lcignY2xpY2snLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IGVsLmRyYXdlck1hc2spIGNsb3NlRHJhd2Vy" +
      "KCk7IH0pOwogIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCAoZSkgPT4gewogICAgaWYgKGUua2V5ID09PSAn" +
      "RXNjYXBlJykgeyBjbG9zZURyYXdlcigpOyBjbG9zZVNpZGViYXIoKTsgfQogIH0pOwogIGVsLmRlbW9CYW5uZXJDbG9zZS5hZGRF" +
      "dmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IGVsLmRlbW9CYW5uZXIuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJykpOwoKICAvKiAt" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0g5LqR5aSH5Lu9IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwog" +
      "IGZ1bmN0aW9uIHN5bmNQcm92aWRlclBhbmVscygpIHsKICAgIGNvbnN0IHByb3ZpZGVyID0gZWwuYmFja3VwUHJvdmlkZXIudmFs" +
      "dWU7CiAgICBlbC5iYWNrdXBQYW5lbHMuZm9yRWFjaCgocGFuZWwpID0+IHsKICAgICAgcGFuZWwuaGlkZGVuID0gcGFuZWwuZGF0" +
      "YXNldC5wcm92aWRlciAhPT0gcHJvdmlkZXI7CiAgICB9KTsKICAgIGNvbnN0IG9uID0gZWwuYmFja3VwRW5hYmxlZC5jaGVja2Vk" +
      "ICYmIHByb3ZpZGVyICE9PSAnbm9uZSc7CiAgICBlbC5iYWNrdXBFbmFibGVkLmRpc2FibGVkID0gcHJvdmlkZXIgPT09ICdub25l" +
      "JzsKICAgIGVsLmJhY2t1cEF1dG8uZGlzYWJsZWQgPSAhb247CiAgICBlbC5iYWNrdXBTY2hlZHVsZWQuZGlzYWJsZWQgPSAhb247" +
      "CiAgICBbZWwuYmFja3VwVGVzdCwgZWwuYmFja3VwUnVuLCBlbC5iYWNrdXBSZXN0b3JlXS5mb3JFYWNoKChiKSA9PiB7IGIuZGlz" +
      "YWJsZWQgPSBwcm92aWRlciA9PT0gJ25vbmUnOyB9KTsKICAgIGlmICghb24pIHsgZWwuYmFja3VwQXV0by5jaGVja2VkID0gZmFs" +
      "c2U7IGVsLmJhY2t1cFNjaGVkdWxlZC5jaGVja2VkID0gZmFsc2U7IH0KCiAgICAvLyDpopHnjofnm7jlhbPmjqfku7blj6rlnKjl" +
      "r7nlupTlvIDlhbPmiZPlvIDml7blh7rnjrAKICAgIGVsLmJhY2t1cEludGVydmFsRmllbGQuY2xhc3NMaXN0LnRvZ2dsZSgnaGlk" +
      "ZGVuJywgIShvbiAmJiBlbC5iYWNrdXBBdXRvLmNoZWNrZWQpKTsKICAgIGVsLmJhY2t1cFBlcmlvZEZpZWxkLmNsYXNzTGlzdC50" +
      "b2dnbGUoJ2hpZGRlbicsICEob24gJiYgZWwuYmFja3VwU2NoZWR1bGVkLmNoZWNrZWQpKTsKCiAgICB1cGRhdGVTdGFtcEhpbnQo" +
      "KTsKICAgIHVwZGF0ZUZyZXF1ZW5jeUhpbnRzKCk7CiAgfQoKICAvKiog5a6J5YWo5Zyw57uZIHNlbGVjdCDotYvlgLzvvJrphY3n" +
      "va7ph4znmoTlgLzkuI3lnKjpgInpobnliJfooajph4zml7bkuLTml7booaXkuIDkuKrpgInpobkgKi8KICBmdW5jdGlvbiBzZXRT" +
      "ZWxlY3RWYWx1ZShzZWxlY3QsIHZhbHVlKSB7CiAgICBjb25zdCB2ID0gU3RyaW5nKHZhbHVlKTsKICAgIGlmICghQXJyYXkuZnJv" +
      "bShzZWxlY3Qub3B0aW9ucykuc29tZSgobykgPT4gby52YWx1ZSA9PT0gdikpIHsKICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQu" +
      "Y3JlYXRlRWxlbWVudCgnb3B0aW9uJyk7CiAgICAgIG9wdC52YWx1ZSA9IHY7CiAgICAgIG9wdC50ZXh0Q29udGVudCA9IGAke2h1" +
      "bWFuTWludXRlcyh2KX3vvIjoh6rlrprkuYnvvIlgOwogICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgIH0KICAgIHNl" +
      "bGVjdC52YWx1ZSA9IHY7CiAgfQoKICAvKiog5oqK44CM5YiG6ZKf44CN57+76K+R5oiQ5Lq66K+dICovCiAgZnVuY3Rpb24gaHVt" +
      "YW5NaW51dGVzKG1pbikgewogICAgY29uc3QgbiA9IE51bWJlcihtaW4pOwogICAgaWYgKG4gPT09IDApIHJldHVybiAn5LiN6ZmQ" +
      "5Yi2JzsKICAgIGlmIChuIDwgNjApIHJldHVybiBgJHtufSDliIbpkp9gOwogICAgaWYgKG4gPT09IDYwKSByZXR1cm4gJzEg5bCP" +
      "5pe2JzsKICAgIGlmIChuIDwgMTQ0MCkgcmV0dXJuIGAke24gLyA2MH0g5bCP5pe2YDsKICAgIGlmIChuID09PSAxNDQwKSByZXR1" +
      "cm4gJzI0IOWwj+aXtic7CiAgICByZXR1cm4gYCR7TWF0aC5yb3VuZChuIC8gMTQ0MCl9IOWkqWA7CiAgfQoKICAvKiog6aKR546H" +
      "IC8g5a6a5pe25aSH5Lu955qE6K+05piOICsgQ3JvbiDmmK/lkKbnnJ/nmoTlnKjot5HnmoTor4rmlq0gKi8KICBmdW5jdGlvbiB1" +
      "cGRhdGVGcmVxdWVuY3lIaW50cygpIHsKICAgIGNvbnN0IGV2ZXJ5ID0gaHVtYW5NaW51dGVzKGVsLmJhY2t1cEludGVydmFsLnZh" +
      "bHVlKTsKICAgIGVsLmJhY2t1cEludGVydmFsSGludC50ZXh0Q29udGVudCA9IE51bWJlcihlbC5iYWNrdXBJbnRlcnZhbC52YWx1" +
      "ZSkgPT09IDAKICAgICAgPyAn5q+P5qyh5pWw5o2u5Y+Y5pu06YO95Lya5aSH5Lu95LiA5qyh77yM5Y6G5Y+y5paH5Lu25aKe6ZW/" +
      "5pyA5b+r44CCJwogICAgICA6IGDot53kuIrmrKHlpIfku73kuI3otrMgJHtldmVyeX3ml7bkuI3kvJrph43lpI3lpIfku73vvIjm" +
      "r4/mlLnkuIDmrKHku7vliqHpg73kvJrmo4Dmn6XvvInjgIJgOwoKICAgIGlmICghZWwuYmFja3VwU2NoZWR1bGVkLmNoZWNrZWQp" +
      "IHsKICAgICAgZWwuYmFja3VwQ3JvbkhpbnQudGV4dENvbnRlbnQgPSAn5omT5byA5ZCO55SxIENsb3VkZmxhcmUg5a6a5pe26Kem" +
      "5Y+R77yI5q+PIDUg5YiG6ZKf5qOA5p+l5LiA5qyh77yJ77yM5LiN6ZyA6KaB5L2g5omT5byA6aG16Z2i44CCJzsKICAgICAgcmV0" +
      "dXJuOwogICAgfQogICAgY29uc3QgcGVyaW9kID0gaHVtYW5NaW51dGVzKGVsLmJhY2t1cFBlcmlvZC52YWx1ZSk7CiAgICBjb25z" +
      "dCBzdGF0dXMgPSBzdGF0ZS5jcm9uIHx8IHt9OwogICAgbGV0IHRleHQgPSBg5LqR56uv5q+PIDUg5YiG6ZKf5qOA5p+l5LiA5qyh" +
      "77yM5Yiw54K55bCx5aSH5Lu977yM57qm5q+PICR7cGVyaW9kfeS4gOasoeOAgmA7CiAgICBpZiAoc3RhdHVzLmxhc3RSdW4pIHsK" +
      "ICAgICAgY29uc3QgYWdvID0gTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChEYXRlLm5vdygpIC8gMTAwMCAtIHN0YXR1cy5sYXN0UnVu" +
      "KSk7CiAgICAgIGNvbnN0IGFnb1RleHQgPSBhZ28gPCA5MCA/IGAke2Fnb30g56eS5YmNYCA6IGAke01hdGgucm91bmQoYWdvIC8g" +
      "NjApfSDliIbpkp/liY1gOwogICAgICB0ZXh0ICs9IHN0YXR1cy5oZWFsdGh5CiAgICAgICAgPyBgIOWumuaXtuS7u+WKoei/kOih" +
      "jOato+W4uO+8iOS4iuasoeajgOafpSAke2Fnb1RleHR977yJ44CCYAogICAgICAgIDogYCDimqDvuI8g5LiK5qyh5qOA5p+l5piv" +
      "ICR7YWdvVGV4dH3vvIzlrprml7bku7vliqHlj6/og73msqHlnKjot5HvvJrpnIDlnKggV29ya2VyIOeahCBUcmlnZ2VycyDph4zm" +
      "t7vliqAgQ3JvbuOAjCovNSAqICogKiAq44CN44CCYDsKICAgIH0gZWxzZSB7CiAgICAgIHRleHQgKz0gJyDimqDvuI8g6L+Y5rKh" +
      "5pS25Yiw6L+H5a6a5pe25Lu75Yqh55qE5b+D6Lez77ya6K+356Gu6K6k5bey5ZyoIFdvcmtlciDnmoQgVHJpZ2dlcnMg4oaSIENy" +
      "b24gVHJpZ2dlcnMg6YeM5re75Yqg44CMKi81ICogKiAqICrjgI3jgIInOwogICAgfQogICAgZWwuYmFja3VwQ3JvbkhpbnQudGV4" +
      "dENvbnRlbnQgPSB0ZXh0OwogIH0KCiAgLyoqIOacrOWcsOaXtumXtOeahOaXtumXtOaIs+ekuuS+i++8jOS4juWQjuerryBmaWxl" +
      "U3RhbXAg5qC85byP5LiA6Ie077yaWVlZWU1NREQtSEhtbXNzICovCiAgZnVuY3Rpb24gbG9jYWxTdGFtcChkID0gbmV3IERhdGUo" +
      "KSkgewogICAgY29uc3QgcCA9IChuKSA9PiBTdHJpbmcobikucGFkU3RhcnQoMiwgJzAnKTsKICAgIHJldHVybiBgJHtkLmdldEZ1" +
      "bGxZZWFyKCl9JHtwKGQuZ2V0TW9udGgoKSArIDEpfSR7cChkLmdldERhdGUoKSl9LSR7cChkLmdldEhvdXJzKCkpfSR7cChkLmdl" +
      "dE1pbnV0ZXMoKSl9JHtwKGQuZ2V0U2Vjb25kcygpKX1gOwogIH0KCiAgLyoqIOS4juWQjuerryBzdGFtcEtleSDkuIDoh7TnmoTl" +
      "kb3lkI3op4TliJnvvJrml7bpl7TmiLPmj5LlnKjmianlsZXlkI3kuYvliY0gKi8KICBmdW5jdGlvbiBzdGFtcE5hbWUoYmFzZSwg" +
      "c3RhbXApIHsKICAgIGNvbnN0IG5hbWUgPSBTdHJpbmcoYmFzZSB8fCAndG9kby10b2RheS5iYWNrdXAuanNvbicpOwogICAgY29u" +
      "c3QgZG90ID0gbmFtZS5sYXN0SW5kZXhPZignLicpOwogICAgcmV0dXJuIGRvdCA+IDAgPyBgJHtuYW1lLnNsaWNlKDAsIGRvdCl9" +
      "LiR7c3RhbXB9JHtuYW1lLnNsaWNlKGRvdCl9YCA6IGAke25hbWV9LiR7c3RhbXB9YDsKICB9CgogIC8qKiDlvZPliY3phY3nva7k" +
      "uIvlrp7pmYXkvJrlhpnlhaXnmoTlm7rlrprmlofku7blkI3vvIjkuI7lkI7nq68gb2JqZWN0S2V5T2Yg5a+55bqU77yJICovCiAg" +
      "ZnVuY3Rpb24gY3VycmVudEJhY2t1cEJhc2UoKSB7CiAgICBjb25zdCBwcm92aWRlciA9IGVsLmJhY2t1cFByb3ZpZGVyLnZhbHVl" +
      "OwogICAgaWYgKHByb3ZpZGVyID09PSAncjInKSByZXR1cm4gZWwucjJLZXkudmFsdWUudHJpbSgpIHx8ICd0b2RvLXRvZGF5LmJh" +
      "Y2t1cC5qc29uJzsKICAgIGlmIChwcm92aWRlciA9PT0gJ3dlYmRhdicpIHJldHVybiBlbC5kYXZGaWxlLnZhbHVlLnRyaW0oKSB8" +
      "fCAndG9kby10b2RheS5iYWNrdXAuanNvbic7CiAgICBjb25zdCBwcmVmaXggPSBlbC5zM1ByZWZpeC52YWx1ZS50cmltKCkucmVw" +
      "bGFjZSgvXlwvKy8sICcnKTsKICAgIHJldHVybiBgJHtwcmVmaXh9JHtlbC5zM0ZpbGUudmFsdWUudHJpbSgpIHx8ICd0b2RvLXRv" +
      "ZGF5LmJhY2t1cC5qc29uJ31gOwogIH0KCiAgZnVuY3Rpb24gdXBkYXRlU3RhbXBIaW50KCkgewogICAgY29uc3QgcHJvdmlkZXIg" +
      "PSBlbC5iYWNrdXBQcm92aWRlci52YWx1ZTsKICAgIGlmIChwcm92aWRlciA9PT0gJ25vbmUnKSB7CiAgICAgIGVsLmJhY2t1cFN0" +
      "YW1wSGludC50ZXh0Q29udGVudCA9ICfpgInmi6nlpIfku73mlrnlvI/lkI7vvIzov5nph4zkvJrmmL7npLrlrp7pmYXlhpnlhaXk" +
      "upHnq6/nmoTmlofku7blkI3jgIInOwogICAgICByZXR1cm47CiAgICB9CiAgICBjb25zdCBiYXNlID0gY3VycmVudEJhY2t1cEJh" +
      "c2UoKTsKICAgIGlmICghZWwuYmFja3VwU3RhbXApIHJldHVybjsKICAgIGlmICghZWwuYmFja3VwU3RhbXAuY2hlY2tlZCkgewog" +
      "ICAgICBlbC5iYWNrdXBTdGFtcEhpbnQudGV4dENvbnRlbnQgPSBg5q+P5qyh5aSH5Lu96YO95Lya6KaG55uW5ZCM5LiA5Liq5paH" +
      "5Lu277yaJHtiYXNlfWA7CiAgICAgIHJldHVybjsKICAgIH0KICAgIGVsLmJhY2t1cFN0YW1wSGludC50ZXh0Q29udGVudCA9CiAg" +
      "ICAgIGDmr4/mrKHlpIfku73lhpnlhaUgJHtzdGFtcE5hbWUoYmFzZSwgbG9jYWxTdGFtcCgpKX3vvIzlubblkIzml7bliLfmlrDl" +
      "m7rlrprlkI3lv6vnhacgJHtiYXNlfe+8iOOAjOS7juS6keerr+aBouWkjeOAjeivu+eahOaYr+i/meS7ve+8ieOAgmA7CiAgfQoK" +
      "ICBlbC5iYWNrdXBQcm92aWRlci5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCBzeW5jUHJvdmlkZXJQYW5lbHMpOwogIGVsLmJh" +
      "Y2t1cEVuYWJsZWQuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgc3luY1Byb3ZpZGVyUGFuZWxzKTsKICBlbC5iYWNrdXBTdGFt" +
      "cC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCB1cGRhdGVTdGFtcEhpbnQpOwogIGVsLmJhY2t1cEF1dG8uYWRkRXZlbnRMaXN0" +
      "ZW5lcignY2hhbmdlJywgc3luY1Byb3ZpZGVyUGFuZWxzKTsKICBlbC5iYWNrdXBTY2hlZHVsZWQuYWRkRXZlbnRMaXN0ZW5lcign" +
      "Y2hhbmdlJywgc3luY1Byb3ZpZGVyUGFuZWxzKTsKICBlbC5iYWNrdXBJbnRlcnZhbC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2Un" +
      "LCB1cGRhdGVGcmVxdWVuY3lIaW50cyk7CiAgZWwuYmFja3VwUGVyaW9kLmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsIHVwZGF0" +
      "ZUZyZXF1ZW5jeUhpbnRzKTsKICBbZWwucjJLZXksIGVsLnMzRmlsZSwgZWwuczNQcmVmaXgsIGVsLmRhdkZpbGVdLmZvckVhY2go" +
      "KGlucHV0KSA9PiB7CiAgICBpbnB1dC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsIHVwZGF0ZVN0YW1wSGludCk7CiAgfSk7Cgog" +
      "IGFzeW5jIGZ1bmN0aW9uIGxvYWRCYWNrdXBDb25maWcoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBkYXRhID0gYXdhaXQgYXBp" +
      "KCcvYmFja3VwL2NvbmZpZycpOwogICAgICBzdGF0ZS5jcm9uID0gZGF0YS5jcm9uIHx8IG51bGw7CiAgICAgIGZpbGxCYWNrdXBG" +
      "b3JtKGRhdGEuY29uZmlnIHx8IHt9KTsKICAgICAgaWYgKGRhdGEubGFzdEJhY2t1cCkgewogICAgICAgIGVsLmxhc3RCYWNrdXBM" +
      "aW5lLnRleHRDb250ZW50ID0gYOS4iuasoeWkh+S7ve+8miR7bmV3IERhdGUoZGF0YS5sYXN0QmFja3VwICogMTAwMCkudG9Mb2Nh" +
      "bGVTdHJpbmcoKX1gOwogICAgICB9IGVsc2UgewogICAgICAgIGVsLmxhc3RCYWNrdXBMaW5lLnRleHRDb250ZW50ID0gJ+Wwmuac" +
      "quWkh+S7vei/h+OAgic7CiAgICAgIH0KICAgIH0gY2F0Y2ggKGVycikgewogICAgICBzZXRTdGF0dXMoZWwuYmFja3VwU3RhdHVz" +
      "LCBg6K+75Y+W5aSH5Lu96YWN572u5aSx6LSl77yaJHtlcnIubWVzc2FnZX1gLCAnZXJyJyk7CiAgICB9CiAgfQoKICBmdW5jdGlv" +
      "biBmaWxsQmFja3VwRm9ybShjb25maWcpIHsKICAgIGVsLmJhY2t1cFByb3ZpZGVyLnZhbHVlID0gY29uZmlnLnByb3ZpZGVyIHx8" +
      "ICdub25lJzsKICAgIGVsLmJhY2t1cEVuYWJsZWQuY2hlY2tlZCA9ICEhY29uZmlnLmVuYWJsZWQ7CiAgICBlbC5iYWNrdXBBdXRv" +
      "LmNoZWNrZWQgPSAhIWNvbmZpZy5hdXRvOwogICAgZWwuYmFja3VwU3RhbXAuY2hlY2tlZCA9IGNvbmZpZy5zdGFtcCAhPT0gZmFs" +
      "c2U7ICAgLy8g6buY6K6k5byA5ZCvCiAgICBzZXRTZWxlY3RWYWx1ZShlbC5iYWNrdXBJbnRlcnZhbCwgY29uZmlnLmludGVydmFs" +
      "TWluID8/IDEpOwogICAgZWwuYmFja3VwU2NoZWR1bGVkLmNoZWNrZWQgPSAhIWNvbmZpZy5zY2hlZHVsZWQ7CiAgICBzZXRTZWxl" +
      "Y3RWYWx1ZShlbC5iYWNrdXBQZXJpb2QsIGNvbmZpZy5zY2hlZHVsZU1pbiA/PyA2MCk7CgogICAgZWwucjJLZXkudmFsdWUgPSBj" +
      "b25maWcucjI/LmtleSB8fCAnJzsKICAgIGlmIChjb25maWcuaGFzUjJCaW5kaW5nID09PSBmYWxzZSkgewogICAgICBlbC5yMktl" +
      "eS5wbGFjZWhvbGRlciA9ICfmnKrmo4DmtYvliLAgUjIg57uR5a6aIEJBQ0tVUFMnOwogICAgfQoKICAgIGNvbnN0IHMzID0gY29u" +
      "ZmlnLnMzIHx8IHt9OwogICAgZWwuczNFbmRwb2ludC52YWx1ZSA9IHMzLmVuZHBvaW50IHx8ICcnOwogICAgZWwuczNSZWdpb24u" +
      "dmFsdWUgPSBzMy5yZWdpb24gfHwgJ2F1dG8nOwogICAgZWwuczNCdWNrZXQudmFsdWUgPSBzMy5idWNrZXQgfHwgJyc7CiAgICBl" +
      "bC5zM0FraWQudmFsdWUgPSBzMy5hY2Nlc3NLZXlJZCB8fCAnJzsKICAgIGVsLnMzU2VjcmV0LnZhbHVlID0gJyc7CiAgICBlbC5z" +
      "M1NlY3JldC5wbGFjZWhvbGRlciA9IHMzLmhhc1NlY3JldEtleQogICAgICA/IChzMy5zZWNyZXRGcm9tRW52ID8gJ+W3suWcqOeO" +
      "r+Wig+WPmOmHj+S4remFjee9ru+8iOeVmeepuuWNs+S9v+eUqO+8iScgOiAn5bey5L+d5a2Y77yM55WZ56m66KGo56S65LiN5L+u" +
      "5pS5JykKICAgICAgOiAn55WZ56m66KGo56S65LiN5L+u5pS5JzsKICAgIGVsLnMzUHJlZml4LnZhbHVlID0gczMucHJlZml4IHx8" +
      "ICcnOwogICAgZWwuczNGaWxlLnZhbHVlID0gY29uZmlnLmZpbGUgJiYgY29uZmlnLnByb3ZpZGVyID09PSAnczMnID8gY29uZmln" +
      "LmZpbGUgOiAoY29uZmlnLmZpbGUgfHwgJycpOwogICAgZWwuczNQYXRoU3R5bGUuY2hlY2tlZCA9ICEhczMucGF0aFN0eWxlOwoK" +
      "ICAgIGNvbnN0IGRhdiA9IGNvbmZpZy53ZWJkYXYgfHwge307CiAgICBlbC5kYXZVcmwudmFsdWUgPSBkYXYudXJsIHx8ICcnOwog" +
      "ICAgZWwuZGF2VXNlci52YWx1ZSA9IGRhdi51c2VybmFtZSB8fCAnJzsKICAgIGVsLmRhdlBhc3MudmFsdWUgPSAnJzsKICAgIGVs" +
      "LmRhdlBhc3MucGxhY2Vob2xkZXIgPSBkYXYuaGFzUGFzc3dvcmQKICAgICAgPyAoZGF2LnBhc3N3b3JkRnJvbUVudiA/ICflt7Ll" +
      "nKjnjq/looPlj5jph4/kuK3phY3nva7vvIjnlZnnqbrljbPkvb/nlKjvvIknIDogJ+W3suS/neWtmO+8jOeVmeepuuihqOekuuS4" +
      "jeS/ruaUuScpCiAgICAgIDogJ+eVmeepuuihqOekuuS4jeS/ruaUuSc7CiAgICBlbC5kYXZGaWxlLnZhbHVlID0gZGF2LmZpbGUg" +
      "fHwgJyc7CgogICAgc3luY1Byb3ZpZGVyUGFuZWxzKCk7CiAgfQoKICBmdW5jdGlvbiBjb2xsZWN0QmFja3VwRm9ybSgpIHsKICAg" +
      "IGNvbnN0IHByb3ZpZGVyID0gZWwuYmFja3VwUHJvdmlkZXIudmFsdWU7CiAgICByZXR1cm4gewogICAgICBwcm92aWRlciwKICAg" +
      "ICAgZW5hYmxlZDogZWwuYmFja3VwRW5hYmxlZC5jaGVja2VkICYmIHByb3ZpZGVyICE9PSAnbm9uZScsCiAgICAgIGF1dG86IGVs" +
      "LmJhY2t1cEF1dG8uY2hlY2tlZCAmJiBlbC5iYWNrdXBFbmFibGVkLmNoZWNrZWQgJiYgcHJvdmlkZXIgIT09ICdub25lJywKICAg" +
      "ICAgaW50ZXJ2YWxNaW46IE51bWJlcihlbC5iYWNrdXBJbnRlcnZhbC52YWx1ZSkgfHwgMCwKICAgICAgc2NoZWR1bGVkOiBlbC5i" +
      "YWNrdXBTY2hlZHVsZWQuY2hlY2tlZCAmJiBlbC5iYWNrdXBFbmFibGVkLmNoZWNrZWQgJiYgcHJvdmlkZXIgIT09ICdub25lJywK" +
      "ICAgICAgc2NoZWR1bGVNaW46IE51bWJlcihlbC5iYWNrdXBQZXJpb2QudmFsdWUpIHx8IDYwLAogICAgICBzdGFtcDogZWwuYmFj" +
      "a3VwU3RhbXAuY2hlY2tlZCwKICAgICAgLy8g5YmN56uv55u05o6l5oqK5rWP6KeI5Zmo5pe25Yy65oql57uZ5ZCO56uv77yM5a6a" +
      "5pe25aSH5Lu95ou85paH5Lu25ZCN5pe255SoCiAgICAgIHR6OiBJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25z" +
      "KCkudGltZVpvbmUgfHwgJycsCiAgICAgIGZpbGU6IHByb3ZpZGVyID09PSAnd2ViZGF2JwogICAgICAgID8gKGVsLmRhdkZpbGUu" +
      "dmFsdWUudHJpbSgpIHx8ICd0b2RvLXRvZGF5LmJhY2t1cC5qc29uJykKICAgICAgICA6IChlbC5zM0ZpbGUudmFsdWUudHJpbSgp" +
      "IHx8ICd0b2RvLXRvZGF5LmJhY2t1cC5qc29uJyksCiAgICAgIHIyOiB7IGtleTogZWwucjJLZXkudmFsdWUudHJpbSgpIH0sCiAg" +
      "ICAgIHMzOiB7CiAgICAgICAgZW5kcG9pbnQ6IGVsLnMzRW5kcG9pbnQudmFsdWUudHJpbSgpLAogICAgICAgIHJlZ2lvbjogZWwu" +
      "czNSZWdpb24udmFsdWUudHJpbSgpIHx8ICdhdXRvJywKICAgICAgICBidWNrZXQ6IGVsLnMzQnVja2V0LnZhbHVlLnRyaW0oKSwK" +
      "ICAgICAgICBhY2Nlc3NLZXlJZDogZWwuczNBa2lkLnZhbHVlLnRyaW0oKSwKICAgICAgICBzZWNyZXRBY2Nlc3NLZXk6IGVsLnMz" +
      "U2VjcmV0LnZhbHVlLnRyaW0oKSwKICAgICAgICBwcmVmaXg6IGVsLnMzUHJlZml4LnZhbHVlLnRyaW0oKSwKICAgICAgICBwYXRo" +
      "U3R5bGU6IGVsLnMzUGF0aFN0eWxlLmNoZWNrZWQsCiAgICAgIH0sCiAgICAgIHdlYmRhdjogewogICAgICAgIHVybDogZWwuZGF2" +
      "VXJsLnZhbHVlLnRyaW0oKSwKICAgICAgICB1c2VybmFtZTogZWwuZGF2VXNlci52YWx1ZS50cmltKCksCiAgICAgICAgcGFzc3dv" +
      "cmQ6IGVsLmRhdlBhc3MudmFsdWUudHJpbSgpLAogICAgICAgIGZpbGU6IGVsLmRhdkZpbGUudmFsdWUudHJpbSgpLAogICAgICB9" +
      "LAogICAgfTsKICB9CgogIGVsLmJhY2t1cFNhdmUuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3luYyAoKSA9PiB7CiAgICBz" +
      "ZXRTdGF0dXMoZWwuYmFja3VwU3RhdHVzLCAn5L+d5a2Y5Lit4oCmJywgJ2J1c3knKTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGRh" +
      "dGEgPSBhd2FpdCBhcGkoJy9iYWNrdXAvY29uZmlnJywgeyBtZXRob2Q6ICdQVVQnLCBib2R5OiBjb2xsZWN0QmFja3VwRm9ybSgp" +
      "IH0pOwogICAgICBmaWxsQmFja3VwRm9ybShkYXRhLmNvbmZpZyB8fCB7fSk7CiAgICAgIHNldFN0YXR1cyhlbC5iYWNrdXBTdGF0" +
      "dXMsICfphY3nva7lt7Lkv53lrZgnLCAnb2snKTsKICAgICAgdG9hc3QoJ+Wkh+S7vemFjee9ruW3suS/neWtmCcsICdvaycpOwog" +
      "ICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgIHNldFN0YXR1cyhlbC5iYWNrdXBTdGF0dXMsIGDkv53lrZjlpLHotKXvvJoke2Vyci5t" +
      "ZXNzYWdlfWAsICdlcnInKTsKICAgIH0KICB9KTsKCiAgZWwuYmFja3VwVGVzdC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFz" +
      "eW5jICgpID0+IHsKICAgIHNldFN0YXR1cyhlbC5iYWNrdXBTdGF0dXMsICfmraPlnKjmtYvor5Xov57mjqXigKYnLCAnYnVzeScp" +
      "OwogICAgdHJ5IHsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGFwaSgnL2JhY2t1cC90ZXN0JywgeyBtZXRob2Q6ICdQT1NUJywg" +
      "Ym9keTogY29sbGVjdEJhY2t1cEZvcm0oKSB9KTsKICAgICAgc2V0U3RhdHVzKGVsLmJhY2t1cFN0YXR1cywgZGF0YS5tZXNzYWdl" +
      "IHx8ICfov57mjqXmraPluLgnLCAnb2snKTsKICAgIH0gY2F0Y2ggKGVycikgewogICAgICBzZXRTdGF0dXMoZWwuYmFja3VwU3Rh" +
      "dHVzLCBg6L+e5o6l5aSx6LSl77yaJHtlcnIubWVzc2FnZX1gLCAnZXJyJyk7CiAgICB9CiAgfSk7CgogIGVsLmJhY2t1cFJ1bi5h" +
      "ZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICAgIHNldFN0YXR1cyhlbC5iYWNrdXBTdGF0dXMsICfmraPl" +
      "nKjlpIfku73igKYnLCAnYnVzeScpOwogICAgdHJ5IHsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGFwaSgnL2JhY2t1cC9ydW4n" +
      "LCB7IG1ldGhvZDogJ1BPU1QnIH0pOwogICAgICBjb25zdCByID0gZGF0YS5yZXN1bHQgfHwge307CiAgICAgIGNvbnN0IGRldGFp" +
      "bCA9IHIua2V5ICYmIHIua2V5ICE9PSByLmxhdGVzdEtleQogICAgICAgID8gYOWFsSAke3IudG90YWwgPz8gJy0nfSDmnaHku7vl" +
      "iqHvvIwke2Zvcm1hdEJ5dGVzKHIuc2l6ZSl9IOKGkiAke3Iua2V5fWAKICAgICAgICA6IGDlhbEgJHtyLnRvdGFsID8/ICctJ30g" +
      "5p2h5Lu75Yqh77yMJHtmb3JtYXRCeXRlcyhyLnNpemUpfSDihpIgJHtyLmtleSB8fCByLmxhdGVzdEtleSB8fCAnJ31gOwogICAg" +
      "ICBzZXRTdGF0dXMoZWwuYmFja3VwU3RhdHVzLCBg5aSH5Lu95oiQ5Yqf77yaJHtkZXRhaWx9YCwgJ29rJyk7CiAgICAgIGVsLmxh" +
      "c3RCYWNrdXBMaW5lLnRleHRDb250ZW50ID0gYOS4iuasoeWkh+S7ve+8miR7bmV3IERhdGUoKS50b0xvY2FsZVN0cmluZygpfWA7" +
      "CiAgICAgIHRvYXN0KCflt7LlpIfku73liLDkupHnq68nLCAnb2snKTsKICAgIH0gY2F0Y2ggKGVycikgewogICAgICBzZXRTdGF0" +
      "dXMoZWwuYmFja3VwU3RhdHVzLCBg5aSH5Lu95aSx6LSl77yaJHtlcnIubWVzc2FnZX1gLCAnZXJyJyk7CiAgICB9CiAgfSk7Cgog" +
      "IGVsLmJhY2t1cFJlc3RvcmUuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBhcm1lZENsaWNrKGVsLmJhY2t1" +
      "cFJlc3RvcmUsICfnoa7orqTopobnm5bvvJ8nLCBhc3luYyAoKSA9PiB7CiAgICAgIHNldFN0YXR1cyhlbC5iYWNrdXBTdGF0dXMs" +
      "ICfmraPlnKjku47kupHnq6/mgaLlpI3igKYnLCAnYnVzeScpOwogICAgICB0cnkgewogICAgICBjb25zdCBkYXRhID0gYXdhaXQg" +
      "YXBpKCcvYmFja3VwL3Jlc3RvcmUnLCB7IG1ldGhvZDogJ1BPU1QnLCBib2R5OiB7IG1vZGU6ICdyZXBsYWNlJyB9IH0pOwogICAg" +
      "ICBzZXRTdGF0dXMoZWwuYmFja3VwU3RhdHVzLCBgJHtkYXRhLm1lc3NhZ2V977yI5paw5aKeICR7ZGF0YS5yZXN1bHQ/Lmluc2Vy" +
      "dGVkID8/IDB9IOadoe+8iWAsICdvaycpOwogICAgICBjYWNoZUNsZWFyQWxsKCk7ICAgLy8g5LqR56uv5pWw5o2u5pW05L2T5pu/" +
      "5o2i77yM57yT5a2Y5YWo6YOo5aSx5pWICiAgICAgIGF3YWl0IHJlZnJlc2goKTsKICAgICAgc2NoZWR1bGVTaWRlYmFyUmVmcmVz" +
      "aCgpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzZXRTdGF0dXMoZWwuYmFja3VwU3RhdHVzLCBg5oGi5aSN5aSx6LSl" +
      "77yaJHtlcnIubWVzc2FnZX1gLCAnZXJyJyk7CiAgICAgIH0KICAgIH0pOwogIH0pOwoKICBmdW5jdGlvbiBmb3JtYXRCeXRlcyhu" +
      "KSB7CiAgICBjb25zdCBudW0gPSBOdW1iZXIobikgfHwgMDsKICAgIGlmIChudW0gPCAxMDI0KSByZXR1cm4gYCR7bnVtfSBCYDsK" +
      "ICAgIGlmIChudW0gPCAxMDI0ICogMTAyNCkgcmV0dXJuIGAkeyhudW0gLyAxMDI0KS50b0ZpeGVkKDEpfSBLQmA7CiAgICByZXR1" +
      "cm4gYCR7KG51bSAvIDEwMjQgLyAxMDI0KS50b0ZpeGVkKDIpfSBNQmA7CiAgfQoKICAvKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0g5a+85YWl5a+85Ye6IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwogIGVsLmV4cG9ydEJ0bi5hZGRF" +
      "dmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICAgIHRyeSB7CiAgICAgIGlmIChzdGF0ZS5kZW1vKSB7CiAgICAg" +
      "ICAgY29uc3QgZGIgPSBkZW1vUmVhZCgpOwogICAgICAgIGRvd25sb2FkSnNvbih7IGFwcDogJ3RvZG8tdG9kYXknLCB2ZXJzaW9u" +
      "OiAxLCBleHBvcnRlZEF0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksIHRvZG9zOiBkYi50b2RvcyB9KTsKICAgICAgICByZXR1" +
      "cm47CiAgICAgIH0KICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goYCR7QVBJX0JBU0V9L2V4cG9ydGAsIHsgY3JlZGVudGlh" +
      "bHM6ICdzYW1lLW9yaWdpbicgfSk7CiAgICAgIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoYOWvvOWHuuWksei0pSAoJHty" +
      "ZXMuc3RhdHVzfSlgKTsKICAgICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgIGRvd25sb2FkQmxvYihibG9i" +
      "LCBgdG9kby10b2RheS0ke3RvZGF5U3RyKCl9Lmpzb25gKTsKICAgICAgdG9hc3QoJ+W3suWvvOWHuiBKU09OJywgJ29rJyk7CiAg" +
      "ICB9IGNhdGNoIChlcnIpIHsKICAgICAgdG9hc3QoZXJyLm1lc3NhZ2UsICdlcnInKTsKICAgIH0KICB9KTsKCiAgZWwuaW1wb3J0" +
      "QnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gZWwuaW1wb3J0RmlsZS5jbGljaygpKTsKCiAgZWwuaW1wb3J0Rmls" +
      "ZS5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCBhc3luYyAoKSA9PiB7CiAgICBjb25zdCBmaWxlID0gZWwuaW1wb3J0RmlsZS5m" +
      "aWxlcz8uWzBdOwogICAgZWwuaW1wb3J0RmlsZS52YWx1ZSA9ICcnOwogICAgaWYgKCFmaWxlKSByZXR1cm47CgogICAgdHJ5IHsK" +
      "ICAgICAgY29uc3QgdGV4dCA9IGF3YWl0IGZpbGUudGV4dCgpOwogICAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5wYXJzZSh0ZXh0" +
      "KTsKICAgICAgaWYgKCFBcnJheS5pc0FycmF5KHBheWxvYWQ/LnRvZG9zKSkgdGhyb3cgbmV3IEVycm9yKCfmlofku7bmoLzlvI/k" +
      "uI3mraPnoa7vvJrnvLrlsJEgdG9kb3Mg5pWw57uEJyk7CgogICAgICBpZiAoc3RhdGUuZGVtbykgewogICAgICAgIGNvbnN0IGRi" +
      "ID0gZGVtb1JlYWQoKTsKICAgICAgICBkYi50b2RvcyA9IHBheWxvYWQudG9kb3MubWFwKCh0LCBpKSA9PiAoewogICAgICAgICAg" +
      "aWQ6IGRlbW9JZCgpLCB0aXRsZTogU3RyaW5nKHQudGl0bGUgfHwgJycpLnRyaW0oKSwgZG9uZTogISF0LmRvbmUsCiAgICAgICAg" +
      "ICBkYXRlOiB0LmRhdGUgfHwgdG9kYXlTdHIoKSwgb3JkZXI6IGksIGNyZWF0ZWRBdDogTWF0aC5mbG9vcihEYXRlLm5vdygpIC8g" +
      "MTAwMCksCiAgICAgICAgfSkpLmZpbHRlcigodCkgPT4gdC50aXRsZSk7CiAgICAgICAgZGVtb1dyaXRlKGRiKTsKICAgICAgICBj" +
      "YWNoZUNsZWFyQWxsKCk7CiAgICAgICAgYXdhaXQgcmVmcmVzaCgpOwogICAgICAgIHRvYXN0KGDlr7zlhaXlrozmiJDvvJoke2Ri" +
      "LnRvZG9zLmxlbmd0aH0g5p2hYCwgJ29rJyk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBkYXRhID0gYXdh" +
      "aXQgYXBpKCcvaW1wb3J0JywgeyBtZXRob2Q6ICdQT1NUJywgYm9keTogeyBwYXlsb2FkLCBtb2RlOiAncmVwbGFjZScgfSB9KTsK" +
      "ICAgICAgY2FjaGVDbGVhckFsbCgpOyAgIC8vIOWvvOWFpeaVtOS9k+abv+aNouaVsOaNru+8jOe8k+WtmOWFqOmDqOWkseaViAog" +
      "ICAgICBhd2FpdCByZWZyZXNoKCk7CiAgICAgIHNjaGVkdWxlU2lkZWJhclJlZnJlc2goKTsKICAgICAgdG9hc3QoZGF0YS5tZXNz" +
      "YWdlIHx8ICflr7zlhaXlrozmiJAnLCAnb2snKTsKICAgIH0gY2F0Y2ggKGVycikgewogICAgICB0b2FzdChg5a+85YWl5aSx6LSl" +
      "77yaJHtlcnIubWVzc2FnZX1gLCAnZXJyJyk7CiAgICB9CiAgfSk7CgogIGZ1bmN0aW9uIGRvd25sb2FkSnNvbihvYmopIHsKICAg" +
      "IGRvd25sb2FkQmxvYihuZXcgQmxvYihbSlNPTi5zdHJpbmdpZnkob2JqLCBudWxsLCAyKV0sIHsgdHlwZTogJ2FwcGxpY2F0aW9u" +
      "L2pzb24nIH0pLCBgdG9kby10b2RheS0ke3RvZGF5U3RyKCl9Lmpzb25gKTsKICB9CgogIGZ1bmN0aW9uIGRvd25sb2FkQmxvYihi" +
      "bG9iLCBmaWxlbmFtZSkgewogICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgIGNvbnN0IGEgPSBk" +
      "b2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7CiAgICBhLmhyZWYgPSB1cmw7CiAgICBhLmRvd25sb2FkID0gZmlsZW5hbWU7CiAg" +
      "ICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOwogICAgYS5jbGljaygpOwogICAgYS5yZW1vdmUoKTsKICAgIHNldFRpbWVv" +
      "dXQoKCkgPT4gVVJMLnJldm9rZU9iamVjdFVSTCh1cmwpLCAxMDAwKTsKICB9CgogIC8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqCiAgICog5ZCv5YqoCiAgICogLS0tLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCiAgZWwuYWJvdXRWZXJzaW9u" +
      "LnRleHRDb250ZW50ID0gYOWJjeerryB2JHtBUFBfVkVSU0lPTn1gOwoKICAvLyDlv6vmjbfplK7vvJovIOiBmueEpuaWsOWinui+" +
      "k+WFpeahhu+8m0N0cmwvQ21kK0sg6IGa54Sm5pCc57Si77ybRXNjIOWFs+aKveWxiS/kvqfmoI8KICBkb2N1bWVudC5hZGRFdmVu" +
      "dExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHsKICAgIGNvbnN0IGluRmllbGQgPSAvXihJTlBVVHxURVhUQVJFQXxTRUxFQ1Qp" +
      "JC8udGVzdChkb2N1bWVudC5hY3RpdmVFbGVtZW50Py50YWdOYW1lIHx8ICcnKQogICAgICB8fCBkb2N1bWVudC5hY3RpdmVFbGVt" +
      "ZW50Py5pc0NvbnRlbnRFZGl0YWJsZTsKCiAgICBpZiAoKGUuY3RybEtleSB8fCBlLm1ldGFLZXkpICYmIGUua2V5LnRvTG93ZXJD" +
      "YXNlKCkgPT09ICdrJykgewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGVsLnNlYXJjaElucHV0LmZvY3VzKCk7CiAg" +
      "ICAgIGVsLnNlYXJjaElucHV0LnNlbGVjdCgpOwogICAgICByZXR1cm47CiAgICB9CiAgICBpZiAoZS5rZXkgPT09ICcvJyAmJiAh" +
      "aW5GaWVsZCkgewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGVsLmFkZElucHV0LmZvY3VzKCk7CiAgICB9CiAgfSk7" +
      "CgogIChhc3luYyBmdW5jdGlvbiBib290KCkgewogICAgcmVuZGVyRGF0ZSgpOwoKICAgIGlmIChGT1JDRV9ERU1PKSB7CiAgICAg" +
      "IHN0YXRlLmRlbW8gPSB0cnVlOwogICAgICBzZWVkRGVtb0RhdGEoKTsKICAgICAgZWwuZGVtb0Jhbm5lci5jbGFzc0xpc3QucmVt" +
      "b3ZlKCdoaWRkZW4nKTsKICAgICAgZWwuYWJvdXRWZXJzaW9uLnRleHRDb250ZW50ID0gYOWJjeerryB2JHtBUFBfVkVSU0lPTn0g" +
      "wrcg5ryU56S65qih5byPYDsKICAgICAgc3RhdGUudXNlciA9IGRlbW9SZWFkKCkudXNlcjsKICAgICAgYXdhaXQgc2hvd01haW4o" +
      "KTsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIHRyeSB7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBhcGkoJy9hdXRoL21lJyk7" +
      "CiAgICAgIHN0YXRlLnVzZXIgPSBkYXRhLnVzZXI7CiAgICAgIGlmIChzdGF0ZS51c2VyKSBhd2FpdCBzaG93TWFpbigpOwogICAg" +
      "ICBlbHNlIHNob3dBdXRoKCk7CiAgICB9IGNhdGNoIHsKICAgICAgc2hvd0F1dGgoKTsKICAgIH0KICB9KSgpOwp9KSgpOwo="
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
      "di1tb250aCIgYXJpYS1sYWJlbD0i5LiK5Liq5pyIIiB0aXRsZT0i5LiK5Liq5pyIIj7igLk8L2J1dHRvbj4KICAgIDxzcGFuIGlk" +
      "PSJwb3AtdGl0bGUiIGNsYXNzPSJkYXRlLXBvcC10aXRsZSI+4oCUPC9zcGFuPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNs" +
      "YXNzPSJtaW5pLWJ0biIgaWQ9InBvcC1uZXh0LW1vbnRoIiBhcmlhLWxhYmVsPSLkuIvkuKrmnIgiIHRpdGxlPSLkuIvkuKrmnIgi" +
      "PuKAujwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJtaW5pLWJ0biIgaWQ9InBvcC1uZXh0LXllYXIi" +
      "IGFyaWEtbGFiZWw9IuS4i+S4gOW5tCIgdGl0bGU9IuS4i+S4gOW5tCI+wrs8L2J1dHRvbj4KICA8L2Rpdj4KICA8ZGl2IGlkPSJw" +
      "b3AtZ3JpZCIgY2xhc3M9ImNhbGVuZGFyIHBvcC1ncmlkIj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJkYXRlLXBvcC1mb290Ij4KICAg" +
      "IDxidXR0b24gdHlwZT0iYnV0dG9uIiBpZD0icG9wLWNsZWFyIiBjbGFzcz0iYnRuIHN1YnRsZSBzbWFsbCIgdGl0bGU9IuaBouWk" +
      "jeS4uuWOn+aXpeacnyI+5riF56m6PC9idXR0b24+CiAgICA8c3BhbiBjbGFzcz0iZGF0ZS1wb3AtZ2FwIj48L3NwYW4+CiAgICA8" +
      "YnV0dG9uIHR5cGU9ImJ1dHRvbiIgaWQ9InBvcC10b2RheSIgY2xhc3M9ImJ0biBzdWJ0bGUgc21hbGwiPuS7iuWkqTwvYnV0dG9u" +
      "PgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJwb3Atb2siIGNsYXNzPSJidG4gcHJpbWFyeSBzbWFsbCI+56Gu5a6aPC9i" +
      "dXR0b24+CiAgPC9kaXY+CjwvZGl2PgoKPGRpdiBpZD0idG9hc3QtaG9zdCIgY2xhc3M9InRvYXN0LWhvc3QiIGFyaWEtbGl2ZT0i" +
      "cG9saXRlIj48L2Rpdj4KCjxzY3JpcHQgc3JjPSIuL2FwcC5qcyI+PC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo="
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
      "IDJweDsKICBtYXJnaW4tYm90dG9tOiA0cHg7Cn0KLmRhdGUtcG9wLXRpdGxlIHsKICBmbGV4OiAxOwogIHRleHQtYWxpZ246IGNl" +
      "bnRlcjsKICBmb250LXdlaWdodDogNzAwOwogIGZvbnQtc2l6ZTogMTQuNXB4OwogIGxldHRlci1zcGFjaW5nOiAwLjAyZW07Cn0K" +
      "LmRhdGUtcG9wIC5taW5pLWJ0biB7IHdpZHRoOiAzMHB4OyBoZWlnaHQ6IDMwcHg7IGZvbnQtc2l6ZTogMTRweDsgfQoucG9wLWdy" +
      "aWQgeyBnYXA6IDFweDsgfQoucG9wLWdyaWQgLmNhbC1kYXkgeyBoZWlnaHQ6IDM2cHg7IH0KLnBvcC1ncmlkIC5jYWwtZGF5Lmlz" +
      "LW91dHNpZGUgeyBjb2xvcjogdmFyKC0tdGV4dC1mYWludCk7IG9wYWNpdHk6IDAuNTU7IH0KLmRhdGUtcG9wLWZvb3QgewogIGRp" +
      "c3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBnYXA6IDhweDsKICBtYXJnaW4tdG9wOiA4cHg7CiAgcGFkZGlu" +
      "Zy10b3A6IDEwcHg7CiAgYm9yZGVyLXRvcDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Cn0KLmRhdGUtcG9wLWdhcCB7IGZsZXg6" +
      "IDE7IH0KQG1lZGlhIChtYXgtd2lkdGg6IDUyMHB4KSB7CiAgLmRhdGUtcG9wIHsKICAgIGxlZnQ6IDUwJSAhaW1wb3J0YW50Owog" +
      "ICAgcmlnaHQ6IGF1dG8gIWltcG9ydGFudDsKICAgIGJvdHRvbTogY2FsYygxNnB4ICsgdmFyKC0tc2FmZS1ib3R0b20pKSAhaW1w" +
      "b3J0YW50OwogICAgdG9wOiBhdXRvICFpbXBvcnRhbnQ7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBhbmlt" +
      "YXRpb246IHBvcC1pbi1ib3R0b20gMC4xNnMgY3ViaWMtYmV6aWVyKDAuMiwgMC44LCAwLjIsIDEpOwogIH0KICBAa2V5ZnJhbWVz" +
      "IHBvcC1pbi1ib3R0b20gewogICAgZnJvbSB7IG9wYWNpdHk6IDA7IHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xh" +
      "dGVZKDEwcHgpOyB9CiAgICB0byB7IG9wYWNpdHk6IDE7IHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsgfQogIH0KfQoKLyog" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSDmir3lsYkgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LSAqLwouZHJhd2VyLW1hc2sgewogIHBvc2l0aW9uOiBmaXhlZDsKICBpbnNldDogMDsKICBiYWNrZ3JvdW5kOiByZ2JhKDE0LCAx" +
      "NSwgMjUsIDAuNDIpOwogIGJhY2tkcm9wLWZpbHRlcjogYmx1cigzcHgpOwogIC13ZWJraXQtYmFja2Ryb3AtZmlsdGVyOiBibHVy" +
      "KDNweCk7CiAgei1pbmRleDogNDA7CiAgZGlzcGxheTogZmxleDsKICBqdXN0aWZ5LWNvbnRlbnQ6IGZsZXgtZW5kOwogIGFuaW1h" +
      "dGlvbjogZmFkZS1pbiAwLjIycyBlYXNlOwp9CkBrZXlmcmFtZXMgZmFkZS1pbiB7IGZyb20geyBvcGFjaXR5OiAwOyB9IHRvIHsg" +
      "b3BhY2l0eTogMTsgfSB9CgouZHJhd2VyIHsKICB3aWR0aDogbWluKDQ0MHB4LCAxMDAlKTsKICBoZWlnaHQ6IDEwMCU7CiAgYmFj" +
      "a2dyb3VuZDogdmFyKC0tYmcpOwogIGRpc3BsYXk6IGZsZXg7CiAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICBib3gtc2hhZG93" +
      "OiB2YXIoLS1zaGFkb3ctbGcpOwogIGFuaW1hdGlvbjogc2xpZGUtaW4gMC4yOHMgY3ViaWMtYmV6aWVyKDAuMiwgMC44LCAwLjIs" +
      "IDEpOwp9CkBrZXlmcmFtZXMgc2xpZGUtaW4geyBmcm9tIHsgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKDI0cHgpOyBvcGFjaXR5OiAw" +
      "LjQ7IH0gdG8geyB0cmFuc2Zvcm06IG5vbmU7IG9wYWNpdHk6IDE7IH0gfQoKLmRyYXdlci1oZWFkIHsKICBkaXNwbGF5OiBmbGV4" +
      "OyBhbGlnbi1pdGVtczogY2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgcGFkZGluZzogMTZweCAxNnB4" +
      "IDEycHg7CiAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgcG9zaXRpb246IHN0aWNreTsgdG9wOiAw" +
      "OwogIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICB6LWluZGV4OiAyOwp9Ci5kcmF3ZXItaGVhZCBoMiB7IG1hcmdpbjogMDsgZm9u" +
      "dC1zaXplOiAxOHB4OyBmb250LXdlaWdodDogNzAwOyB9Ci5kcmF3ZXItYm9keSB7IG92ZXJmbG93LXk6IGF1dG87IHBhZGRpbmc6" +
      "IDE0cHggMTZweCBjYWxjKDI4cHggKyB2YXIoLS1zYWZlLWJvdHRvbSkpOyAtd2Via2l0LW92ZXJmbG93LXNjcm9sbGluZzogdG91" +
      "Y2g7IH0KCi5jYXJkIHsKICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3Jk" +
      "ZXIpOwogIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgcGFkZGluZzogMTVweCAxNXB4IDE2cHg7CiAgbWFyZ2luLWJv" +
      "dHRvbTogMTJweDsKICBib3gtc2hhZG93OiB2YXIoLS1zaGFkb3ctc20pOwp9Ci5jYXJkLWxhYmVsIHsKICBtYXJnaW46IDAgMCA0" +
      "cHg7CiAgZm9udC1zaXplOiAxMnB4OyBmb250LXdlaWdodDogNzAwOwogIGNvbG9yOiB2YXIoLS10ZXh0LWZhaW50KTsKICB0ZXh0" +
      "LXRyYW5zZm9ybTogdXBwZXJjYXNlOwogIGxldHRlci1zcGFjaW5nOiAwLjA3ZW07Cn0KLmNhcmQtZGVzYyB7IG1hcmdpbjogMCAw" +
      "IDE0cHg7IGZvbnQtc2l6ZTogMTNweDsgY29sb3I6IHZhcigtLXRleHQtbXV0ZWQpOyBsaW5lLWhlaWdodDogMS42NTsgfQoKLnJv" +
      "dy1iZXR3ZWVuIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3" +
      "ZWVuOyBnYXA6IDEycHg7IH0KLmFjY291bnQtbmFtZSB7IG1hcmdpbjogMnB4IDAgMDsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1z" +
      "aXplOiAxNXB4OyB9CgouY29sbGFwc2Ugc3VtbWFyeSB7CiAgY3Vyc29yOiBwb2ludGVyOwogIGZvbnQtc2l6ZTogMTMuNXB4Owog" +
      "IGZvbnQtd2VpZ2h0OiA2MDA7CiAgY29sb3I6IHZhcigtLXRleHQtbXV0ZWQpOwogIGxpc3Qtc3R5bGU6IG5vbmU7CiAgcGFkZGlu" +
      "ZzogNHB4IDA7Cn0KLmNvbGxhcHNlIHN1bW1hcnk6Oi13ZWJraXQtZGV0YWlscy1tYXJrZXIgeyBkaXNwbGF5OiBub25lOyB9Ci5j" +
      "b2xsYXBzZSBzdW1tYXJ5OjpiZWZvcmUgeyBjb250ZW50OiAn4pa4ICc7IGRpc3BsYXk6IGlubGluZS1ibG9jazsgdHJhbnNpdGlv" +
      "bjogdHJhbnNmb3JtIDAuMThzIGVhc2U7IH0KLmNvbGxhcHNlW29wZW5dIHN1bW1hcnk6OmJlZm9yZSB7IGNvbnRlbnQ6ICfilr4g" +
      "JzsgfQouY29sbGFwc2UtYm9keSB7IHBhZGRpbmctdG9wOiAxMnB4OyB9Cgouc3dpdGNoLXJvdyB7IGRpc3BsYXk6IGZsZXg7IGZs" +
      "ZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMTBweDsgbWFyZ2luOiA0cHggMCAxNHB4OyB9Ci5zd2l0Y2ggewogIGRpc3BsYXk6" +
      "IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMTBweDsKICBjdXJzb3I6IHBvaW50ZXI7CiAgZm9udC1zaXplOiAxMy41" +
      "cHg7CiAgdXNlci1zZWxlY3Q6IG5vbmU7Cn0KLnN3aXRjaCBpbnB1dCB7IHBvc2l0aW9uOiBhYnNvbHV0ZTsgb3BhY2l0eTogMDsg" +
      "d2lkdGg6IDA7IGhlaWdodDogMDsgfQouc3dpdGNoIC5zbGlkZXIgewogIHBvc2l0aW9uOiByZWxhdGl2ZTsKICBmbGV4OiBub25l" +
      "OwogIHdpZHRoOiA0NHB4OyBoZWlnaHQ6IDI2cHg7CiAgYmFja2dyb3VuZDogdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVz" +
      "OiB2YXIoLS1yYWRpdXMtcGlsbCk7CiAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAwLjJzIGVhc2U7Cn0KLnN3aXRjaCAuc2xpZGVy" +
      "OjphZnRlciB7CiAgY29udGVudDogJyc7CiAgcG9zaXRpb246IGFic29sdXRlOwogIHRvcDogM3B4OyBsZWZ0OiAzcHg7CiAgd2lk" +
      "dGg6IDIwcHg7IGhlaWdodDogMjBweDsKICBiYWNrZ3JvdW5kOiAjZmZmOwogIGJvcmRlci1yYWRpdXM6IDUwJTsKICBib3gtc2hh" +
      "ZG93OiB2YXIoLS1zaGFkb3ctc20pOwogIHRyYW5zaXRpb246IHRyYW5zZm9ybSAwLjJzIGN1YmljLWJlemllcigwLjMsIDEuNCwg" +
      "MC41LCAxKTsKfQouc3dpdGNoIGlucHV0OmNoZWNrZWQgKyAuc2xpZGVyIHsgYmFja2dyb3VuZDogdmFyKC0tYnJhbmQpOyB9Ci5z" +
      "d2l0Y2ggaW5wdXQ6Y2hlY2tlZCArIC5zbGlkZXI6OmFmdGVyIHsgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKDE4cHgpOyB9Ci5zd2l0" +
      "Y2gtdGV4dCB7IGNvbG9yOiB2YXIoLS10ZXh0LW11dGVkKTsgfQouc3dpdGNoLmNvbXBhY3QgeyBtYXJnaW4tdG9wOiAycHg7IH0K" +
      "LnN3aXRjaC5jb21wYWN0IC5zd2l0Y2gtdGV4dCB7IGZvbnQtc2l6ZTogMTIuNXB4OyBsaW5lLWhlaWdodDogMS41OyB9CgoucHJv" +
      "dmlkZXItcGFuZWwgewogIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgYm9yZGVyOiAxcHggZGFzaGVkIHZhcigtLWJv" +
      "cmRlcik7CiAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXNtKTsKICBwYWRkaW5nOiAxNHB4IDEzcHggNHB4OwogIG1hcmdp" +
      "bi1ib3R0b206IDE0cHg7CiAgYW5pbWF0aW9uOiBmYWRlLXVwIDAuMjRzIGVhc2U7Cn0KCi5idG4tcm93IHsgZGlzcGxheTogZmxl" +
      "eDsgZ2FwOiA4cHg7IG1hcmdpbi1ib3R0b206IDhweDsgfQouYnRuLXJvdyAuYnRuIHsgZmxleDogMTsgfQoKLnN0YXR1cy1saW5l" +
      "IHsKICBmb250LXNpemU6IDEyLjVweDsKICBwYWRkaW5nOiA4cHggMTFweDsKICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMt" +
      "c20pOwogIG1hcmdpbjogOHB4IDAgMDsKICB3b3JkLWJyZWFrOiBicmVhay13b3JkOwp9Ci5zdGF0dXMtbGluZS5vayB7IGJhY2tn" +
      "cm91bmQ6IHJnYmEoNDcsIDE2MiwgMTA2LCAwLjEyKTsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9Ci5zdGF0dXMtbGluZS5lcnIg" +
      "eyBiYWNrZ3JvdW5kOiByZ2JhKDIyMCwgNzQsIDc0LCAwLjEyKTsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KLnN0YXR1cy1saW5l" +
      "LmJ1c3kgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBjb2xvcjogdmFyKC0tdGV4dC1tdXRlZCk7IH0KCi5hYm91dC1j" +
      "YXJkIC5jYXJkLWRlc2MgeyBtYXJnaW4tYm90dG9tOiA2cHg7IH0KCi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t" +
      "LS0gVG9hc3QgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqLwoudG9hc3QtaG9zdCB7CiAgcG9zaXRpb246IGZp" +
      "eGVkOwogIGxlZnQ6IDUwJTsKICBib3R0b206IGNhbGMoODRweCArIHZhcigtLXNhZmUtYm90dG9tKSk7CiAgdHJhbnNmb3JtOiB0" +
      "cmFuc2xhdGVYKC01MCUpOwogIGRpc3BsYXk6IGZsZXg7CiAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICBhbGlnbi1pdGVtczog" +
      "Y2VudGVyOwogIGdhcDogOHB4OwogIHotaW5kZXg6IDcwOwogIHBvaW50ZXItZXZlbnRzOiBub25lOwogIHdpZHRoOiBtaW4oOTJ2" +
      "dywgNDYwcHgpOwp9Ci50b2FzdCB7CiAgYmFja2dyb3VuZDogIzFmMjEzMDsKICBjb2xvcjogI2ZmZjsKICBwYWRkaW5nOiAxMHB4" +
      "IDE2cHg7CiAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXBpbGwpOwogIGZvbnQtc2l6ZTogMTMuNXB4OwogIGJveC1zaGFk" +
      "b3c6IHZhcigtLXNoYWRvdy1tZCk7CiAgYW5pbWF0aW9uOiB0b2FzdC1pbiAwLjI0cyBjdWJpYy1iZXppZXIoMC4yLCAwLjgsIDAu" +
      "MiwgMSk7CiAgbWF4LXdpZHRoOiAxMDAlOwogIHRleHQtYWxpZ246IGNlbnRlcjsKfQoudG9hc3QuZXJyIHsgYmFja2dyb3VuZDog" +
      "I2IzMzgzYTsgfQoudG9hc3Qub2sgeyBiYWNrZ3JvdW5kOiAjMWY3YTUzOyB9Ci8qIOmVv+aWh+ahiO+8iOWmguWQjuerr+i/lOWb" +
      "nueahOaOkuafpeaMh+W8le+8ieeUqOWNoeeJh+agt+W8j++8jOiDtuWbiuW9ouS8muaSkeW+l+W+iOaAqiAqLwoudG9hc3QubG9u" +
      "ZyB7CiAgYm9yZGVyLXJhZGl1czogMTRweDsKICBwYWRkaW5nOiAxMnB4IDE2cHg7CiAgdGV4dC1hbGlnbjogbGVmdDsKICBsaW5l" +
      "LWhlaWdodDogMS42NTsKICB3b3JkLWJyZWFrOiBicmVhay13b3JkOwp9Ci50b2FzdC5sZWF2aW5nIHsgYW5pbWF0aW9uOiB0b2Fz" +
      "dC1vdXQgMC4yMnMgZWFzZSBmb3J3YXJkczsgfQpAa2V5ZnJhbWVzIHRvYXN0LWluIHsgZnJvbSB7IG9wYWNpdHk6IDA7IHRyYW5z" +
      "Zm9ybTogdHJhbnNsYXRlWSgxMHB4KSBzY2FsZSgwLjk2KTsgfSB0byB7IG9wYWNpdHk6IDE7IHRyYW5zZm9ybTogbm9uZTsgfSB9" +
      "CkBrZXlmcmFtZXMgdG9hc3Qtb3V0IHsgdG8geyBvcGFjaXR5OiAwOyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVkoNnB4KSBzY2FsZSgw" +
      "Ljk3KTsgfSB9CgovKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIOahjOmdouerr+W4g+WxgCAtLS0tLS0tLS0t" +
      "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovCkBtZWRpYSAobWluLXdpZHRoOiA5ODBweCkgewogIC5zaGVsbCB7CiAgICBkaXNw" +
      "bGF5OiBncmlkOwogICAgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAyNjhweCBtaW5tYXgoMCwgMWZyKTsKICAgIG1heC13aWR0aDog" +
      "MTE4MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBhbGlnbi1pdGVtczogc3RhcnQ7CiAgfQogIC5zaWRlYmFyIHsKICAgIHBv" +
      "c2l0aW9uOiBzdGlja3k7CiAgICB0b3A6IDA7CiAgICBoZWlnaHQ6IDEwMGR2aDsKICAgIHdpZHRoOiBhdXRvOwogICAgdHJhbnNm" +
      "b3JtOiBub25lOwogICAgdmlzaWJpbGl0eTogdmlzaWJsZTsKICAgIGJhY2tncm91bmQ6IHRyYW5zcGFyZW50OwogICAgYm9yZGVy" +
      "LXJpZ2h0OiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJveC1zaGFkb3c6IG5vbmU7CiAgICBwYWRkaW5nOiAyMnB4IDE2" +
      "cHggMjBweDsKICB9CiAgLnNpZGUtbWFzayB7IGRpc3BsYXk6IG5vbmUgIWltcG9ydGFudDsgfQogIC5zaWRlLXRvZ2dsZSB7IGRp" +
      "c3BsYXk6IG5vbmU7IH0KICAvKiBncmlkIOmhueS4iueahCBtYXJnaW46YXV0byDkvJrmlL7lvIPmi4nkvLjjgIHmjIkgZml0LWNv" +
      "bnRlbnQg5pS257yp77yM5b+F6aG75pi+5byP57uZ5a69ICovCiAgLmNvbnRlbnQgewogICAgd2lkdGg6IDEwMCU7CiAgICBtYXgt" +
      "d2lkdGg6IDc2MHB4OwogICAgcGFkZGluZzogMCAyOHB4IGNhbGMoMThweCArIHZhcigtLXNhZmUtYm90dG9tKSk7CiAgfQogIC50" +
      "b3BiYXIgeyBwYWRkaW5nLXRvcDogMzBweDsgfQogIC50b3BiYXItdGl0bGUgeyBmb250LXNpemU6IDI4cHg7IH0KfQoKQG1lZGlh" +
      "IChtYXgtd2lkdGg6IDk3OXB4KSB7CiAgLm1haW4tdmlldyB7IG1heC13aWR0aDogNzAwcHg7IG1hcmdpbjogMCBhdXRvOyB9Cn0K" +
      "CkBtZWRpYSAocHJlZmVycy1yZWR1Y2VkLW1vdGlvbjogcmVkdWNlKSB7CiAgKiwgKjo6YmVmb3JlLCAqOjphZnRlciB7IGFuaW1h" +
      "dGlvbi1kdXJhdGlvbjogMC4wMDFtcyAhaW1wb3J0YW50OyB0cmFuc2l0aW9uLWR1cmF0aW9uOiAwLjAwMW1zICFpbXBvcnRhbnQ7" +
      "IH0KfQo="
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
