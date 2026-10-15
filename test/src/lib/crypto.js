/**
 * 加密工具：全部基于 WebCrypto，Workers 运行时原生可用，无需额外依赖。
 *  - PBKDF2-SHA256 派生口令哈希（10 万次迭代 + 16 字节随机盐）
 *  - 定长比较，避免时序侧信道
 *  - 随机 ID / Token
 */

const encoder = new TextEncoder();

const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEY_BYTES = 32;

export function toHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex) {
  const clean = String(hex || '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

/** 生成随机 hex 串，len 为字节数（输出长度为 2*len） */
export function randomHex(len = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return toHex(bytes);
}

export function newId(prefix = '') {
  return `${prefix}${Date.now().toString(36)}${randomHex(6)}`;
}

/** 派生口令哈希，salt 为空时自动生成 */
export async function hashPassword(password, saltHex = null) {
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
export function safeEqualHex(a, b) {
  const x = String(a || '');
  const y = String(b || '');
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

export async function verifyPassword(password, hashHex, saltHex) {
  if (!hashHex || !saltHex) return false;
  const { hash } = await hashPassword(password, saltHex);
  return safeEqualHex(hash, hashHex);
}

/* ---------- S3 SigV4 需要的哈希原语 ---------- */

export async function sha256Hex(data) {
  const buf = typeof data === 'string' ? encoder.encode(data) : data;
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return toHex(new Uint8Array(digest));
}

export async function hmacSha256(keyBytes, message) {
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
export function basicAuthHeader(username, password) {
  const bytes = encoder.encode(`${username}:${password}`);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return `Basic ${btoa(binary)}`;
}
