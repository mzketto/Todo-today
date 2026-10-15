/**
 * 账号与登录态。
 *  - 口令使用 PBKDF2-SHA256 派生，绝不明文落库
 *  - 登录成功后签发随机 token，写入 HttpOnly Cookie，同时在 D1 的 sessions 表留痕
 */

import { newId, randomHex, hashPassword, verifyPassword } from './crypto.js';
import { parseCookies, serializeCookie, isSecureRequest } from './http.js';

export const SESSION_COOKIE = 'todo_sid';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 天
const USERNAME_RE = /^[A-Za-z0-9_\u4e00-\u9fa5.\-]{2,20}$/;

export class HttpError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function publicUser(row) {
  return { id: row.id, username: row.username, createdAt: row.created_at };
}

/* ------------------------------ 注册 / 登录 ------------------------------ */

export async function register(env, { username, password }) {
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

export async function login(env, { username, password }) {
  const name = String(username || '').trim();
  const row = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(name).first();
  if (!row) throw new HttpError('用户名或密码不正确', 401);

  const valid = await verifyPassword(String(password || ''), row.password_hash, row.salt);
  if (!valid) throw new HttpError('用户名或密码不正确', 401);

  return publicUser(row);
}

/* -------------------------------- 会话 -------------------------------- */

export async function createSession(env, userId) {
  const token = randomHex(32);
  const ts = nowSeconds();
  await env.DB.prepare(
    'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
  )
    .bind(token, userId, ts, ts + SESSION_TTL_SECONDS)
    .run();
  return token;
}

export function sessionCookie(request, token) {
  return serializeCookie(SESSION_COOKIE, token, {
    maxAge: token ? SESSION_TTL_SECONDS : 0,
    path: '/',
    httpOnly: true,
    secure: isSecureRequest(request),
    sameSite: 'Lax',
  });
}

export async function destroySession(env, token) {
  if (!token) return;
  await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
}

/** 顺带清理过期会话（低频调用即可，失败不影响主流程） */
export async function purgeExpiredSessions(env) {
  try {
    await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(nowSeconds()).run();
  } catch {
    /* ignore */
  }
}

/** 读取当前登录用户，未登录返回 null */
export async function getSessionUser(request, env) {
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
export async function requireUser(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) throw new HttpError('请先登录', 401);
  return user;
}

/** 修改密码 */
export async function changePassword(env, user, { currentPassword, newPassword }) {
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
