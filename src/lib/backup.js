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
 */

import { sha256Hex, hmacSha256, toHex, basicAuthHeader } from './crypto.js';
import { HttpError, nowSeconds } from './auth.js';
import { listAllTodos } from './todos.js';

export const BACKUP_VERSION = 1;
export const DEFAULT_FILE = 'todo-today.backup.json';

const EMPTY_CONFIG = {
  provider: 'none',   // none | r2 | s3 | webdav
  enabled: false,
  auto: false,        // 数据变更后自动备份（带节流）
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

export const AUTO_BACKUP_THROTTLE_SECONDS = 60;

/* ============================== 配置读写 ============================== */

function pickString(value, fallback = '') {
  return typeof value === 'string' ? value.trim() : fallback;
}

/** 归一化 + 合并旧的加密字段（前端留空 = 不修改） */
export function normalizeConfig(input = {}, previous = {}) {
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
export function maskConfig(config = EMPTY_CONFIG, env = {}) {
  const s3Secret = config.s3?.secretAccessKey || env.BACKUP_S3_SECRET_KEY || '';
  const davPass = config.webdav?.password || env.BACKUP_WEBDAV_PASSWORD || '';
  return {
    provider: config.provider || 'none',
    enabled: !!config.enabled,
    auto: !!config.auto,
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

export async function readConfig(env, userId) {
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

export async function writeConfig(env, userId, config) {
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

export async function buildPayload(env, user) {
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

export async function applyPayload(env, user, payload, { mode = 'merge' } = {}) {
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
export async function signRequest({
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
export async function s3Fetch(env, config, {
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

export async function runBackup(env, user, config) {
  if (!config || config.provider === 'none') throw new HttpError('未配置备份方式');

  const key = objectKeyOf(config, config.provider);
  const payload = await buildPayload(env, user);
  const text = JSON.stringify(payload, null, 2);
  const result = await putObject(env, config, key, text);

  await env.DB.prepare('UPDATE settings SET last_backup = ?, updated_at = ? WHERE user_id = ?')
    .bind(nowSeconds(), nowSeconds(), user.id)
    .run();

  return {
    ...result,
    size: new TextEncoder().encode(text).length,
    total: payload.stats.total,
    remaining: payload.stats.remaining,
    at: payload.exportedAt,
  };
}

export async function testConnection(env, config) {
  if (!config || config.provider === 'none') throw new HttpError('未配置备份方式');
  const key = objectKeyOf(config, config.provider);
  const info = await headObject(env, config, key);
  return { provider: config.provider, key, ...info };
}

export async function restoreBackup(env, user, config, mode = 'merge') {
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
 * 数据变更后的自动备份（节流：AUTO_BACKUP_THROTTLE_SECONDS 内最多一次）。
 * 用 ctx.waitUntil 调用，不阻塞用户请求。
 */
export async function maybeAutoBackup(env, user) {
  try {
    const { config, lastBackup } = await readConfig(env, user.id);
    if (!config.enabled || !config.auto || config.provider === 'none') return;
    if (lastBackup && nowSeconds() - lastBackup < AUTO_BACKUP_THROTTLE_SECONDS) return;
    await runBackup(env, user, config);
    console.log(`[auto-backup] user=${user.id} provider=${config.provider} ok`);
  } catch (err) {
    console.error(`[auto-backup] 失败：${err?.message || err}`);
  }
}
