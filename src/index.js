/**
 * 今日待办 · Cloudflare Worker 入口
 *
 * 路由策略：
 *   /api/*  -> 由本 Worker 处理
 *   其它    -> 交给静态资源绑定 ASSETS（public/ 目录）
 */

import { ok, fail, json, readJson } from './lib/http.js';
import { INLINE_ASSETS } from './lib/assets.js';
import * as auth from './lib/auth.js';
import * as todos from './lib/todos.js';
import * as backup from './lib/backup.js';

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
      return fail(err?.message || '服务器内部错误', status);
    }
  },
};

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
  if (path === '/api/health' && method === 'GET') {
    return ok({
      app: env.APP_NAME || '今日待办',
      time: new Date().toISOString(),
      db: !!env.DB,
      r2: !!env.BACKUPS,
      registration: String(env.ALLOW_REGISTRATION ?? 'true').toLowerCase() !== 'false',
    });
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
    scheduleAutoBackup(ctx, env, user);
    return json({ ok: true, todo, ...stat }, { status: 201 });
  }

  if (path === '/api/todos/batch' && method === 'POST') {
    const user = await auth.requireUser(request, env);
    const body = await readJson(request);
    const date = todos.normalizeDate(body.date);

    if (body.action === 'clear-completed') {
      const res = await todos.clearCompleted(env, user.id, date);
      const stat = await todos.countByDate(env, user.id, date);
      scheduleAutoBackup(ctx, env, user);
      return ok({ ...res, ...stat });
    }

    if (body.action === 'toggle-all') {
      const res = await todos.toggleAll(env, user.id, date, !!body.done);
      const stat = await todos.countByDate(env, user.id, date);
      scheduleAutoBackup(ctx, env, user);
      return ok({ ...res, ...stat });
    }

    if (body.action === 'reorder') {
      const res = await todos.reorderTodos(env, user.id, date, body.ids);
      scheduleAutoBackup(ctx, env, user);
      return ok(res);
    }

    if (body.action === 'carry-over') {
      const res = await todos.carryOver(env, user.id, { from: body.from || null, to: date });
      const list = await todos.listTodos(env, user.id, date);
      const stat = await todos.countByDate(env, user.id, date);
      scheduleAutoBackup(ctx, env, user);
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

  const todoMatch = path.match(/^\/api\/todos\/([^/]+)$/);
  if (todoMatch) {
    const id = decodeURIComponent(todoMatch[1]);
    const user = await auth.requireUser(request, env);

    if (method === 'PATCH') {
      const body = await readJson(request);
      const todo = await todos.updateTodo(env, user.id, id, body);
      const stat = await todos.countByDate(env, user.id, todo.date);
      scheduleAutoBackup(ctx, env, user);
      return ok({ todo, ...stat });
    }

    if (method === 'DELETE') {
      const res = await todos.deleteTodo(env, user.id, id);
      const date = url.searchParams.get('date');
      let stat = { remaining: 0, total: 0 };
      if (date && todos.DATE_RE.test(date)) stat = await todos.countByDate(env, user.id, date);
      scheduleAutoBackup(ctx, env, user);
      return ok({ ...res, ...stat });
    }
  }

  /* ---------- 备份 ---------- */
  if (path === '/api/backup/config' && method === 'GET') {
    const user = await auth.requireUser(request, env);
    const { config, lastBackup } = await backup.readConfig(env, user.id);
    return ok({
      config: backup.maskConfig(config, env),
      lastBackup,
      throttleSeconds: backup.AUTO_BACKUP_THROTTLE_SECONDS,
    });
  }

  if (path === '/api/backup/config' && method === 'PUT') {
    const user = await auth.requireUser(request, env);
    const body = await readJson(request);
    const { config: previous } = await backup.readConfig(env, user.id);
    const merged = backup.normalizeConfig(body, previous);
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
    const result = await backup.runBackup(env, user, config.provider === 'none' ? { ...config, provider: 'none' } : config);
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
    const filename = `todo-today-${new Date().toISOString().slice(0, 10)}.json`;
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
    scheduleAutoBackup(ctx, env, user);
    return ok({ message: `导入完成：新增 ${result.inserted} 条`, result });
  }

  return fail(`接口不存在：${method} ${path}`, 404);
}

/** 数据变更后触发自动备份（节流由 maybeAutoBackup 内部处理） */
function scheduleAutoBackup(ctx, env, user) {
  if (!ctx?.waitUntil) return;
  ctx.waitUntil(backup.maybeAutoBackup(env, user));
}
