/**
 * 单文件版（网页控制台粘贴部署用）的验证。
 *
 *   node test/bundle.mjs
 *
 * 会先重新执行打包脚本，然后把产物当成一个真实 Worker 跑一遍：
 *  - 静态资源是否由 Worker 自己正确返回（网页部署没有 assets 绑定）
 *  - 账号 / 待办接口是否与多文件版本行为一致
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

import { createD1 } from './d1-shim.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const OUT_FILE = join(ROOT, 'dist', 'worker.cloudflare-dashboard.js');

/* 先打包 */
execFileSync(process.execPath, [join(ROOT, 'scripts', 'build-dashboard.mjs')], { stdio: 'pipe' });
assert.ok(existsSync(OUT_FILE), '打包产物不存在');

const worker = (await import(pathToFileURL(OUT_FILE).href + `?t=${Date.now()}`)).default;

const TODAY = (() => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
})();

function makeHarness() {
  const db = createD1(':memory:');
  db._raw.exec(readFileSync(join(ROOT, 'schema.sql'), 'utf8'));

  // 注意：故意不提供 ASSETS 绑定，模拟「网页控制台部署」的环境
  const env = { DB: db, APP_NAME: '今日待办', ALLOW_REGISTRATION: 'true' };
  const ctx = { waitUntil: (p) => Promise.resolve(p).catch(() => {}), passThroughOnException() {} };
  let cookie = '';

  async function call(method, path, body, { auth = true } = {}) {
    const headers = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (auth && cookie) headers.cookie = cookie;

    const res = await worker.fetch(
      new Request(`https://todo.example.com${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
      env,
      ctx,
    );
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    return res;
  }

  return { call, db, env, get cookie() { return cookie; }, set cookie(v) { cookie = v; } };
}

async function json(res) {
  const text = await res.text();
  try { return JSON.parse(text); } catch { return null; }
}

/* ------------------------------------------------------------------ */

test('产物是自包含的：没有残留 import / 有 export default', () => {
  const code = readFileSync(OUT_FILE, 'utf8');
  assert.ok(!/^\s*import\b/m.test(code), '产物里不应再有 import');
  assert.ok(/^export\s+default\s/m.test(code), '缺少 export default 入口');
  assert.ok(!code.includes('const INLINE_ASSETS_B64 = null;'), '占位行未被替换');
  assert.ok(statSync(OUT_FILE).size > 50_000, '产物太小，资源可能没内联进去');
});

test('首页由 Worker 自己返回（无需 assets 绑定）', async () => {
  const h = makeHarness();
  const res = await h.call('GET', '/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') || '', /text\/html/);
  const html = await res.text();
  assert.match(html, /今日待办/);
  assert.match(html, /app\.js/);
});

test('CSS / JS / manifest / icon 都能取到且 MIME 正确', async () => {
  const h = makeHarness();
  const cases = [
    ['/style.css', /text\/css/],
    ['/app.js', /javascript/],
    ['/manifest.webmanifest', /manifest\+json/],
    ['/icon.svg', /image\/svg\+xml/],
  ];
  for (const [path, type] of cases) {
    const res = await h.call('GET', path);
    assert.equal(res.status, 200, `${path} 应返回 200`);
    assert.match(res.headers.get('content-type') || '', type, `${path} 的 MIME 不对`);
    assert.ok((await res.text()).length > 0, `${path} 内容为空`);
  }
});

test('内联的 index.html 与 public/index.html 完全一致', async () => {
  const h = makeHarness();
  const served = await (await h.call('GET', '/index.html')).text();
  const original = readFileSync(join(ROOT, 'public', 'index.html'), 'utf8');
  assert.equal(served, original);
});

test('未知静态路径返回 404', async () => {
  const h = makeHarness();
  assert.equal((await h.call('GET', '/nope.txt')).status, 404);
  assert.equal((await h.call('GET', '/../secret')).status, 404);
});

test('接口就绪：/api/health 能识别 DB，且识别不到 R2', async () => {
  const h = makeHarness();
  const data = await json(await h.call('GET', '/api/health'));
  assert.equal(data.db, true);
  assert.equal(data.r2, false);
});

test('完整用例：注册 → 新增（含空白拦截）→ 勾选 → 计数 → 删除', async () => {
  const h = makeHarness();

  assert.equal((await h.call('GET', `/api/todos?date=${TODAY}`)).status, 401, '未登录应为 401');

  const reg = await h.call('POST', '/api/auth/register', { username: '演示用户', password: 'secret123' });
  assert.equal(reg.status, 200);
  assert.equal((await json(reg)).user.username, '演示用户');

  for (const blank of ['', '   ', null]) {
    assert.equal((await h.call('POST', '/api/todos', { title: blank, date: TODAY })).status, 400);
  }

  const a = await json(await h.call('POST', '/api/todos', { title: '第一条', date: TODAY }));
  assert.equal(a.remaining, 1);
  await h.call('POST', '/api/todos', { title: '第二条', date: TODAY });
  const c = await json(await h.call('POST', '/api/todos', { title: '第三条', date: TODAY }));

  let list = await json(await h.call('GET', `/api/todos?date=${TODAY}`));
  assert.equal(list.todos.length, 3);
  assert.equal(list.remaining, 3);

  const toggled = await json(await h.call('PATCH', `/api/todos/${a.todo.id}`, { done: true }));
  assert.equal(toggled.remaining, 2);

  list = await json(await h.call('GET', `/api/todos?date=${TODAY}`));
  assert.equal(list.todos.at(-1).id, a.todo.id, '已完成项应沉底');

  const del = await h.call('DELETE', `/api/todos/${c.todo.id}?date=${TODAY}`);
  assert.equal(del.status, 200);
  list = await json(await h.call('GET', `/api/todos?date=${TODAY}`));
  assert.equal(list.todos.length, 2);
});

test('单文件版同样支持导出 JSON 与备份配置', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: '备份用户', password: 'secret123' });
  await h.call('POST', '/api/todos', { title: '导出我', date: TODAY });

  const exported = await json(await h.call('GET', '/api/export'));
  assert.equal(exported.todos.length, 1);
  assert.equal(exported.todos[0].title, '导出我');

  const cfg = await json(await h.call('GET', '/api/backup/config'));
  assert.equal(cfg.config.provider, 'none');
  assert.equal(cfg.config.hasR2Binding, false, '网页部署时未绑定 R2');

  const saved = await json(await h.call('PUT', '/api/backup/config', { provider: 'webdav', enabled: true, webdav: { url: 'https://dav.example.com/x', username: 'u', password: 'p' } }));
  assert.equal(saved.config.enabled, true);
  assert.equal(saved.config.webdav.hasPassword, true);
  assert.equal(saved.config.webdav.password, '', '密码不应回显');
});

test('单文件版仍可通过 ASSETS 绑定让位给 wrangler 部署', async () => {
  const h = makeHarness();
  let forwarded = null;
  h.env.ASSETS = {
    fetch: (req) => { forwarded = new URL(req.url).pathname; return new Response('from-assets', { status: 200 }); },
  };
  const res = await h.call('GET', '/index.html');
  assert.equal(await res.text(), 'from-assets');
  assert.equal(forwarded, '/index.html');
});

test('单文件版也会暴露定时备份处理器，并支持自定义频率', async () => {
  assert.equal(typeof worker.scheduled, 'function', '缺少 scheduled 处理器，Cron Triggers 会报错');

  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: '定时用户', password: 'secret123' });
  await h.call('POST', '/api/todos', { title: '定时备份我', date: TODAY });

  const saved = await json(await h.call('PUT', '/api/backup/config', {
    provider: 'r2', enabled: true, scheduled: true, intervalMin: 30, scheduleMin: 15, stamp: true,
  }));
  assert.equal(saved.config.intervalMin, 30);
  assert.equal(saved.config.scheduleMin, 15);

  // 网页部署没有 R2 绑定 -> 定时任务给出人话报错，且不会抛出去
  const report = await worker.scheduled({ scheduledTime: Date.now() }, h.env, { waitUntil: (p) => p });
  assert.equal(report.due, 1);
  assert.equal(report.ok, 0);
  assert.match(report.failed[0].error, /R2/);

  const after = await json(await h.call('GET', '/api/backup/config'));
  assert.equal(after.cron.healthy, true, '心跳已写入，设置页可据此判断定时任务是否生效');
});
