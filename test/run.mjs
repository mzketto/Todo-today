/**
 * 测试入口：node --test test/    或   node test/run.mjs
 *
 *  1) SigV4 签名回归：跑 AWS 官方 aws-sig-v4-test-suite 的测试向量
 *  2) API 端到端：用内存 SQLite 冒充 D1，把 Worker 的 fetch 全流程跑一遍
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import worker from '../src/index.js';
import { signRequest } from '../src/lib/backup.js';
import { createD1 } from './d1-shim.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

/* ============================================================
 * 1. SigV4 官方测试向量
 * ============================================================ */

const VECTORS = {
  accessKeyId: 'AKIDEXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
  region: 'us-east-1',
  service: 'service',
};

/** 解析 aws-sig-v4-test-suite 的 .req 文件 */
function parseReq(text) {
  const lines = text.replace(/\r\n/g, '\n').split('\n').filter((l) => l.length);
  const [method, path] = lines[0].split(' ');
  const headers = {};
  for (const line of lines.slice(1)) {
    const i = line.indexOf(':');
    if (i === -1) continue;
    headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return { method, path, headers };
}

const fixtureDir = join(__dirname, 'fixtures', 'sigv4');
const cases = readdirSync(fixtureDir).filter((f) => f.endsWith('.authz')).map((f) => f.replace(/\.authz$/, ''));

assert.ok(cases.length >= 4, '测试向量缺失');

for (const name of cases) {
  test(`SigV4 官方向量 · ${name}`, async () => {
    const req = parseReq(readFileSync(join(fixtureDir, `${name}.req`), 'utf8'));
    const expectedAuth = readFileSync(join(fixtureDir, `${name}.authz`), 'utf8').trim();
    const expectedCreq = readFileSync(join(fixtureDir, `${name}.creq`), 'utf8').trim();
    const expectedSts = readFileSync(join(fixtureDir, `${name}.sts`), 'utf8').trim();

    const amzDate = req.headers['X-Amz-Date'] || req.headers['x-amz-date'];
    const date = new Date(
      `${amzDate.slice(0, 4)}-${amzDate.slice(4, 6)}-${amzDate.slice(6, 8)}T` +
      `${amzDate.slice(9, 11)}:${amzDate.slice(11, 13)}:${amzDate.slice(13, 15)}.000Z`,
    );

    const { authorization, canonicalRequest, stringToSign } = await signRequest({
      method: req.method,
      url: `https://example.amazonaws.com${req.path}`,
      headers: req.headers,
      body: '',
      date,
      addContentSha256: false,
      ...VECTORS,
    });

    assert.equal(canonicalRequest, expectedCreq, '规范请求不一致');
    assert.equal(stringToSign, expectedSts, '待签字符串不一致');
    assert.equal(authorization, expectedAuth, 'Authorization 头不一致');
  });
}

/* ============================================================
 * 2. API 端到端
 * ============================================================ */

function makeHarness() {
  const db = createD1(':memory:');
  db._raw.exec(readFileSync(join(ROOT, 'schema.sql'), 'utf8'));

  const env = { DB: db, APP_NAME: '今日待办', ALLOW_REGISTRATION: 'true' };
  const pending = [];
  const ctx = { waitUntil: (p) => pending.push(Promise.resolve(p).catch(() => {})), passThroughOnException() {} };

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

    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = null; }
    return { status: res.status, data, text };
  }

  return {
    call,
    db,
    env,
    flush: () => Promise.all(pending),
    /** 读写当前会话 Cookie，便于在多用户场景间切换身份 */
    get cookie() { return cookie; },
    set cookie(value) { cookie = value; },
  };
}

const TODAY = (() => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
})();

test('健康检查', async () => {
  const h = makeHarness();
  const res = await h.call('GET', '/api/health');
  assert.equal(res.status, 200);
  assert.equal(res.data.db, true);
  assert.equal(res.data.r2, false);
});

test('未登录访问待办返回 401', async () => {
  const h = makeHarness();
  const res = await h.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(res.status, 401);
  assert.equal(res.data.ok, false);
});

test('注册与登录校验', async () => {
  const h = makeHarness();

  assert.equal((await h.call('POST', '/api/auth/register', { username: 'a', password: '123456' })).status, 400, '用户名太短');
  assert.equal((await h.call('POST', '/api/auth/register', { username: 'someone', password: '123' })).status, 400, '密码太短');

  const reg = await h.call('POST', '/api/auth/register', { username: '小明', password: 'secret123' });
  assert.equal(reg.status, 200);
  assert.equal(reg.data.user.username, '小明');

  const me = await h.call('GET', '/api/auth/me');
  assert.equal(me.data.user.username, '小明');

  const dup = await h.call('POST', '/api/auth/register', { username: '小明', password: 'secret123' });
  assert.equal(dup.status, 409, '重复用户名应被拒绝');

  const badLogin = await h.call('POST', '/api/auth/login', { username: '小明', password: 'wrong' }, { auth: false });
  assert.equal(badLogin.status, 401);

  const goodLogin = await h.call('POST', '/api/auth/login', { username: '小明', password: 'secret123' }, { auth: false });
  assert.equal(goodLogin.status, 200);
});

test('新增待办：空白任务不添加', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user1', password: 'secret123' });

  for (const blank of ['', '   ', '\t\n ', null, undefined]) {
    const res = await h.call('POST', '/api/todos', { title: blank, date: TODAY });
    assert.equal(res.status, 400, `空白任务 [${JSON.stringify(blank)}] 应被拒绝`);
  }

  const created = await h.call('POST', '/api/todos', { title: '  写周报  ', date: TODAY });
  assert.equal(created.status, 201);
  assert.equal(created.data.todo.title, '写周报', '应自动去除首尾空白');
  assert.equal(created.data.remaining, 1);
});

test('勾选 / 删除 / 剩余计数', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user2', password: 'secret123' });

  const a = (await h.call('POST', '/api/todos', { title: '任务A', date: TODAY })).data.todo;
  await h.call('POST', '/api/todos', { title: '任务B', date: TODAY });
  const c = (await h.call('POST', '/api/todos', { title: '任务C', date: TODAY })).data.todo;

  let list = await h.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(list.data.todos.length, 3);
  assert.equal(list.data.remaining, 3);
  assert.equal(list.data.total, 3);

  // 勾选 A
  const toggled = await h.call('PATCH', `/api/todos/${a.id}`, { done: true });
  assert.equal(toggled.status, 200);
  assert.equal(toggled.data.remaining, 2);

  // 已完成的应沉到列表底部
  list = await h.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(list.data.todos.at(-1).id, a.id, '已完成项应排在最后');
  assert.equal(list.data.todos.at(-1).done, true);

  // 取消勾选
  await h.call('PATCH', `/api/todos/${a.id}`, { done: false });
  list = await h.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(list.data.remaining, 3);

  // 删除 C
  const del = await h.call('DELETE', `/api/todos/${c.id}?date=${TODAY}`);
  assert.equal(del.status, 200);
  list = await h.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(list.data.todos.length, 2);

  // 删除不存在的
  assert.equal((await h.call('DELETE', `/api/todos/nope?date=${TODAY}`)).status, 404);

  // 改标题
  const renamed = await h.call('PATCH', `/api/todos/${a.id}`, { title: '任务A改名' });
  assert.equal(renamed.data.todo.title, '任务A改名');
  assert.equal((await h.call('PATCH', `/api/todos/${a.id}`, { title: '   ' })).status, 400, '改成空白应被拒绝');
});

test('日期隔离与非法日期', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user3', password: 'secret123' });

  await h.call('POST', '/api/todos', { title: '今天的事', date: TODAY });
  await h.call('POST', '/api/todos', { title: '明天的事', date: '2030-01-01' });

  const today = await h.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(today.data.todos.length, 1);

  const other = await h.call('GET', '/api/todos?date=2030-01-01');
  assert.equal(other.data.todos.length, 1);
  assert.equal(other.data.todos[0].title, '明天的事');

  assert.equal((await h.call('GET', '/api/todos?date=2024-13-01')).status, 400);
  assert.equal((await h.call('GET', '/api/todos?date=not-a-date')).status, 400);
});

test('清除已完成 / 全选 / 顺延未完成', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user4', password: 'secret123' });

  await h.call('POST', '/api/todos', { title: '旧任务1', date: '2020-01-01' });
  await h.call('POST', '/api/todos', { title: '旧任务2', date: '2020-01-02' });
  const t1 = (await h.call('POST', '/api/todos', { title: '今日任务', date: TODAY })).data.todo;

  // 顺延：把过去所有未完成项挪到今天
  const carry = await h.call('POST', '/api/todos/batch', { action: 'carry-over', date: TODAY });
  assert.equal(carry.status, 200);
  assert.equal(carry.data.moved, 2);
  const afterCarry = await h.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(afterCarry.data.todos.length, 3);
  assert.equal((await h.call('GET', '/api/todos?date=2020-01-01')).data.todos.length, 0, '源日期应已清空');

  // 全部完成
  const all = await h.call('POST', '/api/todos/batch', { action: 'toggle-all', date: TODAY, done: true });
  assert.equal(all.data.remaining, 0);
  assert.equal(all.data.total, 3);

  // 清除已完成
  const cleared = await h.call('POST', '/api/todos/batch', { action: 'clear-completed', date: TODAY });
  assert.equal(cleared.data.removed, 3);
  assert.equal((await h.call('GET', `/api/todos?date=${TODAY}`)).data.todos.length, 0);

  // 顺延一次没有任务的情况
  const empty = await h.call('POST', '/api/todos/batch', { action: 'carry-over', date: TODAY });
  assert.equal(empty.data.moved, 0);

  // 修改已完成状态不影响
  await h.call('PATCH', `/api/todos/${t1.id}`, { done: true });
});

test('多用户数据隔离', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'alice', password: 'secret123' });
  const aliceTodo = (await h.call('POST', '/api/todos', { title: 'Alice 的秘密', date: TODAY })).data.todo;

  const aliceCookie = h.cookie;
  await h.call('POST', '/api/auth/register', { username: 'bob', password: 'secret123' }, { auth: false });

  assert.equal((await h.call('GET', `/api/todos?date=${TODAY}`)).data.todos.length, 0, 'bob 不应看到 alice 的数据');
  assert.equal((await h.call('PATCH', `/api/todos/${aliceTodo.id}`, { done: true })).status, 404, 'bob 不能改 alice 的任务');

  // 换回 alice
  h.cookie = aliceCookie;
  assert.equal((await h.call('GET', `/api/todos?date=${TODAY}`)).data.todos.length, 1);
  assert.equal((await h.call('GET', `/api/todos?date=${TODAY}`)).data.remaining, 1);
});

test('退出登录后会话失效', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user5', password: 'secret123' });
  assert.equal((await h.call('GET', '/api/auth/me')).data.user.username, 'user5');

  await h.call('POST', '/api/auth/logout');
  assert.equal((await h.call('GET', '/api/auth/me')).data.user, null);
  assert.equal((await h.call('GET', `/api/todos?date=${TODAY}`)).status, 401);
});

test('修改密码后其它会话被注销', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user6', password: 'secret123' });

  assert.equal((await h.call('POST', '/api/auth/password', { currentPassword: 'nope', newPassword: 'newsecret' })).status, 401);
  assert.equal((await h.call('POST', '/api/auth/password', { currentPassword: 'secret123', newPassword: '123' })).status, 400);

  const ok = await h.call('POST', '/api/auth/password', { currentPassword: 'secret123', newPassword: 'newsecret' });
  assert.equal(ok.status, 200);

  // 旧密码失效
  assert.equal((await h.call('POST', '/api/auth/login', { username: 'user6', password: 'secret123' }, { auth: false })).status, 401);
  assert.equal((await h.call('POST', '/api/auth/login', { username: 'user6', password: 'newsecret' }, { auth: false })).status, 200);
});

test('导出 JSON', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user7', password: 'secret123' });
  await h.call('POST', '/api/todos', { title: '导出测试', date: TODAY });

  const res = await h.call('GET', '/api/export');
  assert.equal(res.status, 200);
  const payload = JSON.parse(res.text);
  assert.equal(payload.app, 'todo-today');
  assert.equal(payload.todos.length, 1);
  assert.equal(payload.todos[0].title, '导出测试');
  assert.equal(payload.stats.remaining, 1);
});

test('导入 JSON（覆盖模式）', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user8', password: 'secret123' });
  await h.call('POST', '/api/todos', { title: '会被覆盖', date: TODAY });

  const payload = {
    app: 'todo-today',
    version: 1,
    todos: [
      { title: '导入A', done: false, date: TODAY, order: 0 },
      { title: '导入B', done: true, date: TODAY, order: 1 },
      { title: '   ', done: false, date: TODAY, order: 2 },
      { title: '坏日期', done: false, date: 'xx', order: 3 },
    ],
  };

  const res = await h.call('POST', '/api/import', { payload, mode: 'replace' });
  assert.equal(res.status, 200);
  assert.equal(res.data.result.inserted, 2, '空白标题与非法日期应被过滤');

  const list = await h.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(list.data.todos.length, 2);
  assert.equal(list.data.remaining, 1);

  // 格式错误
  assert.equal((await h.call('POST', '/api/import', { payload: { nope: 1 } })).status, 400);
});

test('合并导入时去重', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user9', password: 'secret123' });
  await h.call('POST', '/api/todos', { title: '重复项', date: TODAY });

  const payload = {
    todos: [
      { title: '重复项', done: false, date: TODAY, order: 0 },
      { title: '新项', done: false, date: TODAY, order: 1 },
    ],
  };
  const res = await h.call('POST', '/api/import', { payload, mode: 'merge' });
  assert.equal(res.data.result.inserted, 1);
  assert.equal(res.data.result.skipped, 1);
  assert.equal((await h.call('GET', `/api/todos?date=${TODAY}`)).data.todos.length, 2);
});

test('备份配置读写与脱敏', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user10', password: 'secret123' });

  const initial = await h.call('GET', '/api/backup/config');
  assert.equal(initial.status, 200);
  assert.equal(initial.data.config.provider, 'none');
  assert.equal(initial.data.config.s3.secretAccessKey, '');

  const saved = await h.call('PUT', '/api/backup/config', {
    provider: 's3',
    enabled: true,
    auto: true,
    file: 'my.json',
    s3: {
      endpoint: 'https://acc.r2.cloudflarestorage.com/',
      region: 'auto',
      bucket: 'bkt',
      accessKeyId: 'AKID',
      secretAccessKey: 'SUPERSECRET',
      prefix: '/todo/',
      pathStyle: false,
    },
  });
  assert.equal(saved.status, 200);
  assert.equal(saved.data.config.enabled, true);
  assert.equal(saved.data.config.s3.endpoint, 'https://acc.r2.cloudflarestorage.com', '应去掉末尾斜杠');
  assert.equal(saved.data.config.s3.prefix, 'todo/', '应去掉开头斜杠');
  assert.equal(saved.data.config.s3.secretAccessKey, '', '密钥绝不能回显');
  assert.equal(saved.data.config.s3.hasSecretKey, true);

  // 再次保存但密钥留空 -> 应保留原值
  const again = await h.call('PUT', '/api/backup/config', {
    provider: 's3', enabled: true, auto: true, file: 'my.json',
    s3: { endpoint: 'https://acc.r2.cloudflarestorage.com', region: 'auto', bucket: 'bkt', accessKeyId: 'AKID', secretAccessKey: '' },
  });
  assert.equal(again.data.config.s3.hasSecretKey, true, '留空应沿用旧密钥');

  const row = h.db._raw.prepare('SELECT backup_json FROM settings WHERE user_id = (SELECT id FROM users WHERE username = ?)').get('user10');
  assert.ok(JSON.parse(row.backup_json).s3.secretAccessKey === 'SUPERSECRET', '密钥应真实落库');
});

test('未配置备份时执行备份应报错', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user11', password: 'secret123' });

  assert.equal((await h.call('POST', '/api/backup/run')).status, 400);
  assert.equal((await h.call('POST', '/api/backup/test', { provider: 's3' })).status, 400);
  assert.equal((await h.call('POST', '/api/backup/restore', { mode: 'merge' })).status, 400);
});

test('S3 配置不完整时给出明确错误', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user12', password: 'secret123' });
  await h.call('PUT', '/api/backup/config', { provider: 's3', enabled: true, s3: { bucket: 'bkt' } });

  const res = await h.call('POST', '/api/backup/test', { provider: 's3', enabled: true, s3: { bucket: 'bkt' } });
  assert.equal(res.status, 400);
  assert.match(res.data.error, /endpoint/);
});

test('R2 模式下未绑定存储桶时提示清晰', async () => {
  const h = makeHarness();
  await h.call('POST', '/api/auth/register', { username: 'user13', password: 'secret123' });
  await h.call('PUT', '/api/backup/config', { provider: 'r2', enabled: true });

  const res = await h.call('POST', '/api/backup/run');
  assert.equal(res.status, 400);
  assert.match(res.data.error, /R2/);
});

test('R2 绑定可用时能完成备份与恢复', async () => {
  const h = makeHarness();

  // 假的内存 R2
  const store = new Map();
  h.env.BACKUPS = {
    async put(key, value) { store.set(key, value); },
    async get(key) { return store.has(key) ? { text: async () => store.get(key) } : null; },
    async head(key) { return store.has(key) ? { size: String(store.get(key)).length, uploaded: new Date() } : null; },
  };

  await h.call('POST', '/api/auth/register', { username: 'user14', password: 'secret123' });
  await h.call('POST', '/api/todos', { title: '备份前', date: TODAY });
  await h.call('PUT', '/api/backup/config', { provider: 'r2', enabled: true, auto: false });

  const run = await h.call('POST', '/api/backup/run');
  assert.equal(run.status, 200);
  assert.equal(run.data.result.total, 1);
  assert.ok(store.has('todo-today.backup.json'));

  // 清空后从云端恢复
  await h.call('POST', '/api/todos/batch', { action: 'clear-completed', date: TODAY });
  h.db._raw.exec('DELETE FROM todos');
  assert.equal((await h.call('GET', `/api/todos?date=${TODAY}`)).data.todos.length, 0);

  const restore = await h.call('POST', '/api/backup/restore', { mode: 'replace' });
  assert.equal(restore.status, 200);
  assert.equal(restore.data.result.inserted, 1);

  const list = await h.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(list.data.todos.length, 1);
  assert.equal(list.data.todos[0].title, '备份前');

  const test2 = await h.call('POST', '/api/backup/test', { provider: 'r2', enabled: true });
  assert.equal(test2.status, 200);
  assert.equal(test2.data.info.exists, true);
});

test('未知接口返回 404', async () => {
  const h = makeHarness();
  const res = await h.call('GET', '/api/nope');
  assert.equal(res.status, 404);
});

test('无 D1 绑定时给出可操作的错误', async () => {
  const res = await worker.fetch(new Request('https://x.com/api/todos?date=2024-01-01'), {}, { waitUntil() {} });
  assert.equal(res.status, 503);
  const body = await res.json();
  assert.match(body.error, /D1/);
});

/* ============================================================
 * 3. 静态资源路由
 * ============================================================ */

test('非 /api 请求交给静态资源绑定', async () => {
  let forwarded = null;
  const env = {
    ASSETS: { fetch: (req) => { forwarded = new URL(req.url).pathname; return new Response('html', { status: 200 }); } },
  };
  const res = await worker.fetch(new Request('https://x.com/index.html'), env, { waitUntil() {} });
  assert.equal(res.status, 200);
  assert.equal(forwarded, '/index.html');
});
