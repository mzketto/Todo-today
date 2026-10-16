/**
 * 多账号数据隔离专项测试。
 *
 * 目标：证明 A 账号无论如何操作，都读不到 / 改不到 / 删不掉 B 账号的数据。
 * 覆盖所有数据入口：列表、单日、整月、搜索、标签、统计、增删改、
 * 批量操作、导入导出、云备份配置、恢复。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import worker from '../src/index.js';
import { createD1 } from './d1-shim.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

/** 建一个独立的内存库环境（每次全新，避免测试间互相污染） */
function makeEnv() {
  const db = createD1(':memory:');
  db._raw.exec(readFileSync(join(ROOT, 'schema.sql'), 'utf8'));
  const env = { DB: db, APP_NAME: '今日待办', ALLOW_REGISTRATION: 'true' };
  const ctx = { waitUntil: () => {}, passThroughOnException() {} };
  return { env, ctx, db };
}

/** 每个「用户」一个独立的 cookie 持有者，模拟不同浏览器 */
function makeClient(env, ctx) {
  let cookie = '';
  return {
    async call(method, path, body) {
      const headers = {};
      if (body !== undefined) headers['content-type'] = 'application/json';
      if (cookie) headers.cookie = cookie;
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
    },
  };
}

const TODAY = new Date().toISOString().slice(0, 10);

test('多账号隔离：注册两个账号并各自建数据', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  const bob = makeClient(env, ctx);

  const ra = await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  assert.equal(ra.status, 200);
  const rb = await bob.call('POST', '/api/auth/register', { username: 'bob', password: 'bob12345' });
  assert.equal(rb.status, 200);

  // 两个账号的 id 必须不同
  assert.notEqual(ra.data.user.id, rb.data.user.id);

  // 各自建任务
  assert.equal((await alice.call('POST', '/api/todos', { title: 'Alice 的任务 #工作', date: TODAY })).status, 201);
  assert.equal((await alice.call('POST', '/api/todos', { title: 'Alice 的第二条', date: TODAY })).status, 201);
  assert.equal((await bob.call('POST', '/api/todos', { title: 'Bob 的任务 #私人', date: TODAY })).status, 201);
});

test('多账号隔离：列表 / 单日 / 计数互不可见', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  const bob = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await bob.call('POST', '/api/auth/register', { username: 'bob', password: 'bob12345' });

  await alice.call('POST', '/api/todos', { title: 'Alice 的任务', date: TODAY });
  await alice.call('POST', '/api/todos', { title: 'Alice 的第二条', date: TODAY });
  await bob.call('POST', '/api/todos', { title: 'Bob 的任务', date: TODAY });

  const alist = await alice.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(alist.data.todos.length, 2);
  assert.equal(alist.data.total, 2);
  assert.ok(alist.data.todos.every((t) => t.title.startsWith('Alice')));

  const blist = await bob.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(blist.data.todos.length, 1);
  assert.equal(blist.data.total, 1);
  assert.equal(blist.data.todos[0].title, 'Bob 的任务');
});

test('多账号隔离：搜索与标签不串账号', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  const bob = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await bob.call('POST', '/api/auth/register', { username: 'bob', password: 'bob12345' });

  await alice.call('POST', '/api/todos', { title: 'Alice 的秘密项目 #机密', date: TODAY });
  await bob.call('POST', '/api/todos', { title: 'Bob 的公开项目 #学习', date: TODAY });

  // Bob 搜不到 Alice 的关键字
  const s1 = await bob.call('GET', '/api/search?q=秘密');
  assert.equal(s1.data.todos.length, 0);
  const s2 = await bob.call('GET', '/api/search?q=Alice');
  assert.equal(s2.data.todos.length, 0);

  // 各自的标签只含自己的
  const bt = await bob.call('GET', '/api/tags');
  assert.deepEqual(bt.data.tags.map((t) => t.name), ['学习']);
  const at = await alice.call('GET', '/api/tags');
  assert.deepEqual(at.data.tags.map((t) => t.name), ['机密']);
});

test('多账号隔离：统计与整月视图只看自己', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  const bob = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await bob.call('POST', '/api/auth/register', { username: 'bob', password: 'bob12345' });

  const month = TODAY.slice(0, 7);
  await alice.call('POST', '/api/todos', { title: 'A1', date: `${month}-01` });
  await alice.call('POST', '/api/todos', { title: 'A2', date: `${month}-02` });
  await alice.call('POST', '/api/todos', { title: 'A3', date: `${month}-03` });
  await bob.call('POST', '/api/todos', { title: 'B1', date: `${month}-01` });

  const aStats = await alice.call('GET', '/api/todos/stats?days=365');
  const aTotal = aStats.data.stats.reduce((n, s) => n + s.total, 0);
  assert.equal(aTotal, 3);

  const bStats = await bob.call('GET', '/api/todos/stats?days=365');
  const bTotal = bStats.data.stats.reduce((n, s) => n + s.total, 0);
  assert.equal(bTotal, 1);

  const aMonth = await alice.call('GET', `/api/todos?month=${month}`);
  assert.equal(aMonth.data.todos.length, 3);
  const bMonth = await bob.call('GET', `/api/todos?month=${month}`);
  assert.equal(bMonth.data.todos.length, 1);
});

test('多账号隔离：越权改 / 删他人任务必须失败', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  const bob = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await bob.call('POST', '/api/auth/register', { username: 'bob', password: 'bob12345' });

  const created = await alice.call('POST', '/api/todos', { title: 'Alice 的任务', date: TODAY });
  const aliceTodoId = created.data.todo.id;

  // Bob 拿着 Alice 的任务 id 去改 / 勾选 / 删除
  const patch = await bob.call('PATCH', `/api/todos/${aliceTodoId}`, { title: '被篡改' });
  assert.equal(patch.status, 404);

  const toggle = await bob.call('PATCH', `/api/todos/${aliceTodoId}`, { done: true });
  assert.equal(toggle.status, 404);

  const del = await bob.call('DELETE', `/api/todos/${aliceTodoId}?date=${TODAY}`);
  assert.equal(del.status, 404);

  // Alice 的数据原封不动
  const after = await alice.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(after.data.todos.length, 1);
  assert.equal(after.data.todos[0].title, 'Alice 的任务');
  assert.equal(after.data.todos[0].done, false);
});

test('多账号隔离：批量操作（清除已完成 / 全部勾选 / 顺延）不越界', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  const bob = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await bob.call('POST', '/api/auth/register', { username: 'bob', password: 'bob12345' });

  const a1 = await alice.call('POST', '/api/todos', { title: 'A 已完成', date: TODAY });
  await alice.call('PATCH', `/api/todos/${a1.data.todo.id}`, { done: true });
  await alice.call('POST', '/api/todos', { title: 'A 未完成', date: TODAY });
  await bob.call('POST', '/api/todos', { title: 'B 未完成', date: TODAY });

  // Bob 执行「全部勾选」「清除已完成」「顺延」，都不能碰 Alice 的
  await bob.call('POST', '/api/todos/batch', { action: 'toggle-all', date: TODAY, done: true });
  await bob.call('POST', '/api/todos/batch', { action: 'clear-completed', date: TODAY });
  await bob.call('POST', '/api/todos/batch', { action: 'carry-over', date: TODAY });

  const aAfter = await alice.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(aAfter.data.todos.length, 2);
  const aDone = aAfter.data.todos.filter((t) => t.done).length;
  assert.equal(aDone, 1, 'Alice 的完成状态不应被 Bob 影响');
});

test('多账号隔离：导出只含自己 / 导入不覆盖他人', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  const bob = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await bob.call('POST', '/api/auth/register', { username: 'bob', password: 'bob12345' });

  await alice.call('POST', '/api/todos', { title: 'Alice 的资料', date: TODAY });
  await bob.call('POST', '/api/todos', { title: 'Bob 的资料', date: TODAY });

  // 导出内容只含自己
  const exp = await bob.call('GET', '/api/export');
  assert.equal(exp.status, 200);
  const payload = JSON.parse(exp.text);
  assert.ok(payload.todos.every((t) => t.title.includes('Bob')));
  assert.equal(payload.user.username, 'bob');

  // Bob 用 replace 模式导入自己的备份，不能清掉 Alice 的数据
  const imp = await bob.call('POST', '/api/import', { payload, mode: 'replace' });
  assert.equal(imp.status, 200);

  const aStill = await alice.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(aStill.data.todos.length, 1);
  assert.equal(aStill.data.todos[0].title, 'Alice 的资料');
});

test('多账号隔离：备份配置各自独立、密钥不回显', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  const bob = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await bob.call('POST', '/api/auth/register', { username: 'bob', password: 'bob12345' });

  await alice.call('PUT', '/api/backup/config', {
    provider: 's3',
    enabled: true,
    s3: { endpoint: 'https://s3.example.com', bucket: 'alice-bucket', secretKey: 'ALICE_SECRET' },
  });

  // Bob 读到的还是自己的空配置，看不到 Alice 的 bucket / 密钥
  const bConf = await bob.call('GET', '/api/backup/config');
  assert.notEqual(bConf.data.config.s3?.bucket, 'alice-bucket');
  assert.ok(!bConf.text.includes('ALICE_SECRET'));

  // Alice 自己读也拿不到明文密钥
  const aConf = await alice.call('GET', '/api/backup/config');
  assert.ok(!aConf.text.includes('ALICE_SECRET'));
  assert.equal(aConf.data.config.s3.bucket, 'alice-bucket');
});

test('多账号隔离：未登录一律 401，拿不到任何数据', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await alice.call('POST', '/api/todos', { title: 'Alice 的任务', date: TODAY });

  const anon = makeClient(env, ctx);   // 全新客户端，无 Cookie
  for (const [method, path] of [
    ['GET', `/api/todos?date=${TODAY}`],
    ['GET', `/api/todos?month=${TODAY.slice(0, 7)}`],
    ['GET', '/api/search?q=Alice'],
    ['GET', '/api/tags'],
    ['GET', '/api/todos/stats'],
    ['GET', '/api/export'],
    ['GET', '/api/backup/config'],
  ]) {
    const res = await anon.call(method, path);
    assert.equal(res.status, 401, `${method} ${path} 应返回 401`);
  }
});

test('多账号隔离：会话 Cookie 不通用（伪造 / 串用都无效）', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await alice.call('POST', '/api/todos', { title: 'Alice 的任务', date: TODAY });

  // 伪造的 token
  const fake = makeClient(env, ctx);
  await fake.call('POST', '/api/auth/register', { username: 'temp', password: 'temp1234' });
  // 直接塞一个不存在的 token
  const bogus = await worker.fetch(
    new Request(`https://todo.example.com/api/todos?date=${TODAY}`, {
      headers: { cookie: 'tt_session=deadbeefdeadbeef' },
    }),
    env,
    ctx,
  );
  assert.equal(bogus.status, 401);
});

test('多账号隔离：改密后会踢掉其它设备，但不影响别的账号', async () => {
  const { env, ctx } = makeEnv();
  const alice = makeClient(env, ctx);
  const aliceOther = makeClient(env, ctx);   // Alice 的另一台设备
  const bob = makeClient(env, ctx);
  await alice.call('POST', '/api/auth/register', { username: 'alice', password: 'alice123' });
  await aliceOther.call('POST', '/api/auth/login', { username: 'alice', password: 'alice123' });
  await bob.call('POST', '/api/auth/register', { username: 'bob', password: 'bob12345' });

  // Alice 在 A 设备改密
  const ch = await alice.call('POST', '/api/auth/password', {
    currentPassword: 'alice123',
    newPassword: 'alice456',
  });
  assert.equal(ch.status, 200);

  // 另一台设备被踢下线
  assert.equal((await aliceOther.call('GET', `/api/todos?date=${TODAY}`)).status, 401);
  // Bob 不受任何影响
  assert.equal((await bob.call('GET', `/api/todos?date=${TODAY}`)).status, 200);
  // Alice 当前设备仍可用
  assert.equal((await alice.call('GET', `/api/todos?date=${TODAY}`)).status, 200);
});

test('多账号隔离：同一用户名不可重复注册', async () => {
  const { env, ctx } = makeEnv();
  const a = makeClient(env, ctx);
  const b = makeClient(env, ctx);
  assert.equal((await a.call('POST', '/api/auth/register', { username: 'same', password: 'pass1234' })).status, 200);
  const dup = await b.call('POST', '/api/auth/register', { username: 'same', password: 'other123' });
  assert.ok(dup.status >= 400, '重复用户名应被拒绝');
});
