/**
 * 跨用户越权（IDOR / 水平越权）对抗性测试。
 *
 * 与 test/isolation.mjs 的「正向隔离」不同，本文件专门模拟**攻击者视角**，
 * 尝试各种手段去读到 / 改到别人的待办。任何一项被攻破都说明存在越权漏洞。
 *
 * 攻击面清单：
 *   1. 用别人的 todo id 直接读 / 改 / 删
 *   2. 用别人的 todo id 做批量重排
 *   3. 拿别人的会话 token 行不行（token 是否可猜 / 可枚举）
 *   4. 篡改 Cookie（不存在的 / 过期的 / 空的 / 畸形值）
 *   5. 篡改请求体里的 user_id / id 字段试图越权
 *   6. 通过 month / date 参数枚举他人数据
 *   7. 通过导入接口注入别人的 todo id 试图覆盖
 *   8. 通过搜索结果反推他人内容
 *   9. 大小写 / 编码 / 路径变体绕过（URL 编码、多斜杠、尾随点）
 *  10. 他人 todo id 与 slug 混用
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

function makeEnv() {
  const db = createD1(':memory:');
  db._raw.exec(readFileSync(join(ROOT, 'schema.sql'), 'utf8'));
  const env = { DB: db, APP_NAME: '今日待办', ALLOW_REGISTRATION: 'true' };
  const ctx = { waitUntil: () => {}, passThroughOnException() {} };
  return { env, ctx, db };
}

/** 可指定任意 cookie 的原始客户端（攻击者用） */
async function raw(env, ctx, method, path, { body, cookie, headers = {} } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['content-type'] = 'application/json';
  if (cookie !== undefined) h.cookie = cookie;
  const res = await worker.fetch(
    new Request(`https://todo.example.com${path}`, {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    env,
    ctx,
  );
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = null; }
  return { status: res.status, data, text, setCookie: res.headers.get('set-cookie') };
}

/** 正常登录的客户端，自动持有自己的 cookie */
function makeClient(env, ctx) {
  let cookie = '';
  return {
    get cookie() { return cookie; },
    async call(method, path, body) {
      const r = await raw(env, ctx, method, path, { body, cookie: cookie || undefined });
      if (r.setCookie) cookie = r.setCookie.split(';')[0];
      return r;
    },
  };
}

const TODAY = new Date().toISOString().slice(0, 10);
const MONTH = TODAY.slice(0, 7);

/** 通用准备：victim 有数据，attacker 空账号 */
async function setup() {
  const { env, ctx, db } = makeEnv();
  const victim = makeClient(env, ctx);
  const attacker = makeClient(env, ctx);
  await victim.call('POST', '/api/auth/register', { username: 'victim', password: 'victim123' });
  await attacker.call('POST', '/api/auth/register', { username: 'attacker', password: 'attack123' });
  const created = await victim.call('POST', '/api/todos', {
    title: '受害者机密任务 #绝密',
    date: TODAY,
  });
  const victimTodoId = created.data.todo.id;
  // 再给 victim 若干天数据，用于枚举测试
  await victim.call('POST', '/api/todos', { title: '受害者 2 号', date: `${MONTH}-02` });
  await victim.call('POST', '/api/todos', { title: '受害者 3 号', date: `${MONTH}-03` });
  return { env, ctx, db, victim, attacker, victimTodoId };
}

test('攻击1：用他人 todo id 直接 PATCH 修改 → 必须 404 且数据不变', async () => {
  const { victim, attacker, victimTodoId } = await setup();
  const r = await attacker.call('PATCH', `/api/todos/${victimTodoId}`, { title: '被攻击者改写' });
  assert.equal(r.status, 404);

  const after = await victim.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(after.data.todos[0].title, '受害者机密任务 #绝密', '标题不能被改');
});

test('攻击2：用他人 todo id 直接 DELETE 删除 → 必须 404 且数据还在', async () => {
  const { victim, attacker, victimTodoId } = await setup();
  const r = await attacker.call('DELETE', `/api/todos/${victimTodoId}?date=${TODAY}`);
  assert.equal(r.status, 404);

  const after = await victim.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(after.data.todos.length, 1, '任务不能消失');
});

test('攻击3：勾选他人任务（done 翻转）→ 必须 404 且状态不变', async () => {
  const { victim, attacker, victimTodoId } = await setup();
  const r = await attacker.call('PATCH', `/api/todos/${victimTodoId}`, { done: true });
  assert.equal(r.status, 404);

  const after = await victim.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(after.data.todos[0].done, false, '完成状态不能被改');
});

test('攻击4：用他人 id 做批量重排 → 不能影响他人数据', async () => {
  const { victim, attacker, victimTodoId } = await setup();
  await attacker.call('POST', '/api/todos/batch', {
    action: 'reorder', date: TODAY, ids: [victimTodoId],
  });
  const after = await victim.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(after.data.todos.length, 1);
  assert.equal(after.data.todos[0].title, '受害者机密任务 #绝密');
});

test('攻击5：把他人 todo id 塞进自己的 reorder，也不能被自己读到', async () => {
  const { attacker, victimTodoId } = await setup();
  const mine = await attacker.call('POST', '/api/todos', { title: '我的任务', date: TODAY });
  const mineId = mine.data.todo.id;
  // 混合自己的和别人的 id 一起重排
  await attacker.call('POST', '/api/todos/batch', {
    action: 'reorder', date: TODAY, ids: [mineId, victimTodoId],
  });
  const list = await attacker.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(list.data.todos.length, 1, '攻击者列表里只应有自己那一条');
  assert.equal(list.data.todos[0].title, '我的任务');
});

test('攻击6：篡改 / 伪造 / 过期 Cookie 一律 401', async () => {
  const { env, ctx, attacker } = await setup();
  const badCookies = [
    '',                                        // 空
    'todo_sid=',                               // 空值
    'todo_sid=deadbeef',                       // 随机值
    'todo_sid=0000000000000000',               // 全零
    'todo_sid=../../etc/passwd',               // 路径穿越字面量
    "todo_sid=' OR '1'='1",                    // SQL 注入字符串
    'todo_sid="; DROP TABLE todos; --',        // SQL 注入字符串
    'todo_sid=%00%00%00',                      // 空字节
    'other=1',                                 // 别的 cookie 名
    'todo_sid=a; todo_sid=b',                  // 重复键
  ];
  for (const c of badCookies) {
    const r = await raw(env, ctx, 'GET', `/api/todos?date=${TODAY}`, { cookie: c });
    assert.equal(r.status, 401, `伪造 Cookie「${c}」应被拒绝`);
  }
});

test('攻击7：请求体里塞 user_id 试图越权 → 被忽略', async () => {
  const { victim, attacker } = await setup();
  // victim 的 userId
  const me = await victim.call('GET', '/api/auth/me');
  const victimId = me.data.user.id;

  // 攻击者创建任务时伪造 user_id 指向 victim
  const r = await attacker.call('POST', '/api/todos', {
    title: '注入到受害者名下',
    date: TODAY,
    user_id: victimId,
    userId: victimId,
    id: 't_injected_by_attacker',
  });
  assert.equal(r.status, 201);

  // 受害者不应该看到这条
  const vlist = await victim.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(vlist.data.todos.length, 1, '受害者只应有自己的 1 条');
  assert.ok(!vlist.data.todos.some((t) => t.title.includes('注入')), '注入的任务不能落到受害者名下');

  // 攻击者自己能看到（因为实际存在自己名下）
  const alist = await attacker.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(alist.data.todos.length, 1);
});

test('攻击8：PATCH 时伪造 user_id 转移归属 → 失败', async () => {
  const { victim, attacker, victimTodoId } = await setup();
  const me = await victim.call('GET', '/api/auth/me');
  const victimId = me.data.user.id;

  // 攻击者先建自己的任务，试图把它「送」给 victim
  const mine = await attacker.call('POST', '/api/todos', { title: '我的', date: TODAY });
  const mineId = mine.data.todo.id;
  const r = await attacker.call('PATCH', `/api/todos/${mineId}`, { user_id: victimId });
  assert.ok(r.status === 200 || r.status === 404);

  // 无论如何，victim 都不该多出记录
  const vlist = await victim.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(vlist.data.todos.length, 1);
  assert.equal(vlist.data.todos[0].title, '受害者机密任务 #绝密');

  // 攻击者也不能把 victim 的任务改到自己名下
  const r2 = await attacker.call('PATCH', `/api/todos/${victimTodoId}`, { user_id: me.data.user.id });
  assert.equal(r2.status, 404);
});

test('攻击9：枚举 date / month 参数拿不到他人数据', async () => {
  const { attacker, victim } = await setup();
  // 逐个日期试
  for (let d = 1; d <= 31; d += 1) {
    const date = `${MONTH}-${String(d).padStart(2, '0')}`;
    const r = await attacker.call('GET', `/api/todos?date=${date}`);
    assert.equal(r.data.todos.length, 0, `${date} 攻击者不该有任何数据`);
  }
  // 整月
  const m = await attacker.call('GET', `/api/todos?month=${MONTH}`);
  assert.equal(m.data.todos.length, 0, '整月视图不该返回他人数据');

  // 统计数据里也不能出现他人日期
  const s = await attacker.call('GET', '/api/todos/stats?days=365');
  assert.equal(s.data.stats.length, 0, '统计不该暴露他人数据');

  // 而受害者自己能看到 3 条
  const vm = await victim.call('GET', `/api/todos?month=${MONTH}`);
  assert.equal(vm.data.todos.length, 3);
});

test('攻击10：搜索接口不能作为读取他人数据的侧信道', async () => {
  const { attacker } = await setup();
  for (const q of ['受害者', '机密', '绝密', 'victim', '#绝密', '%', '_', '', '1']) {
    const r = await attacker.call('GET', `/api/search?q=${encodeURIComponent(q)}`);
    assert.equal(r.data.todos.length, 0, `搜索「${q}」不该返回他人数据`);
  }
});

test('攻击11：LIKE 通配符与转义注入无法绕过用户过滤', async () => {
  const { attacker } = await setup();
  // 如果转义写错，% 会匹配全部记录
  const injections = ['%', '%%', '_%', String.raw`\%`, "' OR 1=1 --", String.raw`%' OR '1'='1`];
  for (const q of injections) {
    const r = await attacker.call('GET', `/api/search?q=${encodeURIComponent(q)}`);
    assert.equal(r.data.todos.length, 0, `注入串「${q}」不该返回数据`);
    assert.equal(r.status, 200);
  }
});

test('攻击12：标签接口不泄漏他人标签', async () => {
  const { attacker } = await setup();
  const r = await attacker.call('GET', '/api/tags');
  assert.deepEqual(r.data.tags, [], '攻击者的标签列表应为空');
});

test('攻击13：导入接口无法用他人 todo id 覆盖他人数据', async () => {
  const { victim, attacker, victimTodoId } = await setup();
  // 攻击者构造一份「带受害者 id」的备份，试图 replace 模式覆盖
  const evil = {
    app: '今日待办',
    version: 1,
    user: { username: 'victim' },
    todos: [
      { id: victimTodoId, title: '被篡改的内容', done: true, date: TODAY, order: 0, createdAt: 1 },
      { title: '攻击者插入的新任务', done: false, date: TODAY, order: 1, createdAt: 2 },
    ],
  };
  const r = await attacker.call('POST', '/api/import', { payload: evil, mode: 'replace' });
  assert.equal(r.status, 200);

  // 受害者数据必须原封不动
  const vlist = await victim.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(vlist.data.todos.length, 1, '受害者的数据不能被攻击者的导入影响');
  assert.equal(vlist.data.todos[0].title, '受害者机密任务 #绝密');

  // 攻击者只拿到自己导入的那条
  const alist = await attacker.call('GET', `/api/todos?date=${TODAY}`);
  assert.equal(alist.data.todos.length, 2);
  assert.ok(!alist.data.todos.some((t) => t.id === victimTodoId), '攻击者不能持有受害者的 id');
});

test('攻击14：导出接口只吐自己的数据', async () => {
  const { attacker } = await setup();
  const r = await attacker.call('GET', '/api/export');
  const payload = JSON.parse(r.text);
  assert.equal(payload.user.username, 'attacker');
  assert.equal(payload.todos.length, 0, '攻击者导出应为空');
  assert.ok(!r.text.includes('绝密'), '导出内容不能含他人任务');
});

test('攻击15：URL 编码 / 路径变体绕过尝试', async () => {
  const { env, ctx, attacker, victimTodoId } = await setup();
  const enc = encodeURIComponent(victimTodoId);
  const variants = [
    `/api/todos/${enc}`,
    `/api/todos/${enc}%20`,
    `/api/todos//${enc}`,
    `/api/todos/${enc}/`,
    `/api/todos/${victimTodoId.toUpperCase()}`,
  ];
  for (const p of variants) {
    const r = await raw(env, ctx, 'PATCH', p, { body: { title: 'x' }, cookie: attacker.cookie });
    assert.ok(r.status === 404 || r.status === 405, `${p} 不应成功（实际 ${r.status}）`);
  }
});

test('攻击16：未登录时的所有数据接口都必须 401', async () => {
  const { env, ctx } = await setup();
  const paths = [
    ['GET', `/api/todos?date=${TODAY}`],
    ['GET', `/api/todos?month=${MONTH}`],
    ['GET', '/api/search?q=a'],
    ['GET', '/api/tags'],
    ['GET', '/api/todos/stats?days=365'],
    ['GET', '/api/export'],
    ['GET', '/api/backup/config'],
    ['POST', '/api/todos'],
    ['POST', '/api/todos/batch'],
    ['POST', '/api/import'],
    ['POST', '/api/backup/run'],
    ['POST', '/api/backup/restore'],
    ['PATCH', '/api/todos/t_whatever'],
    ['DELETE', '/api/todos/t_whatever'],
    ['POST', '/api/auth/password'],
    ['PUT', '/api/backup/config'],
  ];
  for (const [m, p] of paths) {
    const r = await raw(env, ctx, m, p, { body: m === 'GET' ? undefined : {} });
    assert.equal(r.status, 401, `${m} ${p} 必须 401（实际 ${r.status}）`);
  }
});

test('攻击17：会话 token 不可预测（非顺序 / 非时间戳）', async () => {
  const { env, ctx } = makeEnv();
  const tokens = [];
  for (const name of ['u1', 'u2', 'u3', 'u4', 'u5']) {
    const c = makeClient(env, ctx);
    const r = await c.call('POST', '/api/auth/register', { username: name, password: 'pass1234' });
    tokens.push(r.setCookie.split(';')[0]);
  }
  // 全部不同
  assert.equal(new Set(tokens).size, tokens.length, 'token 必须唯一');
  // 长度足够（≥ 32 hex = 128 bit）
  for (const t of tokens) {
    const val = t.split('=')[1];
    assert.ok(val.length >= 32, `token 长度不足：${val.length}`);
    assert.ok(/^[0-9a-f]+$/i.test(val), 'token 应为十六进制随机串');
  }
});

test('攻击18：改密后「其它设备」的旧会话必须失效，当前设备保留', async () => {
  const { env, ctx } = makeEnv();
  const deviceA = makeClient(env, ctx);   // 当前设备：执行改密
  const deviceB = makeClient(env, ctx);   // 另一台设备：被泄漏的旧会话

  await deviceA.call('POST', '/api/auth/register', { username: 'victim2', password: 'victim123' });
  // 模拟第二台设备登录（拿到独立的会话 token）
  await deviceB.call('POST', '/api/auth/login', { username: 'victim2', password: 'victim123' });
  assert.equal((await deviceB.call('GET', `/api/todos?date=${TODAY}`)).status, 200, '对照组：改密前 B 可用');

  const stolenCookie = deviceB.cookie;

  // A 设备改密
  const ch = await deviceA.call('POST', '/api/auth/password', {
    currentPassword: 'victim123', newPassword: 'victim456',
  });
  assert.equal(ch.status, 200);

  // 被泄漏的 B 会话必须立即失效（防止借旧会话越权）
  const r = await raw(env, ctx, 'GET', `/api/todos?date=${TODAY}`, { cookie: stolenCookie });
  assert.equal(r.status, 401, '改密后其它设备的旧会话必须失效');

  // 当前设备（A）按设计仍然可用
  assert.equal((await deviceA.call('GET', `/api/todos?date=${TODAY}`)).status, 200, '当前设备应保持登录');

  // 且 B 也无法用新密码自动复活（需要重新登录）
  const relogin = await deviceB.call('POST', '/api/auth/login', { username: 'victim2', password: 'victim456' });
  assert.equal(relogin.status, 200, '用新密码重新登录应成功');
});

test('攻击19：拿别人的 username 不能登录他人账号', async () => {
  const { env, ctx } = makeEnv();
  const c1 = makeClient(env, ctx);
  await c1.call('POST', '/api/auth/register', { username: 'realuser', password: 'correct123' });

  const bad = makeClient(env, ctx);
  for (const pwd of ['wrong123', 'correct124', 'Correct123', 'correct123 ', '']) {
    const r = await bad.call('POST', '/api/auth/login', { username: 'realuser', password: pwd });
    assert.ok(r.status >= 400, `错误密码「${pwd}」不该登录成功`);
  }
  const good = await bad.call('POST', '/api/auth/login', { username: 'realuser', password: 'correct123' });
  assert.equal(good.status, 200, '正确密码应能登录（对照组）');
});

test('攻击20：大范围数据下反复尝试他人 id 也不能命中', async () => {
  const { env, ctx, victim } = await setup();
  // 受害者再建 50 条，扩大 id 空间
  const ids = [];
  for (let i = 0; i < 50; i += 1) {
    const r = await victim.call('POST', '/api/todos', { title: `批量 ${i}`, date: `${MONTH}-10` });
    ids.push(r.data.todo.id);
  }
  const attacker = makeClient(env, ctx);
  await attacker.call('POST', '/api/auth/register', { username: 'attacker2', password: 'attack123' });

  // 攻击者逐个尝试所有受害者的 id
  for (const id of ids) {
    const r = await attacker.call('PATCH', `/api/todos/${id}`, { done: true });
    assert.equal(r.status, 404, `id ${id} 不应可改`);
  }
  // 受害者数据完好
  const after = await victim.call('GET', `/api/todos?date=${MONTH}-10`);
  assert.equal(after.data.todos.length, 50);
  assert.equal(after.data.todos.filter((t) => t.done).length, 0, '没有任何一条被改');
});
