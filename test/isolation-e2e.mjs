/**
 * 多账号隔离 · 浏览器端端到端验证。
 *
 * 起一个真实的本地 Worker（D1 用 node:sqlite 模拟），打开真实页面，
 * 让两个账号在同一浏览器里先后登录，验证：
 *   1) 各自只看到自己的待办
 *   2) 切换账号后不残留上一个账号的数据（缓存 / DOM）
 *   3) 退出登录后缓存清空
 */

import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import worker from '../src/index.js';
import { createD1 } from './d1-shim.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const PORT = 8792;

/* ---------- 1. 起本地 Worker ---------- */
const db = createD1(':memory:');
db._raw.exec(readFileSync(join(ROOT, 'schema.sql'), 'utf8'));
const env = { DB: db, APP_NAME: '今日待办', ALLOW_REGISTRATION: 'true' };
const ctx = { waitUntil: () => {}, passThroughOnException() {} };

/** 极简静态资源托管：把 public/ 目录当 assets 用 */
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json',
};
function serveStatic(pathname) {
  const rel = pathname === '/' ? '/index.html' : pathname;
  const file = join(ROOT, 'public', rel);
  if (!file.startsWith(join(ROOT, 'public'))) return null;
  try {
    const buf = readFileSync(file);
    const ext = rel.slice(rel.lastIndexOf('.'));
    return new Response(buf, { headers: { 'content-type': MIME[ext] || 'application/octet-stream' } });
  } catch { return null; }
}

const server = createServer(async (req, res) => {
  const url = `http://127.0.0.1:${PORT}${req.url}`;
  const { pathname } = new URL(url);

  // 非 /api 路径直接由本地文件托管（等价于 assets 优先）
  if (!pathname.startsWith('/api/')) {
    const asset = serveStatic(pathname);
    if (asset) {
      res.writeHead(asset.status, Object.fromEntries(asset.headers));
      res.end(Buffer.from(await asset.arrayBuffer()));
      return;
    }
  }

  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = chunks.length ? Buffer.concat(chunks) : undefined;
  const request = new Request(url, {
    method: req.method,
    headers: req.headers,
    body,
    duplex: 'half',
  });
  const response = await worker.fetch(request, env, ctx);
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
});
await new Promise((r) => server.listen(PORT, '127.0.0.1', r));

/* ---------- 2. 用 HTTP 直接造两个账号的数据 ---------- */
async function apiCall(path, { method = 'GET', body, cookie } = {}) {
  const headers = {};
  if (body) headers['content-type'] = 'application/json';
  if (cookie) headers.cookie = cookie;
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
  const setCookie = res.headers.getSetCookie?.()?.[0] || res.headers.get('set-cookie');
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = null; }
  return { status: res.status, data, cookie: setCookie ? setCookie.split(';')[0] : null };
}

const today = new Date().toISOString().slice(0, 10);
const aliceReg = await apiCall('/api/auth/register', { method: 'POST', body: { username: 'alice', password: 'alice123' } });
const bobReg = await apiCall('/api/auth/register', { method: 'POST', body: { username: 'bob', password: 'bob12345' } });
await apiCall('/api/todos', { method: 'POST', body: { title: 'ALICE 的待办一', date: today }, cookie: aliceReg.cookie });
await apiCall('/api/todos', { method: 'POST', body: { title: 'ALICE 的待办二', date: today }, cookie: aliceReg.cookie });
await apiCall('/api/todos', { method: 'POST', body: { title: 'BOB 的待办一', date: today }, cookie: bobReg.cookie });
console.log('已准备：alice 2 条 / bob 1 条');

/* ---------- 3. 浏览器端验证 ---------- */
const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const CDP_PORT = 9336;
const results = [];
const check = (name, cond) => results.push([cond ? 'PASS' : 'FAIL', name]);

const chrome = spawn(CHROME, [
  '--headless=new', '--disable-gpu', `--remote-debugging-port=${CDP_PORT}`,
  '--window-size=1400,900', '--user-data-dir=C:/Users/ketto/AppData/Local/Temp/chrome-cdp-iso',
  'about:blank',
], { stdio: 'ignore' });
await sleep(2500);

const list = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json`)).json();
const page = list.find((t) => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));

let id = 0;
const pending = new Map();
const consoleErrors = [];
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  if (msg.method === 'Runtime.exceptionThrown') consoleErrors.push(msg.params?.exceptionDetails?.text);
};
const send = (method, params = {}) => new Promise((resolve) => {
  const mid = ++id; pending.set(mid, resolve);
  ws.send(JSON.stringify({ id: mid, method, params }));
});
async function evalJs(expression) {
  const res = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (res.result?.exceptionDetails) throw new Error(JSON.stringify(res.result.exceptionDetails));
  return res.result?.result?.value;
}

await send('Runtime.enable');
await send('Page.enable');
await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/` });
await sleep(1500);
await evalJs(`localStorage.clear(); 'ok'`);
await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/` });
await sleep(2000);

// 登录辅助
async function login(username, password) {
  await evalJs(`(() => {
    const u = document.getElementById('auth-username');
    const p = document.getElementById('auth-password');
    u.value = ${JSON.stringify(username)};
    p.value = ${JSON.stringify(password)};
    document.getElementById('auth-form').dispatchEvent(new Event('submit', { cancelable: true }));
    return 'ok';
  })()`);
  await sleep(1200);
}
const feedText = () => evalJs(`document.getElementById('feed').textContent`);
const userInitial = () => evalJs(`document.getElementById('user-initial').textContent`);

// Alice 登录
await login('alice', 'alice123');
const aliceFeed = await feedText();
check(`Alice 只看到自己的 2 条：${(aliceFeed.match(/ALICE/g) || []).length} 条含 ALICE，${(aliceFeed.match(/BOB/g) || []).length} 条含 BOB`,
  aliceFeed.includes('ALICE 的待办一') && aliceFeed.includes('ALICE 的待办二') && !aliceFeed.includes('BOB'));
check(`Alice 账号标识=${await userInitial()}`, (await userInitial()) === 'A');

// 直接退出登录（点击设置里的退出）
await evalJs(`document.getElementById('user-menu').click()`);
await sleep(400);
await evalJs(`document.getElementById('logout-btn').click()`);
await sleep(800);
const afterLogoutFeed = await feedText();
const authVisible = await evalJs(`!document.getElementById('auth-view').classList.contains('hidden')`);
check(`退出后回到登录页且列表已清空：feed="${afterLogoutFeed.trim()}"`, authVisible && !afterLogoutFeed.includes('ALICE'));

// Bob 登录 —— 关键：不能残留 Alice 的任何数据
await login('bob', 'bob12345');
const bobFeed = await feedText();
check(`Bob 只看到自己的 1 条：含 BOB=${bobFeed.includes('BOB 的待办一')}，含 ALICE=${bobFeed.includes('ALICE')}`,
  bobFeed.includes('BOB 的待办一') && !bobFeed.includes('ALICE'));
check(`Bob 账号标识=${await userInitial()}`, (await userInitial()) === 'B');

// Bob 的计数应为 1
const bobRemaining = await evalJs(`document.getElementById('remaining-count').textContent`);
check(`Bob 剩余计数=${bobRemaining}`, bobRemaining === '1');

// 直接切换账号（不点退出，用登录接口重登 Alice）—— 模拟换号不干净的最坏场景
await evalJs(`(async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  const r = await fetch('/api/auth/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'alice', password: 'alice123' }),
  });
  return r.status;
})()`);
await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/` });
await sleep(2000);
const afterReload = await feedText();
check(`刷新后仍为 Alice 且无 BOB 残留：含 ALICE=${afterReload.includes('ALICE')}，含 BOB=${afterReload.includes('BOB')}`,
  afterReload.includes('ALICE') && !afterReload.includes('BOB'));

console.log(results.map(([s, n]) => `${s}  ${n}`).join('\n'));
console.log(`console 错误 ${consoleErrors.length} 个`);
if (consoleErrors.length) console.log(consoleErrors.join('\n'));

ws.close();
chrome.kill();
server.close();
const failed = results.some(([s]) => s === 'FAIL') || consoleErrors.length;
process.exit(failed ? 1 : 0);
