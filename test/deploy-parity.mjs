/**
 * 部署路径对照测试：验证「GitHub 自动构建」与「网页粘贴单文件」两条路径
 * 产出的前端运行结果完全一致（尤其是多账号数据隔离修复）。
 *
 * 差异只在【静态资源从哪来】：
 *   - GitHub 路径：wrangler.jsonc 的 assets.directory = ./public，浏览器直接拿 public/ 下的文件
 *   - 网页路径：assets 不生效，由 dist 单文件里的 INLINE_ASSETS_B64 内联返回
 *
 * 所以本测试要证明：两条路径返回的 app.js / index.html / style.css 内容一致，
 * 且都包含多账号隔离的修复代码。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

/** 解码单文件产物里的内联资源表 */
function decodeBundleAssets() {
  const src = readFileSync(join(ROOT, 'dist/worker.cloudflare-dashboard.js'), 'utf8');
  const start = src.indexOf('const INLINE_ASSETS_B64 = {');
  assert.ok(start !== -1, '单文件产物里应存在 INLINE_ASSETS_B64');
  const from = src.indexOf('{', start);
  let depth = 0;
  let end = -1;
  for (let i = from; i < src.length; i += 1) {
    const c = src[i];
    if (c === '{') depth += 1;
    else if (c === '}') { depth -= 1; if (depth === 0) { end = i; break; } }
  }
  assert.ok(end !== -1, '应能定位内联资源对象的结尾');
  // eslint-disable-next-line no-eval
  const obj = eval(`(${src.slice(from, end + 1)})`);
  return Object.fromEntries(
    Object.entries(obj).map(([p, entry]) => [
      p,
      Buffer.from(entry.body, 'base64').toString('utf8'),
    ]),
  );
}

const bundleAssets = decodeBundleAssets();

test('两条部署路径的静态资源内容一致（GitHub 版 === 网页粘贴版）', () => {
  for (const name of ['/app.js', '/index.html', '/style.css']) {
    const onDisk = readFileSync(join(ROOT, 'public', name), 'utf8');
    assert.equal(
      bundleAssets[name],
      onDisk,
      `${name}：GitHub 路径直接用 public/ 文件，单文件路径用内联副本，两者必须一致`,
    );
  }
});

test('多账号隔离修复已包含在两条路径共用的前端代码里', () => {
  const app = bundleAssets['/app.js'];
  // 关键修复点必须存在
  for (const key of ['resetUserState', 'handleSessionLost', 'syncRegistrationTab']) {
    assert.ok(app.includes(key), `app.js 应包含 ${key}`);
  }
  // 登录流程必须调用 resetUserState（这是原来缺失的那一环）
  const loginBlock = app.slice(app.indexOf('auth/${state.authMode}'), app.indexOf('resetUserState();'));
  assert.ok(loginBlock.length < 400, '登录成功后应紧接着调用 resetUserState()');
  // 退出登录也必须调用
  const logoutIdx = app.indexOf('logoutBtn.addEventListener');
  const logoutBlock = app.slice(logoutIdx, logoutIdx + 300);
  assert.ok(logoutBlock.includes('resetUserState'), '退出登录应调用 resetUserState()');
  // 旧的 401 裸分支不应再存在（已统一收口）
  assert.ok(!/if \(err\.status === 401\) \{ showAuth\(\); return; \}/.test(app),
    '401 分支应统一走 handleSessionLost()');
});

test('wrangler.jsonc 走 GitHub 路径时，静态资源确实由 public/ 目录提供', () => {
  const cfgRaw = readFileSync(join(ROOT, 'wrangler.jsonc'), 'utf8');
  const cfg = JSON.parse(cfgRaw.replace(/^\s*\/\/.*$/gm, ''));
  assert.equal(cfg.main, 'src/index.js', 'Worker 入口');
  assert.equal(cfg.assets.directory, './public', '静态资源目录');
  assert.equal(cfg.assets.binding, 'ASSETS', 'assets 绑定名');
  assert.ok(existsSync(join(ROOT, 'public', 'app.js')), 'public/app.js 必须存在并入库');
  assert.ok(existsSync(join(ROOT, 'public', 'index.html')), 'public/index.html 必须存在并入库');
  assert.ok(existsSync(join(ROOT, 'public', 'style.css')), 'public/style.css 必须存在并入库');
});

test('后端隔离逻辑在 src/ 里（两条路径共用同一个 Worker 入口）', () => {
  const index = readFileSync(join(ROOT, 'src/index.js'), 'utf8');
  // 所有 todos.* 调用都必须传 user.id
  const calls = index.match(/todos\.\w+\([^)]*\)/g) || [];
  const offenders = calls.filter((c) => !/\buser\.id\b/.test(c) && !/DATE_RE|normalize/.test(c));
  assert.equal(offenders.length, 0, `这些调用没带 user.id：\n${offenders.join('\n')}`);

  // 会话校验：只能通过 Cookie 里的 token 查 sessions 表
  const auth = readFileSync(join(ROOT, 'src/lib/auth.js'), 'utf8');
  assert.ok(auth.includes('FROM sessions s'), '会话必须查 sessions 表');
  assert.ok(auth.includes('JOIN users u ON u.id = s.user_id'), '会话与用户必须 JOIN 关联');
});

test('单文件产物与 public/ 完全同步（不会出现「修了这个没修那个」）', () => {
  const files = Object.keys(bundleAssets);
  assert.deepEqual(
    files.sort(),
    ['/app.js', '/icon.svg', '/index.html', '/manifest.webmanifest', '/style.css'].sort(),
    '内联资源清单应与 public/ 目录一致',
  );
  // 每个内联文件都必须与磁盘上的 public/ 逐字节相同
  for (const p of files) {
    const onDisk = readFileSync(join(ROOT, 'public', p), 'utf8');
    assert.equal(bundleAssets[p], onDisk, `${p} 与磁盘不一致，需要重新执行打包脚本`);
  }
});
