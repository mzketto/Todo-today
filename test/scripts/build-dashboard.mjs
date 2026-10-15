#!/usr/bin/env node
/**
 * 打包成「单个 Worker 文件」—— 用于「不装命令行，只在 Cloudflare 网页控制台部署」。
 *
 *   node scripts/build-dashboard.mjs
 *   或  npm run build:dashboard
 *
 * 产出：dist/worker.cloudflare-dashboard.js
 *   1. 把 src/lib/*.js 按依赖顺序拼成一个文件
 *   2. 把 public/ 下的静态文件 base64 内联进去（网页端不支持 assets 配置）
 *   3. 生成与真实 import 等价的命名空间对象
 *
 * 该文件与 wrangler 部署用的是同一份源码，逻辑完全一致，只是少了一次模块拆分。
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = 'src/index.js';

/** 依赖顺序：被依赖的排在前面 */
const MODULES = [
  'src/lib/crypto.js',
  'src/lib/http.js',
  'src/lib/assets.js',
  'src/lib/auth.js',
  'src/lib/todos.js',
  'src/lib/backup.js',
];

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2',
};

const fail = (msg) => {
  console.error(`\n✗ 打包失败：${msg}\n`);
  process.exit(1);
};

const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');

/* ------------------------------------------------------------------ *
 * 1. 解析入口文件的 import，得到需要保留的命名空间
 * ------------------------------------------------------------------ */
const entrySource = read(ENTRY);

const namespaces = []; // [{ name, from }]
const resolved = new Set();

for (const line of entrySource.split('\n')) {
  const trimmed = line.trim();
  const ns = trimmed.match(/^import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"];?$/);
  if (ns) {
    namespaces.push({ name: ns[1], from: resolveFromEntry(ns[2]) });
    resolved.add(resolveFromEntry(ns[2]));
    continue;
  }
  const named = trimmed.match(/^import\s*\{[^}]*\}\s*from\s+['"]([^'"]+)['"];?$/);
  if (named) {
    resolved.add(resolveFromEntry(named[1]));
    continue;
  }
  if (/^import\b/.test(trimmed)) {
    fail(`入口文件里有无法识别的 import 写法，请改为单行写法：\n  ${trimmed}`);
  }
}

function resolveFromEntry(spec) {
  if (!spec.startsWith('.')) fail(`不支持裸模块依赖：${spec}（本项目不依赖任何 npm 包）`);
  return 'src/' + spec.replace(/^\.\//, '');
}

// 入口 import 到的模块必须在 MODULES 里，反之亦然（顺序由 MODULES 决定）
const missing = [...resolved].filter((m) => !MODULES.includes(m));
if (missing.length) fail(`这些模块没有写进 MODULES：${missing.join(', ')}`);

/* ------------------------------------------------------------------ *
 * 2. 处理每个模块：去掉 import / export 关键字，收集导出名
 * ------------------------------------------------------------------ */
const exportRe = /^export\s+(?:async\s+)?(?:function|const|let|var|class)\s+([A-Za-z_$][\w$]*)/;

function processModule(rel, { keepDefault }) {
  const source = read(rel);
  const out = [];
  const exports = [];
  let sawImport = false;

  for (const line of source.split('\n')) {
    const trimmed = line.trimStart();

    if (/^import\b/.test(trimmed)) { sawImport = true; continue; }

    if (/^export\s+default\b/.test(trimmed)) {
      out.push(keepDefault ? line : line.replace(/^(\s*)export\s+default/, '$1'));
      continue;
    }

    const m = trimmed.match(exportRe);
    if (m) {
      exports.push(m[1]);
      out.push(line.replace(/^(\s*)export\s+/, '$1'));
      continue;
    }

    if (/^export\s/.test(trimmed)) {
      fail(`${rel} 里有未支持的导出写法：${trimmed}`);
    }

    out.push(line);
  }

  if (!exports.length && !keepDefault) fail(`${rel} 没有解析到任何导出`);

  return { code: out.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd(), exports, hadImport: sawImport };
}

const processed = MODULES.map((rel) => ({ rel, ...processModule(rel, { keepDefault: false }) }));
const entry = processModule(ENTRY, { keepDefault: true });

/* ------------------------------------------------------------------ *
 * 3. 重复声明检查（拼接后同名变量会互相覆盖，必须提前发现）
 * ------------------------------------------------------------------ */
const declared = new Map(); // name -> file
const declRe = /^(?:async\s+)?(?:function|const|let|var|class)\s+([A-Za-z_$][\w$]*)/;

for (const mod of [...processed, { rel: ENTRY, code: entry.code }]) {
  for (const line of mod.code.split('\n')) {
    const m = line.match(declRe);
    if (!m) continue;
    if (declared.has(m[1])) {
      fail(`顶层标识符冲突：\`${m[1]}\` 同时出现在 ${declared.get(m[1])} 和 ${mod.rel}`);
    }
    declared.set(m[1], mod.rel);
  }
}

for (const { name } of namespaces) {
  if (declared.has(name)) fail(`命名空间 \`${name}\` 与 ${declared.get(name)} 里的同名声明冲突`);
}

/* ------------------------------------------------------------------ *
 * 4. 收集 public/ 静态资源并 base64 内联
 * ------------------------------------------------------------------ */
const PUBLIC_DIR = join(ROOT, 'public');
const assetMap = {};

for (const name of readdirSync(PUBLIC_DIR).sort()) {
  const full = join(PUBLIC_DIR, name);
  if (!statSync(full).isFile()) continue;
  if (name.startsWith('.')) continue;
  const type = MIME[extname(name).toLowerCase()] || 'application/octet-stream';
  assetMap[`/${name}`] = { type, body: readFileSync(full).toString('base64') };
}

if (!assetMap['/index.html']) fail('public/index.html 不存在，无法生成可直接访问的站点');

const assetBytes = Object.values(assetMap).reduce((sum, a) => sum + a.body.length, 0);

/* ------------------------------------------------------------------ *
 * 5. 拼装
 * ------------------------------------------------------------------ */
const banner = `/**
 * 今日待办 · 单文件版（供 Cloudflare 网页控制台直接粘贴部署）
 *
 * ⚠️ 这是自动生成的文件，请勿手动修改。
 *    源码在 src/ 与 public/，改完执行：npm run build:dashboard
 *
 * 生成时间：${new Date().toISOString()}
 * 内联静态资源：${Object.keys(assetMap).join(', ')}
 *
 * 部署要点：
 *   D1 绑定名必须是 DB
 *   R2 绑定名必须是 BACKUPS（可选，用于原生云备份）
 *   变量：APP_NAME / ALLOW_REGISTRATION
 *   密钥：BACKUP_S3_SECRET_KEY / BACKUP_WEBDAV_PASSWORD（可选）
 */`;

const parts = [banner];

for (const mod of processed) {
  parts.push(`/* ${'='.repeat(64)} *\n * ${mod.rel}\n * ${'='.repeat(64)} */`);
  parts.push(mod.code);
}

if (namespaces.length) {
  parts.push(`/* ${'='.repeat(64)} *\n * 命名空间（等价于原文件的 import * as xxx）\n * ${'='.repeat(64)} */`);
  for (const { name, from } of namespaces) {
    const mod = processed.find((m) => m.rel === from);
    if (!mod) fail(`命名空间 ${name} 指向的模块 ${from} 不在 MODULES 中`);
    const body = mod.exports.length
      ? mod.exports.map((e) => `  ${e},`).join('\n')
      : '  /* 无导出 */';
    parts.push(`const ${name} = {\n${body}\n};`);
  }
}

parts.push(`/* ${'='.repeat(64)} *\n * ${ENTRY}（入口，export default 由 Cloudflare 识别）\n * ${'='.repeat(64)} */`);
parts.push(entry.code);

let output = parts.join('\n\n') + '\n';

/* ------------------------------------------------------------------ *
 * 6. 把 assets.js 里的占位行换成真实资源表
 * ------------------------------------------------------------------ */
const MARKER = 'const INLINE_ASSETS_B64 = null;';
const markerCount = output.split(MARKER).length - 1;
if (markerCount !== 1) fail(`在 assets.js 中未找到唯一的占位行（找到 ${markerCount} 处）`);

/**
 * 逐行输出资源表。
 * base64 必须切块拼接：网页编辑器对动辄几万字符的单行支持很差，容易卡死或截断。
 */
function emitAssets(map, indent = '') {
  const lines = [`${indent}const INLINE_ASSETS_B64 = {`];
  for (const [path, entry] of Object.entries(map)) {
    lines.push(`${indent}  ${JSON.stringify(path)}: {`);
    lines.push(`${indent}    type: ${JSON.stringify(entry.type)},`);
    lines.push(`${indent}    body:`);
    const chunks = entry.body.match(/.{1,100}/g) || [''];
    chunks.forEach((chunk, i) => {
      const tail = i === chunks.length - 1 ? '' : ' +';
      lines.push(`${indent}      ${JSON.stringify(chunk)}${tail}`);
    });
    lines.push(`${indent}  },`);
  }
  lines.push(`${indent}};`);
  return lines.join('\n');
}

output = output.replace(MARKER, () => emitAssets(assetMap));
if (output.includes(MARKER)) fail('占位行替换后仍然存在，请检查脚本');
if (/^.{500,}$/m.test(output)) fail('产物中仍存在超长行，网页编辑器可能无法正常粘贴');

/* ------------------------------------------------------------------ *
 * 7. 自检 + 落盘
 * ------------------------------------------------------------------ */
for (const mod of [...processed, entry]) {
  if (/^\s*import\b/m.test(mod.code)) fail(`${mod.rel} 处理后仍残留 import 语句`);
}
if (!/^export\s+default\s/m.test(output)) fail('产物里没有 export default，Cloudflare 无法识别入口');

const OUT_DIR = join(ROOT, 'dist');
mkdirSync(OUT_DIR, { recursive: true });
const OUT_FILE = join(OUT_DIR, 'worker.cloudflare-dashboard.js');
writeFileSync(OUT_FILE, output, 'utf8');

const kb = (n) => `${(n / 1024).toFixed(1)} KB`;
console.log('✓ 已生成单文件版本');
console.log(`  产物        : dist/worker.cloudflare-dashboard.js`);
console.log(`  文件大小    : ${kb(Buffer.byteLength(output))}（其中内联资源 ${kb(assetBytes * 3 / 4)}）`);
console.log(`  合并模块    : ${MODULES.length} 个 + 入口`);
console.log(`  内联资源    : ${Object.keys(assetMap).length} 个 -> ${Object.keys(assetMap).join(', ')}`);
console.log(`  命名空间    : ${namespaces.map((n) => n.name).join(', ') || '（无）'}`);
console.log('');
console.log('  下一步：把该文件全文复制，粘贴到 Cloudflare 控制台的 Worker 在线编辑器中。');
