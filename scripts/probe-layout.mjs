// 用 Electron-as-Node 通过 CDP 探查页面布局
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = 9333;

const chrome = spawn(CHROME, [
  '--headless=new', '--disable-gpu', `--remote-debugging-port=${PORT}`,
  '--window-size=1520,900', '--user-data-dir=C:/Users/ketto/AppData/Local/Temp/chrome-cdp-probe',
  'about:blank',
], { stdio: 'ignore' });

await sleep(2500);

const list = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
const page = list.find(t => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise(r => (ws.onopen = r));

let id = 0;
const pending = new Map();
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
};
function send(method, params = {}) {
  return new Promise((resolve) => {
    const mid = ++id;
    pending.set(mid, resolve);
    ws.send(JSON.stringify({ id: mid, method, params }));
  });
}

await send('Page.enable');
await send('Page.navigate', { url: 'http://127.0.0.1:8791/index.html?demo=1' });
await sleep(4000);

const expr = `(() => {
  const pick = (sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    return { sel, x: Math.round(r.x), w: Math.round(r.width), maxW: cs.maxWidth, display: cs.display, pos: cs.position };
  };
  return JSON.stringify({
    innerWidth: innerWidth,
    shell: pick('.shell'),
    sidebar: pick('.sidebar'),
    content: pick('.content'),
    composer: pick('.composer'),
    datebar: pick('.datebar'),
    feed: pick('.feed'),
    matchMedia980: matchMedia('(min-width: 980px)').matches,
    styleSheetCount: document.styleSheets.length,
  }, null, 1);
})()`;

const res = await send('Runtime.evaluate', { expression: expr, returnByValue: true });
console.log(res.result?.result?.value || JSON.stringify(res));

ws.close();
chrome.kill();
process.exit(0);
