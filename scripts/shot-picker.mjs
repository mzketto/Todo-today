// 截图：日期弹层打开状态（桌面 / 手机）
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = 9335;

async function shot(width, height, out) {
  const chrome = spawn(CHROME, [
    '--headless=new', '--disable-gpu', `--remote-debugging-port=${PORT}`,
    `--window-size=${width},${height}`, '--user-data-dir=C:/Users/ketto/AppData/Local/Temp/chrome-cdp-shot',
    'about:blank',
  ], { stdio: 'ignore' });
  await sleep(2500);
  const list = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
  const page = list.find((t) => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let id = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  };
  const send = (method, params = {}) => new Promise((resolve) => {
    const mid = ++id; pending.set(mid, resolve);
    ws.send(JSON.stringify({ id: mid, method, params }));
  });
  await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: width < 600 });
  await send('Page.navigate', { url: 'http://127.0.0.1:8791/index.html?demo=1' });
  await sleep(3000);
  await send('Runtime.evaluate', { expression: `localStorage.clear(); document.getElementById('date-pill').click(); 'ok'` });
  await sleep(600);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  const { writeFileSync } = await import('node:fs');
  writeFileSync(out, Buffer.from(shot.result.data, 'base64'));
  console.log('saved', out);
  ws.close();
  chrome.kill();
  await sleep(800);
}

await shot(1400, 900, 'C:/Users/ketto/WorkBuddy/2026-10-15-16-34-37/todo-today/shot-pop-desktop.png');
await shot(400, 800, 'C:/Users/ketto/WorkBuddy/2026-10-15-16-34-37/todo-today/shot-pop-mobile.png');
process.exit(0);
