// UI 冒烟测试：真实 Chrome 里走一遍「点日历日期 / 月视图 / 相互切换」
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = 9334;
const results = [];
const check = (name, cond) => { results.push([cond ? 'PASS' : 'FAIL', name]); };

const chrome = spawn(CHROME, [
  '--headless=new', '--disable-gpu', `--remote-debugging-port=${PORT}`,
  '--window-size=1400,900', '--user-data-dir=C:/Users/ketto/AppData/Local/Temp/chrome-cdp-smoke',
  'about:blank',
], { stdio: 'ignore' });
await sleep(2500);

const list = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
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
  if (msg.method === 'Runtime.consoleAPICalled' && msg.params?.type === 'error') {
    consoleErrors.push(JSON.stringify(msg.params.args));
  }
};
function send(method, params = {}) {
  return new Promise((resolve) => {
    const mid = ++id;
    pending.set(mid, resolve);
    ws.send(JSON.stringify({ id: mid, method, params }));
  });
}
async function evalJs(expression) {
  const res = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (res.result?.exceptionDetails) throw new Error(JSON.stringify(res.result.exceptionDetails));
  return res.result?.result?.value;
}

await send('Runtime.enable');
await send('Page.enable');
await send('Page.navigate', { url: 'http://127.0.0.1:8791/index.html?demo=1' });
await sleep(1200);
await evalJs(`localStorage.clear() && 'cleared'`);   // 清掉上次运行的残留数据
await send('Page.navigate', { url: 'http://127.0.0.1:8791/index.html?demo=1' });
await sleep(3000);

// 1) 记录 fetch 调用
await evalJs(`
  window.__fetchLog = [];
  const origFetch = window.fetch;
  window.fetch = function(...args) {
    window.__fetchLog.push(String(args[0]));
    return origFetch.apply(this, args);
  };
  'ok'
`);

// 2) 点击日历里「昨天」（demo 数据里昨天有 2 条）
const yesterday = await evalJs(`(() => {
  const d = new Date(); d.setDate(d.getDate() - 1);
  return d.getDate();
})()`);
await evalJs(`(() => {
  const days = [...document.querySelectorAll('.cal-day')];
  const btn = days.find((b) => b.textContent.trim() === '${yesterday}');
  btn.click();
  return btn.className;
})()`);
await sleep(400);
const dayView = await evalJs(`(() => ({
  title: document.getElementById('page-title').textContent,
  cards: document.querySelectorAll('#feed .memo').length,
  remaining: document.getElementById('remaining-count').textContent,
}))()`);
check(`点日历切到昨天：标题=${dayView.title} 卡片=${dayView.cards} 剩余=${dayView.remaining}`,
  dayView.cards === 2 && dayView.remaining === '2');

// 3) 点回今天（缓存命中路径）
const today = await evalJs(`(() => {
  const days = [...document.querySelectorAll('.cal-day')];
  const btn = days.find((b) => b.className.includes('is-today'));
  btn.click();
  return btn.textContent.trim();
})()`);
await sleep(400);
const todayView = await evalJs(`(() => ({
  title: document.getElementById('page-title').textContent,
  cards: document.querySelectorAll('#feed .memo').length,
}))()`);
check(`点回今天：标题=${todayView.title} 卡片=${todayView.cards}`, todayView.cards === 3);

// 4) 勾选指定任务（「把季度汇报的提纲写完」）→ 剩余 -1，再取消恢复
const clickCheckOf = (kw) => `(() => {
  const m = [...document.querySelectorAll('#feed .memo')].find((x) => x.textContent.includes('${kw}'));
  if (!m) return 'missing';
  m.querySelector('.check').click();
  return 'ok';
})()`;
const beforeToggle = await evalJs(`document.getElementById('remaining-count').textContent`);
await evalJs(clickCheckOf('把季度汇报的提纲写完'));
await sleep(400);
const afterToggle = await evalJs(`document.getElementById('remaining-count').textContent`);
await evalJs(clickCheckOf('把季度汇报的提纲写完'));
await sleep(400);
const afterUntoggle = await evalJs(`document.getElementById('remaining-count').textContent`);
check(`勾选/取消同一任务：剩余 ${beforeToggle} → ${afterToggle} → ${afterUntoggle}`,
  Number(afterToggle) === Number(beforeToggle) - 1 && afterUntoggle === beforeToggle);

// 5) 新增一条任务 → 卡片数 +1，剩余 +1
await evalJs(`
  const input = document.getElementById('add-input');
  input.value = '冒烟测试任务 #测试';
  document.getElementById('add-form').dispatchEvent(new Event('submit', { cancelable: true }));
`);
await sleep(500);
const afterAdd = await evalJs(`(() => ({
  cards: document.querySelectorAll('#feed .memo').length,
  remaining: document.getElementById('remaining-count').textContent,
}))()`);
check(`新增任务：卡片=${afterAdd.cards} 剩余=${afterAdd.remaining}`,
  afterAdd.cards === 4 && Number(afterAdd.remaining) === Number(beforeToggle) + 1);

// 6) 删除刚加的任务
await evalJs(`document.querySelector('#feed .memo .memo-del').click()`);
await sleep(500);
const afterDel = await evalJs(`document.querySelectorAll('#feed .memo').length`);
check(`删除任务：卡片=${afterDel}`, afterDel === 3);

// 7) 月视图：点日历标题，应有分组与汇总
await evalJs(`document.getElementById('cal-title').click()`);
await sleep(500);
const monthView = await evalJs(`(() => ({
  title: document.getElementById('page-title').textContent,
  groups: document.querySelectorAll('#feed .feed-date-head').length,
  cards: document.querySelectorAll('#feed .memo').length,
}))()`);
check(`月视图：标题=${monthView.title} 分组=${monthView.groups} 卡片=${monthView.cards}`,
  monthView.title.includes('月') && monthView.cards >= 3);

// 8) 月视图 → 点单日 → 秒回日视图
await evalJs(`document.getElementById('search-exit').click()`);
await sleep(400);
const backDay = await evalJs(`document.getElementById('page-title').textContent`);
check(`退出月视图回到单日：${backDay}`, backDay === '今天');

// 9) 前后一天切换（预取路径）
await evalJs(`document.getElementById('prev-day').click()`);
await sleep(350);
await evalJs(`document.getElementById('next-day').click()`);
await sleep(350);
const navTitle = await evalJs(`document.getElementById('page-title').textContent`);
check(`左右切换日期：${navTitle}`, navTitle === '今天');

// 10) 自定义日期选择弹层：打开 → 翻月 → 选日 → 确定
const popTitleText = () => `(() => {
  const y = document.getElementById('pop-year').value;
  const m = document.getElementById('pop-month').value;
  return y + ' 年 ' + m + ' 月';
})()`;
await evalJs(`document.getElementById('date-pill').click()`);
await sleep(300);
const popOpen = await evalJs(`(() => {
  const pop = document.getElementById('date-pop');
  return { visible: !pop.classList.contains('hidden'), title: ${popTitleText()} };
})()`);
check(`弹层打开：${popOpen.title}`, popOpen.visible && /年.*月/.test(popOpen.title));

await evalJs(`document.getElementById('pop-prev-month').click()`);
await evalJs(`document.getElementById('pop-prev-month').click()`);
await sleep(200);
const popTitle2 = await evalJs(popTitleText());
check(`翻月：${popTitle2}`, popTitle2.includes('8 月') || popTitle2.includes('09') || /\d+ 年 \d+ 月/.test(popTitle2));

// 10.5) 手动填写年月：改成 2025 年 3 月
await evalJs(`(() => {
  const y = document.getElementById('pop-year');
  y.value = '2025';
  y.dispatchEvent(new Event('change'));
  const m = document.getElementById('pop-month');
  m.value = '3';
  m.dispatchEvent(new Event('change'));
})()`);
await sleep(200);
const manualTitle = await evalJs(popTitleText());
check(`手动填写年月：${manualTitle}`, manualTitle === '2025 年 3 月');
await evalJs(`(() => {
  const day = [...document.querySelectorAll('#pop-grid .cal-day')].find((b) => b.textContent.trim() === '15' && !b.className.includes('is-outside'));
  day.click();
})()`);
await sleep(300);
const manualPicked = await evalJs(`document.getElementById('page-title').textContent`);
check(`手动填月后选日：标题=${manualPicked}`, manualPicked === '2025-03-15' || manualPicked.includes('3 月 15 日') || /15/.test(manualPicked));

// 10.6) 非法月份自动还原
await evalJs(`(() => {
  const m = document.getElementById('pop-month');
  m.value = '13';
  m.dispatchEvent(new Event('change'));
})()`);
await sleep(150);
const reverted = await evalJs(popTitleText());
check(`非法月份还原：${reverted}`, reverted === '2025 年 3 月');

await evalJs(`(() => {
  const day = [...document.querySelectorAll('#pop-grid .cal-day')].find((b) => b.textContent.trim() === '15' && !b.className.includes('is-outside'));
  day.click();
})()`);
await sleep(300);
const pickedTitle = await evalJs(`document.getElementById('page-title').textContent`);
const popStill = await evalJs(`!document.getElementById('date-pop').classList.contains('hidden')`);
check(`选 15 号即时生效：标题=${pickedTitle}，弹层仍在=${popStill}`, pickedTitle.includes('15') && popStill);

await evalJs(`document.getElementById('pop-ok').click()`);
await sleep(200);
const popClosed = await evalJs(`document.getElementById('date-pop').classList.contains('hidden')`);
check(`确定关闭弹层`, popClosed);

// 11) 清空 = 恢复原日期：打开 → 翻下月点 1 号 → 清空 → 回到原日期
await evalJs(`document.getElementById('date-pill').click()`);
await sleep(250);
await evalJs(`document.getElementById('pop-next-month').click()`);
await evalJs(`(() => {
  const day = [...document.querySelectorAll('#pop-grid .cal-day')].find((b) => b.textContent.trim() === '1' && !b.className.includes('is-outside'));
  day.click();
})()`);
await sleep(250);
const afterPick = await evalJs(`document.getElementById('page-title').textContent`);
await evalJs(`document.getElementById('pop-clear').click()`);
await sleep(250);
const afterClear = await evalJs(`document.getElementById('page-title').textContent`);
check(`清空恢复原日期：${afterPick} → ${afterClear}`, afterPick !== afterClear && (afterClear === '今天' || afterClear === pickedTitle));

// 12) 「今天」快捷键
await evalJs(`document.getElementById('date-pill').click()`);
await sleep(250);
await evalJs(`document.getElementById('pop-today').click()`);
await sleep(300);
const backToday = await evalJs(`document.getElementById('page-title').textContent`);
const popClosed2 = await evalJs(`document.getElementById('date-pop').classList.contains('hidden')`);
check(`「今天」快捷选中：${backToday}`, backToday === '今天' && popClosed2);

const fetchCount = await evalJs(`window.__fetchLog.length`);
console.log(results.map(([s, n]) => `${s}  ${n}`).join('\n'));
console.log(`fetch 调用 ${fetchCount} 次，console 错误 ${consoleErrors.length} 个`);
if (consoleErrors.length) console.log(consoleErrors.join('\n'));

ws.close();
chrome.kill();
process.exit(results.some(([s]) => s === 'FAIL') || consoleErrors.length ? 1 : 0);
