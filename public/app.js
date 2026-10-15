/* ============================================================
 * 今日待办 · 前端逻辑（零依赖，无构建）
 *
 *  - 默认走真实后端 /api/*
 *  - 若检测到后端不可用（例如直接打开静态文件预览），自动降级为
 *    「演示模式」，用 localStorage 模拟完整后端，方便本地查看界面。
 * ============================================================ */

(() => {
  'use strict';

  const API_BASE = '/api';
  const APP_VERSION = '1.0.0';
  const URL_PARAMS = new URLSearchParams(location.search);
  /** ?demo=1 直接进入演示模式并灌入示例数据，用于无后端时预览界面 */
  const FORCE_DEMO = URL_PARAMS.get('demo') === '1';

  /* ------------------------------------------------------------------ *
   * DOM 引用
   * ------------------------------------------------------------------ */
  const $ = (id) => document.getElementById(id);

  const el = {
    boot: $('boot'),
    authView: $('auth-view'),
    mainView: $('main-view'),
    authForm: $('auth-form'),
    authUsername: $('auth-username'),
    authPassword: $('auth-password'),
    authError: $('auth-error'),
    authSubmit: $('auth-submit'),
    authSubmitLabel: $('auth-submit-label'),
    togglePassword: $('toggle-password'),
    tabs: Array.from(document.querySelectorAll('.tab')),

    pageTitle: $('page-title'),
    pageDate: $('page-date'),
    themeToggle: $('theme-toggle'),
    userMenu: $('user-menu'),
    userInitial: $('user-initial'),
    demoBanner: $('demo-banner'),
    demoBannerClose: $('demo-banner-close'),

    prevDay: $('prev-day'),
    nextDay: $('next-day'),
    datePill: $('date-pill'),
    datePillText: $('date-pill-text'),
    dateInput: $('date-input'),

    addForm: $('add-form'),
    addInput: $('add-input'),
    addHint: $('add-hint'),
    composerDate: $('composer-date'),
    composerDateText: $('composer-date-text'),
    composerDateInput: $('composer-date-input'),

    // 侧栏
    sidebar: $('sidebar'),
    sideMask: $('side-mask'),
    sideToggle: $('side-toggle'),
    searchInput: $('search-input'),
    searchClear: $('search-clear'),
    statDays: $('stat-days'),
    statTotal: $('stat-total'),
    statDone: $('stat-done'),
    calTitle: $('cal-title'),
    calPrev: $('cal-prev'),
    calNext: $('cal-next'),
    calendar: $('calendar'),
    tagsBlock: $('tags-block'),
    tagsList: $('tags-list'),
    timelineBlock: $('timeline-block'),
    timelineList: $('timeline-list'),

    // 卡片流
    feed: $('feed'),
    searchBanner: $('search-banner'),
    searchBannerText: $('search-banner-text'),
    searchExit: $('search-exit'),
    emptyState: $('empty-state'),
    emptyTitle: $('empty-title'),
    emptySub: $('empty-sub'),
    remainingCount: $('remaining-count'),
    remainingLabel: $('remaining-label'),
    carryoverBtn: $('carryover-btn'),
    clearDoneBtn: $('clear-done-btn'),

    drawerMask: $('drawer-mask'),
    drawerClose: $('drawer-close'),
    accountName: $('account-name'),
    logoutBtn: $('logout-btn'),

    pwdCurrent: $('pwd-current'),
    pwdNew: $('pwd-new'),
    pwdSubmit: $('pwd-submit'),

    backupProvider: $('backup-provider'),
    backupEnabled: $('backup-enabled'),
    backupAuto: $('backup-auto'),
    backupPanels: Array.from(document.querySelectorAll('.provider-panel')),
    r2Key: $('r2-key'),
    s3Endpoint: $('s3-endpoint'),
    s3Region: $('s3-region'),
    s3Bucket: $('s3-bucket'),
    s3Akid: $('s3-akid'),
    s3Secret: $('s3-secret'),
    s3Prefix: $('s3-prefix'),
    s3File: $('s3-file'),
    s3PathStyle: $('s3-pathstyle'),
    davUrl: $('dav-url'),
    davUser: $('dav-user'),
    davPass: $('dav-pass'),
    davFile: $('dav-file'),
    backupTest: $('backup-test'),
    backupSave: $('backup-save'),
    backupRun: $('backup-run'),
    backupRestore: $('backup-restore'),
    backupStatus: $('backup-status'),
    backupStamp: $('backup-stamp'),
    backupStampHint: $('backup-stamp-hint'),
    backupInterval: $('backup-interval'),
    backupIntervalField: $('backup-interval-field'),
    backupIntervalHint: $('backup-interval-hint'),
    backupScheduled: $('backup-scheduled'),
    backupPeriod: $('backup-period'),
    backupPeriodField: $('backup-period-field'),
    backupCronHint: $('backup-cron-hint'),
    lastBackupLine: $('last-backup-line'),

    exportBtn: $('export-btn'),
    importBtn: $('import-btn'),
    importFile: $('import-file'),
    aboutVersion: $('about-version'),

    toastHost: $('toast-host'),
  };

  /* ------------------------------------------------------------------ *
   * 应用状态
   * ------------------------------------------------------------------ */
  const state = {
    user: null,
    date: todayStr(),
    todos: [],
    remaining: 0,
    total: 0,
    // 月视图：非空时卡片流展示整月任务
    month: null,
    monthTodos: [],
    authMode: 'login',
    demo: false,
    apiConfirmed: false,
    busy: false,
    // 侧栏
    stats: [],            // [{ date, remaining, total }] 按日期倒序
    tags: [],             // [{ name, count }]
    cal: (() => { const d = new Date(); return { y: d.getFullYear(), m: d.getMonth() }; })(),
    search: { q: '', active: false, loading: false, results: [] },
    cron: null,           // 定时任务（Cron）心跳状态
  };

  const TAG_RE = /#([^\s#]{1,24})/g;

  /* ------------------------------------------------------------------ *
   * 客户端缓存：点击日期/月份先秒开缓存，再后台校新，并预取相邻日期
   * （stale-while-revalidate，消除「点一下等一下」的网络往返感）
   * ------------------------------------------------------------------ */
  const dayCache = new Map();      // date -> { todos, remaining, total }
  const monthCache = new Map();    // month -> todos[]
  const prefetching = new Set();   // 正在预取的日期，防重复请求
  const DAY_CACHE_MAX = 90;
  const MONTH_CACHE_MAX = 24;

  function cacheSetDay(date, todos, remaining, total) {
    if (dayCache.size >= DAY_CACHE_MAX) dayCache.delete(dayCache.keys().next().value);
    dayCache.set(date, { todos, remaining, total });
  }

  function cacheClearAll() {
    dayCache.clear();
    monthCache.clear();
    prefetching.clear();
  }

  function prefetchDay(date) {
    if (dayCache.has(date) || prefetching.has(date)) return;
    prefetching.add(date);
    api(`/todos?date=${encodeURIComponent(date)}`)
      .then((d) => {
        const todos = d.todos || [];
        cacheSetDay(date, todos, d.remaining ?? todos.filter((t) => !t.done).length, d.total ?? todos.length);
      })
      .catch(() => { /* 预取失败静默忽略 */ })
      .finally(() => prefetching.delete(date));
  }

  /** 写操作成功后，把当前单日视图状态同步回缓存 */
  function syncDayCache() {
    if (state.month || state.search.active) return;
    cacheSetDay(state.date, state.todos, state.remaining, state.total);
  }

  /* ------------------------------------------------------------------ *
   * 工具函数
   * ------------------------------------------------------------------ */
  function pad(n) { return String(n).padStart(2, '0'); }

  function todayStr() {
    const d = new Date();
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  }

  function shiftDate(dateStr, delta) {
    const [y, m, d] = dateStr.split('-').map(Number);
    const dt = new Date(y, m - 1, d);
    dt.setDate(dt.getDate() + delta);
    return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}`;
  }

  /** 月份平移：'2025-10' + (-1) → '2025-09' */
  function shiftMonthStr(monthStr, delta) {
    const [y, m] = monthStr.split('-').map(Number);
    const zero = y * 12 + (m - 1) + delta;
    return `${Math.floor(zero / 12)}-${pad((zero % 12) + 1)}`;
  }

  const WEEKDAYS = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];

  function humanDate(dateStr) {
    const today = todayStr();
    if (dateStr === today) return { title: '今天', sub: `${dateStr} · ${WEEKDAYS[weekdayOf(dateStr)]}` };
    if (dateStr === shiftDate(today, -1)) return { title: '昨天', sub: `${dateStr} · ${WEEKDAYS[weekdayOf(dateStr)]}` };
    if (dateStr === shiftDate(today, 1)) return { title: '明天', sub: `${dateStr} · ${WEEKDAYS[weekdayOf(dateStr)]}` };
    const [y, m, d] = dateStr.split('-').map(Number);
    return { title: `${m} 月 ${d} 日`, sub: `${y}-${pad(m)}-${pad(d)} · ${WEEKDAYS[weekdayOf(dateStr)]}` };
  }

  function weekdayOf(dateStr) {
    const [y, m, d] = dateStr.split('-').map(Number);
    return new Date(y, m - 1, d).getDay();
  }

  function toast(message, kind = '', duration = 2400) {
    const text = String(message ?? '');
    const long = text.length > 56;   // 长文案改用卡片样式并多停留一会儿
    const node = document.createElement('div');
    node.className = `toast ${kind}${long ? ' long' : ''}`;
    node.textContent = text;
    el.toastHost.appendChild(node);
    setTimeout(() => {
      node.classList.add('leaving');
      setTimeout(() => node.remove(), 240);
    }, long ? Math.max(duration, 7000) : duration);
  }

  function setStatus(node, text, kind = 'busy') {
    if (!text) { node.hidden = true; node.textContent = ''; return; }
    node.hidden = false;
    node.className = `status-line ${kind}`;
    node.textContent = text;
  }

  /** iframe 里 window.confirm 可能被拦截，改用「再点一次确认」 */
  function armedClick(button, label, action) {
    if (button.dataset.armed === '1') {
      delete button.dataset.armed;
      button.textContent = button.dataset.original || label;
      return action();
    }
    button.dataset.original = button.dataset.original || button.textContent;
    button.dataset.armed = '1';
    button.textContent = label;
    setTimeout(() => {
      if (button.dataset.armed === '1') {
        delete button.dataset.armed;
        button.textContent = button.dataset.original;
      }
    }, 3200);
    return undefined;
  }

  /* ------------------------------------------------------------------ *
   * 演示模式：用 localStorage 模拟后端
   * ------------------------------------------------------------------ */
  const DEMO_KEY = 'todo-today:demo:v1';

  function demoRead() {
    try {
      const raw = localStorage.getItem(DEMO_KEY);
      if (raw) return JSON.parse(raw);
    } catch { /* ignore */ }
    return { user: null, todos: [], backup: null };
  }

  function demoWrite(data) {
    try { localStorage.setItem(DEMO_KEY, JSON.stringify(data)); } catch { /* ignore */ }
  }

  function demoId() {
    return `d_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  }

  function demoCount(todos, date) {
    const list = todos.filter((t) => t.date === date);
    return { remaining: list.filter((t) => !t.done).length, total: list.length };
  }

  function demoList(todos, date) {
    return todos
      .filter((t) => t.date === date)
      .sort((a, b) => Number(a.done) - Number(b.done) || a.order - b.order || a.createdAt - b.createdAt);
  }

  function demoApi(path, { method = 'GET', body } = {}) {
    const db = demoRead();
    const [rawPath, query] = path.split('?');
    const params = new URLSearchParams(query || '');
    const seg = rawPath.split('/').filter(Boolean); // ['auth','me'] etc.
    const jsonRes = (data, status = 200) => ({ ...data, __status: status });

    /* --- auth --- */
    if (seg[0] === 'auth') {
      if (seg[1] === 'me') return { ok: true, user: db.user };
      if (seg[1] === 'login' || seg[1] === 'register') {
        const name = String(body?.username || '').trim();
        const pass = String(body?.password || '');
        if (name.length < 2) throw new ApiError('用户名至少 2 位');
        if (pass.length < 6) throw new ApiError('密码至少 6 位');
        db.user = { id: 'demo-user', username: name, createdAt: Math.floor(Date.now() / 1000) };
        demoWrite(db);
        return { ok: true, user: db.user };
      }
      if (seg[1] === 'logout') {
        db.user = null;
        demoWrite(db);
        return { ok: true };
      }
      if (seg[1] === 'password') return { ok: true, message: '演示模式下不会真的改密码' };
    }

    if (!db.user) throw new ApiError('请先登录', 401);

    /* --- 搜索 / 标签 --- */
    if (seg[0] === 'search' && method === 'GET') {
      const q = (params.get('q') || '').trim().toLowerCase();
      const list = db.todos
        .filter((t) => t.title.toLowerCase().includes(q))
        .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : b.createdAt - a.createdAt))
        .slice(0, 50);
      return { ok: true, q, todos: list };
    }

    if (seg[0] === 'tags' && method === 'GET') {
      const counter = new Map();
      db.todos.forEach((t) => {
        const tags = String(t.title || '').match(/#([^\s#]{1,24})/g) || [];
        tags.forEach((raw) => {
          const name = raw.slice(1);
          counter.set(name, (counter.get(name) || 0) + 1);
        });
      });
      const tags = Array.from(counter, ([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'zh-Hans-CN'))
        .slice(0, 30);
      return { ok: true, tags };
    }

    /* --- todos --- */
    if (seg[0] === 'todos') {
      const date = params.get('date') || state.date;

      // 整月视图
      const month = params.get('month');
      if (!seg[1] && method === 'GET' && month) {
        if (!/^\d{4}-(?:0[1-9]|1[0-2])$/.test(month)) throw new ApiError('月份格式不正确，应为 YYYY-MM');
        const list = db.todos
          .filter((t) => t.date.startsWith(`${month}-`))
          .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : Number(a.done) - Number(b.done) || a.order - b.order));
        return { ok: true, month, todos: list, remaining: list.filter((t) => !t.done).length, total: list.length };
      }

      if (!seg[1] && method === 'GET') {
        return { ok: true, date, todos: demoList(db.todos, date), ...demoCount(db.todos, date) };
      }

      if (!seg[1] && method === 'POST') {
        const title = String(body?.title || '').replace(/\s+/g, ' ').trim();
        if (!title) throw new ApiError('任务内容不能为空');
        const day = body?.date || date;
        const minOrder = Math.min(0, ...db.todos.filter((t) => t.date === day).map((t) => t.order));
        const todo = {
          id: demoId(), title, done: false, date: day,
          order: minOrder - 1, createdAt: Math.floor(Date.now() / 1000),
        };
        db.todos.push(todo);
        demoWrite(db);
        return { ok: true, todo, ...demoCount(db.todos, day), __status: 201 };
      }

      if (seg[1] === 'batch' && method === 'POST') {
        const day = body?.date || date;
        if (body?.action === 'clear-completed') {
          const before = db.todos.length;
          if (body?.month) {
            if (!/^\d{4}-(?:0[1-9]|1[0-2])$/.test(body.month)) throw new ApiError('月份格式不正确，应为 YYYY-MM');
            db.todos = db.todos.filter((t) => !(t.date.startsWith(`${body.month}-`) && t.done));
          } else {
            db.todos = db.todos.filter((t) => !(t.date === day && t.done));
          }
          demoWrite(db);
          return { ok: true, removed: before - db.todos.length, ...demoCount(db.todos, day) };
        }
        if (body?.action === 'toggle-all') {
          db.todos.forEach((t) => { if (t.date === day) t.done = !!body.done; });
          demoWrite(db);
          return { ok: true, ...demoCount(db.todos, day) };
        }
        if (body?.action === 'carry-over') {
          let moved = 0;
          const pending = body?.from
            ? db.todos.filter((t) => t.date === body.from && !t.done)
            : db.todos.filter((t) => t.date < day && !t.done);
          let order = Math.min(0, ...db.todos.filter((t) => t.date === day).map((t) => t.order)) - 1;
          pending.forEach((t) => { t.date = day; t.order = order--; moved += 1; });
          demoWrite(db);
          return { ok: true, moved, todos: demoList(db.todos, day), ...demoCount(db.todos, day) };
        }
        return { ok: true };
      }

      if (seg[1] === 'stats') {
        const map = new Map();
        db.todos.forEach((t) => {
          const cur = map.get(t.date) || { date: t.date, remaining: 0, total: 0 };
          cur.total += 1;
          if (!t.done) cur.remaining += 1;
          map.set(t.date, cur);
        });
        return { ok: true, stats: Array.from(map.values()).sort((a, b) => (a.date < b.date ? 1 : -1)) };
      }

      const id = seg[1];
      const index = db.todos.findIndex((t) => t.id === id);
      if (index === -1) throw new ApiError('任务不存在', 404);

      if (method === 'PATCH') {
        const t = db.todos[index];
        if ('title' in (body || {})) {
          const title = String(body.title).replace(/\s+/g, ' ').trim();
          if (!title) throw new ApiError('任务内容不能为空');
          t.title = title;
        }
        if ('done' in (body || {})) t.done = !!body.done;
        if ('date' in (body || {})) t.date = body.date;
        demoWrite(db);
        return { ok: true, todo: t, ...demoCount(db.todos, t.date) };
      }

      if (method === 'DELETE') {
        const [removed] = db.todos.splice(index, 1);
        demoWrite(db);
        return { ok: true, id: removed.id, ...demoCount(db.todos, removed.date) };
      }
    }

    /* --- backup --- */
    if (seg[0] === 'backup') {
      if (seg[1] === 'config' && method === 'GET') {
        return {
          ok: true,
          config: db.backup || {
            provider: 'none', enabled: false, auto: false, stamp: true,
            intervalMin: 1, scheduled: false, scheduleMin: 60, tz: '',
            file: 'todo-today.backup.json',
            hasR2Binding: false,
            s3: { endpoint: '', region: 'auto', bucket: '', accessKeyId: '', hasSecretKey: false, prefix: '', pathStyle: false },
            webdav: { url: '', username: '', hasPassword: false, file: '' },
          },
          lastBackup: null,
          cron: { lastRun: null, healthy: false, intervalSeconds: 300 },
        };
      }
      if (seg[1] === 'config' && method === 'PUT') {
        db.backup = { ...body, hasR2Binding: false };
        demoWrite(db);
        return { ok: true, config: db.backup };
      }
      if (seg[1] === 'test') return { ok: true, message: '演示模式：未真正连接云存储' };
      if (seg[1] === 'run') return { ok: true, message: '演示模式：未真正上传' };
      if (seg[1] === 'restore') return { ok: true, message: '演示模式：未真正下载' };
    }

    throw new ApiError(`演示模式暂不支持：${method} ${path}`, 404);
  }

  class ApiError extends Error {
    constructor(message, status = 400) { super(message); this.status = status; }
  }

  /* ------------------------------------------------------------------ *
   * 请求封装：真实后端优先，必要时降级演示模式
   * ------------------------------------------------------------------ */
  async function api(path, { method = 'GET', body } = {}) {
    if (state.demo) return demoApi(path, { method, body });

    let res;
    try {
      res = await fetch(API_BASE + path, {
        method,
        credentials: 'same-origin',
        headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (networkError) {
      if (!state.apiConfirmed) return fallbackToDemo(path, method, body);
      throw new Error('网络异常，请检查连接后重试');
    }

    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      // 静态托管 / 后端未部署 —— 自动进入演示模式
      if (!state.apiConfirmed) return fallbackToDemo(path, method, body);
      throw new Error(`服务返回了非预期内容 (${res.status})`);
    }

    state.apiConfirmed = true;
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) {
      throw new ApiError(data.error || `请求失败 (${res.status})`, res.status);
    }
    return data;
  }

  function fallbackToDemo(path, method, body) {
    enableDemoMode();
    return demoApi(path, { method, body });
  }

  function enableDemoMode() {
    if (state.demo) return;
    state.demo = true;
    el.demoBanner.classList.remove('hidden');
    el.aboutVersion.textContent = `前端 v${APP_VERSION} · 演示模式`;
    toast('未检测到后端服务，已切换到演示模式', '', 3200);
  }

  /** 演示用的示例数据，仅在 ?demo=1 首次进入时灌一次 */
  function seedDemoData() {
    const db = demoRead();
    if (db.user) return;
    const today = todayStr();
    const day = (delta) => shiftDate(today, delta);
    // [标题, 是否完成, 日期偏移]
    const samples = [
      ['把季度汇报的提纲写完 #工作', false, 0],
      ['回复客户的邮件 #工作', true, 0],
      ['预约周五的体检 #生活', false, 0],
      ['晚上 8 点去健身房 #生活', false, -1],
      ['读完《卡片笔记写作法》第三章 #阅读', false, -1],
      ['给阳台的绿萝浇水 #生活', true, -2],
      ['整理下一步的旅行清单 #生活', false, -4],
      ['review 同事的方案文档 #工作', true, -5],
    ];
    db.user = { id: 'demo-user', username: 'demo', createdAt: Math.floor(Date.now() / 1000) };
    db.todos = samples.map(([title, done, delta], i) => ({
      id: demoId(),
      title,
      done,
      date: day(delta),
      order: i,
      createdAt: Math.floor(Date.now() / 1000) + i,
    }));
    demoWrite(db);
  }

  /* ------------------------------------------------------------------ *
   * 视图切换
   * ------------------------------------------------------------------ */
  function showAuth() {
    el.boot.classList.add('hidden');
    el.authView.classList.remove('hidden');
    el.mainView.classList.add('hidden');
    el.authUsername.focus({ preventScroll: true });
  }

  async function showMain() {
    el.boot.classList.add('hidden');
    el.authView.classList.add('hidden');
    el.mainView.classList.remove('hidden');
    el.userInitial.textContent = (state.user?.username || 'U').slice(0, 1).toUpperCase();
    el.accountName.textContent = state.user?.username || '-';
    await refresh();          // 主列表优先渲染
    loadSidebarData();        // 侧栏与备份配置并行加载，不阻塞首屏
    loadBackupConfig();
    el.addInput.focus({ preventScroll: true });
    // ?panel=settings 用于直接打开设置抽屉（演示/截图用）
    if (URL_PARAMS.get('panel') === 'settings') openDrawer();
    // ?panel=sidebar 用于直接展开移动端侧栏（截图用）
    if (URL_PARAMS.get('panel') === 'sidebar') openSidebar();
    // ?q=xxx 直接进入搜索状态（演示/截图用）
    const q = URL_PARAMS.get('q');
    if (q) startSearch(q);
    // ?month=YYYY-MM 直接进入整月视图（演示/截图用）
    const mv = URL_PARAMS.get('month');
    if (mv && /^\d{4}-\d{2}$/.test(mv)) openMonth(mv);
  }

  /* ------------------------------------------------------------------ *
   * 认证
   * ------------------------------------------------------------------ */
  function setAuthMode(mode) {
    state.authMode = mode;
    el.tabs.forEach((t) => t.classList.toggle('active', t.dataset.mode === mode));
    el.authSubmitLabel.textContent = mode === 'login' ? '登录' : '创建账号';
    el.authPassword.setAttribute('autocomplete', mode === 'login' ? 'current-password' : 'new-password');
    el.authError.hidden = true;
    el.authPassword.value = '';
  }

  function showAuthError(message) {
    el.authError.textContent = message;
    el.authError.hidden = false;
  }

  el.tabs.forEach((tab) => tab.addEventListener('click', () => setAuthMode(tab.dataset.mode)));

  el.togglePassword.addEventListener('click', () => {
    const isPassword = el.authPassword.type === 'password';
    el.authPassword.type = isPassword ? 'text' : 'password';
    el.togglePassword.textContent = isPassword ? '🙈' : '👁';
  });

  el.authForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = el.authUsername.value.trim();
    const password = el.authPassword.value;

    if (!username) return showAuthError('请输入用户名');
    if (password.length < 6) return showAuthError('密码至少 6 位');

    el.authSubmit.disabled = true;
    el.authSubmitLabel.textContent = state.authMode === 'login' ? '登录中…' : '创建中…';
    el.authError.hidden = true;

    try {
      const data = await api(`/auth/${state.authMode}`, { method: 'POST', body: { username, password } });
      state.user = data.user;
      el.authPassword.value = '';
      await showMain();
    } catch (err) {
      showAuthError(err.message || '操作失败');
    } finally {
      el.authSubmit.disabled = false;
      el.authSubmitLabel.textContent = state.authMode === 'login' ? '登录' : '创建账号';
    }
  });

  el.logoutBtn.addEventListener('click', async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
    state.user = null;
    state.todos = [];
    cacheClearAll();
    closeDrawer();
    showAuth();
    toast('已退出登录');
  });

  el.pwdSubmit.addEventListener('click', async () => {
    const currentPassword = el.pwdCurrent.value;
    const newPassword = el.pwdNew.value;
    if (newPassword.length < 6) return toast('新密码至少 6 位', 'err');
    try {
      const data = await api('/auth/password', { method: 'POST', body: { currentPassword, newPassword } });
      toast(data.message || '密码已更新', 'ok');
      el.pwdCurrent.value = '';
      el.pwdNew.value = '';
    } catch (err) {
      toast(err.message, 'err');
    }
  });

  /* ------------------------------------------------------------------ *
   * 日期
   * ------------------------------------------------------------------ */
  function renderDate() {
    const { title, sub } = humanDate(state.date);
    el.pageTitle.textContent = title;
    el.pageDate.textContent = sub;
    el.datePillText.textContent = `${state.date} ${WEEKDAYS[weekdayOf(state.date)]}`;
    el.dateInput.value = state.date;
    el.composerDateText.textContent = title === '今天' ? '今天' : `${state.date.slice(5)} ${WEEKDAYS[weekdayOf(state.date)]}`;
    el.composerDateInput.value = state.date;
    const isToday = state.date === todayStr();
    el.carryoverBtn.style.visibility = isToday ? 'visible' : 'hidden';
    // 日历视图跟随所选日期
    const [y, m] = state.date.split('-').map(Number);
    if (state.cal.y !== y || state.cal.m !== m - 1) {
      state.cal = { y, m: m - 1 };
      renderCalendar();
    } else {
      renderCalendar();   // 重新标亮选中日
    }
  }

  el.prevDay.addEventListener('click', () => {
    if (state.month) { openMonth(shiftMonthStr(state.month, -1), { closeSide: false }); return; }
    gotoDate(shiftDate(state.date, -1));
  });
  el.nextDay.addEventListener('click', () => {
    if (state.month) { openMonth(shiftMonthStr(state.month, 1), { closeSide: false }); return; }
    gotoDate(shiftDate(state.date, 1));
  });
  el.dateInput.addEventListener('change', () => {
    if (/^\d{4}-\d{2}-\d{2}$/.test(el.dateInput.value)) gotoDate(el.dateInput.value);
  });
  el.composerDateInput.addEventListener('change', () => {
    if (/^\d{4}-\d{2}-\d{2}$/.test(el.composerDateInput.value)) gotoDate(el.composerDateInput.value);
  });

  async function gotoDate(date) {
    if (state.search.active || el.searchInput.value) exitSearch();
    state.month = null;
    state.date = date;
    renderDate();
    closeSidebar();
    await refresh();
  }

  /* ------------------------------ 月视图 ------------------------------ */

  /** 进入整月视图：展示该月所有任务，按日期倒序分组 */
  async function openMonth(month, { closeSide = true } = {}) {
    if (state.search.active || el.searchInput.value) exitSearch();
    state.month = month;

    // 同步日历与「当前日期」上下文（composer 归属日期落在该月内）
    const [y, m] = month.split('-').map(Number);
    state.cal = { y, m: m - 1 };
    if (!state.date.startsWith(`${month}-`)) {
      state.date = state.stats.find((s) => s.date.startsWith(`${month}-`))?.date || `${month}-01`;
    }

    renderMonthHeader();
    renderCalendar();
    closeSide && closeSidebar();
    await refreshMonth();
  }

  function exitMonth() {
    state.month = null;
    renderDate();
    renderList();
    el.addInput.focus({ preventScroll: true });
  }

  /** 月视图的顶部标题与日期条 */
  function renderMonthHeader() {
    const [y, m] = state.month.split('-').map(Number);
    el.pageTitle.textContent = `${y} 年 ${m} 月`;
    el.pageDate.textContent = '整月视图 · 按日期倒序';
    el.datePillText.textContent = `${state.month} 全月`;
    // composer 归属日期保持在当月，新添加的任务会落进当前查看的月份
    el.composerDateText.textContent = `${state.date.slice(5)} ${WEEKDAYS[weekdayOf(state.date)]}`;
    el.composerDateInput.value = state.date;
    el.carryoverBtn.style.visibility = 'hidden';
  }

  /** 应用整月数据到视图（refreshMonth 专用） */
  function applyMonthData(month, todos) {
    if (state.month !== month) return;   // 用户已切走
    state.monthTodos = todos;
    const undone = todos.filter((t) => !t.done).length;
    state.remaining = undone;
    state.total = todos.length;
    el.remainingCount.textContent = String(undone);
    el.remainingLabel.textContent = undone === 0
      ? (todos.length ? '本月全部完成 🎉' : '项待完成')
      : '项待完成';
    el.clearDoneBtn.disabled = !todos.some((t) => t.done);
    renderList();
  }

  async function refreshMonth() {
    const month = state.month;
    if (!month) return;

    // 1) 有缓存：立即渲染
    const cached = monthCache.get(month);
    if (cached && state.month === month) applyMonthData(month, cached);

    // 2) 后台校新（数据没变就不重绘）
    try {
      const data = await api(`/todos?month=${encodeURIComponent(month)}`);
      if (state.month !== month) return;   // 用户已切走
      const todos = data.todos || [];
      const unchanged = cached && JSON.stringify(cached) === JSON.stringify(todos);
      if (unchanged) return;
      if (monthCache.size >= MONTH_CACHE_MAX) monthCache.delete(monthCache.keys().next().value);
      monthCache.set(month, todos);
      applyMonthData(month, todos);

      // 3) 整月数据顺手灌进单日缓存：点该月任何一天都秒开
      const byDate = new Map();
      for (const t of todos) {
        if (!byDate.has(t.date)) byDate.set(t.date, []);
        byDate.get(t.date).push(t);
      }
      for (const [d, list] of byDate) {
        if (!dayCache.has(d)) {
          cacheSetDay(d, list, list.filter((t) => !t.done).length, list.length);
        }
      }
    } catch (err) {
      if (err.status === 401) { state.user = null; showAuth(); return; }
      if (!cached) toast(err.message, 'err');
    }
  }

  /* ------------------------------------------------------------------ *
   * 卡片流渲染
   * ------------------------------------------------------------------ */
  function renderList() {
    el.feed.innerHTML = '';

    if (state.search.active) {
      el.searchBanner.classList.remove('hidden');
      el.searchBannerText.textContent = state.search.loading
        ? `正在搜索「${state.search.q}」…`
        : `搜索「${state.search.q}」：${state.search.results.length} 条结果`;
      el.searchExit.textContent = '退出搜索';
      renderSearchResults();
      return;
    }

    if (state.month) {
      el.searchBanner.classList.remove('hidden');
      const [y, m] = state.month.split('-').map(Number);
      const undone = state.monthTodos.filter((t) => !t.done).length;
      el.searchBannerText.textContent = `${y} 年 ${m} 月 · 共 ${state.monthTodos.length} 条 · ${undone} 项未完成`;
      el.searchExit.textContent = '返回单日';
      renderMonthResults();
      return;
    }

    el.searchBanner.classList.add('hidden');
    renderDayList();
  }

  /** 当前日期的待办卡片 */
  function renderDayList() {
    if (!state.todos.length) {
      el.emptyState.classList.remove('hidden');
      el.emptyTitle.textContent = '这里还没有安排';
      el.emptySub.textContent = '在上面的输入框敲下第一件事吧';
    } else {
      el.emptyState.classList.add('hidden');
      const fragment = document.createDocumentFragment();
      state.todos.forEach((todo) => fragment.appendChild(renderItem(todo, { showDate: false })));
      el.feed.appendChild(fragment);
    }
    el.remainingCount.textContent = String(state.remaining);
    el.remainingLabel.textContent = state.remaining === 0
      ? (state.total ? '全部完成 🎉' : '项待完成')
      : '项待完成';
    el.clearDoneBtn.disabled = !state.todos.some((t) => t.done);
  }

  /** 搜索结果：按日期分组展示 */
  function renderSearchResults() {
    if (!state.search.results.length) {
      el.emptyState.classList.remove('hidden');
      el.emptyTitle.textContent = state.search.loading ? '正在搜索…' : '没有找到匹配的任务';
      el.emptySub.textContent = state.search.loading ? '' : '换个关键词试试，#标签 也可以直接搜';
      return;
    }
    el.emptyState.classList.add('hidden');
    renderGroupedByDate(state.search.results);
  }

  /** 月视图：整月任务按日期分组（日期倒序）展示 */
  function renderMonthResults() {
    if (!state.monthTodos.length) {
      el.emptyState.classList.remove('hidden');
      el.emptyTitle.textContent = '这个月还没有任务';
      el.emptySub.textContent = '在日历或时间线选一天，敲下第一件事吧';
      return;
    }
    el.emptyState.classList.add('hidden');
    renderGroupedByDate(state.monthTodos);
  }

  /** 通用：按日期分组渲染卡片流，组头显示「x 月 x 日 · 剩余 / 共 N」 */
  function renderGroupedByDate(list) {
    const groups = new Map();
    for (const todo of list) {
      if (!groups.has(todo.date)) groups.set(todo.date, []);
      groups.get(todo.date).push(todo);
    }

    const fragment = document.createDocumentFragment();
    for (const [date, items] of groups) {
      const head = document.createElement('div');
      head.className = 'feed-date-head';
      const { title } = humanDate(date);
      head.append(
        Object.assign(document.createElement('span'), { textContent: title }),
        Object.assign(document.createElement('small'), { textContent: date }),
        Object.assign(document.createElement('span'), {
          className: 'feed-date-count',
          textContent: `${items.filter((t) => !t.done).length} 项未完成 / 共 ${items.length}`,
        }),
      );
      fragment.appendChild(head);
      items.forEach((todo) => fragment.appendChild(renderItem(todo, { showDate: false })));
    }
    el.feed.appendChild(fragment);
  }

  const CHECK_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';
  const TRASH_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6M10 11v6M14 11v6"/></svg>';
  const PENCIL_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>';

  function formatTime(unix) {
    const d = new Date((Number(unix) || 0) * 1000);
    return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function renderItem(todo, { showDate = false } = {}) {
    const card = document.createElement('article');
    card.className = `memo${todo.done ? ' done' : ''}`;
    card.dataset.id = todo.id;

    /* meta 行：时间 + 操作 */
    const meta = document.createElement('div');
    meta.className = 'memo-meta';

    const time = document.createElement('span');
    time.className = 'memo-time';
    const created = new Date((Number(todo.createdAt) || 0) * 1000);
    const dateText = showDate
      ? `${created.getFullYear()}/${pad(created.getMonth() + 1)}/${pad(created.getDate())} `
      : '';
    time.textContent = `${dateText}${formatTime(todo.createdAt)}`;

    const acts = document.createElement('span');
    acts.className = 'memo-acts';

    const edit = document.createElement('button');
    edit.type = 'button';
    edit.setAttribute('aria-label', '编辑任务');
    edit.innerHTML = PENCIL_SVG;

    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'memo-del';
    del.setAttribute('aria-label', '删除任务');
    del.innerHTML = TRASH_SVG;
    del.addEventListener('click', () => deleteTodo(todo, card));

    acts.append(edit, del);
    meta.append(time, acts);

    /* body：勾选 + 内容 */
    const body = document.createElement('div');
    body.className = 'memo-body';

    const check = document.createElement('button');
    check.type = 'button';
    check.className = 'check';
    check.setAttribute('aria-label', todo.done ? '标记为未完成' : '标记为已完成');
    check.setAttribute('aria-pressed', String(todo.done));
    check.innerHTML = CHECK_SVG;
    check.addEventListener('click', () => toggleTodo(todo));

    const text = document.createElement('div');
    text.className = 'memo-text';
    text.title = '长按或双击可编辑';
    renderTitleWithTags(text, todo.title);
    const editApi = bindEdit(card, text, todo);
    edit.addEventListener('click', () => editApi.enterEdit());

    body.append(check, text);
    card.append(meta, body);
    return card;
  }

  /** 把标题里的 #标签 渲染成可点击的徽片（其余保持纯文本，防 XSS） */
  function renderTitleWithTags(container, title) {
    const re = new RegExp(TAG_RE.source, 'g');
    let last = 0;
    let match;
    while ((match = re.exec(title))) {
      if (match.index > last) {
        container.appendChild(document.createTextNode(title.slice(last, match.index)));
      }
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'tag-chip';
      chip.textContent = `#${match[1]}`;
      chip.title = `查看 #${match[1]} 的全部任务`;
      chip.addEventListener('click', () => startSearch(`#${match[1]}`));
      container.appendChild(chip);
      last = match.index + match[0].length;
    }
    if (last < title.length) {
      container.appendChild(document.createTextNode(title.slice(last)));
    }
  }

  /** 长按 / 双击 / 铅笔进入行内编辑 */
  function bindEdit(card, node, todo) {
    let timer = null;

    const start = () => {
      timer = setTimeout(() => { timer = null; enterEdit(); }, 520);
    };
    const cancel = () => { if (timer) { clearTimeout(timer); timer = null; } };

    node.addEventListener('touchstart', start, { passive: true });
    node.addEventListener('touchend', cancel);
    node.addEventListener('touchmove', cancel);
    node.addEventListener('mousedown', start);
    node.addEventListener('mouseup', cancel);
    node.addEventListener('mouseleave', cancel);
    node.addEventListener('dblclick', (e) => { e.preventDefault(); enterEdit(); });

    function enterEdit() {
      if (node.isContentEditable) return;
      const original = todo.title;
      // 先拍平成纯文本再编辑（去掉标签徽片）
      node.textContent = original;
      node.contentEditable = 'true';
      node.focus();
      document.getSelection()?.selectAllChildren(node);

      const finish = async (save) => {
        node.contentEditable = 'false';
        const next = node.textContent.replace(/\s+/g, ' ').trim();

        if (!save || !next || next === original) {
          node.textContent = '';
          renderTitleWithTags(node, original);
          return;
        }
        node.textContent = next;
        try {
          const data = await api(`/todos/${encodeURIComponent(todo.id)}`, { method: 'PATCH', body: { title: next } });
          Object.assign(todo, { title: next });
          updateCounts(data);
          syncDayCache();
          scheduleSidebarRefresh();
        } catch (err) {
          toast(err.message, 'err');
        } finally {
          node.textContent = '';
          renderTitleWithTags(node, todo.title);
        }
      };

      const onKey = (e) => {
        if (e.key === 'Enter') { e.preventDefault(); node.blur(); }
        if (e.key === 'Escape') { node.textContent = original; node.blur(); }
      };
      const onBlur = () => {
        node.removeEventListener('keydown', onKey);
        node.removeEventListener('blur', onBlur);
        finish(node.textContent.trim() !== original);
      };

      node.addEventListener('keydown', onKey);
      node.addEventListener('blur', onBlur);
    }

    return { enterEdit };
  }

  function updateCounts(data) {
    if (typeof data?.remaining === 'number') state.remaining = data.remaining;
    if (typeof data?.total === 'number') state.total = data.total;
    el.remainingCount.textContent = String(state.remaining);
    el.remainingLabel.textContent = state.remaining === 0
      ? (state.total ? '全部完成 🎉' : '项待完成')
      : '项待完成';
    el.clearDoneBtn.disabled = !state.todos.some((t) => t.done);
  }

  async function refresh() {
    const date = state.date;
    const cached = dayCache.get(date);

    // 1) 有缓存：立即渲染，用户零等待
    if (cached && state.date === date && !state.month && !state.search.active) {
      state.todos = cached.todos;
      state.remaining = cached.remaining;
      state.total = cached.total;
      renderList();
    }

    // 2) 后台请求最新数据（有缓存时数据没变就不重绘，避免闪烁）
    try {
      const data = await api(`/todos?date=${encodeURIComponent(date)}`);
      const todos = data.todos || [];
      const remaining = data.remaining ?? todos.filter((t) => !t.done).length;
      const total = data.total ?? todos.length;
      const unchanged = cached
        && cached.remaining === remaining
        && cached.total === total
        && JSON.stringify(cached.todos) === JSON.stringify(todos);
      if (!unchanged) cacheSetDay(date, todos, remaining, total);

      if (state.date !== date || state.month || state.search.active) return;   // 用户已切走
      if (unchanged) return;                                                   // 画面已是最新
      state.todos = todos;
      state.remaining = remaining;
      state.total = total;
      renderList();

      // 3) 顺手预取前一天/后一天，左右切换日期时秒开
      prefetchDay(shiftDate(date, -1));
      prefetchDay(shiftDate(date, 1));
    } catch (err) {
      if (err.status === 401) { state.user = null; showAuth(); return; }
      if (!cached) toast(err.message, 'err');   // 已有缓存内容在展示时静默
    }
  }

  /* ------------------------------------------------------------------ *
   * 侧栏：统计 / 日历 / 标签 / 时间线
   * ------------------------------------------------------------------ */
  let sidebarTimer = null;
  /** 数据变更后静默刷新侧栏（防抖，避免频繁请求） */
  function scheduleSidebarRefresh() {
    clearTimeout(sidebarTimer);
    sidebarTimer = setTimeout(loadSidebarData, 900);
  }

  async function loadSidebarData() {
    try {
      const [statsRes, tagsRes] = await Promise.all([
        api('/todos/stats?days=365'),
        api('/tags'),
      ]);
      state.stats = statsRes.stats || [];
      state.tags = tagsRes.tags || [];
    } catch { /* 静默失败，不影响主流程 */ }
    renderStats();
    renderCalendar();
    renderTags();
    renderTimeline();
  }

  function renderStats() {
    let total = 0;
    let remaining = 0;
    for (const s of state.stats) { total += s.total; remaining += s.remaining; }
    el.statDays.textContent = String(state.stats.length);
    el.statTotal.textContent = String(total);
    el.statDone.textContent = String(total - remaining);
  }

  function renderCalendar() {
    const { y, m } = state.cal;
    el.calTitle.textContent = `${y} 年 ${m + 1} 月`;
    el.calTitle.title = `查看 ${y} 年 ${m + 1} 月全部任务`;
    el.calendar.innerHTML = '';

    const byDate = new Map(state.stats.map((s) => [s.date, s]));
    const today = todayStr();
    for (const name of ['日', '一', '二', '三', '四', '五', '六']) {
      el.calendar.appendChild(Object.assign(document.createElement('span'), { className: 'cal-dow', textContent: name }));
    }

    const firstDow = new Date(y, m, 1).getDay();
    const daysInMonth = new Date(y, m + 1, 0).getDate();
    for (let i = 0; i < firstDow; i += 1) {
      el.calendar.appendChild(Object.assign(document.createElement('span'), { className: 'cal-blank' }));
    }
    for (let d = 1; d <= daysInMonth; d += 1) {
      const dateStr = `${y}-${pad(m + 1)}-${pad(d)}`;
      const info = byDate.get(dateStr);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cal-day'
        + (info ? ' has-tasks' : '')
        + (dateStr === today ? ' is-today' : '')
        + (dateStr === state.date ? ' is-selected' : '');
      btn.textContent = String(d);
      if (info) {
        btn.title = `${dateStr} · ${info.remaining} 项未完成 / 共 ${info.total}`;
        btn.appendChild(Object.assign(document.createElement('span'), { className: 'dot' }));
      }
      btn.addEventListener('click', () => gotoDate(dateStr));
      el.calendar.appendChild(btn);
    }
  }

  el.calPrev.addEventListener('click', () => shiftMonth(-1));
  el.calNext.addEventListener('click', () => shiftMonth(1));
  // 点击日历标题 → 查看该月全部任务的整月视图
  el.calTitle.addEventListener('click', () => openMonth(`${state.cal.y}-${pad(state.cal.m + 1)}`));
  function shiftMonth(delta) {
    const d = new Date(state.cal.y, state.cal.m + delta, 1);
    state.cal = { y: d.getFullYear(), m: d.getMonth() };
    renderCalendar();
  }

  function renderTags() {
    el.tagsBlock.classList.toggle('hidden', !state.tags.length);
    el.tagsList.innerHTML = '';
    state.tags.forEach(({ name, count }) => {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'tag-row';
      row.title = `查看 #${name} 的全部任务`;
      row.append(
        Object.assign(document.createElement('span'), { className: 'tag-hash', textContent: '#' }),
        Object.assign(document.createElement('span'), { textContent: name }),
        Object.assign(document.createElement('b'), { textContent: String(count) }),
      );
      row.addEventListener('click', () => startSearch(`#${name}`));
      el.tagsList.appendChild(row);
    });
  }

  function renderTimeline() {
    el.timelineBlock.classList.toggle('hidden', !state.stats.length);
    el.timelineList.innerHTML = '';

    // stats 已按日期倒序：按 年 → 月 聚合，记录每月/每年最近一个有任务的日期
    const years = new Map();
    for (const s of state.stats) {
      const [y, m] = s.date.split('-').map(Number);
      if (!years.has(y)) years.set(y, { count: 0, latest: s.date, months: new Map() });
      const year = years.get(y);
      year.count += s.total;
      if (!year.months.has(m)) year.months.set(m, { count: 0, latest: s.date });
      year.months.get(m).count += s.total;
    }

    for (const [y, year] of years) {
      const latestMonth = Array.from(year.months.keys())[0];
      const yearRow = document.createElement('div');
      yearRow.className = 'tl-year';
      yearRow.title = `查看 ${y} 年 ${latestMonth} 月及更早的任务`;
      yearRow.append(
        Object.assign(document.createElement('span'), { textContent: String(y) }),
        Object.assign(document.createElement('small'), { textContent: `${year.count} 条` }),
      );
      // 点击年份 → 打开该年最近有任务的月份的整月视图
      yearRow.addEventListener('click', () => openMonth(`${y}-${pad(latestMonth)}`));
      el.timelineList.appendChild(yearRow);

      const months = document.createElement('div');
      months.className = 'tl-months';
      for (const [m, info] of Array.from(year.months).sort((a, b) => b[0] - a[0])) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'tl-month';
        btn.title = `查看 ${y} 年 ${m} 月全部 ${info.count} 条任务`;
        btn.append(
          document.createTextNode(`${m} 月`),
          Object.assign(document.createElement('b'), { textContent: String(info.count) }),
        );
        // 点击月份 → 整月视图（该月所有任务按日期分组展示）
        btn.addEventListener('click', () => openMonth(`${y}-${pad(m)}`));
        months.appendChild(btn);
      }
      el.timelineList.appendChild(months);
    }
  }

  /* ------------------------------ 侧栏开合（移动端抽屉） ------------------------------ */
  function openSidebar() {
    document.body.classList.add('side-open');
    el.sideMask.classList.remove('hidden');
  }
  function closeSidebar() {
    document.body.classList.remove('side-open');
    el.sideMask.classList.add('hidden');
  }
  el.sideToggle.addEventListener('click', openSidebar);
  el.sideMask.addEventListener('click', closeSidebar);
  window.addEventListener('resize', () => { if (window.innerWidth >= 980) closeSidebar(); });

  /* ------------------------------------------------------------------ *
   * 搜索
   * ------------------------------------------------------------------ */
  let searchTimer = null;

  el.searchInput.addEventListener('input', () => {
    const q = el.searchInput.value.trim();
    el.searchClear.classList.toggle('hidden', !q);
    clearTimeout(searchTimer);
    if (!q) { exitSearch(); return; }
    searchTimer = setTimeout(() => runSearch(q), 260);
  });

  el.searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { exitSearch(); el.searchInput.blur(); }
  });

  el.searchClear.addEventListener('click', () => { exitSearch(); el.addInput.focus({ preventScroll: true }); });
  el.searchExit.addEventListener('click', () => {
    if (state.month) { exitMonth(); return; }
    exitSearch();
    el.addInput.focus({ preventScroll: true });
  });

  async function runSearch(q) {
    state.search = { q, active: true, loading: true, results: [] };
    renderList();
    try {
      const data = await api(`/search?q=${encodeURIComponent(q)}`);
      if (state.search.active && state.search.q === q) {
        state.search.results = data.todos || [];
      }
    } catch (err) {
      if (err.status === 401) { state.user = null; showAuth(); return; }
      toast(err.message, 'err');
    } finally {
      if (state.search.active && state.search.q === q) {
        state.search.loading = false;
        renderList();
      }
    }
  }

  function startSearch(q) {
    el.searchInput.value = q;
    el.searchClear.classList.remove('hidden');
    clearTimeout(searchTimer);
    runSearch(q);
    closeSidebar();
  }

  function exitSearch() {
    clearTimeout(searchTimer);
    const had = state.search.active || el.searchInput.value;
    state.search = { q: '', active: false, loading: false, results: [] };
    el.searchInput.value = '';
    el.searchClear.classList.add('hidden');
    if (had) renderList();
  }

  /* ------------------------------------------------------------------ *
   * 增 / 改 / 删
   * ------------------------------------------------------------------ */
  el.addForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (state.busy) return;

    const title = el.addInput.value.replace(/\s+/g, ' ').trim();
    if (!title) {
      // 空白任务不添加
      el.addHint.textContent = '任务内容不能为空';
      el.addHint.hidden = false;
      el.addForm.classList.add('shake');
      setTimeout(() => el.addForm.classList.remove('shake'), 360);
      el.addInput.focus();
      return;
    }

    el.addHint.hidden = true;
    if (state.search.active) exitSearch();   // 搜索状态下添加任务，先回到日期视图
    state.busy = true;
    const btn = el.addBtn || el.addForm.querySelector('button[type=submit]');
    if (btn) btn.disabled = true;

    // 月视图：不做日视图的乐观插入，成功后刷新整月数据
    if (state.month) {
      el.addInput.value = '';
      try {
        await api('/todos', { method: 'POST', body: { title, date: state.date } });
        await refreshMonth();
        scheduleSidebarRefresh();
      } catch (err) {
        if (err.status === 401) { showAuth(); return; }
        toast(err.message, 'err');
        el.addInput.value = title;
      } finally {
        state.busy = false;
        if (btn) btn.disabled = false;
        el.addInput.focus({ preventScroll: true });
      }
      return;
    }

    // 乐观插入
    const tempId = `tmp_${Date.now()}`;
    const optimistic = { id: tempId, title, done: false, date: state.date, order: -Infinity, createdAt: Date.now() / 1000 };
    state.todos.unshift(optimistic);
    state.total += 1;
    state.remaining += 1;
    renderList();
    el.addInput.value = '';

    try {
      const data = await api('/todos', { method: 'POST', body: { title, date: state.date } });
      const index = state.todos.findIndex((t) => t.id === tempId);
      if (index !== -1) state.todos[index] = data.todo;
      state.todos.sort((a, b) => Number(a.done) - Number(b.done) || a.order - b.order);
      state.remaining = data.remaining;
      state.total = data.total;
      renderList();
      syncDayCache();
      scheduleSidebarRefresh();
    } catch (err) {
      state.todos = state.todos.filter((t) => t.id !== tempId);
      state.total = Math.max(0, state.total - 1);
      state.remaining = state.todos.filter((t) => !t.done).length;
      renderList();
      if (err.status === 401) { showAuth(); return; }
      toast(err.message, 'err');
      el.addInput.value = title;
    } finally {
      state.busy = false;
      if (btn) btn.disabled = false;
      el.addInput.focus({ preventScroll: true });
    }
  });

  el.addInput.addEventListener('input', () => { el.addHint.hidden = true; });

  async function toggleTodo(todo) {
    const next = !todo.done;
    todo.done = next;
    // 已完成的沉到底部
    state.todos.sort((a, b) => Number(a.done) - Number(b.done) || a.order - b.order);
    state.remaining = state.todos.filter((t) => !t.done).length;
    renderList();

    try {
      const data = await api(`/todos/${encodeURIComponent(todo.id)}`, { method: 'PATCH', body: { done: next } });
      if (state.month) { await refreshMonth(); }
      else { updateCounts(data); syncDayCache(); }
      scheduleSidebarRefresh();
    } catch (err) {
      todo.done = !next;
      if (state.month) { renderList(); } else {
        state.todos.sort((a, b) => Number(a.done) - Number(b.done) || a.order - b.order);
        state.remaining = state.todos.filter((t) => !t.done).length;
        renderList();
      }
      toast(err.message, 'err');
    }
  }

  async function deleteTodo(todo, li) {
    li.classList.add('removing');
    const backup = state.month ? state.monthTodos.slice() : state.todos.slice();
    if (state.month) {
      state.monthTodos = state.monthTodos.filter((t) => t.id !== todo.id);
    } else {
      state.todos = state.todos.filter((t) => t.id !== todo.id);
      state.remaining = state.todos.filter((t) => !t.done).length;
      state.total = state.todos.length;
    }

    setTimeout(renderList, 180);
    try {
      const data = await api(`/todos/${encodeURIComponent(todo.id)}?date=${encodeURIComponent(state.date)}`, { method: 'DELETE' });
      if (state.month) { await refreshMonth(); }
      else { updateCounts(data); syncDayCache(); }
      scheduleSidebarRefresh();
    } catch (err) {
      if (state.month) {
        state.monthTodos = backup;
      } else {
        state.todos = backup;
        state.remaining = backup.filter((t) => !t.done).length;
        state.total = backup.length;
      }
      renderList();
      toast(err.message, 'err');
    }
  }

  el.clearDoneBtn.addEventListener('click', () => {
    const hasDone = state.month
      ? state.monthTodos.some((t) => t.done)
      : state.todos.some((t) => t.done);
    if (!hasDone) return;

    armedClick(el.clearDoneBtn, '确认清除？', async () => {
      try {
        const body = state.month
          ? { action: 'clear-completed', month: state.month }
          : { action: 'clear-completed', date: state.date };
        const data = await api('/todos/batch', { method: 'POST', body });
        scheduleSidebarRefresh();
        if (state.month) {
          await refreshMonth();
          toast(`已清除本月 ${data.removed || 0} 项已完成任务`, 'ok');
        } else {
          await refresh();
          syncDayCache();
          toast('已清除完成的任务', 'ok');
        }
      } catch (err) { toast(err.message, 'err'); }
    });
  });

  el.carryoverBtn.addEventListener('click', async () => {
    try {
      const data = await api('/todos/batch', { method: 'POST', body: { action: 'carry-over', date: state.date } });
      cacheClearAll();   // 顺延会改动多个日期的数据，直接清空缓存最稳妥
      await refresh();
      scheduleSidebarRefresh();
      toast(data.moved ? `已顺延 ${data.moved} 项未完成任务` : '没有需要顺延的任务', data.moved ? 'ok' : '');
    } catch (err) { toast(err.message, 'err'); }
  });

  /* ------------------------------------------------------------------ *
   * 主题
   * ------------------------------------------------------------------ */
  const THEME_KEY = 'todo-today:theme';
  function applyTheme(theme) {
    if (theme === 'light' || theme === 'dark') {
      document.documentElement.setAttribute('data-theme', theme);
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    el.themeToggle.textContent = theme === 'dark' ? '☀️' : theme === 'light' ? '🌙' : '🌓';
  }
  el.themeToggle.addEventListener('click', () => {
    const order = ['auto', 'light', 'dark'];
    const current = localStorage.getItem(THEME_KEY) || 'auto';
    const next = order[(order.indexOf(current) + 1) % order.length];
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next === 'auto' ? null : next);
  });
  applyTheme(localStorage.getItem(THEME_KEY) || null);

  /* ------------------------------------------------------------------ *
   * 设置抽屉
   * ------------------------------------------------------------------ */
  function openDrawer() {
    el.drawerMask.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }
  function closeDrawer() {
    el.drawerMask.classList.add('hidden');
    document.body.style.overflow = '';
  }
  el.userMenu.addEventListener('click', openDrawer);
  el.drawerClose.addEventListener('click', closeDrawer);
  el.drawerMask.addEventListener('click', (e) => { if (e.target === el.drawerMask) closeDrawer(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeDrawer(); closeSidebar(); }
  });
  el.demoBannerClose.addEventListener('click', () => el.demoBanner.classList.add('hidden'));

  /* ------------------------------ 云备份 ------------------------------ */
  function syncProviderPanels() {
    const provider = el.backupProvider.value;
    el.backupPanels.forEach((panel) => {
      panel.hidden = panel.dataset.provider !== provider;
    });
    const on = el.backupEnabled.checked && provider !== 'none';
    el.backupEnabled.disabled = provider === 'none';
    el.backupAuto.disabled = !on;
    el.backupScheduled.disabled = !on;
    [el.backupTest, el.backupRun, el.backupRestore].forEach((b) => { b.disabled = provider === 'none'; });
    if (!on) { el.backupAuto.checked = false; el.backupScheduled.checked = false; }

    // 频率相关控件只在对应开关打开时出现
    el.backupIntervalField.classList.toggle('hidden', !(on && el.backupAuto.checked));
    el.backupPeriodField.classList.toggle('hidden', !(on && el.backupScheduled.checked));

    updateStampHint();
    updateFrequencyHints();
  }

  /** 安全地给 select 赋值：配置里的值不在选项列表里时临时补一个选项 */
  function setSelectValue(select, value) {
    const v = String(value);
    if (!Array.from(select.options).some((o) => o.value === v)) {
      const opt = document.createElement('option');
      opt.value = v;
      opt.textContent = `${humanMinutes(v)}（自定义）`;
      select.appendChild(opt);
    }
    select.value = v;
  }

  /** 把「分钟」翻译成人话 */
  function humanMinutes(min) {
    const n = Number(min);
    if (n === 0) return '不限制';
    if (n < 60) return `${n} 分钟`;
    if (n === 60) return '1 小时';
    if (n < 1440) return `${n / 60} 小时`;
    if (n === 1440) return '24 小时';
    return `${Math.round(n / 1440)} 天`;
  }

  /** 频率 / 定时备份的说明 + Cron 是否真的在跑的诊断 */
  function updateFrequencyHints() {
    const every = humanMinutes(el.backupInterval.value);
    el.backupIntervalHint.textContent = Number(el.backupInterval.value) === 0
      ? '每次数据变更都会备份一次，历史文件增长最快。'
      : `距上次备份不足 ${every}时不会重复备份（每改一次任务都会检查）。`;

    if (!el.backupScheduled.checked) {
      el.backupCronHint.textContent = '打开后由 Cloudflare 定时触发（每 5 分钟检查一次），不需要你打开页面。';
      return;
    }
    const period = humanMinutes(el.backupPeriod.value);
    const status = state.cron || {};
    let text = `云端每 5 分钟检查一次，到点就备份，约每 ${period}一次。`;
    if (status.lastRun) {
      const ago = Math.max(0, Math.round(Date.now() / 1000 - status.lastRun));
      const agoText = ago < 90 ? `${ago} 秒前` : `${Math.round(ago / 60)} 分钟前`;
      text += status.healthy
        ? ` 定时任务运行正常（上次检查 ${agoText}）。`
        : ` ⚠️ 上次检查是 ${agoText}，定时任务可能没在跑：需在 Worker 的 Triggers 里添加 Cron「*/5 * * * *」。`;
    } else {
      text += ' ⚠️ 还没收到过定时任务的心跳：请确认已在 Worker 的 Triggers → Cron Triggers 里添加「*/5 * * * *」。';
    }
    el.backupCronHint.textContent = text;
  }

  /** 本地时间的时间戳示例，与后端 fileStamp 格式一致：YYYYMMDD-HHmmss */
  function localStamp(d = new Date()) {
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
  }

  /** 与后端 stampKey 一致的命名规则：时间戳插在扩展名之前 */
  function stampName(base, stamp) {
    const name = String(base || 'todo-today.backup.json');
    const dot = name.lastIndexOf('.');
    return dot > 0 ? `${name.slice(0, dot)}.${stamp}${name.slice(dot)}` : `${name}.${stamp}`;
  }

  /** 当前配置下实际会写入的固定文件名（与后端 objectKeyOf 对应） */
  function currentBackupBase() {
    const provider = el.backupProvider.value;
    if (provider === 'r2') return el.r2Key.value.trim() || 'todo-today.backup.json';
    if (provider === 'webdav') return el.davFile.value.trim() || 'todo-today.backup.json';
    const prefix = el.s3Prefix.value.trim().replace(/^\/+/, '');
    return `${prefix}${el.s3File.value.trim() || 'todo-today.backup.json'}`;
  }

  function updateStampHint() {
    const provider = el.backupProvider.value;
    if (provider === 'none') {
      el.backupStampHint.textContent = '选择备份方式后，这里会显示实际写入云端的文件名。';
      return;
    }
    const base = currentBackupBase();
    if (!el.backupStamp) return;
    if (!el.backupStamp.checked) {
      el.backupStampHint.textContent = `每次备份都会覆盖同一个文件：${base}`;
      return;
    }
    el.backupStampHint.textContent =
      `每次备份写入 ${stampName(base, localStamp())}，并同时刷新固定名快照 ${base}（「从云端恢复」读的是这份）。`;
  }

  el.backupProvider.addEventListener('change', syncProviderPanels);
  el.backupEnabled.addEventListener('change', syncProviderPanels);
  el.backupStamp.addEventListener('change', updateStampHint);
  el.backupAuto.addEventListener('change', syncProviderPanels);
  el.backupScheduled.addEventListener('change', syncProviderPanels);
  el.backupInterval.addEventListener('change', updateFrequencyHints);
  el.backupPeriod.addEventListener('change', updateFrequencyHints);
  [el.r2Key, el.s3File, el.s3Prefix, el.davFile].forEach((input) => {
    input.addEventListener('input', updateStampHint);
  });

  async function loadBackupConfig() {
    try {
      const data = await api('/backup/config');
      state.cron = data.cron || null;
      fillBackupForm(data.config || {});
      if (data.lastBackup) {
        el.lastBackupLine.textContent = `上次备份：${new Date(data.lastBackup * 1000).toLocaleString()}`;
      } else {
        el.lastBackupLine.textContent = '尚未备份过。';
      }
    } catch (err) {
      setStatus(el.backupStatus, `读取备份配置失败：${err.message}`, 'err');
    }
  }

  function fillBackupForm(config) {
    el.backupProvider.value = config.provider || 'none';
    el.backupEnabled.checked = !!config.enabled;
    el.backupAuto.checked = !!config.auto;
    el.backupStamp.checked = config.stamp !== false;   // 默认开启
    setSelectValue(el.backupInterval, config.intervalMin ?? 1);
    el.backupScheduled.checked = !!config.scheduled;
    setSelectValue(el.backupPeriod, config.scheduleMin ?? 60);

    el.r2Key.value = config.r2?.key || '';
    if (config.hasR2Binding === false) {
      el.r2Key.placeholder = '未检测到 R2 绑定 BACKUPS';
    }

    const s3 = config.s3 || {};
    el.s3Endpoint.value = s3.endpoint || '';
    el.s3Region.value = s3.region || 'auto';
    el.s3Bucket.value = s3.bucket || '';
    el.s3Akid.value = s3.accessKeyId || '';
    el.s3Secret.value = '';
    el.s3Secret.placeholder = s3.hasSecretKey
      ? (s3.secretFromEnv ? '已在环境变量中配置（留空即使用）' : '已保存，留空表示不修改')
      : '留空表示不修改';
    el.s3Prefix.value = s3.prefix || '';
    el.s3File.value = config.file && config.provider === 's3' ? config.file : (config.file || '');
    el.s3PathStyle.checked = !!s3.pathStyle;

    const dav = config.webdav || {};
    el.davUrl.value = dav.url || '';
    el.davUser.value = dav.username || '';
    el.davPass.value = '';
    el.davPass.placeholder = dav.hasPassword
      ? (dav.passwordFromEnv ? '已在环境变量中配置（留空即使用）' : '已保存，留空表示不修改')
      : '留空表示不修改';
    el.davFile.value = dav.file || '';

    syncProviderPanels();
  }

  function collectBackupForm() {
    const provider = el.backupProvider.value;
    return {
      provider,
      enabled: el.backupEnabled.checked && provider !== 'none',
      auto: el.backupAuto.checked && el.backupEnabled.checked && provider !== 'none',
      intervalMin: Number(el.backupInterval.value) || 0,
      scheduled: el.backupScheduled.checked && el.backupEnabled.checked && provider !== 'none',
      scheduleMin: Number(el.backupPeriod.value) || 60,
      stamp: el.backupStamp.checked,
      // 前端直接把浏览器时区报给后端，定时备份拼文件名时用
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
      file: provider === 'webdav'
        ? (el.davFile.value.trim() || 'todo-today.backup.json')
        : (el.s3File.value.trim() || 'todo-today.backup.json'),
      r2: { key: el.r2Key.value.trim() },
      s3: {
        endpoint: el.s3Endpoint.value.trim(),
        region: el.s3Region.value.trim() || 'auto',
        bucket: el.s3Bucket.value.trim(),
        accessKeyId: el.s3Akid.value.trim(),
        secretAccessKey: el.s3Secret.value.trim(),
        prefix: el.s3Prefix.value.trim(),
        pathStyle: el.s3PathStyle.checked,
      },
      webdav: {
        url: el.davUrl.value.trim(),
        username: el.davUser.value.trim(),
        password: el.davPass.value.trim(),
        file: el.davFile.value.trim(),
      },
    };
  }

  el.backupSave.addEventListener('click', async () => {
    setStatus(el.backupStatus, '保存中…', 'busy');
    try {
      const data = await api('/backup/config', { method: 'PUT', body: collectBackupForm() });
      fillBackupForm(data.config || {});
      setStatus(el.backupStatus, '配置已保存', 'ok');
      toast('备份配置已保存', 'ok');
    } catch (err) {
      setStatus(el.backupStatus, `保存失败：${err.message}`, 'err');
    }
  });

  el.backupTest.addEventListener('click', async () => {
    setStatus(el.backupStatus, '正在测试连接…', 'busy');
    try {
      const data = await api('/backup/test', { method: 'POST', body: collectBackupForm() });
      setStatus(el.backupStatus, data.message || '连接正常', 'ok');
    } catch (err) {
      setStatus(el.backupStatus, `连接失败：${err.message}`, 'err');
    }
  });

  el.backupRun.addEventListener('click', async () => {
    setStatus(el.backupStatus, '正在备份…', 'busy');
    try {
      const data = await api('/backup/run', { method: 'POST' });
      const r = data.result || {};
      const detail = r.key && r.key !== r.latestKey
        ? `共 ${r.total ?? '-'} 条任务，${formatBytes(r.size)} → ${r.key}`
        : `共 ${r.total ?? '-'} 条任务，${formatBytes(r.size)} → ${r.key || r.latestKey || ''}`;
      setStatus(el.backupStatus, `备份成功：${detail}`, 'ok');
      el.lastBackupLine.textContent = `上次备份：${new Date().toLocaleString()}`;
      toast('已备份到云端', 'ok');
    } catch (err) {
      setStatus(el.backupStatus, `备份失败：${err.message}`, 'err');
    }
  });

  el.backupRestore.addEventListener('click', () => {
    armedClick(el.backupRestore, '确认覆盖？', async () => {
      setStatus(el.backupStatus, '正在从云端恢复…', 'busy');
      try {
      const data = await api('/backup/restore', { method: 'POST', body: { mode: 'replace' } });
      setStatus(el.backupStatus, `${data.message}（新增 ${data.result?.inserted ?? 0} 条）`, 'ok');
      cacheClearAll();   // 云端数据整体替换，缓存全部失效
      await refresh();
      scheduleSidebarRefresh();
      } catch (err) {
        setStatus(el.backupStatus, `恢复失败：${err.message}`, 'err');
      }
    });
  });

  function formatBytes(n) {
    const num = Number(n) || 0;
    if (num < 1024) return `${num} B`;
    if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
    return `${(num / 1024 / 1024).toFixed(2)} MB`;
  }

  /* ------------------------------ 导入导出 ------------------------------ */
  el.exportBtn.addEventListener('click', async () => {
    try {
      if (state.demo) {
        const db = demoRead();
        downloadJson({ app: 'todo-today', version: 1, exportedAt: new Date().toISOString(), todos: db.todos });
        return;
      }
      const res = await fetch(`${API_BASE}/export`, { credentials: 'same-origin' });
      if (!res.ok) throw new Error(`导出失败 (${res.status})`);
      const blob = await res.blob();
      downloadBlob(blob, `todo-today-${todayStr()}.json`);
      toast('已导出 JSON', 'ok');
    } catch (err) {
      toast(err.message, 'err');
    }
  });

  el.importBtn.addEventListener('click', () => el.importFile.click());

  el.importFile.addEventListener('change', async () => {
    const file = el.importFile.files?.[0];
    el.importFile.value = '';
    if (!file) return;

    try {
      const text = await file.text();
      const payload = JSON.parse(text);
      if (!Array.isArray(payload?.todos)) throw new Error('文件格式不正确：缺少 todos 数组');

      if (state.demo) {
        const db = demoRead();
        db.todos = payload.todos.map((t, i) => ({
          id: demoId(), title: String(t.title || '').trim(), done: !!t.done,
          date: t.date || todayStr(), order: i, createdAt: Math.floor(Date.now() / 1000),
        })).filter((t) => t.title);
        demoWrite(db);
        cacheClearAll();
        await refresh();
        toast(`导入完成：${db.todos.length} 条`, 'ok');
        return;
      }

      const data = await api('/import', { method: 'POST', body: { payload, mode: 'replace' } });
      cacheClearAll();   // 导入整体替换数据，缓存全部失效
      await refresh();
      scheduleSidebarRefresh();
      toast(data.message || '导入完成', 'ok');
    } catch (err) {
      toast(`导入失败：${err.message}`, 'err');
    }
  });

  function downloadJson(obj) {
    downloadBlob(new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' }), `todo-today-${todayStr()}.json`);
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /* ------------------------------------------------------------------ *
   * 启动
   * ------------------------------------------------------------------ */
  el.aboutVersion.textContent = `前端 v${APP_VERSION}`;

  // 快捷键：/ 聚焦新增输入框；Ctrl/Cmd+K 聚焦搜索；Esc 关抽屉/侧栏
  document.addEventListener('keydown', (e) => {
    const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || '')
      || document.activeElement?.isContentEditable;

    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      el.searchInput.focus();
      el.searchInput.select();
      return;
    }
    if (e.key === '/' && !inField) {
      e.preventDefault();
      el.addInput.focus();
    }
  });

  (async function boot() {
    renderDate();

    if (FORCE_DEMO) {
      state.demo = true;
      seedDemoData();
      el.demoBanner.classList.remove('hidden');
      el.aboutVersion.textContent = `前端 v${APP_VERSION} · 演示模式`;
      state.user = demoRead().user;
      await showMain();
      return;
    }

    try {
      const data = await api('/auth/me');
      state.user = data.user;
      if (state.user) await showMain();
      else showAuth();
    } catch {
      showAuth();
    }
  })();
})();
