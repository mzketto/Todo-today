/**
 * 待办事项数据访问层。
 * 排序规则：未完成在前、已完成沉底；同组内按 sort_order、创建时间。
 */

import { newId } from './crypto.js';
import { HttpError, nowSeconds } from './auth.js';

const MAX_TITLE = 500;
export const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
export const MONTH_RE = /^\d{4}-(?:0[1-9]|1[0-2])$/;
/** 标题里的 #标签（1-24 个非空白字符，不含 #） */
const TAG_RE = /#([^\s#]{1,24})/g;

function normalizeTitle(raw) {
  const title = String(raw ?? '').replace(/\s+/g, ' ').trim();
  if (!title) throw new HttpError('任务内容不能为空');
  if (title.length > MAX_TITLE) throw new HttpError(`任务内容不能超过 ${MAX_TITLE} 字`);
  return title;
}

export function normalizeDate(raw, fallback = null) {
  const value = String(raw || '').trim();
  if (!value) {
    if (fallback) return fallback;
    throw new HttpError('日期格式不正确，应为 YYYY-MM-DD');
  }
  if (!DATE_RE.test(value)) throw new HttpError('日期格式不正确，应为 YYYY-MM-DD');
  const d = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) throw new HttpError('日期无效');
  return value;
}

/** 校验月份参数（YYYY-MM），供整月视图使用 */
export function normalizeMonth(raw, fallback = null) {
  const value = String(raw || '').trim();
  if (!value) {
    if (fallback) return fallback;
    throw new HttpError('月份格式不正确，应为 YYYY-MM');
  }
  if (!MONTH_RE.test(value)) throw new HttpError('月份格式不正确，应为 YYYY-MM');
  return value;
}

function toDto(row) {
  return {
    id: row.id,
    title: row.title,
    done: !!row.done,
    date: row.todo_date,
    order: row.sort_order,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function listTodos(env, userId, date) {
  const day = normalizeDate(date);
  const { results } = await env.DB.prepare(
    `SELECT * FROM todos
      WHERE user_id = ? AND todo_date = ?
      ORDER BY done ASC, sort_order ASC, created_at ASC`,
  )
    .bind(userId, day)
    .all();
  return (results || []).map(toDto);
}

/** 一次性取回所有日期，用于本地缓存/导出场景 */
export async function listAllTodos(env, userId) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM todos WHERE user_id = ? ORDER BY todo_date DESC, sort_order ASC, created_at ASC`,
  )
    .bind(userId)
    .all();
  return (results || []).map(toDto);
}

/**
 * 取回某个整月的待办（按日期倒序、组内未完成在前），供「月视图」使用。
 * 上限 500 条，个人应用足够；超出时提示用户缩小范围。
 */
export async function listByMonth(env, userId, rawMonth) {
  const month = normalizeMonth(rawMonth);
  const { results } = await env.DB.prepare(
    `SELECT * FROM todos
      WHERE user_id = ? AND todo_date >= ? AND todo_date < ?
      ORDER BY todo_date DESC, done ASC, sort_order ASC, created_at ASC
      LIMIT 501`,
  )
    .bind(userId, `${month}-01`, nextMonthStart(month))
    .all();

  const rows = results || [];
  if (rows.length > 500) {
    throw new HttpError('该月任务超过 500 条，请按日期缩小范围查看', 413);
  }
  return { month, todos: rows.map(toDto) };
}

/** 月份 +1 的起点日期（如 2025-10 → 2025-11-01），用于范围查询 */
function nextMonthStart(month) {
  const [y, m] = month.split('-').map(Number);
  const date = m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, '0')}-01`;
  return date;
}

export async function countByDate(env, userId, date) {
  const day = normalizeDate(date);
  const row = await env.DB.prepare(
    `SELECT
        SUM(CASE WHEN done = 0 THEN 1 ELSE 0 END) AS remaining,
        COUNT(*) AS total
       FROM todos WHERE user_id = ? AND todo_date = ?`,
  )
    .bind(userId, day)
    .first();
  return {
    remaining: Number(row?.remaining || 0),
    total: Number(row?.total || 0),
  };
}

export async function createTodo(env, userId, { title, date }) {
  const text = normalizeTitle(title);
  const day = normalizeDate(date);
  const ts = nowSeconds();

  const minRow = await env.DB.prepare(
    'SELECT MIN(sort_order) AS min_order FROM todos WHERE user_id = ? AND todo_date = ?',
  )
    .bind(userId, day)
    .first();

  // 新任务排在最上面
  const order = (Number(minRow?.min_order ?? 0) || 0) - 1;

  const id = newId('t_');
  await env.DB.prepare(
    `INSERT INTO todos (id, user_id, title, done, todo_date, sort_order, created_at, updated_at)
     VALUES (?, ?, ?, 0, ?, ?, ?, ?)`,
  )
    .bind(id, userId, text, day, order, ts, ts)
    .run();

  return {
    id,
    title: text,
    done: false,
    date: day,
    order,
    createdAt: ts,
    updatedAt: ts,
  };
}

export async function updateTodo(env, userId, id, patch = {}) {
  const row = await env.DB.prepare('SELECT * FROM todos WHERE id = ? AND user_id = ?')
    .bind(id, userId)
    .first();
  if (!row) throw new HttpError('任务不存在或无权访问', 404);

  const sets = [];
  const values = [];

  if ('title' in patch) {
    sets.push('title = ?');
    values.push(normalizeTitle(patch.title));
  }
  if ('done' in patch) {
    sets.push('done = ?');
    values.push(patch.done ? 1 : 0);
  }
  if ('date' in patch) {
    sets.push('todo_date = ?');
    values.push(normalizeDate(patch.date));
  }
  if ('order' in patch) {
    const n = Number(patch.order);
    sets.push('sort_order = ?');
    values.push(Number.isFinite(n) ? n : 0);
  }

  if (!sets.length) return toDto(row);

  sets.push('updated_at = ?');
  values.push(nowSeconds());
  values.push(id, userId);

  await env.DB.prepare(`UPDATE todos SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`)
    .bind(...values)
    .run();

  const fresh = await env.DB.prepare('SELECT * FROM todos WHERE id = ?').bind(id).first();
  return toDto(fresh);
}

export async function deleteTodo(env, userId, id) {
  const res = await env.DB.prepare('DELETE FROM todos WHERE id = ? AND user_id = ?')
    .bind(id, userId)
    .run();
  const changed = res?.meta?.changes ?? 0;
  if (!changed) throw new HttpError('任务不存在或已删除', 404);
  return { id };
}

/** 批量重排：body.ids 为按目标顺序排列的任务 id */
export async function reorderTodos(env, userId, date, ids) {
  const day = normalizeDate(date);
  if (!Array.isArray(ids) || !ids.length) return { updated: 0 };

  const ts = nowSeconds();
  const stmts = ids.map((id, index) =>
    env.DB.prepare(
      'UPDATE todos SET sort_order = ?, updated_at = ? WHERE id = ? AND user_id = ? AND todo_date = ?',
    ).bind(index, ts, String(id), userId, day),
  );
  await env.DB.batch(stmts);
  return { updated: ids.length };
}

export async function clearCompleted(env, userId, date) {
  const day = normalizeDate(date);
  const res = await env.DB.prepare(
    'DELETE FROM todos WHERE user_id = ? AND todo_date = ? AND done = 1',
  )
    .bind(userId, day)
    .run();
  return { removed: res?.meta?.changes ?? 0 };
}

/** 清除整个月份的已完成任务（月视图用） */
export async function clearCompletedMonth(env, userId, rawMonth) {
  const month = normalizeMonth(rawMonth);
  const res = await env.DB.prepare(
    'DELETE FROM todos WHERE user_id = ? AND todo_date >= ? AND todo_date < ? AND done = 1',
  )
    .bind(userId, `${month}-01`, nextMonthStart(month))
    .run();
  return { removed: res?.meta?.changes ?? 0 };
}

export async function toggleAll(env, userId, date, done) {
  const day = normalizeDate(date);
  const res = await env.DB.prepare(
    'UPDATE todos SET done = ?, updated_at = ? WHERE user_id = ? AND todo_date = ?',
  )
    .bind(done ? 1 : 0, nowSeconds(), userId, day)
    .run();
  return { updated: res?.meta?.changes ?? 0 };
}

/**
 * 把某天之前（含指定来源日期）所有未完成的任务顺延到目标日期。
 * 默认：把「今天之前」全部未完成项搬到今天。
 */
export async function carryOver(env, userId, { from = null, to }) {
  const target = normalizeDate(to);
  const ts = nowSeconds();

  let rows;
  if (from) {
    const source = normalizeDate(from);
    const res = await env.DB.prepare(
      'SELECT * FROM todos WHERE user_id = ? AND todo_date = ? AND done = 0 ORDER BY sort_order ASC',
    )
      .bind(userId, source)
      .all();
    rows = res.results || [];
  } else {
    const res = await env.DB.prepare(
      'SELECT * FROM todos WHERE user_id = ? AND todo_date < ? AND done = 0 ORDER BY todo_date ASC, sort_order ASC',
    )
      .bind(userId, target)
      .all();
    rows = res.results || [];
  }

  if (!rows.length) return { moved: 0 };

  const minRow = await env.DB.prepare(
    'SELECT MIN(sort_order) AS min_order FROM todos WHERE user_id = ? AND todo_date = ?',
  )
    .bind(userId, target)
    .first();
  let order = (Number(minRow?.min_order ?? 0) || 0) - 1;

  const stmts = rows.map((row) => {
    const nextOrder = order;
    order -= 1;
    return env.DB.prepare(
      'UPDATE todos SET todo_date = ?, sort_order = ?, updated_at = ? WHERE id = ? AND user_id = ?',
    ).bind(target, nextOrder, ts, row.id, userId);
  });

  await env.DB.batch(stmts);
  return { moved: rows.length };
}

/** 全文搜索（LIKE，转义 %/_），按日期倒序，供前端搜索框使用 */
export async function searchTodos(env, userId, rawQuery, limit = 50) {
  const q = String(rawQuery ?? '').trim().slice(0, 100);
  if (!q) return [];

  const like = `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
  const { results } = await env.DB.prepare(
    `SELECT * FROM todos
      WHERE user_id = ? AND title LIKE ? ESCAPE '\\'
      ORDER BY todo_date DESC, created_at DESC
      LIMIT ?`,
  )
    .bind(userId, like, Math.max(1, Math.min(100, Number(limit) || 50)))
    .all();
  return (results || []).map(toDto);
}

/** 提取标题里的 #标签 并按出现次数排序（个人应用量级，直接扫标题） */
export async function listTags(env, userId, limit = 30) {
  const { results } = await env.DB.prepare('SELECT title FROM todos WHERE user_id = ?')
    .bind(userId)
    .all();

  const counter = new Map();
  for (const row of results || []) {
    const tags = String(row.title || '').match(TAG_RE);
    if (!tags) continue;
    for (const raw of tags) {
      const name = raw.slice(1);
      counter.set(name, (counter.get(name) || 0) + 1);
    }
  }

  return Array.from(counter, ([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'zh-Hans-CN'))
    .slice(0, Math.max(1, Math.min(100, Number(limit) || 30)));
}

/** 统计每个日期的待办数量，用于日历角标 */
export async function statsByDate(env, userId, days = 30) {
  const { results } = await env.DB.prepare(
    `SELECT todo_date AS date,
            SUM(CASE WHEN done = 0 THEN 1 ELSE 0 END) AS remaining,
            COUNT(*) AS total
       FROM todos
      WHERE user_id = ?
      GROUP BY todo_date
      ORDER BY todo_date DESC
      LIMIT ?`,
  )
    .bind(userId, Math.max(1, Math.min(365, Number(days) || 30)))
    .all();
  return (results || []).map((r) => ({
    date: r.date,
    remaining: Number(r.remaining || 0),
    total: Number(r.total || 0),
  }));
}
