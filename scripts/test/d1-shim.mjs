/**
 * 最小可用的 D1 兼容层，基于 Node 22 内置的 node:sqlite。
 * 仅用于本地测试与 `npm test`，不参与 Worker 部署。
 */

import { DatabaseSync } from 'node:sqlite';

function sanitize(params) {
  return params.map((p) => {
    if (p === undefined) return null;
    if (typeof p === 'boolean') return p ? 1 : 0;
    if (typeof p === 'bigint') return Number(p);
    return p;
  });
}

class Statement {
  constructor(db, sql, params = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }

  bind(...params) {
    return new Statement(this.db, this.sql, sanitize(params));
  }

  async first(column) {
    const row = this.db.prepare(this.sql).get(...this.params);
    if (row === undefined || row === null) return null;
    return column ? row[column] ?? null : row;
  }

  async all() {
    const results = this.db.prepare(this.sql).all(...this.params);
    return { results, success: true, meta: { duration: 0, changes: 0, rows_read: results.length } };
  }

  async run() {
    const info = this.db.prepare(this.sql).run(...this.params);
    return {
      success: true,
      meta: {
        duration: 0,
        changes: Number(info.changes ?? 0),
        last_row_id: Number(info.lastInsertRowid ?? 0),
      },
    };
  }
}

export function createD1(path = ':memory:') {
  const raw = new DatabaseSync(path);
  return {
    prepare(sql) {
      return new Statement(raw, sql);
    },
    async batch(statements) {
      const out = [];
      for (const stmt of statements) out.push(await stmt.run());
      return out;
    },
    async exec(sql) {
      raw.exec(sql);
      return { count: 0, duration: 0 };
    },
    /** 测试专用：拿到底层 DatabaseSync */
    _raw: raw,
  };
}
