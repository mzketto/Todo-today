-- ============================================================
--  今日待办 · Cloudflare D1 数据库结构
--  初始化：
--    本地  npx wrangler d1 execute todo-today --local  --file=./schema.sql
--    线上  npx wrangler d1 execute todo-today --remote --file=./schema.sql
--  该脚本可重复执行（IF NOT EXISTS），不会清空已有数据。
-- ============================================================

-- 用户
CREATE TABLE IF NOT EXISTS users (
  id            TEXT    PRIMARY KEY,
  username      TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,          -- PBKDF2-SHA256 派生结果（hex）
  salt          TEXT    NOT NULL,          -- 随机盐（hex）
  created_at    INTEGER NOT NULL           -- Unix 秒
);

-- 登录会话（HttpOnly Cookie 里的 token 指向这里）
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT    PRIMARY KEY,
  user_id    TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);

-- 待办事项
CREATE TABLE IF NOT EXISTS todos (
  id         TEXT    PRIMARY KEY,
  user_id    TEXT    NOT NULL,
  title      TEXT    NOT NULL,
  done       INTEGER NOT NULL DEFAULT 0,   -- 0 未完成 / 1 已完成
  todo_date  TEXT    NOT NULL,             -- 归属日期 YYYY-MM-DD
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_todos_user_date ON todos (user_id, todo_date);
CREATE INDEX IF NOT EXISTS idx_todos_user_done ON todos (user_id, done);

-- 用户设置（云备份配置等）
CREATE TABLE IF NOT EXISTS settings (
  user_id     TEXT    PRIMARY KEY,
  backup_json TEXT,                        -- 备份配置 JSON
  last_backup INTEGER,                     -- 上次备份时间（Unix 秒，用于自动备份节流）
  updated_at  INTEGER NOT NULL
);
