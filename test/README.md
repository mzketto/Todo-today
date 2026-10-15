# 今日待办 · todo-today

一个极简的**每日待办清单**，可直接一键部署到 **Cloudflare Workers**，完全无服务器、无固定成本。

> **不想装命令行？** 打开 [docs/cloudflare-网页部署手册.html](./docs/cloudflare-网页部署手册.html)，
> 全程只用浏览器，粘贴一个文件就能部署。

> 演示/预览：直接用浏览器打开 `public/index.html?demo=1`（数据只存在本机浏览器，用于看界面）。

## 功能

**待办**

- 新增任务（**空白任务不会被添加**，自动 trim、限 500 字）
- 勾选 / 取消勾选，已完成的自动沉到列表底部
- 单条删除、一键「清除已完成」
- 实时**剩余计数**（底部常驻：`3 项待完成` / `全部完成 🎉`）
- 行内编辑（长按 / 双击任务文字，或点卡片上的铅笔）
- 日期切换（‹ › / 日期选择器 / 侧栏日历点选），按天隔离
- 「顺延未完成」：把以往所有没做完的事一键挪到今天
- JSON 导出 / 导入（本地备份）

**侧栏与检索（Memos 风格）**

- **侧栏**（桌面常驻、移动端抽屉）：搜索、统计、日历、标签、时间线
- **全文搜索**：跨所有日期找任务（后端 LIKE 查询），结果按日期分组展示
- **#标签**：任务标题里写 `#工作`、`#购物` 即自动成签；侧栏汇总标签与计数，点击即过滤；卡片里点标签徽片同样直达
- **迷你日历**：有任务的日期带圆点角标，点选任意日期直达当天；`‹ ›` 翻月；**点标题查看整月**
- **时间线**：按 年 → 月 聚合任务数，**点击月份打开整月视图**（该月所有任务按日期倒序分组展示，横幅显示月度统计，可一键清除整月已完成）
- **统计卡**：记录天数 / 全部任务 / 已完成
- 快捷键：`/` 聚焦新增，`Ctrl/⌘+K` 聚焦搜索

**账号**

- 用户名 + 密码注册登录，多用户数据完全隔离
- 口令用 **PBKDF2-SHA256**（10 万次迭代 + 16 字节随机盐）派生，绝不存明文
- 登录态用 **HttpOnly Cookie + D1 会话表**，30 天有效
- 支持改密码（改完自动注销其它设备）

**云备份（可自由配置）**

| 方式 | 说明 |
|---|---|
| `r2` | Cloudflare R2 原生绑定，**不需要任何密钥** |
| `s3` | 任意 S3 兼容存储：AWS S3、R2 的 S3 接口、MinIO、阿里云 OSS、Backblaze B2…（Worker 内手写 AWS SigV4，无 SDK 依赖） |
| `webdav` | 任意 WebDAV：坚果云、Nextcloud、群晖、Alist… |

- 支持「立即备份」「从云端恢复」「测试连接」
- 支持「变更后自动备份」，**最短备份间隔可自行设置**：
  不限流 / 1 分钟 / 5 分钟 / 15 分钟 / 30 分钟 / 1 小时 / 6 小时 / 24 小时
- 支持「**定时备份**」（不操作也会备份），周期同样可自选（5 分钟～每天）：
  由 Cloudflare Cron Triggers 驱动 —— wrangler 部署已在 `wrangler.jsonc` 里配好；
  网页控制台部署需手动到 Worker 的 **Settings › Triggers › Cron Triggers** 添加
  `*/5 * * * *`。设置页会显示定时任务的心跳状态，没生效一眼就能看出来
- **文件名带时间戳**（默认开启，可在设置里关闭）：每次备份额外写入一份
  `todo-today.backup.20261015-215730.json` 这样的历史版本，同时始终刷新固定名的
  `todo-today.backup.json` 作为「最新快照」——「从云端恢复 / 测试连接」读的就是这份，
  因此开不开时间戳都不影响恢复。时间戳按你所在时区生成（取 Cloudflare 的请求时区信息）。
  注意：历史文件会随备份次数累积，建议在 R2 / S3 存储端配置生命周期规则自动清理旧备份
- 密钥可以存在页面上，也可以放在 **Worker 环境变量 / 密钥**里（推荐，更安全）

**体验**

- 桌面双栏（侧栏 + 卡片流），移动端单列 + 侧栏抽屉；浅色 / 深色 / 跟随系统三种主题
- PWA manifest，可「添加到主屏幕」当 App 用
- 前端零依赖、零构建，`public/` 目录即静态资源
- 部署后可访问 `/api/health?check=1` 自查数据库表是否建齐

---

## 目录结构

```
todo-today/
├── wrangler.jsonc          # Cloudflare 部署配置（D1 / R2 / 静态资源）
├── schema.sql              # D1 表结构，可重复执行
├── src/
│   ├── index.js            # Worker 入口 + 路由
│   └── lib/
│       ├── http.js         # JSON 响应 / Cookie
│       ├── crypto.js       # PBKDF2、随机 ID、HMAC/SHA256
│       ├── auth.js         # 注册、登录、会话
│       ├── todos.js        # 待办 CRUD 与统计
│       └── backup.js       # 云备份（R2 / S3 SigV4 / WebDAV）
├── public/                 # 静态前端（无构建）
│   ├── index.html
│   ├── style.css
│   ├── app.js
│   ├── icon.svg
│   └── manifest.webmanifest
└── test/                   # 测试
    ├── d1-shim.mjs         # 用 node:sqlite 冒充 D1
    ├── run.mjs             # 26 个用例
    └── fixtures/sigv4/     # AWS 官方 SigV4 测试向量
```

---

## 部署到 Cloudflare（约 5 分钟）

前置：本机装有 Node.js 18+ 与 npm。

```bash
cd todo-today
npm install
npx wrangler login
```

### 1. 创建 D1 数据库

```bash
npx wrangler d1 create todo-today
```

命令会输出一个 `database_id`，把它填进 `wrangler.jsonc`：

```jsonc
"d1_databases": [
  { "binding": "DB", "database_name": "todo-today", "database_id": "<粘贴这里>" }
]
```

### 2. 初始化表结构

```bash
npx wrangler d1 execute todo-today --remote --file=./schema.sql
```

### 3. （可选）启用 R2 原生备份

```bash
npx wrangler r2 bucket create todo-backups
```

然后在 `wrangler.jsonc` 中取消这段注释：

```jsonc
"r2_buckets": [
  { "binding": "BACKUPS", "bucket_name": "todo-backups" }
]
```

> 不想用 R2 也完全可以，用 S3 兼容存储或 WebDAV 做备份即可。

### 4. （可选）把备份密钥放进 Worker 密钥

```bash
npx wrangler secret put BACKUP_S3_SECRET_KEY
npx wrangler secret put BACKUP_WEBDAV_PASSWORD
```

留空直接回车表示不设置；此时密钥就必须在网页的设置面板里填。

### 5. 部署

```bash
npx wrangler deploy
```

完成后会输出形如 `https://todo-today.<你的子域>.workers.dev` 的地址，打开注册一个账号即可开始用。

---

## 本地开发

```bash
npm run db:local      # 在本地 .wrangler 里建表
npm run dev           # 启动 wrangler dev
```

打开 <http://localhost:8787>。

> 需要本地也用上 D1 吗？`wrangler dev` 默认就是本地 SQLite 模拟，直接可用，无需真实 `database_id`。

## 跑测试

```bash
npm test
```

- 用 Node 22 内置的 `node:sqlite` 冒充 D1，把 Worker 的 `fetch()` 全流程跑一遍（注册/登录/增删改查/计数/顺延/导入导出/备份配置/多用户隔离…）
- SigV4 签名部分用 **AWS 官方 `aws-sig-v4-test-suite` 测试向量**做回归，逐字节比对规范请求、待签字符串与最终 Authorization 头

当前 26 个用例全部通过。

---

## 云备份怎么填

### Cloudflare R2（原生绑定）

设置面板选 **Cloudflare R2（原生绑定）**，对象键名留空即可（默认 `todo-today.backup.json`）。
前提是已完成上面第 3 步的 `r2_buckets` 绑定。

### S3 兼容存储

| 字段 | 示例 |
|---|---|
| Endpoint | `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`（R2）<br>`https://s3.us-east-1.amazonaws.com`（AWS）<br>`http://127.0.0.1:9000`（MinIO） |
| Region | R2 填 `auto`；AWS 填如 `us-east-1` |
| Bucket | `todo-backups` |
| Access Key ID / Secret | 在对应平台的 API 令牌页生成 |
| 路径前缀 | 可空，如 `todo/` |
| Path-Style | MinIO 等自建服务一般要勾上；AWS / R2 不勾 |

寻址规则：默认**虚拟主机式** `https://<bucket>.<endpoint 域名>/<key>`；勾选 Path-Style 后为 `https://<endpoint>/<bucket>/<key>`。

### WebDAV

| 字段 | 示例 |
|---|---|
| 目录地址 | 坚果云：`https://dav.jianguoyun.com/dav/我的坚果云/todo`<br>Nextcloud：`https://cloud.example.com/remote.php/dav/files/<用户名>/todo` |
| 用户名 / 密码 | 坚果云需在「安全选项」里生成**应用密码** |

> 目标目录需已存在（WebDAV 一般不会自动建目录）。

---

## 变量与密钥

| 名称 | 类型 | 说明 |
|---|---|---|
| `APP_NAME` | 变量 | 站点名，默认 `今日待办` |
| `ALLOW_REGISTRATION` | 变量 | 设为 `"false"` 可关闭注册（单人自用推荐） |
| `BACKUP_S3_SECRET_KEY` | 密钥 | S3 Secret Access Key 的兜底值 |
| `BACKUP_WEBDAV_PASSWORD` | 密钥 | WebDAV 密码的兜底值 |

页面上填了密钥则优先用页面上的；留空则回落到上面的环境密钥。

---

## API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/health` | 健康检查（是否绑定 DB / R2） |
| `POST` | `/api/auth/register` \| `/login` \| `/logout` | 注册 / 登录 / 退出 |
| `GET` | `/api/auth/me` | 当前用户 |
| `POST` | `/api/auth/password` | 改密码 |
| `GET` | `/api/todos?date=YYYY-MM-DD` | 某天列表 + 剩余计数 |
| `POST` | `/api/todos` | 新增 `{title, date}` |
| `PATCH` | `/api/todos/:id` | 改 `{done?, title?, date?}` |
| `DELETE` | `/api/todos/:id?date=` | 删除 |
| `POST` | `/api/todos/batch` | `clear-completed` / `toggle-all` / `carry-over` / `reorder` |
| `GET` | `/api/todos/stats?days=30` | 按日期统计 |
| `GET/PUT` | `/api/backup/config` | 读取 / 保存备份配置（密钥永不回显） |
| `POST` | `/api/backup/test` \| `/run` \| `/restore` | 测试连接 / 立即备份 / 云端恢复 |
| `GET` | `/api/export` · `POST` `/api/import` | 本地导出 / 导入 |

---

## 安全设计

- 口令：PBKDF2-SHA256，10 万次迭代 + 每用户独立随机盐
- 会话：32 字节 CSPRNG token，仅存于 `HttpOnly; SameSite=Lax` Cookie（HTTPS 下自动加 `Secure`）
- 授权：所有 `/api/*`（除健康检查与认证接口）都要求有效会话，且每条 SQL 都带 `user_id` 过滤
- 密钥：备份密钥写入后**永不回显**给前端，只返回「已配置 / 来自环境变量」的布尔标记
- XSS：前端所有动态文本走 `textContent`，不拼 HTML

## 常见问题

**Q: 注册时报 `D1_ERROR: no such table: users: SQLITE_ERROR`？**
数据库建好了，但**表还没建**。这一条最常见，补上第 2 步即可：

```bash
npx wrangler d1 execute todo-today --remote --file=./schema.sql
```

如果你是在 Cloudflare 网页控制台部署的，去 **D1 → 选中该数据库 → Console 标签页**，
把 `schema.sql` 全文粘进去点 Execute。执行完访问 `/api/health?check=1`，
看到 `"schema":{"ok":true,...}` 就说明表齐了。

> 注意别在「本地实例 / Local」里执行——要选远程的那个数据库，否则线上还是空表。

**Q: 怎么确认后台是否健康？**
访问 `/api/health` 看绑定，访问 `/api/health?check=1` 会真的连一次库并列出缺失的表。

**Q: 部署后打开是登录页但注册报错？**
先确认第 2 步的建表命令在 `--remote` 上执行过；看日志：`npx wrangler tail`。

**Q: 想改成只给自己用？**
在 `wrangler.jsonc` 里把 `ALLOW_REGISTRATION` 设为 `"false"`，然后用第一个注册的账号登录即可（注册第一个账号后再改也来得及）。

**Q: 备份文件里有什么？**
完整 JSON：`{ app, version, exportedAt, user, stats, todos[] }`，可直接被「导入 JSON」或「从云端恢复」读回。

**Q: 想换成别的 S3 服务 / 自建 MinIO？**
直接在设置面板改 Endpoint 与 Bucket，勾上 Path-Style，点「测试连接」验证即可，无需改代码。
