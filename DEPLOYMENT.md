# Cloudflare Workers 部署指南（含管理端登录与导入）

本指南介绍如何将 NFC 产品防伪系统部署到 Cloudflare Workers（含静态页面、API、D1 数据库、管理员登录鉴权与 Excel/CSV 导入）。

## 1. 前提条件
- Cloudflare 账号与已接入 `plearance.com` 域名
- 已创建 D1 数据库并获取 `database_id`
- GitHub 仓库与配置了 Secrets：`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`
- 设置管理端凭据（可在 `wrangler.toml [vars]` 中配置或通过 `wrangler secret`）

## 2. 关键文件
- `wrangler.toml`：Worker 配置（静态资源、D1 绑定、自定义域）
- `worker/index.js`：Worker 端 API 逻辑与静态资源路由
- `migrations/0001_init.sql`：D1 初始结构（`products`, `scan_records`）
- `migrations/0002_admin_tokens.sql`：D1 登录令牌表（`admin_tokens`）
- `migrations/0003_seed_from_sqlite.sql`：由脚本生成的数据导入 SQL
- `.github/workflows/deploy-worker.yml`：GitHub Actions 自动部署
- `scripts/export_sqlite_to_sql.js`：从本地 SQLite 导出数据到 D1 的 SQL 脚本

## 3. wrangler.toml 关键配置
```toml
name = "nfc-verification-worker"
main = "worker/index.js"
compatibility_date = "2024-10-31"
workers_dev = true
# logpush disabled for non-Enterprise accounts
# logpush = false
compatibility_flags = ["nodejs_compat"]

routes = [
  { pattern = "verify.plearance.com/*", zone_name = "plearance.com" }
]

[vars]
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
ADMIN_TOKEN_TTL_HOURS = "24"

[assets]
directory = "./public"

[[d1_databases]]
binding = "DB"
database_name = "NFC_DB"
database_id = "<your-d1-id>"

migrations_dir = "migrations"
```

- `compatibility_flags = ["nodejs_compat"]`：替代旧的 `node_compat` 以消除弃用警告
- `[assets]`：自动服务 `public/` 静态资源（支持 `/admin-login.html` 等）
- 路径重写：Worker 内置将 `/admin-login` 重写到 `/admin-login.html`，`/admin-dashboard` 重写到 `/admin-dashboard.html`
- 注意：`logpush` 为企业功能，标准账户请勿启用，否则部署会报错（代码 10023）

## 4. 管理端 API（Worker）
- `POST /api/admin/login`
  - Body: `{ username, password }`
  - 返回: `{ token, expiresAt }`
- `GET /api/admin/verify`
  - Header: `Authorization: Bearer <token>`
  - 返回: `{ success: true }`
- `GET /api/admin/stats`
  - Header: `Authorization: Bearer <token>`
  - 返回: `{ products: [...] }`（含扫描次数、国家绑定信息）
- `POST /api/admin/products`
  - Header: `Authorization: Bearer <token>`
  - Body: `{ nfcCode, productName, isAuthentic }`
  - 返回: `{ success: true }`
- `POST /api/admin/products/import`
  - Header: `Authorization: Bearer <token>`
  - FormData: `excelFile=<Excel或CSV文件>`
  - 返回: `{ successCount, errorCount, errors, message }`

## 5. 验证接口（Worker）
- `POST /api/verify/:nfcCode`：记录扫描并返回产品真实性、总扫描次数与国家信息
- `GET /api/test/ip-location`：返回客户端 IP与国家（基于 `request.cf.country`）

## 6. D1 迁移与导入
1. 执行迁移（创建表）
   - 本地或 CI 中运行：
     - `npm run db:migrate`
2. 从本地 SQLite 导出数据到 D1 SQL
   - 如果本地有 `nfc_verification.db` 或 `database.db`：
     - `node scripts/export_sqlite_to_sql.js [可选：sqlite路径]`
     - 生成文件：`migrations/0003_seed_from_sqlite.sql`
3. 导入到 D1：
   - `npm run db:seed`

## 7. 自定义域名 `verify.plearance.com`
1. 在 `wrangler.toml` 添加 `routes`（见第3节）
2. Cloudflare DNS 为 `verify` 子域添加代理启用记录（橙云）
3. 推送到 `main` 分支，GitHub Actions 将自动部署到自定义域

## 8. Excel/CSV 导入说明
- 支持 `.xlsx`（首个工作表）与 `.csv`（逗号分隔，首行表头）
- 识别字段：`nfc_code` / `NFC_CODE` / `NFC`，`product_name` / `PRODUCT_NAME` / `name`，`is_authentic`（1/0）
- 失败会返回 `errors` 列表；已存在的 `nfc_code` 将被忽略（`INSERT OR IGNORE`）

## 9. 示例调用
- 登录：
  ```bash
  curl -X POST https://verify.plearance.com/api/admin/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"admin123"}'
  ```
- 导入（Excel/CSV）：
  ```bash
  curl -X POST https://verify.plearance.com/api/admin/products/import \
    -H "Authorization: Bearer <TOKEN>" \
    -F excelFile=@products.xlsx
  ```
- 单个添加：
  ```bash
  curl -X POST https://verify.plearance.com/api/admin/products \
    -H "Authorization: Bearer <TOKEN>" \
    -H 'Content-Type: application/json' \
    -d '{"nfcCode":"NFC999","productName":"示例产品","isAuthentic":1}'
  ```
- 查看统计：
  ```bash
  curl -X GET https://verify.plearance.com/api/admin/stats \
    -H "Authorization: Bearer <TOKEN>"
  ```

## 10. 常见问题
- 访问 `/admin-login` 404：确保部署的是 Worker+Assets（已在 Worker 内做了路径重写）
- XLSX 解析失败：检查文件是否有效 Excel；或改用 CSV 导入
- D1 执行失败：确认 `database_id` 正确、迁移已执行、SQL 中无非法字符

## 11. 下一步
- 按需迁移更多管理端能力（分页、搜索、导出等）
- 优化统计口径（日期范围、按国家汇总、Top N 等）