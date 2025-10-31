# NFC验证系统 - Cloudflare Workers部署指南

## 🏗️ 架构概述

这个部署方案将NFC验证系统分为两个部分：
- **Cloudflare Workers**: 处理API请求和业务逻辑
- **Cloudflare Pages**: 托管静态文件（HTML, CSS, JS）
- **Cloudflare D1**: 替代SQLite数据库
- **Cloudflare KV**: 用于缓存和速率限制

## 📋 部署前准备

### 1. 安装Wrangler CLI
```bash
npm install -g wrangler
```

### 2. 登录Cloudflare
```bash
wrangler login
```

### 3. 安装依赖
```bash
# 重命名package文件
mv package-worker.json package.json
npm install
```

## 🗄️ 数据库设置

### 1. 创建D1数据库
```bash
wrangler d1 create nfc-verification-db
```

### 2. 更新wrangler.toml
将返回的database_id填入`wrangler.toml`中的`database_id`字段。

### 3. 初始化数据库
```bash
wrangler d1 execute nfc-verification-db --file=./schema.sql
```

### 4. 验证数据库
```bash
wrangler d1 execute nfc-verification-db --command="SELECT * FROM products LIMIT 5;"
```

## 🔑 KV命名空间设置

### 1. 创建KV命名空间
```bash
wrangler kv:namespace create "CACHE"
wrangler kv:namespace create "CACHE" --preview
```

### 2. 更新wrangler.toml
将返回的ID填入相应字段。

## ⚙️ 环境变量配置

在`wrangler.toml`中更新以下变量：
```toml
[vars]
ADMIN_USERNAME = "your-admin-username"
ADMIN_PASSWORD = "your-secure-password"
JWT_SECRET = "your-jwt-secret-key"
```

## 🚀 部署步骤

### 1. 部署Worker
```bash
wrangler deploy
```

### 2. 部署静态文件到Pages

#### 方法A: 通过Wrangler
```bash
wrangler pages deploy public --project-name=verify-plearance
```

#### 方法B: 通过Cloudflare Dashboard
1. 登录Cloudflare Dashboard
2. 进入Pages部分
3. 创建新项目，项目名称：verify-plearance
4. 上传`public`文件夹内容

### 3. 配置自定义域名
1. 在Cloudflare Dashboard中进入您的域名 `plearance.com`
2. 为Worker配置子域名：`nfc-verification-worker.verify.plearance.com`
3. 为Pages配置主域名：`verify.plearance.com`

## 🔧 配置说明

### Worker配置 (wrangler.toml)
- `name`: Worker名称
- `main`: 入口文件
- `compatibility_date`: 兼容性日期
- `d1_databases`: D1数据库绑定
- `kv_namespaces`: KV存储绑定
- `vars`: 环境变量

### Pages配置
- `_headers`: HTTP头配置
- `_redirects`: 路由重定向配置

## 🧪 测试部署

### 1. 测试API端点
```bash
# 测试产品验证
curl -X POST "https://nfc-verification-worker.verify.plearance.com/api/verify/NFC001"

# 测试管理员登录
curl -X POST "https://nfc-verification-worker.verify.plearance.com/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### 2. 测试静态页面
访问：
- `https://verify.plearance.com/` - 主页
- `https://verify.plearance.com/admin-login` - 管理员登录
- `https://verify.plearance.com/verify/NFC001` - 产品验证

## 📊 监控和日志

### 1. 查看Worker日志
```bash
wrangler tail
```

### 2. 查看分析数据
在Cloudflare Dashboard的Analytics部分查看请求统计。

## 🔄 更新部署

### 更新Worker代码
```bash
wrangler deploy
```

### 更新静态文件
```bash
wrangler pages deploy public
```

### 更新数据库结构
```bash
wrangler d1 execute nfc-verification-db --file=./migration.sql
```

## 🚨 故障排除

### 常见问题

1. **数据库连接失败**
   - 检查`wrangler.toml`中的database_id是否正确
   - 确认数据库已正确初始化

2. **CORS错误**
   - 检查`_headers`文件配置
   - 确认API路由正确重定向到Worker

3. **认证失败**
   - 检查JWT_SECRET环境变量
   - 确认管理员凭据正确

4. **速率限制问题**
   - 检查KV命名空间配置
   - 调整速率限制参数

### 调试命令
```bash
# 查看Worker日志
wrangler tail

# 测试本地开发
wrangler dev

# 检查D1数据库
wrangler d1 execute nfc-verification-db --command="SELECT COUNT(*) FROM products;"
```

## 💰 成本估算

Cloudflare的免费套餐包括：
- Workers: 100,000 请求/天
- Pages: 无限静态请求
- D1: 5GB存储，25M行读取/月
- KV: 100,000 读取/天，1,000 写入/天

对于大多数中小型应用，免费套餐已经足够使用。

## 🔒 安全建议

1. **更改默认凭据**: 修改默认的管理员用户名和密码
2. **使用强JWT密钥**: 生成复杂的JWT_SECRET
3. **启用WAF**: 在Cloudflare中启用Web应用防火墙
4. **监控异常**: 设置告警监控异常请求
5. **定期备份**: 定期导出D1数据库数据

## 📞 支持

如果遇到问题，可以：
1. 查看Cloudflare Workers文档
2. 检查Cloudflare社区论坛
3. 查看项目的GitHub Issues

---

部署完成后，您的NFC验证系统将具备：
- ✅ 全球CDN加速
- ✅ 自动扩展
- ✅ 高可用性
- ✅ 低延迟
- ✅ 成本效益