# 鉴流（JianFlow WAF）

基于 Jev AI 判断与传统规则引擎的三模式 WAF 原型：

> 此项目用于功能演示与实验，尚未经过安全审计、压力测试或生产部署验证。不要直接用于保护生产站点。

- `AI 判断`：使用 Jev 返回的 `noul` 恶意概率和拦截阈值。
- `传统规则`：使用本地 OWASP CRS 风格规则子集。
- `混合模式`：先运行本地规则，再由 Jev 复核。

## 本地开发

```bash
npm install
cp .env.example .env
npm run dev
```

- 管理后台：`http://127.0.0.1:3000`
- API：`http://127.0.0.1:4000`
- WAF HTTP 入口：`http://127.0.0.1:8080`
- 默认管理员：由 `ADMIN_USER` 和 `ADMIN_PASSWORD` 配置

没有 `DATABASE_URL` 时使用内存存储，适合快速试运行。Linux 长期运行建议启用 PostgreSQL。

## Docker Compose

```bash
cp .env.example .env
# 编辑 .env，至少修改 ADMIN_PASSWORD、SESSION_SECRET 和 OPENROUTER_API_KEY
docker compose up -d --build
```

- 管理后台：`http://服务器地址:3000`
- API：`http://服务器地址:4000`
- WAF：`http://服务器地址:8080`

默认 Compose 上游地址是 `http://host.docker.internal:9000`。如果被保护服务也运行在 Compose 中，将 `UPSTREAM_URL` 改成对应服务名，例如 `http://app:8080`。

## HTTPS

将证书挂载到 `TLS_CERT_DIR`，并在 `.env` 中设置容器内路径：

```dotenv
TLS_CERT_DIR=./certs
TLS_KEY_PATH=/app/certs/tls.key
TLS_CERT_PATH=/app/certs/tls.crt
```

HTTPS 入口是 `8443`。WebSocket 握手同样进入 WAF 决策管线，升级后的消息按原连接透传。

## Jev 配置

密钥只通过服务端环境变量注入：

```dotenv
OPENROUTER_API_KEY=your-openrouter-key
OPENROUTER_MODEL=typesafe/jev-1.13
```

后台可以切换到 `~typesafe/jev-latest`。首版默认阈值：

| 强度 | Jev 概率 |
| --- | ---: |
| 低 | 50% |
| 中 | 70% |
| 高 | 85% |
| 极高 | 95% |
| 自定义 | 0% - 100% |

发送给 Jev 的内容按字段脱敏：凭据请求头与常见查询参数、JSON 或表单字段的敏感值会被遮蔽；其他格式的请求体不发送。脱敏不是隐私保证，切勿用真实客户数据测试。

## 验证

```bash
npm run typecheck
npm run build
npm test -w packages/waf-core
npm test -w apps/api
```

传统规则测试：

```bash
curl -X POST http://127.0.0.1:4000/api/v1/rules/test \
  -H 'content-type: application/json' \
  -d '{"method":"GET","path":"/search","query":"?q=union+select+password+from+users","headers":{}}'
```

管理 API 需要先通过 `/api/v1/auth/login` 获取 HttpOnly 会话 Cookie。
