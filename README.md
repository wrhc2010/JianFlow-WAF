# 鉴流（JianFlow WAF）

鉴流是一个面向自托管场景的 Web 应用防火墙。它把本地规则、Jev AI 判断和可追溯的请求事件放在同一条防护链路里，适合需要自己掌握数据、策略和部署方式的团队。

[![License: MIT](https://img.shields.io/github/license/wrhc2010/JianFlow-WAF)](LICENSE)
[![Release](https://img.shields.io/github/v/release/wrhc2010/JianFlow-WAF)](https://github.com/wrhc2010/JianFlow-WAF/releases)
[![CI](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml/badge.svg)](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml)
[![Node.js 22](https://img.shields.io/badge/Node.js-22-339933)](package.json)

**中文** | [English](README.en.md)

项目提供三种防护模式：

- **传统规则**：只使用本地规则引擎，行为稳定、延迟低。
- **AI 判断**：使用 Jev 返回的恶意概率和拦截阈值做决策。
- **混合模式**：先用本地规则拦截明显攻击，再让 Jev 复核剩余请求。

这不是一个“开箱即替代所有安全设备”的黑盒。正式接入生产流量前，仍应结合自身业务做安全审计、压力测试和灰度验证。

## 这版重点

`v0.2.0` 是一次从原型走向可持续试运行的升级，重点解决了请求检查不完整、统计口径不清楚和初次部署门槛高的问题：

- 全量事件统计，支持游标分页、搜索、动作、IP 和时间筛选。
- 10%、30%、50%、70%、90% 五档阈值，并支持自定义阈值。
- 检查路径、查询参数、请求头、Cookie、IP 和完整请求体。
- 支持 JSON、表单、XML、multipart、纯文本，以及 gzip、deflate 和 brotli 请求体。
- 对重复编码、Unicode 变体、危险 URL、内网目标和常见注入语法做规范化检查。
- 支持 JSON 和常见 ModSecurity `SecRule` 规则导入，提供预览、校验、冲突处理和原子写入。
- WebUI 提供初始化、登录、规则库、Jev 配置、事件中心、2D 地图和 3D 攻击地球。
- GeoIP 使用操作方提供的 MaxMind City/ASN MMDB 文件，不依赖在线 IP 查询。

## 看一眼

![鉴流控制台的实际运行截图](docs/images/console.png)

登录后可以查看请求事件、切换防护模式、测试规则、修改上游地址，并在攻击大屏中查看 2D/3D 统计视图。

## 本地开发

需要 Node.js 22 或更高版本。

```bash
npm install
cp .env.example .env
npm run dev
```

启动后可以访问：

- 管理后台：`http://127.0.0.1:3000`
- API：`http://127.0.0.1:4000`
- WAF HTTP 入口：`http://127.0.0.1:8080`

没有设置 `DATABASE_URL` 时，API 会使用 `DATA_DIR` 下的 SQLite 文件保存设置、规则和事件，适合本地试运行。首次打开 WebUI 只需要设置管理员密码，Jev key、模型和 GeoIP 都可以之后再配置。

## Docker Compose

```bash
cp .env.example .env
mkdir -p secrets
printf 'replace-with-a-long-random-password\n' > secrets/postgres_password
docker compose up -d --build
```

Windows PowerShell 可以这样创建密码文件：

```powershell
New-Item -ItemType Directory -Force secrets | Out-Null
Set-Content -NoNewline secrets/postgres_password 'replace-with-a-long-random-password'
docker compose up -d --build
```

服务地址：

- 管理后台：`http://服务器地址:3000`
- API：`http://服务器地址:4000`
- WAF：`http://服务器地址:8080`

Compose 使用 Docker secret 提供 PostgreSQL 密码，不把默认数据库口令写进 compose 文件。也可以通过 `POSTGRES_PASSWORD_FILE_SOURCE` 指向现有的 secret 文件；如果显式设置 `DATABASE_URL`，API 会优先使用它。

默认上游地址是 `http://host.docker.internal:9000`。如果被保护服务也运行在 Compose 网络中，把 `UPSTREAM_URL` 改成对应的服务名，例如 `http://app:8080`。Compose 会持久化 PostgreSQL 数据和 API 数据目录；GeoIP 文件通过 `GEOIP_DIR` 挂载。

## HTTPS 和 WebSocket

将证书目录挂载到 `TLS_CERT_DIR`，并在 `.env` 中设置容器内路径：

```dotenv
TLS_CERT_DIR=./certs
TLS_KEY_PATH=/app/certs/tls.key
TLS_CERT_PATH=/app/certs/tls.crt
```

HTTPS 入口是 `8443`。WebSocket 握手也会进入 WAF 决策管线，确认升级成功后再透传连接。

## Jev 配置

Jev 可以通过环境变量配置，也可以在 WebUI 的“防护策略”中配置。WebUI 保存的 key 会使用 `SESSION_SECRET` 加密后写入数据库；接口只返回是否已配置以及 key 的来源，不会回显明文。

```dotenv
JEV_API_KEY=your-jev-key
JEV_MODEL=typesafe/jev-1.13
JEV_BASE_URL=https://openrouter.ai
```

`JEV_BASE_URL` 同时接受供应商根地址和完整决策接口地址，例如：

- `https://openrouter.ai`
- `https://provider.example.com/api/alpha/decisions`
- `https://provider.example.com/api/v1/decisions`

没有 key 时仍然可以完成首次初始化。AI 模式在 Jev 不可用时会记录错误并阻断；混合模式会在传统规则通过后按传统结果降级，同时保留 AI 不可用信息。

默认阈值如下：

| 强度 | Jev 概率达到该值时拦截 |
| --- | ---: |
| 极低 | 10% |
| 低 | 30% |
| 中 | 50% |
| 高 | 70% |
| 极高 | 90% |
| 自定义 | 0% - 100% |

发送给 Jev 的内容会按字段脱敏：凭据请求头、常见敏感查询参数、JSON 和表单字段会遮蔽值；XML、纯文本和 multipart body 会在限制范围内参与检查。脱敏不是隐私保证，不要把真实客户数据直接用于测试。

## 初始化、规则和 GeoIP

首次进入 WebUI 会显示初始化页面，只要求设置管理员密码。初始化完成后，可以在“防护策略”中调整模式、阈值、模型、base URL 和 API key，也可以在“规则库”中测试、启停和导入规则。

规则导入支持：

- 严格 JSON 规则数组，或包含 `rules` 数组的 JSON 对象。
- 常见 ModSecurity `SecRule`，包括请求变量、常用 operator、转换和 `deny`/`log` 动作。
- 导入前预览、字段校验、正则安全检查、重复 ID 检查和冲突策略。

导入器不执行任意脚本，也不会把不支持的 ModSecurity 语义静默转换成另一种行为。每次导入和规则总数都有上限。

GeoIP 使用本地 MMDB 文件：

- City：`GeoIP2-City.mmdb`
- ASN：`GeoIP2-ASN.mmdb`

可以把文件放在 `DATA_DIR/geoip`，也可以通过 `GEOIP_DATABASE_PATH` 和 `GEOIP_ASN_DATABASE_PATH` 分别指定路径。没有数据库时，地图仍然可用，但来源会显示为“未知地区”。2D 地图轮廓来自随前端依赖分发的离线 Natural Earth-derived `world-atlas` 数据。

## 防护边界

请求体默认最多接收 10 MB。WAF 会在检查前解压 gzip、deflate 和 brotli，并拒绝无法完整检查的请求，包括格式错误的 JSON/XML、非法 UTF-8、multipart 解析失败、压缩层过多和解压后超限。

只有来自 `TRUSTED_PROXY_CIDRS` 的连接才会采用 `X-Forwarded-For`。代理会清理客户端伪造的路由和转发头，并拒绝 HTTP/0.9、冲突的 Content-Length/Transfer-Encoding 以及不支持的传输编码。

统计口径是：

```text
总计 = 已放行 + 已拦截 + 错误
```

一个请求只保存一个最终事件，避免先记录 allow、再记录上游 error 造成重复统计。

## 验证

```bash
npm run typecheck
npm run build
npm test
```

传统规则测试：

```bash
curl -X POST http://127.0.0.1:4000/api/v1/rules/test \
  -H 'content-type: application/json' \
  -d '{"method":"GET","path":"/search","query":"?q=union+select+password+from+users","headers":{}}'
```

管理 API 需要先通过 `/api/v1/auth/login` 获取 HttpOnly 会话 Cookie。正式版验证还覆盖 PostgreSQL 迁移、重启持久化、压缩请求、请求头攻击、可信代理 IP、规则导入原子性、2D/3D 地图和 WebGL 回退。

## 项目结构

```text
apps/api           Fastify 管理 API、WAF 代理、数据库和 GeoIP
apps/web           React + Vite 管理后台
packages/waf-core  规则引擎、请求规范化和安全正则
```

规则包和离线地图的授权边界见 [`packages/waf-core/RULES.md`](packages/waf-core/RULES.md)。

## 许可证

项目代码与文档采用 MIT 许可证。规则包和离线地图的授权边界见 [`packages/waf-core/RULES.md`](packages/waf-core/RULES.md)；第三方依赖仍以各自许可证为准。
