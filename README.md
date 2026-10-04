# 鉴流（JianFlow WAF）

鉴流是一个面向 Linux 自托管的 Web 应用防火墙，以本地规则为基础，可选接入 Jev AI。它按端口管理多个站点，提供站点策略、限速和请求事件，适合希望查看、修改防护代码的开发者和小团队。

[![License: MIT](https://img.shields.io/github/license/wrhc2010/JianFlow-WAF)](LICENSE)
[![Release](https://img.shields.io/github/v/release/wrhc2010/JianFlow-WAF)](https://github.com/wrhc2010/JianFlow-WAF/releases)
[![CI](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml/badge.svg)](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml)
[![Node.js 22](https://img.shields.io/badge/Node.js-22-339933)](package.json)

**中文** | [English](README.en.md)

项目提供三种防护模式：

- **传统规则**：只使用本地规则引擎，行为稳定、延迟低。
- **AI 判断**：使用 Jev 返回的风险分数和拦截阈值做决策，强制访问控制和协议限制仍然生效。
- **混合模式**：先检查本地规则，默认只让 Jev 复核规则记录的可疑请求，也可选择全部请求或影子评估。

这不是一个“开箱即替代所有安全设备”的黑盒。正式接入生产流量前，仍应结合自身业务做安全审计、压力测试和灰度验证。

## 这版重点

`v0.2.2` 增加了站点策略和误报调优，并修复 HTTPS 启停、AI 响应校验及出站脱敏问题：

- 站点按监听端口区分入口，默认可用端口为 `8080-8099`，每个端口可以指向不同上游并使用不同防护模式。
- “防护策略”和站点表单都采用草稿 + 保存/取消，避免输入过程中直接改动服务端配置。
- 没有配置 Jev key 时，AI 和混合模式在 WebUI 中不可选，API 也会回退到传统规则。
- 固定侧边栏高度，右侧内容独立滚动；站点页面改为卡片网格，适合查看多个入口。
- 站点可继承全局策略或独立配置阈值、观察模式、停用规则和 AI 行为。
- 按站点、方法、完整路径、字段和规则 ID 配置有期限的精确例外，支持样本回放；访问控制和业务 CC 限速不受例外或观察模式影响。
- 事件记录站点、策略版本、命中字段及检查范围；详情按保留天数清理，独立计数保留历史总计。
- 10%、30%、50%、70%、90% 五档拦截阈值及自定义值。阈值越低，拦截越多，已有数值不变。
- 检查路径、查询参数、请求头、Cookie、IP 和完整请求体。
- 支持 JSON、表单、XML、multipart、纯文本，以及 gzip、deflate 和 brotli 请求体。
- 对重复编码、Unicode 变体、危险 URL、内网目标和常见注入语法做规范化检查。
- 支持 JSON 和常见 ModSecurity `SecRule` 规则导入，提供预览、校验、冲突处理和原子写入。
- WebUI 提供初始化、登录、规则库、Jev 配置、事件中心、2D 地图和 3D 攻击地球。
- GeoIP 使用操作方提供的 MaxMind City/ASN MMDB 文件，不依赖在线 IP 查询。

## 看一眼

![鉴流控制台的实际运行截图](docs/images/console.png)

登录后可以查看请求事件、切换防护模式、测试规则、修改上游地址，并在攻击大屏中查看 2D/3D 统计视图。

## 在 Linux 上部署

以下步骤面向 Linux 服务器，命令使用 Bash，配置对应 `v0.2.2`。先准备一套测试环境，再接入真实业务。完整变更见 [更新日志](CHANGELOG.md)。

需要 Git、curl、OpenSSL，以及已安装并运行的 Docker Engine 和 Docker Compose v2。使用容器部署不需要在宿主机安装 Node.js。

### 获取代码和准备配置

```bash
git clone https://github.com/wrhc2010/JianFlow-WAF.git
cd JianFlow-WAF
cp .env.example .env
chmod 600 .env
mkdir -p secrets certs geoip
chmod 700 secrets
openssl rand -hex 32 > secrets/postgres_password
chmod 644 secrets/postgres_password
```

密码文件需要能被容器中的 PostgreSQL 用户读取，所以使用 `644`；宿主机上的 `secrets` 目录使用 `700`，限制其他普通用户访问。上述密码生成命令只在首次部署时执行，已有数据库不要重新生成密码。

编辑 `.env`，把上游和 GeoIP 路径改为容器可访问的地址：

```dotenv
UPSTREAM_URL=http://host.docker.internal:9000
SITE_PORT_RANGE=8080-8099
GEOIP_DIR=./geoip
GEOIP_DATABASE_PATH=/app/geoip/GeoIP2-City.mmdb
GEOIP_ASN_DATABASE_PATH=/app/geoip/GeoIP2-ASN.mmdb
```

`host.docker.internal` 已在 Compose 中映射到宿主机网关。Linux 上的上游服务必须监听容器可访问的宿主机地址，不能只监听 `127.0.0.1`；同时用访问控制限制上游入口。如果上游也在同一个容器网络中，使用服务名，例如 `UPSTREAM_URL=http://app:8080`。**容器内的 `127.0.0.1` 指向容器自身，不是宿主机。**

`ADMIN_PASSWORD` 和 `SESSION_SECRET` 可以留空。首次打开后台时设置管理员密码；会话密钥会自动生成并保存在持久化数据目录中。Jev 和 GeoIP 可以稍后配置。

### 启动和检查

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:4000/api/v1/health
```

等待服务健康检查通过后，健康接口应返回包含 `"ok": true` 的 JSON。管理端口默认只绑定服务器回环地址；远程管理可先建立 SSH 隧道：

```bash
ssh -L 3000:127.0.0.1:3000 user@server
```

随后在本地浏览器打开 `http://127.0.0.1:3000` 完成初始化。`/api/v1/health/live` 检查进程存活，`/api/v1/health/ready` 检查启用入口及策略版本是否实际应用。

| 入口 | 端口 | 用途 |
| --- | ---: | --- |
| 管理后台 | 3000 | 初始化、规则和事件管理 |
| 管理 API | 4000 | 健康检查和管理接口 |
| WAF HTTP | 8080-8099 | 按站点分配的 HTTP 入口 |
| WAF HTTPS | 8443 | 配置证书后使用 |

Compose 将 `3000` 和 `4000` 绑定到 `127.0.0.1`，WAF 入口发布到所有接口，PostgreSQL 不对宿主机开放。需要远程多人管理时，使用受控的 HTTPS 反向代理；不要直接把管理端口暴露到公网。

Compose 使用文件型 Docker secret 提供 PostgreSQL 密码。可以通过 `POSTGRES_PASSWORD_FILE_SOURCE` 指向已有密码文件；显式设置 `DATABASE_URL` 时，API 会优先使用它。PostgreSQL 数据和 API 数据目录由命名卷持久化，GeoIP 文件从宿主机 `GEOIP_DIR` 只读挂载。

### 配置多个入口

默认站点固定使用 `8080`。在“站点与上游”页面新建站点时，从当前范围内选择未占用端口，填写上游地址和防护模式。保存后动态应用监听器；卡片分别显示期望版本和实际版本，端口占用或证书加载失败会显示应用失败，可重试。停用默认站点会同时关闭其 HTTP 和 HTTPS 入口。

站点可继承全局策略，也可覆盖阈值、执行方式、停用规则、AI 数据范围和限速。观察模式保留命中及“原本会拦截”的记录，但不阻断检测命中；强制 ACL、协议校验、正文上限和 CC 限速仍会拒绝请求。限速是单进程内的每站点、每 IP 令牌桶和并发限制，不是分布式限流或 Bot 挑战。

`SITE_PORT_RANGE` 只在部署启动时读取，范围必须包含默认入口 `8080`。例如扩展到 `8080-8109`，修改 `.env` 后重启；仓库中的 Compose 会按这个变量发布端口。如果使用了自定义端口映射，也要同步调整：

```dotenv
SITE_PORT_RANGE=8080-8109
```

默认站点仍要求使用 `PROXY_PORT`，默认值是 `8080`；自定义范围应包含这个端口。

### 使用发布镜像

不想在服务器构建时，可以从 [v0.2.2 Release](https://github.com/wrhc2010/JianFlow-WAF/releases/tag/v0.2.2) 下载 API 和 Web 镜像压缩包。先按上面的步骤准备配置和密码文件，再导入镜像：

```bash
sha256sum -c jianflow-waf-api-v0.2.2.tar.gz.sha256
sha256sum -c jianflow-waf-web-v0.2.2.tar.gz.sha256
docker load -i jianflow-waf-api-v0.2.2.tar.gz
docker load -i jianflow-waf-web-v0.2.2.tar.gz
IMAGE_TAG=v0.2.2 docker compose up -d --no-build --pull never
```

`--pull never` 不会下载缺失的镜像；如果本机还没有 PostgreSQL 镜像，先运行 `docker pull postgres:16-alpine`。

请同时下载对应的 `.sha256` 文件。GHCR 是否允许匿名拉取取决于 GitHub 包权限；这里以 Release 镜像包作为不需要 GHCR 登录的部署入口。

### 日志和日常维护

```bash
docker compose logs --tail=100 api web postgres
docker compose restart api web
docker compose down
```

`docker compose down` 只停止并移除容器和网络，数据卷仍保留。不要在需要保留数据时加 `-v`。备份时同时保存 PostgreSQL 数据、API 数据卷、`.env` 和数据库密码文件；丢失或更换会话密钥会导致已有 API key 密文无法解密。

## Linux 本地开发

需要 Node.js 22 或更高版本和 npm。在仓库根目录执行：

```bash
npm ci
cp .env.example .env
chmod 600 .env
npm run dev
```

如果已有 `.env`，不要再次复制覆盖。`npm run dev` 会先编译规则引擎，再启动 API 和前端开发服务。

- 管理后台：`http://127.0.0.1:3000`
- API：`http://127.0.0.1:4000`
- WAF HTTP 入口：`http://127.0.0.1:8080`，其他站点使用已分配的端口

本地直接运行时，宿主机上游可以使用 `UPSTREAM_URL=http://127.0.0.1:9000`。没有配置 PostgreSQL 时，设置、规则和事件会保存到 `DATA_DIR` 下的 SQLite 文件；首次初始化只需要设置管理员密码。

## HTTPS 和 WebSocket

在 Linux 服务器上把证书和私钥放入 `./certs`，确保容器可读取，并在 `.env` 中设置：

```dotenv
TLS_CERT_DIR=./certs
TLS_KEY_PATH=/app/certs/tls.key
TLS_CERT_PATH=/app/certs/tls.crt
```

执行 `docker compose up -d --build` 应用配置。HTTPS WAF 入口是 `8443`，这不会为 `3000` 管理后台自动启用 HTTPS。后台通过 HTTPS 反向代理访问时，设置 `SESSION_COOKIE_SECURE=true`。

WebSocket 握手也会进入 WAF 决策管线，确认升级成功后再透传连接；建立连接后的消息不做内容检查。

## Jev 配置

Jev 可以通过环境变量配置，也可以在 WebUI 的“防护策略”中配置。WebUI 保存的 key 会使用会话密钥（显式设置的 `SESSION_SECRET`，或数据目录中的自动生成密钥）加密后写入数据库；接口只返回是否已配置以及 key 的来源，不会回显明文。

```dotenv
JEV_API_KEY=your-jev-key
JEV_MODEL=typesafe/jev-1.13
JEV_BASE_URL=https://openrouter.ai
```

`JEV_BASE_URL` 同时接受供应商根地址和完整决策接口地址，例如：

- `https://openrouter.ai`
- `https://provider.example.com/api/alpha/decisions`
- `https://provider.example.com/api/v1/decisions`

没有 key 时仍然可以完成首次初始化，但 WebUI 和 API 都只允许传统规则模式。配置 key 并保存后，才可以选择 AI 或混合模式。AI 模式在 Jev 不可用时会记录错误并阻断；混合模式会在传统规则通过后按传统结果降级，同时保留 AI 不可用信息。

Jev 分数不是经过本项目校准的真实恶意概率。阈值越低，越容易拦截；本版仅修正显示名称，不翻转已有配置：

| 配置值 | Jev 风险分数达到该值时拦截 |
| --- | ---: |
| veryLow | 10% |
| low | 30% |
| medium | 50% |
| high | 70% |
| extreme | 90% |
| 自定义 | 0% - 100% |

默认不向 AI 发送正文业务字段的值。策略中的 `aiBodyFields` 可允许 JSON 点路径或表单字段出站，`*` 表示允许全部可解析字段；识别到的凭据仍会遮蔽。`application/*+json` 和 JSON Patch 使用结构化脱敏，XML、纯文本、multipart 和未知格式不发送正文给 AI，但仍接受完整本地检测。路径和查询串中的常见凭据也会脱敏。脱敏不能保证识别所有业务秘密，不要用真实客户数据测试。

事件分别记录本地和 AI 检查是否完整，以及 AI 省略正文的原因。默认在 AI 正文不完整时继续本地结果，可按站点改为拒绝。影子评估不改变代理响应，AI 结果异步合入该请求的最终事件。

AI 调用没有等待队列，默认最多 8 个并发、每分钟 120 次，另有每站点预算；连续 5 次失败后熔断 30 秒。可通过 `AI_MAX_CONCURRENT`、`AI_REQUESTS_PER_MINUTE` 调整，超时仍使用 `AI_TIMEOUT_MS`。代理全局并发使用 `MAX_PROXY_CONCURRENT`，IP 状态上限使用 `MAX_TRACKED_CLIENTS`，事件待写上限使用 `EVENT_QUEUE_LIMIT`。

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

Docker 部署时，把文件放在宿主机的 `./geoip`，并使用上文的 `/app/geoip/...` 容器内路径。本地直接运行时，可以放在 `DATA_DIR/geoip`，也可以通过 `GEOIP_DATABASE_PATH` 和 `GEOIP_ASN_DATABASE_PATH` 指定其他路径。没有数据库时，来源会显示为“未知地区”，但地图仍然可以打开。2D 地图轮廓来自随前端依赖分发的离线 Natural Earth-derived `world-atlas` 数据。

## 防护边界

请求体默认最多接收 10 MB。WAF 会在检查前解压 gzip、deflate 和 brotli，并拒绝无法完整检查的请求，包括格式错误的 JSON/XML、非法 UTF-8、multipart 解析失败、压缩层过多和解压后超限。

只有来自 `TRUSTED_PROXY_CIDRS` 的连接才会采用 `X-Forwarded-For`。代理会清理客户端伪造的路由和转发头，并拒绝 HTTP/0.9、冲突的 Content-Length/Transfer-Encoding 以及不支持的传输编码。

统计口径是：

```text
总计 = 已放行 + 已拦截 + 错误
```

一个请求只保存一个最终事件，避免先记录 allow、再记录上游 error 造成重复统计。

`LOG_RETENTION_DAYS` 默认 30，每分钟最多清理 1000 条过期详情，大量历史数据需要多轮清理。趋势和地图只统计当前保留详情；历史总计由独立计数保存，不会随详情删除减少。SQLite 使用索引和 SQL 分页，不再把全部历史事件读入内存。系统信息提供事件待写、丢弃及写入错误计数，达到队列上限时可能丢失详情。

## 验证

```bash
npm run typecheck
npm run build
npm test
```

完成初始化后，可以直接向 WAF 入口发送一条规则测试请求：

```bash
curl -i 'http://127.0.0.1:8080/search?q=union+select+password+from+users'
```

在传统规则或启用阻断的混合模式下，预期返回 `403`，不需要上游或 Jev 在线。普通请求返回 `502` 时，先检查 `UPSTREAM_URL` 和上游服务的监听地址；服务启动异常可查看 `docker compose logs --tail=100 api postgres`。

管理 API 需要先通过 `/api/v1/auth/login` 获取 HttpOnly 会话 Cookie。正式版验证还覆盖 PostgreSQL 迁移、站点端口持久化、动态监听器、按端口转发、重启持久化、压缩请求、请求头攻击、可信代理 IP、规则导入原子性、2D/3D 地图和 WebGL 回退。

## 项目结构

```text
apps/api           Fastify 管理 API、WAF 代理、数据库和 GeoIP
apps/web           React + Vite 管理后台
packages/waf-core  规则引擎、请求规范化和安全正则
```

规则包和离线地图的授权边界见 [`packages/waf-core/RULES.md`](packages/waf-core/RULES.md)。

## 许可证

项目代码与文档采用 MIT 许可证。规则包和离线地图的授权边界见 [`packages/waf-core/RULES.md`](packages/waf-core/RULES.md)；第三方依赖仍以各自许可证为准。
