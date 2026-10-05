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

正式接入生产流量前，请按自己的业务做安全审计、压力测试和灰度验证。项目不提供分布式限流或高可用集群。

## 这版重点

`v0.3.0` 换成青绿工作台，支持深色模式和图标导航。Compose 统一由 Nginx 提供入口，API 不再直接暴露在宿主机。

目前 `main` 还包含发布后的验收修正，尚未更新已发布的 `v0.3.0` 标签和镜像包。下面的快速开始使用 `main` 源码构建；使用旧标签或 Release 包不会包含这些修正。

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
- 站点支持防御、记录、维护三种运行模式，单个上游、加权轮询池和 301/302 跳转。
- 等候室按站点限制活动并发、FIFO 队列和等待超时；浏览器显示排队页，队列满返回 `429` 或 `503`。
- Jev/API Profile 支持不同的 Base URL、模型、超时和独立密钥；API 只返回是否已配置，不返回密钥明文。
- 支持同步审核、异步追封和活动连接中断，白名单不会被追封。
- CC 防护可触发本地 PoW 或第三方验证码；自定义 HTML、IP 库、GeoIP MMDB 和 Nginx 配置都有管理入口。

## 看一眼

![鉴流控制台的实际运行截图](docs/images/console.png)

登录后可以查看请求事件、切换防护模式、测试规则、修改上游地址，并在攻击大屏中查看 2D/3D 统计视图。

## 在 Linux 上部署

以下步骤面向 Linux 服务器，命令使用 Bash，配置对应当前 `main`。先准备一套测试环境，再接入真实业务。完整变更见 [更新日志](CHANGELOG.md)。

需要 Git、curl、OpenSSL，以及已安装并运行的 Docker Engine 和 Docker Compose v2.24.4 或更高版本。使用容器部署不需要在宿主机安装 Node.js。

### 获取代码和准备配置

```bash
git clone https://github.com/wrhc2010/JianFlow-WAF.git
cd JianFlow-WAF
git checkout main
cp .env.example .env
chmod 600 .env
mkdir -p secrets certs geoip config pages
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
curl -fsS http://127.0.0.1:3000/api/v1/health
```

等待服务健康检查通过后，健康接口应返回包含 `"ok": true` 的 JSON。管理端口默认只绑定服务器回环地址；远程管理可先建立 SSH 隧道：

```bash
ssh -L 3000:127.0.0.1:3000 user@server
```

随后在本地浏览器打开 `http://127.0.0.1:3000` 完成初始化。`/api/v1/health/live` 检查进程存活，`/api/v1/health/ready` 检查启用入口及策略版本是否实际应用。

| 入口 | 端口 | 用途 |
| --- | ---: | --- |
| 管理后台 | 3000 | 初始化、规则和事件管理 |
| 管理 API | 3000/api/v1 | 经 Nginx 访问，容器内使用 4000 |
| WAF HTTP | 8080-8099 | 按站点分配的 HTTP 入口 |
| WAF HTTPS | 8443 | 配置证书后使用 |

Compose 只将管理入口 `3000` 绑定到 `127.0.0.1`，WAF 入口发布到所有接口。API 的 `4000` 和 PostgreSQL 都不向宿主机发布。需要远程多人管理时，使用受控的 HTTPS 反向代理；不要直接把管理端口暴露到公网。

Compose 使用文件型 Docker secret 提供 PostgreSQL 密码。可以通过 `POSTGRES_PASSWORD_FILE_SOURCE` 指向已有密码文件；显式设置 `DATABASE_URL` 时，API 会优先使用它。PostgreSQL 数据和 API 数据目录由命名卷持久化，GeoIP 文件从宿主机 `GEOIP_DIR` 只读挂载。

小型单机也可以使用 SQLite。首次部署选择以下命令，不会启动 PostgreSQL；SQLite 保存在 API 数据卷。两种数据库不会自动互相复制数据，已有部署不要直接切换后端：

```bash
docker compose -f docker-compose.yml -f docker-compose.sqlite.yml up -d --build
```

之后的 `logs`、`restart`、`down` 也带上相同的两个 `-f` 参数。SQLite 使用 Node 22 的内置驱动，该驱动仍有 experimental 提示；生产默认推荐 PostgreSQL。

### 配置多个入口

默认站点固定使用 `8080`，可以编辑和停用，但不能删除。在“站点与上游”新建站点，从当前范围选择未占用端口，填写上游和防护模式。保存后动态应用监听器；卡片显示期望与实际版本，应用失败时可以重试。Nginx 保留端口范围的入口，停用站点后拒绝转发，不会落到另一个站点；停用默认站点同时停用其 HTTPS 业务入口。

站点可继承全局策略，也可覆盖阈值、执行方式、停用规则、AI 数据范围和限速。策略里的“观察”只改变检测命中的处理，不放宽强制 ACL、协议或资源限制；整站“记录模式”的范围更大，见下文。限速和等候室是单进程状态，不能跨多副本共享。

`SITE_PORT_RANGE` 只在部署启动时读取，范围必须包含默认入口 `8080`。例如扩展到 `8080-8109`，修改 `.env` 后重启；仓库中的 Compose 会按这个变量发布端口。如果使用了自定义端口映射，也要同步调整：

```dotenv
SITE_PORT_RANGE=8080-8109
```

默认站点仍要求使用 `PROXY_PORT`，默认值是 `8080`；自定义范围应包含这个端口。

### Nginx 生产入口

推荐的生产链路是：

```text
客户端 -> Nginx(TLS/基础转发) -> JianFlow Node WAF(规则/审核/等候室) -> 上游
```

Compose 的 `web` 镜像包含控制台和 Nginx，不需要另起一个 Nginx 服务。启动时按 `SITE_PORT_RANGE` 生成全部入口，每个端口只转发到对应的 Node WAF 监听器。TLS、代理头和连接超时在 Nginx 处理；上游池分配、故障回退及站点跳转在 WAF 检查后执行，保证它们不能绕过防护。

新建或导入站点只需动态调整 WAF 监听器，范围内已有的 Nginx 映射无需 reload。改端口范围或证书后运行 `docker compose up -d --force-recreate api web`。导入配置不会原样写进 Nginx，也不会执行任意指令。

默认网关固定使用 `172.29.83.2`，API 固定使用 `172.29.83.3`，避免启动顺序导致地址冲突。只信任网关 `172.29.83.2/32` 的转发头。调整 `GATEWAY_SUBNET` 时同时修改 `GATEWAY_IP`、`API_GATEWAY_IP` 和 `TRUSTED_PROXY_CIDRS`，两个地址必须不同且位于同一子网；不要把可信代理设成 `0.0.0.0/0`。直接运行 Node 时留空，不信任客户端传来的转发头。

### 高级配置格式

| 文件或数据 | 支持格式 | 保存方式 |
| --- | --- | --- |
| 等候室、维护、上游错误页 | UTF-8 `.html`，每页最多 512 KB | 站点编辑器“页面”上传，保存站点后生效；也可引用挂载文件 |
| 白名单、恶意 IP 库 | CIDR 文本、JSON、CSV、STIX Bundle、TAXII JSON envelope，内容最多 1 MB | “防护策略”导入预览，确认列表后保存策略 |
| GeoIP | MaxMind City/ASN `.mmdb`，每文件最多 128 MB | “GeoIP 数据库”选择文件后单独保存，或只读挂载 |
| Nginx 站点 | UTF-8 `.conf` 或粘贴文本，最多 1 MB | 站点页预览、确认；整批事务写入，冲突时不部分导入 |
| 本地规则 | 严格 JSON、受支持的 ModSecurity `.conf`/`.txt` | 规则库预览并提交规则包 |
| 启动配置 | UTF-8 `.json`，最多 4 MB | `JIANFLOW_CONFIG_FILE` 指定容器内路径，重启时应用 |

详细格式和限制在下面的配置章节。不要把密码、客户请求或供应商 Secret 放进公开仓库。

### 使用发布镜像

现有 `v0.3.0` 包对应提交 `a3b5783`，不包含本轮验收修正。要验证本 README 描述的当前行为，请先使用上面的源码构建方式。以下命令仅用于部署已有发布包，并使用对应标签的 Compose 配置。

不想在服务器构建时，可以从 [v0.3.0 Release](https://github.com/wrhc2010/JianFlow-WAF/releases/tag/v0.3.0) 下载 API 和 Web 镜像压缩包。先按上面的步骤准备配置和密码文件，再导入镜像：

```bash
git checkout v0.3.0
sha256sum -c jianflow-waf-api-v0.3.0.tar.gz.sha256
sha256sum -c jianflow-waf-web-v0.3.0.tar.gz.sha256
docker load -i jianflow-waf-api-v0.3.0.tar.gz
docker load -i jianflow-waf-web-v0.3.0.tar.gz
IMAGE_TAG=v0.3.0 docker compose up -d --no-build --pull never
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

### 升级和回滚

先备份，再停服务并升级到明确的标签：

```bash
docker compose exec -T postgres pg_dump -U jevwaf jevwaf > backup.sql
docker compose down
docker run --rm -v jianflow-waf_jevwaf-data:/data:ro -v "$PWD":/backup alpine \
  tar -czf /backup/jianflow-data.tar.gz -C /data .
git fetch --tags
git checkout main
docker compose up -d --build
curl -fsS http://127.0.0.1:3000/api/v1/health/ready
```

上面的卷名只适用于默认目录名；先用 `docker volume ls` 核对自己的 Compose 项目名。SQLite 部署省略 `pg_dump`，停机后备份 API 卷即可。`.env`、`secrets`、`config`、`pages`、`geoip` 和证书也要单独备份；镜像需提前导入。迁移保留旧事件、规则、站点和管理员，旧 Jev 配置转成默认 Profile，默认端口仍是 `8080`。

回滚时停止新版，恢复升级前的数据库、API 数据卷及配置，然后启动旧标签。不要让旧程序直接写入迁移后的数据库。备份包含密钥材料，限制读取权限并离线保管。

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

AI 调用没有等待队列，默认最多 8 个并发、每分钟 120 次，另有每站点预算；连续 5 次失败后熔断 30 秒。可通过 `AI_MAX_CONCURRENT`、`AI_REQUESTS_PER_MINUTE` 调整。代理全局并发使用 `MAX_PROXY_CONCURRENT`，IP 限速状态上限使用 `MAX_TRACKED_CLIENTS`，事件待写上限使用 `EVENT_QUEUE_LIMIT`。

### 多组 API Profile

在“防护策略”新增 Profile，填写名称、Base URL、模型、Key、启用状态、优先级、超时和失败策略。数字较小的优先级先被自动选择；站点也可以指定一个 Profile。指定组不可用时回退传统规则，不会暗中使用另一组密钥。优先级不是密钥轮询或失败重试。

Key 输入留空表示不修改，勾选移除后点击保存才删除。数据库加密保存 Key 和第三方验证码 Secret，接口只返回配置状态。旧环境变量和单组数据库配置会迁移为默认 Profile；如果 Key 来自环境变量，移除数据库 Key 不会删除环境变量，需要修改部署配置再重启。

### 同步和异步审核

默认同步：等 Jev 返回后再决定是否转发。异步模式先跑本地规则，通过后立即转发，后台进行 Jev 审核；判恶意后追封来源 IP，并中断该站点中该 IP 仍在活动的 HTTP 和 WebSocket 连接。已经发给上游的请求无法撤回，已经产生的业务副作用也不能恢复。

审核范围使用站点策略的 `aiScope`：`all` 检查所有规则通过的请求，`suspicious` 只检查仍带有风险信号的请求。基础封禁秒数、每次递增秒数、最大秒数在设置里保存；历史次数跨重启保留。审核失败按 Profile/站点失败策略处理，但不因供应商不可用而永久追封。影子评估只记录，不执行追封。

## 站点运行与上游

防护模式和运行模式是两组选项。运行模式决定站点是否照常服务：

- `defense`：执行规则、AI、恶意 IP、CC 和封禁。
- `record`：记录可疑请求及 `wouldBlock`，不因安全检测、恶意 IP、CC 或异步结果拦截；协议、正文上限、全局容量和排队上限仍然有效。
- `maintenance`：优先返回维护页面，默认 `503`，不会转发上游。

反向代理支持单个 HTTP(S) 地址或最多 32 个节点的加权轮询池，权重 `1-1000`。连接失败时只对安全方法尝试其他节点；不会重放 POST。301/302 跳转需要一个明确的目标 URL，不支持按路径匹配的跳转规则。连接失败、无效上游或上游 HTTP 5xx 显示上游错误页；默认 `502`，这会替换上游原本的错误正文。

### 等候室

活动并发指正在传输的请求，WebSocket 连接在关闭前也占一个名额，不是登录用户数或在线会话数。设置最大活动数、队列长度、等待超时和队列满策略，保存后生效。站点继承全局默认值，或单独配置。

浏览器导航超限时收到 `202` 等候室页面，按 FIFO ticket 自动轮询，轮到后再访问原路径；刷新复用当前 ticket。非浏览器请求在连接上等待名额。等待超时返回 `429`，队列满按配置返回 `429` 或 `503`。队列和 ticket 不跨进程重启保留，也不是跨服务器分布式队列。

### 自定义 HTML

站点编辑器“页面”分别配置等候室、维护页和上游错误页。选择内置页面、上传 UTF-8 `.html` 或填挂载文件的相对路径。上传内容仅进入草稿，点击“保存站点”才提交；取消不会上传。

文件最多 512 KB，不能使用 `.htm`、压缩包或服务端模板。挂载文件放在 `PAGES_DIR`（默认 `./pages`），容器内固定 `/app/pages`，例如引用 `maintenance.html`；不允许绝对路径、`..` 或指向目录外的符号链接。内联内容保存在数据库，文件引用需要另行备份挂载目录。

页面按静态 HTML 返回，安全响应头禁止脚本和表单，只允许内联样式、data 图片及 HTTPS 图片。等候室的自定义内容放在隔离 iframe，排队和跳转由外层受控脚本处理，不能上传脚本替换排队逻辑。维护/错误页可设置 `400-599` 状态码；等候室排队阶段固定 `202`，其超时状态不由页面状态码覆盖。

## CC 与人机验证

在站点“限速”配置单 IP 每秒速率、突发容量、并发和临时封禁秒数，也可以限定关键路径。启用验证码后，CC 触发的非白名单请求进入验证页面；站点可继承、单独启用或关闭全局开关。验证通过后签发绑定站点/IP、有效 10 分钟的 HttpOnly Cookie，清除当前 CC 封禁；更换 IP、过期或另一个站点都需要重新验证。它不会跳过规则、恶意库或异步追封。

- 本地：短期签名挑战和 JavaScript PoW，无第三方依赖。公网部署需要 HTTPS，浏览器的 `crypto.subtle` 不适用于普通公网 HTTP；localhost 测试可以使用 HTTP。
- 第三方：Turnstile、hCaptcha、reCAPTCHA v2，配置对应 Site Key、Secret、校验超时和供应商故障时放行/阻断策略。Secret 加密保存，服务端调用 siteverify 并核对 hostname。真实供应商接入需要自己的有效密钥和域名；自动化测试验证协议和失败分支，不代替供应商账号验收。

首次启动也可使用 `CAPTCHA_ENABLED`、`CAPTCHA_PROVIDER`、`CAPTCHA_SITE_KEY`、`CAPTCHA_SECRET_KEY`、`CAPTCHA_TIMEOUT_MS`、`CAPTCHA_FAILURE_ACTION`。API 保存配置后以数据库值为准。客户端验证依赖 JavaScript；自动化 API 客户端应按业务需要配置白名单或关闭该站点挑战。

## IP 库与启动配置

白名单优先于 IP 封禁和恶意库，不跳过一般的内容检查或资源限制。名单变更也是草稿，保存策略才生效。支持 IPv4、IPv6 和 CIDR：

```text
203.0.113.10
2001:db8::/32
```

也可以导入 JSON 数组，例如 `["203.0.113.10","2001:db8::/32"]`，或对象 `{"ips":["203.0.113.10"]}`。CSV 使用第一列，支持带引号字段，表头和非 IP 行不作为地址导入。STIX/TAXII 只提取 `indicator.pattern` 中 `ipv4-addr:value`/`ipv6-addr:value` 的直接等值地址，不执行 STIX 的完整逻辑。TAXII 接受已导出的 `objects` envelope 文件，不接受服务器 URL，也不自动同步。导入预览会去重和排除非法地址，请核对列表后再确认，尤其是白名单。

不附带生产 GeoIP 或实时恶意 IP 数据库，不自动从第三方下载；默认 IP 名单为空，本地规则可以独立运行。导入的库需要你确认来源、授权和更新时间。

### Nginx 导入示例

```nginx
upstream app {
    server app-a:9000 weight=2;
    server app-b:9000 weight=1;
}
server {
    listen 8081;
    server_name shop.example.com;
    location / { proxy_pass http://app; }
}
server { listen 8082; return 302 https://example.com/new; }
```

支持 `server`、单端口 `listen`、`server_name`、根路径 `location /`、`proxy_pass`、`return 301/302`、`upstream`、基础代理 Header 和 timeout。导入器识别 Header/timeout 指令并在预览中提示，但不应用其参数，仍使用网关默认值。`server_name` 用作站点名称，不启用 Host 路由。未知指令、`include`、Lua、执行脚本、多个路由、正则 location、TLS listen 等都拒绝导入；完整系统级 nginx.conf 需要先提取受支持的站点块。入口端口必须在当前范围内且未被占用。确认导入后可在卡片查看运行状态；历史保留摘要、时间及端口，不保存原始配置中的秘密。

### JSON 配置文件

可把下面的文件保存为 `config/jianflow.json`，设置 `JIANFLOW_CONFIG_FILE=/app/config/jianflow.json`，然后重启 API：

```json
{
  "settings": { "auditMode": "async", "whitelistCidrs": ["203.0.113.10"] },
  "profiles": [{ "id": "primary", "name": "主审核", "baseUrl": "https://openrouter.ai", "model": "typesafe/jev-1.13", "apiKey": "replace-with-your-key" }],
  "sites": [{ "id": "shop", "name": "商城", "listenPort": 8081, "upstreamUrl": "http://app:9000", "mode": "hybrid", "aiProfileId": "primary", "auditMode": "async", "captchaEnabled": false, "maintenance": { "source": "file", "filePath": "maintenance.html", "statusCode": 503 } }]
}
```

文件只接受 `settings`、`profiles`、`sites`，字段复用管理 API 校验，拒绝未知字段。Profile/站点要求稳定 `id`，每次重启重新应用，未列出的已有站点不会被删除。按 Profile、设置、站点顺序分别持久化，整个文件不是一个事务；语义或存储错误可能在部分条目保存后使启动失败，请先在测试环境验证。WebUI 修改列在文件中的设置后，下次重启会被文件重新覆盖。配置内的 Key 是明文，宿主机权限设为 `600`，目录只让管理者读取，并确保降权的容器用户有只读权限；不要提交它。

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

支持 MaxMind GeoLite2/GeoIP2 City 和 ASN，不能上传 CSV 或普通 JSON 冒充 MMDB。数据库不随项目提供，需要按 MaxMind 授权下载并定期更新。

WebUI 的 GeoIP 区域可以选择 City/ASN 文件，取消不上传，点击“保存 GeoIP”才提交；会校验数据库类型，失败不替换原库。上传库写入 API 数据卷的 `geoip/uploaded-city.mmdb` / `uploaded-asn.mmdb`，跨重启保留，并优先于环境变量路径。

也可以把文件放在宿主机 `./geoip` 并使用 `/app/geoip/...` 容器路径，只读挂载；替换挂载库后重启 API。要恢复使用挂载库，先停止 API，备份并移走对应的 uploaded 文件再启动。直接运行时可以放在 `DATA_DIR/geoip` 或通过两个环境变量指定路径。没有数据库时显示“未知地区”，不调用在线查询；地图仍可打开。测试目录的 MaxMind 合成库只用于测试，不能用于生产定位。2D 地图来自离线 `world-atlas` 数据。

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
npm run test:e2e
```

完成初始化后，可以直接向 WAF 入口发送一条规则测试请求：

```bash
curl -i 'http://127.0.0.1:8080/search?q=union+select+password+from+users'
```

在传统规则或启用阻断的混合模式下，预期返回 `403`，不需要上游或 Jev 在线。普通请求返回 `502` 时，先检查 `UPSTREAM_URL` 和上游服务的监听地址；服务启动异常可查看 `docker compose logs --tail=100 api postgres`。

管理 API 需要先通过 `/api/v1/auth/login` 获取 HttpOnly 会话 Cookie。设置 `TEST_DATABASE_URL` 可运行实库 PostgreSQL 测试，否则这些用例会跳过。浏览器测试首次运行需 `npx playwright install chromium`；本地默认使用 Chrome，CI 使用 Chromium。验证覆盖配置和密钥持久化、端口路由、请求体/协议、规则、等候室、异步封禁、验证码协议、IP/MMDB/Nginx 导入及三个视口的浅深主题和 3D 像素/交互检查。

## 项目结构

```text
apps/api           Fastify 管理 API、WAF 代理、数据库和 GeoIP
apps/web           React + Vite 管理后台
packages/waf-core  规则引擎、请求规范化和安全正则
```

规则包和离线地图的授权边界见 [`packages/waf-core/RULES.md`](packages/waf-core/RULES.md)。

## 许可证

项目代码与文档采用 MIT 许可证。规则包和离线地图的授权边界见 [`packages/waf-core/RULES.md`](packages/waf-core/RULES.md)；第三方依赖仍以各自许可证为准。
