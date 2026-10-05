# JianFlow WAF

A self-hosted Web Application Firewall that checks HTTP requests using local rules, Jev AI classification, or both. This guide targets Linux servers and uses Bash commands for v0.3.0.

[![License: MIT](https://img.shields.io/github/license/wrhc2010/JianFlow-WAF)](LICENSE)
[![Release](https://img.shields.io/github/v/release/wrhc2010/JianFlow-WAF)](https://github.com/wrhc2010/JianFlow-WAF/releases)
[![CI](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml/badge.svg)](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml)
[![Node.js 22](https://img.shields.io/badge/Node.js-22-339933)](package.json)

[中文](README.md) | **English**

Run a test deployment before connecting real traffic. A production rollout still needs a security audit, load testing, and staged validation for your application. See the [changelog](CHANGELOG.md) for release details.

Version 0.3.0 adds the mint workstation UI, light/dark themes, icon-only navigation, multiple API profiles, waiting rooms, asynchronous review and visitor challenges. Compose uses Nginx as the public entry and TLS layer; the Node WAF handles inspection, upstream routing, events and bans. Local rules work without AI.

The current `main` branch includes post-release acceptance fixes that are not yet in the published `v0.3.0` tag or image archives. The quick start below builds `main`; checking out the old tag or loading its archives does not include these fixes.

## Screenshot

![JianFlow console running locally](docs/images/console.png)

The console provides site, rule, event and policy management.

## Deploy on Linux

Requires Git, curl, OpenSSL, Docker Engine, and Docker Compose v2.24.4 or newer. Docker must be running; the host does not need Node.js for a container deployment.

### Prepare configuration

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

The password file must be readable by the PostgreSQL container user. Its mode is `644`, while the host's `secrets` directory is `700` to prevent access by other ordinary host users. Generate this password only for a new deployment; do not replace it for an existing database.

Edit `.env` to use an upstream and GeoIP paths accessible from the container:

```dotenv
UPSTREAM_URL=http://host.docker.internal:9000
SITE_PORT_RANGE=8080-8099
GEOIP_DIR=./geoip
GEOIP_DATABASE_PATH=/app/geoip/GeoIP2-City.mmdb
GEOIP_ASN_DATABASE_PATH=/app/geoip/GeoIP2-ASN.mmdb
```

Compose maps `host.docker.internal` to the host gateway. On Linux, an upstream running on the host must listen on an address reachable from the container, not just `127.0.0.1`; restrict access to that upstream. For a service on the same container network, use its service name, such as `http://app:8080`. Inside a container, `127.0.0.1` refers to that container, not the host.

Leave `ADMIN_PASSWORD` and `SESSION_SECRET` empty if you want to set the administrator password in the console at first launch. The session secret is generated and persisted automatically. Jev and GeoIP can be configured later.

### Start and verify

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:3000/api/v1/health
```

Wait for the health checks to pass. The health endpoint should return JSON containing `"ok": true`. Management ports bind to loopback by default. For remote access, open an SSH tunnel:

```bash
ssh -L 3000:127.0.0.1:3000 user@server
```

Then open `http://127.0.0.1:3000` locally to finish initialization. `/api/v1/health/live` checks process liveness; `/api/v1/health/ready` checks enabled listeners and applied policy revisions.

| Entry point | Port | Purpose |
| --- | ---: | --- |
| Console | 3000 | Setup, rules, and events |
| Management API | 3000/api/v1 | Through Nginx; container-internal port 4000 |
| WAF HTTP | 8080-8099 | Port-based protected HTTP entries |
| WAF HTTPS | 8443 | Available after configuring certificates |

Compose binds the console to `127.0.0.1:3000` and publishes WAF entries on all host interfaces. The API port 4000 and PostgreSQL are not published. Use a controlled HTTPS reverse proxy for shared remote administration instead of exposing management ports directly to the Internet.

PostgreSQL reads its password from a file-backed Docker secret. Use `POSTGRES_PASSWORD_FILE_SOURCE` for an existing password file; an explicit `DATABASE_URL` takes precedence for the API. PostgreSQL and API data use persistent named volumes. GeoIP files are mounted read-only from the host's `GEOIP_DIR`.

For a new single-machine SQLite deployment, use:

```bash
docker compose -f docker-compose.yml -f docker-compose.sqlite.yml up -d --build
```

Use the same two `-f` options for later operations. This does not start PostgreSQL; SQLite stays in the API data volume. Switching backends does not migrate data automatically. PostgreSQL is the production default; Node 22's built-in SQLite driver still reports an experimental warning.

### Configure multiple entries

The default site always uses port `8080` and cannot be deleted. Create a site, choose an unused port and configure its upstream and mode. Cards show desired and applied revisions, with retry for listener errors. Nginx keeps the range mappings when a site is disabled, but refuses to forward to another site's upstream; disabling the default site also disables its HTTPS business entry.

Site policies can inherit or override thresholds, enforcement, rules, AI scope and rate limits. Policy observation affects detection hits only; mandatory ACL, protocol/body validation and capacity limits remain. Site record mode has a broader scope, described below. Rate limits and queues are in-process, not distributed.

`SITE_PORT_RANGE` is read when the deployment starts and must include the default entry port, `8080`. To extend it to `8080-8109`, update `.env` and restart. The supplied Compose file publishes ports using this variable; update any custom port mapping as well:

```dotenv
SITE_PORT_RANGE=8080-8109
```

The default site still uses `PROXY_PORT`, which defaults to `8080`; a custom range must include that port.

### Use release images

The existing `v0.3.0` archives were built from `a3b5783` and do not contain the current acceptance fixes. Build from source above to verify the behavior described in this README. The following commands deploy the existing archives with their matching tagged Compose configuration.

To skip the build, download both image archives from the [v0.3.0 release](https://github.com/wrhc2010/JianFlow-WAF/releases/tag/v0.3.0). Prepare configuration and the password file as above, then import the images:

```bash
git checkout v0.3.0
sha256sum -c jianflow-waf-api-v0.3.0.tar.gz.sha256
sha256sum -c jianflow-waf-web-v0.3.0.tar.gz.sha256
docker load -i jianflow-waf-api-v0.3.0.tar.gz
docker load -i jianflow-waf-web-v0.3.0.tar.gz
IMAGE_TAG=v0.3.0 docker compose up -d --no-build --pull never
```

`--pull never` will not download missing images. If the PostgreSQL image is not available locally, run `docker pull postgres:16-alpine` first.

Download the matching `.sha256` files as well. Anonymous GHCR access depends on GitHub package permissions; Release archives remain the deployment path that does not require a GHCR login.

### Logs and maintenance

```bash
docker compose logs --tail=100 api web postgres
docker compose restart api web
docker compose down
```

`docker compose down` removes containers and networks but keeps named volumes. Do not add `-v` when you need to keep the data. Back up PostgreSQL data, the API data volume, `.env`, and the database password file together. Losing or changing the session secret makes existing encrypted API keys unreadable.

### Upgrade and rollback

Back up before checking out a new tag. Dump PostgreSQL with `docker compose exec -T postgres pg_dump -U jevwaf jevwaf > backup.sql`, stop the deployment, and archive its API data volume. SQLite needs an offline API-volume backup instead of `pg_dump`. Use `docker volume ls` to identify your actual volume names; also preserve `.env`, secrets, certificates, config, pages and GeoIP files. Backups contain key material and need restricted access.

For the current fixes, check out `main` and run `docker compose up -d --build`. For a published release, load its images and use the matching source tag and `IMAGE_TAG`. Check `/api/v1/health/ready` through port 3000. Existing users, rules, events and sites remain; old Jev settings become the default Profile and port 8080 remains the default entry. To roll back, stop the new services and restore the pre-upgrade database, API volume and configuration before starting the old tag. Do not run an old binary against a migrated database.

## Develop locally on Linux

Requires Node.js 22 or newer and npm. From the repository root:

```bash
npm ci
cp .env.example .env
chmod 600 .env
npm run dev
```

Do not overwrite `.env` if it already exists. The dev script builds the core package before starting the API and frontend. The console, API, and WAF use ports 3000, 4000, and `8080-8099` by default. When running directly on the host, `UPSTREAM_URL=http://127.0.0.1:9000` can reach a local upstream. Without PostgreSQL configuration, settings, rules, sites, and events persist in SQLite under `DATA_DIR`.

Set the administrator password on first launch; the default username is `admin`. With enforcing traditional or hybrid mode, try a rule-triggering request:

```bash
curl -i "http://127.0.0.1:8080/search?q=union+select+password+from+users"
```

It should return `403` without needing the upstream or AI service.

## Features and configuration

- **AI**: compares Jev's `noul` risk score with the threshold. The score is not a calibrated malicious probability. Provider failures follow the selected failure policy; the inherited AI-mode policy rejects unavailable decisions.
- **Rules**: local request normalization and rules for common SQL injection, XSS, traversal, template injection, NoSQL injection, command injection, and unsafe URL patterns. JSON and supported ModSecurity `SecRule` imports include preview, validation, conflict handling, and atomic writes; this is not the full OWASP CRS engine.
- **Hybrid**: local rules first, then Jev for suspicious requests by default. Select all requests or asynchronous shadow evaluation when needed. The inherited hybrid failure policy continues the local result and records the failure.
- **Inspection**: checks paths, queries, headers, cookies, IPs, and complete request bodies, including JSON, forms, XML, multipart, text, and gzip/deflate/brotli bodies. HTTP and WebSocket handshakes are inspected; subsequent WebSocket frames are passed through.
- **Sites**: port-based entries with single upstreams, weighted pools or 301/302 redirects; defense, record and maintenance modes; built-in, uploaded or mounted static pages.
- **Console and storage**: all-history statistics, cursor pagination, filters, rule management, encrypted API key storage, PostgreSQL or persistent SQLite, and offline GeoIP with 2D/3D attack views.

Threshold presets are 10%, 30%, 50%, 70%, and 90%, with custom values from 0% to 100%. Lower thresholds block more requests; stored values are unchanged by this upgrade. Configure Jev in the console or use server-side environment variables:

```dotenv
JEV_API_KEY=your-jev-key
JEV_MODEL=typesafe/jev-1.13
JEV_BASE_URL=https://openrouter.ai
```

The base URL accepts a provider root or a full decision endpoint. Keys saved through the console are encrypted using the session secret; management responses do not return their plaintext.

By default, body business-field values are not sent to AI. A policy's `aiBodyFields` allowlist accepts JSON dot paths or form keys; `*` opts into all parsed fields, with recognized credentials still redacted. Structured redaction handles `application/*+json` and JSON Patch. XML, text, multipart, and unknown-format bodies are omitted from AI but still inspected locally. Sensitive URL values are also redacted. This cannot identify every business secret; use synthetic data for tests.

Events report local and AI completeness separately, including reasons for omitted AI bodies. The default incomplete-AI policy continues the local result; sites can choose rejection. Shadow evaluation does not alter the proxy response and merges its result into one final event.

AI admission has no waiting queue: defaults are 8 concurrent calls and 120 calls/minute, with per-site budgets. Five consecutive failures open a 30-second circuit. Configure `AI_MAX_CONCURRENT`, `AI_REQUESTS_PER_MINUTE`, and `AI_TIMEOUT_MS` as needed. `MAX_PROXY_CONCURRENT`, `MAX_TRACKED_CLIENTS`, and `EVENT_QUEUE_LIMIT` bound proxy concurrency, tracked IP state, and outstanding event writes.

`LOG_RETENTION_DAYS` defaults to 30. Cleanup removes at most 1000 expired details per minute, so a large backlog needs multiple passes. Trends and maps use retained details; independent counters preserve all-history totals. SQLite uses indexed SQL queries rather than loading full history. The system endpoint exposes event queue depth, drops, and write errors; details may be dropped when the queue is full.

For offline GeoIP in Docker, mount City/ASN `.mmdb` files under `./geoip`, or choose a file in the console and click **Save GeoIP**. Uploads are limited to 128 MB, validate the database type and do not replace a working database on failure. Uploaded files persist as `geoip/uploaded-city.mmdb` and `uploaded-asn.mmdb` in the API volume, taking precedence over environment paths. To return to mounted databases, stop the API, back up and move the corresponding uploaded file, then restart. Obtain and update databases under MaxMind's license; neither a production GeoIP database nor a live malicious-IP feed is bundled. Synthetic fixtures are test-only. Without a database, locations remain unknown and no online lookup occurs.

### API profiles and review

Each profile has a name, base URL, model, encrypted Key, enabled state, priority, timeout and failure policy. Lower priority numbers are selected first; a site can select a specific profile. This is not key rotation or provider failover. An unavailable selected profile falls back to rules, rather than silently using another key. Blank Key input keeps the current key; explicit removal applies on Save. Environment keys require an environment change and restart to remove. Third-party CAPTCHA secrets are encrypted too, and management responses never return plaintext.

Synchronous review waits for Jev. Asynchronous review forwards after local rules pass, then reviews in the background. A malicious result bans the source IP and interrupts its active HTTP/WebSocket traffic for that site. The base ban duration increases per occurrence, capped at the configured maximum; history survives restart. Already-forwarded requests and business side effects cannot be undone. `aiScope: all` reviews all passed requests; `suspicious` only reviews requests retaining risk signals. Whitelisted IPs are never chased or banned, and shadow evaluation only records. Unavailable providers follow failure policy without escalating ban history.

### Operation modes and queues

`defense` enforces security decisions. `record` forwards suspicious traffic, including CC/threat-feed/AI hits, and records `wouldBlock`; protocol checks, body limits and resource limits still apply. `maintenance` returns the configured static page and HTTP code, default 503, without contacting the upstream.

Waiting rooms count active requests, not logged-in people. An open WebSocket uses a slot until it closes. Configure activity, FIFO queue length, timeout and queue-full policy. Browser navigations receive a 202 queue page and poll a reusable ticket; non-browser requests wait on their connection. Timeout returns 429 and a full queue returns 429 or 503. Tickets and queues are not restart-persistent or distributed.

Upstream pools support at most 32 nodes, weights 1-1000, and safe-method connection failover. POST is not replayed. Redirects use explicit HTTP(S) targets and 301/302 codes, without per-path routing. Upstream connection failures and HTTP 5xx responses use the configured error page, default 502, replacing the upstream error body.

### CC and visitor verification

Per-site limits cover requests/second, burst capacity, concurrency, ban duration and selected paths. CAPTCHA can inherit global settings or be enabled/disabled per site. A CC-triggered client receives a local PoW or third-party challenge. Success issues a 10-minute HttpOnly token bound to site and IP, clears the CC ban, but does not bypass rules, threat feeds or asynchronous bans.

Local PoW has no external dependency but requires HTTPS on public domains because it uses `crypto.subtle`; localhost HTTP works for tests. Third-party providers are Turnstile, hCaptcha and reCAPTCHA v2, with Site Key, Secret, timeout and fail-open/fail-closed options. The server calls siteverify and checks hostname. Tests cover the verification protocol and failures; a real account/domain still needs your valid credentials and provider acceptance. Environment defaults use `CAPTCHA_ENABLED`, `CAPTCHA_PROVIDER`, `CAPTCHA_SITE_KEY`, `CAPTCHA_SECRET_KEY`, `CAPTCHA_TIMEOUT_MS` and `CAPTCHA_FAILURE_ACTION`; saved settings take precedence.

### Upload and import formats

| Content | Accepted format | Limit and behavior |
| --- | --- | --- |
| Waiting, maintenance, upstream error page | UTF-8 `.html` | 512 KB per page; upload to draft, Save site to apply |
| Whitelist / malicious IPs | CIDR text, JSON, CSV, STIX, TAXII JSON envelope | 1 MB content; preview, confirm list, Save policy |
| GeoIP | MaxMind GeoLite2/GeoIP2 City or ASN `.mmdb` | 128 MB; separately saved or mounted read-only |
| Nginx sites | UTF-8 `.conf` or pasted text | 1 MB; preview plus explicit transactional import |
| Rules | Strict JSON / supported ModSecurity `.conf` or `.txt` | Rule library preview and submission |
| Startup config | UTF-8 `.json` | 4 MB; applies at API startup |

HTML cannot execute server templates. Mounted files are relative to `/app/pages` (`PAGES_DIR=./pages`); absolute paths and directory escapes are rejected. Custom pages block scripts and forms, allowing inline styles and data/HTTPS images. Custom waiting content is isolated in a sandbox iframe; the outer controlled page manages polling. Maintenance/error status codes accept 400-599; active queue pages always return 202. Back up file-based pages separately from database-stored inline HTML.

IP text is one IPv4/IPv6/CIDR per line. JSON accepts `["203.0.113.10","2001:db8::/32"]` or `{"ips":["203.0.113.10"]}`. CSV uses the first column and supports quoted fields. STIX/TAXII extract direct equality indicators for `ipv4-addr:value` or `ipv6-addr:value` from an `objects` envelope; full STIX logical evaluation and TAXII URL polling are not supported. Preview removes invalid entries and duplicates, so inspect the result before confirming, especially a whitelist. The whitelist takes priority over IP bans/feeds, not content inspection or capacity checks. Default IP lists are empty.

The Nginx subset accepts `server`, single-port `listen`, `server_name`, root `location /`, `proxy_pass`, `upstream`, 301/302 `return`, basic proxy headers and timeouts. Header/timeout directives are recognized with preview warnings; their arguments are not applied and gateway defaults remain in use. `server_name` supplies a site name, not Host routing. Includes, Lua, unknown directives, regex or non-root locations and TLS listen directives are rejected. Extract supported site blocks from a full nginx.conf first. Ports must be unused and in the deployed range. Import history stores timestamps, ports and digests, not raw config. For example:

```nginx
upstream app { server app-a:9000 weight=2; server app-b:9000; }
server { listen 8081; server_name shop.example; location / { proxy_pass http://app; } }
server { listen 8082; return 302 https://example.com/new; }
```

Nginx generates all range mappings at startup; importing sites dynamically updates Node listeners without a reload. All entries still traverse the WAF. TLS and entry forwarding are in Nginx; pool balancing and redirects occur after WAF inspection. Changing the range or certificates requires recreating API/Web. Nginx and the API have fixed addresses (`172.29.83.2` and `172.29.83.3`) to avoid startup allocation conflicts. Only the configured gateway (`172.29.83.2/32` by default) is trusted for forwarding headers. Change `GATEWAY_IP`, `API_GATEWAY_IP` and `TRUSTED_PROXY_CIDRS` with `GATEWAY_SUBNET`; addresses must be distinct and within that subnet. Leave trusted proxies empty for direct Node access, never trust all clients.

### Startup JSON

Mount `config/jianflow.json` and set `JIANFLOW_CONFIG_FILE=/app/config/jianflow.json`:

```json
{
  "settings": { "auditMode": "async", "whitelistCidrs": ["203.0.113.10"] },
  "profiles": [{ "id": "primary", "name": "Primary", "baseUrl": "https://openrouter.ai", "model": "typesafe/jev-1.13", "apiKey": "replace-with-your-key" }],
  "sites": [{ "id": "shop", "name": "Shop", "listenPort": 8081, "upstreamUrl": "http://app:9000", "mode": "hybrid", "aiProfileId": "primary", "auditMode": "async", "maintenance": { "source": "file", "filePath": "maintenance.html", "statusCode": 503 } }]
}
```

Only `settings`, `profiles` and `sites` are accepted, with API schema validation and stable profile/site IDs. Missing sites are not deleted. Profiles, settings and sites persist sequentially; the entire file is not one transaction, so a later semantic/storage failure can leave earlier changes applied and abort startup. Test files before deployment. Listed settings override console changes again on restart. Keys in this file are plaintext: do not commit it, restrict access and make it readable only by the administrator and container user.

For HTTPS on the **WAF entry point**, put readable certificate files under `./certs` and set:

```dotenv
TLS_CERT_DIR=./certs
TLS_KEY_PATH=/app/certs/tls.key
TLS_CERT_PATH=/app/certs/tls.crt
```

Apply the configuration with `docker compose up -d --build`. The HTTPS WAF entry point uses port 8443; this does not add HTTPS to the console on port 3000. Set `SESSION_COOKIE_SECURE=true` when accessing the console through an HTTPS reverse proxy.

## Docs and FAQ

- [Linux deployment](#deploy-on-linux) · [Local development](#develop-locally-on-linux) · [Modes and configuration](#features-and-configuration) · [License](#license)
- Management API: `GET /api/v1/health` is public; other `/api/v1/*` endpoints require an HttpOnly session cookie obtained from `POST /api/v1/auth/login`. Test rules using `POST /api/v1/rules/test` with `method`, `path`, `query`, and `headers`.
- **No AI key?** The console disables AI and hybrid modes and the API falls back to rules-only mode. Save a Jev key before selecting either AI mode.
- **502 on allowed requests?** Check the upstream's listening address and whether `UPSTREAM_URL` is reachable from the API container. Do not use container-local `127.0.0.1` for a host service.
- **Startup failure?** Run `docker compose logs --tail=100 api postgres` and check the password file, volume access, `SITE_PORT_RANGE`, and configured paths.
- **Production ready?** Validate against your traffic first. Isolate administration, use HTTPS, and complete security and load testing before a production rollout.

## Contributing

```bash
npm ci
npm run typecheck
npm test
npm run build
npm run test:e2e
```

Open an [issue](https://github.com/wrhc2010/JianFlow-WAF/issues) with reproduction steps and expected versus actual behavior. Documentation, tests, and reproducible false-positive cases are good places to start; check [good first issues](https://github.com/wrhc2010/JianFlow-WAF/labels/good%20first%20issue) or open a discussion issue. Do not include keys or customer request data.

## License

[MIT](LICENSE). Rule and offline map attribution is documented in [RULES.md](packages/waf-core/RULES.md). Review the licenses and security of bundled dependencies before deploying the images.
