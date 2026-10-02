# JianFlow WAF

A self-hosted Web Application Firewall that checks HTTP requests using local rules, Jev AI classification, or both. This guide targets Linux servers and uses Bash commands for v0.2.0.

[![License: MIT](https://img.shields.io/github/license/wrhc2010/JianFlow-WAF)](LICENSE)
[![Release](https://img.shields.io/github/v/release/wrhc2010/JianFlow-WAF)](https://github.com/wrhc2010/JianFlow-WAF/releases)
[![CI](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml/badge.svg)](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml)
[![Node.js 22](https://img.shields.io/badge/Node.js-22-339933)](package.json)

[中文](README.md) | **English**

Run a test deployment before connecting real traffic. A production rollout still needs a security audit, load testing, and staged validation for your application. See the [changelog](CHANGELOG.md) for release details.

## Screenshot

![JianFlow console running locally](docs/images/console.png)

This is the login page from a running local instance. Sign in to inspect decisions, rules, and settings.

## Deploy on Linux

Requires Git, curl, OpenSSL, Docker Engine, and Docker Compose v2. Docker must be running; the host does not need Node.js for a container deployment.

### Prepare configuration

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

The password file must be readable by the PostgreSQL container user. Its mode is `644`, while the host's `secrets` directory is `700` to prevent access by other ordinary host users. Generate this password only for a new deployment; do not replace it for an existing database.

Edit `.env` to use an upstream and GeoIP paths accessible from the container:

```dotenv
UPSTREAM_URL=http://host.docker.internal:9000
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
curl -fsS http://127.0.0.1:4000/api/v1/health
```

Wait for the health checks to pass. The health endpoint should return JSON containing `"ok": true`. Open `http://SERVER_ADDRESS:3000` in your browser to finish initialization.

| Entry point | Port | Purpose |
| --- | ---: | --- |
| Console | 3000 | Setup, rules, and events |
| Management API | 4000 | Health checks and management endpoints |
| WAF HTTP | 8080 | Protected HTTP traffic |
| WAF HTTPS | 8443 | Available after configuring certificates |

The current Compose file publishes these ports on all host interfaces; PostgreSQL is not published. Restrict access to the console and API. Use a trusted HTTPS reverse proxy for remote administration instead of exposing ports 3000 and 4000 directly to the Internet.

PostgreSQL reads its password from a file-backed Docker secret. Use `POSTGRES_PASSWORD_FILE_SOURCE` for an existing password file; an explicit `DATABASE_URL` takes precedence for the API. PostgreSQL and API data use persistent named volumes. GeoIP files are mounted read-only from the host's `GEOIP_DIR`.

### Use release images

To skip the build, download both image archives from the [v0.2.0 release](https://github.com/wrhc2010/JianFlow-WAF/releases/tag/v0.2.0). Prepare configuration and the password file as above, then import the images:

```bash
docker load -i jianflow-waf-api-v0.2.0.tar.gz
docker load -i jianflow-waf-web-v0.2.0.tar.gz
IMAGE_TAG=v0.2.0 docker compose up -d --no-build --pull never
```

`--pull never` will not download missing images. If the PostgreSQL image is not available locally, run `docker pull postgres:16-alpine` first.

### Logs and maintenance

```bash
docker compose logs --tail=100 api web postgres
docker compose restart api web
docker compose down
```

`docker compose down` removes containers and networks but keeps named volumes. Do not add `-v` when you need to keep the data. Back up PostgreSQL data, the API data volume, `.env`, and the database password file together. Losing or changing the session secret makes existing encrypted API keys unreadable.

## Develop locally on Linux

Requires Node.js 22 or newer and npm. From the repository root:

```bash
npm ci
cp .env.example .env
chmod 600 .env
npm run dev
```

Do not overwrite `.env` if it already exists. The dev script builds the core package before starting the API and frontend. The console, API, and WAF use ports 3000, 4000, and 8080. When running directly on the host, `UPSTREAM_URL=http://127.0.0.1:9000` can reach a local upstream. Without PostgreSQL configuration, settings, rules, and events persist in SQLite under `DATA_DIR`.

Set the administrator password on first launch; the default username is `admin`. With the default hybrid mode, try a rule-triggering request:

```bash
curl -i "http://127.0.0.1:8080/search?q=union+select+password+from+users"
```

It should return `403` without needing the upstream or AI service.

## Features and configuration

- **AI**: blocks when Jev's `noul` malicious probability meets the threshold; returns 503 when Jev is unavailable.
- **Rules**: local request normalization and rules for common SQL injection, XSS, traversal, template injection, NoSQL injection, command injection, and unsafe URL patterns. JSON and supported ModSecurity `SecRule` imports include preview, validation, conflict handling, and atomic writes; this is not the full OWASP CRS engine.
- **Hybrid**: rules first, then Jev. If Jev is unavailable, requests that pass the rules are allowed and logged as degraded.
- **Inspection**: checks paths, queries, headers, cookies, IPs, and complete request bodies, including JSON, forms, XML, multipart, text, and gzip/deflate/brotli bodies. HTTP and WebSocket handshakes are inspected; subsequent WebSocket frames are passed through.
- **Console and storage**: all-history statistics, cursor pagination, filters, rule management, encrypted API key storage, PostgreSQL or persistent SQLite, and offline GeoIP with 2D/3D attack views.

Threshold presets are 10%, 30%, 50%, 70%, and 90%, with custom values from 0% to 100%. Configure Jev in the console or use server-side environment variables:

```dotenv
JEV_API_KEY=your-jev-key
JEV_MODEL=typesafe/jev-1.13
JEV_BASE_URL=https://openrouter.ai
```

The base URL accepts a provider root or a full decision endpoint. Keys saved through the console are encrypted using the session secret; management responses do not return their plaintext. Sensitive fields are redacted before AI submission where recognized, but this is not a privacy guarantee. Do not test with real customer data.

For offline GeoIP in Docker, place your `GeoIP2-City.mmdb` and `GeoIP2-ASN.mmdb` files under `./geoip` and use the container paths shown above. Without the databases, source locations remain unknown.

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
- **No AI key?** Select rules-only mode. Hybrid mode allows rule-passing requests when Jev is unavailable.
- **502 on allowed requests?** Check the upstream's listening address and whether `UPSTREAM_URL` is reachable from the API container. Do not use container-local `127.0.0.1` for a host service.
- **Startup failure?** Run `docker compose logs --tail=100 api postgres` and check the password file, volume access, and configured paths.
- **Production ready?** Validate against your traffic first. Isolate administration, use HTTPS, and complete security and load testing before a production rollout.

## Contributing

```bash
npm ci
npm run typecheck
npm test
npm run build
```

Open an [issue](https://github.com/wrhc2010/JianFlow-WAF/issues) with reproduction steps and expected versus actual behavior. Documentation, tests, and reproducible false-positive cases are good places to start; check [good first issues](https://github.com/wrhc2010/JianFlow-WAF/labels/good%20first%20issue) or open a discussion issue. Do not include keys or customer request data.

## License

[MIT](LICENSE). Rule and offline map attribution is documented in [RULES.md](packages/waf-core/RULES.md). Review the licenses and security of bundled dependencies before deploying the images.
