# JianFlow WAF

A small WAF prototype for developers who want to test rule-based filtering, Jev AI classification, or both in front of an HTTP service.

[![License: MIT](https://img.shields.io/github/license/wrhc2010/JianFlow-WAF)](LICENSE)
[![Release](https://img.shields.io/github/v/release/wrhc2010/JianFlow-WAF)](https://github.com/wrhc2010/JianFlow-WAF/releases)
[![CI](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml/badge.svg)](https://github.com/wrhc2010/JianFlow-WAF/actions/workflows/ci.yml)
[![Node.js 22](https://img.shields.io/badge/Node.js-22-339933)](package.json)

[中文](README.md) | **English**

> For experiments only. This prototype has not been security-audited, load-tested, or validated for production protection.

## Screenshot

![JianFlow console running locally](docs/images/console.png)

This is the login page from a running local instance. Sign in to inspect decisions, rules, and settings.

## Quick start

Requires Docker Compose v2 and a test upstream service. Clone the repository and create your local configuration:

```bash
git clone https://github.com/wrhc2010/JianFlow-WAF.git
cd JianFlow-WAF
cp .env.example .env
```

Set `ADMIN_PASSWORD`, `SESSION_SECRET`, and `POSTGRES_PASSWORD` in `.env` (use a random PostgreSQL password with no URL-reserved characters). Set `UPSTREAM_URL` to your test application. Add `OPENROUTER_API_KEY` only if you want AI classification.

```bash
docker compose up -d --pull always --no-build
```

This pulls the published API and Web images from GHCR. Use `docker compose up -d --build` to build locally instead. Open the console at `http://localhost:3000`, send test traffic to `http://localhost:8080`, or check the API at `http://localhost:4000/api/v1/health`. The console and WAF listen on LAN by default; the API binds to the host loopback, and PostgreSQL is not published. Do not expose the console on an untrusted network without an HTTPS reverse proxy and access controls.

The default container upstream is `http://host.docker.internal:9000`. For a service on the same Compose network, use its service name, such as `UPSTREAM_URL=http://app:8080`.

For local development with Node.js 22:

```bash
npm ci
cp .env.example .env
# Set ADMIN_PASSWORD; leave DATABASE_URL empty to use in-memory storage
npm run dev
```

The local console, API, and WAF listen on ports 3000, 4000, and 8080 respectively. The default username is `admin`. With the default hybrid mode, try a rule-triggering request:

```bash
curl -i "http://127.0.0.1:8080/search?q=union+select+password+from+users"
```

It should return `403` without needing the upstream or AI service.

## Features and configuration

- **AI**: blocks when Jev's `noul` malicious probability meets the threshold; returns 503 when Jev is unavailable.
- **Rules**: five built-in CRS-style examples, not the full OWASP CRS. Covers a limited set of SQLi, XSS, traversal, command-injection, and scanning patterns.
- **Hybrid**: rules first, then Jev. If Jev is unavailable, requests that pass the rules are allowed and logged as degraded.
- **Console**: inspect recent decisions, test rules, set the mode and threshold, and change the default upstream. HTTP and WebSocket handshakes are inspected; subsequent WebSocket frames are passed through.

Current thresholds: low 50%, medium 70%, high 85%, extreme 95%, or a custom value from 0% to 100%. The default model is `typesafe/jev-1.13`; `~typesafe/jev-latest` is also selectable. Supply the OpenRouter key only through the server-side `.env`. Sensitive fields are redacted before AI submission where recognized, but this is not a privacy guarantee. Do not test with real customer data.

For HTTPS on the **WAF entry point**, mount a certificate directory using `TLS_CERT_DIR` and set `TLS_KEY_PATH=/app/certs/tls.key` and `TLS_CERT_PATH=/app/certs/tls.crt` (port 8443). This does not add HTTPS to the management console on port 3000.

## Docs and FAQ

- [Installation](#quick-start) · [Modes and configuration](#features-and-configuration) · [License](#license)
- Management API: `GET /api/v1/health` is public; other `/api/v1/*` endpoints require an HttpOnly session cookie obtained from `POST /api/v1/auth/login`. Test rules using `POST /api/v1/rules/test` with `method`, `path`, `query`, and `headers`.
- **No AI key?** Select rules-only mode. Hybrid mode allows rule-passing requests when Jev is unavailable.
- **502 on allowed requests?** Check that `UPSTREAM_URL` is reachable from the API container.
- **Production ready?** No. The prototype needs stronger authentication, fuller rules, a security audit, and load testing.

## Contributing

```bash
npm ci
npm run typecheck
npm test
npm run build
```

Open an [issue](https://github.com/wrhc2010/JianFlow-WAF/issues) with reproduction steps and expected versus actual behavior. Documentation, tests, and reproducible false-positive cases are good places to start; check [good first issues](https://github.com/wrhc2010/JianFlow-WAF/labels/good%20first%20issue) or open a discussion issue. Do not include keys or customer request data.

## License

[MIT](LICENSE). Review the licenses and security of bundled dependencies before deploying the images.
