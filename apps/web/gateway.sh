#!/bin/sh
set -eu

range="${SITE_PORT_RANGE:-8080-8099}"
case "$range" in *[!0-9-]*|""|-*|*-) echo "Invalid SITE_PORT_RANGE" >&2; exit 1 ;; esac
first="${range%-*}"
last="${range#*-}"
[ "$first" -ge 1 ] && [ "$last" -le 65535 ] && [ "$first" -le "$last" ] && [ $((last-first)) -le 999 ] || exit 1
output="${GATEWAY_CONFIG_FILE:-/etc/nginx/conf.d/jianflow-entries.conf}"
temporary="${output}.tmp"
printf 'map $http_upgrade $jianflow_connection { default upgrade; "" close; }\n' > "$temporary"
port="$first"
while [ "$port" -le "$last" ]; do
  printf 'server {\n  listen %s;\n  server_name _;\n  client_max_body_size 10m;\n  location / {\n    proxy_pass http://api:%s;\n    proxy_http_version 1.1;\n    proxy_set_header Host $http_host;\n    proxy_set_header X-Forwarded-For $remote_addr;\n    proxy_set_header X-Forwarded-Proto $scheme;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $jianflow_connection;\n    proxy_buffering off;\n    proxy_request_buffering off;\n    proxy_connect_timeout 10s;\n    proxy_read_timeout 86400s;\n    proxy_send_timeout 60s;\n  }\n}\n' "$port" "$port" >> "$temporary"
  port=$((port+1))
done
if [ -n "${GATEWAY_TLS_CERT:-}" ] || [ -n "${GATEWAY_TLS_KEY:-}" ]; then
  [ -r "${GATEWAY_TLS_CERT:-}" ] && [ -r "${GATEWAY_TLS_KEY:-}" ] || { echo "Both gateway TLS files are required" >&2; exit 1; }
  case "${GATEWAY_TLS_CERT}${GATEWAY_TLS_KEY}" in *[!a-zA-Z0-9_./-]*) echo "Invalid TLS file path" >&2; exit 1 ;; esac
  printf 'server { listen 8443 ssl; server_name _; ssl_certificate %s; ssl_certificate_key %s; client_max_body_size 10m; location / { proxy_pass http://api:8080; proxy_http_version 1.1; proxy_set_header Host $http_host; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Proto $scheme; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $jianflow_connection; proxy_buffering off; proxy_request_buffering off; proxy_read_timeout 86400s; } }\n' "$GATEWAY_TLS_CERT" "$GATEWAY_TLS_KEY" >> "$temporary"
fi
mv "$temporary" "$output"
if [ "${GATEWAY_SKIP_TEST:-false}" != "true" ]; then nginx -t; fi
