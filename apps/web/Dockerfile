FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/waf-core/package.json packages/waf-core/package.json
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
RUN npm ci
COPY packages/waf-core packages/waf-core
COPY apps/web apps/web
RUN npm run build -w packages/waf-core && npm run build -w apps/web

FROM nginx:1.30.5-alpine
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/web/gateway.sh /docker-entrypoint.d/40-jianflow-gateway.sh
RUN chmod 755 /docker-entrypoint.d/40-jianflow-gateway.sh
EXPOSE 80 8080-8099 8443
