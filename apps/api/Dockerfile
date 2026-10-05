FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/waf-core/package.json packages/waf-core/package.json
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
RUN npm ci
COPY packages/waf-core packages/waf-core
COPY apps/api apps/api
RUN npm run build -w packages/waf-core && npm run build -w apps/api

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/apps/web/package.json ./apps/web/package.json
COPY --from=build /app/packages/waf-core/package.json ./packages/waf-core/package.json
COPY --from=build /app/packages/waf-core/dist ./packages/waf-core/dist
COPY --from=build /app/apps/api/package.json ./apps/api/package.json
COPY --from=build /app/apps/api/dist ./apps/api/dist
RUN npm ci --omit=dev --workspace=apps/api --workspace=packages/waf-core && apk add --no-cache su-exec
COPY apps/api/docker-entrypoint.sh /usr/local/bin/jianflow-entrypoint
RUN chmod 755 /usr/local/bin/jianflow-entrypoint
EXPOSE 4000 8080-8099 8443
ENTRYPOINT ["jianflow-entrypoint"]
CMD ["node", "apps/api/dist/server.js"]
