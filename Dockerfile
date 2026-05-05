FROM node:20-alpine

WORKDIR /app

COPY scouts-i-am/package.json ./
COPY scouts-i-am/src ./src

ENV PORT=3000
ENV DATA_FILE=/data/store.json
ENV ORM_BASE_URL=http://127.0.0.1:4175
ENV INTERNAL_SERVICE_TOKEN=scouts-internal-service

EXPOSE 3000

RUN mkdir -p /data && chown -R node:node /app /data

USER node

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/health').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "src/server.js"]
