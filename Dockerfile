# Build from this directory: docker build -t atc-auth .
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production DB_PATH=/data/auth.db JWT_PRIVATE_KEY_PATH=/keys/jwt-private.pem PORT=3002
WORKDIR /app
RUN mkdir -p /data /keys && chown node:node /data /keys
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY openapi.yaml ./
COPY src ./src
COPY scripts ./scripts
USER node
VOLUME ["/data", "/keys"]
EXPOSE 3002
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- --no-check-certificate "$( [ -n "$TLS_CERT_PATH" ] && echo https || echo http )://127.0.0.1:3002/health" || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "src/index.js"]
