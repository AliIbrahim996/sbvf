# SBVF frontend — Next.js dashboard.
# Multi-stage build producing a slim standalone server image. It talks to the
# Python SSE backend over the compose network; set SBVF_API_ORIGIN to its origin
# (e.g. http://sbvf:8080). See docker-compose.yml.

# ---- deps: install node_modules from the lockfile ---------------------------
FROM node:24-alpine3.22 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ---- build: compile the standalone output -----------------------------------
FROM node:24-alpine3.22 AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ---- run: minimal runtime image ---------------------------------------------
FROM node:24-alpine3.22 AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001
RUN apk upgrade --no-cache

# Standalone output ships its own minimal server + the pruned node_modules.
COPY --from=build /app/public ./public
COPY --from=build --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=build --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
