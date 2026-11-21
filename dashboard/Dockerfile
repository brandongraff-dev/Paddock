# ---- build stage ----------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /app

# Install deps first for layer caching
COPY package.json ./
RUN npm install --no-audit --no-fund --loglevel=error

# Copy source + build
COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
COPY tests ./tests

# VITE_API_URL at build-time is only used for dev; in prod we proxy via nginx.
ARG VITE_API_URL=""
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# ---- serve stage ----------------------------------------------------------
FROM nginx:alpine AS serve

# Replace default nginx config
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

# Copy built static bundle
COPY --from=build /app/dist /usr/share/nginx/html

# Run as the stock unprivileged `nginx` user (uid 101). When the master is
# non-root, worker processes also run as that user (the conf's `user`
# directive, if any, is ignored), so every dir nginx writes must be owned by
# it: the cache/temp scratch dirs, the log dir, and the served html. The pid
# file defaults to /run, which nginx cannot write as non-root, so it is moved
# to /tmp via the `-g` flag below (nginx.conf is intentionally left untouched).
# Port 3000 is >1024, so no privileged-port change is needed.
RUN chown -R nginx:nginx /var/cache/nginx /var/log/nginx /usr/share/nginx/html

EXPOSE 3000

USER nginx

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:3000/ >/dev/null || exit 1

CMD ["nginx", "-g", "daemon off; pid /tmp/nginx.pid;"]
