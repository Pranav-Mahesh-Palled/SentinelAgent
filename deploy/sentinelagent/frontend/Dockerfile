# =============================================================================
# SentinelAgent Frontend Production Multi-Stage Dockerfile
# Stage 1: Build React Dashboard
# Stage 2: Unprivileged Nginx Runtime
# =============================================================================

# --- Stage 1: Build ---
FROM node:22-alpine AS builder

WORKDIR /build

# Copy dependency manifests
COPY frontend/package.json frontend/package-lock.json* ./

# Install dependencies deterministically
RUN npm ci

# Copy frontend source files and configuration
COPY frontend/ ./

# Run production build (TypeScript check + Vite bundle)
RUN npm run build

# --- Stage 2: Runtime ---
FROM nginx:1.30-alpine@sha256:901e593c95dc85f5a729f5765516321366ef4ac401821431d408897e95287d0a AS runtime

# Install wget for healthcheck
RUN apk add --no-cache wget

# Set up unprivileged permissions for nginx
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chmod -R 755 /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    touch /tmp/nginx.pid && \
    chown -R nginx:nginx /tmp/nginx.pid

# Copy custom Nginx configuration
COPY deploy/sentinelagent/frontend/nginx.conf /etc/nginx/nginx.conf

# Copy production static assets from builder stage
COPY --from=builder /build/dist /usr/share/nginx/html

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:8080/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
