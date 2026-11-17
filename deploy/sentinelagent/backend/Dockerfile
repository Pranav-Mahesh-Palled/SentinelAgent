# =============================================================================
# SentinelAgent Backend Production Dockerfile
# Multi-purpose image serving API, Background Worker, and Migration Runner
# =============================================================================

FROM python:3.13-slim-bookworm AS production

# Security: Create non-root system user and group
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -m -s /bin/sh sentinel

WORKDIR /app

# Install security updates and curl for container health checks
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy entrypoint script and set permissions
COPY deploy/sentinelagent/backend/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Copy application configuration and source code
COPY alembic.ini /app/alembic.ini
COPY backend /app/backend

# Set non-root ownership
RUN chown -R sentinel:sentinel /app

# Switch to non-root user
USER sentinel

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app/backend" \
    ENVIRONMENT=production

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["api"]
