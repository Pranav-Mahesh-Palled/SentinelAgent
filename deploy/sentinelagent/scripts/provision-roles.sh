#!/bin/sh
# =============================================================================
# Helper script to provision database roles against an already-running SentinelAgent database
# Useful when mounting an already-initialized persistent PostgreSQL volume.
# =============================================================================
set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)"
SECRETS_DIR="$DIR/secrets"

if [ ! -f "$SECRETS_DIR/postgres_admin_password.txt" ]; then
    echo "ERROR: $SECRETS_DIR/postgres_admin_password.txt not found." >&2
    exit 1
fi

ADMIN_PASS=$(cat "$SECRETS_DIR/postgres_admin_password.txt" | tr -d '\r\n')
MIG_PASS=$(cat "$SECRETS_DIR/migration_password.txt" | tr -d '\r\n')
APP_PASS=$(cat "$SECRETS_DIR/app_password.txt" | tr -d '\r\n')

echo "Executing role provisioning against sentinelagent-db container..."

docker compose -f "$DIR/compose.yaml" exec -T db env \
    PGPASSWORD="$ADMIN_PASS" \
    MIGRATION_PASSWORD="$MIG_PASS" \
    APP_PASSWORD="$APP_PASS" \
    sh -c '/docker-entrypoint-initdb.d/01-init-roles.sh'

echo "Role provisioning complete."
