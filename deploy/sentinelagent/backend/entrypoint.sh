#!/bin/sh
# =============================================================================
# SentinelAgent Backend Container Entrypoint
# Dispatches execution to api, worker, or migration runner while preserving
# process replacement (exec) for graceful signal handling (SIGTERM/SIGINT).
# =============================================================================
set -e

export PYTHONPATH="/app/backend:${PYTHONPATH}"

# Verify secret file readability for non-root container process (UID 10001)
verify_secret_readable() {
    file_var="$1"
    file_path="$2"
    required="${3:-false}"
    if [ -n "$file_path" ]; then
        if [ ! -e "$file_path" ]; then
            if [ "$required" = "true" ]; then
                echo "FATAL [entrypoint]: Required secret file configured by $file_var does not exist at $file_path" >&2
                exit 1
            fi
            return 0
        fi
        if [ ! -r "$file_path" ]; then
            echo "FATAL [entrypoint]: Secret file configured by $file_var ($file_path) is not readable by non-root UID $(id -u):GID $(id -g) (Permission denied)." >&2
            echo "HINT: Docker Compose bind-mounts file secrets directly from the host. Ensure host secret files have mode 0644 (chmod 644 deploy/sentinelagent/secrets/*)." >&2
            exit 1
        fi
    fi
}

# Subcommand dispatch
case "$1" in
    api)
        shift
        # Ensure runtime application role DSN is used if direct DATABASE_URL is not set
        if [ -z "$DATABASE_URL" ] && [ -z "$DATABASE_URL_FILE" ]; then
            if [ -n "$APP_DATABASE_URL_FILE" ]; then
                export DATABASE_URL_FILE="$APP_DATABASE_URL_FILE"
            elif [ -n "$APP_DATABASE_URL" ]; then
                export DATABASE_URL="$APP_DATABASE_URL"
            fi
        fi
        # Fast pre-flight check for secret file readability
        verify_secret_readable "DATABASE_URL_FILE" "$DATABASE_URL_FILE" true
        verify_secret_readable "APP_DATABASE_URL_FILE" "$APP_DATABASE_URL_FILE" false
        verify_secret_readable "OPERATOR_CREDENTIALS_FILE" "$OPERATOR_CREDENTIALS_FILE" true
        verify_secret_readable "GEMINI_API_KEY_FILE" "$GEMINI_API_KEY_FILE" false

        echo "Starting SentinelAgent FastAPI production server (sentinel_app_role)..."
        exec uvicorn app.main:app \
            --host 0.0.0.0 \
            --port 8000 \
            --workers "${UVICORN_WORKERS:-2}" \
            --timeout-graceful-shutdown 15 \
            "$@"
        ;;
    worker)
        shift
        # Ensure runtime application role DSN is used if direct DATABASE_URL is not set
        if [ -z "$DATABASE_URL" ] && [ -z "$DATABASE_URL_FILE" ]; then
            if [ -n "$APP_DATABASE_URL_FILE" ]; then
                export DATABASE_URL_FILE="$APP_DATABASE_URL_FILE"
            elif [ -n "$APP_DATABASE_URL" ]; then
                export DATABASE_URL="$APP_DATABASE_URL"
            fi
        fi
        # Fast pre-flight check for secret file readability
        verify_secret_readable "DATABASE_URL_FILE" "$DATABASE_URL_FILE" true
        verify_secret_readable "APP_DATABASE_URL_FILE" "$APP_DATABASE_URL_FILE" false
        verify_secret_readable "OPERATOR_CREDENTIALS_FILE" "$OPERATOR_CREDENTIALS_FILE" false
        verify_secret_readable "GEMINI_API_KEY_FILE" "$GEMINI_API_KEY_FILE" false

        echo "Starting SentinelAgent Response Orchestration Worker (sentinel_app_role)..."
        exec python -m app.worker "$@"
        ;;
    migrate)
        shift
        # Ensure migration role DSN is used if direct DATABASE_URL is not set
        if [ -z "$DATABASE_URL" ] && [ -z "$DATABASE_URL_FILE" ]; then
            if [ -n "$MIGRATION_DATABASE_URL_FILE" ]; then
                export DATABASE_URL_FILE="$MIGRATION_DATABASE_URL_FILE"
            elif [ -n "$MIGRATION_DATABASE_URL" ]; then
                export DATABASE_URL="$MIGRATION_DATABASE_URL"
            fi
        fi
        # Fast pre-flight check for secret file readability
        verify_secret_readable "DATABASE_URL_FILE" "$DATABASE_URL_FILE" true
        verify_secret_readable "MIGRATION_DATABASE_URL_FILE" "$MIGRATION_DATABASE_URL_FILE" false

        echo "Running SentinelAgent Alembic database migrations (sentinel_migration_role)..."
        alembic upgrade head "$@"
        echo "Enforcing least-privilege runtime grants on sentinel_app_role..."
        python -m app.db.align_roles
        ;;
    *)
        exec "$@"
        ;;
esac
