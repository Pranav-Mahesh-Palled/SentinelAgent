#!/bin/sh
# =============================================================================
# Helper script to generate initial high-entropy secrets for SentinelAgent
# =============================================================================
set -e

SECRETS_DIR="$(cd "$(dirname "$0")/.." && pwd)/secrets"
mkdir -p "$SECRETS_DIR"

# Verify directory ownership
DIR_OWNER_UID=$(stat -c '%u' "$SECRETS_DIR" 2>/dev/null || stat -f '%u' "$SECRETS_DIR" 2>/dev/null || id -u)
CURRENT_UID=$(id -u 2>/dev/null || echo "$DIR_OWNER_UID")

if [ "$DIR_OWNER_UID" != "$CURRENT_UID" ]; then
    echo "WARNING: $SECRETS_DIR is owned by UID $DIR_OWNER_UID, but current process is running as UID $CURRENT_UID." >&2
fi

# Restrict host directory traversal exclusively to the directory owner (0700)
chmod 700 "$SECRETS_DIR"

gen_password() {
    python3 -c "import secrets; print(secrets.token_urlsafe(32))"
}

# 1. PostgreSQL Admin Password
if [ ! -f "$SECRETS_DIR/postgres_admin_password.txt" ]; then
    gen_password > "$SECRETS_DIR/postgres_admin_password.txt"
    echo "Generated postgres_admin_password.txt"
fi

# 2. Migration Role Password & DSN
if [ ! -f "$SECRETS_DIR/migration_password.txt" ]; then
    MIG_PASS=$(gen_password)
    echo -n "$MIG_PASS" > "$SECRETS_DIR/migration_password.txt"
    echo -n "postgresql+psycopg://sentinel_migration_role:${MIG_PASS}@db:5432/sentinelagent" > "$SECRETS_DIR/migration_database_url.txt"
    echo "Generated migration_password.txt and migration_database_url.txt"
fi

# 3. Application Role Password & DSN
if [ ! -f "$SECRETS_DIR/app_password.txt" ]; then
    APP_PASS=$(gen_password)
    echo -n "$APP_PASS" > "$SECRETS_DIR/app_password.txt"
    echo -n "postgresql+psycopg://sentinel_app_role:${APP_PASS}@db:5432/sentinelagent" > "$SECRETS_DIR/app_database_url.txt"
    echo "Generated app_password.txt and app_database_url.txt"
fi

# 4. Operator Credentials template
if [ ! -f "$SECRETS_DIR/operator_credentials.json" ]; then
    cat > "$SECRETS_DIR/operator_credentials.json" << 'EOF'
[
  {
    "operator_id": "op-analyst-01",
    "role": "analyst",
    "key_sha256": "c04fb597231c134cb36ab30d09e7bcfb0b030d8431813982b1cb1c55e10bc7ff"
  },
  {
    "operator_id": "op-approver-01",
    "role": "approver",
    "key_sha256": "1674ad86283e3eb9b6965b72c250e020da6bf456f6992bbdf97a805ed30abede"
  },
  {
    "operator_id": "op-admin-01",
    "role": "admin",
    "key_sha256": "07cc606494fc364c3f41e2c519de30a46b3eef4db3c2629aa5e06ed85270e738"
  }
]
EOF
    echo "Created operator_credentials.json template"
fi

# 5. Gemini API Key placeholder
if [ ! -f "$SECRETS_DIR/gemini_api_key.txt" ]; then
    touch "$SECRETS_DIR/gemini_api_key.txt"
    echo "Created gemini_api_key.txt placeholder"
fi

# Host permissions for Docker Compose bind-mount secrets:
# Standard Docker Compose implements 'file:' secrets as read-only bind mounts,
# ignoring container-level uid/gid/mode overrides.
#
# Permission Model:
# 1. Parent Directory: Explicitly restricted to owner (mode 0700: drwx------).
#    Unprivileged host users cannot traverse into or list $SECRETS_DIR.
# 2. Secret Files: Retained at mode 0644 (rw-r--r--) ONLY if the parent directory
#    is restricted to its owner (0700). Mode 0644 allows the Docker daemon to bind-mount
#    the files so non-root container processes (UID 10001 for api/worker/migration,
#    UID 70 for postgres) can read them inside the container namespace.
#    Files are never world-writable (o-w is zero).
#
# Rootful vs Rootless Docker Requirements:
# - Rootful Docker: The daemon runs as host root, bypassing the 0700 directory restriction
#   to establish the bind mount. Non-root container processes can then read the mounted
#   0644 inodes inside the container.
# - Rootless Docker: The daemon runs inside the user's unprivileged user namespace.
#   The user executing 'docker compose' MUST own the 0700 secrets directory (UID match),
#   otherwise the rootless daemon will receive EACCES when attempting to access the source files.

DIR_PERM=$(stat -c '%a' "$SECRETS_DIR" 2>/dev/null || stat -f '%Lp' "$SECRETS_DIR" 2>/dev/null || echo "700")

# Ensure parent directory is strictly owner-restricted before applying 0644
if [ "$DIR_PERM" = "700" ]; then
    chmod 644 "$SECRETS_DIR"/*
    echo "Secret provisioning completed in $SECRETS_DIR (file mode 0644, directory mode 0700)."
else
    echo "ERROR: Directory $SECRETS_DIR permission is $DIR_PERM, expected 700. Refusing to set 0644 on secrets." >&2
    exit 1
fi
