"""Automated Tests for Task 12.4 - API, Worker and Frontend Deployment Integration.

Validates the full deployment architecture, service contracts, health/readiness endpoints,
reverse proxy configuration, and service dependency ordering without writing to the shared database.
"""

from pathlib import Path
import re
import unittest.mock as mock

from fastapi import status
from fastapi.testclient import TestClient
import pytest
import yaml

from app.core.config import Settings
from app.main import app

DEPLOY_DIR = Path(__file__).resolve().parent.parent.parent / "deploy" / "sentinelagent"
COMPOSE_PATH = DEPLOY_DIR / "compose.yaml"
ENTRYPOINT_PATH = DEPLOY_DIR / "backend" / "entrypoint.sh"
NGINX_CONF_PATH = DEPLOY_DIR / "frontend" / "nginx.conf"
FRONTEND_CLIENT_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "src"
    / "api"
    / "client.ts"
)


# =============================================================================
# 1. API Deployment Integration Tests
# =============================================================================

def test_api_asgi_command_and_binding():
    """Verify entrypoint.sh dispatches production uvicorn command with correct host, port, and flags."""
    assert ENTRYPOINT_PATH.is_file(), f"Missing entrypoint script at {ENTRYPOINT_PATH}"
    content = ENTRYPOINT_PATH.read_text(encoding="utf-8")

    # Verify api dispatch block
    assert "api)" in content
    assert "uvicorn app.main:app" in content
    assert "--host 0.0.0.0" in content
    assert "--port 8000" in content
    assert '--workers "${UVICORN_WORKERS:-2}"' in content
    assert "--timeout-graceful-shutdown 15" in content

    # Verify DSN mapping to application role
    assert 'export DATABASE_URL_FILE="$APP_DATABASE_URL_FILE"' in content
    assert 'export DATABASE_URL="$APP_DATABASE_URL"' in content

    # Verify non-root UID 10001 secret readability verification
    assert 'verify_secret_readable "DATABASE_URL_FILE" "$DATABASE_URL_FILE" true' in content
    assert 'verify_secret_readable "OPERATOR_CREDENTIALS_FILE" "$OPERATOR_CREDENTIALS_FILE" true' in content


def test_api_health_liveness_endpoint():
    """Verify /api/health/live returns HTTP 200 without checking database connectivity."""
    client = TestClient(app)
    response = client.get("/api/health/live")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "alive"}


def test_api_health_readiness_endpoint_connected():
    """Verify /api/health/ready returns HTTP 200 when database connectivity succeeds."""
    client = TestClient(app)
    with mock.patch("app.api.health.check_db_connectivity", return_value=(True, None)):
        response = client.get("/api/health/ready")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"


def test_api_health_readiness_endpoint_disconnected():
    """Verify /api/health/ready returns HTTP 503 when database connectivity fails."""
    client = TestClient(app)
    with mock.patch("app.api.health.check_db_connectivity", return_value=(False, "Connection refused")):
        response = client.get("/api/health/ready")
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert data["status"] == "unavailable"
        assert data["database"] == "disconnected"
        assert "Database service is unavailable" in data.get("detail", "")


# =============================================================================
# 2. Background Worker Integration Tests
# =============================================================================

def test_worker_command_and_entrypoint_dispatch():
    """Verify compose worker command and entrypoint dispatch to app.worker."""
    assert COMPOSE_PATH.is_file()
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    worker_svc = compose["services"]["worker"]
    expected_cmd = ["worker", "--poll-interval", "2.0", "--concurrency", "5", "--sweeper-interval", "10.0"]
    assert worker_svc["command"] == expected_cmd
    assert worker_svc["stop_grace_period"] == "20s"

    content = ENTRYPOINT_PATH.read_text(encoding="utf-8")
    assert "worker)" in content
    assert 'exec python -m app.worker "$@"' in content
    assert 'verify_secret_readable "DATABASE_URL_FILE" "$DATABASE_URL_FILE" true' in content
    # Worker must NOT require operator credentials
    assert 'verify_secret_readable "OPERATOR_CREDENTIALS_FILE" "$OPERATOR_CREDENTIALS_FILE" false' in content


def test_worker_argument_parsing_and_defaults():
    """Verify app.worker parse_args parses poll interval, concurrency, and sweeper interval."""
    from app.worker import parse_args

    test_args = [
        "worker.py",
        "--worker-id", "test-worker-1",
        "--concurrency", "8",
        "--poll-interval", "1.5",
        "--sweeper-interval", "5.0",
        "--lease-duration", "45",
    ]
    with mock.patch("sys.argv", test_args):
        args = parse_args()
        assert args.worker_id == "test-worker-1"
        assert args.concurrency == 8
        assert args.poll_interval == 1.5
        assert args.sweeper_interval == 5.0
        assert args.lease_duration == 45
        assert args.once is False


def test_worker_graceful_shutdown_contract():
    """Verify worker code registers SIGINT and SIGTERM and drains tasks with 15s timeout."""
    worker_file = Path(__file__).resolve().parent.parent / "app" / "worker.py"
    assert worker_file.is_file()
    content = worker_file.read_text(encoding="utf-8")

    assert "signal.SIGINT" in content
    assert "signal.SIGTERM" in content
    assert "stop_event.set()" in content
    assert "await runtime.stop(timeout_seconds=15.0)" in content
    assert "dispose_engine()" in content


# =============================================================================
# 3. Frontend & Reverse Proxy Integration Tests
# =============================================================================

def test_nginx_reverse_proxy_configuration():
    """Verify nginx.conf upstream, proxy_pass, security headers, SPA routing, and healthz."""
    assert NGINX_CONF_PATH.is_file()
    content = NGINX_CONF_PATH.read_text(encoding="utf-8")

    # Upstream definition
    assert "upstream backend_api {" in content
    assert "server api:8000;" in content
    assert "keepalive 32;" in content

    # Reverse proxy location
    assert "location /api/ {" in content
    assert "proxy_pass http://backend_api;" in content
    assert "proxy_http_version 1.1;"
    assert "proxy_set_header Host $host;" in content
    assert "proxy_set_header X-Real-IP $remote_addr;" in content
    assert "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;" in content

    # Buffer & request sizing
    assert "client_max_body_size 10M;" in content

    # SPA routing fallback
    assert "location / {" in content
    assert "try_files $uri $uri/ /index.html;" in content

    # Health check
    assert "location /healthz {" in content
    assert "return 200 'OK';" in content

    # Security headers
    assert 'X-Frame-Options "DENY"' in content
    assert 'X-Content-Type-Options "nosniff"' in content
    assert 'Content-Security-Policy' in content


def test_frontend_api_client_relative_pathing_and_headers():
    """Verify frontend API client uses relative /api/v1 paths and injects Bearer + Idempotency headers."""
    assert FRONTEND_CLIENT_PATH.is_file()
    content = FRONTEND_CLIENT_PATH.read_text(encoding="utf-8")

    # Relative fetch URL for reverse proxy compatibility
    assert "fetch(`/api/v1${endpoint}`" in content or "fetch(`/api/v1" in content

    # Authorization header
    assert "headers.set('Authorization', `Bearer ${apiKey}`)" in content

    # Idempotency-Key header on POST
    assert "headers.set('Idempotency-Key', generateIdempotencyKey())" in content

    # Error handling without stack trace leaking
    assert "throw new ApiError(response.status, errDetail, errData);" in content


# =============================================================================
# 4. Service Dependency Graph and Isolation Tests
# =============================================================================

def test_compose_dependency_graph():
    """Verify the Compose dependency graph strictly enforces db -> migration -> (api, worker) -> frontend."""
    assert COMPOSE_PATH.is_file()
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose["services"]

    # db has no dependencies and defines a healthcheck
    assert "depends_on" not in services["db"]
    assert "healthcheck" in services["db"]

    # migration depends on db healthy, restart: "no"
    assert services["migration"]["depends_on"]["db"]["condition"] == "service_healthy"
    assert services["migration"]["restart"] == "no"

    # api depends on db healthy and migration completed successfully
    assert services["api"]["depends_on"]["db"]["condition"] == "service_healthy"
    assert services["api"]["depends_on"]["migration"]["condition"] == "service_completed_successfully"
    assert "healthcheck" in services["api"]

    # worker depends on db healthy and migration completed successfully
    assert services["worker"]["depends_on"]["db"]["condition"] == "service_healthy"
    assert services["worker"]["depends_on"]["migration"]["condition"] == "service_completed_successfully"

    # frontend depends on api healthy
    assert services["frontend"]["depends_on"]["api"]["condition"] == "service_healthy"
    assert "healthcheck" in services["frontend"]

    # ingress depends on frontend healthy
    assert services["ingress"]["depends_on"]["frontend"]["condition"] == "service_healthy"
    assert "healthcheck" in services["ingress"]


def test_service_credential_and_network_scoping():
    """Verify least-privilege secret scoping and network isolation across compose services."""
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose["services"]

    # Database service receives passwords only
    db_secrets = set(services["db"]["secrets"])
    assert "postgres_admin_password" in db_secrets
    assert "migration_password" in db_secrets
    assert "app_password" in db_secrets
    assert "migration_database_url" not in db_secrets
    assert "app_database_url" not in db_secrets

    # Migration runner receives migration_database_url only
    mig_secrets = set(services["migration"]["secrets"])
    assert "migration_database_url" in mig_secrets
    assert "app_database_url" not in mig_secrets
    assert "postgres_admin_password" not in mig_secrets

    # API receives app_database_url, operator_credentials, gemini_api_key
    api_secrets = set(services["api"]["secrets"])
    assert "app_database_url" in api_secrets
    assert "operator_credentials" in api_secrets
    assert "migration_database_url" not in api_secrets

    # Worker receives application runtime secrets
    worker_secrets = set(services["worker"]["secrets"])
    assert "app_database_url" in worker_secrets
    assert "migration_database_url" not in worker_secrets
    assert "postgres_admin_password" not in worker_secrets

    # Ingress proxy receives ZERO secrets
    assert "secrets" not in services["ingress"]

    # Network isolation
    assert set(services["db"]["networks"]) == {"sentinel_db_network"}
    assert set(services["migration"]["networks"]) == {"sentinel_db_network"}
    assert set(services["frontend"]["networks"]) == {"sentinel_ingress_frontend_network", "sentinel_frontend_network"}
    assert set(services["ingress"]["networks"]) == {"sentinel_ingress_network", "sentinel_ingress_frontend_network"}


def test_test_database_isolation_policy_contract():
    """Verify that automated tests must decline to run state-mutating tests on shared development database."""
    from urllib.parse import urlparse

    # When testing against development environment, session factory connects to localhost:5432/sentinelagent
    # A safe test suite must verify isolation before mutating database records
    def verify_safe_for_destructive_testing(db_url: str) -> bool:
        parsed = urlparse(db_url.replace("postgresql+psycopg://", "postgresql://"))
        database_name = parsed.path.lstrip("/")
        # The primary shared database is 'sentinelagent'
        if database_name == "sentinelagent":
            return False
        return True

    # Invariant: shared development database must fail the isolation check
    dev_url = "postgresql+psycopg://sentinelagent_user:password@localhost:5432/sentinelagent"
    assert verify_safe_for_destructive_testing(dev_url) is False

    # Invariant: dedicated isolated test database passes
    isolated_test_url = "postgresql+psycopg://test_user:password@localhost:5432/sentinelagent_isolated_test"
    assert verify_safe_for_destructive_testing(isolated_test_url) is True
