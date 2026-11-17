"""Automated Security and Operational Hardening Regression Tests (Task 12.5).

Verifies container privilege restrictions, capability dropping, read-only filesystems,
resource/process limits, bounded logging, network isolation, non-root execution,
and Nginx defensive headers without writing to the shared development database.
"""

from pathlib import Path
import yaml
import pytest
from pydantic import SecretStr

from app.core.config import Settings

DEPLOY_DIR = Path(__file__).resolve().parent.parent.parent / "deploy" / "sentinelagent"
COMPOSE_PATH = DEPLOY_DIR / "compose.yaml"
NGINX_CONF_PATH = DEPLOY_DIR / "frontend" / "nginx.conf"
BACKEND_DOCKERFILE_PATH = DEPLOY_DIR / "backend" / "Dockerfile"
FRONTEND_DOCKERFILE_PATH = DEPLOY_DIR / "frontend" / "Dockerfile"


@pytest.fixture
def compose_data():
    """Load and parse the compose.yaml specification."""
    assert COMPOSE_PATH.is_file(), f"Missing compose.yaml at {COMPOSE_PATH}"
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# =============================================================================
# 1. Container Hardening & Privilege Restriction Tests
# =============================================================================

def test_container_no_new_privileges_all_services(compose_data):
    """Verify all services strictly enforce no-new-privileges:true."""
    services = compose_data["services"]
    assert len(services) == 6
    for name, svc in services.items():
        sec_opts = svc.get("security_opt", [])
        assert "no-new-privileges:true" in sec_opts, f"Service {name} lacks no-new-privileges:true"


def test_container_capability_dropping(compose_data):
    """Verify application, worker, migration, and proxy services drop ALL Linux capabilities."""
    services = compose_data["services"]
    hardened_services = ["migration", "api", "worker", "frontend", "ingress"]
    for name in hardened_services:
        cap_drop = services[name].get("cap_drop", [])
        assert "ALL" in cap_drop, f"Service {name} does not drop ALL capabilities: {cap_drop}"


def test_container_read_only_filesystems(compose_data):
    """Verify application, worker, migration, and proxy services use read-only root filesystems."""
    services = compose_data["services"]
    hardened_services = ["migration", "api", "worker", "frontend", "ingress"]
    for name in hardened_services:
        assert services[name].get("read_only") is True, f"Service {name} lacks read_only: true"


def test_container_tmpfs_security_flags(compose_data):
    """Verify tmpfs mounts enforce noexec and nosuid flags to prevent binary execution in temp dirs."""
    services = compose_data["services"]
    for name in ["migration", "api", "worker", "frontend", "ingress"]:
        tmpfs_list = services[name].get("tmpfs", [])
        assert len(tmpfs_list) > 0, f"Service {name} lacks tmpfs mounts"
        for mount in tmpfs_list:
            assert "noexec" in mount, f"Tmpfs mount '{mount}' in {name} lacks noexec flag"
            assert "nosuid" in mount, f"Tmpfs mount '{mount}' in {name} lacks nosuid flag"


def test_container_absence_of_privileged_execution(compose_data):
    """Verify no service runs in privileged mode or mounts the Docker daemon socket."""
    services = compose_data["services"]
    for name, svc in services.items():
        assert svc.get("privileged") is not True, f"Service {name} is configured with privileged: true!"
        volumes = svc.get("volumes", [])
        for vol in volumes:
            vol_str = str(vol)
            assert "docker.sock" not in vol_str, f"Service {name} mounts docker.sock: {vol_str}"


# =============================================================================
# 2. Resource, Process, and Logging Limits Tests
# =============================================================================

def test_container_resource_limits_configured(compose_data):
    """Verify CPU, memory, and PID limits are configured across all services to prevent exhaustion."""
    services = compose_data["services"]
    for name, svc in services.items():
        deploy = svc.get("deploy", {})
        resources = deploy.get("resources", {})
        limits = resources.get("limits", {})

        assert "cpus" in limits, f"Service {name} lacks CPU limits"
        assert "memory" in limits, f"Service {name} lacks memory limits"
        assert "pids" in limits, f"Service {name} lacks pids limit"
        # Invariant: PID limit must be bounded (<= 100) to protect host kernel from fork bombs
        assert limits["pids"] <= 100, f"Service {name} has excessive pids limit: {limits['pids']}"


def test_container_bounded_logging_configuration(compose_data):
    """Verify all services configure bounded json-file logging to prevent disk exhaustion."""
    services = compose_data["services"]
    for name, svc in services.items():
        logging_cfg = svc.get("logging", {})
        assert logging_cfg.get("driver") == "json-file", f"Service {name} logging driver is not json-file"
        opts = logging_cfg.get("options", {})
        assert opts.get("max-size") == "10m", f"Service {name} max-size is not 10m"
        assert opts.get("max-file") == "3", f"Service {name} max-file is not 3"


def test_database_shm_size_configured(compose_data):
    """Verify PostgreSQL database container specifies shm_size for parallel query safety."""
    db_svc = compose_data["services"]["db"]
    assert db_svc.get("shm_size") == "128m", "Database lacks shm_size: 128m"


# =============================================================================
# 3. Network and Exposure Security Tests
# =============================================================================

def test_database_port_not_exposed_to_host(compose_data):
    """Verify PostgreSQL container exposes ZERO host ports and remains strictly on internal network."""
    db_svc = compose_data["services"]["db"]
    assert "ports" not in db_svc, "Database service unexpectedly publishes host ports!"
    networks = db_svc.get("networks", [])
    assert networks == ["sentinel_db_network"]


def test_published_ports_loopback_restriction(compose_data):
    """Verify published ports default to 127.0.0.1 and frontend publishes ZERO host ports."""
    services = compose_data["services"]
    # Frontend application remains strictly internal behind ingress proxy
    assert len(services["frontend"].get("ports", [])) == 0, "Frontend service unexpectedly publishes host ports!"

    for name in ["api", "ingress"]:
        ports = services[name].get("ports", [])
        assert len(ports) > 0, f"Service {name} has no published ports"
        for p in ports:
            assert "BIND_IP:-127.0.0.1" in str(p), f"Service {name} port '{p}' does not restrict to loopback"


def test_internal_networks_declared_internal(compose_data):
    """Verify internal networks are declared with internal: true and external ingress/egress are non-internal."""
    networks = compose_data.get("networks", {})
    assert networks["sentinel_db_network"].get("internal") is True
    assert networks["sentinel_ingress_frontend_network"].get("internal") is True
    assert networks["sentinel_frontend_network"].get("internal") is True
    # Ingress and egress networks have external routing/gateways
    assert networks["sentinel_ingress_network"].get("internal") is False
    assert networks["sentinel_egress_network"].get("internal") is False


# =============================================================================
# 4. Nginx and HTTP Boundary Security Tests
# =============================================================================

def test_nginx_server_tokens_off():
    """Verify Nginx configuration hides version tokens to prevent version enumeration."""
    assert NGINX_CONF_PATH.is_file()
    content = NGINX_CONF_PATH.read_text(encoding="utf-8")
    assert "server_tokens off;" in content


def test_nginx_security_response_headers():
    """Verify defensive HTTP security headers and tightened CSP are present in Nginx configuration."""
    content = NGINX_CONF_PATH.read_text(encoding="utf-8")
    assert 'add_header X-Frame-Options "DENY"' in content
    assert 'add_header X-Content-Type-Options "nosniff"' in content
    assert 'add_header Referrer-Policy "strict-origin-when-cross-origin"' in content
    assert 'add_header Permissions-Policy' in content
    assert 'add_header Content-Security-Policy' in content
    assert 'proxy_hide_header X-Powered-By;' in content

    # Tightened CSP checks
    assert "script-src 'self';" in content
    assert "connect-src 'self';" in content
    assert "style-src 'self' 'unsafe-inline';" in content
    assert "object-src 'none';" in content
    assert "frame-ancestors 'none';" in content


def test_nginx_request_size_limit():
    """Verify client_max_body_size is explicitly constrained."""
    content = NGINX_CONF_PATH.read_text(encoding="utf-8")
    assert "client_max_body_size 10M;" in content


# =============================================================================
# 5. Image & Non-Root Execution Security Tests
# =============================================================================

def test_frontend_dockerfile_stable_nginx_digest_pinning():
    """Verify frontend Dockerfile pins to verified official nginx:1.30-alpine image digest."""
    assert FRONTEND_DOCKERFILE_PATH.is_file()
    content = FRONTEND_DOCKERFILE_PATH.read_text(encoding="utf-8")
    # Verified multi-platform index digest from official registry
    expected_digest = "sha256:901e593c95dc85f5a729f5765516321366ef4ac401821431d408897e95287d0a"
    assert "FROM nginx:1.30-alpine@" in content
    assert expected_digest in content


def test_compose_postgres_image_digest_pinning(compose_data):
    """Verify PostgreSQL image in compose.yaml pins to verified official 18.6-alpine digest."""
    db_svc = compose_data["services"]["db"]
    expected_digest = "sha256:9ba53c7d41ea093baf5c1ba635ba5434c4f979880527d49bb7d9237d3193085b"
    image_str = db_svc.get("image", "")
    assert expected_digest in image_str, f"Database image '{image_str}' lacks verified digest {expected_digest}"

def test_backend_dockerfile_non_root_execution():
    """Verify backend Dockerfile creates and switches to non-root sentinel user (UID 10001)."""
    assert BACKEND_DOCKERFILE_PATH.is_file()
    content = BACKEND_DOCKERFILE_PATH.read_text(encoding="utf-8")
    assert "groupadd -g 10001 sentinel" in content
    assert "useradd -u 10001 -g sentinel" in content
    assert "USER sentinel" in content


def test_frontend_dockerfile_multi_stage_and_non_root():
    """Verify frontend Dockerfile uses multi-stage build and switches to non-root nginx user."""
    assert FRONTEND_DOCKERFILE_PATH.is_file()
    content = FRONTEND_DOCKERFILE_PATH.read_text(encoding="utf-8")
    # Multi-stage check: builder stage and runtime stage
    assert "AS builder" in content
    assert "AS runtime" in content
    # Non-root user in runtime stage
    assert "USER nginx" in content


def test_secrets_redaction_contract():
    """Verify Settings SecretStr types redact credentials in string representations and logging."""
    raw_secret = "super_secret_password_12345"
    s = Settings(
        DATABASE_URL=SecretStr(f"postgresql://user:{raw_secret}@localhost/db"),
        _env_file=None,
    )
    # Representation must NOT contain the raw secret
    assert raw_secret not in str(s.DATABASE_URL)
    assert raw_secret not in repr(s.DATABASE_URL)
    assert "**********" in str(s.DATABASE_URL)
