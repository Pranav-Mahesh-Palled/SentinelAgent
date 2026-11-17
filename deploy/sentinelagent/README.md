# SentinelAgent Production Deployment Guide

Self-hosted, hardened Docker Compose deployment package for the **SentinelAgent** autonomous cybersecurity investigation and response system.

---

## 1. Architecture Overview

The production deployment decouples the application into five dedicated container services segmented across three isolated Docker networks with strict least-privilege role separation:

```
                      [ Host Interface ]
                             │
            ┌────────────────┴────────────────┐
            │ 127.0.0.1:8080                  │ 127.0.0.1:8000 (Optional direct)
            ▼                                 ▼
   ┌─────────────────┐               ┌─────────────────┐
   │    frontend     │──/api/proxy──▶│       api       │────────┐
   │  (Nginx SPA)    │               │  (FastAPI)      │        │
   └─────────────────┘               └─────────────────┘        │
     (sentinel_frontend_network)              │                 │ (sentinel_egress_network)
                                              ▼                 ▼
                                     ┌─────────────────┐ ┌─────────────┐
                                     │     worker      │ │  External   │
                                     │ (Outbox Worker) │ │ AI Provider │
                                     └─────────────────┘ └─────────────┘
                                              │                 ▲
                                     (sentinel_db_network)      │
                                              ▼                 │
   ┌─────────────────┐               ┌─────────────────┐        │
   │    migration    │──────────────▶│       db        │        │
   │(One-Shot Alembic)               │ (Postgres 18.6) │────────┘
   └─────────────────┘               └─────────────────┘      (NO ACCESS)
                                              ▲
                                              │
                                      [sentinel_pgdata]
```

### Network Topology & External Egress Policy

| Network | Type | Connected Services | Purpose & Egress Policy |
| :--- | :--- | :--- | :--- |
| **`sentinel_db_network`** | `internal: true` | `db`, `migration`, `api`, `worker` | **Zero external egress.** Transports PostgreSQL queries and migrations. Completely isolated from the internet and the frontend (`internal: true` prevents Docker from configuring a default gateway or outbound NAT). |
| **`sentinel_frontend_network`** | `internal: true` | `frontend`, `api` | Transports HTTP reverse-proxy traffic from Nginx to the FastAPI application. Cannot route to `db` or the internet. |
| **`sentinel_egress_network`** | `internal: false` (Bridge) | `api`, `worker` | **External Layer-3 egress allowed.** Enables `api` and `worker` to reach external AI providers (such as Google Gemini API via `generativelanguage.googleapis.com`). `db` and `migration` are **NEVER** attached to this network. |

> [!NOTE]
> **Docker Bridge Network Egress Behavior**: Standard Docker bridge networks provide default Layer-3 NAT routing to the internet; they **do not** perform Layer-4 port filtering (e.g. restricting outbound traffic to port 443 only) or packet inspection without external tooling. Egress from `sentinel_egress_network` is strictly used by `api` and `worker` for outbound LLM calls. Organizations requiring strict egress port restrictions (e.g. TCP 443 only) or IP pinning should enforce them using host-level firewall policies (`iptables`, `nftables`, `UFW`) or an enterprise egress proxy.

---

## 2. Service Responsibilities

| Service | Container Name | Identity / User | Role & Responsibility |
| :--- | :--- | :--- | :--- |
| **`db`** | `sentinelagent-db` | `postgres` (internal) | PostgreSQL 18.6 database storing incidents, investigations, evidence, and response actions. Bound exclusively to internal network `sentinel_db_network`. |
| **`migration`** | `sentinelagent-migration` | `sentinel_migration_role` | One-shot Alembic migration runner. Runs `alembic upgrade head` at startup, creates/updates tables, indexes, immutability triggers, executes fail-closed least-privilege alignment via `app.db.align_roles`, and exits cleanly. |
| **`api`** | `sentinelagent-api` | `sentinel_app_role` (UID 10001) | Production FastAPI REST backend. Serves health checks, event ingestion, investigation workflows, and response proposals/approvals. Read-only filesystem with tmpfs. |
| **`worker`** | `sentinelagent-worker` | `sentinel_app_role` (UID 10001) | Autonomous background worker polling `response_outbox` for simulation execution, verification, and probe reconciliation. Continuous loop with 15s graceful drain on SIGTERM. |
| **`frontend`** | `sentinelagent-frontend` | `nginx` (unprivileged, port 8080) | Serves pre-built production React SPA assets and reverse-proxies `/api/` traffic to `http://api:8000`. |

---

## 3. Database Privilege Matrix & Fail-Closed Classification

SentinelAgent enforces strict database identity separation and a **fail-closed** privilege architecture:

1. **`sentinel_migration_role` (Migration Authority):**
   - Owns the database schema (`public`) and all schema objects.
   - Possesses `ALL PRIVILEGES` on schema `public` and database `sentinelagent`.
   - Used exclusively by the `migration` container.
2. **`sentinel_app_role` (Runtime Application Authority):**
   - Possesses only `USAGE` on schema `public` (`CREATE` is revoked).
   - Possesses explicit, minimal table-by-table privileges applied dynamically by `app.db.align_roles`.
   - **Fail-Closed Enforcement**: If any unclassified table is detected in schema `public`, `align_roles` raises `UnclassifiedTableError` and halts startup rather than granting blanket default permissions.
   - **Default Privilege Revocation for Migration Role**: When `sentinel_migration_role` creates tables, sequences, or functions, PostgreSQL default privileges could fail-open if not configured. SentinelAgent enforces global and schema-scoped default privilege revocations (`ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migration_role REVOKE ALL ON TABLES/SEQUENCES/FUNCTIONS FROM sentinel_app_role` and `REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`).
   - **Zero DELETE Privileges**: Production application and worker services are strictly non-destructive. Outbox queues settle via status updates (`completed`, `dead_letter`), associations are append-only, and forensic records are immutable. Consequently, `DELETE` is revoked across all tables.
   - **Sequences & Functions**: SentinelAgent exclusively utilizes UUID primary keys (`gen_random_uuid()`), resulting in 0 database sequences. Both default and direct sequence privileges are revoked (`REVOKE ALL ON ALL SEQUENCES ...`).
   - **Function Execution & Trigger Mechanics**: By default, PostgreSQL grants `EXECUTE` on new functions to pseudo-role `PUBLIC`. Because `sentinel_app_role` is a member of `PUBLIC`, SentinelAgent revokes `EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC` and from `sentinel_app_role`, and revokes future default execution rights. This ensures `has_function_privilege('sentinel_app_role', ..., 'execute')` returns `FALSE`. Functions `fn_prevent_immutable_modification` and `fn_prevent_response_action_rel_update` return `trigger`; under PostgreSQL's architecture, trigger functions are executed internally by table triggers during DML and do not require user-level `EXECUTE` grants.

### Table-by-Table Privilege Grants for `sentinel_app_role` (All 17 Tables)

| Table | Classification | SELECT | INSERT | UPDATE | DELETE | TRUNCATE | REFERENCES | TRIGGER | Purpose |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `incidents` | Operational | **YES** | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | Incident lifecycle & state machine transitions |
| `investigations` | Operational | **YES** | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | Autonomous investigation status and execution |
| `response_actions` | Operational | **YES** | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | Response action proposals, approvals, settlement |
| `ssh_events` | Operational | **YES** | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | Telemetry event ingestion & analysis |
| `detection_results` | Operational | **YES** | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | Rule and ML detection results |
| `investigation_tool_runs` | Operational | **YES** | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | Investigation tool execution audit trail |
| `response_outbox` | Queue | **YES** | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | Transactional outbox claiming & status transitions |
| `incident_memory_outbox` | Queue | **YES** | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | Memory outbox claiming & status transitions |
| `incident_events` | Immutable Forensic | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | **NO** | Append-only incident-to-event associations |
| `evidence_items` | Immutable Forensic | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | **NO** | Append-only investigation forensic evidence |
| `response_audit_events` | Immutable Forensic | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | **NO** | Trigger-enforced immutable response audit log |
| `simulated_blocklist_entries` | Immutable Forensic | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | **NO** | Trigger-enforced immutable simulation ledger |
| `verification_reconciliation_records` | Immutable Forensic | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | **NO** | Trigger-enforced immutable reconciliation records |
| `verification_reconciliation_evidence`| Immutable Forensic | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | **NO** | Trigger-enforced immutable reconciliation evidence |
| `verification_reconciliation_probes`  | Immutable Forensic | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | **NO** | Trigger-enforced immutable probe telemetry |
| `response_action_evidence`            | Immutable Forensic | **YES** | **YES** | **NO** | **NO** | **NO** | **NO** | Trigger-enforced immutable proposal evidence |
| `alembic_version`                     | System Internal | **YES** | **NO** | **NO** | **NO** | **NO** | **NO** | **NO** | Read-only inspection of schema revision |

---

## 4. DSN Configuration Mapping

The application natively maps runtime and migration DSNs with zero credential leakage:

* **Migration DSN:** Provided via `MIGRATION_DATABASE_URL_FILE` (or `MIGRATION_DATABASE_URL`). Maps directly to Alembic runner.
* **Runtime Application DSN:** Provided via `APP_DATABASE_URL_FILE` (or `APP_DATABASE_URL`). Maps to FastAPI API and Response Worker.
* **Bootstrap Admin DSN:** Used strictly by `01-init-roles.sh` during first-time database initialization; runtime containers never receive bootstrap credentials.

---

## 5. PostgreSQL 18 Configuration & Storage

* **Version Pinning:** Pinned to **PostgreSQL 18.6** (`postgres:18.6-alpine`), matching the local development and testing environment.
* **Verified Registry Image Digest:**
  The multi-architecture index digest verified directly against the Docker official library registry via `docker buildx imagetools inspect postgres:18.6-alpine`:
  ```bash
  # Multi-Architecture OCI Image Index Digest:
  POSTGRES_IMAGE=postgres:18.6-alpine@sha256:9ba53c7d41ea093baf5c1ba635ba5434c4f979880527d49bb7d9237d3193085b
  
  # Architecture-Specific Manifest Digests:
  # linux/amd64:  sha256:300ebd02c6d4de9ee27ad7f6855d5d21b4d3a4a5117767c1197d284c635d9736
  # linux/arm64:  sha256:c935aff069a7bbe5c286411a08e9678850d79be7848b190a0e4637b266478626
  ```
  Procedure to re-verify at any time without running Docker Desktop:
  ```bash
  docker buildx imagetools inspect postgres:18.6-alpine
  ```
* **Persistent Storage Layout & PostgreSQL 18 `PGDATA`:**
  - Named volume `sentinel_pgdata` mounts to `/var/lib/postgresql`.
  - **Backward-Compatible Default**: `compose.yaml` defaults to `PGDATA: ${PGDATA:-/var/lib/postgresql/data}`.
  - This default ensures that existing deployments running with persistent volumes initialized under `/var/lib/postgresql/data` do not accidentally launch against a freshly initialized, empty cluster.
  - **Official PostgreSQL 18 Location**: The official Alpine PostgreSQL 18 image defaults internally to `/var/lib/postgresql/18/docker`. New deployments wishing to use this official path can explicitly set `PGDATA=/var/lib/postgresql/18/docker` in `.env`.
  - Because `sentinel_pgdata` mounts to `/var/lib/postgresql`, both paths reside 100% inside the mounted persistent volume.

### Migrating an Existing Cluster to `/var/lib/postgresql/18/docker`
If you wish to align an existing deployment's data directory with the official PostgreSQL 18 default path:
1. **Create a Full Database Backup**:
   ```bash
   docker compose exec -T db pg_dump -U sentinel_admin -d sentinelagent -Fc > backup_before_pgdata_migration.dump
   ```
2. **Stop Application and Database Services**:
   ```bash
   docker compose down
   ```
3. **Relocate Data Directory Inside the Persistent Volume**:
   ```bash
   docker run --rm -v sentinel_pgdata:/var/lib/postgresql alpine sh -c "mkdir -p /var/lib/postgresql/18 && mv /var/lib/postgresql/data /var/lib/postgresql/18/docker"
   ```
4. **Update `.env`**:
   Add or update `PGDATA=/var/lib/postgresql/18/docker` in `deploy/sentinelagent/.env`.
5. **Start Services and Verify**:
   ```bash
   docker compose up -d
   docker compose logs db
   ```
   Verify that PostgreSQL detects the existing database cluster at `/var/lib/postgresql/18/docker` and starts without running `initdb`.

### Container Lifecycle vs. Database Storage Lifecycle
SentinelAgent strictly separates stateless container lifecycles from stateful database storage:
- **Container Replacement**: Destroying, updating, or recreating the `sentinelagent-db` container (`docker compose up --force-recreate` or image upgrade) only replaces the disposable ephemeral container environment.
- **Storage Persistence**: Named volume `sentinel_pgdata` survives container destruction untouched in Docker's persistent volume store (`/var/lib/docker/volumes/sentinel_pgdata/_data`).
- **Cluster Detection**: When a new database container boots, PostgreSQL checks `$PGDATA`. If an existing cluster (`PG_VERSION`) is detected, PostgreSQL **skips `initdb` and `/docker-entrypoint-initdb.d/` entirely**, immediately mounting existing data, schemas, triggers, and demonstration records.
- **Migration Gating**: The one-shot `migration` container connects using dedicated migration credentials (`sentinel_migration_role`), checks `alembic_version`, applies pending migrations, aligns least-privilege role permissions via `app.db.align_roles`, and exits 0 before `api` or `worker` containers are permitted to launch.

---

## 6. Initial Setup & Secret Generation

### Step 6.1: Run the Secret Generator

**Linux / macOS:**
```bash
cd deploy/sentinelagent
chmod +x scripts/generate-secrets.sh
./scripts/generate-secrets.sh
```

**Windows (PowerShell):**
```powershell
cd deploy/sentinelagent
.\scripts\generate-secrets.ps1
```

### Step 6.2: Configure `.env`

Copy the sanitized configuration template:
```bash
cp .env.example .env
```
Review `.env` to verify binding interfaces and ports (`127.0.0.1:8080` for Frontend and `127.0.0.1:8000` for API).

---

## 7. Startup & Verification

### Step 7.1: Build and Launch Containers
```bash
docker compose up -d --build
```

### Step 7.2: Verify Service Status
```bash
docker compose ps
```

### Step 7.3: Health Check
```bash
# API Application Readiness Check (verifies database and catalogue)
curl -f http://127.0.0.1:8000/api/health/ready

# Frontend Proxy Health Check
curl -f http://127.0.0.1:8080/healthz
```

### Step 7.4: Service Integration & Architecture Verification

SentinelAgent integrates five distinct production services with fail-closed dependencies:

1. **API ASGI Production Runtime (`api`):**
   - Dispatches via `uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${UVICORN_WORKERS:-2} --timeout-graceful-shutdown 15`.
   - Maps runtime secrets (`APP_DATABASE_URL_FILE`, `OPERATOR_CREDENTIALS_FILE`, `GEMINI_API_KEY_FILE`) and executes pre-flight readability checks for non-root UID 10001.
   - Dual health endpoints:
     - `/api/health/live`: Fast process liveness (HTTP 200 `{"status": "alive"}`) without touching dependencies.
     - `/api/health/ready`: Deep dependency readiness verifying primary PostgreSQL connectivity, MITRE catalogue status, and Hindsight availability. Returns HTTP 503 if the database or required services are unavailable.

2. **Background Response Worker Runtime (`worker`):**
   - Autonomous background service running `python -m app.worker --poll-interval 2.0 --concurrency 5 --sweeper-interval 10.0`.
   - Completely separate process and container lifecycle from the web API.
   - Signal handling catches `SIGTERM` / `SIGINT`, halts new task claims, drains in-flight execution and verification tasks within a 15-second graceful window, and disposes the SQLAlchemy engine before exit.
   - Docker Compose enforces `stop_grace_period: 20s`, guaranteeing zero orphaned leases or interrupted simulations during container restarts.

3. **Frontend & Nginx Reverse Proxy (`frontend`):**
   - Multi-stage build compiles React + TypeScript via Vite into static distribution assets (`/usr/share/nginx/html`).
   - Unprivileged Nginx runtime listens on port 8080 (UID `nginx`).
   - Reverse proxies `/api/` traffic to `http://backend_api` (`api:8000`), preserving all request headers (`Authorization`, `Idempotency-Key`, `Content-Type`) and supporting payloads up to `10M` (`client_max_body_size 10M;`).
   - SPA client routing fallback (`try_files $uri $uri/ /index.html;`) ensures deep links and browser refreshes load properly without 404 errors.

4. **Service Dependency DAG:**
   ```
   [db (PostgreSQL 18)]
          │ (condition: service_healthy)
          ▼
   [migration (Alembic + align_roles)]
          │ (condition: service_completed_successfully)
          ├──────────────────────────┐
          ▼                          ▼
   [api (FastAPI REST)]       [worker (Response Orchestrator)]
          │ (condition: service_healthy)
          ▼
   [frontend (Nginx Reverse Proxy)]
   ```

5. **Static Configuration Verification vs. Live Container Runtime Verification:**
   - **Static Configuration Verification (Completed in Phase 12):** Validates all Docker Compose service graphs, network isolations, volume bindings, environment contracts, entrypoint scripts, secret permission gates, Nginx proxy rules, and ASGI startup commands using automated tests, YAML compilers, and mock harnesses.
   - **Live Container Runtime Verification (Scheduled for Task 12.6):** Validates actual live multi-container execution inside an active Docker engine daemon, verifying container network packet flow, bridge IP isolation, and multi-container lifecycle transitions.

---

## 8. Existing-Volume Role Provisioning & Schema Upgrades

When mounting an existing persistent PostgreSQL volume where `initdb` was already executed in a previous cluster run:
1. **Entrypoint Behavior**: PostgreSQL detects an existing cluster and **skips `01-init-roles.sh`**.
2. **Schema Upgrades**: The one-shot `migration` container automatically runs `alembic upgrade head`. If the database is already at the current head (`34ea070e907d`), Alembic applies 0 migrations and preserves all existing tables and demonstration records.
3. **Role Alignment**: `migration` immediately runs `python -m app.db.align_roles`, verifying that all 17 tables are classified, ensuring trigger functions are present, revoking excess privileges, and granting least-privilege access to `sentinel_app_role`.
4. **Credential Rotation on Existing Volumes**: If database passwords have been rotated in `./secrets/`, run the role provisioning helper script against the running container to update PostgreSQL role passwords without resetting data:

**Linux / macOS:**
```bash
./scripts/provision-roles.sh
```

**Windows (PowerShell):**
```powershell
.\scripts\provision-roles.ps1
```
Or execute SQL directly:
```bash
docker compose exec -T db psql -U sentinel_admin -d sentinelagent < init-db/01-init-roles.sql
```

---

## 9. Production Configuration Contract & Taxonomy

SentinelAgent strictly classifies all configuration parameters into four distinct operational tiers:

### 1. Required Production Settings
These parameters are mandatory when `ENVIRONMENT=production`. The application validates them at startup and aborts if missing:
- **`APP_DATABASE_URL` (or `APP_DATABASE_URL_FILE`)**: Application-role PostgreSQL connection URL for `api` and `worker` services. Must connect as `sentinel_app_role`.
- **`MIGRATION_DATABASE_URL` (or `MIGRATION_DATABASE_URL_FILE`)**: Migration-role PostgreSQL connection URL for the `migration` runner. Must connect as `sentinel_migration_role`.
- **`OPERATOR_CREDENTIALS` (or `OPERATOR_CREDENTIALS_FILE`)**: Required for the `api` service. JSON array specifying authorized operator IDs, roles (`analyst`, `approver`, `admin`), and constant-time SHA-256 key digests.

### 2. Optional Production Settings
Operational features with safe default behaviors when unconfigured:
- **`GEMINI_API_KEY` (or `GEMINI_API_KEY_FILE`)**: Google Gemini API key. If omitted or empty, SentinelAgent starts normally and serves response orchestration/verification workflows, while AI investigation capabilities remain unconfigured.
- **`HINDSIGHT_ENABLED`**: Defaults to `false`. When false, all Hindsight memory and recall settings are ignored, allowing SentinelAgent to start without any Hindsight credentials or services.
- **`MITRE_REQUIRED`**: Defaults to `false`. Loads local MITRE enterprise attack catalogue from packaged JSON.
- **Queue & Sweeper Intervals**: `RESPONSE_OUTBOX_POLL_INTERVAL_SECONDS` (default: 2.0s), `RESPONSE_OUTBOX_MAX_CONCURRENCY` (default: 5), `RESPONSE_SWEEPER_INTERVAL_SECONDS` (default: 10.0s).

### 3. Development-Only Settings
Configurations forbidden or restricted in production:
- **`DEBUG`**: Must be `false` in production. If set to `true` when `ENVIRONMENT=production`, startup fails immediately.
- **`HINDSIGHT_BANK_ID`**: Defaults to `sentinelagent-incident-memory-dev` in development and `sentinelagent-incident-memory-prod` in production. Non-production environments cannot target production memory banks.

### 4. Sensitive Credentials
All secrets are modeled using Pydantic `SecretStr`:
- Database connection DSNs (`APP_DATABASE_URL`, `MIGRATION_DATABASE_URL`, `DATABASE_URL`)
- Operator authentication records (`OPERATOR_CREDENTIALS`)
- External provider API keys (`GEMINI_API_KEY`, `HINDSIGHT_API_KEY`, `HINDSIGHT_HMAC_KEY`)
- PostgreSQL passwords (`postgres_admin_password`, `migration_password`, `app_password`)

---

## 10. Secrets Management & File Permissions

### Secret Mounting & Resolution Architecture
Production deployments mount secrets as read-only files in `/run/secrets/` via Docker Secrets:

```
[Host ./secrets/ directory]  ──(Docker Compose Secrets)──▶  [Container /run/secrets/ directory]
  ├── app_database_url.txt                                    └── /run/secrets/app_database_url
  ├── operator_credentials.json                               └── /run/secrets/operator_credentials
  └── gemini_api_key.txt                                      └── /run/secrets/gemini_api_key
```

### Precedence Hierarchy
When both direct environment variables and file-based secrets are present, the application enforces the following resolution order:
1. **Direct Environment Variable** (e.g. `APP_DATABASE_URL="postgresql+psycopg://..."`): Highest priority. If non-empty, file path is ignored.
2. **File-Based Secret Variable** (e.g. `APP_DATABASE_URL_FILE="/run/secrets/app_database_url"`): Used when direct variable is unset or empty.
3. **Derived Database DSN Mapping**: If `DATABASE_URL` is unset, `APP_DATABASE_URL` (for runtime) or `MIGRATION_DATABASE_URL` (for migration) is automatically mapped to `DATABASE_URL`.

### File Permissions on Host & Docker Compose Bind-Mount Mechanics
All secrets defined in `compose.yaml` use the Compose `file:` directive (file-backed secrets).

> [!WARNING]
> **Docker Compose File Secret Bind-Mount Limitation**: In Docker Compose (unlike Docker Swarm mode), `file:` secrets are mounted directly into containers as read-only bind mounts at `/run/secrets/`. Because file secrets are bind mounts, Docker Compose **ignores** container-level `uid`, `gid`, and `mode` attributes. The mounted file inside the container retains the exact host file ownership (UID/GID) and POSIX permission bits.

If host secret files are provisioned with restrictive `chmod 600` owned by the host deployer (e.g. UID 1000), non-root container processes running with different user IDs cannot read the secret files:
- `api`, `worker`, and `migration` run as `sentinel` (non-root **UID 10001**, **GID 10001**).
- `db` runs as `postgres` (**UID 70**, **GID 70** in Alpine).

Attempting to read a `0600` host file as UID 10001 or UID 70 immediately results in an `EACCES (Errno 13, Permission denied)` kernel error, preventing container startup.

#### Required Host Permission Strategy:
To guarantee that non-root container processes can read their secrets while preventing unauthorized host users from accessing or modifying them:
1. **Host Directory Permissions Restrict Access to Secret Files**: The host directory (`./secrets`) is strictly restricted to **mode `0700`** (`drwx------`). On Linux, standard POSIX path traversal rules enforce that any process lacking execute (`+x`) permissions on parent directories cannot open, read, or list files within that directory. This prevents unauthorized host users from accessing the secret files regardless of the file-level permission bits.
2. **File Permissions Allow Intended Non-Root Container UIDs to Read Mounted Secrets**: Individual secret files are set to **mode `0644`** (`rw-r--r--`) **only because** the parent directory is restricted to its owner (`0700`). When Docker Compose bind-mounts these files into containers at `/run/secrets/`, the Linux kernel evaluates the inode's POSIX DAC bits. Mode `0644` allows unprivileged container UIDs (such as `sentinel` at UID 10001 and `postgres` at UID 70) to read their mounted secrets, while preventing write access (never world-writable).

```bash
# Set directory permissions (restrict host traversal exclusively to owner)
chmod 700 deploy/sentinelagent/secrets

# Set file permissions (read-only for non-root containers, non-world-writable)
chmod 644 deploy/sentinelagent/secrets/*
```

#### Service-Level Secret Scoping & In-Container Process Access:
- **Service-Level Secret Grants**: Docker Compose grants secrets at the **service level**, not at the individual-process level. Secrets declared under a service's `secrets:` block in `compose.yaml` are mounted into the container's `/run/secrets/` directory.
- **In-Container Read Access**: Any process executing inside a container that receives a particular secret can potentially read it. Secret isolation is enforced at container and service boundaries:
  - `db` receives only PostgreSQL admin and role passwords (`postgres_admin_password`, `migration_password`, `app_password`). It never receives application credentials or API keys.
  - `migration` receives only `migration_database_url`. It never receives application runtime secrets or operator credentials.
  - `api` and `worker` receive runtime application secrets (`app_database_url`, `operator_credentials`, `gemini_api_key`). They never receive database superuser or migration role passwords.
- Consequently, applications must not run untrusted third-party code within the same container namespace as sensitive secrets.

#### Rootful vs. Rootless Docker Deployments:
- **Rootful Docker**: The Docker daemon executes as host root, allowing it to traverse the owner-restricted `0700` host directory and bind-mount individual secret files into container namespaces. Non-root container processes (UID 10001 and UID 70) then read the mounted `0644` inodes within their container mount namespace.
- **Rootless Docker**: The Docker daemon executes entirely within an unprivileged user namespace. The deploying user running `docker compose` **must be the owner** of the `0700` secrets directory (UID match). If `compose` is executed by a different user than the directory owner, the rootless daemon will receive an `EACCES (Permission denied)` error during container bind-mount creation.

#### Windows / Docker Desktop Behavior & NTFS ACLs:
- **NTFS Access Control**: Windows NTFS does not use POSIX permission bits (`700`, `644`). Permissions are governed by Access Control Lists (ACLs) containing Access Control Entries (ACEs). Files created via PowerShell inherit parent folder DACLs (typically granting access to the creating user, `SYSTEM`, and `Administrators`).
- **Filesystem Virtualization**: Under Docker Desktop for Windows (WSL2 or Hyper-V virtiofs backends), host NTFS file paths are mounted via drvfs/virtiofs and presented to containers as virtual Linux inodes owned by `root:root` with default read permissions (`0755`/`0777`). This virtualization layer masks Linux POSIX DAC permission errors during local Windows development. Production Linux deployments strictly enforce POSIX DAC; running `./scripts/generate-secrets.sh` enforces the `0700` directory and `0644` file permissions automatically.

#### Container Entrypoint Pre-Flight Verification:
The backend entrypoint (`deploy/sentinelagent/backend/entrypoint.sh`) executes a fast pre-flight check on all configured `*_FILE` paths before dispatching to `uvicorn`, `worker`, or `alembic`. If any secret file is unreadable by UID 10001, the container halts immediately with a clear diagnostic message:
```text
FATAL [entrypoint]: Secret file configured by APP_DATABASE_URL_FILE (/run/secrets/app_database_url) is not readable by non-root UID 10001 (Permission denied).
HINT: Docker Compose bind-mounts file secrets directly from the host. Ensure host secret files have mode 0644 (chmod 644 deploy/sentinelagent/secrets/*).
```

---

## 11. Credential Rotation Procedures

### A. Rotating Operator API Keys
1. Generate a new high-entropy API key for the operator:
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
2. Compute the SHA-256 digest of the new key:
   ```bash
   echo -n "<NEW_SECRET_KEY>" | sha256sum | awk '{print $1}'
   ```
3. Update `deploy/sentinelagent/secrets/operator_credentials.json` with the new hash.
4. Restart the API container to pick up the updated secret mount:
   ```bash
   docker compose restart api
   ```
5. Securely distribute the new raw secret key to the authorized operator.

### B. Rotating PostgreSQL Application or Migration Passwords
1. Generate a new password:
   ```bash
   NEW_APP_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
   ```
2. Update the role password in the database:
   ```bash
   docker compose exec -T db psql -U sentinel_admin -d sentinelagent -c \
       "ALTER ROLE sentinel_app_role WITH PASSWORD '$NEW_APP_PASS';"
   ```
3. Update the local secret files:
   ```bash
   echo -n "$NEW_APP_PASS" > deploy/sentinelagent/secrets/app_password.txt
   echo -n "postgresql+psycopg://sentinel_app_role:${NEW_APP_PASS}@db:5432/sentinelagent" > deploy/sentinelagent/secrets/app_database_url.txt
   ```
4. Restart dependent services:
   ```bash
   docker compose restart api worker
   ```

### C. Rotating Google Gemini API Key
1. Update `deploy/sentinelagent/secrets/gemini_api_key.txt` with the new API key.
2. Restart API and Worker services:
   ```bash
   docker compose restart api worker
   ```

---

## 12. Backup, Recovery, and Startup Validation

### Safe Database Backup & Recovery
- **Logical Backup (Recommended)**: Create transactionally consistent backups without taking PostgreSQL offline:
  ```bash
  docker compose exec -T db pg_dump -U sentinel_admin -F c -b -v -f /tmp/backup.dump sentinelagent
  docker compose cp db:/tmp/backup.dump ./sentinelagent_backup_$(date +%Y%m%d_%H%M%S).dump
  ```
- **Volume Backup**: If taking physical volume snapshots of `sentinel_pgdata`, always shut down containers first (`docker compose stop db`) to prevent write tearing.

### Startup Validation & Common Configuration Errors

SentinelAgent validates the production contract during container initialization. Errors fail fast and output safe messages:

| Error Symptom | Root Cause | Safe Remediation |
| :--- | :--- | :--- |
| `ProductionConfigurationError: Required production configuration missing: APP_DATABASE_URL` | Neither `APP_DATABASE_URL` nor `APP_DATABASE_URL_FILE` was provided in production. | Ensure `app_database_url.txt` exists and is populated under `./secrets/`. |
| `ValueError: Secret file configured by APP_DATABASE_URL_FILE does not exist` | The path specified in `APP_DATABASE_URL_FILE` cannot be found on the filesystem. | Verify the Docker secret is mounted at `/run/secrets/app_database_url`. |
| `ValueError: Secret file configured by OPERATOR_CREDENTIALS_FILE is empty` | The operator credentials secret file exists but contains 0 bytes. | Populate `operator_credentials.json` with valid JSON before starting. |
| `ProductionConfigurationError: DEBUG mode cannot be enabled in production` | `DEBUG=true` was specified in `.env` while `ENVIRONMENT=production`. | Set `DEBUG=false` in your `.env` file. |
| `ProductionConfigurationError: Production api process must not use bootstrap admin credentials` | `DATABASE_URL` contains `sentinel_admin` credentials instead of `sentinel_app_role`. | Use `app_database_url` connection string for API and worker containers. |
| **Leak Prevention Guarantee** | Secrets are never printed in logs or exceptions. | All error messages identify only the parameter or file name, never the secret value. |

---

## 13. Security Hardening, Resource Governance & Operational Runbook

### 13.1 Container Security Controls

SentinelAgent enforces defense-in-depth container isolation across all five services:

1. **Non-Root Execution**:
   - Backend (`api`, `worker`, `migration`): Runs under dedicated system UID `10001` (group `sentinel`).
   - Frontend (`frontend`): Runs under unprivileged user `nginx` (UID `101`).
   - Database (`db`): Official PostgreSQL daemon runs internally under user `postgres` (UID `70`).
2. **Privilege Escalation Prevention**:
   - `security_opt: [no-new-privileges:true]` enforced unconditionally on all 5 containers, preventing setuid binaries from gaining host root.
   - `privileged: true` is forbidden and absent across all services.
   - Docker daemon socket (`/var/run/docker.sock`) is never mounted.
3. **Linux Capability Dropping**:
   - `cap_drop: [ALL]` applied to `migration`, `api`, `worker`, and `frontend`. Containers possess 0 supplemental kernel capabilities.
4. **Read-Only Root Filesystem**:
   - `read_only: true` enforced on `migration`, `api`, `worker`, and `frontend`.
   - Ephemeral writable storage is strictly restricted to designated tmpfs mounts configured with `noexec,nosuid` flags (`/tmp`, `/var/cache/nginx`, `/var/run`), preventing execution of dropped binaries or malicious scripts.
5. **Database Storage & Runtime Hardening Analysis**:
   - PostgreSQL persistent data resides exclusively in named volume `sentinel_pgdata`.
   - `shm_size: 128m` configured for shared memory query reliability.
   - Database port `5432` is not published to the host, preventing external network probing.
   - **Technical Analysis of `cap_drop: [ALL]` & `read_only: true` on PostgreSQL**:
     - *Capability Dropping*: The official PostgreSQL container entrypoint (`docker-entrypoint.sh`) starts as root to verify `$PGDATA` volume ownership and then invokes `gosu postgres` to execute the database daemon as unprivileged user `postgres` (UID 70). Applying `cap_drop: [ALL]` strips `CAP_SETUID` and `CAP_SETGID`, causing `gosu` to fail with `setuid: Operation not permitted` and crashing container startup.
     - *Read-Only Root Filesystem*: Applying `read_only: true` to PostgreSQL risks breaking UNIX domain socket creation (`/var/run/postgresql/.s.PGSQL.5432`), lockfiles, query sorting spillover in temporary directories, and configuration generation during `initdb`.
     - *Residual Risk & Mitigation*: PostgreSQL security relies on `no-new-privileges:true`, non-root daemon execution (`postgres` UID 70), strict CPU/RAM/PID cgroup bounding, zero host port publishing, and complete network confinement to `sentinel_db_network` (`internal: true`).

### 13.2 Resource Governance & Process Limits

Every service is bounded by explicit CPU, memory, and process (`pids`) ceilings to constrain container consumption:

| Service | CPU Limit | Memory Limit | Memory Reservation | PID Limit | Writable Tmpfs Paths |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`db`** | `2.0` | `1024M` | `256M` | `100` | Volume-backed `/var/lib/postgresql` |
| **`migration`** | `1.0` | `512M` | `128M` | `50` | `/tmp:rw,noexec,nosuid,size=64m` |
| **`api`** | `2.0` | `1024M` | `256M` | `100` | `/tmp:rw,noexec,nosuid,size=64m` |
| **`worker`** | `2.0` | `1024M` | `256M` | `100` | `/tmp:rw,noexec,nosuid,size=64m` |
| **`frontend`** | `1.0` | `256M` | `64M` | `50` | `/tmp` (32m), `/var/cache/nginx` (64m), `/var/run` (16m) |

> [!NOTE]
> **Operational Realities of Container Limits:**
> - **Container-Level vs Host-Wide**: Resource limits constrain individual containers; they do **not** guarantee zero host-wide resource exhaustion if aggregate host capacity is oversubscribed.
> - **OOM Termination**: Exceeding the container memory ceiling may result in container-level OOM termination (`OOMKilled`) by the host Linux kernel.
> - **CPU Throttling**: Strict CPU quotas constrain compute bursts by throttling CPU execution when utilization exceeds the allocated quota.

### 13.3 Bounded Docker Logging

All containers utilize Docker's `json-file` logging driver with strict rotation policies:
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```
- **Per-Container Scope**: Docker log rotation applies on a **per-container basis** (3 files × 10MB = 30MB maximum per container), not as a global host-wide disk quota.
- **Container Recreation Requirement**: Existing running containers must be recreated (`docker compose up -d --force-recreate`) to apply changed logging configuration; a simple `docker compose restart` does not update container log driver settings.

### 13.4 Nginx & HTTP Perimeter Hardening

The reverse proxy boundary implements strict defensive HTTP controls:
- **Server Token Concealment**: `server_tokens off;` suppresses Nginx version numbers in response headers and default error pages.
- **Header Obfuscation**: `proxy_hide_header X-Powered-By;` removes upstream framework signatures.
- **Defensive Security Headers**:
  - `X-Frame-Options: DENY` (anti-clickjacking)
  - `X-Content-Type-Options: nosniff` (anti-MIME-sniffing)
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=()` (disables unused browser device APIs)
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';`
    - *`script-src 'self'`*: Vite compiles all JavaScript into external chunks (`/assets/*.js`). Zero inline scripts exist in the production distribution, eliminating `'unsafe-inline'`.
    - *`connect-src 'self'`*: Overly broad `http: https:` is eliminated. All API calls target same-origin relative `/api/v1` routes reverse-proxied by Nginx.
    - *`style-src 'self' 'unsafe-inline'`*: Retained `'unsafe-inline'` specifically for React JSX dynamic inline styles (`style={{ ... }}`) used across dashboard components.
    - *`object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`*: Restricts plugins, base URI modification, and frame nesting.
- **Request Sizing**: `client_max_body_size 10M;` protects against oversized payload memory exhaustion while accommodating batch event telemetry ingestion.
- **Network Interface Pinning**: Host ports for `api` (8000) and `frontend` (8080) bind by default to loopback interface `${BIND_IP:-127.0.0.1}`, preventing accidental public internet exposure.

### 13.5 Operational Command Runbook

#### Service Status & Health Inspection
```bash
# Check container status and health state
docker compose ps

# Inspect deep API dependency readiness (PostgreSQL & MITRE status)
curl -f http://127.0.0.1:8000/api/health/ready

# Inspect fast API process liveness
curl -f http://127.0.0.1:8000/api/health/live

# Inspect frontend proxy health
curl -f http://127.0.0.1:8080/healthz
```

#### Log Monitoring & Tailing
```bash
# Tail all services with timestamps
docker compose logs -f -t

# Tail specific services
docker compose logs -f --tail=100 api
docker compose logs -f --tail=100 worker
docker compose logs -f --tail=100 db
```

#### Safe Lifecycle Operations
```bash
# Graceful worker and API drain and stop (allows worker 15s in-flight task drain)
docker compose stop -t 20 worker api

# Graceful restart of application services
docker compose restart api worker

# Full graceful teardown (preserves database volumes and secrets)
docker compose down

# Rebuild and relaunch after code updates
docker compose up -d --build
```

### 13.6 Residual Security Risks & Host-Level Production Recommendations

1. **Outbound Egress Filtering**:
   - *Risk*: `sentinel_egress_network` provides Layer 3 NAT outbound internet access to permit Google Gemini API communication. Standard Docker bridge networks do not enforce Layer 4 port or destination IP filtering.
   - *Host Recommendation*: Enforce host-level firewall rules (`iptables` / `nftables` / cloud security group) restricting container outbound traffic strictly to TCP port `443` (HTTPS) targeting authorized Google API ranges or route egress through an enterprise outbound proxy.
2. **TLS Termination & HSTS**:
   - *Risk*: SentinelAgent frontend listens on HTTP port `8080`. HSTS cannot be served over plaintext HTTP.
   - *Host Recommendation*: Terminate TLS upstream using an ingress reverse proxy, cloud load balancer (e.g. AWS ALB, GCP Cloud Load Balancing), or Cloudflare, and configure HTTP-to-HTTPS redirection and HSTS (`Strict-Transport-Security`) at that public boundary.
3. **User Namespaces / Rootless Docker**:
   - *Host Recommendation*: In high-assurance production environments, configure rootless Docker or user namespaces (`userns-remap`) on the Docker daemon so that container root (used briefly during initdb) maps to an unprivileged UID on the host system.
4. **Static vs. Live Verification Scope**:
   - *Verification Scope*: All security configurations, capability drops, read-only policies, tmpfs flags, logging limits, and resource ceilings have been verified via automated pytest contract suites, Docker Compose schema compilation, and frontend test suites. Live multi-container runtime execution in the Docker daemon will be verified in Task 12.6 upon daemon activation.

