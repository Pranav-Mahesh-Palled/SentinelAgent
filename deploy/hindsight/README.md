# SentinelAgent — Hindsight Auxiliary Subsystem Deployment Specification

This directory contains the production-grade local container deployment specification for **Hindsight v1.2.1** and its containerized inference engine (**Ollama v0.40.16** running **Gemma 3 4B**), governed by the approved **Option B 4-Network Partitioned Ingress Architecture**.

---

## 1. Architecture & Network Topology Overview (Option B Partitioned Ingress)

SentinelAgent strictly segregates **authoritative forensic telemetry** (stored immutably in PostgreSQL) from **auxiliary incident memory** (managed by Hindsight).

Option B enforces network isolation and host loopback access by splitting the deployment into **four distinct networks** bridged solely by unprivileged, read-only reverse proxy gateways:

```
+-------------------------------------------------------------------------------------------------------------------------+
|                                           HOST WORKSTATION (WINDOWS 11 / WSL2)                                          |
|                                                                                                                         |
|  +-------------------------------------+                                                                                |
|  | SentinelAgent Backend (FastAPI)     |                                                                                |
|  | PID: Host Process                   |                                                                                |
|  | Config: HINDSIGHT_ENABLED=false     |                                                                                |
|  +------------------+------------------+                                                                                |
|                     |                                                                                                   |
|                     | 1. HTTP/1.1 REST (Loopback Only)                                                                  |
|                     |    Host Binding: 127.0.0.1:8888                                                                   |
|                     |    Authorization: Bearer <secret>                                                                 |
|                     v                                                                                                   |
|  +-------------------------------------------------------------------------------------------------------------------+  |
|  | DOCKER BRIDGE 1: sentinelagent-ingress-net (driver: bridge, internal: false)                                       |  |
|  |                                                                                                                   |  |
|  |   +--------------------------------------------------------------------+                                          |  |
|  |   | Dedicated API Ingress Proxy: sentinelagent-hindsight-gw             |                                          |  |
|  |   | Image: nginxinc/nginx-unprivileged:stable-alpine-slim              |                                          |  |
|  |   | Published Port: 127.0.0.1:8888:8888                                |                                          |  |
|  |   | Security: Read-Only Root FS, CapDrop ALL, UID 101, No-New-Priv     |                                          |  |
|  |   | Auth: Forwards Authorization header; safe_ingress log format       |                                          |  |
|  |   +---------------------------------+----------------------------------+                                          |  |
|  +-------------------------------------|-----------------------------------------------------------------------------+  |
|                                        |                                                                                |
|                                        | Forward to Upstream (HTTP)                                                     |
|                                        v                                                                                |
|  +-------------------------------------------------------------------------------------------------------------------+  |
|  | DOCKER INTERNAL BRIDGE 2: sentinelagent-api-net (driver: bridge, internal: true)                                  |  |
|  |                                                                                                                   |  |
|  |   +--------------------------------------------------------------------+                                          |  |
|  |   | Hindsight v1.2.1 Daemon                                            |                                          |  |
|  |   | container: sentinelagent-hindsight                                 |                                          |  |
|  |   | Ports: NONE PUBLISHED (Unbound on host)                            |                                          |  |
|  |   | LLM: http://sentinelagent-ollama-gw:11434/v1                        |                                          |  |
|  |   | Control Plane 9999: UNBOUND, MCP Server: DISABLED                  |                                          |  |
|  |   +---------------------------------+----------------------------------+                                          |  |
|  +-------------------------------------|-----------------------------------------------------------------------------+  |
|                                        |                                                                                |
|                                        | LLM Request (HTTP)                                                             |
|                                        v                                                                                |
|  +-------------------------------------------------------------------------------------------------------------------+  |
|  | DOCKER INTERNAL BRIDGE 3: sentinelagent-hindsight-net (driver: bridge, internal: true)                            |  |
|  |                                                                                                                   |  |
|  |   +--------------------------------------------------------------------+                                          |  |
|  |   | Restricted Ollama Reverse-Proxy Gateway                            |                                          |  |
|  |   | container: sentinelagent-ollama-gw                                 |                                          |  |
|  |   | Image: nginxinc/nginx-unprivileged:stable-alpine-slim              |                                          |  |
|  |   | Listening: 11434 (Internal only, no host publish)                  |                                          |  |
|  |   | Allowlist: POST /api/chat, POST /v1/chat/completions               |                                          |  |
|  |   +---------------------------------+----------------------------------+                                          |  |
|  +-------------------------------------|-----------------------------------------------------------------------------+  |
|                                        |                                                                                |
|                                        | Filtered Inference Request (HTTP)                                              |
|                                        v                                                                                |
|  +-------------------------------------------------------------------------------------------------------------------+  |
|  | DOCKER INTERNAL BRIDGE 4: sentinelagent-ollama-net (driver: bridge, internal: true)                               |  |
|  |                                                                                                                   |  |
|  |   +--------------------------------------------------------------------+                                          |  |
|  |   | Containerized Ollama v0.40.16 Daemon                               |                                          |  |
|  |   | container: sentinelagent-ollama                                    |                                          |  |
|  |   | Engine: llama.cpp / cuBLAS                                         |                                          |  |
|  |   | Model: gemma3:4b (Q4_K_M)                                          |                                          |  |
|  |   | Listening: 0.0.0.0:11434 (No host publish)                         |                                          |  |
|  |   | Volume: sentinelagent-ollama-models (rw)                           |                                          |  |
|  |   +---------------------------------+----------------------------------+                                          |  |
|  +-------------------------------------|-----------------------------------------------------------------------------+  |
|                                        |                                                                                |
|         +------------------------------+-------+                  +------------------------------------+                |
|         |                                      |                  | Dedicated Model Volume:            |                |
|         v                                      v                  | sentinelagent-ollama-models        |                |
|  +------------------------------------+ +-----------------------+ | Target: /root/.ollama              |                |
|  | sentinelagent-hindsight-data       | | hindsight-models      | | Status: Preloaded via Bootstrap    |                |
|  | (/home/hindsight/.pg0)             | | (.cache/huggingface)  | +------------------------------------+                |
|  +------------------------------------+ +-----------------------+                                                       |
+-------------------------------------------------------------------------------------------------------------------------+
```

### Expected Communication Paths Matrix

| Source | Destination | Expected Connectivity | Technical & Security Boundary |
| :--- | :--- | :---: | :--- |
| **Host Workstation** | **Hindsight Ingress Proxy** (`sentinelagent-hindsight-gw`) | **YES** | Host loopback `127.0.0.1:8888` via `sentinelagent-ingress-net`. Mediated by unprivileged Nginx reverse proxy. |
| **Hindsight Ingress Proxy** | **Hindsight Daemon** (`sentinelagent-hindsight`) | **YES** | Internal HTTP on `sentinelagent-api-net` to `http://sentinelagent-hindsight:8888`. Forwards Bearer token. |
| **SentinelAgent Backend** | **Hindsight Daemon (Direct)** | **NO** | Hindsight container has no published ports (`ports:` omitted). Access must traverse `sentinelagent-hindsight-gw`. |
| **Hindsight Ingress Proxy** | **Ollama / Ollama Gateway** | **NO** | No shared Docker network. Ingress gateway cannot resolve or route to `sentinelagent-ollama-gw` or `sentinelagent-ollama`. |
| **Hindsight Daemon** | **Ollama Gateway** (`sentinelagent-ollama-gw`) | **YES** | Internal HTTP on `sentinelagent-hindsight-net` to `http://sentinelagent-ollama-gw:11434`. |
| **Ollama Gateway** | **Ollama Daemon** (`sentinelagent-ollama`) | **YES** | Internal HTTP on `sentinelagent-ollama-net` to `http://sentinelagent-ollama:11434`. |
| **Hindsight Daemon** | **Ollama Daemon (Direct)** | **NO** | No shared Docker network. Container names do not resolve across separate bridges; direct routing is absent. |
| **Ollama Daemon** | **Hindsight Daemon** | **NO** | No shared Docker network. Container names do not resolve; direct routing is absent. |

### Key Architectural Tenets
1. **Host Ingress Mediation via Unprivileged Proxy**: The application daemon (`hindsight`) publishes zero ports to the host and attaches only to internal networks. Host loopback `127.0.0.1:8888` is published exclusively by `sentinelagent-hindsight-gw` on `sentinelagent-ingress-net`.
2. **Zero Core Subsystem Egress**: Neither `hindsight`, `ollama-gw`, nor `ollama` attach to the default bridge or any external network. Networks `sentinelagent-api-net`, `sentinelagent-hindsight-net`, and `sentinelagent-ollama-net` all declare `internal: true`.
3. **No Direct Hindsight-to-Ollama Path**: Hindsight cannot resolve or connect directly to `sentinelagent-ollama`. All inference traffic passes through `sentinelagent-ollama-gw`.
4. **Credential Confidentiality**: The ingress gateway logs via `safe_ingress`, strictly omitting `$http_authorization` and request bodies. The gateway container possesses no secrets in its environment.

---

## 2. Pinned Immutable Image References & Authenticity Status

Every container image in this deployment specification is strictly pinned to its immutable Content Addressable Identifier (SHA-256 digest) targeting `linux/amd64`. Floating or mutable tags (`:latest`, `:1.2.1`, `:stable`) are strictly prohibited in runtime files.

| Service | Canonical Image Descriptor | Media Type & Digest Role | Publisher Authenticity Status |
| :--- | :--- | :--- | :--- |
| `hindsight-gw` | `nginxinc/nginx-unprivileged@sha256:07783a7bd042ac2229183c0660aca15fcdf9a006bb4e37c7efd78482bc3900b9` | Platform-specific `linux/amd64` manifest payload *(Parent Index: `sha256:5d8bb943...`)*. | **NOT INDEPENDENTLY VERIFIED**: Official Docker Hub image, but no independent Sigstore/Cosign signature is published. Content immutability is guaranteed by digest pinning only. |
| `hindsight` | `ghcr.io/vectorize-io/hindsight@sha256:d2bc230a714e933affd63753e181a0579328fdcbbc021800a76e0bc7b6e76b31` | Multi-platform OCI Index (`linux/amd64` manifest: `sha256:b14729de...`). | **Cosign Verifiable**: Published via GitHub Actions release workflow from `vectorize-io/hindsight` with OIDC issuer `https://token.actions.githubusercontent.com`. |
| `ollama-gw` | `nginxinc/nginx-unprivileged@sha256:07783a7bd042ac2229183c0660aca15fcdf9a006bb4e37c7efd78482bc3900b9` | Platform-specific `linux/amd64` manifest payload *(Parent Index: `sha256:5d8bb943...`)*. | **NOT INDEPENDENTLY VERIFIED**: Official Docker Hub image, but no independent Sigstore/Cosign signature is published. Content immutability is guaranteed by digest pinning only. |
| `ollama` | `ollama/ollama@sha256:910d0d8107b538fb0894e63163eb195de0cc7aefcbc666dc62d3b18f71124592` | Multi-platform OCI Index (`linux/amd64` manifest: `sha256:a372a1c0...`). | **NOT INDEPENDENTLY VERIFIED**: Official Docker Hub image, but no independent cryptographic signatures are published in registry metadata. Content immutability is guaranteed by digest pinning only. |
| `cuda-sample` | `nvcr.io/nvidia/k8s/cuda-sample:nbody@sha256:59261e419d6d48a772aad5bb213f9f1588fcdb042b115ceb7166c89a51f03363` | Multi-platform Docker manifest list (`linux/amd64` manifest: `sha256:7278897b...`). | **NOT INDEPENDENTLY VERIFIED**: Hosted on NVIDIA NGC (`nvcr.io`). Immutability guaranteed by digest pinning. |

---

## 3. Reverse-Proxy Gateway Policies & Security Boundaries

### 3.1 API Ingress Gateway Policy (`deploy/hindsight/gateway/api-nginx.conf`)
The API ingress proxy (`sentinelagent-hindsight-gw`) acts as the single entry point for host traffic into Hindsight, enforcing an explicit, non-recursive route and method allowlist tailored strictly to SentinelAgent backend requirements. All canonical paths are forwarded using normalized `$uri$is_args$args`.

#### Pre-Routing Strict Raw Path Canonicalization Security Gate
Before evaluating any location block, Nginx inspects the raw request path component of `$request_uri` (preceding any query delimiter `?`) and rejects noncanonical requests with `HTTP 400 Bad Request`:
- **ANY percent-encoded characters in path**: Blocks encoded unreserved characters (`%62`, `%74`, `%2d`, `%5F`, `%7e`, `%41`), encoded traversal sequences (`%2e`), encoded slashes (`%2f`), and double-encoded markers (`%25`).
- **Duplicate consecutive slashes**: Blocks `//` anywhere in the path.
- **Raw backslashes**: Blocks `\` in the path.
- **Dot segments and traversals**: Blocks `..`, `/.`, and trailing dots (`.$` or `.?`).
- **Query String Distinction**: Query parameters following `?` are evaluated by endpoint-specific query filters and are not conflated with the raw path gate.

| Endpoint | Method | Status | Purpose | Backend Client Method |
| :--- | :---: | :---: | :--- | :--- |
| `/healthz` | `GET` | **ALLOWED** | Ingress gateway local container liveness probe. HEAD/POST/PUT rejected with 405. *(Does NOT prove upstream reachability).* | Compose healthcheck |
| `/health`, `/health/ready`, `/health/live` | `GET`, `HEAD` | **ALLOWED** | Upstream Hindsight application and database readiness probes. Query parameters rejected with 400. | Operator / Host curl |
| `/v1/default/banks` | `GET` | **ALLOWED** | Memory bank enumeration and readiness verification probe. *(Query param `limit=[0-9]+` only; HEAD rejected with 405; bare `/v1/banks` rejected with 403).* | `HindsightClientService.check_health()` |
| `.../banks/{bank_id}/memories` | `POST` | **ALLOWED** | Incident memory retention (`aretain`). *(Query params, GET, HEAD, PUT, PATCH, DELETE blocked).* | `HindsightClientService.retain_investigation_memory()` |
| `.../banks/{bank_id}/memories/recall` | `POST` | **ALLOWED** | Incident memory semantic retrieval (`arecall`). *(Query params, GET, HEAD, PUT, DELETE blocked; bare `/recall` blocked with 403).* | `HindsightClientService.recall_memories()` |
| `.../banks/{bank_id}/operations/{id}` | `GET` | **ALLOWED** | Asynchronous retention operation status polling. *(Query param `include_payload=(true\|false\|0\|1)` only; HEAD rejected with 405).* | `HindsightClientService.get_operation_status()` |
| `.../banks/{bank_id}/operations/{id}/retry` | `POST` | **ALLOWED** | Asynchronous retention operation retry submission. *(Query params blocked).* | `HindsightClientService.retry_operation()` |
| `/docs`, `/redoc`, `/openapi.json` | ANY | **DENIED (404)** | Administrative documentation and schema inspection blocked. | None (blocked) |
| `/metrics` | ANY | **DENIED (404)** | Prometheus metrics exposition blocked. | None (blocked) |
| `/mcp`, `/sse` | ANY | **DENIED (404)** | Model Context Protocol endpoints blocked. | None (blocked) |
| `/version`, `/v1/version` | ANY | **DENIED (404)** | Upstream version metadata reconnaissance blocked. | None (blocked) |
| All other paths & methods | ANY | **DENIED (403)** | Default deny policy; blocks DELETE, PUT, PATCH, bare `/v1/banks`, documents, config, and unmapped paths. | None (blocked) |

#### Ingress Gateway Hardening & Confidentiality
- **Unprivileged User**: Runs as UID `101` (`nginx`).
- **Read-Only Root Filesystem**: `read_only: true` in Compose.
- **Capabilities Dropped**: `cap_drop: [ALL]`.
- **Privilege Escalation Prevention**: `security_opt: [no-new-privileges:true]`.
- **Ephemeral Writable Storage**: Memory-backed `tmpfs` mounts for `/tmp`, `/var/run`, `/var/cache/nginx`.
- **Fixed Upstream Host Header**: `proxy_set_header Host sentinelagent-hindsight:8888;` prevents Host-header injection attacks and aligns with upstream container identity.
- **Authorization Forwarding**: Configured with `proxy_set_header Authorization $http_authorization;` to forward the client Bearer token to Hindsight's `ApiKeyTenantExtension`.
- **Logging Confidentiality**: The `safe_ingress` log format logs `$remote_addr`, `$request_method`, and `$uri`, strictly omitting `$http_authorization`, `$http_referer`, `$http_user_agent`, query parameters, and request/response bodies.
- **Payload & Timeout Limits**: `client_max_body_size 16m;` accommodates maximum batch outbox retention (~1 MB actual max) with safety margin; route-specific `proxy_read_timeout` (15s to 60s) aligns with backend client timeouts.

### 3.2 Ollama Egress Gateway Policy (`deploy/hindsight/gateway/nginx.conf`)
The inference proxy (`sentinelagent-ollama-gw`) mediates LLM traffic between Hindsight and Ollama.

| Endpoint | Method | Status | Purpose |
| :--- | :---: | :---: | :--- |
| `/api/chat` | `POST` | **ALLOWED** | Primary LLM generation, retain extraction, recall synthesis, and startup `verify_connection()` probe. |
| `/v1/chat/completions` | `POST` | **ALLOWED** | Conditional fallback OpenAI chat completion route. |
| `/healthz` | `GET` | **ALLOWED** | Gateway internal readiness and liveness health probe. |
| `/api/pull` | ANY | **DENIED (403)** | Administrative model downloading blocked. |
| `/api/delete` | ANY | **DENIED (403)** | Administrative model deletion blocked. |
| `/api/create` | ANY | **DENIED (403)** | Administrative custom model creation blocked. |
| `/api/generate` | ANY | **DENIED (403)** | Raw text completion unused by Hindsight; blocked. |
| `/api/embeddings` | ANY | **DENIED (403)** | Embeddings execute in-container via FastEmbed; blocked. |
| `/api/tags` | ANY | **DENIED (403)** | Catalog inspection blocked. |
| All other paths | ANY | **DENIED (403)** | Default deny policy; CONNECT tunneling blocked. |

---

## 4. Threat Disclosure & Residual Risk Analysis

> [!WARNING]
> **Accepted Residual Risk: Partitioned Ingress Proxy & Lateral Movement**
>
> 1. **Protocol Security & Credential Transit**:
>    - Communication between the host and `sentinelagent-hindsight-gw`, as well as between `sentinelagent-hindsight-gw` and `sentinelagent-hindsight`, utilizes unencrypted **HTTP over local loopback and internal Docker bridges** (TLS is not configured).
>    - Because the ingress proxy forwards `Authorization: Bearer <token>`, a compromised gateway process can inspect plaintext memory buffers and capture API credentials in transit. No secret volume mount is required for the gateway to observe credentials flowing through it.
> 2. **Ingress Gateway Network Position & Bridge Egress**:
>    - `sentinelagent-hindsight-gw` attaches to `sentinelagent-ingress-net` (an ordinary Docker bridge) solely to publish `127.0.0.1:8888`.
>    - Ordinary Docker bridges do not suppress default gateway routes; therefore, a compromised ingress container has potential outbound egress or host-service reachability.
>    - The ingress gateway container possesses **zero secrets**, **zero database mounts**, **zero model weights**, and shares **no network** with `sentinelagent-ollama` or `sentinelagent-ollama-gw`.
> 3. **Core Subsystem Isolation**:
>    - The core application and inference containers (`hindsight`, `ollama-gw`, `ollama`) remain 100% attached to `internal: true` bridges (`api-net`, `hindsight-net`, `ollama-net`) with zero default gateway routes and zero published host ports.
>    - Lateral movement to the Ollama container is barred because Hindsight cannot route to `sentinelagent-ollama` directly, only through `sentinelagent-ollama-gw`.
> 4. **Ollama Administrative Surface**: Ollama lacks native authentication. Protection of the Ollama engine relies entirely on the internal bridge boundary and the strict allowlist of `sentinelagent-ollama-gw`.
> 5. **Formal Risk Acceptance**: For this single-developer local workstation deployment, these residual risks are formally **accepted**.

---

## 5. Startup & Model Volume Compatibility Analysis

### Upstream Startup Routines (`ollama/server/routes.go`)
Inspection of Ollama v0.40.16 source code confirms that during `Serve(ln)`:
1. `llm.PruneSplitModelDirs(blobsDir)` runs unconditionally.
2. `fixBlobs(blobsDir)` scans for `.partial` files or 0-byte corrupt records and attempts file system write operations (`os.Remove`, `os.Rename`).
3. `PruneLayers()` scans unreferenced blobs and removes them, unless disabled.

### Why `sentinelagent-ollama-models` Remains Writable
- Passing `OLLAMA_NOPRUNE=true` successfully bypasses `PruneLayers()`.
- However, `fixBlobs()` remains **active and unconditional**. If `/root/.ollama` is mounted read-only (`:ro`), startup fails immediately with `EROFS: read-only file system`.
- **Security Boundary Reality**: The model volume is writable at the container filesystem layer. Network isolation (`internal: true`) and gateway path restrictions reduce accidental unauthorized access, but do **not** make the writable volume immutable once the network boundary or gateway is traversed.

---

## 6. Model Preloading Protocol (Bootstrap Script)

Because runtime containers have zero internet access, model acquisition occurs in a controlled, ephemeral preparation phase.

### 6.1 Ollama Gemma 3 4B Preloading Script
The automated PowerShell bootstrap script [`deploy/hindsight/scripts/bootstrap-ollama-model.ps1`](scripts/bootstrap-ollama-model.ps1) coordinates this process safely:

```powershell
# Run from repository root in PowerShell:
.\deploy\hindsight\scripts\bootstrap-ollama-model.ps1
```

**Bootstrap Guarantees:**
1. Connects an ephemeral container (`sentinelagent-ollama-bootstrap`) to the default bridge network solely during model download.
2. Mounts **only** `sentinelagent-ollama-models` (no application code, no secrets).
3. Publishes **zero** host ports.
4. Uses immutable image digest `ollama/ollama@sha256:910d0d8107b538fb0894e63163eb195de0cc7aefcbc666dc62d3b18f71124592`.
5. Cryptographically verifies model manifest descriptors against actual disk blobs via SHA-256 calculation (`sha256sum`). Fails closed on missing blobs or hash mismatches.
6. Cleanly stops and removes the temporary container in a `finally` block upon completion or failure.

### 6.2 Model Blob Integrity vs. Model Publisher Authenticity

> [!IMPORTANT]
> **Crucial Supply-Chain Distinction:**
> - **Local Blob Integrity (VERIFIED)**: The bootstrap script computes the SHA-256 checksum of every downloaded layer blob on disk and validates that it matches the descriptor declared in the downloaded manifest. This guarantees that blobs on disk are not corrupted or altered relative to that manifest.
> - **Model Publisher Authenticity (NOT INDEPENDENTLY VERIFIED)**: The bootstrap script pulls `gemma3:4b` from `registry.ollama.ai` by tag. The script does **not** independently pin the manifest digest itself or cryptographically verify a digital signature from Google or Ollama via an independent PKI. The authenticity of the upstream model artifact depends entirely on transport trust to `registry.ollama.ai`.

### 6.3 Hindsight Offline Model Seeding (BGE & HS Reranker)
Hindsight v1.2.1 operates under `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`. Prior to launching Hindsight, seed the `sentinelagent-hindsight-models` volume:

```powershell
# One-time model weight acquisition container
docker run --rm `
  -v sentinelagent-hindsight-models:/home/hindsight/.cache/huggingface `
  ghcr.io/vectorize-io/hindsight@sha256:d2bc230a714e933affd63753e181a0579328fdcbbc021800a76e0bc7b6e76b31 `
  python3 -c "from sentence_transformers import CrossEncoder, SentenceTransformer; SentenceTransformer('BAAI/bge-small-en-v1.5'); CrossEncoder('hindsight-ai/hs-rerank-1')"
```

---

## 7. GPU and CPU Deployment Modes

### 7.1 Pre-Flight GPU Validation
Before enabling GPU acceleration, verify Docker Desktop and WSL2 NVIDIA paravirtualization using Docker's official CUDA benchmark:
```powershell
docker run --rm --platform=linux/amd64 --gpus=all nvcr.io/nvidia/k8s/cuda-sample:nbody@sha256:59261e419d6d48a772aad5bb213f9f1588fcdb042b115ceb7166c89a51f03363 nbody -gpu -benchmark
```
*(Platform Linux AMD64 image manifest: `sha256:7278897bef4fc36f4d21cf3c591be597911a2d7ee45c7d1e55bde9d89b96c75a`).*

### 7.2 CPU Fallback Mode (Default)
Standard execution runs Ollama in CPU mode with dynamic layer scheduling:
```powershell
docker compose -f .\deploy\hindsight\compose.yaml --env-file .\deploy\hindsight\.env.hindsight up -d
```

### 7.3 GPU Accelerated Mode (Override)
To enable NVIDIA hardware reservation (RTX 3050 Laptop via `/dev/dxg`), apply the GPU Compose override:
```powershell
docker compose -f .\deploy\hindsight\compose.yaml -f .\deploy\hindsight\compose.gpu.yaml --env-file .\deploy\hindsight\.env.hindsight up -d
```

---

## 8. Operational Lifecycle Commands

All commands are executed from the repository root:

```powershell
# 1. Validate Compose Configuration (Without starting containers)
docker compose -f .\deploy\hindsight\compose.yaml --env-file .\deploy\hindsight\.env.hindsight config --quiet

# 2. Validate GPU Compose Configuration (Without starting containers)
docker compose -f .\deploy\hindsight\compose.yaml -f .\deploy\hindsight\compose.gpu.yaml --env-file .\deploy\hindsight\.env.hindsight config --quiet

# 3. Start Subsystem (Detached Mode - CPU)
docker compose -f .\deploy\hindsight\compose.yaml --env-file .\deploy\hindsight\.env.hindsight up -d

# 4. Start Subsystem (Detached Mode - GPU Accelerated)
docker compose -f .\deploy\hindsight\compose.yaml -f .\deploy\hindsight\compose.gpu.yaml --env-file .\deploy\hindsight\.env.hindsight up -d

# 5. Check Service Status & Container Health
docker compose -f .\deploy\hindsight\compose.yaml --env-file .\deploy\hindsight\.env.hindsight ps

# 6. Inspect Service Logs
docker compose -f .\deploy\hindsight\compose.yaml --env-file .\deploy\hindsight\.env.hindsight logs -f

# 7. Graceful Teardown
docker compose -f .\deploy\hindsight\compose.yaml --env-file .\deploy\hindsight\.env.hindsight down

# 8. Complete Teardown (DESTRUCTIVE: Deletes persistent data and model volumes)
docker compose -f .\deploy\hindsight\compose.yaml --env-file .\deploy\hindsight\.env.hindsight down -v
```

---

## 9. Version Control & Git Change-Boundary Limitations

> [!NOTE]
> **Git Tracking Status: `GIT CHANGESET VERIFICATION UNAVAILABLE`**
>
> - The parent directory `d:\PROJECTS` hosts a Git repository where `SentinelAgent` is an untracked subfolder (`?? SentinelAgent/`).
> - There is no isolated `.git` repository initialized inside `d:\PROJECTS\SentinelAgent`.
> - Consequently, native `git diff` changeset comparison cannot be performed within SentinelAgent.
> - Change boundary verification relies strictly on explicit filesystem auditing and task execution activity logs. Operating engineers must not claim Git proves the absence of out-of-scope modifications.
