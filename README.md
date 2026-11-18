# mu-cd-controller

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/mu-cd-controller/card.svg" alt="mu-cd-controller Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-cd-controller/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-cd-controller/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-cd-controller/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-cd-controller/benchmark.svg" alt="Benchmark"/></a>
</p>

______________________________________________________________________

Continuous Delivery (CD) control plane orchestrator in the [`mu-cd`](https://github.com/LMA1980/mu-cd) workspace managing zero-downtime, autonomous deployments across cluster worker nodes over [`mu-cd-ipc`](https://github.com/LMA1980/mu-cd-ipc) and `rustls` mTLS (`step-ca` PKI).

`mu-cd-controller` coordinates with [`mu-ci-controller`](https://github.com/LMA1980/mu-ci-controller) (`GET https://controller.ci.internal:8443/api/cluster/nodes` and incoming `POST /api/cd/deploy` triggers), pulls verified artifacts from [`mu-registry`](https://github.com/LMA1980/mu-registry) (`https://registry.ci.internal:8444`), queries canary bake SLOs from [`mu-observable-hub`](https://github.com/LMA1980/mu-observable-hub), emits W3C trace spans and audit logs (`MuObserveCdSink` via `mu-observable-ipc`) to [`mu-observable-collector`](https://github.com/LMA1980/mu-observable-collector), and drives node-level [`mu-cd-agent`](https://github.com/LMA1980/mu-cd-agent) daemons over `mu-cd-ipc`.

______________________________________________________________________

## Core Responsibilities

- **Idle Runner Discovery**: Inspects target host worker utilization and pending queue depths (`active_slots == 0 && !exclusive_locked`) with exponential backoff (`MUCONDE_IDLE_*`) to schedule deployments during verified idle windows without interrupting active CI pipelines.
- **TTL-Bounded Deployment Leases**: Negotiates time-to-live leases (default `300s`) on target nodes. If lease renewal fails or verification stalls, the target node autonomously rolls back.
- **Declarative Deployment Contracts (`.mucd/mu-cd.yml` with `.muconde/MuConDe.yml` fallback)**:
  - Parses target nodes, service binary / static `web_root` / `systemd_unit` placement (`deployment`), Btrfs snapshot retention (`ab_rules`), bake SLO bounds (`bake_window_seconds`, `max_error_logs`, `max_p99_latency_ms`), and required Integration Test suites (`integration_tests: [...]` or `"all"`, plus optional `it_archive_digest`).
- **Symmetric A/B Promotion / Rollback State Machine (`@a` \<-> `@b`)**:
  - Snapshots the currently active slot (`snapshots/@snap-<digest>`) and stages the candidate release into the opposite inactive slot (`@b` when `@a` is active, `@a` when `@b` is active).
  - Atomically swaps `<service>/current` to the candidate slot and triggers warmup and live integration tests on the agent.
  - Verifies the canary bake window against [`mu-observable-hub`](https://github.com/LMA1980/mu-observable-hub) via `MuObserveSloClient` (`CanarySloAssertionRequest` over `step-ca` mTLS `MUOB` Fory RPC).
  - **Success Path**: Commits the symmetric active slot transition (`@a <-> @b`) and marks the release healthy in [`mu-registry`](https://github.com/LMA1980/mu-registry) (`POST /api/v1/canary/{digest}/promote`).
  - **Failure Path**: Dispatches immediate rollback to restore `restore_slot`, sweeps the lease, and taints the artifact digest in [`mu-registry`](https://github.com/LMA1980/mu-registry) (`POST /api/v1/canary/{digest}/taint`).

______________________________________________________________________

## Deployment State Machine

```text
[ Idle ]  <── POST /api/cd/deploy (mu-ci-controller) or CLI
   │
   ▼
[ Discover Idle Node ] ──(Node Busy)──> [ Wait / Backoff ]
   │
   ▼
[ Acquire TTL Lease ]
   │
   ▼
[ Stage Candidate in Inactive Slot (@a <-> @b) ]
   │
   ▼
[ Atomic Swap (<service>/current -> candidate) ]
   │
   ▼
[ Execute Health Probes, IT Gate & Canary Bake SLO (MuObserveSloClient) ]
   ├── All Passed ──> [ Commit Slot (@a <-> @b) ] ──> [ mu-registry Promote ] ──> [ Complete ]
   └── Fail / Timeout ──> [ Rollback to restore_slot ] ──> [ mu-registry Taint Digest ]
```

______________________________________________________________________

## Declarative Contract (`.mucd/mu-cd.yml`)

Phase 1 supports `.mucd/mu-cd.yml` (`.yaml`) with automatic fallback to `.muconde/MuConDe.yml`:

```yaml
version: "1"
service: "mu-ci-worker"

target_nodes:
  - "node-a"
  - "node-b"
  - "worker-riscv64"

lease_ttl_seconds: 300
warmup_timeout_seconds: 30
bake_window_seconds: 60
max_error_logs: 0
max_p99_latency_ms: 250.0
integration_tests: "all"

ab_rules:
  btrfs_snapshots: true
  keep_snapshots: 5
  auto_rollback_on_critical: true

deployment:
  target_nodes:
    - "node-a"
    - "node-b"
    - "worker-riscv64"
  binary: "mu-ci-worker"
  install_path: "/usr/local/bin/mu-ci-worker"
  systemd_unit: "mu-ci-worker.service"
```

______________________________________________________________________

## CD Status, Rollout & A/B Gate API (`/api/cd/*`)

> Source of truth for the `/api/cd/*` JSON contract consumed by [`mu-console`](https://github.com/LMA1980/mu-console) and [`mu-ci-controller`](https://github.com/LMA1980/mu-ci-controller).
> Field names and enums are `snake_case`; timestamps are Unix epoch milliseconds; clients must ignore unknown fields.

### Listener & Dual Authorization (`mu-auth` + Service Tokens)

| Env var                                       | Default                          | Meaning                                                                                                                              |
| --------------------------------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `MUCONDE_CD_API_ADDR`                         | unset (API **disabled**)         | Bind address of the separate axum listener, e.g. `127.0.0.1:8447`                                                                    |
| `MUCONDE_CD_API_TOKEN_FILE`                   | unset                            | File holding the service-to-service bearer token (`cd:service.deploy` and service-scoped reads)                                      |
| `MUCONDE_PROXY_SECRET_FILE`                   | unset                            | File holding the shared edge proxy secret (`X-Proxy-Secret`) for interactive [`mu-auth`](https://github.com/LMA1980/mu-auth) callers |
| `MUCONDE_OPERATOR_USERS`                      | unset                            | Comma-separated GitHub logins bootstrapped with baseline CD/A\|B operator folios                                                     |
| `MUCONDE_REPO`                                | unset                            | `owner/repo` recorded for CLI `deploy` runs (used by `?repo=`)                                                                       |
| `MUOBSERVE_ADDR` / `MUOBSERVE_COLLECTOR_ADDR` | `observe.ci.internal:9445` (SLO) | `mu-observable-hub` SLO RPC endpoint (`MuObserveSloClient`) and `mu-observable-collector` sink (`MuObserveCdSink`)                   |

`mu-cd-controller` enforces **dual authorization** (`CdAuthorizer` backed by [`mu-auth`](https://github.com/LMA1980/mu-auth)):

1. **Interactive Edge-Proxied Operators (`mu-console` via [`mu-auth`](https://github.com/LMA1980/mu-auth))**:
   - The edge reverse proxy presents `X-Proxy-Secret` (validated in constant time against `MUCONDE_PROXY_SECRET_FILE`) and `X-Forwarded-User` (GitHub login).
   - `CdAuthorizer` evaluates `PolicyFolio`s and `RoleLeases` (`member`, `gate-inspector`, `ab-emergency`, `platform-admin`, and passkey-gated `super-operator`) against canonical capabilities: `cd:runs.read`, `cd:steps.read`, `ab:slots.read`, `ab:gate.logs.read` (redacting `log_excerpt` when absent), and `ab:rollback` (there is zero `ab:promote` endpoint).
1. **Service-to-Service Bearer Tokens (`mu-ci-controller`)**:
   - Callers present `Authorization: Bearer <token>` matched in constant time against `MUCONDE_CD_API_TOKEN_FILE` for service-scoped reads and automated `POST /api/cd/deploy` triggers (`cd:service.deploy`).
   - Fails closed (`401`/`403`) if credentials are missing, unreadable, empty, or lack the required `PolicyFolio`.

Service-to-service IPC and observability traffic (`mu-cd-agent`, `mu-registry`, `mu-observable-hub`, `mu-observable-collector`) uses `step-ca` mTLS or `MUOB` framing independently of the loopback HTTP API.

### State Model & Endpoints

State is held as an immutable `Arc` snapshot updated by the orchestrator, lease coordinator, and agent `IntegrationTestProgress` frames (`MSG_TYPE_IT_PROGRESS = 0x0C`).

**Gate state machine** (`verdict`):

- `rollback` when any critical test is `failed` or the lease expired.
- `promote` when every critical test is `passed`; if there are no critical tests, when every test is terminal.
- `pending` otherwise, including an empty test list.

| Method & Route                                        | Policy Required                                                    | Purpose                                                                                   |
| ----------------------------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `GET /api/cd/runs?ecosystem=&repo=&limit=N`           | `cd:runs.read` (`cd:steps.read` for step details)                  | Lists ecosystem-agnostic CD staging/publish runs                                          |
| `GET /api/cd/deployments?repo={owner}/{repo}&limit=N` | `ab:slots.read`                                                    | Lists newest A/B deployments first (history strip and active slot)                        |
| `GET /api/cd/deployments/{id}/gate`                   | `ab:slots.read` (`ab:gate.logs.read` for unredacted `log_excerpt`) | Returns full `DeploymentGate` and per-test progress                                       |
| `POST /api/cd/deployments/{id}/rollback`              | `ab:rollback`                                                      | Triggers emergency rollback of a deployment to `restore_slot`                             |
| `GET /api/cd/leases`                                  | `ab:slots.read`                                                    | Lists active node deployment leases and remaining TTL                                     |
| `GET /api/cd/events`                                  | `ab:slots.read`                                                    | Server-Sent Events (`it_progress`, `promoted`, `rolled_back`, `tainted`, `lease_expired`) |
| `POST /api/cd/deploy`                                 | `cd:service.deploy`                                                | Triggers asynchronous or synchronous (`wait: true`) rollout from `mu-ci-controller`       |

### `GET /api/cd/deployments?repo={owner}/{repo}&limit=N`

- `repo` matches `owner/repo`, bare repo name, or service name. `limit` defaults to 20 and clamps to `1..=256`.
- `outcome`: `pending` | `promoted` | `rolled_back` | `tainted`.
- `rollback_reason`: `critical_test_failed` | `lease_expired` | `manual` | `null`.

```json
[
  {
    "deployment_id": "dep-7f3c",
    "owner": "LMA1980",
    "repo": "example",
    "service": "example-svc",
    "artifact_digest": "sha256:4be1…",
    "target_node": "worker-riscv64",
    "active_slot": "b",
    "staged_slot": "b",
    "outcome": "promoted",
    "verdict": "promote",
    "it_passed": 2,
    "it_failed": 0,
    "it_total": 2,
    "critical_failed": 0,
    "rollback_reason": null,
    "tainted": false,
    "started_epoch_ms": 1793563000000,
    "finished_epoch_ms": 1793563012345
  }
]
```

### `GET /api/cd/deployments/{id}/gate`

Returns a `DeploymentGate` (`404 {"error":"deployment_not_found"}` when missing). `log_excerpt` is populated for failed tests when the caller holds `ab:gate.logs.read` and redacted otherwise.

```json
{
  "deployment_id": "dep-7f3c",
  "owner": "LMA1980",
  "repo": "example",
  "service": "example-svc",
  "artifact_digest": "sha256:4be1…",
  "target_node": "worker-riscv64",
  "active_slot": "a",
  "staged_slot": "b",
  "restore_slot": "a",
  "lease_id": "lease-91d2",
  "lease_expires_epoch_ms": 1793563300000,
  "lease_ttl_remaining_ms": 287655,
  "outcome": "pending",
  "verdict": "pending",
  "rollback_reason": null,
  "rollback_detail": null,
  "tainted": false,
  "started_epoch_ms": 1793563000000,
  "finished_epoch_ms": null,
  "tests": [
    { "name": "systemd_unit_active", "critical": true, "state": "passed", "duration_ms": 512, "crate_name": null, "log_excerpt": null },
    { "name": "health_endpoint_ready", "critical": true, "state": "running", "duration_ms": 0, "crate_name": null, "log_excerpt": null }
  ]
}
```

### `GET /api/cd/leases` & `GET /api/cd/events` (SSE)

```json
[
  {
    "lease_id": "lease-91d2",
    "deployment_id": "dep-7f3c",
    "target_node": "worker-riscv64",
    "service": "example-svc",
    "artifact_digest": "sha256:4be1…",
    "active_slot": "a",
    "candidate_slot": "b",
    "expires_epoch_ms": 1793563300000,
    "ttl_remaining_ms": 287655,
    "promoted": false
  }
]
```

`/api/cd/events` streams `text/event-stream` with `: heartbeat` every 15 s (lagged consumers > 1024 events disconnect to reconnect and resync):

| `event:`        | `data:`                                                                               |
| --------------- | ------------------------------------------------------------------------------------- |
| `it_progress`   | `{"deployment_id","test_name","critical","state","duration_ms","timestamp_epoch_ms"}` |
| `promoted`      | `{"deployment_id","slot"}`                                                            |
| `rolled_back`   | `{"deployment_id","restore_slot","reason","detail"}`                                  |
| `tainted`       | `{"deployment_id","artifact_digest","reason"}`                                        |
| `lease_expired` | `{"deployment_id","lease_id"}`                                                        |

______________________________________________________________________

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See [LICENSE](LICENSE) for details.
