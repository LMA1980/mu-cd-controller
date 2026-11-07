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

---

Continuous Delivery (CD) control plane orchestrator managing zero-downtime, safe, autonomous deployment across cluster worker nodes over `mu-cd-ipc` and `rustls` mTLS (`step-ca` PKI).

`mu-cd-controller` coordinates with `ActionRunner-controller` (`GET https://controller.ci.internal:8443/api/cluster/nodes`), pulls verified artifacts from `MuRegist` (`https://registry.ci.internal:8444`), and drives node-level `mu-cd-agent` daemons over `mu-cd-ipc`.

---

## Core Responsibilities

- **Idle Runner Discovery**: Inspects target host worker utilization and pending queue depths (`active_slots == 0 && !exclusive_locked`) to schedule deployments during verified idle windows without interrupting active factory pipelines.
- **TTL-Bounded Deployment Leases**: Negotiates time-to-live leases (e.g. 300s) on target nodes. If lease renewal fails or verification stalls, the target node autonomously rolls back.
- **Declarative IT Failure Contracts (`.mucd/mu-cd.yml` with `.muconde/MuConDe.yml` fallback)**:
  - Parses deployment requirements: target node, target slot, probe endpoints, and required critical Integration Test suites (`integration_tests: [...]` or `"all"`).
- **Atomic Promotion / Rollback State Machine**:
  - Stages candidate release in inactive slot (Slot B).
  - Swaps active execution pointer to candidate slot.
  - Executes live integration tests and health probes against Slot B.
  - **Success Path**: Dispatches atomic promotion trigger to swap Slot B to baseline Slot A and marks release healthy in `MuRegist` (`POST /api/v1/canary/{digest}/promote`).
  - **Failure Path**: Dispatches immediate rollback trigger to restore baseline Slot A, sweeps lease, and marks artifact digest as tainted in `MuRegist` (`POST /api/v1/canary/{digest}/taint`).

---

## Deployment State Machine

```text
[ Idle ]
   │
   ▼
[ Discover Idle Node ] ──(Node Busy)──> [ Wait / Backoff ]
   │
   ▼
[ Acquire TTL Lease ]
   │
   ▼
[ Stage Deployment (Slot B) ]
   │
   ▼
[ Slot Swap to Slot B ]
   │
   ▼
[ Execute Health Probes & ITs ]
   ├── All Passed ──> [ Promote Slot B ➔ Slot A ] ──> [ MuRegist Promote ] ──> [ Complete ]
   └── Probe Fail / Timeout ──> [ Rollback to Slot A ] ──> [ MuRegist Taint Digest ]
```

---

## Declarative Contract (`.mucd/mu-cd.yml`)

Phase 1 supports both `.mucd/mu-cd.yml` (and `.yaml`) and legacy `.muconde/MuConDe.yml` (with fallback warning).

```yaml
version: "1"
service: "action-runner"
target_nodes:
  - "worker-riscv64"
lease_ttl_seconds: 300
warmup_timeout_seconds: 30
integration_tests: "all"
```

Or target specific integration test suites:

```yaml
version: "1"
service: "action-runner"
target_nodes:
  - "worker-riscv64"
lease_ttl_seconds: 300
warmup_timeout_seconds: 30
integration_tests:
  - "it_smoke"
  - "it_mtls_handshake"
```

---

## Read-only CD Status & Integration-Gate API (`/api/cd/*`)

> This section is the source of truth for the `/api/cd/*` JSON contract consumed by MuConsole.
> Field names and enums are `snake_case`; timestamps are Unix epoch milliseconds; clients must
> ignore unknown fields so the server can add fields without breaking them.

### Listener and authentication

| Env var | Default | Meaning |
|---|---|---|
| `MUCONDE_CD_API_ADDR` | unset (API **disabled**) | Bind address of the separate axum listener, e.g. `127.0.0.1:8447` |
| `MUCONDE_CD_API_TOKEN_FILE` | unset | Path of a file holding the bearer token |
| `MUCONDE_REPO` | unset | `owner/repo` recorded for CLI `deploy` runs (used by `?repo=`) |

- The listener is plain HTTP and **read-only** (`GET` only). Bind it to loopback; browsers reach it only through the reverse proxy, which authenticates the session and forwards `Authorization: Bearer <token>`.
- **Every** `/api/cd/*` route, including the SSE stream, requires `Authorization: Bearer <token>`. Without it, or with a wrong token, the response is `401` with `WWW-Authenticate: Bearer realm="muconde-cd"` and `{"error":"unauthorized"}`.
- The token is read from `MUCONDE_CD_API_TOKEN_FILE` and trimmed. The API **fails closed**: if the variable is unset or the file is missing, unreadable or empty, every request gets `401`. The path is never used as the token.
- Tokens are compared in constant time.
- Service-to-service traffic (agents, MuRegist, MuObserve) keeps using mTLS and is unaffected.

### State model

State is held as an immutable `Arc` snapshot. The snapshot is replaced by the orchestrator (deployment start, IT report, promotion, rollback, taint), by the lease coordinator (lease mirror every 1 s, plus expiry sweeps) and by agent IPC (`IntegrationTestProgress`, `MSG_TYPE_IT_PROGRESS = 0x0C`, forwarded by `IpcAgentClient::with_progress_sink`). Handlers only clone the `Arc`. Unknown agent message types are skipped without decoding the payload (`dispatch_agent_frame`).

**Gate state machine** (`verdict`):

- `rollback` when any critical test is `failed` or the lease expired.
- `promote` when every critical test is `passed`; if there are no critical tests, when every test is terminal.
- `pending` otherwise, including an empty test list.

The contract has no per-test criticality yet, so every contract test is critical (`[C]`). The agent announces its own flags.

### `GET /api/cd/deployments?repo={owner}/{repo}&limit=N`

Returns the newest deployments first. This list is the history strip, and each entry's `active_slot` gives the current A/B slot on its target.

- `repo` matches `owner/repo`, the bare repo name, or the service name. Omit it to get every repo.
- `limit` defaults to 20 and is clamped to 1..=256.

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

- `outcome`: `pending` | `promoted` | `rolled_back` | `tainted`.
- `rollback_reason`: `critical_test_failed` | `lease_expired` | `manual` | `null`. Staging, swap, health and SLO verification failures map to `critical_test_failed`; the full text is in the gate's `rollback_detail`.

### `GET /api/cd/deployments/{id}/gate`

Returns a `DeploymentGate`, or `404 {"error":"deployment_not_found"}`.

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

- `tests[]` follows contract order. With `integration_tests: "all"`, tests appear in the order the agent announces them in its `Pending` frames.
- `state`: `pending` | `running` | `passed` | `failed`.
- `log_excerpt` is filled for failed tests from the final `IntegrationTestReport`.
- `lease_ttl_remaining_ms` is computed per request and is `0` once the gate is final.

### `GET /api/cd/leases`

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

### `GET /api/cd/events` (SSE)

The stream is `text/event-stream`. It sends a `: heartbeat` comment every 15 s while idle. A consumer that falls more than 1024 events behind is disconnected so it reconnects and re-fetches the snapshot.

| `event:` | `data:` |
|---|---|
| `it_progress` | `{"deployment_id","test_name","critical","state","duration_ms","timestamp_epoch_ms"}` |
| `promoted` | `{"deployment_id","slot"}` (the slot now serving traffic) |
| `rolled_back` | `{"deployment_id","restore_slot","reason","detail"}` |
| `tainted` | `{"deployment_id","artifact_digest","reason"}` |
| `lease_expired` | `{"deployment_id","lease_id"}` |

```text
event: it_progress
data: {"deployment_id":"dep-7f3c","test_name":"health_endpoint_ready","critical":true,"state":"failed","duration_ms":740,"timestamp_epoch_ms":1793563004321}

event: rolled_back
data: {"deployment_id":"dep-7f3c","restore_slot":"a","reason":"critical_test_failed","detail":"Integration tests failed: [\"health_endpoint_ready\"]"}

event: tainted
data: {"deployment_id":"dep-7f3c","artifact_digest":"sha256:4be1…","reason":"Integration tests failed: [\"health_endpoint_ready\"]"}
```

---

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See [LICENSE](LICENSE) for details.
