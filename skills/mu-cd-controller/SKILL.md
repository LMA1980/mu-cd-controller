---
name: mu-cd-controller
description: "Orchestrate zero-downtime A/B continuous delivery, deployment leases, canary bake-window SLO gates, and automatic digest tainting in mu-cd-controller."
---

# `mu-cd-controller` Continuous Delivery Control Plane

## 1. Canary Bake-Window SLO & Automatic Tainting

- Every production deployment specification (`.mucd/` or legacy `.muconde/`) undergoes canary verification and SLO evaluation (`max_error_logs`, `max_p99_latency_ms`).
- When an SLO breach or health-probe failure occurs during the bake window, `mu-cd-controller` triggers an immediate atomic rollback and marks the artifact digest as tainted (`should_rollback_and_taint`).
