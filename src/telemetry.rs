//! OpenTelemetry W3C trace span and audit log telemetry sink for `mu-cd-controller`.
//!
//! Emits `MUOB`-framed `OtelSpanEntry` and `OtelLogEntry` Arrow batches to `muObserve` / `mu-observable-collector`
//! for deployment lifecycle events:
//! - `cd.deployment.start`: Root or multi-hop span representing an entire continuous delivery rollout.
//! - `cd.slot.stage_a` / `cd.slot.stage_b`: Child span recording candidate artifact staging into `@a` or `@b`.
//! - `cd.gate.evaluate`: Child span recording canary SLO and integration test evaluation.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use mu_observable_ipc::{
    encode_hex, encode_log_batch, encode_metric_batch, encode_span_batch, write_frame,
    DeterministicSecretRedactor, IpcHeader, OtelLogEntry, OtelMetricEntry, OtelSpanEntry,
    SecretRedactor, MSG_TYPE_ARROW_OTEL_LOGS, MSG_TYPE_ARROW_OTEL_METRICS,
    MSG_TYPE_ARROW_OTEL_SPANS,
};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Canonical service name emitted on `mu-cd-controller` spans.
pub const CD_SERVICE_NAME: &str = "mu-cd-controller";

/// Current timestamp in nanoseconds since Unix epoch.
#[must_use]
pub fn now_unix_nano() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Abstract sink receiving OpenTelemetry spans, audit logs, and metrics from `mu-cd-controller`.
#[async_trait]
pub trait CdTelemetrySink: Send + Sync + fmt::Debug {
    /// Emits a batch of [`OtelSpanEntry`] records.
    async fn emit_spans(&self, spans: Vec<OtelSpanEntry>);

    /// Emits a batch of [`OtelLogEntry`] audit records.
    async fn emit_logs(&self, logs: Vec<OtelLogEntry>);

    /// Emits a batch of [`OtelMetricEntry`] metric records.
    async fn emit_metrics(&self, _metrics: Vec<OtelMetricEntry>) {}
}

/// Network sink streaming `MUOB`-framed Arrow batches (`MSG_TYPE_ARROW_OTEL_SPANS` and
/// `MSG_TYPE_ARROW_OTEL_LOGS`) to `muObserve` / `mu-observable-collector` with non-blocking
/// graceful fallback.
#[derive(Debug)]
pub struct MuObserveCdSink {
    collector_addr: Option<String>,
    node_id: String,
    sequence: AtomicU64,
    connect_timeout: Duration,
}

impl MuObserveCdSink {
    #[must_use]
    pub fn new(collector_addr: Option<String>, node_id: impl Into<String>) -> Self {
        Self {
            collector_addr,
            node_id: node_id.into(),
            sequence: AtomicU64::new(1),
            connect_timeout: Duration::from_millis(500),
        }
    }

    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_lookup(&|key| std::env::var(key).ok())
    }

    /// Pure parser constructing [`MuObserveCdSink`] via a caller-supplied environment lookup.
    #[must_use]
    pub fn from_env_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Self {
        let addr = crate::first_non_empty_var(
            lookup,
            &[
                "MU_OBSERVABLE_COLLECTOR_ADDR",
                "MU_CD_CONTROLLER_COLLECTOR_ADDR",
                "MU_CD_COLLECTOR_ADDR",
                "MUOBSERVE_COLLECTOR_ADDR",
                "MU_OBSERVABLE_ADDR",
                "MUOBSERVE_ADDR",
            ],
        );
        let node_id = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_NODE_ID",
                "MU_CD_NODE_ID",
                "MUCONDE_NODE_ID",
            ],
        )
        .unwrap_or_else(|| "node-a".to_string());
        Self::new(addr, node_id)
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    async fn send_frame(&self, msg_type: u16, payload: Vec<u8>) {
        let Some(ref addr) = self.collector_addr else {
            return;
        };
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let header = IpcHeader::new(msg_type, payload.len() as u32, 0, seq);

        let connect_fut = TcpStream::connect(addr);
        if let Ok(Ok(mut stream)) = tokio::time::timeout(self.connect_timeout, connect_fut).await {
            let _ = write_frame(&mut stream, &header, &payload).await;
        }
    }
}

#[async_trait]
impl CdTelemetrySink for MuObserveCdSink {
    async fn emit_spans(&self, mut spans: Vec<OtelSpanEntry>) {
        if spans.is_empty() || self.collector_addr.is_none() {
            return;
        }
        let redactor = DeterministicSecretRedactor::new();
        for span in &mut spans {
            span.redact_in_place(&redactor);
        }
        if let Ok(bytes) = encode_span_batch(&spans) {
            self.send_frame(MSG_TYPE_ARROW_OTEL_SPANS, bytes).await;
        }
    }

    async fn emit_logs(&self, mut logs: Vec<OtelLogEntry>) {
        if logs.is_empty() || self.collector_addr.is_none() {
            return;
        }
        let redactor = DeterministicSecretRedactor::new();
        for log in &mut logs {
            log.redact_in_place(&redactor);
        }
        if let Ok(bytes) = encode_log_batch(&logs) {
            self.send_frame(MSG_TYPE_ARROW_OTEL_LOGS, bytes).await;
        }
    }

    async fn emit_metrics(&self, mut metrics: Vec<OtelMetricEntry>) {
        if metrics.is_empty() || self.collector_addr.is_none() {
            return;
        }
        let redactor = DeterministicSecretRedactor::new();
        for metric in &mut metrics {
            metric.attributes_json = redactor.redact(&metric.attributes_json);
        }
        if let Ok(bytes) = encode_metric_batch(&metrics) {
            self.send_frame(MSG_TYPE_ARROW_OTEL_METRICS, bytes).await;
        }
    }
}

/// In-memory recording sink for deterministic unit and integration testing.
#[derive(Default)]
pub struct RecordingCdTelemetrySink {
    spans: Mutex<Vec<OtelSpanEntry>>,
    logs: Mutex<Vec<OtelLogEntry>>,
    metrics: Mutex<Vec<OtelMetricEntry>>,
    forward_to: Option<Arc<dyn CdTelemetrySink>>,
}

impl fmt::Debug for RecordingCdTelemetrySink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingCdTelemetrySink").finish()
    }
}

impl RecordingCdTelemetrySink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_forwarder(mut self, sink: Arc<dyn CdTelemetrySink>) -> Self {
        self.forward_to = Some(sink);
        self
    }

    pub async fn recorded_spans(&self) -> Vec<OtelSpanEntry> {
        self.spans.lock().await.clone()
    }

    pub async fn recorded_logs(&self) -> Vec<OtelLogEntry> {
        self.logs.lock().await.clone()
    }

    pub async fn recorded_metrics(&self) -> Vec<OtelMetricEntry> {
        self.metrics.lock().await.clone()
    }
}

#[async_trait]
impl CdTelemetrySink for RecordingCdTelemetrySink {
    async fn emit_spans(&self, mut spans: Vec<OtelSpanEntry>) {
        let redactor = DeterministicSecretRedactor::new();
        for span in &mut spans {
            span.redact_in_place(&redactor);
        }
        self.spans.lock().await.extend(spans.clone());
        if let Some(ref fwd) = self.forward_to {
            fwd.emit_spans(spans).await;
        }
    }

    async fn emit_logs(&self, mut logs: Vec<OtelLogEntry>) {
        let redactor = DeterministicSecretRedactor::new();
        for log in &mut logs {
            log.redact_in_place(&redactor);
        }
        self.logs.lock().await.extend(logs.clone());
        if let Some(ref fwd) = self.forward_to {
            fwd.emit_logs(logs).await;
        }
    }

    async fn emit_metrics(&self, mut metrics: Vec<OtelMetricEntry>) {
        let redactor = DeterministicSecretRedactor::new();
        for metric in &mut metrics {
            metric.attributes_json = redactor.redact(&metric.attributes_json);
        }
        self.metrics.lock().await.extend(metrics.clone());
        if let Some(ref fwd) = self.forward_to {
            fwd.emit_metrics(metrics).await;
        }
    }
}

/// Builds an [`OtelSpanEntry`] for continuous delivery operations.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_cd_span(
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    node_id: &str,
    span_name: &str,
    span_kind: &str,
    start_ns: i64,
    end_ns: i64,
    status_code: &str,
    status_msg: Option<String>,
    attributes: serde_json::Value,
) -> OtelSpanEntry {
    let duration_ns = (end_ns.saturating_sub(start_ns).max(0)) as u64;
    OtelSpanEntry {
        trace_id: encode_hex(&trace_id),
        span_id: encode_hex(&span_id),
        parent_span_id: parent_span_id.map(|p| encode_hex(&p)),
        service_name: CD_SERVICE_NAME.to_string(),
        node_id: node_id.to_string(),
        span_name: span_name.to_string(),
        span_kind: span_kind.to_string(),
        start_time_unix_nano: start_ns,
        end_time_unix_nano: end_ns,
        duration_ns,
        status_code: status_code.to_string(),
        status_message: status_msg,
        attributes_json: attributes.to_string(),
    }
}

/// Builds an [`OtelLogEntry`] audit record for continuous delivery lifecycle events
/// (single-node rollbacks, emergency operator rollbacks, and multi-node partial rollbacks).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_cd_log(
    trace_id: [u8; 16],
    span_id: [u8; 8],
    timestamp_ns: i64,
    severity_number: i32,
    severity_text: &str,
    node_id: &str,
    body: impl Into<String>,
    attributes: serde_json::Value,
) -> OtelLogEntry {
    OtelLogEntry {
        timestamp_unix_nano: timestamp_ns,
        trace_id: encode_hex(&trace_id),
        span_id: encode_hex(&span_id),
        severity_number,
        severity_text: severity_text.to_string(),
        service_name: CD_SERVICE_NAME.to_string(),
        node_id: node_id.to_string(),
        body: body.into(),
        attributes_json: attributes.to_string(),
        job_id: None,
        stage_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_muobserve_cd_sink_env_precedence_and_legacy_fallback() {
        let canonical = HashMap::from([
            ("MU_OBSERVABLE_COLLECTOR_ADDR", "127.0.0.1:4319"),
            ("MUOBSERVE_COLLECTOR_ADDR", "127.0.0.1:9999"),
            ("MU_CD_CONTROLLER_NODE_ID", "node-b"),
            ("MUCONDE_NODE_ID", "node-legacy"),
        ]);
        let sink = MuObserveCdSink::from_env_lookup(&|k| canonical.get(k).map(|v| (*v).into()));
        assert_eq!(sink.collector_addr.as_deref(), Some("127.0.0.1:4319"));
        assert_eq!(sink.node_id(), "node-b");

        // Legacy collector addr beats generic MU_OBSERVABLE_ADDR
        let mixed = HashMap::from([
            ("MUOBSERVE_COLLECTOR_ADDR", "127.0.0.1:4320"),
            ("MU_OBSERVABLE_ADDR", "observe.ci.internal:9445"),
            ("MUCONDE_NODE_ID", "node-legacy"),
        ]);
        let sink_mixed = MuObserveCdSink::from_env_lookup(&|k| mixed.get(k).map(|v| (*v).into()));
        assert_eq!(sink_mixed.collector_addr.as_deref(), Some("127.0.0.1:4320"));
        assert_eq!(sink_mixed.node_id(), "node-legacy");

        let default_sink = MuObserveCdSink::from_env_lookup(&|_| None);
        assert!(default_sink.collector_addr.is_none());
        assert_eq!(default_sink.node_id(), "node-a");
    }
}
