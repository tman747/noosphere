//! Node metrics registry (`noos_*` Prometheus text surface; plan §13.4
//! naming law applied to the operator RPC).

use std::sync::atomic::{AtomicU64, Ordering};

/// Shared atomic counters/gauges. All relaxed: metrics never gate logic.
#[derive(Debug, Default)]
pub struct Metrics {
    pub height: AtomicU64,
    pub justified_epoch: AtomicU64,
    pub finalized_epoch: AtomicU64,
    pub blocks_imported_total: AtomicU64,
    pub blocks_rejected_total: AtomicU64,
    pub blocks_produced_total: AtomicU64,
    pub blocks_parked: AtomicU64,
    pub reorgs_total: AtomicU64,
    pub mempool_txs: AtomicU64,
    pub mempool_bytes: AtomicU64,
    pub txs_settled_total: AtomicU64,
    pub store_seq: AtomicU64,
    pub rpc_requests_total: AtomicU64,
    pub rpc_unauthorized_total: AtomicU64,
    pub task_restarts_total: AtomicU64,
}

impl Metrics {
    pub fn set(&self, gauge: &AtomicU64, v: u64) {
        gauge.store(v, Ordering::Relaxed);
    }

    pub fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Renders the Prometheus text exposition (every series `noos_*`).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(1024);
        let mut put = |name: &str, kind: &str, help: &str, v: u64| {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push_str("\n# TYPE ");
            out.push_str(name);
            out.push(' ');
            out.push_str(kind);
            out.push('\n');
            out.push_str(name);
            out.push(' ');
            out.push_str(&v.to_string());
            out.push('\n');
        };
        let g = Ordering::Relaxed;
        put(
            "noos_head_height",
            "gauge",
            "unsafe head height",
            self.height.load(g),
        );
        put(
            "noos_justified_epoch",
            "gauge",
            "justified checkpoint epoch",
            self.justified_epoch.load(g),
        );
        put(
            "noos_finalized_epoch",
            "gauge",
            "finalized checkpoint epoch",
            self.finalized_epoch.load(g),
        );
        put(
            "noos_blocks_imported_total",
            "counter",
            "blocks imported and executed",
            self.blocks_imported_total.load(g),
        );
        put(
            "noos_blocks_rejected_total",
            "counter",
            "blocks rejected as invalid",
            self.blocks_rejected_total.load(g),
        );
        put(
            "noos_blocks_produced_total",
            "counter",
            "blocks produced locally",
            self.blocks_produced_total.load(g),
        );
        put(
            "noos_blocks_parked",
            "gauge",
            "blocks parked awaiting DA shards",
            self.blocks_parked.load(g),
        );
        put(
            "noos_reorgs_total",
            "counter",
            "reorg rollback/replay operations",
            self.reorgs_total.load(g),
        );
        put(
            "noos_mempool_txs",
            "gauge",
            "mempool transaction count",
            self.mempool_txs.load(g),
        );
        put(
            "noos_mempool_bytes",
            "gauge",
            "mempool byte total",
            self.mempool_bytes.load(g),
        );
        put(
            "noos_txs_settled_total",
            "counter",
            "transactions settled in blocks",
            self.txs_settled_total.load(g),
        );
        put(
            "noos_store_seq",
            "gauge",
            "durable store applied sequence",
            self.store_seq.load(g),
        );
        put(
            "noos_rpc_requests_total",
            "counter",
            "RPC requests served",
            self.rpc_requests_total.load(g),
        );
        put(
            "noos_rpc_unauthorized_total",
            "counter",
            "RPC requests refused by bearer auth",
            self.rpc_unauthorized_total.load(g),
        );
        put(
            "noos_task_restarts_total",
            "counter",
            "supervised task restarts",
            self.task_restarts_total.load(g),
        );
        out
    }
}
