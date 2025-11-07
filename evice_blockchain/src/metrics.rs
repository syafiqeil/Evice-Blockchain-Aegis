// evice_blockchain/src/metrics.rs

use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge, Encoder, HistogramVec,
    IntCounterVec, IntGauge, Opts, TextEncoder,
};
use tiny_http::{Response, Server};

lazy_static! {
    // === MEMPOOL METRICS ===
    pub static ref MEMPOOL_TRANSACTIONS: IntGauge =
        register_int_gauge!(Opts::new("mempool_transactions_total", "Current number of transactions in the mempool")).unwrap();
    pub static ref MEMPOOL_ADD_RESULT: IntCounterVec =
        register_int_counter_vec!("mempool_add_transaction_results_total", "Results of adding transactions to the mempool", &["result"]).unwrap();

    // === P2P METRICS ===
    pub static ref P2P_RECEIVED_MESSAGES: IntCounterVec =
        register_int_counter_vec!("p2p_received_messages_total", "Number of received p2p messages by type", &["type"]).unwrap();
    pub static ref P2P_CONNECTED_PEERS: IntGauge =
        register_int_gauge!(Opts::new("p2p_connected_peers", "Number of currently connected peers")).unwrap();

    // === CONSENSUS METRICS ===
    pub static ref CONSENSUS_CURRENT_VIEW: IntGauge =
        register_int_gauge!(Opts::new("consensus_current_view", "The current view number of the consensus engine")).unwrap();
    pub static ref CONSENSUS_BLOCKS_PRODUCED: IntCounterVec =
        register_int_counter_vec!("consensus_blocks_produced_total", "Number of blocks produced by this node", &["status"]).unwrap();
    pub static ref CONSENSUS_VOTES_RECEIVED: IntCounterVec =
        register_int_counter_vec!("consensus_votes_received_total", "Number of votes received by this node as a leader", &["is_valid"]).unwrap();
    pub static ref CONSENSUS_VIEW_TIMEOUTS: IntCounterVec =
        register_int_counter_vec!("consensus_view_timeouts_total", "Number of view timeouts", &["role"]).unwrap();

    // === BLOCKCHAIN METRICS ===
    pub static ref BLOCKCHAIN_COMMITTED_BLOCK_HEIGHT: IntGauge =
        register_int_gauge!(Opts::new("blockchain_committed_block_height", "The height of the latest committed block")).unwrap();
    pub static ref BLOCKCHAIN_TX_EXECUTION_TIME: HistogramVec =
        register_histogram_vec!("blockchain_transaction_execution_duration_seconds", "Histogram of transaction execution times", &["tx_type"]).unwrap();
}

pub fn run_metrics_server(port: u16) {
    let server_addr = format!("0.0.0.0:{}", port);
    let server = Server::http(&server_addr).expect("Gagal memulai server metrik tiny_http.");

    for request in server.incoming_requests() {
        if request.url() == "/metrics" {
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = vec![];
            encoder.encode(&metric_families, &mut buffer).unwrap();

            let response = Response::from_data(buffer).with_header(
                "Content-Type: text/plain; version=0.0.4"
                    .parse::<tiny_http::Header>()
                    .unwrap(),
            );
            request.respond(response).unwrap_or_default();
        } else {
            let response = Response::empty(404);
            request.respond(response).unwrap_or_default();
        }
    }
}
