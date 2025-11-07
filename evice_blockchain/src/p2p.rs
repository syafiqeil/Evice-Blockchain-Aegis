// evice_blockchain/src/p2p.rs

use libp2p::{
    futures::StreamExt,
    gossipsub::{self, MessageAcceptance},
    identity::{Keypair as P2pKeypair},
    kad::self,
    request_response::{self, ProtocolSupport, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    identify, Multiaddr, PeerId, StreamProtocol,
};

use log::{error, info, warn, debug};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, Duration};
use tokio::sync::{RwLock, Mutex, mpsc, broadcast, oneshot};
use tokio::time::interval;
use tokio::select;
use rand::prelude::*;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::crypto;
use crate::snapshot;
use crate::mempool::Mempool;
use crate::{Address, Transaction};
use crate::snapshot::SnapshotMetadata;
use crate::blockchain::{
    Block, Blockchain, 
    BlockHeader, ChainMessage,
};
use crate::consensus::{
    ConsensusMessage, OptimisticConfirmation, QuorumCertificate,
    PendingBlock, ConsensusState, VelocityVote
};

const INITIAL_PEER_SCORE: i32 = 0;
const MAX_PEER_SCORE: i32 = 100;
const BAN_THRESHOLD: i32 = -50;
const PENALTY_INVALID_SIGNATURE: i32 = -50;
const PENALTY_BAD_TRANSACTION: i32 = -10;
const PENALTY_DESERIALIZATION_ERROR: i32 = -5;
const REWARD_VALID_MESSAGE: i32 = 2;
const BAN_DURATION: Duration = Duration::from_secs(1800); 
const NETWORK_STABILITY_WINDOW: Duration = Duration::from_secs(3);

pub static DEV_MODE: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
struct PeerInfo {
    score: i32,
    is_banned: bool,
    ban_until: Option<Instant>,
}

impl PeerInfo {
    fn new() -> Self {
        Self {
            score: INITIAL_PEER_SCORE,
            is_banned: false,
            ban_until: None,
        }
    }

    fn apply_penalty(&mut self, penalty: i32) {
        self.score = (self.score + penalty).max(BAN_THRESHOLD - 1);
        if self.score <= BAN_THRESHOLD {
            self.is_banned = true;
            self.ban_until = Some(Instant::now() + BAN_DURATION);
            warn!("Peer di-ban karena skor mencapai {}. Diblokir hingga {:?}.", self.score, self.ban_until);
        }
    }

    fn apply_reward(&mut self, reward: i32) {
        self.score = (self.score + reward).min(MAX_PEER_SCORE);
    }

    fn is_currently_banned(&mut self) -> bool {
        if self.is_banned {
            if let Some(ban_until) = self.ban_until {
                if Instant::now() < ban_until {
                    return true;
                } else {
                    info!("Masa ban untuk peer telah berakhir. Mereset skor.");
                    self.is_banned = false;
                    self.ban_until = None;
                    self.score = INITIAL_PEER_SCORE;
                    return false;
                }
            }
        }
        false
    }
}

#[derive(Debug)]
struct PendingResponse {
    channel: ResponseChannel<SyncResponse>,
    response: SyncResponse,
}

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub sync: request_response::Behaviour<request_response::cbor::codec::Codec<SyncRequest, SyncResponse>>,
}

#[derive(Debug)]
pub enum P2pCommand {
    BroadcastConsensusMessage(ConsensusMessage),
    BroadcastMissingBlockRequest(Vec<u8>),
    SendDirectRequest {
        destination: PeerId,
        request: SyncRequest, 
    },
    ApplyPenalty {
        peer_id: PeerId,
        penalty: i32,
    },
    DialAddress(Multiaddr),
    GetConnectedPeers(oneshot::Sender<Vec<PeerId>>),
    TriggerReassessment,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    GetBlocks { 
        since_index: u64 
    },
    GetBlockHeaders { 
        since_index: u64, 
        count: u32 
    },
    GetChainInfo,
    GetSnapshotMetadata,
    GetSnapshotChunk { 
        file_name: String, 
        chunk_index: u32 },
    InformAboutPeers(Vec<String>),
    GetTxsByHash { 
        request_id: u64, 
        hashes: Vec<Vec<u8>> }, 
    ConsensusRequest(Box<ConsensusMessage>),
    GetFullProposal(Vec<u8>),
    FullProposalForCommittee {
        confirmation: Box<OptimisticConfirmation>,
        transactions: Vec<Transaction>,
    },
    SubmitVote(Box<VelocityVote>),
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Blocks { 
        blocks: Vec<crate::blockchain::Block> 
    },
    BlockHeaders { 
        headers: Vec<BlockHeader>, 
        final_qc: Option<QuorumCertificate>
    },
    ChainInfo {
        height: u64,
        best_block_hash: Vec<u8>,
    },
    SnapshotMetadata(Option<SnapshotMetadata>),
    SnapshotChunk { 
        data: Vec<u8> 
    },
    TxsByHash { 
        request_id: u64, txs: Vec<Transaction> 
    },
    MempoolTxHashes(Vec<Vec<u8>>),
    PeersReceivedAck,
    ConsensusResponse(Option<Box<ConsensusMessage>>), 
    FullProposal(Option<Box<PendingBlock>>),
    FullProposalReceivedAck,
    VoteAck,
}

#[derive(Clone, Debug)]
pub struct PeerIdentityInfo {
    pub peer_id: PeerId,
    pub multiaddr: Multiaddr,
    pub version: u64, 
}

#[derive(Default, Clone)]
pub struct AddressBook {
    address_to_identity: HashMap<Address, PeerIdentityInfo>,
}

impl AddressBook {
    pub fn update_from_chain_state(&mut self, chain: &Blockchain) {
        let previous_size = self.address_to_identity.len();

        for validator_addr in &chain.state.validators {
            if let Ok(Some(account)) = chain.state.get_account(validator_addr) {
                if let Some(multiaddr_bytes) = account.network_identity {
                    if let Ok(multiaddr) = Multiaddr::try_from(multiaddr_bytes) {
                        if let Some(peer_id) = multiaddr.iter().find_map(|p| {
                            if let libp2p::multiaddr::Protocol::P2p(peer_id) = p { Some(peer_id) } else { None }
                        }) {
                            let current_info = self.address_to_identity.entry(*validator_addr).or_insert_with(|| PeerIdentityInfo {
                                peer_id,
                                multiaddr: multiaddr.clone(),
                                version: 0, 
                            });

                            if account.network_identity_version > current_info.version {
                                current_info.peer_id = peer_id;
                                current_info.multiaddr = multiaddr;
                                current_info.version = account.network_identity_version;
                            }
                        }
                    }
                }
            }
        }
        
        let new_size = self.address_to_identity.len();
        if new_size != previous_size {
            info!("[AddressBook] Diperbarui, sekarang melacak {} validator (sebelumnya {}).", new_size, previous_size);
        }
    }

    pub fn get_peer_id(&self, address: &Address) -> Option<PeerId> {
        self.address_to_identity.get(address).map(|info| info.peer_id)
    }

    pub fn get_address(&self, peer_id_to_find: &PeerId) -> Option<Address> {
        for (addr, info) in &self.address_to_identity {
            if &info.peer_id == peer_id_to_find {
                return Some(*addr);
            }
        }
        None
    }

    pub fn get_all_peer_ids(&self) -> Vec<PeerId> {
        self.address_to_identity.values().map(|info| info.peer_id).collect()
    }
}

fn is_loopback(addr: &Multiaddr) -> bool {
    if DEV_MODE.load(Ordering::SeqCst) {
        return false;
    }
    addr.iter().any(|protocol| match protocol {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

pub async fn run(
    p2p_keypair: P2pKeypair,
    blockchain: Arc<tokio::sync::RwLock<Blockchain>>,
    mempool: Arc<Mempool>,
    mut _rx_gossip: mpsc::Receiver<ChainMessage>, 
    mut rx_sync_cmd: mpsc::Receiver<SyncRequest>,
    tx_sync_resp: broadcast::Sender<(SyncResponse, PeerId)>,
    _tx_sync_cmd: mpsc::Sender<SyncRequest>, 
    bootstrap_nodes: Vec<String>,
    p2p_port: u16,
    p2p_to_consensus_tx: mpsc::Sender<(ConsensusMessage, PeerId, Option<Vec<Transaction>>)>,
    txs_response_to_consensus_tx: mpsc::Sender<SyncResponse>,
    snapshot_dir: String,
    is_bootstrap_node: bool,
    consensus_state: Option<Arc<RwLock<ConsensusState>>>,
    mut p2p_cmd_rx: mpsc::Receiver<P2pCommand>,
    p2p_cmd_tx: mpsc::Sender<P2pCommand>,
    network_ready_flag: Arc<AtomicBool>,
    mut new_block_rx: broadcast::Receiver<()>,
    address_book: Arc<Mutex<AddressBook>>,
    sync_trigger_tx: mpsc::Sender<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let local_key = p2p_keypair;
    let local_peer_id = PeerId::from(local_key.public());
    info!("Peer ID lokal: {}", local_peer_id);

    let peer_scores = Arc::new(Mutex::new(HashMap::<PeerId, PeerInfo>::new()));
    let known_peers = Arc::new(Mutex::new(HashMap::<PeerId, Multiaddr>::new()));
    let gossip_topic = gossipsub::IdentTopic::new("evice-blockchain-topic");
    let fallback_sync_topic = gossipsub::IdentTopic::new("evice-fallback-sync-topic");
    let mut pending_dials = HashSet::<PeerId>::new();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .mesh_n_low(4)
                .history_gossip(3)
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .expect("Valid gossipsub config");

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            ).unwrap();
            
            let kademlia = kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));
            let identify = identify::Behaviour::new(identify::Config::new("/evice-blockchain/1.0.0".to_string(), key.public()));
            let sync = request_response::Behaviour::new([(StreamProtocol::new("/evice-blockchain/sync/1.0"), ProtocolSupport::Full)], request_response::Config::default());
           
            Ok(AppBehaviour { gossipsub, kademlia, identify, sync})
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    swarm.behaviour_mut().gossipsub.subscribe(&gossip_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&fallback_sync_topic)?;

    for remote_addr_str in &bootstrap_nodes {
        if let Ok(remote_addr) = Multiaddr::from_str(remote_addr_str) {
            info!("Mencoba terhubung ke bootstrap node: {}", remote_addr);
            if let Err(e) = swarm.dial(remote_addr.clone()) {
                 error!("Gagal melakukan dial ke bootstrap node {}: {:?}", remote_addr, e);
            }
        }
    }

    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
        warn!("P2P: Gagal memulai Kademlia bootstrap awal: {:?}", e);
    }
    
    let required_peer_threshold = {
        let chain = blockchain.read().await;
        let num_validators = chain.state.validators.len();
        if num_validators > 0 {
            (num_validators * 2 / 3).max(1)
        } else {
            1 
        }
    };
    info!("[P2P] Ambang batas koneksi peer untuk memulai konsensus diatur ke: {} peers", required_peer_threshold);

    let listen_addr_tcp = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse()?;
    swarm.listen_on(listen_addr_tcp)?;
    let listen_addr_quic = format!("/ip4/0.0.0.0/udp/{}/quic-v1", p2p_port).parse()?;
    swarm.listen_on(listen_addr_quic)?;
    
    let mut network_stability_check = interval(Duration::from_secs(1));
    let mut stable_since: Option<Instant> = None;
    let mut initial_discovery_triggered = false;
    let (response_tx, mut response_rx) = mpsc::channel::<PendingResponse>(32);

    loop {
        select! {
            Ok(_) = new_block_rx.recv() => {
                info!("[P2P] Menerima notifikasi blok baru. Memperbarui AddressBook...");
                let mut ab = address_book.lock().await;
                let chain = blockchain.read().await;
                ab.update_from_chain_state(&*chain);
            },
            _ = network_stability_check.tick() => {
                let current_peers = swarm.connected_peers().count();
                
                if current_peers >= required_peer_threshold {
                    let now = Instant::now();
                    let stable_instant = stable_since.get_or_insert(now);
            
                    if now.duration_since(*stable_instant) >= NETWORK_STABILITY_WINDOW {
                        if !network_ready_flag.load(Ordering::SeqCst) {
                            info!("[P2P] Jaringan stabil (terhubung ke {}/{} peers selama >{} detik). Mengirim sinyal NetworkReady.", current_peers, required_peer_threshold, NETWORK_STABILITY_WINDOW.as_secs());
                            network_ready_flag.store(true, Ordering::SeqCst);
                        }
                    }
                } else {
                    if stable_since.is_some() {
                        stable_since = None;
                    }
                    if network_ready_flag.load(Ordering::SeqCst) {
                        warn!("[P2P] Jaringan menjadi tidak stabil (koneksi turun ke {}/{} peers). Menjeda konsensus.", current_peers, required_peer_threshold);
                        network_ready_flag.store(false, Ordering::SeqCst);
                    }
                }
            },

            Some(cmd) = p2p_cmd_rx.recv() => {
                match cmd {
                    P2pCommand::BroadcastConsensusMessage(msg) => {
                        let chain_msg = ChainMessage::NewConsensusMessage(msg);
                        if let Ok(encoded) = borsh::to_vec(&chain_msg) {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(gossip_topic.clone(), encoded) {
                                error!("[P2P GOSSIP] Gagal menyiarkan pesan konsensus: {:?}", e);
                            }
                        }
                    }
                    P2pCommand::BroadcastMissingBlockRequest(block_hash) => {
                        let request = SyncRequest::GetFullProposal(block_hash.clone());
                        if let Ok(encoded) = borsh::to_vec(&request) {
                            info!("[P2P FALLBACK] Menyiarkan permintaan untuk blok yang hilang 0x{} ke jaringan.", hex::encode(&block_hash[..4]));
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(fallback_sync_topic.clone(), encoded) {
                                error!("[P2P FALLBACK] Gagal menyiarkan permintaan blok: {:?}", e);
                            }
                        }
                    }
                    P2pCommand::SendDirectRequest { destination, request } => {
                        match &request {
                            SyncRequest::SubmitVote(vote) => {
                                debug!("[P2P DIRECT] Mengirim suara untuk blok 0x{} ke peer {}", hex::encode(&vote.block_hash[..4]), destination);
                            }
                            _ => {}
                        }
                        swarm.behaviour_mut().sync.send_request(&destination, request);
                    }
                    P2pCommand::ApplyPenalty { peer_id, penalty } => {
                        info!("[P2P] Menerapkan penalti konsensus sebesar {} ke peer {}", penalty, peer_id);
                        let mut scores = peer_scores.lock().await;
                        if let Some(peer_info) = scores.get_mut(&peer_id) {
                            peer_info.apply_penalty(penalty);
                        }
                    }
                    P2pCommand::DialAddress(addr) => {
                        if let Some(peer_id) = addr.iter().last().and_then(|p| if let libp2p::multiaddr::Protocol::P2p(id) = p { Some(id) } else { None }) {
                            if !swarm.is_connected(&peer_id) && !pending_dials.contains(&peer_id) {
                                info!("PEER EXCHANGE: Mencoba terhubung ke peer baru dari daftar: {}", addr);
                                if let Err(e) = swarm.dial(addr.clone()) {
                                    warn!("PEER EXCHANGE: Gagal melakukan dial ke {}: {:?}", addr, e);
                                } else {
                                    pending_dials.insert(peer_id);
                                }
                            }
                        }
                    }
                    P2pCommand::GetConnectedPeers(sender) => {
                        let peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
                        if sender.send(peers).is_err() {
                            warn!("[P2P] Gagal mengirim daftar peer yang terhubung: receiver dijatuhkan.");
                        }
                    }
                    P2pCommand::TriggerReassessment => {
                        if sync_trigger_tx.send(()).await.is_err() {
                            warn!("[P2P] Gagal mengirim pemicu penilaian ulang ke SyncManager.");
                        }
                    }
                }
            },
            Some(sync_req) = rx_sync_cmd.recv() => {
                let peers: Vec<_> = swarm.connected_peers().cloned().collect();
                if let Some(peer) = peers.choose(&mut rand::rng()) { 
                    info!("[SYNC] Mengirim permintaan sinkronisasi {:?} ke peer {}", sync_req, peer);
                    swarm.behaviour_mut().sync.send_request(peer, sync_req);
                } else {
                    warn!("[SYNC] Ingin memulai sinkronisasi, tetapi tidak terhubung ke peer manapun.");
                }
            },
            Some(pending) = response_rx.recv() => {
                if let Err(e) = swarm.behaviour_mut().sync.send_response(pending.channel, pending.response) {
                    warn!("[P2P] Gagal mengirim respons yang sudah diproses: {:?}", e);
                }
            },

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(AppBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. })) => {
                        if let kad::QueryResult::GetClosestPeers(Ok(ok)) = result {
                            for peer_info in ok.peers {
                                let discovered_peer_id = peer_info.peer_id;
                                if discovered_peer_id != local_peer_id && !swarm.is_connected(&discovered_peer_id) {
                                    info!("KAD: Menemukan peer baru {:?}, mencoba terhubung...", discovered_peer_id);
                                    if let Err(e) = swarm.dial(discovered_peer_id) {
                                        warn!("Gagal melakukan dial ke peer baru yang ditemukan: {:?}", e);
                                    }
                                }
                            }
                        }
                    },
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received {
                        peer_id,
                        info,
                        ..
                    })) => {
                        info!("IDENTIFY: Menerima info alamat dari peer {}: {:?}", peer_id, info.listen_addrs);
                        let mut valid_addrs = Vec::new();
                        for addr in info.listen_addrs {                        
                            if !is_loopback(&addr) {
                                let full_addr = addr.clone().with(libp2p::multiaddr::Protocol::P2p(peer_id));
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                valid_addrs.push(full_addr);
                            } else {
                                debug!("IDENTIFY: Mengabaikan alamat loopback {} dari peer {}.", addr, peer_id);
                            }
                        }

                        if is_bootstrap_node && !valid_addrs.is_empty() {
                            let mut peers_guard = known_peers.lock().await;
                            if !peers_guard.contains_key(&peer_id) {
                                let existing_peers_list: Vec<String> = peers_guard.values().map(|a| a.to_string()).collect();
                                if !existing_peers_list.is_empty() {
                                    info!("BOOTSTRAP: Mengirim {} alamat peer yang ada ke peer baru {}", existing_peers_list.len(), peer_id);
                                    let request = SyncRequest::InformAboutPeers(existing_peers_list);
                                    swarm.behaviour_mut().sync.send_request(&peer_id, request);
                                }
                                
                                let newcomer_addr_list: Vec<String> = valid_addrs.iter().map(|a| a.to_string()).collect();
                                let all_other_peers: Vec<PeerId> = peers_guard.keys().cloned().collect();
                                for other_peer_id in all_other_peers {
                                    info!("BOOTSTRAP: Menginformasikan peer {} tentang kedatangan {}", other_peer_id, peer_id);
                                    let request = SyncRequest::InformAboutPeers(newcomer_addr_list.clone());
                                    swarm.behaviour_mut().sync.send_request(&other_peer_id, request);
                                }

                                peers_guard.insert(peer_id, valid_addrs.first().unwrap().clone());
                            }
                        }
                    },
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        info!("P2P: Koneksi berhasil dibuat dengan peer: {}", peer_id);
                        pending_dials.remove(&peer_id);

                        let addr = endpoint.get_remote_address().clone();
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
            
                        let mut scores = peer_scores.lock().await;
                        scores.entry(peer_id).or_insert_with(PeerInfo::new);

                        if !initial_discovery_triggered && swarm.connected_peers().count() > 0 {
                            info!("[P2P Discovery] Memulai pencarian peer aktif dengan query GetClosestPeers...");
                            swarm.behaviour_mut().kademlia.get_closest_peers(local_peer_id);
                            initial_discovery_triggered = true;
                        }
                    },
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        warn!("P2P: Koneksi dengan peer {} ditutup. Penyebab: {:?}", peer_id, cause);
                        pending_dials.remove(&peer_id);

                        let mut scores = peer_scores.lock().await;
                        scores.remove(&peer_id);
                    },
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("P2P: Node lokal sekarang mendengarkan di: {}/p2p/{}", address, local_peer_id);
                    },
                    SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source: peer_id,
                        message_id,
                        message,
                    })) => {
                        if message.topic == fallback_sync_topic.hash() {
                            if let Ok(SyncRequest::GetFullProposal(hash)) = SyncRequest::try_from_slice(&message.data) {
                                info!("[P2P FALLBACK] Menerima permintaan gossip untuk blok 0x{} dari {}. Memeriksa ketersediaan lokal...", hex::encode(&hash[..4]), peer_id);

                                let blockchain_clone = Arc::clone(&blockchain);
                                let consensus_state_clone = consensus_state.clone();
                                let p2p_cmd_tx_clone = p2p_cmd_tx.clone();

                                tokio::spawn(async move {
                                    let mut found_block: Option<PendingBlock> = None;
                                    let chain = blockchain_clone.read().await;
                                    if let Some(block) = chain.get_block_by_hash(&hash) {
                                        info!("[P2P FALLBACK] Menemukan blok 0x{} di rantai final untuk peer {}.", hex::encode(&hash[..4]), peer_id);
                                        found_block = Some(PendingBlock {
                                            header: block.header.clone(),
                                            transactions: block.transactions.clone(),
                                            parent_qc: block.justify.clone(),
                                            round: block.round,
                                        });
                                    }

                                    if found_block.is_none() {
                                        if let Some(cs) = consensus_state_clone {
                                            if let Some(pending_block) = cs.read().await.pending_proposals.read().await.get(&hash) {
                                                info!("[P2P FALLBACK] Menemukan blok 0x{} di `pending_proposals` untuk peer {}.", hex::encode(&hash[..4]), peer_id);
                                                found_block = Some(pending_block.clone());
                                            } else if let Some(block) = cs.read().await.core_state.read().await.optimistically_confirmed_blocks.iter().find(|b| b.header.calculate_hash() == hash) {
                                                info!("[P2P FALLBACK] Menemukan blok 0x{} di `optimistically_confirmed_blocks` untuk peer {}.", hex::encode(&hash[..4]), peer_id);
                                                found_block = Some(PendingBlock {
                                                    header: block.header.clone(),
                                                    transactions: block.transactions.clone(),
                                                    parent_qc: block.justify.clone(),
                                                    round: block.round,
                                                });
                                            }
                                        }
                                    }

                                    if let Some(block) = found_block {
                                        let confirmation = OptimisticConfirmation {
                                            header: block.header.clone(),
                                            transaction_hashes: block.transactions.iter().map(|tx| tx.message_hash()).collect(),
                                            parent_qc: block.parent_qc.clone(),
                                            round: block.round,
                                        };

                                        let full_proposal_response = SyncRequest::FullProposalForCommittee {
                                            confirmation: Box::new(confirmation),
                                            transactions: block.transactions,
                                        };

                                        let cmd = P2pCommand::SendDirectRequest {
                                            destination: peer_id,
                                            request: full_proposal_response,
                                        };

                                        if p2p_cmd_tx_clone.send(cmd).await.is_err() {
                                            error!("[P2P FALLBACK] Gagal mengirim respons blok penuh ke peer {}.", peer_id);
                                        } else {
                                            info!("[P2P FALLBACK] Berhasil mengirim blok penuh 0x{} langsung ke peer {}.", hex::encode(&hash[..4]), peer_id);
                                        }
                                    } else {
                                        debug!("[P2P FALLBACK] Tidak dapat menemukan blok 0x{} yang diminta oleh {}.", hex::encode(&hash[..4]), peer_id);
                                    }
                                });
                            }
                            continue;
                        }

                        let acceptance = MessageAcceptance::Accept;
                        let report_sent_successfully = swarm.behaviour_mut().gossipsub.report_message_validation_result(&message_id, &peer_id, acceptance);
                        
                        if !report_sent_successfully {
                             warn!("Gagal melaporkan hasil validasi awal untuk message_id: {}", message_id);
                        }

                        let blockchain_clone = Arc::clone(&blockchain);
                        let mempool_clone = Arc::clone(&mempool);
                        let p2p_to_consensus_tx_clone = p2p_to_consensus_tx.clone();
                        let peer_scores_clone = Arc::clone(&peer_scores);
                        let address_book_clone = Arc::clone(&address_book);

                        tokio::spawn(async move {
                            let mut scores = peer_scores_clone.lock().await;
                            let peer_info = scores.entry(peer_id).or_insert_with(PeerInfo::new);
                            if peer_info.is_currently_banned() {
                                warn!("[P2P GOSSIP] Pesan dari peer {} yang diblokir diabaikan.", peer_id);
                                return;
                            }

                            let penalty = match ChainMessage::try_from_slice(&message.data) {
                                Ok(chain_msg) => match chain_msg {
                                    ChainMessage::NewConsensusMessage(ConsensusMessage::AegisBlockProposal(ref block)) => {
                                        let proposer_address = &block.header.authority;
                                        let chain = blockchain_clone.read().await;
                                        let proposer_account = match chain.state.get_account(proposer_address) {
                                            Ok(Some(account)) => account,
                                            _ => {
                                                warn!("[P2P GOSSIP] Proposal blok dari peer {} berasal dari proposer 0x{} yang tidak dikenal. Menolak.", peer_id, hex::encode(proposer_address.as_ref()));
                                                return; 
                                            }
                                        };

                                        if crypto::verify(&proposer_account.signing_public_key, &block.header.canonical_bytes_for_signing(), &block.header.signature) {
                                            if p2p_to_consensus_tx_clone.send((ConsensusMessage::AegisBlockProposal(block.clone()), peer_id, None)).await.is_err() {
                                                error!("P2P (Task): Gagal mengirim proposal valid ke Aegis Engine.");
                                            }
                                            0 
                                        } else {
                                            warn!("[P2P GOSSIP] Proposal blok dari peer {} memiliki TANDA TANGAN TIDAK VALID. Menolak dan memberikan penalti.", peer_id);
                                            PENALTY_INVALID_SIGNATURE
                                        }
                                    }
                                    ChainMessage::NewConsensusMessage(other_consensus_msg) => {
                                        if p2p_to_consensus_tx_clone.send((other_consensus_msg, peer_id, None)).await.is_err() {
                                            error!("P2P (Task): Gagal mengirim pesan konsensus ke Aegis Engine.");
                                        }
                                        0
                                    }
                                    ChainMessage::NewTransaction(tx) => {
                                        if let crate::TransactionData::UpdateNetworkIdentity { ref multiaddr } = &tx.data {
                                            if let Ok(ma) = Multiaddr::try_from(multiaddr.clone()) {
                                                if let Some(peer_id_from_tx) = ma.iter().find_map(|p| {
                                                    if let libp2p::multiaddr::Protocol::P2p(id) = p { Some(id) } else { None }
                                                }) {
                                                    info!("[P2P AddressBook] Memperbarui PeerId untuk alamat {} secara spekulatif dari gossip.", tx.sender());
                                                    let mut ab = address_book_clone.lock().await;
                                                    
                                                    let current_info = ab.address_to_identity.entry(tx.sender()).or_insert_with(|| PeerIdentityInfo {
                                                        peer_id: peer_id_from_tx,
                                                        multiaddr: ma.clone(),
                                                        version: 0, 
                                                    });

                                                    if current_info.version == 0 {
                                                        current_info.peer_id = peer_id_from_tx;
                                                        current_info.multiaddr = ma;
                                                    }
                                                }
                                            }
                                        }
                                        
                                        let state = blockchain_clone.write().await.state.clone();
                                        match mempool_clone.add_from_p2p(tx, &state).await {
                                            Ok(_) => 0, 
                                            Err(e) if e == "Tanda tangan tidak valid" => PENALTY_INVALID_SIGNATURE,
                                            Err(_) => PENALTY_BAD_TRANSACTION,
                                        }
                                    }
                                    _ => 0,
                                },
                                Err(_) => PENALTY_DESERIALIZATION_ERROR,
                            };

                            if penalty < 0 {
                                peer_info.apply_penalty(penalty);
                            } else {
                                peer_info.apply_reward(REWARD_VALID_MESSAGE);
                            }
                        });
                    },

                    SwarmEvent::Behaviour(AppBehaviourEvent::Sync(request_response::Event::Message {
                        peer,
                        message,
                        ..
                    })) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                match &request {
                                    SyncRequest::SubmitVote(vote) => {
                                        debug!("[SYNC] Menerima suara untuk blok 0x{} dari peer {}", hex::encode(&vote.block_hash[..4]), peer);
                                    }
                                    SyncRequest::FullProposalForCommittee { confirmation, transactions } => {
                                        info!(
                                            "[SYNC] Menerima proposal lengkap untuk blok #{} ({} txs) dari peer {}",
                                            confirmation.header.index,
                                            transactions.len(),
                                            peer
                                        );
                                    }
                                    _ => {
                                        info!("[SYNC] Menerima permintaan {:?} dari peer {}", request, peer);
                                    }
                                }
                                
                                let blockchain_clone = Arc::clone(&blockchain);
                                let snapshot_dir_clone = snapshot_dir.clone(); 
                                let response_tx_clone = response_tx.clone();
                                let mempool_clone = Arc::clone(&mempool);
                                let p2p_to_consensus_tx_clone = p2p_to_consensus_tx.clone();
                                let p2p_cmd_tx_clone = p2p_cmd_tx.clone();
                                let local_peer_id_clone = local_peer_id;
                                let consensus_state_clone = consensus_state.clone();

                                tokio::spawn(async move {
                                    match request {
                                        SyncRequest::SubmitVote(vote) => {
                                            if p2p_to_consensus_tx_clone.send((ConsensusMessage::AegisVelocityVote(*vote), peer, None)).await.is_err() {
                                                error!("[P2P DIRECT] Gagal meneruskan vote ke engine konsensus.");
                                            }
                                            let response = SyncResponse::VoteAck;
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim VoteAck ke channel internal.");
                                            }
                                        }
                                        SyncRequest::GetBlocks { since_index } => {
                                            let chain = blockchain_clone.read().await;
                                            let blocks_to_send: Vec<Block> = chain.chain.iter().filter(|block| block.header.index >= since_index).cloned().take(100).collect();
                                            let response = SyncResponse::Blocks { blocks: blocks_to_send };

                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons GetBlocks ke channel internal.");
                                            }
                                        }
                                        SyncRequest::GetBlockHeaders { since_index, count } => {
                                            let chain = blockchain_clone.read().await;
                                            let headers: Vec<BlockHeader> = chain.chain
                                                .iter()
                                                .filter(|block| block.header.index >= since_index)
                                                .map(|b| b.header.clone())
                                                .take(count as usize)
                                                .collect();
                                            
                                            let final_qc = chain.chain.last().map(|b| b.justify.clone()).unwrap_or_else(QuorumCertificate::genesis_qc);
                                            
                                            let response = SyncResponse::BlockHeaders { headers, final_qc: Some(final_qc) };
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons GetBlockHeaders ke channel internal.");
                                            }
                                        }
                                        SyncRequest::GetTxsByHash { request_id, hashes } => {
                                            let txs = mempool_clone.get_transactions_by_hashes(&hashes);
                                            let response = SyncResponse::TxsByHash { request_id, txs };
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons GetTxsByHash ke channel internal.");
                                            }
                                        }
                                        SyncRequest::ConsensusRequest(consensus_msg) => {
                                            if let Err(e) = p2p_to_consensus_tx_clone.send((*consensus_msg, peer, None)).await {
                                                error!("P2P: Gagal meneruskan pesan konsensus direct ke engine: {}", e);
                                            }

                                            let response = SyncResponse::ConsensusResponse(None);
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons ACK konsensus ke channel internal.");
                                            }
                                        }
                                        SyncRequest::GetFullProposal(block_hash) => {
                                            let mut found_block: Option<PendingBlock> = None;
                                            
                                            // 1. Cek di BlockTree 
                                            let chain_ro = blockchain_clone.read().await;
                                            if let Some(node) = chain_ro.block_tree.read().await.get_node(&block_hash) {
                                                info!("[P2P SYNC] Menemukan blok 0x{} di `BlockTree`.", hex::encode(&block_hash[..4]));
                                                let block = &node.block;
                                                found_block = Some(PendingBlock {
                                                    header: block.header.clone(),
                                                    transactions: block.transactions.clone(),
                                                    parent_qc: block.justify.clone(),
                                                    round: block.round,
                                                });
                                            }

                                            // 2. Cek di cache 
                                            if found_block.is_none() {
                                                if let Some(cs) = consensus_state_clone {
                                                    let consensus_state_guard = cs.read().await;
                                                    let pending_proposals_guard = consensus_state_guard.pending_proposals.read().await;
                                                    if let Some(pending) = pending_proposals_guard.get(&block_hash) {
                                                        info!("[P2P SYNC] Menemukan blok 0x{} di `pending_proposals`.", hex::encode(&block_hash[..4]));
                                                        found_block = Some(pending.clone());
                                                    } else {
                                                        let core_state_guard = consensus_state_guard.core_state.read().await;
                                                        if let Some(optimistic) = core_state_guard.optimistically_confirmed_blocks.iter().find(|b| b.header.calculate_hash() == block_hash) {
                                                            info!("[P2P SYNC] Menemukan blok 0x{} di `optimistically_confirmed_blocks`.", hex::encode(&block_hash[..4]));
                                                            found_block = Some(PendingBlock {
                                                                header: optimistic.header.clone(),
                                                                transactions: optimistic.transactions.clone(),
                                                                parent_qc: optimistic.justify.clone(),
                                                                round: optimistic.round,
                                                            });
                                                        }
                                                    }
                                                }
                                            }

                                            // 3. Cek di rantai yang sudah difinalisasi 
                                            if found_block.is_none() {
                                                if let Some(finalized_block) = chain_ro.get_block_by_hash(&block_hash) {
                                                    info!("[P2P SYNC] Menemukan blok 0x{} di rantai final.", hex::encode(&block_hash[..4]));
                                                    found_block = Some(PendingBlock {
                                                        header: finalized_block.header.clone(),
                                                        transactions: finalized_block.transactions.clone(),
                                                        parent_qc: finalized_block.justify.clone(),
                                                        round: finalized_block.round,
                                                    });
                                                }
                                            }

                                            let response = if let Some(block) = found_block {
                                                SyncResponse::FullProposal(Some(Box::new(block)))
                                            } else {
                                                warn!("[P2P SYNC] Gagal menemukan proposal 0x{} untuk peer {}.", hex::encode(&block_hash[..4]), peer);
                                                SyncResponse::FullProposal(None)
                                            };
                                            
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons FullProposal ke channel internal.");
                                            }
                                        }
                                        SyncRequest::FullProposalForCommittee { confirmation, transactions } => {
                                            let block_proposal = Block {
                                                header: confirmation.header.clone(),
                                                transactions: transactions.clone(),
                                                round: confirmation.round,
                                                view_number: confirmation.round,
                                                justify: confirmation.parent_qc.clone(),
                                                vrf_output: vec![], 
                                                vrf_proof: vec![],  
                                            };

                                            let msg_tuple = (
                                                ConsensusMessage::AegisBlockProposal(Box::new(block_proposal)),
                                                peer,
                                                None 
                                            );
                                            
                                            if p2p_to_consensus_tx_clone.send(msg_tuple).await.is_err() {
                                                error!("[P2P DIRECT] Gagal meneruskan FullProposalForCommittee ke engine konsensus.");
                                            }

                                            let response = SyncResponse::FullProposalReceivedAck;
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons FullProposalReceivedAck ke channel internal.");
                                            }
                                        }
                                        SyncRequest::GetSnapshotMetadata => {
                                            let metadata = snapshot::find_latest_snapshot(&snapshot_dir_clone).unwrap_or(None);
                                            let response = SyncResponse::SnapshotMetadata(metadata);
                                            
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons GetSnapshotMetadata ke channel internal.");
                                            }
                                        }
                                        SyncRequest::GetSnapshotChunk { file_name, chunk_index } => {
                                            let chunk_data = snapshot::read_snapshot_chunk(&snapshot_dir_clone, &file_name, chunk_index).unwrap_or_default().unwrap_or_default();
                                            let response = SyncResponse::SnapshotChunk { data: chunk_data };
                                            
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons GetSnapshotChunk ke channel internal.");
                                            }
                                        }
                                        SyncRequest::GetChainInfo => {
                                            let chain_info = {
                                                let chain = blockchain_clone.read().await;
                                                let x = chain.info_snapshot.read().await.clone();
                                                x 
                                            };
                                            
                                            let response = SyncResponse::ChainInfo {
                                                height: chain_info.height,
                                                best_block_hash: chain_info.best_block_hash,
                                            };

                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons ChainInfo ke channel internal.");
                                            }
                                        }
                                        SyncRequest::InformAboutPeers(peer_addrs) => {
                                            info!("PEER EXCHANGE: Menerima daftar {} peer dari {}", peer_addrs.len(), peer);
                                            for addr_str in peer_addrs {
                                                if let Ok(addr) = Multiaddr::from_str(&addr_str) {
                                                    if let Some(peer_id_from_addr) = addr.iter().last().and_then(|p| if let libp2p::multiaddr::Protocol::P2p(id) = p { Some(id) } else { None }) {
                                                        if peer_id_from_addr != local_peer_id_clone {
                                                            let _ = p2p_cmd_tx_clone.send(P2pCommand::DialAddress(addr)).await;
                                                        }
                                                    }
                                                }
                                            }
                                          
                                            let response = SyncResponse::PeersReceivedAck;
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Gagal mengirim respons PeersReceivedAck ke channel internal.");
                                            }
                                        } 
                                    }
                                });
                            }, 

                            request_response::Message::Response { response, .. } => { 
                                match response { 
                                    SyncResponse::PeersReceivedAck => { 
                                        debug!("PEER EXCHANGE: Peer {} mengonfirmasi penerimaan daftar peer.", peer); 
                                    }, 
                                    SyncResponse::TxsByHash { .. } => {
                                        if txs_response_to_consensus_tx.send(response).await.is_err() {
                                            warn!("[P2P] Gagal meneruskan respons TxsByHash ke ConsensusEngine (channel tertutup).");
                                        }
                                    },
                                    SyncResponse::ConsensusResponse(Some(consensus_msg)) => {
                                        info!("[P2P DIRECT] Menerima respons konsensus dari {}: {:?}", peer, consensus_msg);
                                        if p2p_to_consensus_tx.send((*consensus_msg, peer, None)).await.is_err() {
                                            warn!("[P2P DIRECT] Gagal mengirim respons konsensus ke engine (tidak ada yang mendengarkan).");
                                        }
                                    },
                                    SyncResponse::ConsensusResponse(None) => {
                                        debug!("[P2P DIRECT] Menerima ack konsensus dari peer {}", peer);
                                    }
                                    SyncResponse::FullProposal(Some(pending_block)) => {
                                        info!("[SYNC] Menerima proposal lengkap untuk blok 0x{} dari peer {}", hex::encode(&pending_block.header.calculate_hash()[..4]), peer);
                                        let block_proposal = Block {
                                            header: pending_block.header.clone(),
                                            transactions: pending_block.transactions.clone(),
                                            round: pending_block.round,
                                            view_number: pending_block.round,
                                            justify: pending_block.parent_qc.clone(),
                                            vrf_output: vec![],
                                            vrf_proof: vec![],
                                        };

                                        let msg_tuple = (
                                            ConsensusMessage::AegisBlockProposal(Box::new(block_proposal)),
                                            peer,
                                            None
                                        );
                                        if p2p_to_consensus_tx.send(msg_tuple).await.is_err() {
                                            error!("[P2P] Gagal mengirim proposal yang diterima dari sync ke channel konsensus.");
                                        }
                                    },
                                    SyncResponse::FullProposal(None) => {
                                        warn!("[SYNC] Peer {} merespons tetapi tidak dapat menemukan proposal yang diminta.", peer);
                                    },
                                    _ => { 
                                        info!("[SYNC] Menerima respons sinkronisasi dari peer {}", peer); 
                                        if tx_sync_resp.send((response, peer)).is_err() { 
                                            warn!("[SYNC] Gagal mengirim respons sinkronisasi ke SyncManager (tidak ada yang mendengarkan)."); 
                                        } 
                                    } 
                                } 
                            } 
                        } 
                    }, 
                    _ => {} 
                } 
            } 
        } 
    }
}