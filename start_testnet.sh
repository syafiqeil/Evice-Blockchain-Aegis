#!/bin/bash

# ==============================================================================
# SKRIP TESTNET (LOKAL & PUBLIK) 
# ==============================================================================
#
# MODE PENGGUNAAN:
# chmod +x start_testnet.sh
# ./start_testnet.sh local      
# ./start_testnet.sh public_gen                               
#
# ==============================================================================

set -e

NUM_NODES=7
MODE=$1

function compile_project() {
    echo "===== FASE KOMPILASI ====="
    echo "Menjalankan 'cargo build' untuk memastikan semua biner sudah diperbarui..."
    RUST_LOG=info,evice_blockchain=debug ROCKSDB_LIB_DIR=/usr/lib CXX=clang++ cargo build
    echo "✅ Proyek siap."
}

# ==============================================================================
#                       MODE: local (Testnet Lokal)
# ==============================================================================

if [ "$MODE" == "local" ]; then
echo "🚀 Memulai setup untuk TESTNET LOKAL ($NUM_NODES node)..."

# --- FASE 1: PEMBERSIHAN ---
echo "===== FASE 1: PEMBERSIHAN LINGKUNGAN LOKAL ====="
rm -rf ./local_testnet ./keystores ./database *.pem *.crt *.key *.csr *.srl *.log san.cnf genesis.json
echo "Lingkungan lama dibersihkan."

compile_project

# --- FASE 2: PEMBUATAN ASET KRIPTOGRAFI (METODE LAMA YANG ANDAL) ---
echo -e "\n===== FASE 2: PEMBUATAN ASET KRIPTOGRAFI YANG KONSISTEN ====="
mkdir -p ./local_testnet

# 2a. Buat semua kunci validator (Signing, VRF, BLS) dalam satu file sebagai sumber kebenaran
target/debug/evice_blockchain --bootstrap > ./local_testnet/validator_keys.txt
echo "✅ Kunci validator (Signing, VRF, BLS) telah dibuat di validator_keys.txt."

# 2b. Buat kunci P2P persisten untuk setiap node
PEER_IDS=()
echo "Membuat kunci P2P dan mendapatkan PeerID untuk setiap node..."
for i in $(seq 1 $NUM_NODES); do
    mkdir -p ./local_testnet/node$i/database
    ID=$(target/debug/evice_blockchain --db-path ./local_testnet/node$i/database --get-peer-id)
    PEER_IDS+=($ID)
done
echo "✅ Semua PeerID persisten berhasil dibuat."

# 2c. Bangun genesis.json dari sumber kebenaran (validator_keys.txt)
echo "Membangun genesis.json yang konsisten..."
GENESIS_TIME=$(date +%s)
{
    echo "{"
    echo "  \"genesis_time\": $GENESIS_TIME,"
    echo "  \"chain_id\": \"evice-local-testnet\","
    echo "  \"parameters\": {"
    echo "    \"aegis_sub_committee_size\": 6,"
    echo "    \"aegis_gravity_epoch_length\": 10,"
    echo "    \"proposer_timeout_ms\": 1200,"
    echo "    \"max_transactions_per_block\": 500,"
    echo "    \"minimum_stake\": \"10000\","
    echo "    \"proposal_voting_period_blocks\": 100"
    echo "  },"
    echo "  \"accounts\": {"
    for i in $(seq 1 $NUM_NODES); do
        PUB_KEY=$(grep -A 7 -e "--- Validator $i ---" ./local_testnet/validator_keys.txt | grep "Alamat (Sign PubKey)" | sed 's/.*: *0x//')
        VRF_KEY=$(grep -A 7 -e "--- Validator $i ---" ./local_testnet/validator_keys.txt | grep "VRF Public Key" | sed 's/.*: *0x//')
        BLS_KEY=$(grep -A 7 -e "--- Validator $i ---" ./local_testnet/validator_keys.txt | grep "BLS Public Key" | sed 's/.*: *0x//')

        if [ -z "$PUB_KEY" ]; then
            echo "FATAL ERROR: Gagal mengekstrak Full Public Key untuk Validator $i." >&2
            exit 1
        fi

        ADDR_HASH=$(target/debug/address_calculator "$PUB_KEY")
        P2P_PORT=$((50000 + i - 1))
        PEER_ID=${PEER_IDS[$i-1]}
        
        if [ $i -lt $NUM_NODES ]; then
            BALANCE="9500000"
            STAKED_AMOUNT="500000"
        else
            BALANCE="10000000"
            STAKED_AMOUNT="0"
        fi

        echo "    \"0x$ADDR_HASH\": {"
        echo "      \"public_key\": \"$PUB_KEY\","
        echo "      \"balance\": \"$BALANCE\","
        echo "      \"staked_amount\": \"$STAKED_AMOUNT\","
        echo "      \"vrf_public_key\": \"$VRF_KEY\","
        echo "      \"bls_public_key\": \"$BLS_KEY\","
        echo "      \"network_identity\": \"/ip4/127.0.0.1/tcp/$P2P_PORT/p2p/$PEER_ID\""
        echo -n "    }"
        if [ $i -lt $NUM_NODES ]; then echo ","; else echo ""; fi
    done
    echo "  }"
    echo "}"
} > genesis.json
echo "✅ genesis.json berhasil dibuat."

# 2d. Buat Keystores dan salin aset yang diperlukan ke setiap node
echo "Membuat keystore dan menyalin aset ke direktori node..."
cat <<EOF > san.cnf
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = localhost
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF
openssl genrsa -out ca.key 4096 &>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem -subj "/CN=MyTestCA" &>/dev/null
openssl req -new -nodes -newkey rsa:4096 -keyout server.key -out server.csr -config san.cnf &>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.crt -days 3650 -sha256 -extfile san.cnf -extensions v3_req &>/dev/null
mv server.crt cert.pem && mv server.key key.pem

if [ ! -f "verifying_key.bin" ] || [ ! -f "agg_verifying_key.bin" ]; then
    echo "⚠️  File ZK verifying keys tidak ditemukan. Menjalankan 'generate_zk_params'..."
    target/debug/generate_zk_params
fi

for i in $(seq 1 $NUM_NODES); do
    mkdir -p ./local_testnet/node$i/keystores
  
    cp genesis.json ./local_testnet/node$i/
    cp cert.pem key.pem ca.pem ./local_testnet/node$i/
    cp verifying_key.bin agg_verifying_key.bin ./local_testnet/node$i/

    PUB_KEY=$(grep -A 7 -e "--- Validator $i ---" ./local_testnet/validator_keys.txt | grep "Alamat (Sign PubKey)" | sed 's/.*: *0x//')
    PRIV_KEY=$(grep -A 7 -e "--- Validator $i ---" ./local_testnet/validator_keys.txt | grep "Signing Private Key" | sed 's/.*: *0x//')
    
    if [ -z "$PUB_KEY" ] || [ -z "$PRIV_KEY" ]; then
        echo "FATAL ERROR: Gagal mengekstrak kunci untuk pembuatan Keystore Validator $i." >&2
        exit 1
    fi
    
    target/debug/create_keystore --import-public-key "$PUB_KEY" --import-private-key "$PRIV_KEY" --password "1234"
    mv ./keystores/UTC--* ./local_testnet/node$i/keystores/
done
echo "✅ Semua aset berhasil disiapkan untuk setiap node."

# --- FASE 3: MENAMPILKAN PERINTAH UNTUK MENJALANKAN NODE ---
echo -e "\n✅ PENYIAPAN SELESAI! ✅"
echo -e "\n=============================================================================="
echo "          PANDUAN MENJALANKAN TESTNET SECARA MANUAL ($NUM_NODES NODE)              "
echo "=============================================================================="

LOG_LEVEL="info,evice_blockchain=trace"
BOOTSTRAP_PEER_ID=${PEER_IDS[0]}

declare -a KEYSTORE_PATHS
declare -a VRF_PRIV_KEYS
declare -a ADDR_HASHES
declare -a BLS_PRIV_KEYS 

for i in $(seq 1 $NUM_NODES); do
    KEYSTORE_PATHS+=("$(find ./local_testnet/node$i/keystores -type f)")
    VRF_PRIV_KEYS+=("$(awk -v i=$i '/--- Validator/ { if ($3 == i) found=1 } found && /VRF Secret Key/ { print $4; exit }' ./local_testnet/validator_keys.txt | sed 's/0x//' | tr -d '\r')")
    
    PUB_KEY_FOR_ADDR=$(grep -A 7 -e "--- Validator $i ---" ./local_testnet/validator_keys.txt | grep "Alamat (Sign PubKey)" | sed 's/.*: *0x//')
    if [ -z "$PUB_KEY_FOR_ADDR" ]; then
        echo "FATAL ERROR: Gagal mengekstrak kunci untuk kalkulasi Alamat Validator $i." >&2
        exit 1
    fi
    BLS_PRIV_KEYS+=("$(awk -v i=$i '/--- Validator/ { if ($3 == i) found=1 } found && /BLS Secret Key/ { print $4; exit }' ./local_testnet/validator_keys.txt | sed 's/0x//' | tr -d '\r')")
    ADDR_HASHES+=("$(target/debug/address_calculator "$PUB_KEY_FOR_ADDR")")
done

for i in {1..6}; do
    NODE_INDEX=$((i - 1)) 
    RPC_PORT=$((8080 + NODE_INDEX))
    P2P_PORT=$((50000 + NODE_INDEX))
    METRICS_PORT=$((9615 + NODE_INDEX))
    KEYSTORE_FULL_PATH=${KEYSTORE_PATHS[$NODE_INDEX]}
    KEYSTORE_RELATIVE_PATH="keystores/$(basename "$KEYSTORE_FULL_PATH")"
    
    VRF_KEY=${VRF_PRIV_KEYS[$NODE_INDEX]}
    BLS_KEY=${BLS_PRIV_KEYS[$NODE_INDEX]}

    if [ $i -eq 1 ]; then
        echo -e "\n------------------------------ TERMINAL 1 (Node Bootstrap) ------------------------------"
        echo "cd ./local_testnet/node1 && RUST_LOG=$LOG_LEVEL ../../target/debug/evice_blockchain --db-path ./database --is-authority --keystore-path '$KEYSTORE_RELATIVE_PATH' --vrf-private-key '$VRF_KEY' --bls-private-key '$BLS_KEY' --password '1234' --dev"
    else
        echo -e "\n------------------------------ TERMINAL $i ------------------------------"
        echo "cd ./local_testnet/node$i && RUST_LOG=$LOG_LEVEL ../../target/debug/evice_blockchain --db-path ./database --rpc-port $RPC_PORT --p2p-port $P2P_PORT --metrics-port $METRICS_PORT --is-authority --keystore-path '$KEYSTORE_RELATIVE_PATH' --vrf-private-key '$VRF_KEY' --bls-private-key '$BLS_KEY' --bootstrap-node \"/ip4/127.0.0.1/tcp/50000/p2p/$BOOTSTRAP_PEER_ID\" --password '1234' --dev"
    fi
done

echo -e "\n========================================================================="
echo "         MENJALANKAN NODE KE-7 (NON-VALIDATOR AWAL)                       "
echo "=============================================================================="
L1_RPC_URL="https://127.0.0.1:8080"
STAKE_AMOUNT="500000"
KEYSTORE_7_FULL_PATH=${KEYSTORE_PATHS[6]}

echo "# 1. Tunggu jaringan berjalan. Buka terminal baru dan jalankan staking:"
echo "target/debug/create_tx --l1-rpc-url $L1_RPC_URL stake --keystore-path '$KEYSTORE_7_FULL_PATH' --amount $STAKE_AMOUNT --nonce 0"
echo ""
echo "# 2. Setelah transaksi terkonfirmasi, jalankan Node 7 sebagai validator:"
RPC_PORT_7=8086
P2P_PORT_7=50006
METRICS_PORT_7=9621
VRF_KEY_7=${VRF_PRIV_KEYS[6]}
BLS_KEY_7=${BLS_PRIV_KEYS[6]}
KEYSTORE_7_RELATIVE_PATH="keystores/$(basename "$KEYSTORE_7_FULL_PATH")"
echo "------------------------------ TERMINAL 7 ------------------------------"
echo "cd ./local_testnet/node7 && RUST_LOG=$LOG_LEVEL ../../target/debug/evice_blockchain --db-path ./database --rpc-port $RPC_PORT_7 --p2p-port $P2P_PORT_7 --metrics-port $METRICS_PORT_7 --is-authority --keystore-path '$KEYSTORE_7_RELATIVE_PATH' --vrf-private-key '$VRF_KEY_7' --bls-private-key '$BLS_KEY_7' --bootstrap-node \"/ip4/127.0.0.1/tcp/50000/p2p/$BOOTSTRAP_PEER_ID\" --password '1234' --dev"
echo ""

echo "=============================================================================="
echo "              PERINTAH PENGUJIAN FUNGSIONALITAS INTI                          "
echo "=============================================================================="
echo ""
V2_ADDR_HASH=${ADDR_HASHES[1]}
KEYSTORE_1_FULL_PATH=${KEYSTORE_PATHS[0]}
KEYSTORE_2_FULL_PATH=${KEYSTORE_PATHS[1]}
KEYSTORE_3_FULL_PATH=${KEYSTORE_PATHS[2]}

echo "--- 1. TRANSFER ---"
echo "# Transfer 100 token dari Validator 1 ke Validator 2 (nonce 0):"
echo "target/debug/create_tx --l1-rpc-url $L1_RPC_URL transfer --keystore-path '$KEYSTORE_1_FULL_PATH' --recipient '0x$V2_ADDR_HASH' --amount 100 --nonce 0"
echo ""
echo "--- 2. STAKING ---"
echo "# Validator 2 melakukan staking tambahan 5000 token (nonce 0):"
echo "target/debug/create_tx --l1-rpc-url $L1_RPC_URL stake --keystore-path '$KEYSTORE_2_FULL_PATH' --amount 5000 --nonce 0"
echo ""
echo "--- 3. GOVERNANCE (MEMBUAT PROPOSAL) ---"
echo "# Validator 1 mengajukan proposal (setelah transfer, nonce jadi 1):"
echo "target/debug/create_tx --l1-rpc-url $L1_RPC_URL submit-proposal --keystore-path '$KEYSTORE_1_FULL_PATH' --nonce 1 --title \"My Proposal\" --description \"My Description\""
echo ""
echo "--- 4. GOVERNANCE (MEMBERIKAN SUARA) ---"
echo "# Validator 2 memberikan suara 'Ya' pada proposal ID 0 (setelah staking, nonce jadi 1):"
echo "target/debug/create_tx --l1-rpc-url $L1_RPC_URL cast-vote --keystore-path '$KEYSTORE_2_FULL_PATH' --nonce 1 --proposal-id 0 --vote-yes"
echo ""
echo "--- 5. BRIDGE DEPOSIT (L1 -> L2) ---"
echo "# Validator 3 deposit 2500 token ke L2 (nonce 0):"
echo "target/debug/create_tx --l1-rpc-url $L1_RPC_URL deposit --keystore-path '$KEYSTORE_3_FULL_PATH' --amount 2500 --nonce 0"
echo "=============================================================================="
echo ""

# Bagian public_gen tetap sama, tidak perlu diubah

elif [ "$MODE" == "public_gen" ]; then
    echo "🚀 Memulai agregasi untuk GENESIS PUBLIK..."
    REG_DIR="./registrations"
    if [ ! -d "$REG_DIR" ] || [ -z "$(ls -A $REG_DIR)" ]; then
        echo "❌ Error: Direktori '$REG_DIR' tidak ada atau kosong."
        echo "Buat direktori '$REG_DIR' dan tempatkan file pendaftaran validator (registration-*.json) di dalamnya."
        exit 1
    fi

    compile_project
    
    echo "Membangun genesis.json dari file pendaftaran..."
    GENESIS_TIME=$(date +%s)
    
    # Gunakan template, tambahkan akun faucet
    FAUCET_KEYS=$(target/debug/validator-tool --public-ip 1.1.1.1 --p2p-port 1234 --output-dir /tmp/faucet_keys 2>&1)
    FAUCET_ADDR=$(echo "$FAUCET_KEYS" | sed -n 's/.*"address":"\([^"]*\)".*/\1/p')
    FAUCET_PK=$(echo "$FAUCET_KEYS" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
    
    cat <<EOF > genesis.json
{
  "genesis_time": $GENESIS_TIME,
  "chain_id": "evice-public-testnet-v1",
  "parameters": {
    "aegis_sub_committee_size": 6,
    "aegis_gravity_epoch_length": 10,
    "proposer_timeout_ms": 1200,
    "max_transactions_per_block": 500,
    "minimum_stake": "10000",
    "proposal_voting_period_blocks": 100
  },
  "accounts": {
    "$FAUCET_ADDR": {
        "public_key": "$FAUCET_PK",
        "balance": "1000000",
        "staked_amount": "0",
        "vrf_public_key": null,
        "bls_public_key": null,
        "network_identity": null
    },
EOF

    # Loop melalui file pendaftaran dan tambahkan ke genesis
    FILES=($REG_DIR/registration-*.json)
    NUM_FILES=${#FILES[@]}
    COUNTER=0
    for file in "${FILES[@]}"; do
        ADDR=$(cat "$file" | sed -n 's/.*"address":"\([^"]*\)".*/\1/p')
        PK=$(cat "$file" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
        VRF_PK=$(cat "$file" | sed -n 's/.*"vrf_public_key":"\([^"]*\)".*/\1/p')
        BLS_PK=$(cat "$file" | sed -n 's/.*"bls_public_key":"\([^"]*\)".*/\1/p')
        NET_ID=$(cat "$file" | sed -n 's/.*"network_identity":"\([^"]*\)".*/\1/p')

        cat <<EOF >> genesis.json
    "$ADDR": {
      "public_key": "$PK",
      "balance": "95000",
      "staked_amount": "50000",
      "vrf_public_key": "$VRF_PK",
      "bls_public_key": "$BLS_PK",
      "network_identity": "$NET_ID"
    }
EOF
        COUNTER=$((COUNTER + 1))
        if [ $COUNTER -lt $NUM_FILES ]; then echo "," >> genesis.json; fi
    done

    echo "  }" >> genesis.json
    echo "}" >> genesis.json

    echo "✅ Genesis publik berhasil dibuat dari $NUM_FILES validator!"
    echo "   File 'genesis.json' siap untuk didistribusikan."

else
    echo "Mode tidak valid. Gunakan 'local' atau 'public_gen'."
    exit 1
fi