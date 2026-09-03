// Copyright (c) 2014-2022, The Monero Project
// Copyright (c) 2024-2026, Privacy Bank Chain (PBC)
// BSD-3-Clause License (see LICENSE)
#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <boost/uuid/uuid.hpp>

#define CRYPTONOTE_DNS_TIMEOUT_MS                       20000
#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_TX_SIZE                          1000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK                     0x10000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V2         1440

// PBC Vesting schedule (Whitepaper §3.6) — 4 outputs staggered unlock
#define PBC_VESTING_OUTPUTS                              4
#define PBC_VESTING_UNLOCK_1                             1440      // ~24h
#define PBC_VESTING_UNLOCK_2                             43200     // ~30 days
#define PBC_VESTING_UNLOCK_3                             86400    // ~60 days
#define PBC_VESTING_UNLOCK_4                             129600    // ~90 days
#define HF_VERSION_VESTING                               19

#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            60
#define CURRENT_TRANSACTION_VERSION                     2
#define CURRENT_BLOCK_MAJOR_VERSION                     21
#define CURRENT_BLOCK_MINOR_VERSION                     21
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2           60*10
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT              60*60*2
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE             4
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2            11
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW               60

// Emission (Whitepaper §19.2): ~18.4M PBC, 1 PBC = 10^12 atomic
#define MONEY_SUPPLY                                    ((uint64_t)18446744000000000000ULL)
#define EMISSION_SPEED_FACTOR_PER_MINUTE                (22)
#define FINAL_SUBSIDY_PER_MINUTE                        ((uint64_t)(0))

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    60000
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    20000
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    900000  // increased for PQC (TXs ~3x larger with Dilithium+Kyber)
#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   500000
#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR 50
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                12
#define COIN                                            ((uint64_t)1000000000000) // 10^12

#define FEE_PER_KB_OLD                                  ((uint64_t)10000000000)
#define FEE_PER_KB                                      ((uint64_t)2000000000)
#define FEE_PER_BYTE                                    ((uint64_t)300000)
#define DYNAMIC_FEE_PER_KB_BASE_FEE                     ((uint64_t)2000000000)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)10000000000000)
#define DYNAMIC_FEE_PER_KB_BASE_FEE_V5                  ((uint64_t)2000000000 * (uint64_t)CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT         ((uint64_t)3000)
#define ORPHANED_BLOCKS_MAX_COUNT                       10000

// Block time 300s / 5min (Whitepaper §3.1)
#define DIFFICULTY_TARGET_V2                            60
#define DIFFICULTY_TARGET_V1                            60
#define DIFFICULTY_WINDOW_V3                            144
#define DIFFICULTY_WINDOW_V2                            60
#define DIFFICULTY_WINDOW                               720
#define DIFFICULTY_LAG_V2                               3
#define DIFFICULTY_LAG                                  15
#define DIFFICULTY_CUT_V2                               12
#define DIFFICULTY_CUT                                  60
#define DIFFICULTY_BLOCKS_COUNT_V4                      DIFFICULTY_WINDOW_V3 + 1
#define DIFFICULTY_BLOCKS_COUNT_V3                      DIFFICULTY_WINDOW_V3 + 1
#define DIFFICULTY_BLOCKS_COUNT_V2                      DIFFICULTY_WINDOW_V2 + 1
#define DIFFICULTY_BLOCKS_COUNT                         DIFFICULTY_WINDOW + DIFFICULTY_LAG

#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1   DIFFICULTY_TARGET_V1 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   DIFFICULTY_TARGET_V2 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1
#define DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN             DIFFICULTY_TARGET_V1

#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000
#define BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT              25000
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4       100
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              20
#define BLOCKS_SYNCHRONIZING_MAX_COUNT                  2048
#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    (86400*3)
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     604800

#define CRYPTONOTE_DANDELIONPP_STEMS              2
#define CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY 20
#define CRYPTONOTE_DANDELIONPP_MIN_EPOCH         10
#define CRYPTONOTE_DANDELIONPP_EPOCH_RANGE       30
#define CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE      5
#define CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE   39
#define CRYPTONOTE_NOISE_MIN_EPOCH                      5
#define CRYPTONOTE_NOISE_EPOCH_RANGE                    30
#define CRYPTONOTE_NOISE_MIN_DELAY                      10
#define CRYPTONOTE_NOISE_DELAY_RANGE                    5
#define CRYPTONOTE_NOISE_BYTES                          3*1024
#define CRYPTONOTE_NOISE_CHANNELS                       2
#define CRYPTONOTE_FORWARD_DELAY_BASE (CRYPTONOTE_NOISE_MIN_DELAY + CRYPTONOTE_NOISE_DELAY_RANGE)
#define CRYPTONOTE_FORWARD_DELAY_AVERAGE (CRYPTONOTE_FORWARD_DELAY_BASE + (CRYPTONOTE_FORWARD_DELAY_BASE / 2))
#define CRYPTONOTE_MAX_FRAGMENTS                        20

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT     1000
#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT        20000
#define DEFAULT_RPC_MAX_CONNECTIONS_PER_PUBLIC_IP       3
#define DEFAULT_RPC_MAX_CONNECTIONS_PER_PRIVATE_IP      25
#define DEFAULT_RPC_MAX_CONNECTIONS                     100
#define DEFAULT_RPC_SOFT_LIMIT_SIZE                     25 * 1024 * 1024
#define MAX_RPC_CONTENT_LENGTH                          1048576
#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000
#define P2P_DEFAULT_CONNECTIONS_COUNT                   12
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_MAX_PEERS_IN_HANDSHAKE                      250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT               45
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT       2
#define P2P_DEFAULT_LIMIT_RATE_UP                       8192
#define P2P_DEFAULT_LIMIT_RATE_DOWN                     32768
#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)
#define P2P_IP_BLOCKTIME                                (60*60*24)
#define P2P_IP_FAILS_BEFORE_BLOCK                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60)
#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAGS                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS
#define RPC_IP_FAILS_BEFORE_BLOCK                       3

#define CRYPTONOTE_NAME                         "pbcchain"

// PBC Block Reward Split (Whitepaper §19.2-§19.3), per-mille
#define PBC_MINER_SHARE                   910   // 91.0% of R
#define PBC_DEV_SHARE                     20    // 2.0% of R
#define PBC_FEE_POOL_SHARE                35    // 3.5% of R (virtual)
#define PBC_DEPOSIT_POOL_SHARE            25    // 2.5% of R (virtual)
#define PBC_INSURANCE_POOL_SHARE          10    // 1.0% of R (virtual)
#define PBC_FEE_MINER_SHARE              500   // 50% of fees to miner
#define PBC_FEE_POOL_FEE_SHARE           500   // 50% of fees to Fee Pool
#define PBC_POOL_TOTAL_SHARE             (PBC_FEE_POOL_SHARE + PBC_DEPOSIT_POOL_SHARE + PBC_INSURANCE_POOL_SHARE) // 70

// PBC Dev Fund (Whitepaper §3.2) — replace keys before production mainnet!
#define PBC_DEV_FUND_VIEWKEY                   "1db45c9a1443f69f7240699653e622b7e331d89e48b8aaefc6defc05c4e7d9c5"
#define PBC_DEV_FUND_VIEWKEY_SECRET            "dd228d1197028cd736c93d4c327bdd1f41a569182cc42262d2213e5784ebe706"
#define PBC_DEV_FUND_SPENDKEY                  "38e2998a030155815ff72c345c9cb87e411e4a1bc339a27aede79545d1514e40"

// PBC Consensus Constants (Whitepaper §19.2) — Phase 1 parameters
#define PBC_DISTRIBUTION_PERIOD           1440
#define PBC_MIN_DEPOSIT_AMOUNT            ((uint64_t)10000000000000)
#define PBC_MAX_DEPOSITS_PER_ADDR         10
#define PBC_DEPOSIT_CREATION_FEE          ((uint64_t)1000000000000)
#define PBC_EARLY_WITHDRAWAL_PENALTY      20
#define PBC_TIER_30D_BLOCKS               43200
#define PBC_TIER_90D_BLOCKS               129600
#define PBC_TIER_180D_BLOCKS              259200
#define PBC_LOCK_MIN_DURATION             50
#define PBC_LOCK_MAX_DURATION             1440
#define PBC_TIER_270D_BLOCKS              388800
#define PBC_TIER_365D_BLOCKS              525600

// Consensus upper bound on a deposit's unlock_height, measured from the block
// that INCLUDES the deposit TX: unlock_height <= block_height + tier_blocks + this.
// The wallet sets unlock_height = creation + tier_blocks + small_margin (<= this);
// the extra here absorbs mempool inclusion drift. Prevents a modified wallet from
// inflating unlock_height to earn rewards beyond its tier (reward eligibility is
// unlock_height > current_height) at the expense of other depositors.
#define PBC_DEPOSIT_UNLOCK_MAX_MARGIN     256
#define PBC_MULT_30D                      1000
#define PBC_MULT_90D                      1300
#define PBC_MULT_180D                     1600
#define PBC_MULT_270D                     1800
#define PBC_MULT_365D                     2000
#define PBC_LSM_THRESHOLD                 600
#define PBC_LSM_MIN_RATE                  100
#define PBC_INSURANCE_CAP                 ((uint64_t)184467000000000000ULL)
#define PBC_INSURANCE_SUBSIDY_RATE        100
#define PBC_MIN_DEPOSIT_POOL              ((uint64_t)100000000000000ULL)
#define PBC_FEE_FLOOR_SCALE               1000
#define PBC_FEE_FLOOR_CAP                 2000
#define PBC_MIN_INHERITANCE_TIMEOUT       262800
#define PBC_SCALE                         ((uint64_t)1000000000000000000ULL)

// PBC Term Deposit TX extra tags (§19.4–§19.7)
// Range 0x50–0x5F reserved for PBC; avoids 0x00–0x04 (core) and 0xDE (minergate)
#define TX_EXTRA_TAG_PBC_TX_TYPE          0x50  // 1-byte payload: PBC tx type
#define TX_EXTRA_TAG_PBC_DEPOSIT_INFO     0x51  // deposit: amount + unlock_height + tier
#define TX_EXTRA_TAG_PBC_CLAIM_INFO       0x52  // claim:   deposit_id hash
#define TX_EXTRA_TAG_PBC_WITHDRAW_INFO    0x53  // withdraw: deposit_id hash
#define TX_EXTRA_TAG_PBC_OWNER_KEY        0x54  // TD-8: owner's spend public key (32 bytes)
#define TX_EXTRA_TAG_PBC_OWNER_SIG        0x55  // TD-8: ownership proof signature (64 bytes)
// PF-C1: TERM_WITHDRAW payout (public subsidy amount + kind)
#define TX_EXTRA_TAG_PBC_WITHDRAW_PAYOUT  0x56  // withdraw: payout_amount (u64) + payout_kind (u8)
#define TX_EXTRA_TAG_PBC_INHERIT_SETUP    0x57  // inheritance: heir address (spend+view pubkeys)
#define TX_EXTRA_TAG_PBC_INHERIT_TARGET   0x58  // inheritance: principal spend pubkey (32 bytes)
#define TX_EXTRA_TAG_PBC_INHERIT_CANCEL   0x59  // inheritance: cancel marker (empty payload)
#define TX_EXTRA_TAG_PBC_TRANSFER_DEPOSIT 0x5A  // marketplace: deposit_id + new owner spend pubkey
#define TX_EXTRA_TAG_PBC_LOCK_COLLATERAL  0x5B  // marketplace: collateral lock payload
#define TX_EXTRA_TAG_PBC_CANCEL_LOCK      0x5C  // marketplace: cancel / expiry lock payload
#define TX_EXTRA_TAG_PBC_MARKET_ASK       0x5D  // marketplace: list / update / delist a deposit for sale
#define TX_EXTRA_TAG_PBC_MARKET_PAYOUT    0x5E  // marketplace: claim deferred seller rewards
#define TX_EXTRA_TAG_PBC_DILITHIUM_PUBKEY 0x5F  // PQC: ML-DSA-65 public key (1952 bytes)
#define TX_EXTRA_TAG_PBC_DILITHIUM_SIG    0x60  // PQC: ML-DSA-65 signature (up to 3309 bytes)
#define TX_EXTRA_TAG_PBC_KYBER_PUBKEY     0x61  // PQC: ML-KEM-768 public key (1184 bytes)
#define TX_EXTRA_TAG_PBC_PQC_REGISTER     0x62  // PQC: registration marker (pqc_hash commitment)
#define TX_EXTRA_TAG_PBC_KYBER_CIPHERTEXT 0x63  // PQC: ML-KEM-768 ciphertext for hybrid ECDH (1088 bytes)
// ── A3 (héritage on-chain gaté consensus) — FONDATION, câblage en sous-étapes (voir testsheritage/) ──
// Premier tag libre = 0x64 (0x50–0x63 tous pris). Porte le principal_spend_pubkey du balayage d'héritage.
#define TX_EXTRA_TAG_PBC_INHERIT_SWEEP    0x64  // A3: marqueur de balayage d'héritage
#define TX_EXTRA_TAG_PBC_INHERIT_TESTAMENT 0x65  // A4: tx porteur du testament on-chain
#define PBC_DEPOSIT_OWNER_MSG_PREFIX    "PBC_DEPOSIT_OWNER_V1"
#define PBC_WITHDRAW_OWNER_MSG_PREFIX   "PBC_WITHDRAW_V1"
// M2 fix — PQC registration proof-of-possession. The owner_sig on a PQC_REGISTER TX signs
// H(PBC_PQC_REGISTER_MSG_PREFIX || owner_spend_pubkey || pqc_hash) with the spend secret key,
// proving the registrant controls the spend key it is binding PQC keys to, and committing to
// the exact (dilithium||kyber) hash being registered. Verified by consensus at block apply.
#define PBC_PQC_REGISTER_MSG_PREFIX     "PBC_PQC_REGISTER_V1"

// ── PQC spend authority (Problem 2) — Dilithium co-signature over TERM_WITHDRAW / MARKET_PAYOUT ──
// A withdraw / payout-claim TX authorises the spend of a *named, public* deposit (deposit_id is
// on-chain and dep_rec.owner_key is revealed), so it has NO ring anonymity to protect. That lets
// us add a genuine post-quantum authorisation requirement to exactly these virtual-input TXs
// WITHOUT any anonymity loss: alongside the Ed25519 owner_sig we additionally require an ML-DSA-65
// (Dilithium) signature, produced by the deposit owner's registered PQC key, over the SAME logical
// message (domain-separated with this prefix). Breaking Ed25519 alone then no longer authorises a
// withdraw — the attacker would also have to forge Dilithium, which Shor's algorithm does not break.
// The signed message is H(PBC_PQC_WITHDRAW_MSG_PREFIX || deposit_id || payout_amount_le8), and it is
// byte-identical between wallet (signer, tag 0x60) and consensus (verifier). This does NOT make
// ordinary RingCT transfers quantum-safe (their spend authority is the CLSAG ring, whose anonymity
// forbids a naive per-output PQC signature — see QUANTUM_ANALYSIS.md).
#define PBC_PQC_WITHDRAW_MSG_PREFIX     "PBC_PQC_WITHDRAW_V1"

// Hard-fork version at which a valid Dilithium co-signature becomes MANDATORY on TERM_WITHDRAW and
// MARKET_PAYOUT_CLAIM TXs (Problem 2). Before this version the co-signature is accepted-if-present
// but not required (soft transition); at/after it, a withdraw/payout without a valid registered
// Dilithium co-signature is rejected by both mempool and block validation. Reserved above the
// current chain version (21) and the BP+ migration slot (22). Activation is a table change in
// hardforks.cpp; until an entry is added, get_current_version() never reaches this value, so the
// requirement stays dormant and no existing TX path is affected.
#define HF_VERSION_PBC_PQC_SPEND_AUTH   23


// PBC TX type identifiers (payload of TX_EXTRA_TAG_PBC_TX_TYPE)
#define PBC_TX_TYPE_TERM_DEPOSIT          1
#define PBC_TX_TYPE_CLAIM                 2
#define PBC_TX_TYPE_TERM_WITHDRAW         3

// PBC Inheritance TX types
#define PBC_TX_TYPE_INHERIT_SETUP         4
#define PBC_TX_TYPE_INHERIT_REQUEST       5
#define PBC_TX_TYPE_INHERIT_CANCEL        6
#define PBC_TX_TYPE_TRANSFER_DEPOSIT      7
#define PBC_TX_TYPE_LOCK_COLLATERAL       8
#define PBC_TX_TYPE_CANCEL_LOCK           9
#define PBC_TX_TYPE_MARKET_ASK            10  // list / update price / delist a deposit (ask_price=0 = delist)
#define PBC_TX_TYPE_MARKET_PAYOUT_CLAIM   11  // claim deferred seller rewards after auto-match
// A3 (héritage on-chain gaté consensus) — FONDATION : type 12 réservé (12 et 13 étaient libres)
#define PBC_TX_TYPE_INHERIT_SWEEP         12
#define PBC_TX_TYPE_INHERIT_TESTAMENT     13   // A4: tx porteur du testament on-chain

// ─────────────────────────────────────────────────────────────────────────
// DURÉE D'HÉRITAGE (délai d'exécution) — CONSENSUS-CRITIQUE
// ─────────────────────────────────────────────────────────────────────────
// Délai, compté en BLOCS (pas en horloge), entre la REQUÊTE d'héritage et son
// exécution autorisée. Bloc ≈ 1 min (DIFFICULTY_TARGET_V2 = 60 s).
//   blocs = jours * 86400 / DIFFICULTY_TARGET_V2 = jours * 1440
//
//     PRODUCTION : 18 mois ≈ 540 jours → 540 * 1440 = 777600 blocs
//     TEST       :  2 jours            →   2 * 1440 =   2880 blocs
//
//   ►►► POUR CHANGER LA DURÉE : éditer UNIQUEMENT PBC_INHERIT_WAIT_DAYS ci-dessous.
//       Remettre 540 (=18 mois) AVANT tout déploiement mainnet.
//       (En difficulté fixe, ces 2880 blocs sont minés en quelques minutes/heures.)
//
#define PBC_INHERIT_WAIT_DAYS             ((uint64_t)540)      /* PROD : 540 = 18 mois (~1,5 an) — bascule mainnet 20/08/2026 */
#define PBC_INHERIT_WAIT_BLOCKS           ((uint64_t)(PBC_INHERIT_WAIT_DAYS * 86400ULL / DIFFICULTY_TARGET_V2))
// A3 gate: fenêtre (en blocs) durant laquelle un balayage d'héritage marqué est accepté,
// à partir de la hauteur d'exécution executed[P]=B. Avant B -> rejeté (diffusion prématurée).
// Généreux : laisse le temps au balayage d'être miné après exécution. Tunable.
#define PBC_INHERIT_EXEC_WINDOW_BLOCKS    ((uint64_t)2880)

// Conception v2 (2026-08-14) : oracle deterministe "mine en chaine" — remplace l'oracle local
// "add_tx a reussi" de la tentative precedente (invalidee pour risque de fork : request_active
// devenait fonction du resultat local d'add_tx, or elle est lue par 2 portes de validation de
// bloc pouvant rejeter le bloc entier — LOCK_COLLATERAL et TRANSFER_DEPOSIT).
// K fusionne deux roles : delai de grace pour la preuve de minage (un balayage diffuse peut
// mettre plusieurs blocs a etre inclus) ET espacement entre tentatives (evite de re-tenter a
// chaque bloc une cause d'echec qui a de bonnes chances d'etre encore vraie l'instant d'apres).
// Meme valeur que le recul cote wallet (PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS, wallet_rpc_server.h).
#define PBC_INHERIT_SWEEP_CONFIRM_BLOCKS        ((uint64_t)20)
// Plafond de tentatives avant abandon definitif (request_active clos). Au-dela, la cause est
// traitee comme permanente. ~50 tentatives x 20 blocs ~= 1000 blocs (~16-17h a 60s/bloc) avant
// abandon — largement suffisant pour absorber une cause transitoire (delai de propagation,
// pic de frais passager), sans ouvrir de vecteur de deni de service (chaque tentative reparse
// au plus 64 TX et appelle add_tx pour chacune, localement, sans effet sur le consensus).
#define PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS      ((uint64_t)50)

#define PBC_INHERIT_SETUP_MSG_PREFIX      "PBC_INHERIT_SETUP_V1"
#define PBC_INHERIT_REQUEST_MSG_PREFIX    "PBC_INHERIT_REQUEST_V1"
#define PBC_INHERIT_CANCEL_MSG_PREFIX     "PBC_INHERIT_CANCEL_V1"
#define PBC_INHERIT_TESTAMENT_MSG_PREFIX  "PBC_INHERIT_TESTAMENT_V1"  // A4: P signe prefix||P||seq||hash(testament)
#define PBC_TRANSFER_OWNER_MSG_PREFIX     "PBC_TRANSFER_DEPOSIT_V1"
#define PBC_MARKET_ASK_MSG_PREFIX         "PBC_MARKET_ASK_V1"
#define PBC_MARKET_PAYOUT_MSG_PREFIX      "PBC_MKTPAY_V1"
// Problem 2 — domain-separation prefix for the Dilithium spend-authority co-signature on
// MARKET_PAYOUT_CLAIM TXs. Same role as PBC_PQC_WITHDRAW_MSG_PREFIX but for marketplace payouts.
// Signed message: H(PBC_PQC_MKTPAY_MSG_PREFIX || seller_pubkey(32) || payout_amount(8 LE)).
#define PBC_PQC_MKTPAY_MSG_PREFIX         "PBC_PQC_MKTPAY_V1"

#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME      "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "lock.mdb"
#define P2P_NET_DATA_FILENAME                   "p2pstate.bin"
#define RPC_PAYMENTS_DATA_FILENAME              "rpcpayments.bin"
#define MINER_CONFIG_FILE_NAME                  "miner_conf.json"
#define THREAD_STACK_SIZE                       5 * 1024 * 1024

#define HF_VERSION_DYNAMIC_FEE                  4
#define HF_VERSION_MIN_MIXIN_7                  7
#define HF_VERSION_MIN_MIXIN_21                 9
#define HF_VERSION_ENFORCE_RCT                  6
#define HF_VERSION_PER_BYTE_FEE                 12
#define HF_VERSION_SMALLER_BP                   13
#define HF_VERSION_LONG_TERM_BLOCK_WEIGHT       13
#define HF_VERSION_MIN_2_OUTPUTS                15
#define HF_VERSION_MIN_V2_COINBASE_TX           15
#define HF_VERSION_SAME_MIXIN                   15
#define HF_VERSION_REJECT_SIGS_IN_COINBASE      15
#define HF_VERSION_ENFORCE_MIN_AGE              15
#define HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY 15
#define HF_VERSION_EXACT_COINBASE               16
#define HF_VERSION_CLSAG                        16
#define HF_VERSION_DETERMINISTIC_UNLOCK_TIME    16
#define HF_VERSION_DYNAMIC_UNLOCK               17
#define HF_VERSION_FIXED_UNLOCK                 18
#define HF_VERSION_BULLETPROOF_PLUS             18
#define HF_VERSION_BLOCK_HEADER_MINER_SIG       255
#define HF_VERSION_VIEW_TAGS                    20
#define HF_VERSION_2021_SCALING                 20
#define HF_VERSION_BP_PLUS_FULL_COMMIT          21
// A3 (héritage on-chain gaté consensus) — gate du balayage marqué INHERIT_SWEEP.
// ⚠ NE PAS utiliser 22 : v22 est RÉSERVÉE à la migration des preuves de portée
//   (HF_VERSION_BP_PLUS_FULL_COMMIT+1 interdit les BP+ legacy => rejette toutes les TX
//    tant que le wallet produit du BP+ legacy). On gate donc sur la version COURANTE 21.
// Sûr : le gate ne s'applique qu'aux TX portant PBC_TX_TYPE_INHERIT_SWEEP (type 12, nouveau) ;
//   les TX normales ne sont jamais affectées. Aucune nouvelle entrée hardfork n'est nécessaire.
#define HF_VERSION_PBC_INHERIT_GATE             21

#define PER_KB_FEE_QUANTIZATION_DECIMALS        8
#define CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES 2
#define HASH_OF_HASHES_STEP                     512
#define DEFAULT_TXPOOL_MAX_WEIGHT               648000000ull
#define BULLETPROOF_MAX_OUTPUTS                 16
#define BULLETPROOF_PLUS_MAX_OUTPUTS            16
#define CRYPTONOTE_PRUNING_STRIPE_SIZE          4096
#define CRYPTONOTE_PRUNING_LOG_STRIPES          3
#define CRYPTONOTE_PRUNING_TIP_BLOCKS           5500
#define RPC_CREDITS_PER_HASH_SCALE ((float)(1<<24))
#define DNS_BLOCKLIST_LIFETIME (86400 * 8)
#define MAX_TX_EXTRA_SIZE                       8192  // increased for PQC (Dilithium 5.3KB + Kyber 1.1KB + PBC fields)
// A4 (sous-étape 4) : limite tx_extra ÉTENDUE, appliquée UNIQUEMENT aux tx portant un champ
// testament on-chain (tag 0x65). Les tx normaux restent plafonnés à MAX_TX_EXTRA_SIZE.
#define PBC_INHERIT_TESTAMENT_MAX_EXTRA         40960

namespace config
{
  uint64_t const DEFAULT_FEE_ATOMIC_XMR_PER_KB = 500;
  uint8_t const FEE_CALCULATION_MAX_RETRIES = 10;
  uint64_t const DEFAULT_DUST_THRESHOLD = ((uint64_t)2000000000);
  uint64_t const BASE_REWARD_CLAMP_THRESHOLD = ((uint64_t)100000000);

  uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 3207;  // "Pbc..." addresses
  uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_V2_BASE58_PREFIX = 3210;  // PQC v2 "Pbc..." with pqc_hash // PQC address with pqc_hash commitment
  uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 3208;  // "PmK..." integrated
  uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 3209;  // "Pw2..." subaddress
  uint16_t const P2P_DEFAULT_PORT = 18830;
  uint16_t const RPC_DEFAULT_PORT = 18831;
  uint16_t const ZMQ_RPC_DEFAULT_PORT = 18832;
  boost::uuids::uuid const NETWORK_ID = { {
      0x50, 0x42, 0x43, 0x01, 0x20, 0x26, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x00, 0x01, 0x00
    } };
  std::string const GENESIS_TX = "013c01ff0001d6ddffffff1f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1";
  uint32_t const GENESIS_NONCE = 10001;

  const char HASH_KEY_BULLETPROOF_EXPONENT[] = "bulletproof";
  const char HASH_KEY_BULLETPROOF_PLUS_EXPONENT[] = "bulletproof_plus";
  const char HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT[] = "bulletproof_plus_transcript";
  const char HASH_KEY_RINGDB[] = "ringdsb";
  const char HASH_KEY_SUBADDRESS[] = "SubAddr";
  const unsigned char HASH_KEY_ENCRYPTED_PAYMENT_ID = 0x8d;
  const unsigned char HASH_KEY_WALLET = 0x8c;
  const unsigned char HASH_KEY_WALLET_CACHE = 0x8d;
  const unsigned char HASH_KEY_BACKGROUND_CACHE = 0x8e;
  const unsigned char HASH_KEY_BACKGROUND_KEYS_FILE = 0x8f;
  const unsigned char HASH_KEY_RPC_PAYMENT_NONCE = 0x58;
  const unsigned char HASH_KEY_MEMORY = 'k';
  const unsigned char HASH_KEY_MULTISIG[] = {'M', 'u', 'l', 't' , 'i', 's', 'i', 'g', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const unsigned char HASH_KEY_MULTISIG_KEY_AGGREGATION[] = "Multisig_key_agg";
  const unsigned char HASH_KEY_CLSAG_ROUND_MULTISIG[] = "CLSAG_round_ms_merge_factor";
  const unsigned char HASH_KEY_TXPROOF_V2[] = "TXPROOF_V2";
  const unsigned char HASH_KEY_CLSAG_ROUND[] = "CLSAG_round";
  const unsigned char HASH_KEY_CLSAG_AGG_0[] = "CLSAG_agg_0";
  const unsigned char HASH_KEY_CLSAG_AGG_1[] = "CLSAG_agg_1";
  const char HASH_KEY_MESSAGE_SIGNING[] = "PBCChainMessageSignature";
  const unsigned char HASH_KEY_MM_SLOT = 'm';
  const constexpr char HASH_KEY_MULTISIG_TX_PRIVKEYS_SEED[] = "multisig_tx_privkeys_seed";
  const constexpr char HASH_KEY_MULTISIG_TX_PRIVKEYS[] = "multisig_tx_privkeys";
  const constexpr char HASH_KEY_TXHASH_AND_MIXRING[] = "txhash_and_mixring";
  const uint32_t MULTISIG_MAX_SIGNERS{16};

  namespace testnet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 53;
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_V2_BASE58_PREFIX = 56; // PQC address with pqc_hash commitment
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 54;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 63;
    uint16_t const P2P_DEFAULT_PORT = 28830;
    uint16_t const RPC_DEFAULT_PORT = 28831;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 28832;
    boost::uuids::uuid const NETWORK_ID = { {
        0x50, 0x42, 0x43, 0x01, 0x20, 0x26, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x00, 0x01, 0x01
      } };
    std::string const GENESIS_TX = "013c01ff0001d6ddffffff1f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1";
    uint32_t const GENESIS_NONCE = 10001;
  }

  namespace stagenet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 24;
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_V2_BASE58_PREFIX = 27; // PQC v2
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 25;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 36;
    uint16_t const P2P_DEFAULT_PORT = 38830;
    uint16_t const RPC_DEFAULT_PORT = 38831;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 38832;
    boost::uuids::uuid const NETWORK_ID = { {
        0x50, 0x42, 0x43, 0x01, 0x20, 0x26, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x00, 0x01, 0x02
      } };
    std::string const GENESIS_TX = "013c01ff0001d6ddffffff1f02df5d56da0c7d643ddd1ce61901c7bdc5fb1738bfe39fbe69c28a3a7032729c0f2101168d0c4ca86fb55a4cf6a36d31431be1c53a3bd7411bb24e8832410289fa6f3b";
    uint32_t const GENESIS_NONCE = 10002;
  }
}

namespace cryptonote
{
  enum network_type : uint8_t
  { MAINNET = 0, TESTNET, STAGENET, FAKECHAIN, UNDEFINED = 255 };
  struct config_t
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t const P2P_DEFAULT_PORT;
    uint16_t const RPC_DEFAULT_PORT;
    uint16_t const ZMQ_RPC_DEFAULT_PORT;
    boost::uuids::uuid const NETWORK_ID;
    std::string const GENESIS_TX;
    uint32_t const GENESIS_NONCE;
  };
  inline const config_t& get_config(network_type nettype)
  {
    static const config_t mainnet = { ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX, ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX, ::config::P2P_DEFAULT_PORT, ::config::RPC_DEFAULT_PORT, ::config::ZMQ_RPC_DEFAULT_PORT, ::config::NETWORK_ID, ::config::GENESIS_TX, ::config::GENESIS_NONCE };
    static const config_t testnet = { ::config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, ::config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX, ::config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX, ::config::testnet::P2P_DEFAULT_PORT, ::config::testnet::RPC_DEFAULT_PORT, ::config::testnet::ZMQ_RPC_DEFAULT_PORT, ::config::testnet::NETWORK_ID, ::config::testnet::GENESIS_TX, ::config::testnet::GENESIS_NONCE };
    static const config_t stagenet = { ::config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, ::config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX, ::config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX, ::config::stagenet::P2P_DEFAULT_PORT, ::config::stagenet::RPC_DEFAULT_PORT, ::config::stagenet::ZMQ_RPC_DEFAULT_PORT, ::config::stagenet::NETWORK_ID, ::config::stagenet::GENESIS_TX, ::config::stagenet::GENESIS_NONCE };
    switch (nettype)
    {
      case MAINNET: return mainnet;
      case TESTNET: return testnet;
      case STAGENET: return stagenet;
      case FAKECHAIN: return mainnet;
      default: throw std::runtime_error("Invalid network type");
    }
  };
}
