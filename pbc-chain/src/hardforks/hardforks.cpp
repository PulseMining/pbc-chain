// Copyright (c) 2014-2022, The Monero Project
// Privacy Bank Chain — BSD-3-Clause
#include "hardforks.h"
#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain.hardforks"

// PBC hard forks — genesis at v17, immediately activate v21 at block 2
const hardfork_t mainnet_hard_forks[] = {
  { 17, 0, 1, 1700000000 },
  { 21, 2, 1, 1700000001 },
  // PBC PQC spend-authority (HF_VERSION_PBC_PQC_SPEND_AUTH = 23): from this height a valid
  // registered Dilithium co-signature becomes MANDATORY on TERM_WITHDRAW and MARKET_PAYOUT_CLAIM.
  // Ordering constraint of HardFork::add_fork is strict on all three fields vs the previous entry
  // { 21, 2, 1700000001 }: version 23 > 21, height 1000 > 2, time 1700000002 > 1700000001.
  { 23, 1000, 1, 1700000002 },
};
const size_t num_mainnet_hard_forks = sizeof(mainnet_hard_forks) / sizeof(mainnet_hard_forks[0]);
const uint64_t mainnet_hard_fork_version_1_till = 0;

const hardfork_t testnet_hard_forks[] = {
  { 17, 0, 1, 1700000000 },
  { 21, 2, 1, 1700000001 },
  // PBC PQC spend-authority (v23) — identical activation to mainnet. See mainnet comment above.
  { 23, 1000, 1, 1700000002 },
};
const size_t num_testnet_hard_forks = sizeof(testnet_hard_forks) / sizeof(testnet_hard_forks[0]);
const uint64_t testnet_hard_fork_version_1_till = 0;

const hardfork_t stagenet_hard_forks[] = {
  { 17, 0, 1, 1700000000 },
  { 21, 2, 1, 1700000001 },
  // PBC PQC spend-authority (v23) — identical activation to mainnet. See mainnet comment above.
  { 23, 1000, 1, 1700000002 },
};
const size_t num_stagenet_hard_forks = sizeof(stagenet_hard_forks) / sizeof(stagenet_hard_forks[0]);
