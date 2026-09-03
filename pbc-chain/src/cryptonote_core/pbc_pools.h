// Copyright (c) 2024-2026, Privacy Bank Chain (PBC)
// BSD-3-Clause License (see LICENSE)
//
// PBC Virtual Reward Pool State Management
// Whitepaper §19.2–§19.12, Phase 1 consensus feature
//
// This module manages the three virtual reward pools:
//   - Term Deposit Pool  (2.5% of R)
//   - Fee Pool            (3.5% of R + 50% of F)
//   - Insurance Pool      (1.0% of R + penalties + deposit fees)
//
// All balances are uint64_t atomic units. No floating point.
// All intermediate multiplications use __uint128_t (Rule A1).
// All divisions are floor (Rule A3).
//
// Pool state is persisted in LMDB via the properties table and
// is fully deterministic: rebuildable from genesis by replaying
// all blocks.

#pragma once

#include <cstdint>
#include <cassert>
#include <cstdio>
#include <string>
#include <cstring>
#include "cryptonote_config.h"
#include "crypto/hash.h"

namespace cryptonote
{

// ═══════════════════════════════════════════════════════════════
// TD-6 §6: Compile-time SCALE safety check (Whitepaper §19.6)
// ═══════════════════════════════════════════════════════════════
static_assert(PBC_SCALE == 1000000000000000000ULL,
              "PBC SCALE must be exactly 1e18 — consensus-critical constant");

// Hardening: compile-time guarantee that __uint128_t is 16 bytes on this platform
static_assert(sizeof(__uint128_t) == 16,
              "uint128 must be exactly 16 bytes — LMDB pack/unpack depends on this");

// ═══════════════════════════════════════════════════════════════
// Utility: uint128 → decimal string (for logging & RPC)
// ═══════════════════════════════════════════════════════════════
inline std::string pbc_uint128_to_str(__uint128_t v)
{
  if (v == 0) return "0";
  char buf[40]; // uint128 max is 39 digits
  int pos = 39;
  buf[pos] = '\0';
  while (v > 0) {
    buf[--pos] = '0' + (int)(v % 10);
    v /= 10;
  }
  return std::string(&buf[pos]);
}

// ═══════════════════════════════════════════════════════════════
// Pool State — the 5 supply-accounting variables (§19.8)
// plus per-pool balances and period tracking
// ═══════════════════════════════════════════════════════════════

struct pbc_pool_state
{
  // --- Virtual reward pool balances ---
  uint64_t deposit_pool_balance  = 0;  // Term Deposit Pool
  uint64_t fee_pool_balance      = 0;  // Fee Pool
  uint64_t insurance_pool_balance = 0; // Insurance Pool

  // --- Pending interest rewards (claimed but not yet withdrawn) ---
  uint64_t pending_rewards_total = 0; // Σ accumulated_reward across deposits not yet withdrawn

  // --- Supply accounting ---
  uint64_t total_destroyed         = 0;  // cumulative insurance overflow
  uint64_t total_locked_in_deposits = 0; // Σ active deposit amounts
  uint64_t total_vested_outputs    = 0;  // Σ unvested coinbase outputs

  // BUG4-FIX: Track cumulative TX fees that entered pool/coinbase split.
  // Fees are recycled coins (already in agc from original emission), but
  // pools absorb pools_F and coinbase absorbs miner_F — both unaccounted
  // in agc. Without this, conservation check fails: cie - vested = -Σ(F).
  // supply_base = agc + cumulative_fees restores the balance.
  uint64_t cumulative_fees = 0;

  // --- Global Indices (§19.6) ---
  // BUG1-FIX: uint64→uint128. With SCALE=10^18, a single period's δI can reach ~10^28,
  // far exceeding uint64_max (1.84×10^19). uint128 gives ~27M years before overflow.
  __uint128_t global_deposit_index = 0;  // scaled by SCALE = 10^18
  __uint128_t global_fee_index     = 0;  // scaled by SCALE = 10^18

  // --- Period tracking ---
  // Inflows accumulated during current distribution period,
  // applied at next period boundary (Step 5, §19.12)
  uint64_t deposit_pool_period_inflow = 0;
  uint64_t fee_pool_period_inflow     = 0;

  // --- Term Deposit aggregate (TD-1, §19.5) ---
  uint64_t deposit_sum_weights = 0;  // Σw = sum of all active deposit weights

  // --- Index update tracking (TD-4) ---
  uint64_t last_index_update_height = 0;  // height of last index update boundary

  // --- Helper: total pool balances ---
  uint64_t pool_balances() const {
    return deposit_pool_balance + fee_pool_balance + insurance_pool_balance;
  }
};

// ═══════════════════════════════════════════════════════════════
// Block reward split result (§19.3)
// ═══════════════════════════════════════════════════════════════

struct pbc_block_split
{
  // From R (block reward)
  uint64_t miner_R;
  uint64_t dev_R;
  uint64_t pools_R;          // total virtual from R
  uint64_t deposit_share;    // sub-split of pools_R
  uint64_t fee_share;        // sub-split of pools_R (absorbs remainder)
  uint64_t insurance_share;  // sub-split of pools_R

  // From F (transaction fees)
  uint64_t miner_F;
  uint64_t pools_F;          // to Fee Pool

  // Derived
  uint64_t total_miner;      // miner_R + miner_F (4 vesting outputs)
  uint64_t total_dev;        // dev_R (1 output)
  uint64_t total_coinbase;   // total_miner + total_dev (actual coins created)
};

// ═══════════════════════════════════════════════════════════════
// Vesting delta — tracks change in vested outputs per block
// ═══════════════════════════════════════════════════════════════

struct pbc_vesting_delta
{
  uint64_t added   = 0;  // new coinbase vesting outputs this block
  uint64_t expired = 0;  // outputs that unlocked at this height
};

// ═══════════════════════════════════════════════════════════════
// Pure functions — deterministic arithmetic (§19.3)
// ═══════════════════════════════════════════════════════════════

// Compute the exact block reward split with remainder absorption.
// R = theoretical block reward, F = total transaction fees.
// All divisions are floor. Remainder goes to pools (never miner/dev).
// INVARIANT: split.miner_R + split.dev_R + split.pools_R == R
// INVARIANT: split.miner_F + split.pools_F == F
pbc_block_split pbc_compute_block_split(uint64_t R, uint64_t F);

// Compute circulating supply (§19.8)
// Returns: already_generated_coins - pool_balances - total_destroyed
//          - total_locked_in_deposits - total_vested_outputs
uint64_t pbc_calc_circulating_supply(uint64_t already_generated_coins,
                                     const pbc_pool_state& state);

// Compute locked ratio in per-mille [0, 1000] (§19.8)
// Uses __uint128_t intermediate (Rule A1)
uint64_t pbc_calc_locked_ratio(const pbc_pool_state& state,
                               uint64_t already_generated_coins);

// Compute dynamic fee floor (§19.9)
// Returns min_fee for a transaction of tx_size_bytes
uint64_t pbc_calc_min_fee(uint64_t tx_size_bytes,
                          uint64_t base_fee_per_byte,
                          const pbc_pool_state& state,
                          uint64_t already_generated_coins);

// Deposit weight calculation (§19.5) — linear model (TD-5c)
// tier: 0=30d, 1=90d, 2=180d, 3=270d, 4=365d
uint64_t pbc_calc_weight(uint64_t amount_atomic, uint8_t tier);

// Get duration multiplier for a tier (per-mille)
uint64_t pbc_get_tier_multiplier(uint8_t tier);

// Get lock duration in blocks for a tier
uint64_t pbc_get_tier_blocks(uint8_t tier);

// ═══════════════════════════════════════════════════════════════
// State update functions — called during block processing
// ═══════════════════════════════════════════════════════════════

// Apply block reward split to pool state (Steps 1-2 of §19.12)
// Updates: deposit_pool_balance, fee_pool_balance, insurance_pool_balance,
//          deposit_pool_period_inflow, fee_pool_period_inflow
void pbc_apply_block_reward(pbc_pool_state& state, const pbc_block_split& split);

// Revert block reward split from pool state (for pop_block / reorg)
void pbc_revert_block_reward(pbc_pool_state& state, const pbc_block_split& split);

// Apply insurance overflow check (Step 8 of §19.12)
// Returns overflow amount (0 if no overflow)
uint64_t pbc_apply_insurance_overflow(pbc_pool_state& state);

// Apply insurance subsidy check (Step 7 of §19.12)
// Only at period boundaries. Returns subsidy amount.
uint64_t pbc_apply_insurance_subsidy(pbc_pool_state& state);

// Update vesting tracking
void pbc_update_vesting(pbc_pool_state& state, const pbc_vesting_delta& delta);

// ═══════════════════════════════════════════════════════════════
// Global Index Update — TD-4 (§7.2, §19.6)
// Applied at period boundaries: height % 720 == 0 && height > 0
// BEFORE the block reward split for that block.
// ═══════════════════════════════════════════════════════════════

// Snapshot of index state for reorg-safe reversal
struct pbc_index_snapshot
{
  __uint128_t global_deposit_index;       // BUG1-FIX: uint64→uint128
  __uint128_t global_fee_index;           // BUG1-FIX: uint64→uint128
  uint64_t deposit_pool_period_inflow;
  uint64_t fee_pool_period_inflow;
  uint64_t last_index_update_height;
};

static constexpr size_t PBC_INDEX_SNAPSHOT_PACKED_SIZE = 56;  // 2×16 + 3×8 bytes

// Hardening: compile-time packed size coherence check
static_assert(PBC_INDEX_SNAPSHOT_PACKED_SIZE == 2*16 + 3*8,
    "snapshot packed size must be 2×uint128(16) + 3×uint64(8)");

inline void pbc_pack_index_snapshot(const pbc_index_snapshot& snap, uint8_t buf[PBC_INDEX_SNAPSHOT_PACKED_SIZE])
{
  memcpy(buf +  0, &snap.global_deposit_index,      16);
  memcpy(buf + 16, &snap.global_fee_index,           16);
  memcpy(buf + 32, &snap.deposit_pool_period_inflow,  8);
  memcpy(buf + 40, &snap.fee_pool_period_inflow,      8);
  memcpy(buf + 48, &snap.last_index_update_height,    8);
}

inline void pbc_unpack_index_snapshot(const uint8_t buf[PBC_INDEX_SNAPSHOT_PACKED_SIZE], pbc_index_snapshot& snap)
{
  memcpy(&snap.global_deposit_index,       buf +  0, 16);
  memcpy(&snap.global_fee_index,           buf + 16, 16);
  memcpy(&snap.deposit_pool_period_inflow, buf + 32,  8);
  memcpy(&snap.fee_pool_period_inflow,     buf + 40,  8);
  memcpy(&snap.last_index_update_height,   buf + 48,  8);
}

// Compute Locked Supply Multiplier effective inflow (§7.7 LSM)
// Returns the effective inflow after LSM dampening.
// All arithmetic in uint128, no float. (Rule A1, A2)
//
// If locked_ratio > 600 (60%):
//   rate_mod = max(1000 - (locked_ratio - 600) * 1000 / 400, 100)
//   effective = inflow * rate_mod / 1000
// Else:
//   effective = inflow
uint64_t pbc_calc_lsm_effective(uint64_t inflow,
                                uint64_t total_locked,
                                uint64_t circulating_supply);

// Apply global index update at period boundary.
// Computes δI_P and δI_F, increments indices, resets accumulators.
// eligible_sum_weights = Σw_k from deposits where:
//   created_height < boundary_height AND unlock_height > boundary_height
// already_generated_coins: for LSM calculation
// Does NOTHING if eligible_sum_weights == 0 (inflows stay in pools).
void pbc_apply_index_update(pbc_pool_state& state,
                            uint64_t eligible_sum_weights,
                            uint64_t already_generated_coins,
                            uint64_t boundary_height);

// ═══════════════════════════════════════════════════════════════
// Debug invariant checks (§19.15) — MUST pass at every block
// ═══════════════════════════════════════════════════════════════

// Check master conservation invariant (Invariant 1)
bool pbc_check_conservation(uint64_t already_generated_coins,
                            const pbc_pool_state& state);

// Check block reward conservation (Invariant 2)
bool pbc_check_block_split(uint64_t R, uint64_t F, const pbc_block_split& split);

// Check non-negativity (Invariant 3) — always true for uint64 if no underflow
bool pbc_check_non_negativity(const pbc_pool_state& state);

// ═══════════════════════════════════════════════════════════════
// LMDB property keys for pool state persistence
// ═══════════════════════════════════════════════════════════════

#define PBC_PROP_DEPOSIT_POOL_BALANCE       "pbc_deposit_pool_balance"
#define PBC_PROP_FEE_POOL_BALANCE           "pbc_fee_pool_balance"
#define PBC_PROP_INSURANCE_POOL_BALANCE     "pbc_insurance_pool_balance"
#define PBC_PROP_PENDING_REWARDS_TOTAL     "pbc_pending_rewards_total"
#define PBC_PROP_TOTAL_DESTROYED            "pbc_total_destroyed"
#define PBC_PROP_TOTAL_LOCKED_DEPOSITS      "pbc_total_locked_in_deposits"
#define PBC_PROP_TOTAL_VESTED_OUTPUTS       "pbc_total_vested_outputs"
#define PBC_PROP_GLOBAL_DEPOSIT_INDEX       "pbc_global_deposit_index"
#define PBC_PROP_GLOBAL_FEE_INDEX           "pbc_global_fee_index"
#define PBC_PROP_DEPOSIT_PERIOD_INFLOW      "pbc_deposit_period_inflow"
#define PBC_PROP_FEE_PERIOD_INFLOW          "pbc_fee_period_inflow"
#define PBC_PROP_DEPOSIT_SUM_WEIGHTS        "pbc_deposit_sum_weights"
#define PBC_PROP_LAST_INDEX_UPDATE_HEIGHT   "pbc_last_index_update_height"
#define PBC_PROP_CUMULATIVE_FEES           "pbc_cumulative_fees"

// ═══════════════════════════════════════════════════════════════
// Per-block delta keys — for exact reorg reversal
// ═══════════════════════════════════════════════════════════════
//
// Problem: Insurance overflow destroys coins (total_destroyed += X)
// and insurance subsidy transfers between pools. Both are irreversible
// without knowing the exact delta that was applied at that height.
// A deep reorg crossing these events would cause state divergence.
//
// Solution: Store the delta per block height. On pop_block, read it
// back, reverse the operation, and delete the key.
//
// Key format: "pbc_ovf_XXXXXXXXXXXX" / "pbc_sub_XXXXXXXXXXXX"
// where X is 12-digit zero-padded height. Only stored when non-zero.
//
// Space: overflow is rare (insurance must exceed cap), subsidy is
// at most every PBC_DISTRIBUTION_PERIOD blocks. ~33 bytes per entry.

#define PBC_DELTA_KEY_PREFIX_OVF    "pbc_ovf_"
#define PBC_DELTA_KEY_PREFIX_SUB    "pbc_sub_"
#define PBC_DELTA_KEY_PREFIX_IDX    "pbc_idx_"   // TD-4: index update snapshot
#define PBC_DELTA_KEY_PREFIX_CLM    "pbc_clm_"   // TD-5: claim delta per deposit
// PF: withdraw delta per TX (payout materialization)
#define PBC_DELTA_KEY_PREFIX_WDR    "pbc_wdr_"
// FIX-12: Per-block vesting coinbase storage for tier expiry tracking
#define PBC_DELTA_KEY_PREFIX_VM     "pbc_vm_"    // total_miner per block
#define PBC_DELTA_KEY_PREFIX_VD     "pbc_vd_"    // total_dev per block

// TD-5: Key helper for claim deltas (stored in property table, not deposits table)
// Suffix: "_rd" reward_dep(u64), "_rf" reward_fee(u64),
//         "_di" prev_dep_idx(u128), "_fi" prev_fee_idx(u128),
//         "_lh" prev_last_claim_height(u64), "_ar" prev_accumulated_reward(u64)
inline std::string pbc_claim_key(const crypto::hash& claim_tx_id, const char* suffix)
{
  // Full 32-byte hash as hex (64 chars) — guaranteed unique per TX
  const uint8_t* p = reinterpret_cast<const uint8_t*>(&claim_tx_id);
  char hex[65];
  for (int i = 0; i < 32; ++i)
    snprintf(hex + i * 2, 3, "%02x", p[i]);
  hex[64] = '\0';
  return std::string(PBC_DELTA_KEY_PREFIX_CLM) + hex + suffix;
}

// PF: Key helper for TERM_WITHDRAW deltas (stored in property table)
// Suffix: "_ar" prev_accumulated_reward(u64)
inline std::string pbc_withdraw_key(const crypto::hash& withdraw_tx_id, const char* suffix)
{
  const uint8_t* p = reinterpret_cast<const uint8_t*>(&withdraw_tx_id);
  char hex[65];
  for (int i = 0; i < 32; ++i)
    snprintf(hex + i * 2, 3, "%02x", p[i]);
  hex[64] = '\0';
  return std::string(PBC_DELTA_KEY_PREFIX_WDR) + hex + suffix;
}
// Per-field snapshot keys
// DI/FI: stored as uint128 (16 bytes) via set_property_uint128
// DA/FA/LH: stored as uint64 (8 bytes) via set_property_uint64
#define PBC_DELTA_KEY_IDX_DI       "pbc_ixdi"   // global_deposit_index before update (uint128)
#define PBC_DELTA_KEY_IDX_FI       "pbc_ixfi"   // global_fee_index before update (uint128)
#define PBC_DELTA_KEY_IDX_DA       "pbc_ixda"   // deposit_pool_period_inflow before update
#define PBC_DELTA_KEY_IDX_FA       "pbc_ixfa"   // fee_pool_period_inflow before update
#define PBC_DELTA_KEY_IDX_LH       "pbc_ixlh"   // last_index_update_height before update

// Format a height-keyed property name for per-block deltas
// Returns e.g. "pbc_ovf_000000001234" for height 1234
inline std::string pbc_delta_key(const char* prefix, uint64_t height)
{
  char buf[32];
  snprintf(buf, sizeof(buf), "%s%012lu", prefix, (unsigned long)height);
  return std::string(buf);
}

} // namespace cryptonote
