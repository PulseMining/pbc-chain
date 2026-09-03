// Copyright (c) 2024-2026, Privacy Bank Chain (PBC)
// BSD-3-Clause License (see LICENSE)
//
// PBC Virtual Reward Pool State — Implementation
// See pbc_pools.h for documentation.

#include "pbc_pools.h"
#include <algorithm>
#include "include_base_utils.h"  // TD-6: CHECK_AND_ASSERT_THROW_MES, CHECK_AND_ASSERT_MES

// Rule A2: ASSERT no float/double anywhere in this file.
// CI should grep for float/double and fail if found in consensus modules.

namespace cryptonote
{

// ═══════════════════════════════════════════════════════════════
// pbc_compute_block_split — §19.3 exact integer split
// ═══════════════════════════════════════════════════════════════

pbc_block_split pbc_compute_block_split(uint64_t R, uint64_t F)
{
  pbc_block_split s{};

  // ── R split (order matters: miner & dev first, pools absorbs remainder) ──
  // Rule A1: ALL intermediate products via __uint128_t, cast to uint64_t only at end
  s.miner_R = static_cast<uint64_t>(static_cast<unsigned __int128>(R) * PBC_MINER_SHARE / 1000);   // floor(R × 910 / 1000)
  s.dev_R   = static_cast<uint64_t>(static_cast<unsigned __int128>(R) * PBC_DEV_SHARE   / 1000);   // floor(R × 20  / 1000)
  s.pools_R = R - s.miner_R - s.dev_R;       // absorbs all rounding dust — no multiplication needed

  // Sub-split pools_R among 3 reward pools (§19.3)
  // Shares: deposit=25, insurance=10, fee gets remainder out of total 70
  static_assert(PBC_POOL_TOTAL_SHARE == 70, "Pool shares must sum to 70");
  s.deposit_share   = static_cast<uint64_t>(static_cast<unsigned __int128>(s.pools_R) * PBC_DEPOSIT_POOL_SHARE / PBC_POOL_TOTAL_SHARE);   // floor(pools_R × 25 / 70)
  s.insurance_share = static_cast<uint64_t>(static_cast<unsigned __int128>(s.pools_R) * PBC_INSURANCE_POOL_SHARE / PBC_POOL_TOTAL_SHARE); // floor(pools_R × 10 / 70)
  s.fee_share       = s.pools_R - s.deposit_share - s.insurance_share;              // absorbs sub-split remainder — no multiplication

  // ── F split ──
  s.miner_F = static_cast<uint64_t>(static_cast<unsigned __int128>(F) * PBC_FEE_MINER_SHARE / 1000);  // floor(F × 500 / 1000)
  s.pools_F = F - s.miner_F;                     // remainder to Fee Pool — no multiplication

  // ── Derived ──
  s.total_miner   = s.miner_R + s.miner_F;
  s.total_dev     = s.dev_R;
  s.total_coinbase = s.total_miner + s.total_dev;

  // Conservation assertions (Invariant 2, §19.15)
  // TD-6 §1: Reward split conservation — pools_R absorbs remainder
  assert(s.miner_R + s.dev_R + s.pools_R == R);
  CHECK_AND_ASSERT_THROW_MES(
      s.miner_R + s.dev_R + s.pools_R == R,
      "PBC TD-6 §1: reward conservation violated: miner_R + dev_R + pools_R != R");

  // TD-6 §2: Sub-split conservation — fee_share absorbs remainder
  assert(s.deposit_share + s.fee_share + s.insurance_share == s.pools_R);
  CHECK_AND_ASSERT_THROW_MES(
      s.deposit_share + s.fee_share + s.insurance_share == s.pools_R,
      "PBC TD-6 §2: pools sub-split conservation violated");

  assert(s.miner_F + s.pools_F == F);
  CHECK_AND_ASSERT_THROW_MES(
      s.miner_F + s.pools_F == F,
      "PBC TD-6 §1: fee conservation violated: miner_F + pools_F != F");

  return s;
}

// ═══════════════════════════════════════════════════════════════
// Supply calculations — §19.8
// ═══════════════════════════════════════════════════════════════

uint64_t pbc_calc_circulating_supply(uint64_t already_generated_coins,
                                     const pbc_pool_state& state)
{
  // BUG4-FIX: Supply base must include cumulative fees.
  uint64_t supply_base = already_generated_coins + state.cumulative_fees;
  uint64_t pools_total = state.pool_balances();

  // Overflow check: cumulative_fees should never cause wrap
  if (supply_base < already_generated_coins)
  {
    LOG_ERROR("PBC TRACE FAIL supply_base_overflow:"
      << " agc=" << already_generated_coins
      << " cf=" << state.cumulative_fees
      << " S(wrapped)=" << supply_base);
  }
  CHECK_AND_ASSERT_THROW_MES(supply_base >= already_generated_coins,
      "PBC BUG4: supply_base overflow (agc + cumulative_fees wrapped)");

  if (supply_base < state.total_destroyed)
  {
    LOG_ERROR("PBC TRACE FAIL destroyed_exceeds_supply:"
      << " agc=" << already_generated_coins
      << " cf=" << state.cumulative_fees
      << " S=" << supply_base
      << " destroyed=" << state.total_destroyed
      << " dep=" << state.deposit_pool_balance
      << " fee=" << state.fee_pool_balance
      << " ins=" << state.insurance_pool_balance
      << " P=" << pools_total
      << " vested=" << state.total_vested_outputs
      << " locked=" << state.total_locked_in_deposits
      << " sumW=" << state.deposit_sum_weights);
  }
  CHECK_AND_ASSERT_THROW_MES(supply_base >= state.total_destroyed,
      "PBC TD-6 §10: destroyed exceeds supply base");
  uint64_t coins_total = supply_base - state.total_destroyed;

  // 1) pools must not exceed total existence
  if (coins_total < pools_total)
  {
    LOG_ERROR("PBC TRACE FAIL pools_exceed_existence:"
      << " agc=" << already_generated_coins
      << " cf=" << state.cumulative_fees
      << " S=" << supply_base
      << " destroyed=" << state.total_destroyed
      << " existence=" << coins_total
      << " dep=" << state.deposit_pool_balance
      << " fee=" << state.fee_pool_balance
      << " ins=" << state.insurance_pool_balance
      << " P=" << pools_total
      << " diff=" << (pools_total - coins_total)
      << " vested=" << state.total_vested_outputs
      << " locked=" << state.total_locked_in_deposits
      << " sumW=" << state.deposit_sum_weights);
  }
  CHECK_AND_ASSERT_THROW_MES(coins_total >= pools_total,
      "PBC TD-6 §10: pools exceed existence");

  // 2) NOTE: total_locked_in_deposits tracks principal locked in deposit UTXOs.
  //    This is NOT inside the deposit pool — the deposit pool only holds
  //    reward inflow (25/70 of pool share per block). The principal is a
  //    separate frozen UTXO returned to the depositor at unlock_height.
  //    No conservation relationship between deposit_pool_balance and locked.
  //    (Previous check was incorrect — deposit_pool < locked is normal on
  //    young chains or after large deposits.)

  // 3) vested is outside pools — verify against coins outside pools
  uint64_t coins_outside_pools = coins_total - pools_total;
  if (coins_outside_pools < state.total_vested_outputs)
  {
    LOG_ERROR("PBC TRACE FAIL vested_exceeds_outside:"
      << " agc=" << already_generated_coins
      << " cf=" << state.cumulative_fees
      << " S=" << supply_base
      << " destroyed=" << state.total_destroyed
      << " existence=" << coins_total
      << " P=" << pools_total
      << " outside=" << coins_outside_pools
      << " vested=" << state.total_vested_outputs
      << " diff=" << (state.total_vested_outputs - coins_outside_pools)
      << " dep=" << state.deposit_pool_balance
      << " fee=" << state.fee_pool_balance
      << " ins=" << state.insurance_pool_balance
      << " locked=" << state.total_locked_in_deposits
      << " sumW=" << state.deposit_sum_weights);
  }
  CHECK_AND_ASSERT_THROW_MES(coins_outside_pools >= state.total_vested_outputs,
      "PBC TD-6 §10: vested exceeds outside supply");

  // circulating = coins outside pools minus vested
  // (locked deposits are frozen UTXOs outside pools, counted in coins_outside_pools;
  //  LSM uses locked/circ ratio separately to dampen reward distribution)
  return coins_outside_pools - state.total_vested_outputs;
}

uint64_t pbc_calc_locked_ratio(const pbc_pool_state& state,
                               uint64_t already_generated_coins)
{
  uint64_t circ = pbc_calc_circulating_supply(already_generated_coins, state);
  if (circ == 0)
    return 1000;  // 100% — treat as maximally locked (Rule A4)

  // Rule A1: uint128 intermediate required
  __uint128_t ratio_num = (__uint128_t)state.total_locked_in_deposits * 1000;
  uint64_t raw_ratio = (uint64_t)(ratio_num / (__uint128_t)circ);

  // Rule A4: clamp to [0, 1000]
  return std::min(raw_ratio, (uint64_t)1000);
}

// ═══════════════════════════════════════════════════════════════
// Dynamic fee floor — §19.9
// ═══════════════════════════════════════════════════════════════

uint64_t pbc_calc_min_fee(uint64_t tx_size_bytes,
                          uint64_t base_fee_per_byte,
                          const pbc_pool_state& state,
                          uint64_t already_generated_coins)
{
  uint64_t locked_ratio = pbc_calc_locked_ratio(state, already_generated_coins);

  // fee_multiplier in per-mille: 1000 + locked_ratio, capped at FEE_FLOOR_CAP
  uint64_t fee_multiplier = std::min(
    (uint64_t)PBC_FEE_FLOOR_SCALE + locked_ratio,
    (uint64_t)PBC_FEE_FLOOR_CAP
  );

  // Rule A1: uint128 for safety
  __uint128_t product = (__uint128_t)base_fee_per_byte * (__uint128_t)tx_size_bytes;
  product = product * (__uint128_t)fee_multiplier;
  return (uint64_t)(product / PBC_FEE_FLOOR_SCALE);
}

// ═══════════════════════════════════════════════════════════════
// Weight calculation — §19.5
// ═══════════════════════════════════════════════════════════════

uint64_t pbc_get_tier_multiplier(uint8_t tier)
{
  switch (tier)
  {
    case 0: return PBC_MULT_30D;
    case 1: return PBC_MULT_90D;
    case 2: return PBC_MULT_180D;
    case 3: return PBC_MULT_270D;
    case 4: return PBC_MULT_365D;
    default: return 0;  // invalid tier
  }
}

uint64_t pbc_get_tier_blocks(uint8_t tier)
{
  switch (tier)
  {
    case 0: return PBC_TIER_30D_BLOCKS;
    case 1: return PBC_TIER_90D_BLOCKS;
    case 2: return PBC_TIER_180D_BLOCKS;
    case 3: return PBC_TIER_270D_BLOCKS;
    case 4: return PBC_TIER_365D_BLOCKS;
    default: return 0;
  }
}

uint64_t pbc_calc_weight(uint64_t amount_atomic, uint8_t tier)
{
  // TD-5c: Linear weight eliminates split attack profitability.
  // Before: base = isqrt(amount_atomic) → Σ√ai > √S  (split profitable)
  // After:  base = amount_atomic / COIN → Σai = S     (split neutral)
  uint64_t base_weight = amount_atomic / COIN;  // weight in whole PBC
  uint64_t multiplier = pbc_get_tier_multiplier(tier);
  if (multiplier == 0) return 0;  // invalid tier
  return base_weight * multiplier / 1000;
}

// ═══════════════════════════════════════════════════════════════
// State update — block reward application (Steps 1-2, §19.12)
// ═══════════════════════════════════════════════════════════════

void pbc_apply_block_reward(pbc_pool_state& state, const pbc_block_split& split)
{
  // Step 1: virtual pool allocations from R
  state.deposit_pool_balance    += split.deposit_share;
  state.fee_pool_balance        += split.fee_share;
  state.insurance_pool_balance  += split.insurance_share;

  // Track period inflows for index update (Step 5)
  state.deposit_pool_period_inflow += split.deposit_share;
  state.fee_pool_period_inflow     += split.fee_share;

  // Step 2: fee pool allocation from F
  state.fee_pool_balance         += split.pools_F;
  state.fee_pool_period_inflow   += split.pools_F;

  // TD-6 §4: Overflow detection after addition (defense-in-depth, release)
  // If wrap occurred, balance would be < what we just added.
  CHECK_AND_ASSERT_THROW_MES(state.deposit_pool_balance >= split.deposit_share,
      "PBC TD-6 §4: deposit_pool_balance overflow in apply_block_reward");
  CHECK_AND_ASSERT_THROW_MES(state.fee_pool_balance >= split.fee_share + split.pools_F,
      "PBC TD-6 §4: fee_pool_balance overflow in apply_block_reward");
  CHECK_AND_ASSERT_THROW_MES(state.insurance_pool_balance >= split.insurance_share,
      "PBC TD-6 §4: insurance_pool_balance overflow in apply_block_reward");
}

void pbc_revert_block_reward(pbc_pool_state& state, const pbc_block_split& split)
{
  // Exact reverse of pbc_apply_block_reward
  // TD-6 §4: Non-negativity pre-checks (underflow prevention)
  assert(state.deposit_pool_balance >= split.deposit_share);
  assert(state.fee_pool_balance >= split.fee_share + split.pools_F);
  assert(state.insurance_pool_balance >= split.insurance_share);
  CHECK_AND_ASSERT_THROW_MES(state.deposit_pool_balance >= split.deposit_share,
      "PBC TD-6 §4: revert would underflow deposit_pool_balance");
  CHECK_AND_ASSERT_THROW_MES(state.fee_pool_balance >= split.fee_share + split.pools_F,
      "PBC TD-6 §4: revert would underflow fee_pool_balance");
  CHECK_AND_ASSERT_THROW_MES(state.insurance_pool_balance >= split.insurance_share,
      "PBC TD-6 §4: revert would underflow insurance_pool_balance");

  state.deposit_pool_balance    -= split.deposit_share;
  state.fee_pool_balance        -= split.fee_share;
  state.insurance_pool_balance  -= split.insurance_share;
  state.fee_pool_balance        -= split.pools_F;

  // Revert period inflow tracking
  assert(state.deposit_pool_period_inflow >= split.deposit_share);
  assert(state.fee_pool_period_inflow >= split.fee_share + split.pools_F);
  CHECK_AND_ASSERT_THROW_MES(state.deposit_pool_period_inflow >= split.deposit_share,
      "PBC TD-6 §4: revert would underflow deposit_pool_period_inflow");
  CHECK_AND_ASSERT_THROW_MES(state.fee_pool_period_inflow >= split.fee_share + split.pools_F,
      "PBC TD-6 §4: revert would underflow fee_pool_period_inflow");
  state.deposit_pool_period_inflow -= split.deposit_share;
  state.fee_pool_period_inflow     -= split.fee_share + split.pools_F;
}

// ═══════════════════════════════════════════════════════════════
// Insurance overflow — Step 8, §19.11
// ═══════════════════════════════════════════════════════════════

uint64_t pbc_apply_insurance_overflow(pbc_pool_state& state)
{
  if (state.insurance_pool_balance > PBC_INSURANCE_CAP)
  {
    uint64_t overflow = state.insurance_pool_balance - PBC_INSURANCE_CAP;
    state.insurance_pool_balance -= overflow;
    state.total_destroyed += overflow;
    // TD-6 §4: insurance_pool_balance == PBC_INSURANCE_CAP after overflow
    CHECK_AND_ASSERT_THROW_MES(state.insurance_pool_balance == PBC_INSURANCE_CAP,
        "PBC TD-6 §4: insurance_pool_balance != cap after overflow (logic bug)");
    return overflow;
  }
  return 0;
}

// ═══════════════════════════════════════════════════════════════
// Insurance subsidy — Step 7, §19.12 (period boundary only)
// ═══════════════════════════════════════════════════════════════

uint64_t pbc_apply_insurance_subsidy(pbc_pool_state& state)
{
  if (state.deposit_pool_balance < PBC_MIN_DEPOSIT_POOL)
  {
    // Rule A1: __uint128_t for multiplication
    uint64_t max_subsidy = static_cast<uint64_t>(
      static_cast<unsigned __int128>(state.insurance_pool_balance) * PBC_INSURANCE_SUBSIDY_RATE / 1000);
    uint64_t needed = PBC_MIN_DEPOSIT_POOL - state.deposit_pool_balance;
    uint64_t subsidy = std::min(max_subsidy, needed);
    if (subsidy > 0 && subsidy <= state.insurance_pool_balance)
    {
      state.insurance_pool_balance -= subsidy;
      state.deposit_pool_balance   += subsidy;
      return subsidy;
    }
  }
  return 0;
}

// ═══════════════════════════════════════════════════════════════
// Vesting tracking — Step 9, §19.12
// ═══════════════════════════════════════════════════════════════

void pbc_update_vesting(pbc_pool_state& state, const pbc_vesting_delta& delta)
{
  state.total_vested_outputs += delta.added;
  assert(state.total_vested_outputs >= delta.expired);
  CHECK_AND_ASSERT_THROW_MES(state.total_vested_outputs >= delta.expired,
      "PBC TD-6 §4: vesting revert would underflow total_vested_outputs");
  state.total_vested_outputs -= delta.expired;
}

// ═══════════════════════════════════════════════════════════════
// Locked Supply Multiplier — §7.7 LSM
// ═══════════════════════════════════════════════════════════════

uint64_t pbc_calc_lsm_effective(uint64_t inflow,
                                uint64_t total_locked,
                                uint64_t circulating_supply)
{
  if (inflow == 0) return 0;

  // Compute locked_ratio in per-mille [0, 1000]
  uint64_t locked_ratio;
  if (circulating_supply == 0)
    locked_ratio = 1000;  // Rule A4: treat as max locked
  else
  {
    // Rule A1: uint128 intermediate
    __uint128_t ratio_num = (__uint128_t)total_locked * 1000;
    locked_ratio = (uint64_t)(ratio_num / (__uint128_t)circulating_supply);
    locked_ratio = std::min(locked_ratio, (uint64_t)1000);  // Rule A4: clamp
  }

  if (locked_ratio <= PBC_LSM_THRESHOLD)
    return inflow;  // no dampening below 60%

  // rate_mod = max(1000 - (locked_ratio - 600) * 1000 / 400, 100)
  // All in integer arithmetic (Rule A1, A2)
  uint64_t excess = locked_ratio - PBC_LSM_THRESHOLD;  // [1, 400]
  // excess * 1000 / 400: max is 400*1000/400 = 1000 → fits in uint64
  uint64_t dampening = excess * 1000 / 400;  // floor division
  uint64_t rate_mod;
  if (dampening >= 900)
    rate_mod = PBC_LSM_MIN_RATE;  // floor at 10% = 100 per mille
  else
    rate_mod = 1000 - dampening;

  // effective = inflow * rate_mod / 1000
  // Rule A1: uint128 for safety (inflow can be up to ~10^15)
  __uint128_t product = (__uint128_t)inflow * (__uint128_t)rate_mod;
  return (uint64_t)(product / 1000);
}

// ═══════════════════════════════════════════════════════════════
// Global Index Update — TD-4 (§7.2, §19.6)
// ═══════════════════════════════════════════════════════════════

void pbc_apply_index_update(pbc_pool_state& state,
                            uint64_t eligible_sum_weights,
                            uint64_t already_generated_coins,
                            uint64_t boundary_height)
{
  // If no eligible deposits, inflows stay in pools, no index advancement (§7.2)
  // "If Σw_k = 0: ΔP_k accumulates in the pool, no index advancement."
  // Accumulators are NOT reset — they carry over to next period.
  if (eligible_sum_weights == 0)
  {
    state.last_index_update_height = boundary_height;
    return;
  }

  // ── Compute circulating supply for LSM ──
  uint64_t circ = pbc_calc_circulating_supply(already_generated_coins, state);

  // ── Apply LSM to each inflow (§7.7) ──
  uint64_t effective_deposit_inflow = pbc_calc_lsm_effective(
    state.deposit_pool_period_inflow,
    state.total_locked_in_deposits,
    circ);

  uint64_t effective_fee_inflow = pbc_calc_lsm_effective(
    state.fee_pool_period_inflow,
    state.total_locked_in_deposits,
    circ);

  // ── Compute raw index deltas (Rule A1: uint128, Rule A3: floor) ──
  // δI_P = floor(effective_ΔP × SCALE / Σw_k)
  // δI_F = floor(effective_ΔF × SCALE / Σw_k)
  __uint128_t numerator_P = (__uint128_t)effective_deposit_inflow * (__uint128_t)PBC_SCALE;
  __uint128_t numerator_F = (__uint128_t)effective_fee_inflow     * (__uint128_t)PBC_SCALE;

  __uint128_t delta_dep = numerator_P / (__uint128_t)eligible_sum_weights;
  __uint128_t delta_fee = numerator_F / (__uint128_t)eligible_sum_weights;

  // ── PBC TRACE: INDEX-UPDATE — LSM + delta details ──
  LOG_PRINT_L1("PBC TRACE INDEX-UPDATE h=" << boundary_height
    << " agc=" << already_generated_coins
    << " circ=" << circ
    << " sumW=" << eligible_sum_weights
    << " locked=" << state.total_locked_in_deposits
    << " raw_dep_inflow=" << state.deposit_pool_period_inflow
    << " raw_fee_inflow=" << state.fee_pool_period_inflow
    << " eff_dep_inflow=" << effective_deposit_inflow
    << " eff_fee_inflow=" << effective_fee_inflow
    << " delta_dep=" << pbc_uint128_to_str(delta_dep)
    << " delta_fee=" << pbc_uint128_to_str(delta_fee)
    << " old_dep_idx=" << pbc_uint128_to_str(state.global_deposit_index)
    << " old_fee_idx=" << pbc_uint128_to_str(state.global_fee_index));

  // BUG1-FIX: indices are now __uint128_t — no clamping needed.
  // uint128 gives ~27M years before overflow at current emission rate.
  __uint128_t old_deposit_index = state.global_deposit_index;
  __uint128_t old_fee_index     = state.global_fee_index;

  state.global_deposit_index += delta_dep;
  state.global_fee_index     += delta_fee;

  // TD-6 §5: Index monotonicity — I_new >= I_old (Whitepaper §19.6)
  CHECK_AND_ASSERT_THROW_MES(
      state.global_deposit_index >= old_deposit_index,
      "PBC TD-6 §5: global_deposit_index not monotonic (overflow?)");
  CHECK_AND_ASSERT_THROW_MES(
      state.global_fee_index >= old_fee_index,
      "PBC TD-6 §5: global_fee_index not monotonic (overflow?)");

  // ── Reset period accumulators ──
  state.deposit_pool_period_inflow = 0;
  state.fee_pool_period_inflow     = 0;

  // ── Update tracking ──
  state.last_index_update_height = boundary_height;
}

// ═══════════════════════════════════════════════════════════════
// Invariant checks — §19.15
// ═══════════════════════════════════════════════════════════════

bool pbc_check_conservation(uint64_t already_generated_coins,
                            const pbc_pool_state& state)
{
  // BUG4-FIX: Supply base must include cumulative fees.
  uint64_t supply_base = already_generated_coins + state.cumulative_fees;
  uint64_t pools_total = state.pool_balances();

  // Overflow safety
  if (supply_base < already_generated_coins)
  {
    LOG_ERROR("PBC CONSERVATION FAIL #0 supply_base_overflow:"
      << " agc=" << already_generated_coins
      << " cf=" << state.cumulative_fees
      << " S(wrapped)=" << supply_base);
    return false;  // wrapped
  }

  if (supply_base < state.total_destroyed)
  {
    LOG_ERROR("PBC CONSERVATION FAIL #1 destroyed_exceeds_S:"
      << " agc=" << already_generated_coins
      << " cf=" << state.cumulative_fees
      << " S=" << supply_base
      << " destroyed=" << state.total_destroyed
      << " dep=" << state.deposit_pool_balance
      << " fee=" << state.fee_pool_balance
      << " ins=" << state.insurance_pool_balance
      << " P=" << pools_total
      << " vested=" << state.total_vested_outputs
      << " locked=" << state.total_locked_in_deposits);
    return false;
  }
  uint64_t coins_total = supply_base - state.total_destroyed;

  // 1) pools must not exceed total existence
  if (coins_total < pools_total)
  {
    LOG_ERROR("PBC CONSERVATION FAIL #2 pools_exceed_existence:"
      << " agc=" << already_generated_coins
      << " cf=" << state.cumulative_fees
      << " S=" << supply_base
      << " destroyed=" << state.total_destroyed
      << " existence=" << coins_total
      << " dep=" << state.deposit_pool_balance
      << " fee=" << state.fee_pool_balance
      << " ins=" << state.insurance_pool_balance
      << " P=" << pools_total
      << " diff=" << (pools_total - coins_total)
      << " vested=" << state.total_vested_outputs
      << " locked=" << state.total_locked_in_deposits);
    return false;
  }

  // 2) NOTE: total_locked_in_deposits tracks principal locked in deposit UTXOs.
  //    This is NOT inside the deposit pool — the deposit pool only holds
  //    reward inflow (25/70 of pool share per block). The principal is a
  //    separate frozen UTXO returned to the depositor at unlock_height.
  //    No conservation relationship between deposit_pool_balance and locked.
  //    (Previous check was incorrect — deposit_pool < locked is normal.)

  // 3) vested is outside pools — verify against coins outside pools
  uint64_t coins_outside_pools = coins_total - pools_total;
  if (coins_outside_pools < state.total_vested_outputs)
  {
    LOG_ERROR("PBC CONSERVATION FAIL #4 vested_exceeds_outside:"
      << " agc=" << already_generated_coins
      << " cf=" << state.cumulative_fees
      << " S=" << supply_base
      << " destroyed=" << state.total_destroyed
      << " existence=" << coins_total
      << " P=" << pools_total
      << " outside=" << coins_outside_pools
      << " vested=" << state.total_vested_outputs
      << " diff=" << (state.total_vested_outputs - coins_outside_pools)
      << " dep=" << state.deposit_pool_balance
      << " fee=" << state.fee_pool_balance
      << " ins=" << state.insurance_pool_balance
      << " locked=" << state.total_locked_in_deposits);
    return false;
  }

  return true;
}

bool pbc_check_block_split(uint64_t R, uint64_t F, const pbc_block_split& split)
{
  // Invariant 2: exact conservation per block
  if (split.miner_R + split.dev_R + split.pools_R != R) return false;
  if (split.deposit_share + split.fee_share + split.insurance_share != split.pools_R) return false;
  if (split.miner_F + split.pools_F != F) return false;
  return true;
}

bool pbc_check_non_negativity(const pbc_pool_state& state)
{
  // Invariant 3: all uint64 fields are non-negative by definition.
  // This check exists for documentation completeness.
  // In practice, we assert before any subtraction that the result won't underflow.
  (void)state;
  return true;
}

} // namespace cryptonote
