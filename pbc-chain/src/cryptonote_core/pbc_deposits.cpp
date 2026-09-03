// Copyright (c) 2024-2026, Privacy Bank Chain (PBC)
// BSD-3-Clause License (see LICENSE)
//
// PBC Term Deposit Record — TD-1 storage + TD-2 consensus validation + TD-3 RCT verification

#include "pbc_deposits.h"
#include "pbc_pools.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"   // TD-8: check_signature, cn_fast_hash, check_key
#include "crypto/pqc/pqc_dilithium.h" // Problem 2: Dilithium co-signature verification
#include "ringct/rctOps.h"  // TD-3: rct::commit(), rct::zero()
#include <algorithm>  // std::sort (TD-8)

// Rule A2: ASSERT no float/double anywhere in this file.
// CI should grep for float/double and fail if found in consensus modules.

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "pbc.deposits"

namespace cryptonote
{

// ═══════════════════════════════════════════════════════════════
// TD-1 parse (kept for compatibility, used in non-consensus paths)
// ═══════════════════════════════════════════════════════════════

bool pbc_parse_deposit_from_tx(const transaction& tx,
                               uint64_t block_height,
                               pbc_deposit_record& rec)
{
  std::vector<tx_extra_field> fields;
  if (!parse_tx_extra(tx.extra, fields))
    return false;

  // Must have PBC TX type tag
  tx_extra_pbc_tx_type type_field;
  if (!find_tx_extra_field_by_type(fields, type_field))
    return false;

  // Must be TERM_DEPOSIT
  if (type_field.type != PBC_TX_TYPE_TERM_DEPOSIT)
    return false;

  // Must have deposit info
  tx_extra_pbc_deposit_info info;
  if (!find_tx_extra_field_by_type(fields, info))
  {
    LOG_PRINT_L1("PBC: TERM_DEPOSIT TX missing deposit_info in extra");
    return false;
  }

  // Tier must be valid (0-4)
  if (info.tier > 4)
  {
    LOG_PRINT_L1("PBC: TERM_DEPOSIT TX has invalid tier=" << (unsigned)info.tier);
    return false;
  }

  // Compute weight using existing helper (pbc_pools.h)
  uint64_t weight = pbc_calc_weight(info.amount, info.tier);

  rec.amount         = info.amount;
  rec.created_height = block_height;
  rec.unlock_height  = info.unlock_height;
  rec.tier           = info.tier;
  rec.weight         = weight;

  return true;
}

// ═══════════════════════════════════════════════════════════════
// TD-2: Consensus-critical deposit validation (§7, §19.2, §19.5)
//
// This function is the SOLE gatekeeper for deposit acceptance.
// Any deposit TX that passes this function WILL be stored in LMDB
// and affect Σw. Any that fails MUST cause block rejection.
//
// Rule A2: No float/double.
// All checks use uint64_t comparisons only.
// ═══════════════════════════════════════════════════════════════

pbc_deposit_result pbc_validate_deposit_tx(
    const transaction& tx,
    uint64_t block_height,
    pbc_deposit_record& rec_out,
    std::string& fail_reason)
{
  // ── Step 0: Parse tx_extra ──
  std::vector<tx_extra_field> fields;
  if (!parse_tx_extra(tx.extra, fields))
    return PBC_DEPOSIT_NOT_APPLICABLE;

  // ── Step 1: Check for PBC TX type tag ──
  tx_extra_pbc_tx_type type_field;
  if (!find_tx_extra_field_by_type(fields, type_field))
    return PBC_DEPOSIT_NOT_APPLICABLE;  // not a PBC TX at all

  // Not a deposit? Not our concern.
  if (type_field.type != PBC_TX_TYPE_TERM_DEPOSIT)
    return PBC_DEPOSIT_NOT_APPLICABLE;

  // ════════════════════════════════════════════════════════════
  // FROM HERE: This TX declares itself as TERM_DEPOSIT.
  // ALL failures below are CONSENSUS-CRITICAL → block rejected.
  // ════════════════════════════════════════════════════════════

  // ── Check 1: Uniqueness of tx_type tag ──
  // A valid deposit TX must have exactly ONE pbc_tx_type in tx_extra.
  {
    size_t type_count = 0;
    for (const auto& f : fields)
      if (f.type() == typeid(tx_extra_pbc_tx_type))
        ++type_count;
    if (type_count != 1)
    {
      fail_reason = "multiple pbc_tx_type tags in tx_extra (" + std::to_string(type_count) + ")";
      return PBC_DEPOSIT_INVALID;
    }
  }

  // ── Check 2: Uniqueness + presence of deposit_info ──
  tx_extra_pbc_deposit_info info;
  {
    size_t info_count = 0;
    for (const auto& f : fields)
      if (f.type() == typeid(tx_extra_pbc_deposit_info))
        ++info_count;
    if (info_count != 1)
    {
      fail_reason = "expected exactly 1 deposit_info tag, found " + std::to_string(info_count);
      return PBC_DEPOSIT_INVALID;
    }
    if (!find_tx_extra_field_by_type(fields, info))
    {
      fail_reason = "failed to extract deposit_info from tx_extra";
      return PBC_DEPOSIT_INVALID;
    }
  }

  // ── Check 3: Tier ∈ [0,4] (§7.5, §19.2) ──
  if (info.tier > 4)
  {
    fail_reason = "tier " + std::to_string(info.tier) + " out of valid range [0,4]";
    return PBC_DEPOSIT_INVALID;
  }

  // ── Check 4: Minimum deposit amount (§7.7, §19.2: 10 PBC) ──
  if (info.amount < PBC_MIN_DEPOSIT_AMOUNT)
  {
    fail_reason = "deposit amount " + std::to_string(info.amount)
                + " below minimum " + std::to_string(PBC_MIN_DEPOSIT_AMOUNT);
    return PBC_DEPOSIT_INVALID;
  }

  // ── Check 5: unlock_height coherence (§7.5, §19.2) ──
  // unlock_height must be >= block_height + tier_lock_duration
  uint64_t tier_blocks = pbc_get_tier_blocks(info.tier);
  if (tier_blocks == 0)
  {
    // Should never happen if tier ∈ [0,4], but defense-in-depth
    fail_reason = "pbc_get_tier_blocks returned 0 for tier " + std::to_string(info.tier);
    return PBC_DEPOSIT_INVALID;
  }

  // Check for overflow BEFORE addition (defense-in-depth, Rule A1)
  if (block_height > UINT64_MAX - tier_blocks)
  {
    fail_reason = "overflow computing min_unlock_height";
    return PBC_DEPOSIT_INVALID;
  }

  uint64_t min_unlock = block_height + tier_blocks;  // safe, overflow checked above

  if (info.unlock_height < min_unlock)
  {
    fail_reason = "unlock_height " + std::to_string(info.unlock_height)
                + " < required minimum " + std::to_string(min_unlock)
                + " (height=" + std::to_string(block_height)
                + " + tier_blocks=" + std::to_string(tier_blocks) + ")";
    return PBC_DEPOSIT_INVALID;
  }

  // ── Check 5b: unlock_height upper bound (anti over-extension) ──
  // unlock_height must be <= block_height + tier_blocks + PBC_DEPOSIT_UNLOCK_MAX_MARGIN.
  // The wallet sets unlock_height = creation + tier_blocks + (small margin << MAX_MARGIN);
  // the extra MAX_MARGIN absorbs mempool inclusion drift. Without this cap, a modified
  // wallet could inflate unlock_height to keep earning rewards beyond its tier at the
  // expense of other depositors (reward eligibility is: unlock_height > current_height).
  if (min_unlock > UINT64_MAX - PBC_DEPOSIT_UNLOCK_MAX_MARGIN)
  {
    fail_reason = "overflow computing max_unlock_height";
    return PBC_DEPOSIT_INVALID;
  }

  uint64_t max_unlock = min_unlock + PBC_DEPOSIT_UNLOCK_MAX_MARGIN;  // safe, overflow checked above

  if (info.unlock_height > max_unlock)
  {
    fail_reason = "unlock_height " + std::to_string(info.unlock_height)
                + " > allowed maximum " + std::to_string(max_unlock)
                + " (height=" + std::to_string(block_height)
                + " + tier_blocks=" + std::to_string(tier_blocks)
                + " + max_margin=" + std::to_string((uint64_t)PBC_DEPOSIT_UNLOCK_MAX_MARGIN) + ")";
    return PBC_DEPOSIT_INVALID;
  }

  // ── Check 6: Weight must be > 0 (§19.5) ──
  // weight = (amount / COIN) * multiplier / 1000  (linear model, TD-5c)
  // With amount >= 10 PBC (10^13) and multiplier >= 1000,
  // weight = 10 * 1000 / 1000 = 10 > 0
  // This check is defense-in-depth.
  uint64_t weight = pbc_calc_weight(info.amount, info.tier);
  if (weight == 0)
  {
    fail_reason = "computed weight is 0 for amount=" + std::to_string(info.amount)
                + " tier=" + std::to_string(info.tier);
    return PBC_DEPOSIT_INVALID;
  }

  // ── Check 7: Owner identity + proof of ownership (TD-8) ──
  // A valid deposit MUST carry a stable owner_spend_pubkey in tx_extra (tag 0x54)
  // and a valid signature (tag 0x55) proving the depositor controls the
  // corresponding spend secret key. This identity is used for
  // PBC_MAX_DEPOSITS_PER_ADDR enforcement (anti-split).
  // The signature message includes all key images (preventing cross-TX replay)
  // plus the deposit parameters (amount, unlock_height, tier).
  {
    // 7a: Extract owner_spend_pubkey from tx_extra (tag 0x54) — exactly one
    {
      size_t owner_key_count = 0;
      for (const auto& f : fields)
        if (f.type() == typeid(tx_extra_pbc_owner_key))
          ++owner_key_count;
      if (owner_key_count != 1)
      {
        fail_reason = "expected exactly 1 pbc_owner_key tag, found " + std::to_string(owner_key_count);
        return PBC_DEPOSIT_INVALID;
      }
    }
    tx_extra_pbc_owner_key owner_field;
    if (!find_tx_extra_field_by_type(fields, owner_field))
    {
      fail_reason = "missing pbc_owner_key (tag 0x54) in tx_extra";
      return PBC_DEPOSIT_INVALID;
    }

    // 7b: Extract owner_sig from tx_extra (tag 0x55) — exactly one
    {
      size_t owner_sig_count = 0;
      for (const auto& f : fields)
        if (f.type() == typeid(tx_extra_pbc_owner_sig))
          ++owner_sig_count;
      if (owner_sig_count != 1)
      {
        fail_reason = "expected exactly 1 pbc_owner_sig tag, found " + std::to_string(owner_sig_count);
        return PBC_DEPOSIT_INVALID;
      }
    }
    tx_extra_pbc_owner_sig sig_field;
    if (!find_tx_extra_field_by_type(fields, sig_field))
    {
      fail_reason = "missing pbc_owner_sig (tag 0x55) in tx_extra";
      return PBC_DEPOSIT_INVALID;
    }

    // 7c: Null check
    if (owner_field.owner_spend_pubkey == crypto::null_pkey)
    {
      fail_reason = "owner_spend_pubkey is null (all zeros)";
      return PBC_DEPOSIT_INVALID;
    }

    // 7d: Valid curve point check (defense in depth)
    if (!crypto::check_key(owner_field.owner_spend_pubkey))
    {
      fail_reason = "owner_spend_pubkey is not a valid curve point";
      return PBC_DEPOSIT_INVALID;
    }

    // 7e: Rebuild deterministic message and verify signature
    // msg = H(PBC_DEPOSIT_OWNER_MSG_PREFIX || key_images_from_vin || amount || unlock_height || tier)
    // Key images bind the signature to THIS specific TX (prevents replay).
    crypto::hash msg_hash;
    {
      std::vector<crypto::key_image> key_images;
      key_images.reserve(tx.vin.size());
      for (const auto& vin_entry : tx.vin)
      {
        if (vin_entry.type() == typeid(txin_to_key))
        {
          const auto& in = boost::get<txin_to_key>(vin_entry);
          key_images.push_back(in.k_image);
        }
      }
      std::sort(key_images.begin(), key_images.end(),
        [](const crypto::key_image& a, const crypto::key_image& b)
        {
          return std::memcmp(&a, &b, sizeof(crypto::key_image)) < 0;
        });

      std::string msg_data(PBC_DEPOSIT_OWNER_MSG_PREFIX);
      for (const auto& ki : key_images)
        msg_data.append(reinterpret_cast<const char*>(&ki), sizeof(crypto::key_image));

      uint64_t le_amount = info.amount;
      uint64_t le_unlock = info.unlock_height;
      uint8_t  le_tier   = info.tier;
      msg_data.append(reinterpret_cast<const char*>(&le_amount), 8);
      msg_data.append(reinterpret_cast<const char*>(&le_unlock), 8);
      msg_data.append(reinterpret_cast<const char*>(&le_tier),   1);
      msg_hash = crypto::cn_fast_hash(msg_data.data(), msg_data.size());
    }

    if (!crypto::check_signature(msg_hash, owner_field.owner_spend_pubkey, sig_field.sig))
    {
      fail_reason = "owner_sig verification failed — spend key does not match signature";
      return PBC_DEPOSIT_INVALID;
    }

    rec_out.owner_key = owner_field.owner_spend_pubkey;
  }

  // ════════════════════════════════════════════════════════════
  // All consensus checks passed — fill the deposit record
  // ════════════════════════════════════════════════════════════

  rec_out.amount         = info.amount;
  rec_out.created_height = block_height;
  rec_out.unlock_height  = info.unlock_height;
  rec_out.tier           = info.tier;
  rec_out.weight         = weight;

  return PBC_DEPOSIT_VALID;
}

// ═══════════════════════════════════════════════════════════════
// TD-3: RCT commitment verification for TX_TERM_DEPOSIT
//
// Called AFTER pbc_validate_deposit_tx() returns PBC_DEPOSIT_VALID.
// The deposit_info fields (amount, tier, unlock_height) are already
// validated by TD-2. This function checks RingCT-level constraints:
//
//   1. tx.unlock_time matches the deposit's unlock_height
//   2. tx.version == 2 with a real RCT signature (not Null)
//   3. outPk size matches vout size (sanity)
//   4. At least 1 output exists (deposit output at index 0)
//   5. Commitment at outPk[0].mask == amount * H (mask = 0)
//
// Whitepaper §3.9, §19.1 Rule A5: canonical uint64→scalar conversion.
// rct::commit(amount, rct::zero()) produces exactly amount*H because:
//   C = mask*G + amount*H, with mask = zero → C = 0*G + amount*H = amount*H
//   Internally d2h(amount) writes amount as 8 LE bytes + 24 zero bytes,
//   which is the canonical conversion required by §3.5 / §19.1 Rule A5.
//
// Rule A2: No float/double in this function.
// ═══════════════════════════════════════════════════════════════

bool pbc_verify_term_deposit_rct_simple(
    const transaction& tx,
    const pbc_deposit_record& validated_rec,
    std::string& fail_reason)
{
  // ── Step 1: Verify unlock_time matches deposit info (§7.5) ──
  // The wallet must set tx.unlock_time = unlock_height from the deposit_info
  // tag. This locks the TX outputs until the deposit matures.
  if (tx.unlock_time != validated_rec.unlock_height)
  {
    fail_reason = "deposit tx unlock_time mismatch: tx.unlock_time="
                + std::to_string(tx.unlock_time)
                + " expected=" + std::to_string(validated_rec.unlock_height);
    return false;
  }

  // ── Step 2: Verify RCT format basics (§3.9) ──
  // Deposit TXs must be version 2 (RingCT) with a real signature type.
  if (tx.version != 2)
  {
    fail_reason = "deposit tx version=" + std::to_string(tx.version)
                + " expected 2 (RCT)";
    return false;
  }

  if (tx.rct_signatures.type == rct::RCTTypeNull)
  {
    fail_reason = "deposit tx has RCTTypeNull (no RCT signature)";
    return false;
  }

  // ── Step 3: outPk size sanity ──
  if (tx.rct_signatures.outPk.size() != tx.vout.size())
  {
    fail_reason = "outPk.size()=" + std::to_string(tx.rct_signatures.outPk.size())
                + " != vout.size()=" + std::to_string(tx.vout.size());
    return false;
  }

  // ── Step 4: Deposit output existence ──
  // Consensus rule: deposit output is always vout[PBC_DEPOSIT_VOUT_INDEX] (= 0).
  if (tx.vout.size() < PBC_DEPOSIT_VOUT_INDEX + 1)
  {
    fail_reason = "tx has " + std::to_string(tx.vout.size())
                + " outputs, need at least " + std::to_string(PBC_DEPOSIT_VOUT_INDEX + 1);
    return false;
  }

  // ── Step 5: Deterministic commitment check (§3.9, §19.1 Rule A5) ──
  // The deposit output commitment must be C = amount * H (mask = 0).
  // This makes the deposit amount verifiable by all nodes.
  //
  // IMPORTANT: For RCTTypeBulletproofPlus (type 8, "legacy"), the wallet stores
  // outPk[i].mask = (1/8) * commitment, because bulletproof_plus_PROVE divides
  // by 8 for subgroup safety (see bulletproofs_plus.cc line 554-556).
  // For RCTTypeBulletproofPlus_FullCommit (type 9), scalarmult8 is applied at
  // storage time so outPk[i].mask = full commitment.
  //
  // We must recover the full commitment before comparison:
  //   Legacy (type 8):  C_full = 8 * outPk[0].mask
  //   Full   (type 9):  C_full = outPk[0].mask
  //
  // rct::commit(amount, rct::zero()) computes the FULL commitment:
  //   C = zero() * G + d2h(amount) * H = amount * H
  const rct::key C_expected = rct::commit(validated_rec.amount, rct::zero());

  rct::key C_actual;
  if (rct::is_rct_bp_plus_legacy(tx.rct_signatures.type))
    C_actual = rct::scalarmult8(tx.rct_signatures.outPk[PBC_DEPOSIT_VOUT_INDEX].mask);
  else
    C_actual = tx.rct_signatures.outPk[PBC_DEPOSIT_VOUT_INDEX].mask;

  if (!(C_actual == C_expected))
  {
    fail_reason = "deposit commitment mismatch at outPk["
                + std::to_string(PBC_DEPOSIT_VOUT_INDEX)
                + "]: expected amount*H (mask=0) for amount="
                + std::to_string(validated_rec.amount);
    return false;
  }

  return true;
}

// ═══════════════════════════════════════════════════════════════
// TD-5: TX_CLAIM validation
//
// Checks:
//   1. tx_extra has pbc_tx_type == PBC_TX_TYPE_CLAIM
//   2. tx_extra has exactly one pbc_claim_info with deposit_id
//   3. No pbc_deposit_info (not a deposit TX)
//
// Does NOT check: deposit existence, eligibility, reward calc
// (those are done by the caller in blockchain.cpp).
// ═══════════════════════════════════════════════════════════════

pbc_claim_result pbc_validate_claim_tx(
    const transaction& tx,
    crypto::hash& deposit_id_out,
    std::string& fail_reason)
{
  std::vector<tx_extra_field> fields;
  if (!parse_tx_extra(tx.extra, fields))
  {
    // Unparseable extra is not necessarily a claim, just skip
    return PBC_CLAIM_NOT_APPLICABLE;
  }

  // Look for PBC TX type tag
  tx_extra_pbc_tx_type type_field;
  if (!find_tx_extra_field_by_type(fields, type_field))
    return PBC_CLAIM_NOT_APPLICABLE;

  if (type_field.type != PBC_TX_TYPE_CLAIM)
    return PBC_CLAIM_NOT_APPLICABLE;

  // It's a claim TX — now validate strictly

  // Must have exactly one pbc_tx_type
  int type_count = 0;
  for (const auto& f : fields)
    if (f.type() == typeid(tx_extra_pbc_tx_type))
      ++type_count;
  if (type_count != 1)
  {
    fail_reason = "multiple pbc_tx_type tags in claim tx (" + std::to_string(type_count) + ")";
    return PBC_CLAIM_INVALID;
  }

  // Must have EXACTLY ONE claim_info with deposit_id.
  // L1 fix: enforce strict uniqueness of the payload tag, mirroring the deposit and
  // withdraw validators (which already count their info tag and require exactly one).
  // Without this, a CLAIM carrying two pbc_claim_info fields would silently use only the
  // first (find_tx_extra_field_by_type returns the first match). Harmless economically
  // (see M1) but an inconsistency with the "one tag = one meaning, strict uniqueness"
  // principle; rejecting such malformed TXs closes the ambiguity. No legitimate CLAIM
  // ever needs two claim_info tags.
  {
    size_t claim_info_count = 0;
    for (const auto& f : fields)
      if (f.type() == typeid(tx_extra_pbc_claim_info))
        ++claim_info_count;
    if (claim_info_count != 1)
    {
      fail_reason = "expected exactly 1 pbc_claim_info tag, found " + std::to_string(claim_info_count);
      return PBC_CLAIM_INVALID;
    }
  }

  tx_extra_pbc_claim_info claim_info;
  if (!find_tx_extra_field_by_type(fields, claim_info))
  {
    fail_reason = "claim tx missing pbc_claim_info (deposit_id)";
    return PBC_CLAIM_INVALID;
  }

  // Must NOT have deposit_info (not a deposit)
  tx_extra_pbc_deposit_info deposit_info;
  if (find_tx_extra_field_by_type(fields, deposit_info))
  {
    fail_reason = "claim tx must not contain pbc_deposit_info";
    return PBC_CLAIM_INVALID;
  }

  deposit_id_out = claim_info.deposit_id;
  return PBC_CLAIM_VALID;
}

// ═══════════════════════════════════════════════════════════════
// PF: TERM_WITHDRAW payout TX validation (format-level only)
//
// Requirements:
//   - tx_extra has exactly one pbc_tx_type == PBC_TX_TYPE_TERM_WITHDRAW
//   - tx_extra has exactly one pbc_withdraw_info (deposit_id)
//   - tx_extra has exactly one pbc_withdraw_payout (amount+kind)
//   - payout_kind == 0 (rewards-only)
//   - must NOT contain pbc_deposit_info
//
// Does NOT validate:
//   - deposit existence
//   - eligibility (claim-before-withdraw, accrued amount, etc.)
// Those checks are done in blockchain.cpp / tx_pool.cpp.
// ═══════════════════════════════════════════════════════════════

pbc_withdraw_result pbc_validate_withdraw_tx(
    const transaction& tx,
    crypto::hash& deposit_id_out,
    uint64_t& payout_amount_out,
    uint8_t& payout_kind_out,
    std::string& fail_reason)
{
  std::vector<tx_extra_field> fields;
  if (!parse_tx_extra(tx.extra, fields))
    return PBC_WITHDRAW_NOT_APPLICABLE;

  // Look for PBC TX type tag
  tx_extra_pbc_tx_type type_field;
  if (!find_tx_extra_field_by_type(fields, type_field))
    return PBC_WITHDRAW_NOT_APPLICABLE;

  if (type_field.type != PBC_TX_TYPE_TERM_WITHDRAW)
    return PBC_WITHDRAW_NOT_APPLICABLE;

  // Must have exactly one pbc_tx_type
  int type_count = 0;
  for (const auto& f : fields)
    if (f.type() == typeid(tx_extra_pbc_tx_type))
      ++type_count;
  if (type_count != 1)
  {
    fail_reason = "multiple pbc_tx_type tags in withdraw tx (" + std::to_string(type_count) + ")";
    return PBC_WITHDRAW_INVALID;
  }

  // Must have exactly one withdraw_info
  tx_extra_pbc_withdraw_info w_info;
  {
    int w_count = 0;
    for (const auto& f : fields)
      if (f.type() == typeid(tx_extra_pbc_withdraw_info))
        ++w_count;
    if (w_count != 1)
    {
      fail_reason = "expected exactly 1 pbc_withdraw_info tag, found " + std::to_string(w_count);
      return PBC_WITHDRAW_INVALID;
    }
    if (!find_tx_extra_field_by_type(fields, w_info))
    {
      fail_reason = "failed to extract pbc_withdraw_info from tx_extra";
      return PBC_WITHDRAW_INVALID;
    }
  }

  // Must have exactly one withdraw_payout
  tx_extra_pbc_withdraw_payout w_pay;
  {
    int p_count = 0;
    for (const auto& f : fields)
      if (f.type() == typeid(tx_extra_pbc_withdraw_payout))
        ++p_count;
    if (p_count != 1)
    {
      fail_reason = "expected exactly 1 pbc_withdraw_payout tag, found " + std::to_string(p_count);
      return PBC_WITHDRAW_INVALID;
    }
    if (!find_tx_extra_field_by_type(fields, w_pay))
    {
      fail_reason = "failed to extract pbc_withdraw_payout from tx_extra";
      return PBC_WITHDRAW_INVALID;
    }
  }

  // Must NOT have deposit_info
  tx_extra_pbc_deposit_info deposit_info;
  if (find_tx_extra_field_by_type(fields, deposit_info))
  {
    fail_reason = "withdraw tx must not contain pbc_deposit_info";
    return PBC_WITHDRAW_INVALID;
  }

  if (w_pay.payout_kind != 0)
  {
    fail_reason = "unsupported payout_kind=" + std::to_string(w_pay.payout_kind);
    return PBC_WITHDRAW_INVALID;
  }

  if (w_pay.payout_amount == 0)
  {
    fail_reason = "payout_amount must be > 0";
    return PBC_WITHDRAW_INVALID;
  }

  // NOTE: For RingCT transactions, tx.vout[i].amount is always 0.
  // For RCTTypeNull (virtual input) tx, amounts are clear — validated later in consensus.
  // We only require that the TX actually has outputs.
  if (tx.vout.empty())
  {
    fail_reason = "withdraw tx has no outputs";
    return PBC_WITHDRAW_INVALID;
  }

  // Must have exactly one owner_sig (tag 0x55) — presence + uniqueness (no LMDB, format-only)
  {
    int sig_count = 0;
    for (const auto& f : fields)
      if (f.type() == typeid(tx_extra_pbc_owner_sig))
        ++sig_count;
    if (sig_count != 1)
    {
      fail_reason = "expected exactly 1 pbc_owner_sig tag (0x55), found " + std::to_string(sig_count);
      return PBC_WITHDRAW_INVALID;
    }
  }

  deposit_id_out = w_info.deposit_id;
  payout_amount_out = w_pay.payout_amount;
  payout_kind_out = w_pay.payout_kind;
  return PBC_WITHDRAW_VALID;
}

// ═══════════════════════════════════════════════════════════════
// PF: Build withdraw ownership message hash
// msg = PBC_WITHDRAW_OWNER_MSG_PREFIX || deposit_id (32 bytes) || payout_amount (8 bytes LE)
// Used by wallet (sign) and consensus (verify).
// ═══════════════════════════════════════════════════════════════

crypto::hash pbc_build_withdraw_msg_hash(const crypto::hash& deposit_id, uint64_t payout_amount)
{
  std::string msg_data(PBC_WITHDRAW_OWNER_MSG_PREFIX);
  msg_data.append(reinterpret_cast<const char*>(&deposit_id), sizeof(crypto::hash));
  msg_data.append(reinterpret_cast<const char*>(&payout_amount), sizeof(uint64_t));
  return crypto::cn_fast_hash(msg_data.data(), msg_data.size());
}

// Problem 2 — Dilithium co-signature message. SAME layout as the Ed25519 owner_sig message but a
// DIFFERENT domain-separation prefix, so an owner_sig can never be replayed as a PQC co-signature
// or vice versa. Must remain byte-identical to the wallet-side construction in create_term_withdraw_tx.
crypto::hash pbc_build_pqc_withdraw_msg_hash(const crypto::hash& deposit_id, uint64_t payout_amount)
{
  std::string msg_data(PBC_PQC_WITHDRAW_MSG_PREFIX);
  msg_data.append(reinterpret_cast<const char*>(&deposit_id), sizeof(crypto::hash));
  msg_data.append(reinterpret_cast<const char*>(&payout_amount), sizeof(uint64_t));
  return crypto::cn_fast_hash(msg_data.data(), msg_data.size());
}

// ═══════════════════════════════════════════════════════════════
// MARKET_PAYOUT_CLAIM: validate a seller reward claim TX (type 11).
// TX format: virtual input (txin_pbc_withdraw with null deposit_id),
// fee=0, RCTTypeNull, single output to seller, extra has:
//   0x50 = TX type 11
//   0x5E = tx_extra_pbc_market_payout_claim (seller_pubkey + payout_amount + seller_sig)
// ═══════════════════════════════════════════════════════════════

pbc_market_payout_result pbc_validate_market_payout_tx(
    const transaction& tx,
    crypto::public_key& seller_pubkey_out,
    uint64_t& payout_amount_out,
    std::string& fail_reason)
{
  std::vector<tx_extra_field> fields;
  if (!parse_tx_extra(tx.extra, fields))
    return PBC_MARKET_PAYOUT_NOT_APPLICABLE;

  tx_extra_pbc_tx_type type_field;
  if (!find_tx_extra_field_by_type(fields, type_field))
    return PBC_MARKET_PAYOUT_NOT_APPLICABLE;

  if (type_field.type != PBC_TX_TYPE_MARKET_PAYOUT_CLAIM)
    return PBC_MARKET_PAYOUT_NOT_APPLICABLE;

  tx_extra_pbc_market_payout_claim pay_field;
  if (!find_tx_extra_field_by_type(fields, pay_field))
  {
    fail_reason = "missing tx_extra_pbc_market_payout_claim field";
    return PBC_MARKET_PAYOUT_INVALID;
  }

  if (pay_field.payout_amount == 0)
  {
    fail_reason = "payout_amount must be > 0";
    return PBC_MARKET_PAYOUT_INVALID;
  }

  if (tx.vout.empty())
  {
    fail_reason = "TX has no outputs";
    return PBC_MARKET_PAYOUT_INVALID;
  }

  seller_pubkey_out = pay_field.seller_pubkey;
  payout_amount_out = pay_field.payout_amount;
  return PBC_MARKET_PAYOUT_VALID;
}

// ═══════════════════════════════════════════════════════════════
// Build market payout ownership message hash.
// msg = PBC_MKTPAY_V1 || seller_pubkey (32 bytes) || payout_amount (8 bytes LE)
// ═══════════════════════════════════════════════════════════════

crypto::hash pbc_build_market_payout_msg_hash(const crypto::public_key& seller_pubkey, uint64_t payout_amount)
{
  std::string msg_data(PBC_MARKET_PAYOUT_MSG_PREFIX);
  msg_data.append(reinterpret_cast<const char*>(&seller_pubkey), sizeof(crypto::public_key));
  msg_data.append(reinterpret_cast<const char*>(&payout_amount), sizeof(uint64_t));
  return crypto::cn_fast_hash(msg_data.data(), msg_data.size());
}

// Problem 2 — Dilithium co-signature message for MARKET_PAYOUT_CLAIM. Same layout as the seller_sig
// message but with a distinct domain prefix. Must stay byte-identical to the wallet-side construction.
crypto::hash pbc_build_pqc_market_payout_msg_hash(const crypto::public_key& seller_pubkey, uint64_t payout_amount)
{
  std::string msg_data(PBC_PQC_MKTPAY_MSG_PREFIX);
  msg_data.append(reinterpret_cast<const char*>(&seller_pubkey), sizeof(crypto::public_key));
  msg_data.append(reinterpret_cast<const char*>(&payout_amount), sizeof(uint64_t));
  return crypto::cn_fast_hash(msg_data.data(), msg_data.size());
}

// Problem 2 — see header for full semantics. DB-free: caller loads the registered key.
bool pbc_verify_dilithium_cosig(const std::vector<tx_extra_field>& parsed_fields,
                                const crypto::hash& msg_hash,
                                const uint8_t* registered_dilithium_pubkey,
                                size_t registered_dilithium_pubkey_size,
                                bool required,
                                bool& present_out,
                                std::string& fail_reason)
{
  tx_extra_pbc_dilithium_pubkey dil_pk_field;
  tx_extra_pbc_dilithium_sig    dil_sig_field;
  const bool present =
      find_tx_extra_field_by_type(parsed_fields, dil_pk_field) &&
      find_tx_extra_field_by_type(parsed_fields, dil_sig_field);
  present_out = present;

  if (!present)
  {
    if (required)
    {
      fail_reason = "Dilithium spend-authority co-signature (0x5F/0x60) is MANDATORY at this "
                    "hard-fork version but is missing";
      return false;
    }
    return true; // soft transition: absence tolerated before the fork
  }

  // Size checks.
  if (dil_pk_field.pubkey.size() != pqc::DILITHIUM_PUBLIC_KEY_SIZE)
  {
    fail_reason = "Dilithium co-signature pubkey wrong size";
    return false;
  }
  if (dil_sig_field.sig.size() == 0 || dil_sig_field.sig.size() > pqc::DILITHIUM_SIGNATURE_SIZE)
  {
    fail_reason = "Dilithium co-signature wrong size";
    return false;
  }

  // Must match the key registered for the spender — a TX cannot smuggle an attacker-chosen key.
  if (registered_dilithium_pubkey == nullptr ||
      registered_dilithium_pubkey_size != pqc::DILITHIUM_PUBLIC_KEY_SIZE)
  {
    if (required)
    {
      fail_reason = "no registered Dilithium key for the spender, but a valid PQC co-signature is "
                    "MANDATORY at this hard-fork version (register PQC keys first)";
      return false;
    }
    return true; // soft transition: can't verify without a registered key, tolerate before fork
  }
  if (std::memcmp(registered_dilithium_pubkey, dil_pk_field.pubkey.data(), pqc::DILITHIUM_PUBLIC_KEY_SIZE) != 0)
  {
    fail_reason = "Dilithium co-signature pubkey does not match the key registered for the spender "
                  "(possible key substitution)";
    return false;
  }

  // Verify the signature over the caller-provided (domain-separated) message hash.
  pqc::dilithium_public_key pk;
  std::memcpy(pk.data, dil_pk_field.pubkey.data(), pqc::DILITHIUM_PUBLIC_KEY_SIZE);
  pqc::dilithium_signature sig;
  sig.length = dil_sig_field.sig.size();
  std::memcpy(sig.data, dil_sig_field.sig.data(), sig.length);

  if (!pqc::dilithium_verify(reinterpret_cast<const uint8_t*>(&msg_hash), sizeof(msg_hash), sig, pk))
  {
    fail_reason = "Dilithium spend-authority co-signature verification FAILED";
    return false;
  }
  return true;
}

} // namespace cryptonote
