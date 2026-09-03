// Copyright (c) 2024-2026, Privacy Bank Chain (PBC)
// BSD-3-Clause License (see LICENSE)
//
// PBC Term Deposit Record — TD-1 storage + TD-2 consensus validation + TD-3 RCT verification + TD-8 owner_key
// Stores deposit metadata in LMDB. Validates deposit TX fields and RCT commitments.

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h" // tx_extra_field — requis par la décl. pbc_verify_dilithium_cosig (l.~383)
#include "misc_log_ex.h"  // TD-8: MWARNING in unpack
#include "string_tools.h" // epee::string_tools::pod_to_hex for pbc_mktpay_key

namespace cryptonote
{

// ═══════════════════════════════════════════════════════════════
// Deposit record — stored in LMDB pbc_deposits table
// Key: deposit_id (= tx hash, 32 bytes)
// Value: packed POD blob (see pack/unpack below)
// ═══════════════════════════════════════════════════════════════

struct pbc_deposit_record
{
  uint64_t amount         = 0;  // deposit amount in atomic units
  uint64_t created_height = 0;  // block height when deposit was created
  uint64_t unlock_height  = 0;  // block height when deposit unlocks
  uint8_t  tier           = 0;  // 0=30d, 1=90d, 2=180d, 3=270d, 4=365d
  uint64_t weight         = 0;  // (amount / COIN) * tier_multiplier / 1000  (linear model)

  // TD-5: Claim tracking — initialized at deposit creation to current global indices
  // BUG1-FIX: uint64→uint128 to match global indices (SCALE=10^18 overflows uint64)
  __uint128_t deposit_entry_index = 0;  // I_deposit at last action (creation or claim)
  __uint128_t fee_entry_index     = 0;  // I_fee at last action
  uint64_t last_claim_height   = 0;  // height of last claim (0 = never claimed)
  uint64_t accumulated_reward  = 0;  // total rewards claimed so far (atomic units)
  uint64_t total_withdrawn     = 0;  // lifetime total of all withdraw payouts (atomic units)

  // TD-8: Owner identity for anti-split enforcement (PBC_MAX_DEPOSITS_PER_ADDR)
  // Stored at deposit creation, immutable. Eliminates get_tx() dependency in consensus.
  crypto::public_key owner_key = crypto::null_pkey;
};

// Packed sizes for LMDB storage (manual pack to avoid struct padding)
static constexpr size_t PBC_DEPOSIT_RECORD_PACKED_SIZE_V1 = 33;  // TD-1 through TD-4 (legacy, no indices)
static constexpr size_t PBC_DEPOSIT_RECORD_PACKED_SIZE_V2 = 97;  // pre-BUG1-FIX (uint64 indices)
static constexpr size_t PBC_DEPOSIT_RECORD_PACKED_SIZE_V3 = 113; // pre-total_withdrawn
static constexpr size_t PBC_DEPOSIT_RECORD_PACKED_SIZE    = 121; // V4: +total_withdrawn(8)

// TD-8: compile-time safety — pack/unpack/constant must stay aligned
// Layout: 25(base) + 2×16(indices) + 2×8(claim/accum) + 32(owner_key) + 8(total_withdrawn) = 121
static_assert(PBC_DEPOSIT_RECORD_PACKED_SIZE == 25 + 32 + 16 + 8 + 32 + 8,
  "V4: packed size must be base(25) + indices(32) + claim(16) + owner_key(32) + withdrawn(8)");
static_assert(sizeof(crypto::public_key) == 32,
  "TD-8: owner_key must be exactly 32 bytes");

inline void pbc_pack_deposit_record(const pbc_deposit_record& rec, uint8_t buf[PBC_DEPOSIT_RECORD_PACKED_SIZE])
{
  memcpy(buf +  0, &rec.amount,         8);
  memcpy(buf +  8, &rec.created_height, 8);
  memcpy(buf + 16, &rec.unlock_height,  8);
  buf[24] = rec.tier;
  memcpy(buf + 25, &rec.weight,         8);
  // TD-5 + BUG1-FIX: indices are now 16 bytes each
  memcpy(buf + 33, &rec.deposit_entry_index, 16);
  memcpy(buf + 49, &rec.fee_entry_index,     16);
  memcpy(buf + 65, &rec.last_claim_height,    8);
  memcpy(buf + 73, &rec.accumulated_reward,   8);
  // TD-8: owner_key at offset 81
  memcpy(buf + 81, &rec.owner_key, 32);
  // V4: total_withdrawn at offset 113
  memcpy(buf + 113, &rec.total_withdrawn, 8);
}

inline void pbc_unpack_deposit_record(const uint8_t* buf, size_t buf_size, pbc_deposit_record& rec)
{
  // L5 fix: exact-size discrimination. Deposit records are ONLY ever produced by
  // pbc_pack_deposit_record() and read back from LMDB — they never come from the network.
  // The version bands below use `>=` comparisons, so an unexpected intermediate size (e.g.
  // 100 bytes) would fall into a lower version band and be re-interpreted with a mismatched
  // layout. We refuse any size that is not EXACTLY one of the known packed sizes and null
  // out the record instead of silently reading garbage. A record that fails this check
  // signals DB corruption or a version mismatch, not a legitimate state.
  if (buf_size != PBC_DEPOSIT_RECORD_PACKED_SIZE_V1 &&
      buf_size != PBC_DEPOSIT_RECORD_PACKED_SIZE_V2 &&
      buf_size != PBC_DEPOSIT_RECORD_PACKED_SIZE_V3 &&
      buf_size != PBC_DEPOSIT_RECORD_PACKED_SIZE)
  {
    memset(&rec, 0, sizeof(rec));
    rec.owner_key = crypto::null_pkey;
    MERROR("PBC: unpack deposit record with INVALID size " << buf_size
      << " (expected exactly one of {"
      << PBC_DEPOSIT_RECORD_PACKED_SIZE_V1 << ","
      << PBC_DEPOSIT_RECORD_PACKED_SIZE_V2 << ","
      << PBC_DEPOSIT_RECORD_PACKED_SIZE_V3 << ","
      << PBC_DEPOSIT_RECORD_PACKED_SIZE << "}) — record nulled (possible DB corruption)");
    return;
  }

  // V1 fields (always present)
  memcpy(&rec.amount,         buf +  0, 8);
  memcpy(&rec.created_height, buf +  8, 8);
  memcpy(&rec.unlock_height,  buf + 16, 8);
  rec.tier = buf[24];
  memcpy(&rec.weight,         buf + 25, 8);
  // BUG1-FIX: new packed format with uint128 indices
  if (buf_size >= PBC_DEPOSIT_RECORD_PACKED_SIZE_V3)
  {
    memcpy(&rec.deposit_entry_index, buf + 33, 16);
    memcpy(&rec.fee_entry_index,     buf + 49, 16);
    memcpy(&rec.last_claim_height,   buf + 65,  8);
    memcpy(&rec.accumulated_reward,  buf + 73,  8);
    memcpy(&rec.owner_key, buf + 81, 32);
    if (buf_size >= PBC_DEPOSIT_RECORD_PACKED_SIZE)
      memcpy(&rec.total_withdrawn, buf + 113, 8);
    else
      rec.total_withdrawn = 0;  // V3 migration: no withdrawn history
  }
  // Legacy V2 format (uint64 indices, 97 bytes) — migration path
  else if (buf_size >= PBC_DEPOSIT_RECORD_PACKED_SIZE_V2)
  {
    uint64_t dep_idx64 = 0, fee_idx64 = 0;
    memcpy(&dep_idx64, buf + 33, 8);
    memcpy(&fee_idx64, buf + 41, 8);
    rec.deposit_entry_index = (__uint128_t)dep_idx64;
    rec.fee_entry_index     = (__uint128_t)fee_idx64;
    memcpy(&rec.last_claim_height,   buf + 49, 8);
    memcpy(&rec.accumulated_reward,  buf + 57, 8);
    memcpy(&rec.owner_key, buf + 65, 32);
    MWARNING("PBC: unpack deposit record V2 (97 bytes, pre-BUG1-FIX) — indices widened to uint128");
  }
  else
  {
    rec.deposit_entry_index = 0;
    rec.fee_entry_index     = 0;
    rec.last_claim_height   = 0;
    rec.accumulated_reward  = 0;
    rec.owner_key = crypto::null_pkey;
    MWARNING("PBC: unpack deposit record with unexpected size " << buf_size
      << " (expected " << PBC_DEPOSIT_RECORD_PACKED_SIZE << ") — owner_key set to null");
  }
}

// Legacy 2-arg unpack (for existing call sites using V1 size)
inline void pbc_unpack_deposit_record(const uint8_t buf[PBC_DEPOSIT_RECORD_PACKED_SIZE_V1], pbc_deposit_record& rec)
{
  pbc_unpack_deposit_record(buf, PBC_DEPOSIT_RECORD_PACKED_SIZE_V1, rec);
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

// Parse a transaction's tx_extra and build a deposit record.
// Returns true only if the TX is a valid PBC_TX_TYPE_TERM_DEPOSIT
// with a parseable deposit_info field and a valid tier.
// Does NOT validate amounts, fees, or consensus rules (that's TD-2+).
bool pbc_parse_deposit_from_tx(const transaction& tx,
                               uint64_t block_height,
                               pbc_deposit_record& rec);

// ═══════════════════════════════════════════════════════════════
// TD-2: Consensus validation for TX_TERM_DEPOSIT
//
// Tri-state result to distinguish:
//   NOT_APPLICABLE — TX is not a deposit, skip silently
//   VALID          — deposit validated, rec_out filled
//   INVALID        — deposit is malformed → REJECT BLOCK
// ═══════════════════════════════════════════════════════════════

enum pbc_deposit_result
{
  PBC_DEPOSIT_NOT_APPLICABLE,  // not a deposit TX, ignore
  PBC_DEPOSIT_VALID,           // valid deposit, rec filled
  PBC_DEPOSIT_INVALID          // invalid → caller MUST reject the block
};

// Consensus-critical validation of a deposit TX.
// Checks (all from whitepaper §7, §19.2, §19.5, §19.12):
//   1. tx_extra uniqueness: exactly one pbc_tx_type + one deposit_info
//   2. type == TERM_DEPOSIT + deposit_info present
//   3. tier ∈ [0,4]
//   4. amount >= PBC_MIN_DEPOSIT_AMOUNT (10 PBC)
//   5. unlock_height >= block_height + pbc_get_tier_blocks(tier)
//   6. weight > 0
//   7. (TD-8) owner_spend_pubkey + owner_sig in tx_extra, valid signature
// Does NOT check: duplicate deposit_id (caller checks via DB),
//   deposit creation fee (balance equation, future TD),
//   rate limits (future TD).
// POST-CONDITION: if VALID, rec_out.owner_key is guaranteed non-null
//   (set to the verified owner_spend_pubkey from tx_extra).
pbc_deposit_result pbc_validate_deposit_tx(
    const transaction& tx,
    uint64_t block_height,
    pbc_deposit_record& rec_out,
    std::string& fail_reason);

// ═══════════════════════════════════════════════════════════════
// TD-3: RCT commitment verification for TX_TERM_DEPOSIT
//
// Called AFTER pbc_validate_deposit_tx() returns PBC_DEPOSIT_VALID.
// Verifies that the on-chain RingCT data matches the deposit:
//   1. tx.unlock_time == deposit_info.unlock_height
//   2. tx.version == 2 and RCT type != Null
//   3. outPk.size() == vout.size() (sanity)
//   4. Deposit output at DEPOSIT_VOUT_INDEX = 0
//   5. Commitment: outPk[0].mask == commit(amount, zero()) = amount*H
//
// This is the "simple" verification (mask=0 deterministic commitment).
// Future TD-3_C / TD-4 may add BP+ separated proof verification.
//
// Returns true if all checks pass. On failure, sets fail_reason.
// ═══════════════════════════════════════════════════════════════

// Consensus rule: deposit output is always vout[0]
static constexpr size_t PBC_DEPOSIT_VOUT_INDEX = 0;

bool pbc_verify_term_deposit_rct_simple(
    const transaction& tx,
    const pbc_deposit_record& validated_rec,
    std::string& fail_reason);

// ═══════════════════════════════════════════════════════════════
// TD-5: TX_CLAIM validation
//
// Tri-state result (same as deposit):
//   NOT_APPLICABLE — TX is not a claim, skip silently
//   VALID          — claim validated, deposit_id_out filled
//   INVALID        — claim is malformed → REJECT BLOCK
// ═══════════════════════════════════════════════════════════════

enum pbc_claim_result
{
  PBC_CLAIM_NOT_APPLICABLE,
  PBC_CLAIM_VALID,
  PBC_CLAIM_INVALID
};

pbc_claim_result pbc_validate_claim_tx(
    const transaction& tx,
    crypto::hash& deposit_id_out,
    std::string& fail_reason);

// ═══════════════════════════════════════════════════════════════
// PF: TERM_WITHDRAW payout validation (format-level)
//
// Tri-state result:
//   NOT_APPLICABLE — TX is not a withdraw payout, skip silently
//   VALID          — withdraw validated, fields filled
//   INVALID        — malformed → REJECT BLOCK
//
// NOTE: This ONLY validates tx_extra shape + payout vout[0] amount.
// It does NOT check deposit existence or state eligibility.
// ═══════════════════════════════════════════════════════════════

enum pbc_withdraw_result
{
  PBC_WITHDRAW_NOT_APPLICABLE,
  PBC_WITHDRAW_VALID,
  PBC_WITHDRAW_INVALID
};

pbc_withdraw_result pbc_validate_withdraw_tx(
    const transaction& tx,
    crypto::hash& deposit_id_out,
    uint64_t& payout_amount_out,
    uint8_t& payout_kind_out,
    std::string& fail_reason);

// PF: Build the canonical withdraw message hash for owner_sig verification.
// msg = PBC_WITHDRAW_OWNER_MSG_PREFIX || deposit_id (32 bytes) || payout_amount (8 bytes LE)
// Used by wallet (sign) and consensus (verify).
crypto::hash pbc_build_withdraw_msg_hash(const crypto::hash& deposit_id, uint64_t payout_amount);

// Problem 2 — message hashed by the MANDATORY-after-HF Dilithium co-signature on TERM_WITHDRAW /
// MARKET_PAYOUT_CLAIM TXs. Domain-separated from the Ed25519 owner_sig message (different prefix)
// so the two signatures are never interchangeable. Byte-identical on wallet (signer) and consensus
// (verifier): H(PBC_PQC_WITHDRAW_MSG_PREFIX || deposit_id(32) || payout_amount(8, little-endian)).
crypto::hash pbc_build_pqc_withdraw_msg_hash(const crypto::hash& deposit_id, uint64_t payout_amount);

// PF: Withdraw delta record — stored per-withdraw for reorg reversal
struct pbc_withdraw_delta
{
  uint64_t prev_accumulated_reward;
};

static constexpr size_t PBC_WITHDRAW_DELTA_PACKED_SIZE = 8;

inline void pbc_pack_withdraw_delta(const pbc_withdraw_delta& d, uint8_t buf[PBC_WITHDRAW_DELTA_PACKED_SIZE])
{
  memcpy(buf + 0, &d.prev_accumulated_reward, 8);
}

inline void pbc_unpack_withdraw_delta(const uint8_t buf[PBC_WITHDRAW_DELTA_PACKED_SIZE], pbc_withdraw_delta& d)
{
  memcpy(&d.prev_accumulated_reward, buf + 0, 8);
}

// TD-5: Claim delta record — stored per-claim for reorg reversal
struct pbc_claim_delta
{
  uint64_t reward_dep;              // amount taken from deposit pool
  uint64_t reward_fee;              // amount taken from fee pool
  __uint128_t prev_deposit_entry_index;  // BUG1-FIX: uint64→uint128
  __uint128_t prev_fee_entry_index;      // BUG1-FIX: uint64→uint128
  uint64_t prev_last_claim_height;
  uint64_t prev_accumulated_reward;
};

static constexpr size_t PBC_CLAIM_DELTA_PACKED_SIZE = 64;  // 4×8 + 2×16

// Hardening: compile-time packed size coherence checks
static_assert(PBC_CLAIM_DELTA_PACKED_SIZE == 4*8 + 2*16,
    "claim delta packed size must be 4×uint64(8) + 2×uint128(16)");
static_assert(sizeof(__uint128_t) == 16,
    "uint128 must be exactly 16 bytes — LMDB pack/unpack depends on this");

inline void pbc_pack_claim_delta(const pbc_claim_delta& d, uint8_t buf[PBC_CLAIM_DELTA_PACKED_SIZE])
{
  memcpy(buf +  0, &d.reward_dep,               8);
  memcpy(buf +  8, &d.reward_fee,               8);
  memcpy(buf + 16, &d.prev_deposit_entry_index, 16);
  memcpy(buf + 32, &d.prev_fee_entry_index,     16);
  memcpy(buf + 48, &d.prev_last_claim_height,   8);
  memcpy(buf + 56, &d.prev_accumulated_reward,  8);
}

inline void pbc_unpack_claim_delta(const uint8_t buf[PBC_CLAIM_DELTA_PACKED_SIZE], pbc_claim_delta& d)
{
  memcpy(&d.reward_dep,               buf +  0, 8);
  memcpy(&d.reward_fee,               buf +  8, 8);
  memcpy(&d.prev_deposit_entry_index, buf + 16, 16);
  memcpy(&d.prev_fee_entry_index,     buf + 32, 16);
  memcpy(&d.prev_last_claim_height,   buf + 48, 8);
  memcpy(&d.prev_accumulated_reward,  buf + 56, 8);
}

// ── Market payout claim (MARKET_PAYOUT_CLAIM TX type 11) ───────────────────
// LMDB key for seller deferred reward payout.
inline std::string pbc_mktpay_key(const crypto::public_key& seller_pubkey)
{
  return std::string("pbc_mktpay_") + epee::string_tools::pod_to_hex(seller_pubkey);
}
enum pbc_market_payout_result
{
  PBC_MARKET_PAYOUT_NOT_APPLICABLE,
  PBC_MARKET_PAYOUT_VALID,
  PBC_MARKET_PAYOUT_INVALID
};

// Validate that a TX is a well-formed MARKET_PAYOUT_CLAIM virtual-input TX.
// Returns VALID + fills out params on success, INVALID on malformed, NOT_APPLICABLE if not this type.
pbc_market_payout_result pbc_validate_market_payout_tx(
    const transaction& tx,
    crypto::public_key& seller_pubkey_out,
    uint64_t& payout_amount_out,
    std::string& fail_reason);

// Build H(PBC_MKTPAY_V1 || seller_pubkey || payout_amount_le8) for seller_sig verification.
crypto::hash pbc_build_market_payout_msg_hash(const crypto::public_key& seller_pubkey, uint64_t payout_amount);

// Problem 2 — message hashed by the Dilithium spend-authority co-signature on MARKET_PAYOUT_CLAIM.
// Domain-separated from the Ed25519 seller_sig message. Byte-identical on wallet and consensus:
// H(PBC_PQC_MKTPAY_MSG_PREFIX || seller_pubkey(32) || payout_amount(8 LE)).
crypto::hash pbc_build_pqc_market_payout_msg_hash(const crypto::public_key& seller_pubkey, uint64_t payout_amount);

// Problem 2 — shared, DB-free verifier for the Dilithium spend-authority co-signature carried in
// tags 0x5F (pubkey) + 0x60 (sig) of a TERM_WITHDRAW / MARKET_PAYOUT_CLAIM TX. The caller supplies:
//   - the already-parsed tx_extra fields,
//   - the exact message hash the co-signature must sign (domain-separated per TX type),
//   - the registered Dilithium public key bytes for the spender (loaded from the DB by the caller),
//     or nullptr if none is registered.
// Semantics (returns true = accept, false = reject; *present set to whether any co-sig was found):
//   - no co-sig present      -> accept iff !required (soft transition), reject iff required.
//   - co-sig present but no registered key -> accept iff !required, else reject.
//   - co-sig present + registered key      -> reject unless the TX pubkey == registered key AND the
//                                             Dilithium signature verifies over msg_hash.
// Keeping this in one function guarantees the withdraw path, the block-apply payout path and the
// mempool payout path enforce IDENTICAL rules.
bool pbc_verify_dilithium_cosig(const std::vector<tx_extra_field>& parsed_fields,
                                const crypto::hash& msg_hash,
                                const uint8_t* registered_dilithium_pubkey, // nullptr if none
                                size_t registered_dilithium_pubkey_size,
                                bool required,
                                bool& present_out,
                                std::string& fail_reason);

} // namespace cryptonote
