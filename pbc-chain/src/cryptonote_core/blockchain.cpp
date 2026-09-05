// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <algorithm>
#include <cstdio>
#include <inttypes.h>
#include <unordered_set>
#include <boost/asio/dispatch.hpp>
#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/format.hpp>

#include "include_base_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "tx_pool.h"
#include "blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/events.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/miner.h"
#include "hardforks/hardforks.h"
#include "misc_language.h"
#include "profile_tools.h"
#include "file_io_utils.h"
#include "int-util.h"
#include "common/threadpool.h"
#include "common/boost_serialization_helper.h"
#include "warnings.h"
#include "crypto/hash.h"
#include "crypto/crypto.h"
#include "cryptonote_core.h"
#include "ringct/rctSigs.h"
#include "common/perf_timer.h"
#include "common/notify.h"
#include "common/varint.h"
#include "common/pruning.h"
#include "common/data_cache.h"
#include "pbc_deposits.h"
#include "pbc_inherit.h"
#include "crypto/pqc/pqc_dilithium.h"
#include "pbc_collateral_lock.h"
#include "time_helper.h"

// Helper: parse tx.extra and find a field by type in one call
template <typename T>
static bool get_tx_extra_field_by_type(const std::vector<uint8_t>& extra, T& field)
{
  std::vector<cryptonote::tx_extra_field> fields;
  if (!cryptonote::parse_tx_extra(extra, fields))
    return false;
  return cryptonote::find_tx_extra_field_by_type(fields, field);
}


static std::string pbc_market_key(const crypto::hash &txid, const char *suffix)
{
  return std::string("pbc_market_") + epee::string_tools::pod_to_hex(txid) + suffix;
}

// A3: clé property-store de l'état "héritage exécuté" pour un principal.
// Valeur = hauteur d'exécution B (>0). Absente / 0 => non exécuté (balayage rejeté).
// Conception v2 (2026-08-14) : sert AUSSI d'ancre déterministe pour la Pass 0/1 (héritage du
// rôle A3), mise à jour à CHAQUE tentative — la fenêtre mempool glisse tant que des tentatives
// ont lieu.
static std::string pbc_inh_exec_key(const crypto::public_key &principal)
{
  return std::string("pbc_inh_exec_") + epee::string_tools::pod_to_hex(principal);
}

// Conception v2 (2026-08-14) : clé property-store du nombre de tentatives de diffusion du
// testament déjà effectuées pour le CYCLE COURANT (REQUEST→exécution). Remise à 0 à chaque
// REQUEST/SETUP/CANCEL — le budget appartient au cycle, pas au principal (§7 conception :
// corrige le défaut où un nouveau cycle héritait d'un compteur déjà épuisé). Plafonnée par
// PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS.
static std::string pbc_inh_testament_attempts_key(const crypto::public_key &principal)
{
  return std::string("pbc_inh_tst_att_") + epee::string_tools::pod_to_hex(principal);
}

// A4 (sous-étape 4) : clé property-store de la séquence anti-rejeu du dernier testament
// on-chain stocké pour un principal. Un nouveau porteur n'écrase que si sa séquence est
// STRICTEMENT supérieure. Absente => 0 (aucun testament on-chain encore stocké).
static std::string pbc_testament_seq_key(const crypto::public_key &principal)
{
  return std::string("pbc_testament_seq_") + epee::string_tools::pod_to_hex(principal);
}

static std::array<uint8_t, 8 + sizeof(crypto::hash)> pbc_make_lock_expiry_key(uint64_t expiry_height, const crypto::hash &lock_id)
{
  std::array<uint8_t, 8 + sizeof(crypto::hash)> out{};
  std::memcpy(out.data(), &expiry_height, sizeof(expiry_height));
  std::memcpy(out.data() + 8, &lock_id, sizeof(lock_id));
  return out;
}

static void pbc_store_packed_props(cryptonote::BlockchainDB *db, const std::string &base, const void *data, size_t size)
{
  const uint8_t *bytes = static_cast<const uint8_t*>(data);
  db->set_property_uint64(base + "_sz", static_cast<uint64_t>(size));
  const size_t words = (size + 7) / 8;
  for (size_t i = 0; i < words; ++i)
  {
    uint64_t word = 0;
    const size_t off = i * 8;
    const size_t n = std::min<size_t>(8, size - off);
    std::memcpy(&word, bytes + off, n);
    db->set_property_uint64(base + "_" + std::to_string(i), word);
  }
}

static bool pbc_load_packed_props(const cryptonote::BlockchainDB *db, const std::string &base, void *data, size_t max_size, size_t &size_out)
{
  uint64_t sz = 0;
  if (!db->get_property_uint64(base + "_sz", sz) || sz > max_size)
    return false;
  std::memset(data, 0, max_size);
  uint8_t *bytes = static_cast<uint8_t*>(data);
  const size_t words = (static_cast<size_t>(sz) + 7) / 8;
  for (size_t i = 0; i < words; ++i)
  {
    uint64_t word = 0;
    if (!db->get_property_uint64(base + "_" + std::to_string(i), word))
      return false;
    const size_t off = i * 8;
    const size_t n = std::min<size_t>(8, static_cast<size_t>(sz) - off);
    std::memcpy(bytes + off, &word, n);
  }
  size_out = static_cast<size_t>(sz);
  return true;
}

static void pbc_delete_packed_props(cryptonote::BlockchainDB *db, const std::string &base)
{
  uint64_t sz = 0;
  if (!db->get_property_uint64(base + "_sz", sz))
    return;
  const size_t words = (static_cast<size_t>(sz) + 7) / 8;
  for (size_t i = 0; i < words; ++i)
    db->delete_property(base + "_" + std::to_string(i));
  db->delete_property(base + "_sz");
}

// ── Market Ask LMDB helpers ──────────────────────────────────────────────────
static std::string pbc_ask_dep_key(const crypto::hash &dep_id, const char *suffix)
{
  return std::string("pbc_ask_") + epee::string_tools::pod_to_hex(dep_id) + suffix;
}

static bool pbc_ask_list_find(const cryptonote::BlockchainDB *db, const crypto::hash &dep_id, uint64_t &out_idx)
{
  uint64_t count = 0;
  db->get_property_uint64("pbc_ask_list_count", count);
  for (uint64_t i = 0; i < count; ++i)
  {
    uint8_t buf[32]; size_t sz = 0;
    if (!pbc_load_packed_props(db, "pbc_ask_list_" + std::to_string(i), buf, 32, sz))
      continue;
    if (sz == 32 && memcmp(buf, dep_id.data, 32) == 0) { out_idx = i; return true; }
  }
  return false;
}

static void pbc_ask_list_add(cryptonote::BlockchainDB *db, const crypto::hash &dep_id)
{
  uint64_t idx = 0;
  if (pbc_ask_list_find(db, dep_id, idx)) return;
  uint64_t count = 0;
  db->get_property_uint64("pbc_ask_list_count", count);
  pbc_store_packed_props(db, "pbc_ask_list_" + std::to_string(count), dep_id.data, 32);
  db->set_property_uint64("pbc_ask_list_count", count + 1);
}

static void pbc_ask_list_remove(cryptonote::BlockchainDB *db, const crypto::hash &dep_id)
{
  uint64_t idx = 0;
  if (!pbc_ask_list_find(db, dep_id, idx)) return;
  uint64_t count = 0;
  db->get_property_uint64("pbc_ask_list_count", count);
  if (count == 0) return;
  const uint64_t last = count - 1;
  if (idx != last)
  {
    uint8_t last_buf[32]; size_t sz = 0;
    if (pbc_load_packed_props(db, "pbc_ask_list_" + std::to_string(last), last_buf, 32, sz) && sz == 32)
      pbc_store_packed_props(db, "pbc_ask_list_" + std::to_string(idx), last_buf, 32);
  }
  db->delete_property("pbc_ask_list_" + std::to_string(last));
  db->set_property_uint64("pbc_ask_list_count", last);
}

// ── Sold deposits list: per-seller history of completed marketplace sales ──
// Pattern: pbc_sold_<seller_hex>_count, pbc_sold_<seller_hex>_<idx> = deposit_id (32 bytes)
// Details: pbc_sold_<seller_hex>_<dep_hex>_{price,reward,height,principal,buyer}

static std::string pbc_sold_prefix(const crypto::public_key &seller)
{
  return std::string("pbc_sold_") + epee::string_tools::pod_to_hex(seller);
}

static std::string pbc_sold_detail_key(const crypto::public_key &seller, const crypto::hash &dep_id, const char *suffix)
{
  return pbc_sold_prefix(seller) + "_" + epee::string_tools::pod_to_hex(dep_id) + suffix;
}

static void pbc_sold_list_add(cryptonote::BlockchainDB *db, const crypto::public_key &seller, const crypto::hash &dep_id,
    uint64_t sale_price, uint64_t seller_reward, uint64_t sale_height, uint64_t principal,
    const crypto::public_key &buyer)
{
  const std::string prefix = pbc_sold_prefix(seller);
  uint64_t count = 0;
  db->get_property_uint64(prefix + "_count", count);
  pbc_store_packed_props(db, prefix + "_" + std::to_string(count), dep_id.data, 32);
  db->set_property_uint64(prefix + "_count", count + 1);

  // Store sale details
  db->set_property_uint64(pbc_sold_detail_key(seller, dep_id, "_price"),     sale_price);
  db->set_property_uint64(pbc_sold_detail_key(seller, dep_id, "_reward"),    seller_reward);
  db->set_property_uint64(pbc_sold_detail_key(seller, dep_id, "_height"),    sale_height);
  db->set_property_uint64(pbc_sold_detail_key(seller, dep_id, "_principal"), principal);
  pbc_store_packed_props(db, pbc_sold_detail_key(seller, dep_id, "_buyer"),
                          reinterpret_cast<const uint8_t*>(&buyer), sizeof(buyer));
}

static void pbc_sold_list_remove(cryptonote::BlockchainDB *db, const crypto::public_key &seller, const crypto::hash &dep_id)
{
  const std::string prefix = pbc_sold_prefix(seller);
  uint64_t count = 0;
  db->get_property_uint64(prefix + "_count", count);
  if (count == 0) return;

  // Find the deposit in the list
  uint64_t found_idx = UINT64_MAX;
  for (uint64_t i = 0; i < count; ++i)
  {
    uint8_t buf[32]; size_t sz = 0;
    if (!pbc_load_packed_props(db, prefix + "_" + std::to_string(i), buf, 32, sz))
      continue;
    if (sz == 32 && memcmp(buf, dep_id.data, 32) == 0) { found_idx = i; break; }
  }
  if (found_idx == UINT64_MAX) return;

  // Swap with last and shrink
  const uint64_t last = count - 1;
  if (found_idx != last)
  {
    uint8_t last_buf[32]; size_t sz = 0;
    if (pbc_load_packed_props(db, prefix + "_" + std::to_string(last), last_buf, 32, sz) && sz == 32)
      pbc_store_packed_props(db, prefix + "_" + std::to_string(found_idx), last_buf, 32);
  }
  db->delete_property(prefix + "_" + std::to_string(last));
  db->set_property_uint64(prefix + "_count", last);

  // Remove detail keys
  db->delete_property(pbc_sold_detail_key(seller, dep_id, "_price"));
  db->delete_property(pbc_sold_detail_key(seller, dep_id, "_reward"));
  db->delete_property(pbc_sold_detail_key(seller, dep_id, "_height"));
  db->delete_property(pbc_sold_detail_key(seller, dep_id, "_principal"));
  pbc_delete_packed_props(db, pbc_sold_detail_key(seller, dep_id, "_buyer"));
}

static bool pbc_get_collateral_lock_record(cryptonote::BlockchainDB *db, const crypto::hash &lock_id, cryptonote::collateral_lock_record &rec)
{
  uint8_t buf[cryptonote::PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE];
  size_t sz = sizeof(buf);
  if (!db->get_pbc_collateral_lock(lock_id, buf, sz))
    return false;
  return cryptonote::pbc_unpack_collateral_lock_record(buf, sz, rec);
}

static void pbc_add_collateral_lock_record(cryptonote::BlockchainDB *db, const cryptonote::collateral_lock_record &rec)
{
  uint8_t buf[cryptonote::PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE];
  cryptonote::pbc_pack_collateral_lock_record(rec, buf);
  db->add_pbc_collateral_lock(rec.lock_id, buf, sizeof(buf));
  if (rec.status == cryptonote::PBC_COLLATERAL_LOCK_ACTIVE)
  {
    db->set_active_pbc_collateral_lock_for_deposit(rec.deposit_id, rec.lock_id);
    const auto expiry_key = pbc_make_lock_expiry_key(rec.expiry_height, rec.lock_id);
    db->add_pbc_collateral_lock_expiry(expiry_key.data(), expiry_key.size());
  }
}

static void pbc_remove_collateral_lock_record(cryptonote::BlockchainDB *db, const cryptonote::collateral_lock_record &rec)
{
  db->remove_pbc_collateral_lock(rec.lock_id);
  db->clear_active_pbc_collateral_lock_for_deposit(rec.deposit_id);
  const auto expiry_key = pbc_make_lock_expiry_key(rec.expiry_height, rec.lock_id);
  db->remove_pbc_collateral_lock_expiry(expiry_key.data(), expiry_key.size());
}

static void pbc_update_collateral_lock_status(cryptonote::BlockchainDB *db, cryptonote::collateral_lock_record &rec, uint8_t new_status)
{
  pbc_remove_collateral_lock_record(db, rec);
  rec.status = new_status;
  uint8_t buf[cryptonote::PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE];
  cryptonote::pbc_pack_collateral_lock_record(rec, buf);
  db->add_pbc_collateral_lock(rec.lock_id, buf, sizeof(buf));
}

static uint64_t pbc_sum_vout_amounts(const cryptonote::transaction &tx)
{
  uint64_t sum = 0;
  for (const auto &o : tx.vout)
  {
    if (sum > std::numeric_limits<uint64_t>::max() - o.amount)
      return std::numeric_limits<uint64_t>::max();
    sum += o.amount;
  }
  return sum;
}

static bool pbc_tx_has_output_amount(const cryptonote::transaction &tx, uint64_t amount)
{
  uint64_t sum = 0;
  for (const auto &o : tx.vout)
  {
    if (o.amount == amount)
      return true;
    if (sum <= std::numeric_limits<uint64_t>::max() - o.amount)
      sum += o.amount;
  }
  return sum == amount;
}

static bool pbc_tx_has_market_payout_amount(const cryptonote::transaction &tx, uint64_t amount)
{
  if (tx.vout.empty())
    return false;

  if (tx.rct_signatures.type == rct::RCTTypeNull)
    return pbc_tx_has_output_amount(tx, amount);

  return !tx.vout.empty();
}

struct pbc_transfer_claim_apply_result
{
  __uint128_t effective_dep_idx = 0;
  __uint128_t effective_fee_idx = 0;
  uint64_t fresh_reward = 0;
  uint64_t pending_reward = 0;
  uint64_t materialized_reward = 0;
  uint64_t dep_debit = 0;
  uint64_t fee_debit = 0;
};

static bool pbc_apply_implicit_claim_for_transfer(
    cryptonote::BlockchainDB *db,
    cryptonote::pbc_pool_state &pool_state,
    const crypto::hash &deposit_id,
    cryptonote::pbc_deposit_record &dep_rec,
    uint64_t block_height,
    const crypto::hash &xfer_tx_id,
    pbc_transfer_claim_apply_result &out,
    std::string &fail_reason)
{
  out = {};
  out.effective_dep_idx = pool_state.global_deposit_index;
  out.effective_fee_idx = pool_state.global_fee_index;

  if (dep_rec.unlock_height <= block_height)
  {
    const uint64_t freeze_boundary = ((dep_rec.unlock_height - 1) / PBC_DISTRIBUTION_PERIOD) * PBC_DISTRIBUTION_PERIOD;
    if (block_height >= freeze_boundary + PBC_DISTRIBUTION_PERIOD)
    {
      const uint64_t snapshot_boundary = freeze_boundary + PBC_DISTRIBUTION_PERIOD;
      __uint128_t snap_dep = 0, snap_fee = 0;
      bool ok_dep = db->get_property_uint128(cryptonote::pbc_delta_key(PBC_DELTA_KEY_IDX_DI, snapshot_boundary), snap_dep);
      bool ok_fee = db->get_property_uint128(cryptonote::pbc_delta_key(PBC_DELTA_KEY_IDX_FI, snapshot_boundary), snap_fee);
      if (!(ok_dep && ok_fee))
      {
        fail_reason = std::string("missing frozen index snapshot at boundary ") + std::to_string(snapshot_boundary)
          + " for transfer deposit " + epee::string_tools::pod_to_hex(deposit_id);
        return false;
      }
      out.effective_dep_idx = snap_dep;
      out.effective_fee_idx = snap_fee;
    }
  }

  __uint128_t delta_dep = 0;
  __uint128_t delta_fee = 0;
  if (out.effective_dep_idx >= dep_rec.deposit_entry_index)
    delta_dep = out.effective_dep_idx - dep_rec.deposit_entry_index;
  if (out.effective_fee_idx >= dep_rec.fee_entry_index)
    delta_fee = out.effective_fee_idx - dep_rec.fee_entry_index;

  __uint128_t raw_reward_dep = (delta_dep * dep_rec.weight) / (__uint128_t)PBC_SCALE;
  __uint128_t raw_reward_fee = (delta_fee * dep_rec.weight) / (__uint128_t)PBC_SCALE;
  if (!(raw_reward_dep <= UINT64_MAX && raw_reward_fee <= UINT64_MAX))
  {
    fail_reason = std::string("implicit claim overflow on transfer tx=") + epee::string_tools::pod_to_hex(xfer_tx_id);
    return false;
  }

  const uint64_t reward_dep = (uint64_t)raw_reward_dep;
  const uint64_t reward_fee = (uint64_t)raw_reward_fee;

  const uint64_t pools_total = pool_state.deposit_pool_balance + pool_state.fee_pool_balance;
  if (pool_state.pending_rewards_total > pools_total)
  {
    fail_reason = "pending rewards exceed available pools before transfer";
    return false;
  }
  const uint64_t available_total = pools_total - pool_state.pending_rewards_total;
  out.fresh_reward = reward_dep + reward_fee;
  if (out.fresh_reward > available_total)
    out.fresh_reward = available_total;

  out.pending_reward = dep_rec.accumulated_reward;
  if (pool_state.pending_rewards_total < out.pending_reward)
  {
    fail_reason = "pending rewards underflow on transfer";
    return false;
  }
  pool_state.pending_rewards_total -= out.pending_reward;

  out.materialized_reward = out.pending_reward + out.fresh_reward;
  out.dep_debit = out.materialized_reward;
  if (out.dep_debit > pool_state.deposit_pool_balance)
    out.dep_debit = pool_state.deposit_pool_balance;
  out.fee_debit = out.materialized_reward - out.dep_debit;
  if (pool_state.fee_pool_balance < out.fee_debit)
  {
    fail_reason = "fee pool underflow on transfer payout";
    return false;
  }

  pool_state.deposit_pool_balance -= out.dep_debit;
  pool_state.fee_pool_balance -= out.fee_debit;

  dep_rec.deposit_entry_index = out.effective_dep_idx;
  dep_rec.fee_entry_index = out.effective_fee_idx;
  dep_rec.last_claim_height = block_height;
  dep_rec.accumulated_reward = 0;
  dep_rec.total_withdrawn += out.materialized_reward;
  return true;
}

static void pbc_process_collateral_lock_expiries(cryptonote::BlockchainDB *db, uint64_t block_height)
{
  std::vector<cryptonote::collateral_lock_record> to_expire;
  db->for_each_pbc_collateral_lock_expiry([&](const void* key, size_t key_size) {
    if (key_size < 8 + sizeof(crypto::hash))
      return true;
    uint64_t expiry_height = 0;
    crypto::hash lock_id = crypto::null_hash;
    std::memcpy(&expiry_height, key, 8);
    std::memcpy(&lock_id, static_cast<const uint8_t*>(key) + 8, sizeof(lock_id));
    if (expiry_height > block_height)
      return true;
    cryptonote::collateral_lock_record rec{};
    if (pbc_get_collateral_lock_record(db, lock_id, rec) && rec.status == cryptonote::PBC_COLLATERAL_LOCK_ACTIVE)
      to_expire.push_back(rec);
    return true;
  });

  db->set_property_uint64(std::string("pbc_market_exp_count_") + std::to_string(block_height), static_cast<uint64_t>(to_expire.size()));
  for (size_t i = 0; i < to_expire.size(); ++i)
  {
    uint8_t buf[cryptonote::PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE];
    cryptonote::pbc_pack_collateral_lock_record(to_expire[i], buf);
    pbc_store_packed_props(db, std::string("pbc_market_exp_") + std::to_string(block_height) + "_" + std::to_string(i), buf, sizeof(buf));
    auto rec = to_expire[i];
    pbc_update_collateral_lock_status(db, rec, cryptonote::PBC_COLLATERAL_LOCK_EXPIRED);
  }
}
static bool pbc_block_has_withdraw_for_deposit(const std::vector<std::pair<cryptonote::transaction, cryptonote::blobdata>> &txs, const crypto::hash &deposit_id)
{
  for (const auto &entry : txs)
  {
    crypto::hash dep{};
    uint64_t payout = 0;
    uint8_t kind = 0;
    std::string fail;
    if (cryptonote::pbc_validate_withdraw_tx(entry.first, dep, payout, kind, fail) == cryptonote::PBC_WITHDRAW_VALID && dep == deposit_id)
      return true;
  }
  return false;
}

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain"

#define FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE (100*1024*1024) // 100 MB

using namespace crypto;

//#include "serialization/json_archive.h"

/* TODO:
 *  Clean up code:
 *    Possibly change how outputs are referred to/indexed in blockchain and wallets
 *
 */

using namespace cryptonote;
using epee::string_tools::pod_to_hex;
extern "C" void slow_hash_allocate_state();
extern "C" void slow_hash_free_state();
extern "C" void slow_hash_free_state_cn_only(); // PBC: preserves RandomX VMs

DISABLE_VS_WARNINGS(4267)

#define MERROR_VER(x) MCERROR("verify", x)

// used to overestimate the block reward when estimating a per kB to use
#define BLOCK_REWARD_OVERESTIMATE (10 * 1000000000000)

//------------------------------------------------------------------
Blockchain::Blockchain(tx_memory_pool& tx_pool) :
  m_db(), m_tx_pool(tx_pool), m_hardfork(NULL), m_timestamps_and_difficulties_height(0), m_reset_timestamps_and_difficulties_height(true), m_current_block_cumul_weight_limit(0), m_current_block_cumul_weight_median(0),
  m_enforce_dns_checkpoints(false), m_max_prepare_blocks_threads(4), m_db_sync_on_blocks(true), m_db_sync_threshold(1), m_db_sync_mode(db_async), m_db_default_sync(false), m_fast_sync(true), m_show_time_stats(false), m_sync_counter(0), m_bytes_to_sync(0), m_cancel(false),
  m_long_term_block_weights_window(CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE),
  m_long_term_effective_median_block_weight(0),
  m_long_term_block_weights_cache_tip_hash(crypto::null_hash),
  m_long_term_block_weights_cache_rolling_median(CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE),
  m_difficulty_for_next_block_top_hash(crypto::null_hash),
  m_difficulty_for_next_block(1),
  m_btc_valid(false),
  m_batch_success(true),
  m_prepare_height(0),
  m_rct_ver_cache()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
}
//------------------------------------------------------------------
Blockchain::~Blockchain()
{
  try { deinit(); }
  catch (const std::exception &e) { /* ignore */ }
}
//------------------------------------------------------------------
bool Blockchain::have_tx(const crypto::hash &id) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->tx_exists(id);
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimg_as_spent(const crypto::key_image &key_im) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return  m_db->has_key_image(key_im);
}
//------------------------------------------------------------------
// This function makes sure that each "input" in an input (mixins) exists
// and collects the public key for each from the transaction it was included in
// via the visitor passed to it.
template <class visitor_t>
bool Blockchain::scan_outputkeys_for_indexes(size_t tx_version, const txin_to_key& tx_in_to_key, visitor_t &vis, const crypto::hash &tx_prefix_hash, uint64_t* pmax_related_block_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // ND: Disable locking and make method private.
  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // verify that the input has key offsets (that it exists properly, really)
  if(!tx_in_to_key.key_offsets.size())
    return false;

  // cryptonote_format_utils uses relative offsets for indexing to the global
  // outputs list.  that is to say that absolute offset #2 is absolute offset
  // #1 plus relative offset #2.
  // TODO: Investigate if this is necessary / why this is done.
  std::vector<uint64_t> absolute_offsets = relative_output_offsets_to_absolute(tx_in_to_key.key_offsets);
  std::vector<output_data_t> outputs;

  bool found = false;
  auto it = m_scan_table.find(tx_prefix_hash);
  if (it != m_scan_table.end())
  {
    auto its = it->second.find(tx_in_to_key.k_image);
    if (its != it->second.end())
    {
      outputs = its->second;
      found = true;
    }
  }

  if (!found)
  {
    try
    {
      m_db->get_output_key(epee::span<const uint64_t>(&tx_in_to_key.amount, 1), absolute_offsets, outputs, true);
      if (absolute_offsets.size() != outputs.size())
      {
        MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
        return false;
      }
    }
    catch (...)
    {
      MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
      return false;
    }
  }
  else
  {
    // check for partial results and add the rest if needed;
    if (outputs.size() < absolute_offsets.size() && outputs.size() > 0)
    {
      MDEBUG("Additional outputs needed: " << absolute_offsets.size() - outputs.size());
      std::vector < uint64_t > add_offsets;
      std::vector<output_data_t> add_outputs;
      add_outputs.reserve(absolute_offsets.size() - outputs.size());
      for (size_t i = outputs.size(); i < absolute_offsets.size(); i++)
        add_offsets.push_back(absolute_offsets[i]);
      try
      {
        m_db->get_output_key(epee::span<const uint64_t>(&tx_in_to_key.amount, 1), add_offsets, add_outputs, true);
        if (add_offsets.size() != add_outputs.size())
        {
          MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
          return false;
        }
      }
      catch (...)
      {
        MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
        return false;
      }
      outputs.insert(outputs.end(), add_outputs.begin(), add_outputs.end());
    }
  }

  size_t count = 0;
  for (const uint64_t& i : absolute_offsets)
  {
    try
    {
      output_data_t output_index;
      try
      {
        // get tx hash and output index for output
        if (count < outputs.size())
          output_index = outputs.at(count);
        else
          output_index = m_db->get_output_key(tx_in_to_key.amount, i);

        // call to the passed boost visitor to grab the public key for the output
        if (!vis.handle_output(output_index.unlock_time, output_index.pubkey, output_index.commitment))
        {
          MERROR_VER("Failed to handle_output for output no = " << count << ", with absolute offset " << i);
          return false;
        }
      }
      catch (...)
      {
        MERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount << ", absolute_offset = " << i);
        return false;
      }

      // if on last output and pmax_related_block_height not null pointer
      if(++count == absolute_offsets.size() && pmax_related_block_height)
      {
        // set *pmax_related_block_height to tx block height for this output
        auto h = output_index.height;
        if(*pmax_related_block_height < h)
        {
          *pmax_related_block_height = h;
        }
      }

    }
    catch (const OUTPUT_DNE& e)
    {
      MERROR_VER("Output does not exist: " << e.what());
      return false;
    }
    catch (const TX_DNE& e)
    {
      MERROR_VER("Transaction does not exist: " << e.what());
      return false;
    }

  }

  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_blockchain_height() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->height();
}
//------------------------------------------------------------------
//FIXME: possibly move this into the constructor, to avoid accidentally
//       dereferencing a null BlockchainDB pointer
bool Blockchain::init(BlockchainDB* db, const network_type nettype, bool offline, const cryptonote::test_options *test_options, difficulty_type fixed_difficulty, const GetCheckpointsCallback& get_checkpoints/* = nullptr*/)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  CHECK_AND_ASSERT_MES(nettype != FAKECHAIN || test_options, false, "fake chain network type used without options");

  CRITICAL_REGION_LOCAL(m_tx_pool);
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  if (db == nullptr)
  {
    LOG_ERROR("Attempted to init Blockchain with null DB");
    return false;
  }
  if (!db->is_open())
  {
    LOG_ERROR("Attempted to init Blockchain with unopened DB");
    delete db;
    return false;
  }

  m_db = db;

  m_nettype = test_options != NULL ? FAKECHAIN : nettype;
  m_offline = offline;
  m_fixed_difficulty = fixed_difficulty;
  if (m_hardfork == nullptr)
  {
    if (m_nettype ==  FAKECHAIN || m_nettype == STAGENET)
      m_hardfork = new HardFork(*db, 17, 0);
    else if (m_nettype == TESTNET)
      m_hardfork = new HardFork(*db, 17, testnet_hard_fork_version_1_till);
    else
      m_hardfork = new HardFork(*db, 17, mainnet_hard_fork_version_1_till);
  }
  if (m_nettype == FAKECHAIN)
  {
    for (size_t n = 0; test_options->hard_forks[n].first; ++n)
      m_hardfork->add_fork(test_options->hard_forks[n].first, test_options->hard_forks[n].second, 0, n + 1);
  }
  else if (m_nettype == TESTNET)
  {
    for (size_t n = 0; n < num_testnet_hard_forks; ++n)
      m_hardfork->add_fork(testnet_hard_forks[n].version, testnet_hard_forks[n].height, testnet_hard_forks[n].threshold, testnet_hard_forks[n].time);
  }
  else if (m_nettype == STAGENET)
  {
    for (size_t n = 0; n < num_stagenet_hard_forks; ++n)
      m_hardfork->add_fork(stagenet_hard_forks[n].version, stagenet_hard_forks[n].height, stagenet_hard_forks[n].threshold, stagenet_hard_forks[n].time);
  }
  else
  {
    for (size_t n = 0; n < num_mainnet_hard_forks; ++n)
      m_hardfork->add_fork(mainnet_hard_forks[n].version, mainnet_hard_forks[n].height, mainnet_hard_forks[n].threshold, mainnet_hard_forks[n].time);
  }
  m_hardfork->init();

  m_db->set_hard_fork(m_hardfork);

  // if the blockchain is new, add the genesis block
  // this feels kinda kludgy to do it this way, but can be looked at later.
  // TODO: add function to create and store genesis block,
  //       taking testnet into account
  if(!m_db->height())
  {
    MINFO("Blockchain not loaded, generating genesis block.");
    block bl;
    block_verification_context bvc = {};
    generate_genesis_block(bl, get_config(m_nettype).GENESIS_TX, get_config(m_nettype).GENESIS_NONCE);
    db_wtxn_guard wtxn_guard(m_db);
    add_new_block(bl, bvc);
    CHECK_AND_ASSERT_MES(!bvc.m_verifivation_failed, false, "Failed to add genesis block to blockchain");
  }
  // TODO: if blockchain load successful, verify blockchain against both
  //       hard-coded and runtime-loaded (and enforced) checkpoints.
  else
  {
  }

  if (m_nettype != FAKECHAIN)
  {
    // ensure we fixup anything we found and fix in the future
    m_db->fixup();
  }

  db_rtxn_guard rtxn_guard(m_db);

  // check how far behind we are
  uint64_t top_block_timestamp = m_db->get_top_block_timestamp();
  uint64_t timestamp_diff = time(NULL) - top_block_timestamp;

  // genesis block has no timestamp, could probably change it to have timestamp of 1522624244 (2018-04-01 23:10:44, block 1)...
  if(!top_block_timestamp)
    timestamp_diff = time(NULL) - 1522624244;

  // create general purpose async service queue

  m_async_work_idle = std::make_unique<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(m_async_service.get_executor());
  // we only need 1
  m_async_pool.create_thread(boost::bind(&boost::asio::io_context::run, &m_async_service));

#if defined(PER_BLOCK_CHECKPOINT)
  if (m_nettype != FAKECHAIN)
    load_compiled_in_block_hashes(get_checkpoints);
#endif

  MINFO("Blockchain initialized. last block: " << m_db->height() - 1 << ", " << epee::misc_utils::get_time_interval_string(timestamp_diff) << " time ago, current difficulty: " << get_difficulty_for_next_block(m_nettype));

  rtxn_guard.stop();

  uint64_t num_popped_blocks = 0;
  while (!m_db->is_read_only())
  {
    uint64_t top_height;
    const crypto::hash top_id = m_db->top_block_hash(&top_height);
    const block top_block = m_db->get_top_block();
    const uint8_t ideal_hf_version = get_ideal_hard_fork_version(top_height);
    if (ideal_hf_version <= 1 || ideal_hf_version == top_block.major_version)
    {
      if (num_popped_blocks > 0)
        MGINFO("Initial popping done, top block: " << top_id << ", top height: " << top_height << ", block version: " << (uint64_t)top_block.major_version);
      break;
    }
    else
    {
      if (num_popped_blocks == 0)
        MGINFO("Current top block " << top_id << " at height " << top_height << " has version " << (uint64_t)top_block.major_version << " which disagrees with the ideal version " << (uint64_t)ideal_hf_version);
      if (num_popped_blocks % 100 == 0)
        MGINFO("Popping blocks... " << top_height);
      ++num_popped_blocks;
      block popped_block;
      std::vector<transaction> popped_txs;
      try
      {
        m_db->pop_block(popped_block, popped_txs);
      }
      // anything that could cause this to throw is likely catastrophic,
      // so we re-throw
      catch (const std::exception& e)
      {
        MERROR("Error popping block from blockchain: " << e.what());
        throw;
      }
      catch (...)
      {
        MERROR("Error popping block from blockchain, throwing!");
        throw;
      }
    }
  }
  if (num_popped_blocks > 0)
  {
    m_timestamps_and_difficulties_height = 0;
    m_reset_timestamps_and_difficulties_height = true;
    m_hardfork->reorganize_from_chain_height(get_current_blockchain_height());
    uint64_t top_block_height;
    crypto::hash top_block_hash = get_tail_id(top_block_height);
    m_tx_pool.on_blockchain_dec(top_block_height, top_block_hash);
  }

  if (test_options && test_options->long_term_block_weight_window)
  {
    m_long_term_block_weights_window = test_options->long_term_block_weight_window;
    m_long_term_block_weights_cache_rolling_median = epee::misc_utils::rolling_median_t<uint64_t>(m_long_term_block_weights_window);
  }

  bool difficulty_ok;
  uint64_t difficulty_recalc_height;
  std::tie(difficulty_ok, difficulty_recalc_height) = check_difficulty_checkpoints();
  if (!difficulty_ok)
  {
    MERROR("Difficulty drift detected!");
    recalculate_difficulties(difficulty_recalc_height);
  }

  {
    db_txn_guard txn_guard(m_db, m_db->is_read_only());
    if (!update_next_cumulative_weight_limit())
      return false;
  }

  if (m_hardfork->get_current_version() >= RX_BLOCK_VERSION)
  {
    const crypto::hash seedhash = get_block_id_by_height(crypto::rx_seedheight(m_db->height()));
    if (seedhash != crypto::null_hash)
      rx_set_main_seedhash(seedhash.data, tools::get_max_concurrency());
  }

  // PBC: Load virtual pool state from LMDB
  pbc_load_pool_state();
  LOG_PRINT_L0("PBC Pool State loaded: deposit_pool=" << m_pbc_pool_state.deposit_pool_balance
    << " fee_pool=" << m_pbc_pool_state.fee_pool_balance
    << " insurance_pool=" << m_pbc_pool_state.insurance_pool_balance
    << " destroyed=" << m_pbc_pool_state.total_destroyed
    << " vested=" << m_pbc_pool_state.total_vested_outputs
    << " Σw=" << m_pbc_pool_state.deposit_sum_weights
    << " dep_idx_hi=" << (uint64_t)(m_pbc_pool_state.global_deposit_index >> 64)
    << " dep_idx_lo=" << (uint64_t)(m_pbc_pool_state.global_deposit_index)
    << " fee_idx_hi=" << (uint64_t)(m_pbc_pool_state.global_fee_index >> 64)
    << " fee_idx_lo=" << (uint64_t)(m_pbc_pool_state.global_fee_index));

  return true;
}
//------------------------------------------------------------------
bool Blockchain::init(BlockchainDB* db, HardFork*& hf, const network_type nettype, bool offline)
{
  if (hf != nullptr)
    m_hardfork = hf;
  bool res = init(db, nettype, offline, NULL);
  if (hf == nullptr)
    hf = m_hardfork;
  return res;
}
//------------------------------------------------------------------
bool Blockchain::store_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // lock because the rpc_thread command handler also calls this
  CRITICAL_REGION_LOCAL(m_db->m_synchronization_lock);

  TIME_MEASURE_START(save);
  // TODO: make sure sync(if this throws that it is not simply ignored higher
  // up the call stack
  try
  {
    m_db->sync();
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Error syncing blockchain db: ") + e.what() + "-- shutting down now to prevent issues!");
    throw;
  }
  catch (...)
  {
    MERROR("There was an issue storing the blockchain, shutting down now to prevent issues!");
    throw;
  }

  TIME_MEASURE_FINISH(save);
  if(m_show_time_stats)
    MINFO("Blockchain stored OK, took: " << save << " ms");
  return true;
}
//------------------------------------------------------------------
bool Blockchain::deinit()
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  MTRACE("Stopping blockchain read/write activity");

 // stop async service
  m_async_work_idle.reset();
  m_async_pool.join_all();
  m_async_service.stop();

  // as this should be called if handling a SIGSEGV, need to check
  // if m_db is a NULL pointer (and thus may have caused the illegal
  // memory operation), otherwise we may cause a loop.
  try
  {
    if (m_db)
    {
      m_db->close();
      MTRACE("Local blockchain read/write activity stopped successfully");
    }
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(std::string("Error closing blockchain db: ") + e.what());
  }
  catch (...)
  {
    LOG_ERROR("There was an issue closing/storing the blockchain, shutting down now to prevent issues!");
  }

  delete m_hardfork;
  m_hardfork = NULL;
  delete m_db;
  m_db = NULL;
  return true;
}
//------------------------------------------------------------------
// This function removes blocks from the top of blockchain.
// It starts a batch and calls private method pop_block_from_blockchain().
bool Blockchain::pop_blocks(uint64_t nblocks)
{
  uint64_t i = 0;
  CRITICAL_REGION_LOCAL(m_tx_pool);
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  bool stop_batch = m_db->batch_start();

  try
  {
    const uint64_t blockchain_height = m_db->height();
    if (blockchain_height > 0)
      nblocks = std::min(nblocks, blockchain_height - 1);
    while (i < nblocks)
    {
      pop_block_from_blockchain();
      ++i;
    }
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("Error when popping blocks after processing " << i << " blocks: " << e.what());
    if (stop_batch)
      m_db->batch_abort();
    return false;
  }

  CHECK_AND_ASSERT_THROW_MES(update_next_cumulative_weight_limit(), "Error updating next cumulative weight limit");

  if (stop_batch)
    m_db->batch_stop();

  if (m_hardfork->get_current_version() >= RX_BLOCK_VERSION)
  {
    const crypto::hash seedhash = get_block_id_by_height(crypto::rx_seedheight(m_db->height()));
    rx_set_main_seedhash(seedhash.data, tools::get_max_concurrency());
  }

  return true;
}
//------------------------------------------------------------------
// This function tells BlockchainDB to remove the top block from the
// blockchain and then returns all transactions (except the miner tx, of course)
// from it to the tx_pool
block Blockchain::pop_block_from_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;

  block popped_block;
  std::vector<transaction> popped_txs;

  CHECK_AND_ASSERT_THROW_MES(m_db->height() > 1, "Cannot pop the genesis block");

  const uint8_t previous_hf_version = get_current_hard_fork_version();

  // ═══════════════════════════════════════════════════════════════
  // PBC ATOMICITY GUARANTEE: If no batch is active, start one so that
  // m_db->pop_block() + PBC revert writes are in the SAME LMDB txn.
  // Without this, pop_block's block_wtxn_start() creates and commits
  // its own standalone txn, then our PBC writes would be separate.
  // ═══════════════════════════════════════════════════════════════
  bool pbc_started_batch = false;
  if (previous_hf_version >= HF_VERSION_VESTING && !m_db->is_batch_active())
  {
    LOG_PRINT_L1("PBC: No active batch — starting local batch for pop+revert atomicity");
    m_db->batch_start();
    pbc_started_batch = true;
  }
  MDEBUG("PBC atomicity: batch_active=" << m_db->is_batch_active()
    << " pbc_started_batch=" << pbc_started_batch
    << " (pre-pop_block)");

  // ═══════════════════════════════════════════════════════════════
  // PBC FIX: Save generated_coins BEFORE pop_block() removes the block.
  // After pop, block_info for the popped block no longer exists in DB.
  // ═══════════════════════════════════════════════════════════════
  uint64_t pbc_pre_pop_height = 0;
  uint64_t pbc_coins_at_top = 0;
  uint64_t pbc_coins_before_top = 0;
  if (previous_hf_version >= HF_VERSION_VESTING)
  {
    pbc_pre_pop_height = m_db->height();  // e.g. 722 (blocks 0..721 exist)
    pbc_coins_at_top = m_db->get_block_already_generated_coins(pbc_pre_pop_height - 1);  // block 721
    pbc_coins_before_top = (pbc_pre_pop_height >= 2)
        ? m_db->get_block_already_generated_coins(pbc_pre_pop_height - 2)  // block 720
        : 0;
  }

  try
  {
    m_db->pop_block(popped_block, popped_txs);
  }
  // anything that could cause this to throw is likely catastrophic,
  // so we re-throw
  catch (const std::exception& e)
  {
    LOG_ERROR("Error popping block from blockchain: " << e.what());
    if (pbc_started_batch) m_db->batch_abort();
    throw;
  }
  catch (...)
  {
    LOG_ERROR("Error popping block from blockchain, throwing!");
    if (pbc_started_batch) m_db->batch_abort();
    throw;
  }

  // make sure the hard fork object updates its current version
  m_hardfork->on_block_popped(1);

  // ═══════════════════════════════════════════════════════════════
  // PBC: Revert virtual reward pool state for the popped block
  // ═══════════════════════════════════════════════════════════════
  if (previous_hf_version >= HF_VERSION_VESTING)
  {
    // STRUCTURAL GUARANTEE: batch must be active here
    assert(m_db->is_batch_active());
    MDEBUG("PBC atomicity: batch_active=" << m_db->is_batch_active()
      << " pbc_started_batch=" << pbc_started_batch
      << " (during PBC revert)");

    // CRITICAL GUARD: Same atomicity requirement as add_block.
    // Pool state revert + delta key deletion MUST be in same LMDB transaction
    // as the block pop. Otherwise a crash mid-revert corrupts consensus state.
    CHECK_AND_ASSERT_THROW_MES(m_db->is_batch_active(),
      "FATAL: PBC pool state revert requires active LMDB batch transaction. "
      "Pop and pool revert must be atomic. Aborting to prevent corruption.");

#ifdef PBC_CRASH_TEST_AFTER_POP_BLOCK
    // ── CRASH INJECTION (compile-time debug only) ──
    // Simulates a crash AFTER m_db->pop_block() but BEFORE PBC revert.
    // Expected: batch is aborted, both pop and revert are rolled back,
    // DB state is as-if nothing happened (block still present).
    LOG_ERROR("PBC_CRASH_TEST: Throwing after pop_block but before PBC revert");
    if (pbc_started_batch) m_db->batch_abort();
    throw std::runtime_error("PBC_CRASH_TEST: simulated crash after pop_block");
#endif

    // Recompute the block split for the popped block
    // Using values saved BEFORE pop_block() (block no longer in DB after pop)
    uint64_t popped_height = pbc_pre_pop_height - 1;  // height of the block being popped
    uint64_t popped_R = pbc_coins_at_top - pbc_coins_before_top;

    // Calculate total fees from the popped block's transactions
    uint64_t popped_fees = 0;
    for (const auto& tx : popped_txs)
    {
      if (!is_coinbase(tx))
      {
        // Fee = sum of inputs - sum of outputs (for RCT, fee is stored explicitly)
        popped_fees += get_tx_fee(tx);
      }
    }

    pbc_block_split split = pbc_compute_block_split(popped_R, popped_fees);

    // ═══════════════════════════════════════════════════════════
    // REVERT in REVERSE order of application:
    //   Apply order:  idx_update → block_reward → vesting → subsidy → overflow → deposits → claims → withdraw
    //   Revert order: withdraw → claims → deposits → overflow → subsidy → vesting → block_reward → idx_update
    // ═══════════════════════════════════════════════════════════

    // ── 0a. PF: Revert MARKET_PAYOUT_CLAIM (applied before TERM_WITHDRAW) ──
    for (const auto& tx : popped_txs)
    {
      if (is_coinbase(tx))
        continue;
      const crypto::hash p_tx_id = get_transaction_hash(tx);
      crypto::public_key seller_pubkey;
      uint64_t payout_amount = 0;
      std::string p_fail;
      const pbc_market_payout_result pres = pbc_validate_market_payout_tx(tx, seller_pubkey, payout_amount, p_fail);
      if (pres != PBC_MARKET_PAYOUT_VALID)
        continue;

      uint64_t prev_balance = 0;
      if (!m_db->get_property_uint64(pbc_market_key(p_tx_id, "_mktpay_prev"), prev_balance))
      {
        LOG_ERROR("PBC MKTPAY: Cannot find payout_prev for tx=" << p_tx_id << " — skipping revert");
        continue;
      }

      // Restore pbc_mktpay balance (pool was already credited at auto-match time, no pool restoration needed here).
      m_db->set_property_uint64(pbc_mktpay_key(seller_pubkey), prev_balance);
      m_db->delete_property(pbc_market_key(p_tx_id, "_mktpay_prev"));

      MGINFO("PBC MKTPAY: MARKET_PAYOUT_CLAIM reverted: tx=" << p_tx_id
        << " seller=" << seller_pubkey << " restored=" << prev_balance);
    }

    // ── 0a. PF: Revert TERM_WITHDRAW payouts (applied AFTER claims) ──
    for (const auto& tx : popped_txs)
    {
      if (is_coinbase(tx))
        continue;

      crypto::hash w_tx_id = get_transaction_hash(tx);
      crypto::hash deposit_id;
      uint64_t payout_amount = 0;
      uint8_t payout_kind = 0;
      std::string w_fail;

      const pbc_withdraw_result wres = pbc_validate_withdraw_tx(tx, deposit_id, payout_amount, payout_kind, w_fail);
      if (wres != PBC_WITHDRAW_VALID)
        continue;

      uint64_t prev_ar = 0;
      if (!m_db->get_property_uint64(pbc_withdraw_key(w_tx_id, "_ar"), prev_ar))
      {
        LOG_ERROR("PBC PF: Cannot find withdraw delta for tx=" << w_tx_id << " — skipping revert");
        continue;
      }

      // Restore pool balances + pending reserve
      uint64_t dep_debit = 0, fee_debit = 0;
      m_db->get_property_uint64(pbc_withdraw_key(w_tx_id, "_dp"), dep_debit);
      m_db->get_property_uint64(pbc_withdraw_key(w_tx_id, "_fp"), fee_debit);
      m_pbc_pool_state.deposit_pool_balance += dep_debit;
      m_pbc_pool_state.fee_pool_balance     += fee_debit;
      m_pbc_pool_state.pending_rewards_total += payout_amount;

      // Restore deposit record accumulated_reward
      uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
      size_t dep_size = PBC_DEPOSIT_RECORD_PACKED_SIZE;
      if (m_db->get_pbc_deposit(deposit_id, dep_buf, dep_size))
      {
        pbc_deposit_record dep_rec;
        pbc_unpack_deposit_record(dep_buf, dep_size, dep_rec);
        dep_rec.accumulated_reward = prev_ar;
        if (dep_rec.total_withdrawn >= payout_amount)
          dep_rec.total_withdrawn -= payout_amount;
        else
          dep_rec.total_withdrawn = 0;  // safety clamp

        m_db->remove_pbc_deposit(deposit_id);
        uint8_t upd_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
        pbc_pack_deposit_record(dep_rec, upd_buf);
        m_db->add_pbc_deposit(deposit_id, upd_buf, PBC_DEPOSIT_RECORD_PACKED_SIZE);
      }

      m_db->delete_property(pbc_withdraw_key(w_tx_id, "_ar"));
      m_db->delete_property(pbc_withdraw_key(w_tx_id, "_dp"));
      m_db->delete_property(pbc_withdraw_key(w_tx_id, "_fp"));

      MGINFO("PBC PF: TERM_WITHDRAW reverted: tx=" << w_tx_id
        << " deposit=" << deposit_id
        << " restored_accumulated=" << prev_ar);
    }

    // ── 0ab. Marketplace: revert direct owner transfers ────────────────────
    for (const auto& tx : popped_txs)
    {
      if (is_coinbase(tx))
        continue;

      const crypto::hash tx_id = get_transaction_hash(tx);
      tx_extra_pbc_tx_type type_field{};
      if (!get_tx_extra_field_by_type(tx.extra, type_field) || type_field.type != PBC_TX_TYPE_TRANSFER_DEPOSIT)
        continue;

      tx_extra_pbc_transfer_deposit xfer_field{};
      if (!get_tx_extra_field_by_type(tx.extra, xfer_field))
        continue;

      uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
      size_t dep_sz = PBC_DEPOSIT_RECORD_PACKED_SIZE;
      if (m_db->get_pbc_deposit(xfer_field.deposit_id, dep_buf, dep_sz))
      {
        pbc_deposit_record dep_rec;
        pbc_unpack_deposit_record(dep_buf, dep_sz, dep_rec);

        const std::string base = pbc_market_key(tx_id, "");
        uint64_t w0=0,w1=0,w2=0,w3=0;
        if (m_db->get_property_uint64(base+"_old_owner_0", w0) &&
            m_db->get_property_uint64(base+"_old_owner_1", w1) &&
            m_db->get_property_uint64(base+"_old_owner_2", w2) &&
            m_db->get_property_uint64(base+"_old_owner_3", w3))
        {
          crypto::public_key old_owner{};
          std::memcpy(reinterpret_cast<uint8_t*>(&old_owner)+0,  &w0, 8);
          std::memcpy(reinterpret_cast<uint8_t*>(&old_owner)+8,  &w1, 8);
          std::memcpy(reinterpret_cast<uint8_t*>(&old_owner)+16, &w2, 8);
          std::memcpy(reinterpret_cast<uint8_t*>(&old_owner)+24, &w3, 8);
          dep_rec.owner_key = old_owner;
        }
        m_db->get_property_uint128(base+"_old_di", dep_rec.deposit_entry_index);
        m_db->get_property_uint128(base+"_old_fi", dep_rec.fee_entry_index);
        m_db->get_property_uint64(base+"_old_lh", dep_rec.last_claim_height);
        m_db->get_property_uint64(base+"_old_ar", dep_rec.accumulated_reward);
        m_db->get_property_uint64(base+"_old_tw", dep_rec.total_withdrawn);

        m_db->remove_pbc_deposit(xfer_field.deposit_id);
        uint8_t out[PBC_DEPOSIT_RECORD_PACKED_SIZE];
        pbc_pack_deposit_record(dep_rec, out);
        m_db->add_pbc_deposit(xfer_field.deposit_id, out, sizeof(out));

        m_db->get_property_uint64(base+"_old_dep_pool", m_pbc_pool_state.deposit_pool_balance);
        m_db->get_property_uint64(base+"_old_fee_pool", m_pbc_pool_state.fee_pool_balance);
        m_db->get_property_uint64(base+"_old_pending", m_pbc_pool_state.pending_rewards_total);

        uint8_t lock_buf[PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE];
        size_t lock_sz = 0;
        if (pbc_load_packed_props(m_db, base+"_lock", lock_buf, sizeof(lock_buf), lock_sz))
        {
          collateral_lock_record lock_rec{};
          if (pbc_unpack_collateral_lock_record(lock_buf, lock_sz, lock_rec))
          {
            pbc_remove_collateral_lock_record(m_db, lock_rec);
            lock_rec.status = PBC_COLLATERAL_LOCK_ACTIVE;
            pbc_add_collateral_lock_record(m_db, lock_rec);
          }
        }

        pbc_delete_packed_props(m_db, base+"_lock");
        m_db->delete_property(base+"_old_owner_0");
        m_db->delete_property(base+"_old_owner_1");
        m_db->delete_property(base+"_old_owner_2");
        m_db->delete_property(base+"_old_owner_3");
        m_db->delete_property(base+"_old_di");
        m_db->delete_property(base+"_old_fi");
        m_db->delete_property(base+"_old_lh");
        m_db->delete_property(base+"_old_ar");
        m_db->delete_property(base+"_old_tw");
        m_db->delete_property(base+"_old_dep_pool");
        m_db->delete_property(base+"_old_fee_pool");
        m_db->delete_property(base+"_old_pending");
        m_db->delete_property(base+"_dep_debit");
        m_db->delete_property(base+"_fee_debit");
        m_db->delete_property(base+"_materialized_reward");
      }
    }

    // ── 0abb. Marketplace: revert automatic expiries for popped height ────
    {
      uint64_t exp_count = 0;
      const std::string exp_count_key = std::string("pbc_market_exp_count_") + std::to_string(popped_height);
      if (m_db->get_property_uint64(exp_count_key, exp_count) && exp_count > 0)
      {
        for (uint64_t i = 0; i < exp_count; ++i)
        {
          const std::string base = std::string("pbc_market_exp_") + std::to_string(popped_height) + "_" + std::to_string(i);
          uint8_t lock_buf[PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE];
          size_t lock_sz = 0;
          if (!pbc_load_packed_props(m_db, base, lock_buf, sizeof(lock_buf), lock_sz))
            continue;
          collateral_lock_record lock_rec{};
          if (!pbc_unpack_collateral_lock_record(lock_buf, lock_sz, lock_rec))
            continue;
          pbc_remove_collateral_lock_record(m_db, lock_rec);
          lock_rec.status = PBC_COLLATERAL_LOCK_ACTIVE;
          pbc_add_collateral_lock_record(m_db, lock_rec);
          pbc_delete_packed_props(m_db, base);
        }
        m_db->delete_property(exp_count_key);
      }
    }

    // ── 0ac. Marketplace: revert CANCEL_LOCK / EXPIRY ─────────────────────
    for (const auto& tx : popped_txs)
    {
      if (is_coinbase(tx))
        continue;

      const crypto::hash tx_id = get_transaction_hash(tx);
      tx_extra_pbc_tx_type type_field{};
      if (!get_tx_extra_field_by_type(tx.extra, type_field) || type_field.type != PBC_TX_TYPE_CANCEL_LOCK)
        continue;

      uint8_t lock_buf[PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE];
      size_t lock_sz = 0;
      if (!pbc_load_packed_props(m_db, pbc_market_key(tx_id, "_cancel_lock"), lock_buf, sizeof(lock_buf), lock_sz))
        continue;
      collateral_lock_record lock_rec{};
      if (!pbc_unpack_collateral_lock_record(lock_buf, lock_sz, lock_rec))
        continue;

      pbc_remove_collateral_lock_record(m_db, lock_rec);
      lock_rec.status = PBC_COLLATERAL_LOCK_ACTIVE;
      pbc_add_collateral_lock_record(m_db, lock_rec);
      pbc_delete_packed_props(m_db, pbc_market_key(tx_id, "_cancel_lock"));
    }

    // ── 0ad. Marketplace: revert LOCK_COLLATERAL creations ─────────────────
    for (const auto& tx : popped_txs)
    {
      if (is_coinbase(tx))
        continue;

      const crypto::hash tx_id = get_transaction_hash(tx);
      tx_extra_pbc_tx_type type_field{};
      if (!get_tx_extra_field_by_type(tx.extra, type_field) || type_field.type != PBC_TX_TYPE_LOCK_COLLATERAL)
        continue;
      uint64_t applied = 0;
      if (!m_db->get_property_uint64(pbc_market_key(tx_id, "_lock_applied"), applied) || applied == 0)
        continue;

      // ── Revert auto-match if it was applied ──
      uint64_t am_applied = 0;
      if (m_db->get_property_uint64(pbc_market_key(tx_id, "_am_applied"), am_applied) && am_applied != 0)
      {
        tx_extra_pbc_lock_collateral lock_field{};
        if (get_tx_extra_field_by_type(tx.extra, lock_field))
        {
          // Restore pool state.
          uint64_t old_dep_pool = 0, old_fee_pool = 0, old_pending = 0;
          m_db->get_property_uint64(pbc_market_key(tx_id, "_am_old_dep_pool"), old_dep_pool);
          m_db->get_property_uint64(pbc_market_key(tx_id, "_am_old_fee_pool"), old_fee_pool);
          m_db->get_property_uint64(pbc_market_key(tx_id, "_am_old_pending"),  old_pending);
          m_pbc_pool_state.deposit_pool_balance  = old_dep_pool;
          m_pbc_pool_state.fee_pool_balance      = old_fee_pool;
          m_pbc_pool_state.pending_rewards_total = old_pending;

          // Restore pbc_mktpay.
          uint64_t prev_mktpay = 0;
          m_db->get_property_uint64(pbc_market_key(tx_id, "_am_prev_mktpay"), prev_mktpay);
          if (prev_mktpay > 0)
            m_db->set_property_uint64(pbc_mktpay_key(lock_field.seller_pubkey), prev_mktpay);
          else
            m_db->delete_property(pbc_mktpay_key(lock_field.seller_pubkey));

          // Restore deposit record (revert owner transfer + index reset).
          // We need to restore the pre-match dep_rec. The implicit claim already
          // updated dep_rec.owner_key, deposit_entry_index, fee_entry_index,
          // last_claim_height, accumulated_reward. We read the current (post-match)
          // record and restore it using the saved undo fields from the LOCK_COLLATERAL apply.
          uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
          size_t dep_sz = PBC_DEPOSIT_RECORD_PACKED_SIZE;
          if (m_db->get_pbc_deposit(lock_field.deposit_id, dep_buf, dep_sz))
          {
            pbc_deposit_record dep_rec;
            pbc_unpack_deposit_record(dep_buf, dep_sz, dep_rec);
            // Restore owner to seller.
            dep_rec.owner_key = lock_field.seller_pubkey;
            // Restore ALL deposit fields from pre-match undo keys.
            {
              __uint128_t old_dep_idx = 0, old_fee_idx = 0;
              uint64_t old_last_claim = 0, old_acc_reward = 0, old_total_withdrawn = 0;
              m_db->get_property_uint128(pbc_market_key(tx_id, "_am_old_dep_idx"), old_dep_idx);
              m_db->get_property_uint128(pbc_market_key(tx_id, "_am_old_fee_idx"), old_fee_idx);
              m_db->get_property_uint64(pbc_market_key(tx_id, "_am_old_last_claim_h"), old_last_claim);
              m_db->get_property_uint64(pbc_market_key(tx_id, "_am_old_acc_reward"), old_acc_reward);
              m_db->get_property_uint64(pbc_market_key(tx_id, "_am_old_total_withdrawn"), old_total_withdrawn);
              dep_rec.deposit_entry_index = old_dep_idx;
              dep_rec.fee_entry_index = old_fee_idx;
              dep_rec.last_claim_height = old_last_claim;
              dep_rec.accumulated_reward = old_acc_reward;
              dep_rec.total_withdrawn = old_total_withdrawn;
            }
            m_db->remove_pbc_deposit(lock_field.deposit_id);
            uint8_t upd[PBC_DEPOSIT_RECORD_PACKED_SIZE];
            pbc_pack_deposit_record(dep_rec, upd);
            m_db->add_pbc_deposit(lock_field.deposit_id, upd, sizeof(upd));
          }

          // Restore ask.
          // The ask was removed during auto-match. Restore it from MARKET_ASK undo keys
          // which are stored when the MARKET_ASK TX was applied (not this TX).
          // Since MARKET_ASK is replayed separately, we just note that the ask restoration
          // is handled by the 0ae MARKET_ASK revert loop when processing the original ask TX.
          // Here we only need to restore it if the ask is currently missing.
          // We stored the ask price in the lock TX for this purpose:
          uint64_t ask_price_at_match = 0;
          m_db->get_property_uint64(pbc_market_key(tx_id, "_am_ask_price"), ask_price_at_match);
          uint64_t existing_ask = 0;
          const bool ask_already_present = m_db->get_property_uint64(pbc_ask_dep_key(lock_field.deposit_id, "_price"), existing_ask);
          if (ask_price_at_match > 0 && !ask_already_present)
          {
            // Restore the ask using the seller pubkey + height + price we saved.
            m_db->set_property_uint64(pbc_ask_dep_key(lock_field.deposit_id, "_price"), ask_price_at_match);
            uint64_t ask_height = 0;
            m_db->get_property_uint64(pbc_market_key(tx_id, "_am_ask_height"), ask_height);
            m_db->set_property_uint64(pbc_ask_dep_key(lock_field.deposit_id, "_height"), ask_height);
            // Restore addr blob.
            uint8_t addr_buf[sizeof(cryptonote::account_public_address)];
            size_t addr_sz = sizeof(addr_buf);
            if (pbc_load_packed_props(m_db, pbc_market_key(tx_id, "_am_ask_addr"), addr_buf, sizeof(addr_buf), addr_sz))
              pbc_store_packed_props(m_db, pbc_ask_dep_key(lock_field.deposit_id, "_addr"), addr_buf, addr_sz);
            pbc_ask_list_add(m_db, lock_field.deposit_id);
          }

          // Remove this sale from seller's sold deposits history.
          pbc_sold_list_remove(m_db, lock_field.seller_pubkey, lock_field.deposit_id);

          // Clean up auto-match undo keys.
          m_db->delete_property(pbc_market_key(tx_id, "_am_old_dep_idx"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_old_fee_idx"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_old_last_claim_h"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_old_acc_reward"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_old_total_withdrawn"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_applied"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_dep_debit"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_fee_debit"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_mat_reward"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_prev_mktpay"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_old_dep_pool"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_old_fee_pool"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_old_pending"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_ask_price"));
          m_db->delete_property(pbc_market_key(tx_id, "_am_ask_height"));
          pbc_delete_packed_props(m_db, pbc_market_key(tx_id, "_am_ask_addr"));
        }
      }

      collateral_lock_record lock_rec{};
      if (pbc_get_collateral_lock_record(m_db, tx_id, lock_rec))
        pbc_remove_collateral_lock_record(m_db, lock_rec);
      m_db->delete_property(pbc_market_key(tx_id, "_lock_applied"));
    }

    // ── 0ae. Marketplace: revert MARKET_ASK ────────────────────────────────
    for (const auto& tx : popped_txs)
    {
      if (is_coinbase(tx)) continue;
      const crypto::hash tx_id = get_transaction_hash(tx);
      tx_extra_pbc_tx_type type_field{};
      if (!get_tx_extra_field_by_type(tx.extra, type_field) || type_field.type != PBC_TX_TYPE_MARKET_ASK)
        continue;
      tx_extra_pbc_market_ask ask_field{};
      if (!get_tx_extra_field_by_type(tx.extra, ask_field)) continue;

      uint64_t had_prev = 0;
      m_db->get_property_uint64(pbc_market_key(tx_id, "_ask_u0"), had_prev);

      // Remove what was applied
      m_db->delete_property(pbc_ask_dep_key(ask_field.deposit_id, "_price"));
      m_db->delete_property(pbc_ask_dep_key(ask_field.deposit_id, "_height"));
      pbc_delete_packed_props(m_db, pbc_ask_dep_key(ask_field.deposit_id, "_addr"));
      pbc_ask_list_remove(m_db, ask_field.deposit_id);

      if (had_prev)
      {
        uint64_t old_price = 0, old_height = 0;
        m_db->get_property_uint64(pbc_market_key(tx_id, "_ask_u1"), old_price);
        m_db->get_property_uint64(pbc_market_key(tx_id, "_ask_u2"), old_height);
        if (old_price > 0)
        {
          m_db->set_property_uint64(pbc_ask_dep_key(ask_field.deposit_id, "_price"), old_price);
          m_db->set_property_uint64(pbc_ask_dep_key(ask_field.deposit_id, "_height"), old_height);
          uint8_t old_addr[sizeof(cryptonote::account_public_address)];
          size_t old_addr_sz = 0;
          if (pbc_load_packed_props(m_db, pbc_market_key(tx_id, "_ask_u3"),
                                    old_addr, sizeof(old_addr), old_addr_sz)
              && old_addr_sz == sizeof(cryptonote::account_public_address))
          {
            pbc_store_packed_props(m_db, pbc_ask_dep_key(ask_field.deposit_id, "_addr"),
                                   old_addr, sizeof(old_addr));
          }
          pbc_ask_list_add(m_db, ask_field.deposit_id);
        }
        m_db->delete_property(pbc_market_key(tx_id, "_ask_u1"));
        m_db->delete_property(pbc_market_key(tx_id, "_ask_u2"));
        pbc_delete_packed_props(m_db, pbc_market_key(tx_id, "_ask_u3"));
      }
      m_db->delete_property(pbc_market_key(tx_id, "_ask_u0"));
      MGINFO("PBC MARKET ASK: rollback tx=" << tx_id << " deposit=" << ask_field.deposit_id
        << (had_prev ? " (prev ask restored)" : " (no prev ask)"));
    }

    // ── 0b. TD-5: Revert claims (applied AFTER deposits) ──
    for (const auto& tx : popped_txs)
    {
      if (is_coinbase(tx))
        continue;

      crypto::hash claim_tx_id = get_transaction_hash(tx);
      crypto::hash deposit_id;
      std::string fail_reason;

      pbc_claim_result cr = pbc_validate_claim_tx(tx, deposit_id, fail_reason);
      if (cr != PBC_CLAIM_VALID)
        continue;

      // Read claim delta from properties
      // BUG1-FIX: _di/_fi are uint128, rest are uint64
      uint64_t delta_rt = 0, delta_lh = 0, delta_ar = 0;
      __uint128_t delta_di = 0, delta_fi = 0;
      if (!m_db->get_property_uint64(pbc_claim_key(claim_tx_id, "_rt"), delta_rt))
      {
        LOG_ERROR("PBC TD-5: Cannot find claim delta for tx=" << claim_tx_id << " — skipping revert");
        continue;
      }
      m_db->get_property_uint128(pbc_claim_key(claim_tx_id, "_di"), delta_di);
      m_db->get_property_uint128(pbc_claim_key(claim_tx_id, "_fi"), delta_fi);
      m_db->get_property_uint64(pbc_claim_key(claim_tx_id, "_lh"), delta_lh);
      m_db->get_property_uint64(pbc_claim_key(claim_tx_id, "_ar"), delta_ar);

      // Restore pending reserve (CLAIM = pending only)
      CHECK_AND_ASSERT_MES(m_pbc_pool_state.pending_rewards_total >= delta_rt, cryptonote::block(),
          "PBC TD-5: pending_rewards_total underflow on claim revert");
      m_pbc_pool_state.pending_rewards_total -= delta_rt;

      // Restore deposit record to pre-claim state
      uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
      size_t dep_size = PBC_DEPOSIT_RECORD_PACKED_SIZE;
      if (m_db->get_pbc_deposit(deposit_id, dep_buf, dep_size))
      {
        pbc_deposit_record dep_rec;
        pbc_unpack_deposit_record(dep_buf, dep_size, dep_rec);

        dep_rec.deposit_entry_index = delta_di;
        dep_rec.fee_entry_index     = delta_fi;
        dep_rec.last_claim_height   = delta_lh;
        dep_rec.accumulated_reward  = delta_ar;

        // Remove + re-add (add_pbc_deposit uses MDB_NOOVERWRITE)
        m_db->remove_pbc_deposit(deposit_id);
        uint8_t upd_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
        pbc_pack_deposit_record(dep_rec, upd_buf);
        m_db->add_pbc_deposit(deposit_id, upd_buf, PBC_DEPOSIT_RECORD_PACKED_SIZE);
      }

      // Cleanup claim delta properties
      m_db->delete_property(pbc_claim_key(claim_tx_id, "_rt"));
      m_db->delete_property(pbc_claim_key(claim_tx_id, "_di"));
      m_db->delete_property(pbc_claim_key(claim_tx_id, "_fi"));
      m_db->delete_property(pbc_claim_key(claim_tx_id, "_lh"));
      m_db->delete_property(pbc_claim_key(claim_tx_id, "_ar"));

      MGINFO("PBC TD-5: Claim reverted: tx=" << claim_tx_id
        << " deposit=" << deposit_id
        << " -pending=" << delta_rt);
    }

    // ── 0c. Revert term deposits (TD-2, applied before claims) ──
    for (const auto& tx : popped_txs)
    {
      if (is_coinbase(tx))
        continue;

      crypto::hash deposit_id = get_transaction_hash(tx);

      // Skip claim TXs (already handled above)
      {
        crypto::hash dummy_id;
        std::string dummy_reason;
        if (pbc_validate_claim_tx(tx, dummy_id, dummy_reason) == PBC_CLAIM_VALID)
          continue;
      }

      // Try to retrieve the deposit record
      uint8_t buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
      size_t buf_size = PBC_DEPOSIT_RECORD_PACKED_SIZE;
      if (m_db->get_pbc_deposit(deposit_id, buf, buf_size))
      {
        pbc_deposit_record dep_rec;
        pbc_unpack_deposit_record(buf, buf_size, dep_rec);

        // Revert Σw
        assert(m_pbc_pool_state.deposit_sum_weights >= dep_rec.weight);
        CHECK_AND_ASSERT_THROW_MES(m_pbc_pool_state.deposit_sum_weights >= dep_rec.weight,
            "PBC TD-6 §4: deposit revert would underflow deposit_sum_weights");
        m_pbc_pool_state.deposit_sum_weights -= dep_rec.weight;
        // BUG2-FIX: revert locked amount
        if (m_pbc_pool_state.total_locked_in_deposits >= dep_rec.amount)
          m_pbc_pool_state.total_locked_in_deposits -= dep_rec.amount;

        // Remove from DB
        m_db->remove_pbc_deposit(deposit_id);

        MGINFO("PBC: Deposit reverted: id=" << deposit_id
          << " weight=" << dep_rec.weight
          << " Σw=" << m_pbc_pool_state.deposit_sum_weights);
      }
    }

    // ── 0d. Revert PBC Inheritance (tx changes + executions) ──
    // 1) Revert executions at this height (may have changed deposit owner_key)
    m_db->for_each_pbc_inherit_exec_undo(popped_height, [&](const void* blob_data, size_t blob_size) {
      if (blob_size < 32 + PBC_INHERIT_RECORD_PACKED_SIZE + 4)
        return true;
      size_t off = 0;
      crypto::public_key principal_pk;
      memcpy(&principal_pk, (const uint8_t*)blob_data + off, sizeof(principal_pk)); off += sizeof(principal_pk);
      const uint8_t* prev_rec_buf = (const uint8_t*)blob_data + off; off += PBC_INHERIT_RECORD_PACKED_SIZE;
      uint32_t count = 0;
      memcpy(&count, (const uint8_t*)blob_data + off, 4); off += 4;
      if (blob_size < 32 + PBC_INHERIT_RECORD_PACKED_SIZE + 4 + (size_t)count * sizeof(crypto::hash))
        return true;

      // Revert deposit owner_key back to principal
      for (uint32_t i = 0; i < count; ++i)
      {
        crypto::hash dep_id;
        memcpy(&dep_id, (const uint8_t*)blob_data + off, sizeof(dep_id));
        off += sizeof(dep_id);
        uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
        size_t dep_sz = PBC_DEPOSIT_RECORD_PACKED_SIZE;
        if (!m_db->get_pbc_deposit(dep_id, dep_buf, dep_sz))
          continue;
        if (dep_sz < PBC_DEPOSIT_RECORD_PACKED_SIZE)
          continue;
        pbc_deposit_record drec;
        pbc_unpack_deposit_record(dep_buf, dep_sz, drec);
        drec.owner_key = principal_pk;
        uint8_t out[PBC_DEPOSIT_RECORD_PACKED_SIZE];
        pbc_pack_deposit_record(drec, out);
        m_db->remove_pbc_deposit(dep_id);
        m_db->add_pbc_deposit(dep_id, out, sizeof(out));
      }

      // Restore previous inheritance record
      pbc_inherit_record prev_rec;
      if (pbc_unpack_inherit_record(prev_rec_buf, PBC_INHERIT_RECORD_PACKED_SIZE, prev_rec))
      {
        uint8_t out[PBC_INHERIT_RECORD_PACKED_SIZE];
        pbc_pack_inherit_record(prev_rec, out);
        m_db->add_pbc_inherit_record(principal_pk, out, sizeof(out));
      }

      // Conception v2 (2026-08-14) — CORRECTIF : cette ligne remettait exec_key à 0 SANS
      // CONDITION. Correct pour une PREMIÈRE tentative (rien à restaurer), mais FAUX pour le
      // reorg d'une RETENTATIVE : exec_key valait alors la hauteur de la tentative PRÉCÉDENTE
      // avant que celle-ci (maintenant dépilée) ne l'écrase — il faut restaurer CETTE valeur,
      // pas la forcer à 0. La valeur correcte est lue plus bas (suffixe attempts+exec_key) ;
      // par défaut (blob ancien format, sans suffixe) on conserve 0, comportement inchangé.
      uint64_t restore_exec_key = 0;

      // Restore testament blob if present in undo record (new-format blobs have 4-byte size suffix)
      // Old-format blobs (no testament field) are silently skipped — backwards compatible.
      if (off + sizeof(uint32_t) <= blob_size)
      {
        uint32_t testament_size = 0;
        memcpy(&testament_size, (const uint8_t*)blob_data + off, sizeof(testament_size));
        off += sizeof(testament_size);
        if (testament_size > 0 && off + testament_size <= blob_size)
        {
          m_db->store_pbc_inherit_testament(principal_pk,
            (const uint8_t*)blob_data + off, testament_size);
          MINFO("PBC INHERIT UNDO: testament restored for principal=" << principal_pk
            << " blob_size=" << testament_size);
          off += testament_size;
        }
        else if (testament_size == 0)
        {
          MINFO("PBC INHERIT UNDO: no testament to restore for principal=" << principal_pk
            << " (principal had no testament at exec time)");
        }
        else
        {
          MERROR("PBC INHERIT UNDO: testament blob truncated for principal=" << principal_pk
            << " expected=" << testament_size << " available=" << (blob_size - off));
        }
      }
      // else: old-format undo blob without testament field — skip silently

      // Conception v2 (2026-08-14) : suffixe attempts+exec_key (16 octets), ajouté APRÈS le
      // testament. Absent sur un blob ancien format -> restore_exec_key reste à 0 (comportement
      // préexistant), et le compteur de tentatives n'est PAS touché (concept inexistant alors).
      if (off + sizeof(uint64_t) + sizeof(uint64_t) <= blob_size)
      {
        uint64_t restored_attempts = 0;
        memcpy(&restored_attempts, (const uint8_t*)blob_data + off, sizeof(restored_attempts)); off += sizeof(restored_attempts);
        memcpy(&restore_exec_key, (const uint8_t*)blob_data + off, sizeof(restore_exec_key)); off += sizeof(restore_exec_key);
        m_db->set_property_uint64(pbc_inh_testament_attempts_key(principal_pk), restored_attempts);
        MINFO("PBC INHERIT GATE: reorg undo -> executed[" << principal_pk << "]=" << restore_exec_key
          << " (retentative défaite, valeur d'avant restaurée) attempts=" << restored_attempts);
      }
      else
      {
        // Blob ancien format sans suffixe : comportement préexistant inchangé (première
        // tentative défaite -> executed[P]=0, aucun compteur de tentatives à restaurer).
        MINFO("PBC INHERIT GATE: reorg undo -> executed[" << principal_pk << "]=0 (blob sans suffixe)");
      }
      m_db->set_property_uint64(pbc_inh_exec_key(principal_pk), restore_exec_key);
      return true;
    });
    m_db->clear_pbc_inherit_exec_undo(popped_height);

    // Conception v2 (2026-08-14) : rejeu de l'undo de CLÔTURE Pass 0 (succès/abandon), même
    // hauteur, table séparée pbc_inherit_close_undo. Doit s'exécuter dans la même fenêtre de
    // reorg-undo que l'exec-undo ci-dessus — un bloc peut porter une clôture Pass 0 pour un
    // principal ET une nouvelle tentative (Pass 2) pour un AUTRE, sans jamais se chevaucher
    // pour le MÊME principal (Pass 0 clôt request_active avant que la Pass 1/2 du même bloc
    // ne puisse re-sélectionner ce principal — voir Pass 0 dans handle_block_to_main_chain).
    m_db->for_each_pbc_inherit_close_undo(popped_height, [&](const void* blob_data, size_t blob_size) {
      // Format : [1B tag]['S'|'A'][32B principal_pk][96B prev_rec][8B prev_attempts]
      //          [4B testament_size][testament_size bytes si tag=='S' et >0]
      //          [4B attempt_blob_size][attempt_blob_size bytes]
      size_t off = 0;
      if (blob_size < 1 + 32 + PBC_INHERIT_RECORD_PACKED_SIZE + sizeof(uint64_t) + sizeof(uint32_t))
        return true;
      const uint8_t tag = *(const uint8_t*)blob_data; off += 1;
      crypto::public_key principal_pk;
      memcpy(&principal_pk, (const uint8_t*)blob_data + off, sizeof(principal_pk)); off += sizeof(principal_pk);
      const uint8_t* prev_rec_buf = (const uint8_t*)blob_data + off; off += PBC_INHERIT_RECORD_PACKED_SIZE;
      uint64_t prev_attempts = 0;
      memcpy(&prev_attempts, (const uint8_t*)blob_data + off, sizeof(prev_attempts)); off += sizeof(prev_attempts);

      uint32_t testament_size = 0;
      memcpy(&testament_size, (const uint8_t*)blob_data + off, sizeof(testament_size)); off += sizeof(testament_size);
      if (testament_size > 0)
      {
        // Correctif F5 (2026-08-14, revue croisée sur v8.2.8) : garde de troncature — même
        // patron que le rejeu exec-undo (l.1756) et le rejeu SETUP/REQUEST/CANCEL (l.2053),
        // qui l'avaient déjà. Ici, en son absence, un blob tronqué laissait `off` inchangé et
        // la lecture suivante (att_size) relisait des octets du testament tronqué comme si
        // c'était l'en-tête de taille de l'attempt-blob — corruption silencieuse en cascade.
        if (off + testament_size <= blob_size)
        {
          if (tag == 'S')
          {
            // Succès défait : le testament avait été retiré, on le restaure.
            m_db->store_pbc_inherit_testament(principal_pk, (const uint8_t*)blob_data + off, testament_size);
            MINFO("PBC INHERIT PASS0 UNDO: testament restauré (succès défait) principal=" << principal_pk);
          }
          off += testament_size;
        }
        else
        {
          MERROR("PBC INHERIT PASS0 UNDO: testament blob truncated principal=" << principal_pk
            << " expected=" << testament_size << " available=" << (blob_size - off));
          off = blob_size; // ne rien tenter de relire au-delà d'un blob corrompu
        }
      }

      if (off + sizeof(uint32_t) > blob_size)
        return true;
      uint32_t att_size = 0;
      memcpy(&att_size, (const uint8_t*)blob_data + off, sizeof(att_size)); off += sizeof(att_size);
      if (att_size > 0)
      {
        // Correctif F5 : même garde pour l'attempt-blob, jusqu'ici seul le testament (ci-dessus,
        // après ce correctif) et les deux autres chemins de rejeu l'avaient.
        if (off + att_size <= blob_size)
        {
          m_db->store_pbc_inherit_attempt(principal_pk, (const uint8_t*)blob_data + off, att_size);
          off += att_size;
        }
        else
        {
          MERROR("PBC INHERIT PASS0 UNDO: attempt blob truncated principal=" << principal_pk
            << " expected=" << att_size << " available=" << (blob_size - off));
          off = blob_size;
        }
      }

      pbc_inherit_record prev_rec;
      if (pbc_unpack_inherit_record(prev_rec_buf, PBC_INHERIT_RECORD_PACKED_SIZE, prev_rec))
      {
        uint8_t out[PBC_INHERIT_RECORD_PACKED_SIZE];
        pbc_pack_inherit_record(prev_rec, out);
        m_db->add_pbc_inherit_record(principal_pk, out, sizeof(out));
      }
      m_db->set_property_uint64(pbc_inh_testament_attempts_key(principal_pk), prev_attempts);
      // exec_key n'est jamais touché par Pass 0 (ni à la clôture, ni ici à l'undo) — il reste
      // ce que la dernière Pass 2 y avait écrit, propriété inchangée par construction.
      MINFO("PBC INHERIT PASS0 UNDO: clôture (" << (tag == 'S' ? "succès" : "abandon")
        << ") défaite, request_active restauré, principal=" << principal_pk);
      return true;
    });
    m_db->clear_pbc_inherit_close_undo(popped_height);

    // 2) Revert tx-level changes using per-tx undo records
    for (const auto& tx : popped_txs)
    {
      if (is_coinbase(tx))
        continue;
      const crypto::hash tx_id = get_transaction_hash(tx);
      tx_extra_pbc_tx_type type_field;
      if (!get_tx_extra_field_by_type(tx.extra, type_field))
        continue;

      // ── Bug1 fix: handle activity-only undo (TERM_DEPOSIT / TERM_WITHDRAW) ──
      // These TX types update last_activity_height and store a 129-byte activity undo blob
      // BEFORE the mutation: [0xFF sentinel][96-byte record][32-byte principal_pk].
      // SECURITY FIX (M1): CLAIM no longer refreshes proof-of-life and no longer writes an
      // activity undo (it is permissionless — see the apply path). PBC_TX_TYPE_CLAIM is kept
      // in the condition below purely for robustness/defense-in-depth: for any CLAIM produced
      // by the fixed code, get_pbc_inherit_tx_undo() returns false and we simply `continue`,
      // leaving the inherit record untouched — which is exactly the desired behavior.
      if (type_field.type == PBC_TX_TYPE_TERM_DEPOSIT ||
          type_field.type == PBC_TX_TYPE_CLAIM        ||
          type_field.type == PBC_TX_TYPE_TERM_WITHDRAW)
      {
        static constexpr size_t ACT_UNDO_SIZE = PBC_INHERIT_TX_UNDO_SIZE + sizeof(crypto::public_key);
        uint8_t act_undo[ACT_UNDO_SIZE];
        size_t act_sz = sizeof(act_undo);
        if (!m_db->get_pbc_inherit_tx_undo(tx_id, act_undo, act_sz))
          continue; // no activity undo stored (principal had no inherit record at the time)
        if (act_sz != ACT_UNDO_SIZE || act_undo[0] != PBC_INHERIT_UNDO_TAG_ACTIVITY)
        {
          m_db->remove_pbc_inherit_tx_undo(tx_id);
          continue; // unexpected format — skip safely
        }
        pbc_inherit_record prev_act;
        if (pbc_unpack_inherit_record(act_undo + 1, PBC_INHERIT_RECORD_PACKED_SIZE, prev_act))
        {
          crypto::public_key principal_pk;
          memcpy(&principal_pk, act_undo + PBC_INHERIT_TX_UNDO_SIZE, sizeof(principal_pk));
          uint8_t out[PBC_INHERIT_RECORD_PACKED_SIZE];
          pbc_pack_inherit_record(prev_act, out);
          m_db->add_pbc_inherit_record(principal_pk, out, sizeof(out));
          MINFO("PBC INHERIT: activity undo restored last_activity_height for principal="
            << principal_pk << " tx=" << tx_id);
        }
        m_db->remove_pbc_inherit_tx_undo(tx_id);
        continue;
      }

      if (type_field.type == PBC_TX_TYPE_TRANSFER_DEPOSIT)
      {
        // Marketplace transfer undo is handled earlier in pop_block, before claim reverts.
        continue;
      }

      // ── A4 (sous-étape 4) : undo du tx PORTEUR de testament (type 13) ──
      // Forward a stocké : [4o prev_test_sz][prev_testament][8o prev_seq]. On restaure le
      // testament précédent (ou on supprime si aucun) + la séquence précédente.
      // NB : si forward a IGNORÉ le porteur (seq périmée), aucun undo n'a été stocké
      // -> get_pbc_inherit_tx_undo échoue -> on skip proprement (rien à défaire).
      if (type_field.type == PBC_TX_TYPE_INHERIT_TESTAMENT)
      {
        tx_extra_pbc_inherit_testament tst_field;
        if (!get_tx_extra_field_by_type(tx.extra, tst_field))
        {
          m_db->remove_pbc_inherit_tx_undo(tx_id);
          continue;
        }
        const crypto::public_key principal_pk = tst_field.principal_spend_pubkey;

        static constexpr size_t MAX_UNDO_BUF_T = 128 * 1024;
        std::vector<uint8_t> uv(MAX_UNDO_BUF_T);
        size_t usz = MAX_UNDO_BUF_T;
        if (!m_db->get_pbc_inherit_tx_undo(tx_id, uv.data(), usz) ||
            usz < sizeof(uint32_t) + sizeof(uint64_t))
        {
          // Pas d'undo (porteur ignoré en forward) -> rien à défaire.
          m_db->remove_pbc_inherit_tx_undo(tx_id);
          continue;
        }
        uint32_t prev_sz = 0;
        memcpy(&prev_sz, uv.data(), sizeof(prev_sz));
        const size_t seq_off = sizeof(uint32_t) + prev_sz;
        if (seq_off + sizeof(uint64_t) > usz)
        {
          MERROR("PBC TESTAMENT UNDO: blob truncated tx=" << tx_id);
          m_db->remove_pbc_inherit_tx_undo(tx_id);
          continue;
        }
        uint64_t prev_seq = 0;
        memcpy(&prev_seq, uv.data() + seq_off, sizeof(prev_seq));

        if (prev_sz == 0)
        {
          m_db->remove_pbc_inherit_testament(principal_pk);
          MINFO("PBC TESTAMENT UNDO: removed testament (none before) principal=" << principal_pk);
        }
        else
        {
          m_db->store_pbc_inherit_testament(principal_pk, uv.data() + sizeof(uint32_t), prev_sz);
          MINFO("PBC TESTAMENT UNDO: restored previous testament principal=" << principal_pk
            << " size=" << prev_sz);
        }
        m_db->set_property_uint64(pbc_testament_seq_key(principal_pk), prev_seq);

        // Correctif F2 (2026-08-14) : restauration du suffixe attempts+exec_key, symétrique à
        // la remise à 0 ajoutée dans le handler A4 forward. Même garde de troncature que les
        // deux autres chemins de rejeu (exec-undo, SETUP/REQUEST/CANCEL) : offset + 16 <= usz,
        // sinon on n'y touche pas (blob ancien format, ou déjà signalé tronqué ci-dessus).
        const size_t a4_suffix_off = seq_off + sizeof(uint64_t);
        if (a4_suffix_off + sizeof(uint64_t) + sizeof(uint64_t) <= usz)
        {
          uint64_t restored_attempts = 0, restored_exec_key = 0;
          memcpy(&restored_attempts, uv.data() + a4_suffix_off, sizeof(restored_attempts));
          memcpy(&restored_exec_key, uv.data() + a4_suffix_off + sizeof(restored_attempts), sizeof(restored_exec_key));
          m_db->set_property_uint64(pbc_inh_testament_attempts_key(principal_pk), restored_attempts);
          m_db->set_property_uint64(pbc_inh_exec_key(principal_pk), restored_exec_key);
          MINFO("PBC TESTAMENT UNDO: attempts/exec_key restaurés (" << restored_attempts
            << "/" << restored_exec_key << ") principal=" << principal_pk);
        }
        m_db->remove_pbc_inherit_tx_undo(tx_id);
        continue;
      }

      // ── SETUP / REQUEST / CANCEL undo (including Bug2 extended blobs) ──
      if (type_field.type != PBC_TX_TYPE_INHERIT_SETUP &&
          type_field.type != PBC_TX_TYPE_INHERIT_REQUEST &&
          type_field.type != PBC_TX_TYPE_INHERIT_CANCEL)
        continue;

      // Read variable-size blob (Bug2 fix: may be > PBC_INHERIT_TX_UNDO_SIZE if testament saved)
      // Use a large stack buffer; testament blobs can be up to ~64 KB.
      // Use vector to avoid stack overflow.
      static constexpr size_t MAX_UNDO_BUF = 128 * 1024; // 128 KB ceiling
      std::vector<uint8_t> undo_vec(MAX_UNDO_BUF);
      size_t undo_sz = MAX_UNDO_BUF;
      if (!m_db->get_pbc_inherit_tx_undo(tx_id, undo_vec.data(), undo_sz))
        continue;
      if (undo_sz < PBC_INHERIT_TX_UNDO_SIZE)
      {
        m_db->remove_pbc_inherit_tx_undo(tx_id);
        continue;
      }

      const uint8_t* undo = undo_vec.data();
      const bool had_prev = undo[0] != 0;
      if (!had_prev)
      {
        // No previous record => tx created it. Find principal key and remove.
        tx_extra_pbc_owner_key owner_field;
        tx_extra_pbc_inherit_target tgt_field;
        if (type_field.type == PBC_TX_TYPE_INHERIT_REQUEST && get_tx_extra_field_by_type(tx.extra, tgt_field))
          m_db->remove_pbc_inherit_record(tgt_field.principal_spend_pubkey);
        else if (get_tx_extra_field_by_type(tx.extra, owner_field))
          m_db->remove_pbc_inherit_record(owner_field.owner_spend_pubkey);
      }
      else
      {
        pbc_inherit_record prev;
        if (!pbc_unpack_inherit_record(undo + 1, PBC_INHERIT_RECORD_PACKED_SIZE, prev))
        {
          m_db->remove_pbc_inherit_tx_undo(tx_id);
          continue;
        }
        // Determine principal key
        tx_extra_pbc_inherit_target tgt_field;
        tx_extra_pbc_owner_key owner_field;
        crypto::public_key principal_pk = crypto::null_pkey;
        if (type_field.type == PBC_TX_TYPE_INHERIT_REQUEST && get_tx_extra_field_by_type(tx.extra, tgt_field))
          principal_pk = tgt_field.principal_spend_pubkey;
        else if (get_tx_extra_field_by_type(tx.extra, owner_field))
          principal_pk = owner_field.owner_spend_pubkey;

        if (principal_pk != crypto::null_pkey)
        {
          uint8_t out[PBC_INHERIT_RECORD_PACKED_SIZE];
          pbc_pack_inherit_record(prev, out);
          m_db->add_pbc_inherit_record(principal_pk, out, sizeof(out));
        }
      }

      // Bug2 fix: if extended blob contains a testament snapshot, restore it.
      // Extended blob layout: [PBC_INHERIT_TX_UNDO_SIZE bytes][4 bytes testament_size][testament bytes]
      size_t suffix_offset = PBC_INHERIT_TX_UNDO_SIZE; // REQUEST : le suffixe suit directement
      if (type_field.type == PBC_TX_TYPE_INHERIT_SETUP ||
          type_field.type == PBC_TX_TYPE_INHERIT_CANCEL)
      {
        if (undo_sz > PBC_INHERIT_TX_UNDO_SIZE + sizeof(uint32_t))
        {
          uint32_t test_sz = 0;
          memcpy(&test_sz, undo + PBC_INHERIT_TX_UNDO_SIZE, sizeof(test_sz));
          const size_t testament_offset = PBC_INHERIT_TX_UNDO_SIZE + sizeof(uint32_t);
          suffix_offset = testament_offset + test_sz; // valable même si test_sz==0
          if (test_sz == 0)
          {
            MINFO("PBC INHERIT: SETUP/CANCEL undo: no testament to restore for tx=" << tx_id);
          }
          else if (testament_offset + test_sz <= undo_sz)
          {
            // Determine principal_pk for testament restore
            tx_extra_pbc_owner_key owner_field;
            if (get_tx_extra_field_by_type(tx.extra, owner_field))
            {
              m_db->store_pbc_inherit_testament(owner_field.owner_spend_pubkey,
                undo + testament_offset, test_sz);
              MINFO("PBC INHERIT: SETUP/CANCEL undo: testament restored for principal="
                << owner_field.owner_spend_pubkey << " blob_size=" << test_sz);
            }
          }
          else
          {
            MERROR("PBC INHERIT: SETUP/CANCEL undo: testament blob truncated in undo record for tx=" << tx_id);
            suffix_offset = undo_sz; // blob corrompu : ne pas tenter de lire le suffixe
          }
        }
        else
        {
          suffix_offset = undo_sz; // blob ancien format sans même le header testament
        }
      }

      // Conception v2 (2026-08-14) : restauration du suffixe attempts+exec_key (16 octets),
      // commun aux trois types (SETUP/REQUEST/CANCEL) — offset déjà calculé ci-dessus selon
      // le type. Absent sur un blob ancien format -> rien à restaurer (comportement inchangé,
      // ces compteurs n'existaient pas avant Conception v2).
      if (suffix_offset + sizeof(uint64_t) + sizeof(uint64_t) <= undo_sz)
      {
        tx_extra_pbc_inherit_target sfx_tgt_field;
        tx_extra_pbc_owner_key sfx_owner_field;
        crypto::public_key sfx_principal_pk = crypto::null_pkey;
        if (type_field.type == PBC_TX_TYPE_INHERIT_REQUEST && get_tx_extra_field_by_type(tx.extra, sfx_tgt_field))
          sfx_principal_pk = sfx_tgt_field.principal_spend_pubkey;
        else if (get_tx_extra_field_by_type(tx.extra, sfx_owner_field))
          sfx_principal_pk = sfx_owner_field.owner_spend_pubkey;

        if (sfx_principal_pk != crypto::null_pkey)
        {
          uint64_t restored_attempts = 0, restored_exec_key = 0;
          memcpy(&restored_attempts, undo + suffix_offset, sizeof(restored_attempts));
          memcpy(&restored_exec_key, undo + suffix_offset + sizeof(restored_attempts), sizeof(restored_exec_key));
          m_db->set_property_uint64(pbc_inh_testament_attempts_key(sfx_principal_pk), restored_attempts);
          m_db->set_property_uint64(pbc_inh_exec_key(sfx_principal_pk), restored_exec_key);
          MINFO("PBC INHERIT: SETUP/REQUEST/CANCEL undo: attempts/exec_key restaurés ("
            << restored_attempts << "/" << restored_exec_key << ") principal=" << sfx_principal_pk);
        }
      }

      m_db->remove_pbc_inherit_tx_undo(tx_id);
    }


    // ── 1. Revert insurance overflow (was applied before deposits) ──
    uint64_t overflow_delta = 0;
    std::string ovf_key = pbc_delta_key(PBC_DELTA_KEY_PREFIX_OVF, popped_height);
    if (m_db->get_property_uint64(ovf_key, overflow_delta) && overflow_delta > 0)
    {
      assert(m_pbc_pool_state.total_destroyed >= overflow_delta);
      CHECK_AND_ASSERT_THROW_MES(m_pbc_pool_state.total_destroyed >= overflow_delta,
          "PBC TD-6 §4: overflow revert would underflow total_destroyed");
      m_pbc_pool_state.total_destroyed -= overflow_delta;
      m_pbc_pool_state.insurance_pool_balance += overflow_delta;
      m_db->delete_property(ovf_key);
      LOG_PRINT_L1("PBC: Reverted insurance overflow of " << overflow_delta << " at height " << popped_height);
    }

    // ── 2. Revert insurance subsidy (was applied before overflow) ──
    uint64_t subsidy_delta = 0;
    std::string sub_key = pbc_delta_key(PBC_DELTA_KEY_PREFIX_SUB, popped_height);
    if (m_db->get_property_uint64(sub_key, subsidy_delta) && subsidy_delta > 0)
    {
      assert(m_pbc_pool_state.deposit_pool_balance >= subsidy_delta);
      CHECK_AND_ASSERT_THROW_MES(m_pbc_pool_state.deposit_pool_balance >= subsidy_delta,
          "PBC TD-6 §4: subsidy revert would underflow deposit_pool_balance");
      m_pbc_pool_state.deposit_pool_balance -= subsidy_delta;
      m_pbc_pool_state.insurance_pool_balance += subsidy_delta;
      m_db->delete_property(sub_key);
      LOG_PRINT_L1("PBC: Reverted insurance subsidy of " << subsidy_delta << " at height " << popped_height);
    }

    // ── 3. Revert vesting (FIX-12: reverse both add and expiry) ──
    {
      // Recompute what was expired at this height (same logic as add_block)
      static const uint64_t VEST_PERIODS[] = {
          PBC_VESTING_UNLOCK_1, PBC_VESTING_UNLOCK_2,
          PBC_VESTING_UNLOCK_3, PBC_VESTING_UNLOCK_4
      };
      uint64_t total_expired = 0;
      for (int tier = 0; tier < 4; tier++)
      {
        if (popped_height < VEST_PERIODS[tier]) continue;
        uint64_t src_h = popped_height - VEST_PERIODS[tier];
        if (src_h == 0) continue;

        uint64_t src_miner = 0, src_dev = 0;
        if (!m_db->get_property_uint64(
                pbc_delta_key(PBC_DELTA_KEY_PREFIX_VM, src_h), src_miner))
          continue;
        m_db->get_property_uint64(
            pbc_delta_key(PBC_DELTA_KEY_PREFIX_VD, src_h), src_dev);

        uint64_t quarter = src_miner / PBC_VESTING_OUTPUTS;
        if (tier == 0) {
          uint64_t remainder = src_miner - (quarter * PBC_VESTING_OUTPUTS);
          total_expired += quarter + remainder + src_dev;
        } else {
          total_expired += quarter;
        }
      }

      // On add: vdelta = {added: total_coinbase, expired: total_expired}
      // Reverse: {added: total_expired, expired: total_coinbase}
      pbc_vesting_delta vdelta;
      vdelta.added = total_expired;
      vdelta.expired = split.total_coinbase;
      pbc_update_vesting(m_pbc_pool_state, vdelta);

      // Delete stored vest keys for this block
      m_db->delete_property(pbc_delta_key(PBC_DELTA_KEY_PREFIX_VM, popped_height));
      m_db->delete_property(pbc_delta_key(PBC_DELTA_KEY_PREFIX_VD, popped_height));
    }

    // ── 4. Revert block reward (was applied after index update) ──
    pbc_revert_block_reward(m_pbc_pool_state, split);

    // ── 4b. BUG4-FIX: Revert cumulative fees (was applied with block reward) ──
    CHECK_AND_ASSERT_THROW_MES(
        m_pbc_pool_state.cumulative_fees >= popped_fees,
        "PBC BUG4: cumulative_fees underflow during pop_block");
    m_pbc_pool_state.cumulative_fees -= popped_fees;

    // ── 5. TD-4: Revert index update (was applied BEFORE block reward) ──
    if (popped_height > 0 && popped_height % PBC_DISTRIBUTION_PERIOD == 0)
    {
      // Restore snapshot saved at application time
      // BUG1-FIX: DI/FI are now __uint128_t
      __uint128_t snap_di = 0, snap_fi = 0;
      uint64_t snap_da = 0, snap_fa = 0, snap_lh = 0;
      std::string key_di = pbc_delta_key(PBC_DELTA_KEY_IDX_DI, popped_height);
      std::string key_fi = pbc_delta_key(PBC_DELTA_KEY_IDX_FI, popped_height);
      std::string key_da = pbc_delta_key(PBC_DELTA_KEY_IDX_DA, popped_height);
      std::string key_fa = pbc_delta_key(PBC_DELTA_KEY_IDX_FA, popped_height);
      std::string key_lh = pbc_delta_key(PBC_DELTA_KEY_IDX_LH, popped_height);

      if (m_db->get_property_uint128(key_di, snap_di))
      {
        m_db->get_property_uint128(key_fi, snap_fi);
        m_db->get_property_uint64(key_da, snap_da);
        m_db->get_property_uint64(key_fa, snap_fa);
        m_db->get_property_uint64(key_lh, snap_lh);

        m_pbc_pool_state.global_deposit_index       = snap_di;
        m_pbc_pool_state.global_fee_index            = snap_fi;
        m_pbc_pool_state.deposit_pool_period_inflow  = snap_da;
        m_pbc_pool_state.fee_pool_period_inflow      = snap_fa;
        m_pbc_pool_state.last_index_update_height    = snap_lh;

        // Clean up snapshot keys
        m_db->delete_property(key_di);
        m_db->delete_property(key_fi);
        m_db->delete_property(key_da);
        m_db->delete_property(key_fa);
        m_db->delete_property(key_lh);

        LOG_PRINT_L1("PBC TD-4: Reverted index update at height " << popped_height
          << " → deposit_idx_hi=" << (uint64_t)(snap_di >> 64)
          << " deposit_idx_lo=" << (uint64_t)snap_di
          << " fee_idx_hi=" << (uint64_t)(snap_fi >> 64)
          << " fee_idx_lo=" << (uint64_t)snap_fi);
      }
    }

    // ── PBC TRACE: POP-AFTER — full state after all rollbacks, before persist ──
    {
      const uint64_t _pop_agc = pbc_coins_before_top;  // agc at height we reverted TO
      const uint64_t _pop_cf  = m_pbc_pool_state.cumulative_fees;
      const uint64_t _pop_S   = _pop_agc + _pop_cf;
      const uint64_t _pop_P   = m_pbc_pool_state.pool_balances();
      const uint64_t _pop_dst = m_pbc_pool_state.total_destroyed;
      const uint64_t _pop_ves = m_pbc_pool_state.total_vested_outputs;
      const uint64_t _pop_lck = m_pbc_pool_state.total_locked_in_deposits;
      const uint64_t _pop_existence = (_pop_S >= _pop_dst) ? (_pop_S - _pop_dst) : 0;
      const uint64_t _pop_outside   = (_pop_existence >= _pop_P) ? (_pop_existence - _pop_P) : 0;
      const uint64_t _pop_circ      = (_pop_outside >= _pop_ves) ? (_pop_outside - _pop_ves) : 0;
      LOG_PRINT_L1("PBC TRACE POP-AFTER popped_h=" << popped_height
        << " reverted_to_h=" << (popped_height > 0 ? popped_height - 1 : 0)
        << " agc=" << _pop_agc
        << " cf=" << _pop_cf
        << " S=" << _pop_S
        << " dep=" << m_pbc_pool_state.deposit_pool_balance
        << " fee=" << m_pbc_pool_state.fee_pool_balance
        << " ins=" << m_pbc_pool_state.insurance_pool_balance
        << " P=" << _pop_P
        << " destroyed=" << _pop_dst
        << " vested=" << _pop_ves
        << " locked=" << _pop_lck
        << " sumW=" << m_pbc_pool_state.deposit_sum_weights
        << " existence=" << _pop_existence
        << " outside=" << _pop_outside
        << " circ=" << _pop_circ
        << " dep_inflow=" << m_pbc_pool_state.deposit_pool_period_inflow
        << " fee_inflow=" << m_pbc_pool_state.fee_pool_period_inflow
        << " chk1_pools_ok=" << (_pop_existence >= _pop_P ? "Y" : "N")
        << " chk2_dep_gt_locked=" << (m_pbc_pool_state.deposit_pool_balance >= _pop_lck ? "Y" : "n(ok)")
        << " chk3_vested_ok=" << (_pop_outside >= _pop_ves ? "Y" : "N"));
    }

    pbc_save_pool_state();
    LOG_PRINT_L1("PBC: Reverted pool state for popped block at height " << popped_height);
  }

  // return transactions from popped block to the tx_pool
  size_t pruned = 0;
  for (transaction& tx : popped_txs)
  {
    if (tx.pruned)
    {
      ++pruned;
      continue;
    }
    if (!is_coinbase(tx))
    {
      cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);

      // FIXME: HardFork
      // Besides the below, popping a block should also remove the last entry
      // in hf_versions.
      uint8_t version = get_ideal_hard_fork_version(m_db->height());

      // We assume that if they were in a block, the transactions are already known to the network
      // as a whole. However, if we had mined that block, that might not be always true. Unlikely
      // though, and always relaying these again might cause a spike of traffic as many nodes
      // re-relay all the transactions in a popped block when a reorg happens. You might notice that
      // we also set the "nic_verified_hf_version" paramater. Since we know we took this transaction
      // from the mempool earlier in this function call, when the mempool has the same current fork
      // version, we can return it without re-verifying the consensus rules on it.
      const bool r = m_tx_pool.add_tx(tx, tvc, relay_method::block, true, version, version);
      if (!r)
      {
        LOG_ERROR("Error returning transaction to tx_pool");
      }
    }
  }
  if (pruned)
    MWARNING(pruned << " pruned txes could not be added back to the txpool");

  m_blocks_longhash_table.clear();
  m_scan_table.clear();

  uint64_t top_block_height;
  crypto::hash top_block_hash = get_tail_id(top_block_height);
  m_tx_pool.on_blockchain_dec(top_block_height, top_block_hash);
  invalidate_block_template_cache();

  const uint8_t new_hf_version = get_current_hard_fork_version();
  if (new_hf_version != previous_hf_version)
  {
    MINFO("Validating txpool for v" << (unsigned)new_hf_version);
    m_tx_pool.validate(new_hf_version);
  }

  // PBC FIX: After a reorg, kept_by_block TXs returned to the pool may have
  // invalid ring signatures (their referenced output indices no longer exist in
  // the reorganized chain). These TXs fail block template building every time
  // but are never expelled — their key images remain in m_spent_key_images and
  // permanently block valid new TXs using the same UTXOs. Purge them now.
  m_tx_pool.purge_bad_kept_by_block_txs();

  // ═══════════════════════════════════════════════════════════════
  // PBC: Commit local batch if we started one (pop + revert atomic)
  // ═══════════════════════════════════════════════════════════════
  if (pbc_started_batch)
  {
    MDEBUG("PBC atomicity: committing local batch for pop+revert");
    m_db->batch_stop();
    pbc_started_batch = false;
  }

  return popped_block;
}
//------------------------------------------------------------------
bool Blockchain::reset_and_set_genesis_block(const block& b)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;
  invalidate_block_template_cache();
  m_db->reset();
  m_db->drop_alt_blocks();
  m_hardfork->init();

  db_wtxn_guard wtxn_guard(m_db);
  block_verification_context bvc = {};
  add_new_block(b, bvc);
  if (!update_next_cumulative_weight_limit())
    return false;
  return bvc.m_added_to_main_chain && !bvc.m_verifivation_failed;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id(uint64_t& height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->top_block_hash(&height);
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->top_block_hash();
}
//------------------------------------------------------------------
/*TODO: this function was...poorly written.  As such, I'm not entirely
 *      certain on what it was supposed to be doing.  Need to look into this,
 *      but it doesn't seem terribly important just yet.
 *
 * puts into list <ids> a list of hashes representing certain blocks
 * from the blockchain in reverse chronological order
 *
 * the blocks chosen, at the time of this writing, are:
 *   the most recent 11
 *   powers of 2 less recent from there, so 13, 17, 25, etc...
 *
 */
bool Blockchain::get_short_chain_history(std::list<crypto::hash>& ids) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t i = 0;
  uint64_t current_multiplier = 1;
  uint64_t sz = m_db->height();

  if(!sz)
    return true;

  db_rtxn_guard rtxn_guard(m_db);
  bool genesis_included = false;
  uint64_t current_back_offset = 1;
  while(current_back_offset < sz)
  {
    ids.push_back(m_db->get_block_hash_from_height(sz - current_back_offset));

    if(sz-current_back_offset == 0)
    {
      genesis_included = true;
    }
    if(i < 10)
    {
      ++current_back_offset;
    }
    else
    {
      current_multiplier *= 2;
      current_back_offset += current_multiplier;
    }
    ++i;
  }

  if (!genesis_included)
  {
    ids.push_back(m_db->get_block_hash_from_height(0));
  }

  return true;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_block_id_by_height(uint64_t height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_hash_from_height(height);
  }
  catch (const BLOCK_DNE& e)
  {
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Something went wrong fetching block hash by height: ") + e.what());
    throw;
  }
  catch (...)
  {
    MERROR(std::string("Something went wrong fetching block hash by height"));
    throw;
  }
  return null_hash;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_pending_block_id_by_height(uint64_t height) const
{
  if (m_prepare_height && height >= m_prepare_height && height - m_prepare_height < m_prepare_nblocks)
    return (*m_prepare_blocks)[height - m_prepare_height].hash;
  return get_block_id_by_height(height);
}
//------------------------------------------------------------------
bool Blockchain::get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // try to find block in main chain
  try
  {
    blk = m_db->get_block(h);
    if (orphan)
      *orphan = false;
    return true;
  }
  // try to find block in alternative chain
  catch (const BLOCK_DNE& e)
  {
    alt_block_data_t data;
    cryptonote::blobdata blob;
    if (m_db->get_alt_block(h, &data, &blob))
    {
      if (!cryptonote::parse_and_validate_block_from_blob(blob, blk))
      {
        MERROR("Found block " << h << " in alt chain, but failed to parse it");
        throw std::runtime_error("Found block in alt chain, but failed to parse it");
      }
      if (orphan)
        *orphan = true;
      return true;
    }
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Something went wrong fetching block by hash: ") + e.what());
    throw;
  }
  catch (...)
  {
    MERROR(std::string("Something went wrong fetching block hash by hash"));
    throw;
  }

  return false;
}
//------------------------------------------------------------------
// This function aggregates the cumulative difficulties and timestamps of the
// last DIFFICULTY_BLOCKS_COUNT blocks and passes them to next_difficulty,
// returning the result of that call.  Ignores the genesis block, and can use
// less blocks than desired if there aren't enough.
difficulty_type Blockchain::get_difficulty_for_next_block(const network_type nettype)
{
  if (m_fixed_difficulty)
  {
    return m_db->height() ? m_fixed_difficulty : 1;
  }

  LOG_PRINT_L3("Blockchain::" << __func__);

  crypto::hash top_hash = get_tail_id();
  {
    CRITICAL_REGION_LOCAL(m_difficulty_lock);
    // we can call this without the blockchain lock, it might just give us
    // something a bit out of date, but that's fine since anything which
    // requires the blockchain lock will have acquired it in the first place,
    // and it will be unlocked only when called from the getinfo RPC
    if (top_hash == m_difficulty_for_next_block_top_hash)
      return m_difficulty_for_next_block;
  }

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> difficulties;
  uint64_t height;
  top_hash = get_tail_id(height); // get it again now that we have the lock
  ++height; // top block height to blockchain height
  // ND: Speedup
  // 1. Keep a list of the last 735 (or less) blocks that is used to compute difficulty,
  //    then when the next block difficulty is queried, push the latest height data and
  //    pop the oldest one from the list. This only requires 1x read per height instead
  //    of doing 735 (DIFFICULTY_BLOCKS_COUNT).
  uint8_t version = get_current_hard_fork_version();
  uint64_t difficulty_blocks_count = version >= 20 ? DIFFICULTY_BLOCKS_COUNT_V4 : version >= 11 ? DIFFICULTY_BLOCKS_COUNT_V3 : version <= 10 && version >= 8 ? DIFFICULTY_BLOCKS_COUNT_V2 : DIFFICULTY_BLOCKS_COUNT;
  if (m_reset_timestamps_and_difficulties_height)
    m_timestamps_and_difficulties_height = 0;
  if (m_timestamps_and_difficulties_height != 0 && ((height - m_timestamps_and_difficulties_height) == 1) && m_timestamps.size() >= difficulty_blocks_count)
  {
    uint64_t index = height - 1;
    m_timestamps.push_back(m_db->get_block_timestamp(index));
    m_difficulties.push_back(m_db->get_block_cumulative_difficulty(index));

    while (m_timestamps.size() > difficulty_blocks_count)
      m_timestamps.erase(m_timestamps.begin());
    while (m_difficulties.size() > difficulty_blocks_count)
      m_difficulties.erase(m_difficulties.begin());

    m_timestamps_and_difficulties_height = height;
    timestamps = m_timestamps;
    difficulties = m_difficulties;
  }
  else
  {
    uint64_t offset = height - std::min <uint64_t> (height, static_cast<uint64_t>(difficulty_blocks_count));
    if (offset == 0)
      ++offset;

    timestamps.clear();
    difficulties.clear();
    if (height > offset)
    {
      timestamps.reserve(height - offset);
      difficulties.reserve(height - offset);
    }
    for (; offset < height; offset++)
    {
      timestamps.push_back(m_db->get_block_timestamp(offset));
      difficulties.push_back(m_db->get_block_cumulative_difficulty(offset));
    }

    m_timestamps_and_difficulties_height = height;
    m_timestamps = timestamps;
    m_difficulties = difficulties;
  }
  size_t target = get_difficulty_target();
  uint64_t HEIGHT = m_db->height();
  difficulty_type diff;
  if (version >= 20) {
    diff = next_difficulty_v5(timestamps, difficulties, HEIGHT, m_nettype);
  } else if (version >= 11) {
    diff = next_difficulty_v5(timestamps, difficulties, HEIGHT, m_nettype);
  } else if (version == 10) {
    diff = next_difficulty_v4(timestamps, difficulties, HEIGHT, m_nettype);
  } else if (version == 9) {
    diff = next_difficulty_v3(timestamps, difficulties, HEIGHT, m_nettype);
  } else if (version == 8) {
    diff = next_difficulty_v2(timestamps, difficulties, target, HEIGHT, m_nettype);
  } else {
    diff = next_difficulty(timestamps, difficulties, target, HEIGHT, m_nettype);
  }

  CRITICAL_REGION_LOCAL1(m_difficulty_lock);
  m_difficulty_for_next_block_top_hash = top_hash;
  m_difficulty_for_next_block = diff;
  return diff;
}
//------------------------------------------------------------------
std::pair<bool, uint64_t> Blockchain::check_difficulty_checkpoints() const
{
  uint64_t res = 0;
  for (const std::pair<const uint64_t, difficulty_type>& i : m_checkpoints.get_difficulty_points())
  {
    if (i.first >= m_db->height())
      break;
    if (m_db->get_block_cumulative_difficulty(i.first) != i.second)
      return {false, res};
    res = i.first;
  }
  return {true, res};
}
//------------------------------------------------------------------
size_t Blockchain::recalculate_difficulties(boost::optional<uint64_t> start_height_opt)
{
  if (m_fixed_difficulty)
  {
    return 0;
  }
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  const uint64_t start_height = start_height_opt ? *start_height_opt : check_difficulty_checkpoints().second;
  const uint64_t top_height = m_db->height() - 1;
  MGINFO("Recalculating difficulties from height " << start_height << " to height " << top_height);

  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> difficulties;
  uint8_t version = get_current_hard_fork_version();
  uint64_t difficulty_blocks_count = version >= 20 ? DIFFICULTY_BLOCKS_COUNT_V4 : version >= 11 ? DIFFICULTY_BLOCKS_COUNT_V3 : version <= 10 && version >= 8 ? DIFFICULTY_BLOCKS_COUNT_V2 : DIFFICULTY_BLOCKS_COUNT;
  timestamps.reserve(difficulty_blocks_count + 1);
  difficulties.reserve(difficulty_blocks_count + 1);
  if (start_height > 1)
  {
    for (uint64_t i = 0; i < difficulty_blocks_count; ++i)
    {
      uint64_t height = start_height - 1 - i;
      if (height == 0)
        break;
      timestamps.insert(timestamps.begin(), m_db->get_block_timestamp(height));
      difficulties.insert(difficulties.begin(), m_db->get_block_cumulative_difficulty(height));
    }
  }
  difficulty_type last_cum_diff = start_height <= 1 ? start_height : difficulties.back();
  uint64_t drift_start_height = 0;
  std::vector<difficulty_type> new_cumulative_difficulties;
  for (uint64_t height = start_height; height <= top_height; ++height)
  {
    size_t target = get_ideal_hard_fork_version(height) < 2 ? DIFFICULTY_TARGET_V1 : DIFFICULTY_TARGET_V2;
    uint64_t HEIGHT = m_db->height();
    difficulty_type recalculated_diff;
    if (version >= 20) {
      recalculated_diff = next_difficulty_v5(timestamps, difficulties, HEIGHT, m_nettype);
    } else if (version >= 11) {
      recalculated_diff = next_difficulty_v5(timestamps, difficulties, HEIGHT, m_nettype);
    } else if (version == 10) {
      recalculated_diff = next_difficulty_v4(timestamps, difficulties, HEIGHT, m_nettype);
    } else if (version == 9) {
      recalculated_diff = next_difficulty_v3(timestamps, difficulties, HEIGHT, m_nettype);
    } else if (version == 8) {
      recalculated_diff = next_difficulty_v2(timestamps, difficulties, target, HEIGHT, m_nettype);
    } else {
      recalculated_diff = next_difficulty(timestamps, difficulties, target, HEIGHT, m_nettype);
    }

    boost::multiprecision::uint256_t recalculated_cum_diff_256 = boost::multiprecision::uint256_t(recalculated_diff) + last_cum_diff;
    CHECK_AND_ASSERT_THROW_MES(recalculated_cum_diff_256 <= std::numeric_limits<difficulty_type>::max(), "Difficulty overflow!");
    difficulty_type recalculated_cum_diff = recalculated_cum_diff_256.convert_to<difficulty_type>();

    if (drift_start_height == 0)
    {
      difficulty_type existing_cum_diff = m_db->get_block_cumulative_difficulty(height);
      if (recalculated_cum_diff != existing_cum_diff)
      {
        drift_start_height = height;
        new_cumulative_difficulties.reserve(top_height + 1 - height);
        LOG_ERROR("Difficulty drift found at height:" << height << ", hash:" << m_db->get_block_hash_from_height(height) << ", existing:" << existing_cum_diff << ", recalculated:" << recalculated_cum_diff);
      }
    }
    if (drift_start_height > 0)
    {
      new_cumulative_difficulties.push_back(recalculated_cum_diff);
      if (height % 100000 == 0)
        LOG_ERROR(boost::format("%llu / %llu (%.1f%%)") % height % top_height % (100 * (height - drift_start_height) / float(top_height - drift_start_height)));
    }

    if (height > 0)
    {
      timestamps.push_back(m_db->get_block_timestamp(height));
      difficulties.push_back(recalculated_cum_diff);
    }
    if (timestamps.size() > difficulty_blocks_count)
    {
      CHECK_AND_ASSERT_THROW_MES(timestamps.size() == difficulty_blocks_count + 1, "Wrong timestamps size: " << timestamps.size());
      timestamps.erase(timestamps.begin());
      difficulties.erase(difficulties.begin());
    }
    last_cum_diff = recalculated_cum_diff;
  }

  if (drift_start_height > 0)
  {
    LOG_ERROR("Writing to the DB...");
    try
    {
      m_db->correct_block_cumulative_difficulties(drift_start_height, new_cumulative_difficulties);
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("Error correcting cumulative difficulties from height " << drift_start_height << ", what = " << e.what());
    }
    LOG_ERROR("Corrected difficulties for " << new_cumulative_difficulties.size() << " blocks");
    // clear cache
    m_difficulty_for_next_block_top_hash = crypto::null_hash;
    m_timestamps_and_difficulties_height = 0;
  }

  return new_cumulative_difficulties.size();
}
//------------------------------------------------------------------
std::vector<time_t> Blockchain::get_last_block_timestamps(unsigned int blocks) const
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t height = m_db->height();
  if (blocks > height)
    blocks = height;
  std::vector<time_t> timestamps(blocks);
  while (blocks--)
    timestamps[blocks] = m_db->get_block_timestamp(height - blocks - 1);
  return timestamps;
}
//------------------------------------------------------------------
// This function removes blocks from the blockchain until it gets to the
// position where the blockchain switch started and then re-adds the blocks
// that had been removed.
bool Blockchain::rollback_blockchain_switching(std::list<block>& original_chain, uint64_t rollback_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // fail if rollback_height passed is too high
  if (rollback_height > m_db->height())
  {
    return true;
  }

  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;

  // remove blocks from blockchain until we get back to where we should be.
  while (m_db->height() != rollback_height)
  {
    pop_block_from_blockchain();
  }
  CHECK_AND_ASSERT_THROW_MES(update_next_cumulative_weight_limit(), "Error updating next cumulative weight limit");

  // make sure the hard fork object updates its current version
  m_hardfork->reorganize_from_chain_height(rollback_height);

  //return back original chain
  for (auto& bl : original_chain)
  {
    block_verification_context bvc = {};
    bool r = handle_block_to_main_chain(bl, bvc);
    CHECK_AND_ASSERT_MES(r && bvc.m_added_to_main_chain, false, "PANIC! failed to add (again) block while chain switching during the rollback!");
  }

  m_hardfork->reorganize_from_chain_height(rollback_height);

  MINFO("Rollback to height " << rollback_height << " was successful.");
  if (!original_chain.empty())
  {
    MINFO("Restoration to previous blockchain successful as well.");
  }
  return true;
}
//------------------------------------------------------------------
// This function attempts to switch to an alternate chain, returning
// boolean based on success therein.
bool Blockchain::switch_to_alternative_blockchain(std::list<block_extended_info>& alt_chain, bool discard_disconnected_chain)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;

  // if empty alt chain passed (not sure how that could happen), return false
  CHECK_AND_ASSERT_MES(alt_chain.size(), false, "switch_to_alternative_blockchain: empty chain passed");

  // verify that main chain has front of alt chain's parent block
  if (!m_db->block_exists(alt_chain.front().bl.prev_id))
  {
    LOG_ERROR("Attempting to move to an alternate chain, but it doesn't appear to connect to the main chain!");
    return false;
  }

  // pop blocks from the blockchain until the top block is the parent
  // of the front block of the alt chain.
  std::list<block> disconnected_chain;
  while (m_db->top_block_hash() != alt_chain.front().bl.prev_id)
  {
    block b = pop_block_from_blockchain();
    disconnected_chain.push_front(b);
  }
  CHECK_AND_ASSERT_THROW_MES(update_next_cumulative_weight_limit(), "Error updating next cumulative weight limit");

  auto split_height = m_db->height();

  //connecting new alternative chain
  for(auto alt_ch_iter = alt_chain.begin(); alt_ch_iter != alt_chain.end(); alt_ch_iter++)
  {
    const auto &bei = *alt_ch_iter;
    block_verification_context bvc = {};

    // add block to main chain
    bool r = handle_block_to_main_chain(bei.bl, bvc);

    // if adding block to main chain failed, rollback to previous state and
    // return false
    if(!r || !bvc.m_added_to_main_chain)
    {
      MERROR("Failed to switch to alternative blockchain");

      // rollback_blockchain_switching should be moved to two different
      // functions: rollback and apply_chain, but for now we pretend it is
      // just the latter (because the rollback was done above).
      rollback_blockchain_switching(disconnected_chain, split_height);

      const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
      m_db->remove_alt_block(blkid);
      alt_ch_iter++;

      for(auto alt_ch_to_orph_iter = alt_ch_iter; alt_ch_to_orph_iter != alt_chain.end(); )
      {
        const auto &bei = *alt_ch_to_orph_iter++;
        const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
        m_db->remove_alt_block(blkid);
      }
      return false;
    }
  }

  // if we're to keep the disconnected blocks, add them as alternates
  const size_t discarded_blocks = disconnected_chain.size();
  if(!discard_disconnected_chain)
  {
    //pushing old chain as alternative chain
    for (auto& old_ch_ent : disconnected_chain)
    {
      block_verification_context bvc = {};
      pool_supplement ps{};
      bool r = handle_alternative_block(old_ch_ent, get_block_hash(old_ch_ent), bvc, ps);
      if(!r)
      {
        MERROR("Failed to push ex-main chain blocks to alternative chain ");
        // previously this would fail the blockchain switching, but I don't
        // think this is bad enough to warrant that.
      }
    }
  }

  //removing alt_chain entries from alternative chains container
  for (const auto &bei: alt_chain)
  {
    m_db->remove_alt_block(cryptonote::get_block_hash(bei.bl));
  }

  m_hardfork->reorganize_from_chain_height(split_height);

  std::shared_ptr<tools::Notify> reorg_notify = m_reorg_notify;
  if (reorg_notify)
    reorg_notify->notify("%s", std::to_string(split_height).c_str(), "%h", std::to_string(m_db->height()).c_str(),
        "%n", std::to_string(m_db->height() - split_height).c_str(), "%d", std::to_string(discarded_blocks).c_str(), NULL);

  const uint64_t new_height = m_db->height();
  const crypto::hash seedhash = get_block_id_by_height(crypto::rx_seedheight(new_height));

  crypto::hash prev_id;
  if (!get_block_hash(alt_chain.back().bl, prev_id))
    MERROR("Failed to get block hash of an alternative chain's tip");
  else
    send_miner_notifications(new_height, seedhash, prev_id, alt_chain.back().already_generated_coins);

  for (const auto& notifier : m_block_notifiers)
  {
    std::size_t notify_height = split_height;
    for (const auto& bei: alt_chain)
    {
      notifier(notify_height, {std::addressof(bei.bl), 1});
      ++notify_height;
    }
  }

  if (m_hardfork->get_current_version() >= RX_BLOCK_VERSION)
    rx_set_main_seedhash(seedhash.data, tools::get_max_concurrency());

  MGINFO_GREEN("REORGANIZE SUCCESS! on height: " << split_height << ", new blockchain size: " << m_db->height());
  return true;
}
//------------------------------------------------------------------
// This function calculates the difficulty target for the block being added to
// an alternate chain.
difficulty_type Blockchain::get_next_difficulty_for_alternative_chain(const std::list<block_extended_info>& alt_chain, block_extended_info& bei) const
{
  if (m_fixed_difficulty)
  {
    return m_db->height() ? m_fixed_difficulty : 1;
  }

  LOG_PRINT_L3("Blockchain::" << __func__);
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> cumulative_difficulties;
  uint8_t version = get_current_hard_fork_version();
  uint64_t difficulty_blocks_count = version >= 20 ? DIFFICULTY_BLOCKS_COUNT_V4 : version >= 11 ? DIFFICULTY_BLOCKS_COUNT_V3 : version <= 10 && version >= 8 ? DIFFICULTY_BLOCKS_COUNT_V2 : DIFFICULTY_BLOCKS_COUNT;

  // if the alt chain isn't long enough to calculate the difficulty target
  // based on its blocks alone, need to get more blocks from the main chain
  if(alt_chain.size()< difficulty_blocks_count)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);

    // Figure out start and stop offsets for main chain blocks
    size_t main_chain_stop_offset = alt_chain.size() ? alt_chain.front().height : bei.height;
    size_t main_chain_count = difficulty_blocks_count - std::min(static_cast<size_t>(difficulty_blocks_count), alt_chain.size());
    main_chain_count = std::min(main_chain_count, main_chain_stop_offset);
    size_t main_chain_start_offset = main_chain_stop_offset - main_chain_count;

    if(!main_chain_start_offset)
      ++main_chain_start_offset; //skip genesis block

    // get difficulties and timestamps from relevant main chain blocks
    for(; main_chain_start_offset < main_chain_stop_offset; ++main_chain_start_offset)
    {
      timestamps.push_back(m_db->get_block_timestamp(main_chain_start_offset));
      cumulative_difficulties.push_back(m_db->get_block_cumulative_difficulty(main_chain_start_offset));
    }

    // make sure we haven't accidentally grabbed too many blocks...maybe don't need this check?
    CHECK_AND_ASSERT_MES((alt_chain.size() + timestamps.size()) <= difficulty_blocks_count, false, "Internal error, alt_chain.size()[" << alt_chain.size() << "] + vtimestampsec.size()[" << timestamps.size() << "] NOT <= DIFFICULTY_WINDOW[]" << difficulty_blocks_count);

    for (const auto &bei : alt_chain)
    {
      timestamps.push_back(bei.bl.timestamp);
      cumulative_difficulties.push_back(bei.cumulative_difficulty);
    }
  }
  // if the alt chain is long enough for the difficulty calc, grab difficulties
  // and timestamps from it alone
  else
  {
    timestamps.resize(static_cast<size_t>(difficulty_blocks_count));
    cumulative_difficulties.resize(static_cast<size_t>(difficulty_blocks_count));
    size_t count = 0;
    size_t max_i = timestamps.size()-1;
    // get difficulties and timestamps from most recent blocks in alt chain
    for (const auto &bei: boost::adaptors::reverse(alt_chain))
    {
      timestamps[max_i - count] = bei.bl.timestamp;
      cumulative_difficulties[max_i - count] = bei.cumulative_difficulty;
      count++;
      if(count >= difficulty_blocks_count)
        break;
    }
  }

  // FIXME: This will fail if fork activation heights are subject to voting
  size_t target = get_ideal_hard_fork_version(bei.height) < 2 ? DIFFICULTY_TARGET_V1 : DIFFICULTY_TARGET_V2;

  // calculate the difficulty target for the block and return it
  uint64_t HEIGHT = m_db->height();
  difficulty_type next_diff;
  if (version >= 20) {
    next_diff = next_difficulty_v5(timestamps, cumulative_difficulties, HEIGHT, m_nettype);
  } else if (version >= 11) {
    next_diff = next_difficulty_v5(timestamps, cumulative_difficulties, HEIGHT, m_nettype);
  } else if (version == 10) {
    next_diff = next_difficulty_v4(timestamps, cumulative_difficulties, HEIGHT, m_nettype);
  } else if (version == 9) {
    next_diff = next_difficulty_v3(timestamps, cumulative_difficulties, HEIGHT, m_nettype);
  } else if (version == 8) {
    next_diff = next_difficulty_v2(timestamps, cumulative_difficulties, target, HEIGHT, m_nettype);
  } else {
    next_diff = next_difficulty(timestamps, cumulative_difficulties, target, HEIGHT, m_nettype);
  }
  return next_diff;
}
//------------------------------------------------------------------
// This function does a sanity check on basic things that all miner
// transactions have in common, such as:
//   one input, of type txin_gen, with height set to the block's height
//   correct miner tx unlock time
//   a non-overflowing tx amount (dubious necessity on this check)
//   valid output types
bool Blockchain::prevalidate_miner_transaction(const block& b, uint64_t height, uint8_t hf_version)
{
  // Miner Block Header Signing
  if (hf_version >= HF_VERSION_BLOCK_HEADER_MINER_SIG)
  {
      // sanity checks
      if (b.miner_tx.vout.size() != 1 && !(hf_version >= HF_VERSION_VESTING && b.miner_tx.vout.size() == 5))
      {
          MWARNING("Only 1 output in miner transaction allowed");
          return false;
      }
      if (!check_output_types(b.miner_tx, hf_version))
      {
          MWARNING("Wrong txout type");
          return false;
      }
      if (b.vote > 2)
      {
          MWARNING("Vote integer must be either 0, 1, or 2");
          return false;
      }
      // keccak hash block header data and check miner signature
      // if signature is invalid, reject block
      crypto::hash sig_data = get_sig_data(b);
      crypto::signature signature = b.signature;
      crypto::public_key output_public_key;
      get_output_public_key(b.miner_tx.vout[0], output_public_key);
      if (!crypto::check_signature(sig_data, output_public_key, signature))
      {
          MWARNING("Miner signature is invalid");
          return false;
      } else {
          LOG_PRINT_L1("Miner signature is good");
          LOG_PRINT_L1("Vote: " << b.vote);
      }
  }

  LOG_PRINT_L3("Blockchain::" << __func__);
  CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, false, "coinbase transaction in the block has no inputs");
  CHECK_AND_ASSERT_MES(b.miner_tx.vin[0].type() == typeid(txin_gen), false, "coinbase transaction in the block has the wrong type");
  CHECK_AND_ASSERT_MES(b.miner_tx.version > 1 || hf_version < HF_VERSION_MIN_V2_COINBASE_TX || height == 0, false, "Invalid coinbase transaction version");

  // for v2 txes (ringct), we only accept empty rct signatures for miner transactions,
  if (hf_version >= HF_VERSION_REJECT_SIGS_IN_COINBASE && b.miner_tx.version >= 2)
  {
    CHECK_AND_ASSERT_MES(b.miner_tx.rct_signatures.type == rct::RCTTypeNull, false, "RingCT signatures not allowed in coinbase transactions");
  }

  if(boost::get<txin_gen>(b.miner_tx.vin[0]).height != height)
  {
    MWARNING("The miner transaction in block has invalid height: " << boost::get<txin_gen>(b.miner_tx.vin[0]).height << ", expected: " << height);
    return false;
  }
  MDEBUG("Miner tx hash: " << get_transaction_hash(b.miner_tx));
  if (height == 0) {
    // PBC CHAIN: skip unlock time check for genesis block
  } else if (hf_version >= HF_VERSION_FIXED_UNLOCK) {
    CHECK_AND_ASSERT_MES(b.miner_tx.unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V2, false, "coinbase transaction transaction has the wrong unlock time=" << b.miner_tx.unlock_time << ", expected " << height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V2);
  } else if (hf_version < HF_VERSION_FIXED_UNLOCK && hf_version >= HF_VERSION_DYNAMIC_UNLOCK) {
    uint64_t N = m_nettype == MAINNET ? 1337 : 5;
    // Correctif v8.2.11 (finding 4.7) : même garde que la construction
    // (cryptonote_tx_utils.cpp) — h < N → null_hash direct (sémantique bit-identique à
    // l'ancien underflow absorbé → 288) ; h >= N → lecture normale.
    crypto::hash blk_id = crypto::null_hash;
    if (height >= N)
      blk_id = get_block_id_by_height(height-N);
    std::string hex_str = epee::string_tools::pod_to_hex(blk_id).substr(0, 3);
    uint64_t blk_num = std::stol(hex_str,nullptr,16)*2;
    uint64_t unlock_window = blk_num + 288;
    CHECK_AND_ASSERT_MES(b.miner_tx.unlock_time == height + unlock_window, false, "coinbase transaction transaction has the wrong unlock time=" << b.miner_tx.unlock_time << ", expected " << height + unlock_window);
  } else {
    CHECK_AND_ASSERT_MES(b.miner_tx.unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, false, "coinbase transaction transaction has the wrong unlock time=" << b.miner_tx.unlock_time << ", expected " << height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
  }

  //check outs overflow
  if(!check_outs_overflow(b.miner_tx))
  {
    MERROR("miner transaction has money overflow in block " << get_block_hash(b));
    return false;
  }

  CHECK_AND_ASSERT_MES(check_output_types(b.miner_tx, hf_version), false, "miner transaction has invalid output type(s) in block " << get_block_hash(b));

  return true;
}
//------------------------------------------------------------------
// This function validates the miner transaction reward
bool Blockchain::validate_miner_transaction(const block& b, size_t cumulative_block_weight, uint64_t fee, uint64_t& base_reward, uint64_t already_generated_coins, bool &partial_block_reward, uint8_t version)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  //validate reward
  uint64_t money_in_use = 0;
  for (auto& o: b.miner_tx.vout)
    money_in_use += o.amount;
  partial_block_reward = false;

  if (version == 3) {
    for (auto &o: b.miner_tx.vout) {
      if (!is_valid_decomposed_amount(o.amount)) {
        MERROR_VER("miner tx output " << print_money(o.amount) << " is not a valid decomposed amount");
        return false;
      }
    }
  }

  uint64_t median_weight;
  if (version >= HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY)
  {
    median_weight = m_current_block_cumul_weight_median;
  }
  else
  {
    std::vector<uint64_t> last_blocks_weights;
    get_last_n_blocks_weights(last_blocks_weights, CRYPTONOTE_REWARD_BLOCKS_WINDOW);
    median_weight = epee::misc_utils::median(last_blocks_weights);
  }
  if (!get_block_reward(median_weight, cumulative_block_weight, already_generated_coins, base_reward, version))
  {
    MERROR_VER("block weight " << cumulative_block_weight << " is bigger than allowed for this blockchain");
    return false;
  }
  if(base_reward + fee < money_in_use)
  {
    MERROR_VER("coinbase transaction spend too much money (" << print_money(money_in_use) << "). Block reward is " << print_money(base_reward + fee) << "(" << print_money(base_reward) << "+" << print_money(fee) << "), cumulative_block_weight " << cumulative_block_weight);
    return false;
  }
  // PBC CHAIN: For HF19+ (vesting), coinbase outputs = miner + dev only.
  // Virtual pools (7%R + 50%F) are NOT in coinbase — they go to LMDB state.
  // We must validate: money_in_use == expected_miner + expected_dev (EXACTLY).
  if (version >= HF_VERSION_VESTING)
  {
    // Recompute split with __uint128_t (Rule A1) — same as pbc_compute_block_split
    uint64_t miner_R = static_cast<uint64_t>(static_cast<unsigned __int128>(base_reward) * PBC_MINER_SHARE / 1000);
    uint64_t dev_R   = static_cast<uint64_t>(static_cast<unsigned __int128>(base_reward) * PBC_DEV_SHARE   / 1000);
    uint64_t miner_F = static_cast<uint64_t>(static_cast<unsigned __int128>(fee) * PBC_FEE_MINER_SHARE / 1000);
    uint64_t expected_coinbase = miner_R + miner_F + dev_R;

    if (money_in_use != expected_coinbase)
    {
      MERROR_VER("PBC coinbase total mismatch: money_in_use=" << print_money(money_in_use)
        << " expected=" << print_money(expected_coinbase)
        << " (miner_R=" << print_money(miner_R)
        << " miner_F=" << print_money(miner_F)
        << " dev_R=" << print_money(dev_R)
        << " | R=" << print_money(base_reward)
        << " F=" << print_money(fee) << ")");
      return false;
    }

    // Conservation sanity: virtual pools + coinbase == R + F
    uint64_t pools_R = base_reward - miner_R - dev_R;
    uint64_t pools_F = fee - miner_F;
    assert(expected_coinbase + pools_R + pools_F == base_reward + fee);

    // TD-6 §1: Hard conservation check (release + debug)
    CHECK_AND_ASSERT_MES(
        miner_R + dev_R + pools_R == base_reward,
        false, "PBC TD-6 §1: validate_miner_tx reward conservation violated");
    CHECK_AND_ASSERT_MES(
        miner_F + pools_F == fee,
        false, "PBC TD-6 §1: validate_miner_tx fee conservation violated");
  }
  else if (version < 2 || version >= HF_VERSION_EXACT_COINBASE)
  {
    if(base_reward + fee != money_in_use)
    {
      MDEBUG("coinbase transaction doesn't use full amount of block reward:  spent: " << money_in_use << ",  block reward " << base_reward + fee << "(" << base_reward << "+" << fee << ")");
      return false;
    }
  }
  else
  {
    // from hard fork 2, since a miner can claim less than the full block reward, we update the base_reward
    // to show the amount of coins that were actually generated, the remainder will be pushed back for later
    // emission. This modifies the emission curve very slightly.
    CHECK_AND_ASSERT_MES(money_in_use - fee <= base_reward, false, "base reward calculation bug");
    if(base_reward + fee != money_in_use)
      partial_block_reward = true;
    base_reward = money_in_use - fee;
  }
  // PBC CHAIN: HF19+ validate dev fund output
  if (version >= HF_VERSION_VESTING && b.miner_tx.vout.size() > 0)
  {
    // Must have exactly 5 outputs: 4 vesting + 1 dev fund
    if (b.miner_tx.vout.size() != 5)
    {
      MERROR_VER("HF19+ coinbase must have exactly 5 outputs (4 vesting + 1 dev fund), got " << b.miner_tx.vout.size());
      return false;
    }

    // Dev fund is the 5th output (index 4) — PBC CHAIN split per Whitepaper §19.3
    // Theoretical R = base_reward (from get_block_reward)
    // Miner gets: floor(R × 910/1000) + floor(F × 500/1000)  (4 vested outputs)
    // Dev gets: floor(R × 20/1000)  (1 output)
    // Virtual pools: R - miner_R - dev_R + (F - miner_F)  (not in coinbase)
    // Rule A1: ALL intermediate products via __uint128_t
    uint64_t miner_R = static_cast<uint64_t>(static_cast<unsigned __int128>(base_reward) * PBC_MINER_SHARE / 1000);
    uint64_t dev_fund_expected = static_cast<uint64_t>(static_cast<unsigned __int128>(base_reward) * PBC_DEV_SHARE / 1000);
    uint64_t miner_F = static_cast<uint64_t>(static_cast<unsigned __int128>(fee) * PBC_FEE_MINER_SHARE / 1000);
    uint64_t miner_reward = miner_R + miner_F;

    // Verify dev fund amount: output[4] must be dev_fund_expected
    uint64_t dev_fund_actual = b.miner_tx.vout[4].amount;
    if (dev_fund_actual != dev_fund_expected)
    {
      MERROR_VER("Dev fund output amount incorrect: expected " << print_money(dev_fund_expected) << ", got " << print_money(dev_fund_actual));
      return false;
    }

    // Verify the 4 vesting outputs each get ~25% of miner_reward
    uint64_t quarter = miner_reward / 4;
    uint64_t remainder = miner_reward - (quarter * 4);
    // Output 0 gets quarter + remainder (dust), outputs 1-3 get quarter
    if (b.miner_tx.vout[0].amount != quarter + remainder)
    {
      MERROR_VER("Vesting output 0 amount incorrect: expected " << print_money(quarter + remainder) << ", got " << print_money(b.miner_tx.vout[0].amount));
      return false;
    }
    for (int i = 1; i < 4; i++)
    {
      if (b.miner_tx.vout[i].amount != quarter)
      {
        MERROR_VER("Vesting output " << i << " amount incorrect: expected " << print_money(quarter) << ", got " << print_money(b.miner_tx.vout[i].amount));
        return false;
      }
    }

    // Verify dev fund output key is derived from the correct dev fund address
    crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(b.miner_tx);
    if (tx_pub_key == crypto::null_pkey)
    {
      MERROR_VER("Failed to get tx pub key from coinbase extra");
      return false;
    }
    crypto::public_key dev_spend_pkey;
    crypto::public_key dev_view_pkey;
    epee::string_tools::hex_to_pod(PBC_DEV_FUND_SPENDKEY, dev_spend_pkey);
    epee::string_tools::hex_to_pod(PBC_DEV_FUND_VIEWKEY, dev_view_pkey);

    // PBC CHAIN: Cryptographic verification that output[4] goes to the dev fund address.
    // We use the dev fund view secret key to reproduce the Diffie-Hellman key exchange
    // and derive the expected ephemeral public key. This is the same operation a wallet
    // performs to detect incoming payments. The view secret key cannot spend funds.
    crypto::secret_key dev_view_skey;
    epee::string_tools::hex_to_pod(PBC_DEV_FUND_VIEWKEY_SECRET, dev_view_skey);

    // Step 1: Diffie-Hellman key derivation
    crypto::key_derivation dev_derivation;
    bool r = crypto::generate_key_derivation(tx_pub_key, dev_view_skey, dev_derivation);
    if (!r)
    {
      MERROR_VER("Dev fund verification failed: could not generate key derivation");
      return false;
    }

    // Step 2: Derive expected ephemeral public key for output index 4
    crypto::public_key expected_dev_key;
    r = crypto::derive_public_key(dev_derivation, 4, dev_spend_pkey, expected_dev_key);
    if (!r)
    {
      MERROR_VER("Dev fund verification failed: could not derive expected public key");
      return false;
    }

    // Step 3: Extract actual public key from output[4]
    crypto::public_key actual_dev_key;
    if (!get_output_public_key(b.miner_tx.vout[4], actual_dev_key))
    {
      MERROR_VER("Dev fund verification failed: could not read output public key");
      return false;
    }

    // Step 4: Compare - if mismatch, the output does NOT go to the dev fund
    if (expected_dev_key != actual_dev_key)
    {
      MERROR_VER("Dev fund output key MISMATCH: block does NOT pay the dev fund address. Rejecting.");
      return false;
    }

    LOG_PRINT_L2("Dev fund validation passed: " << print_money(dev_fund_actual) << " PBC (" << PBC_DEV_SHARE << " per mille) - address cryptographically verified");
  }

  return true;
}
//------------------------------------------------------------------
// get the block weights of the last <count> blocks, and return by reference <sz>.
void Blockchain::get_last_n_blocks_weights(std::vector<uint64_t>& weights, size_t count) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto h = m_db->height();

  // this function is meaningless for an empty blockchain...granted it should never be empty
  if(h == 0)
    return;

  // add weight of last <count> blocks to vector <weights> (or less, if blockchain size < count)
  size_t start_offset = h - std::min<size_t>(h, count);
  weights = m_db->get_block_weights(start_offset, count);
}
//------------------------------------------------------------------
uint64_t Blockchain::get_long_term_block_weight_median(uint64_t start_height, size_t count) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  PERF_TIMER(get_long_term_block_weights);

  CHECK_AND_ASSERT_THROW_MES(count > 0, "count == 0");

  bool cached = false;
  uint64_t blockchain_height = m_db->height();
  uint64_t tip_height = start_height + count - 1;
  crypto::hash tip_hash = crypto::null_hash;
  if (tip_height < blockchain_height && count == (size_t)m_long_term_block_weights_cache_rolling_median.size())
  {
    tip_hash = m_db->get_block_hash_from_height(tip_height);
    cached = tip_hash == m_long_term_block_weights_cache_tip_hash;
  }

  if (cached)
  {
    MTRACE("requesting " << count << " from " << start_height << ", cached");
    return m_long_term_block_weights_cache_rolling_median.median();
  }

  // in the vast majority of uncached cases, most is still cached,
  // as we just move the window one block up:
  if (tip_height > 0 && count == (size_t)m_long_term_block_weights_cache_rolling_median.size() && tip_height < blockchain_height)
  {
    crypto::hash old_tip_hash = m_db->get_block_hash_from_height(tip_height - 1);
    if (old_tip_hash == m_long_term_block_weights_cache_tip_hash)
    {
      MTRACE("requesting " << count << " from " << start_height << ", incremental");
      m_long_term_block_weights_cache_tip_hash = tip_hash;
      m_long_term_block_weights_cache_rolling_median.insert(m_db->get_block_long_term_weight(tip_height));
      return m_long_term_block_weights_cache_rolling_median.median();
    }
  }

  MTRACE("requesting " << count << " from " << start_height << ", uncached");
  std::vector<uint64_t> weights = m_db->get_long_term_block_weights(start_height, count);
  m_long_term_block_weights_cache_tip_hash = tip_hash;
  m_long_term_block_weights_cache_rolling_median.clear();
  for (uint64_t w: weights)
    m_long_term_block_weights_cache_rolling_median.insert(w);
  return m_long_term_block_weights_cache_rolling_median.median();
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_block_weight_limit() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_current_block_cumul_weight_limit;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_block_weight_median() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_current_block_cumul_weight_median;
}
//------------------------------------------------------------------
//TODO: This function only needed minor modification to work with BlockchainDB,
//      and *works*.  As such, to reduce the number of things that might break
//      in moving to BlockchainDB, this function will remain otherwise
//      unchanged for the time being.
//
// This function makes a new block for a miner to mine the hash for
//
// FIXME: this codebase references #if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
// in a lot of places.  That flag is not referenced in any of the code
// nor any of the makefiles, howeve.  Need to look into whether or not it's
// necessary at all.
bool Blockchain::create_block_template(block& b, const crypto::hash *from_block, const account_public_address& miner_address, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce, uint64_t &seed_height, crypto::hash &seed_hash)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t median_weight;
  uint64_t already_generated_coins;
  uint64_t pool_cookie;

  seed_hash = crypto::null_hash;

  m_tx_pool.lock();
  const auto unlock_guard = epee::misc_utils::create_scope_leave_handler([&]() { m_tx_pool.unlock(); });
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if (m_btc_valid && !from_block) {
    // The pool cookie is atomic. The lack of locking is OK, as if it changes
    // just as we compare it, we'll just use a slightly old template, but
    // this would be the case anyway if we'd lock, and the change happened
    // just after the block template was created
    if (!memcmp(&miner_address, &m_btc_address, sizeof(cryptonote::account_public_address)) && m_btc_nonce == ex_nonce
      && m_btc_pool_cookie == m_tx_pool.cookie() && m_btc.prev_id == get_tail_id()) {
      MDEBUG("Using cached template");
      const uint64_t now = time(NULL);
      if (m_btc.timestamp < now) // ensures it can't get below the median of the last few blocks
        m_btc.timestamp = now;
      b = m_btc;
      diffic = m_btc_difficulty;
      height = m_btc_height;
      expected_reward = m_btc_expected_reward;
      seed_height = m_btc_seed_height;
      seed_hash = m_btc_seed_hash;
      return true;
    }
    MDEBUG("Not using cached template: address " << (!memcmp(&miner_address, &m_btc_address, sizeof(cryptonote::account_public_address))) << ", nonce " << (m_btc_nonce == ex_nonce) << ", cookie " << (m_btc_pool_cookie == m_tx_pool.cookie()) << ", from_block " << (!!from_block));
    invalidate_block_template_cache();
  }

  if (from_block)
  {
    //build alternative subchain, front -> mainchain, back -> alternative head
    //block is not related with head of main chain
    //first of all - look in alternative chains container
    alt_block_data_t prev_data;
    bool parent_in_alt = m_db->get_alt_block(*from_block, &prev_data, NULL);
    bool parent_in_main = m_db->block_exists(*from_block);
    if (!parent_in_alt && !parent_in_main)
    {
      MERROR("Unknown from block");
      return false;
    }

    //we have new block in alternative chain
    std::list<block_extended_info> alt_chain;
    block_verification_context bvc = {};
    std::vector<uint64_t> timestamps;
    if (!build_alt_chain(*from_block, alt_chain, timestamps, bvc))
      return false;

    if (parent_in_main)
    {
      cryptonote::block prev_block;
      CHECK_AND_ASSERT_MES(get_block_by_hash(*from_block, prev_block), false, "From block not found"); // TODO
      uint64_t from_block_height = cryptonote::get_block_height(prev_block);
      height = from_block_height + 1;
      if (m_hardfork->get_current_version() >= RX_BLOCK_VERSION)
      {
        uint64_t next_height;
        crypto::rx_seedheights(height, &seed_height, &next_height);
        seed_hash = get_block_id_by_height(seed_height);
      }
    }
    else
    {
      height = alt_chain.back().height + 1;
      uint64_t next_height;
      crypto::rx_seedheights(height, &seed_height, &next_height);

      if (alt_chain.size() && alt_chain.front().height <= seed_height)
      {
        for (auto it=alt_chain.begin(); it != alt_chain.end(); it++)
        {
          if (it->height == seed_height+1)
          {
            seed_hash = it->bl.prev_id;
            break;
          }
        }
      }
      else
      {
        seed_hash = get_block_id_by_height(seed_height);
      }
    }
    b.major_version = m_hardfork->get_ideal_version(height);
    b.minor_version = m_hardfork->get_ideal_version();
    b.prev_id = *from_block;

    // cheat and use the weight of the block we start from, virtually certain to be acceptable
    // and use 1.9 times rather than 2 times so we're even more sure
    if (parent_in_main)
    {
      median_weight = m_db->get_block_weight(height - 1);
      already_generated_coins = m_db->get_block_already_generated_coins(height - 1);
    }
    else
    {
      median_weight = prev_data.cumulative_weight - prev_data.cumulative_weight / 20;
      already_generated_coins = alt_chain.back().already_generated_coins;
    }

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = {};
    bei.bl = b;
    bei.height = alt_chain.size() ? prev_data.height + 1 : m_db->get_block_height(*from_block) + 1;

    diffic = get_next_difficulty_for_alternative_chain(alt_chain, bei);
  }
  else
  {
    height = m_db->height();
    b.major_version = m_hardfork->get_ideal_version(height);
    b.minor_version = m_hardfork->get_ideal_version();
    b.prev_id = get_tail_id();
    median_weight = m_current_block_cumul_weight_limit / 2;
    diffic = get_difficulty_for_next_block(m_nettype);
    already_generated_coins = m_db->get_block_already_generated_coins(height - 1);
    if (m_hardfork->get_current_version() >= RX_BLOCK_VERSION)
    {
      uint64_t next_height;
      crypto::rx_seedheights(height, &seed_height, &next_height);
      seed_hash = get_block_id_by_height(seed_height);
    }
  }
  b.timestamp = time(NULL);

  uint64_t median_ts;
  if (!check_block_timestamp(b, median_ts))
  {
    b.timestamp = median_ts;
  }

  CHECK_AND_ASSERT_MES(diffic, false, "difficulty overhead.");

  size_t txs_weight;
  uint64_t fee;
  if (!m_tx_pool.fill_block_template(b, median_weight, already_generated_coins, txs_weight, fee, expected_reward, b.major_version))
  {
    return false;
  }
  pool_cookie = m_tx_pool.cookie();
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
  size_t real_txs_weight = 0;
  uint64_t real_fee = 0;
  for(crypto::hash &cur_hash: b.tx_hashes)
  {
    auto cur_res = m_tx_pool.m_transactions.find(cur_hash);
    if (cur_res == m_tx_pool.m_transactions.end())
    {
      LOG_ERROR("Creating block template: error: transaction not found");
      continue;
    }
    tx_memory_pool::tx_details &cur_tx = cur_res->second;
    real_txs_weight += cur_tx.weight;
    real_fee += cur_tx.fee;
    if (cur_tx.weight != get_transaction_weight(cur_tx.tx))
    {
      LOG_ERROR("Creating block template: error: invalid transaction weight");
    }
    if (cur_tx.tx.version == 1)
    {
      uint64_t inputs_amount;
      if (!get_inputs_money_amount(cur_tx.tx, inputs_amount))
      {
        LOG_ERROR("Creating block template: error: cannot get inputs amount");
      }
      else if (cur_tx.fee != inputs_amount - get_outs_money_amount(cur_tx.tx))
      {
        LOG_ERROR("Creating block template: error: invalid fee");
      }
    }
    else
    {
      if (cur_tx.fee != cur_tx.tx.rct_signatures.txnFee)
      {
        LOG_ERROR("Creating block template: error: invalid fee");
      }
    }
  }
  if (txs_weight != real_txs_weight)
  {
    LOG_ERROR("Creating block template: error: wrongly calculated transaction weight");
  }
  if (fee != real_fee)
  {
    LOG_ERROR("Creating block template: error: wrongly calculated fee");
  }
  MDEBUG("Creating block template: height " << height <<
      ", median weight " << median_weight <<
      ", already generated coins " << already_generated_coins <<
      ", transaction weight " << txs_weight <<
      ", fee " << fee);
#endif

  /*
   two-phase miner transaction generation: we don't know exact block weight until we prepare block, but we don't know reward until we know
   block weight, so first miner transaction generated with fake amount of money, and with phase we know think we know expected block weight
   */
  //make blocks coin-base tx looks close to real coinbase tx to get truthful blob weight
  uint8_t hf_version = b.major_version;
  size_t max_outs = hf_version >= HF_VERSION_VESTING ? 5 : (hf_version >= 4 ? 1 : 11);
  bool r = construct_miner_tx(this, m_nettype, height, median_weight, already_generated_coins, txs_weight, fee, miner_address, b.miner_tx, ex_nonce, max_outs, hf_version);
  CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, first chance");
  size_t cumulative_weight = txs_weight + get_transaction_weight(b.miner_tx);
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
  MDEBUG("Creating block template: miner tx weight " << get_transaction_weight(b.miner_tx) <<
      ", cumulative weight " << cumulative_weight);
#endif
  for (size_t try_count = 0; try_count != 10; ++try_count)
  {
    r = construct_miner_tx(this, m_nettype, height, median_weight, already_generated_coins, cumulative_weight, fee, miner_address, b.miner_tx, ex_nonce, max_outs, hf_version);

    CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, second chance");
    size_t coinbase_weight = get_transaction_weight(b.miner_tx);
    if (coinbase_weight > cumulative_weight - txs_weight)
    {
      cumulative_weight = txs_weight + coinbase_weight;
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
      MDEBUG("Creating block template: miner tx weight " << coinbase_weight <<
          ", cumulative weight " << cumulative_weight << " is greater than before");
#endif
      continue;
    }

    if (coinbase_weight < cumulative_weight - txs_weight)
    {
      size_t delta = cumulative_weight - txs_weight - coinbase_weight;
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
      MDEBUG("Creating block template: miner tx weight " << coinbase_weight <<
          ", cumulative weight " << txs_weight + coinbase_weight <<
          " is less than before, adding " << delta << " zero bytes");
#endif
      b.miner_tx.extra.insert(b.miner_tx.extra.end(), delta, 0);
      //here  could be 1 byte difference, because of extra field counter is varint, and it can become from 1-byte len to 2-bytes len.
      if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx))
      {
        CHECK_AND_ASSERT_MES(cumulative_weight + 1 == txs_weight + get_transaction_weight(b.miner_tx), false, "unexpected case: cumulative_weight=" << cumulative_weight << " + 1 is not equal txs_cumulative_weight=" << txs_weight << " + get_transaction_weight(b.miner_tx)=" << get_transaction_weight(b.miner_tx));
        b.miner_tx.extra.resize(b.miner_tx.extra.size() - 1);
        if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx))
        {
          //fuck, not lucky, -1 makes varint-counter size smaller, in that case we continue to grow with cumulative_weight
          MDEBUG("Miner tx creation has no luck with delta_extra size = " << delta << " and " << delta - 1);
          cumulative_weight += delta - 1;
          continue;
        }
        MDEBUG("Setting extra for block: " << b.miner_tx.extra.size() << ", try_count=" << try_count);
      }
    }
    CHECK_AND_ASSERT_MES(cumulative_weight == txs_weight + get_transaction_weight(b.miner_tx), false, "unexpected case: cumulative_weight=" << cumulative_weight << " is not equal txs_cumulative_weight=" << txs_weight << " + get_transaction_weight(b.miner_tx)=" << get_transaction_weight(b.miner_tx));
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    MDEBUG("Creating block template: miner tx weight " << coinbase_weight <<
        ", cumulative weight " << cumulative_weight << " is now good");
#endif

    if (!from_block)
      cache_block_template(b, miner_address, ex_nonce, diffic, height, expected_reward, seed_height, seed_hash, pool_cookie);
    return true;
  }
  LOG_ERROR("Failed to create_block_template with " << 10 << " tries");
  return false;
}
//------------------------------------------------------------------
bool Blockchain::create_block_template(block& b, const account_public_address& miner_address, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce, uint64_t &seed_height, crypto::hash &seed_hash)
{
  return create_block_template(b, NULL, miner_address, diffic, height, expected_reward, ex_nonce, seed_height, seed_hash);
}
//------------------------------------------------------------------
bool Blockchain::get_miner_data(uint8_t& major_version, uint64_t& height, crypto::hash& prev_id, crypto::hash& seed_hash, difficulty_type& difficulty, uint64_t& median_weight, uint64_t& already_generated_coins, std::vector<tx_block_template_backlog_entry>& tx_backlog)
{
  prev_id = m_db->top_block_hash(&height);
  ++height;

  major_version = m_hardfork->get_ideal_version(height);

  seed_hash = crypto::null_hash;
  if (m_hardfork->get_current_version() >= RX_BLOCK_VERSION)
  {
    uint64_t seed_height, next_height;
    crypto::rx_seedheights(height, &seed_height, &next_height);
    seed_hash = get_block_id_by_height(seed_height);
  }

  difficulty = get_difficulty_for_next_block(m_nettype);
  median_weight = m_current_block_cumul_weight_median;
  already_generated_coins = m_db->get_block_already_generated_coins(height - 1);

  m_tx_pool.get_block_template_backlog(tx_backlog);

  return true;
}
//------------------------------------------------------------------
// for an alternate chain, get the timestamps from the main chain to complete
// the needed number of timestamps for the BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.
bool Blockchain::complete_timestamps_vector(uint64_t start_top_height, std::vector<uint64_t>& timestamps) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  uint8_t version = get_current_hard_fork_version();
  size_t blockchain_timestamp_check_window = version >= 10 ? BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2 : BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;

  if(timestamps.size() >= blockchain_timestamp_check_window)
    return true;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  size_t need_elements = blockchain_timestamp_check_window - timestamps.size();
  CHECK_AND_ASSERT_MES(start_top_height < m_db->height(), false, "internal error: passed start_height not < " << " m_db->height() -- " << start_top_height << " >= " << m_db->height());
  size_t stop_offset = start_top_height > need_elements ? start_top_height - need_elements : 0;
  timestamps.reserve(timestamps.size() + start_top_height - stop_offset);
  while (start_top_height != stop_offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(start_top_height));
    --start_top_height;
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::build_alt_chain(const crypto::hash &prev_id, std::list<block_extended_info>& alt_chain, std::vector<uint64_t> &timestamps, block_verification_context& bvc) const
{
    //build alternative subchain, front -> mainchain, back -> alternative head
    cryptonote::alt_block_data_t data;
    cryptonote::blobdata blob;
    bool found = m_db->get_alt_block(prev_id, &data, &blob);
    timestamps.clear();
    while(found)
    {
      block_extended_info bei;
      CHECK_AND_ASSERT_MES(cryptonote::parse_and_validate_block_from_blob(blob, bei.bl), false, "Failed to parse alt block");
      bei.height = data.height;
      bei.block_cumulative_weight = data.cumulative_weight;
      bei.cumulative_difficulty = data.cumulative_difficulty_high;
      bei.cumulative_difficulty = (bei.cumulative_difficulty << 64) + data.cumulative_difficulty_low;
      bei.already_generated_coins = data.already_generated_coins;
      timestamps.push_back(bei.bl.timestamp);
      alt_chain.push_front(std::move(bei));
      found = m_db->get_alt_block(bei.bl.prev_id, &data, &blob);
    }

    // if block to be added connects to known blocks that aren't part of the
    // main chain -- that is, if we're adding on to an alternate chain
    if(!alt_chain.empty())
    {
      // make sure alt chain doesn't somehow start past the end of the main chain
      CHECK_AND_ASSERT_MES(m_db->height() > alt_chain.front().height, false, "main blockchain wrong height");

      // make sure that the blockchain contains the block that should connect
      // this alternate chain with it.
      if (!m_db->block_exists(alt_chain.front().bl.prev_id))
      {
        MERROR("alternate chain does not appear to connect to main chain...");
        return false;
      }

      // make sure block connects correctly to the main chain
      auto h = m_db->get_block_hash_from_height(alt_chain.front().height - 1);
      CHECK_AND_ASSERT_MES(h == alt_chain.front().bl.prev_id, false, "alternative chain has wrong connection to main chain");
      complete_timestamps_vector(m_db->get_block_height(alt_chain.front().bl.prev_id), timestamps);
    }
    // if block not associated with known alternate chain
    else
    {
      // if block parent is not part of main chain or an alternate chain,
      // we ignore it
      bool parent_in_main = m_db->block_exists(prev_id);
      CHECK_AND_ASSERT_MES(parent_in_main, false, "internal error: broken imperative condition: parent_in_main");

      complete_timestamps_vector(m_db->get_block_height(prev_id), timestamps);
    }

    return true;
}
//------------------------------------------------------------------
// If a block is to be added and its parent block is not the current
// main chain top block, then we need to see if we know about its parent block.
// If its parent block is part of a known forked chain, then we need to see
// if that chain is long enough to become the main chain and re-org accordingly
// if so.  If not, we need to hang on to the block in case it becomes part of
// a long forked chain eventually.
bool Blockchain::handle_alternative_block(const block& b, const crypto::hash& id,
  block_verification_context& bvc, pool_supplement& extra_block_txs)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;
  uint64_t block_height = get_block_height(b);
  fprintf(stderr,
    "PBC ALT ENTER: h=%" PRIu64 " id=%s prev=%s major=%u minor=%u txs=%zu\n",
    block_height,
    epee::string_tools::pod_to_hex(id).c_str(),
    epee::string_tools::pod_to_hex(b.prev_id).c_str(),
    (unsigned)b.major_version,
    (unsigned)b.minor_version,
    b.tx_hashes.size());
  fflush(stderr);
  if(0 == block_height)
  {
    MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative), but miner tx says height is 0.");
    bvc.m_verifivation_failed = true;
    return false;
  }
  // this basically says if the blockchain is smaller than the first
  // checkpoint then alternate blocks are allowed.  Alternatively, if the
  // last checkpoint *before* the end of the current chain is also before
  // the block to be added, then this is fine.
  if (!m_checkpoints.is_alternative_block_allowed(get_current_blockchain_height(), block_height))
  {
    MERROR_VER("Block with id: " << id << std::endl << " can't be accepted for alternative chain, block height: " << block_height << std::endl << " blockchain height: " << get_current_blockchain_height());
    bvc.m_verifivation_failed = true;
    return false;
  }

  // this is a cheap test
  const uint8_t hf_version = m_hardfork->get_ideal_version(block_height);
  if (!m_hardfork->check_for_height(b, block_height))
  {
    LOG_PRINT_L1("Block with id: " << id << std::endl << "has old version for height " << block_height);
    bvc.m_verifivation_failed = true;
    return false;
  }

  //block is not related with head of main chain
  //first of all - look in alternative chains container
  alt_block_data_t prev_data;
  bool parent_in_alt = m_db->get_alt_block(b.prev_id, &prev_data, NULL);
  bool parent_in_main = m_db->block_exists(b.prev_id);
  if (parent_in_alt || parent_in_main)
  {
    //we have new block in alternative chain
    std::list<block_extended_info> alt_chain;
    std::vector<uint64_t> timestamps;
    if (!build_alt_chain(b.prev_id, alt_chain, timestamps, bvc))
      return false;

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = {};
    bei.bl = b;
    const uint64_t prev_height = alt_chain.size() ? prev_data.height : m_db->get_block_height(b.prev_id);
    bei.height = prev_height + 1;
    // PBC: already_generated_coins must track the full theoretical R, not just coinbase outputs
    // Coinbase only contains 93% of R (miner + dev). The 7% goes to virtual pools.
    // We recompute R from the emission formula for correct tracking.
    const uint64_t prev_generated_coins = alt_chain.size() ? prev_data.already_generated_coins : m_db->get_block_already_generated_coins(prev_height);
    uint64_t alt_base_reward = 0;
    {
      // Compute theoretical R for this alt block using emission formula
      uint64_t median_weight = m_current_block_cumul_weight_limit / 2; // approximation for alt chain
      get_block_reward(median_weight, 1, prev_generated_coins, alt_base_reward, m_hardfork->get_ideal_version());
    }
    bei.already_generated_coins = (alt_base_reward < (MONEY_SUPPLY - prev_generated_coins)) ? prev_generated_coins + alt_base_reward : MONEY_SUPPLY;

    // verify that the block's timestamp is within the acceptable range
    // (not earlier than the median of the last X blocks)
    if(!check_block_timestamp(timestamps, b))
    {
      MERROR_VER("Block with id: " << id << std::endl << " for alternative chain, has invalid timestamp: " << b.timestamp);
      bvc.m_verifivation_failed = true;
      return false;
    }

    bool is_a_checkpoint;
    if(!m_checkpoints.check_block(bei.height, id, is_a_checkpoint))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verifivation_failed = true;
      return false;
    }

    // Check the block's hash against the difficulty target for its alt chain
    difficulty_type current_diff = get_next_difficulty_for_alternative_chain(alt_chain, bei);
    CHECK_AND_ASSERT_MES(current_diff, false, "!!!!!!! DIFFICULTY OVERHEAD !!!!!!!");
    crypto::hash proof_of_work;
    memset(proof_of_work.data, 0xff, sizeof(proof_of_work.data));
    if (b.major_version >= RX_BLOCK_VERSION)
    {
      crypto::hash seedhash = null_hash;
      uint64_t seedheight = rx_seedheight(bei.height);
      // seedblock is on the alt chain somewhere
      if (alt_chain.size() && alt_chain.front().height <= seedheight)
      {
        for (auto it=alt_chain.begin(); it != alt_chain.end(); it++)
        {
          if (it->height == seedheight+1)
          {
            seedhash = it->bl.prev_id;
            break;
          }
        }
      } else
      {
        seedhash = get_block_id_by_height(seedheight);
      }
      fprintf(stderr,
        "PBC ALT POW: prev=%s major=%u minor=%u\n",
        epee::string_tools::pod_to_hex(b.prev_id).c_str(),
        (unsigned)b.major_version,
        (unsigned)b.minor_version);
      fflush(stderr);
      get_altblock_longhash(bei.bl, proof_of_work, seedhash);
    } else
    {
      get_block_longhash(this, bei.bl, proof_of_work, bei.height, 0);
    }
    if(!check_hash(proof_of_work, current_diff))
    {
      MERROR_VER("Block with id: " << id << std::endl << " for alternative chain, does not have enough proof of work: " << proof_of_work << std::endl << " expected difficulty: " << current_diff);
      bvc.m_verifivation_failed = true;
      bvc.m_bad_pow = true;
      return false;
    }

    if(!prevalidate_miner_transaction(b, bei.height, hf_version))
    {
      MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) has incorrect miner transaction.");
      bvc.m_verifivation_failed = true;
      return false;
    }

    // FIXME:
    // this brings up an interesting point: consider allowing to get block
    // difficulty both by height OR by hash, not just height.
    difficulty_type main_chain_cumulative_difficulty = m_db->get_block_cumulative_difficulty(m_db->height() - 1);
    if (alt_chain.size())
    {
      bei.cumulative_difficulty = prev_data.cumulative_difficulty_high;
      bei.cumulative_difficulty = (bei.cumulative_difficulty << 64) + prev_data.cumulative_difficulty_low;
    }
    else
    {
      // passed-in block's previous block's cumulative difficulty, found on the main chain
      bei.cumulative_difficulty = m_db->get_block_cumulative_difficulty(m_db->get_block_height(b.prev_id));
    }
    bei.cumulative_difficulty += current_diff;

    // Now that we have the PoW verification out of the way, verify all pool supplement txs
    tx_verification_context tvc{};
    if (!ver_non_input_consensus(extra_block_txs, tvc, hf_version))
    {
      MERROR_VER("Transaction pool supplement verification failure for alt block " << id);
      bvc.m_verifivation_failed = true;
      return false;
    }

    // Add pool supplement txs to the main mempool with relay_method::block
    CRITICAL_REGION_LOCAL(m_tx_pool);
    for (auto& extra_block_tx : extra_block_txs.txs_by_txid)
    {
      const crypto::hash& txid = extra_block_tx.first;
      transaction& tx = extra_block_tx.second.first;
      const blobdata &tx_blob = extra_block_tx.second.second;

      tx_verification_context tvc{};
      if ((!m_tx_pool.have_tx(txid, relay_category::legacy) &&
          !m_db->tx_exists(txid) &&
          !m_tx_pool.add_tx(tx, tvc, relay_method::block, /*relayed=*/true, hf_version, hf_version))
          || tvc.m_verifivation_failed)
      {
        MERROR_VER("Transaction " << txid <<
          " in pool supplement failed to enter main pool for alt block " << id);
        bvc.m_verifivation_failed = true;
        return false;
      }

      // If new incoming tx in alt block passed verification and entered the pool, notify ZMQ
      if (tvc.m_added_to_pool)
        notify_txpool_event({txpool_event{
          .tx = tx,
          .hash = txid,
          .blob_size = tx_blob.size(),
          .weight = get_transaction_weight(tx),
          .res = true}});
    }
    extra_block_txs.txs_by_txid.clear();
    extra_block_txs.nic_verified_hf_version = 0;

    bei.block_cumulative_weight = cryptonote::get_transaction_weight(b.miner_tx);
    for (const crypto::hash &txid: b.tx_hashes)
    {
      cryptonote::tx_memory_pool::tx_details td;
      cryptonote::blobdata blob;
      if (m_tx_pool.have_tx(txid, relay_category::legacy))
      {
        if (m_tx_pool.get_transaction_info(txid, td, true/*include_sensitive_data*/))
        {
          bei.block_cumulative_weight += td.weight;
        }
        else
        {
          MERROR_VER("Transaction is in the txpool, but metadata not found");
          bvc.m_verifivation_failed = true;
          return false;
        }
      }
      else if (m_db->get_pruned_tx_blob(txid, blob))
      {
        cryptonote::transaction tx;
        if (!cryptonote::parse_and_validate_tx_base_from_blob(blob, tx))
        {
          MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) refers to unparsable transaction hash " << txid << ".");
          bvc.m_verifivation_failed = true;
          return false;
        }
        bei.block_cumulative_weight += cryptonote::get_pruned_transaction_weight(tx);
      }
      else
      {
        // we can't determine the block weight, set it to 0 and break out of the loop
        bei.block_cumulative_weight = 0;
        break;
      }
    }

    // add block to alternate blocks storage,
    // as well as the current "alt chain" container
    CHECK_AND_ASSERT_MES(!m_db->get_alt_block(id, NULL, NULL), false, "insertion of new alternative block returned as it already exists");
    cryptonote::alt_block_data_t data;
    data.height = bei.height;
    data.cumulative_weight = bei.block_cumulative_weight;
    data.cumulative_difficulty_low = (bei.cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
    data.cumulative_difficulty_high = ((bei.cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
    data.already_generated_coins = bei.already_generated_coins;
    m_db->add_alt_block(id, data, cryptonote::block_to_blob(bei.bl));
    alt_chain.push_back(bei);

    // FIXME: is it even possible for a checkpoint to show up not on the main chain?
    if(is_a_checkpoint)
    {
      //do reorganize!
      MGINFO_GREEN("###### REORGANIZE on height: " << alt_chain.front().height << " of " << m_db->height() - 1 << ", checkpoint is found in alternative chain on height " << bei.height);

      bool r = switch_to_alternative_blockchain(alt_chain, true);

      if(r) bvc.m_added_to_main_chain = true;
      else bvc.m_verifivation_failed = true;

      return r;
    }
    else if(main_chain_cumulative_difficulty < bei.cumulative_difficulty) //check if difficulty bigger then in main chain
    {
      //do reorganize!
      MGINFO_GREEN("###### REORGANIZE on height: " << alt_chain.front().height << " of " << m_db->height() - 1 << " with cum_difficulty " << m_db->get_block_cumulative_difficulty(m_db->height() - 1) << std::endl << " alternative blockchain size: " << alt_chain.size() << " with cum_difficulty " << bei.cumulative_difficulty);

      bool r = switch_to_alternative_blockchain(alt_chain, false);
      if (r)
        bvc.m_added_to_main_chain = true;
      else
        bvc.m_verifivation_failed = true;
      return r;
    }
    else
    {
      MGINFO_BLUE("----- BLOCK ADDED AS ALTERNATIVE ON HEIGHT " << bei.height << std::endl << "id:\t" << id << std::endl << "PoW:\t" << proof_of_work << std::endl << "difficulty:\t" << current_diff);
      return true;
    }
  }
  else
  {
    //block orphaned
    bvc.m_marked_as_orphaned = true;
    MERROR_VER("Block recognized as orphaned and rejected, id = " << id << ", height " << block_height
        << ", parent in alt " << parent_in_alt << ", parent in main " << parent_in_main
        << " (parent " << b.prev_id << ", current top " << get_tail_id() << ", chain height " << get_current_blockchain_height() << ")");
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata,block>>& blocks, std::vector<cryptonote::blobdata>& txs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(start_offset >= m_db->height())
    return false;

  if (!get_blocks(start_offset, count, blocks))
  {
    return false;
  }

  for(const auto& blk : blocks)
  {
    std::vector<crypto::hash> missed_ids;
    get_transactions_blobs(blk.second.tx_hashes, txs, missed_ids);
    CHECK_AND_ASSERT_MES(!missed_ids.size(), false, "has missed transactions in own block in main blockchain");
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata,block>>& blocks) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  const uint64_t height = m_db->height();
  if(start_offset >= height)
    return false;

  blocks.reserve(blocks.size() + height - start_offset);
  for(size_t i = start_offset; i < start_offset + count && i < height;i++)
  {
    blocks.push_back(std::make_pair(m_db->get_block_blob_from_height(i), block()));
    if (!parse_and_validate_block_from_blob(blocks.back().first, blocks.back().second))
    {
      LOG_ERROR("Invalid block");
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
//TODO: This function *looks* like it won't need to be rewritten
//      to use BlockchainDB, as it calls other functions that were,
//      but it warrants some looking into later.
//
//FIXME: This function appears to want to return false if any transactions
//       that belong with blocks are missing, but not if blocks themselves
//       are missing.
bool Blockchain::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  db_rtxn_guard rtxn_guard (m_db);
  rsp.current_blockchain_height = get_current_blockchain_height();
  std::vector<std::pair<cryptonote::blobdata,block>> blocks;
  get_blocks(arg.blocks, blocks, rsp.missed_ids);

  for (size_t i = 0; i < blocks.size(); ++i)
  {
    auto& bl = blocks[i];
    std::vector<crypto::hash> missed_tx_ids;

    rsp.blocks.push_back(block_complete_entry());
    block_complete_entry& e = rsp.blocks.back();

    // FIXME: s/rsp.missed_ids/missed_tx_id/ ?  Seems like rsp.missed_ids
    //        is for missed blocks, not missed transactions as well.
    e.pruned = arg.prune;
    get_transactions_blobs(bl.second.tx_hashes, e.txs, missed_tx_ids, arg.prune);
    if (missed_tx_ids.size() != 0)
    {
      // do not display an error if the peer asked for an unpruned block which we are not meant to have
      if (tools::has_unpruned_block(get_block_height(bl.second), get_current_blockchain_height(), get_blockchain_pruning_seed()))
      {
        LOG_ERROR("Error retrieving blocks, missed " << missed_tx_ids.size()
            << " transactions for block with hash: " << get_block_hash(bl.second)
            << std::endl
        );
      }

      // append missed transaction hashes to response missed_ids field,
      // as done below if any standalone transactions were requested
      // and missed.
      rsp.missed_ids.insert(rsp.missed_ids.end(), missed_tx_ids.begin(), missed_tx_ids.end());
      return false;
    }

    //pack block
    e.block = std::move(bl.first);
    e.block_weight = 0;
    if (arg.prune && m_db->block_exists(arg.blocks[i]))
      e.block_weight = m_db->get_block_weight(m_db->get_block_height(arg.blocks[i]));
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_alternative_blocks(std::vector<block>& blocks) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  blocks.reserve(m_db->get_alt_block_count());
  m_db->for_all_alt_blocks([&blocks](const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::blobdata_ref *blob) {
    if (!blob)
    {
      MERROR("No blob, but blobs were requested");
      return false;
    }
    cryptonote::block bl;
    if (cryptonote::parse_and_validate_block_from_blob(*blob, bl))
      blocks.push_back(std::move(bl));
    else
      MERROR("Failed to parse block from blob");
    return true;
  }, true);
  return true;
}
//------------------------------------------------------------------
size_t Blockchain::get_alternative_blocks_count() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->get_alt_block_count();
}
//------------------------------------------------------------------
// This function adds the output specified by <amount, i> to the result_outs container
// unlocked and other such checks should be done by here.
uint64_t Blockchain::get_num_mature_outputs(uint64_t amount) const
{
  uint64_t num_outs = m_db->get_num_outputs(amount);
  // ensure we don't include outputs that aren't yet eligible to be used
  // outpouts are sorted by height
  const uint64_t blockchain_height = m_db->height();
  while (num_outs > 0)
  {
    const tx_out_index toi = m_db->get_output_tx_and_index(amount, num_outs - 1);
    const uint64_t height = m_db->get_tx_block_height(toi.first);
    if (height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE <= blockchain_height)
      break;
    --num_outs;
  }

  return num_outs;
}

crypto::public_key Blockchain::get_output_key(uint64_t amount, uint64_t global_index) const
{
  output_data_t data = m_db->get_output_key(amount, global_index);
  return data.pubkey;
}

//------------------------------------------------------------------
bool Blockchain::get_outs(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  res.outs.clear();
  res.outs.reserve(req.outputs.size());

  std::vector<cryptonote::output_data_t> data;
  try
  {
    std::vector<uint64_t> amounts, offsets;
    amounts.reserve(req.outputs.size());
    offsets.reserve(req.outputs.size());
    for (const auto &i: req.outputs)
    {
      amounts.push_back(i.amount);
      offsets.push_back(i.index);
    }
    m_db->get_output_key(epee::span<const uint64_t>(amounts.data(), amounts.size()), offsets, data);
    if (data.size() != req.outputs.size())
    {
      MERROR("Unexpected output data size: expected " << req.outputs.size() << ", got " << data.size());
      return false;
    }
    const uint8_t hf_version = m_hardfork->get_current_version();
    for (const auto &t: data)
      res.outs.push_back({t.pubkey, t.commitment, is_tx_spendtime_unlocked(t.unlock_time, hf_version), t.height, crypto::null_hash});

    if (req.get_txid)
    {
      for (size_t i = 0; i < req.outputs.size(); ++i)
      {
        tx_out_index toi = m_db->get_output_tx_and_index(req.outputs[i].amount, req.outputs[i].index);
        res.outs[i].txid = toi.first;
      }
    }
  }
  catch (const std::exception &e)
  {
    return false;
  }
  return true;
}
//------------------------------------------------------------------
void Blockchain::get_output_key_mask_unlocked(const uint64_t& amount, const uint64_t& index, crypto::public_key& key, rct::key& mask, bool& unlocked) const
{
  const auto o_data = m_db->get_output_key(amount, index);
  key = o_data.pubkey;
  mask = o_data.commitment;
  const uint8_t hf_version = m_hardfork->get_current_version();
  unlocked = is_tx_spendtime_unlocked(o_data.unlock_time, hf_version);
}
//------------------------------------------------------------------
bool Blockchain::get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) const
{
  // rct outputs don't exist before v4
  if (amount == 0 && m_nettype != network_type::FAKECHAIN)
    start_height = m_hardfork->get_earliest_ideal_height_for_version(HF_VERSION_DYNAMIC_FEE);
  else
    start_height = 0;
  base = 0;

  if (to_height > 0 && to_height < from_height)
    return false;

  if (from_height > start_height)
    start_height = from_height;

  distribution.clear();
  uint64_t db_height = m_db->height();
  if (db_height == 0)
    return false;
  if (start_height >= db_height || to_height >= db_height)
    return false;
  if (amount == 0)
  {
    std::vector<uint64_t> heights;
    heights.reserve(to_height + 1 - start_height);
    const uint64_t real_start_height = start_height > 0 ? start_height-1 : start_height;
    for (uint64_t h = real_start_height; h <= to_height; ++h)
      heights.push_back(h);
    distribution = m_db->get_block_cumulative_rct_outputs(heights);
    if (start_height > 0)
    {
      base = distribution[0];
      distribution.erase(distribution.begin());
    }
    return true;
  }
  else
  {
    return m_db->get_output_distribution(amount, start_height, to_height, distribution, base);
  }
}
//------------------------------------------------------------------
// This function takes a list of block hashes from another node
// on the network to find where the split point is between us and them.
// This is used to see what to send another node that needs to sync.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, uint64_t& starter_offset) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // make sure the request includes at least the genesis block, otherwise
  // how can we expect to sync from the client that the block list came from?
  if(qblock_ids.empty())
  {
    MCERROR("net.p2p", "Client sent wrong NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << qblock_ids.size() << ", dropping connection");
    return false;
  }

  db_rtxn_guard rtxn_guard(m_db);
  // make sure that the last block in the request's block list matches
  // the genesis block
  auto gen_hash = m_db->get_block_hash_from_height(0);
  if(qblock_ids.back() != gen_hash)
  {
    MCERROR("net.p2p", "Client sent wrong NOTIFY_REQUEST_CHAIN: genesis block mismatch: " << std::endl << "id: " << qblock_ids.back() << ", " << std::endl << "expected: " << gen_hash << "," << std::endl << " dropping connection");
    return false;
  }

  // Find the first block the foreign chain has that we also have.
  // Assume qblock_ids is in reverse-chronological order.
  auto bl_it = qblock_ids.begin();
  uint64_t split_height = 0;
  for(; bl_it != qblock_ids.end(); bl_it++)
  {
    try
    {
      if (m_db->block_exists(*bl_it, &split_height))
        break;
    }
    catch (const std::exception& e)
    {
      MWARNING("Non-critical error trying to find block by hash in BlockchainDB, hash: " << *bl_it);
      return false;
    }
  }

  // this should be impossible, as we checked that we share the genesis block,
  // but just in case...
  if(bl_it == qblock_ids.end())
  {
    MERROR("Internal error handling connection, can't find split point");
    return false;
  }

  //we start to put block ids INCLUDING last known id, just to make other side be sure
  starter_offset = split_height;
  return true;
}
//------------------------------------------------------------------
difficulty_type Blockchain::block_difficulty(uint64_t i) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_difficulty(i);
  }
  catch (const BLOCK_DNE& e)
  {
    MERROR("Attempted to get block difficulty for height above blockchain height");
  }
  return 0;
}
//------------------------------------------------------------------
template<typename T> void reserve_container(std::vector<T> &v, size_t N) { v.reserve(N); }
template<typename T> void reserve_container(std::list<T> &v, size_t N) { }
//------------------------------------------------------------------
//TODO: return type should be void, throw on exception
//       alternatively, return true only if no blocks missed
template<class t_ids_container, class t_blocks_container, class t_missed_container>
bool Blockchain::get_blocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  reserve_container(blocks, block_ids.size());
  for (const auto& block_hash : block_ids)
  {
    try
    {
      uint64_t height = 0;
      if (m_db->block_exists(block_hash, &height))
      {
        blocks.push_back(std::make_pair(m_db->get_block_blob_from_height(height), block()));
        if (!parse_and_validate_block_from_blob(blocks.back().first, blocks.back().second))
        {
          LOG_ERROR("Invalid block: " << block_hash);
          blocks.pop_back();
          missed_bs.push_back(block_hash);
        }
      }
      else
        missed_bs.push_back(block_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
static bool fill(BlockchainDB *db, const crypto::hash &tx_hash, cryptonote::blobdata &tx, bool pruned)
{
  if (pruned)
  {
    if (!db->get_pruned_tx_blob(tx_hash, tx))
    {
      MDEBUG("Pruned transaction blob not found for " << tx_hash);
      return false;
    }
  }
  else
  {
    if (!db->get_tx_blob(tx_hash, tx))
    {
      MDEBUG("Transaction blob not found for " << tx_hash);
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
static bool fill(BlockchainDB *db, const crypto::hash &tx_hash, tx_blob_entry &tx, bool pruned)
{
  if (!fill(db, tx_hash, tx.blob, pruned))
    return false;
  if (pruned)
  {
    if (is_v1_tx(tx.blob))
    {
      // v1 txes aren't pruned, so fetch the whole thing
      cryptonote::blobdata prunable_blob;
      if (!db->get_prunable_tx_blob(tx_hash, prunable_blob))
      {
        MDEBUG("Prunable transaction blob not found for " << tx_hash);
        return false;
      }
      tx.blob.append(prunable_blob);
      tx.prunable_hash = crypto::null_hash;
    }
    else
    {
      if (!db->get_prunable_tx_hash(tx_hash, tx.prunable_hash))
      {
        MDEBUG("Prunable transaction data hash not found for " << tx_hash);
        return false;
      }
    }
  }
  return true;
}
//------------------------------------------------------------------
//TODO: return type should be void, throw on exception
//       alternatively, return true only if no transactions missed
bool Blockchain::get_transactions_blobs(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed_txs, bool pruned) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  txs.reserve(txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      cryptonote::blobdata tx;
      if (fill(m_db, tx_hash, tx, pruned))
        txs.push_back(std::move(tx));
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_transactions_blobs(const std::vector<crypto::hash>& txs_ids, std::vector<tx_blob_entry>& txs, std::vector<crypto::hash>& missed_txs, bool pruned) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  txs.reserve(txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      tx_blob_entry tx;
      if (fill(m_db, tx_hash, tx, pruned))
        txs.push_back(std::move(tx));
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
size_t get_transaction_version(const cryptonote::blobdata &bd)
{
  size_t version;
  const char* begin = static_cast<const char*>(bd.data());
  const char* end = begin + bd.size();
  int read = tools::read_varint(begin, end, version);
  if (read <= 0)
    throw std::runtime_error("Internal error getting transaction version");
  return version;
}
//------------------------------------------------------------------
template<class t_ids_container, class t_tx_container, class t_missed_container>
bool Blockchain::get_split_transactions_blobs(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  reserve_container(txs, txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      cryptonote::blobdata tx;
      if (m_db->get_pruned_tx_blob(tx_hash, tx))
      {
        txs.push_back(std::make_tuple(tx_hash, std::move(tx), crypto::null_hash, cryptonote::blobdata()));
        if (!is_v1_tx(std::get<1>(txs.back())) && !m_db->get_prunable_tx_hash(tx_hash, std::get<2>(txs.back())))
        {
          MERROR("Prunable data hash not found for " << tx_hash);
          return false;
        }
        if (!m_db->get_prunable_tx_blob(tx_hash, std::get<3>(txs.back())))
          std::get<3>(txs.back()).clear();
      }
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
template<class t_ids_container, class t_tx_container, class t_missed_container>
bool Blockchain::get_transactions(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs, bool pruned) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  reserve_container(txs, txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      cryptonote::blobdata tx;
      bool res = pruned ? m_db->get_pruned_tx_blob(tx_hash, tx) : m_db->get_tx_blob(tx_hash, tx);
      if (res)
      {
        txs.push_back(transaction());
        res = pruned ? parse_and_validate_tx_base_from_blob(tx, txs.back()) : parse_and_validate_tx_from_blob(tx, txs.back());
        if (!res)
        {
          LOG_ERROR("Invalid transaction");
          return false;
        }
      }
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
// Find the split point between us and foreign blockchain and return
// (by reference) the most recent common block hash along with up to
// BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT additional (more recent) hashes.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, std::vector<crypto::hash>& hashes, std::vector<uint64_t>* weights, uint64_t& start_height, uint64_t& current_height, bool clip_pruned) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if we can't find the split point, return false
  if(!find_blockchain_supplement(qblock_ids, start_height))
  {
    return false;
  }

  db_rtxn_guard rtxn_guard(m_db);
  current_height = get_current_blockchain_height();
  uint64_t stop_height = current_height;
  if (clip_pruned)
  {
    const uint32_t pruning_seed = get_blockchain_pruning_seed();
    if (start_height < tools::get_next_unpruned_block_height(start_height, current_height, pruning_seed))
    {
      MDEBUG("We only have a pruned version of the common ancestor");
      return false;
    }
    stop_height = tools::get_next_pruned_block_height(start_height, current_height, pruning_seed);
  }
  size_t count = 0;
  const size_t reserve = std::min((size_t)(stop_height - start_height), (size_t)BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT);
  hashes.reserve(reserve);
  if (weights)
    weights->reserve(reserve);
  for(size_t i = start_height; i < stop_height && count < BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT; i++, count++)
  {
    hashes.push_back(m_db->get_block_hash_from_height(i));
    if (weights)
      weights->push_back(m_db->get_block_weight(i));
  }

  return true;
}

bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, bool clip_pruned, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  bool result = find_blockchain_supplement(qblock_ids, resp.m_block_ids, &resp.m_block_weights, resp.start_height, resp.total_height, clip_pruned);
  if (result)
  {
    cryptonote::difficulty_type wide_cumulative_difficulty = m_db->get_block_cumulative_difficulty(resp.total_height - 1);
    resp.cumulative_difficulty = (wide_cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
    resp.cumulative_difficulty_top64 = ((wide_cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  }

  return result;
}
//------------------------------------------------------------------
//FIXME: change argument to std::vector, low priority
// find split point between ours and foreign blockchain (or start at
// blockchain height <req_start_block>), and return up to max_count FULL
// blocks by reference.
bool Blockchain::find_blockchain_supplement(const uint64_t req_start_block, const std::list<crypto::hash>& qblock_ids, std::vector<std::pair<std::pair<cryptonote::blobdata, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::blobdata> > > >& blocks, uint64_t& total_height, uint64_t& start_height, bool pruned, bool get_miner_tx_hash, size_t max_block_count, size_t max_tx_count) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if a specific start height has been requested
  if(req_start_block > 0)
  {
    // if requested height is higher than our chain, return false -- we can't help
    if (req_start_block >= m_db->height())
    {
      return false;
    }
    start_height = req_start_block;
  }
  else
  {
    if(!find_blockchain_supplement(qblock_ids, start_height))
    {
      return false;
    }
  }

  db_rtxn_guard rtxn_guard(m_db);
  total_height = get_current_blockchain_height();
  blocks.reserve(std::min(std::min(max_block_count, (size_t)10000), (size_t)(total_height - start_height)));
  CHECK_AND_ASSERT_MES(m_db->get_blocks_from(start_height, 3, max_block_count, max_tx_count, FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE, blocks, pruned, true, get_miner_tx_hash),
      false, "Error getting blocks");

  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block& bl, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  block_extended_info bei = AUTO_VAL_INIT(bei);
  bei.bl = bl;
  return add_block_as_invalid(bei, h);
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block_extended_info& bei, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto i_res = m_invalid_blocks.insert(std::map<crypto::hash, block_extended_info>::value_type(h, bei));
  CHECK_AND_ASSERT_MES(i_res.second, false, "at insertion invalid by tx returned status existed");
  MINFO("BLOCK ADDED AS INVALID: " << h << std::endl << ", prev_id=" << bei.bl.prev_id << ", m_invalid_blocks count=" << m_invalid_blocks.size());
  return true;
}
//------------------------------------------------------------------
void Blockchain::flush_invalid_blocks()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_invalid_blocks.clear();
}
//------------------------------------------------------------------
bool Blockchain::have_block_unlocked(const crypto::hash& id, int *where) const
{
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  LOG_PRINT_L3("Blockchain::" << __func__);

  if(m_db->block_exists(id))
  {
    LOG_PRINT_L2("block " << id << " found in main chain");
    if (where) *where = HAVE_BLOCK_MAIN_CHAIN;
    return true;
  }

  if(m_db->get_alt_block(id, NULL, NULL))
  {
    LOG_PRINT_L2("block " << id << " found in alternative chains");
    if (where) *where = HAVE_BLOCK_ALT_CHAIN;
    return true;
  }

  if(m_invalid_blocks.count(id))
  {
    LOG_PRINT_L2("block " << id << " found in m_invalid_blocks");
    if (where) *where = HAVE_BLOCK_INVALID;
    return true;
  }

  return false;
}
//------------------------------------------------------------------
bool Blockchain::have_block(const crypto::hash& id, int *where) const
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return have_block_unlocked(id, where);
}
//------------------------------------------------------------------
bool Blockchain::handle_block_to_main_chain(const block& bl, block_verification_context& bvc)
{
    LOG_PRINT_L3("Blockchain::" << __func__);
    crypto::hash id = get_block_hash(bl);
    pool_supplement ps{};
    return handle_block_to_main_chain(bl, id, bvc, ps);
}
//------------------------------------------------------------------
size_t Blockchain::get_total_transactions() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->get_tx_count();
}
//------------------------------------------------------------------
// This function checks each input in the transaction <tx> to make sure it
// has not been used already, and adds its key to the container <keys_this_block>.
//
// This container should be managed by the code that validates blocks so we don't
// have to store the used keys in a given block in the permanent storage only to
// remove them later if the block fails validation.
bool Blockchain::check_for_double_spend(const transaction& tx, key_images_container& keys_this_block) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  struct add_transaction_input_visitor: public boost::static_visitor<bool>
  {
    key_images_container& m_spent_keys;
    BlockchainDB* m_db;
    add_transaction_input_visitor(key_images_container& spent_keys, BlockchainDB* db) :
      m_spent_keys(spent_keys), m_db(db)
    {
    }
    bool operator()(const txin_to_key& in) const
    {
      const crypto::key_image& ki = in.k_image;

      // attempt to insert the newly-spent key into the container of
      // keys spent this block.  If this fails, the key was spent already
      // in this block, return false to flag that a double spend was detected.
      //
      // if the insert into the block-wide spent keys container succeeds,
      // check the blockchain-wide spent keys container and make sure the
      // key wasn't used in another block already.
      auto r = m_spent_keys.insert(ki);
      if(!r.second || m_db->has_key_image(ki))
      {
        //double spend detected
        return false;
      }

      // if no double-spend detected, return true
      return true;
    }

    bool operator()(const txin_gen& tx) const
    {
      return true;
    }
    bool operator()(const txin_to_script& tx) const
    {
      return false;
    }
    bool operator()(const txin_to_scripthash& tx) const
    {
      return false;
    }
    // PBC: virtual input — no key image, no ring. Accepted here; full validation in check_tx_inputs.
    bool operator()(const txin_pbc_withdraw& tx) const
    {
      return true;
    }
  };

  for (const txin_v& in : tx.vin)
  {
    if(!boost::apply_visitor(add_transaction_input_visitor(keys_this_block, m_db), in))
    {
      LOG_ERROR("Double spend detected!");
      return false;
    }
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_id, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t tx_index;
  if (!m_db->tx_exists(tx_id, tx_index))
  {
    MERROR_VER("get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }
  indexs = m_db->get_tx_amount_output_indices(tx_index, n_txes);
  CHECK_AND_ASSERT_MES(n_txes == indexs.size(), false, "Wrong indexs size");

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t tx_index;
  if (!m_db->tx_exists(tx_id, tx_index))
  {
    MERROR_VER("get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }
  std::vector<std::vector<uint64_t>> indices = m_db->get_tx_amount_output_indices(tx_index, 1);
  CHECK_AND_ASSERT_MES(indices.size() == 1, false, "Wrong indices size");
  indexs = indices.front();
  return true;
}
//------------------------------------------------------------------
//FIXME: it seems this function is meant to be merely a wrapper around
//       another function of the same name, this one adding one bit of
//       functionality.  Should probably move anything more than that
//       (getting the hash of the block at height max_used_block_id)
//       to the other function to keep everything in one place.
// This function overloads its sister function with
// an extra value (hash of highest block that holds an output used as input)
// as a return-by-reference.
bool Blockchain::check_tx_inputs(transaction& tx, uint64_t& max_used_block_height, crypto::hash& max_used_block_id, tx_verification_context &tvc, bool kept_by_block) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

#if defined(PER_BLOCK_CHECKPOINT)
  // check if we're doing per-block checkpointing
  if (m_db->height() < m_blocks_hash_check.size() && kept_by_block)
  {
    max_used_block_id = null_hash;
    max_used_block_height = 0;
    return true;
  }
#endif

  TIME_MEASURE_START(a);
  bool res = check_tx_inputs(tx, tvc, &max_used_block_height);
  TIME_MEASURE_FINISH(a);
  if(m_show_time_stats)
  {
    size_t ring_size = !tx.vin.empty() && tx.vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(tx.vin[0]).key_offsets.size() : 0;
    MINFO("HASH: " <<  get_transaction_hash(tx) << " I/M/O: " << tx.vin.size() << "/" << ring_size << "/" << tx.vout.size() << " H: " << max_used_block_height << " ms: " << a + m_fake_scan_time << " B: " << get_object_blobsize(tx) << " W: " << get_transaction_weight(tx));
  }
  if (!res)
    return false;

  CHECK_AND_ASSERT_MES(max_used_block_height < m_db->height(), false,  "internal error: max used block index=" << max_used_block_height << " is not less then blockchain size = " << m_db->height());
  max_used_block_id = m_db->get_block_hash_from_height(max_used_block_height);
  return true;
}
//------------------------------------------------------------------
bool Blockchain::check_tx_outputs(const transaction& tx, tx_verification_context &tvc, std::uint8_t hf_version)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  LOG_PRINT_L0("PBC_LOG check_tx_outputs ENTER tx=" << get_transaction_hash(tx)
    << " hf=" << (int)hf_version << " rct_type=" << (int)tx.rct_signatures.type
    << " vin=" << tx.vin.size() << " vout=" << tx.vout.size());

  // from hard fork 2, we forbid dust and compound outputs
  if (hf_version >= 2) {
    for (auto &o: tx.vout) {
      if (tx.version == 1)
      {
        if (!is_valid_decomposed_amount(o.amount)) {
          LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: invalid_decomposed_amount tx=" << get_transaction_hash(tx));
          tvc.m_invalid_output = true;
          return false;
        }
      }
    }
  }

  // in a v2 tx, all outputs must have 0 amount
  // Exception: pbc_withdraw TXs are RCTTypeNull with explicit (non-zero) amounts, like coinbase.
  if (hf_version >= 3) {
    const bool is_pbc_withdraw = tx.vin.size() == 1 &&
                                 tx.vin[0].type() == typeid(txin_pbc_withdraw);
    if (tx.version >= 2 && !is_pbc_withdraw) {
      for (auto &o: tx.vout) {
        if (o.amount != 0) {
          LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: nonzero_amount_v2 tx=" << get_transaction_hash(tx) << " amount=" << o.amount);
          tvc.m_invalid_output = true;
          return false;
        }
      }
    }
  }

  // from v8, allow bulletproofs
  if (hf_version < 8) {
    if (tx.version >= 2) {
      const bool bulletproof = rct::is_rct_bulletproof(tx.rct_signatures.type);
      if (bulletproof || !tx.rct_signatures.p.bulletproofs.empty())
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: bulletproofs_before_v8 tx=" << get_transaction_hash(tx));
        MERROR_VER("Bulletproofs are not allowed before v8");
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // from v9, forbid borromean range proofs
  if (hf_version > 8) {
    if (tx.version >= 2) {
      const bool borromean = rct::is_rct_borromean(tx.rct_signatures.type);
      if (borromean)
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: borromean_after_v8 tx=" << get_transaction_hash(tx));
        MERROR_VER("Borromean range proofs are not allowed after v8");
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // from v13, allow bulletproofs v2
  if (hf_version < HF_VERSION_SMALLER_BP) {
    if (tx.version >= 2) {
      if (tx.rct_signatures.type == rct::RCTTypeBulletproof2)
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: rct_bulletproof2_before tx=" << get_transaction_hash(tx));
        MERROR_VER("Ringct type " << (unsigned)rct::RCTTypeBulletproof2 << " is not allowed before v" << HF_VERSION_SMALLER_BP);
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // from v14, allow only bulletproofs v2
  if (hf_version > HF_VERSION_SMALLER_BP) {
    if (tx.version >= 2) {
      if (tx.rct_signatures.type == rct::RCTTypeBulletproof)
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: rct_bulletproof_after tx=" << get_transaction_hash(tx));
        MERROR_VER("Ringct type " << (unsigned)rct::RCTTypeBulletproof << " is not allowed from v" << (HF_VERSION_SMALLER_BP + 1));
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // from v16, allow CLSAGs
  if (hf_version < HF_VERSION_CLSAG) {
    if (tx.version >= 2) {
      if (tx.rct_signatures.type == rct::RCTTypeCLSAG)
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: clsag_before_v16 tx=" << get_transaction_hash(tx));
        MERROR_VER("Ringct type " << (unsigned)rct::RCTTypeCLSAG << " is not allowed before v" << HF_VERSION_CLSAG);
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // from v17, allow only CLSAGs
  // Exception: pbc_withdraw uses RCTTypeNull (no ring, coinbase-like) — exempt from ring-scheme HF gate.
  if (hf_version > HF_VERSION_CLSAG) {
    const bool is_pbc_withdraw = tx.vin.size() == 1 &&
                                 tx.vin[0].type() == typeid(txin_pbc_withdraw);
    if (tx.version >= 2 && !is_pbc_withdraw) {
      if (tx.rct_signatures.type <= rct::RCTTypeBulletproof2)
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: rct_type_too_old_after_clsag tx=" << get_transaction_hash(tx) << " rct_type=" << (int)tx.rct_signatures.type);
        MERROR_VER("Ringct type " << (unsigned)tx.rct_signatures.type << " is not allowed from v" << (HF_VERSION_CLSAG + 1));
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }


  // from v12, forbid old bulletproofs
  if (hf_version > 11) {
    if (tx.version >= 2) {
      const bool old_bulletproof = rct::is_rct_old_bulletproof(tx.rct_signatures.type);
      if (old_bulletproof)
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: old_bulletproofs_after_v11 tx=" << get_transaction_hash(tx));
        MERROR_VER("Old Bulletproofs are not allowed after v11");
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // from v18, allow bulletproofs plus
  if (hf_version < HF_VERSION_BULLETPROOF_PLUS) {
    if (tx.version >= 2) {
      const bool bulletproof_plus_legacy = rct::is_rct_bp_plus_legacy(tx.rct_signatures.type);
      if (bulletproof_plus_legacy || !tx.rct_signatures.p.bulletproofs_plus.empty())
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: bp_plus_before tx=" << get_transaction_hash(tx));
        MERROR_VER("Bulletproofs plus are not allowed before v" << std::to_string(HF_VERSION_BULLETPROOF_PLUS));
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // from v19, forbid bulletproofs
  if (hf_version > HF_VERSION_BULLETPROOF_PLUS) {
    if (tx.version >= 2) {
      const bool bulletproof = rct::is_rct_bulletproof(tx.rct_signatures.type);
      if (bulletproof)
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: bp_after_bp_plus tx=" << get_transaction_hash(tx));
        MERROR_VER("Bulletproof range proofs are not allowed after v" + std::to_string(HF_VERSION_BULLETPROOF_PLUS));
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // from v20, require view tags on outputs
  if (!check_output_types(tx, hf_version))
  {
    LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: check_output_types tx=" << get_transaction_hash(tx));
    tvc.m_invalid_output = true;
    return false;
  }

  // from v21, allow bulletproofs plus full commit
  if (hf_version < HF_VERSION_BP_PLUS_FULL_COMMIT) {
    if (tx.version >= 2) {
      const bool bulletproof_plus_full_commit = rct::is_rct_bp_plus_full(tx.rct_signatures.type);
      if (bulletproof_plus_full_commit)
      {
        LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: bp_plus_full_before tx=" << get_transaction_hash(tx));
        MERROR_VER("Bulletproofs plus full commit are not allowed before v" << std::to_string(HF_VERSION_BP_PLUS_FULL_COMMIT));
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // from v22, forbid bulletproof plus legacy
  if (hf_version > HF_VERSION_BP_PLUS_FULL_COMMIT && rct::is_rct_bp_plus_legacy(tx.rct_signatures.type)) {
    LOG_PRINT_L0("PBC_LOG check_tx_outputs REJECT: bp_plus_legacy_after tx=" << get_transaction_hash(tx));
    MERROR_VER("Bulletproof Plus legacy range proofs are not allowed after v" << (HF_VERSION_BP_PLUS_FULL_COMMIT + 1));
    tvc.m_invalid_output = true;
    return false;
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimges_as_spent(const transaction &tx) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  for (const txin_v& in: tx.vin)
  {
    CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, in_to_key, true);
    if(have_tx_keyimg_as_spent(in_to_key.k_image))
      return true;
  }
  return false;
}
bool Blockchain::expand_transaction_2(transaction &tx, const crypto::hash &tx_prefix_hash, const std::vector<std::vector<rct::ctkey>> &pubkeys)
{
  PERF_TIMER(expand_transaction_2);
  CHECK_AND_ASSERT_MES(tx.version == 2, false, "Transaction version is not 2");

  rct::rctSig &rv = tx.rct_signatures;

  // message - hash of the transaction prefix
  rv.message = rct::hash2rct(tx_prefix_hash);

  // mixRing - full and simple store it in opposite ways
  if (rv.type == rct::RCTTypeFull || rv.type == rct::RCTTypeFullBulletproof)
  {
    CHECK_AND_ASSERT_MES(!pubkeys.empty() && !pubkeys[0].empty(), false, "empty pubkeys");
    rv.mixRing.resize(pubkeys[0].size());
    for (size_t m = 0; m < pubkeys[0].size(); ++m)
      rv.mixRing[m].clear();
    for (size_t n = 0; n < pubkeys.size(); ++n)
    {
      CHECK_AND_ASSERT_MES(pubkeys[n].size() <= pubkeys[0].size(), false, "More inputs that first ring");
      for (size_t m = 0; m < pubkeys[n].size(); ++m)
      {
        rv.mixRing[m].push_back(pubkeys[n][m]);
      }
    }
  }
  else if (rv.type == rct::RCTTypeSimple || rv.type == rct::RCTTypeBulletproof || rv.type == rct::RCTTypeBulletproof2 || rv.type == rct::RCTTypeSimpleBulletproof || rv.type == rct::RCTTypeCLSAG || rv.type == rct::RCTTypeBulletproofPlus || rv.type == rct::RCTTypeBulletproofPlus_FullCommit)
  {
    CHECK_AND_ASSERT_MES(!pubkeys.empty() && !pubkeys[0].empty(), false, "empty pubkeys");
    rv.mixRing.resize(pubkeys.size());
    for (size_t n = 0; n < pubkeys.size(); ++n)
    {
      rv.mixRing[n].clear();
      for (size_t m = 0; m < pubkeys[n].size(); ++m)
      {
        rv.mixRing[n].push_back(pubkeys[n][m]);
      }
    }
  }
  else
  {
    CHECK_AND_ASSERT_MES(false, false, "Unsupported rct tx type: " + boost::lexical_cast<std::string>(rv.type));
  }

  // II
  if (rv.type == rct::RCTTypeFull || rv.type == rct::RCTTypeFullBulletproof)
  {
    if (!tx.pruned)
    {
      rv.p.MGs.resize(1);
      rv.p.MGs[0].II.resize(tx.vin.size());
      for (size_t n = 0; n < tx.vin.size(); ++n)
        rv.p.MGs[0].II[n] = rct::ki2rct(boost::get<txin_to_key>(tx.vin[n]).k_image);
    }
  }
  else if (rv.type == rct::RCTTypeSimple || rv.type == rct::RCTTypeBulletproof || rv.type == rct::RCTTypeBulletproof2 || rv.type == rct::RCTTypeSimpleBulletproof)
  {
    if (!tx.pruned)
    {
      CHECK_AND_ASSERT_MES(rv.p.MGs.size() == tx.vin.size(), false, "Bad MGs size");
      for (size_t n = 0; n < tx.vin.size(); ++n)
      {
        rv.p.MGs[n].II.resize(1);
        rv.p.MGs[n].II[0] = rct::ki2rct(boost::get<txin_to_key>(tx.vin[n]).k_image);
      }
    }
  }
  else if (rv.type == rct::RCTTypeCLSAG || rv.type == rct::RCTTypeBulletproofPlus || rv.type == rct::RCTTypeBulletproofPlus_FullCommit)
  {
    if (!tx.pruned)
    {
      CHECK_AND_ASSERT_MES(rv.p.CLSAGs.size() == tx.vin.size(), false, "Bad CLSAGs size");
      for (size_t n = 0; n < tx.vin.size(); ++n)
      {
        rv.p.CLSAGs[n].I = rct::ki2rct(boost::get<txin_to_key>(tx.vin[n]).k_image);
      }
    }
  }
  else
  {
    CHECK_AND_ASSERT_MES(false, false, "Unsupported rct tx type: " + boost::lexical_cast<std::string>(rv.type));
  }

  // outPk was already done by handle_incoming_tx

  return true;
}
//------------------------------------------------------------------
// This function validates transaction inputs and their keys.
// FIXME: consider moving functionality specific to one input into
//        check_tx_input() rather than here, and use this function simply
//        to iterate the inputs as necessary (splitting the task
//        using threads, etc.)
bool Blockchain::check_tx_inputs(transaction& tx, tx_verification_context &tvc, uint64_t* pmax_used_block_height) const
{
  PERF_TIMER(check_tx_inputs);
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t sig_index = 0;
  if(pmax_used_block_height)
    *pmax_used_block_height = 0;

  crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

  const uint8_t hf_version = m_hardfork->get_current_version();

  // ─────────────────────────────────────────────────────────────────────────
  // A3 GATE (ferme F3) — partagé mempool + validation de bloc.
  // Un balayage marqué INHERIT_SWEEP n'est accepté qu'APRÈS l'exécution de
  // l'héritage du principal concerné (executed[P]=B posé dans add_block), et
  // seulement dans la fenêtre [B, B+PBC_INHERIT_EXEC_WINDOW_BLOCKS].
  //   • avant exécution -> executed[P] absent -> REJET (diffusion prématurée bloquée)
  //   • hors fenêtre    -> REJET
  // Les balayages que l'exécution elle-même diffuse passent : executed[P]=B est
  // écrit (Pass 2) avant l'add_tx (Pass 3), et ils sont minés dans la fenêtre.
  // Actif uniquement à partir du hard fork dédié.
  // ─────────────────────────────────────────────────────────────────────────
  if (hf_version >= HF_VERSION_PBC_INHERIT_GATE)
  {
    tx_extra_pbc_tx_type ttype_gate{};
    if (get_tx_extra_field_by_type(tx.extra, ttype_gate) &&
        ttype_gate.type == PBC_TX_TYPE_INHERIT_SWEEP)
    {
      tx_extra_pbc_inherit_sweep swp_gate{};
      if (!get_tx_extra_field_by_type(tx.extra, swp_gate))
      {
        MERROR_VER("PBC INHERIT GATE: balayage marqué sans champ principal, tx="
          << get_transaction_hash(tx));
        tvc.m_verifivation_failed = true;
        return false;
      }
      uint64_t exec_h = 0;
      const bool executed =
        m_db->get_property_uint64(pbc_inh_exec_key(swp_gate.principal_spend_pubkey), exec_h)
        && exec_h != 0;
      if (!executed)
      {
        MERROR_VER("PBC INHERIT GATE: balayage prématuré (héritage non exécuté) principal="
          << swp_gate.principal_spend_pubkey << " tx=" << get_transaction_hash(tx));
        tvc.m_verifivation_failed = true;
        return false;
      }
      const uint64_t cur_h = m_db->height();
      if (cur_h < exec_h || cur_h > exec_h + PBC_INHERIT_EXEC_WINDOW_BLOCKS)
      {
        MERROR_VER("PBC INHERIT GATE: balayage hors fenêtre cur=" << cur_h
          << " exec=" << exec_h << " window=" << PBC_INHERIT_EXEC_WINDOW_BLOCKS
          << " principal=" << swp_gate.principal_spend_pubkey
          << " tx=" << get_transaction_hash(tx));
        tvc.m_verifivation_failed = true;
        return false;
      }
      // OK : balayage légitime post-exécution -> on poursuit la validation normale des inputs.
    }
  }

  if (hf_version >= HF_VERSION_MIN_2_OUTPUTS)
  {
    if (tx.version >= 2)
    {
      // pbc_withdraw legitimately has 1 output (payout to owner) — exempt from min-2 rule.
      const bool is_pbc_withdraw_chk = tx.vin.size() == 1 &&
                                       tx.vin[0].type() == typeid(txin_pbc_withdraw);
      if (!is_pbc_withdraw_chk && tx.vout.size() < 2)
      {
        MERROR_VER("Tx " << get_transaction_hash(tx) << " has fewer than two outputs");
        tvc.m_too_few_outputs = true;
        return false;
      }
    }
  }

  // PBC: txin_pbc_withdraw has no UTXO ring inputs — skip mixin/ring checks entirely.
  // Full consensus validation is done in the dedicated E2 block below.
  const bool is_pbc_withdraw_tx_ci = tx.vin.size() == 1 &&
                                     tx.vin[0].type() == typeid(txin_pbc_withdraw);

  // from hard fork 2, we require mixin at least 2 unless one output cannot mix with 2 others
  // if one output cannot mix with 2 others, we accept at most 1 output that can mix
  if (hf_version >= 2 && !is_pbc_withdraw_tx_ci)
  {
    size_t n_unmixable = 0, n_mixable = 0;
    size_t min_actual_mixin = std::numeric_limits<size_t>::max();
    size_t max_actual_mixin = 0;
    const size_t min_mixin = hf_version >= HF_VERSION_MIN_MIXIN_21 ? 21 : 7;
    for (const auto& txin : tx.vin)
    {
      // non txin_to_key inputs will be rejected below
      if (txin.type() == typeid(txin_to_key))
      {
        const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);
        if (in_to_key.amount == 0)
        {
          // always consider rct inputs mixable. Even if there's not enough rct
          // inputs on the chain to mix with, this is going to be the case for
          // just a few blocks right after the fork at most
          ++n_mixable;
        }
        else
        {
          uint64_t n_outputs = m_db->get_num_outputs(in_to_key.amount);
          MDEBUG("output size " << print_money(in_to_key.amount) << ": " << n_outputs << " available");
          // n_outputs includes the output we're considering
          if (n_outputs <= min_mixin)
            ++n_unmixable;
          else
            ++n_mixable;
        }
        size_t ring_mixin = in_to_key.key_offsets.size() - 1;
        if (ring_mixin < min_actual_mixin)
          min_actual_mixin = ring_mixin;
        if (ring_mixin > max_actual_mixin)
          max_actual_mixin = ring_mixin;
      }
    }
    MDEBUG("Mixin: " << min_actual_mixin << "-" << max_actual_mixin);

    if (hf_version >= HF_VERSION_SAME_MIXIN)
    {
      if (min_actual_mixin != max_actual_mixin)
      {
        MERROR_VER("Tx " << get_transaction_hash(tx) << " has varying ring size (" << (min_actual_mixin + 1) << "-" << (max_actual_mixin + 1) << "), it should be constant");
        tvc.m_low_mixin = true;
        return false;
      }
    }

    // The only circumstance where ring sizes less than expected are
    // allowed is when spending unmixable non-RCT outputs in the chain.
    // Caveat: at HF_VERSION_MIN_MIXIN_15, temporarily allow ring sizes
    // of 11 to allow a grace period in the transition to larger ring size.
    if (min_actual_mixin < min_mixin && !(hf_version == HF_VERSION_MIN_MIXIN_21 && min_actual_mixin == 7))
    {
      if (n_unmixable == 0)
      {
        MERROR_VER("Tx " << get_transaction_hash(tx) << " has too low ring size (" << (min_actual_mixin + 1) << "), and no unmixable inputs");
        tvc.m_low_mixin = true;
        return false;
      }
      if (n_mixable > 1)
      {
        MERROR_VER("Tx " << get_transaction_hash(tx) << " has too low ring size (" << (min_actual_mixin + 1) << "), and more than one mixable input with unmixable inputs");
        tvc.m_low_mixin = true;
        return false;
      }
    } else if ((hf_version > HF_VERSION_MIN_MIXIN_21 && min_actual_mixin > 21)
      || (hf_version == HF_VERSION_MIN_MIXIN_21 && min_actual_mixin != 21 && min_actual_mixin != 7) // grace period to allow either 15 or 10
      || (hf_version < HF_VERSION_MIN_MIXIN_21 && hf_version >= HF_VERSION_MIN_MIXIN_7+2 && min_actual_mixin > 7)
      || ((hf_version == HF_VERSION_MIN_MIXIN_7 || hf_version == HF_VERSION_MIN_MIXIN_7+1) && min_actual_mixin != 7)
    )
    {
      MERROR_VER("Tx " << get_transaction_hash(tx) << " has invalid ring size (" << (min_actual_mixin + 1) << "), it should be " << (min_mixin + 1));
      tvc.m_low_mixin = true;
      return false;
    }

    // min/max tx version based on HF, and we accept v1 txes if having a non mixable
    const size_t max_tx_version = (hf_version <= 3) ? 1 : 2;
    if (tx.version > max_tx_version)
    {
      MERROR_VER("transaction version " << (unsigned)tx.version << " is higher than max accepted version " << max_tx_version);
      tvc.m_verifivation_failed = true;
      return false;
    }
    const size_t min_tx_version = (n_unmixable > 0 ? 1 : (hf_version >= HF_VERSION_ENFORCE_RCT) ? 2 : 1);
    if (tx.version < min_tx_version)
    {
      MERROR_VER("transaction version " << (unsigned)tx.version << " is lower than min accepted version " << min_tx_version);
      tvc.m_verifivation_failed = true;
      return false;
    }
  }

  // from v7, sorted ins
  if (hf_version >= 7) {
    const crypto::key_image *last_key_image = NULL;
    for (size_t n = 0; n < tx.vin.size(); ++n)
    {
      const txin_v &txin = tx.vin[n];
      if (txin.type() == typeid(txin_to_key))
      {
        const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);
        if (last_key_image && memcmp(&in_to_key.k_image, last_key_image, sizeof(*last_key_image)) >= 0)
        {
          MERROR_VER("transaction has unsorted inputs");
          tvc.m_verifivation_failed = true;
          return false;
        }
        last_key_image = &in_to_key.k_image;
      }
    }
  }

  std::vector<std::vector<rct::ctkey>> pubkeys(tx.vin.size());
  std::vector < uint64_t > results;
  results.resize(tx.vin.size(), 0);

  tools::threadpool& tpool = tools::threadpool::getInstanceForCompute();
  tools::threadpool::waiter waiter(tpool);
  int threads = tpool.get_max_concurrency();

  uint64_t max_used_block_height = 0;
  if (!pmax_used_block_height)
    pmax_used_block_height = &max_used_block_height;
  for (const auto& txin : tx.vin)
  {
    // make sure output being spent is of type txin_to_key, rather than
    // e.g. txin_gen, which is only used for miner transactions.
    // Exception: txin_pbc_withdraw is a virtual PBC input — validated separately below.
    if (txin.type() == typeid(txin_pbc_withdraw))
    {
      // Full validation is done in the dedicated block below (E2).
      continue;
    }
    CHECK_AND_ASSERT_MES(txin.type() == typeid(txin_to_key), false, "wrong type id in tx input at Blockchain::check_tx_inputs");
    const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);

    // make sure tx output has key offset(s) (is signed to be used)
    CHECK_AND_ASSERT_MES(in_to_key.key_offsets.size(), false, "empty in_to_key.key_offsets in transaction with id " << get_transaction_hash(tx));

    if(have_tx_keyimg_as_spent(in_to_key.k_image))
    {
      MERROR_VER("Key image already spent in blockchain: " << epee::string_tools::pod_to_hex(in_to_key.k_image));
      tvc.m_double_spend = true;
      return false;
    }

    if (tx.version == 1)
    {
      // basically, make sure number of inputs == number of signatures
      CHECK_AND_ASSERT_MES(sig_index < tx.signatures.size(), false, "wrong transaction: not signature entry for input with index= " << sig_index);
    }

    // make sure that output being spent matches up correctly with the
    // signature spending it.
    if (!check_tx_input(tx.version, in_to_key, tx_prefix_hash, tx.version == 1 ? tx.signatures[sig_index] : std::vector<crypto::signature>(), tx.rct_signatures, pubkeys[sig_index], pmax_used_block_height, hf_version))
    {
      MERROR_VER("Failed to check ring signature for tx " << get_transaction_hash(tx) << "  vin key with k_image: " << in_to_key.k_image << "  sig_index: " << sig_index);
      if (pmax_used_block_height) // a default value of NULL is used when called from Blockchain::handle_block_to_main_chain()
      {
        MERROR_VER("  *pmax_used_block_height: " << *pmax_used_block_height);
      }

      return false;
    }

    if (tx.version == 1)
    {
      if (threads > 1)
      {
        // ND: Speedup
        // 1. Thread ring signature verification if possible.
        tpool.submit(&waiter, boost::bind(&Blockchain::check_ring_signature, this, std::cref(tx_prefix_hash), std::cref(in_to_key.k_image), std::cref(pubkeys[sig_index]), std::cref(tx.signatures[sig_index]), std::ref(results[sig_index])), true);
      }
      else
      {
        check_ring_signature(tx_prefix_hash, in_to_key.k_image, pubkeys[sig_index], tx.signatures[sig_index], results[sig_index]);
        if (!results[sig_index])
        {
          MERROR_VER("Failed to check ring signature for tx " << get_transaction_hash(tx) << "  vin key with k_image: " << in_to_key.k_image << "  sig_index: " << sig_index);

          if (pmax_used_block_height)  // a default value of NULL is used when called from Blockchain::handle_block_to_main_chain()
          {
            MERROR_VER("*pmax_used_block_height: " << *pmax_used_block_height);
          }

          return false;
        }
      }
    }

    sig_index++;
  }
  if (tx.version == 1 && threads > 1)
    if (!waiter.wait())
      return false;

  // enforce min output age
  if (hf_version >= HF_VERSION_ENFORCE_MIN_AGE)
  {
    CHECK_AND_ASSERT_MES(*pmax_used_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE <= m_db->height(),
        false, "Transaction spends at least one output which is too young");
  }

  // Warn that new RCT types are present, and thus the cache is not being used effectively
  const std::uint8_t rct_cache_type = (hf_version >= HF_VERSION_BP_PLUS_FULL_COMMIT) ? static_cast<std::uint8_t>(rct::RCTTypeBulletproofPlus_FullCommit) : static_cast<std::uint8_t>(rct::RCTTypeBulletproofPlus);
  if (static_cast<std::uint8_t>(tx.rct_signatures.type) > rct_cache_type)
    MWARNING("RCT cache is not caching new verification results. Please update rct_cache_type.");

  if (tx.version == 1)
  {
    if (threads > 1)
    {
      // save results to table, passed or otherwise
      bool failed = false;
      for (size_t i = 0; i < tx.vin.size(); i++)
      {
        if(!failed && !results[i])
          failed = true;
      }

      if (failed)
      {
        MERROR_VER("Failed to check ring signatures!");
        return false;
      }
    }
  }
  else
  {
    // from version 2, check ringct signatures
    // obviously, the original and simple rct APIs use a mixRing that's indexes
    // in opposite orders, because it'd be too simple otherwise...
    const rct::rctSig &rv = tx.rct_signatures;
    switch (rv.type)
    {
    case rct::RCTTypeNull: {
      // Allow ONLY strict PBC TERM_WITHDRAW virtual-input TX (vin.size==1, txin_pbc_withdraw, fee==0)
      {
        crypto::hash dep_id;
        uint64_t payout = 0;
        uint8_t kind = 0;
        std::string fail;
        const auto wres = pbc_validate_withdraw_tx(tx, dep_id, payout, kind, fail);
        if (wres == PBC_WITHDRAW_VALID &&
            tx.vin.size() == 1 &&
            tx.vin[0].type() == typeid(txin_pbc_withdraw) &&
            get_tx_fee(tx) == 0)
        {
          // No ringct verification for this TX type — ownership proven via owner_sig (tag 0x55)
          break;
        }
      }
      // Allow MARKET_PAYOUT_CLAIM (type 11): same virtual-input format as TERM_WITHDRAW.
      {
        crypto::public_key seller_pubkey;
        uint64_t payout = 0;
        std::string fail;
        const auto pres = pbc_validate_market_payout_tx(tx, seller_pubkey, payout, fail);
        if (pres == PBC_MARKET_PAYOUT_VALID &&
            tx.vin.size() == 1 &&
            tx.vin[0].type() == typeid(txin_pbc_withdraw) &&
            get_tx_fee(tx) == 0)
        {
          break;
        }
      }
      MERROR_VER("Null rct signature on non-coinbase tx");
      return false;
    }
    case rct::RCTTypeSimple:
    case rct::RCTTypeSimpleBulletproof:
    case rct::RCTTypeBulletproof:
    case rct::RCTTypeBulletproof2:
    case rct::RCTTypeCLSAG:
    case rct::RCTTypeBulletproofPlus:
    case rct::RCTTypeBulletproofPlus_FullCommit:
    {
      if (!ver_rct_non_semantics_simple_cached(tx, pubkeys, m_rct_ver_cache, rct_cache_type))
      {
        MERROR_VER("Failed to check ringct signatures!");
        return false;
      }
      break;
    }
    case rct::RCTTypeFull:
    case rct::RCTTypeFullBulletproof:
    {
      if (!expand_transaction_2(tx, tx_prefix_hash, pubkeys))
      {
        MERROR_VER("Failed to expand rct signatures!");
        return false;
      }

      // check all this, either reconstructed (so should really pass), or not
      {
        bool size_matches = true;
        for (size_t i = 0; i < pubkeys.size(); ++i)
          size_matches &= pubkeys[i].size() == rv.mixRing.size();
        for (size_t i = 0; i < rv.mixRing.size(); ++i)
          size_matches &= pubkeys.size() == rv.mixRing[i].size();
        if (!size_matches)
        {
          MERROR_VER("Failed to check ringct signatures: mismatched pubkeys/mixRing size");
          return false;
        }

        for (size_t n = 0; n < pubkeys.size(); ++n)
        {
          for (size_t m = 0; m < pubkeys[n].size(); ++m)
          {
            if (pubkeys[n][m].dest != rct::rct2pk(rv.mixRing[m][n].dest))
            {
              MERROR_VER("Failed to check ringct signatures: mismatched pubkey at vin " << n << ", index " << m);
              return false;
            }
            if (pubkeys[n][m].mask != rct::rct2pk(rv.mixRing[m][n].mask))
            {
              MERROR_VER("Failed to check ringct signatures: mismatched commitment at vin " << n << ", index " << m);
              return false;
            }
          }
        }
      }

      if (rv.p.MGs.size() != 1)
      {
        MERROR_VER("Failed to check ringct signatures: Bad MGs size");
        return false;
      }
      if (rv.p.MGs.empty() || rv.p.MGs[0].II.size() != tx.vin.size())
      {
        MERROR_VER("Failed to check ringct signatures: mismatched II/vin sizes");
        return false;
      }
      for (size_t n = 0; n < tx.vin.size(); ++n)
      {
        if (memcmp(&boost::get<txin_to_key>(tx.vin[n]).k_image, &rv.p.MGs[0].II[n], 32))
        {
          MERROR_VER("Failed to check ringct signatures: mismatched II/vin sizes");
          return false;
        }
      }

      if (!rct::verRct(rv, false))
      {
        MERROR_VER("Failed to check ringct signatures!");
        return false;
      }
      break;
    }
    default:
      MERROR_VER("Unsupported rct type: " << rv.type);
      return false;
    }

    // for bulletproofs, check they're only multi-output after v8
    if (rct::is_rct_bulletproof(rv.type))
    {
      if (hf_version < 8)
      {
        for (const rct::Bulletproof &proof: rv.p.bulletproofs)
        {
          if (proof.V.size() > 1)
          {
            MERROR_VER("Multi output bulletproofs are invalid before v8");
            return false;
          }
        }
      }
    }
  }

  // ── E1b: PQC Dilithium signature verification ──
  // If the TX contains a Dilithium signature in extra, verify it.
  //
  // ACTUAL signed message = H("PBC_DILITHIUM_TX_V1" || dilithium_pubkey)  — the TX contents
  // are NOT part of the signed message (see below). This was previously (mis)documented as
  // "|| hash(extra_without_dilithium)", which was never implemented (L2).
  //
  // Binding-to-this-TX today relies ENTIRELY on the signature living in tx.extra, which is
  // covered by tx_prefix_hash and thus signed by the CLSAG of a normal RingCT TX. This holds
  // for ring TXs, but a txin_pbc_withdraw TX (RCTTypeNull) has NO CLSAG, so on such a TX the
  // (dilithium_pubkey, sig) pair is a replayable proof-of-possession. Impact is currently NIL
  // because (a) PQC is in soft transition — a missing Dilithium sig is allowed (see below),
  // and (b) the Dilithium sig gates NOTHING: authorization of a virtual-input TX is enforced
  // by owner_sig / seller_sig, never by Dilithium. This MUST be fixed (bind the sig to the
  // tx_prefix_hash computed with the Dilithium fields excluded, on both wallet and consensus)
  // BEFORE any hard-fork makes a valid Dilithium signature a condition of acceptance.
  {
    std::vector<tx_extra_field> pqc_fields;
    tx_extra_pbc_dilithium_pubkey dil_pk_field;
    tx_extra_pbc_dilithium_sig dil_sig_field;

    // Problem 2: on TERM_WITHDRAW / MARKET_PAYOUT (txin_pbc_withdraw) the Dilithium fields are NOT
    // the generic proof-of-possession verified here — they are the SPEND-AUTHORITY co-signature over
    // H(PBC_PQC_WITHDRAW_MSG_PREFIX || deposit_id || payout_amount), verified in the E2 withdraw block
    // below (against the key registered for the deposit owner). Verifying them here against the
    // "PBC_DILITHIUM_TX_V1" PoP message would fail (different message), so we skip E1b for these TXs.
    if (is_pbc_withdraw_tx_ci)
    {
      // handled in E2 (withdraw) — do nothing here
    }
    else if (parse_tx_extra(tx.extra, pqc_fields) &&
        find_tx_extra_field_by_type(pqc_fields, dil_pk_field) &&
        find_tx_extra_field_by_type(pqc_fields, dil_sig_field))
    {
      // Validate sizes
      if (dil_pk_field.pubkey.size() != pqc::DILITHIUM_PUBLIC_KEY_SIZE)
      {
        MERROR_VER("PQC: Dilithium pubkey wrong size: " << dil_pk_field.pubkey.size());
        return false;
      }
      if (dil_sig_field.sig.size() == 0 || dil_sig_field.sig.size() > pqc::DILITHIUM_SIGNATURE_SIZE)
      {
        MERROR_VER("PQC: Dilithium sig wrong size: " << dil_sig_field.sig.size());
        return false;
      }

      // Compute message hash: H("PBC_DILITHIUM_TX_V1" || dilithium_pubkey).
      // NOTE (L2): the TX contents are intentionally NOT hashed here; see the block comment
      // above for why this is currently safe and what must change before PQC becomes mandatory.
      std::string msg("PBC_DILITHIUM_TX_V1");
      msg.append(reinterpret_cast<const char*>(dil_pk_field.pubkey.data()), dil_pk_field.pubkey.size());
      crypto::hash msg_hash;
      crypto::cn_fast_hash(msg.data(), msg.size(), msg_hash);

      // Verify signature
      pqc::dilithium_public_key pk;
      memcpy(pk.data, dil_pk_field.pubkey.data(), pqc::DILITHIUM_PUBLIC_KEY_SIZE);
      pqc::dilithium_signature sig;
      sig.length = dil_sig_field.sig.size();
      memcpy(sig.data, dil_sig_field.sig.data(), sig.length);

      if (!pqc::dilithium_verify(reinterpret_cast<const uint8_t*>(&msg_hash), sizeof(msg_hash), sig, pk))
      {
        MERROR_VER("PQC: Dilithium signature verification FAILED");
        return false;
      }
      LOG_PRINT_L2("PQC: Dilithium signature verified OK");
    }
    // If no Dilithium sig present: currently allowed (soft transition).
    // After hard fork activation, this should return false.
  }

  // ── E2: PBC TERM_WITHDRAW virtual-input full validation ──
  // Executed ONLY when vin contains a txin_pbc_withdraw (already bypassed the ring loop above).
  // Checks: strict format + deposit state + ownership signature + vout conservation.
  // NOTE: MARKET_PAYOUT_CLAIM also uses txin_pbc_withdraw — skip it here (validated separately in block apply).
  if (!tx.vin.empty() && tx.vin[0].type() == typeid(txin_pbc_withdraw))
  {
    // Check if this is a MARKET_PAYOUT_CLAIM — skip E2 entirely (handled by PF section in block apply).
    {
      std::vector<tx_extra_field> e2_fields;
      tx_extra_pbc_tx_type e2_type{};
      if (parse_tx_extra(tx.extra, e2_fields) &&
          find_tx_extra_field_by_type(e2_fields, e2_type) &&
          e2_type.type == PBC_TX_TYPE_MARKET_PAYOUT_CLAIM)
      {
        // Already validated by the RCTTypeNull switch above — nothing more to do here.
        return true;
      }
    }

    // E2.1: Strict structural checks
    CHECK_AND_ASSERT_MES(tx.vin.size() == 1, false, "PBC withdraw: vin.size must be 1");
    CHECK_AND_ASSERT_MES(get_tx_fee(tx) == 0, false, "PBC withdraw: fee must be 0");
    CHECK_AND_ASSERT_MES(tx.rct_signatures.type == rct::RCTTypeNull, false, "PBC withdraw: rct type must be Null");

    // E2.2: Parse and validate withdraw tx_extra
    crypto::hash dep_id;
    uint64_t payout_amount = 0;
    uint8_t payout_kind = 0;
    std::string w_fail;
    const pbc_withdraw_result wres = pbc_validate_withdraw_tx(tx, dep_id, payout_amount, payout_kind, w_fail);
    CHECK_AND_ASSERT_MES(wres == PBC_WITHDRAW_VALID, false, "PBC withdraw: pbc_validate_withdraw_tx failed: " + w_fail);
    CHECK_AND_ASSERT_MES(payout_kind == 0, false, "PBC withdraw: unsupported payout_kind");
    CHECK_AND_ASSERT_MES(payout_amount > 0, false, "PBC withdraw: payout_amount must be > 0");

    // E2.3: Coherence vin.deposit_id vs extra deposit_id
    const auto& pbc_in = boost::get<txin_pbc_withdraw>(tx.vin[0]);
    CHECK_AND_ASSERT_MES(pbc_in.deposit_id == dep_id, false, "PBC withdraw: deposit_id mismatch vin vs extra");

    // E2.4: sum(vout.amount) == payout_amount
    uint64_t sum_vout = 0;
    for (const auto& o : tx.vout)
    {
      CHECK_AND_ASSERT_MES(sum_vout <= std::numeric_limits<uint64_t>::max() - o.amount, false,
          "PBC withdraw: vout amount overflow");
      sum_vout += o.amount;
    }
    CHECK_AND_ASSERT_MES(sum_vout == payout_amount, false,
        "PBC withdraw: sum(vout.amount)=" << sum_vout << " != payout_amount=" << payout_amount);

    // E2.5: Load deposit record from LMDB
    uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
    size_t dep_buf_size = PBC_DEPOSIT_RECORD_PACKED_SIZE;
    CHECK_AND_ASSERT_MES(m_db->get_pbc_deposit(dep_id, dep_buf, dep_buf_size), false,
        "PBC withdraw: deposit not found in LMDB: " << dep_id);
    pbc_deposit_record dep_rec;
    pbc_unpack_deposit_record(dep_buf, dep_buf_size, dep_rec);

    // E2.6: Deposit state checks
    const uint64_t cur_height = m_db->height();
    CHECK_AND_ASSERT_MES(dep_rec.created_height < cur_height, false,
        "PBC withdraw: deposit not yet active");
    CHECK_AND_ASSERT_MES(dep_rec.last_claim_height != 0 && dep_rec.last_claim_height < cur_height, false,
        "PBC withdraw: no prior confirmed CLAIM");
    CHECK_AND_ASSERT_MES(dep_rec.accumulated_reward > 0, false,
        "PBC withdraw: accumulated_reward is 0");
    CHECK_AND_ASSERT_MES(dep_rec.accumulated_reward == payout_amount, false,
        "PBC withdraw: payout_amount does not match accumulated_reward");

    // E2.7: Ownership signature (tag 0x55) — verify with dep_rec.owner_key
    CHECK_AND_ASSERT_MES(dep_rec.owner_key != crypto::null_pkey, false,
        "PBC withdraw: owner_key is null in deposit record");
    {
      std::vector<tx_extra_field> fields;
      tx_extra_pbc_owner_sig sig_field;
      CHECK_AND_ASSERT_MES(parse_tx_extra(tx.extra, fields) && find_tx_extra_field_by_type(fields, sig_field),
          false, "PBC withdraw: owner_sig (0x55) not found in tx_extra");
      const crypto::hash msg_hash = pbc_build_withdraw_msg_hash(dep_id, payout_amount);
      CHECK_AND_ASSERT_MES(crypto::check_signature(msg_hash, dep_rec.owner_key, sig_field.sig),
          false, "PBC withdraw: owner_sig verification failed");
    }

    // ── E2.8 (Problem 2): Dilithium spend-authority CO-SIGNATURE ──
    // Breaking Ed25519 alone lets an attacker forge the owner_sig above and steal a matured
    // deposit's reward. To make that insufficient, we additionally require an ML-DSA-65 signature by
    // the deposit owner's REGISTERED post-quantum key over
    //     H(PBC_PQC_WITHDRAW_MSG_PREFIX || deposit_id || payout_amount)
    // (byte-identical to the wallet, tags 0x5F pubkey + 0x60 sig). Because a withdraw is already
    // non-anonymous (public deposit_id + revealed owner_key), this adds post-quantum spend authority
    // with ZERO anonymity cost. This does NOT protect ordinary RingCT transfers (see QUANTUM_ANALYSIS.md).
    //
    // Transition: BEFORE HF_VERSION_PBC_PQC_SPEND_AUTH the co-signature is verified if present but not
    // required; AT/AFTER the fork a valid co-signature is MANDATORY. Enforced via the shared verifier
    // pbc_verify_dilithium_cosig so the withdraw, block-apply payout and mempool payout paths agree.
    {
      const bool pqc_required = (hf_version >= HF_VERSION_PBC_PQC_SPEND_AUTH);

      std::vector<tx_extra_field> pqc_fields;
      parse_tx_extra(tx.extra, pqc_fields);
      const crypto::hash pqc_msg_hash = pbc_build_pqc_withdraw_msg_hash(dep_id, payout_amount);

      // Load the Dilithium key registered under the deposit owner (if any).
      const std::string owner_hex = epee::string_tools::pod_to_hex(dep_rec.owner_key);
      uint8_t reg_dil[pqc::DILITHIUM_PUBLIC_KEY_SIZE];
      size_t  reg_dil_sz = 0;
      const bool have_registered =
          pbc_load_packed_props(m_db, "pbc_pqc_" + owner_hex + "_dilithium", reg_dil, sizeof(reg_dil), reg_dil_sz)
          && reg_dil_sz == pqc::DILITHIUM_PUBLIC_KEY_SIZE;

      bool cosig_present = false;
      std::string cosig_fail;
      const bool cosig_ok = pbc_verify_dilithium_cosig(
          pqc_fields, pqc_msg_hash,
          have_registered ? reg_dil : nullptr, have_registered ? reg_dil_sz : 0,
          pqc_required, cosig_present, cosig_fail);
      CHECK_AND_ASSERT_MES(cosig_ok, false, "PBC withdraw: " + cosig_fail);
      if (cosig_present && cosig_ok && have_registered)
        LOG_PRINT_L2("PBC withdraw: Dilithium spend-authority co-signature verified OK");
    }
  }

  return true;
}

//------------------------------------------------------------------
// Problem 2 — expose the registered-Dilithium-key lookup (wraps the file-static packed-props loader
// used at registration time) so the mempool payout precheck can enforce the same key-binding rule.
bool Blockchain::pbc_get_registered_dilithium(const crypto::public_key& spend_pubkey,
                                              uint8_t* out, size_t out_capacity, size_t& out_size) const
{
  out_size = 0;
  if (out == nullptr || out_capacity < pqc::DILITHIUM_PUBLIC_KEY_SIZE)
    return false;
  const std::string hex = epee::string_tools::pod_to_hex(spend_pubkey);
  size_t sz = 0;
  if (!pbc_load_packed_props(m_db, "pbc_pqc_" + hex + "_dilithium", out, out_capacity, sz))
    return false;
  if (sz != pqc::DILITHIUM_PUBLIC_KEY_SIZE)
    return false;
  out_size = sz;
  return true;
}

//------------------------------------------------------------------
void Blockchain::check_ring_signature(const crypto::hash &tx_prefix_hash, const crypto::key_image &key_image, const std::vector<rct::ctkey> &pubkeys, const std::vector<crypto::signature>& sig, uint64_t &result) const
{
  std::vector<const crypto::public_key *> p_output_keys;
  p_output_keys.reserve(pubkeys.size());
  for (auto &key : pubkeys)
  {
    // rct::key and crypto::public_key have the same structure, avoid object ctor/memcpy
    p_output_keys.push_back(&(const crypto::public_key&)key.dest);
  }

  result = crypto::check_ring_signature(tx_prefix_hash, key_image, p_output_keys, sig.data()) ? 1 : 0;
}

//------------------------------------------------------------------
uint64_t Blockchain::get_dynamic_base_fee(uint64_t block_reward, size_t median_block_weight, uint8_t version)
{
  const uint64_t min_block_weight = get_min_block_weight(version);
  if (median_block_weight < min_block_weight)
    median_block_weight = min_block_weight;
  uint64_t hi, lo;

  if (version >= HF_VERSION_PER_BYTE_FEE)
  {
    lo = mul128(block_reward, DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT, &hi);
    div128_64(hi, lo, median_block_weight, &hi, &lo, NULL, NULL);
    if (version >= HF_VERSION_2021_SCALING)
    {
      // min_fee_per_byte = round_up( 0.95 * block_reward * ref_weight / (fee_median^2) )
      // note: since hardfork HF_VERSION_2021_SCALING, fee_median (a.k.a. median_block_weight) equals effective long term median
      div128_64(hi, lo, median_block_weight, &hi, &lo, NULL, NULL);
      assert(hi == 0);
      lo -= lo / 20;
      return lo == 0 ? 1 : lo;
    }
    else
    {
      // min_fee_per_byte = 0.2 * block_reward * ref_weight / (min_penalty_free_zone * fee_median)
      div128_64(hi, lo, min_block_weight, &hi, &lo, NULL, NULL);
      assert(hi == 0);
      lo /= 5;
      return lo;
    }
  }

  const uint64_t fee_base = version >= 5 ? DYNAMIC_FEE_PER_KB_BASE_FEE_V5 : DYNAMIC_FEE_PER_KB_BASE_FEE;

  uint64_t unscaled_fee_base = (fee_base * min_block_weight / median_block_weight);
  lo = mul128(unscaled_fee_base, block_reward, &hi);
  div128_64(hi, lo, DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD, &hi, &lo, NULL, NULL);
  assert(hi == 0);

  // quantize fee up to 8 decimals
  uint64_t mask = get_fee_quantization_mask();
  uint64_t qlo = (lo + mask - 1) / mask * mask;
  MDEBUG("lo " << print_money(lo) << ", qlo " << print_money(qlo) << ", mask " << mask);

  return qlo;
}

//------------------------------------------------------------------
bool Blockchain::check_fee(size_t tx_weight, uint64_t fee) const
{
  const uint8_t version = get_current_hard_fork_version();

  uint64_t median = 0;
  uint64_t already_generated_coins = 0;
  uint64_t base_reward = 0;
  if (version >= HF_VERSION_DYNAMIC_FEE)
  {
    median = m_current_block_cumul_weight_limit / 2;
    const uint64_t blockchain_height = m_db->height();
    already_generated_coins = blockchain_height ? m_db->get_block_already_generated_coins(blockchain_height - 1) : 0;
    if (!get_block_reward(median, 1, already_generated_coins, base_reward, version))
      return false;
  }

  uint64_t needed_fee;
  if (version >= HF_VERSION_PER_BYTE_FEE)
  {
    const bool use_long_term_median_in_fee = version >= HF_VERSION_LONG_TERM_BLOCK_WEIGHT;
    uint64_t fee_per_byte = get_dynamic_base_fee(base_reward, use_long_term_median_in_fee ? std::min<uint64_t>(median, m_long_term_effective_median_block_weight) : median, version);
    MDEBUG("Using " << print_money(fee_per_byte) << "/byte fee");
    needed_fee = tx_weight * fee_per_byte;
    // quantize fee up to 8 decimals
    const uint64_t mask = get_fee_quantization_mask();
    needed_fee = (needed_fee + mask - 1) / mask * mask;
  }
  else
  {
    uint64_t fee_per_kb;
    if (version < HF_VERSION_DYNAMIC_FEE)
    {
      fee_per_kb = FEE_PER_KB;
    }
    else
    {
      fee_per_kb = get_dynamic_base_fee(base_reward, median, version);
    }
    MDEBUG("Using " << print_money(fee_per_kb) << "/kB fee");

    needed_fee = tx_weight / 1024;
    needed_fee += (tx_weight % 1024) ? 1 : 0;
    needed_fee *= fee_per_kb;
  }

  if (fee < needed_fee - needed_fee / 50) // keep a little 2% buffer on acceptance - no integer overflow
  {
    MERROR_VER("transaction fee is not enough: " << print_money(fee) << ", minimum fee: " << print_money(needed_fee));
    return false;
  }
  return true;
}

//------------------------------------------------------------------
void Blockchain::get_dynamic_base_fee_estimate_2021_scaling(uint64_t grace_blocks, uint64_t base_reward, uint64_t Mnw, uint64_t Mlw, std::vector<uint64_t> &fees) const
{
  // variable names and calculations as per https://github.com/ArticMine/Monero-Documents/blob/master/MoneroScaling2021-02.pdf
  // from (earlier than) this fork, the base fee is per byte
  const uint64_t Mfw = std::min(Mnw, Mlw);

  // 3 kB divided by something ? It's going to be either 0 or *very* quantized, so fold it into integer steps below
  //const uint64_t Brlw = DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / Mfw;

  // constant.... equal to 0, unless floating point, so fold it into integer steps below
  //const uint64_t Br = DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5

  //const uint64_t Fl = base_reward * Brlw / Mfw; fold Brlw from above
  const uint64_t Fl = base_reward * /*Brlw*/ DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / (Mfw * Mfw);

  // fold Fl into this for better precision (and to match the test cases in the PDF)
  // const uint64_t Fn = 4 * Fl;
  const uint64_t Fn = 4 * base_reward * /*Brlw*/ DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / (Mfw * Mfw);

  // const uint64_t Fm = 16 * base_reward * Br / Mfw; fold Br from above
  const uint64_t Fm = 16 * base_reward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / (CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 * Mfw);

  // const uint64_t Fp = 2 * base_reward / Mnw;

  // fold Br from above, move 4Fm in the max to decrease quantization effect
  //const uint64_t Fh = 4 * Fm * std::max<uint64_t>(1, Mfw / (32 * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT * Mnw / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5));
  const uint64_t Fh = std::max<uint64_t>(4 * Fm, 4 * Fm * Mfw / (32 * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT * Mnw / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5));

  fees.resize(4);
  fees[0] = cryptonote::round_money_up(Fl, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES);
  fees[1] = cryptonote::round_money_up(Fn, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES);
  fees[2] = cryptonote::round_money_up(Fm, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES);
  fees[3] = cryptonote::round_money_up(Fh, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES);
}

void Blockchain::get_dynamic_base_fee_estimate_2021_scaling(uint64_t grace_blocks, std::vector<uint64_t> &fees) const
{
  const uint8_t version = get_current_hard_fork_version();
  const uint64_t db_height = m_db->height();

  CHECK_AND_ASSERT_THROW_MES(grace_blocks <= CRYPTONOTE_REWARD_BLOCKS_WINDOW, "Grace blocks invalid In 2021 fee scaling estimate.");

  // we want Mlw = median of max((min(Mbw, 1.7 * Ml), Zm), Ml / 1.7)
  // Mbw: block weight for the last 99990 blocks, 0 for the next 10
  // Ml: penalty free zone (dynamic), aka long_term_median, aka median of max((min(Mb, 1.7 * Ml), Zm), Ml / 1.7)
  // Zm: 300000 (minimum penalty free zone)
  //
  // So we copy the current rolling median state, add 10 (grace_blocks) zeroes to it, and get back Mlw

  epee::misc_utils::rolling_median_t<uint64_t> rm = m_long_term_block_weights_cache_rolling_median;
  for (size_t i = 0; i < grace_blocks; ++i)
    rm.insert(0);
  const uint64_t Mlw_penalty_free_zone_for_wallet = std::max<uint64_t>(rm.median(), CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5);

  // Msw: median over [100 - grace blocks] past + [grace blocks] future blocks
  std::vector<uint64_t> weights;
  get_last_n_blocks_weights(weights, 100 - grace_blocks);
  weights.reserve(100);
  for (size_t i = 0; i < grace_blocks; ++i)
    weights.push_back(0);
  const uint64_t Msw_effective_short_term_median = std::max(epee::misc_utils::median(weights), Mlw_penalty_free_zone_for_wallet);

  const uint64_t Mnw = std::min(Msw_effective_short_term_median, 50 * Mlw_penalty_free_zone_for_wallet);

  uint64_t already_generated_coins = db_height ? m_db->get_block_already_generated_coins(db_height - 1) : 0;
  uint64_t base_reward;
  if (!get_block_reward(m_current_block_cumul_weight_limit / 2, 1, already_generated_coins, base_reward, version))
  {
    MERROR("Failed to determine block reward, using placeholder " << print_money(BLOCK_REWARD_OVERESTIMATE) << " as a high bound");
    base_reward = BLOCK_REWARD_OVERESTIMATE;
  }

  get_dynamic_base_fee_estimate_2021_scaling(grace_blocks, base_reward, Mnw, Mlw_penalty_free_zone_for_wallet, fees);
}

//------------------------------------------------------------------
uint64_t Blockchain::get_dynamic_base_fee_estimate(uint64_t grace_blocks) const
{
  const uint8_t version = get_current_hard_fork_version();
  const uint64_t db_height = m_db->height();

  if (version < HF_VERSION_DYNAMIC_FEE)
    return FEE_PER_KB;

  if (grace_blocks >= CRYPTONOTE_REWARD_BLOCKS_WINDOW)
    grace_blocks = CRYPTONOTE_REWARD_BLOCKS_WINDOW - 1;

  if (version >= HF_VERSION_2021_SCALING)
  {
    std::vector<uint64_t> fees;
    get_dynamic_base_fee_estimate_2021_scaling(grace_blocks, fees);
    return fees[0];
  }

  const uint64_t min_block_weight = get_min_block_weight(version);
  std::vector<uint64_t> weights;
  get_last_n_blocks_weights(weights, CRYPTONOTE_REWARD_BLOCKS_WINDOW - grace_blocks);
  weights.reserve(grace_blocks);
  for (size_t i = 0; i < grace_blocks; ++i)
    weights.push_back(min_block_weight);

  uint64_t median = epee::misc_utils::median(weights);
  if(median <= min_block_weight)
    median = min_block_weight;

  uint64_t already_generated_coins = db_height ? m_db->get_block_already_generated_coins(db_height - 1) : 0;
  uint64_t base_reward;
  if (!get_block_reward(m_current_block_cumul_weight_limit / 2, 1, already_generated_coins, base_reward, version))
  {
    MERROR("Failed to determine block reward, using placeholder " << print_money(BLOCK_REWARD_OVERESTIMATE) << " as a high bound");
    base_reward = BLOCK_REWARD_OVERESTIMATE;
  }

  const bool use_long_term_median_in_fee = version >= HF_VERSION_LONG_TERM_BLOCK_WEIGHT;
  const uint64_t use_median_value = use_long_term_median_in_fee ? std::min<uint64_t>(median, m_long_term_effective_median_block_weight) : median;
  const uint64_t fee = get_dynamic_base_fee(base_reward, use_median_value, version);
  const bool per_byte = version < HF_VERSION_PER_BYTE_FEE;
  MDEBUG("Estimating " << grace_blocks << "-block fee at " << print_money(fee) << "/" << (per_byte ? "byte" : "kB"));
  return fee;
}

//------------------------------------------------------------------
// This function checks to see if a tx is unlocked.  unlock_time is either
// a block index or a unix time.
bool Blockchain::is_tx_spendtime_unlocked(uint64_t unlock_time, uint8_t hf_version) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    // ND: Instead of calling get_current_blockchain_height(), call m_db->height()
    //    directly as get_current_blockchain_height() locks the recursive mutex.
    if(m_db->height()-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
      return true;
    else
      return false;
  }
  else
  {
    //interpret as time
    const uint64_t current_time = hf_version >= HF_VERSION_DETERMINISTIC_UNLOCK_TIME ? get_adjusted_time(m_db->height()) : static_cast<uint64_t>(time(NULL));
    if(current_time + (get_current_hard_fork_version() < 2 ? CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1 : CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2) >= unlock_time)
      return true;
    else
      return false;
  }
  return false;
}
//------------------------------------------------------------------
// This function locates all outputs associated with a given input (mixins)
// and validates that they exist and are usable.  It also checks the ring
// signature for each input.
bool Blockchain::check_tx_input(size_t tx_version, const txin_to_key& txin, const crypto::hash& tx_prefix_hash, const std::vector<crypto::signature>& sig, const rct::rctSig &rct_signatures, std::vector<rct::ctkey> &output_keys, uint64_t* pmax_related_block_height, uint8_t hf_version) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // ND:
  // 1. Disable locking and make method private.
  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  struct outputs_visitor
  {
    std::vector<rct::ctkey >& m_output_keys;
    const Blockchain& m_bch;
    const uint8_t hf_version;
    outputs_visitor(std::vector<rct::ctkey>& output_keys, const Blockchain& bch, uint8_t hf_version) :
      m_output_keys(output_keys), m_bch(bch), hf_version(hf_version)
    {
    }
    bool handle_output(uint64_t unlock_time, const crypto::public_key &pubkey, const rct::key &commitment)
    {
      //check tx unlock time
      if (!m_bch.is_tx_spendtime_unlocked(unlock_time, hf_version))
      {
        MERROR_VER("One of outputs for one of inputs has wrong tx.unlock_time = " << unlock_time);
        return false;
      }

      // The original code includes a check for the output corresponding to this input
      // to be a txout_to_key. This is removed, as the database does not store this info.
      // Only txout_to_key (and since HF_VERSION_VIEW_TAGS, txout_to_tagged_key)
      // outputs are stored in the DB in the first place, done in Blockchain*::add_output.
      // Additional type checks on outputs were also added via cryptonote::check_output_types
      // and cryptonote::get_output_public_key (see Blockchain::check_tx_outputs).

      m_output_keys.push_back(rct::ctkey({rct::pk2rct(pubkey), commitment}));
      return true;
    }
  };

  output_keys.clear();

  // collect output keys
  outputs_visitor vi(output_keys, *this, hf_version);
  if (!scan_outputkeys_for_indexes(tx_version, txin, vi, tx_prefix_hash, pmax_related_block_height))
  {
    MERROR_VER("Failed to get output keys for tx with amount = " << print_money(txin.amount) << " and count indexes " << txin.key_offsets.size());
    return false;
  }

  if(txin.key_offsets.size() != output_keys.size())
  {
    MERROR_VER("Output keys for tx with amount = " << txin.amount << " and count indexes " << txin.key_offsets.size() << " returned wrong keys count " << output_keys.size());
    return false;
  }
  if (tx_version == 1) {
    CHECK_AND_ASSERT_MES(sig.size() == output_keys.size(), false, "internal error: tx signatures count=" << sig.size() << " mismatch with outputs keys count for inputs=" << output_keys.size());
  }
  // rct_signatures will be expanded after this
  return true;
}
//------------------------------------------------------------------
// only works on the main chain
uint64_t Blockchain::get_adjusted_time(uint64_t height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // if not enough blocks, no proper median yet, return current time
  uint8_t version = get_current_hard_fork_version();
  size_t blockchain_timestamp_check_window = version >= 10 ? BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2 : BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
  if(height < blockchain_timestamp_check_window)
  {
      return static_cast<uint64_t>(time(NULL));
  }
  std::vector<uint64_t> timestamps;

  // need most recent 60 blocks, get index of first of those
  size_t offset = height - blockchain_timestamp_check_window;
  timestamps.reserve(height - offset);
  for(;offset < height; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }
  uint64_t median_ts = epee::misc_utils::median(timestamps);

  // project the median to match approximately when the block being validated will appear
  // the median is calculated from a chunk of past blocks, so we use +1 to offset onto the current block
  median_ts += (blockchain_timestamp_check_window + 1) * DIFFICULTY_TARGET_V2 / 2;

  // project the current block's time based on the previous block's time
  // we don't use the current block's time directly to mitigate timestamp manipulation
  uint64_t adjusted_current_block_ts = timestamps.back() + DIFFICULTY_TARGET_V2;

  // return minimum of ~current block time and adjusted median time
  // we do this since it's better to report a time in the past than a time in the future
  return (adjusted_current_block_ts < median_ts ? adjusted_current_block_ts : median_ts);
}
//------------------------------------------------------------------
//TODO: revisit, has changed a bit on upstream
bool Blockchain::check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  median_ts = epee::misc_utils::median(timestamps);

  if(b.timestamp < median_ts)
  {
    uint8_t version = get_current_hard_fork_version();
    size_t blockchain_timestamp_check_window = version >= 10 ? BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2 : BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
    MERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", less than median of last " << blockchain_timestamp_check_window << " blocks, " << median_ts);
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// This function grabs the timestamps from the most recent <n> blocks,
// where n = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.  If there are not those many
// blocks in the blockchain, the timestap is assumed to be valid.  If there
// are, this function returns:
//   true if the block's timestamp is not less than the timestamp of the
//       median of the selected blocks
//   false otherwise
bool Blockchain::check_block_timestamp(const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  uint8_t version = get_current_hard_fork_version();
  uint64_t cryptonote_block_future_time_limit = version >= 8 ? CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2 : CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;
  size_t blockchain_timestamp_check_window = version >= 10 ? BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2 : BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
  if(b.timestamp > (uint64_t)time(NULL) + cryptonote_block_future_time_limit)
  {
    MERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", bigger than local time + 10 minutes");
    return false;
  }

  const auto h = m_db->height();

  // if not enough blocks, no proper median yet, return true
  if(h < blockchain_timestamp_check_window)
  {
    return true;
  }

  std::vector<uint64_t> timestamps;

  // need most recent 60 blocks, get index of first of those
  size_t offset = h - blockchain_timestamp_check_window;
  timestamps.reserve(h - offset);
  for(;offset < h; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }

  return check_block_timestamp(timestamps, b, median_ts);
}
//------------------------------------------------------------------
bool Blockchain::flush_txes_from_pool(const std::vector<crypto::hash> &txids)
{
  CRITICAL_REGION_LOCAL(m_tx_pool);

  bool res = true;
  for (const auto &txid: txids)
  {
    cryptonote::transaction tx;
    cryptonote::blobdata txblob;
    size_t tx_weight;
    uint64_t fee;
    bool relayed, do_not_relay, double_spend_seen, pruned;
    MINFO("Removing txid " << txid << " from the pool");
    if(m_tx_pool.have_tx(txid, relay_category::all) && !m_tx_pool.take_tx(txid, tx, txblob, tx_weight, fee, relayed, do_not_relay, double_spend_seen, pruned))
    {
      MERROR("Failed to remove txid " << txid << " from the pool");
      res = false;
    }
  }
  return res;
}
//------------------------------------------------------------------
//      Needs to validate the block and acquire each transaction from the
//      transaction mem_pool, then pass the block and transactions to
//      m_db->add_block()
bool Blockchain::handle_block_to_main_chain(const block& bl, const crypto::hash& id,
  block_verification_context& bvc, pool_supplement& extra_block_txs)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  TIME_MEASURE_START(block_processing_time);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  TIME_MEASURE_START(t1);

  static bool seen_future_version = false;

  db_rtxn_guard rtxn_guard(m_db);
  uint64_t blockchain_height;
  const crypto::hash top_hash = get_tail_id(blockchain_height);
  ++blockchain_height; // block height to chain height
  if(bl.prev_id != top_hash)
  {
    MERROR_VER("Block with id: " << id << std::endl << "has wrong prev_id: " << bl.prev_id << std::endl << "expected: " << top_hash);
    bvc.m_verifivation_failed = true;
leave:
    return false;
  }

  // warn users if they're running an old version
  if (!seen_future_version && bl.major_version > m_hardfork->get_ideal_version())
  {
    seen_future_version = true;
    const el::Level level = el::Level::Warning;
    MCLOG_RED(level, "global", "**********************************************************************");
    MCLOG_RED(level, "global", "A block was seen on the network with a version higher than the last");
    MCLOG_RED(level, "global", "known one. This may be an old version of the daemon, and a software");
    MCLOG_RED(level, "global", "update may be required to sync further. Try running: update check");
    MCLOG_RED(level, "global", "**********************************************************************");
  }

  // this is a cheap test
  const uint8_t hf_version = get_current_hard_fork_version();
  if (!m_hardfork->check(bl))
  {
    MERROR_VER("Block with id: " << id << std::endl << "has old version: " << (unsigned)bl.major_version << std::endl << "current: " << (unsigned)hf_version);
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  TIME_MEASURE_FINISH(t1);
  TIME_MEASURE_START(t2);

  // make sure block timestamp is not less than the median timestamp
  // of a set number of the most recent blocks.
  if(!check_block_timestamp(bl))
  {
    MERROR_VER("Block with id: " << id << std::endl << "has invalid timestamp: " << bl.timestamp);
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  TIME_MEASURE_FINISH(t2);
  //check proof of work
  TIME_MEASURE_START(target_calculating_time);

  // get the target difficulty for the block.
  // the calculation can overflow, among other failure cases,
  // so we need to check the return type.
  // FIXME: get_difficulty_for_next_block can also assert, look into
  // changing this to throwing exceptions instead so we can clean up.
  difficulty_type current_diffic = get_difficulty_for_next_block(m_nettype);
  CHECK_AND_ASSERT_MES(current_diffic, false, "!!!!!!!!! difficulty overhead !!!!!!!!!");

  TIME_MEASURE_FINISH(target_calculating_time);

  TIME_MEASURE_START(longhash_calculating_time);

  crypto::hash proof_of_work;
  memset(proof_of_work.data, 0xff, sizeof(proof_of_work.data));

  // Formerly the code below contained an if loop with the following condition
  // !m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height())
  // however, this caused the daemon to not bother checking PoW for blocks
  // before checkpoints, which is very dangerous behaviour. We moved the PoW
  // validation out of the next chunk of code to make sure that we correctly
  // check PoW now.
  // FIXME: height parameter is not used...should it be used or should it not
  // be a parameter?
  // validate proof_of_work versus difficulty target
  bool precomputed = false;
  bool fast_check = false;
#if defined(PER_BLOCK_CHECKPOINT)
  if (blockchain_height < m_blocks_hash_check.size())
  {
    const auto &expected_hash = m_blocks_hash_check[blockchain_height].first;
    if (expected_hash != crypto::null_hash)
    {
      if (memcmp(&id, &expected_hash, sizeof(hash)) != 0)
      {
        MERROR_VER("Block with id is INVALID: " << id << ", expected " << expected_hash);
        bvc.m_verifivation_failed = true;
        goto leave;
      }
      fast_check = true;
    }
    else
    {
      MCINFO("verify", "No pre-validated hash at height " << blockchain_height << ", verifying fully");
    }
  }
#endif
  if (!fast_check)
  {
    auto it = m_blocks_longhash_table.find(id);
    if (it != m_blocks_longhash_table.end())
    {
      precomputed = true;
      proof_of_work = it->second;
    }
    else
      proof_of_work = get_block_longhash(this, bl, blockchain_height, 0);

    // validate proof_of_work versus difficulty target
    if(!check_hash(proof_of_work, current_diffic))
    {
      MERROR_VER("Block with id: " << id << std::endl << "does not have enough proof of work: " << proof_of_work << " at height " << blockchain_height << ", unexpected difficulty: " << current_diffic);
      bvc.m_verifivation_failed = true;
      bvc.m_bad_pow = true;
      goto leave;
    }
  }

  // If we're at a checkpoint, ensure that our hardcoded checkpoint hash
  // is correct.
  if(m_checkpoints.is_in_checkpoint_zone(blockchain_height))
  {
    if(!m_checkpoints.check_block(blockchain_height, id))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verifivation_failed = true;
      goto leave;
    }
  }

  TIME_MEASURE_FINISH(longhash_calculating_time);
  if (precomputed)
    longhash_calculating_time += m_fake_pow_calc_time;

  TIME_MEASURE_START(t3);

  // sanity check basic miner tx properties;
  if(!prevalidate_miner_transaction(bl, blockchain_height, hf_version))
  {
    MERROR_VER("Block with id: " << id << " failed to pass prevalidation");
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  // verify all non-input consensus rules for txs inside the pool supplement (if not inside checkpoint zone)
#if defined(PER_BLOCK_CHECKPOINT)
  if (!fast_check)
#endif
  {
    tx_verification_context tvc{};
    // If fail non-input consensus rule checking...
    if (!ver_non_input_consensus(extra_block_txs, tvc, hf_version))
    {
      MERROR_VER("Pool supplement provided for block with id: " << id << " failed to pass validation");
      bvc.m_verifivation_failed = true;
      goto leave;
    }
  }

  size_t coinbase_weight = get_transaction_weight(bl.miner_tx);
  size_t cumulative_block_weight = coinbase_weight;

  std::vector<std::pair<transaction, blobdata>> txs;
  //                          txid     weight mempool?
  std::vector<std::tuple<crypto::hash, size_t, bool>> txs_meta;

  // This will be the data sent to the ZMQ pool listeners for txs which skipped the mempool
  std::vector<txpool_event> txpool_events;

  // this lambda returns relevant txs back to the mempool
  auto return_txs_to_pool = [this, &txs, &txs_meta, &hf_version]()
  {
    if (txs_meta.size() != txs.size())
    {
      MERROR("BUG: txs_meta and txs not matching size!!!");
      return;
    }

    for (size_t i = 0; i < txs.size(); ++i)
    {
      // if this transaction wasn't ever in the pool, don't return it back to the pool
      const bool found_in_pool = std::get<2>(txs_meta[i]);
      if (!found_in_pool)
        continue;

      transaction &tx = txs[i].first;
      const crypto::hash &txid = std::get<0>(txs_meta[i]);
      const blobdata &tx_blob = txs[i].second;
      const size_t tx_weight = std::get<1>(txs_meta[i]);

      // We assume that if they were in a block, the transactions are already known to the network
      // as a whole. However, if we had mined that block, that might not be always true. Unlikely
      // though, and always relaying these again might cause a spike of traffic as many nodes
      // re-relay all the transactions in a popped block when a reorg happens. You might notice that
      // we also set the "nic_verified_hf_version" paramater. Since we know we took this transaction
      // from the mempool earlier in this function call, when the mempool has the same current fork
      // version, we can return it without re-verifying the consensus rules on it.
      cryptonote::tx_verification_context tvc{};
      if (!m_tx_pool.add_tx(tx, txid, tx_blob, tx_weight, tvc, relay_method::block, true,
          hf_version, hf_version))
        MERROR("Failed to return taken transaction with hash: " << txid << " to tx_pool");
    }
  };

  key_images_container keys;

  uint64_t fee_summary = 0;
  uint64_t t_checktx = 0;
  uint64_t t_exists = 0;
  uint64_t t_pool = 0;
  uint64_t t_dblspnd = 0;
  uint64_t n_pruned = 0;
  TIME_MEASURE_FINISH(t3);

// XXX old code adds miner tx here

  // Iterate over the block's transaction hashes, grabbing each
  // from the tx_pool (or from extra_block_txs) and validating them.  Each is then added
  // to txs.  Keys spent in each are added to <keys> by the double spend check.
  txs.reserve(bl.tx_hashes.size());
  txs_meta.reserve(bl.tx_hashes.size());
  txpool_events.reserve(bl.tx_hashes.size());
  for (const crypto::hash& tx_id : bl.tx_hashes)
  {
    TIME_MEASURE_START(aa);

// XXX old code does not check whether tx exists
    if (m_db->tx_exists(tx_id))
    {
      MERROR("Block with id: " << id << " attempting to add transaction already in blockchain with id: " << tx_id);
      bvc.m_verifivation_failed = true;
      return_txs_to_pool();
      return false;
    }

    TIME_MEASURE_FINISH(aa);
    t_exists += aa;
    TIME_MEASURE_START(bb);

    // get transaction with hash <tx_id> from m_tx_pool or extra_block_txs
    // tx info we want:
    //   * tx as `cryptonote::transaction`
    //   * blob
    //   * weight
    //   * fee
    //   * is pruned?
    txs.emplace_back();
    transaction &tx = txs.back().first;
    blobdata &txblob = txs.back().second;
    size_t tx_weight{};
    uint64_t fee{};
    bool pruned{};

    /* 
     * Try pulling transaction data from the mempool proper first. If that fails, then try pulling
     * from the block supplement. We add txs pulled from the block to the txpool events for future
     * notifications, since if the tx skipped the mempool, then listeners have not yet received a
     * notification for this tx.
     */
    bool _unused1, _unused2, _unused3;
    const bool found_tx_in_pool{
        m_tx_pool.take_tx(tx_id, tx, txblob, tx_weight, fee,
          _unused1, _unused2, _unused3, pruned, /*suppress_missing_msgs=*/true)
      };
    bool find_tx_failure{!found_tx_in_pool};
    if (!found_tx_in_pool) // if not in mempool:
    {
      const auto extra_txs_it{extra_block_txs.txs_by_txid.find(tx_id)};
      if (extra_txs_it != extra_block_txs.txs_by_txid.end()) // if in block supplement:
      {
        tx = std::move(extra_txs_it->second.first);
        txblob = std::move(extra_txs_it->second.second);
        tx_weight = tx.pruned ? get_pruned_transaction_weight(tx) : get_transaction_weight(tx, txblob.size());
        fee = get_tx_fee(tx);
        pruned = tx.pruned;
        extra_block_txs.txs_by_txid.erase(extra_txs_it);
        txpool_events.emplace_back(txpool_event{tx, tx_id, txblob.size(), tx_weight, true});
        find_tx_failure = false;
      }
    }

    // @TODO: We should move this section (checking if the daemon has all txs from the block) to
    // right after the PoW check. Since it's now expected the node will sometimes not have all txs
    // in its pool at this point nor the txs included as fluffy txs (and will need to re-request
    // missing fluffy txs), then the node will sometimes waste cycles doing verification for some
    // txs twice.
    if (find_tx_failure) // did not find txid in mempool or provided extra block txs
    {
      const bool fully_supplemented_block = extra_block_txs.txs_by_txid.size() >= bl.tx_hashes.size();
      if (fully_supplemented_block)
        MERROR_VER("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_id);
      else
        LOG_PRINT_L2("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_id);
      txs.pop_back(); // We push to the back preemptively. On fail, we need txs & txs_meta to match size
      bvc.m_verifivation_failed = true;
      bvc.m_missing_txs = true;
      return_txs_to_pool();
      return false;
    }
    if (pruned)
      ++n_pruned;

    TIME_MEASURE_FINISH(bb);
    t_pool += bb;
    // add the transaction to the temp list of transactions, so we can either
    // store the list of transactions all at once or return the ones we've
    // taken from the tx_pool back to it if the block fails verification.
    txs_meta.emplace_back(tx_id, tx_weight, found_tx_in_pool);
    TIME_MEASURE_START(dd);

    // FIXME: the storage should not be responsible for validation.
    //        If it does any, it is merely a sanity check.
    //        Validation is the purview of the Blockchain class
    //        - TW
    //
    // ND: this is not needed, db->add_block() checks for duplicate k_images and fails accordingly.
    // if (!check_for_double_spend(tx, keys))
    // {
    //     LOG_PRINT_L0("Double spend detected in transaction (id: " << tx_id);
    //     bvc.m_verifivation_failed = true;
    //     break;
    // }

    TIME_MEASURE_FINISH(dd);
    t_dblspnd += dd;
    TIME_MEASURE_START(cc);

#if defined(PER_BLOCK_CHECKPOINT)
    if (!fast_check)
#endif
    {
      // validate that transaction inputs and the keys spending them are correct.
      tx_verification_context tvc;
      if(!check_tx_inputs(tx, tvc))
      {
        MERROR_VER("Block with id: " << id  << " has at least one transaction (id: " << tx_id << ") with wrong inputs.");

        //TODO: why is this done?  make sure that keeping invalid blocks makes sense.
        add_block_as_invalid(bl, id);
        MERROR_VER("Block with id " << id << " added as invalid because of wrong inputs in transactions");
        bvc.m_verifivation_failed = true;
        return_txs_to_pool();
        return false;
      }
    }

    TIME_MEASURE_FINISH(cc);
    t_checktx += cc;

    // ── PBC: Detect and log PBC TX types (TD-0: parse only) ──
    if (!pruned)
    {
      std::vector<tx_extra_field> pbc_extra_fields;
      if (parse_tx_extra(tx.extra, pbc_extra_fields))
      {
        tx_extra_pbc_tx_type pbc_type_field;
        if (find_tx_extra_field_by_type(pbc_extra_fields, pbc_type_field))
        {
          const char* pbc_name = pbc_type_field.type == PBC_TX_TYPE_TERM_DEPOSIT  ? "TERM_DEPOSIT" :
                                 pbc_type_field.type == PBC_TX_TYPE_CLAIM         ? "CLAIM" :
                                 pbc_type_field.type == PBC_TX_TYPE_TERM_WITHDRAW ? "TERM_WITHDRAW" : "UNKNOWN";
          MGINFO("PBC: Block TX detected: " << pbc_name << " (type=" << (unsigned)pbc_type_field.type << ") txid=" << tx_id);
        }
      }
    }

    fee_summary += fee;
    cumulative_block_weight += tx_weight;
  }

  // if we were syncing pruned blocks
  if (n_pruned > 0)
  {
    if (blockchain_height >= m_blocks_hash_check.size() || m_blocks_hash_check[blockchain_height].second == 0)
    {
      MERROR("Block at " << blockchain_height << " is pruned, but we do not have a weight for it");
      goto leave;
    }
    cumulative_block_weight = m_blocks_hash_check[blockchain_height].second;
  }

  TIME_MEASURE_START(vmt);
  uint64_t base_reward = 0;
  uint64_t already_generated_coins = blockchain_height ? m_db->get_block_already_generated_coins(blockchain_height - 1) : 0;
  if(!validate_miner_transaction(bl, cumulative_block_weight, fee_summary, base_reward, already_generated_coins, bvc.m_partial_block_reward, m_hardfork->get_current_version()))
  {
    MERROR_VER("Block with id: " << id << " has incorrect miner transaction");
    bvc.m_verifivation_failed = true;
    return_txs_to_pool();
    return false;
  }

  TIME_MEASURE_FINISH(vmt);
  size_t block_weight;
  difficulty_type cumulative_difficulty;

  // populate various metadata about the block to be stored alongside it.
  block_weight = cumulative_block_weight;
  cumulative_difficulty = current_diffic;
  // In the "tail" state when the minimum subsidy (implemented in get_block_reward) is in effect, the number of
  // coins will eventually exceed MONEY_SUPPLY and overflow a uint64. To prevent overflow, cap already_generated_coins
  // at MONEY_SUPPLY. already_generated_coins is only used to compute the block subsidy and MONEY_SUPPLY yields a
  // subsidy of 0 under the base formula and therefore the minimum subsidy >0 in the tail state.
  already_generated_coins = base_reward < (MONEY_SUPPLY-already_generated_coins) ? already_generated_coins + base_reward : MONEY_SUPPLY;

  // TD-6 §10: Emitted coins monotonicity — can never decrease
  {
    uint64_t prev_coins = blockchain_height ? m_db->get_block_already_generated_coins(blockchain_height - 1) : 0;
    CHECK_AND_ASSERT_MES(already_generated_coins >= prev_coins, false,
        "PBC TD-6 §10: already_generated_coins decreased (monotonicity violated)");
  }
  if(blockchain_height)
    cumulative_difficulty += m_db->get_block_cumulative_difficulty(blockchain_height - 1);

  TIME_MEASURE_FINISH(block_processing_time);
  if(precomputed)
    block_processing_time += m_fake_pow_calc_time;

  rtxn_guard.stop();
  TIME_MEASURE_START(addblock);
  uint64_t new_height = 0;

  // ═══════════════════════════════════════════════════════════════
  // PBC ATOMICITY GUARANTEE: If no batch is active, we start one
  // ourselves so that m_db->add_block() + PBC pool writes are in
  // the SAME LMDB transaction. If a batch already exists (the normal
  // case from prepare_handle_incoming_blocks), we piggyback on it.
  // ═══════════════════════════════════════════════════════════════
  bool pbc_started_batch = false;
  if (hf_version >= HF_VERSION_VESTING && !m_db->is_batch_active())
  {
    LOG_PRINT_L1("PBC: No active batch — starting local batch for block+pool atomicity");
    m_db->batch_start();
    pbc_started_batch = true;
  }
  MDEBUG("PBC atomicity: batch_active=" << m_db->is_batch_active()
    << " pbc_started_batch=" << pbc_started_batch
    << " (pre-add_block)");

  if (!bvc.m_verifivation_failed)
  {
    try
    {
      uint64_t long_term_block_weight = get_next_long_term_block_weight(block_weight);
      cryptonote::blobdata bd = cryptonote::block_to_blob(bl);
      new_height = m_db->add_block(std::make_pair(std::move(bl), std::move(bd)), block_weight, long_term_block_weight, cumulative_difficulty, already_generated_coins, txs);
    }
    catch (const KEY_IMAGE_EXISTS& e)
    {
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      if (pbc_started_batch) m_db->batch_abort();
      m_batch_success = false;
      bvc.m_verifivation_failed = true;
      return_txs_to_pool();
      return false;
    }
    catch (const std::exception& e)
    {
      //TODO: figure out the best way to deal with this failure
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      if (pbc_started_batch) m_db->batch_abort();
      m_batch_success = false;
      bvc.m_verifivation_failed = true;
      return_txs_to_pool();
      return false;
    }
  }
  else
  {
    LOG_ERROR("Blocks that failed verification should not reach here");
  }

  TIME_MEASURE_FINISH(addblock);

  // do this after updating the hard fork state since the weight limit may change due to fork
  if (!update_next_cumulative_weight_limit())
  {
    MERROR("Failed to update next cumulative weight limit");
    pop_block_from_blockchain();
    // If we started a local batch, commit it so the pop_block takes effect.
    // The batch now contains: add_block + pop_block = net zero. Committing
    // is safe (restores original state). Aborting would leave the added block
    // in DB without its pop — corrupting state.
    if (pbc_started_batch) m_db->batch_stop();
    return false;
  }

  MINFO("+++++ BLOCK SUCCESSFULLY ADDED" << std::endl << "id:\t" << id << std::endl << "PoW:\t" << proof_of_work << std::endl << "HEIGHT " << new_height-1 << ", difficulty:\t" << current_diffic << std::endl << "block reward: " << print_money(fee_summary + base_reward) << "(" << print_money(base_reward) << " + " << print_money(fee_summary) << "), coinbase_weight: " << coinbase_weight << ", cumulative weight: " << cumulative_block_weight << ", " << block_processing_time << "(" << target_calculating_time << "/" << longhash_calculating_time << ")ms");

  // ═══════════════════════════════════════════════════════════════
  // PBC: Update virtual reward pool state (§19.12 Steps 1-2, 7-9)
  // ═══════════════════════════════════════════════════════════════
  if (hf_version >= HF_VERSION_VESTING && (new_height - 1) > 0)
  {
    // STRUCTURAL GUARANTEE: batch must be active here — either from
    // prepare_handle_incoming_blocks (normal path) or from our local
    // batch_start above (fallback path). This is a hard invariant.
    assert(m_db->is_batch_active());
    MDEBUG("PBC atomicity: batch_active=" << m_db->is_batch_active()
      << " pbc_started_batch=" << pbc_started_batch
      << " (during PBC apply, height=" << (new_height - 1) << ")");

#ifdef PBC_CRASH_TEST_AFTER_ADD_BLOCK
    // ── CRASH INJECTION (compile-time debug only) ──
    // Simulates a crash AFTER m_db->add_block() but BEFORE PBC writes.
    // Expected: on restart, the batch was never committed, so the block
    // is NOT in the DB, height is unchanged, pool_state is unchanged.
    LOG_ERROR("PBC_CRASH_TEST: Throwing after add_block but before PBC apply");
    if (pbc_started_batch) m_db->batch_abort();
    throw std::runtime_error("PBC_CRASH_TEST: simulated crash after add_block");
#endif

    try
    {
      uint64_t block_height = new_height - 1;  // new_height is height AFTER add

      // ═══════════════════════════════════════════════════════════
      // RAII guard: snapshot m_pbc_pool_state BEFORE any PBC mutation.
      // On ANY exit (return false, throw, exception) the destructor
      // restores m_pbc_pool_state to its pre-block value.
      // Only pbc_state_guard.commit() disables the restore (success path).
      // ═══════════════════════════════════════════════════════════
      struct pbc_state_guard_t {
        pbc_pool_state& live;
        pbc_pool_state  snapshot;
        bool            committed;
        pbc_state_guard_t(pbc_pool_state& s) : live(s), snapshot(s), committed(false) {}
        ~pbc_state_guard_t() {
          if (!committed) {
            live = snapshot;
            LOG_PRINT_L1("PBC state guard: restored m_pbc_pool_state (block failed)");
          }
        }
        void commit() { committed = true; }
      } pbc_state_guard(m_pbc_pool_state);

      // ── PBC TRACE: PRE-APPLY — full state dump before any mutation ──
      {
        const uint64_t _agc = already_generated_coins;
        const uint64_t _cf  = m_pbc_pool_state.cumulative_fees;
        const uint64_t _S   = _agc + _cf;
        const uint64_t _P   = m_pbc_pool_state.pool_balances();
        const uint64_t _dst = m_pbc_pool_state.total_destroyed;
        const uint64_t _ves = m_pbc_pool_state.total_vested_outputs;
        const uint64_t _lck = m_pbc_pool_state.total_locked_in_deposits;
        const uint64_t _existence = (_S >= _dst) ? (_S - _dst) : 0;
        const uint64_t _outside   = (_existence >= _P) ? (_existence - _P) : 0;
        const uint64_t _circ      = (_outside >= _ves) ? (_outside - _ves) : 0;
        LOG_PRINT_L1("PBC TRACE PRE-APPLY h=" << block_height
          << " agc=" << _agc
          << " cf=" << _cf
          << " S=" << _S
          << " dep=" << m_pbc_pool_state.deposit_pool_balance
          << " fee=" << m_pbc_pool_state.fee_pool_balance
          << " ins=" << m_pbc_pool_state.insurance_pool_balance
          << " P=" << _P
          << " destroyed=" << _dst
          << " vested=" << _ves
          << " locked=" << _lck
          << " sumW=" << m_pbc_pool_state.deposit_sum_weights
          << " existence=" << _existence
          << " outside=" << _outside
          << " circ=" << _circ
          << " dep_inflow=" << m_pbc_pool_state.deposit_pool_period_inflow
          << " fee_inflow=" << m_pbc_pool_state.fee_pool_period_inflow
          << " boundary=" << ((block_height > 0 && block_height % PBC_DISTRIBUTION_PERIOD == 0) ? "YES" : "no")
          << " fee_summary=" << fee_summary);
      }

      // ═══════════════════════════════════════════════════════════
      // TD-4: Global Index Update — BEFORE split (§7.2, §19.6)
      // At period boundary H (H % 720 == 0, H > 0):
      //   1. Snapshot pre-update state (for reorg reversal)
      //   2. Compute Σw_k from eligible deposits in LMDB
      //   3. Apply index update (LSM + δI calculation)
      // This uses accumulators from blocks [H-720, H-1].
      // ═══════════════════════════════════════════════════════════
      if (block_height > 0 && block_height % PBC_DISTRIBUTION_PERIOD == 0)
      {
        // ── 1. Snapshot before update (reorg safety) ──
        // BUG1-FIX: DI/FI are now __uint128_t → use set_property_uint128
        m_db->set_property_uint128(pbc_delta_key(PBC_DELTA_KEY_IDX_DI, block_height), m_pbc_pool_state.global_deposit_index);
        m_db->set_property_uint128(pbc_delta_key(PBC_DELTA_KEY_IDX_FI, block_height), m_pbc_pool_state.global_fee_index);
        m_db->set_property_uint64(pbc_delta_key(PBC_DELTA_KEY_IDX_DA, block_height), m_pbc_pool_state.deposit_pool_period_inflow);
        m_db->set_property_uint64(pbc_delta_key(PBC_DELTA_KEY_IDX_FA, block_height), m_pbc_pool_state.fee_pool_period_inflow);
        m_db->set_property_uint64(pbc_delta_key(PBC_DELTA_KEY_IDX_LH, block_height), m_pbc_pool_state.last_index_update_height);

        // ── 2. Compute Σw_k and total_locked: eligible deposits ──
        //    Eligible: created_height < H  AND  unlock_height > H
        //    BUG2+BUG3-FIX: recompute both sum_weights and total_locked at boundary
        uint64_t eligible_sum_weights = 0;
        uint64_t active_locked = 0;
        uint64_t _scan_total = 0, _scan_eligible = 0, _scan_skipped = 0;
        m_db->for_each_pbc_deposit([&](const crypto::hash& id, const void* data, size_t data_size) -> bool
        {
          _scan_total++;
          if (data_size < PBC_DEPOSIT_RECORD_PACKED_SIZE_V1)
          {
            _scan_skipped++;
            LOG_PRINT_L2("PBC TRACE BOUNDARY-SKIP id=" << id << " data_size=" << data_size);
            return true;  // skip malformed or non-deposit entries (e.g. claim deltas)
          }
          pbc_deposit_record rec;
          pbc_unpack_deposit_record(static_cast<const uint8_t*>(data), data_size, rec);
          if (rec.created_height < block_height && rec.unlock_height > block_height)
          {
            _scan_eligible++;
            eligible_sum_weights += rec.weight;
            active_locked += rec.amount;
            LOG_PRINT_L2("PBC TRACE BOUNDARY-DEP id=" << id
              << " amount=" << rec.amount
              << " weight=" << rec.weight
              << " created=" << rec.created_height
              << " unlock=" << rec.unlock_height
              << " tier=" << (unsigned)rec.tier
              << " running_locked=" << active_locked
              << " running_sumW=" << eligible_sum_weights);
          }
          return true;
        });
        LOG_PRINT_L1("PBC TRACE BOUNDARY-SCAN-SUMMARY h=" << block_height
          << " total_entries=" << _scan_total
          << " eligible=" << _scan_eligible
          << " skipped=" << _scan_skipped
          << " active_locked=" << active_locked
          << " eligible_sumW=" << eligible_sum_weights);

        // BUG2+BUG3-FIX: Authoritative recompute — replaces stale counters
        m_pbc_pool_state.deposit_sum_weights = eligible_sum_weights;
        m_pbc_pool_state.total_locked_in_deposits = active_locked;

        // ── PBC TRACE: BOUNDARY-SCAN — state after recompute, before index update ──
        {
          const uint64_t _bagc = m_db->get_block_already_generated_coins(block_height - 1);
          const uint64_t _bS   = _bagc + m_pbc_pool_state.cumulative_fees;
          const uint64_t _bP   = m_pbc_pool_state.pool_balances();
          const uint64_t _bdst = m_pbc_pool_state.total_destroyed;
          const uint64_t _bexistence = (_bS >= _bdst) ? (_bS - _bdst) : 0;
          const uint64_t _boutside   = (_bexistence >= _bP) ? (_bexistence - _bP) : 0;
          LOG_PRINT_L1("PBC TRACE BOUNDARY h=" << block_height
            << " agc=" << _bagc
            << " cf=" << m_pbc_pool_state.cumulative_fees
            << " S=" << _bS
            << " dep_pool=" << m_pbc_pool_state.deposit_pool_balance
            << " fee_pool=" << m_pbc_pool_state.fee_pool_balance
            << " ins_pool=" << m_pbc_pool_state.insurance_pool_balance
            << " P=" << _bP
            << " destroyed=" << _bdst
            << " vested=" << m_pbc_pool_state.total_vested_outputs
            << " locked(recomputed)=" << active_locked
            << " locked(was)=" << m_pbc_pool_state.total_locked_in_deposits
            << " sumW(recomputed)=" << eligible_sum_weights
            << " sumW(was)=" << m_pbc_pool_state.deposit_sum_weights
            << " existence=" << _bexistence
            << " outside=" << _boutside
            << " dep_inflow=" << m_pbc_pool_state.deposit_pool_period_inflow
            << " fee_inflow=" << m_pbc_pool_state.fee_pool_period_inflow);
        }

        // ── 3. Apply index update ──
        uint64_t agc = m_db->get_block_already_generated_coins(block_height - 1);
        uint64_t pre_dep_inflow = m_pbc_pool_state.deposit_pool_period_inflow;
        uint64_t pre_fee_inflow = m_pbc_pool_state.fee_pool_period_inflow;
        pbc_apply_index_update(m_pbc_pool_state, eligible_sum_weights, agc, block_height);

        LOG_PRINT_L1("PBC TD-4: Index update at height " << block_height
          << " Σw_k=" << eligible_sum_weights
          << " locked=" << active_locked
          << " ΔP=" << pre_dep_inflow
          << " ΔF=" << pre_fee_inflow
          << " deposit_idx_hi=" << (uint64_t)(m_pbc_pool_state.global_deposit_index >> 64)
          << " deposit_idx_lo=" << (uint64_t)(m_pbc_pool_state.global_deposit_index)
          << " fee_idx_hi=" << (uint64_t)(m_pbc_pool_state.global_fee_index >> 64)
          << " fee_idx_lo=" << (uint64_t)(m_pbc_pool_state.global_fee_index));

        // Hardening 2.1: Prominent log at first period boundary for manual verification
        if (block_height == PBC_DISTRIBUTION_PERIOD) {
          LOG_PRINT_L0("PBC FIRST INDEX UPDATE: height=" << block_height
            << " Σw=" << eligible_sum_weights
            << " locked=" << active_locked
            << " deposit_idx=" << pbc_uint128_to_str(m_pbc_pool_state.global_deposit_index)
            << " fee_idx=" << pbc_uint128_to_str(m_pbc_pool_state.global_fee_index));
        }

        // Hardening 2.2: reinforced sum_weights check at period boundary
        CHECK_AND_ASSERT_MES(
            m_pbc_pool_state.deposit_sum_weights == eligible_sum_weights,
            false, "PBC: sum_weights inconsistent after boundary recompute");
        // NOTE: conservation check intentionally NOT done here —
        // pool_state has not yet absorbed this block's pools_R/pools_F
        // (that happens in pbc_apply_block_reward below).
        // The existing conservation check after apply_block_reward covers this.
      }

      // Steps 1-2: Compute block split and apply to pools
      pbc_block_split split = pbc_compute_block_split(base_reward, fee_summary);
      // TD-6 §1+§2: Hard conservation check (release + debug)
      assert(pbc_check_block_split(base_reward, fee_summary, split));
      CHECK_AND_ASSERT_MES(
          pbc_check_block_split(base_reward, fee_summary, split),
          false, "PBC TD-6 §1: block split conservation failed");

      // BUG4-FIX: Track cumulative fees for conservation invariant.
      // Fees are recycled coins (already emitted) that enter pools (pools_F)
      // and coinbase (miner_F). agc only tracks emission R, so supply_base
      // = agc + cumulative_fees is needed for conservation to hold.
      CHECK_AND_ASSERT_MES(
          UINT64_MAX - m_pbc_pool_state.cumulative_fees >= fee_summary,
          false, "PBC BUG4: cumulative_fees overflow");
      m_pbc_pool_state.cumulative_fees += fee_summary;

      pbc_apply_block_reward(m_pbc_pool_state, split);

      // Step 9: Update vesting tracking
      // FIX-12: Store coinbase split for future vesting expiry lookups
      m_db->set_property_uint64(
          pbc_delta_key(PBC_DELTA_KEY_PREFIX_VM, block_height), split.total_miner);
      m_db->set_property_uint64(
          pbc_delta_key(PBC_DELTA_KEY_PREFIX_VD, block_height), split.total_dev);

      pbc_vesting_delta vdelta;
      vdelta.added = split.total_coinbase;

      // FIX-12: Subtract expired vesting outputs from past blocks
      // Each block creates: 4 miner outputs (tiers 1-4) + 1 dev output (tier 1 unlock)
      // Tier 1 (1440 blk): output 0 = quarter + remainder + dev output
      // Tier 2 (43200 blk): output 1 = quarter
      // Tier 3 (86400 blk): output 2 = quarter
      // Tier 4 (129600 blk): output 3 = quarter
      {
        static const uint64_t VEST_PERIODS[] = {
            PBC_VESTING_UNLOCK_1, PBC_VESTING_UNLOCK_2,
            PBC_VESTING_UNLOCK_3, PBC_VESTING_UNLOCK_4
        };
        uint64_t total_expired = 0;
        for (int tier = 0; tier < 4; tier++)
        {
          if (block_height < VEST_PERIODS[tier]) continue;
          uint64_t src_h = block_height - VEST_PERIODS[tier];
          if (src_h == 0) continue; // genesis has no vesting

          uint64_t src_miner = 0, src_dev = 0;
          if (!m_db->get_property_uint64(
                  pbc_delta_key(PBC_DELTA_KEY_PREFIX_VM, src_h), src_miner))
            continue; // pre-migration block without stored data
          m_db->get_property_uint64(
              pbc_delta_key(PBC_DELTA_KEY_PREFIX_VD, src_h), src_dev);

          uint64_t quarter = src_miner / PBC_VESTING_OUTPUTS;
          if (tier == 0) {
            // Tier 1: first miner output (quarter + remainder) + dev output
            uint64_t remainder = src_miner - (quarter * PBC_VESTING_OUTPUTS);
            total_expired += quarter + remainder + src_dev;
          } else {
            total_expired += quarter;
          }
        }
        vdelta.expired = total_expired;
      }
      pbc_update_vesting(m_pbc_pool_state, vdelta);

      // Step 7: Insurance subsidy (period boundary only)
      uint64_t subsidy_delta = 0;
      if (block_height > 0 && block_height % PBC_DISTRIBUTION_PERIOD == 0)
      {
        subsidy_delta = pbc_apply_insurance_subsidy(m_pbc_pool_state);
        if (subsidy_delta > 0)
          LOG_PRINT_L1("PBC: Insurance subsidy of " << subsidy_delta << " atomic units to deposit pool at height " << block_height);
      }

      // Step 8: Insurance overflow check (every block)
      uint64_t overflow_delta = pbc_apply_insurance_overflow(m_pbc_pool_state);
      if (overflow_delta > 0)
        LOG_PRINT_L1("PBC: Insurance overflow destroyed " << overflow_delta << " atomic units at height " << block_height);

      // ── PBC TRACE: APPLY-STEPS — split + reward + vesting + insurance applied ──
      LOG_PRINT_L2("PBC TRACE APPLY-STEPS h=" << block_height
        << " R=" << base_reward
        << " F=" << fee_summary
        << " miner_R=" << split.miner_R
        << " dev_R=" << split.dev_R
        << " pools_R=" << split.pools_R
        << " miner_F=" << split.miner_F
        << " pools_F=" << split.pools_F
        << " coinbase=" << split.total_coinbase
        << " vesting_added=" << split.total_coinbase
        << " vested_now=" << m_pbc_pool_state.total_vested_outputs
        << " subsidy=" << subsidy_delta
        << " overflow=" << overflow_delta
        << " cf_now=" << m_pbc_pool_state.cumulative_fees);

      // Persist per-block deltas for exact reorg reversal (only if non-zero)
      if (overflow_delta > 0)
        m_db->set_property_uint64(pbc_delta_key(PBC_DELTA_KEY_PREFIX_OVF, block_height), overflow_delta);
      if (subsidy_delta > 0)
        m_db->set_property_uint64(pbc_delta_key(PBC_DELTA_KEY_PREFIX_SUB, block_height), subsidy_delta);

      // ── PBC Inheritance (block-height based, 18 months) ──
      // Process inheritance txs first (so a cancel in this block prevents execution).
      // Then execute any due requests (rare), transferring deposit ownership.
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& tx = txs[i].first;
        const crypto::hash& tx_id = std::get<0>(txs_meta[i]);
        tx_extra_pbc_tx_type type_field;
        if (!get_tx_extra_field_by_type(tx.extra, type_field))
          continue;

        if (type_field.type != PBC_TX_TYPE_INHERIT_SETUP &&
            type_field.type != PBC_TX_TYPE_INHERIT_REQUEST &&
            type_field.type != PBC_TX_TYPE_INHERIT_CANCEL &&
            type_field.type != PBC_TX_TYPE_INHERIT_TESTAMENT)
          continue;

        // Extract owner_key + owner_sig (setup/cancel => principal, request => heir)
        tx_extra_pbc_owner_key owner_field;
        tx_extra_pbc_owner_sig sig_field;
        bool has_owner = get_tx_extra_field_by_type(tx.extra, owner_field);
        bool has_sig   = get_tx_extra_field_by_type(tx.extra, sig_field);

        // Signing message: prefix || static PBC key data (no key_images —
        // adding owner_sig to extra before TX construction avoids the circular
        // dependency where ring sigs must sign over the final tx.extra).
        auto build_msg_hash = [&](const std::string& prefix, const std::string& payload) -> crypto::hash {
          std::string msg(prefix);
          msg.append(payload);
          return crypto::cn_fast_hash(msg.data(), msg.size());
        };

        if (type_field.type == PBC_TX_TYPE_INHERIT_SETUP)
        {
          tx_extra_pbc_inherit_setup setup_field;
          if (!get_tx_extra_field_by_type(tx.extra, setup_field) || !has_owner || !has_sig)
          {
            MERROR("PBC INHERIT: malformed SETUP tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          // verify signature by principal spend key
          std::string payload;
          payload.append(reinterpret_cast<const char*>(&owner_field.owner_spend_pubkey), sizeof(crypto::public_key));
          payload.append(reinterpret_cast<const char*>(&setup_field.heir.m_spend_public_key), sizeof(crypto::public_key));
          payload.append(reinterpret_cast<const char*>(&setup_field.heir.m_view_public_key), sizeof(crypto::public_key));
          const crypto::hash msg_hash = build_msg_hash(PBC_INHERIT_SETUP_MSG_PREFIX, payload);
          MGINFO("PBC INHERIT: verifying SETUP sig tx=" << tx_id
            << " principal=" << owner_field.owner_spend_pubkey
            << " msg_hash=" << msg_hash);
          if (!crypto::check_signature(msg_hash, owner_field.owner_spend_pubkey, sig_field.sig))
          {
            MERROR("PBC INHERIT: invalid SETUP owner_sig tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          // Store undo (previous record or none)
          pbc_inherit_record prev_rec;
          uint8_t prev_buf[PBC_INHERIT_RECORD_PACKED_SIZE];
          size_t prev_sz = PBC_INHERIT_RECORD_PACKED_SIZE;
          bool had_prev = false;
          if (m_db->get_pbc_inherit_record(owner_field.owner_spend_pubkey, prev_buf, prev_sz))
          {
            had_prev = pbc_unpack_inherit_record(prev_buf, prev_sz, prev_rec);
          }

          // Bug2 fix: read testament snapshot BEFORE deleting it.
          // The testament (if any) must be saved in the undo blob so that a reorg
          // of this SETUP can restore both the record AND the testament consistently.
          // Undo blob layout (extended):
          //   [1 byte tag][96 bytes packed prev_rec][4 bytes testament_size][testament_size bytes]
          //   [8 bytes prev_attempts][8 bytes prev_exec_key]   ← Conception v2 (2026-08-14)
          // testament_size == 0 means no testament was present.
          std::vector<uint8_t> setup_testament_snapshot;
          m_db->get_pbc_inherit_testament(owner_field.owner_spend_pubkey, setup_testament_snapshot);
          // Conception v2 (2026-08-14) : le budget de tentatives appartient au CYCLE, pas au
          // principal — un SETUP démarre/renouvelle la désignation, donc un nouveau cycle.
          // Lues AVANT la remise à 0 pour être snapshotées dans l'undo (symétrie exigée :
          // un reorg de CE tx SETUP doit restaurer le compteur à sa valeur d'avant).
          uint64_t setup_prev_attempts = 0;
          m_db->get_property_uint64(pbc_inh_testament_attempts_key(owner_field.owner_spend_pubkey), setup_prev_attempts);
          uint64_t setup_prev_exec_key = 0;
          m_db->get_property_uint64(pbc_inh_exec_key(owner_field.owner_spend_pubkey), setup_prev_exec_key);
          {
            const uint32_t test_sz = (uint32_t)setup_testament_snapshot.size();
            const size_t blob_sz = PBC_INHERIT_TX_UNDO_SIZE + sizeof(uint32_t) + test_sz
                                  + sizeof(uint64_t) + sizeof(uint64_t);
            std::vector<uint8_t> undo_blob(blob_sz);
            // First PBC_INHERIT_TX_UNDO_SIZE bytes = standard undo
            pbc_make_inherit_tx_undo(had_prev, had_prev ? &prev_rec : nullptr, undo_blob.data());
            // Append testament size + testament bytes
            memcpy(undo_blob.data() + PBC_INHERIT_TX_UNDO_SIZE, &test_sz, sizeof(test_sz));
            size_t soff = PBC_INHERIT_TX_UNDO_SIZE + sizeof(test_sz);
            if (test_sz > 0)
            {
              memcpy(undo_blob.data() + soff, setup_testament_snapshot.data(), test_sz);
              soff += test_sz;
            }
            // Conception v2 : suffixe attempts+exec_key (16 octets)
            memcpy(undo_blob.data() + soff, &setup_prev_attempts, sizeof(setup_prev_attempts)); soff += sizeof(setup_prev_attempts);
            memcpy(undo_blob.data() + soff, &setup_prev_exec_key, sizeof(setup_prev_exec_key)); soff += sizeof(setup_prev_exec_key);
            m_db->add_pbc_inherit_tx_undo(tx_id, undo_blob.data(), undo_blob.size());
          }

          // Bug2 fix: delete any existing testament — it was built for the old heir
          // and is no longer valid after the heir designation changes.
          // Restored on reorg via the undo blob above.
          if (!setup_testament_snapshot.empty())
          {
            m_db->remove_pbc_inherit_testament(owner_field.owner_spend_pubkey);
            m_db->remove_pbc_inherit_testament_local(owner_field.owner_spend_pubkey); // v8.2.11 (F-14) : hygiene du cache local RPC
            MGINFO("PBC INHERIT: SETUP removed stale testament for principal="
              << owner_field.owner_spend_pubkey << " (saved in undo blob)");
          }

          // Conception v2 (2026-08-14) : remise à 0 du budget de tentatives et de l'ancre
          // exec_key — le cycle précédent (s'il existe) est clos par ce SETUP, le nouveau
          // testament (à venir) mérite un budget complet, pas les restes d'un cycle épuisé.
          if (setup_prev_attempts != 0)
            m_db->set_property_uint64(pbc_inh_testament_attempts_key(owner_field.owner_spend_pubkey), 0);
          if (setup_prev_exec_key != 0)
            m_db->set_property_uint64(pbc_inh_exec_key(owner_field.owner_spend_pubkey), 0);

          // Write new record
          pbc_inherit_record rec;
          rec.heir = setup_field.heir;
          rec.last_activity_height = block_height;
          rec.request_active = 0;
          rec.request_height = 0;
          uint8_t out[PBC_INHERIT_RECORD_PACKED_SIZE];
          pbc_pack_inherit_record(rec, out);
          m_db->add_pbc_inherit_record(owner_field.owner_spend_pubkey, out, sizeof(out));
          MGINFO("PBC INHERIT: SETUP stored: tx=" << tx_id
            << " principal=" << owner_field.owner_spend_pubkey
            << " heir_spend=" << setup_field.heir.m_spend_public_key
            << " block=" << block_height
            << (had_prev ? " (updated)" : " (new)"));
        }
        else if (type_field.type == PBC_TX_TYPE_INHERIT_REQUEST)
        {
          tx_extra_pbc_inherit_target tgt_field;
          if (!get_tx_extra_field_by_type(tx.extra, tgt_field) || !has_owner || !has_sig)
          {
            MERROR("PBC INHERIT: malformed REQUEST tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          // Load principal record
          uint8_t buf[PBC_INHERIT_RECORD_PACKED_SIZE];
          size_t sz = PBC_INHERIT_RECORD_PACKED_SIZE;
          pbc_inherit_record rec;
          if (!m_db->get_pbc_inherit_record(tgt_field.principal_spend_pubkey, buf, sz) || !pbc_unpack_inherit_record(buf, sz, rec))
          {
            MERROR("PBC INHERIT: REQUEST for missing principal record tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          // Verify request signer matches heir spend key
          if (owner_field.owner_spend_pubkey != rec.heir.m_spend_public_key)
          {
            MERROR("PBC INHERIT: REQUEST signer is not heir tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          std::string payload;
          payload.append(reinterpret_cast<const char*>(&owner_field.owner_spend_pubkey), sizeof(crypto::public_key));
          payload.append(reinterpret_cast<const char*>(&tgt_field.principal_spend_pubkey), sizeof(crypto::public_key));
          const crypto::hash msg_hash = build_msg_hash(PBC_INHERIT_REQUEST_MSG_PREFIX, payload);
          MGINFO("PBC INHERIT: verifying REQUEST sig tx=" << tx_id
            << " heir=" << owner_field.owner_spend_pubkey
            << " principal=" << tgt_field.principal_spend_pubkey
            << " msg_hash=" << msg_hash);
          if (!crypto::check_signature(msg_hash, owner_field.owner_spend_pubkey, sig_field.sig))
          {
            MERROR("PBC INHERIT: invalid REQUEST owner_sig tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          // Store undo
          // Conception v2 (2026-08-14) : le budget de tentatives appartient au CYCLE, pas au
          // principal — un REQUEST démarre (ou redémarre) un cycle. Lues AVANT la remise à 0
          // pour être snapshotées dans l'undo (symétrie : un reorg de CE tx REQUEST doit
          // restaurer le compteur à sa valeur d'avant). L'undo REQUEST était de taille FIXE
          // (PBC_INHERIT_TX_UNDO_SIZE, sans extension) — converti ici en blob variable, même
          // patron de suffixe que SETUP/CANCEL et l'exec-undo ci-dessus.
          pbc_inherit_record prev_rec = rec;
          uint64_t request_prev_attempts = 0;
          m_db->get_property_uint64(pbc_inh_testament_attempts_key(tgt_field.principal_spend_pubkey), request_prev_attempts);
          uint64_t request_prev_exec_key = 0;
          m_db->get_property_uint64(pbc_inh_exec_key(tgt_field.principal_spend_pubkey), request_prev_exec_key);
          {
            std::vector<uint8_t> undo_blob(PBC_INHERIT_TX_UNDO_SIZE + sizeof(uint64_t) + sizeof(uint64_t));
            pbc_make_inherit_tx_undo(true, &prev_rec, undo_blob.data());
            size_t roff = PBC_INHERIT_TX_UNDO_SIZE;
            memcpy(undo_blob.data() + roff, &request_prev_attempts, sizeof(request_prev_attempts)); roff += sizeof(request_prev_attempts);
            memcpy(undo_blob.data() + roff, &request_prev_exec_key, sizeof(request_prev_exec_key)); roff += sizeof(request_prev_exec_key);
            m_db->add_pbc_inherit_tx_undo(tx_id, undo_blob.data(), undo_blob.size());
          }

          // Conception v2 : remise à 0 — un nouveau cycle mérite un budget complet, pas les
          // restes d'un cycle précédent déjà épuisé (§7 conception : corrige le défaut où un
          // re-REQUEST après abandon héritait d'un compteur déjà au plafond).
          if (request_prev_attempts != 0)
            m_db->set_property_uint64(pbc_inh_testament_attempts_key(tgt_field.principal_spend_pubkey), 0);
          if (request_prev_exec_key != 0)
            m_db->set_property_uint64(pbc_inh_exec_key(tgt_field.principal_spend_pubkey), 0);

          // Activate request
          rec.request_active = 1;
          rec.request_height = block_height;
          pbc_pack_inherit_record(rec, buf);
          m_db->add_pbc_inherit_record(tgt_field.principal_spend_pubkey, buf, sizeof(buf));
          MGINFO("PBC INHERIT: REQUEST stored: tx=" << tx_id
            << " heir=" << owner_field.owner_spend_pubkey
            << " principal=" << tgt_field.principal_spend_pubkey
            << " block=" << block_height
            << " transfer_due_at=" << (block_height + PBC_INHERIT_WAIT_BLOCKS));
        }
        else if (type_field.type == PBC_TX_TYPE_INHERIT_CANCEL)
        {
          tx_extra_pbc_inherit_cancel cancel_field;
          if (!get_tx_extra_field_by_type(tx.extra, cancel_field) || !has_owner || !has_sig)
          {
            MERROR("PBC INHERIT: malformed CANCEL tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          uint8_t buf[PBC_INHERIT_RECORD_PACKED_SIZE];
          size_t sz = PBC_INHERIT_RECORD_PACKED_SIZE;
          pbc_inherit_record rec;
          if (!m_db->get_pbc_inherit_record(owner_field.owner_spend_pubkey, buf, sz) || !pbc_unpack_inherit_record(buf, sz, rec))
          {
            MERROR("PBC INHERIT: CANCEL for missing principal record tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          // verify principal signature (payload empty)
          std::string cancel_payload;
          cancel_payload.append(reinterpret_cast<const char*>(&owner_field.owner_spend_pubkey), sizeof(crypto::public_key));
          const crypto::hash msg_hash = build_msg_hash(PBC_INHERIT_CANCEL_MSG_PREFIX, cancel_payload);
          MGINFO("PBC INHERIT: verifying CANCEL sig tx=" << tx_id
            << " principal=" << owner_field.owner_spend_pubkey
            << " msg_hash=" << msg_hash);
          if (!crypto::check_signature(msg_hash, owner_field.owner_spend_pubkey, sig_field.sig))
          {
            MERROR("PBC INHERIT: invalid CANCEL owner_sig tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          // Store undo
          pbc_inherit_record prev_rec = rec;

          // Bug2 fix: read testament snapshot BEFORE deleting it.
          // Same extended undo blob format as SETUP, plus le suffixe attempts+exec_key
          // (Conception v2, 2026-08-14).
          std::vector<uint8_t> cancel_testament_snapshot;
          m_db->get_pbc_inherit_testament(owner_field.owner_spend_pubkey, cancel_testament_snapshot);
          uint64_t cancel_prev_attempts = 0;
          m_db->get_property_uint64(pbc_inh_testament_attempts_key(owner_field.owner_spend_pubkey), cancel_prev_attempts);
          uint64_t cancel_prev_exec_key = 0;
          m_db->get_property_uint64(pbc_inh_exec_key(owner_field.owner_spend_pubkey), cancel_prev_exec_key);
          {
            const uint32_t test_sz = (uint32_t)cancel_testament_snapshot.size();
            const size_t blob_sz = PBC_INHERIT_TX_UNDO_SIZE + sizeof(uint32_t) + test_sz
                                  + sizeof(uint64_t) + sizeof(uint64_t);
            std::vector<uint8_t> undo_blob(blob_sz);
            pbc_make_inherit_tx_undo(true, &prev_rec, undo_blob.data());
            memcpy(undo_blob.data() + PBC_INHERIT_TX_UNDO_SIZE, &test_sz, sizeof(test_sz));
            size_t coff = PBC_INHERIT_TX_UNDO_SIZE + sizeof(test_sz);
            if (test_sz > 0)
            {
              memcpy(undo_blob.data() + coff, cancel_testament_snapshot.data(), test_sz);
              coff += test_sz;
            }
            memcpy(undo_blob.data() + coff, &cancel_prev_attempts, sizeof(cancel_prev_attempts)); coff += sizeof(cancel_prev_attempts);
            memcpy(undo_blob.data() + coff, &cancel_prev_exec_key, sizeof(cancel_prev_exec_key)); coff += sizeof(cancel_prev_exec_key);
            m_db->add_pbc_inherit_tx_undo(tx_id, undo_blob.data(), undo_blob.size());
          }

          // Cancel: remove the full inherit record (heir designation + any pending request).
          // Undo blob already saved above — reorg will restore previous state.
          m_db->remove_pbc_inherit_record(owner_field.owner_spend_pubkey);

          // Bug2 fix: remove testament (it belongs to the cancelled designation).
          // Restored on reorg via the undo blob above.
          if (!cancel_testament_snapshot.empty())
          {
            m_db->remove_pbc_inherit_testament(owner_field.owner_spend_pubkey);
            m_db->remove_pbc_inherit_testament_local(owner_field.owner_spend_pubkey); // v8.2.11 (F-14) : hygiene du cache local RPC
            MGINFO("PBC INHERIT: CANCEL removed testament for principal="
              << owner_field.owner_spend_pubkey << " (saved in undo blob)");
          }

          // Conception v2 (2026-08-14) : hygiène de fin de cycle — le principal n'a plus de
          // désignation active, ces compteurs n'ont plus d'objet tant qu'un nouveau SETUP ne
          // les réutilise pas.
          if (cancel_prev_attempts != 0)
            m_db->set_property_uint64(pbc_inh_testament_attempts_key(owner_field.owner_spend_pubkey), 0);
          if (cancel_prev_exec_key != 0)
            m_db->set_property_uint64(pbc_inh_exec_key(owner_field.owner_spend_pubkey), 0);

          MGINFO("PBC INHERIT: CANCEL executed: tx=" << tx_id
            << " principal=" << owner_field.owner_spend_pubkey
            << " block=" << block_height
            << " record_deleted=true"
            << (prev_rec.request_active ? " (was_request_active=true)" : "")
            << " heir_was=" << prev_rec.heir.m_spend_public_key);
        }
        else if (type_field.type == PBC_TX_TYPE_INHERIT_TESTAMENT)
        {
          // A4 (sous-étape 4) : tx PORTEUR du testament on-chain.
          // Auth (P a signé) + anti-rejeu (séquence) AVANT de stocker — sinon n'importe qui
          // pourrait écraser le testament de P avec un blob bidon (= DoS d'héritage).
          tx_extra_pbc_inherit_testament tst_field;
          if (!get_tx_extra_field_by_type(tx.extra, tst_field) || !has_owner || !has_sig)
          {
            MERROR("PBC TESTAMENT: malformed carrier tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          // Le principal annoncé doit être le signataire (owner_key).
          if (tst_field.principal_spend_pubkey != owner_field.owner_spend_pubkey)
          {
            MERROR("PBC TESTAMENT: principal/owner mismatch tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          // Vérifier la signature de P sur prefix || P || seq || hash(testament).
          const crypto::hash th = crypto::cn_fast_hash(tst_field.testament.data(), tst_field.testament.size());
          std::string tpayload;
          tpayload.append(reinterpret_cast<const char*>(&owner_field.owner_spend_pubkey), sizeof(crypto::public_key));
          tpayload.append(reinterpret_cast<const char*>(&tst_field.seq), sizeof(tst_field.seq));
          tpayload.append(reinterpret_cast<const char*>(&th), sizeof(crypto::hash));
          const crypto::hash msg_hash = build_msg_hash(PBC_INHERIT_TESTAMENT_MSG_PREFIX, tpayload);
          if (!crypto::check_signature(msg_hash, owner_field.owner_spend_pubkey, sig_field.sig))
          {
            MERROR("PBC TESTAMENT: invalid owner_sig tx=" << tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          // Anti-rejeu : la séquence doit être STRICTEMENT > la séquence déjà stockée.
          uint64_t cur_seq = 0;
          m_db->get_property_uint64(pbc_testament_seq_key(owner_field.owner_spend_pubkey), cur_seq);
          if (tst_field.seq <= cur_seq)
          {
            // Périmé / rejeu : on N'ÉCRASE PAS. Ce n'est PAS une erreur de bloc (un porteur
            // retardé peut être miné après un plus récent) -> on ignore proprement.
            MGINFO("PBC TESTAMENT: carrier ignored (stale seq) tx=" << tx_id
              << " principal=" << owner_field.owner_spend_pubkey
              << " seq=" << tst_field.seq << " cur_seq=" << cur_seq);
          }
          else
          {
            // Correctif F2 (2026-08-14, revue croisée sur v8.2.8) : un testament RENOUVELÉ en
            // cours de cycle (nouvelle séquence acceptée) mérite un budget de tentatives
            // complet, pas les restes d'un cycle qui a échoué contre l'ANCIEN contenu — même
            // rationale que SETUP (Bug2 : nouvel héritier -> nouveau testament -> nouveau
            // budget). Un testament renouvelé, même sans changement d'héritier, est un contenu
            // NOUVEAU à essayer ; le pénaliser avec un compteur déjà entamé contre un contenu
            // différent serait injuste et raccourcirait sa vraie fenêtre d'essai. Lues AVANT
            // la remise à 0 pour être snapshotées dans l'undo (même symétrie qu'ailleurs : un
            // reorg de CETTE tx A4 doit restaurer le compteur à sa valeur d'avant).
            uint64_t a4_prev_attempts = 0;
            m_db->get_property_uint64(pbc_inh_testament_attempts_key(owner_field.owner_spend_pubkey), a4_prev_attempts);
            uint64_t a4_prev_exec_key = 0;
            m_db->get_property_uint64(pbc_inh_exec_key(owner_field.owner_spend_pubkey), a4_prev_exec_key);

            // Undo (reorg) : sauver testament + séquence PRÉCÉDENTS.
            // Blob d'undo : [4o prev_test_sz][prev_testament][8o prev_seq]
            //               [8o prev_attempts][8o prev_exec_key]  ← Correctif F2, suffixe
            std::vector<uint8_t> prev_test;
            m_db->get_pbc_inherit_testament(owner_field.owner_spend_pubkey, prev_test);
            const uint32_t prev_sz = (uint32_t)prev_test.size();
            std::vector<uint8_t> undo_blob(sizeof(uint32_t) + prev_sz + sizeof(uint64_t)
                                          + sizeof(uint64_t) + sizeof(uint64_t));
            memcpy(undo_blob.data(), &prev_sz, sizeof(prev_sz));
            if (prev_sz > 0) memcpy(undo_blob.data() + sizeof(uint32_t), prev_test.data(), prev_sz);
            memcpy(undo_blob.data() + sizeof(uint32_t) + prev_sz, &cur_seq, sizeof(cur_seq));
            size_t a4_off = sizeof(uint32_t) + prev_sz + sizeof(cur_seq);
            memcpy(undo_blob.data() + a4_off, &a4_prev_attempts, sizeof(a4_prev_attempts)); a4_off += sizeof(a4_prev_attempts);
            memcpy(undo_blob.data() + a4_off, &a4_prev_exec_key, sizeof(a4_prev_exec_key)); a4_off += sizeof(a4_prev_exec_key);
            m_db->add_pbc_inherit_tx_undo(tx_id, undo_blob.data(), undo_blob.size());

            // Stocker le nouveau testament + séquence.
            m_db->store_pbc_inherit_testament(owner_field.owner_spend_pubkey,
              reinterpret_cast<const uint8_t*>(tst_field.testament.data()), tst_field.testament.size());
            m_db->set_property_uint64(pbc_testament_seq_key(owner_field.owner_spend_pubkey), tst_field.seq);

            // Correctif F2 : remise à 0 effective, après sauvegarde ci-dessus.
            if (a4_prev_attempts != 0)
              m_db->set_property_uint64(pbc_inh_testament_attempts_key(owner_field.owner_spend_pubkey), 0);
            if (a4_prev_exec_key != 0)
              m_db->set_property_uint64(pbc_inh_exec_key(owner_field.owner_spend_pubkey), 0);

            MGINFO("PBC TESTAMENT: stored on-chain testament tx=" << tx_id
              << " principal=" << owner_field.owner_spend_pubkey
              << " seq=" << tst_field.seq << " (prev_seq=" << cur_seq << ")"
              << " blob_size=" << tst_field.testament.size()
              << " attempts_reset=" << (a4_prev_attempts != 0 || a4_prev_exec_key != 0));
          }
        }
      }

      // ══════════════════════════════════════════════════════════════════════════════════
      // Conception v2 (2026-08-14) — Pass 0 : détection déterministe du succès/abandon
      // ══════════════════════════════════════════════════════════════════════════════════
      // Remplace le mécanisme invalidé de v8.2.7 (clôture de request_active pilotée par le
      // résultat local d'add_tx — non déterministe entre nœuds, risque de fork puisque
      // request_active est lu par 2 portes de validation de bloc pouvant rejeter le bloc
      // entier). Ici, l'oracle est purement déterministe : un txid présent en chaîne
      // (tx_exists, identique par construction sur tout nœud partageant la même branche).
      //
      // Pour chaque principal avec request_active==1 ET exec_key>0 (donc déjà tenté au moins
      // une fois) :
      //   • si un txid de la DERNIÈRE tentative est miné → SUCCÈS : clôture, testament retiré.
      //   • sinon, si la fenêtre de grâce K est dépassée ET le plafond de tentatives atteint
      //     → ABANDON : clôture, testament CONSERVÉ (repli consultable, jamais perdu).
      //   • sinon, si la fenêtre K est dépassée mais le plafond n'est pas atteint → RIEN ici :
      //     le principal reste request_active=1 et sera naturellement re-sélectionné par la
      //     Pass 1 (modifiée plus bas) dans CE MÊME bloc, pour une nouvelle tentative.
      //   • sinon (dans la fenêtre de grâce) → RIEN : on attend encore.
      // Aucune de ces décisions ne dépend d'un résultat local (add_tx, contenu du mempool) —
      // uniquement de la hauteur du bloc, du compteur de tentatives, et de tx_exists().
      {
        struct pass0_closure {
          crypto::public_key principal_pk;
          pbc_inherit_record prev_rec;      // état AVANT clôture (request_active=1), pour l'undo
          uint64_t prev_attempts;           // idem, pour l'undo
          bool success;                     // true=succès (retirer le testament), false=abandon (conserver)
          std::vector<uint8_t> attempt_blob_snapshot; // contenu de pbc_inherit_attempt avant purge
          std::vector<uint8_t> testament_snapshot;    // uniquement rempli si success (pour l'undo)
        };
        std::vector<pass0_closure> closures;

        // ── Pass 0a : collecte en lecture seule (même prudence que Pass 1 vis-à-vis du curseur DB) ──
        m_db->for_each_pbc_inherit_record([&](const crypto::public_key& principal_pk, const void* data, size_t data_size) {
          pbc_inherit_record rec;
          if (!pbc_unpack_inherit_record(static_cast<const uint8_t*>(data), data_size, rec))
            return true;
          if (!rec.request_active)
            return true;
          uint64_t exec_h = 0;
          if (!m_db->get_property_uint64(pbc_inh_exec_key(principal_pk), exec_h) || exec_h == 0)
            return true; // jamais tenté — rien à évaluer, la Pass 1 s'en chargera normalement

          std::vector<uint8_t> att_blob;
          const bool has_attempt = m_db->get_pbc_inherit_attempt(principal_pk, att_blob);

          bool mined = false;
          if (has_attempt && att_blob.size() >= sizeof(uint32_t))
          {
            uint32_t cnt = 0;
            memcpy(&cnt, att_blob.data(), sizeof(cnt));
            const size_t need = sizeof(uint32_t) + (size_t)cnt * sizeof(crypto::hash);
            if (att_blob.size() >= need)
            {
              const uint8_t* q = att_blob.data() + sizeof(uint32_t);
              for (uint32_t i = 0; i < cnt && !mined; ++i)
              {
                crypto::hash tid;
                memcpy(&tid, q, sizeof(tid));
                q += sizeof(tid);
                if (have_tx(tid))
                  mined = true;
              }
            }
          }

          uint64_t attempts = 0;
          m_db->get_property_uint64(pbc_inh_testament_attempts_key(principal_pk), attempts);

          if (mined)
          {
            pass0_closure c;
            c.principal_pk = principal_pk;
            c.prev_rec = rec;
            c.prev_attempts = attempts;
            c.success = true;
            c.attempt_blob_snapshot = att_blob;
            m_db->get_pbc_inherit_testament(principal_pk, c.testament_snapshot);
            closures.push_back(std::move(c));
            fprintf(stderr, "PBC INHERIT PASS0: SUCCES (txid mine) principal=%s\n",
              epee::string_tools::pod_to_hex(principal_pk).c_str()); fflush(stderr);
          }
          else if (block_height >= exec_h + PBC_INHERIT_SWEEP_CONFIRM_BLOCKS)
          {
            if (attempts >= PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS)
            {
              pass0_closure c;
              c.principal_pk = principal_pk;
              c.prev_rec = rec;
              c.prev_attempts = attempts;
              c.success = false; // ABANDON : testament conservé
              c.attempt_blob_snapshot = att_blob;
              closures.push_back(std::move(c));
              fprintf(stderr, "PBC INHERIT PASS0: ABANDON (plafond %llu atteint) principal=%s\n",
                (unsigned long long)PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS,
                epee::string_tools::pod_to_hex(principal_pk).c_str()); fflush(stderr);
            }
            // sinon : rien — la Pass 1 (modifiée) re-sélectionnera ce principal dans CE bloc.
          }
          // sinon (encore dans la fenêtre de grâce K) : rien.
          return true;
        });

        // ── Pass 0b : écriture des clôtures collectées ──
        for (const auto& c : closures)
        {
          // Undo AVANT toute modification — symétrique au patron déjà en place pour
          // SETUP/REQUEST/CANCEL/exécution : sans cet undo, un reorg du bloc de clôture
          // laisserait request_active bloqué à 0 (et, en cas de succès, le testament perdu)
          // sans jamais être restauré, puisque la Pass 0 ne re-scannerait plus ce principal
          // (sa propre porte d'entrée exige request_active==1).
          {
            uint8_t prev_buf[PBC_INHERIT_RECORD_PACKED_SIZE];
            pbc_pack_inherit_record(c.prev_rec, prev_buf);
            const uint8_t tag = c.success ? (uint8_t)'S' : (uint8_t)'A';
            const uint32_t testament_size = c.success ? (uint32_t)c.testament_snapshot.size() : 0;
            const uint32_t att_size = (uint32_t)c.attempt_blob_snapshot.size();
            const size_t blob_size = 1 + 32 + PBC_INHERIT_RECORD_PACKED_SIZE + sizeof(uint64_t)
                                   + sizeof(uint32_t) + testament_size
                                   + sizeof(uint32_t) + att_size;
            std::vector<uint8_t> undo_blob(blob_size);
            size_t off = 0;
            undo_blob[off] = tag; off += 1;
            memcpy(undo_blob.data() + off, &c.principal_pk, sizeof(c.principal_pk)); off += sizeof(c.principal_pk);
            memcpy(undo_blob.data() + off, prev_buf, PBC_INHERIT_RECORD_PACKED_SIZE); off += PBC_INHERIT_RECORD_PACKED_SIZE;
            memcpy(undo_blob.data() + off, &c.prev_attempts, sizeof(c.prev_attempts)); off += sizeof(c.prev_attempts);
            memcpy(undo_blob.data() + off, &testament_size, sizeof(testament_size)); off += sizeof(testament_size);
            if (testament_size > 0)
            {
              memcpy(undo_blob.data() + off, c.testament_snapshot.data(), testament_size);
              off += testament_size;
            }
            memcpy(undo_blob.data() + off, &att_size, sizeof(att_size)); off += sizeof(att_size);
            if (att_size > 0)
            {
              memcpy(undo_blob.data() + off, c.attempt_blob_snapshot.data(), att_size);
              off += att_size;
            }
            m_db->add_pbc_inherit_close_undo(block_height, c.principal_pk, undo_blob.data(), undo_blob.size());
          }

          // Clôture : request_active=0 déterministe (fait de chaîne : txid miné, ou hauteur
          // + plafond atteints — jamais un résultat local).
          {
            pbc_inherit_record closed = c.prev_rec;
            closed.request_active = 0;
            closed.request_height = 0;
            uint8_t out[PBC_INHERIT_RECORD_PACKED_SIZE];
            pbc_pack_inherit_record(closed, out);
            m_db->add_pbc_inherit_record(c.principal_pk, out, sizeof(out));
          }

          if (c.success)
          {
            m_db->remove_pbc_inherit_testament(c.principal_pk);
            m_db->remove_pbc_inherit_testament_local(c.principal_pk); // v8.2.11 (F-14) : hygiene du cache local RPC
            MINFO("PBC INHERIT PASS0: succès confirmé (txid miné), testament retiré, cycle clos, principal="
              << c.principal_pk);
          }
          else
          {
            MWARNING("PBC INHERIT PASS0: abandon définitif après " << PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS
              << " tentatives sans succès — testament CONSERVÉ (repli consultable), cycle clos, principal="
              << c.principal_pk);
          }

          m_db->remove_pbc_inherit_attempt(c.principal_pk);
          m_db->set_property_uint64(pbc_inh_testament_attempts_key(c.principal_pk), 0);
        }
      }

      // Execute due requests: if request_active and no principal activity since request.
      // Transfers deposit ownership (owner_key) from principal to heir spend key.
      // ── Pass 1: Collect inherit execution jobs (read-only iteration, no DB writes) ──
      struct inherit_exec_job {
        crypto::public_key principal_pk;
        pbc_inherit_record rec;
      };
      std::vector<inherit_exec_job> inherit_jobs;

      m_db->for_each_pbc_inherit_record([&](const crypto::public_key& principal_pk, const void* data, size_t data_size) {
        pbc_inherit_record rec;
        if (!pbc_unpack_inherit_record(static_cast<const uint8_t*>(data), data_size, rec))
          return true;
        if (!rec.request_active)
          return true;
        if (block_height < rec.request_height + PBC_INHERIT_WAIT_BLOCKS)
          return true;
        if (rec.last_activity_height > rec.request_height)
          return true;

        // Conception v2 (2026-08-14) : si une tentative a déjà eu lieu pour ce principal
        // (exec_key posé par une Pass 2 antérieure — request_active n'est plus jamais remis
        // à 0 par la Pass 2 elle-même, voir plus haut), n'en retenter une nouvelle que si la
        // fenêtre de grâce K est dépassée. Sous ce seuil, la Pass 0 (plus haut, déjà exécutée
        // pour ce bloc) a déjà tranché : succès (request_active==0, on ne serait pas ici) ou
        // encore en attente (rien fait, on patiente). Le plafond de tentatives n'a PAS besoin
        // d'être revérifié ici : si atteint, la Pass 0 a déjà clos (request_active==0) dans ce
        // même bloc, avant que cette Pass 1 ne s'exécute — donc rec.request_active==1 ici
        // implique déjà attempts < plafond.
        {
          uint64_t exec_h = 0;
          if (m_db->get_property_uint64(pbc_inh_exec_key(principal_pk), exec_h) && exec_h > 0
              && block_height < exec_h + PBC_INHERIT_SWEEP_CONFIRM_BLOCKS)
            return true;
        }

        fprintf(stderr, "PBC INHERIT EXECUTING principal=%s height=%" PRIu64 "\n",
          epee::string_tools::pod_to_hex(principal_pk).c_str(), block_height); fflush(stderr);
        inherit_jobs.push_back({principal_pk, rec});
        return true;
      });

      // ── Pass 2: Execute DB writes + parse testament TXs (no add_tx yet) ──
      struct broadcast_job {
        cryptonote::transaction tx;
        crypto::hash txid;
      };
      std::vector<broadcast_job> broadcast_jobs;
      // Conception v2 (2026-08-14) : testament_to_remove n'existe plus — la suppression du
      // testament n'a désormais lieu qu'en Pass 0, sur succès déterministe (txid miné), jamais
      // en Pass 3 sur la base du résultat local d'add_tx.

      for (auto& job : inherit_jobs)
      {
        const crypto::public_key& principal_pk = job.principal_pk;
        pbc_inherit_record& rec = job.rec;

        // Snapshot testament blob BEFORE it is consumed — needed for exec_undo restoration
        // If a reorg pops this execution block, pop_block will re-store this blob.
        std::vector<uint8_t> testament_snapshot;
        m_db->get_pbc_inherit_testament(principal_pk, testament_snapshot);

        // Collect deposit ids owned by principal (read-only scan)
        std::vector<crypto::hash> changed;
        fprintf(stderr, "PBC for_each_pbc_deposit (inherit pass1) ENTER\n"); fflush(stderr);
        m_db->for_each_pbc_deposit([&](const crypto::hash& dep_id, const void* dep_data, size_t dep_size) {
          if (dep_size < PBC_DEPOSIT_RECORD_PACKED_SIZE)
            return true;
          pbc_deposit_record drec;
          pbc_unpack_deposit_record(static_cast<const uint8_t*>(dep_data), dep_size, drec);
          if (drec.owner_key == principal_pk)
            changed.push_back(dep_id);
          return true;
        });

        // Write: update each deposit owner_key by delete+reinsert
        for (const auto& dep_id : changed)
        {
          uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
          size_t dep_sz = PBC_DEPOSIT_RECORD_PACKED_SIZE;
          if (!m_db->get_pbc_deposit(dep_id, dep_buf, dep_sz))
            continue;
          if (dep_sz < PBC_DEPOSIT_RECORD_PACKED_SIZE)
            continue;
          pbc_deposit_record drec;
          pbc_unpack_deposit_record(dep_buf, dep_sz, drec);
          if (drec.owner_key != principal_pk)
            continue;
          drec.owner_key = rec.heir.m_spend_public_key;
          uint8_t out[PBC_DEPOSIT_RECORD_PACKED_SIZE];
          pbc_pack_deposit_record(drec, out);
          m_db->remove_pbc_deposit(dep_id);
          m_db->add_pbc_deposit(dep_id, out, sizeof(out));
        }

        // Conception v2 (2026-08-14) : lire l'état AVANT cette tentative — nécessaire pour
        // le snapshoter dans le blob d'undo étendu ci-dessous (permet à un reorg de cette
        // tentative de restaurer le compteur et la fenêtre mempool à leur valeur d'avant).
        uint64_t prev_attempts_for_undo = 0;
        m_db->get_property_uint64(pbc_inh_testament_attempts_key(principal_pk), prev_attempts_for_undo);
        uint64_t prev_exec_key_for_undo = 0;
        m_db->get_property_uint64(pbc_inh_exec_key(principal_pk), prev_exec_key_for_undo);

        // Write: save undo record
        // Always write undo even if no deposits were transferred (changed.empty()).
        // An execution can still consume the testament and clear request_active with zero
        // deposits transferred — without an undo blob, a reorg cannot restore that state.
        {
          uint8_t prev_buf[PBC_INHERIT_RECORD_PACKED_SIZE];
          pbc_pack_inherit_record(rec, prev_buf);
          const uint32_t count = (uint32_t)changed.size();
          // Blob layout :
          //   [32]          principal_pk
          //   [N]           prev_rec (PBC_INHERIT_RECORD_PACKED_SIZE)
          //   [4]           count          ← peut être 0 si aucun dépôt transféré
          //   [32 * count]  deposit ids    ← absent si count == 0
          //   [4]           testament_size ← 0 si pas de testament au moment de l'exécution
          //   [testament_size] testament_blob ← octets verbatim depuis LMDB
          //   [8]           prev_attempts  ← Conception v2 : compteur AVANT cette tentative
          //   [8]           prev_exec_key  ← Conception v2 : exec_key AVANT cette tentative
          // Les 16 derniers octets sont une extension par SUFFIXE (même principe que
          // l'extension testament ci-dessus) : un ancien lecteur qui ignorerait ce suffixe
          // resterait fonctionnel sur le reste du blob.
          const uint32_t testament_size = (uint32_t)testament_snapshot.size();
          const size_t blob_size = 32 + PBC_INHERIT_RECORD_PACKED_SIZE + 4
                                 + count * sizeof(crypto::hash)
                                 + sizeof(uint32_t) + testament_size
                                 + sizeof(uint64_t) + sizeof(uint64_t);
          std::vector<uint8_t> blob(blob_size);
          size_t off = 0;
          memcpy(blob.data() + off, &principal_pk, sizeof(principal_pk)); off += sizeof(principal_pk);
          memcpy(blob.data() + off, prev_buf, PBC_INHERIT_RECORD_PACKED_SIZE); off += PBC_INHERIT_RECORD_PACKED_SIZE;
          memcpy(blob.data() + off, &count, 4); off += 4;
          for (const auto& id : changed)
          {
            memcpy(blob.data() + off, &id, sizeof(id));
            off += sizeof(id);
          }
          // Append testament snapshot (4-byte size header + raw blob)
          memcpy(blob.data() + off, &testament_size, sizeof(testament_size)); off += sizeof(testament_size);
          if (testament_size > 0)
          {
            memcpy(blob.data() + off, testament_snapshot.data(), testament_size);
            off += testament_size;
          }
          // Conception v2 : suffixe attempts+exec_key (16 octets)
          memcpy(blob.data() + off, &prev_attempts_for_undo, sizeof(prev_attempts_for_undo)); off += sizeof(prev_attempts_for_undo);
          memcpy(blob.data() + off, &prev_exec_key_for_undo, sizeof(prev_exec_key_for_undo)); off += sizeof(prev_exec_key_for_undo);
          m_db->add_pbc_inherit_exec_undo(block_height, principal_pk, blob.data(), blob.size());
          MINFO("PBC INHERIT EXEC UNDO: saved undo blob for principal=" << principal_pk
            << " deposits=" << count << " testament_size=" << testament_size
            << " prev_attempts=" << prev_attempts_for_undo << " prev_exec_key=" << prev_exec_key_for_undo);
        }

        // v8.2.11 (finding croissance non bornée) : élagage amorti des undo d'héritage plus
        // vieux que l'horizon. Déterministe (fonction de block_height uniquement — tous les
        // nœuds élaguent aux mêmes hauteurs), thread propriétaire du batch. Garde
        // anti-underflow : rien à élaguer tant que la chaîne est plus jeune que l'horizon.
        {
          static constexpr uint64_t PBC_INHERIT_UNDO_KEEP_DEPTH = 100800; // > 2× le reorg le plus profond observé (44 700)
          if (block_height > PBC_INHERIT_UNDO_KEEP_DEPTH)
            m_db->prune_pbc_inherit_undos_below(block_height - PBC_INHERIT_UNDO_KEEP_DEPTH);
        }

        // Conception v2 (2026-08-14) — POINT CLÉ : request_active N'EST PLUS JAMAIS ÉCRIT ICI.
        // En v8.2.7, cette écriture était rendue conditionnelle au résultat LOCAL de add_tx
        // (Pass 3) — ce qui rendait request_active non-déterministe entre nœuds, alors qu'il
        // est lu par 2 portes de validation de bloc (LOCK_COLLATERAL, TRANSFER_DEPOSIT) pouvant
        // rejeter le bloc ENTIER. Risque de fork identifié et confirmé par relecture adverse.
        // Ici, request_active reste à 1 pendant TOUTE la phase de retry ; SEULE la Pass 0
        // (plus bas dans cette fonction, exécutée avant la Pass 1 à CHAQUE bloc) le modifie,
        // et uniquement sur un fait de chaîne déterministe : un txid miné (succès), ou une
        // hauteur atteinte combinée au plafond de tentatives (abandon). Aucune trace du
        // résultat d'add_tx n'entre plus jamais dans une donnée lue par une porte de bloc.

        // A3: marquer l'héritage comme EXÉCUTÉ à cette hauteur — à CHAQUE tentative, pas
        // seulement la première. Sert (a) au gate mempool [exec_h, exec_h+WINDOW], qui doit
        // rester ouvert tant que des tentatives ont lieu, et (b) d'ancre déterministe pour la
        // garde de retry de la Pass 1/Pass 0 (fonction pure de la hauteur, identique partout).
        m_db->set_property_uint64(pbc_inh_exec_key(principal_pk), block_height);
        MINFO("PBC INHERIT GATE: executed[" << principal_pk << "]=" << block_height);

        MINFO("PBC INHERIT EXECUTED at block=" << block_height
          << " principal=" << principal_pk
          << " heir=" << rec.heir.m_spend_public_key
          << " deposits_transferred=" << changed.size());

        // Testament: parse TXs and collect broadcast jobs (no add_tx yet)
        {
#define TLOG(fmt, ...) do { \
  MINFO("PBC TESTAMENT: " fmt); \
  fprintf(stderr, "PBC TESTAMENT: " fmt "\n", ##__VA_ARGS__); \
  fflush(stderr); \
} while(0)
#define TERR(fmt, ...) do { \
  MERROR("PBC TESTAMENT: " fmt); \
  fprintf(stderr, "PBC TESTAMENT ERROR: " fmt "\n", ##__VA_ARGS__); \
  fflush(stderr); \
} while(0)

          fprintf(stderr, "PBC TESTAMENT: [DBG-1] entering testament broadcast block principal=%s\n",
            epee::string_tools::pod_to_hex(principal_pk).c_str());
          fflush(stderr);
          MINFO("PBC TESTAMENT: [DBG-1] entering testament broadcast block principal=" << principal_pk);

          // Re-use snapshot read before deposit scan (already saved in exec_undo blob)
          const std::vector<uint8_t>& testament_blob = testament_snapshot;
          const bool has_testament = !testament_snapshot.empty();
          fprintf(stderr, "PBC TESTAMENT: [DBG-3] has=%d blob_size=%zu (from snapshot)\n", (int)has_testament, testament_blob.size()); fflush(stderr);
          MINFO("PBC TESTAMENT: [DBG-3] testament snapshot has=" << has_testament << " blob_size=" << testament_blob.size());

          // Correctif F1 (2026-08-14, revue croisée sur v8.2.8) : les trois chemins où il n'y
          // a STRUCTURELLEMENT rien à diffuser (pas de testament, tx_count hors [1..64], ou
          // aucune TX n'a survécu au parsing) posaient exec_key SANS incrémenter le compteur
          // ni écrire d'entrée de tentative. Or Pass 0 ne peut clore (succès OU abandon) que
          // pour un principal dont exec_key>0 ET dont le compteur atteint le plafond — sans
          // incrément, ces trois cas rebouclaient indéfiniment toutes les K=20 blocs, sans
          // jamais atteindre PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS. Le commentaire qui affirmait
          // « le plafond finira par abandonner » était donc FAUX tel que le code était écrit —
          // corrigé plus bas pour refléter le comportement réel une fois ce correctif appliqué.
          //
          // Ces trois cas sont des tentatives à part entière : le testament (ou son absence)
          // au moment de l'exécution est une donnée CHAÎNÉE (portée par la TX porteuse A4,
          // identique sur tout nœud), donc les compter comme tentative reste déterministe —
          // rien ici ne dépend d'un résultat local (add_tx, mempool). On les compte plutôt que
          // de clore immédiatement en Pass 2 : plus simple (aucune nouvelle écriture d'état
          // consensus ici, la machine Pass 0/Pass 1 existante suffit inchangée), et cohérent
          // avec la politique déjà en place pour une cause véritablement permanente (frais
          // insuffisants, etc.) : on épuise le budget normalement, borné à ~1000 blocs.
          //
          // On purge aussi tout attempt-blob laissé par une tentative ANTÉRIEURE (avec un
          // testament différent, remplacé depuis via une nouvelle TX porteuse A4) — sinon la
          // Pass 0 évaluerait des txids obsolètes, sans rapport avec CETTE tentative-ci.
          auto record_empty_attempt = [&](const char* reason) {
            const uint64_t new_attempts = prev_attempts_for_undo + 1;
            m_db->set_property_uint64(pbc_inh_testament_attempts_key(principal_pk), new_attempts);
            m_db->remove_pbc_inherit_attempt(principal_pk);
            fprintf(stderr, "PBC TESTAMENT: [DBG-13c] tentative %llu/%llu comptee, RIEN A DIFFUSER (%s)\n",
              (unsigned long long)new_attempts, (unsigned long long)PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS, reason); fflush(stderr);
            MWARNING("PBC TESTAMENT: [DBG-13c] tentative " << new_attempts << "/" << PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS
              << " comptée sans rien à diffuser (" << reason << ") pour principal=" << principal_pk);
          };

          if (has_testament && testament_blob.size() >= sizeof(uint32_t))
          {
            const uint8_t* p = testament_blob.data();
            const uint8_t* end = p + testament_blob.size();
            uint32_t tx_count = 0;
            memcpy(&tx_count, p, sizeof(tx_count)); p += sizeof(tx_count);
            fprintf(stderr, "PBC TESTAMENT: [DBG-4] tx_count=%u blob_size=%zu\n", (unsigned)tx_count, testament_blob.size()); fflush(stderr);
            MINFO("PBC TESTAMENT: [DBG-4] tx_count=" << tx_count << " blob_size=" << testament_blob.size() << " for principal=" << principal_pk);

            if (tx_count == 0 || tx_count > 64)
            {
              fprintf(stderr, "PBC TESTAMENT: [DBG-4b] tx_count=%u out of range [1..64] — aborting broadcast\n", (unsigned)tx_count); fflush(stderr);
              MERROR("PBC TESTAMENT: [DBG-4b] tx_count=" << tx_count << " out of range [1..64] — blob may be corrupted, aborting broadcast");
              record_empty_attempt("tx_count hors [1..64] — blob corrompu");
            }
            else
            {
              // Conception v2 (2026-08-14) : liste des txids VALABLEMENT parsés à cette
              // tentative — sauvegardée après la boucle dans la table pbc_inherit_attempt,
              // lue par la Pass 0 aux blocs suivants pour évaluer déterministiquement le
              // succès (txid miné) sans dépendre du résultat local de add_tx (Pass 3).
              std::vector<crypto::hash> attempt_txids;
              for (uint32_t i = 0; i < tx_count && p + sizeof(uint32_t) <= end; ++i)
              {
                fprintf(stderr, "PBC TESTAMENT: [DBG-5] TX[%u] reading len offset=%zu\n", (unsigned)i, (size_t)(p - testament_blob.data())); fflush(stderr);
                MINFO("PBC TESTAMENT: [DBG-5] TX[" << i << "] reading len, offset=" << (p - testament_blob.data()));
                uint32_t len = 0;
                memcpy(&len, p, sizeof(len)); p += sizeof(len);
                fprintf(stderr, "PBC TESTAMENT: [DBG-6] TX[%u] len=%u remaining=%zu\n", (unsigned)i, (unsigned)len, (size_t)(end - p)); fflush(stderr);
                MINFO("PBC TESTAMENT: [DBG-6] TX[" << i << "] len=" << len << " remaining_blob=" << (end - p));

                if (p + len > end)
                {
                  fprintf(stderr, "PBC TESTAMENT: [DBG-6b] blob truncated TX[%u] len=%u remaining=%zu\n", (unsigned)i, (unsigned)len, (size_t)(end - p)); fflush(stderr);
                  MERROR("PBC TESTAMENT: [DBG-6b] testament blob truncated at TX " << i << " len=" << len << " remaining=" << (end - p));
                  break;
                }

                fprintf(stderr, "PBC TESTAMENT: [DBG-7] TX[%u] constructing blobdata len=%u\n", (unsigned)i, (unsigned)len); fflush(stderr);
                MINFO("PBC TESTAMENT: [DBG-7] TX[" << i << "] constructing blobdata len=" << len);
                blobdata tx_blob;
                try {
                  tx_blob = blobdata(reinterpret_cast<const char*>(p), len);
                } catch (const std::bad_alloc& e) {
                  fprintf(stderr, "PBC TESTAMENT: [DBG-7-BADALLOC] bad_alloc constructing blobdata TX[%u] len=%u — %s\n", (unsigned)i, (unsigned)len, e.what()); fflush(stderr);
                  MERROR("PBC TESTAMENT: [DBG-7-BADALLOC] bad_alloc constructing blobdata TX[" << i << "] len=" << len);
                  p += len;
                  continue;
                }
                p += len;

                fprintf(stderr, "PBC TESTAMENT: [DBG-8] TX[%u] calling parse_and_validate_tx_from_blob\n", (unsigned)i); fflush(stderr);
                MINFO("PBC TESTAMENT: [DBG-8] TX[" << i << "] calling parse_and_validate_tx_from_blob");
                cryptonote::transaction tx;
                crypto::hash txid;
                bool parsed = false;
                try {
                  parsed = parse_and_validate_tx_from_blob(tx_blob, tx, txid);
                } catch (const std::bad_alloc& e) {
                  fprintf(stderr, "PBC TESTAMENT: [DBG-8-BADALLOC] bad_alloc in parse_and_validate TX[%u] — %s\n", (unsigned)i, e.what()); fflush(stderr);
                  MERROR("PBC TESTAMENT: [DBG-8-BADALLOC] bad_alloc in parse_and_validate TX[" << i << "]");
                  continue;
                } catch (const std::exception& e) {
                  fprintf(stderr, "PBC TESTAMENT: [DBG-8-EXC] exception in parse_and_validate TX[%u] — %s\n", (unsigned)i, e.what()); fflush(stderr);
                  MERROR("PBC TESTAMENT: [DBG-8-EXC] exception in parse_and_validate TX[" << i << "]: " << e.what());
                  continue;
                }
                if (!parsed)
                {
                  fprintf(stderr, "PBC TESTAMENT: [DBG-8b] TX[%u] failed to parse — skipping\n", (unsigned)i); fflush(stderr);
                  MERROR("PBC TESTAMENT: [DBG-8b] TX " << i << " failed to parse — skipping");
                  continue;
                }
                fprintf(stderr, "PBC TESTAMENT: [DBG-9] TX[%u] parsed OK — queuing for mempool txid=%s\n",
                  (unsigned)i, epee::string_tools::pod_to_hex(txid).c_str()); fflush(stderr);
                MINFO("PBC TESTAMENT: [DBG-9] TX[" << i << "] parsed OK txid=" << txid << " — queuing for mempool");
                broadcast_jobs.push_back({tx, txid});
                attempt_txids.push_back(txid);
              }

              // Conception v2 (2026-08-14) — remplace "Testament will be removed in Pass 3" :
              // la Pass 3 ne supprime plus rien (voir plus bas). Ici : (a) incrémenter le
              // compteur de tentatives du CYCLE, (b) sauvegarder la liste des txids valablement
              // parsés — c'est l'oracle que la Pass 0 relira aux blocs suivants pour décider,
              // de façon purement déterministe (tx_exists), si CETTE tentative a réussi.
              if (!attempt_txids.empty())
              {
                const uint64_t new_attempts = prev_attempts_for_undo + 1;
                m_db->set_property_uint64(pbc_inh_testament_attempts_key(principal_pk), new_attempts);

                const uint32_t att_count = (uint32_t)attempt_txids.size();
                std::vector<uint8_t> att_blob(sizeof(att_count) + att_count * sizeof(crypto::hash));
                size_t att_off = 0;
                memcpy(att_blob.data() + att_off, &att_count, sizeof(att_count)); att_off += sizeof(att_count);
                for (const auto& tid : attempt_txids)
                {
                  memcpy(att_blob.data() + att_off, &tid, sizeof(tid));
                  att_off += sizeof(tid);
                }
                m_db->store_pbc_inherit_attempt(principal_pk, att_blob.data(), att_blob.size());

                fprintf(stderr, "PBC TESTAMENT: [DBG-13] tentative %llu/%llu enregistree, %u txid(s) — Pass 0 evaluera aux blocs suivants\n",
                  (unsigned long long)new_attempts, (unsigned long long)PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS, (unsigned)att_count); fflush(stderr);
                MINFO("PBC TESTAMENT: [DBG-13] tentative " << new_attempts << "/" << PBC_INHERIT_TESTAMENT_MAX_ATTEMPTS
                  << " enregistrée pour principal=" << principal_pk << " (" << att_count << " txid(s))");
              }
              else
              {
                // Correctif F1 : aucune TX n'a survécu au parsing (toutes tronquées/corrompues)
                // — compte quand même comme une tentative (voir record_empty_attempt ci-dessus).
                // Re-tenter un blob dont TOUTES les TX sont corrompues ne changerait rien (le
                // blob ne varie pas avec la hauteur, sauf remplacement par une nouvelle TX
                // porteuse A4) : le plafond ATTEINDRA bien 50 avec ce correctif, et Pass 0
                // abandonnera alors proprement (testament conservé en base, cf. Pass 0 ABANDON).
                fprintf(stderr, "PBC TESTAMENT: [DBG-13b] aucune TX n'a survecu au parsing — rien enregistre\n"); fflush(stderr);
                MWARNING("PBC TESTAMENT: [DBG-13b] aucune TX valablement parsée pour principal=" << principal_pk);
                record_empty_attempt("aucune TX n'a survécu au parsing");
              }
            } // end tx_count range check
          }
          else
          {
            fprintf(stderr, "PBC TESTAMENT: [DBG-3b] no testament found for principal — liquid balance NOT transferred\n"); fflush(stderr);
            MWARNING("PBC TESTAMENT: no testament found for principal=" << principal_pk
              << " — liquid balance will NOT be transferred to heir");
            // Correctif F1 : absence de testament est TOUJOURS une donnée chaînée (le porteur
            // A4, ou son absence, est identique sur tout nœud) — compter comme une tentative
            // vide permet au cycle d'atteindre le plafond et d'être clos par Pass 0, plutôt que
            // de reboucler indéfiniment toutes les K blocs sans jamais progresser.
            record_empty_attempt("aucun testament trouvé");
          }
          fprintf(stderr, "PBC TESTAMENT: [DBG-15] exiting testament broadcast block\n"); fflush(stderr);
          MINFO("PBC TESTAMENT: [DBG-15] exiting testament broadcast block");

#undef TLOG
#undef TERR
        }
      } // end pass 2

      // ── Pass 3: Submit collected TXs to mempool (outside all DB iteration) ──
      {
        uint32_t submitted = 0, failed = 0;
        const uint8_t hf_ver = m_hardfork->get_current_version();
        for (auto& bj : broadcast_jobs)
        {
          tx_verification_context tvc{};
          fprintf(stderr, "PBC TESTAMENT: [DBG-10] calling add_tx txid=%s hf_ver=%d\n",
            epee::string_tools::pod_to_hex(bj.txid).c_str(), (int)hf_ver); fflush(stderr);
          MINFO("PBC TESTAMENT: [DBG-10] hf_ver=" << (int)hf_ver << " calling m_tx_pool.add_tx txid=" << bj.txid);

          bool add_ok = false;
          try {
            add_ok = m_tx_pool.add_tx(bj.tx, tvc, relay_method::fluff, /*relayed=*/false, hf_ver, hf_ver);
          } catch (const std::bad_alloc& e) {
            fprintf(stderr, "PBC TESTAMENT: [DBG-10-BADALLOC] bad_alloc in add_tx — %s\n", e.what()); fflush(stderr);
            MERROR("PBC TESTAMENT: [DBG-10-BADALLOC] bad_alloc in add_tx txid=" << bj.txid);
            ++failed;
            continue;
          } catch (const std::exception& e) {
            fprintf(stderr, "PBC TESTAMENT: [DBG-10-EXC] exception in add_tx — %s\n", e.what()); fflush(stderr);
            MERROR("PBC TESTAMENT: [DBG-10-EXC] exception in add_tx txid=" << bj.txid << ": " << e.what());
            ++failed;
            continue;
          }

          if (!add_ok)
          {
            fprintf(stderr, "PBC TESTAMENT: [DBG-10b] TX rejected double_spend=%d failed=%d txid=%s\n",
              (int)tvc.m_double_spend, (int)tvc.m_verifivation_failed,
              epee::string_tools::pod_to_hex(bj.txid).c_str()); fflush(stderr);
            MERROR("PBC TESTAMENT: [DBG-10b] txid=" << bj.txid
              << " rejected by mempool: double_spend=" << tvc.m_double_spend
              << " failed=" << tvc.m_verifivation_failed);
            ++failed;
          }
          else
          {
            fprintf(stderr, "PBC TESTAMENT: [DBG-11] TX added to mempool OK txid=%s\n",
              epee::string_tools::pod_to_hex(bj.txid).c_str()); fflush(stderr);
            MINFO("PBC TESTAMENT: [DBG-11] txid=" << bj.txid << " added to mempool OK");
            ++submitted;
          }
        }
        if (!broadcast_jobs.empty())
        {
          fprintf(stderr, "PBC TESTAMENT: [DBG-12] broadcast complete submitted=%u failed=%u\n",
            (unsigned)submitted, (unsigned)failed); fflush(stderr);
          MINFO("PBC TESTAMENT: [DBG-12] broadcast complete submitted=" << submitted << " failed=" << failed);
        }

        // Conception v2 (2026-08-14) : AUCUNE écriture d'état ne dépend plus de submitted/failed
        // ci-dessus — c'est le cœur du correctif. En v8.2.7, cette section retirait le testament
        // et/ou clôturait request_active sur la base de ce résultat LOCAL (résultat d'add_tx,
        // qui dépend du mempool de CE nœud — m_timed_out_transactions, key images déjà dans le
        // pool local). Or request_active est lu par 2 portes de validation de bloc pouvant
        // rejeter le bloc ENTIER (LOCK_COLLATERAL, TRANSFER_DEPOSIT) : rendre son état
        // dépendant d'un résultat local ouvrait un risque de fork — identifié et confirmé par
        // relecture adverse sur v8.2.7, qui a été invalidée pour cette raison.
        // Ici, submitted/failed ne servent plus qu'au log [DBG-12] ci-dessus, à but diagnostic.
        // La décision "cette tentative a-t-elle réussi ?" est entièrement déplacée en Pass 0
        // (plus bas), qui l'évalue à un bloc ULTÉRIEUR sur un fait de chaîne déterministe —
        // tx_exists(txid) — identique par construction sur tout nœud ayant la même branche.
      } // end pass 3

      // ── TD-8: Anti-split: Build active deposit count per owner_key ──
      // Iterates ALL existing deposits once. For each active deposit
      // (created < block_height < unlock), reads owner_key directly from
      // the deposit record (stored at creation, no get_tx() needed).
      std::unordered_map<crypto::public_key, uint32_t> active_deposit_counts;
      bool legacy_pbc_deposit_records_present = false; // TD-8: require owner_key-aware records
      m_db->for_each_pbc_deposit([&](const crypto::hash& dep_id, const void* data, size_t data_size) {
        if (data_size < PBC_DEPOSIT_RECORD_PACKED_SIZE)
        {
          legacy_pbc_deposit_records_present = true;
          return true;
        }
        pbc_deposit_record existing_rec;
        pbc_unpack_deposit_record(static_cast<const uint8_t*>(data), data_size, existing_rec);
        if (existing_rec.created_height < block_height && existing_rec.unlock_height > block_height)
        {
          if (existing_rec.owner_key != crypto::null_pkey)
            active_deposit_counts[existing_rec.owner_key]++;
        }
        return true;
      });

      // ── TD-2: Validate + store term deposit TXs (§19.12 Step 4) ──
      // Consensus-critical: invalid deposits → block rejected.
      // Processing is SEQUENTIAL in block order (§19.12 Step 4 rule).
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& dep_tx = txs[i].first;
        const crypto::hash& tx_id = std::get<0>(txs_meta[i]);
        pbc_deposit_record dep_rec;
        std::string fail_reason;

        pbc_deposit_result result = pbc_validate_deposit_tx(dep_tx, block_height, dep_rec, fail_reason);

        if (result == PBC_DEPOSIT_INVALID)
        {
          // CONSENSUS FAILURE: invalid deposit TX → entire block rejected
          LOG_PRINT_L0("PBC_LOG blockchain REJECT: INVALID_DEPOSIT block=" << block_height
            << " tx=" << tx_id << " reason=" << fail_reason);
          MERROR("PBC: INVALID DEPOSIT in block " << block_height
            << " tx=" << tx_id << " — " << fail_reason);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        if (result == PBC_DEPOSIT_VALID)
        {
          // TD-8: Invariant — owner_key must be valid after gatekeeper Check 7
          CHECK_AND_ASSERT_MES(
            dep_rec.owner_key != crypto::null_pkey,
            false,
            "PBC: INVARIANT VIOLATED — owner_key is null after "
            "pbc_validate_deposit_tx returned VALID");

          // Check 7: Reject duplicate deposit_id (defense-in-depth, reorg-safe)
          {
            uint8_t dup_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
            size_t dup_size = PBC_DEPOSIT_RECORD_PACKED_SIZE;
            if (m_db->get_pbc_deposit(tx_id, dup_buf, dup_size))
            {
              LOG_PRINT_L0("PBC_LOG blockchain REJECT: DUPLICATE_DEPOSIT block=" << block_height << " tx=" << tx_id);
              MERROR("PBC: DUPLICATE DEPOSIT in block " << block_height
                << " tx=" << tx_id << " — deposit_id already exists in DB");
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }
          }

          // ── TD-3: Verify RCT commitment for deposit output ──
          // Ensures tx.unlock_time matches deposit, and outPk[0] == amount*H (mask=0).
          // This makes it impossible for a "rigged wallet" to submit a deposit
          // with a non-conformant commitment.
          {
            std::string rct_fail_reason;
            if (!pbc_verify_term_deposit_rct_simple(dep_tx, dep_rec, rct_fail_reason))
            {
              LOG_PRINT_L0("PBC_LOG blockchain REJECT: INVALID_DEPOSIT_RCT block=" << block_height
                << " tx=" << tx_id << " reason=" << rct_fail_reason);
              MERROR("PBC: INVALID DEPOSIT (TD3) in block " << block_height
                << " tx=" << tx_id << " — " << rct_fail_reason);
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }
          }

          // ── TD-8: Anti-split: enforce PBC_MAX_DEPOSITS_PER_ADDR ──
          // dep_rec.owner_key is guaranteed valid by
          // pbc_validate_deposit_tx() Check 7 (TD-8)
          {
            if (legacy_pbc_deposit_records_present)
            {
              MERROR("PBC legacy deposit records without owner_key detected in DB; refusing new deposit tx until chain/DB is migrated or wiped");
              return false;
            }
            uint32_t current_count = active_deposit_counts[dep_rec.owner_key];
            if (current_count >= PBC_MAX_DEPOSITS_PER_ADDR)
            {
              LOG_PRINT_L0("PBC_LOG blockchain REJECT: DEPOSIT_LIMIT_EXCEEDED block=" << block_height
                << " tx=" << tx_id
                << " owner=" << dep_rec.owner_key
                << " count=" << current_count
                << " max=" << PBC_MAX_DEPOSITS_PER_ADDR);
              MERROR("PBC: DEPOSIT LIMIT EXCEEDED in block " << block_height
                << " tx=" << tx_id
                << " owner=" << dep_rec.owner_key
                << " count=" << current_count
                << " max=" << PBC_MAX_DEPOSITS_PER_ADDR);
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }
            active_deposit_counts[dep_rec.owner_key]++;
          }

          // TD-5: Initialize entry indexes at deposit creation.
          // This ensures the deposit cannot claim rewards from before its existence.
          dep_rec.deposit_entry_index = m_pbc_pool_state.global_deposit_index;
          dep_rec.fee_entry_index     = m_pbc_pool_state.global_fee_index;
          dep_rec.last_claim_height   = 0;
          dep_rec.accumulated_reward  = 0;

          // Store record in dedicated LMDB table
          uint8_t buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
          pbc_pack_deposit_record(dep_rec, buf);
          m_db->add_pbc_deposit(tx_id, buf, PBC_DEPOSIT_RECORD_PACKED_SIZE);

          // Update aggregate weight (§19.12 Step 4: Add (amount/COIN)*tier_multiplier/1000 to Σw)
          m_pbc_pool_state.deposit_sum_weights += dep_rec.weight;
          // BUG2-FIX: also track locked amount (recomputed authoritatively at period boundary)
          m_pbc_pool_state.total_locked_in_deposits += dep_rec.amount;

          // NOTE: DEPOSIT_CREATION_FEE (1 PBC → Insurance, §10.1) is NOT applied here.
          // Reason: the creation fee is part of the TX fee field, which already goes through
          // the 50/50 fee split in Step 2. Applying it here would double-count.
          // Proper implementation requires either:
          //   (a) pre-scanning deposits before Step 2 to deduct from F, or
          //   (b) a separate fee field in the TX format.
          // Both require wallet TX crafting support (future TD).

          MGINFO("PBC: Deposit stored: id=" << tx_id
            << " amount=" << dep_rec.amount
            << " tier=" << (unsigned)dep_rec.tier
            << " weight=" << dep_rec.weight
            << " unlock=" << dep_rec.unlock_height
            << " owner=" << dep_rec.owner_key
            << " Σw=" << m_pbc_pool_state.deposit_sum_weights);

          // ── Proof-of-life: reset inactivity clock for inherit ──
          // A TERM_DEPOSIT proves the principal is alive and signing. If an
          // inherit record exists, update last_activity_height so the 18-month
          // clock does not expire on active depositors.
          // Bug1 fix: save activity undo BEFORE mutation so pop_block can restore.
          // Blob: [0xFF sentinel][96-byte packed record BEFORE update][32-byte principal_pk]
          {
            uint8_t inh_buf[PBC_INHERIT_RECORD_PACKED_SIZE];
            size_t  inh_sz = PBC_INHERIT_RECORD_PACKED_SIZE;
            pbc_inherit_record inh_rec;
            if (m_db->get_pbc_inherit_record(dep_rec.owner_key, inh_buf, inh_sz)
                && pbc_unpack_inherit_record(inh_buf, inh_sz, inh_rec))
            {
              // 129-byte undo blob: [0xFF][96-byte record][32-byte principal_pk]
              uint8_t act_undo[PBC_INHERIT_TX_UNDO_SIZE + sizeof(crypto::public_key)];
              act_undo[0] = PBC_INHERIT_UNDO_TAG_ACTIVITY;
              pbc_pack_inherit_record(inh_rec, act_undo + 1);
              memcpy(act_undo + PBC_INHERIT_TX_UNDO_SIZE, &dep_rec.owner_key, sizeof(crypto::public_key));
              m_db->add_pbc_inherit_tx_undo(tx_id, act_undo, sizeof(act_undo));

              inh_rec.last_activity_height = block_height;
              uint8_t inh_out[PBC_INHERIT_RECORD_PACKED_SIZE];
              pbc_pack_inherit_record(inh_rec, inh_out);
              m_db->add_pbc_inherit_record(dep_rec.owner_key, inh_out, sizeof(inh_out));
            }
          }
        }
        // PBC_DEPOSIT_NOT_APPLICABLE: not a deposit TX, silently skip
      }

      // ── TD-5: Process claim TXs ──
      // Claims must be processed AFTER deposits (a deposit and its claim
      // cannot be in the same block) and BEFORE TERM_WITHDRAW (so that a
      // claim + withdraw in the same block is always rejected: the claim
      // would set last_claim_height == block_height, causing the withdraw
      // check last_claim_height < block_height to fail → safe by design).
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& claim_tx = txs[i].first;
        const crypto::hash& claim_tx_id = std::get<0>(txs_meta[i]);
        crypto::hash deposit_id;
        std::string claim_fail_reason;

        pbc_claim_result claim_result = pbc_validate_claim_tx(claim_tx, deposit_id, claim_fail_reason);

        if (claim_result == PBC_CLAIM_INVALID)
        {
          MERROR("PBC TD-5: INVALID CLAIM in block " << block_height
            << " tx=" << claim_tx_id << " — " << claim_fail_reason);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        if (claim_result == PBC_CLAIM_VALID)
        {
          // 1. Read deposit from DB
          uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
          size_t dep_buf_size = PBC_DEPOSIT_RECORD_PACKED_SIZE;
          if (!m_db->get_pbc_deposit(deposit_id, dep_buf, dep_buf_size))
          {
            MERROR("PBC TD-5: Claim references non-existent deposit " << deposit_id
              << " in block " << block_height << " tx=" << claim_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          pbc_deposit_record dep_rec;
          pbc_unpack_deposit_record(dep_buf, dep_buf_size, dep_rec);

          // 2. Eligibility: deposit must have been created before this block
          //    TD-7: Grace illimitée — claims allowed after unlock_height.
          //    Expired deposits get frozen index (no siphoning active rewards).
          if (!(dep_rec.created_height < block_height))
          {
            MERROR("PBC TD-7: Claim on deposit not yet active: " << deposit_id
              << " created=" << dep_rec.created_height
              << " block=" << block_height);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          // 3. Compute effective indices (TD-7: freeze at expiry for expired deposits)
          //    Active deposits: use current global index.
          //    Expired deposits: use snapshot at freeze boundary (index before first
          //    ineligible update = index after last eligible update). This prevents
          //    expired deposits from siphoning rewards earned by active depositors.
          // BUG1-FIX: all indices are __uint128_t
          __uint128_t effective_dep_idx = m_pbc_pool_state.global_deposit_index;
          __uint128_t effective_fee_idx = m_pbc_pool_state.global_fee_index;

          if (dep_rec.unlock_height <= block_height)
          {
            // Freeze boundary = last boundary where deposit was still eligible.
            // Eligible condition: unlock_height > boundary (strict).
            // (unlock_height - 1) / PERIOD * PERIOD handles exact-boundary case:
            //   unlock=2880 → (2879/1440)*1440 = 1440 (last eligible, not 2880).
            const uint64_t freeze_boundary =
                ((dep_rec.unlock_height - 1) / PBC_DISTRIBUTION_PERIOD)
                * PBC_DISTRIBUTION_PERIOD;

            if (block_height >= freeze_boundary + PBC_DISTRIBUTION_PERIOD)
            {
              // The boundary AFTER the last eligible one has been processed.
              // Its pre-update snapshot = index AFTER the last eligible update.
              // Example: unlock=2880 → freeze=1440 → read snapshot(2880)
              //   snapshot(2880) = index before 2880 update = index after 1440 update ✓
              const uint64_t snapshot_boundary = freeze_boundary + PBC_DISTRIBUTION_PERIOD;
              // BUG1-FIX: snapshots are now uint128
              __uint128_t snap_dep = 0, snap_fee = 0;
              bool ok_dep = m_db->get_property_uint128(
                  pbc_delta_key(PBC_DELTA_KEY_IDX_DI, snapshot_boundary), snap_dep);
              bool ok_fee = m_db->get_property_uint128(
                  pbc_delta_key(PBC_DELTA_KEY_IDX_FI, snapshot_boundary), snap_fee);

              CHECK_AND_ASSERT_MES(ok_dep && ok_fee, false,
                  "PBC TD-7: missing index snapshot at boundary "
                  << snapshot_boundary << " for expired deposit " << deposit_id);

              effective_dep_idx = snap_dep;
              effective_fee_idx = snap_fee;
            }
            // else: next boundary not yet processed — current global index IS
            // the correct frozen value (includes the last eligible update).
          }

          // 3b. Compute reward deltas using effective indices (Rule A1: uint128)
          __uint128_t delta_dep = 0;
          __uint128_t delta_fee = 0;
          if (effective_dep_idx >= dep_rec.deposit_entry_index)
            delta_dep = (__uint128_t)(effective_dep_idx - dep_rec.deposit_entry_index);
          if (effective_fee_idx >= dep_rec.fee_entry_index)
            delta_fee = (__uint128_t)(effective_fee_idx - dep_rec.fee_entry_index);

          // Hardening: guard uint128→uint64 cast (overflow after ~219 years without claim)
          __uint128_t raw_reward_dep = (delta_dep * dep_rec.weight) / (__uint128_t)PBC_SCALE;
          __uint128_t raw_reward_fee = (delta_fee * dep_rec.weight) / (__uint128_t)PBC_SCALE;
          CHECK_AND_ASSERT_MES(raw_reward_dep <= UINT64_MAX, false,
              "PBC: reward_dep overflow uint64 — deposit too old without claim?");
          CHECK_AND_ASSERT_MES(raw_reward_fee <= UINT64_MAX, false,
              "PBC: reward_fee overflow uint64 — deposit too old without claim?");
          uint64_t reward_dep = (uint64_t)raw_reward_dep;
          uint64_t reward_fee = (uint64_t)raw_reward_fee;

          // 4. Solvency cap — never exceed AVAILABLE pool balance (excluding pending rewards)
          // We treat CLAIM as "pending only": it reserves capacity but does not move coins yet.
          // available_total = (deposit_pool + fee_pool) - pending_rewards_total
          const uint64_t pools_total = m_pbc_pool_state.deposit_pool_balance + m_pbc_pool_state.fee_pool_balance;
          CHECK_AND_ASSERT_MES(m_pbc_pool_state.pending_rewards_total <= pools_total, false,
              "PBC TD-6: pending_rewards_total exceeds (deposit_pool+fee_pool)");
          const uint64_t available_total = pools_total - m_pbc_pool_state.pending_rewards_total;

          uint64_t reward_total = reward_dep + reward_fee;
          if (reward_total > available_total)
            reward_total = available_total;

          // 5. Zero reward → reject (prevents spam, no economic value)

          // 5. Zero reward → reject (prevents spam, no economic value)
          if (reward_total == 0)
          {
            MERROR("PBC TD-5: Claim on deposit " << deposit_id
              << " yields zero reward — rejected");
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          // 6. Save pre-claim state for revert (property table, like TD-4 snapshots)
          m_db->set_property_uint64(pbc_claim_key(claim_tx_id, "_rt"), reward_total);
          // BUG1-FIX: _di/_fi are uint128
          m_db->set_property_uint128(pbc_claim_key(claim_tx_id, "_di"), dep_rec.deposit_entry_index);
          m_db->set_property_uint128(pbc_claim_key(claim_tx_id, "_fi"), dep_rec.fee_entry_index);
          m_db->set_property_uint64(pbc_claim_key(claim_tx_id, "_lh"), dep_rec.last_claim_height);
          m_db->set_property_uint64(pbc_claim_key(claim_tx_id, "_ar"), dep_rec.accumulated_reward);

          // 7. Apply: reserve pending rewards (CLAIM = pending only)
          const uint64_t prev_pending = m_pbc_pool_state.pending_rewards_total;
          m_pbc_pool_state.pending_rewards_total += reward_total;

          // Non-negativity/overflow hardening
          CHECK_AND_ASSERT_MES(m_pbc_pool_state.pending_rewards_total >= prev_pending, false,
              "PBC TD-6: pending_rewards_total overflow");
          // Ensure we did not reserve more than pools_total
          const uint64_t pools_total_after = m_pbc_pool_state.deposit_pool_balance + m_pbc_pool_state.fee_pool_balance;
          CHECK_AND_ASSERT_MES(m_pbc_pool_state.pending_rewards_total <= pools_total_after, false,
              "PBC TD-6: pending_rewards_total exceeds (deposit_pool+fee_pool) after claim");

          // 8. Apply: update deposit record
          //    TD-7: use effective indices (frozen for expired deposits)
          dep_rec.deposit_entry_index = effective_dep_idx;
          dep_rec.fee_entry_index     = effective_fee_idx;
          dep_rec.last_claim_height   = block_height;
          dep_rec.accumulated_reward += reward_total;

          // 9. Store updated deposit (remove first — add_pbc_deposit uses MDB_NOOVERWRITE)
          m_db->remove_pbc_deposit(deposit_id);
          uint8_t upd_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
          pbc_pack_deposit_record(dep_rec, upd_buf);
          m_db->add_pbc_deposit(deposit_id, upd_buf, PBC_DEPOSIT_RECORD_PACKED_SIZE);

          MGINFO("PBC TD-5: Claim applied: tx=" << claim_tx_id
            << " deposit=" << deposit_id
            << " reward_dep=" << reward_dep
            << " reward_fee=" << reward_fee
            << " reward_total=" << reward_total
            << " dep_pool=" << m_pbc_pool_state.deposit_pool_balance
            << " fee_pool=" << m_pbc_pool_state.fee_pool_balance
            << " accumulated=" << dep_rec.accumulated_reward);

          // ── SECURITY FIX (M1): CLAIM does NOT refresh the inheritance proof-of-life ──
          // A CLAIM is PERMISSIONLESS: pbc_validate_claim_tx() checks only the tx_extra
          // format (deposit_id present, no deposit_info). It carries NO owner_sig and does
          // NOT reference the deposit owner's key image — any third party can submit a CLAIM
          // against anyone's deposit (the reward accrues on dep_rec.accumulated_reward, so it
          // is economically neutral for the submitter). The previous code updated the owner's
          // inherit_record.last_activity_height here, which let an attacker keep a dead-man's-
          // switch open indefinitely by periodically claiming the principal's deposit
          // (griefing: the heir could be denied their inheritance forever).
          //
          // Proof-of-life is now derived ONLY from operations that genuinely require the
          // principal's spend key (a real "I am alive" signal): TERM_DEPOSIT, TERM_WITHDRAW,
          // INHERIT_SETUP — each of which verifies an owner_sig against the principal's key.
          // We therefore write neither last_activity_height nor an activity undo blob for a
          // CLAIM. Symmetry with pop_block is preserved: the CLAIM branch there looks up an
          // activity undo by txid and simply finds none (get_pbc_inherit_tx_undo == false →
          // early continue), so no state is left inconsistent on reorg.
        }
        // PBC_CLAIM_NOT_APPLICABLE: not a claim TX, silently skip
      }

      // ── Marketplace: collateral lock creation ─────────────────────────────
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& lock_tx = txs[i].first;
        const crypto::hash& lock_tx_id = std::get<0>(txs_meta[i]);
        tx_extra_pbc_tx_type type_field{};
        if (!get_tx_extra_field_by_type(lock_tx.extra, type_field) || type_field.type != PBC_TX_TYPE_LOCK_COLLATERAL)
          continue;

        tx_extra_pbc_lock_collateral lock_field{};
        if (!get_tx_extra_field_by_type(lock_tx.extra, lock_field))
        {
          MERROR("PBC MARKET: malformed LOCK_COLLATERAL tx=" << lock_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
        size_t dep_sz = PBC_DEPOSIT_RECORD_PACKED_SIZE;
        if (!m_db->get_pbc_deposit(lock_field.deposit_id, dep_buf, dep_sz))
        {
          MERROR("PBC MARKET: LOCK_COLLATERAL missing deposit tx=" << lock_tx_id << " deposit=" << lock_field.deposit_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        pbc_deposit_record dep_rec;
        pbc_unpack_deposit_record(dep_buf, dep_sz, dep_rec);
        if (!(dep_rec.created_height < block_height))
        {
          MERROR("PBC MARKET: LOCK_COLLATERAL deposit not yet active tx=" << lock_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (dep_rec.owner_key != lock_field.seller_pubkey)
        {
          MERROR("PBC MARKET: LOCK_COLLATERAL seller mismatch tx=" << lock_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        crypto::hash existing_lock_id = crypto::null_hash;
        if (m_db->get_active_pbc_collateral_lock_for_deposit(lock_field.deposit_id, existing_lock_id))
        {
          MERROR("PBC MARKET: LOCK_COLLATERAL deposit already locked tx=" << lock_tx_id << " existing=" << existing_lock_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (lock_field.buyer_pubkey == lock_field.seller_pubkey)
        {
          MERROR("PBC MARKET: LOCK_COLLATERAL buyer == seller tx=" << lock_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (!pbc_tx_has_market_payout_amount(lock_tx, lock_field.amount))
        {
          MERROR("PBC MARKET: LOCK_COLLATERAL backing output missing tx=" << lock_tx_id << " amount=" << lock_field.amount);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        // If an active ask exists, buyer must pay at least the ask_price (can be < principal).
        // Without an active ask, buyer must pay at least the full principal (legacy behavior).
        {
          uint64_t min_lock_amount = dep_rec.amount; // default: full principal
          uint64_t active_ask_price = 0;
          if (m_db->get_property_uint64(pbc_ask_dep_key(lock_field.deposit_id, "_price"), active_ask_price)
              && active_ask_price > 0)
          {
            min_lock_amount = active_ask_price; // ask is active: buyer pays ask_price
          }
          if (lock_field.amount < min_lock_amount)
          {
            MERROR("PBC MARKET: LOCK_COLLATERAL amount " << lock_field.amount
              << " below minimum " << min_lock_amount
              << " (ask=" << active_ask_price << " principal=" << dep_rec.amount
              << ") tx=" << lock_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
        }
        // Note: expected_dep_idx/fee_idx are stored in the lock record for potential use
        // by TRANSFER_DEPOSIT (legacy path), but NOT validated here at lock time.
        // The auto-match path computes current indices atomically via
        // pbc_apply_implicit_claim_for_transfer at block-apply time, so there is no
        // frontrunning risk. Validating stale indices from TX construction time would
        // cause false rejections whenever a distribution boundary passes between
        // TX broadcast and block inclusion.
        if (lock_field.expiry_height < block_height + PBC_LOCK_MIN_DURATION ||
            lock_field.expiry_height > block_height + PBC_LOCK_MAX_DURATION)
        {
          MERROR("PBC MARKET: LOCK_COLLATERAL expiry out of range tx=" << lock_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        uint8_t inh_buf[PBC_INHERIT_RECORD_PACKED_SIZE];
        size_t inh_sz = PBC_INHERIT_RECORD_PACKED_SIZE;
        pbc_inherit_record inh_rec;
        if (m_db->get_pbc_inherit_record(dep_rec.owner_key, inh_buf, inh_sz) && pbc_unpack_inherit_record(inh_buf, inh_sz, inh_rec) && inh_rec.request_active)
        {
          MERROR("PBC MARKET: LOCK_COLLATERAL blocked by active inheritance request tx=" << lock_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        const crypto::hash lock_msg_hash = pbc_build_lock_msg_hash(lock_field.deposit_id, lock_field.buyer_pubkey, lock_field.seller_pubkey, lock_field.amount, lock_field.expiry_height, lock_field.expected_dep_idx, lock_field.expected_fee_idx);
        if (!crypto::check_signature(lock_msg_hash, lock_field.buyer_pubkey, lock_field.buyer_signature))
        {
          MERROR("PBC MARKET: LOCK_COLLATERAL buyer signature invalid tx=" << lock_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        collateral_lock_record rec{};
        rec.lock_id = lock_tx_id;
        rec.deposit_id = lock_field.deposit_id;
        rec.buyer_pubkey = lock_field.buyer_pubkey;
        rec.seller_pubkey = lock_field.seller_pubkey;
        rec.amount = lock_field.amount;
        rec.created_height = block_height;
        rec.expiry_height = lock_field.expiry_height;
        rec.status = PBC_COLLATERAL_LOCK_ACTIVE;
        rec.expected_dep_idx = lock_field.expected_dep_idx;
        rec.expected_fee_idx = lock_field.expected_fee_idx;
        pbc_add_collateral_lock_record(m_db, rec);
        m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_lock_applied"), 1);

        // ── AUTO-MATCH: if an active ask exists with ask_price <= lock amount, transfer immediately ──
        {
          uint64_t ask_price = 0;
          if (m_db->get_property_uint64(pbc_ask_dep_key(lock_field.deposit_id, "_price"), ask_price)
              && ask_price > 0 && lock_field.amount >= ask_price)
          {
            // Save pre-match deposit indices for reorg rollback (BEFORE implicit claim modifies dep_rec).
            m_db->set_property_uint128(pbc_market_key(lock_tx_id, "_am_old_dep_idx"), dep_rec.deposit_entry_index);
            m_db->set_property_uint128(pbc_market_key(lock_tx_id, "_am_old_fee_idx"), dep_rec.fee_entry_index);
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_old_last_claim_h"), dep_rec.last_claim_height);
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_old_acc_reward"), dep_rec.accumulated_reward);
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_old_total_withdrawn"), dep_rec.total_withdrawn);

            // Compute seller's accumulated rewards at this block (same as implicit claim for transfer).
            pbc_transfer_claim_apply_result claim_apply{};
            std::string claim_fail;
            if (!pbc_apply_implicit_claim_for_transfer(m_db, m_pbc_pool_state, lock_field.deposit_id, dep_rec, block_height, lock_tx_id, claim_apply, claim_fail))
            {
              MERROR("PBC AUTO-MATCH: implicit claim failed for deposit=" << lock_field.deposit_id
                << " tx=" << lock_tx_id << " — " << claim_fail);
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }

            // Store undo state for auto-match reward (dep_rec fields already saved above for lock rollback).
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_dep_debit"),  claim_apply.dep_debit);
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_fee_debit"),  claim_apply.fee_debit);
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_mat_reward"), claim_apply.materialized_reward);

            // Save previous pbc_mktpay balance for rollback.
            uint64_t prev_mktpay = 0;
            m_db->get_property_uint64(pbc_mktpay_key(lock_field.seller_pubkey), prev_mktpay);
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_prev_mktpay"), prev_mktpay);

            // Credit seller's pending reward balance.
            const uint64_t new_mktpay = prev_mktpay + claim_apply.materialized_reward;
            if (claim_apply.materialized_reward > 0)
              m_db->set_property_uint64(pbc_mktpay_key(lock_field.seller_pubkey), new_mktpay);

            // Save old owner for rollback.
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_old_dep_pool"), m_pbc_pool_state.deposit_pool_balance + claim_apply.dep_debit);
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_old_fee_pool"), m_pbc_pool_state.fee_pool_balance + claim_apply.fee_debit);
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_old_pending"),  m_pbc_pool_state.pending_rewards_total + claim_apply.pending_reward);

            // Transfer deposit to buyer.
            const crypto::public_key old_owner = dep_rec.owner_key;
            dep_rec.owner_key = lock_field.buyer_pubkey;
            m_db->remove_pbc_deposit(lock_field.deposit_id);
            uint8_t dep_out[PBC_DEPOSIT_RECORD_PACKED_SIZE];
            pbc_pack_deposit_record(dep_rec, dep_out);
            m_db->add_pbc_deposit(lock_field.deposit_id, dep_out, sizeof(dep_out));

            // Remove ask from marketplace.
            // Save ask data first for rollback.
            {
              uint64_t ask_height_val = 0;
              m_db->get_property_uint64(pbc_ask_dep_key(lock_field.deposit_id, "_height"), ask_height_val);
              m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_ask_price"),  ask_price);
              m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_ask_height"), ask_height_val);
              uint8_t addr_buf[sizeof(cryptonote::account_public_address)];
              size_t  addr_sz = sizeof(addr_buf);
              if (pbc_load_packed_props(m_db, pbc_ask_dep_key(lock_field.deposit_id, "_addr"), addr_buf, sizeof(addr_buf), addr_sz))
                pbc_store_packed_props(m_db, pbc_market_key(lock_tx_id, "_am_ask_addr"), addr_buf, addr_sz);
            }
            m_db->delete_property(pbc_ask_dep_key(lock_field.deposit_id, "_price"));
            m_db->delete_property(pbc_ask_dep_key(lock_field.deposit_id, "_height"));
            pbc_delete_packed_props(m_db, pbc_ask_dep_key(lock_field.deposit_id, "_addr"));
            pbc_ask_list_remove(m_db, lock_field.deposit_id);

            // Mark lock as consumed immediately (no expiry / cancel possible).
            pbc_update_collateral_lock_status(m_db, rec, PBC_COLLATERAL_LOCK_CONSUMED_BY_TRANSFER);
            m_db->set_property_uint64(pbc_market_key(lock_tx_id, "_am_applied"), 1);

            MGINFO("PBC AUTO-MATCH: deposit=" << lock_field.deposit_id
              << " buyer=" << lock_field.buyer_pubkey
              << " seller=" << old_owner
              << " ask_price=" << ask_price
              << " lock_amount=" << lock_field.amount
              << " seller_rewards=" << claim_apply.materialized_reward
              << " tx=" << lock_tx_id);

            // Record this sale in the seller's sold deposits history (for UI display).
            pbc_sold_list_add(m_db, old_owner, lock_field.deposit_id,
                lock_field.amount, claim_apply.materialized_reward, block_height,
                dep_rec.amount, lock_field.buyer_pubkey);
          }
        }

        MGINFO("PBC MARKET: LOCK_COLLATERAL applied tx=" << lock_tx_id << " deposit=" << rec.deposit_id << " amount=" << rec.amount << " expiry=" << rec.expiry_height);
      }

      // ── Marketplace: collateral lock cancellation / expiry ───────────────
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& cancel_tx = txs[i].first;
        const crypto::hash& cancel_tx_id = std::get<0>(txs_meta[i]);
        tx_extra_pbc_tx_type type_field{};
        if (!get_tx_extra_field_by_type(cancel_tx.extra, type_field) || type_field.type != PBC_TX_TYPE_CANCEL_LOCK)
          continue;

        tx_extra_pbc_cancel_lock cancel_field{};
        if (!get_tx_extra_field_by_type(cancel_tx.extra, cancel_field))
        {
          MERROR("PBC MARKET: malformed CANCEL_LOCK tx=" << cancel_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        collateral_lock_record rec{};
        if (!pbc_get_collateral_lock_record(m_db, cancel_field.lock_id, rec))
        {
          MERROR("PBC MARKET: CANCEL_LOCK missing lock tx=" << cancel_tx_id << " lock=" << cancel_field.lock_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (rec.status != PBC_COLLATERAL_LOCK_ACTIVE)
        {
          MERROR("PBC MARKET: CANCEL_LOCK lock not active tx=" << cancel_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (cancel_field.is_voluntary)
        {
          const crypto::hash cancel_msg_hash = pbc_build_cancel_lock_msg_hash(cancel_field.lock_id);
          if (!crypto::check_signature(cancel_msg_hash, rec.buyer_pubkey, cancel_field.canceller_sig))
          {
            MERROR("PBC MARKET: CANCEL_LOCK voluntary signature invalid tx=" << cancel_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
        }
        else if (block_height <= rec.expiry_height)
        {
          MERROR("PBC MARKET: CANCEL_LOCK expiry too early tx=" << cancel_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        if (!pbc_tx_has_market_payout_amount(cancel_tx, rec.amount))
        {
          MERROR("PBC MARKET: CANCEL_LOCK refund output missing tx=" << cancel_tx_id << " amount=" << rec.amount);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        uint8_t lock_buf[PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE];
        pbc_pack_collateral_lock_record(rec, lock_buf);
        pbc_store_packed_props(m_db, pbc_market_key(cancel_tx_id, "_cancel_lock"), lock_buf, sizeof(lock_buf));
        pbc_update_collateral_lock_status(m_db, rec, cancel_field.is_voluntary ? PBC_COLLATERAL_LOCK_CANCELLED : PBC_COLLATERAL_LOCK_EXPIRED);

        MGINFO("PBC MARKET: CANCEL_LOCK applied tx=" << cancel_tx_id << " lock=" << rec.lock_id << " status=" << (cancel_field.is_voluntary ? "cancelled" : "expired"));
      }

      // ── Marketplace: direct owner transfer of a deposit ──
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& xfer_tx = txs[i].first;
        const crypto::hash& xfer_tx_id = std::get<0>(txs_meta[i]);
        tx_extra_pbc_tx_type type_field{};
        if (!get_tx_extra_field_by_type(xfer_tx.extra, type_field) || type_field.type != PBC_TX_TYPE_TRANSFER_DEPOSIT)
          continue;

        tx_extra_pbc_transfer_deposit xfer_field{};
        tx_extra_pbc_owner_sig sig_field{};
        if (!get_tx_extra_field_by_type(xfer_tx.extra, xfer_field) || !get_tx_extra_field_by_type(xfer_tx.extra, sig_field))
        {
          MERROR("PBC MARKET: malformed TRANSFER tx=" << xfer_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
        size_t dep_sz = PBC_DEPOSIT_RECORD_PACKED_SIZE;
        if (!m_db->get_pbc_deposit(xfer_field.deposit_id, dep_buf, dep_sz))
        {
          MERROR("PBC MARKET: transfer references missing deposit tx=" << xfer_tx_id << " deposit=" << xfer_field.deposit_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        pbc_deposit_record dep_rec;
        pbc_unpack_deposit_record(dep_buf, dep_sz, dep_rec);
        if (dep_rec.owner_key == crypto::null_pkey || dep_rec.owner_key == xfer_field.new_owner_spend_pubkey)
        {
          MERROR("PBC MARKET: invalid owner transition tx=" << xfer_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        uint8_t inh_buf[PBC_INHERIT_RECORD_PACKED_SIZE];
        size_t inh_sz = PBC_INHERIT_RECORD_PACKED_SIZE;
        pbc_inherit_record inh_rec;
        if (m_db->get_pbc_inherit_record(dep_rec.owner_key, inh_buf, inh_sz) && pbc_unpack_inherit_record(inh_buf, inh_sz, inh_rec) && inh_rec.request_active)
        {
          MERROR("PBC MARKET: transfer blocked by active inheritance request tx=" << xfer_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        const crypto::hash msg_hash = pbc_build_transfer_deposit_msg_hash(xfer_field.deposit_id, xfer_field.new_owner_spend_pubkey, xfer_field.lock_id, xfer_field.expected_dep_idx, xfer_field.expected_fee_idx);
        if (!crypto::check_signature(msg_hash, dep_rec.owner_key, sig_field.sig))
        {
          MERROR("PBC MARKET: invalid owner signature tx=" << xfer_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        collateral_lock_record lock_rec{};
        if (!pbc_get_collateral_lock_record(m_db, xfer_field.lock_id, lock_rec))
        {
          MERROR("PBC MARKET: transfer missing collateral lock tx=" << xfer_tx_id << " lock=" << xfer_field.lock_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (lock_rec.status != PBC_COLLATERAL_LOCK_ACTIVE || lock_rec.deposit_id != xfer_field.deposit_id || lock_rec.seller_pubkey != dep_rec.owner_key)
        {
          MERROR("PBC MARKET: transfer collateral lock invalid tx=" << xfer_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (lock_rec.expected_dep_idx != xfer_field.expected_dep_idx || lock_rec.expected_fee_idx != xfer_field.expected_fee_idx)
        {
          MERROR("PBC MARKET: transfer tx expected indices are not bound to lock snapshot tx=" << xfer_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (block_height > lock_rec.expiry_height)
        {
          MERROR("PBC MARKET: transfer collateral lock expired tx=" << xfer_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (dep_rec.deposit_entry_index != xfer_field.expected_dep_idx || dep_rec.fee_entry_index != xfer_field.expected_fee_idx)
        {
          MERROR("PBC MARKET: transfer expected indices mismatch tx=" << xfer_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (pbc_block_has_withdraw_for_deposit(txs, xfer_field.deposit_id))
        {
          MERROR("PBC MARKET: transfer conflicts with withdraw in same block tx=" << xfer_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (!pbc_tx_has_market_payout_amount(xfer_tx, lock_rec.amount))
        {
          MERROR("PBC MARKET: transfer seller payment output missing tx=" << xfer_tx_id << " amount=" << lock_rec.amount);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        const std::string base = pbc_market_key(xfer_tx_id, "");
        uint64_t words[4] = {0,0,0,0};
        std::memcpy(&words[0], reinterpret_cast<const uint8_t*>(&dep_rec.owner_key)+0, 8);
        std::memcpy(&words[1], reinterpret_cast<const uint8_t*>(&dep_rec.owner_key)+8, 8);
        std::memcpy(&words[2], reinterpret_cast<const uint8_t*>(&dep_rec.owner_key)+16, 8);
        std::memcpy(&words[3], reinterpret_cast<const uint8_t*>(&dep_rec.owner_key)+24, 8);
        m_db->set_property_uint64(base+"_old_owner_0", words[0]);
        m_db->set_property_uint64(base+"_old_owner_1", words[1]);
        m_db->set_property_uint64(base+"_old_owner_2", words[2]);
        m_db->set_property_uint64(base+"_old_owner_3", words[3]);
        m_db->set_property_uint128(base+"_old_di", dep_rec.deposit_entry_index);
        m_db->set_property_uint128(base+"_old_fi", dep_rec.fee_entry_index);
        m_db->set_property_uint64(base+"_old_lh", dep_rec.last_claim_height);
        m_db->set_property_uint64(base+"_old_ar", dep_rec.accumulated_reward);
        m_db->set_property_uint64(base+"_old_tw", dep_rec.total_withdrawn);
        m_db->set_property_uint64(base+"_old_dep_pool", m_pbc_pool_state.deposit_pool_balance);
        m_db->set_property_uint64(base+"_old_fee_pool", m_pbc_pool_state.fee_pool_balance);
        m_db->set_property_uint64(base+"_old_pending", m_pbc_pool_state.pending_rewards_total);
        uint8_t lock_buf[PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE];
        pbc_pack_collateral_lock_record(lock_rec, lock_buf);
        pbc_store_packed_props(m_db, base+"_lock", lock_buf, sizeof(lock_buf));

        pbc_transfer_claim_apply_result claim_apply{};
        std::string claim_apply_fail;
        if (!pbc_apply_implicit_claim_for_transfer(m_db, m_pbc_pool_state, xfer_field.deposit_id, dep_rec, block_height, xfer_tx_id, claim_apply, claim_apply_fail))
        {
          MERROR("PBC MARKET: transfer implicit claim failed tx=" << xfer_tx_id << " — " << claim_apply_fail);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        m_db->set_property_uint64(base+"_dep_debit", claim_apply.dep_debit);
        m_db->set_property_uint64(base+"_fee_debit", claim_apply.fee_debit);
        m_db->set_property_uint64(base+"_materialized_reward", claim_apply.materialized_reward);

        dep_rec.owner_key = xfer_field.new_owner_spend_pubkey;
        m_db->remove_pbc_deposit(xfer_field.deposit_id);
        uint8_t out[PBC_DEPOSIT_RECORD_PACKED_SIZE];
        pbc_pack_deposit_record(dep_rec, out);
        m_db->add_pbc_deposit(xfer_field.deposit_id, out, sizeof(out));

        pbc_update_collateral_lock_status(m_db, lock_rec, PBC_COLLATERAL_LOCK_CONSUMED_BY_TRANSFER);

        MGINFO("PBC MARKET: transfer applied tx=" << xfer_tx_id << " deposit=" << xfer_field.deposit_id << " new_owner=" << dep_rec.owner_key
          << " materialized_reward=" << claim_apply.materialized_reward << " lock_amount=" << lock_rec.amount);
      }

      // ── Marketplace: MARKET_ASK — list / update / delist ─────────────────
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& ask_tx = txs[i].first;
        const crypto::hash& ask_tx_id = std::get<0>(txs_meta[i]);
        tx_extra_pbc_tx_type type_field{};
        if (!get_tx_extra_field_by_type(ask_tx.extra, type_field) || type_field.type != PBC_TX_TYPE_MARKET_ASK)
          continue;

        tx_extra_pbc_market_ask ask_field{};
        if (!get_tx_extra_field_by_type(ask_tx.extra, ask_field))
        {
          MERROR("PBC MARKET ASK: malformed MARKET_ASK tx=" << ask_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        // Verify deposit exists and seller owns it
        uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
        size_t dep_sz = PBC_DEPOSIT_RECORD_PACKED_SIZE;
        if (!m_db->get_pbc_deposit(ask_field.deposit_id, dep_buf, dep_sz))
        {
          MERROR("PBC MARKET ASK: deposit not found tx=" << ask_tx_id << " deposit=" << ask_field.deposit_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        pbc_deposit_record dep_rec;
        pbc_unpack_deposit_record(dep_buf, dep_sz, dep_rec);
        if (dep_rec.owner_key != ask_field.seller_pubkey)
        {
          MERROR("PBC MARKET ASK: seller is not deposit owner tx=" << ask_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        // Only reject listing a mature deposit (ask_price > 0 = list/update).
        // Delisting (ask_price == 0) is always allowed so the seller can clean up.
        if (ask_field.ask_price > 0 && dep_rec.unlock_height <= block_height)
        {
          MERROR("PBC MARKET ASK: deposit is mature, cannot list tx=" << ask_tx_id
            << " unlock_height=" << dep_rec.unlock_height << " block=" << block_height);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        // Verify seller_sig over H(PREFIX || deposit_id || ask_price_le8 || seller_pubkey)
        {
          uint8_t price_le8[8];
          const uint64_t p = ask_field.ask_price;
          for (int b = 0; b < 8; ++b) price_le8[b] = (p >> (b * 8)) & 0xFF;
          std::string msg(PBC_MARKET_ASK_MSG_PREFIX);
          msg.append(reinterpret_cast<const char*>(ask_field.deposit_id.data), sizeof(ask_field.deposit_id));
          msg.append(reinterpret_cast<const char*>(price_le8), 8);
          msg.append(reinterpret_cast<const char*>(&ask_field.seller_pubkey), sizeof(ask_field.seller_pubkey));
          const crypto::hash msg_hash = crypto::cn_fast_hash(msg.data(), msg.size());
          if (!crypto::check_signature(msg_hash, ask_field.seller_pubkey, ask_field.seller_sig))
          {
            MERROR("PBC MARKET ASK: invalid seller_sig tx=" << ask_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
        }

        // Save undo: previous ask state for this deposit
        uint64_t old_price = 0;
        const bool had_prev = m_db->get_property_uint64(pbc_ask_dep_key(ask_field.deposit_id, "_price"), old_price)
                              && old_price > 0;
        m_db->set_property_uint64(pbc_market_key(ask_tx_id, "_ask_u0"), had_prev ? 1 : 0);
        if (had_prev)
        {
          uint64_t old_height = 0;
          m_db->get_property_uint64(pbc_ask_dep_key(ask_field.deposit_id, "_height"), old_height);
          m_db->set_property_uint64(pbc_market_key(ask_tx_id, "_ask_u1"), old_price);
          m_db->set_property_uint64(pbc_market_key(ask_tx_id, "_ask_u2"), old_height);
          // Save old seller address
          uint8_t old_addr_buf[sizeof(cryptonote::account_public_address)];
          size_t old_addr_sz = 0;
          if (pbc_load_packed_props(m_db, pbc_ask_dep_key(ask_field.deposit_id, "_addr"),
                                    old_addr_buf, sizeof(old_addr_buf), old_addr_sz)
              && old_addr_sz == sizeof(cryptonote::account_public_address))
          {
            pbc_store_packed_props(m_db, pbc_market_key(ask_tx_id, "_ask_u3"),
                                   old_addr_buf, sizeof(old_addr_buf));
          }
        }

        if (ask_field.ask_price > 0)
        {
          // List or update price
          m_db->set_property_uint64(pbc_ask_dep_key(ask_field.deposit_id, "_price"), ask_field.ask_price);
          m_db->set_property_uint64(pbc_ask_dep_key(ask_field.deposit_id, "_height"), block_height);
          // Seller address = reconstruct account_public_address from seller_pubkey
          // We store only the spend pubkey; view key is not needed for marketplace display.
          // Pack seller address: spend pubkey + view pubkey (both now available from TX extra).
          uint8_t addr_buf[sizeof(cryptonote::account_public_address)] = {};
          memcpy(addr_buf,                          &ask_field.seller_pubkey,      sizeof(crypto::public_key));
          memcpy(addr_buf + sizeof(crypto::public_key), &ask_field.seller_view_pubkey, sizeof(crypto::public_key));
          pbc_store_packed_props(m_db, pbc_ask_dep_key(ask_field.deposit_id, "_addr"),
                                 addr_buf, sizeof(addr_buf));
          pbc_ask_list_add(m_db, ask_field.deposit_id);
          MGINFO("PBC MARKET ASK: ask stored/updated tx=" << ask_tx_id
            << " deposit=" << ask_field.deposit_id
            << " price=" << ask_field.ask_price
            << " seller=" << ask_field.seller_pubkey);
        }
        else
        {
          // Delist
          m_db->delete_property(pbc_ask_dep_key(ask_field.deposit_id, "_price"));
          m_db->delete_property(pbc_ask_dep_key(ask_field.deposit_id, "_height"));
          pbc_delete_packed_props(m_db, pbc_ask_dep_key(ask_field.deposit_id, "_addr"));
          pbc_ask_list_remove(m_db, ask_field.deposit_id);
          MGINFO("PBC MARKET ASK: ask removed (delist) tx=" << ask_tx_id
            << " deposit=" << ask_field.deposit_id);
        }
      }

      // ── PBC TRACE: POST-APPLY — full state after all mutations, before conservation check ──
      {
        const uint64_t _pagc = already_generated_coins;
        const uint64_t _pcf  = m_pbc_pool_state.cumulative_fees;
        const uint64_t _pS   = _pagc + _pcf;
        const uint64_t _pP   = m_pbc_pool_state.pool_balances();
        const uint64_t _pdst = m_pbc_pool_state.total_destroyed;
        const uint64_t _pves = m_pbc_pool_state.total_vested_outputs;
        const uint64_t _plck = m_pbc_pool_state.total_locked_in_deposits;
        const uint64_t _pexistence = (_pS >= _pdst) ? (_pS - _pdst) : 0;
        const uint64_t _poutside   = (_pexistence >= _pP) ? (_pexistence - _pP) : 0;
        const uint64_t _pcirc      = (_poutside >= _pves) ? (_poutside - _pves) : 0;
        LOG_PRINT_L1("PBC TRACE POST-APPLY h=" << block_height
          << " agc=" << _pagc
          << " cf=" << _pcf
          << " S=" << _pS
          << " dep=" << m_pbc_pool_state.deposit_pool_balance
          << " fee=" << m_pbc_pool_state.fee_pool_balance
          << " ins=" << m_pbc_pool_state.insurance_pool_balance
          << " P=" << _pP
          << " destroyed=" << _pdst
          << " vested=" << _pves
          << " locked=" << _plck
          << " sumW=" << m_pbc_pool_state.deposit_sum_weights
          << " existence=" << _pexistence
          << " outside=" << _poutside
          << " circ=" << _pcirc
          << " dep_inflow=" << m_pbc_pool_state.deposit_pool_period_inflow
          << " fee_inflow=" << m_pbc_pool_state.fee_pool_period_inflow
          << " chk1_pools_ok=" << (_pexistence >= _pP ? "Y" : "N")
          << " chk2_dep_gt_locked=" << (m_pbc_pool_state.deposit_pool_balance >= _plck ? "Y" : "n(ok)")
          << " chk3_vested_ok=" << (_poutside >= _pves ? "Y" : "N"));
      }

      // ── PF: Process MARKET_PAYOUT_CLAIM TXs ──
      // Seller claims deferred rewards that were earmarked during auto-match.
      // The funds are drawn from pbc_mktpay_<seller_pubkey_hex> (already debited from pool at match time).
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& p_tx = txs[i].first;
        const crypto::hash& p_tx_id = std::get<0>(txs_meta[i]);

        crypto::public_key seller_pubkey;
        uint64_t payout_amount = 0;
        std::string p_fail;

        const pbc_market_payout_result pres = pbc_validate_market_payout_tx(p_tx, seller_pubkey, payout_amount, p_fail);
        if (pres == PBC_MARKET_PAYOUT_INVALID)
        {
          MERROR("PBC MKTPAY: INVALID MARKET_PAYOUT_CLAIM in block " << block_height
            << " tx=" << p_tx_id << " — " << p_fail);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (pres != PBC_MARKET_PAYOUT_VALID)
          continue;

        // Format checks (defense in depth).
        if (p_tx.vin.size() != 1 || p_tx.vin[0].type() != typeid(txin_pbc_withdraw))
        {
          MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM vin not exactly 1 txin_pbc_withdraw tx=" << p_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (get_tx_fee(p_tx) != 0)
        {
          MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM fee must be 0 tx=" << p_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (p_tx.rct_signatures.type != rct::RCTTypeNull)
        {
          MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM rct type must be Null tx=" << p_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        // Read pending pbc_mktpay balance for this seller.
        uint64_t mktpay_balance = 0;
        if (!m_db->get_property_uint64(pbc_mktpay_key(seller_pubkey), mktpay_balance) || mktpay_balance == 0)
        {
          MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM no pending balance for seller=" << seller_pubkey
            << " tx=" << p_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }
        if (payout_amount != mktpay_balance)
        {
          MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM payout_amount mismatch: claimed=" << payout_amount
            << " stored=" << mktpay_balance << " seller=" << seller_pubkey << " tx=" << p_tx_id);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        // Verify seller_sig: H(PBC_MKTPAY_V1 || seller_pubkey || payout_amount_le8).
        {
          std::vector<tx_extra_field> p_fields;
          tx_extra_pbc_market_payout_claim p_pay_field;
          if (!parse_tx_extra(p_tx.extra, p_fields) || !find_tx_extra_field_by_type(p_fields, p_pay_field))
          {
            MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM missing payout_claim field tx=" << p_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          const crypto::hash msg_hash = pbc_build_market_payout_msg_hash(seller_pubkey, payout_amount);
          if (!crypto::check_signature(msg_hash, seller_pubkey, p_pay_field.seller_sig))
          {
            MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM seller_sig invalid seller=" << seller_pubkey
              << " tx=" << p_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          // Problem 2: Dilithium spend-authority co-signature (mandatory at/after the fork). Same
          // shared verifier and registered-key lookup as the withdraw/mempool paths.
          {
            const bool pqc_required = (m_hardfork->get_current_version() >= HF_VERSION_PBC_PQC_SPEND_AUTH);
            const crypto::hash pqc_msg_hash = pbc_build_pqc_market_payout_msg_hash(seller_pubkey, payout_amount);
            const std::string seller_hex = epee::string_tools::pod_to_hex(seller_pubkey);
            uint8_t reg_dil[pqc::DILITHIUM_PUBLIC_KEY_SIZE];
            size_t  reg_dil_sz = 0;
            const bool have_registered =
                pbc_load_packed_props(m_db, "pbc_pqc_" + seller_hex + "_dilithium", reg_dil, sizeof(reg_dil), reg_dil_sz)
                && reg_dil_sz == pqc::DILITHIUM_PUBLIC_KEY_SIZE;
            bool cosig_present = false;
            std::string cosig_fail;
            const bool cosig_ok = pbc_verify_dilithium_cosig(
                p_fields, pqc_msg_hash,
                have_registered ? reg_dil : nullptr, have_registered ? reg_dil_sz : 0,
                pqc_required, cosig_present, cosig_fail);
            if (!cosig_ok)
            {
              MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM " << cosig_fail << " seller=" << seller_pubkey
                << " tx=" << p_tx_id);
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }
          }
        }

        // Verify conservation: sum(vout.amount) == payout_amount.
        {
          uint64_t sum_vout = 0;
          for (const auto& o : p_tx.vout)
          {
            if (sum_vout > std::numeric_limits<uint64_t>::max() - o.amount)
            {
              MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM vout sum overflow tx=" << p_tx_id);
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }
            sum_vout += o.amount;
          }
          if (sum_vout != payout_amount)
          {
            MERROR("PBC MKTPAY: MARKET_PAYOUT_CLAIM vout sum mismatch: sum=" << sum_vout
              << " payout=" << payout_amount << " tx=" << p_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
        }

        // Save undo state and apply: zero out the pbc_mktpay balance.
        // (Pool was already debited at auto-match time — no pool debit here.)
        m_db->set_property_uint64(pbc_market_key(p_tx_id, "_mktpay_prev"), mktpay_balance);
        m_db->delete_property(pbc_mktpay_key(seller_pubkey));

        MGINFO("PBC MKTPAY: MARKET_PAYOUT_CLAIM applied: tx=" << p_tx_id
          << " seller=" << seller_pubkey
          << " payout=" << payout_amount);
      }

      // ── PF: Process PQC_REGISTER TXs — store PQC public keys in LMDB ──
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& pqc_tx = txs[i].first;
        std::vector<tx_extra_field> pqc_reg_fields;
        tx_extra_pbc_pqc_register reg_marker;
        tx_extra_pbc_dilithium_pubkey dil_pk;
        tx_extra_pbc_kyber_pubkey kyb_pk;

        if (!parse_tx_extra(pqc_tx.extra, pqc_reg_fields))
          continue;
        if (!find_tx_extra_field_by_type(pqc_reg_fields, reg_marker))
          continue;
        if (!find_tx_extra_field_by_type(pqc_reg_fields, dil_pk))
          continue;
        if (!find_tx_extra_field_by_type(pqc_reg_fields, kyb_pk))
          continue;

        // Verify pqc_hash commitment: H(dilithium_pub || kyber_pub) must match
        {
          std::string hash_input;
          hash_input.append(dil_pk.pubkey);
          hash_input.append(kyb_pk.pubkey);
          crypto::hash computed_hash;
          crypto::cn_fast_hash(hash_input.data(), hash_input.size(), computed_hash);
          if (computed_hash != reg_marker.pqc_hash)
          {
            MERROR("PQC REGISTER: hash commitment mismatch in block " << block_height);
            continue; // skip this TX, don't reject the block
          }
        }

        // Extract the spend_pubkey that these PQC keys are being bound to (tag 0x54).
        tx_extra_pbc_owner_key owner_key_field;
        crypto::public_key reg_spend_pk;
        if (find_tx_extra_field_by_type(pqc_reg_fields, owner_key_field))
          reg_spend_pk = owner_key_field.owner_spend_pubkey;
        else
          continue; // no owner key, can't register

        // ── SECURITY FIX (M2, layer 1): proof-of-possession is MANDATORY ──
        // Previously ANY party could register PQC keys under ANYONE's spend pubkey (no proof),
        // and pbc_store_packed_props OVERWRITES, so an attacker could squat/overwrite a victim's
        // registration with attacker-controlled Kyber keys. Combined with a sender that trusts
        // the on-chain Kyber key blindly, that permanently destroyed funds (griefing).
        //
        // We now REQUIRE an owner_sig (tag 0x55) signing
        //     H(PBC_PQC_REGISTER_MSG_PREFIX || reg_spend_pk || pqc_hash)
        // verified against reg_spend_pk. This proves the registrant holds the spend secret key
        // AND commits to the exact pqc_hash being registered. Without a valid signature we skip
        // the store (continue) — we never overwrite an existing legitimate registration.
        //
        // This is a TX-format change (breaking): registration TXs must now carry a matching
        // owner_sig. Acceptable on a resettable closed network; wallet and daemon are updated
        // together (see wallet2::create_pqc_register_tx).
        {
          tx_extra_pbc_owner_sig reg_sig_field;
          if (!find_tx_extra_field_by_type(pqc_reg_fields, reg_sig_field))
          {
            MERROR("PQC REGISTER: missing owner_sig (tag 0x55) — proof-of-possession required; "
                   "skipping registration for " << epee::string_tools::pod_to_hex(reg_spend_pk)
                   << " in block " << block_height);
            continue;
          }
          if (reg_spend_pk == crypto::null_pkey || !crypto::check_key(reg_spend_pk))
          {
            MERROR("PQC REGISTER: owner_spend_pubkey is null/invalid — skipping in block " << block_height);
            continue;
          }
          std::string reg_msg(PBC_PQC_REGISTER_MSG_PREFIX);
          reg_msg.append(reinterpret_cast<const char*>(&reg_spend_pk), sizeof(reg_spend_pk));
          reg_msg.append(reinterpret_cast<const char*>(&reg_marker.pqc_hash), sizeof(reg_marker.pqc_hash));
          const crypto::hash reg_msg_hash = crypto::cn_fast_hash(reg_msg.data(), reg_msg.size());
          if (!crypto::check_signature(reg_msg_hash, reg_spend_pk, reg_sig_field.sig))
          {
            MERROR("PQC REGISTER: owner_sig verification FAILED for "
                   << epee::string_tools::pod_to_hex(reg_spend_pk)
                   << " — refusing to store/overwrite (block " << block_height << ")");
            continue;
          }
        }

        // Store in LMDB (proof-of-possession verified above)
        const std::string pk_hex = epee::string_tools::pod_to_hex(reg_spend_pk);
        const std::string key_dil = "pbc_pqc_" + pk_hex + "_dilithium";
        const std::string key_kyb = "pbc_pqc_" + pk_hex + "_kyber";
        const std::string key_hash = "pbc_pqc_" + pk_hex + "_hash";

        pbc_store_packed_props(m_db, key_dil,
            reinterpret_cast<const uint8_t*>(dil_pk.pubkey.data()), dil_pk.pubkey.size());
        pbc_store_packed_props(m_db, key_kyb,
            reinterpret_cast<const uint8_t*>(kyb_pk.pubkey.data()), kyb_pk.pubkey.size());
        pbc_store_packed_props(m_db, key_hash,
            reinterpret_cast<const uint8_t*>(&reg_marker.pqc_hash), sizeof(reg_marker.pqc_hash));

        MGINFO("PQC REGISTER: stored keys for " << pk_hex
          << " dilithium=" << dil_pk.pubkey.size() << "B"
          << " kyber=" << kyb_pk.pubkey.size() << "B"
          << " block=" << block_height);
      }

      // ── PF: Process TERM_WITHDRAW payout TXs ──
      // Withdraw payout TXs materialize dep_rec.accumulated_reward into a spendable output.
      // The accumulated_reward must have been created by a prior CLAIM (in an earlier block).
      // PBC: track deposit_ids already withdrawn in this block to deduplicate (reorg safety).
      std::unordered_set<crypto::hash> pbc_withdrawn_this_block;
      for (size_t i = 0; i < txs.size(); ++i)
      {
        const transaction& w_tx = txs[i].first;
        const crypto::hash& w_tx_id = std::get<0>(txs_meta[i]);
        crypto::hash deposit_id;
        uint64_t payout_amount = 0;
        uint8_t payout_kind = 0;
        std::string w_fail_reason;

        const pbc_withdraw_result wres = pbc_validate_withdraw_tx(w_tx, deposit_id, payout_amount, payout_kind, w_fail_reason);
        if (wres == PBC_WITHDRAW_INVALID)
        {
          MERROR("PBC PF: INVALID TERM_WITHDRAW in block " << block_height
            << " tx=" << w_tx_id << " — " << w_fail_reason);
          if (pbc_started_batch) m_db->batch_abort();
          m_batch_success = false;
          // PBC: return taken txs to the pool on block failure (was leaking
          // them out of every mempool on each rejected block — 04/09 incident)
          return_txs_to_pool();
          bvc.m_verifivation_failed = true;
          return false;
        }

        if (wres == PBC_WITHDRAW_VALID)
        {
          // G: Double lock — verify strict format + ownership BEFORE debiting pools
          // (defense in depth: check_tx_inputs already ran, but we enforce here too)
          if (w_tx.vin.size() != 1 || w_tx.vin[0].type() != typeid(txin_pbc_withdraw))
          {
            MERROR("PBC PF: TERM_WITHDRAW in block " << block_height << " tx=" << w_tx_id
              << " — vin is not exactly 1 txin_pbc_withdraw");
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          if (get_tx_fee(w_tx) != 0)
          {
            MERROR("PBC PF: TERM_WITHDRAW in block " << block_height << " tx=" << w_tx_id
              << " — fee must be 0");
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          if (w_tx.rct_signatures.type != rct::RCTTypeNull)
          {
            MERROR("PBC PF: TERM_WITHDRAW in block " << block_height << " tx=" << w_tx_id
              << " — rct type must be Null");
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          // Verify vin.deposit_id coherence with extra
          {
            const auto& pbc_in = boost::get<txin_pbc_withdraw>(w_tx.vin[0]);
            if (pbc_in.deposit_id != deposit_id)
            {
              MERROR("PBC PF: TERM_WITHDRAW in block " << block_height << " tx=" << w_tx_id
                << " — deposit_id mismatch vin vs extra");
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }
          }

          // 1. Read deposit from DB
          uint8_t dep_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
          size_t dep_buf_size = PBC_DEPOSIT_RECORD_PACKED_SIZE;
          if (!m_db->get_pbc_deposit(deposit_id, dep_buf, dep_buf_size))
          {
            MERROR("PBC PF: TERM_WITHDRAW references non-existent deposit " << deposit_id
              << " in block " << block_height << " tx=" << w_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          pbc_deposit_record dep_rec;
          pbc_unpack_deposit_record(dep_buf, dep_buf_size, dep_rec);

          // 2. Eligibility: deposit must be active (created before this block)
          if (!(dep_rec.created_height < block_height))
          {
            MERROR("PBC PF: TERM_WITHDRAW on deposit not yet active: " << deposit_id
              << " created=" << dep_rec.created_height
              << " block=" << block_height);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          // 3. Must have a prior confirmed CLAIM that created accumulated_reward
          if (dep_rec.last_claim_height == 0 || !(dep_rec.last_claim_height < block_height))
          {
            MERROR("PBC PF: TERM_WITHDRAW requires prior CLAIM in earlier block: deposit=" << deposit_id
              << " last_claim_height=" << dep_rec.last_claim_height
              << " block=" << block_height);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          if (dep_rec.accumulated_reward == 0)
          {
            // May be a duplicate TX for a deposit already withdrawn earlier in this same block
            // (e.g. old TX returned to pool after reorg + new TX submitted by wallet).
            // Skip silently rather than aborting the block.
            if (pbc_withdrawn_this_block.count(deposit_id))
            {
              MWARNING("PBC PF: TERM_WITHDRAW duplicate in block (deposit already withdrawn): deposit=" << deposit_id
                << " tx=" << w_tx_id << " — skipping");
              continue;
            }
            MERROR("PBC PF: TERM_WITHDRAW has zero accumulated_reward: deposit=" << deposit_id
              << " tx=" << w_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          // 4. Payout must match the current pending accumulated_reward exactly
          if (payout_amount != dep_rec.accumulated_reward)
          {
            MERROR("PBC PF: TERM_WITHDRAW payout mismatch: deposit=" << deposit_id
              << " tx=" << w_tx_id
              << " payout_amount=" << payout_amount
              << " accumulated_reward=" << dep_rec.accumulated_reward);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }

          // 4b. G: Ownership signature verification (dep_rec.owner_key + tag 0x55)
          if (dep_rec.owner_key == crypto::null_pkey)
          {
            MERROR("PBC PF: TERM_WITHDRAW owner_key is null: deposit=" << deposit_id
              << " tx=" << w_tx_id);
            if (pbc_started_batch) m_db->batch_abort();
            m_batch_success = false;
            // PBC: return taken txs to the pool on block failure (was leaking
            // them out of every mempool on each rejected block — 04/09 incident)
            return_txs_to_pool();
            bvc.m_verifivation_failed = true;
            return false;
          }
          {
            std::vector<tx_extra_field> w_fields;
            tx_extra_pbc_owner_sig w_sig_field;
            if (!parse_tx_extra(w_tx.extra, w_fields) || !find_tx_extra_field_by_type(w_fields, w_sig_field))
            {
              MERROR("PBC PF: TERM_WITHDRAW owner_sig missing: deposit=" << deposit_id
                << " tx=" << w_tx_id);
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }
            const crypto::hash msg_hash = pbc_build_withdraw_msg_hash(deposit_id, payout_amount);
            if (!crypto::check_signature(msg_hash, dep_rec.owner_key, w_sig_field.sig))
            {
              MERROR("PBC PF: TERM_WITHDRAW owner_sig invalid: deposit=" << deposit_id
                << " tx=" << w_tx_id);
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }
          }

          // 4c. G: Conservation — sum(vout.amount) == payout_amount
          {
            uint64_t sum_vout = 0;
            for (const auto& o : w_tx.vout)
            {
              if (sum_vout > std::numeric_limits<uint64_t>::max() - o.amount)
              {
                MERROR("PBC PF: TERM_WITHDRAW vout sum overflow: deposit=" << deposit_id
                  << " tx=" << w_tx_id);
                if (pbc_started_batch) m_db->batch_abort();
                m_batch_success = false;
                // PBC: return taken txs to the pool on block failure (was leaking
                // them out of every mempool on each rejected block — 04/09 incident)
                return_txs_to_pool();
                bvc.m_verifivation_failed = true;
                return false;
              }
              sum_vout += o.amount;
            }
            if (sum_vout != payout_amount)
            {
              MERROR("PBC PF: TERM_WITHDRAW vout sum mismatch: sum=" << sum_vout
                << " payout=" << payout_amount
                << " deposit=" << deposit_id << " tx=" << w_tx_id);
              if (pbc_started_batch) m_db->batch_abort();
              m_batch_success = false;
              // PBC: return taken txs to the pool on block failure (was leaking
              // them out of every mempool on each rejected block — 04/09 incident)
              return_txs_to_pool();
              bvc.m_verifivation_failed = true;
              return false;
            }
          }

          // 5. Save pre-withdraw state for reorg reversal
          m_db->set_property_uint64(pbc_withdraw_key(w_tx_id, "_ar"), dep_rec.accumulated_reward);

          // 5b. Apply: debit pools + pending reserve (WITHDRAW = payment)
          CHECK_AND_ASSERT_MES(m_pbc_pool_state.pending_rewards_total >= payout_amount, false,
              "PBC PF: pending_rewards_total underflow on withdraw");
          m_pbc_pool_state.pending_rewards_total -= payout_amount;

          uint64_t dep_debit = payout_amount;
          if (dep_debit > m_pbc_pool_state.deposit_pool_balance)
            dep_debit = m_pbc_pool_state.deposit_pool_balance;
          uint64_t fee_debit = payout_amount - dep_debit;
          CHECK_AND_ASSERT_MES(m_pbc_pool_state.fee_pool_balance >= fee_debit, false,
              "PBC PF: fee_pool_balance insufficient for withdraw after deposit_pool depleted");

          m_pbc_pool_state.deposit_pool_balance -= dep_debit;
          m_pbc_pool_state.fee_pool_balance     -= fee_debit;

          // Store pool debits for reorg reversal
          m_db->set_property_uint64(pbc_withdraw_key(w_tx_id, "_dp"), dep_debit);
          m_db->set_property_uint64(pbc_withdraw_key(w_tx_id, "_fp"), fee_debit);

          // 6. Apply: track lifetime withdrawn, then zero accumulated_reward
          dep_rec.total_withdrawn += payout_amount;
          dep_rec.accumulated_reward = 0;

          // 7. Store updated deposit record
          m_db->remove_pbc_deposit(deposit_id);
          uint8_t upd_buf[PBC_DEPOSIT_RECORD_PACKED_SIZE];
          pbc_pack_deposit_record(dep_rec, upd_buf);
          m_db->add_pbc_deposit(deposit_id, upd_buf, PBC_DEPOSIT_RECORD_PACKED_SIZE);

          pbc_withdrawn_this_block.insert(deposit_id);
          MGINFO("PBC PF: TERM_WITHDRAW applied: tx=" << w_tx_id
            << " deposit=" << deposit_id
            << " payout=" << payout_amount);

          // ── Proof-of-life: reset inactivity clock for inherit ──
          // TERM_WITHDRAW requires the owner's key image. Proves principal is alive.
          // Bug1 fix: save activity undo BEFORE mutation so pop_block can restore.
          // Blob: [0xFF sentinel][96-byte packed record BEFORE update][32-byte principal_pk]
          {
            uint8_t inh_buf[PBC_INHERIT_RECORD_PACKED_SIZE];
            size_t  inh_sz = PBC_INHERIT_RECORD_PACKED_SIZE;
            pbc_inherit_record inh_rec;
            if (m_db->get_pbc_inherit_record(dep_rec.owner_key, inh_buf, inh_sz)
                && pbc_unpack_inherit_record(inh_buf, inh_sz, inh_rec))
            {
              // 129-byte undo blob: [0xFF][96-byte record][32-byte principal_pk]
              uint8_t act_undo[PBC_INHERIT_TX_UNDO_SIZE + sizeof(crypto::public_key)];
              act_undo[0] = PBC_INHERIT_UNDO_TAG_ACTIVITY;
              pbc_pack_inherit_record(inh_rec, act_undo + 1);
              memcpy(act_undo + PBC_INHERIT_TX_UNDO_SIZE, &dep_rec.owner_key, sizeof(crypto::public_key));
              m_db->add_pbc_inherit_tx_undo(w_tx_id, act_undo, sizeof(act_undo));

              inh_rec.last_activity_height = block_height;
              uint8_t inh_out[PBC_INHERIT_RECORD_PACKED_SIZE];
              pbc_pack_inherit_record(inh_rec, inh_out);
              m_db->add_pbc_inherit_record(dep_rec.owner_key, inh_out, sizeof(inh_out));
            }
          }
        }
      }


      // TD-6 §10: Master supply conservation (debug + release)
      assert(pbc_check_conservation(already_generated_coins, m_pbc_pool_state));
      if (!pbc_check_conservation(already_generated_coins, m_pbc_pool_state))
      {
        LOG_ERROR("PBC TRACE CONSERVATION-FAILED h=" << block_height
          << " agc=" << already_generated_coins
          << " — see PBC CONSERVATION FAIL log above for details");
        return false;
      }
      LOG_PRINT_L1("PBC TRACE CONSERVATION-OK h=" << block_height);

      // Automatic expiry processing for active collateral locks at this height
      pbc_process_collateral_lock_expiries(m_db, block_height);

      // Persist pool state to LMDB
      pbc_save_pool_state();

      // ── RAII guard commit: state is now persisted, disable restore ──
      pbc_state_guard.commit();

      LOG_PRINT_L2("PBC pools: deposit=" << m_pbc_pool_state.deposit_pool_balance
        << " fee=" << m_pbc_pool_state.fee_pool_balance
        << " insurance=" << m_pbc_pool_state.insurance_pool_balance
        << " destroyed=" << m_pbc_pool_state.total_destroyed
        << " vested=" << m_pbc_pool_state.total_vested_outputs
        << " cumulative_fees=" << m_pbc_pool_state.cumulative_fees
        << " Σw=" << m_pbc_pool_state.deposit_sum_weights
        << " locked=" << m_pbc_pool_state.total_locked_in_deposits
        << " dep_idx_hi=" << (uint64_t)(m_pbc_pool_state.global_deposit_index >> 64)
        << " dep_idx_lo=" << (uint64_t)(m_pbc_pool_state.global_deposit_index)
        << " fee_idx_hi=" << (uint64_t)(m_pbc_pool_state.global_fee_index >> 64)
        << " fee_idx_lo=" << (uint64_t)(m_pbc_pool_state.global_fee_index)
        << " dep_inflow=" << m_pbc_pool_state.deposit_pool_period_inflow
        << " fee_inflow=" << m_pbc_pool_state.fee_pool_period_inflow);
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("PBC pool state update failed: " << e.what());
      if (pbc_started_batch) m_db->batch_abort();
      m_batch_success = false;
      // PBC: return taken txs to the pool on block failure (was leaking
      // them out of every mempool on each rejected block — 04/09 incident)
      return_txs_to_pool();
      bvc.m_verifivation_failed = true;
      return false;
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // PBC: Commit local batch if we started one (all writes atomic)
  // ═══════════════════════════════════════════════════════════════
  if (pbc_started_batch)
  {
    MDEBUG("PBC atomicity: batch_active=" << m_db->is_batch_active()
      << " (pre-commit, committing local batch)");
    m_db->batch_stop();
    pbc_started_batch = false;
    LOG_PRINT_L1("PBC: Local batch committed — block + pool state atomic");
  }
  if(m_show_time_stats)
  {
    MINFO("Height: " << new_height << " coinbase weight: " << coinbase_weight << " cumm: "
        << cumulative_block_weight << " p/t: " << block_processing_time << " ("
        << target_calculating_time << "/" << longhash_calculating_time << "/"
        << t1 << "/" << t2 << "/" << t3 << "/" << t_exists << "/" << t_pool
        << "/" << t_checktx << "/" << t_dblspnd << "/" << vmt << "/" << addblock << ")ms");
  }

  bvc.m_added_to_main_chain = true;
  ++m_sync_counter;

  // appears to be a NOP *and* is called elsewhere.  wat?
  m_tx_pool.on_blockchain_inc(new_height, id);
  get_difficulty_for_next_block(m_nettype); // just to cache it
  invalidate_block_template_cache();

  const uint8_t new_hf_version = get_current_hard_fork_version();
  if (new_hf_version != hf_version)
  {
    // the genesis block is added before everything's setup, and the txpool is empty
    // when we start from scratch, so we skip this
    const bool is_genesis_block = new_height == 1;
    if (!is_genesis_block)
    {
      MGINFO("Validating txpool for v" << (unsigned)new_hf_version);
      m_tx_pool.validate(new_hf_version);
    }
  }

  const crypto::hash seedhash = get_block_id_by_height(crypto::rx_seedheight(new_height));

  // Make sure that txpool notifications happen BEFORE block and miner data notifications
  notify_txpool_event(std::move(txpool_events));

  // send miner notifications to switch as soon as possible
  send_miner_notifications(new_height, seedhash, id, already_generated_coins);

  // then send block notifications
  for (const auto& notifier: m_block_notifiers)
    notifier(new_height - 1, {std::addressof(bl), 1});

  if (m_hardfork->get_current_version() >= RX_BLOCK_VERSION)
    rx_set_main_seedhash(seedhash.data, tools::get_max_concurrency());

  return true;
}
//------------------------------------------------------------------
bool Blockchain::prune_blockchain(uint32_t pruning_seed)
{
  m_tx_pool.lock();
  epee::misc_utils::auto_scope_leave_caller unlocker = epee::misc_utils::create_scope_leave_handler([&](){m_tx_pool.unlock();});
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  return m_db->prune_blockchain(pruning_seed);
}
//------------------------------------------------------------------
bool Blockchain::update_blockchain_pruning()
{
  m_tx_pool.lock();
  epee::misc_utils::auto_scope_leave_caller unlocker = epee::misc_utils::create_scope_leave_handler([&](){m_tx_pool.unlock();});
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  return m_db->update_pruning();
}
//------------------------------------------------------------------
bool Blockchain::check_blockchain_pruning()
{
  m_tx_pool.lock();
  epee::misc_utils::auto_scope_leave_caller unlocker = epee::misc_utils::create_scope_leave_handler([&](){m_tx_pool.unlock();});
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  return m_db->check_pruning();
}
//------------------------------------------------------------------
// returns min(Mb, 1.7*Ml) as per https://github.com/ArticMine/Monero-Documents/blob/master/MoneroScaling2021-02.pdf from HF_VERSION_LONG_TERM_BLOCK_WEIGHT
uint64_t Blockchain::get_next_long_term_block_weight(uint64_t block_weight) const
{
  PERF_TIMER(get_next_long_term_block_weight);

  const uint64_t db_height = m_db->height();
  const uint64_t nblocks = std::min<uint64_t>(m_long_term_block_weights_window, db_height);

  const uint8_t hf_version = get_current_hard_fork_version();
  if (hf_version < HF_VERSION_LONG_TERM_BLOCK_WEIGHT || nblocks == 0)
    return block_weight;

  uint64_t long_term_median = get_long_term_block_weight_median(db_height - nblocks, nblocks);
  uint64_t long_term_effective_median_block_weight = std::max<uint64_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, long_term_median);

  uint64_t short_term_constraint;
  if (hf_version >= HF_VERSION_2021_SCALING)
  {
    // long_term_block_weight = block_weight bounded to range [long-term-median/1.7, long-term-median*1.7]
    block_weight = std::max<uint64_t>(block_weight, long_term_effective_median_block_weight * 10 / 17);
    short_term_constraint = long_term_effective_median_block_weight + long_term_effective_median_block_weight * 7 / 10;
  }
  else
  {
    // long_term_block_weight = block_weight bounded to range [0, long-term-median*1.4]
    short_term_constraint = long_term_effective_median_block_weight + long_term_effective_median_block_weight * 2 / 5;
  }
  uint64_t long_term_block_weight = std::min<uint64_t>(block_weight, short_term_constraint);

  return long_term_block_weight;
}
//------------------------------------------------------------------
bool Blockchain::update_next_cumulative_weight_limit(uint64_t *long_term_effective_median_block_weight)
{
  PERF_TIMER(update_next_cumulative_weight_limit);

  LOG_PRINT_L3("Blockchain::" << __func__);

  // when we reach this, the last hf version is not yet written to the db
  const uint64_t db_height = m_db->height();
  const uint8_t hf_version = get_current_hard_fork_version();
  uint64_t full_reward_zone = get_min_block_weight(hf_version);

  if (hf_version < HF_VERSION_LONG_TERM_BLOCK_WEIGHT)
  {
    std::vector<uint64_t> weights;
    get_last_n_blocks_weights(weights, CRYPTONOTE_REWARD_BLOCKS_WINDOW);
    m_current_block_cumul_weight_median = epee::misc_utils::median(weights);
  }
  else
  {
    const uint64_t nblocks = std::min<uint64_t>(m_long_term_block_weights_window, db_height);
    const uint64_t long_term_median = get_long_term_block_weight_median(db_height - nblocks, nblocks);

    m_long_term_effective_median_block_weight = std::max<uint64_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, long_term_median);

    std::vector<uint64_t> weights;
    get_last_n_blocks_weights(weights, CRYPTONOTE_REWARD_BLOCKS_WINDOW);

    uint64_t short_term_median = epee::misc_utils::median(weights);
    uint64_t effective_median_block_weight;
    if (hf_version >= HF_VERSION_2021_SCALING)
    {
      // effective median = short_term_median bounded to range [long_term_median, 50*long_term_median], but it can't be smaller than the
      // minimum penalty free zone (a.k.a. 'full reward zone')
      effective_median_block_weight = std::min<uint64_t>(std::max<uint64_t>(m_long_term_effective_median_block_weight, short_term_median), CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * m_long_term_effective_median_block_weight);
    }
    else
    {
      // effective median = short_term_median bounded to range [0, 50*long_term_median], but it can't be smaller than the
      // minimum penalty free zone (a.k.a. 'full reward zone')
      effective_median_block_weight = std::min<uint64_t>(std::max<uint64_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, short_term_median), CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * m_long_term_effective_median_block_weight);
    }

    m_current_block_cumul_weight_median = effective_median_block_weight;
  }

  if (m_current_block_cumul_weight_median <= full_reward_zone)
    m_current_block_cumul_weight_median = full_reward_zone;

  m_current_block_cumul_weight_limit = m_current_block_cumul_weight_median * 2;

  if (long_term_effective_median_block_weight)
    *long_term_effective_median_block_weight = m_long_term_effective_median_block_weight;

  if (!m_db->is_read_only())
    m_db->add_max_block_size(m_current_block_cumul_weight_limit);

  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_new_block(const block& bl_, block_verification_context& bvc)
{
  pool_supplement ps{};
  return add_new_block(bl_, bvc, ps);
}
//------------------------------------------------------------------
bool Blockchain::add_new_block(const block& bl, block_verification_context& bvc,
  pool_supplement& extra_block_txs)
{
  try
  {

  LOG_PRINT_L3("Blockchain::" << __func__);
  crypto::hash id = get_block_hash(bl);
  CRITICAL_REGION_LOCAL(m_tx_pool);//to avoid deadlock lets lock tx_pool for whole add/reorganize process
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);
  db_rtxn_guard rtxn_guard(m_db);
  if(have_block(id))
  {
    LOG_PRINT_L3("block with id = " << id << " already exists");
    bvc.m_already_exists = true;
    return false;
  }

  //check that block refers to chain tail
  if(!(bl.prev_id == get_tail_id()))
  {
    //chain switching or wrong block
    bvc.m_added_to_main_chain = false;
    rtxn_guard.stop();
    return handle_alternative_block(bl, id, bvc, extra_block_txs);
    //never relay alternative blocks
  }

  rtxn_guard.stop();
  bool r = handle_block_to_main_chain(bl, id, bvc, extra_block_txs);
  return r;

  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Exception at [add_new_block], what=" << e.what());
    bvc.m_verifivation_failed = true;
    return false;
  }
}
//------------------------------------------------------------------
//TODO: Refactor, consider returning a failure height and letting
//      caller decide course of action.
void Blockchain::check_against_checkpoints(const checkpoints& points, bool enforce)
{
  const auto& pts = points.get_points();
  bool stop_batch;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  stop_batch = m_db->batch_start();
  const uint64_t blockchain_height = m_db->height();
  for (const auto& pt : pts)
  {
    // if the checkpoint is for a block we don't have yet, move on
    if (pt.first >= blockchain_height)
    {
      continue;
    }

    if (!points.check_block(pt.first, m_db->get_block_hash_from_height(pt.first)))
    {
      // if asked to enforce checkpoints, roll back to a couple of blocks before the checkpoint
      if (enforce)
      {
        LOG_ERROR("Local blockchain failed to pass a checkpoint, rolling back!");
        std::list<block> empty;
        rollback_blockchain_switching(empty, pt.first - 2);
      }
      else
      {
        LOG_ERROR("WARNING: local blockchain failed to pass a MoneroPulse checkpoint, and you could be on a fork. You should either sync up from scratch, OR download a fresh blockchain bootstrap, OR enable checkpoint enforcing with the --enforce-dns-checkpointing command-line option");
      }
    }
  }
  if (stop_batch)
    m_db->batch_stop();
}
//------------------------------------------------------------------
// returns false if any of the checkpoints loading returns false.
// That should happen only if a checkpoint is added that conflicts
// with an existing checkpoint.
bool Blockchain::update_checkpoints(const std::string& file_path, bool check_dns)
{
  if (!m_checkpoints.load_checkpoints_from_json(file_path))
  {
      return false;
  }

  // if we're checking both dns and json, load checkpoints from dns.
  // if we're not hard-enforcing dns checkpoints, handle accordingly
  if (m_enforce_dns_checkpoints && check_dns && !m_offline)
  {
    if (!m_checkpoints.load_checkpoints_from_dns())
    {
      return false;
    }
  }
  else if (check_dns && !m_offline)
  {
    checkpoints dns_points;
    dns_points.load_checkpoints_from_dns();
    if (m_checkpoints.check_for_conflicts(dns_points))
    {
      check_against_checkpoints(dns_points, false);
    }
    else
    {
      MERROR("One or more checkpoints fetched from DNS conflicted with existing checkpoints!");
    }
  }

  check_against_checkpoints(m_checkpoints, true);

  return true;
}
//------------------------------------------------------------------
void Blockchain::set_enforce_dns_checkpoints(bool enforce_checkpoints)
{
  m_enforce_dns_checkpoints = enforce_checkpoints;
}

//------------------------------------------------------------------
void Blockchain::block_longhash_worker(uint64_t height, const epee::span<const block> &blocks, std::unordered_map<crypto::hash, crypto::hash> &map) const
{
  TIME_MEASURE_START(t);
  slow_hash_allocate_state();

  for (const auto & block : blocks)
  {
    if (m_cancel)
       break;
    crypto::hash id = get_block_hash(block);
    crypto::hash pow = get_block_longhash(this, block, height++, 0);
    map.emplace(id, pow);
  }

  slow_hash_free_state_cn_only(); // PBC: keep RandomX VMs alive between verifications
  TIME_MEASURE_FINISH(t);
}

//------------------------------------------------------------------
bool Blockchain::cleanup_handle_incoming_blocks(bool force_sync)
{
  bool success = false;

  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_BEGIN(m_blockchain_lock);
  TIME_MEASURE_START(t1);

  try
  {
    if (m_batch_success)
    {
      m_db->batch_stop();
      if (m_reset_timestamps_and_difficulties_height)
      {
        m_timestamps_and_difficulties_height = 0;
        m_reset_timestamps_and_difficulties_height = false;
      }
    }
    else
      m_db->batch_abort();
    success = true;
  }
  catch (const std::exception &e)
  {
    MERROR("Exception in cleanup_handle_incoming_blocks: " << e.what());
  }

  if (success && m_sync_counter > 0)
  {
    if (force_sync)
    {
      if(m_db_sync_mode != db_nosync)
        store_blockchain();
      m_sync_counter = 0;
    }
    else if (m_db_sync_threshold && ((m_db_sync_on_blocks && m_sync_counter >= m_db_sync_threshold) || (!m_db_sync_on_blocks && m_bytes_to_sync >= m_db_sync_threshold)))
    {
      MDEBUG("Sync threshold met, syncing");
      if(m_db_sync_mode == db_async)
      {
        m_sync_counter = 0;
        m_bytes_to_sync = 0;
        boost::asio::dispatch(m_async_service, boost::bind(&Blockchain::store_blockchain, this));
      }
      else if(m_db_sync_mode == db_sync)
      {
        store_blockchain();
      }
      else // db_nosync
      {
        // DO NOTHING, not required to call sync.
      }
    }
  }

  TIME_MEASURE_FINISH(t1);
  m_blocks_longhash_table.clear();
  m_scan_table.clear();

  // when we're well clear of the precomputed hashes, free the memory
  if (!m_blocks_hash_check.empty() && m_db->height() > m_blocks_hash_check.size() + 4096)
  {
    MINFO("Dumping block hashes, we're now 4k past " << m_blocks_hash_check.size());
    m_blocks_hash_check.clear();
    m_blocks_hash_check.shrink_to_fit();
  }

  CRITICAL_REGION_END();
  m_tx_pool.unlock();

  update_blockchain_pruning();

  return success;
}

//------------------------------------------------------------------
void Blockchain::output_scan_worker(const uint64_t amount, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs) const
{
  try
  {
    m_db->get_output_key(epee::span<const uint64_t>(&amount, 1), offsets, outputs, true);
  }
  catch (const std::exception& e)
  {
    MERROR_VER("EXCEPTION: " << e.what());
  }
  catch (...)
  {

  }
}

uint64_t Blockchain::prevalidate_block_hashes(uint64_t height, const std::vector<crypto::hash> &hashes, const std::vector<uint64_t> &weights)
{
  // new: . . . . . X X X X X . . . . . .
  // pre: A A A A B B B B C C C C D D D D

  CHECK_AND_ASSERT_MES(weights.empty() || weights.size() == hashes.size(), 0, "Unexpected weights size");

  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // easy case: height >= hashes
  if (height >= m_blocks_hash_of_hashes.size() * HASH_OF_HASHES_STEP)
    return hashes.size();

  // if we're getting old blocks, we might have jettisoned the hashes already
  if (m_blocks_hash_check.empty())
    return hashes.size();

  // find hashes encompassing those block
  size_t first_index = height / HASH_OF_HASHES_STEP;
  size_t last_index = (height + hashes.size() - 1) / HASH_OF_HASHES_STEP;
  MDEBUG("Blocks " << height << " - " << (height + hashes.size() - 1) << " start at " << first_index << " and end at " << last_index);

  // case of not enough to calculate even a single hash
  if (first_index == last_index && hashes.size() < HASH_OF_HASHES_STEP && (height + hashes.size()) % HASH_OF_HASHES_STEP)
    return hashes.size();

  // build hashes vector to hash hashes together
  std::vector<crypto::hash> data_hashes;
  std::vector<uint64_t> data_weights;
  data_hashes.reserve(hashes.size() + HASH_OF_HASHES_STEP - 1); // may be a bit too much
  if (!weights.empty())
    data_weights.reserve(data_hashes.size());

  // we expect height to be either equal or a bit below db height
  bool disconnected = (height > m_db->height());
  size_t pop;
  if (disconnected && height % HASH_OF_HASHES_STEP)
  {
    ++first_index;
    pop = HASH_OF_HASHES_STEP - height % HASH_OF_HASHES_STEP;
  }
  else
  {
    // we might need some already in the chain for the first part of the first hash
    for (uint64_t h = first_index * HASH_OF_HASHES_STEP; h < height; ++h)
    {
      data_hashes.push_back(m_db->get_block_hash_from_height(h));
      if (!weights.empty())
        data_weights.push_back(m_db->get_block_weight(h));
    }
    pop = 0;
  }

  // push the data to check
  for (size_t i = 0; i < hashes.size(); ++i)
  {
    if (pop)
      --pop;
    else
    {
      data_hashes.push_back(hashes[i]);
      if (!weights.empty())
        data_weights.push_back(weights[i]);
    }
  }

  // hash and check
  uint64_t usable = first_index * HASH_OF_HASHES_STEP - height; // may start negative, but unsigned under/overflow is not UB
  for (size_t n = first_index; n <= last_index; ++n)
  {
    if (n < m_blocks_hash_of_hashes.size())
    {
      // if the last index isn't fully filled, we can't tell if valid
      if (data_hashes.size() < (n - first_index) * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP)
        break;

      crypto::hash hash;
      cn_fast_hash(data_hashes.data() + (n - first_index) * HASH_OF_HASHES_STEP, HASH_OF_HASHES_STEP * sizeof(crypto::hash), hash);
      bool valid = hash == m_blocks_hash_of_hashes[n].first;
      if (valid && !weights.empty())
      {
        cn_fast_hash(data_weights.data() + (n - first_index) * HASH_OF_HASHES_STEP, HASH_OF_HASHES_STEP * sizeof(uint64_t), hash);
        valid &= hash == m_blocks_hash_of_hashes[n].second;
      }

      // add to the known hashes array
      if (!valid)
      {
        MDEBUG("invalid hash for blocks " << n * HASH_OF_HASHES_STEP << " - " << (n * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP - 1));
        break;
      }

      size_t end = n * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP;
      for (size_t i = n * HASH_OF_HASHES_STEP; i < end; ++i)
      {
        CHECK_AND_ASSERT_MES(m_blocks_hash_check[i].first == crypto::null_hash || m_blocks_hash_check[i].first == data_hashes[i - first_index * HASH_OF_HASHES_STEP],
            0, "Consistency failure in m_blocks_hash_check construction");
        m_blocks_hash_check[i].first = data_hashes[i - first_index * HASH_OF_HASHES_STEP];
        if (!weights.empty())
        {
          CHECK_AND_ASSERT_MES(m_blocks_hash_check[i].second == 0 || m_blocks_hash_check[i].second == data_weights[i - first_index * HASH_OF_HASHES_STEP],
              0, "Consistency failure in m_blocks_hash_check construction");
          m_blocks_hash_check[i].second = data_weights[i - first_index * HASH_OF_HASHES_STEP];
        }
      }
      usable += HASH_OF_HASHES_STEP;
    }
    else
    {
      // if after the end of the precomputed blocks, accept anything
      usable += HASH_OF_HASHES_STEP;
      if (usable > hashes.size())
        usable = hashes.size();
    }
  }
  MDEBUG("usable: " << usable << " / " << hashes.size());
  CHECK_AND_ASSERT_MES(usable < std::numeric_limits<uint64_t>::max() / 2, 0, "usable is negative");
  return usable;
}

bool Blockchain::has_block_weights(uint64_t height, uint64_t nblocks) const
{
  CHECK_AND_ASSERT_MES(nblocks > 0, false, "nblocks is 0");
  uint64_t last_block_height = height + nblocks - 1;
  if (last_block_height >= m_blocks_hash_check.size())
    return false;
  for (uint64_t h = height; h <= last_block_height; ++h)
    if (m_blocks_hash_check[h].second == 0)
      return false;
  return true;
}

//------------------------------------------------------------------
// ND: Speedups:
// 1. Thread long_hash computations if possible (m_max_prepare_blocks_threads = nthreads, default = 4)
// 2. Group all amounts (from txs) and related absolute offsets and form a table of tx_prefix_hash
//    vs [k_image, output_keys] (m_scan_table). This is faster because it takes advantage of bulk queries
//    and is threaded if possible. The table (m_scan_table) will be used later when querying output
//    keys.
bool Blockchain::prepare_handle_incoming_blocks(const std::vector<block_complete_entry> &blocks_entry, std::vector<block> &blocks)
{
  MTRACE("Blockchain::" << __func__);
  TIME_MEASURE_START(prepare);
  bool stop_batch;
  uint64_t bytes = 0;
  size_t total_txs = 0;
  blocks.clear();

  // Order of locking must be:
  //  m_incoming_tx_lock (optional)
  //  m_tx_pool lock
  //  blockchain lock
  //
  //  Something which takes the blockchain lock may never take the txpool lock
  //  if it has not provably taken the txpool lock earlier
  //
  //  The txpool lock is now taken in prepare_handle_incoming_blocks
  //  and released in cleanup_handle_incoming_blocks. This avoids issues
  //  when something uses the pool, which now uses the blockchain and
  //  needs a batch, since a batch could otherwise be active while the
  //  txpool and blockchain locks were not held

  m_tx_pool.lock();
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  if(blocks_entry.size() == 0)
    return false;

  for (const auto &entry : blocks_entry)
  {
    bytes += entry.block.size();
    for (const auto &tx_blob : entry.txs)
    {
      bytes += tx_blob.blob.size();
    }
    total_txs += entry.txs.size();
  }
  m_bytes_to_sync += bytes;
  while (!(stop_batch = m_db->batch_start(blocks_entry.size(), bytes))) {
    m_blockchain_lock.unlock();
    m_tx_pool.unlock();
    epee::misc_utils::sleep_no_w(1000);
    m_tx_pool.lock();
    m_blockchain_lock.lock();
  }
  m_batch_success = true;

  const uint64_t height = m_db->height();
  if ((height + blocks_entry.size()) < m_blocks_hash_check.size())
    return true;

  bool blocks_exist = false;
  tools::threadpool& tpool = tools::threadpool::getInstanceForCompute();
  unsigned threads = tpool.get_max_concurrency();
  blocks.resize(blocks_entry.size());

  if (1)
  {
    // limit threads, default limit = 4
    if(threads > m_max_prepare_blocks_threads)
      threads = m_max_prepare_blocks_threads;

    unsigned int batches = blocks_entry.size() / threads;
    unsigned int extra = blocks_entry.size() % threads;
    MDEBUG("block_batches: " << batches);
    std::vector<std::unordered_map<crypto::hash, crypto::hash>> maps(threads);
    auto it = blocks_entry.begin();
    unsigned blockidx = 0;

    const crypto::hash tophash = m_db->top_block_hash();
    for (unsigned i = 0; i < threads; i++)
    {
      for (unsigned int j = 0; j < batches; j++, ++blockidx)
      {
        block &block = blocks[blockidx];
        crypto::hash block_hash;

        if (!parse_and_validate_block_from_blob(it->block, block, block_hash))
          return false;

        // check first block and skip all blocks if its not chained properly
        if (blockidx == 0)
        {
          if (block.prev_id != tophash)
          {
            MDEBUG("Skipping prepare blocks. New blocks don't belong to chain.");
            blocks.clear();
            return true;
          }
        }
        if (have_block(block_hash))
          blocks_exist = true;

        std::advance(it, 1);
      }
    }

    for (unsigned i = 0; i < extra && !blocks_exist; i++, blockidx++)
    {
      block &block = blocks[blockidx];
      crypto::hash block_hash;

      if (!parse_and_validate_block_from_blob(it->block, block, block_hash))
        return false;

      if (have_block(block_hash))
        blocks_exist = true;

      std::advance(it, 1);
    }

    if (!blocks_exist)
    {
      m_blocks_longhash_table.clear();
      uint64_t thread_height = height;
      tools::threadpool::waiter waiter(tpool);
      m_prepare_height = height;
      m_prepare_nblocks = blocks_entry.size();
      m_prepare_blocks = &blocks;
      for (unsigned int i = 0; i < threads; i++)
      {
        unsigned nblocks = batches;
        if (i < extra)
          ++nblocks;
        if (nblocks == 0)
          break;
        tpool.submit(&waiter, boost::bind(&Blockchain::block_longhash_worker, this, thread_height, epee::span<const block>(&blocks[thread_height - height], nblocks), std::ref(maps[i])), true);
        thread_height += nblocks;
      }

      if (!waiter.wait())
        return false;
      m_prepare_height = 0;

      if (m_cancel)
         return false;

      for (const auto & map : maps)
      {
        m_blocks_longhash_table.insert(map.begin(), map.end());
      }
    }
  }

  if (m_cancel)
    return false;

  if (blocks_exist)
  {
    MDEBUG("Skipping remainder of prepare blocks. Blocks exist.");
    return true;
  }

  m_fake_scan_time = 0;
  m_fake_pow_calc_time = 0;

  m_scan_table.clear();

  TIME_MEASURE_FINISH(prepare);
  m_fake_pow_calc_time = prepare / blocks_entry.size();

  if (blocks_entry.size() > 1 && threads > 1 && m_show_time_stats)
    MDEBUG("Prepare blocks took: " << prepare << " ms");

  TIME_MEASURE_START(scantable);

  // [input] stores all unique amounts found
  std::vector < uint64_t > amounts;
  // [input] stores all absolute_offsets for each amount
  std::map<uint64_t, std::vector<uint64_t>> offset_map;
  // [output] stores all output_data_t for each absolute_offset
  std::map<uint64_t, std::vector<output_data_t>> tx_map;
  std::vector<std::pair<cryptonote::transaction, crypto::hash>> txes(total_txs);

#define SCAN_TABLE_QUIT(m) \
        do { \
            MERROR_VER(m) ;\
            m_scan_table.clear(); \
            return false; \
        } while(0); \

  // generate sorted tables for all amounts and absolute offsets
  size_t tx_index = 0, block_index = 0;
  for (const auto &entry : blocks_entry)
  {
    if (m_cancel)
      return false;

    for (const auto &tx_blob : entry.txs)
    {
      if (tx_index >= txes.size())
        SCAN_TABLE_QUIT("tx_index is out of sync");
      transaction &tx = txes[tx_index].first;
      crypto::hash &tx_prefix_hash = txes[tx_index].second;
      ++tx_index;

      if (!parse_and_validate_tx_base_from_blob(tx_blob.blob, tx))
        SCAN_TABLE_QUIT("Could not parse tx from incoming blocks.");
      cryptonote::get_transaction_prefix_hash(tx, tx_prefix_hash);

      auto its = m_scan_table.find(tx_prefix_hash);
      if (its != m_scan_table.end())
        SCAN_TABLE_QUIT("Duplicate tx found from incoming blocks.");

      m_scan_table.emplace(tx_prefix_hash, std::unordered_map<crypto::key_image, std::vector<output_data_t>>());
      its = m_scan_table.find(tx_prefix_hash);
      assert(its != m_scan_table.end());

      // get all amounts from tx.vin(s)
      for (const auto &txin : tx.vin)
      {
        // PBC: skip virtual inputs (no key image, no ring)
        if (txin.type() != typeid(txin_to_key))
          continue;
        const txin_to_key &in_to_key = boost::get < txin_to_key > (txin);

        // check for duplicate
        auto it = its->second.find(in_to_key.k_image);
        if (it != its->second.end())
          SCAN_TABLE_QUIT("Duplicate key_image found from incoming blocks.");

        amounts.push_back(in_to_key.amount);
      }

      // sort and remove duplicate amounts from amounts list
      std::sort(amounts.begin(), amounts.end());
      auto last = std::unique(amounts.begin(), amounts.end());
      amounts.erase(last, amounts.end());

      // add amount to the offset_map and tx_map
      for (const uint64_t &amount : amounts)
      {
        if (offset_map.find(amount) == offset_map.end())
          offset_map.emplace(amount, std::vector<uint64_t>());

        if (tx_map.find(amount) == tx_map.end())
          tx_map.emplace(amount, std::vector<output_data_t>());
      }

      // add new absolute_offsets to offset_map
      for (const auto &txin : tx.vin)
      {
        // PBC: skip virtual inputs (no ring offsets)
        if (txin.type() != typeid(txin_to_key))
          continue;
        const txin_to_key &in_to_key = boost::get < txin_to_key > (txin);
        // no need to check for duplicate here.
        auto absolute_offsets = relative_output_offsets_to_absolute(in_to_key.key_offsets);
        for (const auto & offset : absolute_offsets)
          offset_map[in_to_key.amount].push_back(offset);

      }
    }
    ++block_index;
  }

  // sort and remove duplicate absolute_offsets in offset_map
  for (auto &offsets : offset_map)
  {
    std::sort(offsets.second.begin(), offsets.second.end());
    auto last = std::unique(offsets.second.begin(), offsets.second.end());
    offsets.second.erase(last, offsets.second.end());
  }

  // gather all the output keys
  threads = tpool.get_max_concurrency();
  if (!m_db->can_thread_bulk_indices())
    threads = 1;

  if (threads > 1 && amounts.size() > 1)
  {
    tools::threadpool::waiter waiter(tpool);

    for (size_t i = 0; i < amounts.size(); i++)
    {
      uint64_t amount = amounts[i];
      tpool.submit(&waiter, boost::bind(&Blockchain::output_scan_worker, this, amount, std::cref(offset_map[amount]), std::ref(tx_map[amount])), true);
    }
    if (!waiter.wait())
      return false;
  }
  else
  {
    for (size_t i = 0; i < amounts.size(); i++)
    {
      uint64_t amount = amounts[i];
      output_scan_worker(amount, offset_map[amount], tx_map[amount]);
    }
  }

  // now generate a table for each tx_prefix and k_image hashes
  tx_index = 0;
  for (const auto &entry : blocks_entry)
  {
    if (m_cancel)
      return false;

    for (size_t i = 0; i < entry.txs.size(); ++i)
    {
      if (tx_index >= txes.size())
        SCAN_TABLE_QUIT("tx_index is out of sync");
      const transaction &tx = txes[tx_index].first;
      const crypto::hash &tx_prefix_hash = txes[tx_index].second;
      ++tx_index;

      auto its = m_scan_table.find(tx_prefix_hash);
      if (its == m_scan_table.end())
        SCAN_TABLE_QUIT("Tx not found on scan table from incoming blocks.");

      for (const auto &txin : tx.vin)
      {
        // PBC: skip virtual inputs (no key image, no ring)
        if (txin.type() != typeid(txin_to_key))
          continue;
        const txin_to_key &in_to_key = boost::get < txin_to_key > (txin);
        auto needed_offsets = relative_output_offsets_to_absolute(in_to_key.key_offsets);

        std::vector<output_data_t> outputs;
        for (const uint64_t & offset_needed : needed_offsets)
        {
          size_t pos = 0;
          bool found = false;

          for (const uint64_t &offset_found : offset_map[in_to_key.amount])
          {
            if (offset_needed == offset_found)
            {
              found = true;
              break;
            }

            ++pos;
          }

          if (found && pos < tx_map[in_to_key.amount].size())
            outputs.push_back(tx_map[in_to_key.amount].at(pos));
          else
            break;
        }

        its->second.emplace(in_to_key.k_image, outputs);
      }
    }
  }

  TIME_MEASURE_FINISH(scantable);
  if (total_txs > 0)
  {
    m_fake_scan_time = scantable / total_txs;
    if(m_show_time_stats)
      MDEBUG("Prepare scantable took: " << scantable << " ms");
  }

  return true;
}

void Blockchain::prepare_handle_incoming_block_no_preprocess(const size_t block_byte_estimate)
{
  // acquire locks
  m_tx_pool.lock();
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  // increment sync byte counter to trigger sync against database backing store
  // later in cleanup_handle_incoming_blocks()
  m_bytes_to_sync += block_byte_estimate;

  // spin until we start a batch
  while (!m_db->batch_start(1, block_byte_estimate)) {
    m_blockchain_lock.unlock();
    m_tx_pool.unlock();
    epee::misc_utils::sleep_no_w(1000);
    m_tx_pool.lock();
    m_blockchain_lock.lock();
  }
  m_batch_success = true;
}

void Blockchain::add_txpool_tx(const crypto::hash &txid, const cryptonote::blobdata &blob, const txpool_tx_meta_t &meta)
{
  m_db->add_txpool_tx(txid, blob, meta);
}

void Blockchain::update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t &meta)
{
  m_db->update_txpool_tx(txid, meta);
}

void Blockchain::remove_txpool_tx(const crypto::hash &txid)
{
  m_db->remove_txpool_tx(txid);
}

uint64_t Blockchain::get_txpool_tx_count(bool include_sensitive) const
{
  return m_db->get_txpool_tx_count(include_sensitive ? relay_category::all : relay_category::broadcasted);
}

bool Blockchain::get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const
{
  return m_db->get_txpool_tx_meta(txid, meta);
}

bool Blockchain::get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd, relay_category tx_category) const
{
  return m_db->get_txpool_tx_blob(txid, bd, tx_category);
}

cryptonote::blobdata Blockchain::get_txpool_tx_blob(const crypto::hash& txid, relay_category tx_category) const
{
  return m_db->get_txpool_tx_blob(txid, tx_category);
}

bool Blockchain::for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata_ref*)> f, bool include_blob, relay_category tx_category) const
{
  return m_db->for_all_txpool_txes(f, include_blob, tx_category);
}

bool Blockchain::txpool_tx_matches_category(const crypto::hash& tx_hash, relay_category category)
{
  return m_db->txpool_tx_matches_category(tx_hash, category);
}

void Blockchain::set_user_options(uint64_t maxthreads, bool sync_on_blocks, uint64_t sync_threshold, blockchain_db_sync_mode sync_mode, bool fast_sync)
{
  if (sync_mode == db_defaultsync)
  {
    m_db_default_sync = true;
    sync_mode = db_async;
  }
  m_db_sync_mode = sync_mode;
  m_fast_sync = fast_sync;
  m_db_sync_on_blocks = sync_on_blocks;
  m_db_sync_threshold = sync_threshold;
  m_max_prepare_blocks_threads = maxthreads;
}

void Blockchain::set_txpool_notify(TxpoolNotifyCallback&& notify)
{
  std::lock_guard<decltype(m_txpool_notifier_mutex)> lg(m_txpool_notifier_mutex);
  m_txpool_notifier = notify;
}

void Blockchain::add_block_notify(BlockNotifyCallback&& notify)
{
  if (notify)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);
    m_block_notifiers.push_back(std::move(notify));
  }
}

void Blockchain::add_miner_notify(MinerNotifyCallback&& notify)
{
  if (notify)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);
    m_miner_notifiers.push_back(std::move(notify));
  }
}

void Blockchain::notify_txpool_event(std::vector<txpool_event>&& event) const
{
  std::lock_guard<decltype(m_txpool_notifier_mutex)> lg(m_txpool_notifier_mutex);
  if (m_txpool_notifier)
  {
    try
    {
      m_txpool_notifier(std::move(event));
    }
    catch (const std::exception &e)
    {
      MDEBUG("During Blockchain::notify_txpool_event(), ignored exception: " << e.what());
    }
  }
}

void Blockchain::safesyncmode(const bool onoff)
{
  /* all of this is no-op'd if the user set a specific
   * --db-sync-mode at startup.
   */
  if (m_db_default_sync)
  {
    m_db->safesyncmode(onoff);
    m_db_sync_mode = onoff ? db_nosync : db_async;
  }
}

HardFork::State Blockchain::get_hard_fork_state() const
{
  return m_hardfork->get_state();
}

bool Blockchain::get_hard_fork_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const
{
  return m_hardfork->get_voting_info(version, window, votes, threshold, earliest_height, voting);
}

uint64_t Blockchain::get_difficulty_target() const
{
  return get_current_hard_fork_version() < 2 ? DIFFICULTY_TARGET_V1 : DIFFICULTY_TARGET_V2;
}

std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> Blockchain:: get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, uint64_t min_count) const
{
  return m_db->get_output_histogram(amounts, unlocked, recent_cutoff, min_count);
}

std::vector<std::pair<Blockchain::block_extended_info,std::vector<crypto::hash>>> Blockchain::get_alternative_chains() const
{
  std::vector<std::pair<Blockchain::block_extended_info,std::vector<crypto::hash>>> chains;

  blocks_ext_by_hash alt_blocks;
  alt_blocks.reserve(m_db->get_alt_block_count());
  m_db->for_all_alt_blocks([&alt_blocks](const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::blobdata_ref *blob) {
    if (!blob)
    {
      MERROR("No blob, but blobs were requested");
      return false;
    }
    cryptonote::block bl;
    block_extended_info bei;
    if (cryptonote::parse_and_validate_block_from_blob(*blob, bei.bl))
    {
      bei.height = data.height;
      bei.block_cumulative_weight = data.cumulative_weight;
      bei.cumulative_difficulty = data.cumulative_difficulty_high;
      bei.cumulative_difficulty = (bei.cumulative_difficulty << 64) + data.cumulative_difficulty_low;
      bei.already_generated_coins = data.already_generated_coins;
      alt_blocks.insert(std::make_pair(cryptonote::get_block_hash(bei.bl), std::move(bei)));
    }
    else
      MERROR("Failed to parse block from blob");
    return true;
  }, true);

  for (const auto &i: alt_blocks)
  {
    const crypto::hash top = cryptonote::get_block_hash(i.second.bl);
    bool found = false;
    for (const auto &j: alt_blocks)
    {
      if (j.second.bl.prev_id == top)
      {
        found = true;
        break;
      }
    }
    if (!found)
    {
      std::vector<crypto::hash> chain;
      auto h = i.second.bl.prev_id;
      chain.push_back(top);
      blocks_ext_by_hash::const_iterator prev;
      while ((prev = alt_blocks.find(h)) != alt_blocks.end())
      {
        chain.push_back(h);
        h = prev->second.bl.prev_id;
      }
      chains.push_back(std::make_pair(i.second, chain));
    }
  }
  return chains;
}

void Blockchain::cancel()
{
  m_cancel = true;
}

#if defined(PER_BLOCK_CHECKPOINT)
static const char expected_block_hashes_hash[] = "f4608d2d74847169f25202582e9eee3a18e3c904714e47810d815178cfceebc9";
void Blockchain::load_compiled_in_block_hashes(const GetCheckpointsCallback& get_checkpoints)
{
  if (get_checkpoints == nullptr || !m_fast_sync)
  {
    return;
  }
  const epee::span<const unsigned char> &checkpoints = get_checkpoints(m_nettype);
  if (!checkpoints.empty())
  {
    MINFO("Loading precomputed blocks (" << checkpoints.size() << " bytes)");
    if (m_nettype == MAINNET)
    {
      // first check hash
      crypto::hash hash;
      if (!tools::sha256sum(checkpoints.data(), checkpoints.size(), hash))
      {
        MERROR("Failed to hash precomputed blocks data");
        return;
      }
      MINFO("precomputed blocks hash: " << hash << ", expected " << expected_block_hashes_hash);
      cryptonote::blobdata expected_hash_data;
      if (!epee::string_tools::parse_hexstr_to_binbuff(std::string(expected_block_hashes_hash), expected_hash_data) || expected_hash_data.size() != sizeof(crypto::hash))
      {
        MERROR("Failed to parse expected block hashes hash");
        return;
      }
      const crypto::hash expected_hash = *reinterpret_cast<const crypto::hash*>(expected_hash_data.data());
      if (hash != expected_hash)
      {
        MERROR("Block hash data does not match expected hash");
        return;
      }
    }

    if (checkpoints.size() > 4)
    {
      const unsigned char *p = checkpoints.data();
      const uint32_t nblocks = *p | ((*(p+1))<<8) | ((*(p+2))<<16) | ((*(p+3))<<24);
      if (nblocks > (std::numeric_limits<uint32_t>::max() - 4) / sizeof(hash))
      {
        MERROR("Block hash data is too large");
        return;
      }
      const size_t size_needed = 4 + nblocks * (sizeof(crypto::hash) * 2);
      if(checkpoints.size() != size_needed)
      {
        MERROR("Failed to load hashes - unexpected data size");
        return;
      }
      else if(nblocks > 0 && nblocks > (m_db->height() + HASH_OF_HASHES_STEP - 1) / HASH_OF_HASHES_STEP)
      {
        p += sizeof(uint32_t);
        m_blocks_hash_of_hashes.reserve(nblocks);
        for (uint32_t i = 0; i < nblocks; i++)
        {
          crypto::hash hash_hashes, hash_weights;
          memcpy(hash_hashes.data, p, sizeof(hash_hashes.data));
          p += sizeof(hash_hashes.data);
          memcpy(hash_weights.data, p, sizeof(hash_weights.data));
          p += sizeof(hash_weights.data);
          m_blocks_hash_of_hashes.push_back(std::make_pair(hash_hashes, hash_weights));
        }
        m_blocks_hash_check.resize(m_blocks_hash_of_hashes.size() * HASH_OF_HASHES_STEP, std::make_pair(crypto::null_hash, 0));
        MINFO(nblocks << " block hashes loaded");

        // FIXME: clear tx_pool because the process might have been
        // terminated and caused it to store txs kept by blocks.
        // The core will not call check_tx_inputs(..) for these
        // transactions in this case. Consequently, the sanity check
        // for tx hashes will fail in handle_block_to_main_chain(..)
        CRITICAL_REGION_LOCAL(m_tx_pool);

        std::vector<transaction> txs;
        m_tx_pool.get_transactions(txs, true);

        size_t tx_weight;
        uint64_t fee;
        bool relayed, do_not_relay, double_spend_seen, pruned;
        transaction pool_tx;
        blobdata txblob;
        for(const transaction &tx : txs)
        {
          crypto::hash tx_hash = get_transaction_hash(tx);
          m_tx_pool.take_tx(tx_hash, pool_tx, txblob, tx_weight, fee, relayed, do_not_relay, double_spend_seen, pruned);
        }
      }
    }
  }
}
#endif

bool Blockchain::is_within_compiled_block_hash_area(uint64_t height) const
{
  // PBC CHAIN: fresh mainnet, no precomputed block hashes needed
  return false;
}

void Blockchain::lock()
{
  m_blockchain_lock.lock();
}

void Blockchain::unlock()
{
  m_blockchain_lock.unlock();
}

bool Blockchain::for_all_key_images(std::function<bool(const crypto::key_image&)> f) const
{
  return m_db->for_all_key_images(f);
}

bool Blockchain::for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const block&)> f) const
{
  return m_db->for_blocks_range(h1, h2, f);
}

bool Blockchain::for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)> f, bool pruned) const
{
  return m_db->for_all_transactions(f, pruned);
}

bool Blockchain::for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f) const
{
  return m_db->for_all_outputs(f);
}

bool Blockchain::for_all_outputs(uint64_t amount, std::function<bool(uint64_t height)> f) const
{
  return m_db->for_all_outputs(amount, f);
}

void Blockchain::invalidate_block_template_cache()
{
  MDEBUG("Invalidating block template cache");
  m_btc_valid = false;
}

void Blockchain::cache_block_template(const block &b, const cryptonote::account_public_address &address, const blobdata &nonce, const difficulty_type &diff, uint64_t height, uint64_t expected_reward, uint64_t seed_height, const crypto::hash &seed_hash, uint64_t pool_cookie)
{
  MDEBUG("Setting block template cache");
  m_btc = b;
  m_btc_address = address;
  m_btc_nonce = nonce;
  m_btc_difficulty = diff;
  m_btc_height = height;
  m_btc_expected_reward = expected_reward;
  m_btc_seed_hash = seed_hash;
  m_btc_seed_height = seed_height;
  m_btc_pool_cookie = pool_cookie;
  m_btc_valid = true;
}

void Blockchain::send_miner_notifications(uint64_t height, const crypto::hash &seed_hash, const crypto::hash &prev_id, uint64_t already_generated_coins)
{
  if (m_miner_notifiers.empty())
    return;

  const uint8_t major_version = m_hardfork->get_ideal_version(height);
  const difficulty_type diff = get_difficulty_for_next_block(m_nettype);
  const uint64_t median_weight = m_current_block_cumul_weight_median;

  std::vector<tx_block_template_backlog_entry> tx_backlog;
  m_tx_pool.get_block_template_backlog(tx_backlog);

  for (const auto& notifier : m_miner_notifiers)
  {
    notifier(major_version, height, prev_id, seed_hash, diff, median_weight, already_generated_coins, tx_backlog);
  }
}

namespace cryptonote {
template bool Blockchain::get_transactions(const std::vector<crypto::hash>&, std::vector<transaction>&, std::vector<crypto::hash>&, bool) const;
template bool Blockchain::get_split_transactions_blobs(const std::vector<crypto::hash>&, std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>>&, std::vector<crypto::hash>&) const;
}

// ═══════════════════════════════════════════════════════════════
// PBC Virtual Reward Pool State — LMDB Persistence (§19.12)
// ═══════════════════════════════════════════════════════════════

void Blockchain::pbc_save_pool_state() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  m_db->set_property_uint64(PBC_PROP_DEPOSIT_POOL_BALANCE,   m_pbc_pool_state.deposit_pool_balance);
  m_db->set_property_uint64(PBC_PROP_FEE_POOL_BALANCE,       m_pbc_pool_state.fee_pool_balance);
  m_db->set_property_uint64(PBC_PROP_INSURANCE_POOL_BALANCE, m_pbc_pool_state.insurance_pool_balance);
  m_db->set_property_uint64(PBC_PROP_PENDING_REWARDS_TOTAL,  m_pbc_pool_state.pending_rewards_total);
  m_db->set_property_uint64(PBC_PROP_TOTAL_DESTROYED,        m_pbc_pool_state.total_destroyed);
  m_db->set_property_uint64(PBC_PROP_TOTAL_LOCKED_DEPOSITS,  m_pbc_pool_state.total_locked_in_deposits);
  m_db->set_property_uint64(PBC_PROP_TOTAL_VESTED_OUTPUTS,   m_pbc_pool_state.total_vested_outputs);
  // BUG1-FIX: indices are __uint128_t
  m_db->set_property_uint128(PBC_PROP_GLOBAL_DEPOSIT_INDEX,  m_pbc_pool_state.global_deposit_index);
  m_db->set_property_uint128(PBC_PROP_GLOBAL_FEE_INDEX,      m_pbc_pool_state.global_fee_index);
  m_db->set_property_uint64(PBC_PROP_DEPOSIT_PERIOD_INFLOW,  m_pbc_pool_state.deposit_pool_period_inflow);
  m_db->set_property_uint64(PBC_PROP_FEE_PERIOD_INFLOW,      m_pbc_pool_state.fee_pool_period_inflow);
  m_db->set_property_uint64(PBC_PROP_DEPOSIT_SUM_WEIGHTS,    m_pbc_pool_state.deposit_sum_weights);
  m_db->set_property_uint64(PBC_PROP_LAST_INDEX_UPDATE_HEIGHT, m_pbc_pool_state.last_index_update_height);
  m_db->set_property_uint64(PBC_PROP_CUMULATIVE_FEES,        m_pbc_pool_state.cumulative_fees);
}

void Blockchain::pbc_load_pool_state()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // Initialize to zero — if any property is missing, it defaults to 0 (genesis state)
  m_pbc_pool_state = pbc_pool_state{};

  m_db->get_property_uint64(PBC_PROP_DEPOSIT_POOL_BALANCE,   m_pbc_pool_state.deposit_pool_balance);
  m_db->get_property_uint64(PBC_PROP_FEE_POOL_BALANCE,       m_pbc_pool_state.fee_pool_balance);
  m_db->get_property_uint64(PBC_PROP_INSURANCE_POOL_BALANCE, m_pbc_pool_state.insurance_pool_balance);
  m_db->get_property_uint64(PBC_PROP_PENDING_REWARDS_TOTAL,  m_pbc_pool_state.pending_rewards_total);
  m_db->get_property_uint64(PBC_PROP_TOTAL_DESTROYED,        m_pbc_pool_state.total_destroyed);
  m_db->get_property_uint64(PBC_PROP_TOTAL_LOCKED_DEPOSITS,  m_pbc_pool_state.total_locked_in_deposits);
  m_db->get_property_uint64(PBC_PROP_TOTAL_VESTED_OUTPUTS,   m_pbc_pool_state.total_vested_outputs);
  // BUG1-FIX: indices are __uint128_t
  m_db->get_property_uint128(PBC_PROP_GLOBAL_DEPOSIT_INDEX,  m_pbc_pool_state.global_deposit_index);
  m_db->get_property_uint128(PBC_PROP_GLOBAL_FEE_INDEX,      m_pbc_pool_state.global_fee_index);
  m_db->get_property_uint64(PBC_PROP_DEPOSIT_PERIOD_INFLOW,  m_pbc_pool_state.deposit_pool_period_inflow);
  m_db->get_property_uint64(PBC_PROP_FEE_PERIOD_INFLOW,      m_pbc_pool_state.fee_pool_period_inflow);
  m_db->get_property_uint64(PBC_PROP_DEPOSIT_SUM_WEIGHTS,    m_pbc_pool_state.deposit_sum_weights);
  m_db->get_property_uint64(PBC_PROP_LAST_INDEX_UPDATE_HEIGHT, m_pbc_pool_state.last_index_update_height);
  m_db->get_property_uint64(PBC_PROP_CUMULATIVE_FEES,        m_pbc_pool_state.cumulative_fees);
}

void Blockchain::get_pbc_supply_info(uint64_t &agc,
                                     uint64_t &pool_bal,
                                     uint64_t &destroyed,
                                     uint64_t &circulating) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t h = m_db->height();
  agc = h > 0 ? m_db->get_block_already_generated_coins(h - 1) : 0;
  pool_bal = m_pbc_pool_state.pool_balances();
  destroyed = m_pbc_pool_state.total_destroyed;
  circulating = pbc_calc_circulating_supply(agc, m_pbc_pool_state);
}
