#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "crypto/crypto.h"
#include "cryptonote_basic/account.h"

namespace cryptonote
{
static constexpr uint8_t PBC_COLLATERAL_LOCK_ACTIVE = 0;
static constexpr uint8_t PBC_COLLATERAL_LOCK_CONSUMED_BY_TRANSFER = 1;
static constexpr uint8_t PBC_COLLATERAL_LOCK_CANCELLED = 2;
static constexpr uint8_t PBC_COLLATERAL_LOCK_EXPIRED = 3;

struct collateral_lock_record
{
  crypto::hash lock_id;
  crypto::hash deposit_id;
  crypto::public_key buyer_pubkey;
  crypto::public_key seller_pubkey;
  uint64_t amount = 0;
  uint64_t created_height = 0;
  uint64_t expiry_height = 0;
  uint8_t status = PBC_COLLATERAL_LOCK_ACTIVE;
  account_public_address buyer_address{};
  account_public_address seller_address{};
  uint64_t expected_dep_idx = 0;
  uint64_t expected_fee_idx = 0;
};

static constexpr size_t PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE = 32+32+32+32+8+8+8+1+64+64+8+8;

inline void pbc_pack_collateral_lock_record(const collateral_lock_record& rec, uint8_t out[PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE])
{
  uint8_t* p = out;
  memcpy(p, &rec.lock_id, 32); p += 32;
  memcpy(p, &rec.deposit_id, 32); p += 32;
  memcpy(p, &rec.buyer_pubkey, 32); p += 32;
  memcpy(p, &rec.seller_pubkey, 32); p += 32;
  memcpy(p, &rec.amount, 8); p += 8;
  memcpy(p, &rec.created_height, 8); p += 8;
  memcpy(p, &rec.expiry_height, 8); p += 8;
  *p++ = rec.status;
  memcpy(p, &rec.buyer_address, sizeof(account_public_address)); p += sizeof(account_public_address);
  memcpy(p, &rec.seller_address, sizeof(account_public_address)); p += sizeof(account_public_address);
  memcpy(p, &rec.expected_dep_idx, 8); p += 8;
  memcpy(p, &rec.expected_fee_idx, 8);
}

inline bool pbc_unpack_collateral_lock_record(const void* data, size_t size, collateral_lock_record& rec)
{
  if (size < PBC_COLLATERAL_LOCK_RECORD_PACKED_SIZE) return false;
  const uint8_t* p = static_cast<const uint8_t*>(data);
  memcpy(&rec.lock_id, p, 32); p += 32;
  memcpy(&rec.deposit_id, p, 32); p += 32;
  memcpy(&rec.buyer_pubkey, p, 32); p += 32;
  memcpy(&rec.seller_pubkey, p, 32); p += 32;
  memcpy(&rec.amount, p, 8); p += 8;
  memcpy(&rec.created_height, p, 8); p += 8;
  memcpy(&rec.expiry_height, p, 8); p += 8;
  rec.status = *p++;
  memcpy(&rec.buyer_address, p, sizeof(account_public_address)); p += sizeof(account_public_address);
  memcpy(&rec.seller_address, p, sizeof(account_public_address)); p += sizeof(account_public_address);
  memcpy(&rec.expected_dep_idx, p, 8); p += 8;
  memcpy(&rec.expected_fee_idx, p, 8);
  return true;
}

inline crypto::hash pbc_build_lock_msg_hash(const crypto::hash& deposit_id, const crypto::public_key& buyer_pubkey, const crypto::public_key& seller_pubkey, uint64_t amount, uint64_t expiry_height, uint64_t expected_dep_idx, uint64_t expected_fee_idx)
{
  std::string msg("PBC_LOCK_COLLATERAL_V1");
  msg.append(reinterpret_cast<const char*>(&deposit_id), sizeof(deposit_id));
  msg.append(reinterpret_cast<const char*>(&buyer_pubkey), sizeof(buyer_pubkey));
  msg.append(reinterpret_cast<const char*>(&seller_pubkey), sizeof(seller_pubkey));
  msg.append(reinterpret_cast<const char*>(&amount), 8);
  msg.append(reinterpret_cast<const char*>(&expiry_height), 8);
  msg.append(reinterpret_cast<const char*>(&expected_dep_idx), 8);
  msg.append(reinterpret_cast<const char*>(&expected_fee_idx), 8);
  return crypto::cn_fast_hash(msg.data(), msg.size());
}

inline crypto::hash pbc_build_cancel_lock_msg_hash(const crypto::hash& lock_id)
{
  std::string msg("PBC_CANCEL_LOCK_V1");
  msg.append(reinterpret_cast<const char*>(&lock_id), sizeof(lock_id));
  return crypto::cn_fast_hash(msg.data(), msg.size());
}

inline crypto::hash pbc_build_transfer_deposit_msg_hash(const crypto::hash& deposit_id, const crypto::public_key& new_owner, const crypto::hash& lock_id, uint64_t expected_dep_idx, uint64_t expected_fee_idx)
{
  std::string msg("PBC_TRANSFER_DEPOSIT_V2");
  msg.append(reinterpret_cast<const char*>(&deposit_id), sizeof(deposit_id));
  msg.append(reinterpret_cast<const char*>(&new_owner), sizeof(new_owner));
  msg.append(reinterpret_cast<const char*>(&lock_id), sizeof(lock_id));
  msg.append(reinterpret_cast<const char*>(&expected_dep_idx), 8);
  msg.append(reinterpret_cast<const char*>(&expected_fee_idx), 8);
  return crypto::cn_fast_hash(msg.data(), msg.size());
}
}
