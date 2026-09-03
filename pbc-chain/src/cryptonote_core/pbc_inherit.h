#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "cryptonote_basic/account.h"
#include "crypto/crypto.h"

// Consensus-critical, LMDB-stored record describing inheritance settings.
// Keyed by principal spend public key.

#define PBC_INHERIT_RECORD_VERSION 1

namespace cryptonote
{
  struct pbc_inherit_record
  {
    uint8_t version = PBC_INHERIT_RECORD_VERSION;
    account_public_address heir{}; // spend+view pubkeys
    uint64_t last_activity_height = 0; // last confirmed principal activity (setup/cancel)
    uint64_t request_height = 0;       // height of last request (if active)
    uint8_t request_active = 0;        // 0/1
    uint8_t reserved0 = 0;
    uint16_t reserved1 = 0;
  };

  // Packed format: fixed 1 + 64 + 8 + 8 + 1 + 1 + 2 = 85 bytes.
  // We store as 96 bytes for forward compatibility.
  static constexpr size_t PBC_INHERIT_RECORD_PACKED_SIZE = 96;

  void pbc_pack_inherit_record(const pbc_inherit_record& rec, uint8_t out[PBC_INHERIT_RECORD_PACKED_SIZE]);
  bool pbc_unpack_inherit_record(const uint8_t* data, size_t size, pbc_inherit_record& rec);

  // Undo blob for tx-level modifications:
  // [1 byte tag][96 bytes packed record or zero]
  //
  // Tag values:
  //   0x00  = no previous record (SETUP that created a new record)
  //   0x01  = had previous record (SETUP update / REQUEST / CANCEL)
  //   0xFF  = activity-only undo (Bug1 fix: TERM_DEPOSIT / CLAIM / TERM_WITHDRAW
  //           that updated last_activity_height only; the 96 bytes hold the
  //           full record as it was BEFORE the update)
  //
  // Extended blobs (Bug2 fix: SETUP or CANCEL that deleted a testament):
  //   [1 byte tag 0x00 or 0x01][96 bytes record][4 bytes testament_size][testament_size bytes]
  //   testament_size == 0 means no testament was present at that point.
  static constexpr uint8_t  PBC_INHERIT_UNDO_TAG_NO_PREV  = 0x00;
  static constexpr uint8_t  PBC_INHERIT_UNDO_TAG_HAD_PREV = 0x01;
  static constexpr uint8_t  PBC_INHERIT_UNDO_TAG_ACTIVITY = 0xFF; // Bug1 fix
  static constexpr size_t   PBC_INHERIT_TX_UNDO_SIZE = 1 + PBC_INHERIT_RECORD_PACKED_SIZE;

  inline void pbc_make_inherit_tx_undo(bool had_prev, const pbc_inherit_record* prev, uint8_t out[PBC_INHERIT_TX_UNDO_SIZE])
  {
    out[0] = had_prev ? 1 : 0;
    if (had_prev && prev)
      pbc_pack_inherit_record(*prev, out + 1);
    else
      memset(out + 1, 0, PBC_INHERIT_RECORD_PACKED_SIZE);
  }

}
