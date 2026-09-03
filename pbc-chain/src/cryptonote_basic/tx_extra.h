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

#pragma once

// PBC: boost::variant default limit is 20 types (boost::mpl::list<T0..T19>).
// We have 21 types in tx_extra_field — raise the limit before any boost header is pulled in.
// BOOST_MPL_CFG_NO_PREPROCESSED_HEADERS forces boost to use the variadic template-based
// mpl::list instead of the preprocessed gcc/list.hpp which is hardcoded to 20 types.
#ifndef BOOST_VARIANT_LIMIT_TYPES
#  define BOOST_VARIANT_LIMIT_TYPES 30
#endif

#ifndef BOOST_MPL_LIMIT_LIST_SIZE
#  define BOOST_MPL_LIMIT_LIST_SIZE 30
#endif
#ifndef BOOST_MPL_LIMIT_VECTOR_SIZE
#  define BOOST_MPL_LIMIT_VECTOR_SIZE 30
#endif
#ifndef BOOST_MPL_CFG_NO_PREPROCESSED_HEADERS
#  define BOOST_MPL_CFG_NO_PREPROCESSED_HEADERS
#endif


#define TX_EXTRA_PADDING_MAX_COUNT          255
#define TX_EXTRA_NONCE_MAX_COUNT            255

#define TX_EXTRA_TAG_PADDING                0x00
#define TX_EXTRA_TAG_PUBKEY                 0x01
#define TX_EXTRA_NONCE                      0x02
#define TX_EXTRA_MERGE_MINING_TAG           0x03
#define TX_EXTRA_TAG_ADDITIONAL_PUBKEYS     0x04
#define TX_EXTRA_MYSTERIOUS_MINERGATE_TAG   0xDE

#define TX_EXTRA_NONCE_PAYMENT_ID           0x00
#define TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID 0x01

#include "cryptonote_basic/account.h"
#include "serialization/string.h"

namespace cryptonote
{
  struct tx_extra_padding
  {
    size_t size;

    // load
    template <template <bool> class Archive>
    bool member_do_serialize(Archive<false>& ar)
    {
      // size - 1 - because of variant tag
      for (size = 1; size <= TX_EXTRA_PADDING_MAX_COUNT; ++size)
      {
        if (ar.eof())
          break;

        uint8_t zero;
        if (!::do_serialize(ar, zero))
          return false;

        if (0 != zero)
          return false;
      }

      return size <= TX_EXTRA_PADDING_MAX_COUNT;
    }

    // store
    template <template <bool> class Archive>
    bool member_do_serialize(Archive<true>& ar)
    {
      if(TX_EXTRA_PADDING_MAX_COUNT < size)
        return false;

      // i = 1 - because of variant tag
      for (size_t i = 1; i < size; ++i)
      {
        uint8_t zero = 0;
        if (!::do_serialize(ar, zero))
          return false;
      }
      return true;
    }
  };

  struct tx_extra_pub_key
  {
    crypto::public_key pub_key;

    BEGIN_SERIALIZE()
      FIELD(pub_key)
    END_SERIALIZE()
  };

  struct tx_extra_nonce
  {
    std::string nonce;

    BEGIN_SERIALIZE()
      FIELD(nonce)
      if(TX_EXTRA_NONCE_MAX_COUNT < nonce.size()) return false;
    END_SERIALIZE()
  };

  struct tx_extra_merge_mining_tag
  {
    struct serialize_helper
    {
      tx_extra_merge_mining_tag& mm_tag;

      serialize_helper(tx_extra_merge_mining_tag& mm_tag_) : mm_tag(mm_tag_)
      {
      }

      BEGIN_SERIALIZE()
        VARINT_FIELD_N("depth", mm_tag.depth)
        FIELD_N("merkle_root", mm_tag.merkle_root)
      END_SERIALIZE()
    };

    size_t depth;
    crypto::hash merkle_root;

    // load
    template <template <bool> class Archive>
    bool member_do_serialize(Archive<false>& ar)
    {
      std::string field;
      if(!::do_serialize(ar, field))
        return false;

      binary_archive<false> iar{epee::strspan<std::uint8_t>(field)};
      serialize_helper helper(*this);
      return ::serialization::serialize(iar, helper);
    }

    // store
    template <template <bool> class Archive>
    bool member_do_serialize(Archive<true>& ar)
    {
      std::ostringstream oss;
      binary_archive<true> oar(oss);
      serialize_helper helper(*this);
      if(!::do_serialize(oar, helper))
        return false;

      std::string field = oss.str();
      return ::serialization::serialize(ar, field);
    }
  };

  // per-output additional tx pubkey for multi-destination transfers involving at least one subaddress
  struct tx_extra_additional_pub_keys
  {
    std::vector<crypto::public_key> data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  struct tx_extra_mysterious_minergate
  {
    std::string data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  // ═══════════════════════════════════════════════════════════════
  // PBC Term Deposit TX extra fields (TD-0: parse only, no logic)
  // ═══════════════════════════════════════════════════════════════

  // Tag 0x50 — identifies PBC TX type (1=deposit, 2=claim, 3=withdraw)
  struct tx_extra_pbc_tx_type
  {
    uint8_t type;

    BEGIN_SERIALIZE()
      FIELD(type)
    END_SERIALIZE()
  };

  // Tag 0x51 — deposit creation parameters
  struct tx_extra_pbc_deposit_info
  {
    uint64_t amount;
    uint64_t unlock_height;
    uint8_t  tier;

    BEGIN_SERIALIZE()
      FIELD(amount)
      FIELD(unlock_height)
      FIELD(tier)
    END_SERIALIZE()
  };

  // Tag 0x52 — claim: references an existing deposit
  struct tx_extra_pbc_claim_info
  {
    crypto::hash deposit_id;

    BEGIN_SERIALIZE()
      FIELD(deposit_id)
    END_SERIALIZE()
  };

  // Tag 0x53 — early withdrawal: references an existing deposit
  struct tx_extra_pbc_withdraw_info
  {
    crypto::hash deposit_id;

    BEGIN_SERIALIZE()
      FIELD(deposit_id)
    END_SERIALIZE()
  };

  // Tag 0x56 — TERM_WITHDRAW payout specification
  // payout_amount is the public subsidy S (atomic units) which is allowed to
  // increase outputs beyond inputs for this TX (RingCT equation adjusted).
  // payout_kind: 0 = rewards-only (initial supported mode)
  struct tx_extra_pbc_withdraw_payout
  {
    uint64_t payout_amount = 0;
    uint8_t  payout_kind   = 0;

    BEGIN_SERIALIZE()
      VARINT_FIELD(payout_amount)
      FIELD(payout_kind)
    END_SERIALIZE()
  };

  // Tag 0x54 — TD-8: Owner identity (stable spend public key for anti-split)
  struct tx_extra_pbc_owner_key
  {
    crypto::public_key owner_spend_pubkey;

    BEGIN_SERIALIZE()
      FIELD(owner_spend_pubkey)
    END_SERIALIZE()
  };

  // Tag 0x55 — TD-8: Ownership proof (signature by spend secret key)
  struct tx_extra_pbc_owner_sig
  {
    crypto::signature sig;

    BEGIN_SERIALIZE()
      FIELD(sig)
    END_SERIALIZE()
  };

  // ─────────────────────────────────────────────
  // PBC Inheritance
  // ─────────────────────────────────────────────

  // Tag 0x57 — Inheritance setup: define the heir address
  struct tx_extra_pbc_inherit_setup
  {
    account_public_address heir;

    BEGIN_SERIALIZE()
      FIELD(heir)
    END_SERIALIZE()
  };

  // Tag 0x58 — Inheritance target: identify the principal wallet
  struct tx_extra_pbc_inherit_target
  {
    crypto::public_key principal_spend_pubkey;

    BEGIN_SERIALIZE()
      FIELD(principal_spend_pubkey)
    END_SERIALIZE()
  };

  // Tag 0x59 — Inheritance cancel marker (empty payload)
  struct tx_extra_pbc_inherit_cancel
  {
    BEGIN_SERIALIZE()
    END_SERIALIZE()
  };

  // Tag 0x64 — A3 (héritage on-chain gaté consensus) — FONDATION
  // Marqueur posé sur les balayages d'héritage pré-signés. Porte le principal
  // concerné, pour que le consensus puisse REJETER ces TX hors fenêtre d'exécution
  // (anti-diffusion prématurée — verrou F3). Type tx_extra_field, sérialisation
  // tag-driven (clone exact de tx_extra_pbc_inherit_target).
  // INERT tant que le gate (check_tx_inputs) et le marquage wallet ne sont pas câblés.
  struct tx_extra_pbc_inherit_sweep
  {
    crypto::public_key principal_spend_pubkey;

    BEGIN_SERIALIZE()
      FIELD(principal_spend_pubkey)
    END_SERIALIZE()
  };

  // A4 (sous-étape 4) : tx PORTEUR du testament on-chain.
  // Embarque le blob du testament pré-signé (balayage principal->héritier) dans tx_extra,
  // pour qu'il soit ré-extrait et re-stocké par CHAQUE nœud au resync (survie LMDB->chaîne).
  // principal_spend_pubkey identifie le défunt ; testament = blob binaire (<= ~32 KB).
  struct tx_extra_pbc_inherit_testament
  {
    crypto::public_key principal_spend_pubkey;
    uint64_t seq;          // A4 anti-rejeu : séquence monotone signée par P (hauteur de build)
    std::string testament; // blob binaire du balayage pré-signé

    BEGIN_SERIALIZE()
      FIELD(principal_spend_pubkey)
      FIELD(seq)
      FIELD(testament)
      if (testament.empty() || testament.size() > 32768) return false;
    END_SERIALIZE()
  };


  // Tag 0x5A — Marketplace: direct transfer of a deposit to a new owner
  struct tx_extra_pbc_transfer_deposit
  {
    crypto::hash deposit_id;
    crypto::public_key new_owner_spend_pubkey;
    crypto::hash lock_id;
    uint64_t expected_dep_idx;
    uint64_t expected_fee_idx;

    BEGIN_SERIALIZE()
      FIELD(deposit_id)
      FIELD(new_owner_spend_pubkey)
      FIELD(lock_id)
      FIELD(expected_dep_idx)
      FIELD(expected_fee_idx)
    END_SERIALIZE()
  };

  struct tx_extra_pbc_lock_collateral
  {
    crypto::hash deposit_id;
    crypto::public_key buyer_pubkey;
    crypto::public_key seller_pubkey;
    uint64_t amount;
    uint64_t expiry_height;
    uint64_t expected_dep_idx;
    uint64_t expected_fee_idx;
    crypto::signature buyer_signature;

    BEGIN_SERIALIZE()
      FIELD(deposit_id)
      FIELD(buyer_pubkey)
      FIELD(seller_pubkey)
      FIELD(amount)
      FIELD(expiry_height)
      FIELD(expected_dep_idx)
      FIELD(expected_fee_idx)
      FIELD(buyer_signature)
    END_SERIALIZE()
  };

  struct tx_extra_pbc_cancel_lock
  {
    crypto::hash lock_id;
    uint8_t is_voluntary;
    crypto::signature canceller_sig;

    BEGIN_SERIALIZE()
      FIELD(lock_id)
      FIELD(is_voluntary)
      FIELD(canceller_sig)
    END_SERIALIZE()
  };

  // Tag 0x5D — Marketplace: list / update / delist a deposit for sale.
  // ask_price > 0 → list or update; ask_price == 0 → delist.
  // seller_sig signs H(PBC_MARKET_ASK_V1 || deposit_id || ask_price_le8 || seller_pubkey).
  // seller_view_pubkey is included so the daemon can reconstruct the full address for display.
  struct tx_extra_pbc_market_ask
  {
    crypto::hash       deposit_id;
    uint64_t           ask_price = 0;   // atomic units; 0 = delist
    crypto::public_key seller_pubkey;   // spend pubkey (verified against deposit owner_key)
    crypto::public_key seller_view_pubkey; // view pubkey (for address reconstruction only)
    crypto::signature  seller_sig;

    BEGIN_SERIALIZE()
      FIELD(deposit_id)
      VARINT_FIELD(ask_price)
      FIELD(seller_pubkey)
      FIELD(seller_view_pubkey)
      FIELD(seller_sig)
    END_SERIALIZE()
  };

  // Tag 0x5E — Marketplace: claim deferred seller rewards after auto-match.
  // seller_sig signs H(PBC_MKTPAY_V1 || seller_pubkey || payout_amount_le8).
  // TX type must be PBC_TX_TYPE_MARKET_PAYOUT_CLAIM (11).
  struct tx_extra_pbc_market_payout_claim
  {
    crypto::public_key seller_pubkey;   // spend pubkey (key against pbc_mktpay_<hex> in LMDB)
    uint64_t           payout_amount = 0;
    crypto::signature  seller_sig;

    BEGIN_SERIALIZE()
      FIELD(seller_pubkey)
      VARINT_FIELD(payout_amount)
      FIELD(seller_sig)
    END_SERIALIZE()
  };

  // tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
  //   varint tag;
  //   varint size;
  //   varint data[];
  // PQC: ML-DSA-65 (Dilithium3) public key — 1952 bytes
  struct tx_extra_pbc_dilithium_pubkey
  {
    std::string pubkey; // exactly 1952 bytes (stored as binary string)

    BEGIN_SERIALIZE()
      FIELD(pubkey)
      if(pubkey.size() != 1952) return false;
    END_SERIALIZE()
  };

  // PQC: ML-DSA-65 (Dilithium3) signature — up to 3309 bytes
  struct tx_extra_pbc_dilithium_sig
  {
    std::string sig; // up to 3309 bytes (stored as binary string)

    BEGIN_SERIALIZE()
      FIELD(sig)
      if(sig.empty() || sig.size() > 3309) return false;
    END_SERIALIZE()
  };

  // PQC: ML-KEM-768 (Kyber) public key — 1184 bytes
  struct tx_extra_pbc_kyber_pubkey
  {
    std::string pubkey; // exactly 1184 bytes

    BEGIN_SERIALIZE()
      FIELD(pubkey)
      if(pubkey.size() != 1184) return false;
    END_SERIALIZE()
  };

  // PQC: registration marker — contains pqc_hash = H(dilithium_pub || kyber_pub)
  struct tx_extra_pbc_pqc_register
  {
    crypto::hash pqc_hash; // H(dilithium_pub || kyber_pub)

    BEGIN_SERIALIZE()
      FIELD(pqc_hash)
    END_SERIALIZE()
  };

  // PQC: ML-KEM-768 ciphertext for hybrid ECDH — 1088 bytes
  struct tx_extra_pbc_kyber_ciphertext
  {
    std::string ciphertext; // exactly 1088 bytes

    BEGIN_SERIALIZE()
      FIELD(ciphertext)
      if(ciphertext.size() != 1088) return false;
    END_SERIALIZE()
  };

  typedef boost::variant<tx_extra_padding, tx_extra_pub_key, tx_extra_nonce, tx_extra_merge_mining_tag, tx_extra_additional_pub_keys, tx_extra_mysterious_minergate, tx_extra_pbc_tx_type, tx_extra_pbc_deposit_info, tx_extra_pbc_claim_info, tx_extra_pbc_withdraw_info, tx_extra_pbc_owner_key, tx_extra_pbc_owner_sig, tx_extra_pbc_withdraw_payout, tx_extra_pbc_inherit_setup, tx_extra_pbc_inherit_target, tx_extra_pbc_inherit_cancel, tx_extra_pbc_transfer_deposit, tx_extra_pbc_lock_collateral, tx_extra_pbc_cancel_lock, tx_extra_pbc_market_ask, tx_extra_pbc_market_payout_claim, tx_extra_pbc_dilithium_pubkey, tx_extra_pbc_dilithium_sig, tx_extra_pbc_kyber_pubkey, tx_extra_pbc_pqc_register, tx_extra_pbc_kyber_ciphertext, tx_extra_pbc_inherit_sweep, tx_extra_pbc_inherit_testament> tx_extra_field;
}

VARIANT_TAG(binary_archive, cryptonote::tx_extra_padding, TX_EXTRA_TAG_PADDING);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pub_key, TX_EXTRA_TAG_PUBKEY);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_nonce, TX_EXTRA_NONCE);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_merge_mining_tag, TX_EXTRA_MERGE_MINING_TAG);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_additional_pub_keys, TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_mysterious_minergate, TX_EXTRA_MYSTERIOUS_MINERGATE_TAG);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_tx_type, TX_EXTRA_TAG_PBC_TX_TYPE);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_deposit_info, TX_EXTRA_TAG_PBC_DEPOSIT_INFO);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_claim_info, TX_EXTRA_TAG_PBC_CLAIM_INFO);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_withdraw_info, TX_EXTRA_TAG_PBC_WITHDRAW_INFO);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_owner_key, TX_EXTRA_TAG_PBC_OWNER_KEY);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_owner_sig, TX_EXTRA_TAG_PBC_OWNER_SIG);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_withdraw_payout, TX_EXTRA_TAG_PBC_WITHDRAW_PAYOUT);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_inherit_setup, TX_EXTRA_TAG_PBC_INHERIT_SETUP);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_inherit_target, TX_EXTRA_TAG_PBC_INHERIT_TARGET);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_inherit_cancel, TX_EXTRA_TAG_PBC_INHERIT_CANCEL);

VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_transfer_deposit, TX_EXTRA_TAG_PBC_TRANSFER_DEPOSIT);

VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_lock_collateral, TX_EXTRA_TAG_PBC_LOCK_COLLATERAL);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_cancel_lock, TX_EXTRA_TAG_PBC_CANCEL_LOCK);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_dilithium_pubkey, TX_EXTRA_TAG_PBC_DILITHIUM_PUBKEY);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_dilithium_sig, TX_EXTRA_TAG_PBC_DILITHIUM_SIG);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_kyber_pubkey, TX_EXTRA_TAG_PBC_KYBER_PUBKEY);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_pqc_register, TX_EXTRA_TAG_PBC_PQC_REGISTER);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_kyber_ciphertext, TX_EXTRA_TAG_PBC_KYBER_CIPHERTEXT);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_inherit_sweep, TX_EXTRA_TAG_PBC_INHERIT_SWEEP);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_inherit_testament, TX_EXTRA_TAG_PBC_INHERIT_TESTAMENT);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_market_ask, TX_EXTRA_TAG_PBC_MARKET_ASK);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pbc_market_payout_claim, TX_EXTRA_TAG_PBC_MARKET_PAYOUT);
