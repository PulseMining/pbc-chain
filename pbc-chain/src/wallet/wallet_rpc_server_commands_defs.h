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
#include "cryptonote_config.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/subaddress_index.h"
#include "crypto/hash.h"
#include "wallet_rpc_server_error_codes.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.rpc"

// When making *any* change here, bump minor
// If the change is incompatible, then bump major and set minor to 0
// This ensures WALLET_RPC_VERSION always increases, that every change
// has its own version, and that clients can just test major to see
// whether they can talk to a given wallet without having to know in
// advance which version they will stop working with
// Don't go over 32767 for any of these
#define WALLET_RPC_VERSION_MAJOR 1
#define WALLET_RPC_VERSION_MINOR 30
#define MAKE_WALLET_RPC_VERSION(major,minor) (((major)<<16)|(minor))
#define WALLET_RPC_VERSION MAKE_WALLET_RPC_VERSION(WALLET_RPC_VERSION_MAJOR, WALLET_RPC_VERSION_MINOR)
namespace tools
{
namespace wallet_rpc
{
#define WALLET_RPC_STATUS_OK      "OK"
#define WALLET_RPC_STATUS_BUSY    "BUSY"

  struct COMMAND_RPC_GET_BALANCE
  {
    struct request_t
    {
      uint32_t account_index;
      std::set<uint32_t> address_indices;
      bool all_accounts;
      bool strict;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(address_indices)
        KV_SERIALIZE_OPT(all_accounts, false);
        KV_SERIALIZE_OPT(strict, false);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct per_subaddress_info
    {
      uint32_t account_index;
      uint32_t address_index;
      std::string address;
      uint64_t balance;
      uint64_t unlocked_balance;
      std::string label;
      uint64_t num_unspent_outputs;
      uint64_t blocks_to_unlock;
      uint64_t time_to_unlock;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(address_index)
        KV_SERIALIZE(address)
        KV_SERIALIZE(balance)
        KV_SERIALIZE(unlocked_balance)
        KV_SERIALIZE(label)
        KV_SERIALIZE(num_unspent_outputs)
        KV_SERIALIZE(blocks_to_unlock)
        KV_SERIALIZE(time_to_unlock)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      uint64_t 	 balance;
      uint64_t 	 unlocked_balance;
      bool       multisig_import_needed;
      std::vector<per_subaddress_info> per_subaddress;
      uint64_t   blocks_to_unlock;
      uint64_t   time_to_unlock;
      uint64_t   pbc_withdraw_pending_balance; // PBC: TERM_WITHDRAW outputs (unlocked but not ring-signable)

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(balance)
        KV_SERIALIZE(unlocked_balance)
        KV_SERIALIZE(multisig_import_needed)
        KV_SERIALIZE(per_subaddress)
        KV_SERIALIZE(blocks_to_unlock)
        KV_SERIALIZE(time_to_unlock)
        KV_SERIALIZE(pbc_withdraw_pending_balance)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

    struct COMMAND_RPC_GET_ADDRESS
  {
    struct request_t
    {
      uint32_t account_index;
      std::vector<uint32_t> address_index;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(address_index)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct address_info
    {
      std::string address;
      std::string label;
      uint32_t address_index;
      bool used;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(label)
        KV_SERIALIZE(address_index)
        KV_SERIALIZE(used)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      std::string address;                  // to remain compatible with older RPC format
      std::vector<address_info> addresses;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(addresses)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_ADDRESS_INDEX
  {
    struct request_t
    {
      std::string address;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      cryptonote::subaddress_index index;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(index)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SET_SUBADDR_LOOKAHEAD
  {
    struct request_t
    {
      std::string password;
      uint32_t major_idx;
      uint32_t minor_idx;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(password)
        KV_SERIALIZE(major_idx)
        KV_SERIALIZE(minor_idx)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CREATE_ADDRESS
  {
    struct request_t
    {
      uint32_t    account_index;
      uint32_t    count;
      std::string label;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account_index)
        KV_SERIALIZE_OPT(count, 1U)
        KV_SERIALIZE(label)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string              address;
      uint32_t                 address_index;
      std::vector<std::string> addresses;
      std::vector<uint32_t>    address_indices;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(address_index)
        KV_SERIALIZE(addresses)
        KV_SERIALIZE(address_indices)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_LABEL_ADDRESS
  {
    struct request_t
    {
      cryptonote::subaddress_index index;
      std::string label;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(index)
        KV_SERIALIZE(label)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_ACCOUNTS
  {
    struct request_t
    {
      std::string tag;      // all accounts if empty, otherwise those accounts with this tag
      bool strict_balances;
      bool regexp; // allow regular expression filters if set to true

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tag)
        KV_SERIALIZE_OPT(strict_balances, false)
        KV_SERIALIZE_OPT(regexp, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct subaddress_account_info
    {
      uint32_t account_index;
      std::string base_address;
      uint64_t balance;
      uint64_t unlocked_balance;
      std::string label;
      std::string tag;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(base_address)
        KV_SERIALIZE(balance)
        KV_SERIALIZE(unlocked_balance)
        KV_SERIALIZE(label)
        KV_SERIALIZE(tag)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      uint64_t total_balance;
      uint64_t total_unlocked_balance;
      std::vector<subaddress_account_info> subaddress_accounts;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(total_balance)
        KV_SERIALIZE(total_unlocked_balance)
        KV_SERIALIZE(subaddress_accounts)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CREATE_ACCOUNT
  {
    struct request_t
    {
      std::string label;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(label)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint32_t account_index;
      std::string address;      // the 0-th address for convenience
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(address)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_LABEL_ACCOUNT
  {
    struct request_t
    {
      uint32_t account_index;
      std::string label;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(label)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_ACCOUNT_TAGS
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct account_tag_info
    {
      std::string tag;
      std::string label;
      std::vector<uint32_t> accounts;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tag);
        KV_SERIALIZE(label);
        KV_SERIALIZE(accounts);
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      std::vector<account_tag_info> account_tags;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account_tags)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_TAG_ACCOUNTS
  {
    struct request_t
    {
      std::string tag;
      std::set<uint32_t> accounts;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tag)
        KV_SERIALIZE(accounts)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_UNTAG_ACCOUNTS
  {
    struct request_t
    {
      std::set<uint32_t> accounts;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(accounts)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SET_ACCOUNT_TAG_DESCRIPTION
  {
    struct request_t
    {
      std::string tag;
      std::string description;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tag)
        KV_SERIALIZE(description)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

    struct COMMAND_RPC_GET_HEIGHT
    {
      struct request_t
      {
        BEGIN_KV_SERIALIZE_MAP()
        END_KV_SERIALIZE_MAP()
      };
      typedef epee::misc_utils::struct_init<request_t> request;

      struct response_t
      {
        uint64_t  height;
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
        END_KV_SERIALIZE_MAP()
      };
      typedef epee::misc_utils::struct_init<response_t> response;
    };

  struct transfer_destination
  {
    uint64_t amount;
    std::string address;
    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(amount)
      KV_SERIALIZE(address)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_FREEZE
  {
    struct request_t
    {
      std::string key_image;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key_image)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_THAW
  {
    struct request_t
    {
      std::string key_image;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key_image)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_FROZEN
  {
    struct request_t
    {
      std::string key_image;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key_image)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      bool frozen;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(frozen)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct key_image_list
  {
    std::list<std::string> key_images;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(key_images)
    END_KV_SERIALIZE_MAP()
  };

  struct amounts_list
  {
    std::list<uint64_t> amounts;

    bool operator==(const amounts_list& other) const { return amounts == other.amounts; }

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(amounts)
    END_KV_SERIALIZE_MAP()
  };

  struct single_transfer_response
  {
    std::string tx_hash;
    std::string tx_key;
    uint64_t amount;
    amounts_list amounts_by_dest;
    uint64_t fee;
    uint64_t weight;
    std::string tx_blob;
    std::string tx_metadata;
    std::string multisig_txset;
    std::string unsigned_txset;
    key_image_list spent_key_images;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(tx_hash)
      KV_SERIALIZE(tx_key)
      KV_SERIALIZE(amount)
      KV_SERIALIZE_OPT(amounts_by_dest, decltype(amounts_by_dest)())
      KV_SERIALIZE(fee)
      KV_SERIALIZE(weight)
      KV_SERIALIZE(tx_blob)
      KV_SERIALIZE(tx_metadata)
      KV_SERIALIZE(multisig_txset)
      KV_SERIALIZE(unsigned_txset)
      KV_SERIALIZE(spent_key_images)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_TRANSFER
  {
    struct request_t
    {
      std::list<transfer_destination> destinations;
      uint32_t account_index;
      std::set<uint32_t> subaddr_indices;
      std::set<uint32_t> subtract_fee_from_outputs;
      uint32_t priority;
      uint64_t ring_size;
      uint64_t unlock_time;
      std::string payment_id;
      bool get_tx_key;
      bool do_not_relay;
      bool get_tx_hex;
      bool get_tx_metadata;
      std::string idempotency_key;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(destinations)
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(subaddr_indices)
        KV_SERIALIZE_OPT(subtract_fee_from_outputs, decltype(subtract_fee_from_outputs)())
        KV_SERIALIZE(priority)
        KV_SERIALIZE_OPT(ring_size, (uint64_t)0)
        KV_SERIALIZE(unlock_time)
        KV_SERIALIZE(payment_id)
        KV_SERIALIZE(get_tx_key)
        KV_SERIALIZE_OPT(do_not_relay, false)
        KV_SERIALIZE_OPT(get_tx_hex, false)
        KV_SERIALIZE_OPT(get_tx_metadata, false)
        KV_SERIALIZE_OPT(idempotency_key, std::string())
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    typedef single_transfer_response response_t;
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct split_transfer_response
  {
    std::list<std::string> tx_hash_list;
    std::list<std::string> tx_key_list;
    std::list<uint64_t> amount_list;
    std::list<amounts_list> amounts_by_dest_list;
    std::list<uint64_t> fee_list;
    std::list<uint64_t> weight_list;
    std::list<std::string> tx_blob_list;
    std::list<std::string> tx_metadata_list;
    std::string multisig_txset;
    std::string unsigned_txset;
    std::list<key_image_list> spent_key_images_list;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(tx_hash_list)
      KV_SERIALIZE(tx_key_list)
      KV_SERIALIZE(amount_list)
      KV_SERIALIZE_OPT(amounts_by_dest_list, decltype(amounts_by_dest_list)())
      KV_SERIALIZE(fee_list)
      KV_SERIALIZE(weight_list)
      KV_SERIALIZE(tx_blob_list)
      KV_SERIALIZE(tx_metadata_list)
      KV_SERIALIZE(multisig_txset)
      KV_SERIALIZE(unsigned_txset)
      KV_SERIALIZE(spent_key_images_list)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_TRANSFER_SPLIT
  {
    struct request_t
    {
      std::list<transfer_destination> destinations;
      uint32_t account_index;
      std::set<uint32_t> subaddr_indices;
      uint32_t priority;
      uint64_t ring_size;
      uint64_t unlock_time;
      std::string payment_id;
      bool get_tx_keys;
      bool do_not_relay;
      bool get_tx_hex;
      bool get_tx_metadata;
      std::string idempotency_key;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(destinations)
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(subaddr_indices)
        KV_SERIALIZE(priority)
        KV_SERIALIZE_OPT(ring_size, (uint64_t)0)
        KV_SERIALIZE(unlock_time)
        KV_SERIALIZE(payment_id)
        KV_SERIALIZE(get_tx_keys)
        KV_SERIALIZE_OPT(do_not_relay, false)
        KV_SERIALIZE_OPT(get_tx_hex, false)
        KV_SERIALIZE_OPT(get_tx_metadata, false)
        KV_SERIALIZE_OPT(idempotency_key, std::string())
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    typedef split_transfer_response response_t;
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_DESCRIBE_TRANSFER
  {
    struct recipient
    {
      std::string address;
      uint64_t amount;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(amount)
      END_KV_SERIALIZE_MAP()
    };

    struct transfer_description
    {
      uint64_t amount_in;
      uint64_t amount_out;
      uint32_t ring_size;
      uint64_t unlock_time;
      std::list<recipient> recipients;
      std::string payment_id;
      uint64_t change_amount;
      std::string change_address;
      uint64_t fee;
      uint32_t dummy_outputs;
      std::string extra;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(amount_in)
        KV_SERIALIZE(amount_out)
        KV_SERIALIZE(ring_size)
        KV_SERIALIZE(unlock_time)
        KV_SERIALIZE(recipients)
        KV_SERIALIZE(payment_id)
        KV_SERIALIZE(change_amount)
        KV_SERIALIZE(change_address)
        KV_SERIALIZE(fee)
        KV_SERIALIZE(dummy_outputs)
        KV_SERIALIZE(extra)
      END_KV_SERIALIZE_MAP()
    };

    struct txset_summary
    {
      uint64_t amount_in;
      uint64_t amount_out;
      std::list<recipient> recipients;
      uint64_t change_amount;
      std::string change_address;
      uint64_t fee;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(amount_in)
        KV_SERIALIZE(amount_out)
        KV_SERIALIZE(recipients)
        KV_SERIALIZE(change_amount)
        KV_SERIALIZE(change_address)
        KV_SERIALIZE(fee)
      END_KV_SERIALIZE_MAP()
    };

    struct request_t
    {
      std::string unsigned_txset;
      std::string multisig_txset;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(unsigned_txset)
        KV_SERIALIZE(multisig_txset)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::list<transfer_description> desc;
      struct txset_summary summary;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(summary)
        KV_SERIALIZE(desc)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SIGN_TRANSFER
  {
    struct request_t
    {
      std::string unsigned_txset;
      bool export_raw;
      bool get_tx_keys;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(unsigned_txset)
        KV_SERIALIZE_OPT(export_raw, false)
        KV_SERIALIZE_OPT(get_tx_keys, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string signed_txset;
      std::list<std::string> tx_hash_list;
      std::list<std::string> tx_raw_list;
      std::list<std::string> tx_key_list;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(signed_txset)
        KV_SERIALIZE(tx_hash_list)
        KV_SERIALIZE(tx_raw_list)
        KV_SERIALIZE(tx_key_list)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SUBMIT_TRANSFER
  {
    struct request_t
    {
      std::string tx_data_hex;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_data_hex)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::list<std::string> tx_hash_list;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash_list)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SWEEP_DUST
  {
    struct request_t
    {
      bool get_tx_keys;
      bool do_not_relay;
      bool get_tx_hex;
      bool get_tx_metadata;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(get_tx_keys)
        KV_SERIALIZE_OPT(do_not_relay, false)
        KV_SERIALIZE_OPT(get_tx_hex, false)
        KV_SERIALIZE_OPT(get_tx_metadata, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    typedef split_transfer_response response_t;
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SWEEP_ALL
  {
    struct request_t
    {
      std::string address;
      uint32_t account_index;
      std::set<uint32_t> subaddr_indices;
      bool subaddr_indices_all;
      uint32_t priority;
      uint64_t ring_size;
      uint64_t outputs;
      uint64_t unlock_time;
      std::string payment_id;
      bool get_tx_keys;
      uint64_t below_amount;
      bool do_not_relay;
      bool get_tx_hex;
      bool get_tx_metadata;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(subaddr_indices)
        KV_SERIALIZE_OPT(subaddr_indices_all, false)
        KV_SERIALIZE(priority)
        KV_SERIALIZE_OPT(ring_size, (uint64_t)0)
        KV_SERIALIZE_OPT(outputs, (uint64_t)1)
        KV_SERIALIZE(unlock_time)
        KV_SERIALIZE(payment_id)
        KV_SERIALIZE(get_tx_keys)
        KV_SERIALIZE(below_amount)
        KV_SERIALIZE_OPT(do_not_relay, false)
        KV_SERIALIZE_OPT(get_tx_hex, false)
        KV_SERIALIZE_OPT(get_tx_metadata, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    typedef split_transfer_response response_t;
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SWEEP_SINGLE
  {
    struct request_t
    {
      std::string address;
      uint32_t priority;
      uint64_t ring_size;
      uint64_t outputs;
      uint64_t unlock_time;
      std::string payment_id;
      bool get_tx_key;
      std::string key_image;
      bool do_not_relay;
      bool get_tx_hex;
      bool get_tx_metadata;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(priority)
        KV_SERIALIZE_OPT(ring_size, (uint64_t)0)
        KV_SERIALIZE_OPT(outputs, (uint64_t)1)
        KV_SERIALIZE(unlock_time)
        KV_SERIALIZE(payment_id)
        KV_SERIALIZE(get_tx_key)
        KV_SERIALIZE(key_image)
        KV_SERIALIZE_OPT(do_not_relay, false)
        KV_SERIALIZE_OPT(get_tx_hex, false)
        KV_SERIALIZE_OPT(get_tx_metadata, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    typedef single_transfer_response response_t;
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_RELAY_TX
  {
    struct request_t
    {
      std::string hex;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(hex)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_STORE
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct payment_details
  {
    std::string payment_id;
    std::string tx_hash;
    uint64_t amount;
    uint64_t block_height;
    uint64_t unlock_time;
    bool locked;
    cryptonote::subaddress_index subaddr_index;
    std::string address;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(payment_id)
      KV_SERIALIZE(tx_hash)
      KV_SERIALIZE(amount)
      KV_SERIALIZE(block_height)
      KV_SERIALIZE(unlock_time)
      KV_SERIALIZE(locked)
      KV_SERIALIZE(subaddr_index)
      KV_SERIALIZE(address)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_GET_PAYMENTS
  {
    struct request_t
    {
      std::string payment_id;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payment_id)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::list<payment_details> payments;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payments)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_BULK_PAYMENTS
  {
    struct request_t
    {
      std::vector<std::string> payment_ids;
      uint64_t min_block_height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payment_ids)
        KV_SERIALIZE(min_block_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::list<payment_details> payments;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payments)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
  
  struct transfer_details
  {
    uint64_t amount;
    bool spent;
    uint64_t global_index;
    std::string tx_hash;
    cryptonote::subaddress_index subaddr_index;
    std::string key_image;
    std::string pubkey; // owned output public key found
    uint64_t block_height;
    bool frozen;
    bool unlocked;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(amount)
      KV_SERIALIZE(spent)
      KV_SERIALIZE(global_index)
      KV_SERIALIZE(tx_hash)
      KV_SERIALIZE(subaddr_index)
      KV_SERIALIZE(key_image)
      KV_SERIALIZE(pubkey);
      KV_SERIALIZE(block_height)
      KV_SERIALIZE(frozen)
      KV_SERIALIZE(unlocked)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_INCOMING_TRANSFERS
  {
    struct request_t
    {
      std::string transfer_type;
      uint32_t account_index;
      std::set<uint32_t> subaddr_indices;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(transfer_type)
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(subaddr_indices)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::list<transfer_details> transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  //JSON RPC V2
  struct COMMAND_RPC_QUERY_KEY
  {
    struct request_t
    {
      std::string key_type;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key_type)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string key;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_MAKE_INTEGRATED_ADDRESS
  {
    struct request_t
    {
      std::string standard_address;
      std::string payment_id;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(standard_address)
        KV_SERIALIZE(payment_id)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string integrated_address;
      std::string payment_id;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(integrated_address)
        KV_SERIALIZE(payment_id)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SPLIT_INTEGRATED_ADDRESS
  {
    struct request_t
    {
      std::string integrated_address;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(integrated_address)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string standard_address;
      std::string payment_id;
      bool is_subaddress;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(standard_address)
        KV_SERIALIZE(payment_id)
        KV_SERIALIZE(is_subaddress)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_STOP_WALLET
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_RESCAN_BLOCKCHAIN
  {
    struct request_t
    {
      bool hard;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(hard, false);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SET_TX_NOTES
  {
    struct request_t
    {
      std::list<std::string> txids;
      std::list<std::string> notes;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txids)
        KV_SERIALIZE(notes)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_TX_NOTES
  {
    struct request_t
    {
      std::list<std::string> txids;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txids)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::list<std::string> notes;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(notes)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SET_ATTRIBUTE
  {
    struct request_t
    {
      std::string key;
      std::string value;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key)
        KV_SERIALIZE(value)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_ATTRIBUTE
  {
    struct request_t
    {

      std::string key;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string value;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(value)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_TX_KEY
  {
    struct request_t
    {
      std::string txid;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_key;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_key)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CHECK_TX_KEY
  {
    struct request_t
    {
      std::string txid;
      std::string tx_key;
      std::string address;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
        KV_SERIALIZE(tx_key)
        KV_SERIALIZE(address)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint64_t received;
      bool in_pool;
      uint64_t confirmations;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(received)
        KV_SERIALIZE(in_pool)
        KV_SERIALIZE(confirmations)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_TX_PROOF
  {
    struct request_t
    {
      std::string txid;
      std::string address;
      std::string message;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
        KV_SERIALIZE(address)
        KV_SERIALIZE(message)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(signature)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CHECK_TX_PROOF
  {
    struct request_t
    {
      std::string txid;
      std::string address;
      std::string message;
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
        KV_SERIALIZE(address)
        KV_SERIALIZE(message)
        KV_SERIALIZE(signature)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      bool good;
      uint64_t received;
      bool in_pool;
      uint64_t confirmations;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(good)
        KV_SERIALIZE(received)
        KV_SERIALIZE(in_pool)
        KV_SERIALIZE(confirmations)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  typedef std::vector<uint64_t> amounts_container;
  struct transfer_entry
  {
    std::string txid;
    std::string payment_id;
    uint64_t height;
    uint64_t timestamp;
    uint64_t amount;
    amounts_container amounts;
    uint64_t fee;
    std::string note;
    std::list<transfer_destination> destinations;
    std::string type;
    uint64_t unlock_time;
    bool locked;
    cryptonote::subaddress_index subaddr_index;
    std::vector<cryptonote::subaddress_index> subaddr_indices;
    std::string address;
    bool double_spend_seen;
    uint64_t confirmations;
    uint64_t suggested_confirmations_threshold;
    std::string subtype;  // PBC: "deposit", "claim", "withdraw", "transfer", or "" (unknown/incoming)

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(txid);
      KV_SERIALIZE(payment_id);
      KV_SERIALIZE(height);
      KV_SERIALIZE(timestamp);
      KV_SERIALIZE(amount);
      KV_SERIALIZE(amounts);
      KV_SERIALIZE(fee);
      KV_SERIALIZE(note);
      KV_SERIALIZE(destinations);
      KV_SERIALIZE(type);
      KV_SERIALIZE_OPT(subtype, std::string(""))
      KV_SERIALIZE(unlock_time)
      KV_SERIALIZE(locked)
      KV_SERIALIZE(subaddr_index);
      KV_SERIALIZE(subaddr_indices);
      KV_SERIALIZE(address);
      KV_SERIALIZE(double_spend_seen)
      KV_SERIALIZE_OPT(confirmations, (uint64_t)0)
      KV_SERIALIZE_OPT(suggested_confirmations_threshold, (uint64_t)0)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_GET_SPEND_PROOF
  {
    struct request_t
    {
      std::string txid;
      std::string message;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
        KV_SERIALIZE(message)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(signature)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CHECK_SPEND_PROOF
  {
    struct request_t
    {
      std::string txid;
      std::string message;
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
        KV_SERIALIZE(message)
        KV_SERIALIZE(signature)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      bool good;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(good)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_RESERVE_PROOF
  {
    struct request_t
    {
      bool all;
      uint32_t account_index;     // ignored when `all` is true
      uint64_t amount;            // ignored when `all` is true
      std::string message;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(all)
        KV_SERIALIZE(account_index)
        KV_SERIALIZE(amount)
        KV_SERIALIZE(message)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(signature)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CHECK_RESERVE_PROOF
  {
    struct request_t
    {
      std::string address;
      std::string message;
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(message)
        KV_SERIALIZE(signature)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      bool good;
      uint64_t total;
      uint64_t spent;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(good)
        KV_SERIALIZE(total)
        KV_SERIALIZE(spent)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_TRANSFERS
  {
    struct request_t
    {
      bool in;
      bool out;
      bool pending;
      bool failed;
      bool pool;

      bool filter_by_height;
      uint64_t min_height;
      uint64_t max_height;
      uint32_t account_index;
      std::set<uint32_t> subaddr_indices;
      bool all_accounts;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(in);
        KV_SERIALIZE(out);
        KV_SERIALIZE(pending);
        KV_SERIALIZE(failed);
        KV_SERIALIZE(pool);
        KV_SERIALIZE(filter_by_height);
        KV_SERIALIZE(min_height);
        KV_SERIALIZE_OPT(max_height, (uint64_t)CRYPTONOTE_MAX_BLOCK_NUMBER);
        KV_SERIALIZE(account_index);
        KV_SERIALIZE(subaddr_indices);
        KV_SERIALIZE_OPT(all_accounts, false);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::list<transfer_entry> in;
      std::list<transfer_entry> out;
      std::list<transfer_entry> pending;
      std::list<transfer_entry> failed;
      std::list<transfer_entry> pool;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(in);
        KV_SERIALIZE(out);
        KV_SERIALIZE(pending);
        KV_SERIALIZE(failed);
        KV_SERIALIZE(pool);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };


  struct COMMAND_RPC_GET_PBC_STATEMENT
  {
    struct request
    {
      uint32_t days; // default 30
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(days, (uint32_t)30)
      END_KV_SERIALIZE_MAP()
    };

    struct day_entry
    {
      std::string day;
      uint64_t credits;
      uint64_t debits;
      uint64_t fees;
      uint64_t mined;
      int64_t net;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(day)
        KV_SERIALIZE(credits)
        KV_SERIALIZE(debits)
        KV_SERIALIZE(fees)
        KV_SERIALIZE(mined)
        KV_SERIALIZE(net)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::vector<day_entry> days;
      uint64_t claimable;
      uint64_t claimed;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(days)
        KV_SERIALIZE(claimable)
        KV_SERIALIZE(claimed)
      END_KV_SERIALIZE_MAP()
    };

    typedef epee::json_rpc::request<request> json_request;
    typedef epee::json_rpc::response<response, std::string> json_response;
  };
  struct COMMAND_RPC_GET_TRANSFER_BY_TXID
  {
    struct request_t
    {
      std::string txid;
      uint32_t account_index;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid);
        KV_SERIALIZE_OPT(account_index, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      transfer_entry transfer;
      std::list<transfer_entry> transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(transfer);
        KV_SERIALIZE(transfers);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SIGN
  {
    struct request_t
    {
      std::string data;
      uint32_t account_index;
      uint32_t address_index;
      std::string signature_type;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(data)
        KV_SERIALIZE_OPT(account_index, 0u)
        KV_SERIALIZE_OPT(address_index, 0u)
        KV_SERIALIZE(signature_type)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(signature);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_VERIFY
  {
    struct request_t
    {
      std::string data;
      std::string address;
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(data);
        KV_SERIALIZE(address);
        KV_SERIALIZE(signature);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      bool good;
      unsigned version;
      bool old;
      std::string signature_type;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(good);
        KV_SERIALIZE(version);
        KV_SERIALIZE(old);
        KV_SERIALIZE(signature_type);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_EXPORT_OUTPUTS
  {
    struct request_t
    {
      bool all;
      uint32_t start;
      uint32_t count;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(all)
        KV_SERIALIZE_OPT(start, 0u)
        KV_SERIALIZE_OPT(count, 0xffffffffu)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string outputs_data_hex;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(outputs_data_hex);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_IMPORT_OUTPUTS
  {
    struct request_t
    {
      std::string outputs_data_hex;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(outputs_data_hex);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint64_t num_imported;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(num_imported);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_EXPORT_KEY_IMAGES
  {
    struct request_t
    {
      bool all;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(all, false);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct signed_key_image
    {
      std::string key_image;
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key_image);
        KV_SERIALIZE(signature);
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      uint32_t offset;
      std::vector<signed_key_image> signed_key_images;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(offset);
        KV_SERIALIZE(signed_key_images);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_IMPORT_KEY_IMAGES
  {
    struct signed_key_image
    {
      std::string key_image;
      std::string signature;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key_image);
        KV_SERIALIZE(signature);
      END_KV_SERIALIZE_MAP()
    };

    struct request_t
    {
      uint32_t offset;
      std::vector<signed_key_image> signed_key_images;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(offset, (uint32_t)0);
        KV_SERIALIZE(signed_key_images);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint64_t height;
      uint64_t spent;
      uint64_t unspent;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(height)
        KV_SERIALIZE(spent)
        KV_SERIALIZE(unspent)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct uri_spec
  {
    std::string address;
    std::string payment_id;
    uint64_t amount;
    std::string tx_description;
    std::string recipient_name;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(address);
      KV_SERIALIZE(payment_id);
      KV_SERIALIZE(amount);
      KV_SERIALIZE(tx_description);
      KV_SERIALIZE(recipient_name);
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_MAKE_URI
  {
    struct request_t: public uri_spec
    {
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string uri;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(uri)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_PARSE_URI
  {
    struct request_t
    {
      std::string uri;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(uri)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uri_spec uri;
      std::vector<std::string> unknown_parameters;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(uri);
        KV_SERIALIZE(unknown_parameters);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_ADD_ADDRESS_BOOK_ENTRY
  {
    struct request_t
    {
      std::string address;
      std::string description;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(description)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint64_t index;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(index);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_EDIT_ADDRESS_BOOK_ENTRY
  {
    struct request_t
    {
      uint64_t index;
      bool set_address;
      std::string address;
      bool set_description;
      std::string description;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(index)
        KV_SERIALIZE(set_address)
        KV_SERIALIZE(address)
        KV_SERIALIZE(set_description)
        KV_SERIALIZE(description)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_ADDRESS_BOOK_ENTRY
  {
    struct request_t
    {
      std::list<uint64_t> entries;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(entries)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct entry
    {
      uint64_t index;
      std::string address;
      std::string description;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(index)
        KV_SERIALIZE(address)
        KV_SERIALIZE(description)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      std::vector<entry> entries;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(entries)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_DELETE_ADDRESS_BOOK_ENTRY
  {
    struct request_t
    {
      uint64_t index;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(index);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_RESCAN_SPENT
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_REFRESH
  {
    struct request_t
    {
      uint64_t start_height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(start_height, (uint64_t) 0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint64_t blocks_fetched;
      bool received_money;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(blocks_fetched);
        KV_SERIALIZE(received_money);
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_AUTO_REFRESH
  {
    struct request_t
    {
      bool enable;
      uint32_t period; // seconds

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(enable, true)
        KV_SERIALIZE_OPT(period, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SCAN_TX
  {
    struct request_t
    {
      std::list<std::string> txids;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txids)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_START_MINING
  {
    struct request_t
    {
      uint64_t    threads_count;
      bool        do_background_mining;
      bool        ignore_battery;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(threads_count)
        KV_SERIALIZE(do_background_mining)        
        KV_SERIALIZE(ignore_battery)        
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_STOP_MINING
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_LANGUAGES
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::vector<std::string> languages;
      std::vector<std::string> languages_local;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(languages)
        KV_SERIALIZE(languages_local)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CREATE_WALLET
  {
    struct request_t
    {
      std::string filename;
      std::string password;
      std::string language;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(filename)
        KV_SERIALIZE(password)
        KV_SERIALIZE(language)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_OPEN_WALLET
  {
    struct request_t
    {
      std::string filename;
      std::string password;
      bool autosave_current;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(filename)
        KV_SERIALIZE(password)
        KV_SERIALIZE_OPT(autosave_current, true)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CLOSE_WALLET
  {
    struct request_t
    {
      bool autosave_current;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(autosave_current, true)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_CHANGE_WALLET_PASSWORD
  {
    struct request_t
    {
      std::string old_password;
      std::string new_password;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(old_password)
        KV_SERIALIZE(new_password)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GENERATE_FROM_KEYS
  {
    struct request
    {
      uint64_t restore_height;
      std::string filename;
      std::string address;
      std::string spendkey;
      std::string viewkey;
      std::string password;
      bool autosave_current;
      std::string language;

      BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_OPT(restore_height, (uint64_t)0)
      KV_SERIALIZE(filename)
      KV_SERIALIZE(address)
      KV_SERIALIZE(spendkey)
      KV_SERIALIZE(viewkey)
      KV_SERIALIZE(password)
      KV_SERIALIZE_OPT(autosave_current, true)
      KV_SERIALIZE(language)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::string address;
      std::string info;

      BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(address)
      KV_SERIALIZE(info)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET
  {
    struct request_t
    {
      uint64_t restore_height;
      std::string filename;
      std::string seed;
      std::string seed_offset;
      std::string password;
      std::string language;
      bool autosave_current;
      bool enable_multisig_experimental;

      BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_OPT(restore_height, (uint64_t)0)
      KV_SERIALIZE(filename)
      KV_SERIALIZE(seed)
      KV_SERIALIZE(seed_offset)
      KV_SERIALIZE(password)
      KV_SERIALIZE(language)
      KV_SERIALIZE_OPT(autosave_current, true)
      KV_SERIALIZE_OPT(enable_multisig_experimental, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string address;
      std::string seed;
      std::string info;
      bool was_deprecated;

      BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(address)
      KV_SERIALIZE(seed)
      KV_SERIALIZE(info)
      KV_SERIALIZE(was_deprecated)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
  
  struct COMMAND_RPC_IS_MULTISIG
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      bool multisig;
      bool ready;
      uint32_t threshold;
      uint32_t total;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(multisig)
        KV_SERIALIZE(ready)
        KV_SERIALIZE(threshold)
        KV_SERIALIZE(total)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_PREPARE_MULTISIG
  {
    struct request_t
    {
      bool enable_multisig_experimental;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(enable_multisig_experimental, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string multisig_info;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(multisig_info)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_MAKE_MULTISIG
  {
    struct request_t
    {
      std::vector<std::string> multisig_info;
      uint32_t threshold;
      std::string password;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(multisig_info)
        KV_SERIALIZE(threshold)
        KV_SERIALIZE(password)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string address;
      std::string multisig_info;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(multisig_info)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_EXPORT_MULTISIG
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string info;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(info)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_IMPORT_MULTISIG
  {
    struct request_t
    {
      std::vector<std::string> info;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(info)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint64_t n_outputs;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(n_outputs)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_FINALIZE_MULTISIG
  {
    // NOP
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_EXCHANGE_MULTISIG_KEYS
  {
    struct request_t
    {
      std::string password;
      std::vector<std::string> multisig_info;
      bool force_update_use_with_caution;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(password)
        KV_SERIALIZE(multisig_info)
        KV_SERIALIZE_OPT(force_update_use_with_caution, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string address;
      std::string multisig_info;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(multisig_info)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SIGN_MULTISIG
  {
    struct request_t
    {
      std::string tx_data_hex;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_data_hex)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_data_hex;
      std::list<std::string> tx_hash_list;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_data_hex)
        KV_SERIALIZE(tx_hash_list)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SUBMIT_MULTISIG
  {
    struct request_t
    {
      std::string tx_data_hex;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_data_hex)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::list<std::string> tx_hash_list;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash_list)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_VERSION
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint32_t version;
      bool release;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(version)
        KV_SERIALIZE(release)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_VALIDATE_ADDRESS
  {
    struct request_t
    {
      std::string address;
      bool any_net_type;
      bool allow_openalias;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE_OPT(any_net_type, false)
        KV_SERIALIZE_OPT(allow_openalias, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      bool valid;
      bool integrated;
      bool subaddress;
      std::string nettype;
      std::string openalias_address;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(valid)
        KV_SERIALIZE(integrated)
        KV_SERIALIZE(subaddress)
        KV_SERIALIZE(nettype)
        KV_SERIALIZE(openalias_address)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SET_DAEMON
  {
    struct request_t
    {
      std::string address;
      std::string username;
      std::string password;
      bool trusted;
      std::string ssl_support; // disabled, enabled, autodetect
      std::string ssl_private_key_path;
      std::string ssl_certificate_path;
      std::string ssl_ca_file;
      std::vector<std::string> ssl_allowed_fingerprints;
      bool ssl_allow_any_cert;
      std::string proxy;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(username)
        KV_SERIALIZE(password)
        KV_SERIALIZE_OPT(trusted, false)
        KV_SERIALIZE_OPT(ssl_support, (std::string)"autodetect")
        KV_SERIALIZE(ssl_private_key_path)
        KV_SERIALIZE(ssl_certificate_path)
        KV_SERIALIZE(ssl_ca_file)
        KV_SERIALIZE(ssl_allowed_fingerprints)
        KV_SERIALIZE_OPT(ssl_allow_any_cert, false)
        KV_SERIALIZE_OPT(proxy, (std::string)"")
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SET_LOG_LEVEL
  {
    struct request_t
    {
      int8_t level;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(level)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SET_LOG_CATEGORIES
  {
    struct request_t
    {
      std::string categories;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(categories)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string categories;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(categories)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_ESTIMATE_TX_SIZE_AND_WEIGHT
  {
    struct request_t
    {
      uint32_t n_inputs;
      uint32_t n_outputs;
      uint32_t ring_size;
      bool rct;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(n_inputs)
        KV_SERIALIZE(n_outputs)
        KV_SERIALIZE_OPT(ring_size, 0u)
        KV_SERIALIZE_OPT(rct, true)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint64_t size;
      uint64_t weight;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(size)
        KV_SERIALIZE(weight)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_SETUP_BACKGROUND_SYNC
  {
    struct request_t
    {
      std::string background_sync_type;
      std::string wallet_password;
      std::string background_cache_password;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(background_sync_type)
        KV_SERIALIZE(wallet_password)
        KV_SERIALIZE_OPT(background_cache_password, (std::string)"")
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_START_BACKGROUND_SYNC
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_STOP_BACKGROUND_SYNC
  {
    struct request_t
    {
      std::string wallet_password;
      std::string seed;
      std::string seed_offset;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(wallet_password)
        KV_SERIALIZE_OPT(seed, (std::string)"")
        KV_SERIALIZE_OPT(seed_offset, (std::string)"")
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_DEFAULT_FEE_PRIORITY
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint32_t priority;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(priority)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_MAKE_TERM_DEPOSIT
  {
    struct request_t
    {
      uint64_t amount;
      uint8_t  tier;
      uint32_t priority;
      std::string idempotency_key;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(amount)
        KV_SERIALIZE(tier)
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
        KV_SERIALIZE_OPT(idempotency_key, std::string())
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;
      uint64_t    unlock_height;
      uint64_t    fee;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
        KV_SERIALIZE(unlock_height)
        KV_SERIALIZE(fee)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // TD-5: Claim rewards for a term deposit
  struct COMMAND_RPC_CLAIM_DEPOSIT
  {
    struct request_t
    {
      std::string deposit_id;  // TX hash of the deposit
      uint32_t priority;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposit_id)
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;
      uint64_t    fee;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
        KV_SERIALIZE(fee)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // ── PQC registration (Problem 1) ──────────────────────────────────────────
  // Publish this wallet's derived Dilithium (ML-DSA-65) + Kyber (ML-KEM-768) public keys
  // on-chain, bound to its spend pubkey with a proof-of-possession owner_sig (see
  // wallet2::create_pqc_register_tx). This is the prerequisite that makes the hybrid
  // (harvest-now-decrypt-later-resistant) receive path actually activate: without a confirmed
  // registration, senders' get_pqc_keys lookups return "not found" and they fall back to
  // classical-only stealth-address derivation.
  struct COMMAND_RPC_PBC_PQC_REGISTER
  {
    struct request_t
    {
      uint32_t    priority;
      std::string idempotency_key;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
        KV_SERIALIZE_OPT(idempotency_key, std::string())
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;       // hash of the registration marker TX
      std::string spend_pubkey;  // spend pubkey the PQC keys were bound to (hex)
      std::string pqc_hash;      // H(dilithium_pub || kyber_pub) committed on-chain (hex)
      uint64_t    fee;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
        KV_SERIALIZE(spend_pubkey)
        KV_SERIALIZE(pqc_hash)
        KV_SERIALIZE(fee)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // ── PQC v2 address (Problem 1) ────────────────────────────────────────────
  // Return this wallet's post-quantum "v2" address string. The v2 address embeds the classical
  // spend/view pubkeys AND a commitment pqc_hash = H(dilithium_pub || kyber_pub). A sender who is
  // given a v2 address (and finds matching registered keys on-chain) performs hybrid Kyber
  // encapsulation, so the stealth-address ECDH is protected against future quantum decryption.
  // Handing out a v2 address only makes sense after pbc_pqc_register has confirmed on-chain;
  // registered=false is a hint that the sender will currently fall back to classical.
  struct COMMAND_RPC_PBC_GET_PQC_ADDRESS
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string address_v2;    // base58 v2 (PQC) address
      std::string address;       // classical address (for reference)
      std::string spend_pubkey;  // hex
      std::string pqc_hash;      // hex — H(dilithium_pub || kyber_pub)
      bool        registered;    // whether the daemon already has these PQC keys on-chain

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address_v2)
        KV_SERIALIZE(address)
        KV_SERIALIZE(spend_pubkey)
        KV_SERIALIZE(pqc_hash)
        KV_SERIALIZE(registered)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // PF: 2-step flow — materialize accumulated_reward into spendable balance
  struct COMMAND_RPC_TERM_WITHDRAW_DEPOSIT
  {
    struct request_t
    {
      std::string deposit_id;  // TX hash of the deposit
      uint32_t priority;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposit_id)
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;
      uint64_t    fee;
      uint64_t    payout_amount;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
        KV_SERIALIZE(fee)
        KV_SERIALIZE(payout_amount)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_DEPOSITS
  {
    struct request_t
    {
      std::string filter;       // "all", "locked", "unlocked", "pending"
      uint64_t    min_height;   // filter: only deposits created >= this height
      uint64_t    max_height;   // filter: only deposits created <= this height
      bool        include_spent;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(filter, std::string("all"))
        KV_SERIALIZE_OPT(min_height, (uint64_t)0)
        KV_SERIALIZE_OPT(max_height, (uint64_t)UINT64_MAX)
        KV_SERIALIZE_OPT(include_spent, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct deposit_entry
    {
      std::string txid;
      uint64_t    vout_index;
      uint64_t    amount;
      uint8_t     tier;
      uint64_t    height_created;
      uint64_t    timestamp_created;
      uint64_t    unlock_height;
      uint64_t    lock_blocks;
      uint64_t    fee_paid;
      std::string status;
      uint64_t    confirmations;
      bool        in_pool;
      uint64_t    blocks_remaining;
      uint64_t    eta_seconds;
      std::string eta_human;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
        KV_SERIALIZE(vout_index)
        KV_SERIALIZE(amount)
        KV_SERIALIZE(tier)
        KV_SERIALIZE(height_created)
        KV_SERIALIZE(timestamp_created)
        KV_SERIALIZE(unlock_height)
        KV_SERIALIZE(lock_blocks)
        KV_SERIALIZE(fee_paid)
        KV_SERIALIZE(status)
        KV_SERIALIZE(confirmations)
        KV_SERIALIZE(in_pool)
        KV_SERIALIZE(blocks_remaining)
        KV_SERIALIZE(eta_seconds)
        KV_SERIALIZE(eta_human)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      std::vector<deposit_entry> deposits;
      uint64_t current_height;
      uint64_t block_time;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposits)
        KV_SERIALIZE(current_height)
        KV_SERIALIZE(block_time)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_DEPOSIT
  {
    struct request_t
    {
      std::string txid;         // deposit_id = txid (or txid:vout)

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string txid;
      uint64_t    vout_index;
      uint64_t    amount;
      uint8_t     tier;
      uint64_t    height_created;
      uint64_t    timestamp_created;
      uint64_t    unlock_height;
      uint64_t    lock_blocks;
      uint64_t    fee_paid;
      std::string status;
      uint64_t    confirmations;
      bool        in_pool;
      uint64_t    blocks_remaining;
      uint64_t    eta_seconds;
      std::string eta_human;
      bool        found;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
        KV_SERIALIZE(vout_index)
        KV_SERIALIZE(amount)
        KV_SERIALIZE(tier)
        KV_SERIALIZE(height_created)
        KV_SERIALIZE(timestamp_created)
        KV_SERIALIZE(unlock_height)
        KV_SERIALIZE(lock_blocks)
        KV_SERIALIZE(fee_paid)
        KV_SERIALIZE(status)
        KV_SERIALIZE(confirmations)
        KV_SERIALIZE(in_pool)
        KV_SERIALIZE(blocks_remaining)
        KV_SERIALIZE(eta_seconds)
        KV_SERIALIZE(eta_human)
        KV_SERIALIZE(found)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_WALLET_DEPOSIT_STATS
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint64_t height;
      uint64_t deposit_pool_balance;
      uint64_t deposit_sum_weights;
      uint64_t total_locked_in_deposits;
      uint64_t block_reward;
      uint64_t deposit_allocation_per_block;
      uint64_t distribution_period;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(height)
        KV_SERIALIZE(deposit_pool_balance)
        KV_SERIALIZE(deposit_sum_weights)
        KV_SERIALIZE(total_locked_in_deposits)
        KV_SERIALIZE(block_reward)
        KV_SERIALIZE(deposit_allocation_per_block)
        KV_SERIALIZE(distribution_period)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_WALLET_DEPOSIT_APY
  {
    struct request_t
    {
      uint64_t amount;  // atomic, default 100 PBC if 0

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(amount, (uint64_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct tier_entry
    {
      uint8_t  tier;
      uint64_t tier_blocks;
      uint64_t tier_multiplier;
      uint64_t w_user;
      uint64_t yield_atomic;      // real gain over deposit duration
      uint64_t total_return;      // amount + yield_atomic
      double   roi_percent;       // (yield/amount)*100 — real ROI over duration
      double   apy_simple;        // annualized simple rate

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tier)
        KV_SERIALIZE(tier_blocks)
        KV_SERIALIZE(tier_multiplier)
        KV_SERIALIZE(w_user)
        KV_SERIALIZE(yield_atomic)
        KV_SERIALIZE(total_return)
        KV_SERIALIZE(roi_percent)
        KV_SERIALIZE(apy_simple)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      uint64_t sim_amount;
      uint64_t current_sum_weights;
      uint64_t alloc_per_block;
      uint64_t block_reward;
      uint64_t height;
      std::vector<tier_entry> tiers;
      std::string warning;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(sim_amount)
        KV_SERIALIZE(current_sum_weights)
        KV_SERIALIZE(alloc_per_block)
        KV_SERIALIZE(block_reward)
        KV_SERIALIZE(height)
        KV_SERIALIZE(tiers)
        KV_SERIALIZE(warning)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // ── TD-5c+: Accrued rewards display (read-only, new endpoint) ───────────
  struct COMMAND_RPC_GET_DEPOSITS_ACCRUED
  {
    struct request_t
    {
      std::string filter;        // "locked", "unlocked", "all" (default: all active)
      bool        include_spent; // default false

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(filter)
        KV_SERIALIZE_OPT(include_spent, false)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct accrued_entry
    {
      // ── Identity (same as deposit_entry, for convenience) ──
      std::string txid;
      uint64_t    amount;
      uint8_t     tier;
      std::string status;
      uint64_t    height_created;
      uint64_t    unlock_height;

      // ── Weight & Index (from daemon LMDB) ──
      uint64_t    weight;
      std::string deposit_entry_index; // BUG1-FIX: uint128 as decimal string
      std::string fee_entry_index;     // BUG1-FIX: uint128 as decimal string

      // ── Accrued gains (computed, atomic units) ──
      uint64_t    accrued_deposit;     // from Term Deposit Pool
      uint64_t    accrued_fee;         // from Fee Pool
      uint64_t    accrued_total;       // deposit + fee

      // ── Claim status (TD-7) ──
      uint64_t    accumulated_reward;  // already claimed (from daemon LMDB)
      uint64_t    total_withdrawn;     // lifetime total of withdraw payouts
      uint64_t    last_claim_height;   // height of last claim (0 = never)
      uint64_t    claimable;           // accrued_total - accumulated_reward
      double      claimable_pbc;       // human-readable
      bool        is_expired;          // unlock_height <= current_height

      // ── Display helpers ──
      double      accrued_total_pbc;   // accrued_total / COIN (human-readable)
      double      apy_realized;        // annualized yield so far (0.0 = no data)
      uint64_t    blocks_elapsed;      // current_height - height_created

      // ── Daemon data (for transparency) ──
      bool        daemon_found;        // deposit found in LMDB?

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txid)
        KV_SERIALIZE(amount)
        KV_SERIALIZE(tier)
        KV_SERIALIZE(status)
        KV_SERIALIZE(height_created)
        KV_SERIALIZE(unlock_height)
        KV_SERIALIZE(weight)
        KV_SERIALIZE(deposit_entry_index)
        KV_SERIALIZE(fee_entry_index)
        KV_SERIALIZE(accrued_deposit)
        KV_SERIALIZE(accrued_fee)
        KV_SERIALIZE(accrued_total)
        KV_SERIALIZE(accumulated_reward)
          KV_SERIALIZE(total_withdrawn)
        KV_SERIALIZE(last_claim_height)
        KV_SERIALIZE(claimable)
        KV_SERIALIZE(claimable_pbc)
        KV_SERIALIZE(is_expired)
        KV_SERIALIZE(accrued_total_pbc)
        KV_SERIALIZE(apy_realized)
        KV_SERIALIZE(blocks_elapsed)
        KV_SERIALIZE(daemon_found)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      // ── Per-deposit detail lines ──
      std::vector<accrued_entry> deposits;

      // ── Global state (from daemon) ──
      uint64_t current_height;
      std::string global_deposit_index;  // BUG1-FIX: uint128 as decimal string
      std::string global_fee_index;      // BUG1-FIX: uint128 as decimal string
      uint64_t deposit_sum_weights;

      // ── Account Statement Summary ──
      uint64_t total_deposits_count;       // number of active deposits
      uint64_t total_principal_locked;     // Σ amount (atomic)
      double   total_principal_locked_pbc; // human-readable
      uint64_t total_accrued;              // Σ accrued_total (atomic)
      double   total_accrued_pbc;          // human-readable
      uint64_t total_claimable;            // Σ claimable (atomic)
      double   total_claimable_pbc;        // human-readable
      uint64_t total_portfolio_value;      // principal + accrued (atomic)
      double   total_portfolio_value_pbc;  // human-readable
      uint64_t total_fees_paid;            // Σ fee_paid (atomic)
      double   total_fees_paid_pbc;        // human-readable
      int64_t  net_gain;                   // accrued − fees (can be negative early on)
      double   net_gain_pbc;               // human-readable
      double   overall_apy;               // weighted-average APY across all deposits
      uint64_t next_unlock_height;         // nearest maturity (0 = none)
      uint64_t next_unlock_blocks;         // blocks until next maturity
      uint64_t next_unlock_eta_seconds;    // seconds until next maturity
      std::string next_unlock_eta_human;   // "2d 5h 30m"

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposits)
        KV_SERIALIZE(current_height)
        KV_SERIALIZE(global_deposit_index)
        KV_SERIALIZE(global_fee_index)
        KV_SERIALIZE(deposit_sum_weights)
        KV_SERIALIZE(total_deposits_count)
        KV_SERIALIZE(total_principal_locked)
        KV_SERIALIZE(total_principal_locked_pbc)
        KV_SERIALIZE(total_accrued)
        KV_SERIALIZE(total_accrued_pbc)
        KV_SERIALIZE(total_claimable)
        KV_SERIALIZE(total_claimable_pbc)
        KV_SERIALIZE(total_portfolio_value)
        KV_SERIALIZE(total_portfolio_value_pbc)
        KV_SERIALIZE(total_fees_paid)
        KV_SERIALIZE(total_fees_paid_pbc)
        KV_SERIALIZE(net_gain)
        KV_SERIALIZE(net_gain_pbc)
        KV_SERIALIZE(overall_apy)
        KV_SERIALIZE(next_unlock_height)
        KV_SERIALIZE(next_unlock_blocks)
        KV_SERIALIZE(next_unlock_eta_seconds)
        KV_SERIALIZE(next_unlock_eta_human)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // ─────────────────────────────────────────────
  // PBC Inheritance
  // ─────────────────────────────────────────────

  struct COMMAND_RPC_PBC_INHERIT_SETUP
  {
    struct request_t
    {
      std::string heir_address;
      uint32_t priority;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(heir_address)
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_PBC_INHERIT_REQUEST
  {
    struct request_t
    {
      std::string principal_address;
      uint32_t priority;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(principal_address)
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_PBC_INHERIT_CANCEL
  {
    struct request_t
    {
      uint32_t priority;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };



  struct COMMAND_RPC_PBC_LOCK_COLLATERAL
  {
    struct request_t
    {
      std::string deposit_id;
      std::string seller_address;
      uint64_t amount;
      uint64_t expiry_height;
      uint64_t expected_dep_idx;
      uint64_t expected_fee_idx;
      uint32_t priority;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposit_id)
        KV_SERIALIZE(seller_address)
        KV_SERIALIZE(amount)
        KV_SERIALIZE(expiry_height)
        KV_SERIALIZE(expected_dep_idx)
        KV_SERIALIZE(expected_fee_idx)
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
    struct response_t
    {
      std::string tx_hash;
      std::string lock_id;
      uint64_t expected_dep_idx = 0;
      uint64_t expected_fee_idx = 0;
      uint64_t expiry_height = 0;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
        KV_SERIALIZE(lock_id)
        KV_SERIALIZE(expected_dep_idx)
        KV_SERIALIZE(expected_fee_idx)
        KV_SERIALIZE(expiry_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_PBC_CANCEL_LOCK
  {
    struct request_t
    {
      std::string lock_id;
      uint32_t priority;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(lock_id)
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
    struct response_t
    {
      std::string tx_hash;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_PBC_TRANSFER_DEPOSIT
  {
    struct request_t
    {
      std::string deposit_id;
      std::string new_owner_address;
      std::string lock_id;
      uint64_t expected_dep_idx;
      uint64_t expected_fee_idx;
      uint64_t seller_payment_amount;
      uint32_t priority;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposit_id)
        KV_SERIALIZE(new_owner_address)
        KV_SERIALIZE(lock_id)
        KV_SERIALIZE(expected_dep_idx)
        KV_SERIALIZE(expected_fee_idx)
        KV_SERIALIZE_OPT(seller_payment_amount, (uint64_t)0)
        KV_SERIALIZE_OPT(priority, (uint32_t)0)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_COLLATERAL_LOCK
  {
    struct request_t
    {
      std::string lock_id;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(lock_id)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
    struct response_t
    {
      bool found = false;
      std::string lock_id;
      std::string deposit_id;
      std::string buyer_pubkey;
      std::string seller_pubkey;
      std::string buyer_address;
      std::string seller_address;
      uint64_t amount = 0;
      uint64_t created_height = 0;
      uint64_t expiry_height = 0;
      uint8_t lock_status = 0;
      uint64_t expected_dep_idx = 0;
      uint64_t expected_fee_idx = 0;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(found)
        KV_SERIALIZE(lock_id)
        KV_SERIALIZE(deposit_id)
        KV_SERIALIZE(buyer_pubkey)
        KV_SERIALIZE(seller_pubkey)
        KV_SERIALIZE(buyer_address)
        KV_SERIALIZE(seller_address)
        KV_SERIALIZE(amount)
        KV_SERIALIZE(created_height)
        KV_SERIALIZE(expiry_height)
        KV_SERIALIZE(lock_status)
        KV_SERIALIZE(expected_dep_idx)
        KV_SERIALIZE(expected_fee_idx)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  struct COMMAND_RPC_GET_COLLATERAL_LOCK_FOR_DEPOSIT
  {
    struct request_t
    {
      std::string deposit_id;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposit_id)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
    typedef COMMAND_RPC_GET_COLLATERAL_LOCK::response_t response_t;
    typedef epee::misc_utils::struct_init<response_t> response;
  };


  struct COMMAND_RPC_PBC_INHERIT_STATUS
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      bool has_setup;
      std::string heir_address;
      bool request_active;
      uint64_t request_height;
      uint64_t blocks_remaining;
      uint64_t last_activity_height;
      uint64_t wait_blocks;
      uint64_t current_height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(has_setup)
        KV_SERIALIZE(heir_address)
        KV_SERIALIZE(request_active)
        KV_SERIALIZE(request_height)
        KV_SERIALIZE(blocks_remaining)
        KV_SERIALIZE(last_activity_height)
        KV_SERIALIZE(wait_blocks)
        KV_SERIALIZE(current_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };


  // ── Market Ask commands ─────────────────────────────────────────────────────
  struct COMMAND_RPC_SET_MARKET_ASK
  {
    struct request_t
    {
      std::string deposit_id;
      uint64_t    ask_price = 0;  // atomic units; 0 = delist
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposit_id)
        KV_SERIALIZE(ask_price)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
    struct response_t
    {
      std::string tx_hash;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };
  // Note: remove_market_ask is gone — use set_market_ask with ask_price=0 to delist.

  struct COMMAND_RPC_GET_ALL_MARKET_ASKS
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct ask_entry_t
    {
      std::string deposit_id;
      uint64_t    ask_price = 0;
      std::string seller_address;
      uint64_t    created_height = 0;
      uint64_t    principal = 0;
      uint64_t    tier = 0;
      uint64_t    unlock_height = 0;
      uint64_t    blocks_remaining = 0;
      uint64_t    claimable_now = 0;
      std::string dep_idx;
      std::string fee_idx;
      bool        has_active_lock = false;
      std::string lock_id;
      uint64_t    lock_amount = 0;
      std::string lock_buyer_address;
      uint64_t    lock_expiry_height = 0;
      uint64_t    lock_expected_dep_idx = 0;
      uint64_t    lock_expected_fee_idx = 0;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposit_id)
        KV_SERIALIZE(ask_price)
        KV_SERIALIZE(seller_address)
        KV_SERIALIZE(created_height)
        KV_SERIALIZE(principal)
        KV_SERIALIZE(tier)
        KV_SERIALIZE(unlock_height)
        KV_SERIALIZE(blocks_remaining)
        KV_SERIALIZE(claimable_now)
        KV_SERIALIZE(dep_idx)
        KV_SERIALIZE(fee_idx)
        KV_SERIALIZE(has_active_lock)
        KV_SERIALIZE(lock_id)
        KV_SERIALIZE(lock_amount)
        KV_SERIALIZE(lock_buyer_address)
        KV_SERIALIZE(lock_expiry_height)
        KV_SERIALIZE(lock_expected_dep_idx)
        KV_SERIALIZE(lock_expected_fee_idx)
      END_KV_SERIALIZE_MAP()
    };

    struct response_t
    {
      std::vector<ask_entry_t> asks;
      uint64_t current_height = 0;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(asks)
        KV_SERIALIZE(current_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // Query pending marketplace payout for this wallet's spend pubkey.
  struct COMMAND_RPC_GET_MARKET_PENDING_PAYOUT
  {
    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      bool     found = false;
      uint64_t payout_amount = 0;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(found)
        KV_SERIALIZE(payout_amount)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // Broadcast a MARKET_PAYOUT_CLAIM TX to collect pending marketplace rewards.
  struct COMMAND_RPC_CLAIM_MARKET_PAYOUT
  {
    struct request_t
    {
      uint32_t priority = 0;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(priority)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      std::string tx_hash;
      uint64_t    payout_amount = 0;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
        KV_SERIALIZE(payout_amount)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

  // Get list of deposits this wallet has sold on the marketplace.
  struct COMMAND_RPC_GET_SOLD_DEPOSITS
  {
    struct sold_entry_t
    {
      std::string deposit_id;
      uint64_t    principal = 0;
      uint64_t    sale_price = 0;
      uint64_t    seller_reward = 0;
      uint64_t    sale_height = 0;
      std::string buyer_pubkey;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(deposit_id)
        KV_SERIALIZE(principal)
        KV_SERIALIZE(sale_price)
        KV_SERIALIZE(seller_reward)
        KV_SERIALIZE(sale_height)
        KV_SERIALIZE(buyer_pubkey)
      END_KV_SERIALIZE_MAP()
    };

    struct request_t
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;

    struct response_t
    {
      uint64_t payout_available = 0;
      std::vector<sold_entry_t> sales;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payout_available)
        KV_SERIALIZE(sales)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<response_t> response;
  };

}
}
