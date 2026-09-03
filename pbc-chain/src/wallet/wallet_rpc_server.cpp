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
#include <boost/format.hpp>
#include <iomanip>
#include <boost/asio/ip/address.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <cstdint>
#include <chrono>
#include <thread>
#include <algorithm>  // PBC: std::sort / std::max for auto-consolidate liquidity reserve
#include <vector>
#include "include_base_utils.h"
using namespace epee;

#include "version.h"
#include "wallet_rpc_server.h"
#include "wallet/wallet_args.h"
#include "common/command_line.h"
#include "common/i18n.h"
#include "common/scoped_message_writer.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "multisig/multisig.h"
#include "wallet_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "string_coding.h"
#include "string_tools.h"
#include "crypto/hash.h"
#include "mnemonics/electrum-words.h"
#include "rpc/rpc_args.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_core/pbc_collateral_lock.h"
#include "daemonizer/daemonizer.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.rpc"

#define DEFAULT_AUTO_REFRESH_PERIOD 90 // seconds (was 20 — increased for mining wallets with many UTXOs)
#define REFRESH_INDICATIVE_BLOCK_CHUNK_SIZE 64     // yield more often to avoid blocking daemon for miners

#define CHECK_MULTISIG_ENABLED() \
  do \
  { \
    if (m_wallet->multisig() && !m_wallet->is_multisig_enabled()) \
    { \
      er.code = WALLET_RPC_ERROR_CODE_DISABLED; \
      er.message = "This wallet is multisig, and multisig is disabled. Multisig is an experimental feature and may have bugs. Things that could go wrong include: funds sent to a multisig wallet can't be spent at all, can only be spent with the participation of a malicious group member, or can be stolen by a malicious group member. You can enable it by running this once in pbc-wallet: set enable-multisig-experimental 1"; \
      return false; \
    } \
  } while(0)

#define CHECK_IF_BACKGROUND_SYNCING() \
  do \
  { \
    if (!m_wallet) { return not_open(er); } \
    if (m_wallet->is_background_wallet()) \
    { \
      er.code = WALLET_RPC_ERROR_CODE_IS_BACKGROUND_WALLET; \
      er.message = "This command is disabled for background wallets."; \
      return false; \
    } \
    if (m_wallet->is_background_syncing()) \
    { \
      er.code = WALLET_RPC_ERROR_CODE_IS_BACKGROUND_SYNCING; \
      er.message = "This command is disabled while background syncing. Stop background syncing to use this command."; \
      return false; \
    } \
  } while(0)

#define PRE_VALIDATE_BACKGROUND_SYNC() \
  do \
  { \
    if (!m_wallet) { return not_open(er); } \
    if (m_restricted) \
    { \
      er.code = WALLET_RPC_ERROR_CODE_DENIED; \
      er.message = "Command unavailable in restricted mode."; \
      return false; \
    } \
    if (m_wallet->key_on_device()) \
    { \
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR; \
      er.message = "Command not supported by HW wallet"; \
      return false; \
    } \
    if (m_wallet->multisig()) \
    { \
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR; \
      er.message = "Multisig wallet cannot enable background sync"; \
      return false; \
    } \
    if (m_wallet->watch_only()) \
    { \
      er.code = WALLET_RPC_ERROR_CODE_WATCH_ONLY; \
      er.message = "Watch-only wallet cannot enable background sync"; \
      return false; \
    } \
  } while (0)

namespace
{
  const command_line::arg_descriptor<std::string, true> arg_rpc_bind_port = {"rpc-bind-port", "Sets bind port for server"};
  const command_line::arg_descriptor<bool> arg_disable_rpc_login = {"disable-rpc-login", "Disable HTTP authentication for RPC connections served by this process"};
  const command_line::arg_descriptor<bool> arg_restricted = {"restricted-rpc", "Restricts to view-only commands", false};
  const command_line::arg_descriptor<std::string> arg_wallet_dir = {"wallet-dir", "Directory for newly created wallets"};
  const command_line::arg_descriptor<bool> arg_prompt_for_password = {"prompt-for-password", "Prompts for password when not provided", false};
  const command_line::arg_descriptor<bool> arg_no_initial_sync = {"no-initial-sync", "Skips the initial sync before listening for connections", false};
  const command_line::arg_descriptor<uint32_t> arg_auto_refresh_seconds = {"auto-refresh-seconds", "Auto-refresh interval in seconds (0=disable, default=90)", DEFAULT_AUTO_REFRESH_PERIOD};
  const command_line::arg_descriptor<std::size_t> arg_rpc_max_connections_per_public_ip = {"rpc-max-connections-per-public-ip", "Max RPC connections per public IP permitted", DEFAULT_RPC_MAX_CONNECTIONS_PER_PUBLIC_IP};
  const command_line::arg_descriptor<std::size_t> arg_rpc_max_connections_per_private_ip = {"rpc-max-connections-per-private-ip", "Max RPC connections per private and localhost IP permitted", DEFAULT_RPC_MAX_CONNECTIONS_PER_PRIVATE_IP};
  const command_line::arg_descriptor<std::size_t> arg_rpc_max_connections = {"rpc-max-connections", "Max RPC connections permitted", DEFAULT_RPC_MAX_CONNECTIONS};
  const command_line::arg_descriptor<std::size_t> arg_rpc_response_soft_limit = {"rpc-response-soft-limit", "Max response bytes that can be queued, enforced at next response attempt", DEFAULT_RPC_SOFT_LIMIT_SIZE};
  const command_line::arg_descriptor<uint32_t> arg_auto_consolidate_threshold = {"auto-consolidate-threshold", "Auto-consolidate: when the wallet holds more than this many spendable outputs, sweep them to self to merge them. Keeps mining/pool/exchange wallets able to deposit/withdraw (operations that must fit in a single transaction, ~80 inputs max). 0 = disabled (default). Suggested for miners/pools: 500-1000.", 0};
  // A-5 : nombre de blocs d'attente apres un echec de signature du testament, avant de
  // retenter. Assez long pour laisser un change se debloquer et une TX se confirmer, assez
  // court pour qu'un testament finisse toujours par etre signe.
  static constexpr uint64_t PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS = 20;

  const command_line::arg_descriptor<bool> arg_no_pbc_auto_pqc_register = {"no-pbc-auto-pqc-register", "Disable the automatic one-shot on-chain registration of this wallet's post-quantum (Dilithium/Kyber) keys. That registration is REQUIRED to withdraw term-deposit interests or to claim a marketplace payout at/after the PQC spend-authority hard fork; disable this only if you register manually (pbc_pqc_register).", false};
  const command_line::arg_descriptor<uint32_t> arg_auto_consolidate_priority = {"auto-consolidate-priority", "Transaction priority used for auto-consolidation sweeps (0=default, 1=low ... 4=highest). Default: 1.", 1};

  constexpr const char default_rpc_username[] = "pbcchain";

  boost::optional<tools::password_container> password_prompter(const char *prompt, bool verify)
  {
    auto pwd_container = tools::password_container::prompt(verify, prompt);
    if (!pwd_container)
    {
      MERROR("failed to read wallet password");
    }
    return pwd_container;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void set_confirmations(tools::wallet_rpc::transfer_entry &entry, uint64_t blockchain_height, uint64_t block_reward, uint64_t unlock_time)
  {
    if (entry.height >= blockchain_height || (entry.height == 0 && (!strcmp(entry.type.c_str(), "pending") || !strcmp(entry.type.c_str(), "pool"))))
      entry.confirmations = 0;
    else
      entry.confirmations = blockchain_height - entry.height;

    if (block_reward == 0)
      entry.suggested_confirmations_threshold = 0;
    else
      entry.suggested_confirmations_threshold = (entry.amount + block_reward - 1) / block_reward;

    if (unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
    {
      if (unlock_time > blockchain_height)
        entry.suggested_confirmations_threshold = std::max(entry.suggested_confirmations_threshold, unlock_time - blockchain_height);
    }
    else
    {
      const uint64_t now = time(NULL);
      if (unlock_time > now)
        entry.suggested_confirmations_threshold = std::max(entry.suggested_confirmations_threshold, (unlock_time - now + DIFFICULTY_TARGET_V2 - 1) / DIFFICULTY_TARGET_V2);
    }
  }
}

namespace tools
{
  const char* wallet_rpc_server::tr(const char* str)
  {
    return i18n_translate(str, "tools::wallet_rpc_server");
  }

  //------------------------------------------------------------------------------------------------------------------------------
  wallet_rpc_server::wallet_rpc_server():m_wallet(NULL), rpc_login_file(), m_stop(false), m_restricted(false), m_vm(NULL)
  {
  }
  //------------------------------------------------------------------------------------------------------------------------------
  wallet_rpc_server::~wallet_rpc_server()
  {
    if (m_wallet)
      delete m_wallet;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::set_wallet(wallet2 *cr)
  {
    m_wallet = cr;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::run()
  {
    m_stop = false;

    const auto auto_refresh_evaluation_ms = std::chrono::milliseconds(200);

    m_net_server.add_idle_handler([=] { // Implicit capture of this-pointer deprecated in C++20.
      const auto auto_refresh_period = m_auto_refresh_period.load(std::memory_order_relaxed);
      if (auto_refresh_period == 0) // disabled
        return true;

      // Check if m_auto_refresh_period seconds have passed since the last refresh attempt.
      const auto auto_refresh_interval_ms = std::chrono::milliseconds(auto_refresh_period * 1'000);
      if (auto_refresh_interval_ms <= auto_refresh_evaluation_ms)
      {
        LOG_PRINT_L0((boost::format(tr("The auto wallet sync evaluation interval of %i ms must be larger than the refresh interval of %i ms"))
          % auto_refresh_evaluation_ms.count()
          % auto_refresh_interval_ms.count()).str());
        return true;
      }

      const auto now = std::chrono::steady_clock::now();
      if (now < m_last_auto_refresh_time + auto_refresh_interval_ms)
        return true;

      uint64_t blocks_fetched = 0;
      bool refresh_success = false;
      const auto start = std::chrono::steady_clock::now();

      try
      {
        bool received_money = false;
        if (m_wallet) m_wallet->refresh(m_wallet->is_trusted_daemon(), 0, blocks_fetched, received_money, true, true, REFRESH_INDICATIVE_BLOCK_CHUNK_SIZE);
        refresh_success = true;
      }
      catch (const std::exception& ex)
      {
        LOG_ERROR("Exception at while refreshing, what=" << ex.what());
      }

      const auto end = std::chrono::steady_clock::now();
      const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

      if (refresh_success)
      {
        LOG_PRINT_L3((boost::format(tr("Automated wallet block refresh took %i ms")) % elapsed.count()).str());
        // PBC FIX: persist wallet after every successful refresh that fetched new blocks.
        // Without this, m_confirmed_txs (updated in memory by process_unconfirmed) is never
        // written to disk. After a wallet-rpc restart, pbc_withdraw TXs land back in
        // m_unconfirmed_txs, eventually time out to 'failed', and vanish from get_transfers
        // causing 'Interest Withdrawn' to show 0 until rescan_blockchain.
        if (blocks_fetched > 0 && m_wallet)
        {
          try { m_wallet->store(); }
          catch (const std::exception& ex)
          {
            LOG_ERROR("Exception while storing wallet after auto-refresh, what=" << ex.what());
          }
        }
      }

      const bool syncing_against_tip_of_chain = blocks_fetched < REFRESH_INDICATIVE_BLOCK_CHUNK_SIZE;

      // PBC: testament auto-resign — only when synced to chain tip (non-fatal)
      if (refresh_success && syncing_against_tip_of_chain && m_wallet)
      {
        try { pbc_maybe_update_testament(); }
        catch (const std::exception& ex)
        {
          LOG_PRINT_L1("PBC TESTAMENT auto-resign exception (non-fatal): " << ex.what());
        }
      }

      // PBC: auto-consolidate spendable outputs (mining/pool/exchange wallets) — only when synced to tip (non-fatal)
      if (refresh_success && syncing_against_tip_of_chain && m_wallet)
      {
        try { pbc_maybe_auto_consolidate(); }
        catch (const std::exception& ex)
        {
          LOG_PRINT_L1("PBC AUTO-CONSOLIDATE exception (non-fatal): " << ex.what());
        }
      }

      // PBC: register this wallet's post-quantum keys on-chain if not done yet. Mandatory for term
      // withdraw / marketplace payout since the spend-authority hard fork. One-shot, rate-limited,
      // entirely non-fatal - see pbc_maybe_auto_register_pqc().
      //
      // NOTE (bug corrige le 2026-08-10) : ce bloc etait initialement garde par
      // syncing_against_tip_of_chain, par mimetisme avec l'auto-consolidation. C'est FAUX ici :
      // cette variable vaut (blocks_fetched < 64), donc elle est TOUJOURS fausse des que la chaine
      // avance vite (un test qui mine a ~8 blocs/s avec un refresh toutes les 90 s ramene ~720
      // blocs par passage). L'enregistrement n'etait donc JAMAIS tente. Or il n'a aucun besoin
      // d'etre au sommet de la chaine : il lui faut un demon joignable et des fonds, rien de plus.
      if (refresh_success && m_wallet)
      {
        try { pbc_maybe_auto_register_pqc(); }
        catch (const std::exception& ex)
        {
          LOG_PRINT_L1("PBC AUTO-PQC exception (non-fatal): " << ex.what());
        }
      }

      if (syncing_against_tip_of_chain)
      {
        // At this point, we can poll for a refresh every m_auto_refresh_period seconds.
        m_last_auto_refresh_time = end;
      }
      else
      {
        // We are in a state of synchronization, blasting through the maximum chunks of blocks
        // because we are not at the tip of the chain. In this case, if we update m_last_auto_refresh_time,
        // we'll need to wait an entire m_refresh_interval_ms before processing the next batch. On the other hand,
        // if we do not update m_last_auto_refresh_time, we'll never yield (other calls to the RPC will hang)
        // in the case that elapsed > auto_refresh_evaluation_ms since we'll immediately be scheduled for another block sync.
        const bool over_one_refresh_period_passed = end > m_last_auto_refresh_time + auto_refresh_interval_ms;
        if (over_one_refresh_period_passed)
        {
          // auto_refresh_interval_ms of straight-blasting through blocks has elapsed without end.
          // Let's freee up the network thread for between 200ms to 300ms (non-deterministic) to handle other requests.
          const auto refresh_throttle = auto_refresh_evaluation_ms + std::chrono::milliseconds(100);
          m_last_auto_refresh_time = end - auto_refresh_interval_ms + refresh_throttle;
          LOG_PRINT_L3((boost::format(tr("Temporarily throttling wallet block refresh by around %i ms")) % refresh_throttle.count()).str());
        }
      }
      return true;
    }, auto_refresh_evaluation_ms.count());
    m_net_server.add_idle_handler([this](){
      if (m_stop.load(std::memory_order_relaxed))
      {
        send_stop_signal();
        return false;
      }
      return true;
    }, 500);

    //DO NOT START THIS SERVER IN MORE THEN 1 THREADS WITHOUT REFACTORING
    return epee::http_server_impl_base<wallet_rpc_server, connection_context>::run(1, true);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::stop()
  {
    if (m_wallet)
    {
      m_wallet->store();
      m_wallet->deinit();
      delete m_wallet;
      m_wallet = NULL;
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::init(const boost::program_options::variables_map *vm)
  {
    auto rpc_config = cryptonote::rpc_args::process(*vm);
    if (!rpc_config)
      return false;

    m_vm = vm;

    boost::optional<epee::net_utils::http::login> http_login{};
    std::string bind_port = command_line::get_arg(*m_vm, arg_rpc_bind_port);
    const bool disable_auth = command_line::get_arg(*m_vm, arg_disable_rpc_login);
    m_restricted = command_line::get_arg(*m_vm, arg_restricted);
    if (!command_line::is_arg_defaulted(*m_vm, arg_wallet_dir))
    {
      if (!command_line::is_arg_defaulted(*m_vm, wallet_args::arg_wallet_file()))
      {
        MERROR(arg_wallet_dir.name << " and " << wallet_args::arg_wallet_file().name << " are incompatible, use only one of them");
        return false;
      }
      m_wallet_dir = command_line::get_arg(*m_vm, arg_wallet_dir);
#ifdef _WIN32
#define MKDIR(path, mode)    mkdir(path)
#else
#define MKDIR(path, mode)    mkdir(path, mode)
#endif
      if (!m_wallet_dir.empty() && MKDIR(m_wallet_dir.c_str(), 0700) < 0 && errno != EEXIST)
      {
#ifdef _WIN32
        LOG_ERROR(tr("Failed to create directory ") + m_wallet_dir);
#else
        LOG_ERROR((boost::format(tr("Failed to create directory %s: %s")) % m_wallet_dir % strerror(errno)).str());
#endif
        return false;
      }
    }

    if (disable_auth)
    {
      if (rpc_config->login)
      {
        const cryptonote::rpc_args::descriptors arg{};
        LOG_ERROR(tr("Cannot specify --") << arg_disable_rpc_login.name << tr(" and --") << arg.rpc_login.name);
        return false;
      }
    }
    else // auth enabled
    {
      if (!rpc_config->login)
      {
        std::array<std::uint8_t, 16> rand_128bit{{}};
        crypto::rand(rand_128bit.size(), rand_128bit.data());
        http_login.emplace(
          default_rpc_username,
          string_encoding::base64_encode(rand_128bit.data(), rand_128bit.size())
        );

        std::string temp = "pbc-wallet-rpc." + bind_port + ".login";
        rpc_login_file = tools::private_file::drop_and_recreate(temp);
        if (!rpc_login_file.handle())
        {
          LOG_ERROR(tr("Failed to create file ") << temp << tr(". Check permissions or remove file"));
          return false;
        }
        std::fputs(http_login->username.c_str(), rpc_login_file.handle());
        std::fputc(':', rpc_login_file.handle());
        const epee::wipeable_string password = http_login->password;
        std::fwrite(password.data(), 1, password.size(), rpc_login_file.handle());
        std::fflush(rpc_login_file.handle());
        if (std::ferror(rpc_login_file.handle()))
        {
          LOG_ERROR(tr("Error writing to file ") << temp);
          return false;
        }
        LOG_PRINT_L0(tr("RPC username/password is stored in file ") << temp);
      }
      else // chosen user/pass
      {
        http_login.emplace(
          std::move(rpc_config->login->username), std::move(rpc_config->login->password).password()
        );
      }
      assert(bool(http_login));
    } // end auth enabled

    const uint32_t auto_refresh_sec = command_line::get_arg(vm, arg_auto_refresh_seconds);
    m_auto_refresh_period.store(auto_refresh_sec, std::memory_order_relaxed);
    m_auto_consolidate_threshold.store(command_line::get_arg(vm, arg_auto_consolidate_threshold), std::memory_order_relaxed);
    m_pqc_auto_register_enabled.store(!command_line::get_arg(vm, arg_no_pbc_auto_pqc_register), std::memory_order_relaxed);
    LOG_PRINT_L0("PBC AUTO-PQC registration: " << (m_pqc_auto_register_enabled.load(std::memory_order_relaxed)
      ? "enabled (this wallet registers its post-quantum keys on-chain once, as required for term "
        "withdraw and marketplace payout)"
      : "DISABLED by --no-pbc-auto-pqc-register - register manually with pbc_pqc_register, otherwise "
        "withdraws and payout claims will be rejected by consensus"));
    m_auto_consolidate_priority = command_line::get_arg(vm, arg_auto_consolidate_priority);
    if (m_auto_consolidate_threshold.load(std::memory_order_relaxed) > 0)
      LOG_PRINT_L0("PBC AUTO-CONSOLIDATE enabled: threshold=" << m_auto_consolidate_threshold.load(std::memory_order_relaxed)
        << " spendable outputs, priority=" << m_auto_consolidate_priority);
    if (auto_refresh_sec == 0)
      LOG_PRINT_L0("Auto-refresh DISABLED (--auto-refresh-seconds 0)");
    else
      LOG_PRINT_L0("Auto-refresh interval: " << auto_refresh_sec << " seconds");
    const auto over_one_period_ago = std::chrono::steady_clock::now() - std::chrono::seconds(m_auto_refresh_period.load(std::memory_order_relaxed) * 2);
    m_last_auto_refresh_time = over_one_period_ago;

    check_background_mining();

    const auto max_connections_public = command_line::get_arg(vm, arg_rpc_max_connections_per_public_ip);
    const auto max_connections_private = command_line::get_arg(vm, arg_rpc_max_connections_per_private_ip);
    const auto max_connections = command_line::get_arg(vm, arg_rpc_max_connections);

    if (max_connections < max_connections_public)
    {
      MFATAL(arg_rpc_max_connections_per_public_ip.name << " is bigger than " << arg_rpc_max_connections.name);
      return false;
    }
    if (max_connections < max_connections_private)
    {
      MFATAL(arg_rpc_max_connections_per_private_ip.name << " is bigger than " << arg_rpc_max_connections.name);
      return false;
    }

    m_net_server.set_threads_prefix("RPC");
    auto rng = [](size_t len, uint8_t *ptr) { return crypto::rand(len, ptr); };
    return epee::http_server_impl_base<wallet_rpc_server, connection_context>::init(
      rng, std::move(bind_port), std::move(rpc_config->bind_ip),
      std::move(rpc_config->bind_ipv6_address), std::move(rpc_config->use_ipv6), std::move(rpc_config->require_ipv4),
      std::move(rpc_config->access_control_origins), std::move(http_login),
      std::move(rpc_config->ssl_options),
      max_connections_public, max_connections_private, max_connections,
      command_line::get_arg(vm, arg_rpc_response_soft_limit)
    );
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::check_background_mining()
  {
    if (!m_wallet)
      return;
    // Background mining can be toggled from the main wallet
    if (m_wallet->is_background_wallet() || m_wallet->is_background_syncing())
      return;

    tools::wallet2::BackgroundMiningSetupType setup = m_wallet->setup_background_mining();
    if (setup == tools::wallet2::BackgroundMiningNo)
    {
      MLOG_RED(el::Level::Warning, "Background mining not enabled. Run \"set setup-background-mining 1\" in pbc-wallet to change.");
      return;
    }

    if (!m_wallet->is_trusted_daemon())
    {
      MDEBUG("Using an untrusted daemon, skipping background mining check");
      return;
    }

    cryptonote::COMMAND_RPC_MINING_STATUS::request req;
    cryptonote::COMMAND_RPC_MINING_STATUS::response res;
    bool r = m_wallet->invoke_http_json("/mining_status", req, res);
    if (!r || res.status != CORE_RPC_STATUS_OK)
    {
      MERROR("Failed to query mining status: " << (r ? res.status : "No connection to daemon"));
      return;
    }
    if (res.active || res.is_background_mining_enabled)
      return;

    if (setup == tools::wallet2::BackgroundMiningMaybe)
    {
      MINFO("The daemon is not set up to background mine.");
      MINFO("With background mining enabled, the daemon will mine when idle and not on battery.");
      MINFO("Enabling this supports the network you are using, and makes you eligible for receiving new WOW");
      MINFO("Set setup-background-mining to 1 in pbc-wallet to change.");
      return;
    }

    cryptonote::COMMAND_RPC_START_MINING::request req2;
    cryptonote::COMMAND_RPC_START_MINING::response res2;
    req2.miner_address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    req2.threads_count = 1;
    req2.do_background_mining = true;
    req2.ignore_battery = false;
    r = m_wallet->invoke_http_json("/start_mining", req2, res);
    if (!r || res2.status != CORE_RPC_STATUS_OK)
    {
      MERROR("Failed to setup background mining: " << (r ? res.status : "No connection to daemon"));
      return;
    }

    MINFO("Background mining enabled. The daemon will mine when idle and not on battery.");
  }
  //------------------------------------------------------------------------------------------------------------------------------
  // PBC: when a wallet accumulates many small spendable outputs (typical for mining, pool and
  // exchange wallets), single-transaction operations such as term deposits and withdraws start to
  // fail, because one TX can only hold ~80 inputs (ring 22, CLSAG ≈ 1500 bytes/input, daemon weight
  // limit). This periodically sweeps spendable outputs to self, merging them into a few large
  // outputs so those operations keep working. Opt-in via --auto-consolidate-threshold (0=disabled).
  // Runs from the idle handler, only when synced to the chain tip. Non-fatal on error.
  //------------------------------------------------------------------------------------------------------------------------------
  // PBC — AUTOMATIC ON-CHAIN REGISTRATION OF THIS WALLET'S POST-QUANTUM KEYS
  //
  // WHY. At/after HF_VERSION_PBC_PQC_SPEND_AUTH, consensus requires a Dilithium co-signature on
  // TERM_WITHDRAW and MARKET_PAYOUT_CLAIM, and only accepts it if the signing key is REGISTERED
  // on-chain under the spender's account (blockchain.cpp: "no registered Dilithium key for the
  // spender"). A user who never registered gets his transaction rejected by the daemon and his
  // interests stay stuck in `pending`, with nothing telling him why. The registration itself is a
  // one-shot, public, cheap transaction that every deposit owner needs — including a marketplace
  // BUYER or an HEIR who acquired a deposit without ever creating one. Automating it removes a
  // manual step that nothing else reminds anyone about.
  //
  // SAFETY (each point matters, do not simplify away):
  //  * runs only when the wallet is synced to the tip and can actually sign (not watch-only, not
  //    a hardware device);
  //  * asks the CHAIN first; an inconclusive answer (daemon unreachable) is never treated as
  //    "not registered" — we retry later, we never guess;
  //  * a confirmed matching registration latches m_pqc_registered_confirmed and the function
  //    becomes a no-op for the rest of the process life (no polling cost);
  //  * a registration exists but with DIFFERENT keys => we do NOT spend a fee re-registering (it
  //    would not help): we warn loudly instead, because that needs human attention;
  //  * after submitting, a cooldown of RETRY_BLOCKS blocks lets the transaction be mined instead
  //    of being resubmitted — no fee burn, no mempool spam;
  //  * every failure is non-fatal: "not enough unlocked money" on a young wallet is the normal
  //    case and is simply retried later.
  void wallet_rpc_server::pbc_maybe_auto_register_pqc()
  {
    // Blocks to wait after an attempt before trying again: comfortably above the few blocks a
    // registration needs to be mined, so a pending registration is never resubmitted.
    constexpr uint64_t RETRY_BLOCKS = 20;

    if (!m_pqc_auto_register_enabled.load(std::memory_order_relaxed) || !m_wallet)
      return;
    if (m_pqc_registered_confirmed.load(std::memory_order_relaxed))
      return; // already registered and verified - nothing left to do
    if (m_wallet->watch_only() || m_wallet->key_on_device())
    {
      MWARNING("PBC AUTO-PQC: skipped (watch-only or hardware wallet cannot sign the registration)");
      return;
    }

    // ── A-3 : garde « wallet occupe » ────────────────────────────────────────────────────
    // L'inscription est une tache de FOND : elle doit ceder le passage a l'utilisateur, jamais
    // lui prendre ses fonds. Si des transactions sortantes sont encore non confirmees, le wallet
    // vient d'agir : on reporte au passage suivant.
    //
    // POURQUOI PAS une garde « ne pas depenser le dernier output » (option ecartee le 2026-08-10) :
    // elle creerait un BLOCAGE DEFINITIF. Apres un depot il ne reste au wallet que le change, soit
    // UN SEUL output ; un tel wallet ne s'enregistrerait jamais, donc ne pourrait jamais retirer
    // ses interets. Une garde temporelle n'a pas cet effet de bord : des le repos, l'inscription
    // se fait. Aucun etat supplementaire n'est necessaire.
    {
      std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>> pending_out;
      m_wallet->get_unconfirmed_payments_out(pending_out);
      if (!pending_out.empty())
      {
        LOG_PRINT_L1("PBC AUTO-PQC: wallet occupe (" << pending_out.size()
                     << " TX sortante(s) non confirmee(s)) - report au prochain passage");
        return;
      }
    }

    const uint64_t height = m_wallet->get_blockchain_current_height();
    const uint64_t last_attempt = m_pqc_register_last_attempt_height.load(std::memory_order_relaxed);
    if (last_attempt != 0 && height < last_attempt + RETRY_BLOCKS)
      return; // an attempt is in flight: give it time to be mined

    // 1) Ask the chain. false = inconclusive => retry later, never assume.
    bool found = false, matches = false;
    if (!m_wallet->pbc_is_pqc_registered(found, matches))
    {
      MWARNING("PBC AUTO-PQC: on-chain registration status UNKNOWN (daemon unreachable or PQC keys "
               "not derived) - retrying later, no assumption made");
      return;
    }

    if (found && matches)
    {
      m_pqc_registered_confirmed.store(true, std::memory_order_relaxed);
      MWARNING("PBC AUTO-PQC: post-quantum keys already registered on-chain - nothing to do");
      return;
    }

    if (found && !matches)
    {
      // Registered under this account, but not with this wallet's keys. Re-registering would not
      // fix a withdraw (consensus compares against what is stored) and would silently burn a fee.
      MWARNING("PBC AUTO-PQC: an on-chain registration exists for this account but does NOT match "
               "this wallet's derived keys — NOT auto-registering. Term withdraws and marketplace "
               "payout claims will be rejected by consensus until this is resolved (wrong wallet/seed?)");
      m_pqc_register_last_attempt_height.store(height, std::memory_order_relaxed);
      return;
    }

    // 2) Not registered: build and broadcast the one-shot registration transaction.
    m_pqc_register_last_attempt_height.store(height, std::memory_order_relaxed);
    try
    {
      tools::wallet2::pending_tx ptx = m_wallet->create_pqc_register_tx(0 /* default priority */);
      m_wallet->commit_tx(ptx);
      m_wallet->store();
      LOG_PRINT_L0("PBC AUTO-PQC: registration submitted, tx="
                   << epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx))
                   << " at height " << height
                   << " — effective once mined; required for term withdraw / marketplace payout");
    }
    catch (const std::exception &ex)
    {
      // Normal on a young wallet (no mature funds yet for the fee): retry after the cooldown.
      MWARNING("PBC AUTO-PQC: registration FAILED (" << ex.what()
               << ") - will retry around height " << (height + RETRY_BLOCKS));
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::pbc_maybe_auto_consolidate()
  {
    const uint32_t threshold = m_auto_consolidate_threshold.load(std::memory_order_relaxed);
    if (threshold == 0 || !m_wallet)
      return;
    if (m_wallet->watch_only()) // view-only wallet cannot sign a sweep
      return;

    // Collect the amounts of the outputs the sweep below would actually be allowed to spend.
    // This MUST mirror create_transactions_all's own selection (wallet2.cpp:12154); if it does not,
    // `below` (derived from this set) and the sweep (which selects from create_transactions_all's
    // set) disagree — which both inflates the trigger and can make create_transactions_all throw
    // "The smallest amount found is not below the specified threshold". So we apply the SAME filters:
    //   - not spent / not frozen / actually unlocked      (already required)
    //   - NOT a partial-key-image (multisig) output        [matches !td.m_key_image_partial]
    //   - belongs to account 0                              [the sweep is called with account=0]
    // Two clauses of create_transactions_all are deliberately NOT replicated here:
    //   * its fractional-output skip (m_ignore_fractional_outputs && amount < fractional_threshold):
    //     recomputing that fee/weight threshold would duplicate non-trivial logic and risk drifting
    //     from the real one. Instead the sweep call is wrapped in a try/catch below, so a
    //     "nothing sweepable below the reserve" outcome (e.g. only dust sits below it) is a clean skip.
    //   * the RingCT clause "(use_rct ? true : !is_rct())": PBC is RingCT from genesis (mainnet
    //     HF >= 17 at height 0), so use_rct is always true and the clause never excludes anything;
    //     the try/catch covers the impossible-on-PBC alternative anyway.
    std::vector<uint64_t> spendable_amounts;
    const size_t n = m_wallet->get_num_transfer_details();
    for (size_t i = 0; i < n; ++i)
    {
      const tools::wallet2::transfer_details &td = m_wallet->get_transfer_details(i);
      if (td.m_spent)
        continue;
      if (td.m_frozen)
        continue;
      if (td.m_key_image_partial)            // PBC FIX: multisig partial outputs are not sweepable
        continue;
      if (td.m_subaddr_index.major != 0)     // PBC FIX: the sweep below targets account 0 only
        continue;
      if (!m_wallet->is_transfer_unlocked(td))
        continue;
      spendable_amounts.push_back(td.amount());
    }
    const size_t spendable = spendable_amounts.size();
    if (spendable <= threshold)
      return;

    // Rate-limit: leave time for the previous sweep to confirm before sweeping (or skipping) again,
    // so we don't re-spend outputs already pending in a just-submitted sweep — and so we don't
    // repeat the work below (sort + sweep attempt) on every idle refresh. Checked BEFORE the
    // (potentially large) sort so a rate-limited cycle does no extra work. Every path that has
    // "decided" for this cycle (success, skip, or could-not-build) stamps m_last_auto_consolidate_time.
    const auto now = std::chrono::steady_clock::now();
    const uint32_t refresh_sec = m_auto_refresh_period.load(std::memory_order_relaxed);
    const auto min_gap = std::chrono::seconds(static_cast<uint64_t>(refresh_sec ? refresh_sec : 90) * 3);
    if (m_last_auto_consolidate_time.time_since_epoch().count() != 0 && now < m_last_auto_consolidate_time + min_gap)
      return;

    // ── PBC FIX (liquidity reserve) ──────────────────────────────────────────────
    // Previously the sweep used below=0, i.e. it consumed ALL unlocked outputs. The sweep
    // TX(s) then sit in the mempool and their consolidated change is immature
    // (CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE blocks). During that window unlocked_balance ≈ 0,
    // so any operation that needs liquid funds — a CLAIM (which pays a fee through
    // create_transactions_2), a deposit, or a transfer — fails with not_enough_unlocked_money
    // (wallet2.cpp:11530). Observed in production: an auto-consolidate sweep at 14:13:38 was
    // followed 38 s later by a CLAIM failing on exactly that throw.
    //
    // Fix: keep the largest unlocked outputs (≈ RESERVE_COUNT of them) OUT of the sweep, so a pool
    // of mature, spendable funds always remains to pay operation fees. create_transactions_all
    // sweeps outputs with amount() < below (below=0 means "all"); we set `below` to the value of
    // the RESERVE_COUNT-th largest output, then (see below) bump it up past any run of equal
    // amounts so the sweep can never select zero inputs (which would throw).
    uint64_t below = 0; // 0 = legacy behaviour (sweep everything); used only when very few outputs
    const size_t RESERVE_COUNT = std::max<size_t>(16, threshold / 10);
    if (spendable > RESERVE_COUNT)
    {
      std::sort(spendable_amounts.begin(), spendable_amounts.end()); // ascending
      below = spendable_amounts[spendable - RESERVE_COUNT];          // value of the RESERVE_COUNT-th largest
      // If that rank falls inside a run of equal amounts (e.g. many identical coinbase outputs),
      // sweeping "< below" would select few or zero inputs. Raise `below` to the next DISTINCT
      // (strictly larger) amount so the whole homogeneous run is swept and the larger outputs
      // above it are kept as the liquidity reserve.
      if (spendable_amounts.front() >= below)
      {
        auto it = std::upper_bound(spendable_amounts.begin(), spendable_amounts.end(), below);
        if (it == spendable_amounts.end())
        {
          // Every spendable output has the same amount: we cannot consolidate while keeping a
          // mature reserve, so skip this cycle rather than sweep everything (which is the bug).
          // Stamp the time so we don't re-sort the same set on every idle refresh.
          m_last_auto_consolidate_time = now;
          LOG_PRINT_L1("PBC AUTO-CONSOLIDATE: " << spendable
            << " spendable outputs all of equal value; skipping to preserve a liquidity reserve");
          return;
        }
        below = *it; // next distinct amount up
      }
    }

    // Build a self-sweep (consolidation): spendable outputs -> a few large outputs back to self.
    const std::string self_addr = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    cryptonote::address_parse_info self_info{};
    if (!cryptonote::get_account_address_from_str_or_url(self_info, m_wallet->nettype(), self_addr))
    {
      LOG_ERROR("PBC AUTO-CONSOLIDATE: failed to parse own address — skipping this cycle");
      return;
    }

    const uint64_t mixin    = m_wallet->adjust_mixin(0);
    const uint32_t priority = m_wallet->adjust_priority(m_auto_consolidate_priority);

    // create_transactions_all applies its own selection (wallet2.cpp:12154) and, when
    // m_ignore_fractional_outputs is set (default), skips dust below its fee-based
    // fractional_threshold (12146). If — after that — there is nothing strictly below `below`
    // among the account-0 outputs it will actually consider, it throws "The smallest amount found
    // is not below the specified threshold" (12167). That is NOT an error for us: it means every
    // currently-spendable output is already part of the reserve (or only dust sits below it), so
    // there is simply nothing to consolidate this cycle and keeping the funds liquid is correct.
    // Treat any build failure as a clean, rate-limited skip rather than letting it bubble up and be
    // logged as an exception on every idle refresh. (This is also why we can safely skip dust above:
    // if dust were the only thing below the reserve, we land here and skip cleanly.)
    std::vector<tools::wallet2::pending_tx> ptxs;
    try
    {
      ptxs = m_wallet->create_transactions_all(
        /*below=*/below, self_info.address, /*is_subaddress=*/false,
        /*outputs=*/1, mixin, priority, /*extra=*/{}, /*account=*/0, /*subaddr_indices=*/{});
    }
    catch (const std::exception &ex)
    {
      m_last_auto_consolidate_time = now; // rate-limit: don't retry (and re-sort) every refresh
      LOG_PRINT_L1("PBC AUTO-CONSOLIDATE: nothing to consolidate below the liquidity reserve this "
        "cycle, skipping (non-fatal): " << ex.what());
      return;
    }

    if (ptxs.empty())
    {
      m_last_auto_consolidate_time = now; // rate-limit this path too (previously unstamped)
      LOG_PRINT_L1("PBC AUTO-CONSOLIDATE: " << spendable << " spendable outputs > threshold " << threshold
        << " but no sweep TX could be built (already consolidated?)");
      return;
    }

    m_wallet->commit_tx(ptxs);
    try { m_wallet->store(); } catch (const std::exception &ex) { LOG_PRINT_L1("PBC AUTO-CONSOLIDATE: store() failed (non-fatal): " << ex.what()); }

    m_last_auto_consolidate_time = now;
    LOG_PRINT_L0("PBC AUTO-CONSOLIDATE: " << spendable << " spendable outputs > threshold " << threshold
      << " -> swept to self in " << ptxs.size() << " TX"
      << (below != 0 ? (" (kept the largest unlocked outputs >= " + cryptonote::print_money(below)
                   + " as liquidity reserve)")
                : std::string(" (no reserve: swept all)"))
      << "; outputs will merge once mined");
  }

  void wallet_rpc_server::pbc_maybe_update_testament()
  {
    if (!m_wallet) return;

    // ── F-5 (2026-08-12) : garde « wallet occupe » ────────────────────────────────────────
    // Meme motif que A-3 pour l'auto-inscription PQC (voir pbc_maybe_auto_register_pqc) : la
    // maintenance du testament est une tache de FOND, elle doit ceder le passage a
    // l'utilisateur. Si des transactions sortantes sont encore non confirmees, le wallet vient
    // d'agir : on reporte au passage suivant plutot que de lui prendre ses fonds.
    //
    // Garde TEMPORELLE, sans etat supplementaire : des le repos, le cycle repart. On n'utilise
    // PAS de garde « ne pas depenser le dernier output » ni de fenetre de grace en blocs apres
    // un SETUP : la premiere bloquerait definitivement un wallet a un seul output, la seconde
    // ne se detend qu'au minage et gelerait un test qui attend le testament sans miner.
    //
    // Ce que cette garde ne peut PAS empecher : l'utilisateur qui lance une operation JUSTE
    // APRES le demarrage d'une consolidation. Le change reste immobilise le temps de
    // CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE confirmations ; l'operation echoue alors avec le
    // message explicite de create_term_deposit_tx, qui indique deja de reessayer une fois la
    // transaction concurrente confirmee. C'est un residuel assume, pas un defaut cache.
    {
      std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>> pending_out;
      m_wallet->get_unconfirmed_payments_out(pending_out);
      if (!pending_out.empty())
      {
        LOG_PRINT_L1("PBC TESTAMENT: wallet occupe (" << pending_out.size()
                     << " TX sortante(s) non confirmee(s)) - report au prochain passage");
        return;
      }
    }

    // ── Query inherit status ──────────────────────────────────────────────────
    cryptonote::COMMAND_RPC_GET_PBC_INHERIT_STATUS::request  s_req{};
    cryptonote::COMMAND_RPC_GET_PBC_INHERIT_STATUS::response s_res{};
    const crypto::public_key spend_pub = m_wallet->get_account().get_keys().m_account_address.m_spend_public_key;
    s_req.principal_spend_pubkey = epee::string_tools::pod_to_hex(spend_pub);
    bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_pbc_inherit_status", s_req, s_res,
                                             std::chrono::seconds(15));
    if (!ok || s_res.status != CORE_RPC_STATUS_OK)
    {
      LOG_PRINT_L2("PBC TESTAMENT: cannot query inherit status (daemon unreachable?), skipping");
      return;
    }
    if (!s_res.has_setup)
    {
      // No inherit record — reset all state
      if (m_testament_last_balance != 0 || !m_testament_heir_address.empty() || m_testament_consol_target_height != 0)
        LOG_PRINT_L1("PBC TESTAMENT: no inherit setup — clearing state");
      m_testament_last_balance         = 0;
      m_testament_heir_address.clear();
      m_testament_consol_target_height = 0;
      // F-9 (2026-08-13) : purger AUSSI l'etat de consolidation. Sans cela, une desingnation
      // supprimee puis recreee laisserait un « attendu » et une echeance herites du cycle
      // precedent, qui bloqueraient ou fausseraient le gate observe de la phase 2.
      m_testament_consol_expected        = 0;
      m_testament_consol_deadline_height = 0;
      m_testament_force_split            = false;  // F-11 : purger aussi le forçage de scission
      m_testament_key_images.clear();              // F-13 : purger la garde key-images
      return;
    }

    // Cache heir address
    if (m_testament_heir_address.empty())
      m_testament_heir_address = s_res.heir_address;

    // ── PHASE 2: Consolidation confirmed → build & store testament ───────────
    if (m_testament_consol_target_height > 0)
    {
      const uint64_t current_height = m_wallet->get_blockchain_current_height();

      // ── F-9 (2026-08-13) : condition OBSERVEE, plus une hauteur devinee ─────────────────
      // MESURE du 2026-08-12 (inherit_test, wallet_a_screen.log, 4 cycles perdus en 80 s) :
      //   22:18:10.400  sweeping 1496064822343376 atomics to self
      //   22:18:10.516  consolidation TX submitted, will sign testament at block 18169
      //   22:18:15.434  consolidation confirmed at h=18174   <- la hauteur CIBLE est atteinte
      //   22:18:15.552  build_inherit_testament: unlocked_balance=42 unlocked_utxos=42
      //   22:18:15.554  exception: No unlocked balance -> testament vide -> recul de 20 blocs
      // 42 ATOMES : le change du balayage n'etait pas encore depensable. La cible
      // h + SPENDABLE_AGE + marge etait pourtant franchie, parce qu'elle est calculee sur
      // get_blockchain_current_height() — la hauteur du DEMON telle que le wallet la connait —
      // alors que unlocked_balance() est calculee sur les transferts SCANNES par le wallet.
      // Sur une chaine rapide, la premiere devance la seconde et la phase 2 s'ouvre trop tot.
      // A-5.1 avait deja tente de corriger cela en augmentant la marge : augmenter une valeur
      // devinee ne pouvait pas resoudre une divergence qui n'est pas une question de marge.
      //
      // On observe donc ce qui compte reellement : les fonds balayes sont-ils REVENUS
      // depensables dans la vue du wallet ? m_testament_consol_expected vaut le montant balaye
      // moins les frais, c'est-a-dire exactement ce que la consolidation doit rendre. La
      // hauteur cible est conservee comme PLANCHER (elle evite d'interroger le solde pour
      // rien avant que ce soit seulement possible), mais elle ne suffit plus a elle seule.
      const uint64_t unlocked_now = m_wallet->unlocked_balance(0, false);
      const bool     funds_back   = (unlocked_now >= m_testament_consol_expected);

      if (current_height < m_testament_consol_target_height || !funds_back)
      {
        // Echeance : si les fonds ne reviennent jamais (balayage evince du mempool, reorg),
        // on ne reste pas bloque en phase 2 pour toujours. L'echeance est comptee en BLOCS :
        // une chaine a l'arret prolonge simplement l'attente, ce qui est le comportement voulu.
        if (m_testament_consol_deadline_height > 0 && current_height >= m_testament_consol_deadline_height)
        {
          MWARNING("PBC TESTAMENT: consolidation jamais revenue depensable avant le bloc "
            << m_testament_consol_deadline_height << " (attendu>=" << m_testament_consol_expected
            << " observe=" << unlocked_now << ") — abandon du cycle et recul de "
            << PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS << " blocs");
          m_testament_consol_target_height   = 0;
          m_testament_consol_expected        = 0;
          m_testament_consol_deadline_height = 0;
          m_testament_retry_after_height.store(
              current_height + PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS, std::memory_order_relaxed);
          return;
        }
        LOG_PRINT_L1("PBC TESTAMENT: consolidation pending — bloc>=" << m_testament_consol_target_height
          << " (current=" << current_height << ") ET fonds depensables>=" << m_testament_consol_expected
          << " (observe=" << unlocked_now << ")");
        return;
      }

      // Consolidation confirmed — UTXOs are now merged: build testament
      LOG_PRINT_L0("PBC TESTAMENT: consolidation confirmed at h=" << current_height
        << " (depensable=" << unlocked_now << " >= attendu=" << m_testament_consol_expected
        << ") — building testament TXs for heir");

      cryptonote::address_parse_info heir_info{};
      if (!cryptonote::get_account_address_from_str_or_url(heir_info, m_wallet->nettype(), m_testament_heir_address))
      {
        LOG_ERROR("PBC TESTAMENT: invalid heir address '" << m_testament_heir_address << "'");
        m_testament_consol_target_height   = 0;
        m_testament_consol_expected        = 0;   // F-9 : purge
        m_testament_consol_deadline_height = 0;
        // A-5.2 : armer un recul, sinon le declencheur reste arme et relance une
        // consolidation a chaque passage - boucle infinie (frais brules + testament invalide).
        m_testament_retry_after_height.store(
            m_wallet->get_blockchain_current_height() + PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS,
            std::memory_order_relaxed);
        return;
      }

      std::vector<std::string> hex_blobs;
      bool onchain_published = false;
      try
      {
        // A4 (sous-étape 4) : construit le testament (réserve un output porteur) ET diffuse
        // le tx porteur on-chain (auth + anti-rejeu). Le store LMDB via RPC ci-dessous reste
        // inchangé (le testament reste aussi dans la LMDB locale du nœud).
        hex_blobs = m_wallet->pbc_build_testament_and_publish(heir_info.address, /*priority=*/0, onchain_published);
      }
      catch (const std::exception& e)
      {
        LOG_ERROR("PBC TESTAMENT: build/publish failed: " << e.what());
        m_testament_consol_target_height   = 0;
        m_testament_consol_expected        = 0;   // F-9 : purge
        m_testament_consol_deadline_height = 0;
        // A-5.2 : armer un recul, sinon le declencheur reste arme et relance une
        // consolidation a chaque passage - boucle infinie (frais brules + testament invalide).
        m_testament_retry_after_height.store(
            m_wallet->get_blockchain_current_height() + PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS,
            std::memory_order_relaxed);
        return;
      }
      LOG_PRINT_L0("PBC TESTAMENT: on-chain carrier " << (onchain_published ? "DIFFUSÉ" : "non diffusé (LMDB seul)"));

      if (hex_blobs.empty())
      {
        // ── F-10 (2026-08-13) : corrige F-9 ──────────────────────────────────────────────
        // F-9 conservait la phase 2 armee et reessayait, en supposant que le testament vide
        // signifiait « fonds pas encore depensables ». Depuis F-9 justement, le gate ci-dessus
        // GARANTIT que les fonds sont revenus avant d'arriver ici : un testament vide n'est
        // donc PAS un probleme de minutage, c'est un probleme de STRUCTURE — le porteur a gele
        // le ou les seuls outputs disponibles. Reessayer a l'identique ne peut pas aider : le
        // 2026-08-13 cela a produit 752 repetitions en boucle a 5 s d'intervalle.
        // On repasse donc par la phase 1, qui scindera le solde en plusieurs outputs (F-10a),
        // et on arme un recul pour ne pas boucler entre les deux phases.
        MWARNING("PBC TESTAMENT: testament vide alors que les fonds SONT revenus depensables — "
                 "le porteur a reserve les seuls outputs disponibles. Nouvelle consolidation "
                 "avec scission en " << PBC_TESTAMENT_CONSOL_SPLIT << " sorties, apres un recul de "
                 << PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS << " blocs");
        // F-11 (2026-08-16) : le raccourci A-5.3 a laissé passer un état « 1 gros output +
        // poussière » — la sonde du porteur gèle le gros output (frais ~0,5 PBC) et le
        // balayage n'hérite que des miettes → build vide. Sans forçage, le cycle suivant
        // reprend le même raccourci et boucle à l'infini (observé : 70+ min, run F2#13).
        // On force la scission au prochain passage ; désarmé au premier build réussi.
        m_testament_force_split = true;
        m_testament_consol_target_height   = 0;
        m_testament_consol_expected        = 0;
        m_testament_consol_deadline_height = 0;
        m_testament_retry_after_height.store(
            m_wallet->get_blockchain_current_height() + PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS,
            std::memory_order_relaxed);
        return;
      }

      // ── Repli LMDB : stockage du testament sur le nœud local (best-effort) ──────────────
      // F-3 (2026-08-12) : ce stockage est REDONDANT dès lors que le porteur on-chain a été
      // diffusé. Le porteur fait foi : une fois miné, TOUS les nœuds rangent le testament
      // (branche PBC_TX_TYPE_INHERIT_TESTAMENT de add_block). Le store RPC ci-dessous n'écrit
      // que dans la LMDB du nœud interrogé — utile uniquement quand le porteur n'a PAS pu
      // être diffusé, et de toute façon inopérant après la disparition du nœud du principal.
      cryptonote::COMMAND_RPC_STORE_PBC_INHERIT_TESTAMENT::request  t_req{};
      cryptonote::COMMAND_RPC_STORE_PBC_INHERIT_TESTAMENT::response t_res{};
      t_req.principal_spend_pubkey = epee::string_tools::pod_to_hex(spend_pub);
      t_req.tx_blobs               = hex_blobs;
      ok = m_wallet->invoke_http_json_rpc("/json_rpc", "store_pbc_inherit_testament", t_req, t_res,
                                          std::chrono::seconds(30));
      const bool lmdb_stored = (ok && t_res.status == CORE_RPC_STATUS_OK && t_res.stored);
      if (!lmdb_stored)
        MWARNING("PBC TESTAMENT: repli LMDB indisponible (store_pbc_inherit_testament)"
          << " ok=" << ok << " status=" << t_res.status << " stored=" << t_res.stored
          << (onchain_published
                ? " — SANS CONSEQUENCE : le porteur on-chain fait foi"
                : " — le testament n'est stocke NULLE PART, nouvel essai apres recul"));

      // ── Critere de succes du cycle ─────────────────────────────────────────────────────
      // Le cycle reussit si le testament est opposable, c'est-a-dire diffusable par un nœud
      // TIERS le jour de l'execution. Seul le porteur on-chain le garantit. Le repli LMDB ne
      // vaut que pour le nœud local ; on l'accepte faute de mieux, mais il ne doit jamais
      // faire passer un cycle pour reussi a lui seul si le porteur a echoue... et surtout il
      // ne doit plus faire passer pour ECHOUE un cycle dont le porteur a reussi. C'etait le
      // defaut mesure le 2026-08-11 : le porteur partait (et etait paye), le repli LMDB etait
      // refuse pour une limite de taille deux fois trop basse, le cycle etait compte en echec,
      // m_testament_last_balance restait fige, et tout recommencait au passage suivant.
      const bool cycle_ok = onchain_published || lmdb_stored;
      m_testament_consol_target_height   = 0;
      m_testament_consol_expected        = 0;   // F-9 : purge de l'etat de consolidation
      m_testament_consol_deadline_height = 0;

      if (!cycle_ok)
      {
        LOG_ERROR("PBC TESTAMENT: cycle echoue — ni porteur on-chain ni repli LMDB;"
          << " recul de " << PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS << " blocs avant nouvel essai");
        // F-2 (2026-08-12) : ce chemin d'echec etait le SEUL des quatre a ne pas armer le
        // recul A-5.2 (les trois autres l'arment). Sans lui le declencheur restait arme et
        // relancait une consolidation a CHAQUE passage du handler idle.
        m_testament_retry_after_height.store(
            m_wallet->get_blockchain_current_height() + PBC_TESTAMENT_RETRY_BACKOFF_BLOCKS,
            std::memory_order_relaxed);
        return;
      }

      m_testament_force_split  = false;  // F-11 : build réussi — désarme le forçage de scission
      // ── F-13 (2026-08-17, finding 4.5) : référence en SOLDE TOTAL + key images ────────
      // Avant F-13, la référence était unlocked_balance() : le change du porteur/
      // consolidation (verrouillé 10 blocs) en était exclu, et son déverrouillage
      // remontait le solde débloqué de ≥ seuil → déclenchement en boucle (34 porteurs
      // en 13,5 min au run F5#3). Le solde total (balance(0,false)) est invariant aux
      // verrouillages ; la dépense des outputs référencés par le testament est quant à
      // elle détectée par leurs key images (déclencheur (ii) de la garde).
      m_testament_last_balance = m_wallet->balance(0, false);
      m_testament_key_images.clear();
      for (const auto& hex_blob : hex_blobs)
      {
        std::string raw_blob;
        cryptonote::transaction signed_tx;
        crypto::hash signed_txid;
        if (epee::string_tools::parse_hexstr_to_binbuff(hex_blob, raw_blob)
            && cryptonote::parse_and_validate_tx_from_blob(cryptonote::blobdata(raw_blob), signed_tx, signed_txid))
        {
          for (const auto& vin : signed_tx.vin)
            if (vin.type() == typeid(cryptonote::txin_to_key))
              m_testament_key_images.insert(boost::get<cryptonote::txin_to_key>(vin).k_image);
        }
        else
        {
          MWARNING("PBC TESTAMENT F-13: blob TX non analysable — garde key-images partielle");
        }
      }
      LOG_PRINT_L0("PBC TESTAMENT: testament updated successfully"
        << " tx_count=" << (lmdb_stored ? t_res.tx_count : (uint64_t)hex_blobs.size())
        << " total_balance=" << m_testament_last_balance
        << " key_images=" << m_testament_key_images.size()
        << " heir=" << m_testament_heir_address
        << " porteur_onchain=" << (onchain_published ? "oui" : "non")
        << " repli_lmdb=" << (lmdb_stored ? "oui" : "non"));
      return;
    }

    // ── PHASE 1 (IDLE): Check if update needed ───────────────────────────────
    // A-5.2 : respecter le recul arme par un echec precedent.
    {
      const uint64_t retry_after = m_testament_retry_after_height.load(std::memory_order_relaxed);
      if (retry_after != 0)
      {
        const uint64_t hnow = m_wallet->get_blockchain_current_height();
        if (hnow < retry_after)
        {
          LOG_PRINT_L2("PBC TESTAMENT: recul actif jusqu'au bloc " << retry_after
                       << " (hauteur " << hnow << ") - pas de consolidation");
          return;
        }
        m_testament_retry_after_height.store(0, std::memory_order_relaxed);
      }
    }

    const uint64_t current_balance = m_wallet->unlocked_balance(0, false);
    const uint64_t current_total   = m_wallet->balance(0, false);  // F-13 : référence totale

    // ── F-4 (2026-08-12) : PREMIERE signature ─────────────────────────────────────────────
    // Cette condition etait MORTE. Elle exigeait m_testament_heir_address vide, or l'adresse
    // de l'heritier est mise en cache une centaine de lignes plus haut, des que has_setup est
    // vrai — elle n'est donc JAMAIS vide ici. first_time valait toujours faux (le journal du
    // 2026-08-11 l'affiche noir sur blanc : « first_time=0 » alors que last=0), et le seul
    // declencheur restant etait « solde >= 0 + 100 PBC ».
    // CONSEQUENCE : un portefeuille detenant moins de PBC_TESTAMENT_RESIGN_THRESHOLD ne
    // signait JAMAIS de testament. Son heritier recevait les depots (transfert d'owner_key)
    // mais AUCUN fonds liquide. Le marqueur « jamais signe » est last == 0, rien d'autre.
    const bool first_time = (m_testament_last_balance == 0);

    // ── F-13 (2026-08-17, finding 4.5) : déclenchement sur PREUVE, pas sur variation ─────
    // Le déclencheur F-7 (delta en valeur absolue du solde DÉBLOQUÉ) était juste dans son
    // intention (une dépense périmètre le testament) mais sa mesure était fautive : la
    // référence était échantillonnée change encore verrouillé, donc le déverrouillage du
    // change 10 blocs plus tard était indistinguable d'une dépense externe → boucle
    // auto-entretenue (42 déclencheurs « hausse » ≈271,46 PBC au run F5#3). Nouvelle règle :
    //   (i)  une key image référencée par le testament pré-signé est DÉPENSÉE (dépense
    //        externe prouvée, même sous le seuil — le trou F-7 reste fermé), OU
    //   (ii) le solde TOTAL a CRU de ≥ seuil (réception de fonds → les couvrir pour
    //        l'héritier).
    // Le déverrouillage d'un change ne change NI le total NI les key images → boucle morte.
    // Nos propres TX de renouvellement ne consomment jamais ces key images : la
    // consolidation (phase 1) PRÉCÈDE la signature (l'ensemble enregistré ne référence
    // que des outputs frais), et le porteur gèle ses propres inputs (F-10).
    bool testament_ki_spent = false;
    if (!first_time && !m_testament_key_images.empty())
    {
      tools::wallet2::transfer_container tc;
      m_wallet->get_transfers(tc);   // même motif qu'au bloc A-5.3 (l.1167)
      for (const auto& td : tc)
      {
        if (td.m_spent && m_testament_key_images.count(td.m_key_image) != 0)
        {
          testament_ki_spent = true;
          break;
        }
      }
    }
    const uint64_t balance_growth = (current_total > m_testament_last_balance)
                                  ? (current_total - m_testament_last_balance) : 0;
    const bool balance_grew_enough = (balance_growth >= PBC_TESTAMENT_RESIGN_THRESHOLD);

    if (!first_time && !testament_ki_spent && !balance_grew_enough)
    {
      LOG_PRINT_L3("PBC TESTAMENT: no trigger ("
        << "total=" << current_total << " vs last=" << m_testament_last_balance
        << " growth=" << balance_growth
        << " ki_spent=0"
        << " threshold=" << PBC_TESTAMENT_RESIGN_THRESHOLD << "), skip");
      return;
    }

    LOG_PRINT_L0("PBC TESTAMENT: triggering consolidation (first_time=" << first_time
      << " total=" << current_total
      << " last=" << m_testament_last_balance
      << " growth=" << balance_growth
      << " ki_spent=" << (testament_ki_spent ? 1 : 0)
      << " threshold=" << PBC_TESTAMENT_RESIGN_THRESHOLD << ")");

    // ── A-5.3 : ne pas consolider un wallet DEJA consolide (corrige le 2026-08-11) ────────
    // Balayer un wallet qui n'a qu'un seul output dépensable ne consolide rien : cela ne fait
    // que depenser cet output et verrouiller le change, ce qui (a) empeche la signature du
    // testament juste apres et (b) invalide le testament deja stocke, qui reference l'output
    // desormais depense -> double-spend a l'execution. On saute directement en phase 2.
    {
      tools::wallet2::transfer_container tc;
      m_wallet->get_transfers(tc);   // meme motif que le reste du fichier (l.1246, 1305, 2950)
      size_t spendable = 0;
      for (const auto& td : tc)
        if (!td.m_spent && !td.m_frozen && m_wallet->is_transfer_unlocked(td))
          if (++spendable > PBC_TESTAMENT_CONSOL_SPLIT) break;
      // ── F-10 (2026-08-13) : condition CORRIGEE ────────────────────────────────────────
      // A-5.3 sautait le balayage des qu'il restait UN SEUL output depensable, au motif que
      // balayer un wallet deja consolide ne consolide rien. C'etait vrai, mais cela menait
      // droit dans le mur suivant : avec un seul output, le porteur le gele et le testament
      // n'a plus rien a balayer (cf. F-10 ci-dessous). Un seul output n'est donc PAS un etat
      // acceptable — il faut le SCINDER. On saute desormais le balayage uniquement quand le
      // wallet est deja dans un bon etat : au moins deux outputs (un pour le porteur, au
      // moins un pour le testament) et pas trop fragmente.
      // F-11 (2026-08-16) : le compte ne suffit pas — un état « 1 gros output + poussière »
      // passe ce test alors que la sonde du porteur doit geler le gros output (frais) et que
      // le balayage n'hérite alors que des miettes (build vide, boucle infinie). Après un
      // build vide avéré, m_testament_force_split court-circuite ce raccourci UNE fois :
      // la phase 1 scinde en 8 sorties et la répartition requise est créée.
      if (!m_testament_force_split && spendable >= 2 && spendable <= PBC_TESTAMENT_CONSOL_SPLIT)
      {
        LOG_PRINT_L1("PBC TESTAMENT: wallet deja consolide (" << spendable
                     << " outputs depensables, dont un pour le porteur) - signature directe");
        // F-9 : aucun balayage n'a eu lieu, il n'y a donc rien a attendre — le gate observe
        // de la phase 2 doit passer immediatement. expected=0 le garantit, et l'echeance est
        // desarmee puisqu'elle n'aurait aucun sens ici.
        m_testament_consol_expected        = 0;
        m_testament_consol_deadline_height = 0;
        m_testament_consol_target_height   = 1; // sentinelle : phase 2 au prochain cycle
        return;
      }
    }

    // Phase 1: Sweep all UTXOs to self (consolidation).
    // This merges fragmented coinbase outputs into 1-2 clean UTXOs before signing.
    // The actual testament TX (to heir) is built in Phase 2 after confirmation.
    const std::string self_addr = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    cryptonote::address_parse_info self_info{};
    if (!cryptonote::get_account_address_from_str_or_url(self_info, m_wallet->nettype(), self_addr))
    {
      LOG_ERROR("PBC TESTAMENT: failed to parse own address — cannot consolidate");
      return;
    }

    try
    {
      const uint64_t mixin    = m_wallet->adjust_mixin(0);
      const uint32_t priority = m_wallet->adjust_priority(0);

      LOG_PRINT_L0("PBC TESTAMENT: sweeping " << current_balance
        << " atomics to self (" << self_addr.substr(0, 16) << "...) for consolidation");

      // ── F-10 (2026-08-13) : consolider vers PLUSIEURS outputs, jamais vers un seul ──────
      // MESURE du 2026-08-13 : 756 « No unlocked balance » et 752 « testament vide ».
      // Le commentaire de pbc_build_testament_and_publish enonce la contrainte : le porteur
      // on-chain ne doit PAS depenser un input du testament, donc il GELE ses inputs puis le
      // testament « balaie tout SAUF eux ». Si le wallet n'a qu'UN SEUL output depensable —
      // ce qui est precisement le resultat d'une consolidation vers outputs=1 — le porteur
      // le gele et il ne reste RIEN pour le testament : build_inherit_testament leve
      // « No unlocked balance » et le cycle ne produit jamais de testament.
      // Le porteur et le testament se disputaient donc le meme et unique output.
      // On consolide desormais vers PBC_TESTAMENT_CONSOL_SPLIT sorties : le porteur en
      // reserve une (rarement deux), le testament couvre les autres, et la monnaie du
      // porteur revient au principal pour etre couverte au cycle suivant. Le cout en taille
      // est negligeable : les mesures donnent ~400 octets de blob par input, soit ~3 Ko pour
      // 8 sorties, tres loin de la limite de 32 Ko.
      std::vector<tools::wallet2::pending_tx> ptxs = m_wallet->create_transactions_all(
        /*below=*/0, self_info.address, /*is_subaddress=*/false,
        /*outputs=*/PBC_TESTAMENT_CONSOL_SPLIT, mixin, priority, /*extra=*/{}, /*account=*/0, /*subaddr_indices=*/{});

      if (ptxs.empty())
      {
        LOG_PRINT_L1("PBC TESTAMENT: consolidation: no UTXOs to sweep (already consolidated?)");
        // Skip phase 1, go straight to signing on next call
        // F-9 : idem — rien n'a ete balaye, donc rien a attendre.
        m_testament_consol_expected        = 0;
        m_testament_consol_deadline_height = 0;
        m_testament_consol_target_height   = 1; // sentinel: trigger Phase 2 immediately next cycle
        return;
      }

      m_wallet->commit_tx(ptxs);

      // ── A-5.1 puis F-9 : quand la phase 2 peut-elle s'ouvrir ? ───────────────────────
      // A-5.1 (2026-08-11) avait remplace un « h + 3 » ecrit a la main par la constante
      // CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE plus une marge. Cela n'a pas suffi, et ne pouvait
      // pas suffire : la hauteur ci-dessous vient du DEMON alors que le caractere depensable
      // se lit dans les transferts SCANNES par le wallet, qui retardent. F-9 conserve donc
      // cette hauteur comme simple PLANCHER et lui ajoute la vraie condition, observee dans
      // le gate de la phase 2 : le montant balaye doit etre REVENU depensable.
      constexpr uint64_t TESTAMENT_CONSOL_MARGIN_BLOCKS   = 4;
      // Echeance genereuse : au-dela, on considere que la consolidation ne reviendra pas
      // (evincee du mempool, reorg) et on abandonne franchement le cycle plutot que d'attendre
      // indefiniment. Comptee en blocs : une chaine a l'arret prolonge l'attente, ce qui est
      // exactement le comportement voulu.
      constexpr uint64_t TESTAMENT_CONSOL_DEADLINE_BLOCKS = 720;
      const uint64_t h = m_wallet->get_blockchain_current_height();

      // Ce que la consolidation doit rendre : tout ce qui a ete balaye, moins les frais.
      uint64_t total_fee = 0;
      for (const auto& ptx : ptxs) total_fee += ptx.fee;
      m_testament_consol_expected =
          (current_balance > total_fee) ? (current_balance - total_fee) : 0;

      m_testament_consol_target_height =
          h + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE + TESTAMENT_CONSOL_MARGIN_BLOCKS;
      m_testament_consol_deadline_height = h + TESTAMENT_CONSOL_DEADLINE_BLOCKS;
      LOG_PRINT_L0("PBC TESTAMENT: consolidation TX(s) submitted (" << ptxs.size()
        << " TX, frais=" << total_fee << "), will sign testament at block "
        << m_testament_consol_target_height << " des que " << m_testament_consol_expected
        << " atomics seront redevenus depensables (echeance bloc "
        << m_testament_consol_deadline_height << ")");
    }
    catch (const std::bad_alloc&)
    {
      LOG_ERROR("PBC TESTAMENT: std::bad_alloc during consolidation sweep — retry next cycle");
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("PBC TESTAMENT: consolidation sweep failed: " << e.what() << " — retry next cycle");
    }
  }
    //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::not_open(epee::json_rpc::error& er)
  {
      er.code = WALLET_RPC_ERROR_CODE_NOT_OPEN;
      er.message = "No wallet file";
      return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  // PBC: Determine transaction subtype from tx_extra field
  static std::string determine_pbc_subtype(const std::vector<uint8_t>& extra)
  {
    std::vector<cryptonote::tx_extra_field> fields;
    if (!cryptonote::parse_tx_extra(extra, fields))
      return "";
    cryptonote::tx_extra_pbc_tx_type pbc_type;
    if (!cryptonote::find_tx_extra_field_by_type(fields, pbc_type))
      return "";  // not a PBC-tagged transaction
    switch (pbc_type.type)
    {
      case PBC_TX_TYPE_TERM_DEPOSIT:   return "deposit";
      case PBC_TX_TYPE_CLAIM:          return "claim";
      case PBC_TX_TYPE_TERM_WITHDRAW:  return "withdraw";
      default:                         return "";
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::fill_transfer_entry(tools::wallet_rpc::transfer_entry &entry, const crypto::hash &txid, const crypto::hash &payment_id, const tools::wallet2::payment_details &pd)
  {
    entry.txid = string_tools::pod_to_hex(pd.m_tx_hash);
    entry.payment_id = string_tools::pod_to_hex(payment_id);
    if (entry.payment_id.substr(16).find_first_not_of('0') == std::string::npos)
      entry.payment_id = entry.payment_id.substr(0,16);
    entry.height = pd.m_block_height;
    entry.timestamp = pd.m_timestamp;
    entry.amount = pd.m_amount;
    entry.amounts = pd.m_amounts;
    // PBC CHAIN: for vesting coinbase (5 outputs), use worst-case unlock time (tier 4 = 90 days)
    uint64_t effective_unlock = pd.m_unlock_time;
    if (pd.m_coinbase && pd.m_amounts.size() >= 4) {
      effective_unlock = pd.m_block_height + 129600; // tier 4: ~90 days
    }
    entry.unlock_time = effective_unlock;
    entry.locked = !m_wallet->is_transfer_unlocked(effective_unlock, pd.m_block_height);
    entry.fee = pd.m_fee;
    entry.note = m_wallet->get_tx_note(pd.m_tx_hash);
    entry.type = pd.m_coinbase ? "block" : "in";
    entry.subtype = "";  // PBC: incoming payments have no subtype (no m_tx in payment_details)
    entry.subaddr_index = pd.m_subaddr_index;
    entry.subaddr_indices.push_back(pd.m_subaddr_index);
    entry.address = m_wallet->get_subaddress_as_str(pd.m_subaddr_index);
    set_confirmations(entry, m_wallet->get_blockchain_current_height(), m_wallet->get_last_block_reward(), effective_unlock);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::fill_transfer_entry(tools::wallet_rpc::transfer_entry &entry, const crypto::hash &txid, const tools::wallet2::confirmed_transfer_details &pd)
  {
    entry.txid = string_tools::pod_to_hex(txid);
    entry.payment_id = string_tools::pod_to_hex(pd.m_payment_id);
    if (entry.payment_id.substr(16).find_first_not_of('0') == std::string::npos)
      entry.payment_id = entry.payment_id.substr(0,16);
    entry.height = pd.m_block_height;
    entry.timestamp = pd.m_timestamp;
    entry.unlock_time = pd.m_unlock_time;
    entry.locked = !m_wallet->is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height);
    entry.fee = pd.m_amount_in - pd.m_amount_out;
    uint64_t change = pd.m_change == (uint64_t)-1 ? 0 : pd.m_change; // change may not be known
    entry.amount = pd.m_amount_in - change - entry.fee;
    entry.note = m_wallet->get_tx_note(txid);

    for (const auto &d: pd.m_dests) {
      entry.destinations.push_back(wallet_rpc::transfer_destination());
      wallet_rpc::transfer_destination &td = entry.destinations.back();
      td.amount = d.amount;
      td.address = d.address(m_wallet->nettype(), pd.m_payment_id);
    }

    entry.type = "out";
    entry.subtype = determine_pbc_subtype(pd.m_tx.extra);  // PBC: deposit/claim/withdraw
    entry.subaddr_index = { pd.m_subaddr_account, 0 };
    for (uint32_t i: pd.m_subaddr_indices)
      entry.subaddr_indices.push_back({pd.m_subaddr_account, i});
    entry.address = m_wallet->get_subaddress_as_str({pd.m_subaddr_account, 0});

    // PBC FIX: for pbc_withdraw TXs, m_amount_in=0 (no wallet inputs consumed) but m_amount_out=payout
    // (set by add_unconfirmed_tx summing ptx.dests). This causes uint64 underflow in the generic
    // fee/amount formula above. Override with correct values: fee=0, amount=sum(destinations).
    if (entry.subtype == "withdraw")
    {
      entry.fee = 0;
      entry.amount = 0;
      for (const auto &dest: entry.destinations)
        entry.amount += dest.amount;
    }

    set_confirmations(entry, m_wallet->get_blockchain_current_height(), m_wallet->get_last_block_reward(), pd.m_unlock_time);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::fill_transfer_entry(tools::wallet_rpc::transfer_entry &entry, const crypto::hash &txid, const tools::wallet2::unconfirmed_transfer_details &pd)
  {
    bool is_failed = pd.m_state == tools::wallet2::unconfirmed_transfer_details::failed;
    entry.txid = string_tools::pod_to_hex(txid);
    entry.payment_id = string_tools::pod_to_hex(pd.m_payment_id);
    entry.payment_id = string_tools::pod_to_hex(pd.m_payment_id);
    if (entry.payment_id.substr(16).find_first_not_of('0') == std::string::npos)
      entry.payment_id = entry.payment_id.substr(0,16);
    entry.height = 0;
    entry.timestamp = pd.m_timestamp;
    entry.fee = pd.m_amount_in - pd.m_amount_out;
    entry.amount = pd.m_amount_in - pd.m_change - entry.fee;
    entry.unlock_time = pd.m_tx.unlock_time;
    entry.locked = true;
    entry.note = m_wallet->get_tx_note(txid);

    for (const auto &d: pd.m_dests) {
      entry.destinations.push_back(wallet_rpc::transfer_destination());
      wallet_rpc::transfer_destination &td = entry.destinations.back();
      td.amount = d.amount;
      td.address = d.address(m_wallet->nettype(), pd.m_payment_id);
    }

    entry.type = is_failed ? "failed" : "pending";
    entry.subtype = determine_pbc_subtype(pd.m_tx.extra);  // PBC: deposit/claim/withdraw
    // PBC FIX: for pbc_withdraw pending TXs, m_amount_in=0 but m_amount_out=payout,
    // causing uint64 underflow in fee/amount above. Same override as confirmed path.
    if (entry.subtype == "withdraw")
    {
      entry.fee = 0;
      entry.amount = 0;
      for (const auto &dest: entry.destinations)
        entry.amount += dest.amount;
    }
    entry.subaddr_index = { pd.m_subaddr_account, 0 };
    for (uint32_t i: pd.m_subaddr_indices)
      entry.subaddr_indices.push_back({pd.m_subaddr_account, i});
    entry.address = m_wallet->get_subaddress_as_str({pd.m_subaddr_account, 0});
    set_confirmations(entry, m_wallet->get_blockchain_current_height(), m_wallet->get_last_block_reward(), pd.m_tx.unlock_time);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::fill_transfer_entry(tools::wallet_rpc::transfer_entry &entry, const crypto::hash &payment_id, const tools::wallet2::pool_payment_details &ppd)
  {
    const tools::wallet2::payment_details &pd = ppd.m_pd;
    entry.txid = string_tools::pod_to_hex(pd.m_tx_hash);
    entry.payment_id = string_tools::pod_to_hex(payment_id);
    if (entry.payment_id.substr(16).find_first_not_of('0') == std::string::npos)
      entry.payment_id = entry.payment_id.substr(0,16);
    entry.height = 0;
    entry.timestamp = pd.m_timestamp;
    entry.amount = pd.m_amount;
    entry.amounts = pd.m_amounts;
    entry.unlock_time = pd.m_unlock_time;
    entry.locked = true;
    entry.fee = pd.m_fee;
    entry.note = m_wallet->get_tx_note(pd.m_tx_hash);
    entry.double_spend_seen = ppd.m_double_spend_seen;
    entry.type = "pool";
    entry.subtype = "";  // PBC: pool incoming payments have no subtype (no m_tx in payment_details)
    entry.subaddr_index = pd.m_subaddr_index;
    entry.subaddr_indices.push_back(pd.m_subaddr_index);
    entry.address = m_wallet->get_subaddress_as_str(pd.m_subaddr_index);
    set_confirmations(entry, m_wallet->get_blockchain_current_height(), m_wallet->get_last_block_reward(), pd.m_unlock_time);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_getbalance(const wallet_rpc::COMMAND_RPC_GET_BALANCE::request& req, wallet_rpc::COMMAND_RPC_GET_BALANCE::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      res.balance = req.all_accounts ? m_wallet->balance_all(req.strict) : m_wallet->balance(req.account_index, req.strict);
      res.unlocked_balance = req.all_accounts ? m_wallet->unlocked_balance_all(req.strict, &res.blocks_to_unlock, &res.time_to_unlock) : m_wallet->unlocked_balance(req.account_index, req.strict, &res.blocks_to_unlock, &res.time_to_unlock);
      res.multisig_import_needed = m_wallet->multisig() && m_wallet->has_multisig_partial_key_images();

      // PBC FIX-1: TERM_WITHDRAW outputs are now normal, ring-signable RCT outputs once they
      // pass SPENDABLE_AGE (the wallet reproduces the exact ECDH commitment mask at scan time).
      // There is therefore no longer a category of "unlocked but non-spendable" withdraw outputs:
      // an unlocked withdraw output is already counted in unlocked_balance AND is spendable.
      // Outputs still maturing (< SPENDABLE_AGE) are simply locked, like any immature output, and
      // the UI surfaces them via tx confirmations. So this value is always 0.
      res.pbc_withdraw_pending_balance = 0;
      std::map<uint32_t, std::map<uint32_t, uint64_t>> balance_per_subaddress_per_account;
      std::map<uint32_t, std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>>> unlocked_balance_per_subaddress_per_account;
      if (req.all_accounts)
      {
        for (uint32_t account_index = 0; account_index < m_wallet->get_num_subaddress_accounts(); ++account_index)
        {
          balance_per_subaddress_per_account[account_index] = m_wallet->balance_per_subaddress(account_index, req.strict);
          unlocked_balance_per_subaddress_per_account[account_index] = m_wallet->unlocked_balance_per_subaddress(account_index, req.strict);
        }
      }
      else
      {
        balance_per_subaddress_per_account[req.account_index] = m_wallet->balance_per_subaddress(req.account_index, req.strict);
        unlocked_balance_per_subaddress_per_account[req.account_index] = m_wallet->unlocked_balance_per_subaddress(req.account_index, req.strict);
      }
      std::vector<tools::wallet2::transfer_details> transfers;
      m_wallet->get_transfers(transfers);
      for (const auto& p : balance_per_subaddress_per_account)
      {
        uint32_t account_index = p.first;
        std::map<uint32_t, uint64_t> balance_per_subaddress = p.second;
        std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddress = unlocked_balance_per_subaddress_per_account[account_index];
        std::set<uint32_t> address_indices;
        if (!req.all_accounts && !req.address_indices.empty())
        {
          address_indices = req.address_indices;
        }
        else
        {
          for (const auto& i : balance_per_subaddress)
            address_indices.insert(i.first);
        }
        for (uint32_t i : address_indices)
        {
          wallet_rpc::COMMAND_RPC_GET_BALANCE::per_subaddress_info info;
          info.account_index = account_index;
          info.address_index = i;
          cryptonote::subaddress_index index = {info.account_index, info.address_index};
          info.address = m_wallet->get_subaddress_as_str(index);
          info.balance = balance_per_subaddress[i];
          info.unlocked_balance = unlocked_balance_per_subaddress[i].first;
          info.blocks_to_unlock = unlocked_balance_per_subaddress[i].second.first;
          info.time_to_unlock = unlocked_balance_per_subaddress[i].second.second;
          info.label = m_wallet->get_subaddress_label(index);
          info.num_unspent_outputs = std::count_if(transfers.begin(), transfers.end(), [&](const tools::wallet2::transfer_details& td) { return !td.m_spent && td.m_subaddr_index == index; });
          res.per_subaddress.emplace_back(std::move(info));
        }
      }
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_getaddress(const wallet_rpc::COMMAND_RPC_GET_ADDRESS::request& req, wallet_rpc::COMMAND_RPC_GET_ADDRESS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      THROW_WALLET_EXCEPTION_IF(req.account_index >= m_wallet->get_num_subaddress_accounts(), error::account_index_outofbound);
      res.addresses.clear();
      std::vector<uint32_t> req_address_index;
      if (req.address_index.empty())
      {
        for (uint32_t i = 0; i < m_wallet->get_num_subaddresses(req.account_index); ++i)
          req_address_index.push_back(i);
      }
      else
      {
        req_address_index = req.address_index;
      }
      tools::wallet2::transfer_container transfers;
      m_wallet->get_transfers(transfers);
      for (uint32_t i : req_address_index)
      {
        THROW_WALLET_EXCEPTION_IF(i >= m_wallet->get_num_subaddresses(req.account_index), error::address_index_outofbound);
        res.addresses.resize(res.addresses.size() + 1);
        auto& info = res.addresses.back();
        const cryptonote::subaddress_index index = {req.account_index, i};
        info.address = m_wallet->get_subaddress_as_str(index);
        info.label = m_wallet->get_subaddress_label(index);
        info.address_index = index.minor;
        info.used = std::find_if(transfers.begin(), transfers.end(), [&](const tools::wallet2::transfer_details& td) { return td.m_subaddr_index == index; }) != transfers.end();
      }
      res.address = m_wallet->get_subaddress_as_str({req.account_index, 0});
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_getaddress_index(const wallet_rpc::COMMAND_RPC_GET_ADDRESS_INDEX::request& req, wallet_rpc::COMMAND_RPC_GET_ADDRESS_INDEX::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_wallet->nettype(), req.address))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      er.message = "Invalid address";
      return false;
    }
    auto index = m_wallet->get_subaddress_index(info.address);
    if (!index)
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      er.message = "Address doesn't belong to the wallet";
      return false;
    }
    res.index = *index;
    return true;
  }
  bool wallet_rpc_server::on_set_subaddr_lookahead(const wallet_rpc::COMMAND_RPC_SET_SUBADDR_LOOKAHEAD::request& req, wallet_rpc::COMMAND_RPC_SET_SUBADDR_LOOKAHEAD::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    const std::string wallet_file = m_wallet->get_wallet_file();
    if (wallet_file == "" || m_wallet->verify_password(req.password))
    {
      try
      {
        m_wallet->set_subaddress_lookahead(req.major_idx, req.minor_idx);
        m_wallet->rewrite(wallet_file, req.password);
      }
      catch (const std::exception& e) {
        handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return false;
      }
    }
    else
    {
      er.code = WALLET_RPC_ERROR_CODE_INVALID_PASSWORD;
      er.message = "Invalid password.";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_create_address(const wallet_rpc::COMMAND_RPC_CREATE_ADDRESS::request& req, wallet_rpc::COMMAND_RPC_CREATE_ADDRESS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      if (req.count < 1 || req.count > 65536) {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Count must be between 1 and 65536.";
        return false;
      }

      std::vector<std::string> addresses;
      std::vector<uint32_t>    address_indices;

      addresses.reserve(req.count);
      address_indices.reserve(req.count);

      for (uint32_t i = 0; i < req.count; i++) {
        m_wallet->add_subaddress(req.account_index, req.label);
        uint32_t new_address_index = m_wallet->get_num_subaddresses(req.account_index) - 1;
        address_indices.push_back(new_address_index);
        addresses.push_back(m_wallet->get_subaddress_as_str({req.account_index, new_address_index}));
      }

      res.address = addresses[0];
      res.address_index = address_indices[0];
      res.addresses = addresses;
      res.address_indices = address_indices;
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_label_address(const wallet_rpc::COMMAND_RPC_LABEL_ADDRESS::request& req, wallet_rpc::COMMAND_RPC_LABEL_ADDRESS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      m_wallet->set_subaddress_label(req.index, req.label);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_accounts(const wallet_rpc::COMMAND_RPC_GET_ACCOUNTS::request& req, wallet_rpc::COMMAND_RPC_GET_ACCOUNTS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      res.total_balance = 0;
      res.total_unlocked_balance = 0;
      cryptonote::subaddress_index subaddr_index = {0,0};
      const std::pair<std::map<std::string, std::string>, std::vector<std::string>> account_tags = m_wallet->get_account_tags();
      if (!req.tag.empty() && account_tags.first.count(req.tag) == 0 && !req.regexp)
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = (boost::format(tr("Tag %s is unregistered.")) % req.tag).str();
        return false;
      }
      for (; subaddr_index.major < m_wallet->get_num_subaddress_accounts(); ++subaddr_index.major)
      {
        bool no_match = !req.regexp ? (!req.tag.empty() && req.tag != account_tags.second[subaddr_index.major])
          : (!req.tag.empty() && !boost::regex_match(account_tags.second[subaddr_index.major], boost::regex(req.tag)));
        if (no_match)
          continue;
        wallet_rpc::COMMAND_RPC_GET_ACCOUNTS::subaddress_account_info info;
        info.account_index = subaddr_index.major;
        info.base_address = m_wallet->get_subaddress_as_str(subaddr_index);
        info.balance = m_wallet->balance(subaddr_index.major, req.strict_balances);
        info.unlocked_balance = m_wallet->unlocked_balance(subaddr_index.major, req.strict_balances);
        info.label = m_wallet->get_subaddress_label(subaddr_index);
        info.tag = account_tags.second[subaddr_index.major];
        res.subaddress_accounts.push_back(info);
        res.total_balance += info.balance;
        res.total_unlocked_balance += info.unlocked_balance;
      }
      if (res.subaddress_accounts.size() == 0 && req.regexp)
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = (boost::format(tr("No matches for regex filter %s .")) % req.tag).str();
        return false;
      }
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_create_account(const wallet_rpc::COMMAND_RPC_CREATE_ACCOUNT::request& req, wallet_rpc::COMMAND_RPC_CREATE_ACCOUNT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      m_wallet->add_subaddress_account(req.label);
      res.account_index = m_wallet->get_num_subaddress_accounts() - 1;
      res.address = m_wallet->get_subaddress_as_str({res.account_index, 0});
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_label_account(const wallet_rpc::COMMAND_RPC_LABEL_ACCOUNT::request& req, wallet_rpc::COMMAND_RPC_LABEL_ACCOUNT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      m_wallet->set_subaddress_label({req.account_index, 0}, req.label);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_account_tags(const wallet_rpc::COMMAND_RPC_GET_ACCOUNT_TAGS::request& req, wallet_rpc::COMMAND_RPC_GET_ACCOUNT_TAGS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    const std::pair<std::map<std::string, std::string>, std::vector<std::string>> account_tags = m_wallet->get_account_tags();
    for (const std::pair<const std::string, std::string>& p : account_tags.first)
    {
      res.account_tags.resize(res.account_tags.size() + 1);
      auto& info = res.account_tags.back();
      info.tag = p.first;
      info.label = p.second;
      for (size_t i = 0; i < account_tags.second.size(); ++i)
      {
        if (account_tags.second[i] == info.tag)
          info.accounts.push_back(i);
      }
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_tag_accounts(const wallet_rpc::COMMAND_RPC_TAG_ACCOUNTS::request& req, wallet_rpc::COMMAND_RPC_TAG_ACCOUNTS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      m_wallet->set_account_tag(req.accounts, req.tag);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_untag_accounts(const wallet_rpc::COMMAND_RPC_UNTAG_ACCOUNTS::request& req, wallet_rpc::COMMAND_RPC_UNTAG_ACCOUNTS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      m_wallet->set_account_tag(req.accounts, "");
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_set_account_tag_description(const wallet_rpc::COMMAND_RPC_SET_ACCOUNT_TAG_DESCRIPTION::request& req, wallet_rpc::COMMAND_RPC_SET_ACCOUNT_TAG_DESCRIPTION::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      m_wallet->set_account_tag_description(req.tag, req.description);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_getheight(const wallet_rpc::COMMAND_RPC_GET_HEIGHT::request& req, wallet_rpc::COMMAND_RPC_GET_HEIGHT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      res.height = m_wallet->get_blockchain_current_height();
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_freeze(const wallet_rpc::COMMAND_RPC_FREEZE::request& req, wallet_rpc::COMMAND_RPC_FREEZE::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      if (req.key_image.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = std::string("Must specify key image to freeze");
        return false;
      }
      crypto::key_image ki;
      if (!epee::string_tools::hex_to_pod(req.key_image, ki))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE;
        er.message = "failed to parse key image";
        return false;
      }
      m_wallet->freeze(ki);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_thaw(const wallet_rpc::COMMAND_RPC_THAW::request& req, wallet_rpc::COMMAND_RPC_THAW::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      if (req.key_image.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = std::string("Must specify key image to thaw");
        return false;
      }
      crypto::key_image ki;
      if (!epee::string_tools::hex_to_pod(req.key_image, ki))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE;
        er.message = "failed to parse key image";
        return false;
      }
      m_wallet->thaw(ki);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_frozen(const wallet_rpc::COMMAND_RPC_FROZEN::request& req, wallet_rpc::COMMAND_RPC_FROZEN::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      if (req.key_image.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = std::string("Must specify key image to check if frozen");
        return false;
      }
      crypto::key_image ki;
      if (!epee::string_tools::hex_to_pod(req.key_image, ki))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE;
        er.message = "failed to parse key image";
        return false;
      }
      res.frozen = m_wallet->frozen(ki);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::validate_transfer(const std::list<wallet_rpc::transfer_destination>& destinations, const std::string& payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, bool at_least_one_destination, epee::json_rpc::error& er)
  {
    CHECK_IF_BACKGROUND_SYNCING();

    crypto::hash8 integrated_payment_id = crypto::null_hash8;
    std::string extra_nonce;
    for (auto it = destinations.begin(); it != destinations.end(); it++)
    {
      cryptonote::address_parse_info info;
      cryptonote::tx_destination_entry de;
      er.message = "";
      if(!get_account_address_from_str_or_url(info, m_wallet->nettype(), it->address,
        [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
          if (!dnssec_valid)
          {
            er.message = std::string("Invalid DNSSEC for ") + url;
            return {};
          }
          if (addresses.empty())
          {
            er.message = std::string("No PBC Chain address found at ") + url;
            return {};
          }
          return addresses[0];
        }))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
        if (er.message.empty())
          er.message = std::string("WALLET_RPC_ERROR_CODE_WRONG_ADDRESS: ") + it->address;
        return false;
      }

      de.original = it->address;
      de.addr = info.address;
      de.is_subaddress = info.is_subaddress;
      de.amount = it->amount;
      de.is_integrated = info.has_payment_id;
      dsts.push_back(de);

      if (info.has_payment_id)
      {
        if (!payment_id.empty() || integrated_payment_id != crypto::null_hash8)
        {
          er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
          er.message = "A single payment id is allowed per transaction";
          return false;
        }
        integrated_payment_id = info.payment_id;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, integrated_payment_id);

        /* Append Payment ID data into extra */
        if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
          er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
          er.message = "Something went wrong with integrated payment_id.";
          return false;
        }
      }
    }

    if (at_least_one_destination && dsts.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_ZERO_DESTINATION;
      er.message = "Transaction has no destination";
      return false;
    }

    if (!payment_id.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
      er.message = "Standalone payment IDs are obsolete. Use subaddresses or integrated addresses instead";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  static std::string ptx_to_string(const tools::wallet2::pending_tx &ptx)
  {
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    try
    {
      if (!::serialization::serialize(ar, const_cast<tools::wallet2::pending_tx&>(ptx)))
        return "";
    }
    catch (...)
    {
      return "";
    }
    return epee::string_tools::buff_to_hex_nodelimer(oss.str());
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T> static bool is_error_value(const T &val) { return false; }
  static bool is_error_value(const std::string &s) { return s.empty(); }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T, typename V>
  static bool fill(T &where, V s)
  {
    if (is_error_value(s)) return false;
    where = std::move(s);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T, typename V>
  static bool fill(std::list<T> &where, V s)
  {
    if (is_error_value(s)) return false;
    where.emplace_back(std::move(s));
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  static uint64_t total_amount(const tools::wallet2::pending_tx &ptx)
  {
    uint64_t amount = 0;
    for (const auto &dest: ptx.dests) amount += dest.amount;
    return amount;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename Ts, typename Tu, typename Tk, typename Ta>
  bool wallet_rpc_server::fill_response(std::vector<tools::wallet2::pending_tx> &ptx_vector,
      bool get_tx_key, Ts& tx_key, Tu &amount, Ta &amounts_by_dest, Tu &fee, Tu &weight, std::string &multisig_txset, std::string &unsigned_txset, bool do_not_relay,
      Ts &tx_hash, bool get_tx_hex, Ts &tx_blob, bool get_tx_metadata, Ts &tx_metadata, Tk &spent_key_images, epee::json_rpc::error &er)
  {
    for (const auto & ptx : ptx_vector)
    {
      if (get_tx_key)
      {
        epee::wipeable_string s = epee::to_hex::wipeable_string(ptx.tx_key);
        for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys)
          s += epee::to_hex::wipeable_string(additional_tx_key);
        fill(tx_key, std::string(s.data(), s.size()));
      }
      // Compute amount leaving wallet in tx. By convention dests does not include change outputs
      fill(amount, total_amount(ptx));
      fill(fee, ptx.fee);
      fill(weight, cryptonote::get_transaction_weight(ptx.tx));

      // add amounts by destination
      tools::wallet_rpc::amounts_list abd;
      for (const auto& dst : ptx.dests)
        abd.amounts.push_back(dst.amount);
      fill(amounts_by_dest, abd);

      // add spent key images
      tools::wallet_rpc::key_image_list key_image_list;
      bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const cryptonote::txin_v& s_e) -> bool
      {
        CHECKED_GET_SPECIFIC_VARIANT(s_e, const cryptonote::txin_to_key, in, false);
        key_image_list.key_images.push_back(epee::string_tools::pod_to_hex(in.k_image));
        return true;
      });
      THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, ptx.tx);
      fill(spent_key_images, key_image_list);
    }

    if (m_wallet->multisig())
    {
      multisig_txset = epee::string_tools::buff_to_hex_nodelimer(m_wallet->save_multisig_tx(ptx_vector));
      if (multisig_txset.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Failed to save multisig tx set after creation";
        return false;
      }
    }
    else
    {
      if (m_wallet->watch_only()){
        unsigned_txset = epee::string_tools::buff_to_hex_nodelimer(m_wallet->dump_tx_to_str(ptx_vector));
        if (unsigned_txset.empty())
        {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = "Failed to save unsigned tx set after creation";
          return false;
        }
      }
      else if (!do_not_relay)
        m_wallet->commit_tx(ptx_vector);

      // populate response with tx hashes
      for (auto & ptx : ptx_vector)
      {
        bool r = fill(tx_hash, epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
        r = r && (!get_tx_hex || fill(tx_blob, epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx))));
        r = r && (!get_tx_metadata || fill(tx_metadata, ptx_to_string(ptx)));
        if (!r)
        {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = "Failed to save tx info";
          return false;
        }
      }
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  // PBC idempotency: optional client-supplied key makes a tx-creating RPC safe to retry and immune to
  // double-submission from any client. Duplicate key → reject (no second tx). In-memory; completed
  // entries expire after 10 min; in-flight entries are released on failure so the client can retry.
  bool wallet_rpc_server::idempotency_begin(const std::string &key, std::string &prior_tx_hash)
  {
    prior_tx_hash.clear();
    if (key.empty()) return true;
    std::lock_guard<std::mutex> lock(m_idempotency_lock);
    const auto now = std::chrono::steady_clock::now();
    for (auto it = m_idempotency_cache.begin(); it != m_idempotency_cache.end(); )
    {
      if (!it->second.in_flight && it->second.expiry <= now) it = m_idempotency_cache.erase(it);
      else ++it;
    }
    auto it = m_idempotency_cache.find(key);
    if (it != m_idempotency_cache.end())
    {
      prior_tx_hash = it->second.tx_hash; // empty if the prior request is still in-flight
      return false;                       // duplicate
    }
    pbc_idempotency_entry e;
    e.tx_hash.clear();
    e.expiry = now + std::chrono::minutes(10);
    e.in_flight = true;
    m_idempotency_cache[key] = e;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::idempotency_complete(const std::string &key, const std::string &tx_hash)
  {
    if (key.empty()) return;
    std::lock_guard<std::mutex> lock(m_idempotency_lock);
    pbc_idempotency_entry e;
    e.tx_hash = tx_hash;
    e.expiry = std::chrono::steady_clock::now() + std::chrono::minutes(10);
    e.in_flight = false;
    m_idempotency_cache[key] = e;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::idempotency_release(const std::string &key)
  {
    if (key.empty()) return;
    std::lock_guard<std::mutex> lock(m_idempotency_lock);
    auto it = m_idempotency_cache.find(key);
    if (it != m_idempotency_cache.end() && it->second.in_flight) m_idempotency_cache.erase(it);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_transfer(const wallet_rpc::COMMAND_RPC_TRANSFER::request& req, wallet_rpc::COMMAND_RPC_TRANSFER::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    LOG_PRINT_L3("on_transfer starts");
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    else if (req.unlock_time)
    {
      er.code = WALLET_RPC_ERROR_CODE_NONZERO_UNLOCK_TIME;
      er.message = "Transaction cannot have non-zero unlock time";
      return false;
    }

    CHECK_MULTISIG_ENABLED();

    // validate the transfer requested and populate dsts & extra
    if (!validate_transfer(req.destinations, req.payment_id, dsts, extra, true, er))
    {
      return false;
    }

    // PBC idempotency: optional key → reject a duplicate submission instead of building a 2nd tx.
    std::string idem_prior;
    if (!idempotency_begin(req.idempotency_key, idem_prior))
    {
      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
      er.message = idem_prior.empty()
        ? "Duplicate request: an operation with this idempotency_key is already in progress."
        : ("Duplicate request: this idempotency_key was already submitted (tx " + idem_prior + ").");
      return false;
    }
    idempotency_scope idem_guard(this, req.idempotency_key);

    try
    {
      uint64_t mixin = m_wallet->adjust_mixin(req.ring_size ? req.ring_size - 1 : 0);
      uint32_t priority = m_wallet->adjust_priority(req.priority);
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_transactions_2(dsts, mixin, priority, extra, req.account_index, req.subaddr_indices, req.subtract_fee_from_outputs);

      if (ptx_vector.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE;
        er.message = "No transaction created";
        return false;
      }

      // reject proposed transactions if there are more than one.  see on_transfer_split below.
      if (ptx_vector.size() != 1)
      {
        er.code = WALLET_RPC_ERROR_CODE_TX_TOO_LARGE;
        er.message = "Transaction would be too large.  try /transfer_split.";
        return false;
      }

      {
        const bool ok = fill_response(ptx_vector, req.get_tx_key, res.tx_key, res.amount, res.amounts_by_dest, res.fee, res.weight, res.multisig_txset, res.unsigned_txset, req.do_not_relay,
            res.tx_hash, req.get_tx_hex, res.tx_blob, req.get_tx_metadata, res.tx_metadata, res.spent_key_images, er);
        if (ok) idem_guard.commit(res.tx_hash);
        return ok;
      }
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_transfer_split(const wallet_rpc::COMMAND_RPC_TRANSFER_SPLIT::request& req, wallet_rpc::COMMAND_RPC_TRANSFER_SPLIT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    else if (req.unlock_time)
    {
      er.code = WALLET_RPC_ERROR_CODE_NONZERO_UNLOCK_TIME;
      er.message = "Transaction cannot have non-zero unlock time";
      return false;
    }

    CHECK_MULTISIG_ENABLED();

    // validate the transfer requested and populate dsts & extra; RPC_TRANSFER::request and RPC_TRANSFER_SPLIT::request are identical types.
    if (!validate_transfer(req.destinations, req.payment_id, dsts, extra, true, er))
    {
      return false;
    }

    // PBC idempotency: optional key → reject a duplicate submission instead of building a 2nd tx.
    std::string idem_prior;
    if (!idempotency_begin(req.idempotency_key, idem_prior))
    {
      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
      er.message = idem_prior.empty()
        ? "Duplicate request: an operation with this idempotency_key is already in progress."
        : ("Duplicate request: this idempotency_key was already submitted (tx " + idem_prior + ").");
      return false;
    }
    idempotency_scope idem_guard(this, req.idempotency_key);

    try
    {
      uint64_t mixin = m_wallet->adjust_mixin(req.ring_size ? req.ring_size - 1 : 0);
      uint32_t priority = m_wallet->adjust_priority(req.priority);
      LOG_PRINT_L2("on_transfer_split calling create_transactions_2");
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_transactions_2(dsts, mixin, priority, extra, req.account_index, req.subaddr_indices);
      LOG_PRINT_L2("on_transfer_split called create_transactions_2");

      if (ptx_vector.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE;
        er.message = "No transaction created";
        return false;
      }

      {
        const bool ok = fill_response(ptx_vector, req.get_tx_keys, res.tx_key_list, res.amount_list, res.amounts_by_dest_list, res.fee_list, res.weight_list, res.multisig_txset, res.unsigned_txset, req.do_not_relay,
            res.tx_hash_list, req.get_tx_hex, res.tx_blob_list, req.get_tx_metadata, res.tx_metadata_list, res.spent_key_images_list, er);
        if (ok)
        {
          std::string joined;
          for (const auto &h : res.tx_hash_list) { if (!joined.empty()) joined += ","; joined += h; }
          idem_guard.commit(joined);
        }
        return ok;
      }
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_sign_transfer(const wallet_rpc::COMMAND_RPC_SIGN_TRANSFER::request& req, wallet_rpc::COMMAND_RPC_SIGN_TRANSFER::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    if (m_wallet->key_on_device())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "command not supported by HW wallet";
      return false;
    }
    if(m_wallet->watch_only())
    {
      er.code = WALLET_RPC_ERROR_CODE_WATCH_ONLY;
      er.message = "command not supported by watch-only wallet";
      return false;
    }

    CHECK_MULTISIG_ENABLED();
    CHECK_IF_BACKGROUND_SYNCING();

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.unsigned_txset, blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_HEX;
      er.message = "Failed to parse hex.";
      return false;
    }

    tools::wallet2::unsigned_tx_set exported_txs;
    if(!m_wallet->parse_unsigned_tx_from_str(blob, exported_txs))
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA;
      er.message = "cannot load unsigned_txset";
      return false;
    }

    std::vector<tools::wallet2::pending_tx> ptxs;
    try
    {
      tools::wallet2::signed_tx_set signed_txs;
      std::string ciphertext = m_wallet->sign_tx_dump_to_str(exported_txs, ptxs, signed_txs);
      if (ciphertext.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_SIGN_UNSIGNED;
        er.message = "Failed to sign unsigned tx";
        return false;
      }

      res.signed_txset = epee::string_tools::buff_to_hex_nodelimer(ciphertext);
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_SIGN_UNSIGNED;
      er.message = std::string("Failed to sign unsigned tx: ") + e.what();
      return false;
    }

    for (auto &ptx: ptxs)
    {
      res.tx_hash_list.push_back(epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
      if (req.get_tx_keys)
      {
        res.tx_key_list.push_back(epee::string_tools::pod_to_hex(unwrap(unwrap(ptx.tx_key))));
        for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys)
          res.tx_key_list.back() += epee::string_tools::pod_to_hex(unwrap(unwrap(additional_tx_key)));
      }
    }

    if (req.export_raw)
    {
      for (auto &ptx: ptxs)
      {
        res.tx_raw_list.push_back(epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(ptx.tx)));
      }
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_describe_transfer(const wallet_rpc::COMMAND_RPC_DESCRIBE_TRANSFER::request& req, wallet_rpc::COMMAND_RPC_DESCRIBE_TRANSFER::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    if (m_wallet->key_on_device())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "command not supported by HW wallet";
      return false;
    }
    if(m_wallet->watch_only())
    {
      er.code = WALLET_RPC_ERROR_CODE_WATCH_ONLY;
      er.message = "command not supported by watch-only wallet";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();
    if(req.unsigned_txset.empty() && req.multisig_txset.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "no txset provided";
      return false;
    }

    std::vector <wallet2::tx_construction_data> tx_constructions;
    if (!req.unsigned_txset.empty()) {
      try {
        tools::wallet2::unsigned_tx_set exported_txs;
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(req.unsigned_txset, blob)) {
          er.code = WALLET_RPC_ERROR_CODE_BAD_HEX;
          er.message = "Failed to parse hex.";
          return false;
        }
        if (!m_wallet->parse_unsigned_tx_from_str(blob, exported_txs)) {
          er.code = WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA;
          er.message = "cannot load unsigned_txset";
          return false;
        }
        tx_constructions = exported_txs.txes;
      }
      catch (const std::exception &e) {
        er.code = WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA;
        er.message = "failed to parse unsigned transfers: " + std::string(e.what());
        return false;
      }
    } else if (!req.multisig_txset.empty()) {
      try {
        tools::wallet2::multisig_tx_set exported_txs;
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(req.multisig_txset, blob)) {
          er.code = WALLET_RPC_ERROR_CODE_BAD_HEX;
          er.message = "Failed to parse hex.";
          return false;
        }
        if (!m_wallet->parse_multisig_tx_from_str(blob, exported_txs)) {
          er.code = WALLET_RPC_ERROR_CODE_BAD_MULTISIG_TX_DATA;
          er.message = "cannot load multisig_txset";
          return false;
        }

        for (size_t n = 0; n < exported_txs.m_ptx.size(); ++n) {
          tx_constructions.push_back(exported_txs.m_ptx[n].construction_data);
        }
      }
      catch (const std::exception &e) {
        er.code = WALLET_RPC_ERROR_CODE_BAD_MULTISIG_TX_DATA;
        er.message = "failed to parse multisig transfers: " + std::string(e.what());
        return false;
      }
    }

    try
    {
      // gather info to ask the user
      std::unordered_map<cryptonote::account_public_address, std::pair<std::string, uint64_t>> tx_dests;
      std::unordered_map<cryptonote::account_public_address, std::pair<std::string, uint64_t>> all_dests;
      int first_known_non_zero_change_index = -1;
      res.summary.amount_in = 0;
      res.summary.amount_out = 0;
      res.summary.change_amount = 0;
      res.summary.fee = 0;
      for (size_t n = 0; n < tx_constructions.size(); ++n)
      {
        const tools::wallet2::tx_construction_data &cd = tx_constructions[n];
        res.desc.push_back({0, 0, std::numeric_limits<uint32_t>::max(), 0, {}, "", 0, "", 0, 0, ""});
        wallet_rpc::COMMAND_RPC_DESCRIBE_TRANSFER::transfer_description &desc = res.desc.back();
        // Clear the recipients collection ready for this loop iteration
        tx_dests.clear();

        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        bool has_encrypted_payment_id = false;
        crypto::hash8 payment_id8 = crypto::null_hash8;
        if (cryptonote::parse_tx_extra(cd.extra, tx_extra_fields))
        {
          cryptonote::tx_extra_nonce extra_nonce;
          if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
          {
            crypto::hash payment_id;
            if(cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
            {
              if (payment_id8 != crypto::null_hash8)
              {
                desc.payment_id = epee::string_tools::pod_to_hex(payment_id8);
                has_encrypted_payment_id = true;
              }
            }
            else if (cryptonote::get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
            {
              desc.payment_id = epee::string_tools::pod_to_hex(payment_id);
            }
          }
        }

        for (size_t s = 0; s < cd.sources.size(); ++s)
        {
          desc.amount_in += cd.sources[s].amount;
          size_t ring_size = cd.sources[s].outputs.size();
          if (ring_size < desc.ring_size)
            desc.ring_size = ring_size;
        }
        for (size_t d = 0; d < cd.splitted_dsts.size(); ++d)
        {
          const cryptonote::tx_destination_entry &entry = cd.splitted_dsts[d];
          std::string address = cryptonote::get_account_address_as_str(m_wallet->nettype(), entry.is_subaddress, entry.addr);
          if (has_encrypted_payment_id && !entry.is_subaddress && address != entry.original)
            address = cryptonote::get_account_integrated_address_as_str(m_wallet->nettype(), entry.addr, payment_id8);
          auto i = tx_dests.find(entry.addr);
          if (i == tx_dests.end())
            tx_dests.insert(std::make_pair(entry.addr, std::make_pair(address, entry.amount)));
          else
            i->second.second += entry.amount;
          desc.amount_out += entry.amount;
        }
        if (cd.change_dts.amount > 0)
        {
          auto it = tx_dests.find(cd.change_dts.addr);
          if (it == tx_dests.end())
          {
            er.code = WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA;
            er.message = "Claimed change does not go to a paid address";
            return false;
          }
          if (it->second.second < cd.change_dts.amount)
          {
            er.code = WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA;
            er.message = "Claimed change is larger than payment to the change address";
            return false;
          }
          if (cd.change_dts.amount > 0)
          {
            if (first_known_non_zero_change_index == -1)
              first_known_non_zero_change_index = n;
            const tools::wallet2::tx_construction_data &cdn = tx_constructions[first_known_non_zero_change_index];
            if (memcmp(&cd.change_dts.addr, &cdn.change_dts.addr, sizeof(cd.change_dts.addr)))
            {
              er.code = WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA;
              er.message = "Change goes to more than one address";
              return false;
            }
          }
          desc.change_amount += cd.change_dts.amount;
          it->second.second -= cd.change_dts.amount;
          if (it->second.second == 0)
            tx_dests.erase(cd.change_dts.addr);
        }

        for (auto i = tx_dests.begin(); i != tx_dests.end(); ++i)
        {
          if (i->second.second > 0)
          {
            desc.recipients.push_back({i->second.first, i->second.second});
            auto it_in_all = all_dests.find(i->first);
            if (it_in_all == all_dests.end())
              all_dests.insert(std::make_pair(i->first, i->second));
            else
              it_in_all->second.second += i->second.second;
          }
          else
            ++desc.dummy_outputs;
        }

        if (desc.change_amount > 0)
        {
          const tools::wallet2::tx_construction_data &cd0 = tx_constructions[0];
          desc.change_address = get_account_address_as_str(m_wallet->nettype(), cd0.subaddr_account > 0, cd0.change_dts.addr);
          res.summary.change_address = desc.change_address;
        }

        desc.fee = desc.amount_in - desc.amount_out;
        desc.unlock_time = cd.unlock_time;
        desc.extra = epee::to_hex::string({cd.extra.data(), cd.extra.size()});

        // Update summary items
        res.summary.amount_in += desc.amount_in;
        res.summary.amount_out += desc.amount_out;
        res.summary.change_amount += desc.change_amount;
        res.summary.fee += desc.fee;
      }
      // Populate the summary recipients list
      for (auto i = all_dests.begin(); i != all_dests.end(); ++i)
      {
        res.summary.recipients.push_back({i->second.first, i->second.second});
      }
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA;
      er.message = "failed to parse unsigned transfers";
      return false;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_submit_transfer(const wallet_rpc::COMMAND_RPC_SUBMIT_TRANSFER::request& req, wallet_rpc::COMMAND_RPC_SUBMIT_TRANSFER::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    if (m_wallet->key_on_device())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "command not supported by HW wallet";
      return false;
    }

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.tx_data_hex, blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_HEX;
      er.message = "Failed to parse hex.";
      return false;
    }

    std::vector<tools::wallet2::pending_tx> ptx_vector;
    try
    {
      bool r = m_wallet->parse_tx_from_str(blob, ptx_vector, NULL);
      if (!r)
      {
        er.code = WALLET_RPC_ERROR_CODE_BAD_SIGNED_TX_DATA;
        er.message = "Failed to parse signed tx data.";
        return false;
      }
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_SIGNED_TX_DATA;
      er.message = std::string("Failed to parse signed tx: ") + e.what();
      return false;
    }

    try
    {
      for (auto &ptx: ptx_vector)
      {
        m_wallet->commit_tx(ptx);
        res.tx_hash_list.push_back(epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
      }
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_SIGNED_SUBMISSION;
      er.message = std::string("Failed to submit signed tx: ") + e.what();
      return false;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_sweep_dust(const wallet_rpc::COMMAND_RPC_SWEEP_DUST::request& req, wallet_rpc::COMMAND_RPC_SWEEP_DUST::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    CHECK_MULTISIG_ENABLED();
    CHECK_IF_BACKGROUND_SYNCING();

    try
    {
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_unmixable_sweep_transactions();

      return fill_response(ptx_vector, req.get_tx_keys, res.tx_key_list, res.amount_list, res.amounts_by_dest_list, res.fee_list, res.weight_list, res.multisig_txset, res.unsigned_txset, req.do_not_relay,
          res.tx_hash_list, req.get_tx_hex, res.tx_blob_list, req.get_tx_metadata, res.tx_metadata_list, res.spent_key_images_list, er);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_sweep_all(const wallet_rpc::COMMAND_RPC_SWEEP_ALL::request& req, wallet_rpc::COMMAND_RPC_SWEEP_ALL::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    else if (req.unlock_time)
    {
      er.code = WALLET_RPC_ERROR_CODE_NONZERO_UNLOCK_TIME;
      er.message = "Transaction cannot have non-zero unlock time";
      return false;
    }

    CHECK_MULTISIG_ENABLED();

    // validate the transfer requested and populate dsts & extra
    std::list<wallet_rpc::transfer_destination> destination;
    destination.push_back(wallet_rpc::transfer_destination());
    destination.back().amount = 0;
    destination.back().address = req.address;
    if (!validate_transfer(destination, req.payment_id, dsts, extra, true, er))
    {
      return false;
    }

    if (req.outputs < 1)
    {
      er.code = WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE;
      er.message = "Amount of outputs should be greater than 0.";
      return  false;
    }

    std::set<uint32_t> subaddr_indices;
    if (req.subaddr_indices_all)
    {
      for (uint32_t i = 0; i < m_wallet->get_num_subaddresses(req.account_index); ++i)
        subaddr_indices.insert(i);
    }
    else
    {
      subaddr_indices= req.subaddr_indices;
    }

    try
    {
      uint64_t mixin = m_wallet->adjust_mixin(req.ring_size ? req.ring_size - 1 : 0);
      uint32_t priority = m_wallet->adjust_priority(req.priority);
      LOG_PRINT_L0("PBC_LOG on_sweep_all: ENTER below_amount=" << req.below_amount
        << " ring_size=" << req.ring_size << " mixin=" << mixin
        << " unlocked_balance=" << m_wallet->unlocked_balance(req.account_index, false));
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_transactions_all(req.below_amount, dsts[0].addr, dsts[0].is_subaddress, req.outputs, mixin, priority, extra, req.account_index, subaddr_indices);
      LOG_PRINT_L0("PBC_LOG on_sweep_all: ptx_vector.size()=" << ptx_vector.size());

      return fill_response(ptx_vector, req.get_tx_keys, res.tx_key_list, res.amount_list, res.amounts_by_dest_list, res.fee_list, res.weight_list, res.multisig_txset, res.unsigned_txset, req.do_not_relay,
          res.tx_hash_list, req.get_tx_hex, res.tx_blob_list, req.get_tx_metadata, res.tx_metadata_list, res.spent_key_images_list, er);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }
//------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_sweep_single(const wallet_rpc::COMMAND_RPC_SWEEP_SINGLE::request& req, wallet_rpc::COMMAND_RPC_SWEEP_SINGLE::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    else if (req.unlock_time)
    {
      er.code = WALLET_RPC_ERROR_CODE_NONZERO_UNLOCK_TIME;
      er.message = "Transaction cannot have non-zero unlock time";
      return false;
    }

    if (req.outputs < 1)
    {
      er.code = WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE;
      er.message = "Amount of outputs should be greater than 0.";
      return  false;
    }

    CHECK_MULTISIG_ENABLED();

    // validate the transfer requested and populate dsts & extra
    std::list<wallet_rpc::transfer_destination> destination;
    destination.push_back(wallet_rpc::transfer_destination());
    destination.back().amount = 0;
    destination.back().address = req.address;
    if (!validate_transfer(destination, req.payment_id, dsts, extra, true, er))
    {
      return false;
    }

    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(req.key_image, ki))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE;
      er.message = "failed to parse key image";
      return false;
    }

    try
    {
      uint64_t mixin = m_wallet->adjust_mixin(req.ring_size ? req.ring_size - 1 : 0);
      uint32_t priority = m_wallet->adjust_priority(req.priority);
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_transactions_single(ki, dsts[0].addr, dsts[0].is_subaddress, req.outputs, mixin, priority, extra);

      if (ptx_vector.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "No outputs found";
        return false;
      }
      if (ptx_vector.size() > 1)
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Multiple transactions are created, which is not supposed to happen";
        return false;
      }
      const wallet2::pending_tx &ptx = ptx_vector[0];
      if (ptx.selected_transfers.size() > 1)
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "The transaction uses multiple inputs, which is not supposed to happen";
        return false;
      }

      return fill_response(ptx_vector, req.get_tx_key, res.tx_key, res.amount, res.amounts_by_dest, res.fee, res.weight, res.multisig_txset, res.unsigned_txset, req.do_not_relay,
          res.tx_hash, req.get_tx_hex, res.tx_blob, req.get_tx_metadata, res.tx_metadata, res.spent_key_images, er);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    catch (...)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_relay_tx(const wallet_rpc::COMMAND_RPC_RELAY_TX::request& req, wallet_rpc::COMMAND_RPC_RELAY_TX::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.hex, blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_HEX;
      er.message = "Failed to parse hex.";
      return false;
    }

    bool loaded = false;
    tools::wallet2::pending_tx ptx;

    try
    {
      binary_archive<false> ar{epee::strspan<std::uint8_t>(blob)};
      if (::serialization::serialize(ar, ptx))
        loaded = true;
    }
    catch(...) {}

    if (!loaded && !m_restricted)
    {
      try
      {
        std::istringstream iss(blob);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> ptx;
        loaded = true;
      }
      catch (...) {}
    }

    if (!loaded)
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_TX_METADATA;
      er.message = "Failed to parse tx metadata.";
      return false;
    }

    try
    {
      m_wallet->commit_tx(ptx);
    }
    catch(const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
      er.message = "Failed to commit tx.";
      return false;
    }

    res.tx_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_make_integrated_address(const wallet_rpc::COMMAND_RPC_MAKE_INTEGRATED_ADDRESS::request& req, wallet_rpc::COMMAND_RPC_MAKE_INTEGRATED_ADDRESS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      crypto::hash8 payment_id;
      if (req.payment_id.empty())
      {
        payment_id = crypto::rand<crypto::hash8>();
      }
      else
      {
        if (!tools::wallet2::parse_short_payment_id(req.payment_id,payment_id))
        {
          er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
          er.message = "Invalid payment ID";
          return false;
        }
      }

      if (req.standard_address.empty())
      {
        res.integrated_address = m_wallet->get_integrated_address_as_str(payment_id);
      }
      else
      {
        cryptonote::address_parse_info info;
        if(!get_account_address_from_str(info, m_wallet->nettype(), req.standard_address))
        {
          er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
          er.message = "Invalid address";
          return false;
        }
        if (info.is_subaddress)
        {
          er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
          er.message = "Subaddress shouldn't be used";
          return false;
        }
        if (info.has_payment_id)
        {
          er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
          er.message = "Already integrated address";
          return false;
        }
        res.integrated_address = get_account_integrated_address_as_str(m_wallet->nettype(), info.address, payment_id);
      }
      res.payment_id = epee::string_tools::pod_to_hex(payment_id);
      return true;
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_split_integrated_address(const wallet_rpc::COMMAND_RPC_SPLIT_INTEGRATED_ADDRESS::request& req, wallet_rpc::COMMAND_RPC_SPLIT_INTEGRATED_ADDRESS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      cryptonote::address_parse_info info;

      if(!get_account_address_from_str(info, m_wallet->nettype(), req.integrated_address))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
        er.message = "Invalid address";
        return false;
      }
      if(!info.has_payment_id)
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
        er.message = "Address is not an integrated address";
        return false;
      }
      res.standard_address = get_account_address_as_str(m_wallet->nettype(), info.is_subaddress, info.address);
      res.payment_id = epee::string_tools::pod_to_hex(info.payment_id);
      return true;
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_store(const wallet_rpc::COMMAND_RPC_STORE::request& req, wallet_rpc::COMMAND_RPC_STORE::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    try
    {
      m_wallet->store();
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_payments(const wallet_rpc::COMMAND_RPC_GET_PAYMENTS::request& req, wallet_rpc::COMMAND_RPC_GET_PAYMENTS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    crypto::hash payment_id;
    crypto::hash8 payment_id8;
    cryptonote::blobdata payment_id_blob;
    if(!epee::string_tools::parse_hexstr_to_binbuff(req.payment_id, payment_id_blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
      er.message = "Payment ID has invalid format";
      return false;
    }

      if(sizeof(payment_id) == payment_id_blob.size())
      {
        payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_blob.data());
      }
      else if(sizeof(payment_id8) == payment_id_blob.size())
      {
        payment_id8 = *reinterpret_cast<const crypto::hash8*>(payment_id_blob.data());
        memcpy(payment_id.data, payment_id8.data, 8);
        memset(payment_id.data + 8, 0, 24);
      }
      else
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Payment ID has invalid size: " + req.payment_id;
        return false;
      }

    res.payments.clear();
    std::list<wallet2::payment_details> payment_list;
    m_wallet->get_payments(payment_id, payment_list);
    for (auto & payment : payment_list)
    {
      wallet_rpc::payment_details rpc_payment;
      rpc_payment.payment_id   = req.payment_id;
      rpc_payment.tx_hash      = epee::string_tools::pod_to_hex(payment.m_tx_hash);
      rpc_payment.amount       = payment.m_amount;
      rpc_payment.block_height = payment.m_block_height;
      rpc_payment.unlock_time  = payment.m_unlock_time;
      rpc_payment.locked       = !m_wallet->is_transfer_unlocked(payment.m_unlock_time, payment.m_block_height);
      rpc_payment.subaddr_index = payment.m_subaddr_index;
      rpc_payment.address      = m_wallet->get_subaddress_as_str(payment.m_subaddr_index);
      res.payments.push_back(rpc_payment);
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_bulk_payments(const wallet_rpc::COMMAND_RPC_GET_BULK_PAYMENTS::request& req, wallet_rpc::COMMAND_RPC_GET_BULK_PAYMENTS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    res.payments.clear();
    if (!m_wallet) return not_open(er);

    /* If the payment ID list is empty, we get payments to any payment ID (or lack thereof) */
    if (req.payment_ids.empty())
    {
      std::list<std::pair<crypto::hash,wallet2::payment_details>> payment_list;
      m_wallet->get_payments(payment_list, req.min_block_height);

      for (auto & payment : payment_list)
      {
        wallet_rpc::payment_details rpc_payment;
        rpc_payment.payment_id   = epee::string_tools::pod_to_hex(payment.first);
        rpc_payment.tx_hash      = epee::string_tools::pod_to_hex(payment.second.m_tx_hash);
        rpc_payment.amount       = payment.second.m_amount;
        rpc_payment.block_height = payment.second.m_block_height;
        rpc_payment.unlock_time  = payment.second.m_unlock_time;
        rpc_payment.subaddr_index = payment.second.m_subaddr_index;
        rpc_payment.address      = m_wallet->get_subaddress_as_str(payment.second.m_subaddr_index);
        rpc_payment.locked       = !m_wallet->is_transfer_unlocked(payment.second.m_unlock_time, payment.second.m_block_height);
        res.payments.push_back(std::move(rpc_payment));
      }

      return true;
    }

    for (auto & payment_id_str : req.payment_ids)
    {
      crypto::hash payment_id;
      crypto::hash8 payment_id8;
      cryptonote::blobdata payment_id_blob;

      // TODO - should the whole thing fail because of one bad id?
      bool r;
      if (payment_id_str.size() == 2 * sizeof(payment_id))
      {
        r = epee::string_tools::hex_to_pod(payment_id_str, payment_id);
      }
      else if (payment_id_str.size() == 2 * sizeof(payment_id8))
      {
        r = epee::string_tools::hex_to_pod(payment_id_str, payment_id8);
        if (r)
        {
          memcpy(payment_id.data, payment_id8.data, 8);
          memset(payment_id.data + 8, 0, 24);
        }
      }
      else
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Payment ID has invalid size: " + payment_id_str;
        return false;
      }

      if(!r)
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Payment ID has invalid format: " + payment_id_str;
        return false;
      }

      std::list<wallet2::payment_details> payment_list;
      m_wallet->get_payments(payment_id, payment_list, req.min_block_height);

      for (auto & payment : payment_list)
      {
        wallet_rpc::payment_details rpc_payment;
        rpc_payment.payment_id   = payment_id_str;
        rpc_payment.tx_hash      = epee::string_tools::pod_to_hex(payment.m_tx_hash);
        rpc_payment.amount       = payment.m_amount;
        rpc_payment.block_height = payment.m_block_height;
        rpc_payment.unlock_time  = payment.m_unlock_time;
        rpc_payment.subaddr_index = payment.m_subaddr_index;
        rpc_payment.address      = m_wallet->get_subaddress_as_str(payment.m_subaddr_index);
        rpc_payment.locked       = !m_wallet->is_transfer_unlocked(payment.m_unlock_time, payment.m_block_height);
        res.payments.push_back(std::move(rpc_payment));
      }
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_incoming_transfers(const wallet_rpc::COMMAND_RPC_INCOMING_TRANSFERS::request& req, wallet_rpc::COMMAND_RPC_INCOMING_TRANSFERS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if(req.transfer_type.compare("all") != 0 && req.transfer_type.compare("available") != 0 && req.transfer_type.compare("unavailable") != 0)
    {
      er.code = WALLET_RPC_ERROR_CODE_TRANSFER_TYPE;
      er.message = "Transfer type must be one of: all, available, or unavailable";
      return false;
    }

    bool filter = false;
    bool available = false;
    if (req.transfer_type.compare("available") == 0)
    {
      filter = true;
      available = true;
    }
    else if (req.transfer_type.compare("unavailable") == 0)
    {
      filter = true;
      available = false;
    }

    wallet2::transfer_container transfers;
    m_wallet->get_transfers(transfers);

    for (const auto& td : transfers)
    {
      if (!filter || available != td.m_spent)
      {
        if (req.account_index != td.m_subaddr_index.major || (!req.subaddr_indices.empty() && req.subaddr_indices.count(td.m_subaddr_index.minor) == 0))
          continue;
        wallet_rpc::transfer_details rpc_transfers;
        rpc_transfers.amount       = td.amount();
        rpc_transfers.spent        = td.m_spent;
        rpc_transfers.global_index = td.m_global_output_index;
        rpc_transfers.tx_hash      = epee::string_tools::pod_to_hex(td.m_txid);
        rpc_transfers.subaddr_index = {td.m_subaddr_index.major, td.m_subaddr_index.minor};
        rpc_transfers.key_image    = td.m_key_image_known ? epee::string_tools::pod_to_hex(td.m_key_image) : "";
        rpc_transfers.pubkey       = epee::string_tools::pod_to_hex(td.get_public_key());
        rpc_transfers.block_height = td.m_block_height;
        rpc_transfers.frozen       = td.m_frozen;
        rpc_transfers.unlocked     = m_wallet->is_transfer_unlocked(td);
        res.transfers.push_back(rpc_transfers);
      }
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_query_key(const wallet_rpc::COMMAND_RPC_QUERY_KEY::request& req, wallet_rpc::COMMAND_RPC_QUERY_KEY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
      if (!m_wallet) return not_open(er);
      if (m_restricted)
      {
        er.code = WALLET_RPC_ERROR_CODE_DENIED;
        er.message = "Command unavailable in restricted mode.";
        return false;
      }

      if (req.key_type.compare("mnemonic") == 0)
      {
        epee::wipeable_string seed;
        bool ready;
        if (m_wallet->multisig(&ready))
        {
          if (!ready)
          {
            er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
            er.message = "This wallet is multisig, but not yet finalized";
            return false;
          }
          if (!m_wallet->get_multisig_seed(seed))
          {
            er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
            er.message = "Failed to get multisig seed.";
            return false;
          }
        }
        else
        {
          if (m_wallet->watch_only())
          {
            er.code = WALLET_RPC_ERROR_CODE_WATCH_ONLY;
            er.message = "The wallet is watch-only. Cannot retrieve seed.";
            return false;
          }
          CHECK_IF_BACKGROUND_SYNCING();
          if (!m_wallet->is_deterministic())
          {
            er.code = WALLET_RPC_ERROR_CODE_NON_DETERMINISTIC;
            er.message = "The wallet is non-deterministic. Cannot display seed.";
            return false;
          }
          if (!m_wallet->get_seed(seed))
          {
            er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
            er.message = "Failed to get seed.";
            return false;
          }
        }
        res.key = std::string(seed.data(), seed.size()); // send to the network, then wipe RAM :D
      }
      else if(req.key_type.compare("view_key") == 0)
      {
          epee::wipeable_string key = epee::to_hex::wipeable_string(m_wallet->get_account().get_keys().m_view_secret_key);
          res.key = std::string(key.data(), key.size());
      }
      else if(req.key_type.compare("spend_key") == 0)
      {
          if (m_wallet->watch_only())
          {
            er.code = WALLET_RPC_ERROR_CODE_WATCH_ONLY;
            er.message = "The wallet is watch-only. Cannot retrieve spend key.";
            return false;
          }
          CHECK_IF_BACKGROUND_SYNCING();
          epee::wipeable_string key = epee::to_hex::wipeable_string(m_wallet->get_account().get_keys().m_spend_secret_key);
          res.key = std::string(key.data(), key.size());
      }
      else
      {
          er.message = "key_type " + req.key_type + " not found";
          return false;
      }

      return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_rescan_blockchain(const wallet_rpc::COMMAND_RPC_RESCAN_BLOCKCHAIN::request& req, wallet_rpc::COMMAND_RPC_RESCAN_BLOCKCHAIN::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    try
    {
      m_wallet->rescan_blockchain(req.hard);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_setup_background_sync(const wallet_rpc::COMMAND_RPC_SETUP_BACKGROUND_SYNC::request& req, wallet_rpc::COMMAND_RPC_SETUP_BACKGROUND_SYNC::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    try
    {
      PRE_VALIDATE_BACKGROUND_SYNC();
      const tools::wallet2::BackgroundSyncType background_sync_type = tools::wallet2::background_sync_type_from_str(req.background_sync_type);
      boost::optional<epee::wipeable_string> background_cache_password = boost::none;
      if (background_sync_type == tools::wallet2::BackgroundSyncCustomPassword)
        background_cache_password = boost::optional<epee::wipeable_string>(req.background_cache_password);
      m_wallet->setup_background_sync(background_sync_type, req.wallet_password, background_cache_password);
    }
    catch (...)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_start_background_sync(const wallet_rpc::COMMAND_RPC_START_BACKGROUND_SYNC::request& req, wallet_rpc::COMMAND_RPC_START_BACKGROUND_SYNC::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    try
    {
      PRE_VALIDATE_BACKGROUND_SYNC();
      m_wallet->start_background_sync();
    }
    catch (...)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_stop_background_sync(const wallet_rpc::COMMAND_RPC_STOP_BACKGROUND_SYNC::request& req, wallet_rpc::COMMAND_RPC_STOP_BACKGROUND_SYNC::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    try
    {
      PRE_VALIDATE_BACKGROUND_SYNC();
      crypto::secret_key spend_secret_key = crypto::null_skey;

      // Load the spend key from seed if seed is provided
      if (!req.seed.empty())
      {
        crypto::secret_key recovery_key;
        std::string language;

        if (!crypto::ElectrumWords::words_to_bytes(req.seed, recovery_key, language))
        {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = "Electrum-style word list failed verification";
          return false;
        }

        if (!req.seed_offset.empty())
          recovery_key = cryptonote::decrypt_key(recovery_key, req.seed_offset);

        // generate spend key
        cryptonote::account_base account;
        account.generate(recovery_key, true, false);
        spend_secret_key = account.get_keys().m_spend_secret_key;
      }

      m_wallet->stop_background_sync(req.wallet_password, spend_secret_key);
    }
    catch (...)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  //------------------------------------------------------------------------------------------------------------------------------
  // PQC registration (Problem 1): publish this wallet's Dilithium+Kyber public keys on-chain,
  // bound to its spend pubkey with a proof-of-possession owner_sig. After this TX confirms,
  // senders' get_pqc_keys lookups succeed and the hybrid (quantum-resistant-privacy) receive
  // path activates for payments to this wallet's v2 address.
  bool wallet_rpc_server::on_pbc_pqc_register(const wallet_rpc::COMMAND_RPC_PBC_PQC_REGISTER::request& req, wallet_rpc::COMMAND_RPC_PBC_PQC_REGISTER::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    // Idempotency: an optional key lets a caller safely retry without double-registering.
    std::string idem_prior;
    if (!idempotency_begin(req.idempotency_key, idem_prior))
    {
      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
      er.message = idem_prior.empty()
        ? "Duplicate request: a PQC registration with this idempotency_key is already in progress."
        : ("Duplicate request: this idempotency_key was already submitted (tx " + idem_prior + ").");
      return false;
    }
    idempotency_scope idem_guard(this, req.idempotency_key);

    try
    {
      // Refresh so create_transactions_2 sees currently-unlocked inputs (same rationale as deposit).
      uint64_t fetched_blocks = 0;
      bool received_money = false;
      try { m_wallet->refresh(false, 0, fetched_blocks, received_money); } catch (...) {}

      tools::wallet2::pending_tx ptx = m_wallet->create_pqc_register_tx(req.priority);
      m_wallet->commit_tx(ptx);
      m_wallet->store(); // persist immediately so the marker TX survives a wallet-rpc restart

      res.tx_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
      res.fee = ptx.fee;

      // Report the spend pubkey and pqc_hash actually committed, for the caller's records.
      crypto::hash pqc_hash{};
      std::string dil, kyb;
      if (m_wallet->get_pqc_public_keys(dil, kyb, pqc_hash))
        res.pqc_hash = epee::string_tools::pod_to_hex(pqc_hash);
      res.spend_pubkey = epee::string_tools::pod_to_hex(m_wallet->get_address().m_spend_public_key);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    idem_guard.commit(res.tx_hash);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  // PQC v2 address (Problem 1): return the wallet's post-quantum address string. Also queries the
  // daemon to tell the caller whether the corresponding PQC keys are already registered on-chain
  // (registered=false ⇒ a sender would currently fall back to classical until pbc_pqc_register lands).
  bool wallet_rpc_server::on_pbc_get_pqc_address(const wallet_rpc::COMMAND_RPC_PBC_GET_PQC_ADDRESS::request& req, wallet_rpc::COMMAND_RPC_PBC_GET_PQC_ADDRESS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();

    try
    {
      crypto::hash pqc_hash{};
      std::string address_v2;
      if (!m_wallet->get_pqc_v2_address(address_v2, pqc_hash))
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Failed to derive PQC keys / v2 address for this wallet.";
        return false;
      }

      res.address_v2   = address_v2;
      res.address      = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
      res.pqc_hash     = epee::string_tools::pod_to_hex(pqc_hash);
      const crypto::public_key spend_pk = m_wallet->get_address().m_spend_public_key;
      res.spend_pubkey = epee::string_tools::pod_to_hex(spend_pk);

      // Best-effort on-chain registration check (non-fatal if the daemon is unreachable).
      res.registered = false;
      try
      {
        cryptonote::COMMAND_RPC_GET_PQC_KEYS::request  q{};
        cryptonote::COMMAND_RPC_GET_PQC_KEYS::response  a{};
        q.spend_pubkey = res.spend_pubkey;
        if (m_wallet->invoke_http_json_rpc("/json_rpc", "get_pqc_keys", q, a, tools::wallet2::rpc_timeout)
            && a.found && a.pqc_hash == res.pqc_hash)
          res.registered = true;
      }
      catch (...) { /* leave registered=false */ }
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_make_term_deposit(const wallet_rpc::COMMAND_RPC_MAKE_TERM_DEPOSIT::request& req, wallet_rpc::COMMAND_RPC_MAKE_TERM_DEPOSIT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);

    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    // PBC idempotency: optional key → reject a duplicate deposit submission instead of building a 2nd tx.
    std::string idem_prior;
    if (!idempotency_begin(req.idempotency_key, idem_prior))
    {
      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
      er.message = idem_prior.empty()
        ? "Duplicate request: a deposit with this idempotency_key is already in progress."
        : ("Duplicate request: this idempotency_key was already submitted (tx " + idem_prior + ").");
      return false;
    }
    idempotency_scope idem_guard(this, req.idempotency_key);

    try
    {
      LOG_PRINT_L0("PBC_LOG on_make_term_deposit: ENTER amount=" << req.amount << " tier=" << req.tier);
      // PBC FIX: refresh wallet state before building the deposit TX.
      // create_transactions_2 filters available inputs via is_transfer_unlocked() which
      // uses the wallet's cached blockchain height. A stale height causes recently-unlocked
      // outputs to appear still locked → tx_not_possible despite sufficient balance.
      // A lightweight refresh here eliminates this race condition entirely.
      uint64_t fetched_blocks = 0;
      bool received_money = false;
      try { m_wallet->refresh(false, 0, fetched_blocks, received_money); } catch (...) {}

      tools::wallet2::pending_tx ptx = m_wallet->create_term_deposit_tx(req.amount, req.tier, req.priority);

      m_wallet->commit_tx(ptx);
      m_wallet->store(); // PBC FIX: persist immediately so TX survives wallet-rpc restart
      res.tx_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
      res.unlock_height = ptx.construction_data.unlock_time;
      res.fee = ptx.fee;
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    idem_guard.commit(res.tx_hash);

    // ── PBC / A-1 : enregistrement PQC APRES l'operation, jamais avant ────────────────────
    // Ce wallet est (ou devient) proprietaire d'un depot : sa clef post-quantique DEVRA etre
    // enregistree on-chain pour tout retrait d'interets ou paiement de vente (hard fork
    // spend-authority). On declenche l'inscription ICI, une fois l'operation demandee servie.
    //
    // POURQUOI PAS AVANT (bug corrige le 2026-08-11, prouve par les logs) : place en tete de
    // handler, l'inscription construisait sa TX AVANT le depot et consommait l'unique output
    // disponible du wallet ; le change repartait verrouille et le depot echouait ensuite en
    // not_enough_money. Vu en campagne : antifork T5, inscription soumise a la hauteur 10134,
    // depot refuse dans la foulee. Servir l'utilisateur d'abord est la seule regle sure.
    // Non fatal : un echec ici ne doit jamais faire echouer l'operation deja reussie.
    try { pbc_maybe_auto_register_pqc(); }
    catch (const std::exception &ex) { LOG_PRINT_L1("PBC AUTO-PQC (non-fatal): " << ex.what()); }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_claim_deposit(const wallet_rpc::COMMAND_RPC_CLAIM_DEPOSIT::request& req, wallet_rpc::COMMAND_RPC_CLAIM_DEPOSIT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    try
    {
      crypto::hash deposit_id;
      if (!epee::string_tools::hex_to_pod(req.deposit_id, deposit_id))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
        er.message = "Invalid deposit_id format";
        return false;
      }

      tools::wallet2::pending_tx ptx = m_wallet->create_claim_tx(deposit_id, req.priority);
      m_wallet->commit_tx(ptx);
      m_wallet->store(); // PBC FIX: persist immediately so TX survives wallet-rpc restart
      res.tx_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
      res.fee = ptx.fee;
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }

//----------------------------------------------------------------------------------------------------
// PF: TERM_WITHDRAW payout RPC
bool wallet_rpc_server::on_term_withdraw_deposit(const wallet_rpc::COMMAND_RPC_TERM_WITHDRAW_DEPOSIT::request& req, wallet_rpc::COMMAND_RPC_TERM_WITHDRAW_DEPOSIT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet)
  {
    er.code = WALLET_RPC_ERROR_CODE_NOT_OPEN;
    er.message = "No wallet file";
    return false;
  }

  crypto::hash deposit_id;
  if (!epee::string_tools::hex_to_pod(req.deposit_id, deposit_id))
  {
    er.code = WALLET_RPC_ERROR_CODE_WRONG_PARAM;
    er.message = "Invalid deposit_id";
    return false;
  }

  const uint32_t priority = req.priority;

  try
  {
    LOG_PRINT_L0("PBC_LOG on_term_withdraw_deposit: ENTER deposit_id=" << req.deposit_id << " priority=" << priority);
    wallet2::pending_tx ptx = m_wallet->create_term_withdraw_tx(deposit_id, priority);
    m_wallet->commit_tx(ptx);
    LOG_PRINT_L0("PBC_LOG on_term_withdraw_deposit: commit_tx OK txid=" << epee::string_tools::pod_to_hex(get_transaction_hash(ptx.tx)));
    // PBC FIX: persist immediately after commit so m_unconfirmed_txs (with m_dests
    // populated) survives a wallet-rpc restart before block confirmation. Without
    // this, a restart between send and confirmation leaves m_tx.extra empty after
    // the confirmed_transfer_details is promoted, breaking determine_pbc_subtype()
    // and causing "Interest Withdrawn" to show 0 until rescan_blockchain.
    m_wallet->store();
    res.tx_hash = epee::string_tools::pod_to_hex(get_transaction_hash(ptx.tx));
    res.fee = ptx.fee;

    // Extract payout_amount from tx_extra for UI convenience
    res.payout_amount = 0;
    std::vector<cryptonote::tx_extra_field> extra_fields;
    if (cryptonote::parse_tx_extra(ptx.tx.extra, extra_fields))
    {
      cryptonote::tx_extra_pbc_withdraw_payout pay{};
      if (cryptonote::find_tx_extra_field_by_type(extra_fields, pay))
        res.payout_amount = pay.payout_amount;
    }
  }
  catch (const std::exception& e)
  {
    er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
    er.message = std::string("term_withdraw failed: ") + e.what();
    return false;
  }

  return true;
}
  //------------------------------------------------------------------------------------------------------------------------------
  static const char* deposit_status_to_str(tools::wallet2::deposit_status s)
  {
    switch (s) {
      case tools::wallet2::DEPOSIT_PENDING:  return "pending";
      case tools::wallet2::DEPOSIT_LOCKED:   return "locked";
      case tools::wallet2::DEPOSIT_UNLOCKED: return "unlocked";
      case tools::wallet2::DEPOSIT_SPENT:    return "spent";
      case tools::wallet2::DEPOSIT_ORPHANED: return "orphaned";
      default:                               return "unknown";
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  static std::string rpc_eta_human(uint64_t seconds)
  {
    if (seconds == 0) return "-";
    uint64_t d = seconds / 86400;
    uint64_t h = (seconds % 86400) / 3600;
    uint64_t m = (seconds % 3600) / 60;
    std::ostringstream oss;
    if (d > 0) oss << d << "d ";
    oss << std::setfill('0') << std::setw(2) << h << "h"
        << std::setfill('0') << std::setw(2) << m << "m";
    return oss.str();
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_deposits(const wallet_rpc::COMMAND_RPC_GET_DEPOSITS::request& req, wallet_rpc::COMMAND_RPC_GET_DEPOSITS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      auto deposits = m_wallet->get_term_deposits();

      // Apply status filter
      if (req.filter == "locked")
        deposits.erase(std::remove_if(deposits.begin(), deposits.end(), [](const auto &d) { return d.status != tools::wallet2::DEPOSIT_LOCKED; }), deposits.end());
      else if (req.filter == "unlocked")
        deposits.erase(std::remove_if(deposits.begin(), deposits.end(), [](const auto &d) { return d.status != tools::wallet2::DEPOSIT_UNLOCKED; }), deposits.end());
      else if (req.filter == "pending")
        deposits.erase(std::remove_if(deposits.begin(), deposits.end(), [](const auto &d) { return d.status != tools::wallet2::DEPOSIT_PENDING; }), deposits.end());

      // Apply height filters
      if (req.min_height > 0 || req.max_height < UINT64_MAX)
      {
        deposits.erase(std::remove_if(deposits.begin(), deposits.end(), [&req](const auto &d) {
          if (d.height_created == 0) return false; // keep pending
          return d.height_created < req.min_height || d.height_created > req.max_height;
        }), deposits.end());
      }

      // Exclude spent unless include_spent
      if (!req.include_spent)
      {
        deposits.erase(std::remove_if(deposits.begin(), deposits.end(), [](const auto &d) {
          return d.status == tools::wallet2::DEPOSIT_SPENT;
        }), deposits.end());
      }

      for (const auto &d : deposits)
      {
        wallet_rpc::COMMAND_RPC_GET_DEPOSITS::deposit_entry e;
        e.txid             = epee::string_tools::pod_to_hex(d.txid);
        e.vout_index       = d.vout_index;
        e.amount           = d.amount;
        e.tier             = d.tier;
        e.height_created   = d.height_created;
        e.timestamp_created= d.timestamp_created;
        e.unlock_height    = d.unlock_height;
        e.lock_blocks      = d.lock_blocks;
        e.fee_paid         = d.fee_paid;
        e.status           = deposit_status_to_str(d.status);
        e.confirmations    = d.confirmations;
        e.in_pool          = d.in_pool;
        e.blocks_remaining = d.blocks_remaining;
        e.eta_seconds      = d.eta_seconds;
        e.eta_human        = rpc_eta_human(d.eta_seconds);
        res.deposits.push_back(e);
      }
      res.current_height = m_wallet->get_blockchain_current_height();
      res.block_time = 60;
    }
    catch (...)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_deposit(const wallet_rpc::COMMAND_RPC_GET_DEPOSIT::request& req, wallet_rpc::COMMAND_RPC_GET_DEPOSIT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      crypto::hash txid;
      if (!epee::string_tools::hex_to_pod(req.txid, txid))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
        er.message = "Invalid txid format";
        return false;
      }

      tools::wallet2::term_deposit_record rec;
      res.found = m_wallet->get_term_deposit_by_txid(txid, rec);

      if (res.found)
      {
        res.txid             = req.txid;
        res.vout_index       = rec.vout_index;
        res.amount           = rec.amount;
        res.tier             = rec.tier;
        res.height_created   = rec.height_created;
        res.timestamp_created= rec.timestamp_created;
        res.unlock_height    = rec.unlock_height;
        res.lock_blocks      = rec.lock_blocks;
        res.fee_paid         = rec.fee_paid;
        res.status           = deposit_status_to_str(rec.status);
        res.confirmations    = rec.confirmations;
        res.in_pool          = rec.in_pool;
        res.blocks_remaining = rec.blocks_remaining;
        res.eta_seconds      = rec.eta_seconds;
        res.eta_human        = rpc_eta_human(rec.eta_seconds);
      }
    }
    catch (...)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_wallet_deposit_stats(const wallet_rpc::COMMAND_RPC_WALLET_DEPOSIT_STATS::request& req, wallet_rpc::COMMAND_RPC_WALLET_DEPOSIT_STATS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      tools::wallet2::deposit_stats_result stats;
      if (!m_wallet->get_deposit_stats(stats))
      {
        er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
        er.message = "Failed to fetch deposit stats from daemon";
        return false;
      }
      res.height                      = stats.height;
      res.deposit_pool_balance        = stats.deposit_pool_balance;
      res.deposit_sum_weights         = stats.deposit_sum_weights;
      res.total_locked_in_deposits    = stats.total_locked_in_deposits;
      res.block_reward                = stats.block_reward;
      res.deposit_allocation_per_block= stats.deposit_allocation_per_block;
      res.distribution_period         = stats.distribution_period;
    }
    catch (...)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_wallet_deposit_apy(const wallet_rpc::COMMAND_RPC_WALLET_DEPOSIT_APY::request& req, wallet_rpc::COMMAND_RPC_WALLET_DEPOSIT_APY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      uint64_t sim_amount = req.amount > 0 ? req.amount : 100000000000000ULL; // default 100 PBC

      tools::wallet2::deposit_apy_result apy;
      if (!m_wallet->get_deposit_apy(sim_amount, apy))
      {
        er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
        er.message = "Failed to compute deposit APY";
        return false;
      }

      res.sim_amount          = apy.sim_amount;
      res.current_sum_weights = apy.current_sum_weights;
      res.alloc_per_block     = apy.alloc_per_block;
      res.block_reward        = apy.block_reward;
      res.height              = apy.height;
      res.warning = "Estimate is a snapshot based on current pool weight and block reward; "
                    "real yield depends on future deposits and emissions. NOT a guarantee. NOT compound interest.";

      for (const auto &t : apy.tiers)
      {
        wallet_rpc::COMMAND_RPC_WALLET_DEPOSIT_APY::tier_entry e;
        e.tier            = t.tier;
        e.tier_blocks     = t.tier_blocks;
        e.tier_multiplier = t.tier_multiplier;
        e.w_user          = t.w_user;
        e.yield_atomic    = t.yield_atomic;
        e.total_return    = sim_amount + t.yield_atomic;
        e.roi_percent     = (sim_amount > 0)
                            ? (static_cast<double>(t.yield_atomic) / static_cast<double>(sim_amount)) * 100.0
                            : 0.0;
        e.apy_simple      = t.apy_simple;
        res.tiers.push_back(e);
      }
    }
    catch (...)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_deposits_accrued(const wallet_rpc::COMMAND_RPC_GET_DEPOSITS_ACCRUED::request& req, wallet_rpc::COMMAND_RPC_GET_DEPOSITS_ACCRUED::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      // ── Step 1: Get local deposit list ──
      auto deposits = m_wallet->get_term_deposits();

      // Filter by status
      if (req.filter == "locked")
        deposits.erase(std::remove_if(deposits.begin(), deposits.end(), [](const auto &d) { return d.status != tools::wallet2::DEPOSIT_LOCKED; }), deposits.end());
      else if (req.filter == "unlocked")
        deposits.erase(std::remove_if(deposits.begin(), deposits.end(), [](const auto &d) { return d.status != tools::wallet2::DEPOSIT_UNLOCKED; }), deposits.end());

      // Exclude spent unless asked
      if (!req.include_spent)
        deposits.erase(std::remove_if(deposits.begin(), deposits.end(), [](const auto &d) {
          return d.status == tools::wallet2::DEPOSIT_SPENT || d.status == tools::wallet2::DEPOSIT_ORPHANED;
        }), deposits.end());

      if (deposits.empty())
      {
        res.current_height = m_wallet->get_blockchain_current_height();
        return true;
      }

      // ── Step 2: Fetch global indices from daemon (single call) ──
      cryptonote::COMMAND_RPC_GET_PBC_POOL_BALANCES::request  pool_req{};
      cryptonote::COMMAND_RPC_GET_PBC_POOL_BALANCES::response pool_res{};
      bool r = m_wallet->invoke_http_json_rpc("/json_rpc", "get_pbc_pool_balances",
                                               pool_req, pool_res, tools::wallet2::rpc_timeout);
      if (!r || pool_res.status != "OK")
      {
        er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
        er.message = "Failed to fetch pool balances from daemon";
        return false;
      }

      const uint64_t current_height      = m_wallet->get_blockchain_current_height();
      // BUG1-FIX: indices are now decimal strings from daemon RPC
      const std::string& global_dep_idx  = pool_res.global_deposit_index;
      const std::string& global_fee_idx  = pool_res.global_fee_index;

      res.current_height        = current_height;
      res.global_deposit_index  = global_dep_idx;
      res.global_fee_index      = global_fee_idx;

      // ── Step 3: Fetch deposit_sum_weights from daemon ──
      cryptonote::COMMAND_RPC_GET_DEPOSIT_STATS::request  stats_req{};
      cryptonote::COMMAND_RPC_GET_DEPOSIT_STATS::response stats_res{};
      r = m_wallet->invoke_http_json_rpc("/json_rpc", "get_deposit_stats",
                                          stats_req, stats_res, tools::wallet2::rpc_timeout);
      if (r && stats_res.status == "OK")
        res.deposit_sum_weights = stats_res.deposit_sum_weights;

      constexpr uint64_t BLOCKS_PER_YEAR = 525600; // 365 * 24 * 60

      // ── Summary accumulators ──
      uint64_t sum_principal    = 0;
      uint64_t sum_accrued      = 0;
      uint64_t sum_claimable    = 0;
      uint64_t sum_fees         = 0;
      uint64_t count            = 0;
      uint64_t nearest_unlock   = UINT64_MAX;
      double   weighted_apy_num = 0.0;  // Σ(amount × apy)
      double   weighted_apy_den = 0.0;  // Σ(amount)

      // ── Step 4: For each deposit, fetch LMDB data and compute ──
      for (const auto &d : deposits)
      {
        wallet_rpc::COMMAND_RPC_GET_DEPOSITS_ACCRUED::accrued_entry e{};

        // Identity fields
        e.txid           = epee::string_tools::pod_to_hex(d.txid);
        e.amount         = d.amount;
        e.tier           = d.tier;
        e.status         = deposit_status_to_str(d.status);
        e.height_created = d.height_created;
        e.unlock_height  = d.unlock_height;

        // Default: daemon not queried yet
        e.weight              = 0;
        e.deposit_entry_index = "0";  // BUG1-FIX: string
        e.fee_entry_index     = "0";  // BUG1-FIX: string
        e.accrued_deposit     = 0;
        e.accrued_fee         = 0;
        e.accrued_total       = 0;
        e.accumulated_reward  = 0;
        e.total_withdrawn     = 0;
        e.last_claim_height   = 0;
        e.claimable           = 0;
        e.claimable_pbc       = 0.0;
        e.is_expired          = (d.unlock_height <= current_height);
        e.accrued_total_pbc   = 0.0;
        e.apy_realized        = 0.0;
        e.blocks_elapsed      = 0;
        e.daemon_found        = false;

        // Accumulate principal & fees regardless of daemon availability
        sum_principal += d.amount;
        sum_fees      += d.fee_paid;
        ++count;

        // Track nearest unlock for locked deposits
        if (d.status == tools::wallet2::DEPOSIT_LOCKED && d.unlock_height > current_height)
        {
          if (d.unlock_height < nearest_unlock)
            nearest_unlock = d.unlock_height;
        }

        // Query daemon for this deposit's LMDB record
        cryptonote::COMMAND_RPC_GET_PBC_DEPOSIT_INFO::request  dep_req{};
        cryptonote::COMMAND_RPC_GET_PBC_DEPOSIT_INFO::response dep_res{};
        dep_req.deposit_id = e.txid;

        r = m_wallet->invoke_http_json_rpc("/json_rpc", "get_pbc_deposit_info",
                                            dep_req, dep_res, tools::wallet2::rpc_timeout);
        if (!r || dep_res.status != "OK" || !dep_res.found)
        {
          // Deposit not in LMDB (pending, or not yet mined past boundary)
          e.daemon_found = false;
          res.deposits.push_back(e);
          continue;
        }

        e.daemon_found        = true;
        e.weight              = dep_res.weight;
        e.deposit_entry_index = dep_res.deposit_entry_index;
        e.fee_entry_index     = dep_res.fee_entry_index;
        e.accumulated_reward  = dep_res.accumulated_reward;
        e.total_withdrawn     = dep_res.total_withdrawn;
        e.last_claim_height   = dep_res.last_claim_height;

        // ── Compute accrued rewards (uint128 for overflow safety) ──
        // TD-7: Use daemon-computed claimable (handles freeze for expired deposits)
        e.accrued_deposit = dep_res.claimable_deposit;
        e.accrued_fee     = dep_res.claimable_fee;

        e.accrued_total     = e.accrued_deposit + e.accrued_fee;
        e.accrued_total_pbc = static_cast<double>(e.accrued_total) / static_cast<double>(COIN);

        // ── Claimable = what daemon would pay on claim (TD-7) ──
        // accrued_total is now computed with effective (frozen) indices,
        // so it represents exactly what's claimable right now.
        e.claimable     = e.accrued_total;
        e.claimable_pbc = e.accrued_total_pbc;

        // ── APY realized (display-only, uses double) ──
        if (d.height_created > 0 && current_height > d.height_created)
        {
          e.blocks_elapsed = current_height - d.height_created;
          if (d.amount > 0 && e.blocks_elapsed > 0)
          {
            // Lifetime earned = current accrual + pending claim + already withdrawn
            uint64_t total_earned = e.accrued_total + e.accumulated_reward + e.total_withdrawn;
            if (total_earned > 0) {
            double yield_ratio = static_cast<double>(total_earned) / static_cast<double>(d.amount);
            e.apy_realized = yield_ratio * static_cast<double>(BLOCKS_PER_YEAR) / static_cast<double>(e.blocks_elapsed);

            // Accumulate for weighted-average APY
            double amt_d = static_cast<double>(d.amount);
            weighted_apy_num += amt_d * e.apy_realized;
            weighted_apy_den += amt_d;
            }
          }
        }

        // Accumulate accrued
        sum_accrued   += e.accrued_total;
        sum_claimable += e.claimable;

        res.deposits.push_back(e);
      }

      // ── Step 5: Compute account statement summary ──
      res.total_deposits_count       = count;
      res.total_principal_locked     = sum_principal;
      res.total_principal_locked_pbc = static_cast<double>(sum_principal) / static_cast<double>(COIN);
      res.total_accrued              = sum_accrued;
      res.total_accrued_pbc          = static_cast<double>(sum_accrued) / static_cast<double>(COIN);
      res.total_claimable            = sum_claimable;
      res.total_claimable_pbc        = static_cast<double>(sum_claimable) / static_cast<double>(COIN);
      res.total_portfolio_value      = sum_principal + sum_accrued;
      res.total_portfolio_value_pbc  = static_cast<double>(sum_principal + sum_accrued) / static_cast<double>(COIN);
      res.total_fees_paid            = sum_fees;
      res.total_fees_paid_pbc        = static_cast<double>(sum_fees) / static_cast<double>(COIN);
      res.net_gain                   = static_cast<int64_t>(sum_accrued) - static_cast<int64_t>(sum_fees);
      res.net_gain_pbc               = static_cast<double>(res.net_gain) / static_cast<double>(COIN);
      res.overall_apy                = (weighted_apy_den > 0.0) ? (weighted_apy_num / weighted_apy_den) : 0.0;

      // Next unlock
      if (nearest_unlock != UINT64_MAX && nearest_unlock > current_height)
      {
        res.next_unlock_height      = nearest_unlock;
        res.next_unlock_blocks      = nearest_unlock - current_height;
        res.next_unlock_eta_seconds = res.next_unlock_blocks * 60;
        res.next_unlock_eta_human   = rpc_eta_human(res.next_unlock_eta_seconds);
      }
      else
      {
        res.next_unlock_height      = 0;
        res.next_unlock_blocks      = 0;
        res.next_unlock_eta_seconds = 0;
        res.next_unlock_eta_human   = "-";
      }
    }
    catch (...)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_sign(const wallet_rpc::COMMAND_RPC_SIGN::request& req, wallet_rpc::COMMAND_RPC_SIGN::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    tools::wallet2::message_signature_type_t signature_type = tools::wallet2::sign_with_spend_key;
    if (req.signature_type == "spend" || req.signature_type == "")
      signature_type = tools::wallet2::sign_with_spend_key;
    else if (req.signature_type == "view")
      signature_type = tools::wallet2::sign_with_view_key;
    else
    {
      er.code = WALLET_RPC_ERROR_CODE_INVALID_SIGNATURE_TYPE;
      er.message = "Invalid signature type requested";
      return false;
    }
    res.signature = m_wallet->sign(req.data, signature_type, {req.account_index, req.address_index});
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_verify(const wallet_rpc::COMMAND_RPC_VERIFY::request& req, wallet_rpc::COMMAND_RPC_VERIFY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    cryptonote::address_parse_info info;
    er.message = "";
    if(!get_account_address_from_str_or_url(info, m_wallet->nettype(), req.address,
      [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
        if (!dnssec_valid)
        {
          er.message = std::string("Invalid DNSSEC for ") + url;
          return {};
        }
        if (addresses.empty())
        {
          er.message = std::string("No PBC Chain address found at ") + url;
          return {};
        }
        return addresses[0];
      }))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      return false;
    }

    const auto result = m_wallet->verify(req.data, info.address, req.signature);
    res.good = result.valid;
    res.version = result.version;
    res.old = result.old;
    switch (result.type)
    {
      case tools::wallet2::sign_with_spend_key: res.signature_type = "spend"; break;
      case tools::wallet2::sign_with_view_key: res.signature_type = "view"; break;
      default: res.signature_type = "invalid"; break;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_stop_wallet(const wallet_rpc::COMMAND_RPC_STOP_WALLET::request& req, wallet_rpc::COMMAND_RPC_STOP_WALLET::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    try
    {
      m_wallet->store();
      m_stop.store(true, std::memory_order_relaxed);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_set_tx_notes(const wallet_rpc::COMMAND_RPC_SET_TX_NOTES::request& req, wallet_rpc::COMMAND_RPC_SET_TX_NOTES::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    if (req.txids.size() != req.notes.size())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Different amount of txids and notes";
      return false;
    }

    std::list<crypto::hash> txids;
    std::list<std::string>::const_iterator i = req.txids.begin();
    while (i != req.txids.end())
    {
      cryptonote::blobdata txid_blob;
      if(!epee::string_tools::parse_hexstr_to_binbuff(*i++, txid_blob) || txid_blob.size() != sizeof(crypto::hash))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
        er.message = "TX ID has invalid format";
        return false;
      }

      crypto::hash txid = *reinterpret_cast<const crypto::hash*>(txid_blob.data());
      txids.push_back(txid);
    }

    std::list<crypto::hash>::const_iterator il = txids.begin();
    std::list<std::string>::const_iterator in = req.notes.begin();
    while (il != txids.end())
    {
      m_wallet->set_tx_note(*il++, *in++);
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_tx_notes(const wallet_rpc::COMMAND_RPC_GET_TX_NOTES::request& req, wallet_rpc::COMMAND_RPC_GET_TX_NOTES::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    res.notes.clear();
    if (!m_wallet) return not_open(er);

    std::list<crypto::hash> txids;
    std::list<std::string>::const_iterator i = req.txids.begin();
    while (i != req.txids.end())
    {
      cryptonote::blobdata txid_blob;
      if(!epee::string_tools::parse_hexstr_to_binbuff(*i++, txid_blob) || txid_blob.size() != sizeof(crypto::hash))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
        er.message = "TX ID has invalid format";
        return false;
      }

      crypto::hash txid = *reinterpret_cast<const crypto::hash*>(txid_blob.data());
      txids.push_back(txid);
    }

    std::list<crypto::hash>::const_iterator il = txids.begin();
    while (il != txids.end())
    {
      res.notes.push_back(m_wallet->get_tx_note(*il++));
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_set_attribute(const wallet_rpc::COMMAND_RPC_SET_ATTRIBUTE::request& req, wallet_rpc::COMMAND_RPC_SET_ATTRIBUTE::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    m_wallet->set_attribute(req.key, req.value);

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_attribute(const wallet_rpc::COMMAND_RPC_GET_ATTRIBUTE::request& req, wallet_rpc::COMMAND_RPC_GET_ATTRIBUTE::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    if (!m_wallet->get_attribute(req.key, res.value))
    {
      er.code = WALLET_RPC_ERROR_CODE_ATTRIBUTE_NOT_FOUND;
      er.message = "Attribute not found.";
      return false;
    }
    return true;
  }
  bool wallet_rpc_server::on_get_tx_key(const wallet_rpc::COMMAND_RPC_GET_TX_KEY::request& req, wallet_rpc::COMMAND_RPC_GET_TX_KEY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();

    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(req.txid, txid))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
      er.message = "TX ID has invalid format";
      return false;
    }

    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    if (!m_wallet->get_tx_key(txid, tx_key, additional_tx_keys))
    {
      er.code = WALLET_RPC_ERROR_CODE_NO_TXKEY;
      er.message = "No tx secret key is stored for this tx";
      return false;
    }

    epee::wipeable_string s;
    s += epee::to_hex::wipeable_string(tx_key);
    for (size_t i = 0; i < additional_tx_keys.size(); ++i)
      s += epee::to_hex::wipeable_string(additional_tx_keys[i]);
    res.tx_key = std::string(s.data(), s.size());
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_check_tx_key(const wallet_rpc::COMMAND_RPC_CHECK_TX_KEY::request& req, wallet_rpc::COMMAND_RPC_CHECK_TX_KEY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);

    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(req.txid, txid))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
      er.message = "TX ID has invalid format";
      return false;
    }

    epee::wipeable_string tx_key_str = req.tx_key;
    if (tx_key_str.size() < 64 || tx_key_str.size() % 64)
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_KEY;
      er.message = "Tx key has invalid format";
      return false;
    }
    const char *data = tx_key_str.data();
    crypto::secret_key tx_key;
    if (!epee::wipeable_string(data, 64).hex_to_pod(unwrap(unwrap(tx_key))))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_KEY;
      er.message = "Tx key has invalid format";
      return false;
    }
    size_t offset = 64;
    std::vector<crypto::secret_key> additional_tx_keys;
    while (offset < tx_key_str.size())
    {
      additional_tx_keys.resize(additional_tx_keys.size() + 1);
      if (!epee::wipeable_string(data + offset, 64).hex_to_pod(unwrap(unwrap(additional_tx_keys.back()))))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_KEY;
        er.message = "Tx key has invalid format";
        return false;
      }
      offset += 64;
    }

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_wallet->nettype(), req.address))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      er.message = "Invalid address";
      return false;
    }

    try
    {
      m_wallet->check_tx_key(txid, tx_key, additional_tx_keys, info.address, res.received, res.in_pool, res.confirmations);
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_tx_proof(const wallet_rpc::COMMAND_RPC_GET_TX_PROOF::request& req, wallet_rpc::COMMAND_RPC_GET_TX_PROOF::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();

    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(req.txid, txid))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
      er.message = "TX ID has invalid format";
      return false;
    }

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_wallet->nettype(), req.address))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      er.message = "Invalid address";
      return false;
    }

    try
    {
      res.signature = m_wallet->get_tx_proof(txid, info.address, info.is_subaddress, req.message);
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_check_tx_proof(const wallet_rpc::COMMAND_RPC_CHECK_TX_PROOF::request& req, wallet_rpc::COMMAND_RPC_CHECK_TX_PROOF::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);

    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(req.txid, txid))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
      er.message = "TX ID has invalid format";
      return false;
    }

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_wallet->nettype(), req.address))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      er.message = "Invalid address";
      return false;
    }

    try
    {
      res.good = m_wallet->check_tx_proof(txid, info.address, info.is_subaddress, req.message, req.signature, res.received, res.in_pool, res.confirmations);
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_spend_proof(const wallet_rpc::COMMAND_RPC_GET_SPEND_PROOF::request& req, wallet_rpc::COMMAND_RPC_GET_SPEND_PROOF::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);

    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(req.txid, txid))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
      er.message = "TX ID has invalid format";
      return false;
    }

    try
    {
      res.signature = m_wallet->get_spend_proof(txid, req.message);
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_check_spend_proof(const wallet_rpc::COMMAND_RPC_CHECK_SPEND_PROOF::request& req, wallet_rpc::COMMAND_RPC_CHECK_SPEND_PROOF::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);

    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(req.txid, txid))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
      er.message = "TX ID has invalid format";
      return false;
    }

    try
    {
      res.good = m_wallet->check_spend_proof(txid, req.message, req.signature);
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_reserve_proof(const wallet_rpc::COMMAND_RPC_GET_RESERVE_PROOF::request& req, wallet_rpc::COMMAND_RPC_GET_RESERVE_PROOF::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();

    boost::optional<std::pair<uint32_t, uint64_t>> account_minreserve;
    if (!req.all)
    {
      if (req.account_index >= m_wallet->get_num_subaddress_accounts())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Account index is out of bound";
        return false;
      }
      account_minreserve = std::make_pair(req.account_index, req.amount);
    }

    try
    {
      res.signature = m_wallet->get_reserve_proof(account_minreserve, req.message);
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_check_reserve_proof(const wallet_rpc::COMMAND_RPC_CHECK_RESERVE_PROOF::request& req, wallet_rpc::COMMAND_RPC_CHECK_RESERVE_PROOF::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);

    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, m_wallet->nettype(), req.address))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      er.message = "Invalid address";
      return false;
    }
    if (info.is_subaddress)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Address must not be a subaddress";
      return false;
    }

    try
    {
      res.good = m_wallet->check_reserve_proof(info.address, req.message, req.signature, res.total, res.spent);
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_transfers(const wallet_rpc::COMMAND_RPC_GET_TRANSFERS::request& req, wallet_rpc::COMMAND_RPC_GET_TRANSFERS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    uint64_t min_height = 0, max_height = CRYPTONOTE_MAX_BLOCK_NUMBER;
    if (req.filter_by_height)
    {
      min_height = req.min_height;
      max_height = req.max_height <= max_height ? req.max_height : max_height;
    }

    boost::optional<uint32_t> account_index = req.account_index;
    std::set<uint32_t> subaddr_indices = req.subaddr_indices;
    if (req.all_accounts)
    {
      account_index = boost::none;
      subaddr_indices.clear();
    }

    if (req.in)
    {
      std::list<std::pair<crypto::hash, tools::wallet2::payment_details>> payments;
      m_wallet->get_payments(payments, min_height, max_height, account_index, subaddr_indices);
      for (std::list<std::pair<crypto::hash, tools::wallet2::payment_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
        res.in.push_back(wallet_rpc::transfer_entry());
        fill_transfer_entry(res.in.back(), i->second.m_tx_hash, i->first, i->second);
      }
    }

    if (req.out)
    {
      std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>> payments;
      m_wallet->get_payments_out(payments, min_height, max_height, account_index, subaddr_indices);
      for (std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
        res.out.push_back(wallet_rpc::transfer_entry());
        fill_transfer_entry(res.out.back(), i->first, i->second);
      }
    }

    if (req.pending || req.failed) {
      std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>> upayments;
      m_wallet->get_unconfirmed_payments_out(upayments, account_index, subaddr_indices);
      for (std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>>::const_iterator i = upayments.begin(); i != upayments.end(); ++i) {
        const tools::wallet2::unconfirmed_transfer_details &pd = i->second;
        bool is_failed = pd.m_state == tools::wallet2::unconfirmed_transfer_details::failed;
        if (!((req.failed && is_failed) || (!is_failed && req.pending)))
          continue;
        std::list<wallet_rpc::transfer_entry> &entries = is_failed ? res.failed : res.pending;
        entries.push_back(wallet_rpc::transfer_entry());
        fill_transfer_entry(entries.back(), i->first, i->second);
      }
    }

    if (req.pool)
    {
      std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> process_txs;
      m_wallet->update_pool_state(process_txs);
      if (!process_txs.empty())
        m_wallet->process_pool_state(process_txs);

      std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>> payments;
      m_wallet->get_unconfirmed_payments(payments, account_index, subaddr_indices);
      for (std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
        res.pool.push_back(wallet_rpc::transfer_entry());
        fill_transfer_entry(res.pool.back(), i->first, i->second);
      }
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------

  bool wallet_rpc_server::on_get_pbc_statement(const wallet_rpc::COMMAND_RPC_GET_PBC_STATEMENT::request& req, wallet_rpc::COMMAND_RPC_GET_PBC_STATEMENT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    // Aggregate wallet transfers by UTC day (best-effort)
    wallet_rpc::COMMAND_RPC_GET_TRANSFERS::request treq = AUTO_VAL_INIT(treq);
    wallet_rpc::COMMAND_RPC_GET_TRANSFERS::response tres = AUTO_VAL_INIT(tres);

    treq.in = true;
    treq.out = true;
    treq.pool = true;
    treq.pending = false;
    treq.failed = false;
    treq.filter_by_height = false;
    treq.all_accounts = true;

    if (!on_get_transfers(treq, tres, er, ctx))
      return false;

    const uint64_t now = (uint64_t)time(nullptr);
    const uint64_t days = req.days ? req.days : 30;
    const uint64_t cutoff = now > days * 86400ULL ? (now - days * 86400ULL) : 0;

    auto day_utc = [](uint64_t ts) -> std::string {
      time_t t = (time_t)ts;
      struct tm tm_utc;
      #ifdef _WIN32
      gmtime_s(&tm_utc, &t);
      #else
      gmtime_r(&t, &tm_utc);
      #endif
      char buf[16];
      strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_utc);
      return std::string(buf);
    };

    struct agg_t { uint64_t in=0, out=0, fee=0, mined=0; };
    std::map<std::string, agg_t> agg;

    auto add_in = [&](const wallet_rpc::transfer_entry &e, bool is_pool){
      uint64_t ts = e.timestamp ? e.timestamp : now;
      if (ts < cutoff) return;
      auto &a = agg[day_utc(ts)];
      if (is_pool) a.mined += e.amount; else a.in += e.amount;
    };
    auto add_out = [&](const wallet_rpc::transfer_entry &e){
      uint64_t ts = e.timestamp ? e.timestamp : now;
      if (ts < cutoff) return;
      auto &a = agg[day_utc(ts)];
      a.out += e.amount;
      a.fee += e.fee;
    };

    for (const auto &e : tres.in) add_in(e, false);
    for (const auto &e : tres.pool) add_in(e, true);
    for (const auto &e : tres.out) add_out(e);

    res.days.clear();
    res.days.reserve(agg.size());
    for (const auto &kv : agg)
    {
      wallet_rpc::COMMAND_RPC_GET_PBC_STATEMENT::day_entry de = AUTO_VAL_INIT(de);
      de.day = kv.first;
      de.credits = kv.second.in + kv.second.mined;
      de.debits = kv.second.out;
      de.fees = kv.second.fee;
      de.mined = kv.second.mined;
      de.net = (int64_t)de.credits - (int64_t)de.debits - (int64_t)de.fees;
      res.days.push_back(de);
    }

    // Claimable stats — TODO: implement pbc_get_deposit_stats in wallet2
    res.claimable = 0;
    res.claimed = 0;

    return true;
  }

  bool wallet_rpc_server::on_get_transfer_by_txid(const wallet_rpc::COMMAND_RPC_GET_TRANSFER_BY_TXID::request& req, wallet_rpc::COMMAND_RPC_GET_TRANSFER_BY_TXID::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    crypto::hash txid;
    cryptonote::blobdata txid_blob;
    if(!epee::string_tools::parse_hexstr_to_binbuff(req.txid, txid_blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
      er.message = "Transaction ID has invalid format";
      return false;
    }

    if(sizeof(txid) == txid_blob.size())
    {
      txid = *reinterpret_cast<const crypto::hash*>(txid_blob.data());
    }
    else
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
      er.message = "Transaction ID has invalid size: " + req.txid;
      return false;
    }

    if (req.account_index >= m_wallet->get_num_subaddress_accounts())
    {
      er.code = WALLET_RPC_ERROR_CODE_ACCOUNT_INDEX_OUT_OF_BOUNDS;
      er.message = "Account index is out of bound";
      return false;
    }

    std::list<std::pair<crypto::hash, tools::wallet2::payment_details>> payments;
    m_wallet->get_payments(payments, 0, (uint64_t)-1, req.account_index);
    for (std::list<std::pair<crypto::hash, tools::wallet2::payment_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
      if (i->second.m_tx_hash == txid)
      {
        res.transfers.resize(res.transfers.size() + 1);
        fill_transfer_entry(res.transfers.back(), i->second.m_tx_hash, i->first, i->second);
      }
    }

    std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>> payments_out;
    m_wallet->get_payments_out(payments_out, 0, (uint64_t)-1, req.account_index);
    for (std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>>::const_iterator i = payments_out.begin(); i != payments_out.end(); ++i) {
      if (i->first == txid)
      {
        res.transfers.resize(res.transfers.size() + 1);
        fill_transfer_entry(res.transfers.back(), i->first, i->second);
      }
    }

    std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>> upayments;
    m_wallet->get_unconfirmed_payments_out(upayments, req.account_index);
    for (std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>>::const_iterator i = upayments.begin(); i != upayments.end(); ++i) {
      if (i->first == txid)
      {
        res.transfers.resize(res.transfers.size() + 1);
        fill_transfer_entry(res.transfers.back(), i->first, i->second);
      }
    }

    std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> process_txs;
    m_wallet->update_pool_state(process_txs);
    if (!process_txs.empty())
      m_wallet->process_pool_state(process_txs);

    std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>> pool_payments;
    m_wallet->get_unconfirmed_payments(pool_payments, req.account_index);
    for (std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>>::const_iterator i = pool_payments.begin(); i != pool_payments.end(); ++i) {
      if (i->second.m_pd.m_tx_hash == txid)
      {
        res.transfers.resize(res.transfers.size() + 1);
        fill_transfer_entry(res.transfers.back(), i->first, i->second);
      }
    }

    if (!res.transfers.empty())
    {
      res.transfer = res.transfers.front(); // backward compat
      return true;
    }

    er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
    er.message = "Transaction not found.";
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_export_outputs(const wallet_rpc::COMMAND_RPC_EXPORT_OUTPUTS::request& req, wallet_rpc::COMMAND_RPC_EXPORT_OUTPUTS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    if (m_wallet->key_on_device())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "command not supported by HW wallet";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    try
    {
      res.outputs_data_hex = epee::string_tools::buff_to_hex_nodelimer(m_wallet->export_outputs_to_str(req.all, req.start, req.count));
    }
    catch (const std::exception &e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_import_outputs(const wallet_rpc::COMMAND_RPC_IMPORT_OUTPUTS::request& req, wallet_rpc::COMMAND_RPC_IMPORT_OUTPUTS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    if (m_wallet->key_on_device())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "command not supported by HW wallet";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.outputs_data_hex, blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_HEX;
      er.message = "Failed to parse hex.";
      return false;
    }

    try
    {
      res.num_imported = m_wallet->import_outputs_from_str(blob);
    }
    catch (const std::exception &e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_export_key_images(const wallet_rpc::COMMAND_RPC_EXPORT_KEY_IMAGES::request& req, wallet_rpc::COMMAND_RPC_EXPORT_KEY_IMAGES::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      std::pair<uint64_t, std::vector<std::pair<crypto::key_image, crypto::signature>>> ski = m_wallet->export_key_images(req.all);
      res.offset = ski.first;
      res.signed_key_images.resize(ski.second.size());
      for (size_t n = 0; n < ski.second.size(); ++n)
      {
         res.signed_key_images[n].key_image = epee::string_tools::pod_to_hex(ski.second[n].first);
         res.signed_key_images[n].signature = epee::string_tools::pod_to_hex(ski.second[n].second);
      }
    }

    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_import_key_images(const wallet_rpc::COMMAND_RPC_IMPORT_KEY_IMAGES::request& req, wallet_rpc::COMMAND_RPC_IMPORT_KEY_IMAGES::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    if (!m_wallet->is_trusted_daemon())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "This command requires a trusted daemon.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      std::vector<std::pair<crypto::key_image, crypto::signature>> ski;
      ski.resize(req.signed_key_images.size());
      for (size_t n = 0; n < ski.size(); ++n)
      {
        if (!epee::string_tools::hex_to_pod(req.signed_key_images[n].key_image, ski[n].first))
        {
          er.code = WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE;
          er.message = "failed to parse key image";
          return false;
        }

        if (!epee::string_tools::hex_to_pod(req.signed_key_images[n].signature, ski[n].second))
        {
          er.code = WALLET_RPC_ERROR_CODE_WRONG_SIGNATURE;
          er.message = "failed to parse signature";
          return false;
        }
      }
      uint64_t spent = 0, unspent = 0;
      uint64_t height = m_wallet->import_key_images(ski, req.offset, spent, unspent);
      res.spent = spent;
      res.unspent = unspent;
      res.height = height;
    }

    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_make_uri(const wallet_rpc::COMMAND_RPC_MAKE_URI::request& req, wallet_rpc::COMMAND_RPC_MAKE_URI::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    std::string error;
    std::string uri = m_wallet->make_uri(req.address, req.payment_id, req.amount, req.tx_description, req.recipient_name, error);
    if (uri.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_URI;
      er.message = std::string("Cannot make URI from supplied parameters: ") + error;
      return false;
    }

    res.uri = uri;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_parse_uri(const wallet_rpc::COMMAND_RPC_PARSE_URI::request& req, wallet_rpc::COMMAND_RPC_PARSE_URI::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    std::string error;
    if (!m_wallet->parse_uri(req.uri, res.uri.address, res.uri.payment_id, res.uri.amount, res.uri.tx_description, res.uri.recipient_name, res.unknown_parameters, error))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_URI;
      er.message = "Error parsing URI: " + error;
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_address_book(const wallet_rpc::COMMAND_RPC_GET_ADDRESS_BOOK_ENTRY::request& req, wallet_rpc::COMMAND_RPC_GET_ADDRESS_BOOK_ENTRY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    CHECK_IF_BACKGROUND_SYNCING();
    const auto ab = m_wallet->get_address_book();
    if (req.entries.empty())
    {
      uint64_t idx = 0;
      for (const auto &entry: ab)
      {
        std::string address;
        if (entry.m_has_payment_id)
          address = cryptonote::get_account_integrated_address_as_str(m_wallet->nettype(), entry.m_address, entry.m_payment_id);
        else
          address = get_account_address_as_str(m_wallet->nettype(), entry.m_is_subaddress, entry.m_address);
        res.entries.push_back(wallet_rpc::COMMAND_RPC_GET_ADDRESS_BOOK_ENTRY::entry{idx++, address, entry.m_description});
      }
    }
    else
    {
      for (uint64_t idx: req.entries)
      {
        if (idx >= ab.size())
        {
          er.code = WALLET_RPC_ERROR_CODE_WRONG_INDEX;
          er.message = "Index out of range: " + std::to_string(idx);
          return false;
        }
        const auto &entry = ab[idx];
        std::string address;
        if (entry.m_has_payment_id)
          address = cryptonote::get_account_integrated_address_as_str(m_wallet->nettype(), entry.m_address, entry.m_payment_id);
        else
          address = get_account_address_as_str(m_wallet->nettype(), entry.m_is_subaddress, entry.m_address);
        res.entries.push_back(wallet_rpc::COMMAND_RPC_GET_ADDRESS_BOOK_ENTRY::entry{idx, address, entry.m_description});
      }
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_add_address_book(const wallet_rpc::COMMAND_RPC_ADD_ADDRESS_BOOK_ENTRY::request& req, wallet_rpc::COMMAND_RPC_ADD_ADDRESS_BOOK_ENTRY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    cryptonote::address_parse_info info;
    er.message = "";
    if(!get_account_address_from_str_or_url(info, m_wallet->nettype(), req.address,
      [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
        if (!dnssec_valid)
        {
          er.message = std::string("Invalid DNSSEC for ") + url;
          return {};
        }
        if (addresses.empty())
        {
          er.message = std::string("No PBC Chain address found at ") + url;
          return {};
        }
        return addresses[0];
      }))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      if (er.message.empty())
        er.message = std::string("WALLET_RPC_ERROR_CODE_WRONG_ADDRESS: ") + req.address;
      return false;
    }
    if (!m_wallet->add_address_book_row(info.address, info.has_payment_id ? &info.payment_id : NULL, req.description, info.is_subaddress))
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to add address book entry";
      return false;
    }
    res.index = m_wallet->get_address_book().size() - 1;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_edit_address_book(const wallet_rpc::COMMAND_RPC_EDIT_ADDRESS_BOOK_ENTRY::request& req, wallet_rpc::COMMAND_RPC_EDIT_ADDRESS_BOOK_ENTRY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    const auto ab = m_wallet->get_address_book();
    if (req.index >= ab.size())
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_INDEX;
      er.message = "Index out of range: " + std::to_string(req.index);
      return false;
    }

    tools::wallet2::address_book_row entry = ab[req.index];

    cryptonote::address_parse_info info;
    if (req.set_address)
    {
      er.message = "";
      if(!get_account_address_from_str_or_url(info, m_wallet->nettype(), req.address,
        [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
          if (!dnssec_valid)
          {
            er.message = std::string("Invalid DNSSEC for ") + url;
            return {};
          }
          if (addresses.empty())
          {
            er.message = std::string("No PBC Chain address found at ") + url;
            return {};
          }
          return addresses[0];
        }))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
        if (er.message.empty())
          er.message = std::string("WALLET_RPC_ERROR_CODE_WRONG_ADDRESS: ") + req.address;
        return false;
      }
      entry.m_address = info.address;
      entry.m_is_subaddress = info.is_subaddress;
      if (info.has_payment_id)
        entry.m_payment_id = info.payment_id;
    }

    if (req.set_description)
      entry.m_description = req.description;

    if (!m_wallet->set_address_book_row(req.index, entry.m_address, req.set_address && entry.m_has_payment_id ? &entry.m_payment_id : NULL, entry.m_description, entry.m_is_subaddress))
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to edit address book entry";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_delete_address_book(const wallet_rpc::COMMAND_RPC_DELETE_ADDRESS_BOOK_ENTRY::request& req, wallet_rpc::COMMAND_RPC_DELETE_ADDRESS_BOOK_ENTRY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    const auto ab = m_wallet->get_address_book();
    if (req.index >= ab.size())
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_INDEX;
      er.message = "Index out of range: " + std::to_string(req.index);
      return false;
    }
    if (!m_wallet->delete_address_book_row(req.index))
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to delete address book entry";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_refresh(const wallet_rpc::COMMAND_RPC_REFRESH::request& req, wallet_rpc::COMMAND_RPC_REFRESH::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    try
    {
      m_wallet->refresh(m_wallet->is_trusted_daemon(), req.start_height, res.blocks_fetched, res.received_money);
      // PBC FIX: persist after refresh so m_confirmed_txs (updated in memory by
      // process_unconfirmed) survives a wallet-rpc restart. Without this, pbc_withdraw
      // TXs confirmed during this refresh are lost on restart, causing Interest Withdrawn = 0.
      if (res.blocks_fetched > 0)
      {
        try { m_wallet->store(); }
        catch (const std::exception &) {}
      }
      return true;
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_auto_refresh(const wallet_rpc::COMMAND_RPC_AUTO_REFRESH::request& req, wallet_rpc::COMMAND_RPC_AUTO_REFRESH::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    try
    {
      const auto new_period = req.enable ? req.period ? req.period : DEFAULT_AUTO_REFRESH_PERIOD : 0;
      m_auto_refresh_period.store(new_period, std::memory_order_relaxed);
      MINFO("Auto refresh now " << (new_period ? std::to_string(new_period) + " seconds" : std::string("disabled")));
      return true;
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_scan_tx(const wallet_rpc::COMMAND_RPC_SCAN_TX::request& req, wallet_rpc::COMMAND_RPC_SCAN_TX::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
      if (!m_wallet) return not_open(er);
      if (m_restricted)
      {
          er.code = WALLET_RPC_ERROR_CODE_DENIED;
          er.message = "Command unavailable in restricted mode.";
          return false;
      }
      CHECK_IF_BACKGROUND_SYNCING();

      std::unordered_set<crypto::hash> txids;
      std::list<std::string>::const_iterator i = req.txids.begin();
      while (i != req.txids.end())
      {
          cryptonote::blobdata txid_blob;
          if(!epee::string_tools::parse_hexstr_to_binbuff(*i++, txid_blob) || txid_blob.size() != sizeof(crypto::hash))
          {
              er.code = WALLET_RPC_ERROR_CODE_WRONG_TXID;
              er.message = "TX ID has invalid format";
              return false;
          }

          crypto::hash txid = *reinterpret_cast<const crypto::hash*>(txid_blob.data());
          txids.insert(txid);
      }

      try {
          m_wallet->scan_tx(txids);
      }  catch (const tools::error::wont_reprocess_recent_txs_via_untrusted_daemon &e) {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = e.what() + std::string(". Either connect to a trusted daemon or rescan the chain.");
          return false;
      } catch (const std::exception &e) {
          handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
          return false;
      }
      return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_rescan_spent(const wallet_rpc::COMMAND_RPC_RESCAN_SPENT::request& req, wallet_rpc::COMMAND_RPC_RESCAN_SPENT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();
    try
    {
      m_wallet->rescan_spent();
      return true;
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_start_mining(const wallet_rpc::COMMAND_RPC_START_MINING::request& req, wallet_rpc::COMMAND_RPC_START_MINING::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (!m_wallet->is_trusted_daemon())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "This command requires a trusted daemon.";
      return false;
    }

    size_t max_mining_threads_count = (std::max)(tools::get_max_concurrency(), static_cast<unsigned>(2));
    if (req.threads_count < 1 || max_mining_threads_count < req.threads_count)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "The specified number of threads is inappropriate.";
      return false;
    }

    cryptonote::COMMAND_RPC_START_MINING::request daemon_req = AUTO_VAL_INIT(daemon_req); 
    daemon_req.miner_address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    daemon_req.threads_count        = req.threads_count;
    daemon_req.do_background_mining = req.do_background_mining;
    daemon_req.ignore_battery       = req.ignore_battery;

    cryptonote::COMMAND_RPC_START_MINING::response daemon_res;
    bool r = m_wallet->invoke_http_json("/start_mining", daemon_req, daemon_res);
    if (!r || daemon_res.status != CORE_RPC_STATUS_OK)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Couldn't start mining due to unknown error.";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_stop_mining(const wallet_rpc::COMMAND_RPC_STOP_MINING::request& req, wallet_rpc::COMMAND_RPC_STOP_MINING::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    cryptonote::COMMAND_RPC_STOP_MINING::request daemon_req;
    cryptonote::COMMAND_RPC_STOP_MINING::response daemon_res;
    bool r = m_wallet->invoke_http_json("/stop_mining", daemon_req, daemon_res);
    if (!r || daemon_res.status != CORE_RPC_STATUS_OK)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Couldn't stop mining due to unknown error.";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_languages(const wallet_rpc::COMMAND_RPC_GET_LANGUAGES::request& req, wallet_rpc::COMMAND_RPC_GET_LANGUAGES::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    crypto::ElectrumWords::get_language_list(res.languages, true);
    crypto::ElectrumWords::get_language_list(res.languages_local, false);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_create_wallet(const wallet_rpc::COMMAND_RPC_CREATE_WALLET::request& req, wallet_rpc::COMMAND_RPC_CREATE_WALLET::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (m_wallet_dir.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_NO_WALLET_DIR;
      er.message = "No wallet dir configured";
      return false;
    }

    namespace po = boost::program_options;
    po::variables_map vm2;
    const char *ptr = strchr(req.filename.c_str(), '/');
#ifdef _WIN32
    if (!ptr)
      ptr = strchr(req.filename.c_str(), '\\');
    if (!ptr)
      ptr = strchr(req.filename.c_str(), ':');
#endif
    if (ptr)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Invalid filename";
      return false;
    }
    std::string wallet_file = req.filename.empty() ? "" : (m_wallet_dir + "/" + req.filename);
    {
      if (!crypto::ElectrumWords::is_valid_language(req.language))
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Unknown language: " + req.language;
        return false;
      }
    }
    {
      po::options_description desc("dummy");
      const command_line::arg_descriptor<std::string, true> arg_password = {"password", "password"};
      const char *argv[4];
      int argc = 3;
      argv[0] = "wallet-rpc";
      argv[1] = "--password";
      argv[2] = req.password.c_str();
      argv[3] = NULL;
      vm2 = *m_vm;
      command_line::add_arg(desc, arg_password);
      po::store(po::parse_command_line(argc, argv, desc), vm2);
    }
    std::unique_ptr<tools::wallet2> wal = tools::wallet2::make_new(vm2, true, nullptr).first;
    if (!wal)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to create wallet";
      return false;
    }
    wal->set_seed_language(req.language);
    cryptonote::COMMAND_RPC_GET_HEIGHT::request hreq;
    cryptonote::COMMAND_RPC_GET_HEIGHT::response hres;
    hres.height = 0;
    bool r = wal->invoke_http_json("/getheight", hreq, hres);
    if (r)
      wal->set_refresh_from_block_height(hres.height);
    crypto::secret_key dummy_key;
    try {
      wal->generate(wallet_file, req.password, dummy_key, false, false);
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }
    if (!wal)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to generate wallet";
      return false;
    }

    if (m_wallet)
    {
      try
      {
        m_wallet->store();
      }
      catch (const std::exception& e)
      {
        handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return false;
      }
      delete m_wallet;
    }
    m_wallet = wal.release();
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_open_wallet(const wallet_rpc::COMMAND_RPC_OPEN_WALLET::request& req, wallet_rpc::COMMAND_RPC_OPEN_WALLET::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (m_wallet_dir.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_NO_WALLET_DIR;
      er.message = "No wallet dir configured";
      return false;
    }

    namespace po = boost::program_options;
    po::variables_map vm2;
    const char *ptr = strchr(req.filename.c_str(), '/');
#ifdef _WIN32
    if (!ptr)
      ptr = strchr(req.filename.c_str(), '\\');
    if (!ptr)
      ptr = strchr(req.filename.c_str(), ':');
#endif
    if (ptr)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Invalid filename";
      return false;
    }
    if (m_wallet && req.autosave_current)
    {
      try
      {
        m_wallet->store();
      }
      catch (const std::exception& e)
      {
        handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return false;
      }
    }
    std::string wallet_file = m_wallet_dir + "/" + req.filename;
    {
      po::options_description desc("dummy");
      const command_line::arg_descriptor<std::string, true> arg_password = {"password", "password"};
      const char *argv[4];
      int argc = 3;
      argv[0] = "wallet-rpc";
      argv[1] = "--password";
      argv[2] = req.password.c_str();
      argv[3] = NULL;
      vm2 = *m_vm;
      command_line::add_arg(desc, arg_password);
      po::store(po::parse_command_line(argc, argv, desc), vm2);
    }
    std::unique_ptr<tools::wallet2> wal = nullptr;
    try {
      wal = tools::wallet2::make_from_file(vm2, true, wallet_file, nullptr).first;
    }
    catch (const std::exception& e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
    }
    if (!wal)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to open wallet : " + (!er.message.empty() ? er.message : "Unknown.");
      return false;
    }

    if (m_wallet)
      delete m_wallet;
    m_wallet = wal.release();
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_close_wallet(const wallet_rpc::COMMAND_RPC_CLOSE_WALLET::request& req, wallet_rpc::COMMAND_RPC_CLOSE_WALLET::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);

    if (req.autosave_current)
    {
      try
      {
        m_wallet->store();
      }
      catch (const std::exception& e)
      {
        handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return false;
      }
    }
    delete m_wallet;
    m_wallet = NULL;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_change_wallet_password(const wallet_rpc::COMMAND_RPC_CHANGE_WALLET_PASSWORD::request& req, wallet_rpc::COMMAND_RPC_CHANGE_WALLET_PASSWORD::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();
    if (m_wallet->verify_password(req.old_password))
    {
      try
      {
        m_wallet->change_password(m_wallet->get_wallet_file(), req.old_password, req.new_password);
        LOG_PRINT_L0("Wallet password changed.");
      }
      catch (const std::exception& e)
      {
        handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return false;
      }
    }
    else
    {
      er.code = WALLET_RPC_ERROR_CODE_INVALID_PASSWORD;
      er.message = "Invalid original password.";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::handle_rpc_exception(const std::exception_ptr& e, epee::json_rpc::error& er, int default_error_code) {
    try
    {
      std::rethrow_exception(e);
    }
    catch (const tools::error::no_connection_to_daemon& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_NO_DAEMON_CONNECTION;
      er.message = e.what();
    }
    catch (const tools::error::daemon_busy& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_DAEMON_IS_BUSY;
      er.message = e.what();
    }
    catch (const tools::error::zero_amount& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_ZERO_AMOUNT;
      er.message = e.what();
    }
    catch (const tools::error::zero_destination& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_ZERO_DESTINATION;
      er.message = e.what();
    }
    catch (const tools::error::not_enough_money& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_ENOUGH_MONEY;
      er.message = e.what();
    }
    catch (const tools::error::not_enough_unlocked_money& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_ENOUGH_UNLOCKED_MONEY;
      er.message = e.what();
    }
    catch (const tools::error::tx_not_possible& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE;
      // PBC FIX: the formatted message was being generated then immediately overwritten
      // by e.what() (= bare "tx not possible"). Keep the informative formatted version.
      er.message = (boost::format(tr("Transaction not possible. Available only %s, transaction amount %s = %s + %s (fee)")) %
        cryptonote::print_money(e.available()) %
        cryptonote::print_money(e.tx_amount() + e.fee())  %
        cryptonote::print_money(e.tx_amount()) %
        cryptonote::print_money(e.fee())).str();
    }
    catch (const tools::error::not_enough_outs_to_mix& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_ENOUGH_OUTS_TO_MIX;
      er.message = e.what() + std::string(" Please use sweep_dust.");
    }
    catch (const error::file_exists& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_WALLET_ALREADY_EXISTS;
      er.message = "Cannot create wallet. Already exists.";
    }
    catch (const error::invalid_password& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_INVALID_PASSWORD;
      er.message = "Invalid password.";
    }
    catch (const error::account_index_outofbound& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_ACCOUNT_INDEX_OUT_OF_BOUNDS;
      er.message = e.what();
    }
    catch (const error::address_index_outofbound& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_ADDRESS_INDEX_OUT_OF_BOUNDS;
      er.message = e.what();
    }
    catch (const error::signature_check_failed& e)
    {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_SIGNATURE;
        er.message = e.what();
    }
    catch (const std::exception& e)
    {
      er.code = default_error_code;
      er.message = e.what();
    }
    catch (...)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR";
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_generate_from_keys(const wallet_rpc::COMMAND_RPC_GENERATE_FROM_KEYS::request &req, wallet_rpc::COMMAND_RPC_GENERATE_FROM_KEYS::response &res, epee::json_rpc::error &er, const connection_context *ctx)
  {
    if (m_wallet_dir.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_NO_WALLET_DIR;
      er.message = "No wallet dir configured";
      return false;
    }

    // early check for mandatory fields
    if (req.viewkey.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "field 'viewkey' is mandatory. Please provide a view key you want to restore from.";
      return false;
    }
    if (req.address.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "field 'address' is mandatory. Please provide a public address.";
      return false;
    }

    namespace po = boost::program_options;
    po::variables_map vm2;
    const char *ptr = strchr(req.filename.c_str(), '/');
  #ifdef _WIN32
    if (!ptr)
      ptr = strchr(req.filename.c_str(), '\\');
    if (!ptr)
      ptr = strchr(req.filename.c_str(), ':');
  #endif
    if (ptr)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Invalid filename";
      return false;
    }
    std::string wallet_file = req.filename.empty() ? "" : (m_wallet_dir + "/" + req.filename);
    // check if wallet file already exists
    if (!wallet_file.empty())
    {
      try
      {
        boost::system::error_code ignored_ec;
        THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(wallet_file, ignored_ec), error::file_exists, wallet_file);
      }
      catch (const std::exception &e)
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Wallet already exists.";
        return false;
      }
    }

    {
      po::options_description desc("dummy");
      const command_line::arg_descriptor<std::string, true> arg_password = {"password", "password"};
      const char *argv[4];
      int argc = 3;
      argv[0] = "wallet-rpc";
      argv[1] = "--password";
      argv[2] = req.password.c_str();
      argv[3] = NULL;
      vm2 = *m_vm;
      command_line::add_arg(desc, arg_password);
      po::store(po::parse_command_line(argc, argv, desc), vm2);
    }

    auto rc = tools::wallet2::make_new(vm2, true, nullptr);
    std::unique_ptr<wallet2> wal;
    wal = std::move(rc.first);
    if (!wal)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to create wallet";
      return false;
    }

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, wal->nettype(), req.address))
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to parse public address";
      return false;
    }

    epee::wipeable_string password = rc.second.password();
    epee::wipeable_string viewkey_string = req.viewkey;
    crypto::secret_key viewkey;
    if (!viewkey_string.hex_to_pod(unwrap(unwrap(viewkey))))
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to parse view key secret key";
      return false;
    }

    if (m_wallet && req.autosave_current)
    {
      try
      {
        if (!wallet_file.empty())
          m_wallet->store();
      }
      catch (const std::exception &e)
      {
        handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return false;
      }
    }

    try
    {
      if (!req.spendkey.empty())
      {
        epee::wipeable_string spendkey_string = req.spendkey;
        crypto::secret_key spendkey;
        if (!spendkey_string.hex_to_pod(unwrap(unwrap(spendkey))))
        {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = "Failed to parse spend key secret key";
          return false;
        }
        wal->generate(wallet_file, std::move(rc.second).password(), info.address, spendkey, viewkey, false);
        res.info = "Wallet has been generated successfully.";
      }
      else
      {
        wal->generate(wallet_file, std::move(rc.second).password(), info.address, viewkey, false);
        res.info = "Watch-only wallet has been generated successfully.";
      }
      MINFO("Wallet has been generated.\n");
    }
    catch (const std::exception &e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }

    if (!wal)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to generate wallet";
      return false;
    }

    if (!req.language.empty())
    {
      if (!crypto::ElectrumWords::is_valid_language(req.language))
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "The specified seed language is invalid.";
        return false;
      }
      wal->set_seed_language(req.language);
    }

    // set blockheight if given
    try
    {
      wal->set_refresh_from_block_height(req.restore_height);
      wal->rewrite(wallet_file, password);
    }
    catch (const std::exception &e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }

    if (m_wallet)
      delete m_wallet;
    m_wallet = wal.release();
    res.address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_restore_deterministic_wallet(const wallet_rpc::COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET::request &req, wallet_rpc::COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET::response &res, epee::json_rpc::error &er, const connection_context *ctx)
  {
    if (m_wallet_dir.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_NO_WALLET_DIR;
      er.message = "No wallet dir configured";
      return false;
    }

    // early check for mandatory fields
    if (req.seed.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "field 'seed' is mandatory. Please provide a seed you want to restore from.";
      return false;
    }

    namespace po = boost::program_options;
    po::variables_map vm2;
    const char *ptr = strchr(req.filename.c_str(), '/');
  #ifdef _WIN32
    if (!ptr)
      ptr = strchr(req.filename.c_str(), '\\');
    if (!ptr)
      ptr = strchr(req.filename.c_str(), ':');
  #endif
    if (ptr)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Invalid filename";
      return false;
    }
    std::string wallet_file = req.filename.empty() ? "" : (m_wallet_dir + "/" + req.filename);
    // check if wallet file already exists
    if (!wallet_file.empty())
    {
      try
      {
        boost::system::error_code ignored_ec;
        THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(wallet_file, ignored_ec), error::file_exists, wallet_file);
      }
      catch (const std::exception &e)
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Wallet already exists.";
        return false;
      }
    }
    crypto::secret_key recovery_key;
    std::string old_language;

    // check the given seed
    if (!req.enable_multisig_experimental) {
      if (!crypto::ElectrumWords::words_to_bytes(req.seed, recovery_key, old_language))
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Electrum-style word list failed verification";
        return false;
      }
    }
    if (m_wallet && req.autosave_current)
    {
      try
      {
        m_wallet->store();
      }
      catch (const std::exception &e)
      {
        handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
        return false;
      }
    }

    // process seed_offset if given
    {
      if (req.enable_multisig_experimental && !req.seed_offset.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Multisig seeds are not compatible with seed offsets";
        return false;
      }

      if (!req.seed_offset.empty())
      {
        recovery_key = cryptonote::decrypt_key(recovery_key, req.seed_offset);
      }
    }
    {
      po::options_description desc("dummy");
      const command_line::arg_descriptor<std::string, true> arg_password = {"password", "password"};
      const char *argv[4];
      int argc = 3;
      argv[0] = "wallet-rpc";
      argv[1] = "--password";
      argv[2] = req.password.c_str();
      argv[3] = NULL;
      vm2 = *m_vm;
      command_line::add_arg(desc, arg_password);
      po::store(po::parse_command_line(argc, argv, desc), vm2);
    }

    auto rc = tools::wallet2::make_new(vm2, true, nullptr);
    std::unique_ptr<wallet2> wal;
    wal = std::move(rc.first);
    if (!wal)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to create wallet";
      return false;
    }

    epee::wipeable_string password = rc.second.password();

    bool was_deprecated_wallet = ((old_language == crypto::ElectrumWords::old_language_name) ||
                                  crypto::ElectrumWords::get_is_old_style_seed(req.seed));

    std::string mnemonic_language = old_language;
    if (was_deprecated_wallet)
    {
      // The user had used an older version of the wallet with old style mnemonics.
      res.was_deprecated = true;
    }

    if (old_language == crypto::ElectrumWords::old_language_name)
    {
      if (req.language.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Wallet was using the old seed language. You need to specify a new seed language.";
        return false;
      }
      if (!crypto::ElectrumWords::is_valid_language(req.language))
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Wallet was using the old seed language, and the specified new seed language is invalid.";
        return false;
      }
      mnemonic_language = req.language;
    }

    wal->set_seed_language(mnemonic_language);

    crypto::secret_key recovery_val;
    try
    {
      if (req.enable_multisig_experimental)
      {
        // Parse multisig seed into raw multisig data
        epee::wipeable_string multisig_data;
        multisig_data.resize(req.seed.size() / 2);
        if (!epee::from_hex::to_buffer(epee::to_mut_byte_span(multisig_data), req.seed))
        {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = "Multisig seed not represented as hexadecimal string";
          return false;
        }

        // Generate multisig wallet
        wal->generate(wallet_file, std::move(rc.second).password(), multisig_data, false);
        wal->enable_multisig(true);
      }
      else
      {
        // Generate normal wallet
        recovery_val = wal->generate(wallet_file, std::move(rc.second).password(), recovery_key, true, false, false);
      }
      MINFO("Wallet has been restored.\n");
    }
    catch (const std::exception &e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }

    // // Convert the secret key back to seed
    epee::wipeable_string electrum_words;
    if (!req.enable_multisig_experimental && !crypto::ElectrumWords::bytes_to_words(recovery_val, electrum_words, mnemonic_language))
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to encode seed";
      return false;
    }
    res.seed = std::string(electrum_words.data(), electrum_words.size());

    if (!wal)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to generate wallet";
      return false;
    }

    // set blockheight if given
    try
    {
      wal->set_refresh_from_block_height(req.restore_height);
      wal->rewrite(wallet_file, password);
    }
    catch (const std::exception &e)
    {
      handle_rpc_exception(std::current_exception(), er, WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR);
      return false;
    }

    if (m_wallet)
      delete m_wallet;
    m_wallet = wal.release();
    res.address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    res.info = "Wallet has been restored successfully.";
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_is_multisig(const wallet_rpc::COMMAND_RPC_IS_MULTISIG::request& req, wallet_rpc::COMMAND_RPC_IS_MULTISIG::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    res.multisig = m_wallet->multisig(&res.ready, &res.threshold, &res.total);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_prepare_multisig(const wallet_rpc::COMMAND_RPC_PREPARE_MULTISIG::request& req, wallet_rpc::COMMAND_RPC_PREPARE_MULTISIG::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    if (m_wallet->multisig())
    {
      er.code = WALLET_RPC_ERROR_CODE_ALREADY_MULTISIG;
      er.message = "This wallet is already multisig";
      return false;
    }
    if (req.enable_multisig_experimental)
      m_wallet->enable_multisig(true);
    CHECK_MULTISIG_ENABLED();
    if (m_wallet->watch_only())
    {
      er.code = WALLET_RPC_ERROR_CODE_WATCH_ONLY;
      er.message = "wallet is watch-only and cannot be made multisig";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    res.multisig_info = m_wallet->get_multisig_first_kex_msg();
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_make_multisig(const wallet_rpc::COMMAND_RPC_MAKE_MULTISIG::request& req, wallet_rpc::COMMAND_RPC_MAKE_MULTISIG::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    if (m_wallet->multisig())
    {
      er.code = WALLET_RPC_ERROR_CODE_ALREADY_MULTISIG;
      er.message = "This wallet is already multisig";
      return false;
    }
    CHECK_MULTISIG_ENABLED();
    if (m_wallet->watch_only())
    {
      er.code = WALLET_RPC_ERROR_CODE_WATCH_ONLY;
      er.message = "wallet is watch-only and cannot be made multisig";
      return false;
    }
    CHECK_IF_BACKGROUND_SYNCING();

    try
    {
      res.multisig_info = m_wallet->make_multisig(req.password, req.multisig_info, req.threshold);
      res.address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_export_multisig(const wallet_rpc::COMMAND_RPC_EXPORT_MULTISIG::request& req, wallet_rpc::COMMAND_RPC_EXPORT_MULTISIG::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    bool ready;
    if (!m_wallet->multisig(&ready))
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
      er.message = "This wallet is not multisig";
      return false;
    }
    if (!ready)
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
      er.message = "This wallet is multisig, but not yet finalized";
      return false;
    }
    CHECK_MULTISIG_ENABLED();

    cryptonote::blobdata info;
    try
    {
      info = m_wallet->export_multisig();
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }

    res.info = epee::string_tools::buff_to_hex_nodelimer(info);

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_import_multisig(const wallet_rpc::COMMAND_RPC_IMPORT_MULTISIG::request& req, wallet_rpc::COMMAND_RPC_IMPORT_MULTISIG::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total))
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
      er.message = "This wallet is not multisig";
      return false;
    }
    if (!ready)
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
      er.message = "This wallet is multisig, but not yet finalized";
      return false;
    }
    CHECK_MULTISIG_ENABLED();

    if (req.info.size() < threshold - 1)
    {
      er.code = WALLET_RPC_ERROR_CODE_THRESHOLD_NOT_REACHED;
      er.message = "Needs multisig export info from more participants";
      return false;
    }

    std::vector<cryptonote::blobdata> info;
    info.resize(req.info.size());
    for (size_t n = 0; n < info.size(); ++n)
    {
      if (!epee::string_tools::parse_hexstr_to_binbuff(req.info[n], info[n]))
      {
        er.code = WALLET_RPC_ERROR_CODE_BAD_HEX;
        er.message = "Failed to parse hex.";
        return false;
      }
    }

    try
    {
      res.n_outputs = m_wallet->import_multisig(info);
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = std::string{"Error calling import_multisig: "} + e.what();
      return false;
    }

    if (m_wallet->is_trusted_daemon())
    {
      try
      {
        m_wallet->rescan_spent();
      }
      catch (const std::exception &e)
      {
        er.message = std::string("Success, but failed to update spent status after import multisig info: ") + e.what();
      }
    }
    else
    {
      er.message = "Success, but cannot update spent status after import multisig info as daemon is untrusted";
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_finalize_multisig(const wallet_rpc::COMMAND_RPC_FINALIZE_MULTISIG::request& req, wallet_rpc::COMMAND_RPC_FINALIZE_MULTISIG::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    CHECK_MULTISIG_ENABLED();
    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_exchange_multisig_keys(const wallet_rpc::COMMAND_RPC_EXCHANGE_MULTISIG_KEYS::request& req, wallet_rpc::COMMAND_RPC_EXCHANGE_MULTISIG_KEYS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total))
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
      er.message = "This wallet is not multisig";
      return false;
    }
    CHECK_MULTISIG_ENABLED();

    if (req.multisig_info.size() + 1 < total)
    {
      er.code = WALLET_RPC_ERROR_CODE_THRESHOLD_NOT_REACHED;
      er.message = "Needs multisig info from more participants";
      return false;
    }

    try
    {
      res.multisig_info = m_wallet->exchange_multisig_keys(req.password, req.multisig_info, req.force_update_use_with_caution);
      m_wallet->multisig(&ready);
      if (ready)
      {
        res.address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
      }
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = std::string("Error calling exchange_multisig_info: ") + e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_sign_multisig(const wallet_rpc::COMMAND_RPC_SIGN_MULTISIG::request& req, wallet_rpc::COMMAND_RPC_SIGN_MULTISIG::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total))
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
      er.message = "This wallet is not multisig";
      return false;
    }
    if (!ready)
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
      er.message = "This wallet is multisig, but not yet finalized";
      return false;
    }
    CHECK_MULTISIG_ENABLED();

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.tx_data_hex, blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_HEX;
      er.message = "Failed to parse hex.";
      return false;
    }

    tools::wallet2::multisig_tx_set txs;
    bool r = m_wallet->load_multisig_tx(blob, txs, NULL);
    if (!r)
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_MULTISIG_TX_DATA;
      er.message = "Failed to parse multisig tx data.";
      return false;
    }

    std::vector<crypto::hash> txids;
    try
    {
      bool r = m_wallet->sign_multisig_tx(txs, txids);
      if (!r)
      {
        er.code = WALLET_RPC_ERROR_CODE_MULTISIG_SIGNATURE;
        er.message = "Failed to sign multisig tx";
        return false;
      }
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_MULTISIG_SIGNATURE;
      er.message = std::string("Failed to sign multisig tx: ") + e.what();
      return false;
    }

    res.tx_data_hex = epee::string_tools::buff_to_hex_nodelimer(m_wallet->save_multisig_tx(txs));
    if (!txids.empty())
    {
      for (const crypto::hash &txid: txids)
        res.tx_hash_list.push_back(epee::string_tools::pod_to_hex(txid));
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_submit_multisig(const wallet_rpc::COMMAND_RPC_SUBMIT_MULTISIG::request& req, wallet_rpc::COMMAND_RPC_SUBMIT_MULTISIG::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total))
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
      er.message = "This wallet is not multisig";
      return false;
    }
    if (!ready)
    {
      er.code = WALLET_RPC_ERROR_CODE_NOT_MULTISIG;
      er.message = "This wallet is multisig, but not yet finalized";
      return false;
    }
    CHECK_MULTISIG_ENABLED();

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.tx_data_hex, blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_HEX;
      er.message = "Failed to parse hex.";
      return false;
    }

    tools::wallet2::multisig_tx_set txs;
    bool r = m_wallet->load_multisig_tx(blob, txs, NULL);
    if (!r)
    {
      er.code = WALLET_RPC_ERROR_CODE_BAD_MULTISIG_TX_DATA;
      er.message = "Failed to parse multisig tx data.";
      return false;
    }

    if (txs.m_signers.size() < threshold)
    {
      er.code = WALLET_RPC_ERROR_CODE_THRESHOLD_NOT_REACHED;
      er.message = "Not enough signers signed this transaction.";
      return false;
    }

    try
    {
      for (auto &ptx: txs.m_ptx)
      {
        m_wallet->commit_tx(ptx);
        res.tx_hash_list.push_back(epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
      }
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_MULTISIG_SUBMISSION;
      er.message = std::string("Failed to submit multisig tx: ") + e.what();
      return false;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_validate_address(const wallet_rpc::COMMAND_RPC_VALIDATE_ADDRESS::request& req, wallet_rpc::COMMAND_RPC_VALIDATE_ADDRESS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    cryptonote::address_parse_info info;
    static const struct { cryptonote::network_type type; const char *stype; } net_types[] = {
      { cryptonote::MAINNET, "mainnet" },
      { cryptonote::TESTNET, "testnet" },
      { cryptonote::STAGENET, "stagenet" },
    };
    if (!req.any_net_type && !m_wallet) return not_open(er);
    for (const auto &net_type: net_types)
    {
      if (!req.any_net_type && (!m_wallet || net_type.type != m_wallet->nettype()))
        continue;
      if (req.allow_openalias)
      {
        std::string address;
        res.valid = get_account_address_from_str_or_url(info, net_type.type, req.address,
          [&er, &address](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
            if (!dnssec_valid)
            {
              er.message = std::string("Invalid DNSSEC for ") + url;
              return {};
            }
            if (addresses.empty())
            {
              er.message = std::string("No PBC Chain address found at ") + url;
              return {};
            }
            address = addresses[0];
            return address;
          });
        if (res.valid)
          res.openalias_address = address;
      }
      else
      {
        res.valid = cryptonote::get_account_address_from_str(info, net_type.type, req.address);
      }
      if (res.valid)
      {
        res.integrated = info.has_payment_id;
        res.subaddress = info.is_subaddress;
        res.nettype = net_type.stype;
        return true;
      }
    }

    res.valid = false;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_set_daemon(const wallet_rpc::COMMAND_RPC_SET_DAEMON::request& req, wallet_rpc::COMMAND_RPC_SET_DAEMON::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    if (m_wallet->has_proxy_option() && !req.proxy.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_PROXY_ALREADY_DEFINED;
      er.message = "It is not possible to set daemon specific proxy when --proxy is defined.";
      return false;
    }
   
    std::vector<std::vector<uint8_t>> ssl_allowed_fingerprints;
    ssl_allowed_fingerprints.reserve(req.ssl_allowed_fingerprints.size());
    for (const std::string &fp: req.ssl_allowed_fingerprints)
    {
      ssl_allowed_fingerprints.push_back({});
      std::vector<uint8_t> &v = ssl_allowed_fingerprints.back();
      for (auto c: fp)
        v.push_back(c);
    }

    epee::net_utils::ssl_options_t ssl_options = epee::net_utils::ssl_support_t::e_ssl_support_enabled;
    if (req.ssl_allow_any_cert)
      ssl_options.verification = epee::net_utils::ssl_verification_t::none;
    else if (!ssl_allowed_fingerprints.empty() || !req.ssl_ca_file.empty())
      ssl_options = epee::net_utils::ssl_options_t{std::move(ssl_allowed_fingerprints), std::move(req.ssl_ca_file)};

    if (!epee::net_utils::ssl_support_from_string(ssl_options.support, req.ssl_support))
    {
      er.code = WALLET_RPC_ERROR_CODE_NO_DAEMON_CONNECTION;
      er.message = std::string("Invalid ssl support mode");
      return false;
    }

    ssl_options.auth = epee::net_utils::ssl_authentication_t{
      std::move(req.ssl_private_key_path), std::move(req.ssl_certificate_path)
    };

    const bool verification_required =
      ssl_options.verification != epee::net_utils::ssl_verification_t::none &&
      ssl_options.support == epee::net_utils::ssl_support_t::e_ssl_support_enabled;

    if (verification_required && !ssl_options.has_strong_verification(boost::string_ref{}))
    {
      er.code = WALLET_RPC_ERROR_CODE_NO_DAEMON_CONNECTION;
      er.message = "SSL is enabled but no user certificate or fingerprints were provided";
      return false;
    }

    boost::optional<epee::net_utils::http::login> daemon_login{};
    if (!req.username.empty() || !req.password.empty())
      daemon_login.emplace(req.username, req.password);

    if (!m_wallet->set_daemon(req.address, daemon_login, req.trusted, std::move(ssl_options), req.proxy))
    {
      er.code = WALLET_RPC_ERROR_CODE_NO_DAEMON_CONNECTION;
      er.message = std::string("Unable to set daemon");
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_set_log_level(const wallet_rpc::COMMAND_RPC_SET_LOG_LEVEL::request& req, wallet_rpc::COMMAND_RPC_SET_LOG_LEVEL::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    if (req.level < 0 || req.level > 4)
    {
      er.code = WALLET_RPC_ERROR_CODE_INVALID_LOG_LEVEL;
      er.message = "Error: log level not valid";
      return false;
    }
    mlog_set_log_level(req.level);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_set_log_categories(const wallet_rpc::COMMAND_RPC_SET_LOG_CATEGORIES::request& req, wallet_rpc::COMMAND_RPC_SET_LOG_CATEGORIES::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (m_restricted)
    {
      er.code = WALLET_RPC_ERROR_CODE_DENIED;
      er.message = "Command unavailable in restricted mode.";
      return false;
    }

    mlog_set_log(req.categories.c_str());
    res.categories = mlog_get_categories();
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_estimate_tx_size_and_weight(const wallet_rpc::COMMAND_RPC_ESTIMATE_TX_SIZE_AND_WEIGHT::request& req, wallet_rpc::COMMAND_RPC_ESTIMATE_TX_SIZE_AND_WEIGHT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      size_t extra_size = 34 /* pubkey */ + 10 /* encrypted payment id */; // typical makeup
      const std::pair<size_t, uint64_t> sw = m_wallet->estimate_tx_size_and_weight(req.rct, req.n_inputs, req.ring_size, req.n_outputs, extra_size);
      res.size = sw.first;
      res.weight = sw.second;
    }
    catch (const std::exception &e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to determine size and weight";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_default_fee_priority(const wallet_rpc::COMMAND_RPC_GET_DEFAULT_FEE_PRIORITY::request& req, wallet_rpc::COMMAND_RPC_GET_DEFAULT_FEE_PRIORITY::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    if (!m_wallet) return not_open(er);
    try
    {
      uint32_t priority = m_wallet->adjust_priority(0);
      if (priority == 0)
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Failed to get adjusted fee priority";
        return false;
      }
      res.priority = priority;
    }
    catch (const std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to get adjusted fee priority";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_version(const wallet_rpc::COMMAND_RPC_GET_VERSION::request& req, wallet_rpc::COMMAND_RPC_GET_VERSION::response& res, epee::json_rpc::error& er, const connection_context *ctx)
  {
    res.version = WALLET_RPC_VERSION;
    res.release = MONERO_VERSION_IS_RELEASE;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
}

class t_daemon
{
private:
  const boost::program_options::variables_map& vm;

  std::unique_ptr<tools::wallet_rpc_server> wrpc;

public:
  t_daemon(boost::program_options::variables_map const & _vm)
    : vm(_vm)
    , wrpc(new tools::wallet_rpc_server)
  {
  }

  bool run()
  {
    std::unique_ptr<tools::wallet2> wal;
    try
    {
      const bool testnet = tools::wallet2::has_testnet_option(vm);
      const bool stagenet = tools::wallet2::has_stagenet_option(vm);
      if (testnet && stagenet)
      {
        MERROR(tools::wallet_rpc_server::tr("Can't specify more than one of --testnet and --stagenet"));
        return false;
      }

      const auto arg_wallet_file = wallet_args::arg_wallet_file();
      const auto arg_from_json = wallet_args::arg_generate_from_json();
      const auto arg_rpc_client_secret_key = wallet_args::arg_rpc_client_secret_key();
      const auto arg_password_file = wallet_args::arg_password_file();

      const auto wallet_file = command_line::get_arg(vm, arg_wallet_file);
      const auto from_json = command_line::get_arg(vm, arg_from_json);
      const auto wallet_dir = command_line::get_arg(vm, arg_wallet_dir);
      const auto password_file = command_line::get_arg(vm, arg_password_file);
      const auto prompt_for_password = command_line::get_arg(vm, arg_prompt_for_password);
      const auto password_prompt = prompt_for_password ? password_prompter : nullptr;
      const auto no_initial_sync = command_line::get_arg(vm, arg_no_initial_sync);

      if(!wallet_file.empty() && !from_json.empty())
      {
        LOG_ERROR(tools::wallet_rpc_server::tr("Can't specify more than one of --wallet-file and --generate-from-json"));
        return false;
      }

      if(!wallet_dir.empty() && !password_file.empty())
      {
        LOG_ERROR(tools::wallet_rpc_server::tr("--password-file is not allowed in combination with --wallet-dir"));
        return false;
      }

      if (!wallet_dir.empty())
      {
        wal = NULL;
        goto just_dir;
      }

      if (wallet_file.empty() && from_json.empty())
      {
        LOG_ERROR(tools::wallet_rpc_server::tr("Must specify --wallet-file or --generate-from-json or --wallet-dir"));
        return false;
      }

      LOG_PRINT_L0(tools::wallet_rpc_server::tr("Loading wallet..."));
      if(!wallet_file.empty())
      {
        wal = tools::wallet2::make_from_file(vm, true, wallet_file, password_prompt).first;
      }
      else
      {
        try
        {
          auto rc = tools::wallet2::make_from_json(vm, true, from_json, password_prompt);
          wal = std::move(rc.first);
        }
        catch (const std::exception &e)
        {
          MERROR("Error creating wallet: " << e.what());
          return false;
        }
      }
      if (!wal)
      {
        return false;
      }

      if (!command_line::is_arg_defaulted(vm, arg_rpc_client_secret_key))
      {
        crypto::secret_key client_secret_key;
        if (!epee::string_tools::hex_to_pod(command_line::get_arg(vm, arg_rpc_client_secret_key), client_secret_key))
        {
          MERROR(arg_rpc_client_secret_key.name << ": RPC client secret key should be 32 byte in hex format");
          return false;
        }
        wal->set_rpc_client_secret_key(client_secret_key);
      }

      bool quit = false;
      tools::signal_handler::install([&wal, &quit](int) {
        assert(wal);
        quit = true;
        wal->stop();
      });

      try
      {
        if (!no_initial_sync)
        {
          LOG_PRINT_L0("Starting initial wallet sync (use --no-initial-sync to skip)...");
          // Use chunked refresh to avoid monopolizing daemon for miners
          uint64_t blocks_fetched = 0;
          bool received_money = false;
          do {
            blocks_fetched = 0;
            wal->refresh(wal->is_trusted_daemon(), 0, blocks_fetched, received_money, true, true, REFRESH_INDICATIVE_BLOCK_CHUNK_SIZE);
            if (blocks_fetched >= REFRESH_INDICATIVE_BLOCK_CHUNK_SIZE)
            {
              // Yield to let daemon serve miners between chunks
              std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
          } while (blocks_fetched >= REFRESH_INDICATIVE_BLOCK_CHUNK_SIZE && !quit);
          LOG_PRINT_L0("Initial wallet sync complete");
        }
        else
        {
          LOG_PRINT_L0("Skipped initial sync (--no-initial-sync)");
        }
      }
      catch (const std::exception& e)
      {
        LOG_ERROR(tools::wallet_rpc_server::tr("Initial refresh failed: ") << e.what());
      }
      // if we ^C during potentially length load/refresh, there's no server loop yet
      if (quit)
      {
        MINFO(tools::wallet_rpc_server::tr("Saving wallet..."));
        wal->store();
        MINFO(tools::wallet_rpc_server::tr("Successfully saved"));
        return false;
      }
      MINFO(tools::wallet_rpc_server::tr("Successfully loaded"));
    }
    catch (const std::exception& e)
    {
      LOG_ERROR(tools::wallet_rpc_server::tr("Wallet initialization failed: ") << e.what());
      return false;
    }
  just_dir:
    if (wal) wrpc->set_wallet(wal.release());
    bool r = wrpc->init(&vm);
    CHECK_AND_ASSERT_MES(r, false, tools::wallet_rpc_server::tr("Failed to initialize wallet RPC server"));
    tools::signal_handler::install([this](int) {
      wrpc->send_stop_signal();
    });
    LOG_PRINT_L0(tools::wallet_rpc_server::tr("Starting wallet RPC server"));
    try
    {
      wrpc->run();
    }
    catch (const std::exception &e)
    {
      LOG_ERROR(tools::wallet_rpc_server::tr("Failed to run wallet: ") << e.what());
      return false;
    }
    LOG_PRINT_L0(tools::wallet_rpc_server::tr("Stopped wallet RPC server"));
    try
    {
      LOG_PRINT_L0(tools::wallet_rpc_server::tr("Saving wallet..."));
      wrpc->stop();
      LOG_PRINT_L0(tools::wallet_rpc_server::tr("Successfully saved"));
    }
    catch (const std::exception& e)
    {
      LOG_ERROR(tools::wallet_rpc_server::tr("Failed to save wallet: ") << e.what());
      return false;
    }
    return true;
  }

  void stop()
  {
    wrpc->send_stop_signal();
  }
};

class t_executor final
{
public:
  static std::string const NAME;

  typedef ::t_daemon t_daemon;

  std::string const & name() const
  {
    return NAME;
  }

  t_daemon create_daemon(boost::program_options::variables_map const & vm)
  {
    return t_daemon(vm);
  }

  bool run_non_interactive(boost::program_options::variables_map const & vm)
  {
    return t_daemon(vm).run();
  }

  bool run_interactive(boost::program_options::variables_map const & vm)
  {
    return t_daemon(vm).run();
  }
};

std::string const t_executor::NAME = "Wallet RPC Daemon";

int main(int argc, char** argv) {
  TRY_ENTRY();

  namespace po = boost::program_options;

  const auto arg_wallet_file = wallet_args::arg_wallet_file();
  const auto arg_from_json = wallet_args::arg_generate_from_json();
  const auto arg_rpc_client_secret_key = wallet_args::arg_rpc_client_secret_key();

  po::options_description hidden_options("Hidden");

  po::options_description desc_params(wallet_args::tr("Wallet options"));
  tools::wallet2::init_options(desc_params);
  command_line::add_arg(desc_params, arg_rpc_bind_port);
  command_line::add_arg(desc_params, arg_disable_rpc_login);
  command_line::add_arg(desc_params, arg_restricted);
  cryptonote::rpc_args::init_options(desc_params);
  command_line::add_arg(desc_params, arg_wallet_file);
  command_line::add_arg(desc_params, arg_from_json);
  command_line::add_arg(desc_params, arg_wallet_dir);
  command_line::add_arg(desc_params, arg_prompt_for_password);
  command_line::add_arg(desc_params, arg_rpc_client_secret_key);
  command_line::add_arg(desc_params, arg_no_initial_sync);
  command_line::add_arg(desc_params, arg_auto_refresh_seconds);
  command_line::add_arg(desc_params, arg_auto_consolidate_threshold);
  command_line::add_arg(desc_params, arg_auto_consolidate_priority);
  command_line::add_arg(desc_params, arg_no_pbc_auto_pqc_register);
  command_line::add_arg(desc_params, arg_rpc_max_connections_per_public_ip);
  command_line::add_arg(desc_params, arg_rpc_max_connections_per_private_ip);
  command_line::add_arg(desc_params, arg_rpc_max_connections);
  command_line::add_arg(desc_params, arg_rpc_response_soft_limit);

  daemonizer::init_options(hidden_options, desc_params);
  desc_params.add(hidden_options);

  boost::optional<po::variables_map> vm;
  bool should_terminate = false;
  std::tie(vm, should_terminate) = wallet_args::main(
    argc, argv,
    "pbc-wallet-rpc [--wallet-file=<file>|--generate-from-json=<file>|--wallet-dir=<directory>] [--rpc-bind-port=<port>]",
    tools::wallet_rpc_server::tr("This is the RPC PBC Chain wallet. It needs to connect to a PBC Chain\ndaemon to work correctly."),
    desc_params,
    po::positional_options_description(),
    [](const std::string &s, bool emphasis){ tools::scoped_message_writer(emphasis ? epee::console_color_white : epee::console_color_default, true) << s; },
    "pbc-wallet-rpc.log",
    true
  );
  if (!vm)
  {
    return 1;
  }
  if (should_terminate)
  {
    return 0;
  }

  return daemonizer::daemonize(argc, const_cast<const char**>(argv), t_executor{}, *vm) ? 0 : 1;
  CATCH_ENTRY_L0("main", 1);
}

namespace tools {
//------------------------------------------------------------------------------------------------------------------------------
bool wallet_rpc_server::on_pbc_inherit_setup(const wallet_rpc::COMMAND_RPC_PBC_INHERIT_SETUP::request& req, wallet_rpc::COMMAND_RPC_PBC_INHERIT_SETUP::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  cryptonote::address_parse_info heir_info{};
  if (!cryptonote::get_account_address_from_str_or_url(heir_info, m_wallet->nettype(), req.heir_address))
  {
    er.code = WALLET_RPC_ERROR_CODE_WRONG_PARAM;
    er.message = "Invalid heir_address";
    return false;
  }
  try
  {
    wallet2::pending_tx ptx = m_wallet->create_inherit_setup_tx(heir_info.address, req.priority);
    m_wallet->commit_tx(ptx);
    res.tx_hash = epee::string_tools::pod_to_hex(get_transaction_hash(ptx.tx));
  }
  catch (const std::exception& e)
  {
    er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
    er.message = std::string("pbc_inherit_setup failed: ") + e.what();
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------------------------------------------------------
bool wallet_rpc_server::on_pbc_inherit_request(const wallet_rpc::COMMAND_RPC_PBC_INHERIT_REQUEST::request& req, wallet_rpc::COMMAND_RPC_PBC_INHERIT_REQUEST::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  cryptonote::address_parse_info principal_info{};
  if (!cryptonote::get_account_address_from_str_or_url(principal_info, m_wallet->nettype(), req.principal_address))
  {
    er.code = WALLET_RPC_ERROR_CODE_WRONG_PARAM;
    er.message = "Invalid principal_address";
    return false;
  }
  try
  {
    wallet2::pending_tx ptx = m_wallet->create_inherit_request_tx(principal_info.address.m_spend_public_key, req.priority);
    m_wallet->commit_tx(ptx);
    res.tx_hash = epee::string_tools::pod_to_hex(get_transaction_hash(ptx.tx));
  }
  catch (const std::exception& e)
  {
    er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
    er.message = std::string("pbc_inherit_request failed: ") + e.what();
    return false;
  }

  // ── PBC / A-1 : enregistrement PQC APRES l'operation, jamais avant ────────────────────
  // Ce wallet est (ou devient) proprietaire d'un depot : sa clef post-quantique DEVRA etre
  // enregistree on-chain pour tout retrait d'interets ou paiement de vente (hard fork
  // spend-authority). On declenche l'inscription ICI, une fois l'operation demandee servie.
  //
  // POURQUOI PAS AVANT (bug corrige le 2026-08-11, prouve par les logs) : place en tete de
  // handler, l'inscription construisait sa TX AVANT le depot et consommait l'unique output
  // disponible du wallet ; le change repartait verrouille et le depot echouait ensuite en
  // not_enough_money. Vu en campagne : antifork T5, inscription soumise a la hauteur 10134,
  // depot refuse dans la foulee. Servir l'utilisateur d'abord est la seule regle sure.
  // Non fatal : un echec ici ne doit jamais faire echouer l'operation deja reussie.
  try { pbc_maybe_auto_register_pqc(); }
  catch (const std::exception &ex) { LOG_PRINT_L1("PBC AUTO-PQC (non-fatal): " << ex.what()); }
  return true;
}

//------------------------------------------------------------------------------------------------------------------------------
bool wallet_rpc_server::on_pbc_inherit_cancel(const wallet_rpc::COMMAND_RPC_PBC_INHERIT_CANCEL::request& req, wallet_rpc::COMMAND_RPC_PBC_INHERIT_CANCEL::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  try
  {
    wallet2::pending_tx ptx = m_wallet->create_inherit_cancel_tx(req.priority);
    m_wallet->commit_tx(ptx);
    res.tx_hash = epee::string_tools::pod_to_hex(get_transaction_hash(ptx.tx));
  }
  catch (const std::exception& e)
  {
    er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
    er.message = std::string("pbc_inherit_cancel failed: ") + e.what();
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------------------------------------------------------

bool wallet_rpc_server::on_pbc_lock_collateral(const wallet_rpc::COMMAND_RPC_PBC_LOCK_COLLATERAL::request& req, wallet_rpc::COMMAND_RPC_PBC_LOCK_COLLATERAL::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  crypto::hash deposit_id;
  if (!epee::string_tools::hex_to_pod(req.deposit_id, deposit_id)) { er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS; er.message = "Invalid deposit_id"; return false; }
  cryptonote::address_parse_info addr_info;
  if (!get_account_address_from_str_or_url(addr_info, m_wallet->nettype(), req.seller_address)) { er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS; er.message = "Invalid seller_address"; return false; }

  cryptonote::COMMAND_RPC_GET_PBC_DEPOSIT_INFO::request dep_req{};
  cryptonote::COMMAND_RPC_GET_PBC_DEPOSIT_INFO::response dep_res{};
  dep_req.deposit_id = req.deposit_id;
  bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_pbc_deposit_info", dep_req, dep_res, tools::wallet2::rpc_timeout);
  if (!ok || !dep_res.found) { er.code = -32001; er.message = "DEPOSIT_NOT_FOUND"; return false; }
  if (dep_res.owner_key != epee::string_tools::pod_to_hex(addr_info.address.m_spend_public_key)) { er.code = -32003; er.message = "SELLER_PUBKEY_MISMATCH"; return false; }
  // If an active ask exists, allow amount >= ask_price (marketplace discount).
  // Otherwise require amount >= principal (legacy behavior).
  {
    uint64_t min_amount = dep_res.amount; // default: full principal
    cryptonote::COMMAND_RPC_GET_ALL_MARKET_ASKS::request asks_req{};
    cryptonote::COMMAND_RPC_GET_ALL_MARKET_ASKS::response asks_res{};
    bool asks_ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_all_market_asks", asks_req, asks_res, tools::wallet2::rpc_timeout);
    if (asks_ok) {
      for (const auto& ask : asks_res.asks) {
        if (ask.deposit_id == req.deposit_id && ask.ask_price > 0) {
          min_amount = ask.ask_price;
          break;
        }
      }
    }
    if (req.amount < min_amount) { er.code = -32005; er.message = "AMOUNT_BELOW_MINIMUM (ask=" + std::to_string(min_amount) + " principal=" + std::to_string(dep_res.amount) + ")"; return false; }
  }
  uint64_t expected_dep_idx = req.expected_dep_idx ? req.expected_dep_idx : 0;
  uint64_t expected_fee_idx = req.expected_fee_idx ? req.expected_fee_idx : 0;
  try { if (expected_dep_idx == 0 && !dep_res.deposit_entry_index.empty()) expected_dep_idx = std::stoull(dep_res.deposit_entry_index); } catch(...) {}
  try { if (expected_fee_idx == 0 && !dep_res.fee_entry_index.empty()) expected_fee_idx = std::stoull(dep_res.fee_entry_index); } catch(...) {}

  cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK_FOR_DEPOSIT::request lock_req{};
  cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK_FOR_DEPOSIT::response lock_res{};
  lock_req.deposit_id = req.deposit_id;
  ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_collateral_lock_for_deposit", lock_req, lock_res, tools::wallet2::rpc_timeout);
  if (ok && lock_res.found && lock_res.lock_status == cryptonote::PBC_COLLATERAL_LOCK_ACTIVE) { er.code = -32004; er.message = "DEPOSIT_ALREADY_LOCKED"; return false; }

  try
  {
    uint64_t expiry_height = req.expiry_height;
    if (expiry_height <= PBC_LOCK_MAX_DURATION)
      expiry_height = m_wallet->get_blockchain_current_height() + expiry_height;
    if (expiry_height < m_wallet->get_blockchain_current_height() + PBC_LOCK_MIN_DURATION || expiry_height > m_wallet->get_blockchain_current_height() + PBC_LOCK_MAX_DURATION) { er.code = -32006; er.message = "EXPIRY_OUT_OF_RANGE"; return false; }
    wallet2::pending_tx ptx = m_wallet->create_lock_collateral_tx(deposit_id, addr_info.address, req.amount, expiry_height, expected_dep_idx, expected_fee_idx, req.priority);
    cryptonote::transaction tx = ptx.tx;
    m_wallet->commit_tx(ptx);
    res.tx_hash = epee::string_tools::pod_to_hex(get_transaction_hash(tx));
    res.lock_id = res.tx_hash;
    res.expected_dep_idx = expected_dep_idx;
    res.expected_fee_idx = expected_fee_idx;
    res.expiry_height = expiry_height;

    // ── PBC / A-1 : enregistrement PQC APRES l'operation, jamais avant ────────────────────
    // Ce wallet est (ou devient) proprietaire d'un depot : sa clef post-quantique DEVRA etre
    // enregistree on-chain pour tout retrait d'interets ou paiement de vente (hard fork
    // spend-authority). On declenche l'inscription ICI, une fois l'operation demandee servie.
    //
    // POURQUOI PAS AVANT (bug corrige le 2026-08-11, prouve par les logs) : place en tete de
    // handler, l'inscription construisait sa TX AVANT le depot et consommait l'unique output
    // disponible du wallet ; le change repartait verrouille et le depot echouait ensuite en
    // not_enough_money. Vu en campagne : antifork T5, inscription soumise a la hauteur 10134,
    // depot refuse dans la foulee. Servir l'utilisateur d'abord est la seule regle sure.
    // Non fatal : un echec ici ne doit jamais faire echouer l'operation deja reussie.
    try { pbc_maybe_auto_register_pqc(); }
    catch (const std::exception &ex) { LOG_PRINT_L1("PBC AUTO-PQC (non-fatal): " << ex.what()); }
    return true;
  }
  catch (const std::exception& e)
  {
    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    er.message = std::string("pbc_lock_collateral failed: ") + e.what();
    return false;
  }
}

bool wallet_rpc_server::on_pbc_cancel_lock(const wallet_rpc::COMMAND_RPC_PBC_CANCEL_LOCK::request& req, wallet_rpc::COMMAND_RPC_PBC_CANCEL_LOCK::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  crypto::hash lock_id;
  if (!epee::string_tools::hex_to_pod(req.lock_id, lock_id)) { er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS; er.message = "Invalid lock_id"; return false; }
  cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK::request get_req{};
  cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK::response get_res{};
  get_req.lock_id = req.lock_id;
  bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_collateral_lock", get_req, get_res, tools::wallet2::rpc_timeout);
  if (!ok || !get_res.found) { er.code = -32010; er.message = "LOCK_NOT_FOUND"; return false; }
  const crypto::public_key me = m_wallet->get_account().get_keys().m_account_address.m_spend_public_key;
  if (get_res.buyer_pubkey != epee::string_tools::pod_to_hex(me)) { er.code = -32016; er.message = "NOT_LOCK_BUYER"; return false; }
  if (get_res.lock_status != cryptonote::PBC_COLLATERAL_LOCK_ACTIVE) { er.code = -32011; er.message = "LOCK_NOT_ACTIVE"; return false; }
  try
  {
    wallet2::pending_tx ptx = m_wallet->create_cancel_lock_tx(lock_id, get_res.amount, req.priority);
    cryptonote::transaction tx = ptx.tx;
    m_wallet->commit_tx(ptx);
    res.tx_hash = epee::string_tools::pod_to_hex(get_transaction_hash(tx));
    return true;
  }
  catch (const std::exception& e)
  {
    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    er.message = std::string("pbc_cancel_lock failed: ") + e.what();
    return false;
  }
}

bool wallet_rpc_server::on_pbc_transfer_deposit(const wallet_rpc::COMMAND_RPC_PBC_TRANSFER_DEPOSIT::request& req, wallet_rpc::COMMAND_RPC_PBC_TRANSFER_DEPOSIT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet)
  {
    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    er.message = "Wallet not ready";
    return false;
  }
  crypto::hash deposit_id;
  if (!epee::string_tools::hex_to_pod(req.deposit_id, deposit_id))
  {
    er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
    er.message = "Invalid deposit_id";
    return false;
  }
  cryptonote::address_parse_info addr_info;
  if (!get_account_address_from_str_or_url(addr_info, m_wallet->nettype(), req.new_owner_address))
  {
    er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
    er.message = "Invalid new_owner_address";
    return false;
  }
  try
  {
    crypto::hash lock_id;
    if (!epee::string_tools::hex_to_pod(req.lock_id, lock_id)) { er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS; er.message = "Invalid lock_id"; return false; }
    cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK::request lock_req{};
    cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK::response lock_res{};
    lock_req.lock_id = req.lock_id;
    bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_collateral_lock", lock_req, lock_res, tools::wallet2::rpc_timeout);
    if (!ok || !lock_res.found) { er.code = -32010; er.message = "LOCK_NOT_FOUND"; return false; }
    uint64_t seller_payment_amount = req.seller_payment_amount ? req.seller_payment_amount : lock_res.amount;
    uint64_t expected_dep_idx = req.expected_dep_idx ? req.expected_dep_idx : lock_res.expected_dep_idx;
    uint64_t expected_fee_idx = req.expected_fee_idx ? req.expected_fee_idx : lock_res.expected_fee_idx;
    cryptonote::address_parse_info seller_info{};
    if (!get_account_address_from_str_or_url(seller_info, m_wallet->nettype(), lock_res.seller_address)) { er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS; er.message = "Invalid seller address on lock"; return false; }
    wallet2::pending_tx ptx = m_wallet->create_transfer_deposit_tx(deposit_id, addr_info.address, seller_info.address, lock_id, expected_dep_idx, expected_fee_idx, seller_payment_amount, req.priority);
    cryptonote::transaction tx = ptx.tx;
    m_wallet->commit_tx(ptx);
    res.tx_hash = epee::string_tools::pod_to_hex(get_transaction_hash(tx));
    return true;
  }
  catch (const std::exception& e)
  {
    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    er.message = std::string("pbc_transfer_deposit failed: ") + e.what();
    return false;
  }
}


bool wallet_rpc_server::on_get_collateral_lock(const wallet_rpc::COMMAND_RPC_GET_COLLATERAL_LOCK::request& req, wallet_rpc::COMMAND_RPC_GET_COLLATERAL_LOCK::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK::request daemon_req{};
  cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK::response daemon_res{};
  daemon_req.lock_id = req.lock_id;
  bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_collateral_lock", daemon_req, daemon_res, tools::wallet2::rpc_timeout);
  if (!ok) { er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR; er.message = "get_collateral_lock daemon RPC failed"; return false; }
  res.found = daemon_res.found;
  res.lock_id = daemon_res.lock_id;
  res.deposit_id = daemon_res.deposit_id;
  res.buyer_pubkey = daemon_res.buyer_pubkey;
  res.seller_pubkey = daemon_res.seller_pubkey;
  res.buyer_address = daemon_res.buyer_address;
  res.seller_address = daemon_res.seller_address;
  res.amount = daemon_res.amount;
  res.created_height = daemon_res.created_height;
  res.expiry_height = daemon_res.expiry_height;
  res.lock_status = daemon_res.lock_status;
  res.expected_dep_idx = daemon_res.expected_dep_idx;
  res.expected_fee_idx = daemon_res.expected_fee_idx;
  return true;
}

bool wallet_rpc_server::on_get_collateral_lock_for_deposit(const wallet_rpc::COMMAND_RPC_GET_COLLATERAL_LOCK_FOR_DEPOSIT::request& req, wallet_rpc::COMMAND_RPC_GET_COLLATERAL_LOCK_FOR_DEPOSIT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK_FOR_DEPOSIT::request daemon_req{};
  cryptonote::COMMAND_RPC_GET_COLLATERAL_LOCK_FOR_DEPOSIT::response daemon_res{};
  daemon_req.deposit_id = req.deposit_id;
  bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_collateral_lock_for_deposit", daemon_req, daemon_res, tools::wallet2::rpc_timeout);
  if (!ok) { er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR; er.message = "get_collateral_lock_for_deposit daemon RPC failed"; return false; }
  res.found = daemon_res.found;
  res.lock_id = daemon_res.lock_id;
  res.deposit_id = daemon_res.deposit_id;
  res.buyer_pubkey = daemon_res.buyer_pubkey;
  res.seller_pubkey = daemon_res.seller_pubkey;
  res.buyer_address = daemon_res.buyer_address;
  res.seller_address = daemon_res.seller_address;
  res.amount = daemon_res.amount;
  res.created_height = daemon_res.created_height;
  res.expiry_height = daemon_res.expiry_height;
  res.lock_status = daemon_res.lock_status;
  res.expected_dep_idx = daemon_res.expected_dep_idx;
  res.expected_fee_idx = daemon_res.expected_fee_idx;
  return true;
}

bool wallet_rpc_server::on_pbc_inherit_status(const wallet_rpc::COMMAND_RPC_PBC_INHERIT_STATUS::request& req, wallet_rpc::COMMAND_RPC_PBC_INHERIT_STATUS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);

  // Get our own spend pubkey — that's the LMDB key for our inherit record
  const crypto::public_key spend_pub = m_wallet->get_account().get_keys().m_account_address.m_spend_public_key;

  cryptonote::COMMAND_RPC_GET_PBC_INHERIT_STATUS::request  daemon_req{};
  cryptonote::COMMAND_RPC_GET_PBC_INHERIT_STATUS::response daemon_res{};
  daemon_req.principal_spend_pubkey = epee::string_tools::pod_to_hex(spend_pub);

  bool r = m_wallet->invoke_http_json_rpc("/json_rpc", "get_pbc_inherit_status",
                                          daemon_req, daemon_res, tools::wallet2::rpc_timeout);
  if (!r || daemon_res.status != CORE_RPC_STATUS_OK)
  {
    er.code    = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    er.message = "Failed to query daemon for inherit status";
    return false;
  }

  res.has_setup            = daemon_res.has_setup;
  res.heir_address         = daemon_res.heir_address;
  res.request_active       = daemon_res.request_active;
  res.request_height       = daemon_res.request_height;
  res.blocks_remaining     = daemon_res.blocks_remaining;
  res.last_activity_height = daemon_res.last_activity_height;
  res.wait_blocks          = daemon_res.wait_blocks;
  res.current_height       = m_wallet->get_blockchain_current_height();
  return true;
}

bool wallet_rpc_server::on_set_market_ask(const wallet_rpc::COMMAND_RPC_SET_MARKET_ASK::request& req, wallet_rpc::COMMAND_RPC_SET_MARKET_ASK::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  crypto::hash deposit_id;
  if (!epee::string_tools::hex_to_pod(req.deposit_id, deposit_id))
  {
    er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
    er.message = "Invalid deposit_id";
    return false;
  }
  try
  {
    wallet2::pending_tx ptx = m_wallet->create_market_ask_tx(deposit_id, req.ask_price, 0);
    cryptonote::transaction tx = ptx.tx;
    m_wallet->commit_tx(ptx);
    res.tx_hash = epee::string_tools::pod_to_hex(get_transaction_hash(tx));
    return true;
  }
  catch (const std::exception& e)
  {
    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    er.message = std::string("set_market_ask failed: ") + e.what();
    return false;
  }
}

bool wallet_rpc_server::on_get_all_market_asks(const wallet_rpc::COMMAND_RPC_GET_ALL_MARKET_ASKS::request& req, wallet_rpc::COMMAND_RPC_GET_ALL_MARKET_ASKS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  cryptonote::COMMAND_RPC_GET_ALL_MARKET_ASKS::request daemon_req{};
  cryptonote::COMMAND_RPC_GET_ALL_MARKET_ASKS::response daemon_res{};
  bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_all_market_asks", daemon_req, daemon_res, tools::wallet2::rpc_timeout);
  if (!ok) { er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR; er.message = "get_all_market_asks daemon call failed"; return false; }
  res.current_height = daemon_res.current_height;
  for (const auto& d : daemon_res.asks)
  {
    wallet_rpc::COMMAND_RPC_GET_ALL_MARKET_ASKS::ask_entry_t e;
    e.deposit_id           = d.deposit_id;
    e.ask_price            = d.ask_price;
    e.seller_address       = d.seller_address;
    e.created_height       = d.created_height;
    e.principal            = d.principal;
    e.tier                 = d.tier;
    e.unlock_height        = d.unlock_height;
    e.blocks_remaining     = d.blocks_remaining;
    e.claimable_now        = d.claimable_now;
    e.dep_idx              = d.dep_idx;
    e.fee_idx              = d.fee_idx;
    e.has_active_lock      = d.has_active_lock;
    e.lock_id              = d.lock_id;
    e.lock_amount          = d.lock_amount;
    e.lock_buyer_address   = d.lock_buyer_address;
    e.lock_expiry_height   = d.lock_expiry_height;
    e.lock_expected_dep_idx = d.lock_expected_dep_idx;
    e.lock_expected_fee_idx = d.lock_expected_fee_idx;
    res.asks.push_back(std::move(e));
  }
  return true;
}

bool wallet_rpc_server::on_get_market_pending_payout(const wallet_rpc::COMMAND_RPC_GET_MARKET_PENDING_PAYOUT::request& req, wallet_rpc::COMMAND_RPC_GET_MARKET_PENDING_PAYOUT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);
  const crypto::public_key& spend_pub = m_wallet->get_account().get_keys().m_account_address.m_spend_public_key;

  cryptonote::COMMAND_RPC_GET_MARKET_PENDING_PAYOUT::request daemon_req{};
  cryptonote::COMMAND_RPC_GET_MARKET_PENDING_PAYOUT::response daemon_res{};
  daemon_req.seller_pubkey = epee::string_tools::pod_to_hex(spend_pub);

  bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_market_pending_payout", daemon_req, daemon_res, tools::wallet2::rpc_timeout);
  if (!ok) { er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR; er.message = "get_market_pending_payout daemon call failed"; return false; }

  res.found         = daemon_res.found;
  res.payout_amount = daemon_res.payout_amount;
  return true;
}

bool wallet_rpc_server::on_claim_market_payout(const wallet_rpc::COMMAND_RPC_CLAIM_MARKET_PAYOUT::request& req, wallet_rpc::COMMAND_RPC_CLAIM_MARKET_PAYOUT::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);

  // Query pending balance first.
  const crypto::public_key& spend_pub = m_wallet->get_account().get_keys().m_account_address.m_spend_public_key;
  cryptonote::COMMAND_RPC_GET_MARKET_PENDING_PAYOUT::request daemon_req{};
  cryptonote::COMMAND_RPC_GET_MARKET_PENDING_PAYOUT::response daemon_res{};
  daemon_req.seller_pubkey = epee::string_tools::pod_to_hex(spend_pub);

  bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_market_pending_payout", daemon_req, daemon_res, tools::wallet2::rpc_timeout);
  if (!ok || !daemon_res.found || daemon_res.payout_amount == 0)
  {
    er.code    = -32100;
    er.message = "No pending marketplace payout found for this wallet";
    return false;
  }

  try
  {
    wallet2::pending_tx ptx = m_wallet->create_market_payout_claim_tx(daemon_res.payout_amount, req.priority);
    cryptonote::transaction tx = ptx.tx;
    m_wallet->commit_tx(ptx);
    res.tx_hash      = epee::string_tools::pod_to_hex(get_transaction_hash(tx));
    res.payout_amount = daemon_res.payout_amount;
    return true;
  }
  catch (const std::exception& e)
  {
    er.code    = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    er.message = std::string("claim_market_payout failed: ") + e.what();
    return false;
  }
}

bool wallet_rpc_server::on_get_sold_deposits(const wallet_rpc::COMMAND_RPC_GET_SOLD_DEPOSITS::request& req, wallet_rpc::COMMAND_RPC_GET_SOLD_DEPOSITS::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (!m_wallet) return not_open(er);

  const crypto::public_key& spend_pub = m_wallet->get_account().get_keys().m_account_address.m_spend_public_key;
  cryptonote::COMMAND_RPC_GET_SELLER_SOLD_DEPOSITS::request daemon_req{};
  cryptonote::COMMAND_RPC_GET_SELLER_SOLD_DEPOSITS::response daemon_res{};
  daemon_req.seller_pubkey = epee::string_tools::pod_to_hex(spend_pub);

  bool ok = m_wallet->invoke_http_json_rpc("/json_rpc", "get_seller_sold_deposits", daemon_req, daemon_res, tools::wallet2::rpc_timeout);
  if (!ok)
  {
    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
    er.message = "get_seller_sold_deposits daemon call failed";
    return false;
  }

  res.payout_available = daemon_res.payout_available;
  for (const auto& s : daemon_res.sales)
  {
    wallet_rpc::COMMAND_RPC_GET_SOLD_DEPOSITS::sold_entry_t e;
    e.deposit_id    = s.deposit_id;
    e.principal     = s.principal;
    e.sale_price    = s.sale_price;
    e.seller_reward = s.seller_reward;
    e.sale_height   = s.sale_height;
    e.buyer_pubkey  = s.buyer_pubkey;
    res.sales.push_back(std::move(e));
  }
  return true;
}

} // namespace tools
