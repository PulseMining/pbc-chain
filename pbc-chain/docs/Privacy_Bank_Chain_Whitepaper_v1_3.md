# Privacy Bank Chain — Technical Whitepaper

**Version 1.3 — Draft — February 2026**

---

## Abstract

Privacy Bank Chain (PBC) is a privacy-first, CPU-mineable cryptocurrency built on CryptoNote/RandomX technology. Forked from C64 Chain (itself a Monero/Wownero fork), PBC introduces native financial primitives — Term Deposits, Fee Redistribution, and an Inheritance Protocol — all enforced at the consensus level in C++.

No smart contracts. No oracles. No external dependencies. No web interface. No modification of existing UTXO validity. No fixed-rate promises. Every operation is verified by every miner, every block. Every user action is performed through the wallet.

PBC is designed around three principles:

1. **Solvency by construction** — at any block height, total payouts can never exceed reward pool balances.
2. **Claim-based rewards** — users claim their own rewards individually; no mass coinbase payouts.
3. **Deterministic state** — all state is rebuildable from chain history alone; nothing stored in block headers.

*"Private money that works for you."*

**Terminology note:** This document uses the word "pool" in two distinct contexts. **Reward pools** (Term Deposit Pool, Fee Pool, Insurance Pool) are virtual coin balances managed by consensus — they hold funds for depositor rewards, fee redistribution, and insurance. **Mining pools** are groups of miners who combine hashrate to find blocks, as in any PoW cryptocurrency. Context always clarifies which is meant, and the two are entirely independent: mining pools produce blocks, reward pools fund depositor yields.

---

## Table of Contents

1. Motivation
2. Core Design Principles
3. Architecture & Coinbase Structure
4. Transparency Model (What Is Public vs. Private)
5. Mining Pool Compatibility
6. User Interface Design
7. Term Deposits (Variable-Rate Savings)
8. Fee Redistribution (Real Yield)
9. Inheritance Protocol (Dead Man's Switch)
10. Insurance Pool
11. Dynamic Fee Floor
12. Behavioral Privacy & Anti-Censorship
13. Safety Architecture
14. Supply Invariant & Formal Proofs
15. Supply Dynamics
16. Roadmap
17. Competitive Positioning
18. What PBC Deliberately Does NOT Include
19. Consensus Exact Specification
20. Conclusion
21. Risk Summary
Appendix A — Complete Formula Reference
Appendix B — Mandatory Security Tests

---

## 1. Motivation

### 1.1 The DeFi Problem

The current DeFi ecosystem (Aave, Compound, Morpho) runs on smart contracts deployed on Ethereum, Solana, and similar platforms. These systems are:

- **Hackable**: Poly Network ($600M), Wormhole ($320M), Euler Finance ($197M) — billions lost to smart contract exploits.
- **Public**: Every transaction, every balance, every lending position is visible on-chain.
- **Complex**: Audits cost hundreds of thousands of dollars and still miss critical bugs.
- **Oracle-dependent**: DeFi lending relies on external price feeds. Oracle failures cause cascading liquidations.
- **Web-dependent**: Most DeFi requires connecting a wallet to a website — a phishing vector, vulnerable to DNS hijacking, frontend attacks, and compromised CDNs.

### 1.2 The Monero Limitation

Monero is the gold standard for financial privacy. Ring signatures, stealth addresses, and RingCT make transactions untraceable. But Monero is pure digital cash — you can send and receive, nothing more. There are no financial products, no yield mechanisms, no way to put your coins to work.

### 1.3 The PBC Approach

PBC combines Monero-grade privacy with native financial primitives:

- All financial products are coded in C++ at the consensus level.
- No virtual machine, no smart contracts, no attack surface.
- Every miner validates every financial operation — no trusted third party.
- CryptoNote privacy covers standard transfers; financial operations use a hybrid model (see Section 4).
- CPU-only mining (RandomX variant) ensures decentralization.
- All user actions through the wallet CLI/RPC — no web interface, no browser keys.

---

## 2. Core Design Principles

### 2.1 Solvency by Construction

At any block *t*:

```
SUM(all_payouts_t) ≤ pool_balance_t
```

The blockchain can **never** owe more than it has. Every yield, every bonus, every claim is paid from existing reward pools filled by block rewards and fees. If a reward pool is empty, the payout is zero.

### 2.2 Claim-Based Rewards

Users claim their own rewards by submitting a `TX_CLAIM` transaction. There are no mass payouts injected into coinbase transactions. This eliminates:

- Block bloat from fan-out transactions with hundreds of outputs
- Ordering problems (who gets paid first if the reward pool is low?)
- Forced computation at every distribution block
- Top-N starvation (where small depositors are excluded)

### 2.3 Deterministic State — No Header Fields

All protocol state is **rebuildable from chain history alone**. PBC does NOT store custom fields in block headers:

- Reward pool balances are derived by replaying block rewards, deposits, claims, and fees.
- The Global Index is computed by replaying all distribution periods.
- The Inheritance Registry is rebuilt from setup/modify/cancel transactions.

Nodes maintain a local database cache for performance, but this cache is always derivable from the chain and can be rebuilt from scratch at any time.

### 2.4 No UTXO Modification

Once an output is created, its amount, unlock_time, and destination are **immutable** until spent. PBC never modifies the properties of an existing output.

---

## 3. Architecture & Coinbase Structure

### 3.1 Base Layer

| Component | Technology |
|-----------|------------|
| Privacy | CryptoNote v2 (ring signatures, stealth addresses, RingCT for standard TX) |
| Mining | rx/pbc (RandomX variant, CPU-only, ASIC-resistant) |
| Consensus | Proof of Work |
| Difficulty | LWMA-1 (Zawy's Linearly Weighted Moving Average) |
| Block time | 300 seconds (5 minutes) |
| Emission | Smooth exponential decay (no halving cliffs) |
| User interface | Wallet CLI + Wallet RPC only |

### 3.2 Block Reward Split

Let R = base block reward at height *h*. Let F = sum of all transaction fees in the block.

**Actual coinbase outputs (real coins created):**

| Recipient | Share | Outputs | Unlock |
|-----------|-------|---------|--------|
| Miner | 91% of R + 50% of F | 4 vested outputs | 24h / 30d / 60d / 90d |
| Dev fund | 2% of R | 1 output | 24 hours |

**Total coins actually created per block: 93% of R + 50% of F** (5 coinbase outputs).

**Virtual reward pool allocations (coins NOT created as outputs):**

| Reward Pool | Share | Notes |
|------|-------|-------|
| Fee Pool | 3.5% of R + 50% of F | Real yield for depositors |
| Term Deposit Pool | 2.5% of R | Variable-rate deposit bonuses |
| Insurance Pool | 1% of R | Safety buffer |

**Total virtual: 7% of R + 50% of F.**

These 7% of R are accounted for in the emission curve but never minted as coinbase outputs. They exist as consensus-tracked virtual balances for reward pools. When users claim rewards via TX_CLAIM, virtual pool balance is converted into real coins (see Section 3.5).

### 3.3 Why Miners Get 50% of Fees

In standard CryptoNote, miners receive all transaction fees. PBC splits fees 50/50 between the miner and the Fee Pool.

**If miners got 0% of fees**, they would have zero incentive to include transactions → empty blocks → the Fee Pool starves.

**With 50/50**, miners are incentivized to include every fee-paying transaction (they keep half). The other half flows to the Fee Pool, creating genuine yield from network activity.

### 3.4 Emission Accounting

The emission curve calculates a theoretical block reward R, but only 93% of R + 50% of F is minted as coinbase outputs. The remaining 7% of R + 50% of F goes to virtual reward pools.

**Emission tracking rule:**

```
already_generated_coins += R  (the FULL theoretical reward)
```

This is essential. In standard CryptoNote, `already_generated_coins` is used to calculate the next block reward: `R = (MONEY_SUPPLY − already_generated_coins) >> EMISSION_SPEED_FACTOR`. PBC counts the full R because the virtual pool allocations are part of the economic supply — they will eventually be claimed by depositors via TX_CLAIM and enter circulation as real coins.

```
theoretical_supply = Σ R_h  (sum of all theoretical rewards)
actual_coinbase_minted = Σ (0.93 × R_h + 0.50 × F_h)
virtual_pool_allocated = Σ (0.07 × R_h + 0.50 × F_h)

Invariant: theoretical_supply = coinbase_minted + pool_balances
           + claimed_rewards + total_destroyed
```

**Deflationary mechanism:** PBC's only source of deflation is **Insurance Pool overflow** — when the Insurance Pool exceeds INSURANCE_CAP, the excess is permanently destroyed. This is modest, predictable, and requires no user action. PBC does not need aggressive deflation to be valuable — the value comes from privacy, real yield, and trustless inheritance.

### 3.5 TX_CLAIM: How Virtual Pools Become Real Coins

`TX_CLAIM` is a special transaction type that creates coins from a virtual pool balance.

**Why TX_CLAIM is special:**

In standard CryptoNote with RingCT, every transaction must satisfy:

```
Σ(input_amounts) = Σ(output_amounts) + fee
```

TX_CLAIM violates this rule because the reward creates new coins:

```
Σ(output_amounts) = Σ(input_amounts) − fee + reward
```

This is handled by making **the reward amount public** (not hidden by RingCT). The reward output uses an RCT hybrid format with mask=0 (see Section 3.5 TX_CLAIM format). See Section 4 for details.

**Structure of TX_CLAIM:**

```
Inputs:
  - At least one standard input (ring signature)
    → Proves the claimer owns the deposit
    → Can be ANY unspent output (even dust)
    → The input amount is returned as change

Outputs:
  - Change output (input amount minus fee) — RingCT hidden
  - Reward output (newly created coins) — AMOUNT PUBLIC

Consensus validation:
  1. Verify the input belongs to an address with an eligible deposit
  2. Calculate entitled reward using Global Index
  3. Verify reward ≤ reward_pool_balance × (w / Σw)
  4. Allow output_sum = input_sum − fee + reward
  5. Debit virtual pool balance by reward amount
  6. Verify the public reward amount matches calculated entitlement

Special rule:
  output_sum > input_sum is ONLY valid for TX_CLAIM
  (all other TX types enforce output_sum ≤ input_sum)
```

**RingCT compatibility — canonical verification equation:**

```
Σ(C_input) + reward_amount × H = Σ(C_output) + fee × H
```

This reads: "the inputs plus the authorized coin creation (reward) fund the outputs plus the fee." Both `reward_amount` and `fee` are public scalars stored in the transaction. This is the **only** form implementations must use. The algebraically equivalent form `Σ(C_input) = Σ(C_output) + fee×H − reward×H` is correct mathematically but dangerous to implement because subtraction on group elements can mask bugs; the additive form above makes the verification logic explicit and unambiguous.

**TX_CLAIM exact RingCT format (PBC-defined, self-contained):**

PBC defines its own TX_CLAIM format. The behavior below is **not inherited from Monero coinbase handling** — it is specified explicitly by PBC consensus rules, independent of any external implementation detail.

```
Reward output format:
  The reward output is an RCT HYBRID output:
    - Commitment: C_reward = reward_amount × H + 0 × G
    - The blinding factor (mask) is ZERO.
    - The amount is stored in CLEARTEXT in tx_extra (not encrypted via ECDH).
    - The output IS part of the RingCT transaction graph (it has a commitment),
      but its mask is publicly known to be zero.
  
  This is NOT a "non-RCT output" and NOT a "coinbase-style output."
  It is a standard RCT output whose mask happens to be zero, explicitly
  defined by PBC consensus.

Canonical uint64 → Ed25519 scalar conversion:
  When computing `reward_amount × H`, `fee × H`, or `deposit_amount × H`,
  the uint64 amount MUST be converted to a 32-byte Ed25519 scalar using
  the following canonical procedure:

    1. Write the uint64 value as 8 bytes in LITTLE-ENDIAN byte order.
    2. Zero-pad to 32 bytes (append 24 zero bytes).
    3. Use the resulting 32-byte array directly as a scalar for
       Ed25519 scalar-point multiplication.

  No modular reduction is needed: uint64 max (2^64 - 1 ≈ 1.8×10^19) is
  far below the Ed25519 curve order l (≈ 7.2×10^75). The scalar is
  guaranteed to be in canonical form.

  In C++, this is equivalent to:
    // amount_to_scalar: uint64 → ec_scalar (32 bytes)
    void amount_to_scalar(ec_scalar &s, uint64_t amount) {
        memset(&s, 0, 32);
        memcpy(&s, &amount, 8);  // little-endian on LE platforms
        // On big-endian platforms: store bytes in LE order explicitly
    }

  CONSENSUS RULE: All implementations MUST use this exact conversion.
  Any alternative encoding (big-endian, varint, modular reduction,
  or different zero-padding) will produce a different curve point,
  causing commitment verification failure and chain split.

  This same conversion applies to ALL public-amount commitments in PBC:
    - TX_CLAIM:         reward_amount × H
    - TX_TERM_DEPOSIT:  deposit_amount × H
    - TX_TERM_WITHDRAW: returned_amount × H, penalty_amount × H
    - All TX types:     fee × H

Range proof rules:
  The reward output has NO Bulletproof+ range proof.
  Justification: the amount is public and validated by consensus to be
  ≤ pool_balance × (w / Σw). A range proof would add ~600 bytes
  for zero security benefit.
  
  Change outputs use standard Bulletproof+ range proofs (amounts hidden).
  
  CONSENSUS RULE: A transaction with tx_type = TX_CLAIM that includes
  a range proof on the reward output is INVALID.

Commitment balance verification:
  Σ(C_input) + reward_amount × H = Σ(C_output) + fee × H
  
  Where:
    C_input:        standard RingCT commitments (blinded), from ring signatures
    C_output:       all outputs including reward (reward has mask=0, change is blinded)
    fee:            public uint64, stored in transaction prefix
    reward_amount:  public uint64, stored in tx_extra
    
  Since C_reward = reward_amount × H (mask=0), expanding Σ(C_output):
    Σ(C_input) + reward_amount × H = Σ(C_change) + reward_amount × H + fee × H
  Simplifying:
    Σ(C_input) = Σ(C_change) + fee × H
  This is the standard RingCT balance equation for the hidden portion.
  The verifier checks BOTH the full equation AND that reward_amount
  matches the calculated entitlement from the Global Index.

Spending reward outputs later:
  When spent in a future TX_STANDARD, the reward output's commitment
  (with mask = 0) enters the ring as a normal decoy-eligible output.
  The spender knows the mask is 0 and constructs their pseudo-output
  accordingly. No special handling is needed by the network — the
  output looks like any other RCT output in the UTXO set.
```

**Solvency guarantee:** The reward is bounded by the reward pool balance. Even if every depositor claimed simultaneously, total claims ≤ total reward pool balance (see Section 14 for formal proof).

### 3.6 Vesting (Anti-Dump)

Every miner's block reward is split into 4 outputs with staggered unlock times:

| Portion | Unlock delay | Blocks |
|---------|-------------|--------|
| 25% (of miner share) | ~24 hours | 288 |
| 25% (of miner share) | ~30 days | 8,640 |
| 25% (of miner share) | ~60 days | 17,280 |
| 25% (of miner share) | ~90 days | 25,920 |

Dev fund: single output, unlocks after ~24 hours. Vesting is consensus-enforced.

### 3.7 Tokenomics

| Parameter | Value |
|-----------|-------|
| Max supply | TBD (target: limited, sub-20M) |
| Algorithm | rx/pbc (RandomX variant) |
| Block time | 5 minutes |
| Emission speed factor | TBD |
| Miner share | 91% of R + 50% of F |
| Dev fund | 2% of R (consensus-enforced) |
| Reward pool allocations | 7% of R + 50% of F (virtual) |

### 3.8 Transaction Types

| Type | Code | Purpose | Amount visibility |
|------|------|---------|-------------------|
| TX_STANDARD | 0x00 | Normal transfer | Hidden (RingCT) |
| TX_TERM_DEPOSIT | 0x01 | Lock coins | Deposit amount PUBLIC |
| TX_TERM_WITHDRAW | 0x02 | Early withdrawal | Returned amount PUBLIC |
| TX_CLAIM | 0x03 | Claim rewards | Reward amount PUBLIC |
| TX_HEARTBEAT | 0x04 | Timer reset | Fee only (no amounts) |
| TX_INHERITANCE_SETUP | 0x05 | Configure heir | No amounts |
| TX_INHERITANCE_MODIFY | 0x06 | Modify/cancel | No amounts |

### 3.9 Transaction Format: RCT vs. Public Amounts

PBC uses two transaction formats:

**Standard RCT format (TX_STANDARD):** Identical to Monero. All amounts hidden via Pedersen commitments. Ring signatures hide the sender. Stealth addresses hide the receiver. Full privacy.

**Public-amount format (TX_TERM_DEPOSIT, TX_TERM_WITHDRAW, TX_CLAIM):** These transactions use a modified format where the **operation-specific amounts are public** (stored as clear integers, not commitments), while the **identity of the transactor remains private** (ring signatures still used on inputs).

```
TX_TERM_DEPOSIT:
  Inputs: standard ring signature inputs (identity hidden)
  Outputs:
    - Deposit output: amount PUBLIC (mask=0), locked until unlock_height
    - Change output: amount HIDDEN (RingCT commitment, blinded)
  Balance: Σ(C_input) = Σ(C_output) + fee × H
    Where C_deposit = deposit_amount × H (mask=0), included in Σ(C_output)

TX_CLAIM:
  Inputs: standard ring signature inputs (identity hidden)
  Outputs:
    - Reward output: amount PUBLIC (mask=0, newly created from reward pool)
    - Change output: amount HIDDEN (RingCT commitment, blinded)
  Balance: Σ(C_input) + reward_amount × H = Σ(C_output) + fee × H
    Canonical form: creation on left, consumption on right.

PBC uses a hybrid RCT approach for financial operations: the operation amount is public (stored as a cleartext integer with commitment mask=0), while the transactor's identity remains private (ring signatures on inputs). When a deposit matures and the coins are spent in a standard TX, they enter the full RingCT privacy set with a new blinding factor.

---

## 4. Transparency Model (What Is Public vs. Private)

> **Summary: We know HOW MUCH. We never know WHO.**
>
> Financial operation amounts (deposits, claims) are visible on-chain because the consensus needs them for math (sqrt, index calculations). But the identity of the user performing the operation is always hidden behind ring signatures. An observer sees "someone deposited 1,000 PBC for 90 days" but cannot determine which wallet, and cannot link that deposit to a future claim. This is strictly better than all existing DeFi systems where both amounts AND identities are fully public.

### 4.1 Why Some Amounts Must Be Public

PBC inherits CryptoNote's privacy features (ring signatures, stealth addresses, RingCT) for standard transfers. However, financial operations require consensus to perform arithmetic on amounts, which is incompatible with fully homomorphic encryption in RingCT.

**The fundamental constraint:** To calculate `weight = sqrt(amount)`, the consensus must know `amount`. You cannot compute sqrt() on a Pedersen commitment without revealing the value.

This means:

| Operation | Consensus needs to know | Therefore |
|-----------|-------------------------|-----------|
| Weight calculation | Deposit amount | Deposit amount is PUBLIC |
| Reward validation | Reward amount, weight, index | Reward amount is PUBLIC |
| Penalty calculation | Deposit amount × 2% | Already public from deposit |
| Standard transfer | Nothing | Amounts HIDDEN (RingCT) |

### 4.2 The Privacy Trade-Off — Honestly Stated

**What is ALWAYS private (ring signatures + stealth addresses):**

- WHO deposits (identity hidden by ring signature on inputs)
- WHO claims (identity hidden by ring signature on inputs)
- WHO inherits (stealth address for heir)
- All standard transfer amounts and parties

**What is PUBLIC (required by consensus arithmetic):**

- HOW MUCH is deposited in each TX_TERM_DEPOSIT
- HOW MUCH reward is claimed in each TX_CLAIM
- HOW MUCH is returned in each TX_TERM_WITHDRAW
- Transaction type (tx_extra tag)
- Inheritance timeout duration (consensus needs it)
- Heir stealth address (public one-time address, not linkable to heir's wallet)

**What is NOT linkable:**

- An observer can see "someone deposited 1000 PBC for 90 days" but cannot determine WHICH address did it (ring signature hides the real signer among decoys).
- An observer cannot link a deposit to a later claim (different ring signatures, different key images).
- An observer can see "someone configured inheritance with 365-day timeout" but cannot identify the owner or the heir's real wallet.
- An observer can link an inheritance setup to its trigger event (same stealth heir address), but still cannot identify either party.
- The number and amounts of deposits are public aggregate data, but the mapping "deposit X belongs to person Y" is hidden.

### 4.3 Comparison With Existing Systems

| System | Transfer privacy | Financial op amounts | Financial op identity |
|--------|-----------------|---------------------|----------------------|
| Monero | Full (RingCT) | N/A | N/A |
| Ethereum DeFi | None | Public | Public |
| Zephyr Protocol | Partial | Public | Public |
| **PBC** | **Full (RingCT)** | **Public** | **Private (ring sig)** |

PBC provides a **unique middle ground**: standard transfers have full Monero-grade privacy. Financial operations reveal amounts (necessary for consensus math) but hide identities (ring signatures still work).

### 4.4 Could This Be Improved?

Theoretically, zero-knowledge proofs could enable consensus verification of sqrt() computations without revealing amounts. This would require:

- Custom ZK circuits for sqrt and index arithmetic
- Significant cryptographic R&D
- Much larger proof sizes and verification times

This is considered a possible **Phase 3+ research direction**, not a v1.0 feature. The current model is honest, auditable, and secure.

---

## 5. Mining Pool Compatibility

### 5.1 Overview

PBC is fully compatible with mining pools. All financial features (deposits, claims, inheritance) are **user-side operations** performed through the wallet. Mining pools only interact with the coinbase structure, which is handled entirely by the daemon.

### 5.2 How Pool Mining Works

```
┌──────────────┐    getblocktemplate    ┌──────────────┐
│  PBC Daemon   │ ◄──────────────────── │  Pool Server  │
│  (pbcd)       │ ────────────────────► │  (stratum)    │
│               │    block template     │               │
│  Enforces:    │    with correct       │  Distributes: │
│  - 91% miner  │    coinbase           │  - Shares     │
│  - 2% dev     │                       │  - Payouts    │
│  - 4 vested   │    submitblock        │               │
│    outputs    │ ◄──────────────────── │               │
│  - Pool alloc │    (when nonce found) │               │
└──────────────┘                        └──────────────┘
```

**Step 1:** Pool server calls `getblocktemplate` on the PBC daemon.

**Step 2:** The daemon returns a block template containing the **correct coinbase structure** (5 outputs: 4 miner vested + 1 dev fund). Virtual allocations are tracked internally.

**Step 3:** Pool distributes work via stratum (identical to Monero — no PBC changes).

**Step 4:** Miner finds valid nonce → pool submits block.

**Step 5:** Daemon validates coinbase structure. Wrong structure → rejected network-wide.

### 5.3 What the Pool Needs to Know

**Nothing about PBC financial features.** The pool interacts only with `getblocktemplate` / `submitblock`:

| Pool responsibility | Daemon responsibility |
|---------------------|----------------------|
| Set pool payout address | Construct correct coinbase |
| Distribute work via stratum | Enforce block reward split |
| Track miner shares | Track virtual pool balances |
| Pay miners from pool wallet | Validate TX_CLAIM coin creation |

### 5.4 Coinbase Structure for Pools

```
Coinbase transaction:
  Output 0: pool_address, (91%R + 50%F) × 0.25, unlock: +288 blocks
  Output 1: pool_address, (91%R + 50%F) × 0.25, unlock: +8,640 blocks
  Output 2: pool_address, (91%R + 50%F) × 0.25, unlock: +17,280 blocks
  Output 3: pool_address, (91%R + 50%F) × 0.25, unlock: +25,920 blocks
  Output 4: dev_address,  2%R,                   unlock: +288 blocks

  Total outputs: 5
  Total coins created: 93%R + 50%F
  Not created: 7%R + 50%F (virtual reward pools)
```

### 5.5 Pool Vesting Management

**PPLNS (recommended):** Pool accumulates funds as outputs unlock (25% after 24h, etc.) and pays miners from unlocked balance. Same model as C64 Chain pools.

**PPS:** Pool pays immediately from reserves, absorbing vesting delay risk. Operator's business decision.

### 5.6 Stratum Protocol Compatibility

No changes needed. Existing Monero-fork pool software requires **zero modification** to the stratum layer. Only change: point the pool daemon at `pbcd`.

### 5.7 Feature Compatibility Matrix

| Feature | Affected by pools? | Why |
|---------|-------------------|-----|
| Block reward split | No | Daemon enforces in coinbase |
| Vesting | Payout timing only | Pool manages unlock schedule |
| Term Deposits | No | User wallet feature |
| Fee Redistribution | No | 50% F auto-split in coinbase |
| Global Index | No | Computed from virtual balances |
| TX_CLAIM | No | User wallet operation |
| Insurance Pool | No | Virtual, consensus-enforced |
| Dynamic Fee Floor | No | Pure math |
| Inheritance | No | User wallet feature |

### 5.8 Solo Mining

Identical coinbase structure. Miner's address replaces pool's address.

---

## 6. User Interface Design

### 6.1 Principle: Wallet-Only Interaction

- **Wallet CLI** (`pbc-wallet-cli`): Interactive command-line wallet.
- **Wallet RPC** (`pbc-wallet-rpc`): JSON-RPC server.

No web application, no browser extension, no hosted frontend.

### 6.2 Why No Web Interface

| Attack Vector | Web DeFi | PBC |
|---------------|----------|-----|
| Phishing sites | Common | Impossible — no website to clone |
| DNS hijacking | Redirects | Impossible — local wallet |
| Compromised frontend | Malicious JS | Impossible — compiled binary |
| Private key exposure | Browser memory | Keys never leave wallet file |

### 6.3 Wallet CLI Commands

**Term Deposits:**

```
deposit <amount> <days>
    Lock UNLOCKED coins for a fixed duration.
    Vested (locked) outputs CANNOT be deposited — consensus rejects.
    Eligible for rewards at the NEXT distribution period.
    Example: deposit 1000 90

deposit_status
    Display all active deposits with accrued rewards.

    Example output:
    === PBC DEPOSIT STATUS ===

    Deposit #1:  1,000.00 PBC locked for 90 days
      Locked at block:    4,500 (2026-03-15)
      Unlocks at block:   30,420 (2026-06-13)
      Eligible since:     period 7 (block 5,040)
      Time remaining:     62 days
      Weight (sqrt):      31.62 (effective: 41.11 with 1.3× duration)
      Entry index (I₀):   0.004821
      Current index (Iₙ): 0.005934
      Accrued reward:     45.73 PBC (claimable now)

    Total locked:        1,500.00 PBC
    Network deposits:    847
    Term Deposit Pool:   12,450.30 PBC
    Lock ratio:          34.2%

    Note: deposit amount is PUBLIC on-chain.
    Your identity as depositor remains private (ring signature).

claim <deposit_id>
    Claim accrued rewards. Sends TX_CLAIM.
    Note: reward amount is PUBLIC on-chain.

claim_all
    Claim all accrued rewards.

withdraw_deposit <deposit_id>
    Early withdrawal: 98% returned, 2% penalty, rewards forfeited.
```

**Inheritance:**

```
inheritance_setup <heir_address> <timeout_days>
    Configure inheritance (minimum 180 days).

inheritance_status
    Show configuration, last activity, timer expiry.

inheritance_modify <new_heir_address> <new_timeout_days>
inheritance_cancel
heartbeat
    Reset timer. Wallet adds random delay (see Section 12.7).
```

**Network:**

```
network_pools
    Reward pool balances, lock ratio, global indices, fee floor.
```

### 6.4 Wallet RPC Endpoints

| Method | Description |
|--------|-------------|
| `create_deposit` | Create a term deposit |
| `get_deposits` | List active deposits with accrued rewards |
| `claim_rewards` | Claim rewards for a deposit |
| `claim_all_rewards` | Claim all accrued rewards |
| `withdraw_deposit` | Early withdrawal |
| `setup_inheritance` | Configure inheritance |
| `get_inheritance_status` | Current config |
| `modify_inheritance` | Modify config |
| `cancel_inheritance` | Remove config |
| `send_heartbeat` | Reset timer (with random delay) |
| `get_network_pools` | Pool balances and stats |

### 6.5 Node RPC Endpoints (Read-Only, Public)

| Method | Description |
|--------|-------------|
| `get_pool_balances` | Deposit Pool, Fee Pool, Insurance Pool (virtual) |
| `get_lock_stats` | Total locked, ratio, active count |
| `get_global_indices` | Current deposit and fee indices |
| `get_fee_floor` | Current dynamic minimum fee |
| `get_supply_info` | Minted, destroyed (insurance overflow), effective supply |

---

## 7. Term Deposits (Variable-Rate Savings)

### 7.1 Concept

Users lock UNLOCKED coins for a fixed duration (3 to 12 months). During the lock period, they accrue rewards funded by the Term Deposit Pool. Rewards are claimed individually at any time via `TX_CLAIM` (Section 3.5). No mass payouts, no starvation.

**Only unlocked coins can be deposited.** Vested miner outputs (locked by consensus) cannot serve as inputs for TX_TERM_DEPOSIT until their unlock_time has passed. This is enforced at the consensus level — a TX_TERM_DEPOSIT referencing a locked input is rejected. This means miners must wait for their vested outputs to unlock before depositing them.

### 7.2 The Global Index Mechanism

**Definitions:**

```
I      = Global Deposit Index (starts at 0 at genesis)
ΔP     = new coins added to Term Deposit Pool since last period
Σw     = sum of effective_weight for ALL eligible deposits
```

**Index update (every 720 blocks, ~2.5 days):**

```
I_{t+1} = I_t + (ΔP / Σw)
```

**Exact period boundary rules (consensus-critical):**

```
Period k spans blocks [k×720, (k+1)×720 − 1] inclusive.

  Period 0: blocks [0, 719]
  Period 1: blocks [720, 1439]
  Period 2: blocks [1440, 2159]
  ...

ΔP_k = sum of all Term Deposit Pool inflows during period k
       (from blocks k×720 to (k+1)×720 − 1 inclusive)

Σw_k = sum of effective_weight for all deposits where:
       - created_height < k×720  (created BEFORE this period started)
       - unlock_height > k×720   (not yet expired at period start)

Index update is applied at the FIRST block of the next period:
  At block (k+1)×720: I_{k+1} = I_k + (ΔP_k / Σw_k)

If Σw_k = 0: ΔP_k accumulates in the pool, no index advancement.
```

These rules eliminate all off-by-one ambiguity. Every node computes identical values.

**Per-deposit tracking:**

When a deposit becomes eligible (see Section 7.6):
- It records its **entry index** I₀
- Its effective weight is w = sqrt(amount) × duration_multiplier

**Claiming rewards:**

```
reward = w × (I_now − I₀)

Capped: actual_reward = min(reward, deposit_pool_balance × (w / Σw))
```

After claiming, I₀ is updated to I_now (no double-counting).

### 7.3 Formal Proof: Global Index Guarantees Solvency

**Theorem:** The sum of all claimable rewards at any time ≤ total reward pool inflow.

**Proof:**

For any single distribution period *t* with inflow ΔP_t and active weight Σw_t:

```
Index increment: δI_t = ΔP_t / Σw_t

Sum of all rewards accrued during period t:
  = Σ(w_i × δI_t)  for all eligible deposits i
  = δI_t × Σw_t
  = (ΔP_t / Σw_t) × Σw_t
  = ΔP_t                    ■
```

The total rewards distributed per period **exactly equals** the reward pool inflow for that period. This holds regardless of the number of deposits, their amounts, or when they were created.

**Across all periods:**

```
Total claimable = Σ_t (ΔP_t) = total reward pool inflow
```

Since total reward pool inflow = reward_pool_balance + already_claimed:

```
Total remaining claimable = reward_pool_balance  ■
```

**Edge case — early withdrawals:** Forfeited rewards (from early withdrawals) remain in the reward pool balance but are not accounted for in any deposit's (I_now − I₀). They form a **solvency buffer** — extra coins in the reward pool that no one is entitled to claim. This makes the cap (`min(reward, reward_pool × w/Σw)`) less likely to ever bind.

**Edge case — Locked Supply Multiplier active:** When `effective_ΔP < ΔP`, only effective_ΔP is distributed via the index. The difference `ΔP − effective_ΔP` stays in the reward pool as buffer. Total claimable = Σ(effective_ΔP_t) ≤ Σ(ΔP_t) = total inflow. Solvency holds with an even larger buffer.

### 7.4 Example

```
Block 0-720 (Period 1):
  Deposit Pool receives 500 PBC (virtual, from 2.5% of block rewards)
  Active eligible deposits:
    Alice: 10,000 PBC × 1.0 (30-day) → w = sqrt(10000) × 1.0 = 100.0
    Bob:    1,000 PBC × 1.3 (90-day) → w = sqrt(1000) × 1.3 = 41.1
  Σw = 141.1
  Index: I₁ = 0 + (500 / 141.1) = 3.543

  Alice accrued: 100.0 × 3.543 = 354.3 PBC
  Bob accrued:    41.1 × 3.543 = 145.6 PBC
  Sum: 354.3 + 145.6 = 499.9 PBC ≤ 500 PBC ✓ (rounding)

Block 720-1440 (Period 2):
  Deposit Pool receives 490 PBC
  Charlie joins mid-period 1 → eligible at period 2 start (deferred)
    Charlie: 2,500 PBC × 1.6 (180-day) → w = sqrt(2500) × 1.6 = 80.0
  Σw = 100.0 + 41.1 + 80.0 = 221.1
  Index: I₂ = 3.543 + (490 / 221.1) = 5.759

  Alice claims: 100.0 × (5.759 − 0) = 575.9 PBC (both periods)
    → TX_CLAIM: 575.9 PBC reward (PUBLIC), Term Deposit Pool debited by 575.9
  Bob claims:    41.1 × (5.759 − 0) = 236.7 PBC
  Charlie claims:  80.0 × (5.759 − 3.543) = 177.3 PBC (period 2 only)
  Sum: 575.9 + 236.7 + 177.3 = 989.9 PBC ≤ 990 PBC ✓
```

### 7.5 Duration Tiers & Multipliers

PBC offers 5 deposit durations from 1 month to 1 year:

```
effective_weight = sqrt(amount) × duration_multiplier

   30 days (~1 month):   1.0×
   90 days (~3 months):  1.3×
  180 days (~6 months):  1.6×
  270 days (~9 months):  1.8×
  365 days (~12 months): 2.0×
```

The multiplier curve is progressive with diminishing marginal returns:

```
Duration   Multiplier   Marginal increase
 30 days    1.0×         —
 90 days    1.3×        +0.3 (per +60 days)
180 days    1.6×        +0.3 (per +90 days)
270 days    1.8×        +0.2 (per +90 days)
365 days    2.0×        +0.2 (per +95 days)
```

This means longer locks are always rewarded more, but the incentive to extend from 9 to 12 months is smaller than 1 to 3 months. No cliff effects.

**Example:**

1000 PBC deposited at each tier:

```
 30d: sqrt(1000) × 1.0 = 31.6 effective weight
 90d: sqrt(1000) × 1.3 = 41.1
180d: sqrt(1000) × 1.6 = 50.6
270d: sqrt(1000) × 1.8 = 56.9
365d: sqrt(1000) × 2.0 = 63.2
```

### 7.6 Eligibility Rules (Anti-Gaming)

**RULE: Only unlocked coins.** TX_TERM_DEPOSIT inputs must have `unlock_time ≤ current_height`. Vested outputs, outputs from other deposits that haven't matured, or any locked output is rejected by consensus.

**RULE: Deferred eligibility.** A deposit becomes eligible at the **start of the distribution period following its creation**. Never during the period of creation.

```
Distribution periods: blocks [0-719], [720-1439], [1440-2159], ...

Example:
  - Alice deposits at block 500 (within period 0)
  - NOT eligible during period 0
  - Eligible at block 720 (start of period 1)
  - Entry index I₀ = I at start of period 1
```

**RULE: Claims do not restart eligibility.** After claiming, I₀ updates to I_now, deposit stays eligible.

**Anti-gaming analysis — "deposit-claim-withdraw" attack:**

```
Attacker deposits 10,000 PBC at block 700 (end of period 0).
  - Creation fee: 1 PBC → Insurance Pool
  - Eligible at block 720 (period 1)
  - Claims at block 1440 (end of period 1): 1 period of rewards
  - Early withdraws at block 1441:
      Penalty: 2% of 10,000 = 200 PBC → Insurance Pool
      Forfeited rewards: 0 (already claimed)

  Cost:  1 (fee) + 200 (penalty) = 201 PBC
  Gain:  w = sqrt(10000) × 1.0 = 100
         Assume existing Σw = 241.1, reward pool ΔP = 500
         New Σw = 341.1
         reward = 100 × (500 / 341.1) = 146.6 PBC

  Net: 146.6 − 201 = −54.4 PBC LOSS ✗
```

**Edge case — very low Σw (early chain):**

```
Attacker is the ONLY depositor. Σw = 100 (just them).
  reward = 100 × (500 / 100) = 500 PBC per period
  Cost for 1 period: 201 PBC
  Net: 500 − 201 = +299 PBC PROFIT ✓

BUT: This requires early withdrawal (loses 2% + forfeits rewards).
If the attacker just HOLDS to maturity (30 days = ~12 periods):
  reward = 500 × 12 = 6000 PBC over 30 days
  Cost: 1 PBC (creation fee only, no early withdrawal penalty)
  Net: +5999 PBC

This is NOT an attack — it's the INTENDED BEHAVIOR.
If you're the only person willing to lock coins for 30 days,
you earn all the reward pool's yield. This incentivizes early adoption.
As more depositors join, rewards dilute naturally via Σw.
```

The system is self-balancing: high rewards when few deposit → more people deposit → rewards decrease → equilibrium.

### 7.7 Additional Safety Rules

**RULE: Reward pool solvency.**

```
actual_reward = min(calculated_reward, deposit_pool_balance × (w / Σw))
```

If the reward pool is empty, rewards are zero. Users still get their locked coins back at maturity.

**RULE: Anti-whale (sqrt).** Weight = sqrt(amount). A whale with 1M PBC has weight 1000, not 1,000,000. Someone with 1K PBC has weight 31.6. Ratio: 31.6× (not 1000×).

**RULE: Locked Supply Multiplier.**

```
if locked_ratio > 0.60:
    rate_modifier = 1.0 − ((locked_ratio − 0.60) / 0.40)
    effective_ΔP = ΔP × max(rate_modifier, 0.10)
```

Above 60% locked, only `effective_ΔP` is distributed via the index. The difference `ΔP − effective_ΔP` stays in the reward pool as a solvency buffer. At 100% locked: only 10% of ΔP is distributed.

**RULE: Minimum deposit: 10 PBC.**

**RULE: Maximum 10 active deposits per address.**

**RULE: Anti-sybil fee: 1 PBC per TX_TERM_DEPOSIT → Insurance Pool.**

**RULE: Forfeited rewards stay in reward pool.** Early withdrawal forfeits all accrued rewards. These coins remain in the reward pool balance, forming a solvency buffer that benefits remaining depositors (the buffer makes the cap less likely to bind, but does NOT increase future index increments — only new ΔP from block rewards does that).

### 7.8 Early Withdrawal

- 100% of accrued rewards forfeited (stay in reward pool as buffer)
- 2% penalty on deposited amount → Insurance Pool
- 98% returned immediately (TX_TERM_WITHDRAW, amount PUBLIC)
- Deposit removed from Σw immediately

---

## 8. Fee Redistribution (Real Yield)

### 8.1 Mechanism

The Fee Pool uses an **identical Global Index** with its own separate index:

```
FI_{t+1} = FI_t + (ΔF / Σw)

Where ΔF = 3.5% of block rewards + 50% of tx fees accumulated during the period
```

The same deposit weights (Σw) are used for both indices. The same eligibility rules apply (deferred, anti-gaming). Same solvency proof applies.

Depositors receive **two yield streams** claimed via TX_CLAIM:

1. From the Term Deposit Pool (2.5% of R per block)
2. From the Fee Pool (3.5% of R + 50% of F per block)

### 8.2 Why This Creates Real Yield

The Fee Pool is funded by **actual network usage** — 50% of transaction fees. This is genuine economic activity, not token inflation. The 3.5% of R provides baseline inflow during low-activity periods.

---

## 9. Inheritance Protocol (Dead Man's Switch)

### 9.1 Concept

Users configure an heir (stealth address) and an inactivity timeout (minimum 6 months). If no wallet activity occurs within the timeout, all funds are automatically transferred to the heir. First trustless on-chain inheritance for a privacy blockchain.

### 9.2 Mechanism

**Setup:** TX_INHERITANCE_SETUP with heir_address and timeout_blocks (min 52,560 ≈ 6 months).

**Activity:** Any signed TX resets the counter. TX_HEARTBEAT is a fee-only reset.

**Trigger height index:** When an inheritance is configured or activity resets the timer, the node computes:

```
trigger_height = last_activity_height + timeout_blocks
```

This trigger_height is stored in a local index (derived from chain, not in headers). The index is sorted by trigger_height.

**Block validation (efficient — NOT O(N)):**

```
At each block h:
  for each inheritance where trigger_height == h:
    verify no activity since last_activity_height
    force-withdraw all deposits (2% penalty, rewards forfeited)
    create transfer of all owner outputs to heir_address
```

Only inheritances whose trigger_height matches the current block are checked. This is O(1) amortized per block (typically 0 triggers), not O(N) over all registered inheritances. The index is rebuilt from chain on sync/reorg.

**Activity reset:**

```
When owner signs any TX at height h:
  old_trigger = last_activity + timeout_blocks
  remove from index at old_trigger
  new_trigger = h + timeout_blocks
  insert into index at new_trigger
  last_activity = h
```

**Modification:** Owner signature required. Heir has zero control.

### 9.3 Privacy of Inheritance

**What is private:**

- The identity of the owner configuring inheritance (ring signature on TX_INHERITANCE_SETUP inputs)
- The identity of the heir (stealth address — one-time address generated from heir's public view key)
- The link between the owner's real wallet and the heir's real wallet

**What is public:**

- The fact that an inheritance was configured (TX type visible in tx_extra)
- The timeout duration (consensus needs it to compute trigger_height)
- When the inheritance triggers (deterministic from chain)
- The stealth heir address in the setup transaction

**What is NOT linkable:**

- An observer sees "someone configured inheritance with timeout 365 days" but cannot determine WHO (ring signature)
- The heir's stealth address is a one-time address — it cannot be linked to the heir's main wallet without the heir's private view key
- However, the **same stealth address** appears in both the setup TX and the triggered transfer. An observer can link the setup to the trigger event (same config), but still cannot identify either party.

**Practical privacy:**

The heir shares their public view key with the owner offline (in person, encrypted message, etc.). The wallet generates a stealth address from this key. This is the same mechanism Monero uses for all transactions — the heir address on-chain reveals nothing about the heir's identity to anyone except the heir themselves.

**Comparison:** In traditional inheritance (lawyers, notaries), BOTH parties' identities, the amounts, and the conditions are fully known to third parties. In PBC, only the existence of an inheritance configuration and the timeout are public. Identities remain hidden.

### 9.4 Safety Rules

- Minimum timeout: 6 months (52,560 blocks)
- Heir cannot accelerate
- Inherited outputs preserve vesting locks
- Active deposits: force-withdrawn (2% penalty), 98% to heir
- One config per address; registry pruned on trigger/cancel
- Heir address is a stealth address (one-time, not linkable to heir's wallet)
- Owner identity hidden by ring signature
- Trigger check is O(1) per block via trigger_height index (not O(N) scan)
- Reorg-safe: registry and trigger index rebuilt from chain

**Structural DoS protection:** The inheritance registry cannot grow unboundedly because: (1) each setup requires a real TX with fee (cost barrier), (2) exactly 1 config per address — setting a new one replaces the old one, (3) triggered and cancelled configs are pruned from the registry, (4) rate limit of 1 inheritance TX per 288 blocks per address, (5) the trigger_height index ensures per-block processing cost is O(1) regardless of registry size. No global cap is needed because the registry is bounded by the number of funded addresses, each of which paid at least one fee to register.

### 9.5 Edge Cases

**Heir wallet lost?** Coins unspendable. Same as any lost address.

**User alive but lost keys?** Inheritance triggers after timeout. 6 months provides recovery time.

**Chain reorg?** Registry and trigger_height index rebuilt deterministically from fork point. A reorg that removes a heartbeat may advance the trigger_height. A reorg that removes the setup removes the config entirely.

**Active deposit with inheritance?** If owner has locked deposits when inheritance triggers, the deposits are force-withdrawn (2% penalty applies) and transferred to heir. The heir receives 98% of the deposited amounts. Accrued rewards are forfeited to the reward pool.

---

## 10. Insurance Pool

### 10.1 Sources

| Source | Amount |
|--------|--------|
| Block reward | 1% of R (virtual) |
| Early withdrawal penalties | 2% of deposit amount |
| Deposit creation fees | 1 PBC per TX_TERM_DEPOSIT |
| Inheritance force-withdrawal penalties | 2% of each deposit |

### 10.2 Single Deterministic Use

If Term Deposit Pool < MIN_DEPOSIT_POOL (100 PBC), up to 10% of Insurance Pool per period is transferred. Automatic, no governance.

### 10.3 Safety

- Hard cap: INSURANCE_CAP coins (consensus constant, set at chain launch). Overflow permanently removed from virtual balance. This value is fixed in the source code and does not depend on "max supply" calculations — it is a concrete number decided before genesis.
- No discretionary spending. One use only.
- Rate-limited (10% per period max).

---

## 11. Dynamic Fee Floor

### 11.1 Rationale

When a large portion of the supply is locked in deposits, the circulating (tradeable) supply shrinks. This means:

- Each circulating coin is relatively more valuable
- Spam transactions are relatively cheaper (fewer coins needed)
- The network should charge MORE per transaction, not less

### 11.2 Formula

```
locked_ratio = total_locked / circulating_supply
min_fee = BASE_FEE × (1 + (locked_ratio × 1.0))
```

| Locked ratio | Fee multiplier | Effect |
|-------------|---------------|--------|
| 0% | 1.0× BASE_FEE | Normal fees |
| 30% | 1.3× BASE_FEE | Slightly higher |
| 50% | 1.5× BASE_FEE | Moderate increase |
| 80% | 1.8× BASE_FEE | High fees (spam deterrent) |
| 100% | 2.0× BASE_FEE (cap) | Maximum |

**Cap: 2.0× BASE_FEE.** Fees never exceed double the base rate, ensuring the chain remains usable even at extreme lock ratios.

### 11.3 Why Fees Increase With Locking

When 80% of coins are locked, only 20% is circulating. Spam that would cost X coins now represents 5× more of the tradeable supply. Increasing the fee floor compensates for this, maintaining a consistent anti-spam cost relative to available liquidity.

Miners benefit from the 50/50 fee split: higher fees = higher miner income = stronger incentive to include legitimate transactions.

Pure math from on-chain state. No external data. Deterministic.

---

## 12. Behavioral Privacy & Anti-Censorship

### 12.1 The Observability Problem

PBC tags transaction types in `tx_extra`. The type is visible to any node. Amounts for financial operations are also public (Section 4). This creates risks distinct from solvency:

| Risk | Severity |
|------|----------|
| Selective censorship (miner drops TX types) | Medium |
| Economic griefing (spam near distribution periods) | Low |
| Behavioral correlation (heartbeat patterns) | Medium |
| Amount analysis (deposit sizes visible) | Low-Medium |

**None of these threaten solvency.**

### 12.2 Anti-Censorship: Relay Neutrality

**Type-blind relay ordering:** Mempool ordered by fee density, not type.

**Type-blind block inclusion:** Miners select by fee density only.

**Minimum relay set:** Default node relays all valid TX types. No filter config.

**Economic enforcement:** With 50/50 fee split, censoring fee-paying TX = leaving money on the table.

### 12.3 Fee Parity

Uniform fee calculation: `min_fee = fee_per_byte × tx_size_bytes`, identical for all types.

### 12.4 Transaction Structure Standardization

**Minimum tx_extra:** Padded to 64 bytes (random data).

**Standardized output count:** 2 outputs when feasible.

**Limitation:** Full nodes parse tx_extra and know types. Padding is obfuscation against casual analysis.

### 12.5 Anti-Griefing: Mempool Flood Protection

| Type | Max per address per 288 blocks (~24h) |
|------|--------------------------------------|
| TX_STANDARD | Unlimited |
| TX_TERM_DEPOSIT | 10 |
| TX_CLAIM | 10 |
| TX_TERM_WITHDRAW | 10 |
| TX_HEARTBEAT | 1 |
| TX_INHERITANCE_SETUP | 1 |
| TX_INHERITANCE_MODIFY | 1 |

Claims have no urgency (index only increases). Claims at any block, not at period boundaries.

### 12.6 Amount Correlation Mitigation

Since deposit amounts are public, an observer might try to correlate a deposit with a later claim or withdrawal. Mitigations:

- Ring signatures hide which input is the real one — the depositor's identity is unknown
- Claims and withdrawals also use ring signatures
- Multiple deposits with similar amounts from different users are indistinguishable
- The wallet does NOT automatically create deposits that match exact wallet balance (this would leak information)

### 12.7 Heartbeat Randomization

**Random window:** 25 days ± 10 days → heartbeats between 15 and 35 days.

**Activity piggyback:** Any TX resets timer → active users never send TX_HEARTBEAT.

**Batching:** Pending claim + pending heartbeat → wallet sends TX_CLAIM only.

```bash
#!/bin/bash
# Randomized heartbeat cron
LAST_ACTIVITY=$(curl -s http://127.0.0.1:19650/json_rpc \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_inheritance_status"}' \
  -H 'Content-Type: application/json' | jq '.result.blocks_since_last_activity')

THRESHOLD=$((4320 + RANDOM % 5760))

if [ "$LAST_ACTIVITY" -gt "$THRESHOLD" ]; then
  sleep $((RANDOM % 3600))
  curl -s http://127.0.0.1:19650/json_rpc \
    -d '{"jsonrpc":"2.0","id":"0","method":"send_heartbeat"}' \
    -H 'Content-Type: application/json'
fi
```

### 12.8 Wallet-Side Privacy Hardening

Beyond consensus-level protections, PBC wallets implement additional mitigations:

**Claim-to-fresh-subaddress:** When a TX_CLAIM is sent, the wallet automatically directs the reward output to a freshly generated subaddress. This prevents linking a claim to a previous deposit by output destination. The user never needs to manage this — it happens silently.

**Fee jitter:** The wallet adds a small random amount to the fee (within ±10% of the calculated minimum fee). This reduces fee-based fingerprinting — an observer cannot correlate transactions by their exact fee amounts.

**Claim batching:** When the user has multiple deposits accruing rewards, the wallet offers `claim_all` which combines claims into fewer transactions, reducing the number of observable events.

These are wallet-level behaviors, not consensus rules. They do not affect validation or require changes from other nodes.

### 12.9 Protection Summary

| Threat | Protection | Status |
|--------|-----------|--------|
| Standard TX amounts | RingCT | Full |
| Sender/receiver identity | Ring signatures + stealth | Full |
| Deposit/claim amounts | Public (consensus requires it) | Accepted trade-off |
| Financial op identity | Ring signatures | Full |
| TX type identification | Cannot prevent | Accepted (padding mitigates casual) |
| Selective censorship | Fee parity + relay neutrality + 50/50 incentive | Strong |
| Mempool griefing | Rate limits + no urgency | Strong |
| Heartbeat correlation | Randomized + piggyback | Strong |
| Amount correlation | Ring signatures + non-linkability | Strong |
| Claim output tracking | Claim-to-fresh-subaddress (wallet) | Strong |
| Fee fingerprinting | Fee jitter ±10% (wallet) | Moderate |

---

## 13. Safety Architecture

### 13.1 The Cardinal Rule

```
At any block t: SUM(all_payouts_t) ≤ reward_pool_balance_t
```

### 13.2 No Fixed Rate Promises

The wallet displays accrued rewards from the Global Index — real numbers from actual reward pool inflows, not projected rates.

### 13.3 No Web Attack Surface

All operations through wallet. Any website requesting PBC keys is fraudulent.

### 13.4 State Boundedness

| State | Bound | Overflow |
|-------|-------|----------|
| Insurance Pool | 1% of max supply | Removed permanently |
| Term Deposit Pool | Self-regulating | Depletes via claims |
| Fee Pool | Self-regulating | Depletes via claims |
| Inheritance Registry | 1 per address | Replaced |
| Active Deposits | 10 per address | Rejected |

### 13.5 Attack Analysis

| Attack | Mitigation |
|--------|-----------|
| Whale locking 90% | sqrt() + Locked Supply Multiplier above 60% |
| Mass early withdrawal | Lose 2% + rewards. Insurance gains. |
| Deposit-claim-withdraw | Deferred eligibility + 1 PBC + 2% = net loss |
| Early chain high rewards | Intended behavior. Self-balancing via Σw. |
| Sybil deposits | 1 PBC each. Uneconomical. |
| Empty block mining | 50/50 fee split incentivizes inclusion |
| Inheritance mixer | 6-month timeout. Impractical. |
| Inheritance registry DoS | O(1) per block via trigger_height index |
| Selective censorship | Relay neutrality + fee incentive |
| TX_CLAIM abuse | Bounded by reward pool × (w/Σw) |
| Amount analysis | Identity still hidden by ring signatures |
| Spam at high lock ratio | Fee floor INCREASES with locked ratio |

### 13.6 Reorg Safety

All state rebuildable: reward pool balances, indices, registry. Reorg = recompute from fork point.

### 13.7 Hard Fork Governance

All parameters are consensus constants. No on-chain governance, no token voting, no admin keys.

---

## 14. Supply Invariant & Formal Proofs

### 14.1 The Master Invariant

At any block height *h*:

```
Σ(R_h) = coins_in_existence + pool_balances + total_destroyed

Where:
  Σ(R_h)             = already_generated_coins (sum of all theoretical block rewards)
  coins_in_existence  = all coins existing as UTXO outputs (spendable + locked + vested)
                      = already_generated_coins − pool_balances − total_destroyed
  pool_balances       = deposit_pool_balance + fee_pool_balance + insurance_pool_balance
  total_destroyed     = cumulative insurance overflow
```

**Note:** `already_generated_coins` counts the full theoretical reward R at each block (see Section 3.4). The 7% allocated to virtual reward pools is part of Σ(R_h) even though it's not minted in the coinbase. It becomes real coins only when claimed via TX_CLAIM.

### 14.2 Verification of Each Flow

**Block creation:**

```
+93% R to coins_in_existence (coinbase outputs: miner + dev)
+7% R to virtual reward pools (2.5% deposit + 3.5% fee + 1% insurance)

Check: 93 + 7 = 100% of R ✓
```

**Transaction fee flow:**

```
Sender: −F from coins_in_existence (inputs − outputs)
Miner coinbase: +50% F to coins_in_existence
Fee Pool: +50% F to pool_balances

Net coins_in_existence: −50% F
Net pool_balances: +50% F
Net total: 0  ✓ (no new coins)
```

**Deposit creation fee (1 PBC):**

```
Sender: −1 PBC from coins_in_existence (included in TX inputs)
Insurance Pool: +1 PBC to pool_balances

Net total: 0  ✓
```

**TX_CLAIM:**

```
pool_balances: −reward
coins_in_existence: +reward (new output with public amount)

Net total: 0  ✓
```

**Insurance overflow:**

```
pool_balances: −overflow
total_destroyed: +overflow

Net total: 0  ✓
```

**Every flow preserves the invariant.** ■

### 14.3 Circulating Supply

```
circulating_supply = coins_in_existence − total_locked_in_deposits − total_vested_outputs

Where (see Section 19.8 for exact definitions):
  coins_in_existence      = already_generated_coins − pool_balances − total_destroyed
  total_locked_in_deposits = Σ(amount) for deposits where current_height < unlock_height
  total_vested_outputs     = Σ(amount) for coinbase outputs where current_height < unlock_height
```

### 14.4 Effective Tradeable Supply

```
tradeable = circulating_supply
```

Over time, as insurance overflow grows with adoption, `total_destroyed` slowly increases. At maturity (tail emission), the effective supply stabilizes.

---

## 15. Supply Dynamics

### 15.1 Destruction Sources

| Source | Mechanism | Rate |
|--------|-----------|------|
| Insurance overflow | Virtual balance removed | Variable (when Insurance Pool > INSURANCE_CAP) |

PBC does not rely on aggressive deflation. The value proposition comes from privacy, real yield, and trustless inheritance — not from artificial scarcity.

### 15.2 Long-Term Dynamics

**Phase 1 (early):** Emission dominates. coins_in_existence grows. Early depositors earn high rewards.

**Phase 2 (growth):** Reward pool balances stabilize. Deposit rewards dilute as Σw grows. Insurance overflow begins.

**Phase 3 (mature):** Block rewards → tail emission. Supply growth slows. Insurance overflow provides modest deflation.

---

## 16. Roadmap

### Phase 1 — Genesis (v1.0.0)

- CryptoNote privacy base (RingCT for standard transfers)
- Hybrid transparency model (public amounts for financial ops)
- Vesting anti-dump (4-tier)
- Coinbase structure (91% miner + 2% dev + 7% virtual reward pools)
- Term Deposits: 5 tiers (30/90/180/270/365 days)
- Global Index + claim-based rewards (TX_CLAIM with public reward)
- Deferred eligibility + anti-gaming rules
- Fee Redistribution (separate Global Index, 50/50 fee split)
- Insurance Pool (overflow removal)
- Dynamic Fee Floor
- Anti-whale sqrt + duration multipliers
- Locked Supply Multiplier
- Relay neutrality policy + structural padding
- Wallet CLI/RPC with all commands
- Node RPC (read-only)
- Mining pool compatibility (standard stratum)

**Estimated development:** 8-12 weeks from C64 Chain codebase.

### Phase 2 — Hard Fork v2.0 (~3 months post-genesis)

- Inheritance Protocol (setup, heartbeat, trigger)
- Heartbeat randomization + activity piggyback
- Block explorer
- Parameter tuning from mainnet data

**Estimated development:** 6-8 weeks.

### Phase 3 — Maturity

- Performance optimization
- Research: ZK proofs for private deposit amounts (see Section 4.4)
- Community proposals evaluated against safety principles

---

## 17. Competitive Positioning

| Feature | PBC | Monero | Ethereum DeFi | Zephyr |
|---------|-----|--------|---------------|--------|
| Transfer privacy | Full (RingCT) | Full | None | Partial |
| Financial op identity | Private (ring sig) | N/A | Public | Public |
| Financial op amounts | Public (honest) | N/A | Public | Public |
| Term Deposits (native) | Yes (5 tiers) | No | Yes (contract) | No |
| Claim-based rewards | Yes | N/A | No | No |
| Deflationary mechanism | Yes (insurance overflow) | No | No | No |
| Inheritance | Yes (Phase 2) | No | No | No |
| Oracle dependency | None | None | Yes | Yes |
| Smart contract risk | None | None | High | Medium |
| Web interface risk | None | None | High | Medium |
| Mining pool compatible | Yes (standard) | Yes | N/A (PoS) | Yes |
| Formal solvency proof | Yes | N/A | No | No |
| Fixed rate promises | Never | N/A | Often | Sometimes |

---

## 18. What PBC Deliberately Does NOT Include

| Rejected Feature | Reason |
|-----------------|--------|
| Web transaction interface | Phishing, DNS hijacking, frontend compromise |
| Burn-to-Unlock | Modifying UTXO unlock_time = consensus risk |
| Voluntary burn utilities | Uneconomical for users; no one would actually burn coins for marginal fee discount |
| Fixed-rate yields | Implicit debt the chain cannot guarantee |
| Hidden deposit amounts | Consensus needs sqrt(amount) — see Section 4 |
| Credit scoring | Incompatible with privacy |
| P2P Lending | Requires oracle for collateral valuation |
| Self-repaying loans | Inflationary yield in disguise |
| On-chain governance | Plutocratic risk; incompatible with privacy |
| State in block headers | Divergence risk |
| Coinbase fanout payouts | Block bloat; starvation |
| Stablecoins | Requires oracle |
| Browser wallet | Keys in browser memory |
| 100% fees to miners | Removes Fee Pool yield mechanism |
| Null address burn | Wastes UTXO space |
| Burned at birth | Fake deflation — coins never existed; simpler to increase reward pool shares |
| Fee floor decreasing with locking | Reduces spam cost when circulating supply shrinks |
| O(N) inheritance scan per block | DoS vector; trigger_height index is O(1) |

---

## 19. Consensus Exact Specification

This section provides the implementation-grade specification: all formulas in integer arithmetic, all rounding rules, all edge cases, all constants. Two compliant implementations following this spec will produce identical state for identical chains.

### 19.1 Arithmetic Model & Safety

PBC uses **64-bit unsigned integer arithmetic** throughout. All coin amounts are in **atomic units** (1 PBC = 10^12 atomic units). There are no floating-point operations in consensus code.

For index calculations requiring higher precision, PBC uses **scaled integers** with a fixed scale factor:

```
SCALE = 10^18  (index precision factor)
```

All index values are stored as `uint64` scaled by SCALE. This provides 18 decimal places of precision, far exceeding what is needed for reward calculations.

**CONSENSUS RULES — Arithmetic Safety:**

**Rule A1: 128-bit intermediates (mandatory).** All multiplications in consensus-critical calculations MUST use 128-bit unsigned integer intermediates. The following operations require uint128:

```
// Index update: ΔP can be up to ~10^15 (atomic), SCALE = 10^18
//   → ΔP * SCALE can reach ~10^33 → REQUIRES uint128
uint128 numerator = (uint128)delta_pool * (uint128)SCALE;
uint64 index_delta = (uint64)(numerator / sum_weights);

// Reward calculation: weight up to ~10^9, index delta up to ~10^18
//   → product can reach ~10^27 → REQUIRES uint128
uint128 intermediate = (uint128)weight * (uint128)(index_now - index_entry);
uint64 reward = (uint64)(intermediate / SCALE);

// Locked ratio: total_locked up to ~10^18 (atomic), multiplied by 1000
//   → can reach ~10^21 → REQUIRES uint128
uint128 ratio_num = (uint128)total_locked * 1000;
uint64 locked_ratio = (uint64)(ratio_num / circulating_supply);

// Fee floor: base_fee × multiplier, both uint64
//   → can overflow uint64 if base_fee is large → use uint128
uint128 fee_product = (uint128)base_fee * (uint128)fee_multiplier;
uint64 min_fee = (uint64)(fee_product / 1000);
```

Implementations that use uint64 throughout will produce incorrect results and are non-compliant. Any language or platform that does not support native uint128 must use a bignum library for these operations.

**Rule A2: No floating-point (mandatory).** No consensus code path may use float, double, or any floating-point type. This includes intermediate calculations, comparisons, and conversions. Floating-point arithmetic is non-deterministic across platforms (rounding modes, extended precision, FMA instructions) and WILL cause chain splits.

**Rule A3: Floor division only (mandatory).** All divisions in consensus code use unsigned integer floor division (truncation toward zero). There is no rounding, no ceiling, no banker's rounding. This ensures:

```
// Floor division: always truncate
reward = intermediate / SCALE;          // floor
index_delta = numerator / sum_weights;  // floor

// NEVER:
reward = (intermediate + SCALE/2) / SCALE;  // WRONG: rounds
reward = (intermediate + SCALE - 1) / SCALE;  // WRONG: ceiling
```

The rounding invariant guarantees: Σ(all claimed rewards in a period) ≤ ΔP. The "lost" fractional atomic units remain in the pool, preserving solvency.

**Rule A4: Domain clamping (mandatory).** All derived values MUST be clamped to their valid domain before use:

```
// locked_ratio: [0, 1000] per mille
locked_ratio = min(raw_ratio, 1000);

// fee_multiplier: [1000, FEE_FLOOR_CAP] per mille
fee_multiplier = min(1000 + locked_ratio, FEE_FLOOR_CAP);

// weight: always > 0 for valid deposits (min deposit enforced)
// isqrt(0) = 0 → invalid deposit, rejected at validation

// index delta: Σw = 0 → no index update (skip, not divide-by-zero)
if (sum_weights == 0) { /* no index update this period */ }

// circulating_supply = 0 → locked_ratio := 1000 (treat as max)
if (circulating == 0) { locked_ratio = 1000; }

// reward > pool_balance → reject TX_CLAIM (should never happen if
//   implementation is correct, but defense-in-depth)
assert(reward <= pool_balance);
```

**Rule A5: Canonical uint64→scalar conversion (mandatory).** When any uint64 amount is used in an elliptic curve operation (`amount × H` for commitments, `fee × H` for balance verification), it MUST be converted to a 32-byte Ed25519 scalar using the canonical procedure defined in Section 3.5: 8 bytes little-endian, zero-padded to 32 bytes, no modular reduction. This applies to reward amounts, deposit amounts, withdrawal amounts, and fees. Any deviation produces a different curve point and causes a consensus-breaking commitment mismatch. See Section 3.5 for the C++ reference implementation.

### 19.2 Consensus Constants

```
BLOCK_TIME             = 300              // seconds (5 minutes)
EMISSION_SPEED_FACTOR  = TBD              // set before genesis (see 19.2.1)
MONEY_SUPPLY           = TBD              // total theoretical supply in atomic units (see 19.2.1)
DISTRIBUTION_PERIOD    = 720              // blocks per index update (~2.5 days)

// Block reward split (parts per 1000 for integer division)
MINER_SHARE            = 910              // 91.0% of R (per mille)
DEV_SHARE              = 20               // 2.0% of R (per mille)
FEE_POOL_SHARE         = 35               // 3.5% of R (per mille)
DEPOSIT_POOL_SHARE     = 25               // 2.5% of R (per mille)
INSURANCE_POOL_SHARE   = 10               // 1.0% of R (per mille)
// Total: 910 + 20 + 35 + 25 + 10 = 1000 ✓

FEE_MINER_SHARE        = 500              // 50.0% of F (per mille)
FEE_POOL_FEE_SHARE     = 500              // 50.0% of F (per mille)

// Deposits
MIN_DEPOSIT_AMOUNT     = 10_000000000000  // 10 PBC in atomic units
MAX_DEPOSITS_PER_ADDR  = 10
DEPOSIT_CREATION_FEE   = 1_000000000000   // 1 PBC in atomic units
EARLY_WITHDRAWAL_PENALTY = 20             // 2.0% (per mille)

// Duration tiers (blocks)
TIER_30D_BLOCKS        = 8640             // 30 days
TIER_90D_BLOCKS        = 25920            // 90 days
TIER_180D_BLOCKS       = 51840            // 180 days
TIER_270D_BLOCKS       = 77760            // 270 days
TIER_365D_BLOCKS       = 105120           // 365 days

// Duration multipliers (per mille, applied to weight)
MULT_30D               = 1000             // 1.0×
MULT_90D               = 1300             // 1.3×
MULT_180D              = 1600             // 1.6×
MULT_270D              = 1800             // 1.8×
MULT_365D              = 2000             // 2.0×

// Locked Supply Multiplier
LSM_THRESHOLD          = 600              // locked_ratio > 60% (per mille)
LSM_MIN_RATE           = 100              // minimum 10% (per mille)

// Insurance
INSURANCE_CAP          = TBD              // fixed cap in atomic units (see 19.2.1)
INSURANCE_SUBSIDY_RATE = 100              // max 10% per period (per mille)
MIN_DEPOSIT_POOL       = 100_000000000000 // 100 PBC trigger threshold

// Dynamic fee floor
FEE_FLOOR_SCALE        = 1000             // per mille
FEE_FLOOR_CAP          = 2000             // max 2.0× BASE_FEE (per mille)

// Inheritance (Phase 2)
MIN_INHERITANCE_TIMEOUT = 52560           // ~6 months in blocks

// Index
SCALE                  = 1000000000000000000  // 10^18 for index precision

// Anti-griefing rate limits (per 288 blocks)
RATE_LIMIT_DEPOSIT     = 10
RATE_LIMIT_CLAIM       = 10
RATE_LIMIT_WITHDRAW    = 10
RATE_LIMIT_HEARTBEAT   = 1
RATE_LIMIT_INHERITANCE = 1
```

#### 19.2.1 Parameters to Finalize Before Genesis

Three parameters are marked TBD and MUST be fixed before genesis block. They cannot be changed after launch without a hard fork.

**MONEY_SUPPLY:** Total theoretical maximum emission in atomic units. Candidate: 18,446,744 PBC (= 18,446,744 × 10^12 atomic units). This is comparable to Monero's ~18.4M XMR supply. Rationale: sub-20M supply, psychologically scarce, fits in uint64.

**EMISSION_SPEED_FACTOR:** Controls the halving speed. Candidate: 20 (same as Monero). With MONEY_SUPPLY ~18.4M and factor 20, the emission curve closely matches Monero's proven schedule (50% emitted in ~3.8 years). Higher values (21, 22) slow emission; lower values (18, 19) speed it up. Must be simulated with exact block times before committing.

**INSURANCE_CAP:** Maximum balance of the Insurance Pool. Candidate: 1% of MONEY_SUPPLY (= 184,467 PBC in atomic units). Rationale: large enough to subsidize the deposit pool during low-activity periods, small enough that overflow creates meaningful deflation. The overflow mechanism only activates when Insurance Pool > INSURANCE_CAP, so the cap must be tuned to real adoption expectations.

**Decision process:** These values will be finalized during testnet by running emission simulations at various adoption scenarios (low/medium/high deposit participation). The whitepaper specifies all mechanisms independent of these values — any valid configuration produces correct behavior.

### 19.3 Emission Accounting & Exact Integer Split

```
// Standard CryptoNote emission formula
R = (MONEY_SUPPLY − already_generated_coins) >> EMISSION_SPEED_FACTOR

// Count full theoretical reward (virtual pools are part of emission)
already_generated_coins += R
```

**CONSENSUS RULE: Exact integer split with remainder absorption.**

Block reward R and transaction fees F are split separately. Floor division is used throughout. The remainder (rounding dust) is absorbed by the virtual reward pools — never by the miner or dev. This guarantees exact conservation: `miner + dev + pools == R` and `miner_fee + pools_fee == F` always hold, with zero lost atomic units.

```
// ═══════════════════════════════════════════════════════════
// BLOCK REWARD SPLIT (R) — Compute in this exact order
// ═══════════════════════════════════════════════════════════

// Step 1: Miner and dev by floor division (computed FIRST)
miner_R = R * MINER_SHARE / 1000          // floor(R × 910 / 1000)
dev_R   = R * DEV_SHARE / 1000            // floor(R × 20 / 1000)

// Step 2: Remainder goes entirely to pools
pools_R = R - miner_R - dev_R             // absorbs all rounding dust

// Step 3: Sub-split pools_R among the three pools
// Use per-mille shares relative to total pool share (35+25+10 = 70)
deposit_share = pools_R * DEPOSIT_POOL_SHARE / (FEE_POOL_SHARE + DEPOSIT_POOL_SHARE + INSURANCE_POOL_SHARE)
                                           // floor(pools_R × 25 / 70)
insurance_share = pools_R * INSURANCE_POOL_SHARE / (FEE_POOL_SHARE + DEPOSIT_POOL_SHARE + INSURANCE_POOL_SHARE)
                                           // floor(pools_R × 10 / 70)
fee_share = pools_R - deposit_share - insurance_share
                                           // absorbs sub-split remainder

// Apply to state
deposit_pool_balance  += deposit_share
fee_pool_balance      += fee_share
insurance_pool_balance += insurance_share

// ═══════════════════════════════════════════════════════════
// FEE SPLIT (F) — Same remainder-absorption pattern
// ═══════════════════════════════════════════════════════════

// Step 1: Miner fee share by floor division (computed FIRST)
miner_F = F * FEE_MINER_SHARE / 1000      // floor(F × 500 / 1000)

// Step 2: Fee Pool gets the remainder
pools_F = F - miner_F                     // absorbs rounding dust

// Apply to state
fee_pool_balance += pools_F

// ═══════════════════════════════════════════════════════════
// COINBASE OUTPUTS CREATED
// ═══════════════════════════════════════════════════════════

total_miner = miner_R + miner_F           // split into 4 vesting outputs
total_dev   = dev_R                       // single output

// ═══════════════════════════════════════════════════════════
// CONSERVATION INVARIANT — verified per block
// ═══════════════════════════════════════════════════════════

assert(miner_R + dev_R + pools_R == R)    // exact, zero dust lost
assert(miner_F + pools_F == F)            // exact, zero dust lost
assert(miner_R + dev_R + deposit_share + fee_share + insurance_share == R)
```

**Why remainder goes to pools:** If remainder went to the miner, the miner could manipulate R (via timestamp adjustments) to maximize dust accumulation. Pools are consensus-tracked virtual balances — dust in pools is eventually distributed to depositors via the Global Index, which uses SCALE=10^18 precision. No atomic unit is ever lost.

### 19.4 Integer Square Root

```
function isqrt(n: uint64) → uint64:
    // Floor integer square root (Newton's method)
    if n == 0: return 0
    x = n
    y = (x + 1) / 2
    while y < x:
        x = y
        y = (x + n / x) / 2
    return x

// Example: isqrt(1000_000000000000) = 31622776  (for 1000 PBC)
// Operates on atomic units
```

### 19.5 Weight Calculation

```
function calc_weight(amount_atomic: uint64, tier: uint8) → uint64:
    base_weight = isqrt(amount_atomic)
    multiplier = get_multiplier(tier)  // returns per-mille value
    return base_weight * multiplier / 1000

// Weight is in "weight units" (not atomic units)
// Example: 1000 PBC for 90 days
//   base = isqrt(1000_000000000000) = 31622776
//   weight = 31622776 * 1300 / 1000 = 41109608
```

### 19.6 Global Index Update (Per Period)

**Storage and precision:** `global_deposit_index` and `global_fee_index` are stored as `uint64` values scaled by `SCALE = 10^18`. This provides 18 decimal places of precision. At genesis both indices are 0. They are monotonically non-decreasing (they never go down). The maximum theoretical index value after decades of operation fits comfortably in uint64 (~1.8×10^19).

```
function update_index(period_k: uint64):
    // Period k spans blocks [k*720, (k+1)*720 - 1]
    ΔP = deposit_pool_inflow_during_period_k   // atomic units (uint64)
    Σw = sum_of_weights_of_eligible_deposits   // weight units (uint64)

    // Eligible: created_height < k * DISTRIBUTION_PERIOD
    //           AND unlock_height > k * DISTRIBUTION_PERIOD
    //           AND not withdrawn

    if Σw == 0:
        // No eligible deposits: ΔP stays in pool, no index change
        return

    // Apply Locked Supply Multiplier
    locked_ratio_permille = total_locked * 1000 / max(circulating_supply, 1)
    locked_ratio_permille = min(locked_ratio_permille, 1000)

    if locked_ratio_permille > LSM_THRESHOLD:
        rate_mod = 1000 - ((locked_ratio_permille - LSM_THRESHOLD) * 1000
                          / (1000 - LSM_THRESHOLD))
        rate_mod = max(rate_mod, LSM_MIN_RATE)
        effective_ΔP = ΔP * rate_mod / 1000
    else:
        effective_ΔP = ΔP

    // Index increment (uint128 intermediate REQUIRED — Rule A1)
    // effective_ΔP up to ~10^15, SCALE = 10^18 → product up to ~10^33
    δI = (uint64)((uint128)effective_ΔP * (uint128)SCALE / (uint128)Σw)

    // Update global index (monotonically non-decreasing)
    global_deposit_index += δI

    // The undistributed dust: effective_ΔP - (δI * Σw / SCALE)
    // remains in the pool automatically (solvency buffer)
```

### 19.7 Reward Calculation (TX_CLAIM)

```
function calc_reward(deposit: Deposit) → uint64:
    w = deposit.effective_weight           // weight units
    δI_total = global_deposit_index - deposit.entry_index  // scaled

    // Raw reward (floor division preserves solvency)
    raw_reward = w * δI_total / SCALE      // atomic units, floor

    // Cap by pool share
    pool_share = deposit_pool_balance * w / Σw_current  // floor
    actual_reward = min(raw_reward, pool_share)

    return actual_reward

// After claim:
//   deposit.entry_index = global_deposit_index
//   deposit_pool_balance -= actual_reward
```

### 19.8 Supply Definitions & Locked Ratio

**CONSENSUS RULE: Accounting-based supply tracking.** In CryptoNote with RingCT, output amounts are hidden behind Pedersen commitments. The consensus CANNOT compute supply by scanning UTXO amounts. Instead, PBC maintains five accounting variables as consensus state, updated deterministically during block processing:

```
// ═══════════════════════════════════════════════════════════
// SUPPLY ACCOUNTING — Five state variables (all uint64)
// ═══════════════════════════════════════════════════════════

// (1) already_generated_coins: cumulative sum of all theoretical block rewards
//     Updated: +R at each block (BEFORE splitting into miner/dev/pools)
//     Never decreases.

// (2) pool_balances: sum of virtual reward pool balances
//     = deposit_pool_balance + fee_pool_balance + insurance_pool_balance
//     Updated: +allocations each block, −claims, −penalties, −overflow
//     Each sub-pool is tracked independently.

// (3) total_destroyed: cumulative coins permanently removed
//     Updated: +overflow whenever insurance_pool > INSURANCE_CAP
//     Never decreases. Only source: insurance overflow.

// (4) total_locked_in_deposits: sum of amounts in active term deposits
//     = Σ(deposit.amount) for all deposits where current_height < unlock_height
//     Updated: +amount on TX_TERM_DEPOSIT, −amount on maturity/withdrawal
//     These coins exist in the UTXO set but cannot be spent.

// (5) total_vested_outputs: sum of amounts in vesting coinbase outputs
//     = Σ(output.amount) for miner/dev outputs where current_height < unlock_height
//     Updated: +amount on each coinbase, −amount when unlock_height is reached
//     These coins exist in the UTXO set but cannot be spent.

// ═══════════════════════════════════════════════════════════
// DERIVED VALUES (computed, not stored)
// ═══════════════════════════════════════════════════════════

// coins_in_existence: all coins that exist as spendable UTXO outputs
//   (whether currently locked, vesting, or freely spendable)
//   This is the total value of the UTXO set.
coins_in_existence = already_generated_coins − pool_balances − total_destroyed

// circulating_supply: coins that can actually be transacted RIGHT NOW
//   Excludes: locked deposits (cannot spend until maturity)
//   Excludes: vesting outputs (cannot spend until unlock)
//   This is the "free float" of the economy.
circulating_supply = coins_in_existence − total_locked_in_deposits − total_vested_outputs

// Equivalently:
// circulating_supply = already_generated_coins
//                    − pool_balances
//                    − total_destroyed
//                    − total_locked_in_deposits
//                    − total_vested_outputs

function calc_circulating_supply() → uint64:
    cie = already_generated_coins - pool_balances - total_destroyed
    return cie - total_locked_in_deposits - total_vested_outputs

function calc_locked_ratio() → uint64:
    circ = calc_circulating_supply()
    if circ == 0:
        return 1000  // 100% — treat as maximally locked
    // uint128 intermediate required (Rule A1)
    ratio = (uint128)total_locked_in_deposits * 1000 / (uint128)circ
    return min((uint64)ratio, 1000)  // clamp to [0, 1000] per mille
```

**Why not scan UTXOs?** In RingCT, output amounts are Pedersen commitments `C = a×H + r×G`. The value `a` is encrypted. Only the owner (who knows `r`) can decode the amount. The consensus has no way to sum hidden amounts. The accounting approach above is exact because every flow that creates, moves, or destroys coins updates the state variables.

### 19.9 Dynamic Fee Floor

```
function calc_min_fee(tx_size_bytes: uint64) → uint64:
    locked_ratio = calc_locked_ratio()  // per mille [0, 1000]

    // fee_multiplier in per mille: 1000 + locked_ratio
    // capped at FEE_FLOOR_CAP (2000)
    fee_multiplier = min(FEE_FLOOR_SCALE + locked_ratio, FEE_FLOOR_CAP)

    return BASE_FEE_PER_BYTE * tx_size_bytes * fee_multiplier / FEE_FLOOR_SCALE
```

### 19.10 Early Withdrawal

```
function calc_withdrawal(deposit: Deposit) → (returned, penalty):
    penalty = deposit.amount * EARLY_WITHDRAWAL_PENALTY / 1000  // floor
    returned = deposit.amount - penalty

    // Forfeited rewards stay in pool (not redistributed)
    // Penalty → Insurance Pool
    // Deposit removed from Σw immediately

    return (returned, penalty)
```

### 19.11 Insurance Pool Overflow

```
function check_insurance_overflow():
    if insurance_pool_balance > INSURANCE_CAP:
        overflow = insurance_pool_balance - INSURANCE_CAP
        insurance_pool_balance -= overflow
        // overflow is permanently removed (destroyed from virtual)
        total_destroyed += overflow
```

### 19.12 Deterministic Block Processing Order

**CONSENSUS RULE: Strict sequential processing.** Every block MUST be processed in the exact order below. Steps cannot be reordered, parallelized, or batched differently. Two compliant implementations processing the same block MUST produce identical state after each numbered step. Any deviation in ordering will cause state divergence and chain splits.

At each block height *h*:

```
// ═══════════════════════════════════════════════════════════
// STEP 1: EMISSION & COINBASE (see 19.3 for exact split)
// ═══════════════════════════════════════════════════════════
// Compute block reward from current state BEFORE any modifications.
R = emission_formula(already_generated_coins)
already_generated_coins += R    // count FULL theoretical reward

// Exact integer split with remainder absorption (Section 19.3):
miner_R = R * MINER_SHARE / 1000          // floor
dev_R   = R * DEV_SHARE / 1000            // floor
pools_R = R - miner_R - dev_R             // remainder to pools
// Sub-split pools_R:
deposit_share = pools_R * DEPOSIT_POOL_SHARE / (FEE_POOL_SHARE + DEPOSIT_POOL_SHARE + INSURANCE_POOL_SHARE)
insurance_share = pools_R * INSURANCE_POOL_SHARE / (FEE_POOL_SHARE + DEPOSIT_POOL_SHARE + INSURANCE_POOL_SHARE)
fee_share = pools_R - deposit_share - insurance_share

// Create coinbase outputs (actual UTXO):
total_miner = miner_R   // + miner_F added in Step 2
Create 1 dev output (dev_R)
// Miner vesting outputs created after Step 2 (needs miner_F)

// Allocate virtual reward pools:
deposit_pool_balance   += deposit_share
fee_pool_balance       += fee_share
insurance_pool_balance += insurance_share

// ═══════════════════════════════════════════════════════════
// STEP 2: TRANSACTION FEE SPLIT (see 19.3 for exact split)
// ═══════════════════════════════════════════════════════════
F = sum of all transaction fees in this block
miner_F = F * FEE_MINER_SHARE / 1000      // floor
pools_F = F - miner_F                     // remainder to Fee Pool
fee_pool_balance += pools_F

// Now create 4 miner vesting outputs from (miner_R + miner_F):
total_miner = miner_R + miner_F
Create 4 miner vesting outputs (total_miner split 4-way, remainder to first)
Update total_vested_outputs += total_miner + dev_R

// ═══════════════════════════════════════════════════════════
// STEP 3: VALIDATE ALL TRANSACTIONS
// ═══════════════════════════════════════════════════════════
// Validate every transaction in the block against CURRENT state.
// All validations MUST pass before any state is modified in Step 4.
// If any TX is invalid, the entire block is rejected.
For each transaction in block (in block order):
    Validate signatures, ring membership, key images
    Validate amounts, balance equations, range proofs
    Validate type-specific rules (rate limits, deposit eligibility, etc.)

// ═══════════════════════════════════════════════════════════
// STEP 4: APPLY TRANSACTION STATE CHANGES
// ═══════════════════════════════════════════════════════════
// CONSENSUS RULE: Transactions are applied SEQUENTIALLY in block order.
// Each TX sees the state LEFT BY THE PREVIOUS TX. This is critical for
// TX_CLAIM: the pool balance is decremented after each claim, so a
// subsequent claim in the same block sees a reduced pool balance.
// Two nodes processing the same block in different TX order WILL diverge.
For each transaction in block (in block order):

    TX_STANDARD:
        Consume inputs (mark key images as spent)
        Create outputs

    TX_TERM_DEPOSIT:
        Consume inputs, create locked output + change
        total_locked_in_deposits += deposit_amount
        insurance_pool_balance += DEPOSIT_CREATION_FEE
        Record deposit with entry_index = current global index
        Add sqrt(amount) * duration_multiplier to Σw

    TX_CLAIM:
        reward = calc_reward(deposit)  // uses current indices
        // CONSENSUS RULE: reject if reward > pool balance (defense-in-depth)
        if reward > deposit_pool_balance:  REJECT TX  // (or fee_pool_balance)
        Create reward output (amount PUBLIC, mask=0)
        deposit_pool_balance -= reward  (or fee_pool_balance for fee claims)
        Update deposit.entry_index to current index
        // Note: a second TX_CLAIM for the SAME deposit in this block
        // will compute reward = 0 (entry_index == current index) → valid but no-op

    TX_TERM_WITHDRAW:
        penalty = deposit.amount * EARLY_WITHDRAWAL_PENALTY / 1000
        returned = deposit.amount - penalty
        Create output with 'returned' amount
        insurance_pool_balance += penalty
        total_locked_in_deposits -= deposit.amount
        Remove deposit weight from Σw
        Forfeit any accrued rewards (remain in pool for others)

    TX_HEARTBEAT:
        Update last_activity_height for inheritance
        Recompute and re-index trigger_height

    TX_INHERITANCE_SETUP / MODIFY:
        Record/update config in inheritance registry
        Compute and index trigger_height

// ═══════════════════════════════════════════════════════════
// STEP 5: PERIOD BOUNDARY — INDEX UPDATE
// ═══════════════════════════════════════════════════════════
// Check AFTER all TXs are applied, so new deposits from this block
// are already in Σw but their rewards start from the NEXT period.
if (h > 0 AND h % DISTRIBUTION_PERIOD == 0):
    period_k = h / DISTRIBUTION_PERIOD - 1
    update_deposit_index(period_k)  // I += ΔP_k * SCALE / Σw_k
    update_fee_index(period_k)      // same formula, Fee Pool

// ═══════════════════════════════════════════════════════════
// STEP 6: INHERITANCE TRIGGER CHECK
// ═══════════════════════════════════════════════════════════
// After index update, check if any inheritance triggers at this height.
For each inheritance config where trigger_height == h:
    Force-withdraw all owner deposits (2% penalty each, to Insurance Pool)
    Transfer all owner outputs to heir stealth address

// ═══════════════════════════════════════════════════════════
// STEP 7: INSURANCE SUBSIDY CHECK (at period boundary only)
// ═══════════════════════════════════════════════════════════
if (h > 0 AND h % DISTRIBUTION_PERIOD == 0):
    if deposit_pool_balance < MIN_DEPOSIT_POOL:
        subsidy = min(insurance_pool_balance * INSURANCE_SUBSIDY_RATE / 1000,
                      MIN_DEPOSIT_POOL - deposit_pool_balance)
        insurance_pool_balance -= subsidy
        deposit_pool_balance += subsidy

// ═══════════════════════════════════════════════════════════
// STEP 8: INSURANCE OVERFLOW CHECK
// ═══════════════════════════════════════════════════════════
// Always last. Destroys excess insurance.
if insurance_pool_balance > INSURANCE_CAP:
    overflow = insurance_pool_balance - INSURANCE_CAP
    insurance_pool_balance -= overflow
    total_destroyed += overflow

// ═══════════════════════════════════════════════════════════
// STEP 9: VESTING EXPIRY UPDATE
// ═══════════════════════════════════════════════════════════
// Update vesting tracking: any coinbase outputs whose unlock_height == h
// are now spendable. Reduce total_vested_outputs accordingly.
For each vesting output where unlock_height == h:
    total_vested_outputs -= output.amount
```

**Why ordering matters:** If Step 5 (index update) were done before Step 4 (TX processing), a TX_CLAIM in the same block would use the updated index, giving a different reward than if processed before the update. If Step 8 (overflow) were done before Step 7 (subsidy), the subsidy could pull from an insurance pool that should have been capped first. Every ordering dependency has been analyzed and the above sequence is the only correct one.

### 19.13 Rounding Invariant

All integer divisions in consensus use **floor division** (truncation toward zero). This means:

```
For any period: Σ(claimed_rewards) ≤ effective_ΔP ≤ ΔP

The "dust" from floor division (typically < 1 atomic unit per deposit per period)
remains in the reward pool. Over time, this dust accumulates as a solvency buffer.
This is by design: the chain ALWAYS slightly underpays rather than overpays.
```

### 19.14 Determinism Guarantee

Two nodes processing the same chain will produce identical state because:

- All arithmetic is integer (no floating-point — Rule A2)
- All divisions are floor (no rounding ambiguity — Rule A3)
- All multiplications use uint128 intermediates (no overflow — Rule A1)
- All derived values are clamped (no out-of-domain results — Rule A4)
- All operations are ordered (block order → tx order — Section 19.12)
- All edge cases have explicit behavior (Σw=0, circulating=0, overflow)
- No external data sources (no oracles, no timestamps beyond block height)
- Block reward split uses remainder-absorption (no dust lost — Section 19.3)

### 19.15 Consensus Invariants

The following invariants MUST hold at every block height. Any implementation that violates these invariants at any point is non-compliant. These should be checked as assertions in debug builds and as part of the mandatory test suite (Appendix B).

```
// ═══════════════════════════════════════════════════════════
// INVARIANT 1: Conservation (master supply equation)
// ═══════════════════════════════════════════════════════════
// Every atomic unit is accounted for. Nothing created, nothing lost.
already_generated_coins ==
    coins_in_existence + pool_balances + total_destroyed
// Where:
//   coins_in_existence = all UTXO output values (derived, not scanned)
//   pool_balances = deposit_pool_balance + fee_pool_balance + insurance_pool_balance

// ═══════════════════════════════════════════════════════════
// INVARIANT 2: Block reward conservation (per block)
// ═══════════════════════════════════════════════════════════
// At each block, R is split with zero dust lost.
miner_R + dev_R + deposit_share + fee_share + insurance_share == R
miner_F + pools_F == F

// ═══════════════════════════════════════════════════════════
// INVARIANT 3: Non-negativity (all balances)
// ═══════════════════════════════════════════════════════════
deposit_pool_balance   >= 0
fee_pool_balance       >= 0
insurance_pool_balance >= 0
total_locked_in_deposits >= 0
total_vested_outputs   >= 0
total_destroyed        >= 0
// These are uint64 — underflow MUST be caught before it wraps around.
// Any operation that would make a balance negative MUST be rejected.

// ═══════════════════════════════════════════════════════════
// INVARIANT 4: Index monotonicity (non-decreasing)
// ═══════════════════════════════════════════════════════════
global_deposit_index_new >= global_deposit_index_old  // always
global_fee_index_new     >= global_fee_index_old      // always
// A claim can never produce a negative reward because:
//   reward = weight * (I_now - I_entry) / SCALE
//   I_now >= I_entry (monotonicity) → reward >= 0

// ═══════════════════════════════════════════════════════════
// INVARIANT 5: Solvency (pool balance >= claimable)
// ═══════════════════════════════════════════════════════════
// For any single claim:
reward <= deposit_pool_balance    // (or fee_pool_balance)
// This follows from: Σ(all claimable rewards) ≤ Σ(all pool inflows)
// Proven formally in Section 14.

// ═══════════════════════════════════════════════════════════
// INVARIANT 6: Insurance cap
// ═══════════════════════════════════════════════════════════
// After Step 8 of block processing:
insurance_pool_balance <= INSURANCE_CAP

// ═══════════════════════════════════════════════════════════
// INVARIANT 7: Arithmetic safety
// ═══════════════════════════════════════════════════════════
// All intermediate products in consensus calculations use uint128.
// No float/double anywhere in consensus code paths.
// All divisions are floor (truncation toward zero).
// All derived values clamped to valid domain (Rule A4).
```

---

## 20. Conclusion

Privacy Bank Chain is built on three immutable principles:

1. **Solvency by construction** — the chain can never pay out more than its reward pools contain (formally proven).
2. **No UTXO modification** — once created, outputs are immutable until spent.
3. **No web attack surface** — all operations through the wallet, always.

And three operational commitments:

4. **Honest transparency** — amounts public where consensus requires, identity private where cryptography allows.
5. **Relay neutrality** — all valid transaction types relayed and mineable equally.
6. **Mining pool compatible** — standard stratum, zero pool-side changes.

Every mechanism is deterministic, bounded, self-regulating, formally proven, deflationary-trending, wallet-native, and mining-pool-compatible.

*"Private money that works for you."*

---

## 21. Risk Summary

| Feature | Risk | Notes |
|---------|------|-------|
| Term Deposits (Global Index) | Low | Formally proven solvent, exact period boundaries |
| Fee Redistribution | Low | Same mechanism, same proof |
| TX_CLAIM coin creation | Low | Bounded by reward pool, hybrid RCT format specified |
| Insurance Pool | Low | Hard-capped (INSURANCE_CAP constant), single use |
| Dynamic Fee Floor | Low | Fees increase with lock ratio (anti-spam) |
| Inheritance | Low-Med | O(1) trigger via index, stealth heir, identity private |
| Mining pool compat | Low | Standard stratum |
| Deposit amount publicity | Low | Necessary trade-off, identity private (ring sig) |
| Virtual pool accounting | Low | Formally verified invariant, emission accounting explicit |

---

**Document version:** 1.3 Draft
**Date:** February 2026
**License:** CC BY 4.0

---

## Appendix A — Complete Formula Reference

All formulas used in PBC, collected in one place. All arithmetic is integer (uint64). All divisions are floor. Per-mille notation: 1000 = 100%.

---

### A.1 Emission

```
R = (MONEY_SUPPLY − already_generated_coins) >> EMISSION_SPEED_FACTOR
already_generated_coins += R
```

### A.2 Block Reward Split (remainder-absorption, see 19.3)

```
// R split (order matters):
miner_R       = R * 910 / 1000            // floor, computed first
dev_R         = R * 20  / 1000            // floor, computed second
pools_R       = R - miner_R - dev_R       // remainder absorbed by pools
deposit_share = pools_R * 25 / 70         // floor
insurance_share = pools_R * 10 / 70       // floor
fee_share     = pools_R - deposit_share - insurance_share  // remainder

// F split:
miner_F       = F * 500 / 1000           // floor
pools_F       = F - miner_F              // remainder to Fee Pool

// Conservation: miner_R + dev_R + pools_R == R  (exact)
// Conservation: miner_F + pools_F == F          (exact)
```

### A.3 Integer Square Root

```
isqrt(0) = 0
isqrt(n) = floor(√n)   via Newton's method on uint64
```

### A.4 Deposit Weight

```
base_weight = isqrt(amount_atomic)
effective_weight = base_weight * duration_multiplier / 1000

Multipliers (per mille):
   30 days  → 1000
   90 days  → 1300
  180 days  → 1600
  270 days  → 1800
  365 days  → 2000
```

### A.5 Global Index Update

```
Period k = blocks [k×720, (k+1)×720 − 1]

ΔP_k = deposit pool inflow during period k
Σw_k = Σ effective_weight for eligible deposits
       (created_height < k×720 AND unlock_height > k×720)

if Σw_k == 0: no update, ΔP stays in pool

locked_ratio = min(total_locked * 1000 / max(circulating, 1), 1000)

if locked_ratio > 600:
    rate_mod = max(1000 − (locked_ratio − 600) * 1000 / 400, 100)
    effective_ΔP = ΔP_k * rate_mod / 1000
else:
    effective_ΔP = ΔP_k

δI = effective_ΔP * SCALE / Σw_k          (SCALE = 10^18)
global_deposit_index += δI

Applied at block (k+1) × 720.
```

### A.6 Fee Index Update

```
Same formula as A.5, with:
  ΔF_k = fee pool inflow during period k
  Uses same Σw_k (deposit weights)
  Separate index: global_fee_index += δFI
```

### A.7 Reward Claim

```
w = deposit.effective_weight
raw_reward = w * (global_index − deposit.entry_index) / SCALE     (floor)
pool_share = reward_pool_balance * w / Σw_current                  (floor)
actual_reward = min(raw_reward, pool_share)

After claim: deposit.entry_index = global_index
             reward_pool_balance −= actual_reward
```

### A.8 Solvency Proof

```
For period k:
  δI_k = effective_ΔP_k * SCALE / Σw_k                  (floor)
  Σ rewards = Σ(w_i * δI_k) / SCALE                      (floor each)
            ≤ Σw_k * δI_k / SCALE                         (sum of floors ≤ floor of sum)
            = Σw_k * (effective_ΔP_k * SCALE / Σw_k) / SCALE
            ≤ effective_ΔP_k                               (floor removes remainder)
            ≤ ΔP_k                                          ■

Dust remainder = effective_ΔP_k − Σ rewards ≥ 0  (stays in pool)
```

### A.9 Early Withdrawal

```
penalty = amount * 20 / 1000                     (floor, 2%)
returned = amount − penalty
insurance_pool += penalty
Accrued rewards forfeited (stay in reward pool as buffer)
```

### A.10 Dynamic Fee Floor

```
locked_ratio = min(total_locked * 1000 / max(circulating, 1), 1000)
fee_multiplier = min(1000 + locked_ratio, 2000)
min_fee = BASE_FEE_PER_BYTE * tx_size * fee_multiplier / 1000
```

### A.11 Insurance Pool

```
Sources: 1% of R (virtual) + withdrawal penalties + deposit fees + inheritance penalties
Cap: INSURANCE_CAP (constant). Overflow permanently destroyed.
  total_destroyed += overflow

Subsidy trigger: if deposit_pool < 100 PBC
  subsidy = min(insurance_pool * 100 / 1000, 100 PBC − deposit_pool)
```

### A.12 Circulating Supply

```
coins_in_existence = already_generated_coins − pool_balances − total_destroyed
circulating_supply = coins_in_existence − total_locked_in_deposits − total_vested_outputs
if circulating_supply == 0: locked_ratio := 1000 (max)
```

### A.13 Master Invariant

```
already_generated_coins = coins_in_existence + pool_balances + total_destroyed

Where:
  already_generated_coins = Σ(R_h) counts FULL theoretical R
  coins_in_existence = all UTXO outputs (derived, not scanned)
  pool_balances = deposit_pool_balance + fee_pool_balance + insurance_pool_balance
  total_destroyed = cumulative insurance overflow

Every flow preserves this invariant (Section 14.2).
```

### A.14 Inheritance Trigger

```
trigger_height = last_activity_height + timeout_blocks
Checked only when current_height == trigger_height (O(1) via index)

On trigger:
  For each deposit: penalty = amount * 20 / 1000
                    returned = amount − penalty
  Transfer all outputs to heir stealth address
```

---

## Appendix B — Mandatory Security Tests

Any implementation claiming PBC consensus compliance MUST pass the following test vectors. These tests target the most likely sources of implementation bugs: integer overflow, off-by-one errors, state ordering, and edge cases.

---

### B.1 Arithmetic Overflow Tests

```
TEST: uint128_reward_calculation
  Setup: weight = 999_999_999 (max isqrt for ~10^18 atomic)
         index_now = 10^18 (max plausible scaled index)
         index_entry = 0
  Expected: reward = weight * (index_now - index_entry) / SCALE
          = 999_999_999 * 10^18 / 10^18 = 999_999_999
  Failure mode: uint64 overflow at multiplication → wrong reward or crash

TEST: uint128_index_update
  Setup: delta_pool = 10^15 (large period inflow, atomic units)
         sum_weights = 1 (single minimal deposit)
  Expected: index_delta = 10^15 * 10^18 / 1 = 10^33
  Note: this EXCEEDS uint128 max (~3.4×10^38) only if chained.
        Single multiplication 10^15 * 10^18 = 10^33 fits in uint128.
  Failure mode: uint64 intermediate → truncated index → underpayment

TEST: uint128_locked_ratio
  Setup: total_locked = 10^18 (1 million PBC in atomic)
         circulating = 1 (single atomic unit circulating)
  Expected: raw_ratio = 10^18 * 1000 / 1 = 10^21 → clamped to 1000
  Failure mode: uint64 overflow at 10^18 * 1000 → wrong ratio
```

### B.2 Reorg Safety Tests

```
TEST: reorg_with_tx_claim
  Setup: Block N contains TX_CLAIM for deposit D (reward = 50 PBC)
         Block N is accepted, pool_balance decremented by 50
         Reorg replaces block N with block N' (no TX_CLAIM)
  Expected: pool_balance is restored to pre-N value
            deposit.entry_index is restored to pre-N value
            Deposit D is eligible to claim again
  Failure mode: pool_balance not restored → solvency violation

TEST: reorg_across_period_boundary
  Setup: Period boundary at block 720.
         Block 720 updates global index.
         Reorg forks at block 719, replacing blocks 719-725.
  Expected: Index recalculated from fork point.
            All claims in replaced blocks are reversed.
            New index may differ (different TXs in replaced blocks change Σw).
  Failure mode: stale index persists → incorrect rewards post-reorg

TEST: reorg_with_inheritance_trigger
  Setup: Inheritance trigger_height = 1000.
         Block 1000 triggers inheritance (transfers to heir).
         Reorg forks at block 999, new block 1000 has a TX_HEARTBEAT
         that resets the timer.
  Expected: Inheritance does NOT trigger.
            trigger_height is updated to new value.
  Failure mode: inheritance still triggers → funds sent to heir incorrectly
```

### B.3 Period Boundary Off-by-One Tests

```
TEST: deposit_eligibility_boundary
  Setup: DISTRIBUTION_PERIOD = 720
         Deposit created at block 719 (last block of period 0)
         Deposit created at block 720 (first block of period 1)
  Expected: Deposit at 719 → entry_index = I at period 0 start
            Deposit at 720 → entry_index = I at period 1 start
            Both MUST have different entry_index values
  Failure mode: off-by-one → deposit gets rewards for period it was created in

TEST: index_update_exact_boundary
  Setup: Block 720 is a period boundary
  Expected: Step 4 (TX processing) happens BEFORE Step 5 (index update)
            A TX_CLAIM in block 720 uses the OLD index (pre-update)
            A TX_TERM_DEPOSIT in block 720 enters Σw for the NEXT period
  Failure mode: index updated before TX processing → claim uses wrong index

TEST: period_zero_handling
  Setup: Block 0 (genesis). h % 720 == 0 but h == 0.
  Expected: NO index update at genesis (h > 0 check in Step 5)
  Failure mode: divide-by-zero or empty-period index update
```

### B.4 Edge Case: locked_ratio Extremes

```
TEST: locked_ratio_zero
  Setup: No deposits active. total_locked = 0, circulating > 0.
  Expected: locked_ratio = 0, fee_multiplier = 1000 (1.0×, no increase)
            min_fee = BASE_FEE_PER_BYTE * size * 1000 / 1000 = BASE_FEE * size

TEST: locked_ratio_max
  Setup: circulating_supply = 0 (everything locked or vested)
  Expected: locked_ratio = 1000 (clamped, not divide-by-zero)
            fee_multiplier = min(2000, FEE_FLOOR_CAP) = 2000
            min_fee = BASE_FEE * size * 2

TEST: locked_ratio_over_1000
  Setup: total_locked = 5000, circulating = 3 (ratio would be 1_666_666)
  Expected: locked_ratio = 1000 (clamped)
  Note: This can happen transiently if vested outputs unlock between
        deposit creation and ratio calculation.
```

### B.5 Multiple Claims in Same Block

```
TEST: two_claims_same_deposit_same_block
  Setup: Deposit D has accrued 100 PBC reward.
         Block contains two TX_CLAIM for deposit D.
  Expected: First claim succeeds (reward = 100 PBC, entry_index updated)
            Second claim yields 0 PBC reward (entry_index == current index)
            OR second claim is rejected as invalid (implementation choice)
  CONSENSUS RULE: Both behaviors are acceptable. The second claim MUST NOT
  create coins beyond what the pool can pay.

TEST: claims_from_different_deposits_same_block
  Setup: Address has deposits D1 (reward=50) and D2 (reward=30).
         Block contains TX_CLAIM for D1 then TX_CLAIM for D2.
  Expected: Both succeed. D1 claim: pool -= 50. D2 claim: pool -= 30.
            Total pool decrease = 80.
  Failure mode: both claims use pre-block pool balance → overpayment

TEST: claim_exhausts_pool_balance
  Setup: pool_balance = 100. Two claims in same block: 80 and 40.
  Expected: First claim (80) succeeds. Second claim is rejected because
            reward (40) > remaining pool_balance (20).
  Failure mode: both approved → pool goes negative → solvency violation
```

### B.6 Insurance Overflow Boundary

```
TEST: insurance_exact_cap
  Setup: insurance_pool_balance = INSURANCE_CAP exactly.
         Block adds 10 PBC to insurance (from deposit fees + allocation).
  Expected: After Step 8: overflow = 10, total_destroyed += 10,
            insurance_pool_balance = INSURANCE_CAP
  Failure mode: off-by-one → pool slightly above cap persists

TEST: insurance_subsidy_then_overflow
  Setup: insurance_pool_balance = INSURANCE_CAP + 50
         deposit_pool_balance < MIN_DEPOSIT_POOL
  Expected: Step 7 (subsidy) transfers from insurance to deposit pool FIRST
            Step 8 (overflow) then checks if insurance > CAP
            If subsidy reduced insurance below CAP → no overflow
  Failure mode: overflow checked before subsidy → subsidy uses capped pool
```

### B.7 Canonical uint64→Scalar Conversion

```
TEST: scalar_conversion_basic
  Input:  reward_amount = 1 (uint64)
  Expected scalar (32 bytes, hex):
    01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  Expected commitment: C = 1 × H  (verify against known H point)
  Failure mode: big-endian encoding → different scalar → wrong C

TEST: scalar_conversion_one_pbc
  Input:  reward_amount = 1_000_000_000_000 (1 PBC = 10^12 atomic)
  Expected scalar bytes 0-7 (LE): 00 10 a5 d4 e8 00 00 00
  Bytes 8-31: all zeros
  Failure mode: varint encoding or ASCII conversion → wrong scalar

TEST: scalar_conversion_max_uint64
  Input:  reward_amount = 0xFFFFFFFFFFFFFFFF (max uint64)
  Expected scalar bytes 0-7: FF FF FF FF FF FF FF FF
  Bytes 8-31: all zeros
  Verify: this scalar (≈ 1.8×10^19) is below Ed25519 order l
          (≈ 7.2×10^75), so NO modular reduction occurs.
  Failure mode: implementation applies sc_reduce32() → different scalar
                (for uint64 values this would be a no-op, but if the
                implementation treats it as a generic 32-byte input
                and reduces, it signals a conceptual misunderstanding
                that could break for other operations)

TEST: scalar_conversion_zero
  Input:  reward_amount = 0
  Expected scalar: 32 zero bytes
  Expected commitment: C = 0 × H = identity point (point at infinity)
  Note: reward_amount = 0 is a valid no-op claim. The commitment MUST
        be the identity point, not a random or error value.
  Failure mode: special-case handling that returns a non-identity point

TEST: commitment_balance_with_known_values
  Setup: Single input with known commitment C_in (amount=100, mask=r1)
         reward_amount = 50, fee = 1
         Change output (amount=99, mask=r2)
         Reward output (amount=50, mask=0)
  Verify: C_in + scalar(50)×H == C_change + scalar(50)×H + scalar(1)×H
  Equivalently: C_in == C_change + scalar(1)×H
  This confirms that the canonical scalar conversion produces commitments
  that satisfy the balance equation when combined with blinded outputs.
  Failure mode: any encoding mismatch → equation fails → TX rejected
```

---

*End of document.*
