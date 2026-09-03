# Privacy Bank Chain (PBC)

**Private money that works for you.** Privacy Bank Chain is a Proof-of-Work blockchain that combines Monero-grade privacy with native, consensus-enforced banking primitives — no smart contracts, no trusted third parties, no company behind it.

🌐 **Website & downloads: [privbank.finance](https://privbank.finance)**
🟢 **Mainnet is LIVE since 2026-08-31** — the chain is running, mining is open to everyone (CPU, RandomX V2).

💬 **Community: [Discord](https://discord.gg/UgkdkYXdJQ)**

## What's in this repository

This repository hosts the **source code only** (no binaries):

- **`pbc-chain/`** — the full node, CLI wallet, wallet-RPC and web interface (v8.2.14)
- **`pbc-app/`** — the all-in-one GUI wallet app (Electron, v1.0.11, Windows/Linux) — v1.0.11 adds opt-in pool integration (your pool's vesting data merged with on-chain figures, "solo + pool" breakdown, cross-checked to the cent)
- **`BUILD.md`** — build & setup guide (node, wallets, web UI)

The miner source is distributed separately and is not part of this repository.

📦 **Pre-compiled binaries** (node packages for Zen1/Zen3/Zen5 CPUs, GUI wallets for Windows & Linux, static builds) and **step-by-step quick-start guides** are available on the project website: **[privbank.finance](https://privbank.finance)** — the same source code is also downloadable there as a versioned, md5-verified archive.

## Partnership with PulseMining

Privacy Bank Chain is developed **in partnership with [PulseMining](https://discord.gg/UgkdkYXdJQ)** — a mining community that scouts, tests and delivers high-potential coins turnkey every week: pool, miner, multi-language support and more.

Join the PBC project channels on the PulseMining Discord:

- [Français](https://discord.com/channels/1516526810458755263/1517540676089413732)
- [English](https://discord.com/channels/1516526810458755263/1517540694775038084)
- [Русский](https://discord.com/channels/1516526810458755263/1517540736751505560)
- [Español](https://discord.com/channels/1516526810458755263/1517540713976561765)

---

## What makes PBC different

PBC is a Monero-class privacy chain (ring signatures, stealth addresses, RingCT hidden amounts) extended **at the consensus level** with a complete private-banking layer. Everything below is enforced by every node, in deterministic integer arithmetic — no floating point, no platform-dependent rounding.

### 🔐 Native privacy + ⚛️ hybrid post-quantum by design
CryptoNote privacy (RingCT, ring signatures, stealth addresses) combined with a hybrid post-quantum layer: **ML-DSA-65 (Dilithium) signatures and ML-KEM-768 (Kyber) encapsulation** via liboqs. From hard fork v23, a Dilithium co-signature is **mandatory** to authorize any public spend-authority operation (deposit withdrawals, market payouts) — breaking Ed25519 alone is no longer enough.

### 🏦 Term deposits with real yield
Lock PBC for 30 to 365 days (tiers ×1.0 to ×2.0) and earn protocol-paid rewards. Rewards are **claim-based** through two deterministic global indexes (deposit index + fee index) — claim anytime, your principal stays locked until maturity. Solvency is guaranteed by construction: each distribution period pays exactly what the pools collected. **No fixed rate is ever promised** — a fixed rate would be a debt the chain cannot guarantee. Yield comes from real sources: 6% of every block reward plus 50% of all network fees.

### 🛒 The first native bond market on a privacy chain
Need liquidity before maturity? Every deposit is economically a **private bearer bond** — resell it on the atomic, on-chain secondary market at any price you choose. No intermediary, no commission, no penalty, no trusted third party. To our knowledge, this is the first native bond market on a Monero-class chain.

### 🕊️ Trustless on-chain inheritance
Designate an heir directly on the chain. A dead-man's switch (18-month inactivity, enforced by a consensus gate since HF v21) lets the heir claim the funds with pre-signed sweep transactions maintained automatically by the wallet. Claims and other permissionless operations deliberately cannot reset the inactivity clock — nobody can grief your heir, and no notary is involved.

### 🛡️ Insurance fund with deterministic deflation
1% of every block reward feeds an insurance pool that subsidizes depositor rewards during low-activity periods. The fund is capped at exactly 1% of the maximum supply (184,467 PBC) — **any excess is permanently burned at every block, by consensus**. A finite, auditable monetary policy on a strictly capped supply (18,446,744 PBC).

### ⛏️ Fair CPU mining — RandomX V2
Mining uses RandomX V2 (`rx/pbc`): a regular CPU is enough, no specialized hardware. Miner coinbase rewards vest in 4 staggered tranches (24 h / 30 / 60 / 90 days) enforced by consensus — freshly minted sell pressure is structurally smoothed.

### 📉 Stability by construction
A **Locked Supply Multiplier** dampens reward inflows when more than 60% of circulating supply is locked in deposits, preventing reflexive "lock-everything" spirals. A dynamic fee floor (up to 2×) strengthens the fee-based yield as adoption grows.

## Honest by design

- No premine promises, no fixed APY: yields depend on actual network participation.
- Everything above is implemented in fixed, auditable C++ with full reorg symmetry — read the [technical whitepaper](https://privbank.finance/docs/Privacy_Bank_Chain_Whitepaper_v1_8.pdf) for the exact formulas.

## Getting started

1. **Easy way:** download the all-in-one GUI wallet (Windows / Linux) or a node package from [privbank.finance](https://privbank.finance) and follow the quick-start guide there — 10 minutes from download to mining.
2. **Build from source:** see **[BUILD.md](BUILD.md)** (Ubuntu 24 / Debian 12 — node, CLI wallet, wallet-RPC, web UI, GUI app).
3. The full source code is also published as a versioned, md5-verified archive on [privbank.finance](https://privbank.finance), alongside the compiled binaries.

## License

Privacy Bank Chain is open source. See the `LICENSE` file in `pbc-chain/` for details.

---

*Privacy Bank Chain is experimental software. Nothing in this repository or on the website constitutes financial advice or a promise of return.*
