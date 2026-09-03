# Privacy Bank Chain (PBC)

**PBC** is a privacy-first, CPU-mineable cryptocurrency with native financial primitives.
Forked from C64 Chain (Monero/Wownero fork), PBC introduces Term Deposits, Fee Redistribution, 
and an Inheritance Protocol — all enforced at the consensus level in C++.

## Key Features

* **Monero-grade privacy** — Ring signatures, stealth addresses, RingCT
* **CPU mining only** — rx/pbc algorithm (RandomX variant), ASIC-resistant
* **Native financial products** — Term Deposits with variable-rate yields
* **Solvency by construction** — Total payouts never exceed reward pool balances
* **Claim-based rewards** — Users claim individually via TX_CLAIM, no mass payouts
* **Anti-dump vesting** — 4-tier miner reward vesting (24h / 30d / 60d / 90d)
* **2% dev fund** — Consensus-enforced, cryptographically verified
* **Fee redistribution** — 50/50 fee split between miners and depositors
* **Insurance pool** — Safety buffer with hard cap and overflow deflation

## Building

```bash
# Dependencies (Ubuntu/Debian)
sudo apt install build-essential cmake pkg-config libboost-all-dev \
  libssl-dev libzmq3-dev libunbound-dev libsodium-dev libreadline-dev \
  libexpat1-dev libncurses5-dev doxygen graphviz

# Build
make -j$(nproc)

# Binaries will be in build/release/bin/
```

## Running

```bash
# Start daemon
./build/release/bin/pbcd

# Start wallet CLI
./build/release/bin/pbc-wallet-cli --generate-new-wallet=my_wallet

# Start mining (from daemon console)
start_mining <your_wallet_address> <threads>
```

## Network Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | rx/pbc (RandomX variant) |
| Block time | 300 seconds (5 minutes) |
| Max supply | ~18,446,744 PBC |
| Atomic unit | 10^12 |
| Miner share | 91% of R + 50% of F |
| Dev fund | 2% of R |
| Virtual pools | 7% of R + 50% of F |
| Mainnet P2P | 18830 |
| Mainnet RPC | 18831 |

## License

BSD-3-Clause — See LICENSE file.
