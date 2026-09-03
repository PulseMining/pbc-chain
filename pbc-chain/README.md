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

> **Build order matters: liboqs (post-quantum crypto) MUST be built first** — the
> node build fails without it (`src/crypto/CMakeLists.txt` requires
> `external/liboqs/build/install/lib/liboqs.a`).

```bash
# Dependencies (Ubuntu 24 / Debian 12)
sudo apt update
sudo apt install -y build-essential cmake pkg-config git \
  libboost-all-dev libssl-dev libzmq3-dev libunbound-dev \
  libsodium-dev libreadline-dev libexpat1-dev libncurses5-dev \
  doxygen graphviz screen curl

# 1. Build liboqs (Dilithium + Kyber) — MANDATORY FIRST
cd external/liboqs
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_INSTALL_PREFIX="$PWD/install" ..
make -j$(nproc)
make install

# 2. Build the node, wallets and web UI
cd ../../..        # back to the pbc-chain source root
mkdir -p build/release && cd build/release
cmake -Wno-dev -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=OFF -DBUILD_DOCUMENTATION=OFF \
  -DBUILD_DEBUG_UTILITIES=OFF -DUSE_DEVICE_TREZOR=OFF \
  -DBUILD_GUI_DEPS=OFF ../..
make -j$(nproc) daemon simplewallet wallet_rpc_server pbc-webui

# Binaries: build/release/bin/{pbcd, pbc-wallet-cli, pbc-wallet-rpc}
# Web UI server lands in build/release/src/webui/pbc-webui
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
| Block time | 60 seconds |
| Max supply | ~18,446,744 PBC |
| Atomic unit | 10^12 |
| Miner share | 91% of R + 50% of F |
| Dev fund | 2% of R |
| Virtual pools | 7% of R + 50% of F |
| Mainnet P2P | 18830 |
| Mainnet RPC | 18831 |

## License

BSD-3-Clause — See LICENSE file.
