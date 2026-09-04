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

## Getting everything running (mise en route)

The official startup sequence — same as the
[website guide](https://privbank.finance/en/GUIDE_MISE_EN_ROUTE_PBC.html), adapted
to a source build (binaries in `build/release/bin/`, web files in `web/` at the
source root).

> ⚠️ **One node per LAN.** Only ONE machine on a local network runs a node (or the
> GUI wallet, which embeds one) — with `--rpc-bind-ip 0.0.0.0 --confirm-external-bind`.
> Every other machine on the LAN mines against it.

### 1. Start the node

```bash
screen -dmS node ./build/release/bin/pbcd --log-file $PWD/pbcd.log
# LAN node (accepts miners from other machines):
# screen -dmS node ./build/release/bin/pbcd --rpc-bind-ip 0.0.0.0 --confirm-external-bind --log-file $PWD/pbcd.log
```

The node connects to the network seeds automatically. Check it is syncing:

```bash
curl -s http://127.0.0.1:18831/get_info | grep -E '"height"|connections'
```

### 2. Create your wallet

```bash
./build/release/bin/pbc-wallet-cli --generate-new-wallet ~/mywallet
```

* Choose a wallet password.
* **WRITE DOWN the 25-word recovery phrase** — it is the only backup of your funds.
* Note your address (starts with `Pbc…` / `Pbd…` — command `address`).
* Type `exit` to quit (the wallet is saved as `~/mywallet` + `~/mywallet.keys`).

### 3. Start the wallet-RPC

```bash
screen -dmS wallet-rpc ./build/release/bin/pbc-wallet-rpc \
  --daemon-address 127.0.0.1:18831 \
  --wallet-file ~/mywallet \
  --password "YOUR_WALLET_PASSWORD" \
  --rpc-bind-port 18083 \
  --disable-rpc-login \
  --log-file /tmp/pbc-wallet-rpc.log
```

⚠️ Replace `YOUR_WALLET_PASSWORD` with the password from step 2 — with the placeholder
left in, wallet-rpc dies immediately with `invalid password`
(check: `tail -3 /tmp/pbc-wallet-rpc.log`).

### 4. Start the web interface

```bash
screen -dmS webui ./build/release/src/webui/pbc-webui \
  --rpc-port 18083 \
  --web-dir <source-root>/web \
  --wallet-log /tmp/pbc-wallet-rpc.log
```

### 5. Open your private bank

`http://<machine-IP>:8880` (from the machine itself: `http://127.0.0.1:8880`)

You get: dashboard, term deposits (30d–365d), claimable rewards (CLAIM), the bond
market, on-chain inheritance, and the bank statement.

### 6. Mine

The CPU miner is a separate project — binary + config on
[privbank.finance](https://privbank.finance) (section Downloads), source archive included.
Point `miner/config.json` at your node (`"url": "127.0.0.1:18831"` or the LAN node IP)
and set your address in `"user"`, then:

```bash
sudo screen -dmS miner ./miner/pbcminer --config miner/config.json -t $(($(nproc) - 2))
```

⏳ Mining rewards vest in 4 tranches unlocking at ~24h / ~30d / ~60d / ~90d
(protocol-enforced vesting). Your unlocked balance grows progressively.

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
