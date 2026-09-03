# Building PBC from source — node, wallets & web UI

Build the PBC node (`pbcd`), the CLI wallet, the wallet-RPC and the web interface from the official source code, then get everything running. Tested on **Ubuntu 24 / Debian 12**.

> Don't want to compile? Pre-built node packages and GUI wallets are on [privbank.finance](https://privbank.finance) with a dedicated quick-start guide.
>
> The CPU miner is a separate project — its source and builds are distributed on the project website, not in this repository.

## 1. Prerequisites (Ubuntu 24 / Debian 12)

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config git \
  libboost-all-dev libssl-dev libzmq3-dev libunbound-dev \
  libsodium-dev libreadline-dev libexpat1-dev libncurses5-dev \
  doxygen graphviz screen curl
```

## 2. Get the source

Clone this repository:

```bash
git clone https://github.com/PulseMining/pbc-chain.git
cd pbc-chain/pbc-chain
```

*(Alternatively, download the versioned, md5-verified source archive from [privbank.finance](https://privbank.finance) — always check the md5 against the `md5sums.txt` published on the site before building.)*

## 3. Build liboqs (post-quantum crypto) — MANDATORY FIRST

PBC ships **liboqs** (Dilithium + Kyber) in `external/liboqs`: it must be built and installed **before** the node.

```bash
cd external/liboqs
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_INSTALL_PREFIX="$PWD/install" ..
make -j$(nproc)
make install
```

## 4. Build the node, wallets and web interface

```bash
cd ../../..        # back to the pbc-chain source root
mkdir -p build/release && cd build/release
cmake -Wno-dev -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=OFF -DBUILD_DOCUMENTATION=OFF \
  -DBUILD_DEBUG_UTILITIES=OFF -DUSE_DEVICE_TREZOR=OFF \
  -DBUILD_GUI_DEPS=OFF ../..
make -j$(nproc) daemon simplewallet wallet_rpc_server pbc-webui
```

Binaries land in `build/release/bin/`:

| Binary | Role |
|---|---|
| `pbcd` | the node (daemon) |
| `pbc-wallet-cli` | command-line wallet |
| `pbc-wallet-rpc` | wallet RPC (backend of the web UI) |
| `pbc-webui` | web interface server (web files in `web/` at the source root) |

⏱️ Expect 30 min to 1 h 30 depending on the machine. If the build fails for lack of RAM, re-run `make` with fewer jobs (e.g. `-j2`).

## 5. Run everything

**The node:**

```bash
screen -dmS node ./build/release/bin/pbcd --log-file $PWD/pbcd.log
```

(Several machines on the same LAN? Only ONE runs the node, with `--rpc-bind-ip 0.0.0.0 --confirm-external-bind` — the others point to it.)

**The wallet** (create it once):

```bash
./build/release/bin/pbc-wallet-cli --generate-new-wallet ~/mywallet
```

**Write down the 25-word seed phrase — it is the only backup of your funds.**

**The wallet-RPC:**

```bash
screen -dmS wallet-rpc ./build/release/bin/pbc-wallet-rpc \
  --daemon-address 127.0.0.1:18831 --wallet-file ~/mywallet \
  --password "YOUR_PASSWORD" --rpc-bind-port 18083 \
  --disable-rpc-login --log-file /tmp/pbc-wallet-rpc.log
```

**The web interface:**

```bash
screen -dmS webui ./build/release/bin/pbc-webui \
  --rpc-port 18083 --web-dir <source-root>/web \
  --wallet-log /tmp/pbc-wallet-rpc.log
```

**Open your browser:** `http://<machine-IP>:8880`

From the dashboard you can manage your term deposits, track your vesting mining rewards, use the bond market and set up on-chain inheritance — all features are documented in the guides on [privbank.finance](https://privbank.finance).

## 6. (Optional) Build the GUI wallet app (Electron)

The all-in-one desktop app wraps the daemon, wallet-RPC and web UI in a single native window:

```bash
cd pbc-app                    # from the repository root
npm install
# place the four binaries built in step 4 into resources/bin/
# (pbcd, pbc-wallet-cli, pbc-wallet-rpc, pbc-webui)
npx electron-builder --linux  # produces a .deb + AppImage in dist/
```

For a Windows portable build, place the Windows `.exe` binaries in `resources/bin/` instead and run `npx electron-builder --win portable`.

---

*Network ports: P2P 18830 · daemon RPC 18831 · wallet-RPC 18083 · web UI 8880.*
