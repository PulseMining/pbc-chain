# PBC — Closed Mainnet Launch Guide

## Prerequisites
Build the daemon and wallet (see README.md for dependencies).

## Step 1: Generate Genesis Block
```bash
./build/release/bin/pbcd --print-genesis-tx
```
Copy the genesis TX hex and update `src/cryptonote_config.h`:
```cpp
std::string const GENESIS_TX = "<paste here>";
```
Rebuild after updating.

## Step 2: Generate Dev Fund Wallet
```bash
./build/release/bin/pbc-wallet-cli --generate-new-wallet=devfund
```
Note the public view key, secret view key, and public spend key.
Update in `src/cryptonote_config.h`:
```cpp
#define PBC_DEV_FUND_VIEWKEY       "<public view key>"
#define PBC_DEV_FUND_VIEWKEY_SECRET "<secret view key>"
#define PBC_DEV_FUND_SPENDKEY      "<public spend key>"
```
Rebuild after updating.

## Step 3: Start Seed Node
```bash
./build/release/bin/pbcd --p2p-bind-ip 0.0.0.0 --p2p-bind-port 18830 \
  --rpc-bind-ip 0.0.0.0 --rpc-bind-port 18831 --confirm-external-bind
```

## Step 4: Connect Friends
Each friend runs:
```bash
./build/release/bin/pbcd --add-peer <seed_node_ip>:18830
```

## Step 5: Start Mining
From daemon console:
```
start_mining <wallet_address> auto
```
Or launch with the flag:
```bash
./build/release/bin/pbcd --start-mining <wallet_address> --mining-threads auto
```

## Step 6: Create Wallet
```bash
./build/release/bin/pbc-wallet-cli --daemon-address 127.0.0.1:18831 \
  --generate-new-wallet=my_wallet
```

## Network Ports
| Service | Port |
|---------|------|
| Mainnet P2P | 18830 |
| Mainnet RPC | 18831 |
| Mainnet ZMQ | 18832 |
| Testnet P2P | 28830 |
| Testnet RPC | 28831 |

## Block Reward Split (per block)
- Miner: 91% of R + 50% of fees → 4 vested outputs
- Dev fund: 2% of R → 1 output
- Virtual pools: 7% of R + 50% of fees (not minted, tracked by consensus)
  - Fee Pool: 3.5% of R
  - Term Deposit Pool: 2.5% of R
  - Insurance Pool: 1.0% of R
