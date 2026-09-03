# PBC WebUI — Privacy Bank Chain Dashboard

Interface web bancaire pour le wallet PBC.

## Architecture

```
pbc-webui (binaire C++)          pbc-wallet-rpc
   ├─ HTTP :8880 ──────────┐       ├─ JSON-RPC :18083
   │  GET /  → HTML         │       │
   │  POST /json_rpc ───────┼──────▶│  (proxy transparent)
   │                        │       │
   └─ 0.0.0.0 (LAN)        │       └─ 127.0.0.1 (local)
                            │
                     Navigateur
```

## Lancement

```bash
# 1. Démarrer le daemon
./pbcd --detach

# 2. Démarrer wallet-rpc
./pbc-wallet-rpc --wallet-file ~/PBC/wallet \
                 --password xxx \
                 --rpc-bind-port 18083 \
                 --disable-rpc-login

# 3. Démarrer le WebUI
./pbc-webui --rpc-port 18083

# → Ouvrir http://192.168.x.x:8880 (LAN)
# → Ou     http://127.0.0.1:8880   (local)
```

## Options

```
--port <N>           Port HTTP (default: 8880)
--rpc-host <IP>      Wallet RPC host (default: 127.0.0.1)
--rpc-port <N>       Wallet RPC port (default: 18083)
--web-dir <path>     Chemin vers le dossier web/
--localhost-only     Restreindre à 127.0.0.1 uniquement
```

## Pages

| Page         | Description                                  |
|--------------|----------------------------------------------|
| Dashboard    | Vue patrimoniale, allocation, mining stats   |
| Vesting      | Déblocages mining par tier, graphique        |
| Deposits     | Dépôts à terme, simulateur APY, claim        |
| Transactions | Historique envois/réceptions, formulaire send |
| Statement    | Relevé journalier (crédits/débits/net)       |
| Income       | Revenus mining, projections annuelles        |
| Admin        | Refresh, rescan, infos wallet/daemon         |

## Sécurité

- Le binaire `pbc-webui` écoute sur `0.0.0.0:8880` (tout le LAN)
- Il proxy vers `pbc-wallet-rpc` qui reste sur `127.0.0.1` (local uniquement)
- Pas d'authentification (prévu pour réseau domestique)
- Option `--localhost-only` pour restreindre l'accès
