# PBC — Application tout-en-un (Electron)

Application de bureau unique : démarre **pbcd** (nœud), **pbc-wallet-rpc** et
**pbc-webui** en sous-processus, affiche l'interface dans une fenêtre native,
icône de tray, arrêt propre des enfants à la sortie.

## Structure

```
pbc-app/
├── package.json            # métadonnées + scripts npm
├── electron-builder.yml    # packaging (win: portable .exe / linux: AppImage)
├── build/icon.png          # icône (256×256)
├── src/main.js             # logique : spawn des 3 binaires, fenêtre, tray, kill
│                           #   cross-plateforme par construction (.exe, taskkill
│                           #   vs SIGTERM, chemins path.join, userData)
└── resources/              # CONTENU INJECTÉ AU BUILD (pas dans git)
    ├── bin/                #   pbcd, pbc-wallet-cli, pbc-wallet-rpc, pbc-webui
    └── web/pbc-webui.html  #   interface web (avec page de setup 1er démarrage)
```

## Données utilisateur (à l'exécution)

Tout vit dans `userData` (Windows : `%APPDATA%\PBC`, Linux : `~/.config/PBC`) :
`wallets/` (fichiers wallet), `pbcd.log`, `wallet-rpc.log`.
La blockchain reste dans le dossier standard du nœud (ligne de lancement de
référence inchangée : `--rpc-bind-ip 0.0.0.0 --confirm-external-bind --log-file …`).

## Build Windows (produit : un seul .exe portable)

Prérequis : Node 18+, wine (pour rcedit), les 4 binaires Windows cross-compilés
(voir SUIVI_NEURON_WALLET.md — toolchain depends x86_64-w64-mingw32 sur mine11).

```bash
cd pbc-app
# 1. déposer les binaires Windows dans resources/bin/ et le html dans resources/web/
npm install
npx electron-builder --win portable
# → dist/PBC-<version>-win64-portable.exe
```

## Build Linux (plus tard — même sources)

```bash
# 1. remplacer resources/bin/ par les binaires Linux (pbcd, pbc-wallet-cli,
#    pbc-wallet-rpc, pbc-webui compilés nativement) + resources/web/ identique
npm install
npx electron-builder --linux AppImage
# → dist/PBC-<version>-linux-x86_64.AppImage
```

`src/main.js` n'a AUCUNE ligne spécifique Windows hors branches
`process.platform === 'win32'` déjà en place (.exe, taskkill /T /F, windowsHide).

## Vérifications effectuées (30/08/2026)

- Shell Electron testé sous Xvfb (stubs) : spawn des 3 enfants avec les bons
  arguments, attente du webui (health), fenêtre, tray, userData créé.
- Les binaires Windows eux-mêmes sont validés via le pack ZIP (test réel de
  Stef sur Windows) — l'app embarque exactement les mêmes avec les mêmes args.
- L'exe portable ne peut PAS être testé sous wine (Electron/Chromium crash
  connu de la couche d'émulation, sans rapport avec Windows réel) → validation
  finale sur la machine Windows de Stef.
