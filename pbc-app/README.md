# PBC — All-in-one desktop app (Electron)

A single desktop application: it starts **pbcd** (node), **pbc-wallet-rpc** and
**pbc-webui** as child processes, shows the interface in a native window, with
a tray icon and clean shutdown of the children on exit.

## Structure

```
pbc-app/
├── package.json            # metadata + npm scripts
├── electron-builder.yml    # packaging (win: portable .exe / linux: AppImage + .deb)
├── build/icon.png          # icon (256×256)
├── src/main.js             # logic: spawns the 3 binaries, window, tray, kill
│                           #   cross-platform by construction (.exe, taskkill
│                           #   vs SIGTERM, path.join, userData)
└── resources/              # CONTENT INJECTED AT BUILD TIME (not in git)
    ├── bin/                #   pbcd, pbc-wallet-cli, pbc-wallet-rpc, pbc-webui
    └── web/pbc-webui.html  #   web interface (with first-run setup page)
```

## User data (at runtime)

Everything lives in `userData` (Windows: `%APPDATA%\PBC`, Linux: `~/.config/PBC`):
`wallets/` (wallet files), `pbcd.log`, `wallet-rpc.log`.
The blockchain stays in the node's standard directory (reference launch line
unchanged: `--rpc-bind-ip 0.0.0.0 --confirm-external-bind --log-file …`).

## Windows build (product: a single portable .exe)

Requirements: Node 18+, wine (for rcedit), the 4 cross-compiled Windows
binaries (depends toolchain x86_64-w64-mingw32).

```bash
cd pbc-app
# 1. drop the Windows binaries into resources/bin/ and the html into resources/web/
npm install
npx electron-builder --win portable
# → dist/PBC-<version>-win64-portable.exe
```

## Linux build (same sources)

```bash
# 1. replace resources/bin/ with the Linux binaries (pbcd, pbc-wallet-cli,
#    pbc-wallet-rpc, pbc-webui built natively) + identical resources/web/
npm install
npx electron-builder --linux AppImage deb
# → dist/PBC-<version>-linux-x86_64.AppImage and dist/PBC-<version>-linux-x86_64.deb
```

`src/main.js` has NO Windows-specific line outside the existing
`process.platform === 'win32'` branches (.exe, taskkill /T /F, windowsHide).

## Notes

- The packaged app embeds the exact node/wallet binaries of the corresponding
  chain release — binaries are never stored in this repository; they are
  injected at build time into `resources/`.
- The portable .exe cannot be tested under wine (known Electron/Chromium crash
  of the emulation layer, unrelated to real Windows) → final validation on a
  real Windows machine.
- Pre-built packages are distributed on https://privbank.finance with md5 sums.
