// PBC — Privacy Bank Chain : application tout-en-un (Electron main process)
// Démarre pbcd + pbc-wallet-rpc + pbc-webui en sous-processus, affiche le
// webui dans une fenêtre native, icône de tray, arrêt propre des enfants.
// Cross-plateforme par construction (Windows aujourd'hui, Linux demain) :
//   - nom de binaire : .exe uniquement sous Windows
//   - chemins : path.join partout
//   - arrêt : taskkill /T /F (Windows) / SIGTERM (POSIX)
//   - données : app.getPath('userData') (%APPDATA%\PBC ou ~/.config/PBC)

const { app, BrowserWindow, Tray, Menu, dialog } = require('electron');
const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const http = require('http');
const net = require('net');

const isWin = process.platform === 'win32';
const EXE = isWin ? '.exe' : '';

// En app packagée : resources/ à côté de l'exécutable ; en dev : ./resources du projet
const RES = app.isPackaged ? process.resourcesPath : path.join(__dirname, '..', 'resources');
const BIN = path.join(RES, 'bin');
const WEB = path.join(RES, 'web');

const DATA = app.getPath('userData');
const WALLETS = path.join(DATA, 'wallets');
const LOGS = DATA;
fs.mkdirSync(WALLETS, { recursive: true });

// ── Journal applicatif (diagnostic Windows : %APPDATA%\PBC\pbc-app.log) ──
const APP_LOG = path.join(LOGS, 'pbc-app.log');
function log(...args) {
  const line = new Date().toISOString() + ' ' +
    args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ') + '\r\n';
  try { fs.appendFileSync(APP_LOG, line); } catch (e) { /* rien */ }
  console.log(...args);
}
process.on('uncaughtException', (err) => {
  log('[pbc] UNCAUGHT EXCEPTION:', err && err.stack ? err.stack : String(err));
  app.quit();
});
process.on('unhandledRejection', (err) => {
  log('[pbc] UNHANDLED REJECTION:', err && err.stack ? err.stack : String(err));
});

// Icône : résolution défensive (le layout diffère dev / app packagée)
function resolveIcon() {
  const cands = [
    path.join(__dirname, '..', 'build', 'icon.png'),
    path.join(RES, 'build', 'icon.png'),
    path.join(process.resourcesPath || '', 'build', 'icon.png'),
    path.join(process.resourcesPath || '', 'app', 'build', 'icon.png'),
  ];
  for (const c of cands) {
    try { if (fs.existsSync(c)) return c; } catch (e) { /* suivant */ }
  }
  return null;
}

const WEBUI_PORT = 8880;
const children = [];

// Fichier d'identité de l'instance active (pour le message "déjà en cours")
const INSTANCE_FILE = path.join(DATA, 'pbc-instance.json');
function writeInstanceInfo() {
  try {
    fs.writeFileSync(INSTANCE_FILE, JSON.stringify({
      exe: process.execPath,
      pid: process.pid,
      version: app.getVersion(),
      startedAt: new Date().toISOString()
    }, null, 2));
  } catch (e) { /* non bloquant */ }
}
function readInstanceInfo() {
  try { return JSON.parse(fs.readFileSync(INSTANCE_FILE, 'utf8')); } catch (e) { return null; }
}
function clearInstanceInfo() {
  try { fs.rmSync(INSTANCE_FILE, { force: true }); } catch (e) { /* rien */ }
}

function spawnBin(name, args) {
  const binPath = path.join(BIN, name + EXE);
  log('[pbc] start', binPath, args.join(' '));
  let p;
  try {
    p = spawn(binPath, args, { stdio: 'ignore', windowsHide: true });
  } catch (err) {
    log('[pbc]', name, 'SPAWN FAILED:', err.message);
    return null;
  }
  p.on('exit', (code) => log('[pbc]', name, 'exited with code', code));
  p.on('error', (err) => log('[pbc]', name, 'spawn error:', err.message));
  children.push(p);
  return p;
}

function killChildren() {
  log('[pbc] arrêt des composants (' + children.length + ')');
  for (const p of children) {
    try {
      if (!p || p.killed || p.exitCode !== null) continue;
      if (isWin) {
        execSync(`taskkill /PID ${p.pid} /T /F`, { stdio: 'ignore' });
      } else {
        p.kill('SIGTERM');
      }
    } catch (e) { /* déjà mort */ }
  }
}

// ── Contrôle des ports AVANT spawn (correctif BUG 2 — plus d'échec silencieux) ──
// Si un ancien pbc-webui / pbc-wallet-rpc / pbcd (ex. paquet pbc_node du site,
// ou une instance oubliée) occupe déjà les ports, nos binaires ne peuvent pas
// se binder et la fenêtre chargerait l'ANCIEN webui. On refuse de démarrer,
// avec un message explicite + trace dans pbc-app.log.
const PORTS_REQUIS = [8880, 18083, 18831];
function portOccupe(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolve(true); });
    s.on('error', () => resolve(false));
    s.setTimeout(1000, () => { s.destroy(); resolve(false); });
  });
}
async function portsOccupes() {
  const res = [];
  for (const p of PORTS_REQUIS) { if (await portOccupe(p)) res.push(p); }
  return res;
}

// Attend que le webui réponde, puis ouvre la fenêtre (max ~90 s)
function waitWebUi(cb, tries = 180) {
  if (tries <= 0) { cb(); return; } // ouvre quand même, l'utilisateur verra l'état
  const req = http.get({ host: '127.0.0.1', port: WEBUI_PORT, path: '/', timeout: 1500 }, (res) => {
    res.resume();
    cb();
  });
  req.on('error', () => setTimeout(() => waitWebUi(cb, tries - 1), 500));
  req.on('timeout', () => { req.destroy(); setTimeout(() => waitWebUi(cb, tries - 1), 500); });
}

let win = null;
let tray = null;

function createWindow() {
  if (win) { win.focus(); return; }
  win = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 960,
    minHeight: 640,
    autoHideMenuBar: true,
    backgroundColor: '#0b1020',
    icon: resolveIcon() || undefined,
    webPreferences: { nodeIntegration: false, contextIsolation: true }
  });
  win.loadURL(`http://127.0.0.1:${WEBUI_PORT}`);
  log('[pbc] window opened on', `http://127.0.0.1:${WEBUI_PORT}`);
  win.on('closed', () => { win = null; });
}

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  // Une instance tourne déjà : REFUSER de se lancer et le SIGNALER clairement.
  app.whenReady().then(() => {
    log('[pbc] lancement refusé : une instance est déjà en cours');
    const info = readInstanceInfo();
    const who = info
      ? path.basename(info.exe) + '  —  version ' + (info.version || '?') +
        ', PID ' + info.pid + ', lancée le ' +
        new Date(info.startedAt).toLocaleString()
      : 'instance PBC (détails indisponibles)';
    dialog.showMessageBoxSync({
      type: 'warning',
      title: 'PBC',
      message: 'PBC est déjà en cours d\u2019exécution.',
      detail: 'Instance active : ' + who + '\n\n' +
        'Retrouvez-la via son icône dans la zone de notification ' +
        '(près de l\u2019horloge).\n\n' +
        'Fermez-la d\u2019abord (clic droit sur l\u2019icône → Quitter PBC), ' +
        'puis relancez l\u2019application.',
      buttons: ['OK'],
      noLink: true
    });
    app.quit();
  });
} else {
  app.on('second-instance', () => {
    // Un 2e lancement a été refusé : ramener la fenêtre existante au premier plan
    if (win) {
      if (win.isMinimized()) win.restore();
      win.show();
      win.focus();
    } else {
      createWindow();
    }
  });

  app.whenReady().then(async () => {
    log('[pbc] app ready — version', app.getVersion(), '| platform', process.platform);
    log('[pbc] resources:', RES, '| userData:', DATA);
    writeInstanceInfo();
    // 0. Contrôle des ports : si des composants PBC tournent déjà sur cette
    //    machine (autre installation type paquet pbc_node, instance oubliée),
    //    on refuse de démarrer et on le dit — jamais d'échec silencieux.
    const occupes = await portsOccupes();
    if (occupes.length > 0) {
      log('[pbc] lancement refusé : ports déjà occupés :', occupes.join(', '));
      dialog.showMessageBoxSync({
        type: 'warning',
        title: 'PBC',
        message: 'Des composants PBC tournent déjà sur cette machine.',
        detail: 'Ports occupés : ' + occupes.join(', ') +
          ' (l\u2019application a besoin de 8880, 18083 et 18831).\n\n' +
          'C\u2019est peut-\u00eatre une autre installation (paquet pbc_node) ' +
          'ou une instance oubli\u00e9e.\n\n' +
          'Arr\u00eatez-les (ex. : pkill -f pbc-webui ; pkill -f pbc-wallet-rpc ; ' +
          'pkill -f pbcd) puis relancez PBC.',
        buttons: ['OK'],
        noLink: true
      });
      app.quit();
      return;
    }
    // 1. Noeud PBC — ligne de lancement de référence (aucune autre option)
    spawnBin('pbcd', [
      '--rpc-bind-ip', '0.0.0.0', '--confirm-external-bind',
      '--log-file', path.join(LOGS, 'pbcd.log')
    ]);
    // 2. Wallet RPC — mode dossier (création/import/ouverture via le webui)
    spawnBin('pbc-wallet-rpc', [
      '--wallet-dir', WALLETS,
      '--daemon-address', '127.0.0.1:18831',
      '--rpc-bind-port', '18083',
      '--disable-rpc-login',
      '--log-file', path.join(LOGS, 'wallet-rpc.log')
    ]);
    // 3. Interface web
    spawnBin('pbc-webui', [
      '--web-dir', WEB,
      '--wallet-log', path.join(LOGS, 'wallet-rpc.log'),
      '--rpc-port', '18083',
      '--wallet-dir', WALLETS
    ]);

    waitWebUi(() => createWindow());

    try {
      const iconPath = resolveIcon();
      if (!iconPath) log('[pbc] WARN: icon.png introuvable, tray sans icône');
      tray = new Tray(iconPath);
      tray.setToolTip('PBC — Privacy Bank Chain');
      tray.setContextMenu(Menu.buildFromTemplate([
        { label: 'Ouvrir PBC', click: () => createWindow() },
        { type: 'separator' },
        { label: 'Quitter PBC (arrête le nœud et le wallet)', click: () => app.quit() }
      ]));
      tray.on('click', () => { if (win) win.focus(); });
      log('[pbc] tray créé');
    } catch (err) {
      log('[pbc] TRAY FAILED (non bloquant):', err.message);
    }
  });

  // L'app reste dans le tray quand la fenêtre est fermée ; Quit explicite seulement.
  app.on('window-all-closed', () => { /* volontairement rien : vie dans le tray */ });
  app.on('before-quit', () => { killChildren(); clearInstanceInfo(); });
}
