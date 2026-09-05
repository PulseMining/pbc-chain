// PBC — preload minimal (contextIsolation) : expose UNIQUEMENT les bridges nécessaires.
// Le renderer (webui) n'a aucun accès Node — tout passe par ipcRenderer.invoke.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pbcPool', {
  // fetchVesting(address) → { ok:true, status, body } | { ok:false, error }
  fetchVesting: (address) => ipcRenderer.invoke('pool:fetch-vesting', address),
});

// PBC 05/09 (Stef) : bouton « Parcourir… » du setup + liens explorateur.
contextBridge.exposeInMainWorld('pbcWallet', {
  // pickWalletFile() → { ok:true, name } | { ok:false, error }
  pickWalletFile: () => ipcRenderer.invoke('wallet:pick-file'),
  // openExternal(url) — ouvre une URL https dans le navigateur système.
  openExternal: (url) => ipcRenderer.invoke('shell:open-external', url),
});
