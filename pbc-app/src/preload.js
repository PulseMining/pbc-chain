// PBC — preload minimal (contextIsolation) : expose UNIQUEMENT le fetch pool Aria.
// Le renderer (webui) n'a aucun accès Node — tout passe par ipcRenderer.invoke.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pbcPool', {
  // fetchVesting(address) → { ok:true, status, body } | { ok:false, error }
  fetchVesting: (address) => ipcRenderer.invoke('pool:fetch-vesting', address),
});
