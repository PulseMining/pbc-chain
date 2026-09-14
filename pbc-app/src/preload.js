// PBC — preload minimal (contextIsolation) : expose UNIQUEMENT les bridges nécessaires.
// Le renderer (webui) n'a aucun accès Node — tout passe par ipcRenderer.invoke.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pbcPool', {
  // fetchVesting(address) → { ok:true, status, body, summary, summaryError } | { ok:false, error }
  fetchVesting: (address) => ipcRenderer.invoke('pool:fetch-vesting', address),
});
