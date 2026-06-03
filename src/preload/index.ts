// ============================================================================
// VMTrace Preload Script
// Safely exposes Electron IPC communication methods to the UI Renderer.
// ============================================================================

import { contextBridge, ipcRenderer } from 'electron'

contextBridge.exposeInMainWorld('vmtrace', {
  // ─── Binary Operations ───
  openFileDialog: () => ipcRenderer.invoke('binary:open-dialog'),
  loadBinary: (path: string) => ipcRenderer.invoke('binary:load', { path }),
  getBinaryInfo: () => ipcRenderer.invoke('binary:info'),
  disasmRange: (start: number, end: number, baseAddress: number) => ipcRenderer.invoke('disasm:range', { start, end, baseAddress }),
  disasmSection: (sectionName: string) => ipcRenderer.invoke('disasm:section', { sectionName }),

  // ─── Emulation Controls ───
  step: () => ipcRenderer.invoke('vm:step'),
  stepOver: () => ipcRenderer.invoke('vm:step-over'),
  run: () => ipcRenderer.invoke('vm:run'),
  stop: () => ipcRenderer.invoke('vm:stop'),
  reset: () => ipcRenderer.invoke('vm:reset'),
  getState: () => ipcRenderer.invoke('vm:get-state'),

  // ─── Annotations ───
  labelHandler: (address: number, label: string) => ipcRenderer.invoke('vm:label-handler', { address, label }),
  setHypothesis: (address: number, hypothesis: string) => ipcRenderer.invoke('vm:set-hypothesis', { address, hypothesis }),

  // ─── Bookmarks ───
  addBookmark: (bookmark: any) => ipcRenderer.invoke('bookmark:add', bookmark),
  removeBookmark: (id: string) => ipcRenderer.invoke('bookmark:remove', { id }),
  listBookmarks: () => ipcRenderer.invoke('bookmark:list'),

  // ─── Analysis Views ───
  getTrace: () => ipcRenderer.invoke('trace:get'),
  getCFG: () => ipcRenderer.invoke('cfg:get'),

  // ─── Plugins ───
  listPlugins: () => ipcRenderer.invoke('plugin:list'),
  getPluginLogs: () => ipcRenderer.invoke('plugin:logs'),
  setPluginPort: (port: number) => ipcRenderer.invoke('plugin:set-port', { port }),
  selectPluginFolder: () => ipcRenderer.invoke('plugin:select-folder'),
  loadPluginFolder: (path: string) => ipcRenderer.invoke('plugin:load-folder', { path }),
  getLoadedPluginProcesses: () => ipcRenderer.invoke('plugin:get-loaded-processes'),
  startPlugin: (path: string) => ipcRenderer.invoke('plugin:start', { path }),
  stopPlugin: (path: string) => ipcRenderer.invoke('plugin:stop', { path }),
  installDeps: (packages: string[]) => ipcRenderer.invoke('plugin:install-deps', { packages }),
  setPluginAutoInstall: (enabled: boolean) => ipcRenderer.invoke('plugin:set-auto-install', { enabled }),
  getPluginAutoInstall: () => ipcRenderer.invoke('plugin:get-auto-install'),

  // ─── Events from Main Process ───
  onBinaryLoaded: (callback: (data: any) => void) => {
    ipcRenderer.on('binary:loaded', (_, data) => callback(data))
  },
  onVMStateUpdated: (callback: (data: any) => void) => {
    ipcRenderer.on('vm:state-updated', (_, data) => callback(data))
  },
  onAnnotationsUpdated: (callback: (data: any) => void) => {
    ipcRenderer.on('vm:annotations-updated', (_, data) => callback(data))
  },
  onBookmarksUpdated: (callback: (data: any) => void) => {
    ipcRenderer.on('bookmarks:updated', (_, data) => callback(data))
  },
  onPluginListUpdated: (callback: (data: any) => void) => {
    ipcRenderer.on('plugin:list-updated', (_, data) => callback(data))
  },
  onPluginLogsUpdated: (callback: (data: any) => void) => {
    ipcRenderer.on('plugin:logs-updated', (_, data) => callback(data))
  }
  ,
  onPluginProcessesUpdated: (callback: (data: any) => void) => {
    ipcRenderer.on('plugin:processes-updated', (_, data) => callback(data))
  }
})
