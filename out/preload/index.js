"use strict";
const electron = require("electron");
electron.contextBridge.exposeInMainWorld("vmtrace", {
  // ─── Binary Operations ───
  openFileDialog: () => electron.ipcRenderer.invoke("binary:open-dialog"),
  loadBinary: (path) => electron.ipcRenderer.invoke("binary:load", { path }),
  getBinaryInfo: () => electron.ipcRenderer.invoke("binary:info"),
  disasmRange: (start, end, baseAddress) => electron.ipcRenderer.invoke("disasm:range", { start, end, baseAddress }),
  disasmSection: (sectionName) => electron.ipcRenderer.invoke("disasm:section", { sectionName }),
  // ─── Emulation Controls ───
  step: () => electron.ipcRenderer.invoke("vm:step"),
  stepOver: () => electron.ipcRenderer.invoke("vm:step-over"),
  run: () => electron.ipcRenderer.invoke("vm:run"),
  stop: () => electron.ipcRenderer.invoke("vm:stop"),
  reset: () => electron.ipcRenderer.invoke("vm:reset"),
  getState: () => electron.ipcRenderer.invoke("vm:get-state"),
  // ─── Annotations ───
  labelHandler: (address, label) => electron.ipcRenderer.invoke("vm:label-handler", { address, label }),
  setHypothesis: (address, hypothesis) => electron.ipcRenderer.invoke("vm:set-hypothesis", { address, hypothesis }),
  // ─── Bookmarks ───
  addBookmark: (bookmark) => electron.ipcRenderer.invoke("bookmark:add", bookmark),
  removeBookmark: (id) => electron.ipcRenderer.invoke("bookmark:remove", { id }),
  listBookmarks: () => electron.ipcRenderer.invoke("bookmark:list"),
  // ─── Analysis Views ───
  getTrace: () => electron.ipcRenderer.invoke("trace:get"),
  getCFG: () => electron.ipcRenderer.invoke("cfg:get"),
  // ─── Plugins ───
  listPlugins: () => electron.ipcRenderer.invoke("plugin:list"),
  getPluginLogs: () => electron.ipcRenderer.invoke("plugin:logs"),
  setPluginPort: (port) => electron.ipcRenderer.invoke("plugin:set-port", { port }),
  selectPluginFolder: () => electron.ipcRenderer.invoke("plugin:select-folder"),
  loadPluginFolder: (path) => electron.ipcRenderer.invoke("plugin:load-folder", { path }),
  getLoadedPluginProcesses: () => electron.ipcRenderer.invoke("plugin:get-loaded-processes"),
  startPlugin: (path) => electron.ipcRenderer.invoke("plugin:start", { path }),
  stopPlugin: (path) => electron.ipcRenderer.invoke("plugin:stop", { path }),
  installDeps: (packages) => electron.ipcRenderer.invoke("plugin:install-deps", { packages }),
  setPluginAutoInstall: (enabled) => electron.ipcRenderer.invoke("plugin:set-auto-install", { enabled }),
  getPluginAutoInstall: () => electron.ipcRenderer.invoke("plugin:get-auto-install"),
  // ─── Events from Main Process ───
  onBinaryLoaded: (callback) => {
    electron.ipcRenderer.on("binary:loaded", (_, data) => callback(data));
  },
  onVMStateUpdated: (callback) => {
    electron.ipcRenderer.on("vm:state-updated", (_, data) => callback(data));
  },
  onAnnotationsUpdated: (callback) => {
    electron.ipcRenderer.on("vm:annotations-updated", (_, data) => callback(data));
  },
  onBookmarksUpdated: (callback) => {
    electron.ipcRenderer.on("bookmarks:updated", (_, data) => callback(data));
  },
  onPluginListUpdated: (callback) => {
    electron.ipcRenderer.on("plugin:list-updated", (_, data) => callback(data));
  },
  onPluginLogsUpdated: (callback) => {
    electron.ipcRenderer.on("plugin:logs-updated", (_, data) => callback(data));
  },
  onPluginProcessesUpdated: (callback) => {
    electron.ipcRenderer.on("plugin:processes-updated", (_, data) => callback(data));
  }
});
