import { ipcMain, dialog, BrowserWindow } from 'electron'
import { engineManager } from './engine-manager'
import { getConnectedPlugins, getPluginLogs, startPluginServer, stopPluginServer, loadPluginsFromFolder, getLoadedPluginProcesses, startPlugin, stopPlugin } from './plugin-server'
import { installDeps } from './plugin-server'
import { disassemble } from '../core/disasm/x86-disasm'
import { getBytesAtAddress, getLoadedInfo, getSectionByName, getSectionBytes } from '../core/loader'

export function registerIpcHandlers(): void {
  // ─── Binary Loading ────────────────────────────────────────────────────────
  ipcMain.handle('binary:open-dialog', async (event) => {
    const window = BrowserWindow.fromWebContents(event.sender)
    if (!window) return null
    const result = await dialog.showOpenDialog(window, {
      properties: ['openFile'],
      filters: [
        { name: 'Binarios Soportados (*.exe, *.dll, *.elf, *.so, *.bin)', extensions: ['exe', 'dll', 'elf', 'so', 'bin', ''] },
        { name: 'Todos los archivos', extensions: ['*'] }
      ]
    })
    if (result.canceled || result.filePaths.length === 0) {
      return null
    }
    const path = result.filePaths[0]
    return engineManager.loadBinaryFile(path)
  })

  ipcMain.handle('binary:load', async (_, { path }) => {
    return engineManager.loadBinaryFile(path)
  })

  ipcMain.handle('binary:info', async () => {
    return engineManager.getBinaryInfo()
  })

  ipcMain.handle('disasm:range', async (_, { start, end, baseAddress }) => {
    const size = end - start
    const bytes = getBytesAtAddress(start, size)
    if (!bytes) return []
    const is64 = getLoadedInfo()?.architecture === 'x64'
    return disassemble(bytes, baseAddress, is64)
  })

  ipcMain.handle('disasm:section', async (_, { sectionName }) => {
    const sec = getSectionByName(sectionName)
    if (!sec) return []
    const bytes = getSectionBytes(sec)
    if (!bytes) return []
    const is64 = getLoadedInfo()?.architecture === 'x64'
    return disassemble(bytes, sec.virtualAddress, is64)
  })

  // ─── Emulation Control ──────────────────────────────────────────────────────
  ipcMain.handle('vm:step', async () => {
    return engineManager.step()
  })

  ipcMain.handle('vm:step-over', async () => {
    return engineManager.stepOver()
  })

  ipcMain.handle('vm:run', async () => {
    return engineManager.run()
  })

  ipcMain.handle('vm:stop', async () => {
    engineManager.stop()
    return { success: true }
  })

  ipcMain.handle('vm:reset', async () => {
    engineManager.reset()
    return { success: true }
  })

  ipcMain.handle('vm:get-state', async () => {
    return engineManager.getVMModel().state
  })

  // ─── Annotations & Metadata ─────────────────────────────────────────────────
  ipcMain.handle('vm:label-handler', async (_, { address, label }) => {
    engineManager.setHandlerLabel(address, label)
    return { success: true }
  })

  ipcMain.handle('vm:set-hypothesis', async (_, { address, hypothesis }) => {
    engineManager.setHandlerHypothesis(address, hypothesis)
    return { success: true }
  })

  // ─── Bookmarks ─────────────────────────────────────────────────────────────
  ipcMain.handle('bookmark:add', async (_, bookmark) => {
    engineManager.addBookmark(bookmark)
    return { success: true }
  })

  ipcMain.handle('bookmark:remove', async (_, { id }) => {
    engineManager.removeBookmark(id)
    return { success: true }
  })

  ipcMain.handle('bookmark:list', async () => {
    return engineManager.getBookmarks()
  })

  // ─── Trace & Graph ──────────────────────────────────────────────────────────
  ipcMain.handle('trace:get', async () => {
    return engineManager.getVMModel().trace
  })

  ipcMain.handle('cfg:get', async () => {
    return engineManager.getVMModel().cfg
  })

  // ─── Plugins Management ──────────────────────────────────────────────────────
  ipcMain.handle('plugin:list', async () => {
    return getConnectedPlugins()
  })

  ipcMain.handle('plugin:logs', async () => {
    return getPluginLogs()
  })

  ipcMain.handle('plugin:select-folder', async (event) => {
    const window = BrowserWindow.fromWebContents(event.sender)
    if (!window) return { canceled: true }

    const result = await dialog.showOpenDialog(window, {
      properties: ['openDirectory']
    })

    if (result.canceled || result.filePaths.length === 0) {
      return { canceled: true }
    }

    return { canceled: false, path: result.filePaths[0] }
  })

  ipcMain.handle('plugin:load-folder', async (_, { path }) => {
    return loadPluginsFromFolder(path)
  })

  ipcMain.handle('plugin:get-loaded-processes', async () => {
    return getLoadedPluginProcesses()
  })

  ipcMain.handle('plugin:start', async (_, { path }) => {
    try {
      const info = startPlugin(path)
      return { success: true, info }
    } catch (err: any) {
      return { success: false, error: err.message }
    }
  })

  ipcMain.handle('plugin:stop', async (_, { path }) => {
    try {
      const res = stopPlugin(path)
      return res
    } catch (err: any) {
      return { success: false, error: err.message }
    }
  })

  ipcMain.handle('plugin:install-deps', async (_, { packages }: { packages: string[] }) => {
    try {
      const res = installDeps(packages || ['websocket-client'])
      return res
    } catch (err: any) {
      return { success: false, stdout: '', stderr: err.message }
    }
  })

  ipcMain.handle('plugin:set-auto-install', async (_, { enabled }: { enabled: boolean }) => {
    try {
      setAutoInstallDeps(!!enabled)
      return { success: true, enabled: !!enabled }
    } catch (err: any) {
      return { success: false, error: err.message }
    }
  })

  ipcMain.handle('plugin:get-auto-install', async () => {
    try {
      return { enabled: getAutoInstallDeps() }
    } catch (err: any) {
      return { enabled: false }
    }
  })

  ipcMain.handle('plugin:set-port', async (_, { port }) => {
    startPluginServer(port)
    return { success: true, port }
  })
}
