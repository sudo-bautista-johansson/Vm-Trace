// ============================================================================
// VMTrace AppState (Renderer Process)
// Central reactive state store for UI components.
// ============================================================================

import { BinaryInfo, VMState, TraceEntry, CFGData, VMHandler, Bookmark, createDefaultVMState } from '../../../core/model/types'
import { eventBus } from './EventBus'

export interface AppStateData {
  binaryInfo: BinaryInfo | null
  vmState: VMState
  trace: TraceEntry[]
  cfg: CFGData
  handlers: VMHandler[]
  bookmarks: Bookmark[]
  selectedAddress: number | null
  plugins: any[]
  pluginLogs: any[]
  pluginFolderPath: string | null
  pluginFolderLoadResults: any[]
  pluginProcesses: any[]
  isLoading: boolean
  pluginAutoInstall: boolean
  loadingMsg: string
  loadingSub: string
  activeTab: string // 'tab-cfg' | 'tab-inspector' | 'tab-plugins'
}

class AppState {
  private data: AppStateData = {
    binaryInfo: null,
    vmState: createDefaultVMState(),
    trace: [],
    cfg: { nodes: [], edges: [] },
    handlers: [],
    bookmarks: [],
    selectedAddress: null,
    plugins: [],
    pluginLogs: [],
    pluginFolderPath: null,
    pluginFolderLoadResults: [],
    pluginProcesses: [],
    isLoading: false,
    pluginAutoInstall: false,
    loadingMsg: 'Cargando...',
    loadingSub: '',
    activeTab: 'tab-cfg'
  }

  private listeners = new Set<(state: AppStateData) => void>()

  getState(): AppStateData {
    return { ...this.data }
  }

  subscribe(listener: (state: AppStateData) => void): () => void {
    this.listeners.add(listener)
    listener({ ...this.data })
    return () => {
      this.listeners.delete(listener)
    }
  }

  private notify(): void {
    const copy = { ...this.data }
    for (const listener of this.listeners) {
      listener(copy)
    }
  }

  // ─── State Modifiers ────────────────────────────────────────────────

  setLoading(loading: boolean, msg: string = 'Cargando...', sub: string = ''): void {
    this.data.isLoading = loading
    this.data.loadingMsg = msg
    this.data.loadingSub = sub
    this.notify()
    eventBus.emit('loading:changed', { loading, msg, sub })
  }

  setBinaryLoaded(binaryInfo: BinaryInfo, state: VMState): void {
    this.data.binaryInfo = binaryInfo
    this.data.vmState = state
    this.data.trace = []
    this.data.cfg = { nodes: [], edges: [] }
    this.data.handlers = []
    this.data.selectedAddress = binaryInfo.entryPoint
    this.notify()
    eventBus.emit('binary:loaded', { binaryInfo, state })
  }

  setVMState(state: VMState): void {
    this.data.vmState = state
    this.data.selectedAddress = state.vip
    this.notify()
    eventBus.emit('vm:state-updated', state)
  }

  setTrace(trace: TraceEntry[]): void {
    this.data.trace = trace
    this.notify()
  }

  setCFG(cfg: CFGData): void {
    this.data.cfg = cfg
    this.notify()
    eventBus.emit('cfg:updated', cfg)
  }

  setHandlers(handlers: VMHandler[]): void {
    this.data.handlers = handlers
    this.notify()
  }

  setBookmarks(bookmarks: Bookmark[]): void {
    this.data.bookmarks = bookmarks
    this.notify()
  }

  setSelectedAddress(address: number | null): void {
    this.data.selectedAddress = address
    this.notify()
    eventBus.emit('address:selected', address)
  }

  setPlugins(plugins: any[]): void {
    this.data.plugins = plugins
    this.notify()
  }

  setPluginLogs(logs: any[]): void {
    this.data.pluginLogs = logs
    this.notify()
  }

  setPluginFolderPath(path: string | null): void {
    this.data.pluginFolderPath = path
    this.notify()
  }

  setPluginFolderLoadResults(results: any[]): void {
    this.data.pluginFolderLoadResults = results
    this.notify()
  }

  setPluginProcesses(processes: any[]): void {
    this.data.pluginProcesses = processes
    this.notify()
  }

  setPluginAutoInstall(enabled: boolean): void {
    this.data.pluginAutoInstall = enabled
    this.notify()
  }

  setActiveTab(tabId: string): void {
    this.data.activeTab = tabId
    this.notify()
    eventBus.emit('tab:changed', tabId)
  }
}

export const appState = new AppState()
