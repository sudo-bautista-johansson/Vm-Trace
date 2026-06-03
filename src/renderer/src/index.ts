// ============================================================================
// VMTrace Renderer Entry Point
// Boots CSS styles, AppState, EventBus, and all view components.
// ============================================================================

// Import all styling modules
import './styles/main.css'
import './styles/panels.css'
import './styles/bytecode-viewer.css'
import './styles/vm-state.css'
import './styles/tree.css'
import './styles/plugins-panel.css'
import './styles/handler-inspector.css'

// Import components
import { LogoLoader } from './components/LogoLoader'
import { PanelLayout } from './components/PanelLayout'
import { Toolbar } from './components/Toolbar'
import { ComponentTree } from './components/ComponentTree'
import { BytecodeViewer } from './components/BytecodeViewer'
import { VMStatePanel } from './components/VMStatePanel'
import { CFGGraph } from './components/CFGGraph'
import { PluginsPanel } from './components/PluginsPanel'
import { HandlerInspector } from './components/HandlerInspector'
import { StatusBar } from './components/StatusBar'

import { appState } from './state/AppState'

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize structural layout and loading overlay
  const loader = new LogoLoader()
  const layout = new PanelLayout()

  // Simulate loader connection
  appState.setLoading(true, 'Iniciando VMTrace...', 'Estableciendo interfaz con el motor nativo')
  setTimeout(() => {
    appState.setLoading(false)
  }, 1200)

  // 2. Initialize toolbar & statusbar
  const toolbar = new Toolbar()
  const statusbar = new StatusBar()

  // 3. Initialize components
  const tree = new ComponentTree()
  const bytecodeViewer = new BytecodeViewer()
  const vmStatePanel = new VMStatePanel()
  const cfgGraph = new CFGGraph()
  const inspector = new HandlerInspector()
  const pluginsConsole = new PluginsPanel()

  // 4. Set up tabs navigation
  initTabNavigation()

  // Listen for sync events from main process (IPC)
  ;(window as any).vmtrace.onBinaryLoaded((data: { binaryInfo: any; state: any }) => {
    appState.setBinaryLoaded(data.binaryInfo, data.state)
  })

  ;(window as any).vmtrace.onVMStateUpdated((data: { state: any }) => {
    appState.setVMState(data.state)
  })
})

function initTabNavigation(): void {
  const tabs = document.querySelectorAll('.tab-button')
  const panes = document.querySelectorAll('.tab-pane')

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const tabId = tab.getAttribute('data-tab')
      if (!tabId) return

      // Toggle buttons
      tabs.forEach(t => t.classList.remove('active'))
      tab.classList.add('active')

      // Toggle panes
      panes.forEach(pane => {
        if (pane.id === tabId) {
          pane.classList.add('active')
        } else {
          pane.classList.remove('active')
        }
      })

      // Sync AppState
      appState.setActiveTab(tabId)
    })
  })

  // Listen for external tab switches (e.g. from Tree panel click)
  appState.subscribe((state) => {
    const activeTab = state.activeTab
    const tabBtn = document.querySelector(`.tab-button[data-tab="${activeTab}"]`)
    const pane = document.getElementById(activeTab)

    if (tabBtn && !tabBtn.classList.contains('active')) {
      tabs.forEach(t => t.classList.remove('active'))
      tabBtn.classList.add('active')
    }

    if (pane && !pane.classList.contains('active')) {
      panes.forEach(p => p.classList.remove('active'))
      pane.classList.add('active')
    }
  })
}
