// ============================================================================
// VMTrace PluginsPanel Component (Renderer Process)
// Displays active WS connections, logs, and server port configuration.
// ============================================================================

import { appState } from '../state/AppState'
import { eventBus } from '../state/EventBus'

export class PluginsPanel {
  private container: HTMLElement | null = null

  constructor() {
    this.container = document.getElementById('plugins-container')

    // Subscribe to AppState updates
    appState.subscribe(() => {
      this.render()
    })

    // Listen to main process updates via exposed contextBridge listeners
    ;(window as any).vmtrace.onPluginListUpdated((plugins: any[]) => {
      appState.setPlugins(plugins)
    })

    ;(window as any).vmtrace.onPluginLogsUpdated((logs: any[]) => {
      appState.setPluginLogs(logs)
      this.scrollToBottom()
    })

    ;(window as any).vmtrace.onPluginProcessesUpdated((procs: any[]) => {
      appState.setPluginProcesses(procs)
    })

    // Initial fetch
    this.initialFetch()
  }

  private async initialFetch(): Promise<void> {
    try {
      const list = await (window as any).vmtrace.listPlugins()
      appState.setPlugins(list)

      const logs = await (window as any).vmtrace.getPluginLogs()
      appState.setPluginLogs(logs)
      this.scrollToBottom()
      const procs = await (window as any).vmtrace.getLoadedPluginProcesses()
      appState.setPluginProcesses(procs)
      const auto = await (window as any).vmtrace.getPluginAutoInstall()
      appState.setPluginAutoInstall(!!auto?.enabled)
    } catch (e) {
      console.error('Failed to fetch initial plugins info:', e)
    }
  }

  private render(): void {
    if (!this.container) return

    const state = appState.getState()
    const plugins = state.plugins
    const logs = state.pluginLogs

    let clientRows = ''
    if (plugins.length === 0) {
      clientRows = `<div style="font-size: 11px; color: var(--text-dim); padding: 4px 0;">Esperando conexiones de plugins...</div>`
    } else {
      plugins.forEach(p => {
        clientRows += `
          <div style="display: flex; align-items: center; justify-content: space-between; padding: 4px 6px; border-bottom: 1px solid var(--border); font-size:12px;">
            <span style="color: var(--accent);">⚡ ${p.name} (${p.id})</span>
            <span style="font-family: var(--font-code); font-size:10px; color: var(--text-sub);">Uptime: ${new Date(p.connectedAt).toLocaleTimeString()}</span>
          </div>
        `
      })
    }

    const folderPath = state.pluginFolderPath || ''
    const folderResults = state.pluginFolderLoadResults || []
    const pluginProcesses = state.pluginProcesses || []
    const hasFolder = Boolean(folderPath)
    const folderRows = folderResults.length === 0
      ? '<div style="font-size: 11px; color: var(--text-dim); padding: 4px 0;">No se ha cargado ninguna carpeta de plugins.</div>'
      : folderResults.map((result: any) => {
          const status = result.status === 'running' ? 'Activo' : result.status === 'already-running' ? 'Ya en ejecución' : 'Error'
          const message = result.error ? ` - ${result.error}` : ''
          const control = (result.status === 'failed') ? `<button data-start-path="${result.path}" class="tech-btn btn-start-plugin">Iniciar</button>` : ''
          const installBtn = (result.error && result.error.includes('websocket')) ? `<button data-install="websocket-client" data-install-path="${result.path}" class="tech-btn btn-install-deps">Instalar deps</button>` : ''
          return `<div class="plugin-entry"><span class="plugin-path">${result.path}</span><span style="color: var(--text-sub);">${status}${message}</span><span class="plugin-controls">${control}${installBtn}</span></div>`
        }).join('')

    const procRows = pluginProcesses.length === 0
      ? '<div style="font-size: 12px; color: var(--text-dim); padding: 6px 0;">No hay procesos de plugins activos.</div>'
      : pluginProcesses.map((p: any) => {
          const status = p.status || 'unknown'
          const stopBtn = `<button data-stop-path="${p.path}" class="tech-btn btn-stop-plugin">Detener</button>`
          return `<div class="plugin-process-entry"><span class="plugin-path">${p.path}</span><span style="color: var(--text-sub);">${status}</span><span class="plugin-controls">${stopBtn}</span></div>`
        }).join('')

    this.container.innerHTML = `
      <div class="plugins-dashboard">
        <div class="plugins-folder-card" style="background-color: var(--bg-header); border: 1px solid var(--border); padding: 10px; border-radius: 4px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px; gap: 10px;">
            <div>
              <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-sub); letter-spacing:0.5px;">Carpeta de Plugins</div>
              <div style="font-size:12px; margin-top: 4px; color: var(--text-main);">${hasFolder ? folderPath : 'Ninguna carpeta seleccionada'}</div>
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
              <label style="font-size:11px; color:var(--text-sub);">Instalar deps automáticamente</label>
              <input type="checkbox" id="chk-auto-install" ${state.pluginAutoInstall ? 'checked' : ''} />
              <button id="btn-load-plugin-folder" class="tech-btn" style="padding: 4px 10px;">Agregar carpeta</button>
            </div>
          </div>
          <div style="font-size:11px; color: var(--text-dim);">${hasFolder ? `${folderResults.length} archivo(s) detectado(s)` : 'Selecciona una carpeta para detectar y arrancar plugins compatibles.'}</div>
        </div>

        <!-- Port Config Row -->
        <div class="plugins-config-row">
          <div style="font-size:12px; font-weight:600; color:var(--text-main);">Servidor API WebSocket</div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 11px; color: var(--text-sub); font-family: var(--font-code);">ws://localhost:</span>
            <input type="number" id="plugin-port-input" value="57130" class="tech-input" style="width: 70px;" />
            <button id="btn-restart-server" class="tech-btn" style="padding: 3px 8px;">Reiniciar</button>
          </div>
        </div>

        <!-- Connected Clients Card -->
        <div style="background-color: var(--bg-header); border: 1px solid var(--border); padding: 10px; border-radius: 4px;">
          <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-sub); margin-bottom: 6px; letter-spacing:0.5px;">Clientes Activos</div>
          <div id="plugin-clients-list">${clientRows}</div>
        </div>

        <!-- Plugin Files Detected -->
        <div style="background-color: var(--bg-header); border: 1px solid var(--border); padding: 10px; border-radius: 4px;">
          <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-sub); margin-bottom: 6px; letter-spacing:0.5px;">Plugins detectados</div>
          <div id="plugin-folder-results-list">${folderRows}</div>
        </div>

        <!-- Plugin Processes -->
        <div style="background-color: var(--bg-header); border: 1px solid var(--border); padding: 10px; border-radius: 4px;">
          <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-sub); margin-bottom: 6px; letter-spacing:0.5px;">Procesos de Plugins</div>
          <div id="plugin-processes-list">${procRows}</div>
        </div>

        <!-- JSON-RPC Logs Console -->
        <div class="plugins-console-section">
          <div class="console-header">
            <span>Registro de Comunicación JSON-RPC</span>
            <button id="btn-clear-logs" class="tech-btn" style="padding: 1px 6px; font-size:10px;">Clear</button>
          </div>
          <div class="console-logs" id="console-logs-container">
            ${this.renderLogLines(logs)}
          </div>
        </div>
      </div>
    `

    this.bindEvents()
  }

  private renderLogLines(logs: any[]): string {
    if (logs.length === 0) {
      return `<div class="console-log-line system">Listo para recibir comandos de plugins...</div>`
    }

    return logs.map(l => {
      const dirClass = l.direction === 'in' ? 'dir-in' : 'dir-out'
      const prefix = l.direction === 'in' ? '→ [REQ]' : '← [RES]'
      const name = l.pluginName === 'System' ? 'SYSTEM' : l.pluginName
      
      // Parse message to beautify if possible
      let formattedMsg = l.message
      try {
        const parsed = JSON.parse(l.message)
        // Keep it single line but clean
        formattedMsg = JSON.stringify(parsed)
      } catch {}

      return `
        <div class="console-log-line ${dirClass}">
          <span class="time">[${l.timestamp}]</span>
          <span class="prefix">${prefix}</span>
          <span class="plugin-name">${name}:</span>
          <span>${formattedMsg}</span>
        </div>
      `
    }).join('')
  }

  private bindEvents(): void {
    const btnRestart = document.getElementById('btn-restart-server')
    const portInput = document.getElementById('plugin-port-input') as HTMLInputElement
    const btnClear = document.getElementById('btn-clear-logs')
    const btnLoadFolder = document.getElementById('btn-load-plugin-folder')

    btnRestart?.addEventListener('click', async () => {
      if (!portInput) return
      const port = parseInt(portInput.value)
      if (isNaN(port) || port < 1024 || port > 65535) {
        alert('Por favor ingrese un número de puerto válido (1024-65535).')
        return
      }
      appState.setLoading(true, 'Reiniciando servidor de plugins...', `Puerto ${port}`)
      try {
        await (window as any).vmtrace.setPluginPort(port)
      } catch (err: any) {
        alert(`Error al reiniciar: ${err.message}`)
      } finally {
        appState.setLoading(false)
      }
    })

    btnLoadFolder?.addEventListener('click', async () => {
      try {
        const dialogResult = await (window as any).vmtrace.selectPluginFolder()
        if (!dialogResult || dialogResult.canceled || !dialogResult.path) {
          return
        }

        appState.setLoading(true, 'Cargando carpeta de plugins...', dialogResult.path)
        const result = await (window as any).vmtrace.loadPluginFolder(dialogResult.path)

        appState.setPluginFolderPath(result.folderPath || dialogResult.path)
        appState.setPluginFolderLoadResults(result.results || [])

        if (result.warnings && result.warnings.length > 0) {
          alert(result.warnings.join('\n'))
        }
      } catch (err: any) {
        alert(`Error al cargar plugins: ${err.message}`)
      } finally {
        appState.setLoading(false)
      }
    })

    const chkAuto = document.getElementById('chk-auto-install') as HTMLInputElement | null
    chkAuto?.addEventListener('change', async () => {
      const enabled = chkAuto.checked
      try {
        await (window as any).vmtrace.setPluginAutoInstall(enabled)
        appState.setPluginAutoInstall(enabled)
      } catch (err: any) {
        alert('No se pudo cambiar la configuración: ' + err.message)
      }
    })

    btnClear?.addEventListener('click', () => {
      appState.setPluginLogs([])
    })

    // Delegated listeners for dynamic start/stop buttons
    this.container?.addEventListener('click', async (ev) => {
      const target = ev.target as HTMLElement
      if (!target) return

      const startPath = target.getAttribute('data-start-path')
      const stopPath = target.getAttribute('data-stop-path')
      const installPkg = target.getAttribute('data-install')
      const installPath = target.getAttribute('data-install-path')

      if (startPath) {
        try {
          appState.setLoading(true, 'Iniciando plugin...', startPath)
          await (window as any).vmtrace.startPlugin(startPath)

          // Poll for process to become running (timeout 5s)
          const start = Date.now()
          let running = false
          while (Date.now() - start < 5000) {
            // small delay
            await new Promise(r => setTimeout(r, 300))
            const procs = await (window as any).vmtrace.getLoadedPluginProcesses()
            appState.setPluginProcesses(procs)
            const found = procs.find((p: any) => p.path === startPath)
            if (found && (found.status === 'running' || found.status === 'already-running')) {
              running = true
              break
            }
          }

          if (!running) {
            alert('El plugin no arrancó en el tiempo esperado. Ver logs para más detalles.')
          }
        } catch (err: any) {
          alert(`Error al iniciar plugin: ${err.message}`)
        } finally {
          appState.setLoading(false)
        }
      }

      if (stopPath) {
        try {
          appState.setLoading(true, 'Deteniendo plugin...', stopPath)
          await (window as any).vmtrace.stopPlugin(stopPath)
          const procs = await (window as any).vmtrace.getLoadedPluginProcesses()
          appState.setPluginProcesses(procs)
        } catch (err: any) {
          alert(`Error al detener plugin: ${err.message}`)
        } finally {
          appState.setLoading(false)
        }
      }

      if (installPkg) {
        try {
          appState.setLoading(true, 'Instalando dependencias...', installPath || installPkg)
          const res = await (window as any).vmtrace.installDeps([installPkg])
          if (!res || !res.success) {
            alert('Fallo la instalación: ' + (res?.stderr || ''))
          } else {
            alert('Paquete instalado. Intenta iniciar el plugin de nuevo.')
          }
        } catch (err: any) {
          alert('Error al instalar dependencias: ' + err.message)
        } finally {
          appState.setLoading(false)
        }
      }
    })
  }

  private scrollToBottom(): void {
    const el = document.getElementById('console-logs-container')
    if (el) {
      el.scrollTop = el.scrollHeight
    }
  }
}
