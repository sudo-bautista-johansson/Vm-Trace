// ============================================================================
// VMTrace Toolbar Component (Renderer Process)
// Buttons for file loading, steps, running, and stopping.
// ============================================================================

import { appState } from '../state/AppState'
import { eventBus } from '../state/EventBus'

export class Toolbar {
  private container: HTMLElement | null = null

  constructor() {
    this.container = document.getElementById('toolbar-container')
    this.render()
    this.bindEvents()
  }

  private render(): void {
    if (!this.container) return

    this.container.innerHTML = `
      <div style="display: flex; align-items: center; gap: 16px;">
        <div class="toolbar-brand" style="font-family: var(--font-ui); font-size: 16px; font-weight: 700; color: var(--accent); display: flex; align-items: center; gap: 8px;">
          <!-- Inline Logo -->
          <svg viewBox="0 0 200 200" width="22" height="22" style="filter: drop-shadow(0 0 2px rgba(0,240,255,0.4))">
            <path d="M 30,100 C 65,55 135,55 170,100 M 30,100 C 65,145 135,145 170,100" stroke="#00f0ff" stroke-width="12" fill="none" />
            <circle cx="100" cy="100" r="30" stroke="#00f0ff" stroke-width="12" fill="none" />
            <circle cx="100" cy="100" r="10" fill="#00f0ff" />
          </svg>
          VMTrace
        </div>

        <div style="display: flex; gap: 8px;">
          <button id="btn-open" class="tech-btn primary">
            📂 Cargar Binario
          </button>
        </div>
      </div>

      <div style="display: flex; align-items: center; gap: 6px;">
        <button id="btn-step-into" class="tech-btn" title="Step Into (F7)">
          ➡️ Step (F7)
        </button>
        <button id="btn-step-over" class="tech-btn" title="Step Over (F8)">
          🔄 Step Over (F8)
        </button>
        <button id="btn-run" class="tech-btn" title="Run until Halted (F9)">
          ▶️ Ejecutar (F9)
        </button>
        <button id="btn-stop" class="tech-btn" title="Stop execution">
          ⏹️ Detener
        </button>
        <button id="btn-reset" class="tech-btn" title="Reset VM State">
          🔁 Reiniciar
        </button>
      </div>

      <div style="display: flex; align-items: center; gap: 10px;">
        <div id="vm-running-status" style="font-size: 11px; font-family: var(--font-code); color: var(--text-sub); display: flex; align-items: center; gap: 6px;">
          <span style="width: 8px; height: 8px; border-radius: 50%; background-color: #64748b;" class="status-indicator"></span>
          Idle
        </div>
      </div>
    `
  }

  private bindEvents(): void {
    const fileInput = document.getElementById('binary-file-input') as HTMLInputElement
    const btnOpen = document.getElementById('btn-open')
    const btnStepInto = document.getElementById('btn-step-into')
    const btnStepOver = document.getElementById('btn-step-over')
    const btnRun = document.getElementById('btn-run')
    const btnStop = document.getElementById('btn-stop')
    const btnReset = document.getElementById('btn-reset')
    const statusIndicator = this.container?.querySelector('.status-indicator') as HTMLElement
    const statusText = document.getElementById('vm-running-status')

    if (btnOpen) {
      btnOpen.addEventListener('click', async () => {
        appState.setLoading(true, 'Abriendo explorador...', 'Seleccione un binario PE/ELF')
        try {
          const info = await (window as any).vmtrace.openFileDialog()
          if (info) {
            const state = await (window as any).vmtrace.getState()
            appState.setBinaryLoaded(info, state)
          }
        } catch (err: any) {
          console.error(err)
          alert(`Error al cargar binario: ${err.message}`)
        } finally {
          appState.setLoading(false)
        }
      })
    }

    // Step Into
    btnStepInto?.addEventListener('click', () => this.triggerStep())

    // Step Over
    btnStepOver?.addEventListener('click', () => this.triggerStepOver())

    // Run
    btnRun?.addEventListener('click', () => this.triggerRun())

    // Stop
    btnStop?.addEventListener('click', async () => {
      await (window as any).vmtrace.stop()
      this.updateStatus('stopped')
    })

    // Reset
    btnReset?.addEventListener('click', async () => {
      await (window as any).vmtrace.reset()
      const state = await (window as any).vmtrace.getState()
      appState.setVMState(state)
      this.updateStatus('idle')
    })

    // Global Key listeners for F7, F8, F9
    window.addEventListener('keydown', (e) => {
      if (e.key === 'F7') {
        e.preventDefault()
        this.triggerStep()
      } else if (e.key === 'F8') {
        e.preventDefault()
        this.triggerStepOver()
      } else if (e.key === 'F9') {
        e.preventDefault()
        this.triggerRun()
      }
    })
  }

  private async triggerStep(): Promise<void> {
    this.updateStatus('running')
    try {
      const result = await (window as any).vmtrace.step()
      appState.setVMState(result.state)
      if (result.state.halted) {
        this.updateStatus('halted', result.state.error)
      } else {
        this.updateStatus('idle')
      }
    } catch (e) {
      console.error(e)
      this.updateStatus('error')
    }
  }

  private async triggerStepOver(): Promise<void> {
    this.updateStatus('running')
    try {
      const result = await (window as any).vmtrace.stepOver()
      appState.setVMState(result.state)
      if (result.state.halted) {
        this.updateStatus('halted', result.state.error)
      } else {
        this.updateStatus('idle')
      }
    } catch (e) {
      console.error(e)
      this.updateStatus('error')
    }
  }

  private async triggerRun(): Promise<void> {
    this.updateStatus('running')
    appState.setLoading(true, 'Ejecutando traza...', 'La máquina virtual está corriendo en segundo plano')
    try {
      const result = await (window as any).vmtrace.run()
      const state = await (window as any).vmtrace.getState()
      appState.setVMState(state)
      
      const trace = await (window as any).vmtrace.getTrace()
      appState.setTrace(trace)

      if (state.halted) {
        this.updateStatus('halted', state.error || result.reason)
      } else {
        this.updateStatus('idle')
      }
    } catch (e) {
      console.error(e)
      this.updateStatus('error')
    } finally {
      appState.setLoading(false)
    }
  }

  private updateStatus(status: 'idle' | 'running' | 'stopped' | 'halted' | 'error', detail: string = ''): void {
    const statusText = document.getElementById('vm-running-status')
    const indicator = this.container?.querySelector('.status-indicator') as HTMLElement
    if (!statusText || !indicator) return

    switch (status) {
      case 'idle':
        indicator.style.backgroundColor = '#64748b'
        statusText.innerHTML = `<span style="width: 8px; height: 8px; border-radius: 50%; background-color: #64748b;" class="status-indicator"></span> Idle`
        break
      case 'running':
        indicator.style.backgroundColor = '#38bdf8'
        statusText.innerHTML = `<span style="width: 8px; height: 8px; border-radius: 50%; background-color: #38bdf8; box-shadow: 0 0 4px #38bdf8;" class="status-indicator"></span> Ejecutando...`
        break
      case 'stopped':
        indicator.style.backgroundColor = '#e2e8f0'
        statusText.innerHTML = `<span style="width: 8px; height: 8px; border-radius: 50%; background-color: #e2e8f0;" class="status-indicator"></span> Detenido`
        break
      case 'halted':
        indicator.style.backgroundColor = '#f43f5e'
        statusText.innerHTML = `<span style="width: 8px; height: 8px; border-radius: 50%; background-color: #f43f5e; box-shadow: 0 0 4px #f43f5e;" class="status-indicator"></span> Halted: ${detail || 'halt'}`
        break
      case 'error':
        indicator.style.backgroundColor = '#f43f5e'
        statusText.innerHTML = `<span style="width: 8px; height: 8px; border-radius: 50%; background-color: #f43f5e;" class="status-indicator"></span> Error`
        break
    }
  }
}
