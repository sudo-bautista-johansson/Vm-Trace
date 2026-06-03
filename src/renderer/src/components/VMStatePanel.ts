// ============================================================================
// VMTrace VMStatePanel Component (Renderer Process)
// Renders Stack list, Registers grid, and Flag chips with change indicators.
// ============================================================================

import { VMState } from '../../../core/model/types'
import { eventBus } from '../state/EventBus'

export class VMStatePanel {
  private container: HTMLElement | null = null
  private lastState: VMState | null = null

  constructor() {
    this.container = document.getElementById('state-container')

    // Listen for state changes
    eventBus.on('vm:state-updated', (state: VMState) => {
      this.render(state)
    })

    eventBus.on('binary:loaded', (data: { state: VMState }) => {
      this.lastState = null
      this.render(data.state)
    })
  }

  private render(state: VMState): void {
    if (!this.container) return

    // Find changed registers
    const changedRegs = new Set<string>()
    if (this.lastState) {
      for (const [reg, val] of Object.entries(state.registers)) {
        if ((this.lastState.registers[reg] ?? 0n) !== val) {
          changedRegs.add(reg)
        }
      }
    }
    this.lastState = JSON.parse(JSON.stringify(state, (key, value) => 
      typeof value === 'bigint' ? value.toString() : value
    ))
    // Restore BigInts since JSON.parse won't make them bigints
    for (const [k, v] of Object.entries(this.lastState!.registers)) {
      this.lastState!.registers[k] = BigInt(v as string)
    }

    // Render columns
    let html = `
      <div class="state-layout">
        <!-- Col 1: Registers -->
        <div class="state-column">
          <div class="state-title-sub">Registros Virtuales</div>
          <div class="regs-grid">
    `

    // Sort registers by name for clean order (v0, v1, v2...)
    const regEntries = Object.entries(state.registers).sort(([a], [b]) => a.localeCompare(b))
    
    if (regEntries.length === 0) {
      html += `<div style="grid-column: span 2; color: var(--text-dim); font-size:12px; text-align:center; padding-top:20px;">No inicializados</div>`
    } else {
      for (const [reg, val] of regEntries) {
        const valHex = `0x${val.toString(16).toUpperCase()}`
        const isChanged = changedRegs.has(reg) ? 'changed' : ''
        html += `
          <div class="reg-card">
            <span class="reg-name">${reg}</span>
            <span class="reg-value ${isChanged}">${valHex}</span>
          </div>
        `
      }
    }

    html += `
          </div>
        </div>

        <!-- Col 2: Stack Visualizer -->
        <div class="state-column">
          <div class="state-title-sub">Stack Virtual (VSP: 0x${state.vsp.toString(16).toUpperCase()})</div>
          <div class="stack-list">
    `

    if (state.stack.length === 0) {
      html += `<div class="stack-empty">Stack Vacío</div>`
    } else {
      state.stack.forEach((val, idx) => {
        const valHex = `0x${val.toString(16).toUpperCase()}`
        const offsetHex = `+0x${(idx * 8).toString(16).toUpperCase()}`
        html += `
          <div class="stack-item">
            <span class="stack-offset">${offsetHex}</span>
            <span class="stack-val">${valHex}</span>
          </div>
        `
      })
    }

    html += `
          </div>
        </div>

        <!-- Col 3: Flags -->
        <div class="state-column">
          <div class="state-title-sub">Banderas (Flags)</div>
          <div class="flags-list">
    `

    const flags = state.flags || { ZF: false, CF: false, SF: false, OF: false, PF: false, AF: false }
    for (const [flag, active] of Object.entries(flags)) {
      const activeClass = active ? 'active' : ''
      html += `
        <div class="flag-chip ${activeClass}">
          <span>${flag}</span>
          <div class="flag-indicator"></div>
        </div>
      `
    }

    html += `
          </div>
        </div>
      </div>
    `

    this.container.innerHTML = html
  }
}
