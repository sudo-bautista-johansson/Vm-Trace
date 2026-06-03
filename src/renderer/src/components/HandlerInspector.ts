// ============================================================================
// VMTrace HandlerInspector Component (Renderer Process)
// Displays disassembly and metadata fields for native handlers.
// ============================================================================

import { appState } from '../state/AppState'
import { eventBus } from '../state/EventBus'
import { DisasmInstruction } from '../../../core/model/types'

export class HandlerInspector {
  private container: HTMLElement | null = null
  private selectedAddress: number | null = null
  private disasmLines: DisasmInstruction[] = []

  constructor() {
    this.container = document.getElementById('inspector-container')

    // Listen to address selection
    eventBus.on('address:selected', async (addr: number | null) => {
      this.selectedAddress = addr
      if (addr !== null) {
        await this.loadDisassembly(addr)
      }
      this.render()
    })

    // Listen to annotations changes
    ;(window as any).vmtrace.onAnnotationsUpdated((data: any) => {
      // Sync label and hypotheses changes in local cache
      const state = appState.getState()
      this.render()
    })
  }

  private async loadDisassembly(address: number): Promise<void> {
    try {
      // Fetch 15 instructions starting from selectedAddress
      const instrs = await (window as any).vmtrace.disasmRange(
        address,
        address + 64, // Assume average size is 4 bytes, 15 instrs = 60 bytes
        address
      )
      this.disasmLines = instrs.slice(0, 15)
    } catch (e) {
      console.error('Failed to load inspector disasm:', e)
      this.disasmLines = []
    }
  }

  private render(): void {
    if (!this.container) return

    if (this.selectedAddress === null) {
      this.container.innerHTML = `
        <div class="graph-watermark">
          <span style="font-size:24px;">🔍</span>
          <div class="watermark-text">Selecciona una instrucción para inspeccionar</div>
        </div>
      `
      return
    }

    const state = appState.getState()
    const addrHex = `0x${this.selectedAddress.toString(16).toUpperCase()}`
    
    // Find annotations
    const key = `0x${this.selectedAddress.toString(16)}`
    const currentLabel = state.handlers.find(h => h.address === this.selectedAddress)?.label || ''
    const currentHyp = state.handlers.find(h => h.address === this.selectedAddress)?.hypothesis || ''

    this.container.innerHTML = `
      <div class="inspector-panel">
        <!-- Info cards -->
        <div class="inspector-info-row">
          <div class="inspector-card">
            <div class="inspector-card-title">Dirección de Entrada</div>
            <div class="inspector-card-value">${addrHex}</div>
          </div>
          <div class="inspector-card">
            <div class="inspector-card-title">Opcode VM Asociado</div>
            <div class="inspector-card-value" style="color: #34d399;">
              ${this.getAssociatedOpcode()}
            </div>
          </div>
        </div>

        <!-- Annotation Editors -->
        <div class="inspector-editor-group">
          <label>Nombre del Handler (Etiqueta)</label>
          <input type="text" id="inspector-label-input" value="${currentLabel}" class="tech-input" placeholder="Ej: V_ADD, V_XOR, V_JMP" />
        </div>

        <div class="inspector-editor-group">
          <label>Hipótesis / Notas de Análisis</label>
          <textarea id="inspector-hyp-input" placeholder="Escribe observaciones aquí... (ej: Lee el stack de operandos, realiza una suma e invierte los flags)">${currentHyp}</textarea>
        </div>

        <!-- Disassembly Listing -->
        <div class="inspector-code-section">
          <div class="inspector-code-title">Código Nativo (x86-64 Disassembly)</div>
          <div class="inspector-disasm-list">
            ${this.renderDisasmLines()}
          </div>
        </div>
      </div>
    `

    this.bindEvents()
  }

  private getAssociatedOpcode(): string {
    if (this.selectedAddress === null) return 'N/A'
    const state = appState.getState()
    const handler = state.handlers.find(h => h.address === this.selectedAddress)
    if (handler) {
      return `0x${handler.opcodeValue.toString(16).toUpperCase()}`
    }
    // Mock mapping for demo
    if (this.selectedAddress === 0x401050) return '0x01'
    if (this.selectedAddress === 0x401120) return '0x02'
    if (this.selectedAddress === 0x401200) return '0x03'
    if (this.selectedAddress === 0x401350) return '0x04'
    return 'N/A'
  }

  private renderDisasmLines(): string {
    if (this.disasmLines.length === 0) {
      return `<div style="color:var(--text-dim); text-align:center; padding-top:20px; font-style:italic;">No hay código en esta dirección</div>`
    }

    return this.disasmLines.map(inst => {
      const addrStr = `0x${inst.address.toString(16).toUpperCase()}`
      const bytesStr = inst.bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('')
      const asm = `${inst.mnemonic.padEnd(8)} ${inst.operands}`
      return `
        <div class="inspector-disasm-line">
          <span class="addr">${addrStr}</span>
          <span class="bytes">${bytesStr}</span>
          <span class="code">${asm}</span>
        </div>
      `
    }).join('')
  }

  private bindEvents(): void {
    const labelInput = document.getElementById('inspector-label-input') as HTMLInputElement
    const hypInput = document.getElementById('inspector-hyp-input') as HTMLTextAreaElement

    if (!labelInput || !hypInput || this.selectedAddress === null) return

    const addr = this.selectedAddress

    // Blur / change listeners to auto-save annotations
    labelInput.addEventListener('blur', async () => {
      const val = labelInput.value.trim()
      await (window as any).vmtrace.labelHandler(addr, val)
    })

    labelInput.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter') {
        const val = labelInput.value.trim()
        await (window as any).vmtrace.labelHandler(addr, val)
        labelInput.blur()
      }
    })

    hypInput.addEventListener('blur', async () => {
      const val = hypInput.value.trim()
      await (window as any).vmtrace.setHypothesis(addr, val)
    })
  }
}
