// ============================================================================
// VMTrace BytecodeViewer Component (Renderer Process)
// Renders the assembly instruction grid with colors, step highlight, and comments.
// ============================================================================

import { DisasmInstruction } from '../../../core/model/types'
import { appState } from '../state/AppState'
import { eventBus } from '../state/EventBus'

export class BytecodeViewer {
  private container: HTMLElement | null = null
  private instructions: DisasmInstruction[] = []
  private searchInput: HTMLInputElement | null = null

  constructor() {
    this.container = document.getElementById('bytecode-container')
    this.searchInput = document.getElementById('bytecode-search') as HTMLInputElement

    // Listen for binary loaded to render disassembly
    eventBus.on('binary:loaded', async (data: { binaryInfo: any; state: any }) => {
      appState.setLoading(true, 'Analizando binario...', 'Desensamblando sección de código...')
      try {
        // Disassemble first executable section
        const execSections = data.binaryInfo.sections.filter((s: any) => s.isExecutable)
        if (execSections.length > 0) {
          const mainSec = execSections[0]
          const instrs = await (window as any).vmtrace.disasmRange(
            mainSec.virtualAddress,
            mainSec.virtualAddress + mainSec.virtualSize,
            mainSec.virtualAddress
          )
          this.instructions = instrs
          this.render()
          this.highlightAddress(data.state.vip)
        }
      } catch (err) {
        console.error('Failed to disassemble sections:', err)
      } finally {
        appState.setLoading(false)
      }
    })

    // Listen for step updates to sync VIP line
    eventBus.on('vm:state-updated', (state: any) => {
      this.highlightAddress(Number(state.vip))
    })

    // Search bar go-to-address (Ctrl+G or Enter)
    if (this.searchInput) {
      this.searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          const val = this.searchInput!.value.trim()
          const addr = parseInt(val, 16)
          if (!isNaN(addr)) {
            this.highlightAddress(addr, true)
            appState.setSelectedAddress(addr)
          }
        }
      })
    }

    // Global keyboard shortcut for search focus
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'g') {
        e.preventDefault()
        if (this.searchInput) {
          this.searchInput.focus()
          this.searchInput.select()
        }
      }
    })
  }

  private render(): void {
    if (!this.container) return

    let html = `
      <table class="bytecode-table">
        <thead class="bytecode-header-row">
          <tr>
            <th class="bytecode-th">Dirección</th>
            <th class="bytecode-th">Opcode</th>
            <th class="bytecode-th">Nemónico</th>
            <th class="bytecode-th">Operandos</th>
            <th class="bytecode-th">Etiqueta/Comentario</th>
          </tr>
        </thead>
        <tbody id="bytecode-rows-container">
    `

    for (const inst of this.instructions) {
      const addrStr = `0x${inst.address.toString(16).toUpperCase()}`
      const bytesStr = inst.bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
      const typeClass = `type-${inst.type}`
      const labelText = inst.label ?? ''

      html += `
        <tr class="bytecode-row" data-address="${inst.address}">
          <td class="bytecode-td cell-address">${addrStr}</td>
          <td class="bytecode-td cell-opcode">${bytesStr}</td>
          <td class="bytecode-td cell-mnemonic ${typeClass}">${inst.mnemonic}</td>
          <td class="bytecode-td cell-operands">${inst.operands}</td>
          <td class="bytecode-td cell-comment" data-address="${inst.address}">${labelText}</td>
        </tr>
      `
    }

    html += `
        </tbody>
      </table>
    `

    this.container.innerHTML = html

    // Attach click events
    const rows = this.container.querySelectorAll('.bytecode-row')
    rows.forEach(row => {
      row.addEventListener('click', () => {
        const addr = Number(row.getAttribute('data-address'))
        appState.setSelectedAddress(addr)
        this.selectRow(row as HTMLElement)
      })
    })

    // Inline comment editing on double-click
    const comments = this.container.querySelectorAll('.cell-comment')
    comments.forEach(cell => {
      cell.addEventListener('dblclick', (e) => {
        e.stopPropagation()
        this.startEditingComment(cell as HTMLElement)
      })
    })
  }

  private selectRow(row: HTMLElement): void {
    const active = this.container?.querySelector('.bytecode-row.selected')
    if (active) active.classList.remove('selected')
    row.classList.add('selected')
  }

  private highlightAddress(address: number, forceScroll: boolean = true): void {
    const row = this.container?.querySelector(`.bytecode-row[data-address="${address}"]`) as HTMLElement
    if (row) {
      this.selectRow(row)
      if (forceScroll) {
        row.scrollIntoView({ block: 'center', behavior: 'smooth' })
      }
    }
  }

  private startEditingComment(cell: HTMLElement): void {
    if (cell.querySelector('input')) return // Already editing

    const address = Number(cell.getAttribute('data-address'))
    const currentText = cell.textContent || ''

    const input = document.createElement('input')
    input.type = 'text'
    input.value = currentText
    cell.innerHTML = ''
    cell.appendChild(input)
    input.focus()

    const save = async () => {
      const newVal = input.value.trim()
      cell.innerHTML = newVal
      // Save to main process
      await (window as any).vmtrace.labelHandler(address, newVal)
      // Sincronizar localmente en la lista de instrucciones
      const inst = this.instructions.find(i => i.address === address)
      if (inst) {
        inst.label = newVal
      }
    }

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        save()
      } else if (e.key === 'Escape') {
        cell.innerHTML = currentText
      }
    })

    input.addEventListener('blur', () => {
      save()
    })
  }
}
