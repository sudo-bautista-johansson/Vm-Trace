// ============================================================================
// VMTrace StatusBar Component (Renderer Process)
// Renders the footer bar with current binary info and VM pointer registers.
// ============================================================================

import { appState } from '../state/AppState'

export class StatusBar {
  private container: HTMLElement | null = null

  constructor() {
    this.container = document.getElementById('statusbar-container')

    // Sincronizar estado
    appState.subscribe(() => {
      this.render()
    })
  }

  private render(): void {
    if (!this.container) return

    const state = appState.getState()
    const binary = state.binaryInfo
    const vm = state.vmState

    let leftHtml = 'Sin binario cargado'
    if (binary) {
      leftHtml = `📂 ${binary.path} | Formato: ${binary.format} | Arch: ${binary.architecture}`
    }

    const vipHex = `0x${vm.vip.toString(16).toUpperCase()}`
    const vspHex = `0x${vm.vsp.toString(16).toUpperCase()}`
    const rightHtml = `VIP: ${vipHex} | VSP: ${vspHex} | Stack: ${vm.stack.length} dwords`

    this.container.innerHTML = `
      <div>${leftHtml}</div>
      <div>${rightHtml}</div>
    `
  }
}
