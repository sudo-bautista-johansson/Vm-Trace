// ============================================================================
// VMTrace ComponentTree Component (Renderer Process)
// Left sidebar tree showing project files, bookmarks, and active plugins.
// ============================================================================

import { appState } from '../state/AppState'
import { eventBus } from '../state/EventBus'
import { Bookmark, VMHandler } from '../../../core/model/types'

export class ComponentTree {
  private container: HTMLElement | null = null

  constructor() {
    this.container = document.getElementById('tree-container')

    // Subscribe to state updates to re-render sections
    appState.subscribe(() => {
      this.render()
    })
  }

  private render(): void {
    if (!this.container) return

    const state = appState.getState()
    const binary = state.binaryInfo
    const handlers = state.handlers
    const bookmarks = state.bookmarks
    const plugins = state.plugins

    let html = ''

    // ─── section 1: Loaded VM info ───
    html += `
      <div class="tree-section">
        <div class="tree-header">📁 Binario Cargado</div>
        <ul class="tree-list">
    `
    if (binary) {
      html += `
        <li class="tree-item active">
          <span class="tree-item-label">💎 ${binary.path.split(/[\\/]/).pop()}</span>
          <span class="tree-item-meta">${binary.format} / ${binary.architecture}</span>
        </li>
      `
    } else {
      html += `<div class="tree-empty">Ningún binario cargado</div>`
    }
    html += `</ul></div>`

    // ─── section 2: Handlers list ───
    html += `
      <div class="tree-section">
        <div class="tree-header">⚙️ Handlers Identificados</div>
        <ul class="tree-list" style="max-height: 180px; overflow-y: auto;">
    `
    if (handlers.length === 0) {
      // Mock handlers if demo CFG is active
      if (binary) {
        html += `
          <li class="tree-item" data-addr="0x401050">
            <span class="tree-item-label">🔧 OP_ADD</span>
            <span class="tree-item-meta">0x01</span>
          </li>
          <li class="tree-item" data-addr="0x401120">
            <span class="tree-item-label">🔧 OP_PUSH</span>
            <span class="tree-item-meta">0x02</span>
          </li>
          <li class="tree-item" data-addr="0x401200">
            <span class="tree-item-label">🔧 OP_LOAD</span>
            <span class="tree-item-meta">0x03</span>
          </li>
          <li class="tree-item" data-addr="0x401350">
            <span class="tree-item-label">🔧 OP_JZ</span>
            <span class="tree-item-meta">0x04</span>
          </li>
        `
      } else {
        html += `<div class="tree-empty">No se han detectado handlers</div>`
      }
    } else {
      handlers.forEach(h => {
        const lbl = h.label ?? `OP_${h.opcodeValue.toString(16).toUpperCase()}`
        html += `
          <li class="tree-item" data-addr="${h.address}">
            <span class="tree-item-label">🔧 ${lbl}</span>
            <span class="tree-item-meta">0x${h.opcodeValue.toString(16).toUpperCase()}</span>
          </li>
        `
      })
    }
    html += `</ul></div>`

    // ─── section 3: Bookmarks list ───
    html += `
      <div class="tree-section">
        <div class="tree-header">🔖 Bookmarks / Marcadores</div>
        <ul class="tree-list">
    `
    if (bookmarks.length === 0) {
      html += `<div class="tree-empty">Haga doble click en comentarios para etiquetar</div>`
    } else {
      bookmarks.forEach(b => {
        html += `
          <li class="tree-item bookmark" data-addr="${b.address}" style="border-left-color: ${b.color};">
            <span class="tree-item-label">📍 ${b.label}</span>
            <span class="tree-item-meta">0x${b.address.toString(16).toUpperCase()}</span>
          </li>
        `
      })
    }
    html += `</ul></div>`

    // ─── section 4: Plugins list ───
    html += `
      <div class="tree-section">
        <div class="tree-header">🔌 Plugins Conectados (API)</div>
        <ul class="tree-list">
    `
    if (plugins.length === 0) {
      html += `<div class="tree-empty" style="color: var(--text-sub);">Servidor WebSocket listo (Puerto 57130)</div>`
    } else {
      plugins.forEach(p => {
        html += `
          <li class="tree-item" data-tab-switch="tab-plugins">
            <span class="tree-item-label"><span class="badge-plugin-active"></span> ⚡ ${p.name}</span>
            <span class="tree-item-meta">${p.id}</span>
          </li>
        `
      })
    }
    html += `</ul></div>`

    this.container.innerHTML = html

    // Attach click events to items to navigate
    const items = this.container.querySelectorAll('.tree-item[data-addr]')
    items.forEach(item => {
      item.addEventListener('click', () => {
        const addrStr = item.getAttribute('data-addr')!
        const addr = addrStr.startsWith('0x') ? parseInt(addrStr, 16) : Number(addrStr)
        if (!isNaN(addr)) {
          appState.setSelectedAddress(addr)
        }
      })
    })

    const tabs = this.container.querySelectorAll('.tree-item[data-tab-switch]')
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const tabId = tab.getAttribute('data-tab-switch')!
        appState.setActiveTab(tabId)
      })
    })
  }
}
