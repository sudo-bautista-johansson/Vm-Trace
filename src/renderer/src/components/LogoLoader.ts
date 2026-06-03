// ============================================================================
// VMTrace LogoLoader Component
// Controls the Ojo Cibernético overlay for loader animations.
// ============================================================================

import { eventBus } from '../state/EventBus'

export class LogoLoader {
  private overlay: HTMLElement | null = null
  private appRoot: HTMLElement | null = null
  private titleEl: HTMLElement | null = null
  private subtitleEl: HTMLElement | null = null

  constructor() {
    this.overlay = document.getElementById('loading-overlay')
    this.appRoot = document.getElementById('app-root')
    
    if (this.overlay) {
      this.titleEl = this.overlay.querySelector('.loader-text')
      this.subtitleEl = this.overlay.querySelector('.loader-subtext')
    }

    // Subscribe to EventBus loading updates
    eventBus.on('loading:changed', (data: { loading: boolean; msg: string; sub: string }) => {
      if (data.loading) {
        this.show(data.msg, data.sub)
      } else {
        this.hide()
      }
    })
  }

  show(message: string, submessage: string = ''): void {
    if (this.titleEl) this.titleEl.textContent = message
    if (this.subtitleEl) this.subtitleEl.textContent = submessage

    if (this.overlay) {
      this.overlay.classList.remove('hidden')
    }

    if (this.appRoot) {
      this.appRoot.classList.add('blur-app')
    }
  }

  hide(): void {
    // Graceful fadeout animation managed by CSS
    if (this.overlay) {
      this.overlay.classList.add('hidden')
    }

    if (this.appRoot) {
      this.appRoot.classList.remove('blur-app')
    }
  }
}
