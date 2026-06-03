// ============================================================================
// VMTrace EventBus (Renderer Process)
// Simple pub/sub pattern for communication between UI panels.
// ============================================================================

type Callback = (data?: any) => void

class EventBus {
  private listeners = new Map<string, Set<Callback>>()

  on(event: string, callback: Callback): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set())
    }
    this.listeners.get(event)!.add(callback)
  }

  off(event: string, callback: Callback): void {
    const list = this.listeners.get(event)
    if (list) {
      list.delete(callback)
    }
  }

  emit(event: string, data?: any): void {
    const list = this.listeners.get(event)
    if (list) {
      for (const cb of list) {
        try {
          cb(data)
        } catch (e) {
          console.error(`Error in event listener for ${event}:`, e)
        }
      }
    }
  }
}

export const eventBus = new EventBus()
