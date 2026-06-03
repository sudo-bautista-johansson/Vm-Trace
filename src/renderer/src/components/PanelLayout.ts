// ============================================================================
// VMTrace PanelLayout Manager (Renderer Process)
// Drag-to-resize handlers for Workspace panels.
// ============================================================================

export class PanelLayout {
  constructor() {
    this.initResizablePanels()
  }

  private initResizablePanels(): void {
    const leftPanel = document.getElementById('panel-left')
    const rightPanel = document.getElementById('panel-right')
    const centerPanel = document.getElementById('panel-center')
    const bytecodePanel = document.getElementById('panel-bytecode')
    const statePanel = document.getElementById('panel-state')

    const dividerLeft = document.getElementById('divider-left')
    const dividerRight = document.getElementById('divider-right')
    const dividerCenter = document.getElementById('divider-center')

    // ─── Left Panel Resize ───
    if (dividerLeft && leftPanel) {
      dividerLeft.addEventListener('mousedown', (e) => {
        e.preventDefault()
        dividerLeft.classList.add('active')
        const startWidth = leftPanel.offsetWidth

        const onMouseMove = (moveEvent: MouseEvent) => {
          const deltaX = moveEvent.clientX - e.clientX
          const newWidth = Math.max(180, Math.min(startWidth + deltaX, 480))
          leftPanel.style.width = `${newWidth}px`
        }

        const onMouseUp = () => {
          dividerLeft.classList.remove('active')
          window.removeEventListener('mousemove', onMouseMove)
          window.removeEventListener('mouseup', onMouseUp)
        }

        window.addEventListener('mousemove', onMouseMove)
        window.addEventListener('mouseup', onMouseUp)
      })
    }

    // ─── Right Panel Resize ───
    if (dividerRight && rightPanel) {
      dividerRight.addEventListener('mousedown', (e) => {
        e.preventDefault()
        dividerRight.classList.add('active')
        const startWidth = rightPanel.offsetWidth

        const onMouseMove = (moveEvent: MouseEvent) => {
          const deltaX = e.clientX - moveEvent.clientX
          const newWidth = Math.max(220, Math.min(startWidth + deltaX, 700))
          rightPanel.style.width = `${newWidth}px`
        }

        const onMouseUp = () => {
          dividerRight.classList.remove('active')
          window.removeEventListener('mousemove', onMouseMove)
          window.removeEventListener('mouseup', onMouseUp)
        }

        window.addEventListener('mousemove', onMouseMove)
        window.addEventListener('mouseup', onMouseUp)
      })
    }

    // ─── Center Vertical Split (Bytecode / VM State) ───
    if (dividerCenter && bytecodePanel && statePanel && centerPanel) {
      dividerCenter.addEventListener('mousedown', (e) => {
        e.preventDefault()
        dividerCenter.classList.add('active')
        const startHeight = bytecodePanel.offsetHeight
        const totalHeight = centerPanel.offsetHeight

        const onMouseMove = (moveEvent: MouseEvent) => {
          const deltaY = moveEvent.clientY - e.clientY
          const newHeight = Math.max(150, Math.min(startHeight + deltaY, totalHeight - 120))
          const percentage = (newHeight / totalHeight) * 100
          bytecodePanel.style.height = `${percentage}%`
          statePanel.style.height = `${100 - percentage}%`
        }

        const onMouseUp = () => {
          dividerCenter.classList.remove('active')
          window.removeEventListener('mousemove', onMouseMove)
          window.removeEventListener('mouseup', onMouseUp)
        }

        window.addEventListener('mousemove', onMouseMove)
        window.addEventListener('mouseup', onMouseUp)
      })
    }
  }
}
