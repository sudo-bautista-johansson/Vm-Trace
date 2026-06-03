// ============================================================================
// VMTrace CFGGraph Component (Renderer Process)
// Renders the Control Flow Graph of the VM using Cytoscape.js.
// ============================================================================

import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import { appState } from '../state/AppState'
import { eventBus } from '../state/EventBus'
import { CFGData } from '../../../core/model/types'

// Register the dagre layout extension
cytoscape.use(dagre)

export class CFGGraph {
  private cy: cytoscape.Core | null = null
  private container: HTMLElement | null = null
  private emptyState: HTMLElement | null = null

  constructor() {
    this.container = document.getElementById('cfg-canvas')
    this.emptyState = document.getElementById('cfg-empty-state')

    // Listen for binary loaded to build / display the graph
    eventBus.on('binary:loaded', async () => {
      if (this.emptyState) this.emptyState.classList.add('hidden')
      await this.loadGraph()
    })

    // Listen for stepping to highlight active node
    eventBus.on('vm:state-updated', (state: any) => {
      this.highlightActiveNode(state.vip)
    })
  }

  private async loadGraph(): Promise<void> {
    if (!this.container) return

    if (this.emptyState) {
      this.emptyState.classList.add('hidden')
    }

    let cfgData: CFGData | null = null
    try {
      cfgData = await (window as any).vmtrace.getCFG()
    } catch (error) {
      console.error('Failed to load CFG from main process:', error)
    }

    if (!cfgData || cfgData.nodes.length === 0) {
      cfgData = this.generateSampleCFG()
    }

    const elements: cytoscape.ElementDefinition[] = []

    // Map CFG nodes
    cfgData.nodes.forEach(node => {
      elements.push({
        data: {
          id: node.id,
          label: node.label ?? node.id,
          type: node.type,
          handlerType: node.handlerType || 'unknown'
        }
      })
    })

    // Map CFG edges
    cfgData.edges.forEach(edge => {
      elements.push({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.label ?? ''
        }
      })
    })

    if (this.cy) {
      this.cy.destroy()
      this.cy = null
    }

    // Initialize Cytoscape
    this.cy = cytoscape({
      container: this.container,
      elements: elements,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#e2e8f0',
            'font-family': 'Outfit, sans-serif',
            'font-size': '11px',
            'text-valign': 'center',
            'text-halign': 'center',
            'background-color': '#1a1e26',
            'border-width': '1.5px',
            'border-color': '#1e2430',
            'width': '120px',
            'height': '40px',
            'shape': 'round-rectangle',
            'transition-property': 'background-color, border-color, box-shadow',
            'transition-duration': 0.3
          }
        },
        {
          selector: 'node[type="entry"]',
          style: {
            'background-color': '#0f172a',
            'border-color': '#00f0ff',
            'border-width': '2px',
            'width': '140px',
            'height': '46px',
            'font-weight': 'bold'
          }
        },
        {
          selector: 'node[handlerType="arithmetic"]',
          style: {
            'border-color': '#eab308' /* Yellow */
          }
        },
        {
          selector: 'node[handlerType="control_flow"]',
          style: {
            'border-color': '#06b6d4' /* Cyan */
          }
        },
        {
          selector: 'node[handlerType="stack"]',
          style: {
            'border-color': '#a855f7' /* Purple */
          }
        },
        {
          selector: 'node[handlerType="memory"]',
          style: {
            'border-color': '#10b981' /* Green */
          }
        },
        {
          selector: 'node.active',
          style: {
            'background-color': 'rgba(0, 240, 255, 0.15)',
            'border-color': '#00f0ff',
            'border-width': '2.5px',
            'color': '#00f0ff'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': '#1e2430',
            'target-arrow-color': '#1e2430',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '9px',
            'color': '#64748b',
            'text-background-opacity': 0.8,
            'text-background-color': '#0d0f14',
            'text-background-padding': '2px',
            'arrow-scale': 0.9
          }
        },
        {
          selector: 'edge.active',
          style: {
            'width': 2.5,
            'line-color': '#00f0ff',
            'target-arrow-color': '#00f0ff'
          }
        }
      ],
      layout: {
        name: 'dagre',
        rankDir: 'TB',
        nodeSep: 40,
        rankSep: 60,
        animate: true,
        animationDuration: 500
      } as any
    })

    // Set node click event listener
    this.cy.on('tap', 'node', (evt) => {
      const node = evt.target
      const nodeId = node.id()
      // If it has numeric name like 0x..., go to that address
      if (nodeId.startsWith('0x')) {
        const addr = parseInt(nodeId, 16)
        if (!isNaN(addr)) {
          appState.setSelectedAddress(addr)
        }
      }
    })
  }

  private highlightActiveNode(vip: number): void {
    if (!this.cy) return

    const addrHex = `0x${vip.toString(16).toUpperCase()}`
    
    // Reset highlights
    this.cy.nodes().removeClass('active')
    this.cy.edges().removeClass('active')

    // Find node matching the VIP
    const node = this.cy.getElementById(addrHex)
    if (node.length > 0) {
      node.addClass('active')
      // Pan to the node
      this.cy.animate({
        center: { eles: node },
        zoom: 1.1,
        duration: 300
      })
    } else {
      // Find sample node if running demo VM (OP_XX format)
      // e.g. mapping VIP offsets to opcodes
    }
  }

  private generateSampleCFG(): CFGData {
    // Generates a mock dispatcher layout for VMTrace visual presentation
    return {
      nodes: [
        { id: 'VM_ENTRY', address: 0, endAddress: 0, type: 'entry', label: 'VM Entry (0x401000)', instructionCount: 5, instructions: [] },
        { id: 'DISPATCHER', address: 0, endAddress: 0, type: 'block', label: 'V-Dispatcher\n[Fetch Opcode]', instructionCount: 8, instructions: [] },
        { id: 'OP_ADD', address: 0, endAddress: 0, type: 'handler', label: 'Handler: ADD\n(Opcode 0x01)', handlerType: 'arithmetic' as any, instructionCount: 12, instructions: [] },
        { id: 'OP_PUSH', address: 0, endAddress: 0, type: 'handler', label: 'Handler: PUSH\n(Opcode 0x02)', handlerType: 'stack' as any, instructionCount: 6, instructions: [] },
        { id: 'OP_LOAD', address: 0, endAddress: 0, type: 'handler', label: 'Handler: LOAD\n(Opcode 0x03)', handlerType: 'memory' as any, instructionCount: 8, instructions: [] },
        { id: 'OP_JZ', address: 0, endAddress: 0, type: 'handler', label: 'Handler: JZ (Jump Zero)\n(Opcode 0x04)', handlerType: 'control_flow' as any, instructionCount: 15, instructions: [] },
        { id: 'VM_EXIT', address: 0, endAddress: 0, type: 'exit', label: 'VM Exit\n(Halt)', instructionCount: 4, instructions: [] }
      ],
      edges: [
        { id: 'e1', source: 'VM_ENTRY', target: 'DISPATCHER', type: 'fallthrough' },
        { id: 'e2', source: 'DISPATCHER', target: 'OP_PUSH', type: 'dispatch', label: 'case 0x02' },
        { id: 'e3', source: 'DISPATCHER', target: 'OP_LOAD', type: 'dispatch', label: 'case 0x03' },
        { id: 'e4', source: 'DISPATCHER', target: 'OP_ADD', type: 'dispatch', label: 'case 0x01' },
        { id: 'e5', source: 'DISPATCHER', target: 'OP_JZ', type: 'dispatch', label: 'case 0x04' },
        
        { id: 'e6', source: 'OP_PUSH', target: 'DISPATCHER', type: 'jump' },
        { id: 'e7', source: 'OP_LOAD', target: 'DISPATCHER', type: 'jump' },
        { id: 'e8', source: 'OP_ADD', target: 'DISPATCHER', type: 'jump' },
        
        { id: 'e9', source: 'OP_JZ', target: 'DISPATCHER', type: 'conditional_false', label: 'ZF = 0' },
        { id: 'e10', source: 'OP_JZ', target: 'VM_EXIT', type: 'conditional_true', label: 'ZF = 1' }
      ]
    }
  }
}
