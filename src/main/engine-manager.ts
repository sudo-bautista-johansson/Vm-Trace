// ============================================================================
// VMTrace Engine Manager (Main Process)
// Central coordinator for VMEngine, loader, project state, and events.
// Sinks emulated actions and broadcasts updates to UI and Plugin Server.
// ============================================================================

import { BrowserWindow } from 'electron'
import { VMEngine } from '../core/emulator/vm-engine'
import { loadBinary, getLoadedInfo, getLoadedData } from '../core/loader'
import { BinaryInfo, VMState, TraceEntry, VMHandler, CFGData, CFGEdge, Bookmark, VMModel } from '../core/model/types'
import { DynamicHandlerDetector, HandlerSemanticAnalyzer, RealtimeBytecodeExecutor } from '../core/analysis'
import { notifyPluginEvent } from './plugin-server'
import { t } from '../core/i18n'

class EngineManager {
  private engine: VMEngine | null = null
  private realtimeExecutor: RealtimeBytecodeExecutor | null = null
  private executionMode: 'handlers' | 'realtime' = 'handlers'
  private binaryPath: string | null = null
  private binaryInfo: BinaryInfo | null = null
  private bookmarks: Bookmark[] = []
  private userComments: Record<string, string> = {}  // address hex -> comment
  private handlerLabels: Record<string, string> = {} // address hex -> label
  private handlerHypotheses: Record<string, string> = {} // address hex -> hypothesis
  private mainWindow: BrowserWindow | null = null

  setMainWindow(window: BrowserWindow): void {
    this.mainWindow = window
  }

  getEngine(): VMEngine | null {
    return this.engine
  }

  getBinaryInfo(): BinaryInfo | null {
    return this.binaryInfo
  }

  getBookmarks(): Bookmark[] {
    return this.bookmarks
  }

  getUserComments(): Record<string, string> {
    return this.userComments
  }

  getHandlerLabels(): Record<string, string> {
    return this.handlerLabels
  }

  getHandlerHypotheses(): Record<string, string> {
    return this.handlerHypotheses
  }

  // ─── Actions ────────────────────────────────────────────────────────

  loadBinaryFile(filePath: string): BinaryInfo {
    this.binaryPath = filePath
    this.binaryInfo = loadBinary(filePath)

    // Initialize VMEngine with the entry point
    this.engine = new VMEngine({
      initialVIP: this.binaryInfo.entryPoint,
      opcodeSize: 1 // Default to 1-byte opcodes, configurable
    })

    // Find the first executable section and load it as bytecode
    const execSections = this.binaryInfo.sections.filter(s => s.isExecutable)
    if (execSections.length > 0) {
      const mainSec = execSections[0]
      const data = getLoadedData()
      if (data) {
        // Slice the section's raw bytes
        const sectionBytes = data.subarray(mainSec.rawAddress, mainSec.rawAddress + mainSec.rawSize)
        if (sectionBytes.length === 0) {
          throw new Error(`Executable section ${mainSec.name} contains no data`) 
        }

        this.engine.setBytecode(sectionBytes, mainSec.virtualAddress)

        // Try to auto-detect handlers from bytecode (Phase 1: Detection)
        let phase1Result: any = null
        try {
          const detector = new DynamicHandlerDetector(
            Buffer.from(sectionBytes),
            mainSec.virtualAddress
          )
          const detectionResult = detector.detectHandlers()
          phase1Result = detectionResult

          if (detectionResult.confidence > 0.5 && detectionResult.handlersCreated.length > 0) {
            console.log(
              `[Phase 1] ${t('analysis.phase1_success', { count: detectionResult.handlersCreated.length, confidence: (detectionResult.confidence * 100).toFixed(1) })}`
            )

            // Register auto-detected handlers
            this.engine.setHandlers(detectionResult.handlersCreated)
            this.executionMode = 'handlers'

            // Phase 2: Semantic Analysis - Infer semantics and build dynamic executors
            console.log(`[Phase 2] Starting semantic analysis...`)
            try {
              const semanticAnalyzer = new HandlerSemanticAnalyzer(
                Buffer.from(sectionBytes),
                mainSec.virtualAddress
              )
              const semanticResult = semanticAnalyzer.analyzeAndBuild(
                this.engine,
                detectionResult.handlersCreated
              )

              console.log(
                `[Phase 2] ${t('analysis.phase2_success', { count: semanticResult.successfulExecutors, total: semanticResult.totalHandlers })}`
              )
              console.log(semanticAnalyzer.generateReport(semanticResult))

              // Broadcast combined Phase 1 + Phase 2 results to UI
              this.broadcastToUI('handlers:auto-detected', {
                phase1Result: detectionResult,
                phase1Report: detector.generateReport(detectionResult),
                phase2Result: semanticResult,
                phase2Report: semanticAnalyzer.generateReport(semanticResult),
                totalHandlers: detectionResult.handlersCreated.length,
                buildSuccess: semanticResult.successfulExecutors > 0
              })
            } catch (err) {
              // If Phase 2 fails, Phase 1 still works (handlers are registered but without semantics)
              console.warn(`[Phase 2] ${t('analysis.phase2_failed')}:`, err)
              this.broadcastToUI('handlers:auto-detected', {
                phase1Result: detectionResult,
                phase1Report: detector.generateReport(detectionResult),
                phase2Error: String(err),
                totalHandlers: detectionResult.handlersCreated.length,
                buildSuccess: false
              })
            }
          } else {
            console.log(
              `[Phase 1-3] ${t('analysis.phase1_low_confidence', { confidence: (detectionResult.confidence * 100).toFixed(1) })}`
            )
            this.initializeRealtimeExecutor(sectionBytes, mainSec.virtualAddress)
            this.broadcastToUI('handlers:auto-detected', {
              phase1Result: detectionResult,
              phase1Report: detector.generateReport(detectionResult),
              phase2Result: null,
              phase2Error: 'Skipped due to low detection confidence',
              totalHandlers: 0,
              buildSuccess: false,
              executionMode: 'realtime'
            })
          }
        } catch (err) {
          console.warn(`[Phase 1-3] ${t('analysis.phase1_failed')}:`, err)
          this.initializeRealtimeExecutor(sectionBytes, mainSec.virtualAddress)
          this.broadcastToUI('handlers:auto-detected', {
            phase1Error: String(err),
            executionMode: 'realtime'
          })
        }

        if (this.executionMode === 'handlers' && this.engine.getHandlers().length === 0) {
          console.log(`[Phase 3] ${t('analysis.phase3_enabled')}`)
          this.initializeRealtimeExecutor(sectionBytes, mainSec.virtualAddress)
        }
      }
    }

    // Reset annotations
    this.bookmarks = []
    this.userComments = {}
    this.handlerLabels = {}
    this.handlerHypotheses = {}

    // Broadcast to UI
    this.broadcastToUI('binary:loaded', {
      binaryInfo: this.binaryInfo,
      state: this.engine.getStateManager().getState(),
      executionMode: this.executionMode
    })

    // Notify plugins
    notifyPluginEvent('event.onBinaryLoaded', this.binaryInfo)

    return this.binaryInfo
  }

  step(): { state: VMState; traceEntry: TraceEntry | null } {
    if (!this.engine) throw new Error('No binary loaded')

    let result: { state: VMState; traceEntry: TraceEntry | null }

    if (this.executionMode === 'realtime' && this.realtimeExecutor) {
      const beforeCount = this.engine.getTraceRecorder().getAll().length
      result = this.realtimeExecutor.executeStep()
      if (result.traceEntry) {
        result.traceEntry.index = beforeCount
        this.engine.getTraceRecorder().record(result.traceEntry)
      }
    } else {
      result = this.engine.step()
    }

    // Broadcast to UI
    this.broadcastToUI('vm:state-updated', {
      state: result.state,
      traceEntry: result.traceEntry
    })

    // Notify plugins
    notifyPluginEvent('event.onStep', {
      state: result.state,
      traceEntry: result.traceEntry
    })

    return result
  }

  stepOver(): { state: VMState; traceEntry: TraceEntry | null } {
    // For simple step over, just do a normal step for now (since we have single threads)
    return this.step()
  }

  run(): { state: VMState; stepsExecuted: number; reason: string } {
    if (!this.engine) throw new Error('No binary loaded')

    let result: { state: VMState; stepsExecuted: number; reason: string }

    if (this.executionMode === 'realtime' && this.realtimeExecutor) {
      let stepsExecuted = 0
      const maxSteps = this.engine.getConfig().maxSteps
      let reason = 'completed'

      while (!this.engine.getStateManager().isHalted() && stepsExecuted < maxSteps) {
        const vip = this.engine.getStateManager().getVIP()
        if (stepsExecuted > 0 && this.engine.getBreakpoints().has(vip)) {
          reason = 'breakpoint'
          break
        }

        const stepResult = this.realtimeExecutor.executeStep()
        if (stepResult.traceEntry) {
          stepResult.traceEntry.index = this.engine.getTraceRecorder().getAll().length
          this.engine.getTraceRecorder().record(stepResult.traceEntry)
        }

        stepsExecuted++
        if (stepResult.state.halted) {
          reason = stepResult.state.error || 'halted'
          break
        }
      }

      if (!this.engine.getStateManager().isHalted() && stepsExecuted >= maxSteps) {
        reason = 'max_steps_reached'
      }

      result = { state: this.engine.getStateManager().getState(), stepsExecuted, reason }
    } else {
      result = this.engine.run()
    }

    // Broadcast to UI
    this.broadcastToUI('vm:state-updated', {
      state: result.state,
      traceEntry: null
    })

    // Notify plugins
    notifyPluginEvent('event.onStep', {
      state: result.state,
      traceEntry: null
    })

    return result
  }

  stop(): void {
    if (this.engine) {
      this.engine.stop()
    }
  }

  reset(): void {
    if (!this.engine) return
    this.engine.reset()
    if (this.executionMode === 'realtime' && this.binaryInfo) {
      const execSections = this.binaryInfo.sections.filter(s => s.isExecutable)
      const mainSec = execSections[0]
      const data = getLoadedData()
      if (mainSec && data) {
        const sectionBytes = data.subarray(mainSec.rawAddress, mainSec.rawAddress + mainSec.rawSize)
        this.initializeRealtimeExecutor(sectionBytes, mainSec.virtualAddress)
      }
    }

    // Broadcast to UI
    this.broadcastToUI('vm:state-updated', {
      state: this.engine.getStateManager().getState(),
      traceEntry: null
    })
  }

  setHandlerLabel(address: number, label: string): void {
    const addrHex = `0x${address.toString(16)}`
    this.handlerLabels[addrHex] = label

    if (this.engine) {
      const handler = this.engine.getHandlers().find(h => h.address === address)
      if (handler) {
        handler.label = label
      }
    }

    this.broadcastToUI('vm:annotations-updated', {
      handlerLabels: this.handlerLabels,
      handlerHypotheses: this.handlerHypotheses
    })
  }

  setHandlerHypothesis(address: number, hypothesis: string): void {
    const addrHex = `0x${address.toString(16)}`
    this.handlerHypotheses[addrHex] = hypothesis

    if (this.engine) {
      const handler = this.engine.getHandlers().find(h => h.address === address)
      if (handler) {
        handler.hypothesis = hypothesis
      }
    }

    this.broadcastToUI('vm:annotations-updated', {
      handlerLabels: this.handlerLabels,
      handlerHypotheses: this.handlerHypotheses
    })
  }

  addBookmark(bookmark: Bookmark): void {
    this.bookmarks.push(bookmark)
    this.broadcastToUI('bookmarks:updated', this.bookmarks)
  }

  removeBookmark(id: string): void {
    this.bookmarks = this.bookmarks.filter(b => b.id !== id)
    this.broadcastToUI('bookmarks:updated', this.bookmarks)
  }

  // ─── Helpers ────────────────────────────────────────────────────────

  private broadcastToUI(channel: string, payload: any): void {
    if (this.mainWindow) {
      this.mainWindow.webContents.send(channel, payload)
    }
  }

  private initializeRealtimeExecutor(bytecode: Buffer, baseAddress: number): void {
    if (!this.engine) return

    this.realtimeExecutor = new RealtimeBytecodeExecutor(this.engine, bytecode, baseAddress, {
      decoderConfig: {
        opcodeSize: this.engine.getConfig().opcodeSize,
        unknownOpcodeHandling: 'fallback',
        variableLengthOpcodes: true
      },
      validateInstructions: true,
      recordUnknownOpcodes: true
    })
    this.executionMode = 'realtime'
    this.broadcastToUI('execution:mode-changed', { mode: 'realtime' })
  }

  private appendDynamicCFGEdges(edges: CFGEdge[], handlerNodeIds: Set<string>): void {
    if (!this.engine) return

    const trace = this.engine.getTraceRecorder().getAll()
    if (trace.length < 2) return

    const transitionCounts = new Map<string, { source: string; target: string; count: number }>()
    for (let i = 1; i < trace.length; i++) {
      const prev = trace[i - 1]
      const next = trace[i]
      if (!prev.handlerId || !next.handlerId) continue
      const key = `${prev.handlerId}->${next.handlerId}`
      const existing = transitionCounts.get(key)
      if (existing) {
        existing.count++
      } else {
        transitionCounts.set(key, { source: prev.handlerId, target: next.handlerId, count: 1 })
      }
    }

    for (const transition of transitionCounts.values()) {
      if (transition.count < 2) continue
      if (!handlerNodeIds.has(transition.source) || !handlerNodeIds.has(transition.target)) continue
      const edgeId = `runtime_${transition.source}_to_${transition.target}`
      edges.push({
        id: edgeId,
        source: transition.source,
        target: transition.target,
        type: 'jump',
        label: `runtime x${transition.count}`,
        count: transition.count
      })
    }
  }

  private buildCFG(): CFGData {
    const entryNodeId = 'CFG_ENTRY'
    const nodes = [
      {
        id: entryNodeId,
        address: this.binaryInfo?.entryPoint ?? 0,
        endAddress: this.binaryInfo?.entryPoint ?? 0,
        type: 'entry' as const,
        label: 'VM Entry',
        instructionCount: 0,
        instructions: []
      }
    ]
    const edges = [] as any[]

    if (this.engine) {
      const handlers = this.engine.getHandlers()
      const dispatcher = this.engine.getDispatcher()

      if (handlers.length > 0) {
        if (dispatcher) {
          const dispatcherId = 'CFG_DISPATCHER'
          nodes.push({
            id: dispatcherId,
            address: dispatcher.address,
            endAddress: dispatcher.endAddress,
            type: 'block' as const,
            label: 'Dispatcher',
            instructionCount: 1,
            instructions: []
          })

          edges.push({ id: `${entryNodeId}_to_${dispatcherId}`, source: entryNodeId, target: dispatcherId, type: 'fallthrough' as const })
          handlers.forEach(handler => {
            nodes.push({
              id: handler.id,
              address: handler.address,
              endAddress: handler.endAddress,
              type: 'handler' as const,
              label: handler.label || `OP_${handler.opcodeValue.toString(16).toUpperCase()}`,
              handlerType: handler.type,
              instructionCount: Math.max(1, handler.size),
              instructions: []
            })
            edges.push({
              id: `dispatch_${handler.id}`,
              source: dispatcherId,
              target: handler.id,
              type: 'dispatch' as const,
              label: `opcode 0x${handler.opcodeValue.toString(16).toUpperCase()}`
            })
          })
        } else {
          handlers.forEach((handler, index) => {
            nodes.push({
              id: handler.id,
              address: handler.address,
              endAddress: handler.endAddress,
              type: 'handler' as const,
              label: handler.label || `OP_${handler.opcodeValue.toString(16).toUpperCase()}`,
              handlerType: handler.type,
              instructionCount: Math.max(1, handler.size),
              instructions: []
            })
            edges.push({
              id: `entry_to_${handler.id}`,
              source: entryNodeId,
              target: handler.id,
              type: index === 0 ? 'fallthrough' as const : 'dispatch' as const,
              label: index === 0 ? undefined : `opcode 0x${handler.opcodeValue.toString(16).toUpperCase()}`
            })
          })
        }
      } else if (this.binaryInfo) {
        const execSections = this.binaryInfo.sections.filter(s => s.isExecutable)
        const mainSection = execSections[0]
        const sectionStart = mainSection?.virtualAddress ?? this.binaryInfo.entryPoint
        const sectionEnd = mainSection ? mainSection.virtualAddress + mainSection.virtualSize : sectionStart
        const mainNodeId = 'CODE_SECTION'

        nodes.push({
          id: mainNodeId,
          address: sectionStart,
          endAddress: sectionEnd,
          type: 'block' as const,
          label: mainSection ? `Code Section (${mainSection.name})` : 'Loaded Code',
          instructionCount: 0,
          instructions: []
        })
        nodes.push({
          id: 'CFG_EXIT',
          address: sectionEnd,
          endAddress: sectionEnd,
          type: 'exit' as const,
          label: 'Exit',
          instructionCount: 0,
          instructions: []
        })
        edges.push({ id: `${entryNodeId}_to_${mainNodeId}`, source: entryNodeId, target: mainNodeId, type: 'fallthrough' as const })
        edges.push({ id: `${mainNodeId}_to_CFG_EXIT`, source: mainNodeId, target: 'CFG_EXIT', type: 'fallthrough' as const })
      }
    }

    this.appendDynamicCFGEdges(edges, new Set(nodes.map(n => n.id)))
    return { nodes, edges, entryNodeId }
  }

  getVMModel(): VMModel {
    if (!this.engine) {
      return {
        dispatcher: null,
        handlers: [],
        opcodes: [],
        cfg: { nodes: [], edges: [] },
        trace: [],
        state: {
          vip: 0,
          vsp: 0,
          stack: [],
          registers: {},
          flags: { ZF: false, CF: false, SF: false, OF: false, PF: false, AF: false },
          memory: new Map(),
          halted: false
        }
      }
    }

    return {
      dispatcher: this.engine.getDispatcher(),
      handlers: this.engine.getHandlers(),
      opcodes: [], // Opcodes mappings
      cfg: this.buildCFG(),
      trace: this.engine.getTraceRecorder().getAll(),
      state: this.engine.getStateManager().getState()
    }
  }
}

export const engineManager = new EngineManager()
