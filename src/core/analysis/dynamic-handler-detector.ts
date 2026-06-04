// ============================================================================
// Dynamic Handler Detector
// Integrates with BytecodeAnalyzer to automatically detect opcodes,
// create handler mappings, and register them in VMEngine.
// ============================================================================

import { BytecodeAnalyzer, DispatcherPattern, OpcodeCandidate } from './bytecode-analyzer'
import { OpcodeSemanticAnalyzer } from './opcode-semantic-analyzer'
import { VMHandler } from '../model/types'

export interface DetectionResult {
  dispatcherFound: boolean
  pattern: DispatcherPattern | null
  opcodesCandidates: OpcodeCandidate[]
  handlersCreated: VMHandler[]
  confidence: number // Overall confidence in detection (0-1)
  semanticInfo?: { // Phase 2 enhancement
    analyzed: number
    withKnownSemantics: number
    inferredSemantics: number
  }
}

export class DynamicHandlerDetector {
  private analyzer: BytecodeAnalyzer

  constructor(bytecode: Buffer, baseAddress: number = 0) {
    this.analyzer = new BytecodeAnalyzer(bytecode, baseAddress)
  }

  /**
   * Main entry point: Analyze bytecode and auto-detect handlers
   */
  detectHandlers(): DetectionResult {
    const result: DetectionResult = {
      dispatcherFound: false,
      pattern: null,
      opcodesCandidates: [],
      handlersCreated: [],
      confidence: 0
    }

    // Step 1: Detect dispatcher pattern
    const pattern = this.analyzer.analyzeDispatcher()
    if (pattern && pattern.confidence > 0.5) {
      result.pattern = pattern
      result.dispatcherFound = true
    }

    // Step 2: Identify likely opcodes from frequency analysis
    const opcodes = this.analyzer.identifyLikelyOpcodes()
    result.opcodesCandidates = opcodes.filter(o => o.likely)

    // Step 3: Create handlers for detected opcodes
    result.handlersCreated = this.createHandlers(result.opcodesCandidates)

    // Step 4: Analyze semantics for each handler (Phase 2)
    const semanticInfo = this.analyzeSemantics(result.handlersCreated)
    result.semanticInfo = semanticInfo

    // Step 5: Calculate overall confidence
    result.confidence = this.calculateConfidence(result)

    return result
  }

  /**
   * Create VMHandler objects for detected opcodes
   * These are placeholder handlers; real handlers would analyze semantics
   */
  private createHandlers(opcodes: OpcodeCandidate[]): VMHandler[] {
    const handlers: VMHandler[] = []
    let handlerId = 0

    for (const opcode of opcodes) {
      const handler: VMHandler = {
        id: `auto_op_${opcode.value.toString(16).toUpperCase()}`,
        opcodeValue: opcode.value,
        label: `OP_${opcode.value.toString(16).toUpperCase()}`,
        address: 0, // Unknown during auto-detection
        size: 1, // Default
        operandSize: 0, // Will be determined during execution
        description: `Auto-detected opcode ${opcode.value} (frequency: ${opcode.frequency})`,
        isDataReference: false,
        executionCount: 0,
        handlerType: 'unknown',
        confidence: Math.min(opcode.frequency / 10, 1)
      }

      handlers.push(handler)
      handlerId++
    }

    return handlers
  }

  /**
   * Phase 2: Analyze semantic meaning of detected opcodes
   */
  private analyzeSemantics(handlers: VMHandler[]): { analyzed: number; withKnownSemantics: number; inferredSemantics: number } {
    let analyzed = 0
    let withKnownSemantics = 0
    let inferredSemantics = 0

    for (const handler of handlers) {
      analyzed++

      // Try to find known signature
      const knownSig = OpcodeSemanticAnalyzer.getKnownSignature(handler.opcodeValue)
      if (knownSig) {
        withKnownSemantics++
        handler.label = OpcodeSemanticAnalyzer.getExecutorLabel(knownSig.type)
        handler.handlerType = knownSig.type.split(':')[1] || 'unknown'
        handler.description = knownSig.description
      } else {
        // Gather contextual opcode patterns around a few occurrences.
        const positions = this.analyzer.getOpcodePositions(handler.opcodeValue)
        const samplePositions = positions.slice(0, 5)
        let precedingOpcodes: number[] = []
        let followingOpcodes: number[] = []
        let bytecodeWindow: Buffer | undefined

        for (const pos of samplePositions) {
          const context = this.analyzer.getOpcodeContext(pos, 6)
          precedingOpcodes = precedingOpcodes.concat(context.precedingOpcodes)
          followingOpcodes = followingOpcodes.concat(context.followingOpcodes)
          bytecodeWindow = bytecodeWindow || context.bytecodeWindow
        }

        const inferred = OpcodeSemanticAnalyzer.analyzeOpcode(handler.opcodeValue, {
          frequency: handler.confidence ? Math.round(handler.confidence * 100) : 0,
          precedingOpcodes,
          followingOpcodes,
          bytecodeWindow,
          position: samplePositions[0]
        })
        inferredSemantics++
        handler.label = OpcodeSemanticAnalyzer.getExecutorLabel(inferred.type)
        handler.handlerType = inferred.type.split(':')[1] || 'unknown'
        handler.description = inferred.description
      }
    }

    return { analyzed, withKnownSemantics, inferredSemantics }
  }

  /**
   * Calculate overall confidence in the detection
   */
  private calculateConfidence(result: DetectionResult): number {
    let confidence = 0

    // Dispatcher found: +0.3
    if (result.dispatcherFound && result.pattern) {
      confidence += result.pattern.confidence * 0.3
    }

    // Opcodes detected: +0.4
    if (result.opcodesCandidates.length >= 10) {
      confidence += 0.4
    } else if (result.opcodesCandidates.length >= 5) {
      confidence += 0.2
    }

    // Handlers created: +0.3
    const avgHandlerConfidence = result.handlersCreated.length > 0
      ? result.handlersCreated.reduce((sum, h) => sum + (h.confidence || 0), 0) / result.handlersCreated.length
      : 0
    confidence += Math.min(avgHandlerConfidence, 0.3)

    return Math.min(confidence, 1)
  }

  /**
   * Analyze bytecode structure and statistics
   */
  analyzeStructure() {
    return this.analyzer.getStatistics()
  }

  /**
   * Find all potential jump tables in bytecode
   */
  findJumpTables() {
    return this.analyzer.findJumpTables()
  }

  /**
   * Get most likely opcodes (frequency-based ranking)
   */
  getMostLikelyOpcodes(count: number = 20): OpcodeCandidate[] {
    const candidates = this.analyzer.identifyLikelyOpcodes(500)
    return candidates.slice(0, count)
  }

  /**
   * Generate a report of detection results
   */
  generateReport(result: DetectionResult): string {
    let report = '=== Bytecode Handler Detection Report (with Semantic Analysis) ===\n\n'

    report += `Confidence Level: ${(result.confidence * 100).toFixed(1)}%\n`
    report += `Dispatcher Pattern Found: ${result.dispatcherFound ? 'Yes' : 'No'}\n\n`

    if (result.pattern) {
      report += `Dispatcher Type: ${result.pattern.type}\n`
      report += `Pattern Description: ${result.pattern.pattern}\n`
      report += `Dispatcher Address: 0x${result.pattern.dispatcherAddress.toString(16).toUpperCase()}\n`
      if (result.pattern.jumpTableSize) {
        report += `Handler Count: ${result.pattern.jumpTableSize}\n`
      }
      report += '\n'
    }

    report += `Detected Opcodes: ${result.opcodesCandidates.length}\n`
    for (const opcode of result.opcodesCandidates.slice(0, 10)) {
      report += `  0x${opcode.value.toString(16).toUpperCase().padStart(2, '0')}: frequency=${opcode.frequency}\n`
    }

    if (result.opcodesCandidates.length > 10) {
      report += `  ... and ${result.opcodesCandidates.length - 10} more\n`
    }

    report += `\nHandlers Created: ${result.handlersCreated.length}\n`

    // Phase 2 semantic analysis info
    if (result.semanticInfo) {
      report += `\n=== Semantic Analysis (Phase 2) ===\n`
      report += `Opcodes Analyzed: ${result.semanticInfo.analyzed}\n`
      report += `With Known Semantics: ${result.semanticInfo.withKnownSemantics}\n`
      report += `Inferred Semantics: ${result.semanticInfo.inferredSemantics}\n`

      // Show semantic classification
      report += `\nOpcodes by Semantic Type:\n`
      const classified: Record<string, number> = {}
      for (const handler of result.handlersCreated) {
        const type = handler.handlerType || 'unknown'
        classified[type] = (classified[type] || 0) + 1
      }
      for (const [type, count] of Object.entries(classified)) {
        report += `  ${type}: ${count}\n`
      }
    }

    return report
  }
}

