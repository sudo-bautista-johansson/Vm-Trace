// ============================================================================
// Handler Semantic Analyzer
// Combines bytecode analysis, semantic inference, and executor building
// to create fully functional dynamic handlers from raw bytecode.
// ============================================================================

import { OpcodeSemanticAnalyzer, OpcodeSemanticType, SemanticSignature } from './opcode-semantic-analyzer'
import { DynamicExecutorBuilder } from './dynamic-executor-builder'
import { BytecodeAnalyzer } from './bytecode-analyzer'
import { VMHandler } from '../model/types'
import { VMEngine } from '../emulator/vm-engine'

export interface HandlerSemanticInfo {
  opcodeValue: number
  semantic: SemanticSignature
  confidence: number // 0-1, how confident in this analysis
  context: string // Human-readable description
  executorBuilt: boolean
}

export interface SemanticAnalysisResult {
  handlersAnalyzed: HandlerSemanticInfo[]
  totalHandlers: number
  successfulExecutors: number
  failedExecutors: number
  averageConfidence: number
}

export class HandlerSemanticAnalyzer {
  private bytecode: Buffer
  private baseAddress: number
  private frequency: Record<number, number>

  constructor(bytecode: Buffer, baseAddress: number = 0) {
    this.bytecode = bytecode
    this.baseAddress = baseAddress
    this.frequency = this.calculateFrequency(bytecode)
  }

  /**
   * Analyze handlers and build dynamic executors
   */
  analyzeAndBuild(engine: VMEngine, handlers: VMHandler[]): SemanticAnalysisResult {
    const result: SemanticAnalysisResult = {
      handlersAnalyzed: [],
      totalHandlers: handlers.length,
      successfulExecutors: 0,
      failedExecutors: 0,
      averageConfidence: 0
    }

    let totalConfidence = 0

    for (const handler of handlers) {
      // Analyze semantic for this handler
      const semantic = this.analyzeHandler(handler)

      // Try to build executor
      const built = DynamicExecutorBuilder.buildAndRegister(engine, {
        opcodeValue: handler.opcodeValue,
        semantic: semantic.semantic,
        bytecodeContext: this.bytecode,
        position: handler.address
      })

      if (built) {
        result.successfulExecutors++
      } else {
        result.failedExecutors++
      }

      result.handlersAnalyzed.push(semantic)
      totalConfidence += semantic.confidence
    }

    result.averageConfidence = handlers.length > 0 ? totalConfidence / handlers.length : 0

    return result
  }

  /**
   * Analyze a single handler to infer its semantic type
   */
  private analyzeHandler(handler: VMHandler): HandlerSemanticInfo {
    const opcode = handler.opcodeValue

    // Step 1: Check known signatures
    let semantic = OpcodeSemanticAnalyzer.getKnownSignature(opcode)
    let confidence = 0.9 // High confidence for known opcodes

    // Step 2: If unknown, use pattern-based analysis
    if (!semantic) {
      const context = {
        frequency: this.frequency[opcode] || 0,
        bytecodeWindow: this.bytecode
      }
      semantic = OpcodeSemanticAnalyzer.analyzeOpcode(opcode, context)
      confidence = 0.5 // Lower confidence for inferred opcodes
    }

    // Step 3: Adjust confidence based on frequency
    const freq = this.frequency[opcode] || 0
    if (freq >= 50) confidence = Math.min(confidence + 0.1, 1)
    else if (freq <= 2) confidence = Math.max(confidence - 0.2, 0.2)

    return {
      opcodeValue: opcode,
      semantic,
      confidence,
      context: `Opcode 0x${opcode.toString(16).toUpperCase()} - ${semantic.description}`,
      executorBuilt: false
    }
  }

  /**
   * Calculate byte frequency in bytecode
   */
  private calculateFrequency(bytecode: Buffer): Record<number, number> {
    const freq: Record<number, number> = {}
    for (let i = 0; i < bytecode.length; i++) {
      const byte = bytecode[i]
      freq[byte] = (freq[byte] || 0) + 1
    }
    return freq
  }

  /**
   * Generate detailed analysis report
   */
  generateReport(result: SemanticAnalysisResult): string {
    let report = '=== Handler Semantic Analysis Report ===\n\n'

    report += `Total Handlers Analyzed: ${result.totalHandlers}\n`
    report += `Successful Executors: ${result.successfulExecutors}\n`
    report += `Failed Executors: ${result.failedExecutors}\n`
    report += `Success Rate: ${((result.successfulExecutors / result.totalHandlers) * 100).toFixed(1)}%\n`
    report += `Average Confidence: ${(result.averageConfidence * 100).toFixed(1)}%\n\n`

    report += 'Handler Details:\n'
    report += '─'.repeat(80) + '\n'

    for (const handler of result.handlersAnalyzed) {
      report += `Opcode 0x${handler.opcodeValue.toString(16).toUpperCase().padStart(2, '0')}\n`
      report += `  Type: ${handler.semantic.type}\n`
      report += `  Label: ${OpcodeSemanticAnalyzer.getExecutorLabel(handler.semantic.type)}\n`
      report += `  Confidence: ${(handler.confidence * 100).toFixed(1)}%\n`
      report += `  Description: ${handler.semantic.description}\n`
      report += `  Stack Delta: ${handler.semantic.stackDelta > 0 ? '+' : ''}${handler.semantic.stackDelta}\n`
      report += `  Side Effects: ${handler.semantic.sideEffects.join(', ') || 'none'}\n`
      report += '\n'
    }

    return report
  }

  /**
   * Get summary statistics
   */
  getStatistics(): {
    totalOpcodes: number
    uniqueOpcodes: number
    averageFrequency: number
    maxFrequency: number
    minFrequency: number
  } {
    const opcodes = Object.keys(this.frequency).map(k => parseInt(k))
    const frequencies = opcodes.map(op => this.frequency[op])

    return {
      totalOpcodes: opcodes.length,
      uniqueOpcodes: opcodes.length,
      averageFrequency: frequencies.reduce((a, b) => a + b, 0) / opcodes.length,
      maxFrequency: Math.max(...frequencies),
      minFrequency: Math.min(...frequencies)
    }
  }

  /**
   * Classify handlers by semantic type
   */
  classifyHandlers(handlers: VMHandler[]): Map<OpcodeSemanticType, VMHandler[]> {
    const classified = new Map<OpcodeSemanticType, VMHandler[]>()

    for (const handler of handlers) {
      let signature = OpcodeSemanticAnalyzer.getKnownSignature(handler.opcodeValue)
      if (!signature) {
        signature = OpcodeSemanticAnalyzer.analyzeOpcode(handler.opcodeValue, {
          frequency: this.frequency[handler.opcodeValue] || 0
        })
      }

      const type = signature.type
      if (!classified.has(type)) {
        classified.set(type, [])
      }
      classified.get(type)!.push(handler)
    }

    return classified
  }

  /**
   * Group handlers by semantic family
   */
  getSemanticFamilies(handlers: VMHandler[]): Record<string, VMHandler[]> {
    const families: Record<string, VMHandler[]> = {
      stack: [],
      arithmetic: [],
      logic: [],
      comparison: [],
      control_flow: [],
      memory: [],
      other: []
    }

    for (const handler of handlers) {
      let signature = OpcodeSemanticAnalyzer.getKnownSignature(handler.opcodeValue)
      if (!signature) {
        signature = OpcodeSemanticAnalyzer.analyzeOpcode(handler.opcodeValue, {
          frequency: this.frequency[handler.opcodeValue] || 0
        })
      }

      const type = signature.type
      if (type.includes('stack:')) {
        families.stack.push(handler)
      } else if (type.includes('arith:')) {
        families.arithmetic.push(handler)
      } else if (type.includes('logic:')) {
        families.logic.push(handler)
      } else if (type.includes('cmp:')) {
        families.comparison.push(handler)
      } else if (type.includes('jmp:') || type.includes('control:')) {
        families.control_flow.push(handler)
      } else if (type.includes('mem:')) {
        families.memory.push(handler)
      } else {
        families.other.push(handler)
      }
    }

    return families
  }
}
