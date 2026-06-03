// ============================================================================
// Realtime Bytecode Executor
// Executes VM bytecode in real-time by decoding and executing instructions
// without relying on pre-registered handlers.
// ============================================================================

import { BytecodeDecoder, DecodedInstruction, DecoderConfig } from './bytecode-decoder'
import { OpcodeSemanticAnalyzer, OpcodeSemanticType } from './opcode-semantic-analyzer'
import { VMEngine } from '../emulator/vm-engine'
import { VMState, TraceEntry } from '../model/types'
import { VMStateManager } from '../emulator/vm-state'

export interface RealtimeExecutionConfig {
  decoderConfig?: Partial<DecoderConfig>
  maxInstructionsPerStep?: number
  validateInstructions?: boolean
  recordUnknownOpcodes?: boolean
}

export class RealtimeBytecodeExecutor {
  private decoder: BytecodeDecoder
  private engine: VMEngine
  private config: RealtimeExecutionConfig
  private unknownOpcodes: Set<number> = new Set()
  private semanticAnalyzer: OpcodeSemanticAnalyzer = OpcodeSemanticAnalyzer

  constructor(engine: VMEngine, bytecode: Buffer, baseAddress: number = 0, config?: RealtimeExecutionConfig) {
    this.engine = engine
    this.decoder = new BytecodeDecoder(bytecode, baseAddress, config?.decoderConfig)
    this.config = config || {}
  }

  /**
   * Execute single instruction from bytecode at VIP
   * Returns how many bytes were consumed
   */
  executeInstruction(): number {
    const vip = this.engine.getStateManager().getVIP()

    // Decode instruction at current VIP
    const instruction = this.decoder.decode(vip)

    if (!instruction.isValid) {
      if (instruction.error) {
        this.engine.getStateManager().halt(instruction.error)
      } else {
        this.engine.getStateManager().halt(`Invalid instruction at 0x${vip.toString(16)}`)
      }
      return 0
    }

    // Try to execute the instruction
    this.executeDecodedInstruction(instruction)

    return instruction.size
  }

  executeStep(): { state: VMState; traceEntry: TraceEntry | null } {
    const vip = this.engine.getStateManager().getVIP()
    const stateBefore = this.engine.getStateManager().getState()

    const instruction = this.decoder.decode(vip)
    if (!instruction.isValid) {
      if (instruction.error) {
        this.engine.getStateManager().halt(instruction.error)
      } else {
        this.engine.getStateManager().halt(`Invalid instruction at 0x${vip.toString(16)}`)
      }
      return { state: this.engine.getStateManager().getState(), traceEntry: null }
    }

    this.executeDecodedInstruction(instruction)
    const stateAfter = this.engine.getStateManager().getState()
    const diff = VMStateManager.diff(stateBefore, stateAfter)

    const traceEntry: TraceEntry = {
      index: 0,
      timestamp: Date.now(),
      address: vip,
      opcodeValue: instruction.opcodeValue,
      handlerId: undefined,
      handlerLabel: undefined,
      mnemonic: this.decoder.disassemble(instruction),
      operands: '',
      stackDelta: diff.stackDelta,
      registersChanged: diff.registersChanged,
      flagsChanged: diff.flagsChanged
    }

    return { state: stateAfter, traceEntry }
  }

  /**
   * Execute a decoded instruction
   */
  private executeDecodedInstruction(instruction: DecodedInstruction): void {
    const opcode = instruction.opcodeValue

    // Try known signature first
    let signature = OpcodeSemanticAnalyzer.getKnownSignature(opcode)

    // If unknown, infer semantics
    if (!signature) {
      signature = OpcodeSemanticAnalyzer.analyzeOpcode(opcode, {
        frequency: 1
      })
      if (this.config.recordUnknownOpcodes) {
        this.unknownOpcodes.add(opcode)
      }
    }

    // Execute based on semantic type
    this.executeBySemanticType(instruction, signature.type, instruction.immediateValue)
  }

  /**
   * Execute instruction based on semantic type
   */
  private executeBySemanticType(
    instruction: DecodedInstruction,
    semanticType: OpcodeSemanticType,
    immediate?: number | bigint
  ): void {
    switch (semanticType) {
      // Stack operations
      case OpcodeSemanticType.STACK_PUSH:
        if (immediate !== undefined) {
          this.engine.push(BigInt(immediate))
        }
        break

      case OpcodeSemanticType.STACK_POP:
        this.engine.pop()
        break

      case OpcodeSemanticType.STACK_DUP:
        this.engine.push(this.engine.getStateManager().peek())
        break

      case OpcodeSemanticType.STACK_SWAP: {
        const a = this.engine.pop()
        const b = this.engine.pop()
        this.engine.push(a)
        this.engine.push(b)
        break
      }

      // Arithmetic
      case OpcodeSemanticType.ARITH_ADD: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a + b)
        break
      }

      case OpcodeSemanticType.ARITH_SUB: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a - b)
        break
      }

      case OpcodeSemanticType.ARITH_MUL: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a * b)
        break
      }

      case OpcodeSemanticType.ARITH_DIV: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        if (b === 0n) {
          this.engine.getStateManager().halt('Division by zero')
        } else {
          this.engine.push(a / b)
        }
        break
      }

      case OpcodeSemanticType.ARITH_MOD: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        if (b === 0n) {
          this.engine.getStateManager().halt('Modulo by zero')
        } else {
          this.engine.push(a % b)
        }
        break
      }

      // Logic
      case OpcodeSemanticType.LOGIC_AND: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a & b)
        break
      }

      case OpcodeSemanticType.LOGIC_OR: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a | b)
        break
      }

      case OpcodeSemanticType.LOGIC_XOR: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a ^ b)
        break
      }

      // Comparison
      case OpcodeSemanticType.CMP_EQ: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a === b ? 1n : 0n)
        break
      }

      case OpcodeSemanticType.CMP_NE: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a !== b ? 1n : 0n)
        break
      }

      case OpcodeSemanticType.CMP_LT: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a < b ? 1n : 0n)
        break
      }

      case OpcodeSemanticType.CMP_LE: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a <= b ? 1n : 0n)
        break
      }

      case OpcodeSemanticType.CMP_GT: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a > b ? 1n : 0n)
        break
      }

      case OpcodeSemanticType.CMP_GE: {
        const b = this.engine.pop()
        const a = this.engine.pop()
        this.engine.push(a >= b ? 1n : 0n)
        break
      }

      case OpcodeSemanticType.ARITH_NEG: {
        const a = this.engine.pop()
        this.engine.push(-a)
        break
      }

      case OpcodeSemanticType.LOGIC_SHL: {
        const count = this.engine.pop()
        const value = this.engine.pop()
        this.engine.push(value << count)
        break
      }

      case OpcodeSemanticType.LOGIC_SHR: {
        const count = this.engine.pop()
        const value = this.engine.pop()
        this.engine.push(value >> count)
        break
      }

      // Control Flow
      case OpcodeSemanticType.JMP_UNCONDITIONAL:
        if (immediate !== undefined) {
          const nextVip = instruction.address + instruction.size
          this.engine.setVIP(nextVip + Number(immediate))
          return // Don't advance VIP
        }
        break

      case OpcodeSemanticType.JMP_IF_ZERO:
        if (immediate !== undefined) {
          const top = this.engine.getStateManager().peek()
          if (top === 0n) {
            const nextVip = instruction.address + instruction.size
            this.engine.setVIP(nextVip + Number(immediate))
            return // Don't advance VIP
          }
        }
        break

      case OpcodeSemanticType.JMP_IF_NOT_ZERO:
        if (immediate !== undefined) {
          const top = this.engine.getStateManager().peek()
          if (top !== 0n) {
            const nextVip = instruction.address + instruction.size
            this.engine.setVIP(nextVip + Number(immediate))
            return // Don't advance VIP
          }
        }
        break

      // NOP
      case OpcodeSemanticType.NOP:
        // Do nothing
        break

      // Unknown
      case OpcodeSemanticType.UNKNOWN:
        if (this.config.validateInstructions) {
          this.engine.getStateManager().halt(`Unknown opcode: 0x${instruction.opcodeValue.toString(16)}`)
          return
        }
        // Otherwise just skip
        break

      default:
        // For unhandled semantic types, just advance
        break
    }

    // Advance VIP by instruction size
    this.engine.advanceVIP(instruction.size)
  }

  /**
   * Run until halt or breakpoint using realtime execution
   */
  run(): { state: VMState; stepsExecuted: number; reason: string } {
    let stepsExecuted = 0
    const maxSteps = this.engine.getConfig().maxSteps

    while (!this.engine.getStateManager().isHalted() && stepsExecuted < maxSteps) {
      const vip = this.engine.getStateManager().getVIP()

      // Check breakpoints
      if (stepsExecuted > 0 && this.engine.getBreakpoints().has(vip)) {
        return { state: this.engine.getStateManager().getState(), stepsExecuted, reason: 'breakpoint' }
      }

      // Execute instruction
      this.executeInstruction()
      stepsExecuted++
    }

    let reason = 'completed'
    if (this.engine.getStateManager().isHalted()) {
      reason = this.engine.getStateManager().getError() || 'halted'
    } else if (stepsExecuted >= maxSteps) {
      reason = 'max_steps_reached'
    }

    return { state: this.engine.getStateManager().getState(), stepsExecuted, reason }
  }

  /**
   * Get list of unknown opcodes encountered
   */
  getUnknownOpcodes(): number[] {
    return Array.from(this.unknownOpcodes)
  }

  /**
   * Get disassembly of bytecode
   */
  disassemble(startVip?: number, count: number = 50): string[] {
    const vip = startVip ?? this.engine.getConfig().initialVIP
    const instructions = this.decoder.decodeSequence(vip, count)
    return instructions.map(instr => this.decoder.disassemble(instr))
  }

  /**
   * Get statistics about bytecode execution
   */
  getStatistics() {
    return this.decoder.getStatistics()
  }
}
