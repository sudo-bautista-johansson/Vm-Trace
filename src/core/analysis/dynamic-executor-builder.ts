// ============================================================================
// Dynamic Executor Builder
// Constructs and registers VM handlers based on inferred semantics.
// Bridges semantic analysis to actual handler execution.
// ============================================================================

import { OpcodeSemanticAnalyzer, OpcodeSemanticType, SemanticSignature } from './opcode-semantic-analyzer'
import { VMEngine } from '../emulator/vm-engine'

export interface DynamicExecutorConfig {
  opcodeValue: number
  semantic: SemanticSignature
  bytecodeContext?: Buffer
  position?: number
}

export class DynamicExecutorBuilder {
  /**
   * Build and register a handler executor based on semantic analysis
   */
  static buildAndRegister(engine: VMEngine, config: DynamicExecutorConfig): boolean {
    const executor = this.buildExecutor(config.semantic)
    if (!executor) return false

    // Get label for this semantic type
    const label = OpcodeSemanticAnalyzer.getExecutorLabel(config.semantic.type)

    // Register with engine
    engine.registerExecutor(label, executor)

    return true
  }

  /**
   * Build an executor function for a given semantic signature
   */
  static buildExecutor(semantic: SemanticSignature): ((engine: VMEngine) => void) | null {
    switch (semantic.type) {
      // Stack operations
      case OpcodeSemanticType.STACK_PUSH:
        return this.executePush(semantic)
      case OpcodeSemanticType.STACK_POP:
        return this.executePop(semantic)
      case OpcodeSemanticType.STACK_DUP:
        return this.executeDup(semantic)
      case OpcodeSemanticType.STACK_SWAP:
        return this.executeSwap(semantic)

      // Arithmetic
      case OpcodeSemanticType.ARITH_ADD:
        return this.executeAdd(semantic)
      case OpcodeSemanticType.ARITH_SUB:
        return this.executeSub(semantic)
      case OpcodeSemanticType.ARITH_MUL:
        return this.executeMul(semantic)
      case OpcodeSemanticType.ARITH_DIV:
        return this.executeDiv(semantic)
      case OpcodeSemanticType.ARITH_MOD:
        return this.executeMod(semantic)
      case OpcodeSemanticType.ARITH_NEG:
        return this.executeNeg(semantic)

      // Logic
      case OpcodeSemanticType.LOGIC_AND:
        return this.executeAnd(semantic)
      case OpcodeSemanticType.LOGIC_OR:
        return this.executeOr(semantic)
      case OpcodeSemanticType.LOGIC_XOR:
        return this.executeXor(semantic)
      case OpcodeSemanticType.LOGIC_NOT:
        return this.executeNot(semantic)
      case OpcodeSemanticType.LOGIC_SHL:
        return this.executeShl(semantic)
      case OpcodeSemanticType.LOGIC_SHR:
        return this.executeShr(semantic)

      // Comparison
      case OpcodeSemanticType.CMP_EQ:
        return this.executeCmp(semantic)

      // Jumps
      case OpcodeSemanticType.JMP_UNCONDITIONAL:
        return this.executeJmp(semantic)
      case OpcodeSemanticType.JMP_IF_ZERO:
        return this.executeJz(semantic)
      case OpcodeSemanticType.JMP_IF_NOT_ZERO:
        return this.executeJnz(semantic)

      // Memory
      case OpcodeSemanticType.LOAD_REG:
        return this.executeLoad(semantic)
      case OpcodeSemanticType.STORE_REG:
        return this.executeStore(semantic)

      // Other
      case OpcodeSemanticType.NOP:
        return this.executeNop(semantic)

      default:
        return null
    }
  }

  // ─── Stack Operations ────────────────────────────────────────────────

  private static executePush(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const imm = BigInt(engine.readBytecodeU32(engine.getConfig().opcodeSize))
      engine.push(imm)
      engine.advanceVIP(engine.getConfig().opcodeSize + 4)
    }
  }

  private static executePop(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      engine.pop()
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeDup(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const val = engine.getStateManager().peek()
      engine.push(val)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeSwap(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const a = engine.pop()
      const b = engine.pop()
      engine.push(a)
      engine.push(b)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  // ─── Arithmetic ─────────────────────────────────────────────────────

  private static executeAdd(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const b = engine.pop()
      const a = engine.pop()
      const result = a + b
      engine.push(result)
      engine.getStateManager().updateArithFlags(result)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeSub(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const b = engine.pop()
      const a = engine.pop()
      const result = a - b
      engine.push(result)
      engine.getStateManager().updateArithFlags(result)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeMul(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const b = engine.pop()
      const a = engine.pop()
      engine.push(a * b)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeDiv(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const b = engine.pop()
      const a = engine.pop()
      if (b === 0n) {
        engine.getStateManager().halt('Division by zero')
      } else {
        engine.push(a / b)
      }
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeMod(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const b = engine.pop()
      const a = engine.pop()
      if (b === 0n) {
        engine.getStateManager().halt('Modulo by zero')
      } else {
        engine.push(a % b)
      }
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeNeg(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const a = engine.pop()
      engine.push(-a)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  // ─── Logic/Bitwise ──────────────────────────────────────────────────

  private static executeAnd(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const b = engine.pop()
      const a = engine.pop()
      const result = a & b
      engine.push(result)
      engine.getStateManager().updateArithFlags(result)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeOr(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const b = engine.pop()
      const a = engine.pop()
      const result = a | b
      engine.push(result)
      engine.getStateManager().updateArithFlags(result)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeXor(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const b = engine.pop()
      const a = engine.pop()
      const result = a ^ b
      engine.push(result)
      engine.getStateManager().updateArithFlags(result)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeNot(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const a = engine.pop()
      engine.push(~a)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeShl(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const shift = engine.pop()
      const val = engine.pop()
      engine.push(val << shift)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  private static executeShr(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const shift = engine.pop()
      const val = engine.pop()
      engine.push(val >> shift)
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  // ─── Comparison ─────────────────────────────────────────────────────

  private static executeCmp(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const b = engine.pop()
      const a = engine.pop()
      switch (semantic.type) {
        case OpcodeSemanticType.CMP_EQ:
          engine.push(a === b ? 1n : 0n)
          break
        case OpcodeSemanticType.CMP_NE:
          engine.push(a !== b ? 1n : 0n)
          break
        case OpcodeSemanticType.CMP_LT:
          engine.push(a < b ? 1n : 0n)
          break
        case OpcodeSemanticType.CMP_LE:
          engine.push(a <= b ? 1n : 0n)
          break
        case OpcodeSemanticType.CMP_GT:
          engine.push(a > b ? 1n : 0n)
          break
        case OpcodeSemanticType.CMP_GE:
          engine.push(a >= b ? 1n : 0n)
          break
        default:
          engine.push(0n)
          break
      }
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  // ─── Jumps ──────────────────────────────────────────────────────────

  private static executeJmp(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const displacement = engine.readBytecodeU32(engine.getConfig().opcodeSize) | 0
      const nextVip = engine.getVIP() + engine.getConfig().opcodeSize + 4
      engine.setVIP(nextVip + displacement)
    }
  }

  private static executeJz(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const displacement = engine.readBytecodeU32(engine.getConfig().opcodeSize) | 0
      const top = engine.getStateManager().peek()
      const nextVip = engine.getVIP() + engine.getConfig().opcodeSize + 4
      if (top === 0n) {
        engine.setVIP(nextVip + displacement)
      } else {
        engine.advanceVIP(engine.getConfig().opcodeSize + 4)
      }
    }
  }

  private static executeJnz(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const displacement = engine.readBytecodeU32(engine.getConfig().opcodeSize) | 0
      const top = engine.getStateManager().peek()
      const nextVip = engine.getVIP() + engine.getConfig().opcodeSize + 4
      if (top !== 0n) {
        engine.setVIP(nextVip + displacement)
      } else {
        engine.advanceVIP(engine.getConfig().opcodeSize + 4)
      }
    }
  }

  // ─── Memory ─────────────────────────────────────────────────────────

  private static executeLoad(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const regIdx = engine.readBytecodeU8(engine.getConfig().opcodeSize)
      const regName = `v${regIdx}`
      engine.push(engine.getReg(regName))
      engine.advanceVIP(engine.getConfig().opcodeSize + 1)
    }
  }

  private static executeStore(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      const regIdx = engine.readBytecodeU8(engine.getConfig().opcodeSize)
      const regName = `v${regIdx}`
      engine.setReg(regName, engine.pop())
      engine.advanceVIP(engine.getConfig().opcodeSize + 1)
    }
  }

  // ─── Other ──────────────────────────────────────────────────────────

  private static executeNop(semantic: SemanticSignature) {
    return (engine: VMEngine) => {
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }

  /**
   * Build a generic fallback executor for unknown opcodes
   * Safely advances VIP without crashing
   */
  static buildFallbackExecutor(opcodeValue: number): (engine: VMEngine) => void {
    return (engine: VMEngine) => {
      console.warn(
        `[Fallback] Executing unknown opcode 0x${opcodeValue.toString(16).toUpperCase()}`
      )
      engine.advanceVIP(engine.getConfig().opcodeSize)
    }
  }
}
