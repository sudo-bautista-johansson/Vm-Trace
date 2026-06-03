// ============================================================================
// Opcode Semantic Analyzer
// Infers semantic meaning of opcodes through pattern recognition and
// bytecode structure analysis. Classifies opcodes as arithmetic, stack, etc.
// ============================================================================

export enum OpcodeSemanticType {
  // Stack operations
  STACK_PUSH = 'stack:push',
  STACK_POP = 'stack:pop',
  STACK_DUP = 'stack:dup',
  STACK_SWAP = 'stack:swap',

  // Arithmetic
  ARITH_ADD = 'arith:add',
  ARITH_SUB = 'arith:sub',
  ARITH_MUL = 'arith:mul',
  ARITH_DIV = 'arith:div',
  ARITH_MOD = 'arith:mod',
  ARITH_NEG = 'arith:neg',

  // Logic/Bitwise
  LOGIC_AND = 'logic:and',
  LOGIC_OR = 'logic:or',
  LOGIC_XOR = 'logic:xor',
  LOGIC_NOT = 'logic:not',
  LOGIC_SHL = 'logic:shl',
  LOGIC_SHR = 'logic:shr',

  // Comparison
  CMP_EQ = 'cmp:eq',
  CMP_NE = 'cmp:ne',
  CMP_LT = 'cmp:lt',
  CMP_LE = 'cmp:le',
  CMP_GT = 'cmp:gt',
  CMP_GE = 'cmp:ge',

  // Control Flow
  JMP_UNCONDITIONAL = 'jmp:unconditional',
  JMP_IF_ZERO = 'jmp:if_zero',
  JMP_IF_NOT_ZERO = 'jmp:if_not_zero',
  JMP_IF_CARRY = 'jmp:if_carry',
  JMP_INDIRECT = 'jmp:indirect',
  CALL = 'control:call',
  RET = 'control:ret',

  // Memory
  LOAD_REG = 'mem:load_reg',
  STORE_REG = 'mem:store_reg',
  LOAD_MEM = 'mem:load_mem',
  STORE_MEM = 'mem:store_mem',

  // Other
  NOP = 'misc:nop',
  HALT = 'misc:halt',
  UNKNOWN = 'unknown'
}

export interface SemanticSignature {
  type: OpcodeSemanticType
  stackDelta: number // Net change in stack size (+1, -1, 0, etc.)
  stackIn: number // Items consumed from stack
  stackOut: number // Items pushed to stack
  sideEffects: string[] // List of side effects
  hasImmediate: boolean // Takes immediate operand
  immediateSize?: number // Size of immediate (1, 2, 4, 8 bytes)
  description: string
}

export class OpcodeSemanticAnalyzer {
  /**
   * Analyze bytecode sequence to infer semantic meaning
   * Based on common patterns in VM bytecode
   */
  static analyzeOpcode(
    opcode: number,
    context: {
      frequency: number // How often this appears
      precedingOpcodes?: number[] // Previous opcodes
      followingOpcodes?: number[] // Next opcodes
      bytecodeWindow?: Buffer // Surrounding bytes
      position?: number // Position in bytecode
    } = {}
  ): SemanticSignature {
    // Strategy: Use frequency patterns and contextual analysis
    // to infer what this opcode likely does

    // High frequency + context analysis
    const frequencyHint = this.getFrequencyHint(opcode, context.frequency)
    const contextHint = this.analyzeContext(opcode, context)
    const bytecodeHint = context.bytecodeWindow
      ? this.analyzeBytecodePattern(opcode, context.bytecodeWindow, context.position || 0)
      : null

    // Combine hints to make best guess
    return this.inferSemantics(opcode, frequencyHint, contextHint, bytecodeHint)
  }

  /**
   * Get semantic hint from frequency distribution
   * Stack opcodes tend to appear frequently
   * Rare opcodes tend to be control flow or special operations
   */
  private static getFrequencyHint(opcode: number, frequency: number): Partial<SemanticSignature> {
    // Heuristics based on typical VM bytecode distributions
    if (frequency > 50) {
      // Very frequent: likely stack operations or common arithmetic
      return {
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1
      }
    } else if (frequency > 20) {
      // Common: could be arithmetic or stack
      return {
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1
      }
    } else if (frequency > 5) {
      // Uncommon: likely specialized (jumps, loads, etc.)
      return {
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0
      }
    } else {
      // Rare: likely control flow or special
      return {
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0
      }
    }
  }

  /**
   * Analyze context: what opcodes appear before/after?
   * E.g., if always followed by JZ → likely a comparison
   */
  private static analyzeContext(
    opcode: number,
    context: {
      precedingOpcodes?: number[]
      followingOpcodes?: number[]
    }
  ): Partial<SemanticSignature> {
    // If often followed by conditional jumps → comparison
    if (context.followingOpcodes?.some(op => [0x74, 0x75, 0xEB].includes(op))) {
      return {
        type: OpcodeSemanticType.CMP_EQ,
        stackDelta: -2,
        stackIn: 2,
        stackOut: 0
      }
    }

    // If often preceded by PUSH → likely consumer
    if (context.precedingOpcodes?.some(op => op === 0x68)) {
      return {
        stackDelta: -1,
        stackIn: 1,
        stackOut: 0
      }
    }

    return {}
  }

  /**
   * Analyze bytecode pattern around opcode
   * E.g., PUSH imm + ADD patterns
   */
  private static analyzeBytecodePattern(
    opcode: number,
    window: Buffer,
    position: number
  ): Partial<SemanticSignature> | null {
    // Pattern: 0x68 (PUSH) followed by 4 bytes (immediate)
    if (opcode === 0x68 && position + 5 <= window.length) {
      return {
        type: OpcodeSemanticType.STACK_PUSH,
        hasImmediate: true,
        immediateSize: 4,
        stackDelta: 1,
        stackIn: 0,
        stackOut: 1
      }
    }

    // Pattern: 0x01 (ADD) - common x86 ADD encoding
    if (opcode === 0x01) {
      return {
        type: OpcodeSemanticType.ARITH_ADD,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1
      }
    }

    return null
  }

  /**
   * Infer final semantics from hints
   */
  private static inferSemantics(
    opcode: number,
    frequencyHint: Partial<SemanticSignature>,
    contextHint: Partial<SemanticSignature>,
    bytecodeHint: Partial<SemanticSignature> | null
  ): SemanticSignature {
    // Priority: bytecode pattern > context > frequency > default
    const best = bytecodeHint || contextHint || frequencyHint

    return {
      type: best.type || OpcodeSemanticType.UNKNOWN,
      stackDelta: best.stackDelta ?? 0,
      stackIn: best.stackIn ?? 0,
      stackOut: best.stackOut ?? 0,
      sideEffects: best.sideEffects ?? [],
      hasImmediate: best.hasImmediate ?? false,
      immediateSize: best.immediateSize,
      description: best.description || `Opcode 0x${opcode.toString(16).toUpperCase()}`
    }
  }

  /**
   * Common signature library for known opcodes
   */
  static getKnownSignature(opcode: number): SemanticSignature | null {
    const sigs: Record<number, SemanticSignature> = {
      // Stack operations (x86-inspired)
      0x68: {
        type: OpcodeSemanticType.STACK_PUSH,
        stackDelta: 1,
        stackIn: 0,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: true,
        immediateSize: 4,
        description: 'PUSH immediate'
      },
      0x58: {
        type: OpcodeSemanticType.STACK_POP,
        stackDelta: -1,
        stackIn: 1,
        stackOut: 0,
        sideEffects: [],
        hasImmediate: false,
        description: 'POP (discard)'
      },

      // Arithmetic
      0x01: {
        type: OpcodeSemanticType.ARITH_ADD,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['zf', 'cf', 'of'],
        hasImmediate: false,
        description: 'ADD'
      },
      0x29: {
        type: OpcodeSemanticType.ARITH_SUB,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['zf', 'cf', 'of'],
        hasImmediate: false,
        description: 'SUB'
      },
      0xF7: {
        type: OpcodeSemanticType.ARITH_MUL,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['cf', 'of'],
        hasImmediate: false,
        description: 'MUL'
      },
      0xF6: {
        type: OpcodeSemanticType.ARITH_DIV,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['zf', 'cf', 'of'],
        hasImmediate: false,
        description: 'DIV'
      },
      0xF5: {
        type: OpcodeSemanticType.ARITH_MOD,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['zf', 'cf'],
        hasImmediate: false,
        description: 'MOD'
      },
      0xF8: {
        type: OpcodeSemanticType.ARITH_NEG,
        stackDelta: 0,
        stackIn: 1,
        stackOut: 1,
        sideEffects: ['zf', 'cf', 'of'],
        hasImmediate: false,
        description: 'NEG'
      },
      0xD1: {
        type: OpcodeSemanticType.LOGIC_SHL,
        stackDelta: 0,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['zf', 'cf'],
        hasImmediate: false,
        description: 'SHL'
      },
      0xD3: {
        type: OpcodeSemanticType.LOGIC_SHR,
        stackDelta: 0,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['zf', 'cf'],
        hasImmediate: false,
        description: 'SHR'
      },
      0x88: {
        type: OpcodeSemanticType.STACK_SWAP,
        stackDelta: 0,
        stackIn: 2,
        stackOut: 2,
        sideEffects: [],
        hasImmediate: false,
        description: 'SWAP'
      },
      0x89: {
        type: OpcodeSemanticType.STACK_DUP,
        stackDelta: 1,
        stackIn: 1,
        stackOut: 2,
        sideEffects: [],
        hasImmediate: false,
        description: 'DUP'
      },

      // Logic
      0x21: {
        type: OpcodeSemanticType.LOGIC_AND,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['zf'],
        hasImmediate: false,
        description: 'AND'
      },
      0x09: {
        type: OpcodeSemanticType.LOGIC_OR,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['zf'],
        hasImmediate: false,
        description: 'OR'
      },
      0x31: {
        type: OpcodeSemanticType.LOGIC_XOR,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ['zf'],
        hasImmediate: false,
        description: 'XOR'
      },

      // Comparison
      0x39: {
        type: OpcodeSemanticType.CMP_EQ,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: 'CMP_EQ'
      },
      0x3A: {
        type: OpcodeSemanticType.CMP_NE,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: 'CMP_NE'
      },
      0x3B: {
        type: OpcodeSemanticType.CMP_LT,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: 'CMP_LT'
      },
      0x3C: {
        type: OpcodeSemanticType.CMP_LE,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: 'CMP_LE'
      },
      0x3D: {
        type: OpcodeSemanticType.CMP_GT,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: 'CMP_GT'
      },
      0x3E: {
        type: OpcodeSemanticType.CMP_GE,
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: 'CMP_GE'
      },

      // Jumps
      0xEB: {
        type: OpcodeSemanticType.JMP_UNCONDITIONAL,
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0,
        sideEffects: ['vip'],
        hasImmediate: true,
        immediateSize: 4,
        description: 'JMP'
      },
      0x74: {
        type: OpcodeSemanticType.JMP_IF_ZERO,
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0,
        sideEffects: ['vip'],
        hasImmediate: true,
        immediateSize: 4,
        description: 'JZ'
      },
      0x75: {
        type: OpcodeSemanticType.JMP_IF_NOT_ZERO,
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0,
        sideEffects: ['vip'],
        hasImmediate: true,
        immediateSize: 4,
        description: 'JNZ'
      },
      0xE8: {
        type: OpcodeSemanticType.CALL,
        stackDelta: 1,
        stackIn: 0,
        stackOut: 1,
        sideEffects: ['vip'],
        hasImmediate: true,
        immediateSize: 4,
        description: 'CALL'
      },

      // NOP
      0x90: {
        type: OpcodeSemanticType.NOP,
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0,
        sideEffects: [],
        hasImmediate: false,
        description: 'NOP'
      }
    }

    return sigs[opcode] || null
  }

  /**
   * Map semantic type to handler executor label
   */
  static getExecutorLabel(semanticType: OpcodeSemanticType): string {
    const map: Record<OpcodeSemanticType, string> = {
      [OpcodeSemanticType.STACK_PUSH]: 'PUSH',
      [OpcodeSemanticType.STACK_POP]: 'POP',
      [OpcodeSemanticType.STACK_DUP]: 'DUP',
      [OpcodeSemanticType.STACK_SWAP]: 'SWAP',
      [OpcodeSemanticType.ARITH_ADD]: 'ADD',
      [OpcodeSemanticType.ARITH_SUB]: 'SUB',
      [OpcodeSemanticType.ARITH_MUL]: 'MUL',
      [OpcodeSemanticType.ARITH_DIV]: 'DIV',
      [OpcodeSemanticType.ARITH_MOD]: 'MOD',
      [OpcodeSemanticType.ARITH_NEG]: 'NEG',
      [OpcodeSemanticType.LOGIC_AND]: 'AND',
      [OpcodeSemanticType.LOGIC_OR]: 'OR',
      [OpcodeSemanticType.LOGIC_XOR]: 'XOR',
      [OpcodeSemanticType.LOGIC_NOT]: 'NOT',
      [OpcodeSemanticType.LOGIC_SHL]: 'SHL',
      [OpcodeSemanticType.LOGIC_SHR]: 'SHR',
      [OpcodeSemanticType.CMP_EQ]: 'CMP',
      [OpcodeSemanticType.CMP_NE]: 'CMP_NE',
      [OpcodeSemanticType.CMP_LT]: 'CMP_LT',
      [OpcodeSemanticType.CMP_LE]: 'CMP_LE',
      [OpcodeSemanticType.CMP_GT]: 'CMP_GT',
      [OpcodeSemanticType.CMP_GE]: 'CMP_GE',
      [OpcodeSemanticType.JMP_UNCONDITIONAL]: 'JMP',
      [OpcodeSemanticType.JMP_IF_ZERO]: 'JZ',
      [OpcodeSemanticType.JMP_IF_NOT_ZERO]: 'JNZ',
      [OpcodeSemanticType.JMP_IF_CARRY]: 'JC',
      [OpcodeSemanticType.JMP_INDIRECT]: 'JMP_IND',
      [OpcodeSemanticType.CALL]: 'CALL',
      [OpcodeSemanticType.RET]: 'RET',
      [OpcodeSemanticType.LOAD_REG]: 'LOAD',
      [OpcodeSemanticType.STORE_REG]: 'STORE',
      [OpcodeSemanticType.LOAD_MEM]: 'LOAD_MEM',
      [OpcodeSemanticType.STORE_MEM]: 'STORE_MEM',
      [OpcodeSemanticType.NOP]: 'NOP',
      [OpcodeSemanticType.HALT]: 'HALT',
      [OpcodeSemanticType.UNKNOWN]: 'UNKNOWN'
    }
    return map[semanticType] || 'UNKNOWN'
  }
}
