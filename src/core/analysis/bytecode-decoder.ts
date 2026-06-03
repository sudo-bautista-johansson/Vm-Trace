// ============================================================================
// Bytecode Decoder
// Decodes VM bytecode instructions in real-time during execution.
// Handles variable-length opcodes, immediates, and validates instruction format.
// ============================================================================

export interface DecodedInstruction {
  address: number
  opcodeValue: number
  operands: number[]
  immediateValue?: number | bigint
  size: number // Total instruction size in bytes
  isValid: boolean
  error?: string
}

export interface DecoderConfig {
  opcodeSize: number // Size of opcode (1, 2, 4 bytes)
  immediateSize?: number // Default size of immediate values (4 bytes)
  variableLengthOpcodes?: boolean
  unknownOpcodeHandling: 'skip' | 'error' | 'fallback'
}

const DEFAULT_CONFIG: DecoderConfig = {
  opcodeSize: 1,
  immediateSize: 4,
  variableLengthOpcodes: false,
  unknownOpcodeHandling: 'fallback'
}

export class BytecodeDecoder {
  private bytecode: Buffer
  private baseAddress: number
  private config: DecoderConfig
  private knownOpcodes: Set<number> = new Set()

  constructor(bytecode: Buffer, baseAddress: number = 0, config?: Partial<DecoderConfig>) {
    this.bytecode = bytecode
    this.baseAddress = baseAddress
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.initializeKnownOpcodes()
  }

  /**
   * Initialize set of known opcode values
   */
  private initializeKnownOpcodes(): void {
    // Common VM opcodes
    const known = [
      0x68, // PUSH
      0x58, // POP
      0x01, // ADD
      0x29, // SUB
      0xF7, // MUL
      0xF6, // DIV
      0xF5, // MOD
      0xF8, // NEG
      0x21, // AND
      0x09, // OR
      0x31, // XOR
      0xD1, // SHL
      0xD3, // SHR
      0x39, // CMP_EQ
      0x3A, // CMP_NE
      0x3B, // CMP_LT
      0x3C, // CMP_LE
      0x3D, // CMP_GT
      0x3E, // CMP_GE
      0xEB, // JMP
      0xE8, // CALL
      0x74, // JZ
      0x75, // JNZ
      0x90, // NOP
      0x88, // SWAP
      0x89, // DUP
      0xFF, // CALL
      0xC3  // RET
    ]

    for (const op of known) {
      this.knownOpcodes.add(op)
    }
  }

  /**
   * Decode instruction at given VIP
   */
  decode(vip: number): DecodedInstruction {
    const relativeVip = vip - this.baseAddress

    // Bounds check
    if (relativeVip < 0 || relativeVip >= this.bytecode.length) {
      return {
        address: vip,
        opcodeValue: 0,
        operands: [],
        size: 0,
        isValid: false,
        error: `VIP out of bounds: 0x${vip.toString(16)}`
      }
    }

    // Read opcode
    let opcodeValue = 0
    let opcodeSize = this.config.opcodeSize

    // Support variable-length opcodes (e.g., x86-like escape sequences)
    if (this.config.variableLengthOpcodes && this.bytecode[relativeVip] === 0x0F) {
      // Two-byte opcode
      if (relativeVip + 2 > this.bytecode.length) {
        return {
          address: vip,
          opcodeValue: this.bytecode[relativeVip],
          operands: [],
          size: 1,
          isValid: false,
          error: 'Incomplete two-byte opcode'
        }
      }
      opcodeValue = (this.bytecode[relativeVip] << 8) | this.bytecode[relativeVip + 1]
      opcodeSize = 2
    } else {
      // Standard single/multi-byte opcode
      for (let i = 0; i < this.config.opcodeSize; i++) {
        if (relativeVip + i >= this.bytecode.length) {
          return {
            address: vip,
            opcodeValue,
            operands: [],
            size: i,
            isValid: false,
            error: `Incomplete opcode at 0x${vip.toString(16)}`
          }
        }
        opcodeValue |= this.bytecode[relativeVip + i] << (i * 8)
      }
    }

    // Decode operands
    const { operands, immediateValue, operandSize } = this.decodeOperands(
      opcodeValue,
      relativeVip + opcodeSize
    )

    const isKnown = this.knownOpcodes.has(opcodeValue)
    const totalSize = opcodeSize + operandSize

    return {
      address: vip,
      opcodeValue,
      operands,
      immediateValue,
      size: totalSize,
      isValid: isKnown || this.config.unknownOpcodeHandling !== 'error',
      error: !isKnown && this.config.unknownOpcodeHandling === 'error'
        ? `Unknown opcode: 0x${opcodeValue.toString(16).toUpperCase()}`
        : undefined
    }
  }

  /**
   * Decode operands based on opcode type
   */
  private decodeOperands(
    opcodeValue: number,
    startPos: number
  ): { operands: number[]; immediateValue?: number | bigint; operandSize: number } {
    let operandSize = 0
    let immediateValue: number | bigint | undefined
    const operands: number[] = []

    // Based on opcode, determine operand format
    switch (opcodeValue) {
      // Opcodes with 32-bit signed immediate
      case 0x68: // PUSH imm32
      case 0xEB: // JMP imm32
      case 0xE8: // CALL imm32
      case 0x74: // JZ imm32
      case 0x75: // JNZ imm32
        if (startPos + 4 <= this.bytecode.length) {
          immediateValue = this.bytecode.readInt32LE(startPos)
          operandSize = 4
        }
        break

      // Opcodes with 8-bit operand (register index)
      case 0x8B: // MOV r8
      case 0x89: // MOV r8
        if (startPos + 1 <= this.bytecode.length) {
          operands.push(this.bytecode[startPos])
          operandSize = 1
        }
        break

      // Opcodes with no operands
      case 0x58: // POP
      case 0x01: // ADD
      case 0x29: // SUB
      case 0xF7: // MUL
      case 0xF6: // DIV
      case 0xF5: // MOD
      case 0xF8: // NEG
      case 0x21: // AND
      case 0x09: // OR
      case 0x31: // XOR
      case 0xD1: // SHL
      case 0xD3: // SHR
      case 0x39: // CMP_EQ
      case 0x3B: // CMP_LT
      case 0x3D: // CMP_GT
      case 0x88: // SWAP
      case 0x89: // DUP
      case 0x90: // NOP
      case 0xC3: // RET
      default:
        operandSize = 0
        break
    }

    return { operands, immediateValue, operandSize }
  }

  /**
   * Decode a sequence of instructions
   */
  decodeSequence(startVip: number, maxCount: number = 100): DecodedInstruction[] {
    const instructions: DecodedInstruction[] = []
    let vip = startVip
    let count = 0

    while (count < maxCount) {
      const instr = this.decode(vip)
      instructions.push(instr)

      if (!instr.isValid || instr.size === 0) {
        break
      }

      vip += instr.size
      count++
    }

    return instructions
  }

  /**
   * Check if opcode is a branch/jump instruction
   */
  isBranchOpcode(opcodeValue: number): boolean {
    return [0xEB, 0x74, 0x75, 0xFF, 0xC3].includes(opcodeValue)
  }

  /**
   * Check if opcode is a conditional jump
   */
  isConditionalJump(opcodeValue: number): boolean {
    return [0x74, 0x75].includes(opcodeValue)
  }

  /**
   * Check if opcode modifies stack
   */
  modifiesStack(opcodeValue: number): boolean {
    return [0x68, 0x58, 0x01, 0x29, 0xF7, 0x21, 0x09, 0x31].includes(opcodeValue)
  }

  /**
   * Check if opcode modifies control flow
   */
  modifiesControlFlow(opcodeValue: number): boolean {
    return this.isBranchOpcode(opcodeValue)
  }

  /**
   * Generate human-readable disassembly line
   */
  disassemble(instruction: DecodedInstruction): string {
    const mnemonic = this.getMnemonic(instruction.opcodeValue)
    const addressStr = `0x${instruction.address.toString(16).toUpperCase().padStart(8, '0')}`

    if (instruction.immediateValue !== undefined) {
      if (typeof instruction.immediateValue === 'bigint') {
        return `${addressStr}  ${mnemonic} 0x${instruction.immediateValue.toString(16).toUpperCase()}`
      } else {
        return `${addressStr}  ${mnemonic} 0x${instruction.immediateValue.toString(16).toUpperCase()}`
      }
    } else if (instruction.operands.length > 0) {
      const ops = instruction.operands.map(op => `0x${op.toString(16)}`).join(', ')
      return `${addressStr}  ${mnemonic} ${ops}`
    } else {
      return `${addressStr}  ${mnemonic}`
    }
  }

  /**
   * Get mnemonic for opcode
   */
  private getMnemonic(opcodeValue: number): string {
    const mnemonics: Record<number, string> = {
      0x68: 'PUSH',
      0x58: 'POP',
      0x01: 'ADD',
      0x29: 'SUB',
      0xF7: 'MUL',
      0x21: 'AND',
      0x09: 'OR',
      0x31: 'XOR',
      0x39: 'CMP',
      0xEB: 'JMP',
      0x74: 'JZ',
      0x75: 'JNZ',
      0x90: 'NOP',
      0xFF: 'CALL',
      0xC3: 'RET',
      0x8B: 'MOV',
      0x89: 'MOV'
    }

    return mnemonics[opcodeValue] || `OP_${opcodeValue.toString(16).toUpperCase()}`
  }

  /**
   * Register custom opcode with mnemonic
   */
  registerOpcode(value: number, mnemonic: string): void {
    this.knownOpcodes.add(value)
  }

  /**
   * Get statistics about bytecode
   */
  getStatistics(): {
    totalSize: number
    instructionCount: number
    uniqueOpcodes: number
    validInstructions: number
    errors: number
  } {
    const instructions = this.decodeSequence(this.baseAddress, 10000)
    const uniqueOpcodes = new Set(instructions.map(i => i.opcodeValue))

    return {
      totalSize: this.bytecode.length,
      instructionCount: instructions.length,
      uniqueOpcodes: uniqueOpcodes.size,
      validInstructions: instructions.filter(i => i.isValid).length,
      errors: instructions.filter(i => !i.isValid).length
    }
  }
}
