// ============================================================================
// x86/x64 Disassembler
// Table-driven decoder for the most common x86-64 instructions
// Covers the instructions typically found in VM dispatchers and handlers
// ============================================================================

import { DisasmInstruction, InstructionType } from '../model/types'

// ─── Register Tables ────────────────────────────────────────────────────────

const REG8 = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']
const REG8_REX = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                  'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']
const REG16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
               'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']
const REG32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
               'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
const REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
               'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

const CC_NAMES: Record<number, string> = {
  0x0: 'o', 0x1: 'no', 0x2: 'b', 0x3: 'ae', 0x4: 'e', 0x5: 'ne',
  0x6: 'be', 0x7: 'a', 0x8: 's', 0x9: 'ns', 0xA: 'p', 0xB: 'np',
  0xC: 'l', 0xD: 'ge', 0xE: 'le', 0xF: 'g'
}

// ─── Decoder State ──────────────────────────────────────────────────────────

interface DecoderState {
  data: Buffer | Uint8Array
  pos: number
  startPos: number
  baseAddress: number
  is64Mode: boolean
  // Prefixes
  hasRex: boolean
  rexW: boolean
  rexR: boolean
  rexX: boolean
  rexB: boolean
  hasOperandSizeOverride: boolean
  hasAddressSizeOverride: boolean
  hasRepPrefix: boolean
  hasRepnePrefix: boolean
  segmentOverride: string | null
  hasLockPrefix: boolean
}

function createState(data: Buffer | Uint8Array, baseAddress: number, is64: boolean): DecoderState {
  return {
    data, pos: 0, startPos: 0, baseAddress, is64Mode: is64,
    hasRex: false, rexW: false, rexR: false, rexX: false, rexB: false,
    hasOperandSizeOverride: false, hasAddressSizeOverride: false,
    hasRepPrefix: false, hasRepnePrefix: false,
    segmentOverride: null, hasLockPrefix: false
  }
}

function resetPrefixes(s: DecoderState): void {
  s.hasRex = false; s.rexW = false; s.rexR = false; s.rexX = false; s.rexB = false
  s.hasOperandSizeOverride = false; s.hasAddressSizeOverride = false
  s.hasRepPrefix = false; s.hasRepnePrefix = false
  s.segmentOverride = null; s.hasLockPrefix = false
}

function readByte(s: DecoderState): number {
  if (s.pos >= s.data.length) throw new Error('End of data')
  return s.data[s.pos++]
}

function peekByte(s: DecoderState): number {
  if (s.pos >= s.data.length) return -1
  return s.data[s.pos]
}

function readImm8(s: DecoderState): number {
  return readByte(s)
}

function readImm8Signed(s: DecoderState): number {
  const v = readByte(s)
  return v > 127 ? v - 256 : v
}

function readImm16(s: DecoderState): number {
  const lo = readByte(s)
  const hi = readByte(s)
  return lo | (hi << 8)
}

function readImm32(s: DecoderState): number {
  const b0 = readByte(s)
  const b1 = readByte(s)
  const b2 = readByte(s)
  const b3 = readByte(s)
  return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0
}

function readImm32Signed(s: DecoderState): number {
  const v = readImm32(s)
  return v > 0x7FFFFFFF ? v - 0x100000000 : v
}

function readImm64(s: DecoderState): bigint {
  const lo = BigInt(readImm32(s))
  const hi = BigInt(readImm32(s))
  return lo | (hi << 32n)
}

// ─── Operand Size Helpers ───────────────────────────────────────────────────

function getOperandSize(s: DecoderState): number {
  if (s.rexW) return 64
  if (s.hasOperandSizeOverride) return 16
  return s.is64Mode ? 32 : 32
}

function getRegName(index: number, size: number, hasRex: boolean): string {
  const idx = index & 0xF
  switch (size) {
    case 8: return hasRex ? (REG8_REX[idx] || `r${idx}b`) : (REG8[idx] || `r${idx}b`)
    case 16: return REG16[idx] || `r${idx}w`
    case 32: return REG32[idx] || `r${idx}d`
    case 64: return REG64[idx] || `r${idx}`
    default: return REG32[idx] || `r${idx}d`
  }
}

function getSizePrefix(size: number): string {
  switch (size) {
    case 8: return 'byte'
    case 16: return 'word'
    case 32: return 'dword'
    case 64: return 'qword'
    default: return ''
  }
}

// ─── ModR/M + SIB Decoder ───────────────────────────────────────────────────

interface ModRMResult {
  regField: number
  rmOperand: string   // decoded rm string (register or memory)
  isMemory: boolean
}

function decodeModRM(s: DecoderState, operandSize: number, useRegSize?: number): ModRMResult {
  const modrm = readByte(s)
  const mod = (modrm >> 6) & 3
  const reg = ((modrm >> 3) & 7) | (s.rexR ? 8 : 0)
  let rm = (modrm & 7) | (s.rexB ? 8 : 0)

  const actualSize = useRegSize ?? operandSize

  if (mod === 3) {
    // Register direct
    return {
      regField: reg,
      rmOperand: getRegName(rm, actualSize, s.hasRex),
      isMemory: false
    }
  }

  // Memory operand
  let memStr: string
  const addrSize = s.is64Mode ? 64 : 32
  const addrRegs = addrSize === 64 ? REG64 : REG32

  if ((modrm & 7) === 4 && !s.rexB || (modrm & 7) === 4) {
    // SIB byte follows (rm == 4 without REX.B, or rm == 4)
    const rmBase = modrm & 7
    if (rmBase === 4) {
      rm = 4 | (s.rexB ? 8 : 0)
    }
    const sib = readByte(s)
    const scale = 1 << ((sib >> 6) & 3)
    const indexRaw = ((sib >> 3) & 7) | (s.rexX ? 8 : 0)
    const baseRaw = (sib & 7) | (s.rexB ? 8 : 0)

    const hasIndex = indexRaw !== 4 // RSP/R12 can't be index
    const hasBase = !(mod === 0 && (sib & 7) === 5)

    let parts: string[] = []
    if (hasBase) {
      parts.push(addrRegs[baseRaw] || `r${baseRaw}`)
    }
    if (hasIndex) {
      const indexStr = addrRegs[indexRaw] || `r${indexRaw}`
      parts.push(scale > 1 ? `${indexStr}*${scale}` : indexStr)
    }

    let disp = 0
    if (mod === 0 && (sib & 7) === 5) {
      disp = readImm32Signed(s)
      if (parts.length === 0) {
        memStr = `[0x${(disp >>> 0).toString(16)}]`
      } else {
        memStr = disp !== 0
          ? `[${parts.join('+')}${disp >= 0 ? '+' : ''}0x${Math.abs(disp).toString(16)}]`
          : `[${parts.join('+')}]`
      }
    } else if (mod === 1) {
      disp = readImm8Signed(s)
      const dispStr = disp !== 0 ? (disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${(-disp).toString(16)}`) : ''
      memStr = `[${parts.join('+')}${dispStr}]`
    } else if (mod === 2) {
      disp = readImm32Signed(s)
      const dispStr = disp !== 0 ? (disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${(-disp).toString(16)}`) : ''
      memStr = `[${parts.join('+')}${dispStr}]`
    } else {
      memStr = `[${parts.join('+')}]`
    }
  } else if (mod === 0 && (modrm & 7) === 5) {
    // RIP-relative (64-bit) or absolute (32-bit)
    const disp = readImm32Signed(s)
    if (s.is64Mode) {
      const targetAddr = s.baseAddress + (s.pos - s.startPos) + disp
      memStr = `[rip+0x${(disp >>> 0).toString(16)}]`
    } else {
      memStr = `[0x${(disp >>> 0).toString(16)}]`
    }
  } else {
    // Simple [reg] or [reg+disp]
    const baseReg = addrRegs[rm] || `r${rm}`
    if (mod === 0) {
      memStr = `[${baseReg}]`
    } else if (mod === 1) {
      const disp = readImm8Signed(s)
      const dispStr = disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${(-disp).toString(16)}`
      memStr = `[${baseReg}${dispStr}]`
    } else {
      const disp = readImm32Signed(s)
      const dispStr = disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${(-disp).toString(16)}`
      memStr = `[${baseReg}${dispStr}]`
    }
  }

  const prefix = getSizePrefix(actualSize)
  return {
    regField: reg,
    rmOperand: prefix ? `${prefix} ptr ${memStr}` : memStr,
    isMemory: true
  }
}

// ─── Instruction Classification ─────────────────────────────────────────────

function classifyInstruction(mnemonic: string): InstructionType {
  const m = mnemonic.toLowerCase()
  if (['jmp', 'je', 'jne', 'jz', 'jnz', 'jb', 'jae', 'jbe', 'ja', 'jl', 'jge', 'jle', 'jg',
       'jo', 'jno', 'js', 'jns', 'jp', 'jnp', 'jcxz', 'jecxz', 'jrcxz',
       'call', 'ret', 'retn', 'loop', 'loope', 'loopne'].includes(m)) {
    return InstructionType.ControlFlow
  }
  if (['push', 'pop', 'pushf', 'popf', 'pushfq', 'popfq', 'pusha', 'popa'].includes(m)) {
    return InstructionType.Stack
  }
  if (['add', 'sub', 'mul', 'imul', 'div', 'idiv', 'inc', 'dec', 'neg', 'adc', 'sbb'].includes(m)) {
    return InstructionType.Arithmetic
  }
  if (['and', 'or', 'xor', 'not', 'shl', 'shr', 'sar', 'sal', 'rol', 'ror', 'rcl', 'rcr',
       'bt', 'bts', 'btr', 'btc', 'bsf', 'bsr', 'shld', 'shrd'].includes(m)) {
    return InstructionType.Logic
  }
  if (['mov', 'movzx', 'movsx', 'movsxd', 'lea', 'xchg', 'cmova', 'cmovae', 'cmovb', 'cmovbe',
       'cmove', 'cmovne', 'cmovg', 'cmovge', 'cmovl', 'cmovle', 'cmovs', 'cmovns',
       'cmovo', 'cmovno', 'cmovp', 'cmovnp', 'bswap',
       'movdqa', 'movdqu', 'movaps', 'movups', 'movss', 'movsd'].includes(m)) {
    return InstructionType.Memory
  }
  if (['cmp', 'test'].includes(m)) {
    return InstructionType.Comparison
  }
  if (['nop', 'fnop'].includes(m)) {
    return InstructionType.Nop
  }
  if (['int', 'int3', 'syscall', 'sysenter', 'hlt', 'cpuid', 'rdtsc', 'ud2'].includes(m)) {
    return InstructionType.System
  }
  if (['rep', 'repe', 'repne', 'movs', 'movsb', 'movsd', 'movsq', 'stos', 'stosb',
       'stosd', 'stosq', 'cmps', 'cmpsb', 'cmpsd', 'scas', 'scasb', 'lods'].includes(m)) {
    return InstructionType.String
  }
  return InstructionType.Unknown
}

// ─── ALU Group Decoder ──────────────────────────────────────────────────────

const ALU_OPS = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
const SHIFT_OPS = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sal', 'sar']

// ─── Main Decode Function ───────────────────────────────────────────────────

function decodeOne(s: DecoderState): { mnemonic: string; operands: string } | null {
  s.startPos = s.pos
  resetPrefixes(s)

  // Parse prefixes
  let prefixCount = 0
  while (prefixCount < 15) {
    const b = peekByte(s)
    if (b === -1) return null

    if (b === 0xF0) { s.hasLockPrefix = true; s.pos++; prefixCount++ }
    else if (b === 0xF2) { s.hasRepnePrefix = true; s.pos++; prefixCount++ }
    else if (b === 0xF3) { s.hasRepPrefix = true; s.pos++; prefixCount++ }
    else if (b === 0x66) { s.hasOperandSizeOverride = true; s.pos++; prefixCount++ }
    else if (b === 0x67) { s.hasAddressSizeOverride = true; s.pos++; prefixCount++ }
    else if (b === 0x2E) { s.segmentOverride = 'cs'; s.pos++; prefixCount++ }
    else if (b === 0x36) { s.segmentOverride = 'ss'; s.pos++; prefixCount++ }
    else if (b === 0x3E) { s.segmentOverride = 'ds'; s.pos++; prefixCount++ }
    else if (b === 0x26) { s.segmentOverride = 'es'; s.pos++; prefixCount++ }
    else if (b === 0x64) { s.segmentOverride = 'fs'; s.pos++; prefixCount++ }
    else if (b === 0x65) { s.segmentOverride = 'gs'; s.pos++; prefixCount++ }
    else if (s.is64Mode && (b & 0xF0) === 0x40) {
      // REX prefix
      s.hasRex = true
      s.rexW = (b & 0x08) !== 0
      s.rexR = (b & 0x04) !== 0
      s.rexX = (b & 0x02) !== 0
      s.rexB = (b & 0x01) !== 0
      s.pos++; prefixCount++
    }
    else break
  }

  const opcode = readByte(s)
  const opSize = getOperandSize(s)

  // ─── 1-byte opcodes ───────────────────────────────────────────────

  // ALU r/m, reg (00-3F, even = byte, odd = word/dword)
  if (opcode <= 0x3F && (opcode & 0xC0) === 0) {
    const aluIdx = (opcode >> 3) & 7
    const direction = opcode & 2 // 0 = rm,reg  2 = reg,rm
    const isByte = (opcode & 1) === 0

    // Special cases: 04/05 = AL/AX,imm  0C/0D = etc.
    if ((opcode & 7) === 4) {
      // op AL, imm8
      const imm = readImm8(s)
      return { mnemonic: ALU_OPS[aluIdx], operands: `al, 0x${imm.toString(16)}` }
    }
    if ((opcode & 7) === 5) {
      // op rAX, imm32/16
      const reg = getRegName(0, opSize, s.hasRex)
      const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s)
      return { mnemonic: ALU_OPS[aluIdx], operands: `${reg}, 0x${imm.toString(16)}` }
    }

    const sz = isByte ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    const regStr = getRegName(modrm.regField, sz, s.hasRex)

    if (direction === 0) {
      return { mnemonic: ALU_OPS[aluIdx], operands: `${modrm.rmOperand}, ${regStr}` }
    } else {
      return { mnemonic: ALU_OPS[aluIdx], operands: `${regStr}, ${modrm.rmOperand}` }
    }
  }

  // PUSH/POP reg (50-5F)
  if (opcode >= 0x50 && opcode <= 0x57) {
    const reg = (opcode - 0x50) | (s.rexB ? 8 : 0)
    const regName = getRegName(reg, s.is64Mode ? 64 : opSize, s.hasRex)
    return { mnemonic: 'push', operands: regName }
  }
  if (opcode >= 0x58 && opcode <= 0x5F) {
    const reg = (opcode - 0x58) | (s.rexB ? 8 : 0)
    const regName = getRegName(reg, s.is64Mode ? 64 : opSize, s.hasRex)
    return { mnemonic: 'pop', operands: regName }
  }

  // PUSH imm
  if (opcode === 0x68) {
    const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s)
    return { mnemonic: 'push', operands: `0x${imm.toString(16)}` }
  }
  if (opcode === 0x6A) {
    const imm = readImm8Signed(s)
    return { mnemonic: 'push', operands: `0x${(imm & 0xFF).toString(16)}` }
  }

  // Short conditional jumps (70-7F)
  if (opcode >= 0x70 && opcode <= 0x7F) {
    const cc = CC_NAMES[opcode & 0xF]
    const rel = readImm8Signed(s)
    const target = s.baseAddress + (s.pos - s.startPos) + s.startPos + rel // careful: relative to NEXT instruction
    const instrLen = s.pos - s.startPos
    const absTarget = s.baseAddress + s.pos + rel - (s.pos - s.startPos) + instrLen
    const actualTarget = s.baseAddress + s.pos + rel
    return { mnemonic: `j${cc}`, operands: `0x${(s.baseAddress + s.pos + rel).toString(16)}` }
  }

  // Group 1: ALU r/m, imm (80-83)
  if (opcode >= 0x80 && opcode <= 0x83) {
    const isByte = opcode === 0x80
    const isSignExtImm8 = opcode === 0x83
    const sz = isByte ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    const aluIdx = modrm.regField & 7

    let immStr: string
    if (isByte || isSignExtImm8) {
      const imm = readImm8(s)
      immStr = `0x${imm.toString(16)}`
    } else if (opcode === 0x81) {
      const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s)
      immStr = `0x${imm.toString(16)}`
    } else {
      const imm = readImm8(s)
      immStr = `0x${imm.toString(16)}`
    }

    return { mnemonic: ALU_OPS[aluIdx], operands: `${modrm.rmOperand}, ${immStr}` }
  }

  // TEST r/m, reg (84/85)
  if (opcode === 0x84 || opcode === 0x85) {
    const sz = opcode === 0x84 ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    const regStr = getRegName(modrm.regField, sz, s.hasRex)
    return { mnemonic: 'test', operands: `${modrm.rmOperand}, ${regStr}` }
  }

  // XCHG r/m, reg (86/87)
  if (opcode === 0x86 || opcode === 0x87) {
    const sz = opcode === 0x86 ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    const regStr = getRegName(modrm.regField, sz, s.hasRex)
    return { mnemonic: 'xchg', operands: `${modrm.rmOperand}, ${regStr}` }
  }

  // MOV r/m, reg / reg, r/m (88-8B)
  if (opcode >= 0x88 && opcode <= 0x8B) {
    const isByte = (opcode & 1) === 0
    const direction = opcode & 2
    const sz = isByte ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    const regStr = getRegName(modrm.regField, sz, s.hasRex)

    if (direction === 0) {
      return { mnemonic: 'mov', operands: `${modrm.rmOperand}, ${regStr}` }
    } else {
      return { mnemonic: 'mov', operands: `${regStr}, ${modrm.rmOperand}` }
    }
  }

  // LEA reg, m (8D)
  if (opcode === 0x8D) {
    const modrm = decodeModRM(s, opSize)
    const regStr = getRegName(modrm.regField, opSize, s.hasRex)
    return { mnemonic: 'lea', operands: `${regStr}, ${modrm.rmOperand}` }
  }

  // NOP (90) or XCHG rAX, reg
  if (opcode === 0x90) {
    if (!s.rexB && !s.hasRex) return { mnemonic: 'nop', operands: '' }
    const reg = s.rexB ? 8 : 0
    const regName = getRegName(reg, opSize, s.hasRex)
    return { mnemonic: 'xchg', operands: `${getRegName(0, opSize, s.hasRex)}, ${regName}` }
  }

  // XCHG rAX, reg (91-97)
  if (opcode >= 0x91 && opcode <= 0x97) {
    const reg = (opcode - 0x90) | (s.rexB ? 8 : 0)
    const regName = getRegName(reg, opSize, s.hasRex)
    return { mnemonic: 'xchg', operands: `${getRegName(0, opSize, s.hasRex)}, ${regName}` }
  }

  // CDQ/CWD/CQO (99)
  if (opcode === 0x99) {
    if (s.rexW) return { mnemonic: 'cqo', operands: '' }
    if (s.hasOperandSizeOverride) return { mnemonic: 'cwd', operands: '' }
    return { mnemonic: 'cdq', operands: '' }
  }

  // CBW/CWDE/CDQE (98)
  if (opcode === 0x98) {
    if (s.rexW) return { mnemonic: 'cdqe', operands: '' }
    if (s.hasOperandSizeOverride) return { mnemonic: 'cbw', operands: '' }
    return { mnemonic: 'cwde', operands: '' }
  }

  // PUSHF/POPF (9C/9D)
  if (opcode === 0x9C) return { mnemonic: s.is64Mode ? 'pushfq' : 'pushf', operands: '' }
  if (opcode === 0x9D) return { mnemonic: s.is64Mode ? 'popfq' : 'popf', operands: '' }

  // MOV AL/AX, moffs (A0-A3)
  if (opcode >= 0xA0 && opcode <= 0xA3) {
    const isByte = (opcode & 1) === 0
    const isStore = opcode >= 0xA2
    const sz = isByte ? 8 : opSize
    const addr = s.is64Mode ? Number(readImm64(s)) : readImm32(s)
    const regStr = getRegName(0, sz, s.hasRex)
    const memStr = `${getSizePrefix(sz)} ptr [0x${addr.toString(16)}]`
    if (isStore) {
      return { mnemonic: 'mov', operands: `${memStr}, ${regStr}` }
    }
    return { mnemonic: 'mov', operands: `${regStr}, ${memStr}` }
  }

  // TEST AL/AX, imm (A8/A9)
  if (opcode === 0xA8) {
    const imm = readImm8(s)
    return { mnemonic: 'test', operands: `al, 0x${imm.toString(16)}` }
  }
  if (opcode === 0xA9) {
    const reg = getRegName(0, opSize, s.hasRex)
    const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s)
    return { mnemonic: 'test', operands: `${reg}, 0x${imm.toString(16)}` }
  }

  // MOV reg, imm (B0-BF)
  if (opcode >= 0xB0 && opcode <= 0xB7) {
    const reg = (opcode - 0xB0) | (s.rexB ? 8 : 0)
    const imm = readImm8(s)
    return { mnemonic: 'mov', operands: `${getRegName(reg, 8, s.hasRex)}, 0x${imm.toString(16)}` }
  }
  if (opcode >= 0xB8 && opcode <= 0xBF) {
    const reg = (opcode - 0xB8) | (s.rexB ? 8 : 0)
    let imm: string
    if (s.rexW) {
      const v = readImm64(s)
      imm = `0x${v.toString(16)}`
    } else if (s.hasOperandSizeOverride) {
      imm = `0x${readImm16(s).toString(16)}`
    } else {
      imm = `0x${readImm32(s).toString(16)}`
    }
    return { mnemonic: 'mov', operands: `${getRegName(reg, opSize, s.hasRex)}, ${imm}` }
  }

  // Shift group (C0/C1 = r/m,imm8  D0/D1 = r/m,1  D2/D3 = r/m,CL)
  if (opcode === 0xC0 || opcode === 0xC1) {
    const sz = opcode === 0xC0 ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    const op = SHIFT_OPS[modrm.regField & 7]
    const imm = readImm8(s)
    return { mnemonic: op, operands: `${modrm.rmOperand}, ${imm}` }
  }
  if (opcode === 0xD0 || opcode === 0xD1) {
    const sz = opcode === 0xD0 ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    const op = SHIFT_OPS[modrm.regField & 7]
    return { mnemonic: op, operands: `${modrm.rmOperand}, 1` }
  }
  if (opcode === 0xD2 || opcode === 0xD3) {
    const sz = opcode === 0xD2 ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    const op = SHIFT_OPS[modrm.regField & 7]
    return { mnemonic: op, operands: `${modrm.rmOperand}, cl` }
  }

  // RET (C3/C2)
  if (opcode === 0xC3) return { mnemonic: 'ret', operands: '' }
  if (opcode === 0xC2) {
    const imm = readImm16(s)
    return { mnemonic: 'ret', operands: `0x${imm.toString(16)}` }
  }

  // MOV r/m, imm (C6/C7)
  if (opcode === 0xC6 || opcode === 0xC7) {
    const isByte = opcode === 0xC6
    const sz = isByte ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    let immStr: string
    if (isByte) {
      immStr = `0x${readImm8(s).toString(16)}`
    } else if (s.hasOperandSizeOverride) {
      immStr = `0x${readImm16(s).toString(16)}`
    } else {
      immStr = `0x${readImm32(s).toString(16)}`
    }
    return { mnemonic: 'mov', operands: `${modrm.rmOperand}, ${immStr}` }
  }

  // LEAVE (C9)
  if (opcode === 0xC9) return { mnemonic: 'leave', operands: '' }

  // INT 3 (CC)
  if (opcode === 0xCC) return { mnemonic: 'int3', operands: '' }

  // INT imm8 (CD)
  if (opcode === 0xCD) {
    const imm = readImm8(s)
    return { mnemonic: 'int', operands: `0x${imm.toString(16)}` }
  }

  // CALL rel32 (E8)
  if (opcode === 0xE8) {
    const rel = readImm32Signed(s)
    const target = s.baseAddress + s.pos + rel
    return { mnemonic: 'call', operands: `0x${(target >>> 0).toString(16)}` }
  }

  // JMP rel32 (E9)
  if (opcode === 0xE9) {
    const rel = readImm32Signed(s)
    const target = s.baseAddress + s.pos + rel
    return { mnemonic: 'jmp', operands: `0x${(target >>> 0).toString(16)}` }
  }

  // JMP rel8 (EB)
  if (opcode === 0xEB) {
    const rel = readImm8Signed(s)
    const target = s.baseAddress + s.pos + rel
    return { mnemonic: 'jmp', operands: `0x${(target >>> 0).toString(16)}` }
  }

  // Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV (F6/F7)
  if (opcode === 0xF6 || opcode === 0xF7) {
    const isByte = opcode === 0xF6
    const sz = isByte ? 8 : opSize
    const modrm = decodeModRM(s, sz)
    const grpOp = modrm.regField & 7
    switch (grpOp) {
      case 0: case 1: { // TEST
        let immStr: string
        if (isByte) immStr = `0x${readImm8(s).toString(16)}`
        else if (s.hasOperandSizeOverride) immStr = `0x${readImm16(s).toString(16)}`
        else immStr = `0x${readImm32(s).toString(16)}`
        return { mnemonic: 'test', operands: `${modrm.rmOperand}, ${immStr}` }
      }
      case 2: return { mnemonic: 'not', operands: modrm.rmOperand }
      case 3: return { mnemonic: 'neg', operands: modrm.rmOperand }
      case 4: return { mnemonic: 'mul', operands: modrm.rmOperand }
      case 5: return { mnemonic: 'imul', operands: modrm.rmOperand }
      case 6: return { mnemonic: 'div', operands: modrm.rmOperand }
      case 7: return { mnemonic: 'idiv', operands: modrm.rmOperand }
    }
  }

  // INC/DEC (FE/FF group 4/5)
  if (opcode === 0xFE) {
    const modrm = decodeModRM(s, 8)
    const op = (modrm.regField & 7) === 0 ? 'inc' : 'dec'
    return { mnemonic: op, operands: modrm.rmOperand }
  }
  if (opcode === 0xFF) {
    const modrm = decodeModRM(s, opSize)
    switch (modrm.regField & 7) {
      case 0: return { mnemonic: 'inc', operands: modrm.rmOperand }
      case 1: return { mnemonic: 'dec', operands: modrm.rmOperand }
      case 2: return { mnemonic: 'call', operands: modrm.rmOperand }
      case 3: return { mnemonic: 'call far', operands: modrm.rmOperand }
      case 4: return { mnemonic: 'jmp', operands: modrm.rmOperand }
      case 5: return { mnemonic: 'jmp far', operands: modrm.rmOperand }
      case 6: return { mnemonic: 'push', operands: modrm.rmOperand }
      default: return { mnemonic: 'db', operands: `0x${opcode.toString(16)}` }
    }
  }

  // HLT (F4)
  if (opcode === 0xF4) return { mnemonic: 'hlt', operands: '' }

  // CLC/STC/CLI/STI/CLD/STD (F8-FD)
  if (opcode === 0xF8) return { mnemonic: 'clc', operands: '' }
  if (opcode === 0xF9) return { mnemonic: 'stc', operands: '' }
  if (opcode === 0xFA) return { mnemonic: 'cli', operands: '' }
  if (opcode === 0xFB) return { mnemonic: 'sti', operands: '' }
  if (opcode === 0xFC) return { mnemonic: 'cld', operands: '' }
  if (opcode === 0xFD) return { mnemonic: 'std', operands: '' }

  // MOVS/STOS/LODS/SCAS/CMPS (A4-AF)
  if (opcode === 0xA4) return { mnemonic: 'movsb', operands: '' }
  if (opcode === 0xA5) return { mnemonic: s.rexW ? 'movsq' : 'movsd', operands: '' }
  if (opcode === 0xA6) return { mnemonic: 'cmpsb', operands: '' }
  if (opcode === 0xA7) return { mnemonic: s.rexW ? 'cmpsq' : 'cmpsd', operands: '' }
  if (opcode === 0xAA) return { mnemonic: 'stosb', operands: '' }
  if (opcode === 0xAB) return { mnemonic: s.rexW ? 'stosq' : 'stosd', operands: '' }
  if (opcode === 0xAC) return { mnemonic: 'lodsb', operands: '' }
  if (opcode === 0xAD) return { mnemonic: s.rexW ? 'lodsq' : 'lodsd', operands: '' }
  if (opcode === 0xAE) return { mnemonic: 'scasb', operands: '' }
  if (opcode === 0xAF) return { mnemonic: s.rexW ? 'scasq' : 'scasd', operands: '' }

  // ─── 2-byte opcodes (0F xx) ───────────────────────────────────────

  if (opcode === 0x0F) {
    const opcode2 = readByte(s)

    // Jcc near (0F 80-8F)
    if (opcode2 >= 0x80 && opcode2 <= 0x8F) {
      const cc = CC_NAMES[opcode2 & 0xF]
      const rel = readImm32Signed(s)
      const target = s.baseAddress + s.pos + rel
      return { mnemonic: `j${cc}`, operands: `0x${(target >>> 0).toString(16)}` }
    }

    // SETcc (0F 90-9F)
    if (opcode2 >= 0x90 && opcode2 <= 0x9F) {
      const cc = CC_NAMES[opcode2 & 0xF]
      const modrm = decodeModRM(s, 8)
      return { mnemonic: `set${cc}`, operands: modrm.rmOperand }
    }

    // CMOVcc (0F 40-4F)
    if (opcode2 >= 0x40 && opcode2 <= 0x4F) {
      const cc = CC_NAMES[opcode2 & 0xF]
      const modrm = decodeModRM(s, opSize)
      const regStr = getRegName(modrm.regField, opSize, s.hasRex)
      return { mnemonic: `cmov${cc}`, operands: `${regStr}, ${modrm.rmOperand}` }
    }

    // MOVZX (0F B6/B7)
    if (opcode2 === 0xB6 || opcode2 === 0xB7) {
      const srcSize = opcode2 === 0xB6 ? 8 : 16
      const modrm = decodeModRM(s, srcSize)
      const regStr = getRegName(modrm.regField, opSize, s.hasRex)
      return { mnemonic: 'movzx', operands: `${regStr}, ${modrm.rmOperand}` }
    }

    // MOVSX (0F BE/BF)
    if (opcode2 === 0xBE || opcode2 === 0xBF) {
      const srcSize = opcode2 === 0xBE ? 8 : 16
      const modrm = decodeModRM(s, srcSize)
      const regStr = getRegName(modrm.regField, opSize, s.hasRex)
      return { mnemonic: 'movsx', operands: `${regStr}, ${modrm.rmOperand}` }
    }

    // IMUL reg, r/m (0F AF)
    if (opcode2 === 0xAF) {
      const modrm = decodeModRM(s, opSize)
      const regStr = getRegName(modrm.regField, opSize, s.hasRex)
      return { mnemonic: 'imul', operands: `${regStr}, ${modrm.rmOperand}` }
    }

    // BSF/BSR (0F BC/BD)
    if (opcode2 === 0xBC || opcode2 === 0xBD) {
      const modrm = decodeModRM(s, opSize)
      const regStr = getRegName(modrm.regField, opSize, s.hasRex)
      const mnemonic = opcode2 === 0xBC ? 'bsf' : 'bsr'
      return { mnemonic, operands: `${regStr}, ${modrm.rmOperand}` }
    }

    // BSWAP (0F C8-CF)
    if (opcode2 >= 0xC8 && opcode2 <= 0xCF) {
      const reg = (opcode2 - 0xC8) | (s.rexB ? 8 : 0)
      return { mnemonic: 'bswap', operands: getRegName(reg, opSize, s.hasRex) }
    }

    // BT/BTS/BTR/BTC r/m, reg (0F A3/AB/B3/BB)
    if (opcode2 === 0xA3) { const m = decodeModRM(s, opSize); return { mnemonic: 'bt', operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}` } }
    if (opcode2 === 0xAB) { const m = decodeModRM(s, opSize); return { mnemonic: 'bts', operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}` } }
    if (opcode2 === 0xB3) { const m = decodeModRM(s, opSize); return { mnemonic: 'btr', operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}` } }
    if (opcode2 === 0xBB) { const m = decodeModRM(s, opSize); return { mnemonic: 'btc', operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}` } }

    // SHLD/SHRD (0F A4/A5/AC/AD)
    if (opcode2 === 0xA4) { const m = decodeModRM(s, opSize); const imm = readImm8(s); return { mnemonic: 'shld', operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}, ${imm}` } }
    if (opcode2 === 0xA5) { const m = decodeModRM(s, opSize); return { mnemonic: 'shld', operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}, cl` } }
    if (opcode2 === 0xAC) { const m = decodeModRM(s, opSize); const imm = readImm8(s); return { mnemonic: 'shrd', operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}, ${imm}` } }
    if (opcode2 === 0xAD) { const m = decodeModRM(s, opSize); return { mnemonic: 'shrd', operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}, cl` } }

    // SYSCALL/SYSRET (0F 05/07)
    if (opcode2 === 0x05) return { mnemonic: 'syscall', operands: '' }
    if (opcode2 === 0x07) return { mnemonic: 'sysret', operands: '' }

    // CPUID (0F A2)
    if (opcode2 === 0xA2) return { mnemonic: 'cpuid', operands: '' }

    // RDTSC (0F 31)
    if (opcode2 === 0x31) return { mnemonic: 'rdtsc', operands: '' }

    // UD2 (0F 0B)
    if (opcode2 === 0x0B) return { mnemonic: 'ud2', operands: '' }

    // NOP (0F 1F /0)
    if (opcode2 === 0x1F) {
      const modrm = decodeModRM(s, opSize)
      return { mnemonic: 'nop', operands: modrm.rmOperand }
    }

    // MOVSXD (63 in 64-bit mode with REX.W)
    // Handled below

    return { mnemonic: 'db', operands: `0x0f, 0x${opcode2.toString(16)}` }
  }

  // MOVSXD (63) in 64-bit mode
  if (opcode === 0x63 && s.is64Mode) {
    const modrm = decodeModRM(s, 32)
    const regStr = getRegName(modrm.regField, s.rexW ? 64 : 32, s.hasRex)
    return { mnemonic: 'movsxd', operands: `${regStr}, ${modrm.rmOperand}` }
  }

  // IMUL reg, r/m, imm (69/6B)
  if (opcode === 0x69) {
    const modrm = decodeModRM(s, opSize)
    const regStr = getRegName(modrm.regField, opSize, s.hasRex)
    const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s)
    return { mnemonic: 'imul', operands: `${regStr}, ${modrm.rmOperand}, 0x${imm.toString(16)}` }
  }
  if (opcode === 0x6B) {
    const modrm = decodeModRM(s, opSize)
    const regStr = getRegName(modrm.regField, opSize, s.hasRex)
    const imm = readImm8Signed(s)
    return { mnemonic: 'imul', operands: `${regStr}, ${modrm.rmOperand}, 0x${(imm & 0xFF).toString(16)}` }
  }

  // ENTER/LEAVE (C8/C9)
  if (opcode === 0xC8) {
    const imm16 = readImm16(s)
    const imm8 = readImm8(s)
    return { mnemonic: 'enter', operands: `0x${imm16.toString(16)}, ${imm8}` }
  }

  // Fallback: emit as raw byte
  return { mnemonic: 'db', operands: `0x${opcode.toString(16)}` }
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Disassemble a range of bytes starting at the given address
 */
export function disassemble(
  data: Buffer | Uint8Array,
  baseAddress: number,
  is64: boolean = true,
  maxInstructions: number = 1000
): DisasmInstruction[] {
  const s = createState(data instanceof Buffer ? data : Buffer.from(data), baseAddress, is64)
  const instructions: DisasmInstruction[] = []

  while (s.pos < s.data.length && instructions.length < maxInstructions) {
    const startOffset = s.pos
    const address = baseAddress + startOffset

    try {
      const result = decodeOne(s)
      if (!result) break

      const size = s.pos - startOffset
      const bytes: number[] = []
      for (let i = startOffset; i < s.pos; i++) {
        bytes.push(s.data[i])
      }

      instructions.push({
        address,
        bytes,
        mnemonic: result.mnemonic,
        operands: result.operands,
        size,
        type: classifyInstruction(result.mnemonic)
      })
    } catch {
      // If decoding fails, emit single byte and continue
      instructions.push({
        address,
        bytes: [s.data[startOffset]],
        mnemonic: 'db',
        operands: `0x${s.data[startOffset].toString(16)}`,
        size: 1,
        type: InstructionType.Unknown
      })
      s.pos = startOffset + 1
    }
  }

  return instructions
}

/**
 * Disassemble a single instruction at the given position
 */
export function disassembleOne(
  data: Buffer | Uint8Array,
  offset: number,
  baseAddress: number,
  is64: boolean = true
): DisasmInstruction | null {
  const slice = data instanceof Buffer
    ? data.subarray(offset)
    : data.slice(offset)
  const result = disassemble(slice, baseAddress, is64, 1)
  return result.length > 0 ? result[0] : null
}
