// ============================================================================
// VM State Manager
// Manages the virtual machine's state: stack, registers, flags, memory
// ============================================================================

import { VMState, VMFlags, createDefaultVMState, createDefaultFlags } from '../model/types'

export class VMStateManager {
  private state: VMState
  private snapshots: VMState[] = []
  private maxSnapshots = 10000

  constructor() {
    this.state = createDefaultVMState()
  }

  // ─── State Access ───────────────────────────────────────────────────

  getState(): VMState {
    return this.cloneState(this.state)
  }

  setState(state: VMState): void {
    this.state = this.cloneState(state)
  }

  reset(): void {
    this.state = createDefaultVMState()
    this.snapshots = []
  }

  // ─── VIP (Virtual Instruction Pointer) ──────────────────────────────

  getVIP(): number { return this.state.vip }
  setVIP(addr: number): void { this.state.vip = addr }
  advanceVIP(delta: number): void { this.state.vip += delta }

  // ─── VSP (Virtual Stack Pointer) ────────────────────────────────────

  getVSP(): number { return this.state.vsp }
  setVSP(addr: number): void { this.state.vsp = addr }

  // ─── Stack Operations ───────────────────────────────────────────────

  push(value: bigint): void {
    this.state.stack.unshift(value)
    this.state.vsp += 8
  }

  pop(): bigint {
    if (this.state.stack.length === 0) {
      this.state.error = 'Stack underflow'
      return 0n
    }
    this.state.vsp -= 8
    return this.state.stack.shift()!
  }

  peek(depth: number = 0): bigint {
    if (depth >= this.state.stack.length) return 0n
    return this.state.stack[depth]
  }

  getStackDepth(): number {
    return this.state.stack.length
  }

  getStack(): bigint[] {
    return [...this.state.stack]
  }

  // ─── Register Operations ────────────────────────────────────────────

  getReg(name: string): bigint {
    return this.state.registers[name] ?? 0n
  }

  setReg(name: string, value: bigint): void {
    this.state.registers[name] = value
  }

  getRegisters(): Record<string, bigint> {
    return { ...this.state.registers }
  }

  initRegisters(names: string[]): void {
    for (const name of names) {
      if (!(name in this.state.registers)) {
        this.state.registers[name] = 0n
      }
    }
  }

  // ─── Flag Operations ────────────────────────────────────────────────

  getFlags(): VMFlags {
    return { ...this.state.flags }
  }

  setFlags(flags: Partial<VMFlags>): void {
    Object.assign(this.state.flags, flags)
  }

  getFlag(name: keyof VMFlags): boolean {
    return this.state.flags[name]
  }

  setFlag(name: keyof VMFlags, value: boolean): void {
    this.state.flags[name] = value
  }

  /**
   * Update arithmetic flags based on a result value
   */
  updateArithFlags(result: bigint, operandSize: number = 64): void {
    const mask = operandSize === 64 ? 0xFFFFFFFFFFFFFFFFn
      : operandSize === 32 ? 0xFFFFFFFFn
      : operandSize === 16 ? 0xFFFFn
      : 0xFFn
    const signBit = operandSize === 64 ? 0x8000000000000000n
      : operandSize === 32 ? 0x80000000n
      : operandSize === 16 ? 0x8000n
      : 0x80n

    const masked = result & mask
    this.state.flags.ZF = masked === 0n
    this.state.flags.SF = (masked & signBit) !== 0n

    // Parity flag (based on lowest byte)
    let parity = Number(masked & 0xFFn)
    parity ^= parity >> 4
    parity ^= parity >> 2
    parity ^= parity >> 1
    this.state.flags.PF = (parity & 1) === 0
  }

  // ─── Virtual Memory ─────────────────────────────────────────────────

  readMemory(address: number): number {
    return this.state.memory.get(address) ?? 0
  }

  writeMemory(address: number, value: number): void {
    this.state.memory.set(address, value & 0xFF)
  }

  readMemory32(address: number): number {
    let value = 0
    for (let i = 0; i < 4; i++) {
      value |= this.readMemory(address + i) << (i * 8)
    }
    return value >>> 0
  }

  writeMemory32(address: number, value: number): void {
    for (let i = 0; i < 4; i++) {
      this.writeMemory(address + i, (value >> (i * 8)) & 0xFF)
    }
  }

  readMemory64(address: number): bigint {
    let value = 0n
    for (let i = 0; i < 8; i++) {
      value |= BigInt(this.readMemory(address + i)) << BigInt(i * 8)
    }
    return value
  }

  writeMemory64(address: number, value: bigint): void {
    for (let i = 0; i < 8; i++) {
      this.writeMemory(address + i, Number((value >> BigInt(i * 8)) & 0xFFn))
    }
  }

  // ─── Halt ───────────────────────────────────────────────────────────

  halt(error?: string): void {
    this.state.halted = true
    if (error) this.state.error = error
  }

  isHalted(): boolean { return this.state.halted }
  getError(): string | undefined { return this.state.error }

  // ─── Snapshots ──────────────────────────────────────────────────────

  saveSnapshot(): void {
    if (this.snapshots.length >= this.maxSnapshots) {
      this.snapshots.shift()
    }
    this.snapshots.push(this.cloneState(this.state))
  }

  restoreSnapshot(): boolean {
    const snapshot = this.snapshots.pop()
    if (!snapshot) return false
    this.state = snapshot
    return true
  }

  getSnapshotCount(): number {
    return this.snapshots.length
  }

  // ─── Diff ───────────────────────────────────────────────────────────

  /**
   * Compare two states and return which registers/flags changed
   */
  static diff(before: VMState, after: VMState): {
    registersChanged: string[]
    flagsChanged: string[]
    stackDelta: number
  } {
    const registersChanged: string[] = []
    const allKeys = new Set([...Object.keys(before.registers), ...Object.keys(after.registers)])
    for (const key of allKeys) {
      if ((before.registers[key] ?? 0n) !== (after.registers[key] ?? 0n)) {
        registersChanged.push(key)
      }
    }

    const flagsChanged: string[] = []
    for (const key of ['ZF', 'CF', 'SF', 'OF', 'PF', 'AF'] as (keyof VMFlags)[]) {
      if (before.flags[key] !== after.flags[key]) {
        flagsChanged.push(key)
      }
    }

    return {
      registersChanged,
      flagsChanged,
      stackDelta: after.stack.length - before.stack.length
    }
  }

  // ─── Serialization ─────────────────────────────────────────────────

  serialize(): object {
    return {
      vip: this.state.vip,
      vsp: this.state.vsp,
      stack: this.state.stack.map(v => v.toString()),
      registers: Object.fromEntries(
        Object.entries(this.state.registers).map(([k, v]) => [k, v.toString()])
      ),
      flags: { ...this.state.flags },
      memory: Object.fromEntries(this.state.memory),
      halted: this.state.halted,
      error: this.state.error
    }
  }

  deserialize(obj: any): void {
    this.state = {
      vip: obj.vip ?? 0,
      vsp: obj.vsp ?? 0,
      stack: (obj.stack ?? []).map((v: string) => BigInt(v)),
      registers: Object.fromEntries(
        Object.entries(obj.registers ?? {}).map(([k, v]) => [k, BigInt(v as string)])
      ),
      flags: obj.flags ?? createDefaultFlags(),
      memory: new Map(Object.entries(obj.memory ?? {}).map(([k, v]) => [Number(k), v as number])),
      halted: obj.halted ?? false,
      error: obj.error
    }
  }

  // ─── Internal ───────────────────────────────────────────────────────

  private cloneState(state: VMState): VMState {
    return {
      vip: state.vip,
      vsp: state.vsp,
      stack: [...state.stack],
      registers: { ...state.registers },
      flags: { ...state.flags },
      memory: new Map(state.memory),
      halted: state.halted,
      error: state.error
    }
  }
}
