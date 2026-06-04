// ============================================================================
// VM Execution Engine
// Emulates custom VM execution: fetches opcodes, dispatches to handlers,
// tracks state changes, records trace
// ============================================================================

import { VMStateManager } from './vm-state'
import {
  VMHandler, VMState, TraceEntry, DispatcherInfo, OpcodeMapping, VMFlags
} from '../model/types'
import { TraceRecorder } from '../trace/recorder'

export interface VMEngineConfig {
  /** Max steps before auto-halt (safety) */
  maxSteps: number
  /** Size of each opcode in bytes (1, 2, or 4) */
  opcodeSize: number
  /** Register names for the virtual VM */
  registerNames: string[]
  /** Initial VIP (Virtual Instruction Pointer) */
  initialVIP: number
}

const DEFAULT_CONFIG: VMEngineConfig = {
  maxSteps: 100000,
  opcodeSize: 1,
  registerNames: ['v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7'],
  initialVIP: 0
}

export class VMEngine {
  private stateManager: VMStateManager
  private traceRecorder: TraceRecorder
  private config: VMEngineConfig
  private handlers: Map<number, VMHandler> = new Map() // opcodeValue → handler
  private opcodeMap: OpcodeMapping[] = []
  private dispatcher: DispatcherInfo | null = null
  private bytecode: Buffer | null = null
  private bytecodeBase: number = 0
  private running = false
  private stepCount = 0
  private breakpoints: Set<number> = new Set()
  private handlerExecutors: Map<string, (engine: VMEngine) => void> = new Map()

  constructor(config?: Partial<VMEngineConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.stateManager = new VMStateManager()
    this.traceRecorder = new TraceRecorder()
  }

  // ─── Setup ──────────────────────────────────────────────────────────

  /**
   * Set the bytecode to execute
   */
  setBytecode(data: Buffer, baseAddress: number): void {
    this.bytecode = data
    this.bytecodeBase = baseAddress
    this.stateManager.setVIP(this.config.initialVIP)
    this.stateManager.initRegisters(this.config.registerNames)
  }

  /**
   * Set the dispatcher info
   */
  setDispatcher(dispatcher: DispatcherInfo): void {
    this.dispatcher = dispatcher
  }

  /**
   * Register a handler
   */
  registerHandler(handler: VMHandler): void {
    this.handlers.set(handler.opcodeValue, handler)
  }

  /**
   * Set all handlers at once
   */
  setHandlers(handlers: VMHandler[]): void {
    this.handlers.clear()
    for (const h of handlers) {
      this.handlers.set(h.opcodeValue, h)
    }
  }

  /**
   * Register a custom executor for a labeled handler
   */
  registerExecutor(label: string, executor: (engine: VMEngine) => void): void {
    this.handlerExecutors.set(label, executor)
  }

  /**
   * Add a breakpoint at a VIP address
   */
  addBreakpoint(vip: number): void {
    this.breakpoints.add(vip)
  }

  removeBreakpoint(vip: number): void {
    this.breakpoints.delete(vip)
  }

  // ─── Execution ──────────────────────────────────────────────────────

  /**
   * Execute a single step
   */
  step(): { state: VMState; traceEntry: TraceEntry | null } {
    if (!this.bytecode) {
      this.stateManager.halt('No bytecode loaded')
      return { state: this.stateManager.getState(), traceEntry: null }
    }

    if (this.stateManager.isHalted()) {
      return { state: this.stateManager.getState(), traceEntry: null }
    }

    const vip = this.stateManager.getVIP()
    const relativeVip = vip - this.bytecodeBase

    // Check bounds
    if (relativeVip < 0 || relativeVip + this.config.opcodeSize > this.bytecode.length) {
      this.stateManager.halt(`VIP out of bounds: 0x${vip.toString(16)}`)
      return { state: this.stateManager.getState(), traceEntry: null }
    }

    // Fetch opcode
    let opcodeValue = 0
    for (let i = 0; i < this.config.opcodeSize; i++) {
      opcodeValue |= this.bytecode[relativeVip + i] << (i * 8)
    }

    // Save state before execution
    const stateBefore = this.stateManager.getState()

    // Find and execute handler
    const handler = this.handlers.get(opcodeValue)
    if (handler) {
      handler.executionCount++

      // Check if we have a custom executor for this handler's label
      if (handler.label && this.handlerExecutors.has(handler.label)) {
        this.handlerExecutors.get(handler.label)!(this)
      } else {
        // Default: just advance VIP
        this.executeDefaultHandler(handler, opcodeValue)
      }
    } else {
      // Unknown opcode - advance VIP and log
      this.stateManager.advanceVIP(this.config.opcodeSize)
    }

    const stateAfter = this.stateManager.getState()

    // Record trace entry
    const diff = VMStateManager.diff(stateBefore, stateAfter)
    const traceEntry: TraceEntry = {
      index: this.stepCount++,
      timestamp: Date.now(),
      address: vip,
      opcodeValue,
      handlerId: handler?.id,
      handlerLabel: handler?.label,
      mnemonic: handler?.label ?? `OP_${opcodeValue.toString(16).toUpperCase()}`,
      operands: '',
      stackDelta: diff.stackDelta,
      registersChanged: diff.registersChanged,
      flagsChanged: diff.flagsChanged
    }

    this.traceRecorder.record(traceEntry)

    return { state: stateAfter, traceEntry }
  }

  /**
   * Default handler execution — read operands based on opcode size, advance VIP
   */
  private executeDefaultHandler(handler: VMHandler, opcodeValue: number): void {
    // By default, just advance VIP past the opcode
    this.stateManager.advanceVIP(this.config.opcodeSize)
  }

  /**
   * Run until halted, breakpoint, or max steps
   */
  run(): { state: VMState; stepsExecuted: number; reason: string } {
    this.running = true
    let stepsExecuted = 0

    while (this.running && !this.stateManager.isHalted() && stepsExecuted < this.config.maxSteps) {
      const vip = this.stateManager.getVIP()

      // Check breakpoints (after first step)
      if (stepsExecuted > 0 && this.breakpoints.has(vip)) {
        this.running = false
        return { state: this.stateManager.getState(), stepsExecuted, reason: 'breakpoint' }
      }

      this.step()
      stepsExecuted++
    }

    this.running = false

    let reason = 'completed'
    if (this.stateManager.isHalted()) reason = this.stateManager.getError() || 'halted'
    else if (stepsExecuted >= this.config.maxSteps) reason = 'max_steps_reached'

    return { state: this.stateManager.getState(), stepsExecuted, reason }
  }

  /**
   * Run until a specific handler is executed
   */
  runUntilHandler(handlerId: string): { state: VMState; stepsExecuted: number; reason: string } {
    this.running = true
    let stepsExecuted = 0

    while (this.running && !this.stateManager.isHalted() && stepsExecuted < this.config.maxSteps) {
      const result = this.step()
      stepsExecuted++

      if (result.traceEntry?.handlerId === handlerId) {
        this.running = false
        return { state: this.stateManager.getState(), stepsExecuted, reason: 'handler_reached' }
      }
    }

    this.running = false
    return { state: this.stateManager.getState(), stepsExecuted, reason: 'not_found' }
  }

  /**
   * Run until VIP reaches a specific address
   */
  runUntilAddress(address: number): { state: VMState; stepsExecuted: number; reason: string } {
    this.running = true
    let stepsExecuted = 0

    while (this.running && !this.stateManager.isHalted() && stepsExecuted < this.config.maxSteps) {
      this.step()
      stepsExecuted++

      if (this.stateManager.getVIP() === address) {
        this.running = false
        return { state: this.stateManager.getState(), stepsExecuted, reason: 'address_reached' }
      }
    }

    this.running = false
    return { state: this.stateManager.getState(), stepsExecuted, reason: 'not_reached' }
  }

  /**
   * Stop execution
   */
  stop(): void {
    this.running = false
  }

  /**
   * Reset the engine
   */
  reset(): void {
    this.running = false
    this.stepCount = 0
    this.stateManager.reset()
    this.stateManager.setVIP(this.config.initialVIP)
    this.stateManager.initRegisters(this.config.registerNames)
    this.traceRecorder.clear()
    for (const handler of this.handlers.values()) {
      handler.executionCount = 0
    }
  }

  // ─── Accessors ──────────────────────────────────────────────────────

  getStateManager(): VMStateManager { return this.stateManager }
  getTraceRecorder(): TraceRecorder { return this.traceRecorder }
  getHandlers(): VMHandler[] { return Array.from(this.handlers.values()) }
  getHandler(opcodeValue: number): VMHandler | undefined { return this.handlers.get(opcodeValue) }
  getHandlerById(id: string): VMHandler | undefined {
    for (const h of this.handlers.values()) {
      if (h.id === id) return h
    }
    return undefined
  }
  getDispatcher(): DispatcherInfo | null { return this.dispatcher }
  isRunning(): boolean { return this.running }
  getStepCount(): number { return this.stepCount }
  getConfig(): VMEngineConfig { return { ...this.config } }
  getBytecode(): Buffer | null { return this.bytecode }
  getBytecodeBase(): number { return this.bytecodeBase }

  /**
   * Expose state manager methods for handler executors
   */
  push(value: bigint): void { this.stateManager.push(value) }
  pop(): bigint { return this.stateManager.pop() }
  getReg(name: string): bigint { return this.stateManager.getReg(name) }
  setReg(name: string, value: bigint): void { this.stateManager.setReg(name, value) }
  getVIP(): number { return this.stateManager.getVIP() }
  setVIP(addr: number): void { this.stateManager.setVIP(addr) }
  advanceVIP(delta: number): void { this.stateManager.advanceVIP(delta) }
  getFlags(): VMFlags { return this.stateManager.getFlags() }
  setFlags(flags: Partial<VMFlags>): void { this.stateManager.setFlags(flags) }

  /**
   * Read a value from bytecode at the current VIP + offset
   */
  readBytecodeU8(offset: number = 0): number {
    if (!this.bytecode) return 0
    const pos = this.stateManager.getVIP() - this.bytecodeBase + offset
    if (pos < 0 || pos >= this.bytecode.length) return 0
    return this.bytecode[pos]
  }

  readBytecodeU16(offset: number = 0): number {
    return this.readBytecodeU8(offset) | (this.readBytecodeU8(offset + 1) << 8)
  }

  readBytecodeU32(offset: number = 0): number {
    return (this.readBytecodeU8(offset)
      | (this.readBytecodeU8(offset + 1) << 8)
      | (this.readBytecodeU8(offset + 2) << 16)
      | (this.readBytecodeU8(offset + 3) << 24)) >>> 0
  }

  /**
   * Register built-in handler executors for common VM operations
   */
  registerBuiltinExecutors(): void {
    // PUSH immediate
    this.registerExecutor('PUSH', (e) => {
      const imm = BigInt(e.readBytecodeU32(e.getConfig().opcodeSize))
      e.push(imm)
      e.advanceVIP(e.getConfig().opcodeSize + 4)
    })

    // POP (discard top)
    this.registerExecutor('POP', (e) => {
      e.pop()
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // ADD
    this.registerExecutor('ADD', (e) => {
      const b = e.pop()
      const a = e.pop()
      const result = a + b
      e.push(result)
      e.getStateManager().updateArithFlags(result)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // SUB
    this.registerExecutor('SUB', (e) => {
      const b = e.pop()
      const a = e.pop()
      const result = a - b
      e.push(result)
      e.getStateManager().updateArithFlags(result)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // MUL
    this.registerExecutor('MUL', (e) => {
      const b = e.pop()
      const a = e.pop()
      e.push(a * b)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // XOR
    this.registerExecutor('XOR', (e) => {
      const b = e.pop()
      const a = e.pop()
      const result = a ^ b
      e.push(result)
      e.getStateManager().updateArithFlags(result)
      e.setFlags({ CF: false, OF: false })
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // AND
    this.registerExecutor('AND', (e) => {
      const b = e.pop()
      const a = e.pop()
      const result = a & b
      e.push(result)
      e.getStateManager().updateArithFlags(result)
      e.setFlags({ CF: false, OF: false })
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // OR
    this.registerExecutor('OR', (e) => {
      const b = e.pop()
      const a = e.pop()
      const result = a | b
      e.push(result)
      e.getStateManager().updateArithFlags(result)
      e.setFlags({ CF: false, OF: false })
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // NOT
    this.registerExecutor('NOT', (e) => {
      const a = e.pop()
      e.push(~a)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // NEG
    this.registerExecutor('NEG', (e) => {
      const a = e.pop()
      e.push(-a)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // SHL
    this.registerExecutor('SHL', (e) => {
      const shift = e.pop()
      const val = e.pop()
      e.push(val << shift)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // SHR
    this.registerExecutor('SHR', (e) => {
      const shift = e.pop()
      const val = e.pop()
      // Logical right shift via BigInt
      if (val >= 0n) {
        e.push(val >> shift)
      } else {
        e.push(val >> shift) // Note: BigInt >> is arithmetic
      }
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // CMP_EQ (compare equal and push boolean)
    this.registerExecutor('CMP', (e) => {
      const b = e.pop()
      const a = e.pop()
      e.push(a === b ? 1n : 0n)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // CMP_NE
    this.registerExecutor('CMP_NE', (e) => {
      const b = e.pop()
      const a = e.pop()
      e.push(a !== b ? 1n : 0n)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // CMP_LT
    this.registerExecutor('CMP_LT', (e) => {
      const b = e.pop()
      const a = e.pop()
      e.push(a < b ? 1n : 0n)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // CMP_LE
    this.registerExecutor('CMP_LE', (e) => {
      const b = e.pop()
      const a = e.pop()
      e.push(a <= b ? 1n : 0n)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // CMP_GT
    this.registerExecutor('CMP_GT', (e) => {
      const b = e.pop()
      const a = e.pop()
      e.push(a > b ? 1n : 0n)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // CMP_GE
    this.registerExecutor('CMP_GE', (e) => {
      const b = e.pop()
      const a = e.pop()
      e.push(a >= b ? 1n : 0n)
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // JMP (unconditional relative jump)
    this.registerExecutor('JMP', (e) => {
      const displacement = e.readBytecodeU32(e.getConfig().opcodeSize) | 0
      const nextVip = e.getVIP() + e.getConfig().opcodeSize + 4
      e.setVIP(nextVip + displacement)
    })

    // JZ (jump if zero)
    this.registerExecutor('JZ', (e) => {
      const displacement = e.readBytecodeU32(e.getConfig().opcodeSize) | 0
      const top = e.getStateManager().peek()
      const nextVip = e.getVIP() + e.getConfig().opcodeSize + 4
      if (top === 0n) {
        e.setVIP(nextVip + displacement)
      } else {
        e.advanceVIP(e.getConfig().opcodeSize + 4)
      }
    })

    // JNZ (jump if not zero)
    this.registerExecutor('JNZ', (e) => {
      const displacement = e.readBytecodeU32(e.getConfig().opcodeSize) | 0
      const top = e.getStateManager().peek()
      const nextVip = e.getVIP() + e.getConfig().opcodeSize + 4
      if (top !== 0n) {
        e.setVIP(nextVip + displacement)
      } else {
        e.advanceVIP(e.getConfig().opcodeSize + 4)
      }
    })

    // LOAD register (push register value onto stack)
    this.registerExecutor('LOAD', (e) => {
      const regIdx = e.readBytecodeU8(e.getConfig().opcodeSize)
      const regName = `v${regIdx}`
      e.push(e.getReg(regName))
      e.advanceVIP(e.getConfig().opcodeSize + 1)
    })

    // STORE register (pop stack into register)
    this.registerExecutor('STORE', (e) => {
      const regIdx = e.readBytecodeU8(e.getConfig().opcodeSize)
      const regName = `v${regIdx}`
      e.setReg(regName, e.pop())
      e.advanceVIP(e.getConfig().opcodeSize + 1)
    })

    // NOP
    this.registerExecutor('NOP', (e) => {
      e.advanceVIP(e.getConfig().opcodeSize)
    })

    // HALT
    this.registerExecutor('HALT', (e) => {
      e.getStateManager().halt('VM halted by HALT instruction')
    })

    // RET (pop return address and jump)
    this.registerExecutor('RET', (e) => {
      const retAddr = Number(e.pop())
      e.setVIP(retAddr)
    })

    // CALL (push return address, relative jump)
    this.registerExecutor('CALL', (e) => {
      const displacement = e.readBytecodeU32(e.getConfig().opcodeSize) | 0
      const nextVip = e.getVIP() + e.getConfig().opcodeSize + 4
      const retAddr = nextVip
      e.push(BigInt(retAddr))
      e.setVIP(nextVip + displacement)
    })
  }

  // ─── Additional Public Methods for RealtimeExecutor ──────────────────

  /**
   * Get breakpoints set
   */
  getBreakpoints(): Set<number> {
    return this.breakpoints
  }

  /**
   * Read 8-bit value from bytecode at offset
   */
  readBytecodeU8(offset: number): number {
    if (!this.bytecode) return 0
    const relativeVip = this.stateManager.getVIP() - this.bytecodeBase + offset
    if (relativeVip < 0 || relativeVip >= this.bytecode.length) return 0
    return this.bytecode[relativeVip]
  }

  /**
   * Read 32-bit value from bytecode at offset
   */
  readBytecodeU32(offset: number): number {
    if (!this.bytecode) return 0
    const relativeVip = this.stateManager.getVIP() - this.bytecodeBase + offset
    if (relativeVip + 4 > this.bytecode.length) return 0
    return this.bytecode.readUInt32LE(relativeVip)
  }

  /**
   * Set flag values
   */
  setFlags(flags: Partial<VMFlags>): void {
    this.stateManager.setFlags(flags)
  }

  /**
   * Get current flags
   */
  getFlags(): VMFlags {
    return this.stateManager.getFlags()
  }

  /**
   * Set VIP directly
   */
  setVIP(address: number): void {
    this.stateManager.setVIP(address)
  }

  /**
   * Get current VIP
   */
  getVIP(): number {
    return this.stateManager.getVIP()
  }

  /**
   * Get register value
   */
  getReg(name: string): bigint {
    return this.stateManager.getReg(name)
  }

  /**
   * Set register value
   */
  setReg(name: string, value: bigint): void {
    this.stateManager.setReg(name, value)
  }

  /**
   * Advance VIP by offset
   */
  advanceVIP(offset: number): void {
    this.stateManager.advanceVIP(offset)
  }
}

