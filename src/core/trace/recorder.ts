// ============================================================================
// Trace Recorder
// Records every step of VM execution for analysis and replay
// ============================================================================

import { TraceEntry, TraceFilter } from '../model/types'

export class TraceRecorder {
  private entries: TraceEntry[] = []
  private maxEntries: number = 500000
  private isRecording: boolean = true

  // ─── Recording ──────────────────────────────────────────────────────

  record(entry: TraceEntry): void {
    if (!this.isRecording) return

    if (this.entries.length >= this.maxEntries) {
      // Remove oldest 10% to make room
      this.entries.splice(0, Math.floor(this.maxEntries * 0.1))
    }

    this.entries.push(entry)
  }

  pause(): void { this.isRecording = false }
  resume(): void { this.isRecording = true }
  isPaused(): boolean { return !this.isRecording }

  // ─── Access ─────────────────────────────────────────────────────────

  getAll(): TraceEntry[] {
    return this.entries
  }

  getFiltered(filter: TraceFilter): TraceEntry[] {
    let result = this.entries

    if (filter.handlerIds && filter.handlerIds.length > 0) {
      const ids = new Set(filter.handlerIds)
      result = result.filter(e => e.handlerId && ids.has(e.handlerId))
    }

    if (filter.opcodeValues && filter.opcodeValues.length > 0) {
      const opcodes = new Set(filter.opcodeValues)
      result = result.filter(e => opcodes.has(e.opcodeValue))
    }

    if (filter.addressRange) {
      const { start, end } = filter.addressRange
      result = result.filter(e => e.address >= start && e.address <= end)
    }

    if (filter.onlyStackChanges) {
      result = result.filter(e => e.stackDelta !== 0)
    }

    if (filter.onlyControlFlow) {
      result = result.filter(e => {
        const label = (e.handlerLabel || '').toUpperCase()
        return ['JMP', 'JZ', 'JNZ', 'JE', 'JNE', 'CALL', 'RET', 'JB', 'JA', 'JL', 'JG',
                'JBE', 'JAE', 'JLE', 'JGE'].includes(label)
      })
    }

    return result
  }

  getEntry(index: number): TraceEntry | undefined {
    return this.entries[index]
  }

  getLastN(n: number): TraceEntry[] {
    return this.entries.slice(-n)
  }

  getCount(): number {
    return this.entries.length
  }

  // ─── Analysis ───────────────────────────────────────────────────────

  /**
   * Get handler execution frequency
   */
  getHandlerFrequency(): Map<string, number> {
    const freq = new Map<string, number>()
    for (const entry of this.entries) {
      const key = entry.handlerLabel || entry.handlerId || `OP_${entry.opcodeValue.toString(16)}`
      freq.set(key, (freq.get(key) || 0) + 1)
    }
    return freq
  }

  /**
   * Get opcode frequency
   */
  getOpcodeFrequency(): Map<number, number> {
    const freq = new Map<number, number>()
    for (const entry of this.entries) {
      freq.set(entry.opcodeValue, (freq.get(entry.opcodeValue) || 0) + 1)
    }
    return freq
  }

  /**
   * Find loops: sequences of addresses that repeat
   */
  findLoops(minIterations: number = 3): { addresses: number[]; count: number }[] {
    const loops: { addresses: number[]; count: number }[] = []

    // Simple loop detection: find repeating subsequences of addresses
    const addresses = this.entries.map(e => e.address)

    for (let windowSize = 2; windowSize <= 20; windowSize++) {
      for (let i = 0; i <= addresses.length - windowSize * minIterations; i++) {
        const pattern = addresses.slice(i, i + windowSize)
        let iterations = 1

        let j = i + windowSize
        while (j + windowSize <= addresses.length) {
          const next = addresses.slice(j, j + windowSize)
          if (pattern.every((v, k) => v === next[k])) {
            iterations++
            j += windowSize
          } else {
            break
          }
        }

        if (iterations >= minIterations) {
          // Check we haven't already found a superset of this loop
          const exists = loops.some(l =>
            l.addresses.length === pattern.length &&
            l.addresses.every((v, k) => v === pattern[k])
          )
          if (!exists) {
            loops.push({ addresses: pattern, count: iterations })
          }
          i = j - 1 // skip past this loop
        }
      }
    }

    return loops
  }

  /**
   * Find unique execution paths (sequences of distinct handler IDs)
   */
  getUniquePaths(maxLength: number = 10): string[][] {
    const paths: string[][] = []
    const seen = new Set<string>()

    for (let i = 0; i <= this.entries.length - maxLength; i++) {
      const path = this.entries.slice(i, i + maxLength)
        .map(e => e.handlerLabel || e.handlerId || `OP_${e.opcodeValue.toString(16)}`)
      const key = path.join(',')
      if (!seen.has(key)) {
        seen.add(key)
        paths.push(path)
      }
    }

    return paths
  }

  // ─── Export ─────────────────────────────────────────────────────────

  exportJSON(): string {
    return JSON.stringify(this.entries, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value, 2)
  }

  exportCSV(): string {
    const header = 'Index,Timestamp,Address,Opcode,Handler,Label,Mnemonic,StackDelta,RegsChanged,FlagsChanged\n'
    const rows = this.entries.map(e =>
      `${e.index},${e.timestamp},0x${e.address.toString(16)},0x${e.opcodeValue.toString(16)},` +
      `${e.handlerId || ''},${e.handlerLabel || ''},${e.mnemonic || ''},` +
      `${e.stackDelta},${e.registersChanged.join(';')},${e.flagsChanged.join(';')}`
    ).join('\n')
    return header + rows
  }

  exportText(): string {
    return this.entries.map(e => {
      const addr = `0x${e.address.toString(16).padStart(8, '0')}`
      const op = `0x${e.opcodeValue.toString(16).padStart(2, '0')}`
      const label = e.handlerLabel || e.handlerId || '???'
      const mnemonic = e.mnemonic || ''
      const changes = []
      if (e.stackDelta !== 0) changes.push(`stack:${e.stackDelta > 0 ? '+' : ''}${e.stackDelta}`)
      if (e.registersChanged.length) changes.push(`regs:[${e.registersChanged.join(',')}]`)
      if (e.flagsChanged.length) changes.push(`flags:[${e.flagsChanged.join(',')}]`)
      return `[${e.index.toString().padStart(6)}] ${addr}  ${op}  ${label.padEnd(12)} ${mnemonic.padEnd(8)} ${changes.join(' ')}`
    }).join('\n')
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────

  clear(): void {
    this.entries = []
  }

  setMaxEntries(max: number): void {
    this.maxEntries = max
  }

  serialize(): object[] {
    return this.entries
  }

  deserialize(data: object[]): void {
    this.entries = data as TraceEntry[]
  }
}
