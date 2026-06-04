// ============================================================================
// Bytecode Pattern Analyzer
// Automatically detect dispatcher patterns, switch-case structures,
// indirect jumps, and handler tables from raw bytecode.
// ============================================================================

export interface DispatcherPattern {
  type: 'switch_case' | 'table_lookup' | 'indirect_jump' | 'binary_search'
  confidence: number // 0-1, higher = more confident
  opcodeTableAddress?: number // Where opcode -> handler mappings live
  jumpTableSize?: number // Number of handlers detected
  dispatcherAddress: number // Where dispatcher starts
  pattern: string // Description of pattern
}

export interface OpcodeCandidate {
  value: number
  frequency: number // How often appears in bytecode
  likely: boolean // Statistically likely to be opcode
}

export class BytecodeAnalyzer {
  private bytecode: Buffer
  private baseAddress: number

  constructor(bytecode: Buffer, baseAddress: number = 0) {
    this.bytecode = bytecode
    this.baseAddress = baseAddress
  }

  /**
   * Analyze bytecode to detect dispatcher patterns
   */
  analyzeDispatcher(): DispatcherPattern | null {
    // Strategy: Look for common VM dispatcher patterns.

    // 1. Prefer direct jump table detection when present.
    const tables = this.findJumpTables()
    if (tables.length > 0) {
      const table = tables[0]
      return {
        type: 'table_lookup',
        confidence: Math.min(table.tableSize / 20, 1),
        dispatcherAddress: table.address,
        jumpTableSize: table.tableSize,
        opcodeTableAddress: table.address,
        pattern: `Detected jump table at 0x${table.address.toString(16).toUpperCase()} (${table.tableSize} entries)`
      }
    }

    // 2. Try to find switch-case pattern.
    const switchPattern = this.detectSwitchCasePattern()
    if (switchPattern && switchPattern.confidence > 0.6) {
      return switchPattern
    }

    // 3. Try to find table lookup pattern from indirect structures.
    const tablePattern = this.detectTableLookupPattern()
    if (tablePattern && tablePattern.confidence > 0.6) {
      return tablePattern
    }

    // 4. Try to find indirect jump pattern.
    const indirectPattern = this.detectIndirectJumpPattern()
    if (indirectPattern && indirectPattern.confidence > 0.6) {
      return indirectPattern
    }

    // Return best guess or null.
    return switchPattern || tablePattern || indirectPattern
  }

  /**
   * Detect switch-case pattern: sequence of CMP+JZ or similar
   * Example: cmp eax, 1; jz handler1; cmp eax, 2; jz handler2; ...
   */
  private detectSwitchCasePattern(): DispatcherPattern | null {
    // Look for repeated patterns like:
    // byte_sequence_1 followed by branch (3 byte CMP + 2 byte JZ = 5 bytes minimum)
    // repeated N times consecutively
    
    const minPatternSize = 5
    let maxCandidates = 0
    let bestAddress = -1

    // Scan for regions with repeated branch-like patterns
    for (let i = 0; i < this.bytecode.length - minPatternSize * 4; i++) {
      let candidateCount = 0
      let j = i

      // Count consecutive potential switch cases
      while (j < this.bytecode.length - minPatternSize) {
        const nextBytes = this.bytecode.subarray(j, j + minPatternSize)
        
        // Simple heuristic: look for common branching byte patterns
        // (This is simplified; real pattern detection is more complex)
        if (this.looksLikeBranch(nextBytes)) {
          candidateCount++
          j += minPatternSize
        } else {
          break
        }
      }

      if (candidateCount > maxCandidates) {
        maxCandidates = candidateCount
        bestAddress = i
      }
    }

    if (maxCandidates >= 3) {
      return {
        type: 'switch_case',
        confidence: Math.min(maxCandidates / 10, 1),
        dispatcherAddress: this.baseAddress + bestAddress,
        jumpTableSize: maxCandidates,
        pattern: `${maxCandidates} consecutive branch patterns detected`
      }
    }

    return null
  }

  /**
   * Detect table lookup pattern: array of addresses used as jump targets
   * Common in Themida, VMProtect-like VMs
   */
  private detectTableLookupPattern(): DispatcherPattern | null {
    // Look for sequences of address-like values (pointers or relative offsets)
    // that form a contiguous table
    
    // In a 4-byte pointer architecture, look for aligned sequences
    const alignment = 4
    let longestTableStart = -1
    let longestTableLength = 0

    for (let i = 0; i <= this.bytecode.length - alignment * 4; i += alignment) {
      let tableLength = 0
      let j = i

      // Check if consecutive 4-byte values look like addresses
      while (j <= this.bytecode.length - alignment) {
        const value = this.bytecode.readUInt32LE(j)
        
        // Check if value is a plausible address (roughly in range)
        // For relocated code, this is fuzzy, but we check if in reasonable range
        if (this.isPlausibleAddress(value)) {
          tableLength++
          j += alignment
        } else {
          break
        }
      }

      if (tableLength > longestTableLength) {
        longestTableLength = tableLength
        longestTableStart = i
      }
    }

    if (longestTableLength >= 5) {
      return {
        type: 'table_lookup',
        confidence: Math.min(longestTableLength / 20, 1),
        dispatcherAddress: this.baseAddress + longestTableStart,
        jumpTableSize: longestTableLength,
        opcodeTableAddress: this.baseAddress + longestTableStart,
        pattern: `Address table with ${longestTableLength} entries detected`
      }
    }

    return null
  }

  /**
   * Detect indirect jump pattern: mov reg, [opcode]; jmp [table + reg*scale]
   */
  private detectIndirectJumpPattern(): DispatcherPattern | null {
    // Look for byte sequences that match indirect jump patterns
    // This is x86-specific; for a custom VM, it's different
    // For now, return null as we're focusing on bytecode VM patterns
    return null
  }

  /**
   * Identify likely opcodes from bytecode frequency analysis
   * Opcodes tend to appear more frequently and uniformly than random data
   */
  identifyLikelyOpcodes(sampleSize: number = this.bytecode.length): OpcodeCandidate[] {
    const frequency: Record<number, number> = {}
    const limit = Math.min(sampleSize, this.bytecode.length)

    // Count byte frequencies across the sample window.
    for (let i = 0; i < limit; i++) {
      const byte = this.bytecode[i]
      frequency[byte] = (frequency[byte] || 0) + 1
    }

    // Convert to candidates and mark likely opcodes using distribution heuristics.
    const candidates: OpcodeCandidate[] = Object.entries(frequency).map(([value, freq]) => {
      const numericValue = parseInt(value)
      const frequencyRatio = freq / this.bytecode.length
      return {
        value: numericValue,
        frequency: freq,
        likely: freq >= 2 && frequencyRatio >= 0.005
      }
    })

    // Sort by frequency descending and return.
    candidates.sort((a, b) => b.frequency - a.frequency)

    return candidates
  }

  /**
   * Get positions where a candidate opcode appears in the bytecode.
   */
  getOpcodePositions(opcodeValue: number): number[] {
    const positions: number[] = []
    for (let i = 0; i < this.bytecode.length; i++) {
      if (this.bytecode[i] === opcodeValue) {
        positions.push(this.baseAddress + i)
      }
    }
    return positions
  }

  /**
   * Extract opcode context for a position in the bytecode.
   */
  getOpcodeContext(position: number, windowSize: number = 4): {
    precedingOpcodes: number[]
    followingOpcodes: number[]
    bytecodeWindow: Buffer
    position: number
  } {
    const relativePos = position - this.baseAddress
    const start = Math.max(0, relativePos - windowSize)
    const end = Math.min(this.bytecode.length, relativePos + windowSize + 1)
    const window = this.bytecode.subarray(start, end)
    const preceding = Array.from(this.bytecode.subarray(start, relativePos))
    const following = Array.from(this.bytecode.subarray(relativePos + 1, end))

    return {
      precedingOpcodes: preceding,
      followingOpcodes: following,
      bytecodeWindow: Buffer.from(window),
      position: relativePos - start
    }
  }

  /**
   * Analyze bytecode statistics for indicators of VM structure
   */
  getStatistics(): {
    totalSize: number
    uniqueBytes: number
    byteDistribution: Record<number, number>
    entropy: number
  } {
    const freq: Record<number, number> = {}
    let totalSize = this.bytecode.length
    let entropy = 0

    // Calculate frequency distribution
    for (let i = 0; i < this.bytecode.length; i++) {
      const byte = this.bytecode[i]
      freq[byte] = (freq[byte] || 0) + 1
    }

    // Calculate Shannon entropy
    const uniqueBytes = Object.keys(freq).length
    for (const count of Object.values(freq)) {
      const probability = count / totalSize
      entropy -= probability * Math.log2(probability)
    }

    return {
      totalSize,
      uniqueBytes,
      byteDistribution: freq,
      entropy // 0 = highly ordered, 8 = random
    }
  }

  // ─── Helper Methods ─────────────────────────────────────────────────

  private looksLikeBranch(bytes: Buffer): boolean {
    // Simplified heuristic: certain byte patterns suggest branches
    // In real x86: 0x74 (JZ), 0x75 (JNZ), 0xEB (JMP), etc.
    // For a custom VM bytecode, we'd need VM-specific patterns
    
    // For now, check if bytes have properties of control flow:
    // - Low variance (same byte repeated suggests valid instruction)
    // - Contains branching-related bytes
    
    const first = bytes[0]
    const count = bytes.filter(b => b === first).length
    return count >= 2 // Simple: same byte repeated suggests structure
  }

  private isPlausibleAddress(value: number): boolean {
    // Check if 32-bit value looks like a plausible address
    // Typically: 0x00400000 - 0x7FFFFFFF for user space on 32-bit
    // On 64-bit: much larger ranges
    // This is heuristic; exact checks depend on target architecture
    
    // For now, allow values in typical code section ranges
    return (value >= 0x00400000 && value <= 0x10000000) ||  // Typical PE range
           (value >= 0x400000 && value <= 0x7FFFFFFF)        // ELF range
  }

  /**
   * Find all potential jump table entries (contiguous address sequences)
   */
  findJumpTables(): { address: number; size: number; tableSize: number }[] {
    const tables: { address: number; size: number; tableSize: number }[] = []
    const alignment = 4

    for (let i = 0; i <= this.bytecode.length - alignment * 4; i += alignment) {
      let tableLength = 0
      let j = i

      while (j <= this.bytecode.length - alignment) {
        const value = this.bytecode.readUInt32LE(j)
        if (this.isPlausibleAddress(value)) {
          tableLength++
          j += alignment
        } else {
          break
        }
      }

      if (tableLength >= 5) {
        tables.push({
          address: this.baseAddress + i,
          size: tableLength * alignment,
          tableSize: tableLength
        })

        // Skip this table to avoid overlaps
        i = j - alignment
      }
    }

    return tables
  }
}
