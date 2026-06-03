// ============================================================================
// ELF (Executable and Linkable Format) Parser
// Parses Linux ELF32/ELF64 binaries: headers, sections, symbols
// ============================================================================

import {
  BinaryInfo, SectionInfo, ImportInfo, ImportFunction, ExportInfo
} from '../model/types'
import { t } from '../i18n'

// ─── Constants ──────────────────────────────────────────────────────────────

const ELF_MAGIC = [0x7F, 0x45, 0x4C, 0x46] // '\x7FELF'

// ELF class
const ELFCLASS32 = 1
const ELFCLASS64 = 2

// ELF data encoding
const ELFDATA2LSB = 1 // Little-endian
const ELFDATA2MSB = 2 // Big-endian

// Section header types
const SHT_SYMTAB = 2
const SHT_STRTAB = 3
const SHT_DYNSYM = 11

// Section header flags
const SHF_WRITE = 0x1
const SHF_ALLOC = 0x2
const SHF_EXECINSTR = 0x4

// ELF machine types
const EM_386 = 3
const EM_X86_64 = 62

// ─── ELF Parser ─────────────────────────────────────────────────────────────

export function parseELF(data: Buffer, filePath: string): BinaryInfo {
  // Verify magic
  for (let i = 0; i < 4; i++) {
    if (data[i] !== ELF_MAGIC[i]) {
      throw new Error(t('elf.invalid_magic'))
    }
  }

  const elfClass = data[4]
  const elfData = data[5]
  const is64 = elfClass === ELFCLASS64
  const isLittle = elfData === ELFDATA2LSB

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)

  const read16 = (offset: number) => view.getUint16(offset, isLittle)
  const read32 = (offset: number) => view.getUint32(offset, isLittle)
  const read64 = (offset: number) => Number(view.getBigUint64(offset, isLittle))
  const readAddr = is64 ? read64 : read32
  const readOff = is64 ? read64 : read32

  // --- ELF Header ---
  const machine = read16(18)
  let entryPoint: number
  let phOffset: number
  let shOffset: number
  let phEntSize: number
  let phNum: number
  let shEntSize: number
  let shNum: number
  let shStrIndex: number

  if (is64) {
    entryPoint = read64(24)
    phOffset = read64(32)
    shOffset = read64(40)
    phEntSize = read16(54)
    phNum = read16(56)
    shEntSize = read16(58)
    shNum = read16(60)
    shStrIndex = read16(62)
  } else {
    entryPoint = read32(24)
    phOffset = read32(28)
    shOffset = read32(32)
    phEntSize = read16(42)
    phNum = read16(44)
    shEntSize = read16(46)
    shNum = read16(48)
    shStrIndex = read16(50)
  }

  // --- Section Header String Table ---
  let shStrTab: Buffer | null = null
  if (shStrIndex < shNum && shOffset > 0) {
    const strSecOffset = shOffset + shStrIndex * shEntSize
    const strTabOff = is64
      ? read64(strSecOffset + 24)
      : read32(strSecOffset + 16)
    const strTabSize = is64
      ? read64(strSecOffset + 32)
      : read32(strSecOffset + 20)
    shStrTab = data.subarray(strTabOff, strTabOff + strTabSize)
  }

  // --- Section Headers ---
  const sections: SectionInfo[] = []

  for (let i = 0; i < shNum; i++) {
    const secOffset = shOffset + i * shEntSize
    if (secOffset + shEntSize > data.length) break

    let name = ''
    const nameIndex = read32(secOffset)
    if (shStrTab && nameIndex < shStrTab.length) {
      name = readCString(shStrTab, nameIndex)
    }

    let shFlags: number
    let shAddr: number
    let shFileOffset: number
    let shSize: number

    if (is64) {
      shFlags = read64(secOffset + 8)
      shAddr = read64(secOffset + 16)
      shFileOffset = read64(secOffset + 24)
      shSize = read64(secOffset + 32)
    } else {
      shFlags = read32(secOffset + 8)
      shAddr = read32(secOffset + 12)
      shFileOffset = read32(secOffset + 16)
      shSize = read32(secOffset + 20)
    }

    sections.push({
      name,
      virtualAddress: shAddr,
      virtualSize: shSize,
      rawAddress: shFileOffset,
      rawSize: shSize,
      characteristics: shFlags,
      isExecutable: (shFlags & SHF_EXECINSTR) !== 0,
      isWritable: (shFlags & SHF_WRITE) !== 0,
      isReadable: (shFlags & SHF_ALLOC) !== 0
    })
  }

  // --- Symbols (simplified: just dynamic symbols for imports/exports) ---
  const imports: ImportInfo[] = []
  const exports: ExportInfo[] = []

  // Find .dynsym and .dynstr sections
  const dynsymSection = sections.find(s => s.name === '.dynsym')
  const dynstrSection = sections.find(s => s.name === '.dynstr')

  if (dynsymSection && dynstrSection) {
    const dynstr = data.subarray(dynstrSection.rawAddress, dynstrSection.rawAddress + dynstrSection.rawSize)
    const symEntSize = is64 ? 24 : 16
    const symCount = Math.floor(dynsymSection.rawSize / symEntSize)

    const importFuncs: ImportFunction[] = []

    for (let i = 1; i < symCount; i++) { // skip index 0 (undefined symbol)
      const symOffset = dynsymSection.rawAddress + i * symEntSize

      let stName: number, stValue: number, stInfo: number
      if (is64) {
        stName = read32(symOffset)
        stInfo = data[symOffset + 4]
        stValue = read64(symOffset + 8)
      } else {
        stName = read32(symOffset)
        stValue = read32(symOffset + 4)
        stInfo = data[symOffset + 12]
      }

      const symName = stName < dynstr.length ? readCString(dynstr, stName) : ''
      if (!symName) continue

      const bind = stInfo >> 4
      const type = stInfo & 0xF

      if (stValue === 0 && type === 2) {
        // Undefined function symbol = import
        importFuncs.push({ name: symName })
      } else if (stValue !== 0 && (bind === 1 || bind === 2)) {
        // Global/weak defined symbol = export
        exports.push({
          name: symName,
          ordinal: i,
          address: stValue
        })
      }
    }

    if (importFuncs.length > 0) {
      imports.push({ dllName: 'dynamic', functions: importFuncs })
    }
  }

  const architecture = (machine === EM_X86_64 || is64) ? 'x64' as const : 'x86' as const

  // --- Validate sections for corruption ---
  validateSections(data, sections)

  return {
    path: filePath,
    format: 'ELF',
    architecture,
    entryPoint,
    imageBase: 0,
    sections,
    imports,
    exports,
    fileSize: data.length
  }
}

// ─── Validation ─────────────────────────────────────────────────────────────

function validateSections(data: Buffer, sections: SectionInfo[]): void {
  for (let i = 0; i < sections.length; i++) {
    const sec = sections[i]

    // Check for zero-size sections (warning only)
    if (sec.rawSize === 0 && sec.virtualSize > 0 && sec.isExecutable) {
      console.warn(t('section.corrupted', { section: sec.name, reason: t('section.zero_size', { section: sec.name }) }))
    }

    // Check for file out-of-bounds
    if (sec.rawAddress > 0 && sec.rawAddress + sec.rawSize > data.length) {
      throw new Error(t('section.corrupted', { 
        section: sec.name, 
        reason: t('section.file_oob', { section: sec.name })
      }))
    }

    // Check for overlaps with other sections
    for (let j = i + 1; j < sections.length; j++) {
      const other = sections[j]
      if (sec.rawAddress > 0 && other.rawAddress > 0 &&
          sec.rawAddress < other.rawAddress + other.rawSize &&
          sec.rawAddress + sec.rawSize > other.rawAddress) {
        console.warn(t('section.corrupted', { 
          section: sec.name, 
          reason: t('section.overlapping', { section: sec.name, other: other.name })
        }))
      }
    }
  }
}

// ─── Utility ────────────────────────────────────────────────────────────────

function readCString(data: Buffer | Uint8Array, offset: number, maxLen = 256): string {
  let end = offset
  while (end < data.length && end < offset + maxLen && data[end] !== 0) {
    end++
  }
  let str = ''
  for (let i = offset; i < end; i++) {
    str += String.fromCharCode(data[i])
  }
  return str
}

/**
 * Read raw bytes from an ELF section
 */
export function readELFSectionBytes(
  data: Buffer,
  section: SectionInfo,
  offset: number,
  size: number
): Buffer | null {
  const fileOffset = section.rawAddress + offset
  if (fileOffset + size > data.length) return null
  return data.subarray(fileOffset, fileOffset + size)
}
