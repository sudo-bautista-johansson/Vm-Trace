// ============================================================================
// PE (Portable Executable) Parser
// Parses Windows PE32/PE32+ binaries: headers, sections, imports, exports
// ============================================================================

import {
  BinaryInfo, SectionInfo, ImportInfo, ImportFunction, ExportInfo
} from '../model/types'
import { t } from '../i18n'

// ─── Constants ──────────────────────────────────────────────────────────────

const DOS_MAGIC = 0x5A4D          // 'MZ'
const PE_SIGNATURE = 0x00004550   // 'PE\0\0'
const PE32_MAGIC = 0x10B
const PE32PLUS_MAGIC = 0x20B

// Section characteristics
const IMAGE_SCN_MEM_EXECUTE = 0x20000000
const IMAGE_SCN_MEM_READ = 0x40000000
const IMAGE_SCN_MEM_WRITE = 0x80000000

// Data directory indices
const IMAGE_DIRECTORY_ENTRY_EXPORT = 0
const IMAGE_DIRECTORY_ENTRY_IMPORT = 1

// ─── PE Parser ──────────────────────────────────────────────────────────────

export function parsePE(data: Buffer, filePath: string): BinaryInfo {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)

  // --- DOS Header ---
  const dosMagic = view.getUint16(0, true)
  if (dosMagic !== DOS_MAGIC) {
    throw new Error(t('pe.invalid_mz'))
  }
  const peOffset = view.getUint32(0x3C, true)

  // --- PE Signature ---
  if (peOffset + 4 > data.length) {
    throw new Error(t('pe.header_oob'))
  }
  const peSignature = view.getUint32(peOffset, true)
  if (peSignature !== PE_SIGNATURE) {
    throw new Error(t('pe.invalid_sig'))
  }

  // --- COFF Header ---
  const coffOffset = peOffset + 4
  const machine = view.getUint16(coffOffset, true)
  const numberOfSections = view.getUint16(coffOffset + 2, true)
  const timeDateStamp = view.getUint32(coffOffset + 4, true)
  const sizeOfOptionalHeader = view.getUint16(coffOffset + 16, true)

  // --- Optional Header ---
  const optOffset = coffOffset + 20
  const optMagic = view.getUint16(optOffset, true)
  const is64 = optMagic === PE32PLUS_MAGIC

  let entryPoint: number
  let imageBase: number
  let numberOfRvaAndSizes: number
  let dataDirectoryOffset: number

  if (is64) {
    // PE32+ (64-bit)
    entryPoint = view.getUint32(optOffset + 16, true)
    imageBase = Number(view.getBigUint64(optOffset + 24, true))
    numberOfRvaAndSizes = view.getUint32(optOffset + 108, true)
    dataDirectoryOffset = optOffset + 112
  } else {
    // PE32 (32-bit)
    entryPoint = view.getUint32(optOffset + 16, true)
    imageBase = view.getUint32(optOffset + 28, true)
    numberOfRvaAndSizes = view.getUint32(optOffset + 92, true)
    dataDirectoryOffset = optOffset + 96
  }

  // --- Data Directories ---
  const dataDirectories: { rva: number; size: number }[] = []
  for (let i = 0; i < Math.min(numberOfRvaAndSizes, 16); i++) {
    const dirOffset = dataDirectoryOffset + i * 8
    dataDirectories.push({
      rva: view.getUint32(dirOffset, true),
      size: view.getUint32(dirOffset + 4, true)
    })
  }

  // --- Section Headers ---
  const sectionsOffset = optOffset + sizeOfOptionalHeader
  const sections: SectionInfo[] = []

  for (let i = 0; i < numberOfSections; i++) {
    const secOffset = sectionsOffset + i * 40
    const nameBytes = data.subarray(secOffset, secOffset + 8)
    const name = decodeASCII(nameBytes)
    const virtualSize = view.getUint32(secOffset + 8, true)
    const virtualAddress = view.getUint32(secOffset + 12, true)
    const rawSize = view.getUint32(secOffset + 16, true)
    const rawAddress = view.getUint32(secOffset + 20, true)
    const characteristics = view.getUint32(secOffset + 36, true)

    sections.push({
      name,
      virtualAddress,
      virtualSize,
      rawAddress,
      rawSize,
      characteristics,
      isExecutable: (characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0,
      isWritable: (characteristics & IMAGE_SCN_MEM_WRITE) !== 0,
      isReadable: (characteristics & IMAGE_SCN_MEM_READ) !== 0
    })
  }

  // --- Imports ---
  const imports = parseImports(data, view, dataDirectories, sections, is64)

  // --- Exports ---
  const exports = parseExports(data, view, dataDirectories, sections)

  // --- Validate sections for corruption ---
  validateSections(data, sections)

  const architecture = is64 ? 'x64' as const : 'x86' as const

  return {
    path: filePath,
    format: 'PE',
    architecture,
    entryPoint: imageBase + entryPoint,
    imageBase,
    sections,
    imports,
    exports,
    fileSize: data.length,
    timestamp: timeDateStamp
  }
}

// ─── Import Table Parser ────────────────────────────────────────────────────

function parseImports(
  data: Buffer,
  view: DataView,
  dataDirectories: { rva: number; size: number }[],
  sections: SectionInfo[],
  is64: boolean
): ImportInfo[] {
  if (dataDirectories.length <= IMAGE_DIRECTORY_ENTRY_IMPORT) return []
  const importDir = dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT]
  if (importDir.rva === 0 || importDir.size === 0) return []

  const importFileOffset = rvaToFileOffset(importDir.rva, sections)
  if (importFileOffset === -1) return []

  const imports: ImportInfo[] = []
  let descriptorOffset = importFileOffset

  // Each import descriptor is 20 bytes, terminated by a zero entry
  while (descriptorOffset + 20 <= data.length) {
    const originalFirstThunk = view.getUint32(descriptorOffset, true)
    const nameRva = view.getUint32(descriptorOffset + 12, true)
    const firstThunk = view.getUint32(descriptorOffset + 16, true)

    // Zero entry = end of import descriptors
    if (nameRva === 0) break

    const nameOffset = rvaToFileOffset(nameRva, sections)
    const dllName = nameOffset !== -1 ? readCString(data, nameOffset) : 'unknown'

    const functions: ImportFunction[] = []
    const thunkRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk
    let thunkOffset = rvaToFileOffset(thunkRva, sections)

    if (thunkOffset !== -1) {
      const thunkSize = is64 ? 8 : 4
      let thunkIndex = 0

      while (thunkOffset + thunkSize <= data.length) {
        const thunkValue = is64
          ? Number(view.getBigUint64(thunkOffset, true))
          : view.getUint32(thunkOffset, true)

        if (thunkValue === 0) break

        const isOrdinal = is64
          ? (thunkValue & 0x8000000000000000) !== 0
          : (thunkValue & 0x80000000) !== 0

        if (isOrdinal) {
          functions.push({
            name: `Ordinal_${thunkValue & 0xFFFF}`,
            ordinal: thunkValue & 0xFFFF,
            thunkAddress: firstThunk + thunkIndex * thunkSize
          })
        } else {
          const hintNameOffset = rvaToFileOffset(thunkValue & 0x7FFFFFFF, sections)
          if (hintNameOffset !== -1 && hintNameOffset + 2 < data.length) {
            const funcName = readCString(data, hintNameOffset + 2)
            functions.push({
              name: funcName,
              thunkAddress: firstThunk + thunkIndex * thunkSize
            })
          }
        }

        thunkOffset += thunkSize
        thunkIndex++
        if (thunkIndex > 10000) break // safety
      }
    }

    imports.push({ dllName, functions })
    descriptorOffset += 20
    if (imports.length > 1000) break // safety
  }

  return imports
}

// ─── Export Table Parser ────────────────────────────────────────────────────

function parseExports(
  data: Buffer,
  view: DataView,
  dataDirectories: { rva: number; size: number }[],
  sections: SectionInfo[]
): ExportInfo[] {
  if (dataDirectories.length <= IMAGE_DIRECTORY_ENTRY_EXPORT) return []
  const exportDir = dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT]
  if (exportDir.rva === 0 || exportDir.size === 0) return []

  const exportFileOffset = rvaToFileOffset(exportDir.rva, sections)
  if (exportFileOffset === -1) return []

  const numberOfFunctions = view.getUint32(exportFileOffset + 20, true)
  const numberOfNames = view.getUint32(exportFileOffset + 24, true)
  const addressOfFunctions = view.getUint32(exportFileOffset + 28, true)
  const addressOfNames = view.getUint32(exportFileOffset + 32, true)
  const addressOfNameOrdinals = view.getUint32(exportFileOffset + 36, true)
  const ordinalBase = view.getUint32(exportFileOffset + 16, true)

  const funcTableOffset = rvaToFileOffset(addressOfFunctions, sections)
  const nameTableOffset = rvaToFileOffset(addressOfNames, sections)
  const ordinalTableOffset = rvaToFileOffset(addressOfNameOrdinals, sections)

  if (funcTableOffset === -1) return []

  const exports: ExportInfo[] = []

  for (let i = 0; i < Math.min(numberOfNames, 10000); i++) {
    if (nameTableOffset === -1 || ordinalTableOffset === -1) continue

    const nameRva = view.getUint32(nameTableOffset + i * 4, true)
    const ordinalIndex = view.getUint16(ordinalTableOffset + i * 2, true)
    const funcRva = view.getUint32(funcTableOffset + ordinalIndex * 4, true)

    const nameFileOffset = rvaToFileOffset(nameRva, sections)
    const name = nameFileOffset !== -1 ? readCString(data, nameFileOffset) : `Ordinal_${ordinalIndex + ordinalBase}`

    exports.push({
      name,
      ordinal: ordinalIndex + ordinalBase,
      address: funcRva
    })
  }

  return exports
}

// ─── Utility Functions ──────────────────────────────────────────────────────

function validateSections(data: Buffer, sections: SectionInfo[]): void {
  for (let i = 0; i < sections.length; i++) {
    const sec = sections[i]

    // Check for zero-size sections (corrupted)
    if (sec.rawSize === 0 && sec.virtualSize > 0) {
      console.warn(t('section.corrupted', { section: sec.name, reason: t('section.zero_size', { section: sec.name }) }))
    }

    // Check for file out-of-bounds
    if (sec.rawAddress + sec.rawSize > data.length) {
      throw new Error(t('section.corrupted', { 
        section: sec.name, 
        reason: t('section.file_oob', { section: sec.name })
      }))
    }

    // Check for overlaps with other sections
    for (let j = i + 1; j < sections.length; j++) {
      const other = sections[j]
      if (sec.rawAddress < other.rawAddress + other.rawSize &&
          sec.rawAddress + sec.rawSize > other.rawAddress) {
        console.warn(t('section.corrupted', { 
          section: sec.name, 
          reason: t('section.overlapping', { section: sec.name, other: other.name })
        }))
      }
    }

    // Check for invalid virtual addresses
    if (sec.virtualAddress === 0 && sec.isExecutable) {
      console.warn(t('section.corrupted', { 
        section: sec.name, 
        reason: t('section.invalid_va', { section: sec.name })
      }))
    }
  }
}

// ─── Utility Functions ──────────────────────────────────────────────────────

export function rvaToFileOffset(rva: number, sections: SectionInfo[]): number {
  for (const section of sections) {
    if (rva >= section.virtualAddress &&
        rva < section.virtualAddress + Math.max(section.virtualSize, section.rawSize)) {
      return rva - section.virtualAddress + section.rawAddress
    }
  }
  return -1
}

function readCString(data: Buffer, offset: number, maxLen = 256): string {
  let end = offset
  while (end < data.length && end < offset + maxLen && data[end] !== 0) {
    end++
  }
  return data.subarray(offset, end).toString('ascii')
}

function decodeASCII(bytes: Uint8Array): string {
  let str = ''
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) break
    str += String.fromCharCode(bytes[i])
  }
  return str
}

/**
 * Read raw bytes from a section given an RVA range
 */
export function readBytesAtRva(
  data: Buffer,
  rva: number,
  size: number,
  sections: SectionInfo[]
): Buffer | null {
  const fileOffset = rvaToFileOffset(rva, sections)
  if (fileOffset === -1 || fileOffset + size > data.length) return null
  return data.subarray(fileOffset, fileOffset + size)
}
