// ============================================================================
// Unified Binary Loader
// Detects format (PE/ELF) and dispatches to the appropriate parser
// ============================================================================

import * as fs from 'fs'
import * as crypto from 'crypto'
import { BinaryInfo, SectionInfo } from '../model/types'
import { parsePE, rvaToFileOffset, readBytesAtRva } from './pe-parser'
import { parseELF } from './elf-parser'
import { t } from '../i18n'

// ─── Format Detection ───────────────────────────────────────────────────────

export function detectFormat(data: Buffer): 'PE' | 'ELF' | 'Unknown' {
  if (data.length < 4) return 'Unknown'

  // Check PE (MZ header)
  if (data[0] === 0x4D && data[1] === 0x5A) return 'PE'

  // Check ELF (\x7FELF)
  if (data[0] === 0x7F && data[1] === 0x45 && data[2] === 0x4C && data[3] === 0x46) return 'ELF'

  return 'Unknown'
}

// ─── Loader ─────────────────────────────────────────────────────────────────

let loadedData: Buffer | null = null
let loadedInfo: BinaryInfo | null = null

export function loadBinary(filePath: string): BinaryInfo {
  try {
    const data = fs.readFileSync(filePath)
    if (data.length === 0) {
      throw new Error(t('binary.empty'))
    }

    loadedData = data

    const format = detectFormat(data)
    switch (format) {
      case 'PE':
        loadedInfo = parsePE(data, filePath)
        break
      case 'ELF':
        loadedInfo = parseELF(data, filePath)
        break
      default:
        throw new Error(t('binary.load_error', { path: filePath, error: 'Unsupported binary format' }))
    }

    if (!loadedInfo) {
      throw new Error(t('binary.parse_failed'))
    }

    if (!loadedInfo.sections || loadedInfo.sections.length === 0) {
      throw new Error(t('binary.no_sections'))
    }

    for (const section of loadedInfo.sections) {
      if (section.rawAddress < 0 || section.rawSize < 0 || section.rawAddress + section.rawSize > data.length) {
        throw new Error(t('binary.invalid_section_bounds', { section: section.name }))
      }
    }

    return loadedInfo
  } catch (error: any) {
    const msg = error.message || 'Unknown error'
    const formattedMsg = msg.includes('{') ? msg : t('binary.load_error', { path: filePath, error: msg })
    throw new Error(formattedMsg)
  }
}

export function getLoadedData(): Buffer | null {
  return loadedData
}

export function getLoadedInfo(): BinaryInfo | null {
  return loadedInfo
}

/**
 * Get raw bytes at an absolute address (imageBase-relative for PE)
 */
export function getBytesAtAddress(address: number, size: number): Buffer | null {
  if (!loadedData || !loadedInfo) return null

  if (loadedInfo.format === 'PE') {
    const rva = address - loadedInfo.imageBase
    return readBytesAtRva(loadedData, rva, size, loadedInfo.sections)
  } else {
    // For ELF, addresses are virtual addresses directly
    for (const section of loadedInfo.sections) {
      if (address >= section.virtualAddress &&
          address < section.virtualAddress + section.virtualSize) {
        const offset = address - section.virtualAddress + section.rawAddress
        if (offset + size <= loadedData.length) {
          return loadedData.subarray(offset, offset + size)
        }
      }
    }
  }

  return null
}

/**
 * Get the executable code sections
 */
export function getCodeSections(): SectionInfo[] {
  if (!loadedInfo) return []
  return loadedInfo.sections.filter(s => s.isExecutable)
}

/**
 * Get a section by name
 */
export function getSectionByName(name: string): SectionInfo | undefined {
  if (!loadedInfo) return undefined
  return loadedInfo.sections.find(s => s.name === name)
}

/**
 * Get raw bytes of a section
 */
export function getSectionBytes(section: SectionInfo): Buffer | null {
  if (!loadedData) return null
  if (section.rawAddress + section.rawSize > loadedData.length) return null
  return loadedData.subarray(section.rawAddress, section.rawAddress + section.rawSize)
}

/**
 * Compute SHA-256 hash of the loaded binary
 */
export function computeBinaryHash(): string {
  if (!loadedData) return ''
  return crypto.createHash('sha256').update(loadedData).digest('hex')
}

/**
 * Convert a virtual address to file offset
 */
export function virtualToFileOffset(address: number): number {
  if (!loadedInfo || !loadedData) return -1

  if (loadedInfo.format === 'PE') {
    const rva = address - loadedInfo.imageBase
    return rvaToFileOffset(rva, loadedInfo.sections)
  } else {
    for (const section of loadedInfo.sections) {
      if (address >= section.virtualAddress &&
          address < section.virtualAddress + section.virtualSize) {
        return address - section.virtualAddress + section.rawAddress
      }
    }
  }
  return -1
}

/**
 * Cleanup loaded data
 */
export function unloadBinary(): void {
  loadedData = null
  loadedInfo = null
}
