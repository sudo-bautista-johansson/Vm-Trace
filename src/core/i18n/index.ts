// ============================================================================
// Internationalization (i18n) Module
// Provides localized messages in English and Spanish
// ============================================================================

export type Language = 'en' | 'es'

interface MessageDict {
  [key: string]: string
}

interface LanguageMessages {
  en: MessageDict
  es: MessageDict
}

const MESSAGES: LanguageMessages = {
  en: {
    // Binary Loading
    'binary.empty': 'Binary file is empty',
    'binary.parse_failed': 'Failed to parse binary metadata',
    'binary.no_sections': 'Binary does not contain any sections',
    'binary.invalid_section_bounds': 'Invalid section bounds for section "{section}"',
    'binary.load_error': 'Failed to load binary "{path}": {error}',
    'binary.no_executable': 'Binary does not contain any executable sections',
    
    // PE Format
    'pe.invalid_mz': 'Invalid PE file: Missing MZ signature',
    'pe.header_oob': 'Invalid PE file: PE header offset out of bounds',
    'pe.invalid_sig': 'Invalid PE file: Missing PE signature',
    
    // ELF Format
    'elf.invalid_magic': 'Invalid ELF file: Missing ELF magic',
    
    // Section Corruption
    'section.corrupted': 'Section "{section}" appears corrupted: {reason}',
    'section.zero_size': 'Section "{section}" has zero size',
    'section.overlapping': 'Section "{section}" overlaps with section "{other}"',
    'section.file_oob': 'Section "{section}" extends beyond file boundaries',
    'section.invalid_va': 'Section "{section}" has invalid virtual address',
    'section.checksum_failed': 'Section "{section}" checksum validation failed',
    
    // Execution
    'exec.no_binary': 'No binary loaded',
    'exec.vip_oob': 'Instruction pointer out of bounds: 0x{vip}',
    'exec.invalid_instruction': 'Invalid instruction at 0x{address}',
    'exec.unknown_opcode': 'Unknown opcode: 0x{opcode}',
    'exec.stack_underflow': 'Stack underflow',
    'exec.div_by_zero': 'Division by zero',
    'exec.mod_by_zero': 'Modulo by zero',
    
    // Analysis
    'analysis.phase1_success': 'Phase 1 detection found {count} handlers (confidence: {confidence}%)',
    'analysis.phase1_low_confidence': 'Phase 1 confidence too low ({confidence}%), falling back to realtime execution',
    'analysis.phase1_failed': 'Phase 1 detection failed, falling back to realtime execution',
    'analysis.phase2_success': 'Phase 2 semantic analysis built {count}/{total} executors',
    'analysis.phase2_failed': 'Phase 2 semantic analysis failed, continuing with Phase 1 only',
    'analysis.phase3_enabled': 'Phase 3 realtime bytecode execution enabled',
  },
  es: {
    // Binary Loading
    'binary.empty': 'El archivo binario está vacío',
    'binary.parse_failed': 'No se pudo analizar los metadatos del binario',
    'binary.no_sections': 'El binario no contiene ninguna sección',
    'binary.invalid_section_bounds': 'Límites de sección inválidos para la sección "{section}"',
    'binary.load_error': 'No se pudo cargar el binario "{path}": {error}',
    'binary.no_executable': 'El binario no contiene ninguna sección ejecutable',
    
    // PE Format
    'pe.invalid_mz': 'Archivo PE inválido: Falta la firma MZ',
    'pe.header_oob': 'Archivo PE inválido: El offset del encabezado PE está fuera de límites',
    'pe.invalid_sig': 'Archivo PE inválido: Falta la firma PE',
    
    // ELF Format
    'elf.invalid_magic': 'Archivo ELF inválido: Falta la firma ELF',
    
    // Section Corruption
    'section.corrupted': 'La sección "{section}" parece corrupta: {reason}',
    'section.zero_size': 'La sección "{section}" tiene tamaño cero',
    'section.overlapping': 'La sección "{section}" se superpone con la sección "{other}"',
    'section.file_oob': 'La sección "{section}" se extiende más allá de los límites del archivo',
    'section.invalid_va': 'La sección "{section}" tiene una dirección virtual inválida',
    'section.checksum_failed': 'Falló la validación de suma de verificación de la sección "{section}"',
    
    // Execution
    'exec.no_binary': 'Ningún binario cargado',
    'exec.vip_oob': 'Puntero de instrucción fuera de límites: 0x{vip}',
    'exec.invalid_instruction': 'Instrucción inválida en 0x{address}',
    'exec.unknown_opcode': 'Opcode desconocido: 0x{opcode}',
    'exec.stack_underflow': 'Desbordamiento de pila hacia abajo',
    'exec.div_by_zero': 'División por cero',
    'exec.mod_by_zero': 'Módulo por cero',
    
    // Analysis
    'analysis.phase1_success': 'Detección Phase 1 encontró {count} handlers (confianza: {confidence}%)',
    'analysis.phase1_low_confidence': 'Confianza de Phase 1 demasiado baja ({confidence}%), pasando a ejecución en tiempo real',
    'analysis.phase1_failed': 'Detección de Phase 1 falló, pasando a ejecución en tiempo real',
    'analysis.phase2_success': 'Análisis semántico Phase 2 construyó {count}/{total} ejecutores',
    'analysis.phase2_failed': 'Análisis semántico Phase 2 falló, continuando solo con Phase 1',
    'analysis.phase3_enabled': 'Ejecución de bytecode en tiempo real Phase 3 habilitada',
  }
}

let currentLanguage: Language = 'en'

/**
 * Set the current language for localization
 */
export function setLanguage(lang: Language): void {
  if (lang === 'en' || lang === 'es') {
    currentLanguage = lang
  }
}

/**
 * Get the current language
 */
export function getLanguage(): Language {
  return currentLanguage
}

/**
 * Translate a message key with optional parameters
 */
export function t(key: string, params?: Record<string, string | number>): string {
  const messages = MESSAGES[currentLanguage]
  let message = messages[key] || key

  if (params) {
    for (const [paramKey, paramValue] of Object.entries(params)) {
      message = message.replace(new RegExp(`\\{${paramKey}\\}`, 'g'), String(paramValue))
    }
  }

  return message
}

/**
 * Translate with English as fallback
 */
export function tWithFallback(key: string, params?: Record<string, string | number>): string {
  const messages = MESSAGES[currentLanguage]
  const fallbackMessages = MESSAGES.en

  let message = messages[key] || fallbackMessages[key] || key

  if (params) {
    for (const [paramKey, paramValue] of Object.entries(params)) {
      message = message.replace(new RegExp(`\\{${paramKey}\\}`, 'g'), String(paramValue))
    }
  }

  return message
}

export { MESSAGES }
