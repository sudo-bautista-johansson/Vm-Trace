// ============================================================================
// VMTrace Core Types
// Complete type system for VM analysis, tracing and devirtualization
// ============================================================================

// ─── Binary Analysis ────────────────────────────────────────────────────────

export interface BinaryInfo {
  path: string
  format: 'PE' | 'ELF' | 'Unknown'
  architecture: 'x86' | 'x64' | 'Unknown'
  entryPoint: number
  imageBase: number
  sections: SectionInfo[]
  imports: ImportInfo[]
  exports: ExportInfo[]
  fileSize: number
  timestamp?: number
}

export interface SectionInfo {
  name: string
  virtualAddress: number
  virtualSize: number
  rawAddress: number
  rawSize: number
  characteristics: number
  isExecutable: boolean
  isWritable: boolean
  isReadable: boolean
}

export interface ImportInfo {
  dllName: string
  functions: ImportFunction[]
}

export interface ImportFunction {
  name: string
  ordinal?: number
  thunkAddress?: number
}

export interface ExportInfo {
  name: string
  ordinal: number
  address: number
}

// ─── Disassembly ────────────────────────────────────────────────────────────

export interface DisasmInstruction {
  address: number
  bytes: number[]
  mnemonic: string
  operands: string
  size: number
  type: InstructionType
  comment?: string
  label?: string
  isTarget?: boolean // is a jump/call target
}

export enum InstructionType {
  ControlFlow = 'control_flow',
  Stack = 'stack',
  Arithmetic = 'arithmetic',
  Logic = 'logic',
  Memory = 'memory',
  Comparison = 'comparison',
  System = 'system',
  Suspicious = 'suspicious',
  String = 'string',
  Nop = 'nop',
  Unknown = 'unknown'
}

// ─── VM State ───────────────────────────────────────────────────────────────

export interface VMState {
  vip: number
  vsp: number
  stack: bigint[]
  registers: Record<string, bigint>
  flags: VMFlags
  memory: Map<number, number>
  halted: boolean
  error?: string
}

export interface VMFlags {
  ZF: boolean
  CF: boolean
  SF: boolean
  OF: boolean
  PF: boolean
  AF: boolean
}

export function createDefaultVMState(): VMState {
  return {
    vip: 0,
    vsp: 0,
    stack: [],
    registers: {},
    flags: { ZF: false, CF: false, SF: false, OF: false, PF: false, AF: false },
    memory: new Map(),
    halted: false
  }
}

export function createDefaultFlags(): VMFlags {
  return { ZF: false, CF: false, SF: false, OF: false, PF: false, AF: false }
}

// ─── VM Handlers ────────────────────────────────────────────────────────────

export interface VMHandler {
  id: string
  address?: number
  endAddress?: number
  size: number
  opcodeValue: number
  label?: string
  hypothesis?: string
  comment?: string
  nativeInstructions?: DisasmInstruction[]
  type?: HandlerType
  handlerType?: string // For auto-detected handlers (e.g., 'stack', 'arithmetic')
  description?: string // For auto-detected handlers
  operandSize?: number // For auto-detected handlers
  isDataReference?: boolean // For auto-detected handlers
  executionCount: number
  confidence?: number // For auto-detected handlers (0-1)
}

export enum HandlerType {
  ControlFlow = 'control_flow',
  Arithmetic = 'arithmetic',
  Stack = 'stack',
  Memory = 'memory',
  Comparison = 'comparison',
  Suspicious = 'suspicious',
  DataMovement = 'data_movement',
  Bitwise = 'bitwise',
  Nop = 'nop',
  Unknown = 'unknown'
}

// ─── Control Flow Graph ─────────────────────────────────────────────────────

export interface CFGNode {
  id: string
  address: number
  endAddress: number
  type: 'handler' | 'block' | 'entry' | 'exit'
  label?: string
  handlerType?: HandlerType
  instructionCount: number
  instructions: number[] // addresses of instructions in this block
}

export interface CFGEdge {
  id: string
  source: string
  target: string
  type: 'dispatch' | 'jump' | 'fallthrough' | 'conditional_true' | 'conditional_false'
  label?: string
  count?: number // how many times this edge was taken during tracing
}

export interface CFGData {
  nodes: CFGNode[]
  edges: CFGEdge[]
  entryNodeId?: string
}

// ─── Trace ──────────────────────────────────────────────────────────────────

export interface TraceEntry {
  index: number
  timestamp: number
  address: number
  opcodeValue: number
  handlerId?: string
  handlerLabel?: string
  mnemonic?: string
  operands?: string
  stackDelta: number
  registersChanged: string[]
  flagsChanged: string[]
}

export interface TraceFilter {
  handlerIds?: string[]
  opcodeValues?: number[]
  addressRange?: { start: number; end: number }
  onlyStackChanges?: boolean
  onlyControlFlow?: boolean
}

// ─── VM Model ───────────────────────────────────────────────────────────────

export interface VMModel {
  dispatcher: DispatcherInfo | null
  handlers: VMHandler[]
  opcodes: OpcodeMapping[]
  cfg: CFGData
  trace: TraceEntry[]
  state: VMState
  bytecodeSection?: SectionInfo
  bytecodeStart?: number
  bytecodeEnd?: number
}

export interface DispatcherInfo {
  address: number
  endAddress: number
  size: number
  type: 'switch' | 'indirect_jump' | 'computed' | 'custom'
  handlerTableAddress?: number
  handlerTableSize?: number
  handlerCount?: number
  keyRegister?: string
  dispatchPattern?: string
}

export interface OpcodeMapping {
  opcodeValue: number
  handlerId: string
  handlerAddress: number
  label?: string
}

// ─── Bookmarks ──────────────────────────────────────────────────────────────

export interface Bookmark {
  id: string
  address: number
  label: string
  color: string
  notes?: string
  createdAt: string
}

// ─── Project ────────────────────────────────────────────────────────────────

export interface VMTraceProject {
  version: string
  name: string
  binaryPath: string
  binaryHash: string
  binaryInfo: BinaryInfo
  vmModel: VMModel
  bookmarks: Bookmark[]
  userComments: Record<string, string>  // hex address string → comment
  handlerLabels: Record<string, string> // hex address string → label
  viewState?: ViewState
  createdAt: string
  updatedAt: string
}

export interface ViewState {
  selectedAddress?: number
  scrollPosition?: number
  panelSizes?: number[]
  expandedTreeNodes?: string[]
}

// ─── IPC Channel Types ──────────────────────────────────────────────────────

export interface IPCChannels {
  'binary:load': { path: string }
  'binary:info': void
  'disasm:range': { start: number; end: number; baseAddress: number }
  'disasm:section': { sectionName: string }
  'vm:set-dispatcher': { address: number }
  'vm:detect-handlers': { dispatcherAddress: number; method: 'auto' | 'table' | 'trace' }
  'vm:set-bytecode': { start: number; end: number }
  'vm:step': void
  'vm:step-over': void
  'vm:run': void
  'vm:run-until-handler': { handlerId: string }
  'vm:run-until-address': { address: number }
  'vm:stop': void
  'vm:reset': void
  'vm:get-state': void
  'vm:label-handler': { handlerId: string; label: string }
  'vm:set-hypothesis': { handlerId: string; hypothesis: string }
  'trace:get': { filter?: TraceFilter }
  'trace:clear': void
  'cfg:get': void
  'cfg:rebuild': void
  'bookmark:add': Bookmark
  'bookmark:remove': { id: string }
  'bookmark:list': void
  'project:save': { path: string }
  'project:load': { path: string }
  'project:export-trace': { path: string; format: 'json' | 'csv' | 'text' }
  'project:export-cfg': { path: string; format: 'json' | 'dot' | 'svg' }
}
