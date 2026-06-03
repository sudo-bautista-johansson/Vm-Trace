// ============================================================================
// Analysis Module Index
// Exports bytecode analysis tools for VM handler detection and semantic analysis
// ============================================================================

export { BytecodeAnalyzer, DispatcherPattern, OpcodeCandidate } from './bytecode-analyzer'
export { DynamicHandlerDetector, DetectionResult } from './dynamic-handler-detector'
export {
  OpcodeSemanticAnalyzer,
  OpcodeSemanticType,
  SemanticSignature
} from './opcode-semantic-analyzer'
export { DynamicExecutorBuilder, DynamicExecutorConfig } from './dynamic-executor-builder'
export {
  HandlerSemanticAnalyzer,
  HandlerSemanticInfo,
  SemanticAnalysisResult
} from './handler-semantic-analyzer'
export { BytecodeDecoder, DecodedInstruction, DecoderConfig } from './bytecode-decoder'
export { RealtimeBytecodeExecutor, RealtimeExecutionConfig } from './realtime-bytecode-executor'
