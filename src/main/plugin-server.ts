// ============================================================================
// VMTrace WebSocket Plugin Server
// Exposes a JSON-RPC 2.0 API to external scripts (Python, Java, C++, etc.)
// Runs locally on port 57130 (default)
// ============================================================================

import { IncomingMessage } from 'http'
import { WebSocketServer, WebSocket } from 'ws'
import { engineManager } from './engine-manager'
import { spawn, spawnSync, ChildProcessWithoutNullStreams } from 'child_process'
import { readdirSync, statSync, existsSync } from 'fs'
import { extname, join, dirname } from 'path'

let pluginAuthToken: string | null = process.env['VMTRACE_PLUGIN_TOKEN'] || null

interface JsonRpcRequest {
  jsonrpc: string
  method: string
  params?: any
  id?: number | string | null
}

interface PluginProcessInfo {
  path: string
  command: string
  args: string[]
  startedAt: Date
  status: 'starting' | 'running' | 'already-running' | 'failed' | 'exited'
  exitCode: number | null
  error?: string
}

interface PluginProcessRecord {
  info: PluginProcessInfo
  process: ChildProcessWithoutNullStreams | null
}

const supportedPluginLaunchers: Record<string, { command: string; argBuilder: (filePath: string) => string[] }> = {
  '.py': { command: 'python', argBuilder: (filePath) => [filePath] },
  '.js': { command: 'node', argBuilder: (filePath) => [filePath] },
  '.mjs': { command: 'node', argBuilder: (filePath) => [filePath] },
  '.exe': { command: '', argBuilder: () => [] },
  '.jar': { command: 'java', argBuilder: (filePath) => ['-jar', filePath] },
  '.bat': { command: '', argBuilder: () => [] },
  '.cmd': { command: '', argBuilder: () => [] }
}

const pluginProcesses = new Map<string, PluginProcessRecord>()
let autoInstallDeps = false

export function setAutoInstallDeps(enabled: boolean): void {
  autoInstallDeps = !!enabled
}

export function getAutoInstallDeps(): boolean {
  return autoInstallDeps
}

function createPluginProcessInfo(filePath: string, command: string, args: string[]): PluginProcessInfo {
  return {
    path: filePath,
    command,
    args,
    startedAt: new Date(),
    status: 'starting',
    exitCode: null
  }
}

function getPluginLauncher(filePath: string): { command: string; args: string[] } | null {
  const ext = extname(filePath).toLowerCase()
  const launcher = supportedPluginLaunchers[ext]
  if (!launcher) {
    return null
  }

  let command = launcher.command || filePath
  let args = launcher.argBuilder(filePath)

  // If python launcher, try to prefer workspace venv python if present
  if (ext === '.py') {
    const venvPython = findWorkspaceVenvPython()
    if (venvPython) {
      command = venvPython
      args = launcher.argBuilder(filePath)
    }
  }

  return { command, args }
}

function findWorkspaceVenvPython(): string | null {
  try {
    // Common venv locations relative to project root
    const winPath = join(process.cwd(), 'venv', 'Scripts', 'python.exe')
    const nixPath = join(process.cwd(), 'venv', 'bin', 'python')
    if (existsSync(winPath)) return winPath
    if (existsSync(nixPath)) return nixPath
  } catch {}
  return null
}

function checkPythonHasModule(pythonExe: string, moduleName: string): boolean {
  try {
    const res = spawnSync(pythonExe, ['-c', `import ${moduleName}`], { encoding: 'utf8', shell: false })
    return res.status === 0
  } catch {
    return false
  }
}

export function installDeps(packages: string[], pythonExe?: string): { success: boolean; stdout: string; stderr: string } {
  try {
    const python = pythonExe || findWorkspaceVenvPython() || 'python'
    const args = ['-m', 'pip', 'install', ...packages]
    const res = spawnSync(python, args, { encoding: 'utf8', shell: false })
    return { success: res.status === 0, stdout: res.stdout || '', stderr: res.stderr || '' }
  } catch (err: any) {
    return { success: false, stdout: '', stderr: err.message }
  }
}

function discoverPluginFiles(folderPath: string): string[] {
  const entries = readdirSync(folderPath, { withFileTypes: true })
  const files: string[] = []

  for (const entry of entries) {
    const fullPath = join(folderPath, entry.name)
    if (entry.isFile()) {
      const ext = extname(entry.name).toLowerCase()
      if (supportedPluginLaunchers[ext] || ext === '.cpp' || ext === '.java') {
        files.push(fullPath)
      }
    }
  }

  return files
}

function addPluginProcessListeners(filePath: string, record: PluginProcessRecord): void {
  const proc = record.process
  if (!proc) return

  proc.on('spawn', () => {
    record.info.status = 'running'
    broadcastProcessesToUI()
  })

  proc.on('exit', (code) => {
    record.info.status = 'exited'
    record.info.exitCode = code
    pluginProcesses.delete(filePath)
    broadcastProcessesToUI()
  })

  proc.on('error', (err) => {
    record.info.status = 'failed'
    record.info.error = err.message
    record.info.exitCode = null
    pluginProcesses.delete(filePath)
    broadcastProcessesToUI()
  })
}

function startPluginProcess(filePath: string): PluginProcessInfo {
  if (pluginProcesses.has(filePath)) {
    const existing = pluginProcesses.get(filePath)
    if (existing) {
      existing.info.status = 'already-running'
      return existing.info
    }
  }

  const ext = extname(filePath).toLowerCase()

  // Special-case: compile .cpp using g++ then run resulting executable
  if (ext === '.cpp') {
    try {
      const check = spawnSync('g++', ['--version'], { encoding: 'utf8', shell: false })
      if (check.status !== 0) {
        return {
          path: filePath,
          command: 'g++',
          args: [],
          startedAt: new Date(),
          status: 'failed',
          exitCode: check.status,
          error: 'g++ no encontrado. Instala MinGW/LLVM/Visual Studio y añade g++ al PATH.'
        }
      }
    } catch (err: any) {
      return {
        path: filePath,
        command: 'g++',
        args: [],
        startedAt: new Date(),
        status: 'failed',
        exitCode: null,
        error: 'g++ no disponible: ' + (err.message || String(err))
      }
    }

    const parsed = require('path').parse(filePath)
    const outPath = require('path').join(parsed.dir, parsed.name + (process.platform === 'win32' ? '.exe' : ''))
    const compileArgs = ['-std=c++17', filePath, '-O2', '-o', outPath]
    const compile = spawnSync('g++', compileArgs, { encoding: 'utf8', shell: false })

    logMessage('system_compiler', 'g++', 'out', `Compilar ${filePath} -> stdout:\n${compile.stdout}\nstderr:\n${compile.stderr}`)

    if (compile.status !== 0) {
      return {
        path: filePath,
        command: 'g++',
        args: compileArgs,
        startedAt: new Date(),
        status: 'failed',
        exitCode: compile.status,
        error: 'Fallo la compilación. Revisa los logs.'
      }
    }

    const spawnOptions = { shell: true, cwd: parsed.dir }
    const child = spawn(outPath, [], spawnOptions)
    const info = createPluginProcessInfo(filePath, outPath, [])
    const record: PluginProcessRecord = { info, process: child }
    pluginProcesses.set(filePath, record)
    addPluginProcessListeners(filePath, record)
    return info
  }

  const launcher = getPluginLauncher(filePath)
  if (!launcher) {
    return {
      path: filePath,
      command: '',
      args: [],
      startedAt: new Date(),
      status: 'failed',
      exitCode: null,
      error: 'Tipo de plugin no soportado'
    }
  }

  const spawnOptions = {
    shell: true,
    cwd: dirname(filePath)
  }
  // If Python file, verify required modules before starting
  if (ext === '.py') {
    const pythonExe = launcher.command || 'python'
    const hasWebsocket = checkPythonHasModule(pythonExe, 'websocket')
    if (!hasWebsocket) {
      // If auto-install enabled, attempt to install and log output
      if (autoInstallDeps) {
        logMessage('system_installer', 'Installer', 'out', `Auto-install enabled: installing websocket-client using ${pythonExe}`)
        const installRes = installDeps(['websocket-client'], pythonExe)
        logMessage('system_installer', 'Installer', 'out', `pip stdout:\n${installRes.stdout}\n\npip stderr:\n${installRes.stderr}`)
        if (!installRes.success) {
          return {
            path: filePath,
            command: pythonExe,
            args: launcher.args,
            startedAt: new Date(),
            status: 'failed',
            exitCode: null,
            error: 'Instalación automática falló. Revisa los logs.'
          }
        }

        // Re-check availability
        const nowHas = checkPythonHasModule(pythonExe, 'websocket')
        if (!nowHas) {
          return {
            path: filePath,
            command: pythonExe,
            args: launcher.args,
            startedAt: new Date(),
            status: 'failed',
            exitCode: null,
            error: 'Módulo websocket aún no disponible tras instalación.'
          }
        }
      }

      return {
        path: filePath,
        command: pythonExe,
        args: launcher.args,
        startedAt: new Date(),
        status: 'failed',
        exitCode: null,
        error: 'Módulo Python "websocket" no encontrado. Instala con: ' + `${pythonExe} -m pip install websocket-client`
      }
    }
  }

  const child = spawn(launcher.command, launcher.args, spawnOptions)
  const info = createPluginProcessInfo(filePath, launcher.command, launcher.args)
  const record: PluginProcessRecord = { info, process: child }
  pluginProcesses.set(filePath, record)
  addPluginProcessListeners(filePath, record)
  return info
}

export function loadPluginsFromFolder(folderPath: string): { folderPath: string; discovered: number; results: PluginProcessInfo[]; warnings: string[] } {
  const warnings: string[] = []
  let files: string[] = []

  try {
    const stats = statSync(folderPath)
    if (!stats.isDirectory()) {
      throw new Error('La ruta seleccionada no es una carpeta válida.')
    }
    files = discoverPluginFiles(folderPath)
  } catch (error: any) {
    return { folderPath, discovered: 0, results: [], warnings: [error.message || 'Error al leer la carpeta'] }
  }

  if (files.length === 0) {
    return { folderPath, discovered: 0, results: [], warnings: ['No se encontraron archivos de plugin compatibles en la carpeta.'] }
  }

  const results: PluginProcessInfo[] = []

  for (const filePath of files) {
    const ext = extname(filePath).toLowerCase()
    if (supportedPluginLaunchers[ext]) {
      results.push(startPluginProcess(filePath))
    } else {
      results.push({
        path: filePath,
        command: '',
        args: [],
        startedAt: new Date(),
        status: 'failed',
        exitCode: null,
        error: `Extensión de plugin encontrada, pero no se puede iniciar automáticamente: ${ext}`
      })
    }
  }

  return { folderPath, discovered: files.length, results, warnings }
}

export function getLoadedPluginProcesses(): PluginProcessInfo[] {
  return Array.from(pluginProcesses.values()).map(record => record.info)
}

export function startPlugin(filePath: string): PluginProcessInfo {
  const info = startPluginProcess(filePath)
  broadcastProcessesToUI()
  return info
}

export function stopPlugin(filePath: string): { success: boolean; info?: PluginProcessInfo } {
  const record = pluginProcesses.get(filePath)
  if (!record) {
    return { success: false }
  }

  try {
    if (record.process && !record.process.killed) {
      record.process.kill()
      record.info.status = 'exited'
    }
  } catch (err: any) {
    record.info.status = 'failed'
    record.info.error = err.message
  }

  pluginProcesses.delete(filePath)
  broadcastProcessesToUI()
  return { success: true, info: record.info }
}

interface JsonRpcResponse {
  jsonrpc: string
  result?: any
  error?: {
    code: number
    message: string
    data?: any
  }
  id: number | string | null
}

interface ConnectedPlugin {
  id: string
  ws: WebSocket
  name: string
  connectedAt: Date
  subscriptions: Set<string>
}

let wss: WebSocketServer | null = null
const connectedPlugins = new Map<string, ConnectedPlugin>()
let nextClientId = 1

// We hold logs of plugin communications to display in the UI console
export interface PluginLog {
  timestamp: string
  pluginId: string
  pluginName: string
  direction: 'in' | 'out'
  message: string
}
const pluginLogs: PluginLog[] = []
const MAX_LOGS = 500

function getConnectionToken(request: IncomingMessage | null): string | null {
  if (!request || !request.url) return null
  try {
    const url = new URL(request.url, 'ws://localhost')
    return url.searchParams.get('token') || null
  } catch {
    return null
  }
}

export function startPluginServer(port: number = 57130, authToken?: string | null): void {
  if (authToken !== undefined) {
    pluginAuthToken = authToken
  }

  if (wss) {
    stopPluginServer()
  }

  try {
    wss = new WebSocketServer({ port })

    wss.on('connection', (ws, request) => {
      const token = getConnectionToken(request || null)
      if (pluginAuthToken && token !== pluginAuthToken) {
        const message = JSON.stringify({ error: 'Unauthorized plugin connection: invalid token' })
        ws.send(message)
        ws.close(1008, 'Unauthorized')
        return
      }

      const clientId = `plugin_${nextClientId++}`
      const pluginInfo: ConnectedPlugin = {
        id: clientId,
        ws,
        name: 'Generic Client',
        connectedAt: new Date(),
        subscriptions: new Set()
      }

      connectedPlugins.set(clientId, pluginInfo)
      logMessage(clientId, 'System', 'in', `New client connected from remote address. Assigned ID: ${clientId}`)

      // Sincronizar el estado actual con la UI
      broadcastPluginsToUI()

      ws.on('message', (messageBuffer) => {
        const rawMessage = messageBuffer.toString()
        try {
          const request = JSON.parse(rawMessage) as JsonRpcRequest
          logMessage(clientId, pluginInfo.name, 'in', rawMessage)
          handleJsonRpc(pluginInfo, request)
        } catch (e: any) {
          const errorResponse: JsonRpcResponse = {
            jsonrpc: '2.0',
            error: { code: -32700, message: 'Parse error' },
            id: null
          }
          ws.send(JSON.stringify(errorResponse))
          logMessage(clientId, pluginInfo.name, 'out', JSON.stringify(errorResponse))
        }
      })

      ws.on('close', () => {
        connectedPlugins.delete(clientId)
        logMessage(clientId, pluginInfo.name, 'in', `Client disconnected.`)
        broadcastPluginsToUI()
      })

      ws.on('error', (err) => {
        logMessage(clientId, pluginInfo.name, 'in', `Error: ${err.message}`)
      })
    })

    console.log(`Plugin WebSocket server listening on ws://localhost:${port}`)
  } catch (error: any) {
    console.error(`Failed to start plugin server: ${error.message}`)
  }
}

export function stopPluginServer(): void {
  if (wss) {
    for (const [id, plugin] of connectedPlugins) {
      plugin.ws.close()
    }
    connectedPlugins.clear()
    wss.close(() => {
      console.log('Plugin server stopped.')
    })
    wss = null
    broadcastPluginsToUI()
  }

  for (const [filePath, record] of pluginProcesses) {
    if (record.process && !record.process.killed) {
      try {
        record.process.kill()
      } catch {
        // Ignore any errors while cleaning up plugin child processes.
      }
    }
    record.info.status = 'exited'
  }
  pluginProcesses.clear()
}

export function getConnectedPlugins(): any[] {
  return Array.from(connectedPlugins.values()).map(p => ({
    id: p.id,
    name: p.name,
    connectedAt: p.connectedAt.toISOString(),
    subscriptions: Array.from(p.subscriptions)
  }))
}

export function getPluginLogs(): PluginLog[] {
  return [...pluginLogs]
}

export function clearPluginLogs(): void {
  pluginLogs.length = 0
}

// ─── JSON-RPC Request Handler ──────────────────────────────────────────

function handleJsonRpc(plugin: ConnectedPlugin, request: JsonRpcRequest): void {
  if (request.jsonrpc !== '2.0') {
    sendError(plugin, -32600, 'Invalid Request', request.id)
    return
  }

  const { method, params, id } = request
  const hasId = id !== undefined && id !== null

  try {
    let result: any = null

    switch (method) {
      // ─── System / Registration ───
      case 'plugin.register': {
        plugin.name = params?.name || 'Unnamed Plugin'
        result = { success: true, clientId: plugin.id }
        broadcastPluginsToUI()
        break
      }

      case 'plugin.subscribe': {
        const events = params?.events || []
        for (const ev of events) {
          plugin.subscriptions.add(ev)
        }
        result = { success: true, activeSubscriptions: Array.from(plugin.subscriptions) }
        break
      }

      case 'plugin.unsubscribe': {
        const events = params?.events || []
        for (const ev of events) {
          plugin.subscriptions.delete(ev)
        }
        result = { success: true, activeSubscriptions: Array.from(plugin.subscriptions) }
        break
      }

      // ─── Emulation Control ───
      case 'vm.step': {
        const stepResult = engineManager.step()
        result = {
          vip: stepResult.state.vip.toString(),
          vsp: stepResult.state.vsp,
          halted: stepResult.state.halted,
          error: stepResult.state.error,
          stack: stepResult.state.stack.map(s => s.toString()),
          registers: Object.fromEntries(
            Object.entries(stepResult.state.registers).map(([k, v]) => [k, v.toString()])
          )
        }
        break
      }

      case 'vm.stepOver': {
        const stepResult = engineManager.stepOver()
        result = {
          vip: stepResult.state.vip.toString(),
          vsp: stepResult.state.vsp,
          halted: stepResult.state.halted,
          error: stepResult.state.error,
          stack: stepResult.state.stack.map(s => s.toString()),
          registers: Object.fromEntries(
            Object.entries(stepResult.state.registers).map(([k, v]) => [k, v.toString()])
          )
        }
        break
      }

      case 'vm.run': {
        const runResult = engineManager.run()
        result = {
          stepsExecuted: runResult.stepsExecuted,
          reason: runResult.reason,
          state: {
            vip: runResult.state.vip.toString(),
            vsp: runResult.state.vsp,
            halted: runResult.state.halted,
            error: runResult.state.error,
            stack: runResult.state.stack.map(s => s.toString())
          }
        }
        break
      }

      case 'vm.stop': {
        engineManager.stop()
        result = { success: true }
        break
      }

      case 'vm.reset': {
        engineManager.reset()
        result = { success: true }
        break
      }

      // ─── Emulation State ───
      case 'vm.getState': {
        const engine = engineManager.getEngine()
        if (!engine) {
          throw new Error('No binary loaded')
        }
        const state = engine.getStateManager().getState()
        result = {
          vip: state.vip.toString(),
          vsp: state.vsp,
          halted: state.halted,
          error: state.error,
          stack: state.stack.map(s => s.toString()),
          registers: Object.fromEntries(
            Object.entries(state.registers).map(([k, v]) => [k, v.toString()])
          ),
          flags: state.flags
        }
        break
      }

      case 'vm.setState': {
        const engine = engineManager.getEngine()
        if (!engine) {
          throw new Error('No binary loaded')
        }
        const stateManager = engine.getStateManager()

        if (params.registers) {
          for (const [reg, val] of Object.entries(params.registers)) {
            stateManager.setReg(reg, BigInt(val as string))
          }
        }
        if (params.vip) {
          stateManager.setVIP(Number(params.vip))
        }
        if (params.vsp) {
          stateManager.setVSP(Number(params.vsp))
        }
        if (params.stack) {
          const stackList = (params.stack as string[]).map(s => BigInt(s))
          const st = stateManager.getState()
          st.stack = stackList
          stateManager.setState(st)
        }

        result = { success: true }
        break
      }

      // ─── Analysis Data ───
      case 'vm.getBinaryInfo': {
        const info = engineManager.getBinaryInfo()
        if (!info) {
          throw new Error('No binary loaded')
        }
        result = info
        break
      }

      case 'vm.getCFG': {
        const engine = engineManager.getEngine()
        if (!engine) {
          throw new Error('No binary loaded')
        }
        result = engineManager.getVMModel().cfg
        break
      }

      case 'vm.getTrace': {
        const engine = engineManager.getEngine()
        if (!engine) {
          throw new Error('No binary loaded')
        }
        const trace = engine.getTraceRecorder().getAll()
        result = trace.map(t => ({
          ...t,
          address: t.address.toString(),
          stackDelta: t.stackDelta,
          registersChanged: t.registersChanged,
          flagsChanged: t.flagsChanged
        }))
        break
      }

      case 'vm.getHandlers': {
        const engine = engineManager.getEngine()
        if (!engine) {
          throw new Error('No binary loaded')
        }
        result = engine.getHandlers().map(h => ({
          id: h.id,
          address: h.address.toString(),
          endAddress: h.endAddress.toString(),
          size: h.size,
          opcodeValue: h.opcodeValue,
          label: h.label,
          hypothesis: h.hypothesis,
          executionCount: h.executionCount
        }))
        break
      }

      case 'vm.setHandlerLabel': {
        const address = Number(params?.address)
        const label = params?.label || ''
        if (isNaN(address)) {
          throw new Error('Invalid address')
        }
        engineManager.setHandlerLabel(address, label)
        result = { success: true }
        break
      }

      case 'vm.setHandlerHypothesis': {
        const address = Number(params?.address)
        const hypothesis = params?.hypothesis || ''
        if (isNaN(address)) {
          throw new Error('Invalid address')
        }
        engineManager.setHandlerHypothesis(address, hypothesis)
        result = { success: true }
        break
      }

      default:
        sendError(plugin, -32601, `Method '${method}' not found`, id)
        return
    }

    if (hasId) {
      sendResult(plugin, result, id)
    }

  } catch (error: any) {
    if (hasId) {
      sendError(plugin, -32000, error.message || 'Internal server error', id)
    }
  }
}

// ─── Push Events to Subscribed Plugins ───────────────────────────────────

export function notifyPluginEvent(eventName: string, payload: any): void {
  const notification = {
    jsonrpc: '2.0',
    method: eventName,
    params: formatBigInts(payload)
  }

  const rawMsg = JSON.stringify(notification)

  for (const [id, plugin] of connectedPlugins) {
    if (plugin.subscriptions.has(eventName) || plugin.subscriptions.has('*')) {
      try {
        plugin.ws.send(rawMsg)
        logMessage(plugin.id, plugin.name, 'out', rawMsg)
      } catch (err) {
        console.error(`Failed to notify plugin ${plugin.name}:`, err)
      }
    }
  }
}

// ─── Helpers ────────────────────────────────────────────────────────

function sendResult(plugin: ConnectedPlugin, result: any, id: number | string | null): void {
  const response: JsonRpcResponse = {
    jsonrpc: '2.0',
    result: formatBigInts(result),
    id
  }
  const rawResponse = JSON.stringify(response)
  plugin.ws.send(rawResponse)
  logMessage(plugin.id, plugin.name, 'out', rawResponse)
}

function sendError(plugin: ConnectedPlugin, code: number, message: string, id: number | string | null): void {
  const response: JsonRpcResponse = {
    jsonrpc: '2.0',
    error: { code, message },
    id
  }
  const rawResponse = JSON.stringify(response)
  plugin.ws.send(rawResponse)
  logMessage(plugin.id, plugin.name, 'out', rawResponse)
}

function logMessage(pluginId: string, pluginName: string, direction: 'in' | 'out', message: string): void {
  const log: PluginLog = {
    timestamp: new Date().toLocaleTimeString(),
    pluginId,
    pluginName,
    direction,
    message
  }

  pluginLogs.push(log)
  if (pluginLogs.length > MAX_LOGS) {
    pluginLogs.shift()
  }

  // Notify UI of new logs
  broadcastLogsToUI()
}

// Serealiza BigInts a strings para JSON
function formatBigInts(obj: any): any {
  if (obj === null || obj === undefined) return obj
  if (typeof obj === 'bigint') return obj.toString()
  if (Array.isArray(obj)) return obj.map(formatBigInts)
  if (typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k, formatBigInts(v)])
    )
  }
  return obj
}

let activeUIWindow: any = null
export function registerUIForPluginUpdates(window: any): void {
  activeUIWindow = window
}

function broadcastPluginsToUI(): void {
  if (activeUIWindow) {
    activeUIWindow.webContents.send('plugin:list-updated', getConnectedPlugins())
  }
}

function broadcastLogsToUI(): void {
  if (activeUIWindow) {
    activeUIWindow.webContents.send('plugin:logs-updated', getPluginLogs())
  }
}

function broadcastProcessesToUI(): void {
  if (activeUIWindow) {
    activeUIWindow.webContents.send('plugin:processes-updated', getLoadedPluginProcesses())
  }
}

// Ensure installer logs are also broadcasted
function broadcastInstallerLog(message: string): void {
  logMessage('system_installer', 'Installer', 'out', message)
}
