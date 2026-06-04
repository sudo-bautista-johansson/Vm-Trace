"use strict";
const electron = require("electron");
const path = require("path");
const fs = require("fs");
require("crypto");
const ws = require("ws");
const child_process = require("child_process");
function _interopNamespaceDefault(e) {
  const n = Object.create(null, { [Symbol.toStringTag]: { value: "Module" } });
  if (e) {
    for (const k in e) {
      if (k !== "default") {
        const d = Object.getOwnPropertyDescriptor(e, k);
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: () => e[k]
        });
      }
    }
  }
  n.default = e;
  return Object.freeze(n);
}
const fs__namespace = /* @__PURE__ */ _interopNamespaceDefault(fs);
const is = {
  dev: !electron.app.isPackaged
};
const platform = {
  isWindows: process.platform === "win32",
  isMacOS: process.platform === "darwin",
  isLinux: process.platform === "linux"
};
const electronApp = {
  setAppUserModelId(id) {
    if (platform.isWindows)
      electron.app.setAppUserModelId(is.dev ? process.execPath : id);
  },
  setAutoLaunch(auto) {
    if (platform.isLinux)
      return false;
    const isOpenAtLogin = () => {
      return electron.app.getLoginItemSettings().openAtLogin;
    };
    if (isOpenAtLogin() !== auto) {
      electron.app.setLoginItemSettings({
        openAtLogin: auto,
        path: process.execPath
      });
      return isOpenAtLogin() === auto;
    } else {
      return true;
    }
  },
  skipProxy() {
    return electron.session.defaultSession.setProxy({ mode: "direct" });
  }
};
const optimizer = {
  watchWindowShortcuts(window, shortcutOptions) {
    if (!window)
      return;
    const { webContents } = window;
    const { escToCloseWindow = false, zoom = false } = shortcutOptions || {};
    webContents.on("before-input-event", (event, input) => {
      if (input.type === "keyDown") {
        if (!is.dev) {
          if (input.code === "KeyR" && (input.control || input.meta))
            event.preventDefault();
        } else {
          if (input.code === "F12") {
            if (webContents.isDevToolsOpened()) {
              webContents.closeDevTools();
            } else {
              webContents.openDevTools({ mode: "undocked" });
              console.log("Open dev tool...");
            }
          }
        }
        if (escToCloseWindow) {
          if (input.code === "Escape" && input.key !== "Process") {
            window.close();
            event.preventDefault();
          }
        }
        if (!zoom) {
          if (input.code === "Minus" && (input.control || input.meta))
            event.preventDefault();
          if (input.code === "Equal" && input.shift && (input.control || input.meta))
            event.preventDefault();
        }
      }
    });
  },
  registerFramelessWindowIpc() {
    electron.ipcMain.on("win:invoke", (event, action) => {
      const win = electron.BrowserWindow.fromWebContents(event.sender);
      if (win) {
        if (action === "show") {
          win.show();
        } else if (action === "showInactive") {
          win.showInactive();
        } else if (action === "min") {
          win.minimize();
        } else if (action === "max") {
          const isMaximized = win.isMaximized();
          if (isMaximized) {
            win.unmaximize();
          } else {
            win.maximize();
          }
        } else if (action === "close") {
          win.close();
        }
      }
    });
  }
};
var InstructionType = /* @__PURE__ */ ((InstructionType2) => {
  InstructionType2["ControlFlow"] = "control_flow";
  InstructionType2["Stack"] = "stack";
  InstructionType2["Arithmetic"] = "arithmetic";
  InstructionType2["Logic"] = "logic";
  InstructionType2["Memory"] = "memory";
  InstructionType2["Comparison"] = "comparison";
  InstructionType2["System"] = "system";
  InstructionType2["Suspicious"] = "suspicious";
  InstructionType2["String"] = "string";
  InstructionType2["Nop"] = "nop";
  InstructionType2["Unknown"] = "unknown";
  return InstructionType2;
})(InstructionType || {});
function createDefaultVMState() {
  return {
    vip: 0,
    vsp: 0,
    stack: [],
    registers: {},
    flags: { ZF: false, CF: false, SF: false, OF: false, PF: false, AF: false },
    memory: /* @__PURE__ */ new Map(),
    halted: false
  };
}
function createDefaultFlags() {
  return { ZF: false, CF: false, SF: false, OF: false, PF: false, AF: false };
}
class VMStateManager {
  constructor() {
    this.snapshots = [];
    this.maxSnapshots = 1e4;
    this.state = createDefaultVMState();
  }
  // ─── State Access ───────────────────────────────────────────────────
  getState() {
    return this.cloneState(this.state);
  }
  setState(state) {
    this.state = this.cloneState(state);
  }
  reset() {
    this.state = createDefaultVMState();
    this.snapshots = [];
  }
  // ─── VIP (Virtual Instruction Pointer) ──────────────────────────────
  getVIP() {
    return this.state.vip;
  }
  setVIP(addr) {
    this.state.vip = addr;
  }
  advanceVIP(delta) {
    this.state.vip += delta;
  }
  // ─── VSP (Virtual Stack Pointer) ────────────────────────────────────
  getVSP() {
    return this.state.vsp;
  }
  setVSP(addr) {
    this.state.vsp = addr;
  }
  // ─── Stack Operations ───────────────────────────────────────────────
  push(value) {
    this.state.stack.unshift(value);
    this.state.vsp += 8;
  }
  pop() {
    if (this.state.stack.length === 0) {
      this.state.error = "Stack underflow";
      return 0n;
    }
    this.state.vsp -= 8;
    return this.state.stack.shift();
  }
  peek(depth = 0) {
    if (depth >= this.state.stack.length) return 0n;
    return this.state.stack[depth];
  }
  getStackDepth() {
    return this.state.stack.length;
  }
  getStack() {
    return [...this.state.stack];
  }
  // ─── Register Operations ────────────────────────────────────────────
  getReg(name) {
    return this.state.registers[name] ?? 0n;
  }
  setReg(name, value) {
    this.state.registers[name] = value;
  }
  getRegisters() {
    return { ...this.state.registers };
  }
  initRegisters(names) {
    for (const name of names) {
      if (!(name in this.state.registers)) {
        this.state.registers[name] = 0n;
      }
    }
  }
  // ─── Flag Operations ────────────────────────────────────────────────
  getFlags() {
    return { ...this.state.flags };
  }
  setFlags(flags) {
    Object.assign(this.state.flags, flags);
  }
  getFlag(name) {
    return this.state.flags[name];
  }
  setFlag(name, value) {
    this.state.flags[name] = value;
  }
  /**
   * Update arithmetic flags based on a result value
   */
  updateArithFlags(result, operandSize = 64) {
    const mask = operandSize === 64 ? 0xFFFFFFFFFFFFFFFFn : operandSize === 32 ? 0xFFFFFFFFn : operandSize === 16 ? 0xFFFFn : 0xFFn;
    const signBit = operandSize === 64 ? 0x8000000000000000n : operandSize === 32 ? 0x80000000n : operandSize === 16 ? 0x8000n : 0x80n;
    const masked = result & mask;
    this.state.flags.ZF = masked === 0n;
    this.state.flags.SF = (masked & signBit) !== 0n;
    let parity = Number(masked & 0xFFn);
    parity ^= parity >> 4;
    parity ^= parity >> 2;
    parity ^= parity >> 1;
    this.state.flags.PF = (parity & 1) === 0;
  }
  // ─── Virtual Memory ─────────────────────────────────────────────────
  readMemory(address) {
    return this.state.memory.get(address) ?? 0;
  }
  writeMemory(address, value) {
    this.state.memory.set(address, value & 255);
  }
  readMemory32(address) {
    let value = 0;
    for (let i = 0; i < 4; i++) {
      value |= this.readMemory(address + i) << i * 8;
    }
    return value >>> 0;
  }
  writeMemory32(address, value) {
    for (let i = 0; i < 4; i++) {
      this.writeMemory(address + i, value >> i * 8 & 255);
    }
  }
  readMemory64(address) {
    let value = 0n;
    for (let i = 0; i < 8; i++) {
      value |= BigInt(this.readMemory(address + i)) << BigInt(i * 8);
    }
    return value;
  }
  writeMemory64(address, value) {
    for (let i = 0; i < 8; i++) {
      this.writeMemory(address + i, Number(value >> BigInt(i * 8) & 0xFFn));
    }
  }
  // ─── Halt ───────────────────────────────────────────────────────────
  halt(error) {
    this.state.halted = true;
    if (error) this.state.error = error;
  }
  isHalted() {
    return this.state.halted;
  }
  getError() {
    return this.state.error;
  }
  // ─── Snapshots ──────────────────────────────────────────────────────
  saveSnapshot() {
    if (this.snapshots.length >= this.maxSnapshots) {
      this.snapshots.shift();
    }
    this.snapshots.push(this.cloneState(this.state));
  }
  restoreSnapshot() {
    const snapshot = this.snapshots.pop();
    if (!snapshot) return false;
    this.state = snapshot;
    return true;
  }
  getSnapshotCount() {
    return this.snapshots.length;
  }
  // ─── Diff ───────────────────────────────────────────────────────────
  /**
   * Compare two states and return which registers/flags changed
   */
  static diff(before, after) {
    const registersChanged = [];
    const allKeys = /* @__PURE__ */ new Set([...Object.keys(before.registers), ...Object.keys(after.registers)]);
    for (const key of allKeys) {
      if ((before.registers[key] ?? 0n) !== (after.registers[key] ?? 0n)) {
        registersChanged.push(key);
      }
    }
    const flagsChanged = [];
    for (const key of ["ZF", "CF", "SF", "OF", "PF", "AF"]) {
      if (before.flags[key] !== after.flags[key]) {
        flagsChanged.push(key);
      }
    }
    return {
      registersChanged,
      flagsChanged,
      stackDelta: after.stack.length - before.stack.length
    };
  }
  // ─── Serialization ─────────────────────────────────────────────────
  serialize() {
    return {
      vip: this.state.vip,
      vsp: this.state.vsp,
      stack: this.state.stack.map((v) => v.toString()),
      registers: Object.fromEntries(
        Object.entries(this.state.registers).map(([k, v]) => [k, v.toString()])
      ),
      flags: { ...this.state.flags },
      memory: Object.fromEntries(this.state.memory),
      halted: this.state.halted,
      error: this.state.error
    };
  }
  deserialize(obj) {
    this.state = {
      vip: obj.vip ?? 0,
      vsp: obj.vsp ?? 0,
      stack: (obj.stack ?? []).map((v) => BigInt(v)),
      registers: Object.fromEntries(
        Object.entries(obj.registers ?? {}).map(([k, v]) => [k, BigInt(v)])
      ),
      flags: obj.flags ?? createDefaultFlags(),
      memory: new Map(Object.entries(obj.memory ?? {}).map(([k, v]) => [Number(k), v])),
      halted: obj.halted ?? false,
      error: obj.error
    };
  }
  // ─── Internal ───────────────────────────────────────────────────────
  cloneState(state) {
    return {
      vip: state.vip,
      vsp: state.vsp,
      stack: [...state.stack],
      registers: { ...state.registers },
      flags: { ...state.flags },
      memory: new Map(state.memory),
      halted: state.halted,
      error: state.error
    };
  }
}
class TraceRecorder {
  constructor() {
    this.entries = [];
    this.maxEntries = 5e5;
    this.isRecording = true;
  }
  // ─── Recording ──────────────────────────────────────────────────────
  record(entry) {
    if (!this.isRecording) return;
    if (this.entries.length >= this.maxEntries) {
      this.entries.splice(0, Math.floor(this.maxEntries * 0.1));
    }
    this.entries.push(entry);
  }
  pause() {
    this.isRecording = false;
  }
  resume() {
    this.isRecording = true;
  }
  isPaused() {
    return !this.isRecording;
  }
  // ─── Access ─────────────────────────────────────────────────────────
  getAll() {
    return this.entries;
  }
  getFiltered(filter) {
    let result = this.entries;
    if (filter.handlerIds && filter.handlerIds.length > 0) {
      const ids = new Set(filter.handlerIds);
      result = result.filter((e) => e.handlerId && ids.has(e.handlerId));
    }
    if (filter.opcodeValues && filter.opcodeValues.length > 0) {
      const opcodes = new Set(filter.opcodeValues);
      result = result.filter((e) => opcodes.has(e.opcodeValue));
    }
    if (filter.addressRange) {
      const { start, end } = filter.addressRange;
      result = result.filter((e) => e.address >= start && e.address <= end);
    }
    if (filter.onlyStackChanges) {
      result = result.filter((e) => e.stackDelta !== 0);
    }
    if (filter.onlyControlFlow) {
      result = result.filter((e) => {
        const label = (e.handlerLabel || "").toUpperCase();
        return [
          "JMP",
          "JZ",
          "JNZ",
          "JE",
          "JNE",
          "CALL",
          "RET",
          "JB",
          "JA",
          "JL",
          "JG",
          "JBE",
          "JAE",
          "JLE",
          "JGE"
        ].includes(label);
      });
    }
    return result;
  }
  getEntry(index) {
    return this.entries[index];
  }
  getLastN(n) {
    return this.entries.slice(-n);
  }
  getCount() {
    return this.entries.length;
  }
  // ─── Analysis ───────────────────────────────────────────────────────
  /**
   * Get handler execution frequency
   */
  getHandlerFrequency() {
    const freq = /* @__PURE__ */ new Map();
    for (const entry of this.entries) {
      const key = entry.handlerLabel || entry.handlerId || `OP_${entry.opcodeValue.toString(16)}`;
      freq.set(key, (freq.get(key) || 0) + 1);
    }
    return freq;
  }
  /**
   * Get opcode frequency
   */
  getOpcodeFrequency() {
    const freq = /* @__PURE__ */ new Map();
    for (const entry of this.entries) {
      freq.set(entry.opcodeValue, (freq.get(entry.opcodeValue) || 0) + 1);
    }
    return freq;
  }
  /**
   * Find loops: sequences of addresses that repeat
   */
  findLoops(minIterations = 3) {
    const loops = [];
    const addresses = this.entries.map((e) => e.address);
    for (let windowSize = 2; windowSize <= 20; windowSize++) {
      for (let i = 0; i <= addresses.length - windowSize * minIterations; i++) {
        const pattern = addresses.slice(i, i + windowSize);
        let iterations = 1;
        let j = i + windowSize;
        while (j + windowSize <= addresses.length) {
          const next = addresses.slice(j, j + windowSize);
          if (pattern.every((v, k) => v === next[k])) {
            iterations++;
            j += windowSize;
          } else {
            break;
          }
        }
        if (iterations >= minIterations) {
          const exists = loops.some(
            (l) => l.addresses.length === pattern.length && l.addresses.every((v, k) => v === pattern[k])
          );
          if (!exists) {
            loops.push({ addresses: pattern, count: iterations });
          }
          i = j - 1;
        }
      }
    }
    return loops;
  }
  /**
   * Find unique execution paths (sequences of distinct handler IDs)
   */
  getUniquePaths(maxLength = 10) {
    const paths = [];
    const seen = /* @__PURE__ */ new Set();
    for (let i = 0; i <= this.entries.length - maxLength; i++) {
      const path2 = this.entries.slice(i, i + maxLength).map((e) => e.handlerLabel || e.handlerId || `OP_${e.opcodeValue.toString(16)}`);
      const key = path2.join(",");
      if (!seen.has(key)) {
        seen.add(key);
        paths.push(path2);
      }
    }
    return paths;
  }
  // ─── Export ─────────────────────────────────────────────────────────
  exportJSON() {
    return JSON.stringify(this.entries, (key, value) => typeof value === "bigint" ? value.toString() : value, 2);
  }
  exportCSV() {
    const header = "Index,Timestamp,Address,Opcode,Handler,Label,Mnemonic,StackDelta,RegsChanged,FlagsChanged\n";
    const rows = this.entries.map(
      (e) => `${e.index},${e.timestamp},0x${e.address.toString(16)},0x${e.opcodeValue.toString(16)},${e.handlerId || ""},${e.handlerLabel || ""},${e.mnemonic || ""},${e.stackDelta},${e.registersChanged.join(";")},${e.flagsChanged.join(";")}`
    ).join("\n");
    return header + rows;
  }
  exportText() {
    return this.entries.map((e) => {
      const addr = `0x${e.address.toString(16).padStart(8, "0")}`;
      const op = `0x${e.opcodeValue.toString(16).padStart(2, "0")}`;
      const label = e.handlerLabel || e.handlerId || "???";
      const mnemonic = e.mnemonic || "";
      const changes = [];
      if (e.stackDelta !== 0) changes.push(`stack:${e.stackDelta > 0 ? "+" : ""}${e.stackDelta}`);
      if (e.registersChanged.length) changes.push(`regs:[${e.registersChanged.join(",")}]`);
      if (e.flagsChanged.length) changes.push(`flags:[${e.flagsChanged.join(",")}]`);
      return `[${e.index.toString().padStart(6)}] ${addr}  ${op}  ${label.padEnd(12)} ${mnemonic.padEnd(8)} ${changes.join(" ")}`;
    }).join("\n");
  }
  // ─── Lifecycle ──────────────────────────────────────────────────────
  clear() {
    this.entries = [];
  }
  setMaxEntries(max) {
    this.maxEntries = max;
  }
  serialize() {
    return this.entries;
  }
  deserialize(data) {
    this.entries = data;
  }
}
const DEFAULT_CONFIG$1 = {
  maxSteps: 1e5,
  opcodeSize: 1,
  registerNames: ["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
  initialVIP: 0
};
class VMEngine {
  constructor(config) {
    this.handlers = /* @__PURE__ */ new Map();
    this.opcodeMap = [];
    this.dispatcher = null;
    this.bytecode = null;
    this.bytecodeBase = 0;
    this.running = false;
    this.stepCount = 0;
    this.breakpoints = /* @__PURE__ */ new Set();
    this.handlerExecutors = /* @__PURE__ */ new Map();
    this.config = { ...DEFAULT_CONFIG$1, ...config };
    this.stateManager = new VMStateManager();
    this.traceRecorder = new TraceRecorder();
  }
  // ─── Setup ──────────────────────────────────────────────────────────
  /**
   * Set the bytecode to execute
   */
  setBytecode(data, baseAddress) {
    this.bytecode = data;
    this.bytecodeBase = baseAddress;
    this.stateManager.setVIP(this.config.initialVIP);
    this.stateManager.initRegisters(this.config.registerNames);
  }
  /**
   * Set the dispatcher info
   */
  setDispatcher(dispatcher) {
    this.dispatcher = dispatcher;
  }
  /**
   * Register a handler
   */
  registerHandler(handler) {
    this.handlers.set(handler.opcodeValue, handler);
  }
  /**
   * Set all handlers at once
   */
  setHandlers(handlers) {
    this.handlers.clear();
    for (const h of handlers) {
      this.handlers.set(h.opcodeValue, h);
    }
  }
  /**
   * Register a custom executor for a labeled handler
   */
  registerExecutor(label, executor) {
    this.handlerExecutors.set(label, executor);
  }
  /**
   * Add a breakpoint at a VIP address
   */
  addBreakpoint(vip) {
    this.breakpoints.add(vip);
  }
  removeBreakpoint(vip) {
    this.breakpoints.delete(vip);
  }
  // ─── Execution ──────────────────────────────────────────────────────
  /**
   * Execute a single step
   */
  step() {
    if (!this.bytecode) {
      this.stateManager.halt("No bytecode loaded");
      return { state: this.stateManager.getState(), traceEntry: null };
    }
    if (this.stateManager.isHalted()) {
      return { state: this.stateManager.getState(), traceEntry: null };
    }
    const vip = this.stateManager.getVIP();
    const relativeVip = vip - this.bytecodeBase;
    if (relativeVip < 0 || relativeVip + this.config.opcodeSize > this.bytecode.length) {
      this.stateManager.halt(`VIP out of bounds: 0x${vip.toString(16)}`);
      return { state: this.stateManager.getState(), traceEntry: null };
    }
    let opcodeValue = 0;
    for (let i = 0; i < this.config.opcodeSize; i++) {
      opcodeValue |= this.bytecode[relativeVip + i] << i * 8;
    }
    const stateBefore = this.stateManager.getState();
    const handler = this.handlers.get(opcodeValue);
    if (handler) {
      handler.executionCount++;
      if (handler.label && this.handlerExecutors.has(handler.label)) {
        this.handlerExecutors.get(handler.label)(this);
      } else {
        this.executeDefaultHandler(handler, opcodeValue);
      }
    } else {
      this.stateManager.advanceVIP(this.config.opcodeSize);
    }
    const stateAfter = this.stateManager.getState();
    const diff = VMStateManager.diff(stateBefore, stateAfter);
    const traceEntry = {
      index: this.stepCount++,
      timestamp: Date.now(),
      address: vip,
      opcodeValue,
      handlerId: handler?.id,
      handlerLabel: handler?.label,
      mnemonic: handler?.label ?? `OP_${opcodeValue.toString(16).toUpperCase()}`,
      operands: "",
      stackDelta: diff.stackDelta,
      registersChanged: diff.registersChanged,
      flagsChanged: diff.flagsChanged
    };
    this.traceRecorder.record(traceEntry);
    return { state: stateAfter, traceEntry };
  }
  /**
   * Default handler execution — read operands based on opcode size, advance VIP
   */
  executeDefaultHandler(handler, opcodeValue) {
    this.stateManager.advanceVIP(this.config.opcodeSize);
  }
  /**
   * Run until halted, breakpoint, or max steps
   */
  run() {
    this.running = true;
    let stepsExecuted = 0;
    while (this.running && !this.stateManager.isHalted() && stepsExecuted < this.config.maxSteps) {
      const vip = this.stateManager.getVIP();
      if (stepsExecuted > 0 && this.breakpoints.has(vip)) {
        this.running = false;
        return { state: this.stateManager.getState(), stepsExecuted, reason: "breakpoint" };
      }
      this.step();
      stepsExecuted++;
    }
    this.running = false;
    let reason = "completed";
    if (this.stateManager.isHalted()) reason = this.stateManager.getError() || "halted";
    else if (stepsExecuted >= this.config.maxSteps) reason = "max_steps_reached";
    return { state: this.stateManager.getState(), stepsExecuted, reason };
  }
  /**
   * Run until a specific handler is executed
   */
  runUntilHandler(handlerId) {
    this.running = true;
    let stepsExecuted = 0;
    while (this.running && !this.stateManager.isHalted() && stepsExecuted < this.config.maxSteps) {
      const result = this.step();
      stepsExecuted++;
      if (result.traceEntry?.handlerId === handlerId) {
        this.running = false;
        return { state: this.stateManager.getState(), stepsExecuted, reason: "handler_reached" };
      }
    }
    this.running = false;
    return { state: this.stateManager.getState(), stepsExecuted, reason: "not_found" };
  }
  /**
   * Run until VIP reaches a specific address
   */
  runUntilAddress(address) {
    this.running = true;
    let stepsExecuted = 0;
    while (this.running && !this.stateManager.isHalted() && stepsExecuted < this.config.maxSteps) {
      this.step();
      stepsExecuted++;
      if (this.stateManager.getVIP() === address) {
        this.running = false;
        return { state: this.stateManager.getState(), stepsExecuted, reason: "address_reached" };
      }
    }
    this.running = false;
    return { state: this.stateManager.getState(), stepsExecuted, reason: "not_reached" };
  }
  /**
   * Stop execution
   */
  stop() {
    this.running = false;
  }
  /**
   * Reset the engine
   */
  reset() {
    this.running = false;
    this.stepCount = 0;
    this.stateManager.reset();
    this.stateManager.setVIP(this.config.initialVIP);
    this.stateManager.initRegisters(this.config.registerNames);
    this.traceRecorder.clear();
    for (const handler of this.handlers.values()) {
      handler.executionCount = 0;
    }
  }
  // ─── Accessors ──────────────────────────────────────────────────────
  getStateManager() {
    return this.stateManager;
  }
  getTraceRecorder() {
    return this.traceRecorder;
  }
  getHandlers() {
    return Array.from(this.handlers.values());
  }
  getHandler(opcodeValue) {
    return this.handlers.get(opcodeValue);
  }
  getHandlerById(id) {
    for (const h of this.handlers.values()) {
      if (h.id === id) return h;
    }
    return void 0;
  }
  getDispatcher() {
    return this.dispatcher;
  }
  isRunning() {
    return this.running;
  }
  getStepCount() {
    return this.stepCount;
  }
  getConfig() {
    return { ...this.config };
  }
  getBytecode() {
    return this.bytecode;
  }
  getBytecodeBase() {
    return this.bytecodeBase;
  }
  /**
   * Expose state manager methods for handler executors
   */
  push(value) {
    this.stateManager.push(value);
  }
  pop() {
    return this.stateManager.pop();
  }
  getReg(name) {
    return this.stateManager.getReg(name);
  }
  setReg(name, value) {
    this.stateManager.setReg(name, value);
  }
  getVIP() {
    return this.stateManager.getVIP();
  }
  setVIP(addr) {
    this.stateManager.setVIP(addr);
  }
  advanceVIP(delta) {
    this.stateManager.advanceVIP(delta);
  }
  getFlags() {
    return this.stateManager.getFlags();
  }
  setFlags(flags) {
    this.stateManager.setFlags(flags);
  }
  /**
   * Read a value from bytecode at the current VIP + offset
   */
  readBytecodeU8(offset = 0) {
    if (!this.bytecode) return 0;
    const pos = this.stateManager.getVIP() - this.bytecodeBase + offset;
    if (pos < 0 || pos >= this.bytecode.length) return 0;
    return this.bytecode[pos];
  }
  readBytecodeU16(offset = 0) {
    return this.readBytecodeU8(offset) | this.readBytecodeU8(offset + 1) << 8;
  }
  readBytecodeU32(offset = 0) {
    return (this.readBytecodeU8(offset) | this.readBytecodeU8(offset + 1) << 8 | this.readBytecodeU8(offset + 2) << 16 | this.readBytecodeU8(offset + 3) << 24) >>> 0;
  }
  /**
   * Register built-in handler executors for common VM operations
   */
  registerBuiltinExecutors() {
    this.registerExecutor("PUSH", (e) => {
      const imm = BigInt(e.readBytecodeU32(e.getConfig().opcodeSize));
      e.push(imm);
      e.advanceVIP(e.getConfig().opcodeSize + 4);
    });
    this.registerExecutor("POP", (e) => {
      e.pop();
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("ADD", (e) => {
      const b = e.pop();
      const a = e.pop();
      const result = a + b;
      e.push(result);
      e.getStateManager().updateArithFlags(result);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("SUB", (e) => {
      const b = e.pop();
      const a = e.pop();
      const result = a - b;
      e.push(result);
      e.getStateManager().updateArithFlags(result);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("MUL", (e) => {
      const b = e.pop();
      const a = e.pop();
      e.push(a * b);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("XOR", (e) => {
      const b = e.pop();
      const a = e.pop();
      const result = a ^ b;
      e.push(result);
      e.getStateManager().updateArithFlags(result);
      e.setFlags({ CF: false, OF: false });
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("AND", (e) => {
      const b = e.pop();
      const a = e.pop();
      const result = a & b;
      e.push(result);
      e.getStateManager().updateArithFlags(result);
      e.setFlags({ CF: false, OF: false });
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("OR", (e) => {
      const b = e.pop();
      const a = e.pop();
      const result = a | b;
      e.push(result);
      e.getStateManager().updateArithFlags(result);
      e.setFlags({ CF: false, OF: false });
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("NOT", (e) => {
      const a = e.pop();
      e.push(~a);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("NEG", (e) => {
      const a = e.pop();
      e.push(-a);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("SHL", (e) => {
      const shift = e.pop();
      const val = e.pop();
      e.push(val << shift);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("SHR", (e) => {
      const shift = e.pop();
      const val = e.pop();
      if (val >= 0n) {
        e.push(val >> shift);
      } else {
        e.push(val >> shift);
      }
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("CMP", (e) => {
      const b = e.pop();
      const a = e.pop();
      e.push(a === b ? 1n : 0n);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("CMP_NE", (e) => {
      const b = e.pop();
      const a = e.pop();
      e.push(a !== b ? 1n : 0n);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("CMP_LT", (e) => {
      const b = e.pop();
      const a = e.pop();
      e.push(a < b ? 1n : 0n);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("CMP_LE", (e) => {
      const b = e.pop();
      const a = e.pop();
      e.push(a <= b ? 1n : 0n);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("CMP_GT", (e) => {
      const b = e.pop();
      const a = e.pop();
      e.push(a > b ? 1n : 0n);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("CMP_GE", (e) => {
      const b = e.pop();
      const a = e.pop();
      e.push(a >= b ? 1n : 0n);
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("JMP", (e) => {
      const displacement = e.readBytecodeU32(e.getConfig().opcodeSize) | 0;
      const nextVip = e.getVIP() + e.getConfig().opcodeSize + 4;
      e.setVIP(nextVip + displacement);
    });
    this.registerExecutor("JZ", (e) => {
      const displacement = e.readBytecodeU32(e.getConfig().opcodeSize) | 0;
      const top = e.getStateManager().peek();
      const nextVip = e.getVIP() + e.getConfig().opcodeSize + 4;
      if (top === 0n) {
        e.setVIP(nextVip + displacement);
      } else {
        e.advanceVIP(e.getConfig().opcodeSize + 4);
      }
    });
    this.registerExecutor("JNZ", (e) => {
      const displacement = e.readBytecodeU32(e.getConfig().opcodeSize) | 0;
      const top = e.getStateManager().peek();
      const nextVip = e.getVIP() + e.getConfig().opcodeSize + 4;
      if (top !== 0n) {
        e.setVIP(nextVip + displacement);
      } else {
        e.advanceVIP(e.getConfig().opcodeSize + 4);
      }
    });
    this.registerExecutor("LOAD", (e) => {
      const regIdx = e.readBytecodeU8(e.getConfig().opcodeSize);
      const regName = `v${regIdx}`;
      e.push(e.getReg(regName));
      e.advanceVIP(e.getConfig().opcodeSize + 1);
    });
    this.registerExecutor("STORE", (e) => {
      const regIdx = e.readBytecodeU8(e.getConfig().opcodeSize);
      const regName = `v${regIdx}`;
      e.setReg(regName, e.pop());
      e.advanceVIP(e.getConfig().opcodeSize + 1);
    });
    this.registerExecutor("NOP", (e) => {
      e.advanceVIP(e.getConfig().opcodeSize);
    });
    this.registerExecutor("HALT", (e) => {
      e.getStateManager().halt("VM halted by HALT instruction");
    });
    this.registerExecutor("RET", (e) => {
      const retAddr = Number(e.pop());
      e.setVIP(retAddr);
    });
    this.registerExecutor("CALL", (e) => {
      const displacement = e.readBytecodeU32(e.getConfig().opcodeSize) | 0;
      const nextVip = e.getVIP() + e.getConfig().opcodeSize + 4;
      const retAddr = nextVip;
      e.push(BigInt(retAddr));
      e.setVIP(nextVip + displacement);
    });
  }
  // ─── Additional Public Methods for RealtimeExecutor ──────────────────
  /**
   * Get breakpoints set
   */
  getBreakpoints() {
    return this.breakpoints;
  }
  /**
   * Read 8-bit value from bytecode at offset
   */
  readBytecodeU8(offset) {
    if (!this.bytecode) return 0;
    const relativeVip = this.stateManager.getVIP() - this.bytecodeBase + offset;
    if (relativeVip < 0 || relativeVip >= this.bytecode.length) return 0;
    return this.bytecode[relativeVip];
  }
  /**
   * Read 32-bit value from bytecode at offset
   */
  readBytecodeU32(offset) {
    if (!this.bytecode) return 0;
    const relativeVip = this.stateManager.getVIP() - this.bytecodeBase + offset;
    if (relativeVip + 4 > this.bytecode.length) return 0;
    return this.bytecode.readUInt32LE(relativeVip);
  }
  /**
   * Set flag values
   */
  setFlags(flags) {
    this.stateManager.setFlags(flags);
  }
  /**
   * Get current flags
   */
  getFlags() {
    return this.stateManager.getFlags();
  }
  /**
   * Set VIP directly
   */
  setVIP(address) {
    this.stateManager.setVIP(address);
  }
  /**
   * Get current VIP
   */
  getVIP() {
    return this.stateManager.getVIP();
  }
  /**
   * Get register value
   */
  getReg(name) {
    return this.stateManager.getReg(name);
  }
  /**
   * Set register value
   */
  setReg(name, value) {
    this.stateManager.setReg(name, value);
  }
  /**
   * Advance VIP by offset
   */
  advanceVIP(offset) {
    this.stateManager.advanceVIP(offset);
  }
}
const MESSAGES = {
  en: {
    // Binary Loading
    "binary.empty": "Binary file is empty",
    "binary.parse_failed": "Failed to parse binary metadata",
    "binary.no_sections": "Binary does not contain any sections",
    "binary.invalid_section_bounds": 'Invalid section bounds for section "{section}"',
    "binary.load_error": 'Failed to load binary "{path}": {error}',
    "binary.no_executable": "Binary does not contain any executable sections",
    // PE Format
    "pe.invalid_mz": "Invalid PE file: Missing MZ signature",
    "pe.header_oob": "Invalid PE file: PE header offset out of bounds",
    "pe.invalid_sig": "Invalid PE file: Missing PE signature",
    // ELF Format
    "elf.invalid_magic": "Invalid ELF file: Missing ELF magic",
    // Section Corruption
    "section.corrupted": 'Section "{section}" appears corrupted: {reason}',
    "section.zero_size": 'Section "{section}" has zero size',
    "section.overlapping": 'Section "{section}" overlaps with section "{other}"',
    "section.file_oob": 'Section "{section}" extends beyond file boundaries',
    "section.invalid_va": 'Section "{section}" has invalid virtual address',
    "section.checksum_failed": 'Section "{section}" checksum validation failed',
    // Execution
    "exec.no_binary": "No binary loaded",
    "exec.vip_oob": "Instruction pointer out of bounds: 0x{vip}",
    "exec.invalid_instruction": "Invalid instruction at 0x{address}",
    "exec.unknown_opcode": "Unknown opcode: 0x{opcode}",
    "exec.stack_underflow": "Stack underflow",
    "exec.div_by_zero": "Division by zero",
    "exec.mod_by_zero": "Modulo by zero",
    // Analysis
    "analysis.phase1_success": "Phase 1 detection found {count} handlers (confidence: {confidence}%)",
    "analysis.phase1_low_confidence": "Phase 1 confidence too low ({confidence}%), falling back to realtime execution",
    "analysis.phase1_failed": "Phase 1 detection failed, falling back to realtime execution",
    "analysis.phase2_success": "Phase 2 semantic analysis built {count}/{total} executors",
    "analysis.phase2_failed": "Phase 2 semantic analysis failed, continuing with Phase 1 only",
    "analysis.phase3_enabled": "Phase 3 realtime bytecode execution enabled"
  },
  es: {
    // Binary Loading
    "binary.empty": "El archivo binario está vacío",
    "binary.parse_failed": "No se pudo analizar los metadatos del binario",
    "binary.no_sections": "El binario no contiene ninguna sección",
    "binary.invalid_section_bounds": 'Límites de sección inválidos para la sección "{section}"',
    "binary.load_error": 'No se pudo cargar el binario "{path}": {error}',
    "binary.no_executable": "El binario no contiene ninguna sección ejecutable",
    // PE Format
    "pe.invalid_mz": "Archivo PE inválido: Falta la firma MZ",
    "pe.header_oob": "Archivo PE inválido: El offset del encabezado PE está fuera de límites",
    "pe.invalid_sig": "Archivo PE inválido: Falta la firma PE",
    // ELF Format
    "elf.invalid_magic": "Archivo ELF inválido: Falta la firma ELF",
    // Section Corruption
    "section.corrupted": 'La sección "{section}" parece corrupta: {reason}',
    "section.zero_size": 'La sección "{section}" tiene tamaño cero',
    "section.overlapping": 'La sección "{section}" se superpone con la sección "{other}"',
    "section.file_oob": 'La sección "{section}" se extiende más allá de los límites del archivo',
    "section.invalid_va": 'La sección "{section}" tiene una dirección virtual inválida',
    "section.checksum_failed": 'Falló la validación de suma de verificación de la sección "{section}"',
    // Execution
    "exec.no_binary": "Ningún binario cargado",
    "exec.vip_oob": "Puntero de instrucción fuera de límites: 0x{vip}",
    "exec.invalid_instruction": "Instrucción inválida en 0x{address}",
    "exec.unknown_opcode": "Opcode desconocido: 0x{opcode}",
    "exec.stack_underflow": "Desbordamiento de pila hacia abajo",
    "exec.div_by_zero": "División por cero",
    "exec.mod_by_zero": "Módulo por cero",
    // Analysis
    "analysis.phase1_success": "Detección Phase 1 encontró {count} handlers (confianza: {confidence}%)",
    "analysis.phase1_low_confidence": "Confianza de Phase 1 demasiado baja ({confidence}%), pasando a ejecución en tiempo real",
    "analysis.phase1_failed": "Detección de Phase 1 falló, pasando a ejecución en tiempo real",
    "analysis.phase2_success": "Análisis semántico Phase 2 construyó {count}/{total} ejecutores",
    "analysis.phase2_failed": "Análisis semántico Phase 2 falló, continuando solo con Phase 1",
    "analysis.phase3_enabled": "Ejecución de bytecode en tiempo real Phase 3 habilitada"
  }
};
let currentLanguage = "en";
function t(key, params) {
  const messages = MESSAGES[currentLanguage];
  let message = messages[key] || key;
  if (params) {
    for (const [paramKey, paramValue] of Object.entries(params)) {
      message = message.replace(new RegExp(`\\{${paramKey}\\}`, "g"), String(paramValue));
    }
  }
  return message;
}
const DOS_MAGIC = 23117;
const PE_SIGNATURE = 17744;
const PE32PLUS_MAGIC = 523;
const IMAGE_SCN_MEM_EXECUTE = 536870912;
const IMAGE_SCN_MEM_READ = 1073741824;
const IMAGE_SCN_MEM_WRITE = 2147483648;
const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
function parsePE(data, filePath) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const dosMagic = view.getUint16(0, true);
  if (dosMagic !== DOS_MAGIC) {
    throw new Error(t("pe.invalid_mz"));
  }
  const peOffset = view.getUint32(60, true);
  if (peOffset + 4 > data.length) {
    throw new Error(t("pe.header_oob"));
  }
  const peSignature = view.getUint32(peOffset, true);
  if (peSignature !== PE_SIGNATURE) {
    throw new Error(t("pe.invalid_sig"));
  }
  const coffOffset = peOffset + 4;
  view.getUint16(coffOffset, true);
  const numberOfSections = view.getUint16(coffOffset + 2, true);
  const timeDateStamp = view.getUint32(coffOffset + 4, true);
  const sizeOfOptionalHeader = view.getUint16(coffOffset + 16, true);
  const optOffset = coffOffset + 20;
  const optMagic = view.getUint16(optOffset, true);
  const is64 = optMagic === PE32PLUS_MAGIC;
  let entryPoint;
  let imageBase;
  let numberOfRvaAndSizes;
  let dataDirectoryOffset;
  if (is64) {
    entryPoint = view.getUint32(optOffset + 16, true);
    imageBase = Number(view.getBigUint64(optOffset + 24, true));
    numberOfRvaAndSizes = view.getUint32(optOffset + 108, true);
    dataDirectoryOffset = optOffset + 112;
  } else {
    entryPoint = view.getUint32(optOffset + 16, true);
    imageBase = view.getUint32(optOffset + 28, true);
    numberOfRvaAndSizes = view.getUint32(optOffset + 92, true);
    dataDirectoryOffset = optOffset + 96;
  }
  const dataDirectories = [];
  for (let i = 0; i < Math.min(numberOfRvaAndSizes, 16); i++) {
    const dirOffset = dataDirectoryOffset + i * 8;
    dataDirectories.push({
      rva: view.getUint32(dirOffset, true),
      size: view.getUint32(dirOffset + 4, true)
    });
  }
  const sectionsOffset = optOffset + sizeOfOptionalHeader;
  const sections = [];
  for (let i = 0; i < numberOfSections; i++) {
    const secOffset = sectionsOffset + i * 40;
    const nameBytes = data.subarray(secOffset, secOffset + 8);
    const name = decodeASCII(nameBytes);
    const virtualSize = view.getUint32(secOffset + 8, true);
    const virtualAddress = view.getUint32(secOffset + 12, true);
    const rawSize = view.getUint32(secOffset + 16, true);
    const rawAddress = view.getUint32(secOffset + 20, true);
    const characteristics = view.getUint32(secOffset + 36, true);
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
    });
  }
  const imports = parseImports(data, view, dataDirectories, sections, is64);
  const exports = parseExports(data, view, dataDirectories, sections);
  validateSections$1(data, sections);
  const architecture = is64 ? "x64" : "x86";
  return {
    path: filePath,
    format: "PE",
    architecture,
    entryPoint: imageBase + entryPoint,
    imageBase,
    sections,
    imports,
    exports,
    fileSize: data.length,
    timestamp: timeDateStamp
  };
}
function parseImports(data, view, dataDirectories, sections, is64) {
  if (dataDirectories.length <= IMAGE_DIRECTORY_ENTRY_IMPORT) return [];
  const importDir = dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (importDir.rva === 0 || importDir.size === 0) return [];
  const importFileOffset = rvaToFileOffset(importDir.rva, sections);
  if (importFileOffset === -1) return [];
  const imports = [];
  let descriptorOffset = importFileOffset;
  while (descriptorOffset + 20 <= data.length) {
    const originalFirstThunk = view.getUint32(descriptorOffset, true);
    const nameRva = view.getUint32(descriptorOffset + 12, true);
    const firstThunk = view.getUint32(descriptorOffset + 16, true);
    if (nameRva === 0) break;
    const nameOffset = rvaToFileOffset(nameRva, sections);
    const dllName = nameOffset !== -1 ? readCString$1(data, nameOffset) : "unknown";
    const functions = [];
    const thunkRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
    let thunkOffset = rvaToFileOffset(thunkRva, sections);
    if (thunkOffset !== -1) {
      const thunkSize = is64 ? 8 : 4;
      let thunkIndex = 0;
      while (thunkOffset + thunkSize <= data.length) {
        const thunkValue = is64 ? Number(view.getBigUint64(thunkOffset, true)) : view.getUint32(thunkOffset, true);
        if (thunkValue === 0) break;
        const isOrdinal = is64 ? (thunkValue & 9223372036854776e3) !== 0 : (thunkValue & 2147483648) !== 0;
        if (isOrdinal) {
          functions.push({
            name: `Ordinal_${thunkValue & 65535}`,
            ordinal: thunkValue & 65535,
            thunkAddress: firstThunk + thunkIndex * thunkSize
          });
        } else {
          const hintNameOffset = rvaToFileOffset(thunkValue & 2147483647, sections);
          if (hintNameOffset !== -1 && hintNameOffset + 2 < data.length) {
            const funcName = readCString$1(data, hintNameOffset + 2);
            functions.push({
              name: funcName,
              thunkAddress: firstThunk + thunkIndex * thunkSize
            });
          }
        }
        thunkOffset += thunkSize;
        thunkIndex++;
        if (thunkIndex > 1e4) break;
      }
    }
    imports.push({ dllName, functions });
    descriptorOffset += 20;
    if (imports.length > 1e3) break;
  }
  return imports;
}
function parseExports(data, view, dataDirectories, sections) {
  if (dataDirectories.length <= IMAGE_DIRECTORY_ENTRY_EXPORT) return [];
  const exportDir = dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (exportDir.rva === 0 || exportDir.size === 0) return [];
  const exportFileOffset = rvaToFileOffset(exportDir.rva, sections);
  if (exportFileOffset === -1) return [];
  view.getUint32(exportFileOffset + 20, true);
  const numberOfNames = view.getUint32(exportFileOffset + 24, true);
  const addressOfFunctions = view.getUint32(exportFileOffset + 28, true);
  const addressOfNames = view.getUint32(exportFileOffset + 32, true);
  const addressOfNameOrdinals = view.getUint32(exportFileOffset + 36, true);
  const ordinalBase = view.getUint32(exportFileOffset + 16, true);
  const funcTableOffset = rvaToFileOffset(addressOfFunctions, sections);
  const nameTableOffset = rvaToFileOffset(addressOfNames, sections);
  const ordinalTableOffset = rvaToFileOffset(addressOfNameOrdinals, sections);
  if (funcTableOffset === -1) return [];
  const exports = [];
  for (let i = 0; i < Math.min(numberOfNames, 1e4); i++) {
    if (nameTableOffset === -1 || ordinalTableOffset === -1) continue;
    const nameRva = view.getUint32(nameTableOffset + i * 4, true);
    const ordinalIndex = view.getUint16(ordinalTableOffset + i * 2, true);
    const funcRva = view.getUint32(funcTableOffset + ordinalIndex * 4, true);
    const nameFileOffset = rvaToFileOffset(nameRva, sections);
    const name = nameFileOffset !== -1 ? readCString$1(data, nameFileOffset) : `Ordinal_${ordinalIndex + ordinalBase}`;
    exports.push({
      name,
      ordinal: ordinalIndex + ordinalBase,
      address: funcRva
    });
  }
  return exports;
}
function validateSections$1(data, sections) {
  for (let i = 0; i < sections.length; i++) {
    const sec = sections[i];
    if (sec.rawSize === 0 && sec.virtualSize > 0) {
      console.warn(t("section.corrupted", { section: sec.name, reason: t("section.zero_size", { section: sec.name }) }));
    }
    if (sec.rawAddress + sec.rawSize > data.length) {
      throw new Error(t("section.corrupted", {
        section: sec.name,
        reason: t("section.file_oob", { section: sec.name })
      }));
    }
    for (let j = i + 1; j < sections.length; j++) {
      const other = sections[j];
      if (sec.rawAddress < other.rawAddress + other.rawSize && sec.rawAddress + sec.rawSize > other.rawAddress) {
        console.warn(t("section.corrupted", {
          section: sec.name,
          reason: t("section.overlapping", { section: sec.name, other: other.name })
        }));
      }
    }
    if (sec.virtualAddress === 0 && sec.isExecutable) {
      console.warn(t("section.corrupted", {
        section: sec.name,
        reason: t("section.invalid_va", { section: sec.name })
      }));
    }
  }
}
function rvaToFileOffset(rva, sections) {
  for (const section of sections) {
    if (rva >= section.virtualAddress && rva < section.virtualAddress + Math.max(section.virtualSize, section.rawSize)) {
      return rva - section.virtualAddress + section.rawAddress;
    }
  }
  return -1;
}
function readCString$1(data, offset, maxLen = 256) {
  let end = offset;
  while (end < data.length && end < offset + maxLen && data[end] !== 0) {
    end++;
  }
  return data.subarray(offset, end).toString("ascii");
}
function decodeASCII(bytes) {
  let str = "";
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) break;
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}
function readBytesAtRva(data, rva, size, sections) {
  const fileOffset = rvaToFileOffset(rva, sections);
  if (fileOffset === -1 || fileOffset + size > data.length) return null;
  return data.subarray(fileOffset, fileOffset + size);
}
const ELF_MAGIC = [127, 69, 76, 70];
const ELFCLASS64 = 2;
const ELFDATA2LSB = 1;
const SHF_WRITE = 1;
const SHF_ALLOC = 2;
const SHF_EXECINSTR = 4;
const EM_X86_64 = 62;
function parseELF(data, filePath) {
  for (let i = 0; i < 4; i++) {
    if (data[i] !== ELF_MAGIC[i]) {
      throw new Error(t("elf.invalid_magic"));
    }
  }
  const elfClass = data[4];
  const elfData = data[5];
  const is64 = elfClass === ELFCLASS64;
  const isLittle = elfData === ELFDATA2LSB;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const read16 = (offset) => view.getUint16(offset, isLittle);
  const read32 = (offset) => view.getUint32(offset, isLittle);
  const read64 = (offset) => Number(view.getBigUint64(offset, isLittle));
  const machine = read16(18);
  let entryPoint;
  let shOffset;
  let shEntSize;
  let shNum;
  let shStrIndex;
  if (is64) {
    entryPoint = read64(24);
    read64(32);
    shOffset = read64(40);
    read16(54);
    read16(56);
    shEntSize = read16(58);
    shNum = read16(60);
    shStrIndex = read16(62);
  } else {
    entryPoint = read32(24);
    read32(28);
    shOffset = read32(32);
    read16(42);
    read16(44);
    shEntSize = read16(46);
    shNum = read16(48);
    shStrIndex = read16(50);
  }
  let shStrTab = null;
  if (shStrIndex < shNum && shOffset > 0) {
    const strSecOffset = shOffset + shStrIndex * shEntSize;
    const strTabOff = is64 ? read64(strSecOffset + 24) : read32(strSecOffset + 16);
    const strTabSize = is64 ? read64(strSecOffset + 32) : read32(strSecOffset + 20);
    shStrTab = data.subarray(strTabOff, strTabOff + strTabSize);
  }
  const sections = [];
  for (let i = 0; i < shNum; i++) {
    const secOffset = shOffset + i * shEntSize;
    if (secOffset + shEntSize > data.length) break;
    let name = "";
    const nameIndex = read32(secOffset);
    if (shStrTab && nameIndex < shStrTab.length) {
      name = readCString(shStrTab, nameIndex);
    }
    let shFlags;
    let shAddr;
    let shFileOffset;
    let shSize;
    if (is64) {
      shFlags = read64(secOffset + 8);
      shAddr = read64(secOffset + 16);
      shFileOffset = read64(secOffset + 24);
      shSize = read64(secOffset + 32);
    } else {
      shFlags = read32(secOffset + 8);
      shAddr = read32(secOffset + 12);
      shFileOffset = read32(secOffset + 16);
      shSize = read32(secOffset + 20);
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
    });
  }
  const imports = [];
  const exports = [];
  const dynsymSection = sections.find((s) => s.name === ".dynsym");
  const dynstrSection = sections.find((s) => s.name === ".dynstr");
  if (dynsymSection && dynstrSection) {
    const dynstr = data.subarray(dynstrSection.rawAddress, dynstrSection.rawAddress + dynstrSection.rawSize);
    const symEntSize = is64 ? 24 : 16;
    const symCount = Math.floor(dynsymSection.rawSize / symEntSize);
    const importFuncs = [];
    for (let i = 1; i < symCount; i++) {
      const symOffset = dynsymSection.rawAddress + i * symEntSize;
      let stName, stValue, stInfo;
      if (is64) {
        stName = read32(symOffset);
        stInfo = data[symOffset + 4];
        stValue = read64(symOffset + 8);
      } else {
        stName = read32(symOffset);
        stValue = read32(symOffset + 4);
        stInfo = data[symOffset + 12];
      }
      const symName = stName < dynstr.length ? readCString(dynstr, stName) : "";
      if (!symName) continue;
      const bind = stInfo >> 4;
      const type = stInfo & 15;
      if (stValue === 0 && type === 2) {
        importFuncs.push({ name: symName });
      } else if (stValue !== 0 && (bind === 1 || bind === 2)) {
        exports.push({
          name: symName,
          ordinal: i,
          address: stValue
        });
      }
    }
    if (importFuncs.length > 0) {
      imports.push({ dllName: "dynamic", functions: importFuncs });
    }
  }
  const architecture = machine === EM_X86_64 || is64 ? "x64" : "x86";
  validateSections(data, sections);
  return {
    path: filePath,
    format: "ELF",
    architecture,
    entryPoint,
    imageBase: 0,
    sections,
    imports,
    exports,
    fileSize: data.length
  };
}
function validateSections(data, sections) {
  for (let i = 0; i < sections.length; i++) {
    const sec = sections[i];
    if (sec.rawSize === 0 && sec.virtualSize > 0 && sec.isExecutable) {
      console.warn(t("section.corrupted", { section: sec.name, reason: t("section.zero_size", { section: sec.name }) }));
    }
    if (sec.rawAddress > 0 && sec.rawAddress + sec.rawSize > data.length) {
      throw new Error(t("section.corrupted", {
        section: sec.name,
        reason: t("section.file_oob", { section: sec.name })
      }));
    }
    for (let j = i + 1; j < sections.length; j++) {
      const other = sections[j];
      if (sec.rawAddress > 0 && other.rawAddress > 0 && sec.rawAddress < other.rawAddress + other.rawSize && sec.rawAddress + sec.rawSize > other.rawAddress) {
        console.warn(t("section.corrupted", {
          section: sec.name,
          reason: t("section.overlapping", { section: sec.name, other: other.name })
        }));
      }
    }
  }
}
function readCString(data, offset, maxLen = 256) {
  let end = offset;
  while (end < data.length && end < offset + maxLen && data[end] !== 0) {
    end++;
  }
  let str = "";
  for (let i = offset; i < end; i++) {
    str += String.fromCharCode(data[i]);
  }
  return str;
}
function detectFormat(data) {
  if (data.length < 4) return "Unknown";
  if (data[0] === 77 && data[1] === 90) return "PE";
  if (data[0] === 127 && data[1] === 69 && data[2] === 76 && data[3] === 70) return "ELF";
  return "Unknown";
}
let loadedData = null;
let loadedInfo = null;
function loadBinary(filePath) {
  try {
    const data = fs__namespace.readFileSync(filePath);
    if (data.length === 0) {
      throw new Error(t("binary.empty"));
    }
    loadedData = data;
    const format = detectFormat(data);
    switch (format) {
      case "PE":
        loadedInfo = parsePE(data, filePath);
        break;
      case "ELF":
        loadedInfo = parseELF(data, filePath);
        break;
      default:
        throw new Error(t("binary.load_error", { path: filePath, error: "Unsupported binary format" }));
    }
    if (!loadedInfo) {
      throw new Error(t("binary.parse_failed"));
    }
    if (!loadedInfo.sections || loadedInfo.sections.length === 0) {
      throw new Error(t("binary.no_sections"));
    }
    for (const section of loadedInfo.sections) {
      if (section.rawAddress < 0 || section.rawSize < 0 || section.rawAddress + section.rawSize > data.length) {
        throw new Error(t("binary.invalid_section_bounds", { section: section.name }));
      }
    }
    return loadedInfo;
  } catch (error) {
    const msg = error.message || "Unknown error";
    const formattedMsg = msg.includes("{") ? msg : t("binary.load_error", { path: filePath, error: msg });
    throw new Error(formattedMsg);
  }
}
function getLoadedData() {
  return loadedData;
}
function getLoadedInfo() {
  return loadedInfo;
}
function getBytesAtAddress(address, size) {
  if (!loadedData || !loadedInfo) return null;
  if (loadedInfo.format === "PE") {
    const rva = address - loadedInfo.imageBase;
    return readBytesAtRva(loadedData, rva, size, loadedInfo.sections);
  } else {
    for (const section of loadedInfo.sections) {
      if (address >= section.virtualAddress && address < section.virtualAddress + section.virtualSize) {
        const offset = address - section.virtualAddress + section.rawAddress;
        if (offset + size <= loadedData.length) {
          return loadedData.subarray(offset, offset + size);
        }
      }
    }
  }
  return null;
}
function getSectionByName(name) {
  if (!loadedInfo) return void 0;
  return loadedInfo.sections.find((s) => s.name === name);
}
function getSectionBytes(section) {
  if (!loadedData) return null;
  if (section.rawAddress + section.rawSize > loadedData.length) return null;
  return loadedData.subarray(section.rawAddress, section.rawAddress + section.rawSize);
}
class BytecodeAnalyzer {
  constructor(bytecode, baseAddress = 0) {
    this.bytecode = bytecode;
    this.baseAddress = baseAddress;
  }
  /**
   * Analyze bytecode to detect dispatcher patterns
   */
  analyzeDispatcher() {
    const tables = this.findJumpTables();
    if (tables.length > 0) {
      const table = tables[0];
      return {
        type: "table_lookup",
        confidence: Math.min(table.tableSize / 20, 1),
        dispatcherAddress: table.address,
        jumpTableSize: table.tableSize,
        opcodeTableAddress: table.address,
        pattern: `Detected jump table at 0x${table.address.toString(16).toUpperCase()} (${table.tableSize} entries)`
      };
    }
    const switchPattern = this.detectSwitchCasePattern();
    if (switchPattern && switchPattern.confidence > 0.6) {
      return switchPattern;
    }
    const tablePattern = this.detectTableLookupPattern();
    if (tablePattern && tablePattern.confidence > 0.6) {
      return tablePattern;
    }
    const indirectPattern = this.detectIndirectJumpPattern();
    if (indirectPattern && indirectPattern.confidence > 0.6) {
      return indirectPattern;
    }
    return switchPattern || tablePattern || indirectPattern;
  }
  /**
   * Detect switch-case pattern: sequence of CMP+JZ or similar
   * Example: cmp eax, 1; jz handler1; cmp eax, 2; jz handler2; ...
   */
  detectSwitchCasePattern() {
    const minPatternSize = 5;
    let maxCandidates = 0;
    let bestAddress = -1;
    for (let i = 0; i < this.bytecode.length - minPatternSize * 4; i++) {
      let candidateCount = 0;
      let j = i;
      while (j < this.bytecode.length - minPatternSize) {
        const nextBytes = this.bytecode.subarray(j, j + minPatternSize);
        if (this.looksLikeBranch(nextBytes)) {
          candidateCount++;
          j += minPatternSize;
        } else {
          break;
        }
      }
      if (candidateCount > maxCandidates) {
        maxCandidates = candidateCount;
        bestAddress = i;
      }
    }
    if (maxCandidates >= 3) {
      return {
        type: "switch_case",
        confidence: Math.min(maxCandidates / 10, 1),
        dispatcherAddress: this.baseAddress + bestAddress,
        jumpTableSize: maxCandidates,
        pattern: `${maxCandidates} consecutive branch patterns detected`
      };
    }
    return null;
  }
  /**
   * Detect table lookup pattern: array of addresses used as jump targets
   * Common in Themida, VMProtect-like VMs
   */
  detectTableLookupPattern() {
    const alignment = 4;
    let longestTableStart = -1;
    let longestTableLength = 0;
    for (let i = 0; i <= this.bytecode.length - alignment * 4; i += alignment) {
      let tableLength = 0;
      let j = i;
      while (j <= this.bytecode.length - alignment) {
        const value = this.bytecode.readUInt32LE(j);
        if (this.isPlausibleAddress(value)) {
          tableLength++;
          j += alignment;
        } else {
          break;
        }
      }
      if (tableLength > longestTableLength) {
        longestTableLength = tableLength;
        longestTableStart = i;
      }
    }
    if (longestTableLength >= 5) {
      return {
        type: "table_lookup",
        confidence: Math.min(longestTableLength / 20, 1),
        dispatcherAddress: this.baseAddress + longestTableStart,
        jumpTableSize: longestTableLength,
        opcodeTableAddress: this.baseAddress + longestTableStart,
        pattern: `Address table with ${longestTableLength} entries detected`
      };
    }
    return null;
  }
  /**
   * Detect indirect jump pattern: mov reg, [opcode]; jmp [table + reg*scale]
   */
  detectIndirectJumpPattern() {
    return null;
  }
  /**
   * Identify likely opcodes from bytecode frequency analysis
   * Opcodes tend to appear more frequently and uniformly than random data
   */
  identifyLikelyOpcodes(sampleSize = this.bytecode.length) {
    const frequency = {};
    const limit = Math.min(sampleSize, this.bytecode.length);
    for (let i = 0; i < limit; i++) {
      const byte = this.bytecode[i];
      frequency[byte] = (frequency[byte] || 0) + 1;
    }
    const candidates = Object.entries(frequency).map(([value, freq]) => {
      const numericValue = parseInt(value);
      const frequencyRatio = freq / this.bytecode.length;
      return {
        value: numericValue,
        frequency: freq,
        likely: freq >= 2 && frequencyRatio >= 5e-3
      };
    });
    candidates.sort((a, b) => b.frequency - a.frequency);
    return candidates;
  }
  /**
   * Get positions where a candidate opcode appears in the bytecode.
   */
  getOpcodePositions(opcodeValue) {
    const positions = [];
    for (let i = 0; i < this.bytecode.length; i++) {
      if (this.bytecode[i] === opcodeValue) {
        positions.push(this.baseAddress + i);
      }
    }
    return positions;
  }
  /**
   * Extract opcode context for a position in the bytecode.
   */
  getOpcodeContext(position, windowSize = 4) {
    const relativePos = position - this.baseAddress;
    const start = Math.max(0, relativePos - windowSize);
    const end = Math.min(this.bytecode.length, relativePos + windowSize + 1);
    const window = this.bytecode.subarray(start, end);
    const preceding = Array.from(this.bytecode.subarray(start, relativePos));
    const following = Array.from(this.bytecode.subarray(relativePos + 1, end));
    return {
      precedingOpcodes: preceding,
      followingOpcodes: following,
      bytecodeWindow: Buffer.from(window),
      position: relativePos - start
    };
  }
  /**
   * Analyze bytecode statistics for indicators of VM structure
   */
  getStatistics() {
    const freq = {};
    let totalSize = this.bytecode.length;
    let entropy = 0;
    for (let i = 0; i < this.bytecode.length; i++) {
      const byte = this.bytecode[i];
      freq[byte] = (freq[byte] || 0) + 1;
    }
    const uniqueBytes = Object.keys(freq).length;
    for (const count of Object.values(freq)) {
      const probability = count / totalSize;
      entropy -= probability * Math.log2(probability);
    }
    return {
      totalSize,
      uniqueBytes,
      byteDistribution: freq,
      entropy
      // 0 = highly ordered, 8 = random
    };
  }
  // ─── Helper Methods ─────────────────────────────────────────────────
  looksLikeBranch(bytes) {
    const first = bytes[0];
    const count = bytes.filter((b) => b === first).length;
    return count >= 2;
  }
  isPlausibleAddress(value) {
    return value >= 4194304 && value <= 268435456 || // Typical PE range
    value >= 4194304 && value <= 2147483647;
  }
  /**
   * Find all potential jump table entries (contiguous address sequences)
   */
  findJumpTables() {
    const tables = [];
    const alignment = 4;
    for (let i = 0; i <= this.bytecode.length - alignment * 4; i += alignment) {
      let tableLength = 0;
      let j = i;
      while (j <= this.bytecode.length - alignment) {
        const value = this.bytecode.readUInt32LE(j);
        if (this.isPlausibleAddress(value)) {
          tableLength++;
          j += alignment;
        } else {
          break;
        }
      }
      if (tableLength >= 5) {
        tables.push({
          address: this.baseAddress + i,
          size: tableLength * alignment,
          tableSize: tableLength
        });
        i = j - alignment;
      }
    }
    return tables;
  }
}
var OpcodeSemanticType = /* @__PURE__ */ ((OpcodeSemanticType2) => {
  OpcodeSemanticType2["STACK_PUSH"] = "stack:push";
  OpcodeSemanticType2["STACK_POP"] = "stack:pop";
  OpcodeSemanticType2["STACK_DUP"] = "stack:dup";
  OpcodeSemanticType2["STACK_SWAP"] = "stack:swap";
  OpcodeSemanticType2["ARITH_ADD"] = "arith:add";
  OpcodeSemanticType2["ARITH_SUB"] = "arith:sub";
  OpcodeSemanticType2["ARITH_MUL"] = "arith:mul";
  OpcodeSemanticType2["ARITH_DIV"] = "arith:div";
  OpcodeSemanticType2["ARITH_MOD"] = "arith:mod";
  OpcodeSemanticType2["ARITH_NEG"] = "arith:neg";
  OpcodeSemanticType2["LOGIC_AND"] = "logic:and";
  OpcodeSemanticType2["LOGIC_OR"] = "logic:or";
  OpcodeSemanticType2["LOGIC_XOR"] = "logic:xor";
  OpcodeSemanticType2["LOGIC_NOT"] = "logic:not";
  OpcodeSemanticType2["LOGIC_SHL"] = "logic:shl";
  OpcodeSemanticType2["LOGIC_SHR"] = "logic:shr";
  OpcodeSemanticType2["CMP_EQ"] = "cmp:eq";
  OpcodeSemanticType2["CMP_NE"] = "cmp:ne";
  OpcodeSemanticType2["CMP_LT"] = "cmp:lt";
  OpcodeSemanticType2["CMP_LE"] = "cmp:le";
  OpcodeSemanticType2["CMP_GT"] = "cmp:gt";
  OpcodeSemanticType2["CMP_GE"] = "cmp:ge";
  OpcodeSemanticType2["JMP_UNCONDITIONAL"] = "jmp:unconditional";
  OpcodeSemanticType2["JMP_IF_ZERO"] = "jmp:if_zero";
  OpcodeSemanticType2["JMP_IF_NOT_ZERO"] = "jmp:if_not_zero";
  OpcodeSemanticType2["JMP_IF_CARRY"] = "jmp:if_carry";
  OpcodeSemanticType2["JMP_INDIRECT"] = "jmp:indirect";
  OpcodeSemanticType2["CALL"] = "control:call";
  OpcodeSemanticType2["RET"] = "control:ret";
  OpcodeSemanticType2["LOAD_REG"] = "mem:load_reg";
  OpcodeSemanticType2["STORE_REG"] = "mem:store_reg";
  OpcodeSemanticType2["LOAD_MEM"] = "mem:load_mem";
  OpcodeSemanticType2["STORE_MEM"] = "mem:store_mem";
  OpcodeSemanticType2["NOP"] = "misc:nop";
  OpcodeSemanticType2["HALT"] = "misc:halt";
  OpcodeSemanticType2["UNKNOWN"] = "unknown";
  return OpcodeSemanticType2;
})(OpcodeSemanticType || {});
class OpcodeSemanticAnalyzer {
  /**
   * Analyze bytecode sequence to infer semantic meaning
   * Based on common patterns in VM bytecode
   */
  static analyzeOpcode(opcode, context = {}) {
    const frequencyHint = this.getFrequencyHint(opcode, context.frequency);
    const contextHint = this.analyzeContext(opcode, context);
    const bytecodeHint = context.bytecodeWindow ? this.analyzeBytecodePattern(opcode, context.bytecodeWindow, context.position || 0) : null;
    return this.inferSemantics(opcode, frequencyHint, contextHint, bytecodeHint);
  }
  /**
   * Get semantic hint from frequency distribution
   * Stack opcodes tend to appear frequently
   * Rare opcodes tend to be control flow or special operations
   */
  static getFrequencyHint(opcode, frequency) {
    if (frequency > 50) {
      return {
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1
      };
    } else if (frequency > 20) {
      return {
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1
      };
    } else if (frequency > 5) {
      return {
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0
      };
    } else {
      return {
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0
      };
    }
  }
  /**
   * Analyze context: what opcodes appear before/after?
   * E.g., if always followed by JZ → likely a comparison
   */
  static analyzeContext(opcode, context) {
    if (context.followingOpcodes?.some((op) => [116, 117, 235].includes(op))) {
      return {
        type: "cmp:eq",
        stackDelta: -2,
        stackIn: 2,
        stackOut: 0
      };
    }
    if (context.precedingOpcodes?.some((op) => op === 104)) {
      return {
        stackDelta: -1,
        stackIn: 1,
        stackOut: 0
      };
    }
    return {};
  }
  /**
   * Analyze bytecode pattern around opcode
   * E.g., PUSH imm + ADD patterns
   */
  static analyzeBytecodePattern(opcode, window, position) {
    if (opcode === 104 && position + 5 <= window.length) {
      return {
        type: "stack:push",
        hasImmediate: true,
        immediateSize: 4,
        stackDelta: 1,
        stackIn: 0,
        stackOut: 1
      };
    }
    if (opcode === 1) {
      return {
        type: "arith:add",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1
      };
    }
    return null;
  }
  /**
   * Infer final semantics from hints
   */
  static inferSemantics(opcode, frequencyHint, contextHint, bytecodeHint) {
    const best = bytecodeHint || contextHint || frequencyHint;
    return {
      type: best.type || "unknown",
      stackDelta: best.stackDelta ?? 0,
      stackIn: best.stackIn ?? 0,
      stackOut: best.stackOut ?? 0,
      sideEffects: best.sideEffects ?? [],
      hasImmediate: best.hasImmediate ?? false,
      immediateSize: best.immediateSize,
      description: best.description || `Opcode 0x${opcode.toString(16).toUpperCase()}`
    };
  }
  /**
   * Common signature library for known opcodes
   */
  static getKnownSignature(opcode) {
    const sigs = {
      // Stack operations (x86-inspired)
      104: {
        type: "stack:push",
        stackDelta: 1,
        stackIn: 0,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: true,
        immediateSize: 4,
        description: "PUSH immediate"
      },
      88: {
        type: "stack:pop",
        stackDelta: -1,
        stackIn: 1,
        stackOut: 0,
        sideEffects: [],
        hasImmediate: false,
        description: "POP (discard)"
      },
      // Arithmetic
      1: {
        type: "arith:add",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["zf", "cf", "of"],
        hasImmediate: false,
        description: "ADD"
      },
      41: {
        type: "arith:sub",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["zf", "cf", "of"],
        hasImmediate: false,
        description: "SUB"
      },
      247: {
        type: "arith:mul",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["cf", "of"],
        hasImmediate: false,
        description: "MUL"
      },
      246: {
        type: "arith:div",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["zf", "cf", "of"],
        hasImmediate: false,
        description: "DIV"
      },
      245: {
        type: "arith:mod",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["zf", "cf"],
        hasImmediate: false,
        description: "MOD"
      },
      248: {
        type: "arith:neg",
        stackDelta: 0,
        stackIn: 1,
        stackOut: 1,
        sideEffects: ["zf", "cf", "of"],
        hasImmediate: false,
        description: "NEG"
      },
      209: {
        type: "logic:shl",
        stackDelta: 0,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["zf", "cf"],
        hasImmediate: false,
        description: "SHL"
      },
      211: {
        type: "logic:shr",
        stackDelta: 0,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["zf", "cf"],
        hasImmediate: false,
        description: "SHR"
      },
      136: {
        type: "stack:swap",
        stackDelta: 0,
        stackIn: 2,
        stackOut: 2,
        sideEffects: [],
        hasImmediate: false,
        description: "SWAP"
      },
      137: {
        type: "stack:dup",
        stackDelta: 1,
        stackIn: 1,
        stackOut: 2,
        sideEffects: [],
        hasImmediate: false,
        description: "DUP"
      },
      // Logic
      33: {
        type: "logic:and",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["zf"],
        hasImmediate: false,
        description: "AND"
      },
      9: {
        type: "logic:or",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["zf"],
        hasImmediate: false,
        description: "OR"
      },
      49: {
        type: "logic:xor",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: ["zf"],
        hasImmediate: false,
        description: "XOR"
      },
      // Comparison
      57: {
        type: "cmp:eq",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: "CMP_EQ"
      },
      58: {
        type: "cmp:ne",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: "CMP_NE"
      },
      59: {
        type: "cmp:lt",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: "CMP_LT"
      },
      60: {
        type: "cmp:le",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: "CMP_LE"
      },
      61: {
        type: "cmp:gt",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: "CMP_GT"
      },
      62: {
        type: "cmp:ge",
        stackDelta: -1,
        stackIn: 2,
        stackOut: 1,
        sideEffects: [],
        hasImmediate: false,
        description: "CMP_GE"
      },
      // Jumps
      235: {
        type: "jmp:unconditional",
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0,
        sideEffects: ["vip"],
        hasImmediate: true,
        immediateSize: 4,
        description: "JMP"
      },
      116: {
        type: "jmp:if_zero",
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0,
        sideEffects: ["vip"],
        hasImmediate: true,
        immediateSize: 4,
        description: "JZ"
      },
      117: {
        type: "jmp:if_not_zero",
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0,
        sideEffects: ["vip"],
        hasImmediate: true,
        immediateSize: 4,
        description: "JNZ"
      },
      232: {
        type: "control:call",
        stackDelta: 1,
        stackIn: 0,
        stackOut: 1,
        sideEffects: ["vip"],
        hasImmediate: true,
        immediateSize: 4,
        description: "CALL"
      },
      // NOP
      144: {
        type: "misc:nop",
        stackDelta: 0,
        stackIn: 0,
        stackOut: 0,
        sideEffects: [],
        hasImmediate: false,
        description: "NOP"
      }
    };
    return sigs[opcode] || null;
  }
  /**
   * Map semantic type to handler executor label
   */
  static getExecutorLabel(semanticType) {
    const map = {
      [
        "stack:push"
        /* STACK_PUSH */
      ]: "PUSH",
      [
        "stack:pop"
        /* STACK_POP */
      ]: "POP",
      [
        "stack:dup"
        /* STACK_DUP */
      ]: "DUP",
      [
        "stack:swap"
        /* STACK_SWAP */
      ]: "SWAP",
      [
        "arith:add"
        /* ARITH_ADD */
      ]: "ADD",
      [
        "arith:sub"
        /* ARITH_SUB */
      ]: "SUB",
      [
        "arith:mul"
        /* ARITH_MUL */
      ]: "MUL",
      [
        "arith:div"
        /* ARITH_DIV */
      ]: "DIV",
      [
        "arith:mod"
        /* ARITH_MOD */
      ]: "MOD",
      [
        "arith:neg"
        /* ARITH_NEG */
      ]: "NEG",
      [
        "logic:and"
        /* LOGIC_AND */
      ]: "AND",
      [
        "logic:or"
        /* LOGIC_OR */
      ]: "OR",
      [
        "logic:xor"
        /* LOGIC_XOR */
      ]: "XOR",
      [
        "logic:not"
        /* LOGIC_NOT */
      ]: "NOT",
      [
        "logic:shl"
        /* LOGIC_SHL */
      ]: "SHL",
      [
        "logic:shr"
        /* LOGIC_SHR */
      ]: "SHR",
      [
        "cmp:eq"
        /* CMP_EQ */
      ]: "CMP",
      [
        "cmp:ne"
        /* CMP_NE */
      ]: "CMP_NE",
      [
        "cmp:lt"
        /* CMP_LT */
      ]: "CMP_LT",
      [
        "cmp:le"
        /* CMP_LE */
      ]: "CMP_LE",
      [
        "cmp:gt"
        /* CMP_GT */
      ]: "CMP_GT",
      [
        "cmp:ge"
        /* CMP_GE */
      ]: "CMP_GE",
      [
        "jmp:unconditional"
        /* JMP_UNCONDITIONAL */
      ]: "JMP",
      [
        "jmp:if_zero"
        /* JMP_IF_ZERO */
      ]: "JZ",
      [
        "jmp:if_not_zero"
        /* JMP_IF_NOT_ZERO */
      ]: "JNZ",
      [
        "jmp:if_carry"
        /* JMP_IF_CARRY */
      ]: "JC",
      [
        "jmp:indirect"
        /* JMP_INDIRECT */
      ]: "JMP_IND",
      [
        "control:call"
        /* CALL */
      ]: "CALL",
      [
        "control:ret"
        /* RET */
      ]: "RET",
      [
        "mem:load_reg"
        /* LOAD_REG */
      ]: "LOAD",
      [
        "mem:store_reg"
        /* STORE_REG */
      ]: "STORE",
      [
        "mem:load_mem"
        /* LOAD_MEM */
      ]: "LOAD_MEM",
      [
        "mem:store_mem"
        /* STORE_MEM */
      ]: "STORE_MEM",
      [
        "misc:nop"
        /* NOP */
      ]: "NOP",
      [
        "misc:halt"
        /* HALT */
      ]: "HALT",
      [
        "unknown"
        /* UNKNOWN */
      ]: "UNKNOWN"
    };
    return map[semanticType] || "UNKNOWN";
  }
}
class DynamicHandlerDetector {
  constructor(bytecode, baseAddress = 0) {
    this.analyzer = new BytecodeAnalyzer(bytecode, baseAddress);
  }
  /**
   * Main entry point: Analyze bytecode and auto-detect handlers
   */
  detectHandlers() {
    const result = {
      dispatcherFound: false,
      pattern: null,
      opcodesCandidates: [],
      handlersCreated: [],
      confidence: 0
    };
    const pattern = this.analyzer.analyzeDispatcher();
    if (pattern && pattern.confidence > 0.5) {
      result.pattern = pattern;
      result.dispatcherFound = true;
    }
    const opcodes = this.analyzer.identifyLikelyOpcodes();
    result.opcodesCandidates = opcodes.filter((o) => o.likely);
    result.handlersCreated = this.createHandlers(result.opcodesCandidates);
    const semanticInfo = this.analyzeSemantics(result.handlersCreated);
    result.semanticInfo = semanticInfo;
    result.confidence = this.calculateConfidence(result);
    return result;
  }
  /**
   * Create VMHandler objects for detected opcodes
   * These are placeholder handlers; real handlers would analyze semantics
   */
  createHandlers(opcodes) {
    const handlers = [];
    for (const opcode of opcodes) {
      const handler = {
        id: `auto_op_${opcode.value.toString(16).toUpperCase()}`,
        opcodeValue: opcode.value,
        label: `OP_${opcode.value.toString(16).toUpperCase()}`,
        address: 0,
        // Unknown during auto-detection
        size: 1,
        // Default
        operandSize: 0,
        // Will be determined during execution
        description: `Auto-detected opcode ${opcode.value} (frequency: ${opcode.frequency})`,
        isDataReference: false,
        executionCount: 0,
        handlerType: "unknown",
        confidence: Math.min(opcode.frequency / 10, 1)
      };
      handlers.push(handler);
    }
    return handlers;
  }
  /**
   * Phase 2: Analyze semantic meaning of detected opcodes
   */
  analyzeSemantics(handlers) {
    let analyzed = 0;
    let withKnownSemantics = 0;
    let inferredSemantics = 0;
    for (const handler of handlers) {
      analyzed++;
      const knownSig = OpcodeSemanticAnalyzer.getKnownSignature(handler.opcodeValue);
      if (knownSig) {
        withKnownSemantics++;
        handler.label = OpcodeSemanticAnalyzer.getExecutorLabel(knownSig.type);
        handler.handlerType = knownSig.type.split(":")[1] || "unknown";
        handler.description = knownSig.description;
      } else {
        const positions = this.analyzer.getOpcodePositions(handler.opcodeValue);
        const samplePositions = positions.slice(0, 5);
        let precedingOpcodes = [];
        let followingOpcodes = [];
        let bytecodeWindow;
        for (const pos of samplePositions) {
          const context = this.analyzer.getOpcodeContext(pos, 6);
          precedingOpcodes = precedingOpcodes.concat(context.precedingOpcodes);
          followingOpcodes = followingOpcodes.concat(context.followingOpcodes);
          bytecodeWindow = bytecodeWindow || context.bytecodeWindow;
        }
        const inferred = OpcodeSemanticAnalyzer.analyzeOpcode(handler.opcodeValue, {
          frequency: handler.confidence ? Math.round(handler.confidence * 100) : 0,
          precedingOpcodes,
          followingOpcodes,
          bytecodeWindow,
          position: samplePositions[0]
        });
        inferredSemantics++;
        handler.label = OpcodeSemanticAnalyzer.getExecutorLabel(inferred.type);
        handler.handlerType = inferred.type.split(":")[1] || "unknown";
        handler.description = inferred.description;
      }
    }
    return { analyzed, withKnownSemantics, inferredSemantics };
  }
  /**
   * Calculate overall confidence in the detection
   */
  calculateConfidence(result) {
    let confidence = 0;
    if (result.dispatcherFound && result.pattern) {
      confidence += result.pattern.confidence * 0.3;
    }
    if (result.opcodesCandidates.length >= 10) {
      confidence += 0.4;
    } else if (result.opcodesCandidates.length >= 5) {
      confidence += 0.2;
    }
    const avgHandlerConfidence = result.handlersCreated.length > 0 ? result.handlersCreated.reduce((sum, h) => sum + (h.confidence || 0), 0) / result.handlersCreated.length : 0;
    confidence += Math.min(avgHandlerConfidence, 0.3);
    return Math.min(confidence, 1);
  }
  /**
   * Analyze bytecode structure and statistics
   */
  analyzeStructure() {
    return this.analyzer.getStatistics();
  }
  /**
   * Find all potential jump tables in bytecode
   */
  findJumpTables() {
    return this.analyzer.findJumpTables();
  }
  /**
   * Get most likely opcodes (frequency-based ranking)
   */
  getMostLikelyOpcodes(count = 20) {
    const candidates = this.analyzer.identifyLikelyOpcodes(500);
    return candidates.slice(0, count);
  }
  /**
   * Generate a report of detection results
   */
  generateReport(result) {
    let report = "=== Bytecode Handler Detection Report (with Semantic Analysis) ===\n\n";
    report += `Confidence Level: ${(result.confidence * 100).toFixed(1)}%
`;
    report += `Dispatcher Pattern Found: ${result.dispatcherFound ? "Yes" : "No"}

`;
    if (result.pattern) {
      report += `Dispatcher Type: ${result.pattern.type}
`;
      report += `Pattern Description: ${result.pattern.pattern}
`;
      report += `Dispatcher Address: 0x${result.pattern.dispatcherAddress.toString(16).toUpperCase()}
`;
      if (result.pattern.jumpTableSize) {
        report += `Handler Count: ${result.pattern.jumpTableSize}
`;
      }
      report += "\n";
    }
    report += `Detected Opcodes: ${result.opcodesCandidates.length}
`;
    for (const opcode of result.opcodesCandidates.slice(0, 10)) {
      report += `  0x${opcode.value.toString(16).toUpperCase().padStart(2, "0")}: frequency=${opcode.frequency}
`;
    }
    if (result.opcodesCandidates.length > 10) {
      report += `  ... and ${result.opcodesCandidates.length - 10} more
`;
    }
    report += `
Handlers Created: ${result.handlersCreated.length}
`;
    if (result.semanticInfo) {
      report += `
=== Semantic Analysis (Phase 2) ===
`;
      report += `Opcodes Analyzed: ${result.semanticInfo.analyzed}
`;
      report += `With Known Semantics: ${result.semanticInfo.withKnownSemantics}
`;
      report += `Inferred Semantics: ${result.semanticInfo.inferredSemantics}
`;
      report += `
Opcodes by Semantic Type:
`;
      const classified = {};
      for (const handler of result.handlersCreated) {
        const type = handler.handlerType || "unknown";
        classified[type] = (classified[type] || 0) + 1;
      }
      for (const [type, count] of Object.entries(classified)) {
        report += `  ${type}: ${count}
`;
      }
    }
    return report;
  }
}
class DynamicExecutorBuilder {
  /**
   * Build and register a handler executor based on semantic analysis
   */
  static buildAndRegister(engine, config) {
    const executor = this.buildExecutor(config.semantic);
    if (!executor) return false;
    const label = OpcodeSemanticAnalyzer.getExecutorLabel(config.semantic.type);
    engine.registerExecutor(label, executor);
    return true;
  }
  /**
   * Build an executor function for a given semantic signature
   */
  static buildExecutor(semantic) {
    switch (semantic.type) {
      // Stack operations
      case OpcodeSemanticType.STACK_PUSH:
        return this.executePush(semantic);
      case OpcodeSemanticType.STACK_POP:
        return this.executePop(semantic);
      case OpcodeSemanticType.STACK_DUP:
        return this.executeDup(semantic);
      case OpcodeSemanticType.STACK_SWAP:
        return this.executeSwap(semantic);
      // Arithmetic
      case OpcodeSemanticType.ARITH_ADD:
        return this.executeAdd(semantic);
      case OpcodeSemanticType.ARITH_SUB:
        return this.executeSub(semantic);
      case OpcodeSemanticType.ARITH_MUL:
        return this.executeMul(semantic);
      case OpcodeSemanticType.ARITH_DIV:
        return this.executeDiv(semantic);
      case OpcodeSemanticType.ARITH_MOD:
        return this.executeMod(semantic);
      case OpcodeSemanticType.ARITH_NEG:
        return this.executeNeg(semantic);
      // Logic
      case OpcodeSemanticType.LOGIC_AND:
        return this.executeAnd(semantic);
      case OpcodeSemanticType.LOGIC_OR:
        return this.executeOr(semantic);
      case OpcodeSemanticType.LOGIC_XOR:
        return this.executeXor(semantic);
      case OpcodeSemanticType.LOGIC_NOT:
        return this.executeNot(semantic);
      case OpcodeSemanticType.LOGIC_SHL:
        return this.executeShl(semantic);
      case OpcodeSemanticType.LOGIC_SHR:
        return this.executeShr(semantic);
      // Comparison
      case OpcodeSemanticType.CMP_EQ:
        return this.executeCmp(semantic);
      // Jumps
      case OpcodeSemanticType.JMP_UNCONDITIONAL:
        return this.executeJmp(semantic);
      case OpcodeSemanticType.JMP_IF_ZERO:
        return this.executeJz(semantic);
      case OpcodeSemanticType.JMP_IF_NOT_ZERO:
        return this.executeJnz(semantic);
      // Memory
      case OpcodeSemanticType.LOAD_REG:
        return this.executeLoad(semantic);
      case OpcodeSemanticType.STORE_REG:
        return this.executeStore(semantic);
      // Other
      case OpcodeSemanticType.NOP:
        return this.executeNop(semantic);
      default:
        return null;
    }
  }
  // ─── Stack Operations ────────────────────────────────────────────────
  static executePush(semantic) {
    return (engine) => {
      const imm = BigInt(engine.readBytecodeU32(engine.getConfig().opcodeSize));
      engine.push(imm);
      engine.advanceVIP(engine.getConfig().opcodeSize + 4);
    };
  }
  static executePop(semantic) {
    return (engine) => {
      engine.pop();
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeDup(semantic) {
    return (engine) => {
      const val = engine.getStateManager().peek();
      engine.push(val);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeSwap(semantic) {
    return (engine) => {
      const a = engine.pop();
      const b = engine.pop();
      engine.push(a);
      engine.push(b);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  // ─── Arithmetic ─────────────────────────────────────────────────────
  static executeAdd(semantic) {
    return (engine) => {
      const b = engine.pop();
      const a = engine.pop();
      const result = a + b;
      engine.push(result);
      engine.getStateManager().updateArithFlags(result);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeSub(semantic) {
    return (engine) => {
      const b = engine.pop();
      const a = engine.pop();
      const result = a - b;
      engine.push(result);
      engine.getStateManager().updateArithFlags(result);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeMul(semantic) {
    return (engine) => {
      const b = engine.pop();
      const a = engine.pop();
      engine.push(a * b);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeDiv(semantic) {
    return (engine) => {
      const b = engine.pop();
      const a = engine.pop();
      if (b === 0n) {
        engine.getStateManager().halt("Division by zero");
      } else {
        engine.push(a / b);
      }
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeMod(semantic) {
    return (engine) => {
      const b = engine.pop();
      const a = engine.pop();
      if (b === 0n) {
        engine.getStateManager().halt("Modulo by zero");
      } else {
        engine.push(a % b);
      }
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeNeg(semantic) {
    return (engine) => {
      const a = engine.pop();
      engine.push(-a);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  // ─── Logic/Bitwise ──────────────────────────────────────────────────
  static executeAnd(semantic) {
    return (engine) => {
      const b = engine.pop();
      const a = engine.pop();
      const result = a & b;
      engine.push(result);
      engine.getStateManager().updateArithFlags(result);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeOr(semantic) {
    return (engine) => {
      const b = engine.pop();
      const a = engine.pop();
      const result = a | b;
      engine.push(result);
      engine.getStateManager().updateArithFlags(result);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeXor(semantic) {
    return (engine) => {
      const b = engine.pop();
      const a = engine.pop();
      const result = a ^ b;
      engine.push(result);
      engine.getStateManager().updateArithFlags(result);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeNot(semantic) {
    return (engine) => {
      const a = engine.pop();
      engine.push(~a);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeShl(semantic) {
    return (engine) => {
      const shift = engine.pop();
      const val = engine.pop();
      engine.push(val << shift);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  static executeShr(semantic) {
    return (engine) => {
      const shift = engine.pop();
      const val = engine.pop();
      engine.push(val >> shift);
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  // ─── Comparison ─────────────────────────────────────────────────────
  static executeCmp(semantic) {
    return (engine) => {
      const b = engine.pop();
      const a = engine.pop();
      switch (semantic.type) {
        case OpcodeSemanticType.CMP_EQ:
          engine.push(a === b ? 1n : 0n);
          break;
        case OpcodeSemanticType.CMP_NE:
          engine.push(a !== b ? 1n : 0n);
          break;
        case OpcodeSemanticType.CMP_LT:
          engine.push(a < b ? 1n : 0n);
          break;
        case OpcodeSemanticType.CMP_LE:
          engine.push(a <= b ? 1n : 0n);
          break;
        case OpcodeSemanticType.CMP_GT:
          engine.push(a > b ? 1n : 0n);
          break;
        case OpcodeSemanticType.CMP_GE:
          engine.push(a >= b ? 1n : 0n);
          break;
        default:
          engine.push(0n);
          break;
      }
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  // ─── Jumps ──────────────────────────────────────────────────────────
  static executeJmp(semantic) {
    return (engine) => {
      const displacement = engine.readBytecodeU32(engine.getConfig().opcodeSize) | 0;
      const nextVip = engine.getVIP() + engine.getConfig().opcodeSize + 4;
      engine.setVIP(nextVip + displacement);
    };
  }
  static executeJz(semantic) {
    return (engine) => {
      const displacement = engine.readBytecodeU32(engine.getConfig().opcodeSize) | 0;
      const top = engine.getStateManager().peek();
      const nextVip = engine.getVIP() + engine.getConfig().opcodeSize + 4;
      if (top === 0n) {
        engine.setVIP(nextVip + displacement);
      } else {
        engine.advanceVIP(engine.getConfig().opcodeSize + 4);
      }
    };
  }
  static executeJnz(semantic) {
    return (engine) => {
      const displacement = engine.readBytecodeU32(engine.getConfig().opcodeSize) | 0;
      const top = engine.getStateManager().peek();
      const nextVip = engine.getVIP() + engine.getConfig().opcodeSize + 4;
      if (top !== 0n) {
        engine.setVIP(nextVip + displacement);
      } else {
        engine.advanceVIP(engine.getConfig().opcodeSize + 4);
      }
    };
  }
  // ─── Memory ─────────────────────────────────────────────────────────
  static executeLoad(semantic) {
    return (engine) => {
      const regIdx = engine.readBytecodeU8(engine.getConfig().opcodeSize);
      const regName = `v${regIdx}`;
      engine.push(engine.getReg(regName));
      engine.advanceVIP(engine.getConfig().opcodeSize + 1);
    };
  }
  static executeStore(semantic) {
    return (engine) => {
      const regIdx = engine.readBytecodeU8(engine.getConfig().opcodeSize);
      const regName = `v${regIdx}`;
      engine.setReg(regName, engine.pop());
      engine.advanceVIP(engine.getConfig().opcodeSize + 1);
    };
  }
  // ─── Other ──────────────────────────────────────────────────────────
  static executeNop(semantic) {
    return (engine) => {
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
  /**
   * Build a generic fallback executor for unknown opcodes
   * Safely advances VIP without crashing
   */
  static buildFallbackExecutor(opcodeValue) {
    return (engine) => {
      console.warn(
        `[Fallback] Executing unknown opcode 0x${opcodeValue.toString(16).toUpperCase()}`
      );
      engine.advanceVIP(engine.getConfig().opcodeSize);
    };
  }
}
class HandlerSemanticAnalyzer {
  constructor(bytecode, baseAddress = 0) {
    this.bytecode = bytecode;
    this.baseAddress = baseAddress;
    this.frequency = this.calculateFrequency(bytecode);
  }
  /**
   * Analyze handlers and build dynamic executors
   */
  analyzeAndBuild(engine, handlers) {
    const result = {
      handlersAnalyzed: [],
      totalHandlers: handlers.length,
      successfulExecutors: 0,
      failedExecutors: 0,
      averageConfidence: 0
    };
    let totalConfidence = 0;
    for (const handler of handlers) {
      const semantic = this.analyzeHandler(handler);
      const built = DynamicExecutorBuilder.buildAndRegister(engine, {
        opcodeValue: handler.opcodeValue,
        semantic: semantic.semantic,
        bytecodeContext: this.bytecode,
        position: handler.address
      });
      if (built) {
        result.successfulExecutors++;
      } else {
        result.failedExecutors++;
      }
      result.handlersAnalyzed.push(semantic);
      totalConfidence += semantic.confidence;
    }
    result.averageConfidence = handlers.length > 0 ? totalConfidence / handlers.length : 0;
    return result;
  }
  /**
   * Analyze a single handler to infer its semantic type
   */
  analyzeHandler(handler) {
    const opcode = handler.opcodeValue;
    let semantic = OpcodeSemanticAnalyzer.getKnownSignature(opcode);
    let confidence = 0.9;
    if (!semantic) {
      const context = {
        frequency: this.frequency[opcode] || 0,
        bytecodeWindow: this.bytecode
      };
      semantic = OpcodeSemanticAnalyzer.analyzeOpcode(opcode, context);
      confidence = 0.5;
    }
    const freq = this.frequency[opcode] || 0;
    if (freq >= 50) confidence = Math.min(confidence + 0.1, 1);
    else if (freq <= 2) confidence = Math.max(confidence - 0.2, 0.2);
    return {
      opcodeValue: opcode,
      semantic,
      confidence,
      context: `Opcode 0x${opcode.toString(16).toUpperCase()} - ${semantic.description}`,
      executorBuilt: false
    };
  }
  /**
   * Calculate byte frequency in bytecode
   */
  calculateFrequency(bytecode) {
    const freq = {};
    for (let i = 0; i < bytecode.length; i++) {
      const byte = bytecode[i];
      freq[byte] = (freq[byte] || 0) + 1;
    }
    return freq;
  }
  /**
   * Generate detailed analysis report
   */
  generateReport(result) {
    let report = "=== Handler Semantic Analysis Report ===\n\n";
    report += `Total Handlers Analyzed: ${result.totalHandlers}
`;
    report += `Successful Executors: ${result.successfulExecutors}
`;
    report += `Failed Executors: ${result.failedExecutors}
`;
    report += `Success Rate: ${(result.successfulExecutors / result.totalHandlers * 100).toFixed(1)}%
`;
    report += `Average Confidence: ${(result.averageConfidence * 100).toFixed(1)}%

`;
    report += "Handler Details:\n";
    report += "─".repeat(80) + "\n";
    for (const handler of result.handlersAnalyzed) {
      report += `Opcode 0x${handler.opcodeValue.toString(16).toUpperCase().padStart(2, "0")}
`;
      report += `  Type: ${handler.semantic.type}
`;
      report += `  Label: ${OpcodeSemanticAnalyzer.getExecutorLabel(handler.semantic.type)}
`;
      report += `  Confidence: ${(handler.confidence * 100).toFixed(1)}%
`;
      report += `  Description: ${handler.semantic.description}
`;
      report += `  Stack Delta: ${handler.semantic.stackDelta > 0 ? "+" : ""}${handler.semantic.stackDelta}
`;
      report += `  Side Effects: ${handler.semantic.sideEffects.join(", ") || "none"}
`;
      report += "\n";
    }
    return report;
  }
  /**
   * Get summary statistics
   */
  getStatistics() {
    const opcodes = Object.keys(this.frequency).map((k) => parseInt(k));
    const frequencies = opcodes.map((op) => this.frequency[op]);
    return {
      totalOpcodes: opcodes.length,
      uniqueOpcodes: opcodes.length,
      averageFrequency: frequencies.reduce((a, b) => a + b, 0) / opcodes.length,
      maxFrequency: Math.max(...frequencies),
      minFrequency: Math.min(...frequencies)
    };
  }
  /**
   * Classify handlers by semantic type
   */
  classifyHandlers(handlers) {
    const classified = /* @__PURE__ */ new Map();
    for (const handler of handlers) {
      let signature = OpcodeSemanticAnalyzer.getKnownSignature(handler.opcodeValue);
      if (!signature) {
        signature = OpcodeSemanticAnalyzer.analyzeOpcode(handler.opcodeValue, {
          frequency: this.frequency[handler.opcodeValue] || 0
        });
      }
      const type = signature.type;
      if (!classified.has(type)) {
        classified.set(type, []);
      }
      classified.get(type).push(handler);
    }
    return classified;
  }
  /**
   * Group handlers by semantic family
   */
  getSemanticFamilies(handlers) {
    const families = {
      stack: [],
      arithmetic: [],
      logic: [],
      comparison: [],
      control_flow: [],
      memory: [],
      other: []
    };
    for (const handler of handlers) {
      let signature = OpcodeSemanticAnalyzer.getKnownSignature(handler.opcodeValue);
      if (!signature) {
        signature = OpcodeSemanticAnalyzer.analyzeOpcode(handler.opcodeValue, {
          frequency: this.frequency[handler.opcodeValue] || 0
        });
      }
      const type = signature.type;
      if (type.includes("stack:")) {
        families.stack.push(handler);
      } else if (type.includes("arith:")) {
        families.arithmetic.push(handler);
      } else if (type.includes("logic:")) {
        families.logic.push(handler);
      } else if (type.includes("cmp:")) {
        families.comparison.push(handler);
      } else if (type.includes("jmp:") || type.includes("control:")) {
        families.control_flow.push(handler);
      } else if (type.includes("mem:")) {
        families.memory.push(handler);
      } else {
        families.other.push(handler);
      }
    }
    return families;
  }
}
const DEFAULT_CONFIG = {
  opcodeSize: 1,
  immediateSize: 4,
  variableLengthOpcodes: false,
  unknownOpcodeHandling: "fallback"
};
class BytecodeDecoder {
  constructor(bytecode, baseAddress = 0, config) {
    this.knownOpcodes = /* @__PURE__ */ new Set();
    this.bytecode = bytecode;
    this.baseAddress = baseAddress;
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.initializeKnownOpcodes();
  }
  /**
   * Initialize set of known opcode values
   */
  initializeKnownOpcodes() {
    const known = [
      104,
      // PUSH
      88,
      // POP
      1,
      // ADD
      41,
      // SUB
      247,
      // MUL
      246,
      // DIV
      245,
      // MOD
      248,
      // NEG
      33,
      // AND
      9,
      // OR
      49,
      // XOR
      209,
      // SHL
      211,
      // SHR
      57,
      // CMP_EQ
      58,
      // CMP_NE
      59,
      // CMP_LT
      60,
      // CMP_LE
      61,
      // CMP_GT
      62,
      // CMP_GE
      235,
      // JMP
      232,
      // CALL
      116,
      // JZ
      117,
      // JNZ
      144,
      // NOP
      136,
      // SWAP
      137,
      // DUP
      255,
      // CALL
      195
      // RET
    ];
    for (const op of known) {
      this.knownOpcodes.add(op);
    }
  }
  /**
   * Decode instruction at given VIP
   */
  decode(vip) {
    const relativeVip = vip - this.baseAddress;
    if (relativeVip < 0 || relativeVip >= this.bytecode.length) {
      return {
        address: vip,
        opcodeValue: 0,
        operands: [],
        size: 0,
        isValid: false,
        error: `VIP out of bounds: 0x${vip.toString(16)}`
      };
    }
    let opcodeValue = 0;
    let opcodeSize = this.config.opcodeSize;
    if (this.config.variableLengthOpcodes && this.bytecode[relativeVip] === 15) {
      if (relativeVip + 2 > this.bytecode.length) {
        return {
          address: vip,
          opcodeValue: this.bytecode[relativeVip],
          operands: [],
          size: 1,
          isValid: false,
          error: "Incomplete two-byte opcode"
        };
      }
      opcodeValue = this.bytecode[relativeVip] << 8 | this.bytecode[relativeVip + 1];
      opcodeSize = 2;
    } else {
      for (let i = 0; i < this.config.opcodeSize; i++) {
        if (relativeVip + i >= this.bytecode.length) {
          return {
            address: vip,
            opcodeValue,
            operands: [],
            size: i,
            isValid: false,
            error: `Incomplete opcode at 0x${vip.toString(16)}`
          };
        }
        opcodeValue |= this.bytecode[relativeVip + i] << i * 8;
      }
    }
    const { operands, immediateValue, operandSize } = this.decodeOperands(
      opcodeValue,
      relativeVip + opcodeSize
    );
    const isKnown = this.knownOpcodes.has(opcodeValue);
    const totalSize = opcodeSize + operandSize;
    return {
      address: vip,
      opcodeValue,
      operands,
      immediateValue,
      size: totalSize,
      isValid: isKnown || this.config.unknownOpcodeHandling !== "error",
      error: !isKnown && this.config.unknownOpcodeHandling === "error" ? `Unknown opcode: 0x${opcodeValue.toString(16).toUpperCase()}` : void 0
    };
  }
  /**
   * Decode operands based on opcode type
   */
  decodeOperands(opcodeValue, startPos) {
    let operandSize = 0;
    let immediateValue;
    const operands = [];
    switch (opcodeValue) {
      // Opcodes with 32-bit signed immediate
      case 104:
      // PUSH imm32
      case 235:
      // JMP imm32
      case 232:
      // CALL imm32
      case 116:
      // JZ imm32
      case 117:
        if (startPos + 4 <= this.bytecode.length) {
          immediateValue = this.bytecode.readInt32LE(startPos);
          operandSize = 4;
        }
        break;
      // Opcodes with 8-bit operand (register index)
      case 139:
      // MOV r8
      case 137:
        if (startPos + 1 <= this.bytecode.length) {
          operands.push(this.bytecode[startPos]);
          operandSize = 1;
        }
        break;
      // Opcodes with no operands
      case 88:
      // POP
      case 1:
      // ADD
      case 41:
      // SUB
      case 247:
      // MUL
      case 246:
      // DIV
      case 245:
      // MOD
      case 248:
      // NEG
      case 33:
      // AND
      case 9:
      // OR
      case 49:
      // XOR
      case 209:
      // SHL
      case 211:
      // SHR
      case 57:
      // CMP_EQ
      case 59:
      // CMP_LT
      case 61:
      // CMP_GT
      case 136:
      // SWAP
      case 137:
      // DUP
      case 144:
      // NOP
      case 195:
      // RET
      default:
        operandSize = 0;
        break;
    }
    return { operands, immediateValue, operandSize };
  }
  /**
   * Decode a sequence of instructions
   */
  decodeSequence(startVip, maxCount = 100) {
    const instructions = [];
    let vip = startVip;
    let count = 0;
    while (count < maxCount) {
      const instr = this.decode(vip);
      instructions.push(instr);
      if (!instr.isValid || instr.size === 0) {
        break;
      }
      vip += instr.size;
      count++;
    }
    return instructions;
  }
  /**
   * Check if opcode is a branch/jump instruction
   */
  isBranchOpcode(opcodeValue) {
    return [235, 116, 117, 255, 195].includes(opcodeValue);
  }
  /**
   * Check if opcode is a conditional jump
   */
  isConditionalJump(opcodeValue) {
    return [116, 117].includes(opcodeValue);
  }
  /**
   * Check if opcode modifies stack
   */
  modifiesStack(opcodeValue) {
    return [104, 88, 1, 41, 247, 33, 9, 49].includes(opcodeValue);
  }
  /**
   * Check if opcode modifies control flow
   */
  modifiesControlFlow(opcodeValue) {
    return this.isBranchOpcode(opcodeValue);
  }
  /**
   * Generate human-readable disassembly line
   */
  disassemble(instruction) {
    const mnemonic = this.getMnemonic(instruction.opcodeValue);
    const addressStr = `0x${instruction.address.toString(16).toUpperCase().padStart(8, "0")}`;
    if (instruction.immediateValue !== void 0) {
      if (typeof instruction.immediateValue === "bigint") {
        return `${addressStr}  ${mnemonic} 0x${instruction.immediateValue.toString(16).toUpperCase()}`;
      } else {
        return `${addressStr}  ${mnemonic} 0x${instruction.immediateValue.toString(16).toUpperCase()}`;
      }
    } else if (instruction.operands.length > 0) {
      const ops = instruction.operands.map((op) => `0x${op.toString(16)}`).join(", ");
      return `${addressStr}  ${mnemonic} ${ops}`;
    } else {
      return `${addressStr}  ${mnemonic}`;
    }
  }
  /**
   * Get mnemonic for opcode
   */
  getMnemonic(opcodeValue) {
    const mnemonics = {
      104: "PUSH",
      88: "POP",
      1: "ADD",
      41: "SUB",
      247: "MUL",
      33: "AND",
      9: "OR",
      49: "XOR",
      57: "CMP",
      235: "JMP",
      116: "JZ",
      117: "JNZ",
      144: "NOP",
      255: "CALL",
      195: "RET",
      139: "MOV",
      137: "MOV"
    };
    return mnemonics[opcodeValue] || `OP_${opcodeValue.toString(16).toUpperCase()}`;
  }
  /**
   * Register custom opcode with mnemonic
   */
  registerOpcode(value, mnemonic) {
    this.knownOpcodes.add(value);
  }
  /**
   * Get statistics about bytecode
   */
  getStatistics() {
    const instructions = this.decodeSequence(this.baseAddress, 1e4);
    const uniqueOpcodes = new Set(instructions.map((i) => i.opcodeValue));
    return {
      totalSize: this.bytecode.length,
      instructionCount: instructions.length,
      uniqueOpcodes: uniqueOpcodes.size,
      validInstructions: instructions.filter((i) => i.isValid).length,
      errors: instructions.filter((i) => !i.isValid).length
    };
  }
}
class RealtimeBytecodeExecutor {
  constructor(engine, bytecode, baseAddress = 0, config) {
    this.unknownOpcodes = /* @__PURE__ */ new Set();
    this.semanticAnalyzer = OpcodeSemanticAnalyzer;
    this.engine = engine;
    this.decoder = new BytecodeDecoder(bytecode, baseAddress, config?.decoderConfig);
    this.config = config || {};
  }
  /**
   * Execute single instruction from bytecode at VIP
   * Returns how many bytes were consumed
   */
  executeInstruction() {
    const vip = this.engine.getStateManager().getVIP();
    const instruction = this.decoder.decode(vip);
    if (!instruction.isValid) {
      if (instruction.error) {
        this.engine.getStateManager().halt(instruction.error);
      } else {
        this.engine.getStateManager().halt(`Invalid instruction at 0x${vip.toString(16)}`);
      }
      return 0;
    }
    this.executeDecodedInstruction(instruction);
    return instruction.size;
  }
  executeStep() {
    const vip = this.engine.getStateManager().getVIP();
    const stateBefore = this.engine.getStateManager().getState();
    const instruction = this.decoder.decode(vip);
    if (!instruction.isValid) {
      if (instruction.error) {
        this.engine.getStateManager().halt(instruction.error);
      } else {
        this.engine.getStateManager().halt(`Invalid instruction at 0x${vip.toString(16)}`);
      }
      return { state: this.engine.getStateManager().getState(), traceEntry: null };
    }
    this.executeDecodedInstruction(instruction);
    const stateAfter = this.engine.getStateManager().getState();
    const diff = VMStateManager.diff(stateBefore, stateAfter);
    const traceEntry = {
      index: 0,
      timestamp: Date.now(),
      address: vip,
      opcodeValue: instruction.opcodeValue,
      handlerId: void 0,
      handlerLabel: void 0,
      mnemonic: this.decoder.disassemble(instruction),
      operands: "",
      stackDelta: diff.stackDelta,
      registersChanged: diff.registersChanged,
      flagsChanged: diff.flagsChanged
    };
    return { state: stateAfter, traceEntry };
  }
  /**
   * Execute a decoded instruction
   */
  executeDecodedInstruction(instruction) {
    const opcode = instruction.opcodeValue;
    let signature = OpcodeSemanticAnalyzer.getKnownSignature(opcode);
    if (!signature) {
      signature = OpcodeSemanticAnalyzer.analyzeOpcode(opcode, {
        frequency: 1
      });
      if (this.config.recordUnknownOpcodes) {
        this.unknownOpcodes.add(opcode);
      }
    }
    this.executeBySemanticType(instruction, signature.type, instruction.immediateValue);
  }
  /**
   * Execute instruction based on semantic type
   */
  executeBySemanticType(instruction, semanticType, immediate) {
    switch (semanticType) {
      // Stack operations
      case OpcodeSemanticType.STACK_PUSH:
        if (immediate !== void 0) {
          this.engine.push(BigInt(immediate));
        }
        break;
      case OpcodeSemanticType.STACK_POP:
        this.engine.pop();
        break;
      case OpcodeSemanticType.STACK_DUP:
        this.engine.push(this.engine.getStateManager().peek());
        break;
      case OpcodeSemanticType.STACK_SWAP: {
        const a = this.engine.pop();
        const b = this.engine.pop();
        this.engine.push(a);
        this.engine.push(b);
        break;
      }
      // Arithmetic
      case OpcodeSemanticType.ARITH_ADD: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a + b);
        break;
      }
      case OpcodeSemanticType.ARITH_SUB: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a - b);
        break;
      }
      case OpcodeSemanticType.ARITH_MUL: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a * b);
        break;
      }
      case OpcodeSemanticType.ARITH_DIV: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        if (b === 0n) {
          this.engine.getStateManager().halt("Division by zero");
        } else {
          this.engine.push(a / b);
        }
        break;
      }
      case OpcodeSemanticType.ARITH_MOD: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        if (b === 0n) {
          this.engine.getStateManager().halt("Modulo by zero");
        } else {
          this.engine.push(a % b);
        }
        break;
      }
      // Logic
      case OpcodeSemanticType.LOGIC_AND: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a & b);
        break;
      }
      case OpcodeSemanticType.LOGIC_OR: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a | b);
        break;
      }
      case OpcodeSemanticType.LOGIC_XOR: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a ^ b);
        break;
      }
      // Comparison
      case OpcodeSemanticType.CMP_EQ: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a === b ? 1n : 0n);
        break;
      }
      case OpcodeSemanticType.CMP_NE: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a !== b ? 1n : 0n);
        break;
      }
      case OpcodeSemanticType.CMP_LT: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a < b ? 1n : 0n);
        break;
      }
      case OpcodeSemanticType.CMP_LE: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a <= b ? 1n : 0n);
        break;
      }
      case OpcodeSemanticType.CMP_GT: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a > b ? 1n : 0n);
        break;
      }
      case OpcodeSemanticType.CMP_GE: {
        const b = this.engine.pop();
        const a = this.engine.pop();
        this.engine.push(a >= b ? 1n : 0n);
        break;
      }
      case OpcodeSemanticType.ARITH_NEG: {
        const a = this.engine.pop();
        this.engine.push(-a);
        break;
      }
      case OpcodeSemanticType.LOGIC_SHL: {
        const count = this.engine.pop();
        const value = this.engine.pop();
        this.engine.push(value << count);
        break;
      }
      case OpcodeSemanticType.LOGIC_SHR: {
        const count = this.engine.pop();
        const value = this.engine.pop();
        this.engine.push(value >> count);
        break;
      }
      // Control Flow
      case OpcodeSemanticType.JMP_UNCONDITIONAL:
        if (immediate !== void 0) {
          const nextVip = instruction.address + instruction.size;
          this.engine.setVIP(nextVip + Number(immediate));
          return;
        }
        break;
      case OpcodeSemanticType.JMP_IF_ZERO:
        if (immediate !== void 0) {
          const top = this.engine.getStateManager().peek();
          if (top === 0n) {
            const nextVip = instruction.address + instruction.size;
            this.engine.setVIP(nextVip + Number(immediate));
            return;
          }
        }
        break;
      case OpcodeSemanticType.JMP_IF_NOT_ZERO:
        if (immediate !== void 0) {
          const top = this.engine.getStateManager().peek();
          if (top !== 0n) {
            const nextVip = instruction.address + instruction.size;
            this.engine.setVIP(nextVip + Number(immediate));
            return;
          }
        }
        break;
      // NOP
      case OpcodeSemanticType.NOP:
        break;
      // Unknown
      case OpcodeSemanticType.UNKNOWN:
        if (this.config.validateInstructions) {
          this.engine.getStateManager().halt(`Unknown opcode: 0x${instruction.opcodeValue.toString(16)}`);
          return;
        }
        break;
    }
    this.engine.advanceVIP(instruction.size);
  }
  /**
   * Run until halt or breakpoint using realtime execution
   */
  run() {
    let stepsExecuted = 0;
    const maxSteps = this.engine.getConfig().maxSteps;
    while (!this.engine.getStateManager().isHalted() && stepsExecuted < maxSteps) {
      const vip = this.engine.getStateManager().getVIP();
      if (stepsExecuted > 0 && this.engine.getBreakpoints().has(vip)) {
        return { state: this.engine.getStateManager().getState(), stepsExecuted, reason: "breakpoint" };
      }
      this.executeInstruction();
      stepsExecuted++;
    }
    let reason = "completed";
    if (this.engine.getStateManager().isHalted()) {
      reason = this.engine.getStateManager().getError() || "halted";
    } else if (stepsExecuted >= maxSteps) {
      reason = "max_steps_reached";
    }
    return { state: this.engine.getStateManager().getState(), stepsExecuted, reason };
  }
  /**
   * Get list of unknown opcodes encountered
   */
  getUnknownOpcodes() {
    return Array.from(this.unknownOpcodes);
  }
  /**
   * Get disassembly of bytecode
   */
  disassemble(startVip, count = 50) {
    const vip = startVip ?? this.engine.getConfig().initialVIP;
    const instructions = this.decoder.decodeSequence(vip, count);
    return instructions.map((instr) => this.decoder.disassemble(instr));
  }
  /**
   * Get statistics about bytecode execution
   */
  getStatistics() {
    return this.decoder.getStatistics();
  }
}
let pluginAuthToken = process.env["VMTRACE_PLUGIN_TOKEN"] || null;
const supportedPluginLaunchers = {
  ".py": { command: "python", argBuilder: (filePath) => [filePath] },
  ".js": { command: "node", argBuilder: (filePath) => [filePath] },
  ".mjs": { command: "node", argBuilder: (filePath) => [filePath] },
  ".exe": { command: "", argBuilder: () => [] },
  ".jar": { command: "java", argBuilder: (filePath) => ["-jar", filePath] },
  ".java": { command: "", argBuilder: () => [] },
  ".bat": { command: "", argBuilder: () => [] },
  ".cmd": { command: "", argBuilder: () => [] },
  ".cpp": { command: "", argBuilder: () => [] }
};
const pluginProcesses = /* @__PURE__ */ new Map();
function createPluginProcessInfo(filePath, command, args) {
  return {
    path: filePath,
    command,
    args,
    startedAt: /* @__PURE__ */ new Date(),
    status: "starting",
    exitCode: null
  };
}
function getPluginLauncher(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const launcher = supportedPluginLaunchers[ext];
  if (!launcher) {
    return null;
  }
  let command = launcher.command || filePath;
  let args = launcher.argBuilder(filePath);
  if (ext === ".py") {
    const venvPython = findWorkspaceVenvPython();
    if (venvPython) {
      command = venvPython;
      args = launcher.argBuilder(filePath);
    }
  }
  return { command, args };
}
function findWorkspaceVenvPython() {
  try {
    const winPath = path.join(process.cwd(), "venv", "Scripts", "python.exe");
    const nixPath = path.join(process.cwd(), "venv", "bin", "python");
    if (fs.existsSync(winPath)) return winPath;
    if (fs.existsSync(nixPath)) return nixPath;
  } catch {
  }
  return null;
}
function checkCommandAvailable(command, args = ["--version"]) {
  try {
    const res = child_process.spawnSync(command, args, { encoding: "utf8", shell: false });
    return res.status === 0;
  } catch {
    return false;
  }
}
function checkPythonHasModule(pythonExe, moduleName) {
  try {
    const res = child_process.spawnSync(pythonExe, ["-c", `import ${moduleName}`], { encoding: "utf8", shell: false });
    return res.status === 0;
  } catch {
    return false;
  }
}
function compileJavaSource(filePath) {
  try {
    const outputDir = path.dirname(filePath);
    const compile = child_process.spawnSync("javac", ["-d", outputDir, filePath], { encoding: "utf8", shell: false });
    if (compile.status !== 0) {
      return { success: false, stdout: compile.stdout || "", stderr: compile.stderr || "", error: "Java compilation failed" };
    }
    return { success: true, stdout: compile.stdout || "", stderr: compile.stderr || "" };
  } catch (err) {
    return { success: false, stdout: "", stderr: err.message, error: err.message };
  }
}
function installDeps(packages, pythonExe) {
  try {
    const python = pythonExe || findWorkspaceVenvPython() || "python";
    const args = ["-m", "pip", "install", ...packages];
    const res = child_process.spawnSync(python, args, { encoding: "utf8", shell: false });
    return { success: res.status === 0, stdout: res.stdout || "", stderr: res.stderr || "" };
  } catch (err) {
    return { success: false, stdout: "", stderr: err.message };
  }
}
function discoverPluginFiles(folderPath) {
  const entries = fs.readdirSync(folderPath, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(folderPath, entry.name);
    if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (supportedPluginLaunchers[ext] || ext === ".cpp" || ext === ".java") {
        files.push(fullPath);
      }
    }
  }
  return files;
}
function addPluginProcessListeners(filePath, record) {
  const proc = record.process;
  if (!proc) return;
  proc.on("spawn", () => {
    record.info.status = "running";
    broadcastProcessesToUI();
  });
  proc.on("exit", (code) => {
    record.info.status = "exited";
    record.info.exitCode = code;
    pluginProcesses.delete(filePath);
    broadcastProcessesToUI();
  });
  proc.on("error", (err) => {
    record.info.status = "failed";
    record.info.error = err.message;
    record.info.exitCode = null;
    pluginProcesses.delete(filePath);
    broadcastProcessesToUI();
  });
}
function startPluginProcess(filePath) {
  if (pluginProcesses.has(filePath)) {
    const existing = pluginProcesses.get(filePath);
    if (existing) {
      existing.info.status = "already-running";
      return existing.info;
    }
  }
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".cpp") {
    try {
      const check = child_process.spawnSync("g++", ["--version"], { encoding: "utf8", shell: false });
      if (check.status !== 0) {
        return {
          path: filePath,
          command: "g++",
          args: [],
          startedAt: /* @__PURE__ */ new Date(),
          status: "failed",
          exitCode: check.status,
          error: "g++ no encontrado. Instala MinGW/LLVM/Visual Studio y añade g++ al PATH."
        };
      }
    } catch (err) {
      return {
        path: filePath,
        command: "g++",
        args: [],
        startedAt: /* @__PURE__ */ new Date(),
        status: "failed",
        exitCode: null,
        error: "g++ no disponible: " + (err.message || String(err))
      };
    }
    const parsed = require("path").parse(filePath);
    const outPath = require("path").join(parsed.dir, parsed.name + (process.platform === "win32" ? ".exe" : ""));
    const compileArgs = ["-std=c++17", filePath, "-O2", "-o", outPath];
    const compile = child_process.spawnSync("g++", compileArgs, { encoding: "utf8", shell: false });
    logMessage("system_compiler", "g++", "out", `Compilar ${filePath} -> stdout:
${compile.stdout}
stderr:
${compile.stderr}`);
    if (compile.status !== 0) {
      return {
        path: filePath,
        command: "g++",
        args: compileArgs,
        startedAt: /* @__PURE__ */ new Date(),
        status: "failed",
        exitCode: compile.status,
        error: "Fallo la compilación. Revisa los logs."
      };
    }
    const spawnOptions2 = { shell: true, cwd: parsed.dir };
    const child2 = child_process.spawn(outPath, [], spawnOptions2);
    const info2 = createPluginProcessInfo(filePath, outPath, []);
    const record2 = { info: info2, process: child2 };
    pluginProcesses.set(filePath, record2);
    addPluginProcessListeners(filePath, record2);
    return info2;
  }
  const launcher = getPluginLauncher(filePath);
  if (!launcher) {
    return {
      path: filePath,
      command: "",
      args: [],
      startedAt: /* @__PURE__ */ new Date(),
      status: "failed",
      exitCode: null,
      error: "Tipo de plugin no soportado"
    };
  }
  const spawnOptions = {
    shell: true,
    cwd: path.dirname(filePath)
  };
  if (ext === ".py") {
    const pythonExe = launcher.command || "python";
    const hasWebsocket = checkPythonHasModule(pythonExe, "websocket");
    if (!hasWebsocket) {
      return {
        path: filePath,
        command: pythonExe,
        args: launcher.args,
        startedAt: /* @__PURE__ */ new Date(),
        status: "failed",
        exitCode: null,
        error: `Módulo Python "websocket" no encontrado. Instala con: ${pythonExe} -m pip install websocket-client`
      };
    }
  }
  if (ext === ".jar" || ext === ".java") {
    if (!checkCommandAvailable("java", ["-version"])) {
      return {
        path: filePath,
        command: "java",
        args: launcher.args,
        startedAt: /* @__PURE__ */ new Date(),
        status: "failed",
        exitCode: null,
        error: "Java no encontrado. Instala JDK/JRE y asegúrate de que java esté en el PATH."
      };
    }
    if (ext === ".java") {
      if (!checkCommandAvailable("javac", ["-version"])) {
        return {
          path: filePath,
          command: "javac",
          args: [],
          startedAt: /* @__PURE__ */ new Date(),
          status: "failed",
          exitCode: null,
          error: "javac no encontrado. Instala JDK y asegúrate de que javac esté en el PATH."
        };
      }
      const compileRes = compileJavaSource(filePath);
      if (!compileRes.success) {
        return {
          path: filePath,
          command: "javac",
          args: ["-d", path.dirname(filePath), filePath],
          startedAt: /* @__PURE__ */ new Date(),
          status: "failed",
          exitCode: null,
          error: `Fallo la compilación Java: ${compileRes.stderr || compileRes.error}`
        };
      }
      const className = path.basename(filePath, ".java");
      launcher.command = "java";
      launcher.args = ["-cp", path.dirname(filePath), className];
    }
  }
  if (ext === ".cpp") {
    if (!checkCommandAvailable("g++", ["--version"])) {
      return {
        path: filePath,
        command: "g++",
        args: [],
        startedAt: /* @__PURE__ */ new Date(),
        status: "failed",
        exitCode: null,
        error: "g++ no encontrado. Instala un compilador C++ y añádelo al PATH."
      };
    }
  }
  const child = child_process.spawn(launcher.command, launcher.args, spawnOptions);
  const info = createPluginProcessInfo(filePath, launcher.command, launcher.args);
  const record = { info, process: child };
  pluginProcesses.set(filePath, record);
  addPluginProcessListeners(filePath, record);
  return info;
}
function loadPluginsFromFolder(folderPath) {
  const warnings = [];
  let files = [];
  try {
    const stats = fs.statSync(folderPath);
    if (!stats.isDirectory()) {
      throw new Error("La ruta seleccionada no es una carpeta válida.");
    }
    files = discoverPluginFiles(folderPath);
  } catch (error) {
    return { folderPath, discovered: 0, results: [], warnings: [error.message || "Error al leer la carpeta"] };
  }
  if (files.length === 0) {
    return { folderPath, discovered: 0, results: [], warnings: ["No se encontraron archivos de plugin compatibles en la carpeta."] };
  }
  const results = [];
  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    if (supportedPluginLaunchers[ext]) {
      results.push(startPluginProcess(filePath));
    } else {
      results.push({
        path: filePath,
        command: "",
        args: [],
        startedAt: /* @__PURE__ */ new Date(),
        status: "failed",
        exitCode: null,
        error: `Extensión de plugin encontrada, pero no se puede iniciar automáticamente: ${ext}`
      });
    }
  }
  return { folderPath, discovered: files.length, results, warnings };
}
function getLoadedPluginProcesses() {
  return Array.from(pluginProcesses.values()).map((record) => record.info);
}
function startPlugin(filePath) {
  const info = startPluginProcess(filePath);
  broadcastProcessesToUI();
  return info;
}
function stopPlugin(filePath) {
  const record = pluginProcesses.get(filePath);
  if (!record) {
    return { success: false };
  }
  try {
    if (record.process && !record.process.killed) {
      record.process.kill();
      record.info.status = "exited";
    }
  } catch (err) {
    record.info.status = "failed";
    record.info.error = err.message;
  }
  pluginProcesses.delete(filePath);
  broadcastProcessesToUI();
  return { success: true, info: record.info };
}
let wss = null;
const connectedPlugins = /* @__PURE__ */ new Map();
let nextClientId = 1;
const pluginLogs = [];
const MAX_LOGS = 500;
function getConnectionToken(request) {
  if (!request || !request.url) return null;
  try {
    const url = new URL(request.url, "ws://localhost");
    return url.searchParams.get("token") || null;
  } catch {
    return null;
  }
}
function startPluginServer(port = 57130, authToken) {
  if (wss) {
    stopPluginServer();
  }
  try {
    wss = new ws.WebSocketServer({ port });
    wss.on("connection", (ws2, request) => {
      const token = getConnectionToken(request || null);
      if (pluginAuthToken && token !== pluginAuthToken) {
        const message = JSON.stringify({ error: "Unauthorized plugin connection: invalid token" });
        ws2.send(message);
        ws2.close(1008, "Unauthorized");
        return;
      }
      const clientId = `plugin_${nextClientId++}`;
      const pluginInfo = {
        id: clientId,
        ws: ws2,
        name: "Generic Client",
        connectedAt: /* @__PURE__ */ new Date(),
        subscriptions: /* @__PURE__ */ new Set()
      };
      connectedPlugins.set(clientId, pluginInfo);
      logMessage(clientId, "System", "in", `New client connected from remote address. Assigned ID: ${clientId}`);
      broadcastPluginsToUI();
      ws2.on("message", (messageBuffer) => {
        const rawMessage = messageBuffer.toString();
        try {
          const request2 = JSON.parse(rawMessage);
          logMessage(clientId, pluginInfo.name, "in", rawMessage);
          handleJsonRpc(pluginInfo, request2);
        } catch (e) {
          const errorResponse = {
            jsonrpc: "2.0",
            error: { code: -32700, message: "Parse error" },
            id: null
          };
          ws2.send(JSON.stringify(errorResponse));
          logMessage(clientId, pluginInfo.name, "out", JSON.stringify(errorResponse));
        }
      });
      ws2.on("close", () => {
        connectedPlugins.delete(clientId);
        logMessage(clientId, pluginInfo.name, "in", `Client disconnected.`);
        broadcastPluginsToUI();
      });
      ws2.on("error", (err) => {
        logMessage(clientId, pluginInfo.name, "in", `Error: ${err.message}`);
      });
    });
    console.log(`Plugin WebSocket server listening on ws://localhost:${port}`);
  } catch (error) {
    console.error(`Failed to start plugin server: ${error.message}`);
  }
}
function stopPluginServer() {
  if (wss) {
    for (const [id, plugin] of connectedPlugins) {
      plugin.ws.close();
    }
    connectedPlugins.clear();
    wss.close(() => {
      console.log("Plugin server stopped.");
    });
    wss = null;
    broadcastPluginsToUI();
  }
  for (const [filePath, record] of pluginProcesses) {
    if (record.process && !record.process.killed) {
      try {
        record.process.kill();
      } catch {
      }
    }
    record.info.status = "exited";
  }
  pluginProcesses.clear();
}
function getConnectedPlugins() {
  return Array.from(connectedPlugins.values()).map((p) => ({
    id: p.id,
    name: p.name,
    connectedAt: p.connectedAt.toISOString(),
    subscriptions: Array.from(p.subscriptions)
  }));
}
function getPluginLogs() {
  return [...pluginLogs];
}
function handleJsonRpc(plugin, request) {
  if (request.jsonrpc !== "2.0") {
    sendError(plugin, -32600, "Invalid Request", request.id);
    return;
  }
  const { method, params, id } = request;
  const hasId = id !== void 0 && id !== null;
  try {
    let result = null;
    switch (method) {
      // ─── System / Registration ───
      case "plugin.register": {
        plugin.name = params?.name || "Unnamed Plugin";
        result = { success: true, clientId: plugin.id };
        broadcastPluginsToUI();
        break;
      }
      case "plugin.subscribe": {
        const events = params?.events || [];
        for (const ev of events) {
          plugin.subscriptions.add(ev);
        }
        result = { success: true, activeSubscriptions: Array.from(plugin.subscriptions) };
        break;
      }
      case "plugin.unsubscribe": {
        const events = params?.events || [];
        for (const ev of events) {
          plugin.subscriptions.delete(ev);
        }
        result = { success: true, activeSubscriptions: Array.from(plugin.subscriptions) };
        break;
      }
      // ─── Emulation Control ───
      case "vm.step": {
        const stepResult = engineManager.step();
        result = {
          vip: stepResult.state.vip.toString(),
          vsp: stepResult.state.vsp,
          halted: stepResult.state.halted,
          error: stepResult.state.error,
          stack: stepResult.state.stack.map((s) => s.toString()),
          registers: Object.fromEntries(
            Object.entries(stepResult.state.registers).map(([k, v]) => [k, v.toString()])
          )
        };
        break;
      }
      case "vm.stepOver": {
        const stepResult = engineManager.stepOver();
        result = {
          vip: stepResult.state.vip.toString(),
          vsp: stepResult.state.vsp,
          halted: stepResult.state.halted,
          error: stepResult.state.error,
          stack: stepResult.state.stack.map((s) => s.toString()),
          registers: Object.fromEntries(
            Object.entries(stepResult.state.registers).map(([k, v]) => [k, v.toString()])
          )
        };
        break;
      }
      case "vm.run": {
        const runResult = engineManager.run();
        result = {
          stepsExecuted: runResult.stepsExecuted,
          reason: runResult.reason,
          state: {
            vip: runResult.state.vip.toString(),
            vsp: runResult.state.vsp,
            halted: runResult.state.halted,
            error: runResult.state.error,
            stack: runResult.state.stack.map((s) => s.toString())
          }
        };
        break;
      }
      case "vm.stop": {
        engineManager.stop();
        result = { success: true };
        break;
      }
      case "vm.reset": {
        engineManager.reset();
        result = { success: true };
        break;
      }
      // ─── Emulation State ───
      case "vm.getState": {
        const engine = engineManager.getEngine();
        if (!engine) {
          throw new Error("No binary loaded");
        }
        const state = engine.getStateManager().getState();
        result = {
          vip: state.vip.toString(),
          vsp: state.vsp,
          halted: state.halted,
          error: state.error,
          stack: state.stack.map((s) => s.toString()),
          registers: Object.fromEntries(
            Object.entries(state.registers).map(([k, v]) => [k, v.toString()])
          ),
          flags: state.flags
        };
        break;
      }
      case "vm.setState": {
        const engine = engineManager.getEngine();
        if (!engine) {
          throw new Error("No binary loaded");
        }
        const stateManager = engine.getStateManager();
        if (params.registers) {
          for (const [reg, val] of Object.entries(params.registers)) {
            stateManager.setReg(reg, BigInt(val));
          }
        }
        if (params.vip) {
          stateManager.setVIP(Number(params.vip));
        }
        if (params.vsp) {
          stateManager.setVSP(Number(params.vsp));
        }
        if (params.stack) {
          const stackList = params.stack.map((s) => BigInt(s));
          const st = stateManager.getState();
          st.stack = stackList;
          stateManager.setState(st);
        }
        result = { success: true };
        break;
      }
      // ─── Analysis Data ───
      case "vm.getBinaryInfo": {
        const info = engineManager.getBinaryInfo();
        if (!info) {
          throw new Error("No binary loaded");
        }
        result = info;
        break;
      }
      case "vm.getCFG": {
        const engine = engineManager.getEngine();
        if (!engine) {
          throw new Error("No binary loaded");
        }
        result = engineManager.getVMModel().cfg;
        break;
      }
      case "vm.getTrace": {
        const engine = engineManager.getEngine();
        if (!engine) {
          throw new Error("No binary loaded");
        }
        const trace = engine.getTraceRecorder().getAll();
        result = trace.map((t2) => ({
          ...t2,
          address: t2.address.toString(),
          stackDelta: t2.stackDelta,
          registersChanged: t2.registersChanged,
          flagsChanged: t2.flagsChanged
        }));
        break;
      }
      case "vm.getBytecodeStatistics": {
        const engine = engineManager.getEngine();
        if (!engine) {
          throw new Error("No binary loaded");
        }
        const bytecode = engine.getBytecode();
        if (!bytecode) {
          throw new Error("No bytecode loaded");
        }
        const analyzer = new BytecodeAnalyzer(bytecode, engine.getBytecodeBase());
        result = analyzer.getStatistics();
        break;
      }
      case "vm.findJumpTables": {
        const engine = engineManager.getEngine();
        if (!engine) {
          throw new Error("No binary loaded");
        }
        const bytecode = engine.getBytecode();
        if (!bytecode) {
          throw new Error("No bytecode loaded");
        }
        const analyzer = new BytecodeAnalyzer(bytecode, engine.getBytecodeBase());
        result = analyzer.findJumpTables();
        break;
      }
      case "vm.getBytecodeDisassembly": {
        const engine = engineManager.getEngine();
        if (!engine) {
          throw new Error("No binary loaded");
        }
        const bytecode = engine.getBytecode();
        if (!bytecode) {
          throw new Error("No bytecode loaded");
        }
        const baseAddress = engine.getBytecodeBase();
        const decoder = new BytecodeDecoder(bytecode, baseAddress, { variableLengthOpcodes: true, unknownOpcodeHandling: "fallback" });
        const startVip = params?.startVip ? Number(params.startVip) : baseAddress;
        const count = params?.count ? Number(params.count) : 100;
        const instructions = decoder.decodeSequence(startVip, count);
        result = instructions.map((instr) => decoder.disassemble(instr));
        break;
      }
      case "vm.getHandlers": {
        const engine = engineManager.getEngine();
        if (!engine) {
          throw new Error("No binary loaded");
        }
        result = engine.getHandlers().map((h) => ({
          id: h.id,
          address: h.address.toString(),
          endAddress: h.endAddress.toString(),
          size: h.size,
          opcodeValue: h.opcodeValue,
          label: h.label,
          hypothesis: h.hypothesis,
          executionCount: h.executionCount
        }));
        break;
      }
      case "vm.setHandlerLabel": {
        const address = Number(params?.address);
        const label = params?.label || "";
        if (isNaN(address)) {
          throw new Error("Invalid address");
        }
        engineManager.setHandlerLabel(address, label);
        result = { success: true };
        break;
      }
      case "vm.setHandlerHypothesis": {
        const address = Number(params?.address);
        const hypothesis = params?.hypothesis || "";
        if (isNaN(address)) {
          throw new Error("Invalid address");
        }
        engineManager.setHandlerHypothesis(address, hypothesis);
        result = { success: true };
        break;
      }
      default:
        sendError(plugin, -32601, `Method '${method}' not found`, id);
        return;
    }
    if (hasId) {
      sendResult(plugin, result, id);
    }
  } catch (error) {
    if (hasId) {
      sendError(plugin, -32e3, error.message || "Internal server error", id);
    }
  }
}
function notifyPluginEvent(eventName, payload) {
  const notification = {
    jsonrpc: "2.0",
    method: eventName,
    params: formatBigInts(payload)
  };
  const rawMsg = JSON.stringify(notification);
  for (const [id, plugin] of connectedPlugins) {
    if (plugin.subscriptions.has(eventName) || plugin.subscriptions.has("*")) {
      try {
        plugin.ws.send(rawMsg);
        logMessage(plugin.id, plugin.name, "out", rawMsg);
      } catch (err) {
        console.error(`Failed to notify plugin ${plugin.name}:`, err);
      }
    }
  }
}
function sendResult(plugin, result, id) {
  const response = {
    jsonrpc: "2.0",
    result: formatBigInts(result),
    id
  };
  const rawResponse = JSON.stringify(response);
  plugin.ws.send(rawResponse);
  logMessage(plugin.id, plugin.name, "out", rawResponse);
}
function sendError(plugin, code, message, id) {
  const response = {
    jsonrpc: "2.0",
    error: { code, message },
    id
  };
  const rawResponse = JSON.stringify(response);
  plugin.ws.send(rawResponse);
  logMessage(plugin.id, plugin.name, "out", rawResponse);
}
function logMessage(pluginId, pluginName, direction, message) {
  const log = {
    timestamp: (/* @__PURE__ */ new Date()).toLocaleTimeString(),
    pluginId,
    pluginName,
    direction,
    message
  };
  pluginLogs.push(log);
  if (pluginLogs.length > MAX_LOGS) {
    pluginLogs.shift();
  }
  broadcastLogsToUI();
}
function formatBigInts(obj) {
  if (obj === null || obj === void 0) return obj;
  if (typeof obj === "bigint") return obj.toString();
  if (Array.isArray(obj)) return obj.map(formatBigInts);
  if (typeof obj === "object") {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k, formatBigInts(v)])
    );
  }
  return obj;
}
let activeUIWindow = null;
function registerUIForPluginUpdates(window) {
  activeUIWindow = window;
}
function broadcastPluginsToUI() {
  if (activeUIWindow) {
    activeUIWindow.webContents.send("plugin:list-updated", getConnectedPlugins());
  }
}
function broadcastLogsToUI() {
  if (activeUIWindow) {
    activeUIWindow.webContents.send("plugin:logs-updated", getPluginLogs());
  }
}
function broadcastProcessesToUI() {
  if (activeUIWindow) {
    activeUIWindow.webContents.send("plugin:processes-updated", getLoadedPluginProcesses());
  }
}
class EngineManager {
  constructor() {
    this.engine = null;
    this.realtimeExecutor = null;
    this.executionMode = "handlers";
    this.binaryPath = null;
    this.binaryInfo = null;
    this.bookmarks = [];
    this.userComments = {};
    this.handlerLabels = {};
    this.handlerHypotheses = {};
    this.mainWindow = null;
  }
  setMainWindow(window) {
    this.mainWindow = window;
  }
  getEngine() {
    return this.engine;
  }
  getBinaryInfo() {
    return this.binaryInfo;
  }
  getBookmarks() {
    return this.bookmarks;
  }
  getUserComments() {
    return this.userComments;
  }
  getHandlerLabels() {
    return this.handlerLabels;
  }
  getHandlerHypotheses() {
    return this.handlerHypotheses;
  }
  // ─── Actions ────────────────────────────────────────────────────────
  loadBinaryFile(filePath) {
    this.binaryPath = filePath;
    this.binaryInfo = loadBinary(filePath);
    this.engine = new VMEngine({
      initialVIP: this.binaryInfo.entryPoint,
      opcodeSize: 1
      // Default to 1-byte opcodes, configurable
    });
    const execSections = this.binaryInfo.sections.filter((s) => s.isExecutable);
    if (execSections.length > 0) {
      const mainSec = execSections[0];
      const data = getLoadedData();
      if (data) {
        const sectionBytes = data.subarray(mainSec.rawAddress, mainSec.rawAddress + mainSec.rawSize);
        if (sectionBytes.length === 0) {
          throw new Error(`Executable section ${mainSec.name} contains no data`);
        }
        this.engine.setBytecode(sectionBytes, mainSec.virtualAddress);
        let phase1Result = null;
        try {
          const detector = new DynamicHandlerDetector(
            Buffer.from(sectionBytes),
            mainSec.virtualAddress
          );
          const detectionResult = detector.detectHandlers();
          phase1Result = detectionResult;
          if (detectionResult.confidence > 0.5 && detectionResult.handlersCreated.length > 0) {
            console.log(
              `[Phase 1] ${t("analysis.phase1_success", { count: detectionResult.handlersCreated.length, confidence: (detectionResult.confidence * 100).toFixed(1) })}`
            );
            this.engine.setHandlers(detectionResult.handlersCreated);
            this.executionMode = "handlers";
            console.log(`[Phase 2] Starting semantic analysis...`);
            try {
              const semanticAnalyzer = new HandlerSemanticAnalyzer(
                Buffer.from(sectionBytes),
                mainSec.virtualAddress
              );
              const semanticResult = semanticAnalyzer.analyzeAndBuild(
                this.engine,
                detectionResult.handlersCreated
              );
              console.log(
                `[Phase 2] ${t("analysis.phase2_success", { count: semanticResult.successfulExecutors, total: semanticResult.totalHandlers })}`
              );
              console.log(semanticAnalyzer.generateReport(semanticResult));
              this.broadcastToUI("handlers:auto-detected", {
                phase1Result: detectionResult,
                phase1Report: detector.generateReport(detectionResult),
                phase2Result: semanticResult,
                phase2Report: semanticAnalyzer.generateReport(semanticResult),
                totalHandlers: detectionResult.handlersCreated.length,
                buildSuccess: semanticResult.successfulExecutors > 0
              });
            } catch (err) {
              console.warn(`[Phase 2] ${t("analysis.phase2_failed")}:`, err);
              this.broadcastToUI("handlers:auto-detected", {
                phase1Result: detectionResult,
                phase1Report: detector.generateReport(detectionResult),
                phase2Error: String(err),
                totalHandlers: detectionResult.handlersCreated.length,
                buildSuccess: false
              });
            }
          } else {
            console.log(
              `[Phase 1-3] ${t("analysis.phase1_low_confidence", { confidence: (detectionResult.confidence * 100).toFixed(1) })}`
            );
            this.initializeRealtimeExecutor(sectionBytes, mainSec.virtualAddress);
            this.broadcastToUI("handlers:auto-detected", {
              phase1Result: detectionResult,
              phase1Report: detector.generateReport(detectionResult),
              phase2Result: null,
              phase2Error: "Skipped due to low detection confidence",
              totalHandlers: 0,
              buildSuccess: false,
              executionMode: "realtime"
            });
          }
        } catch (err) {
          console.warn(`[Phase 1-3] ${t("analysis.phase1_failed")}:`, err);
          this.initializeRealtimeExecutor(sectionBytes, mainSec.virtualAddress);
          this.broadcastToUI("handlers:auto-detected", {
            phase1Error: String(err),
            executionMode: "realtime"
          });
        }
        if (this.executionMode === "handlers" && this.engine.getHandlers().length === 0) {
          console.log(`[Phase 3] ${t("analysis.phase3_enabled")}`);
          this.initializeRealtimeExecutor(sectionBytes, mainSec.virtualAddress);
        }
      }
    }
    this.bookmarks = [];
    this.userComments = {};
    this.handlerLabels = {};
    this.handlerHypotheses = {};
    this.broadcastToUI("binary:loaded", {
      binaryInfo: this.binaryInfo,
      state: this.engine.getStateManager().getState(),
      executionMode: this.executionMode
    });
    notifyPluginEvent("event.onBinaryLoaded", this.binaryInfo);
    return this.binaryInfo;
  }
  step() {
    if (!this.engine) throw new Error("No binary loaded");
    let result;
    if (this.executionMode === "realtime" && this.realtimeExecutor) {
      const beforeCount = this.engine.getTraceRecorder().getAll().length;
      result = this.realtimeExecutor.executeStep();
      if (result.traceEntry) {
        result.traceEntry.index = beforeCount;
        this.engine.getTraceRecorder().record(result.traceEntry);
      }
    } else {
      result = this.engine.step();
    }
    this.broadcastToUI("vm:state-updated", {
      state: result.state,
      traceEntry: result.traceEntry
    });
    notifyPluginEvent("event.onStep", {
      state: result.state,
      traceEntry: result.traceEntry
    });
    return result;
  }
  stepOver() {
    return this.step();
  }
  run() {
    if (!this.engine) throw new Error("No binary loaded");
    let result;
    if (this.executionMode === "realtime" && this.realtimeExecutor) {
      let stepsExecuted = 0;
      const maxSteps = this.engine.getConfig().maxSteps;
      let reason = "completed";
      while (!this.engine.getStateManager().isHalted() && stepsExecuted < maxSteps) {
        const vip = this.engine.getStateManager().getVIP();
        if (stepsExecuted > 0 && this.engine.getBreakpoints().has(vip)) {
          reason = "breakpoint";
          break;
        }
        const stepResult = this.realtimeExecutor.executeStep();
        if (stepResult.traceEntry) {
          stepResult.traceEntry.index = this.engine.getTraceRecorder().getAll().length;
          this.engine.getTraceRecorder().record(stepResult.traceEntry);
        }
        stepsExecuted++;
        if (stepResult.state.halted) {
          reason = stepResult.state.error || "halted";
          break;
        }
      }
      if (!this.engine.getStateManager().isHalted() && stepsExecuted >= maxSteps) {
        reason = "max_steps_reached";
      }
      result = { state: this.engine.getStateManager().getState(), stepsExecuted, reason };
    } else {
      result = this.engine.run();
    }
    this.broadcastToUI("vm:state-updated", {
      state: result.state,
      traceEntry: null
    });
    notifyPluginEvent("event.onStep", {
      state: result.state,
      traceEntry: null
    });
    return result;
  }
  stop() {
    if (this.engine) {
      this.engine.stop();
    }
  }
  reset() {
    if (!this.engine) return;
    this.engine.reset();
    if (this.executionMode === "realtime" && this.binaryInfo) {
      const execSections = this.binaryInfo.sections.filter((s) => s.isExecutable);
      const mainSec = execSections[0];
      const data = getLoadedData();
      if (mainSec && data) {
        const sectionBytes = data.subarray(mainSec.rawAddress, mainSec.rawAddress + mainSec.rawSize);
        this.initializeRealtimeExecutor(sectionBytes, mainSec.virtualAddress);
      }
    }
    this.broadcastToUI("vm:state-updated", {
      state: this.engine.getStateManager().getState(),
      traceEntry: null
    });
  }
  setHandlerLabel(address, label) {
    const addrHex = `0x${address.toString(16)}`;
    this.handlerLabels[addrHex] = label;
    if (this.engine) {
      const handler = this.engine.getHandlers().find((h) => h.address === address);
      if (handler) {
        handler.label = label;
      }
    }
    this.broadcastToUI("vm:annotations-updated", {
      handlerLabels: this.handlerLabels,
      handlerHypotheses: this.handlerHypotheses
    });
  }
  setHandlerHypothesis(address, hypothesis) {
    const addrHex = `0x${address.toString(16)}`;
    this.handlerHypotheses[addrHex] = hypothesis;
    if (this.engine) {
      const handler = this.engine.getHandlers().find((h) => h.address === address);
      if (handler) {
        handler.hypothesis = hypothesis;
      }
    }
    this.broadcastToUI("vm:annotations-updated", {
      handlerLabels: this.handlerLabels,
      handlerHypotheses: this.handlerHypotheses
    });
  }
  addBookmark(bookmark) {
    this.bookmarks.push(bookmark);
    this.broadcastToUI("bookmarks:updated", this.bookmarks);
  }
  removeBookmark(id) {
    this.bookmarks = this.bookmarks.filter((b) => b.id !== id);
    this.broadcastToUI("bookmarks:updated", this.bookmarks);
  }
  // ─── Helpers ────────────────────────────────────────────────────────
  broadcastToUI(channel, payload) {
    if (this.mainWindow) {
      this.mainWindow.webContents.send(channel, payload);
    }
  }
  initializeRealtimeExecutor(bytecode, baseAddress) {
    if (!this.engine) return;
    this.realtimeExecutor = new RealtimeBytecodeExecutor(this.engine, bytecode, baseAddress, {
      decoderConfig: {
        opcodeSize: this.engine.getConfig().opcodeSize,
        unknownOpcodeHandling: "fallback",
        variableLengthOpcodes: true
      },
      validateInstructions: true,
      recordUnknownOpcodes: true
    });
    this.executionMode = "realtime";
    this.broadcastToUI("execution:mode-changed", { mode: "realtime" });
  }
  appendDynamicCFGEdges(edges, handlerNodeIds) {
    if (!this.engine) return;
    const trace = this.engine.getTraceRecorder().getAll();
    if (trace.length < 2) return;
    const transitionCounts = /* @__PURE__ */ new Map();
    for (let i = 1; i < trace.length; i++) {
      const prev = trace[i - 1];
      const next = trace[i];
      if (!prev.handlerId || !next.handlerId) continue;
      const key = `${prev.handlerId}->${next.handlerId}`;
      const existing = transitionCounts.get(key);
      if (existing) {
        existing.count++;
      } else {
        transitionCounts.set(key, { source: prev.handlerId, target: next.handlerId, count: 1 });
      }
    }
    for (const transition of transitionCounts.values()) {
      if (transition.count < 2) continue;
      if (!handlerNodeIds.has(transition.source) || !handlerNodeIds.has(transition.target)) continue;
      const edgeId = `runtime_${transition.source}_to_${transition.target}`;
      edges.push({
        id: edgeId,
        source: transition.source,
        target: transition.target,
        type: "jump",
        label: `runtime x${transition.count}`,
        count: transition.count
      });
    }
  }
  buildCFG() {
    const entryNodeId = "CFG_ENTRY";
    const nodes = [
      {
        id: entryNodeId,
        address: this.binaryInfo?.entryPoint ?? 0,
        endAddress: this.binaryInfo?.entryPoint ?? 0,
        type: "entry",
        label: "VM Entry",
        instructionCount: 0,
        instructions: []
      }
    ];
    const edges = [];
    if (this.engine) {
      const handlers = this.engine.getHandlers();
      const dispatcher = this.engine.getDispatcher();
      if (handlers.length > 0) {
        if (dispatcher) {
          const dispatcherId = "CFG_DISPATCHER";
          nodes.push({
            id: dispatcherId,
            address: dispatcher.address,
            endAddress: dispatcher.endAddress,
            type: "block",
            label: "Dispatcher",
            instructionCount: 1,
            instructions: []
          });
          edges.push({ id: `${entryNodeId}_to_${dispatcherId}`, source: entryNodeId, target: dispatcherId, type: "fallthrough" });
          handlers.forEach((handler) => {
            nodes.push({
              id: handler.id,
              address: handler.address,
              endAddress: handler.endAddress,
              type: "handler",
              label: handler.label || `OP_${handler.opcodeValue.toString(16).toUpperCase()}`,
              handlerType: handler.type,
              instructionCount: Math.max(1, handler.size),
              instructions: []
            });
            edges.push({
              id: `dispatch_${handler.id}`,
              source: dispatcherId,
              target: handler.id,
              type: "dispatch",
              label: `opcode 0x${handler.opcodeValue.toString(16).toUpperCase()}`
            });
          });
        } else {
          handlers.forEach((handler, index) => {
            nodes.push({
              id: handler.id,
              address: handler.address,
              endAddress: handler.endAddress,
              type: "handler",
              label: handler.label || `OP_${handler.opcodeValue.toString(16).toUpperCase()}`,
              handlerType: handler.type,
              instructionCount: Math.max(1, handler.size),
              instructions: []
            });
            edges.push({
              id: `entry_to_${handler.id}`,
              source: entryNodeId,
              target: handler.id,
              type: index === 0 ? "fallthrough" : "dispatch",
              label: index === 0 ? void 0 : `opcode 0x${handler.opcodeValue.toString(16).toUpperCase()}`
            });
          });
        }
      } else if (this.binaryInfo) {
        const execSections = this.binaryInfo.sections.filter((s) => s.isExecutable);
        const mainSection = execSections[0];
        const sectionStart = mainSection?.virtualAddress ?? this.binaryInfo.entryPoint;
        const sectionEnd = mainSection ? mainSection.virtualAddress + mainSection.virtualSize : sectionStart;
        const mainNodeId = "CODE_SECTION";
        nodes.push({
          id: mainNodeId,
          address: sectionStart,
          endAddress: sectionEnd,
          type: "block",
          label: mainSection ? `Code Section (${mainSection.name})` : "Loaded Code",
          instructionCount: 0,
          instructions: []
        });
        nodes.push({
          id: "CFG_EXIT",
          address: sectionEnd,
          endAddress: sectionEnd,
          type: "exit",
          label: "Exit",
          instructionCount: 0,
          instructions: []
        });
        edges.push({ id: `${entryNodeId}_to_${mainNodeId}`, source: entryNodeId, target: mainNodeId, type: "fallthrough" });
        edges.push({ id: `${mainNodeId}_to_CFG_EXIT`, source: mainNodeId, target: "CFG_EXIT", type: "fallthrough" });
      }
    }
    this.appendDynamicCFGEdges(edges, new Set(nodes.map((n) => n.id)));
    return { nodes, edges, entryNodeId };
  }
  getVMModel() {
    if (!this.engine) {
      return {
        dispatcher: null,
        handlers: [],
        opcodes: [],
        cfg: { nodes: [], edges: [] },
        trace: [],
        state: {
          vip: 0,
          vsp: 0,
          stack: [],
          registers: {},
          flags: { ZF: false, CF: false, SF: false, OF: false, PF: false, AF: false },
          memory: /* @__PURE__ */ new Map(),
          halted: false
        }
      };
    }
    return {
      dispatcher: this.engine.getDispatcher(),
      handlers: this.engine.getHandlers(),
      opcodes: [],
      // Opcodes mappings
      cfg: this.buildCFG(),
      trace: this.engine.getTraceRecorder().getAll(),
      state: this.engine.getStateManager().getState()
    };
  }
}
const engineManager = new EngineManager();
const REG8 = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"];
const REG8_REX = [
  "al",
  "cl",
  "dl",
  "bl",
  "spl",
  "bpl",
  "sil",
  "dil",
  "r8b",
  "r9b",
  "r10b",
  "r11b",
  "r12b",
  "r13b",
  "r14b",
  "r15b"
];
const REG16 = [
  "ax",
  "cx",
  "dx",
  "bx",
  "sp",
  "bp",
  "si",
  "di",
  "r8w",
  "r9w",
  "r10w",
  "r11w",
  "r12w",
  "r13w",
  "r14w",
  "r15w"
];
const REG32 = [
  "eax",
  "ecx",
  "edx",
  "ebx",
  "esp",
  "ebp",
  "esi",
  "edi",
  "r8d",
  "r9d",
  "r10d",
  "r11d",
  "r12d",
  "r13d",
  "r14d",
  "r15d"
];
const REG64 = [
  "rax",
  "rcx",
  "rdx",
  "rbx",
  "rsp",
  "rbp",
  "rsi",
  "rdi",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15"
];
const CC_NAMES = {
  0: "o",
  1: "no",
  2: "b",
  3: "ae",
  4: "e",
  5: "ne",
  6: "be",
  7: "a",
  8: "s",
  9: "ns",
  10: "p",
  11: "np",
  12: "l",
  13: "ge",
  14: "le",
  15: "g"
};
function createState(data, baseAddress, is64) {
  return {
    data,
    pos: 0,
    startPos: 0,
    baseAddress,
    is64Mode: is64,
    hasRex: false,
    rexW: false,
    rexR: false,
    rexX: false,
    rexB: false,
    hasOperandSizeOverride: false,
    hasAddressSizeOverride: false,
    hasRepPrefix: false,
    hasRepnePrefix: false,
    segmentOverride: null,
    hasLockPrefix: false
  };
}
function resetPrefixes(s) {
  s.hasRex = false;
  s.rexW = false;
  s.rexR = false;
  s.rexX = false;
  s.rexB = false;
  s.hasOperandSizeOverride = false;
  s.hasAddressSizeOverride = false;
  s.hasRepPrefix = false;
  s.hasRepnePrefix = false;
  s.segmentOverride = null;
  s.hasLockPrefix = false;
}
function readByte(s) {
  if (s.pos >= s.data.length) throw new Error("End of data");
  return s.data[s.pos++];
}
function peekByte(s) {
  if (s.pos >= s.data.length) return -1;
  return s.data[s.pos];
}
function readImm8(s) {
  return readByte(s);
}
function readImm8Signed(s) {
  const v = readByte(s);
  return v > 127 ? v - 256 : v;
}
function readImm16(s) {
  const lo = readByte(s);
  const hi = readByte(s);
  return lo | hi << 8;
}
function readImm32(s) {
  const b0 = readByte(s);
  const b1 = readByte(s);
  const b2 = readByte(s);
  const b3 = readByte(s);
  return (b0 | b1 << 8 | b2 << 16 | b3 << 24) >>> 0;
}
function readImm32Signed(s) {
  const v = readImm32(s);
  return v > 2147483647 ? v - 4294967296 : v;
}
function readImm64(s) {
  const lo = BigInt(readImm32(s));
  const hi = BigInt(readImm32(s));
  return lo | hi << 32n;
}
function getOperandSize(s) {
  if (s.rexW) return 64;
  if (s.hasOperandSizeOverride) return 16;
  return s.is64Mode ? 32 : 32;
}
function getRegName(index, size, hasRex) {
  const idx = index & 15;
  switch (size) {
    case 8:
      return hasRex ? REG8_REX[idx] || `r${idx}b` : REG8[idx] || `r${idx}b`;
    case 16:
      return REG16[idx] || `r${idx}w`;
    case 32:
      return REG32[idx] || `r${idx}d`;
    case 64:
      return REG64[idx] || `r${idx}`;
    default:
      return REG32[idx] || `r${idx}d`;
  }
}
function getSizePrefix(size) {
  switch (size) {
    case 8:
      return "byte";
    case 16:
      return "word";
    case 32:
      return "dword";
    case 64:
      return "qword";
    default:
      return "";
  }
}
function decodeModRM(s, operandSize, useRegSize) {
  const modrm = readByte(s);
  const mod = modrm >> 6 & 3;
  const reg = modrm >> 3 & 7 | (s.rexR ? 8 : 0);
  let rm = modrm & 7 | (s.rexB ? 8 : 0);
  const actualSize = operandSize;
  if (mod === 3) {
    return {
      regField: reg,
      rmOperand: getRegName(rm, actualSize, s.hasRex),
      isMemory: false
    };
  }
  let memStr;
  const addrSize = s.is64Mode ? 64 : 32;
  const addrRegs = addrSize === 64 ? REG64 : REG32;
  if ((modrm & 7) === 4 && !s.rexB || (modrm & 7) === 4) {
    const rmBase = modrm & 7;
    if (rmBase === 4) {
      rm = 4 | (s.rexB ? 8 : 0);
    }
    const sib = readByte(s);
    const scale = 1 << (sib >> 6 & 3);
    const indexRaw = sib >> 3 & 7 | (s.rexX ? 8 : 0);
    const baseRaw = sib & 7 | (s.rexB ? 8 : 0);
    const hasIndex = indexRaw !== 4;
    const hasBase = !(mod === 0 && (sib & 7) === 5);
    let parts = [];
    if (hasBase) {
      parts.push(addrRegs[baseRaw] || `r${baseRaw}`);
    }
    if (hasIndex) {
      const indexStr = addrRegs[indexRaw] || `r${indexRaw}`;
      parts.push(scale > 1 ? `${indexStr}*${scale}` : indexStr);
    }
    let disp = 0;
    if (mod === 0 && (sib & 7) === 5) {
      disp = readImm32Signed(s);
      if (parts.length === 0) {
        memStr = `[0x${(disp >>> 0).toString(16)}]`;
      } else {
        memStr = disp !== 0 ? `[${parts.join("+")}${disp >= 0 ? "+" : ""}0x${Math.abs(disp).toString(16)}]` : `[${parts.join("+")}]`;
      }
    } else if (mod === 1) {
      disp = readImm8Signed(s);
      const dispStr = disp !== 0 ? disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${(-disp).toString(16)}` : "";
      memStr = `[${parts.join("+")}${dispStr}]`;
    } else if (mod === 2) {
      disp = readImm32Signed(s);
      const dispStr = disp !== 0 ? disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${(-disp).toString(16)}` : "";
      memStr = `[${parts.join("+")}${dispStr}]`;
    } else {
      memStr = `[${parts.join("+")}]`;
    }
  } else if (mod === 0 && (modrm & 7) === 5) {
    const disp = readImm32Signed(s);
    if (s.is64Mode) {
      s.baseAddress + (s.pos - s.startPos) + disp;
      memStr = `[rip+0x${(disp >>> 0).toString(16)}]`;
    } else {
      memStr = `[0x${(disp >>> 0).toString(16)}]`;
    }
  } else {
    const baseReg = addrRegs[rm] || `r${rm}`;
    if (mod === 0) {
      memStr = `[${baseReg}]`;
    } else if (mod === 1) {
      const disp = readImm8Signed(s);
      const dispStr = disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${(-disp).toString(16)}`;
      memStr = `[${baseReg}${dispStr}]`;
    } else {
      const disp = readImm32Signed(s);
      const dispStr = disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${(-disp).toString(16)}`;
      memStr = `[${baseReg}${dispStr}]`;
    }
  }
  const prefix = getSizePrefix(actualSize);
  return {
    regField: reg,
    rmOperand: prefix ? `${prefix} ptr ${memStr}` : memStr,
    isMemory: true
  };
}
function classifyInstruction(mnemonic) {
  const m = mnemonic.toLowerCase();
  if ([
    "jmp",
    "je",
    "jne",
    "jz",
    "jnz",
    "jb",
    "jae",
    "jbe",
    "ja",
    "jl",
    "jge",
    "jle",
    "jg",
    "jo",
    "jno",
    "js",
    "jns",
    "jp",
    "jnp",
    "jcxz",
    "jecxz",
    "jrcxz",
    "call",
    "ret",
    "retn",
    "loop",
    "loope",
    "loopne"
  ].includes(m)) {
    return InstructionType.ControlFlow;
  }
  if (["push", "pop", "pushf", "popf", "pushfq", "popfq", "pusha", "popa"].includes(m)) {
    return InstructionType.Stack;
  }
  if (["add", "sub", "mul", "imul", "div", "idiv", "inc", "dec", "neg", "adc", "sbb"].includes(m)) {
    return InstructionType.Arithmetic;
  }
  if ([
    "and",
    "or",
    "xor",
    "not",
    "shl",
    "shr",
    "sar",
    "sal",
    "rol",
    "ror",
    "rcl",
    "rcr",
    "bt",
    "bts",
    "btr",
    "btc",
    "bsf",
    "bsr",
    "shld",
    "shrd"
  ].includes(m)) {
    return InstructionType.Logic;
  }
  if ([
    "mov",
    "movzx",
    "movsx",
    "movsxd",
    "lea",
    "xchg",
    "cmova",
    "cmovae",
    "cmovb",
    "cmovbe",
    "cmove",
    "cmovne",
    "cmovg",
    "cmovge",
    "cmovl",
    "cmovle",
    "cmovs",
    "cmovns",
    "cmovo",
    "cmovno",
    "cmovp",
    "cmovnp",
    "bswap",
    "movdqa",
    "movdqu",
    "movaps",
    "movups",
    "movss",
    "movsd"
  ].includes(m)) {
    return InstructionType.Memory;
  }
  if (["cmp", "test"].includes(m)) {
    return InstructionType.Comparison;
  }
  if (["nop", "fnop"].includes(m)) {
    return InstructionType.Nop;
  }
  if (["int", "int3", "syscall", "sysenter", "hlt", "cpuid", "rdtsc", "ud2"].includes(m)) {
    return InstructionType.System;
  }
  if ([
    "rep",
    "repe",
    "repne",
    "movs",
    "movsb",
    "movsd",
    "movsq",
    "stos",
    "stosb",
    "stosd",
    "stosq",
    "cmps",
    "cmpsb",
    "cmpsd",
    "scas",
    "scasb",
    "lods"
  ].includes(m)) {
    return InstructionType.String;
  }
  return InstructionType.Unknown;
}
const ALU_OPS = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];
const SHIFT_OPS = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"];
function decodeOne(s) {
  s.startPos = s.pos;
  resetPrefixes(s);
  let prefixCount = 0;
  while (prefixCount < 15) {
    const b = peekByte(s);
    if (b === -1) return null;
    if (b === 240) {
      s.hasLockPrefix = true;
      s.pos++;
      prefixCount++;
    } else if (b === 242) {
      s.hasRepnePrefix = true;
      s.pos++;
      prefixCount++;
    } else if (b === 243) {
      s.hasRepPrefix = true;
      s.pos++;
      prefixCount++;
    } else if (b === 102) {
      s.hasOperandSizeOverride = true;
      s.pos++;
      prefixCount++;
    } else if (b === 103) {
      s.hasAddressSizeOverride = true;
      s.pos++;
      prefixCount++;
    } else if (b === 46) {
      s.segmentOverride = "cs";
      s.pos++;
      prefixCount++;
    } else if (b === 54) {
      s.segmentOverride = "ss";
      s.pos++;
      prefixCount++;
    } else if (b === 62) {
      s.segmentOverride = "ds";
      s.pos++;
      prefixCount++;
    } else if (b === 38) {
      s.segmentOverride = "es";
      s.pos++;
      prefixCount++;
    } else if (b === 100) {
      s.segmentOverride = "fs";
      s.pos++;
      prefixCount++;
    } else if (b === 101) {
      s.segmentOverride = "gs";
      s.pos++;
      prefixCount++;
    } else if (s.is64Mode && (b & 240) === 64) {
      s.hasRex = true;
      s.rexW = (b & 8) !== 0;
      s.rexR = (b & 4) !== 0;
      s.rexX = (b & 2) !== 0;
      s.rexB = (b & 1) !== 0;
      s.pos++;
      prefixCount++;
    } else break;
  }
  const opcode = readByte(s);
  const opSize = getOperandSize(s);
  if (opcode <= 63 && (opcode & 192) === 0) {
    const aluIdx = opcode >> 3 & 7;
    const direction = opcode & 2;
    const isByte = (opcode & 1) === 0;
    if ((opcode & 7) === 4) {
      const imm = readImm8(s);
      return { mnemonic: ALU_OPS[aluIdx], operands: `al, 0x${imm.toString(16)}` };
    }
    if ((opcode & 7) === 5) {
      const reg = getRegName(0, opSize, s.hasRex);
      const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s);
      return { mnemonic: ALU_OPS[aluIdx], operands: `${reg}, 0x${imm.toString(16)}` };
    }
    const sz = isByte ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    const regStr = getRegName(modrm.regField, sz, s.hasRex);
    if (direction === 0) {
      return { mnemonic: ALU_OPS[aluIdx], operands: `${modrm.rmOperand}, ${regStr}` };
    } else {
      return { mnemonic: ALU_OPS[aluIdx], operands: `${regStr}, ${modrm.rmOperand}` };
    }
  }
  if (opcode >= 80 && opcode <= 87) {
    const reg = opcode - 80 | (s.rexB ? 8 : 0);
    const regName = getRegName(reg, s.is64Mode ? 64 : opSize, s.hasRex);
    return { mnemonic: "push", operands: regName };
  }
  if (opcode >= 88 && opcode <= 95) {
    const reg = opcode - 88 | (s.rexB ? 8 : 0);
    const regName = getRegName(reg, s.is64Mode ? 64 : opSize, s.hasRex);
    return { mnemonic: "pop", operands: regName };
  }
  if (opcode === 104) {
    const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s);
    return { mnemonic: "push", operands: `0x${imm.toString(16)}` };
  }
  if (opcode === 106) {
    const imm = readImm8Signed(s);
    return { mnemonic: "push", operands: `0x${(imm & 255).toString(16)}` };
  }
  if (opcode >= 112 && opcode <= 127) {
    const cc = CC_NAMES[opcode & 15];
    const rel = readImm8Signed(s);
    s.baseAddress + (s.pos - s.startPos) + s.startPos + rel;
    const instrLen = s.pos - s.startPos;
    s.baseAddress + s.pos + rel - (s.pos - s.startPos) + instrLen;
    s.baseAddress + s.pos + rel;
    return { mnemonic: `j${cc}`, operands: `0x${(s.baseAddress + s.pos + rel).toString(16)}` };
  }
  if (opcode >= 128 && opcode <= 131) {
    const isByte = opcode === 128;
    const isSignExtImm8 = opcode === 131;
    const sz = isByte ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    const aluIdx = modrm.regField & 7;
    let immStr;
    if (isByte || isSignExtImm8) {
      const imm = readImm8(s);
      immStr = `0x${imm.toString(16)}`;
    } else if (opcode === 129) {
      const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s);
      immStr = `0x${imm.toString(16)}`;
    } else {
      const imm = readImm8(s);
      immStr = `0x${imm.toString(16)}`;
    }
    return { mnemonic: ALU_OPS[aluIdx], operands: `${modrm.rmOperand}, ${immStr}` };
  }
  if (opcode === 132 || opcode === 133) {
    const sz = opcode === 132 ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    const regStr = getRegName(modrm.regField, sz, s.hasRex);
    return { mnemonic: "test", operands: `${modrm.rmOperand}, ${regStr}` };
  }
  if (opcode === 134 || opcode === 135) {
    const sz = opcode === 134 ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    const regStr = getRegName(modrm.regField, sz, s.hasRex);
    return { mnemonic: "xchg", operands: `${modrm.rmOperand}, ${regStr}` };
  }
  if (opcode >= 136 && opcode <= 139) {
    const isByte = (opcode & 1) === 0;
    const direction = opcode & 2;
    const sz = isByte ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    const regStr = getRegName(modrm.regField, sz, s.hasRex);
    if (direction === 0) {
      return { mnemonic: "mov", operands: `${modrm.rmOperand}, ${regStr}` };
    } else {
      return { mnemonic: "mov", operands: `${regStr}, ${modrm.rmOperand}` };
    }
  }
  if (opcode === 141) {
    const modrm = decodeModRM(s, opSize);
    const regStr = getRegName(modrm.regField, opSize, s.hasRex);
    return { mnemonic: "lea", operands: `${regStr}, ${modrm.rmOperand}` };
  }
  if (opcode === 144) {
    if (!s.rexB && !s.hasRex) return { mnemonic: "nop", operands: "" };
    const reg = s.rexB ? 8 : 0;
    const regName = getRegName(reg, opSize, s.hasRex);
    return { mnemonic: "xchg", operands: `${getRegName(0, opSize, s.hasRex)}, ${regName}` };
  }
  if (opcode >= 145 && opcode <= 151) {
    const reg = opcode - 144 | (s.rexB ? 8 : 0);
    const regName = getRegName(reg, opSize, s.hasRex);
    return { mnemonic: "xchg", operands: `${getRegName(0, opSize, s.hasRex)}, ${regName}` };
  }
  if (opcode === 153) {
    if (s.rexW) return { mnemonic: "cqo", operands: "" };
    if (s.hasOperandSizeOverride) return { mnemonic: "cwd", operands: "" };
    return { mnemonic: "cdq", operands: "" };
  }
  if (opcode === 152) {
    if (s.rexW) return { mnemonic: "cdqe", operands: "" };
    if (s.hasOperandSizeOverride) return { mnemonic: "cbw", operands: "" };
    return { mnemonic: "cwde", operands: "" };
  }
  if (opcode === 156) return { mnemonic: s.is64Mode ? "pushfq" : "pushf", operands: "" };
  if (opcode === 157) return { mnemonic: s.is64Mode ? "popfq" : "popf", operands: "" };
  if (opcode >= 160 && opcode <= 163) {
    const isByte = (opcode & 1) === 0;
    const isStore = opcode >= 162;
    const sz = isByte ? 8 : opSize;
    const addr = s.is64Mode ? Number(readImm64(s)) : readImm32(s);
    const regStr = getRegName(0, sz, s.hasRex);
    const memStr = `${getSizePrefix(sz)} ptr [0x${addr.toString(16)}]`;
    if (isStore) {
      return { mnemonic: "mov", operands: `${memStr}, ${regStr}` };
    }
    return { mnemonic: "mov", operands: `${regStr}, ${memStr}` };
  }
  if (opcode === 168) {
    const imm = readImm8(s);
    return { mnemonic: "test", operands: `al, 0x${imm.toString(16)}` };
  }
  if (opcode === 169) {
    const reg = getRegName(0, opSize, s.hasRex);
    const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s);
    return { mnemonic: "test", operands: `${reg}, 0x${imm.toString(16)}` };
  }
  if (opcode >= 176 && opcode <= 183) {
    const reg = opcode - 176 | (s.rexB ? 8 : 0);
    const imm = readImm8(s);
    return { mnemonic: "mov", operands: `${getRegName(reg, 8, s.hasRex)}, 0x${imm.toString(16)}` };
  }
  if (opcode >= 184 && opcode <= 191) {
    const reg = opcode - 184 | (s.rexB ? 8 : 0);
    let imm;
    if (s.rexW) {
      const v = readImm64(s);
      imm = `0x${v.toString(16)}`;
    } else if (s.hasOperandSizeOverride) {
      imm = `0x${readImm16(s).toString(16)}`;
    } else {
      imm = `0x${readImm32(s).toString(16)}`;
    }
    return { mnemonic: "mov", operands: `${getRegName(reg, opSize, s.hasRex)}, ${imm}` };
  }
  if (opcode === 192 || opcode === 193) {
    const sz = opcode === 192 ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    const op = SHIFT_OPS[modrm.regField & 7];
    const imm = readImm8(s);
    return { mnemonic: op, operands: `${modrm.rmOperand}, ${imm}` };
  }
  if (opcode === 208 || opcode === 209) {
    const sz = opcode === 208 ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    const op = SHIFT_OPS[modrm.regField & 7];
    return { mnemonic: op, operands: `${modrm.rmOperand}, 1` };
  }
  if (opcode === 210 || opcode === 211) {
    const sz = opcode === 210 ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    const op = SHIFT_OPS[modrm.regField & 7];
    return { mnemonic: op, operands: `${modrm.rmOperand}, cl` };
  }
  if (opcode === 195) return { mnemonic: "ret", operands: "" };
  if (opcode === 194) {
    const imm = readImm16(s);
    return { mnemonic: "ret", operands: `0x${imm.toString(16)}` };
  }
  if (opcode === 198 || opcode === 199) {
    const isByte = opcode === 198;
    const sz = isByte ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    let immStr;
    if (isByte) {
      immStr = `0x${readImm8(s).toString(16)}`;
    } else if (s.hasOperandSizeOverride) {
      immStr = `0x${readImm16(s).toString(16)}`;
    } else {
      immStr = `0x${readImm32(s).toString(16)}`;
    }
    return { mnemonic: "mov", operands: `${modrm.rmOperand}, ${immStr}` };
  }
  if (opcode === 201) return { mnemonic: "leave", operands: "" };
  if (opcode === 204) return { mnemonic: "int3", operands: "" };
  if (opcode === 205) {
    const imm = readImm8(s);
    return { mnemonic: "int", operands: `0x${imm.toString(16)}` };
  }
  if (opcode === 232) {
    const rel = readImm32Signed(s);
    const target = s.baseAddress + s.pos + rel;
    return { mnemonic: "call", operands: `0x${(target >>> 0).toString(16)}` };
  }
  if (opcode === 233) {
    const rel = readImm32Signed(s);
    const target = s.baseAddress + s.pos + rel;
    return { mnemonic: "jmp", operands: `0x${(target >>> 0).toString(16)}` };
  }
  if (opcode === 235) {
    const rel = readImm8Signed(s);
    const target = s.baseAddress + s.pos + rel;
    return { mnemonic: "jmp", operands: `0x${(target >>> 0).toString(16)}` };
  }
  if (opcode === 246 || opcode === 247) {
    const isByte = opcode === 246;
    const sz = isByte ? 8 : opSize;
    const modrm = decodeModRM(s, sz);
    const grpOp = modrm.regField & 7;
    switch (grpOp) {
      case 0:
      case 1: {
        let immStr;
        if (isByte) immStr = `0x${readImm8(s).toString(16)}`;
        else if (s.hasOperandSizeOverride) immStr = `0x${readImm16(s).toString(16)}`;
        else immStr = `0x${readImm32(s).toString(16)}`;
        return { mnemonic: "test", operands: `${modrm.rmOperand}, ${immStr}` };
      }
      case 2:
        return { mnemonic: "not", operands: modrm.rmOperand };
      case 3:
        return { mnemonic: "neg", operands: modrm.rmOperand };
      case 4:
        return { mnemonic: "mul", operands: modrm.rmOperand };
      case 5:
        return { mnemonic: "imul", operands: modrm.rmOperand };
      case 6:
        return { mnemonic: "div", operands: modrm.rmOperand };
      case 7:
        return { mnemonic: "idiv", operands: modrm.rmOperand };
    }
  }
  if (opcode === 254) {
    const modrm = decodeModRM(s, 8);
    const op = (modrm.regField & 7) === 0 ? "inc" : "dec";
    return { mnemonic: op, operands: modrm.rmOperand };
  }
  if (opcode === 255) {
    const modrm = decodeModRM(s, opSize);
    switch (modrm.regField & 7) {
      case 0:
        return { mnemonic: "inc", operands: modrm.rmOperand };
      case 1:
        return { mnemonic: "dec", operands: modrm.rmOperand };
      case 2:
        return { mnemonic: "call", operands: modrm.rmOperand };
      case 3:
        return { mnemonic: "call far", operands: modrm.rmOperand };
      case 4:
        return { mnemonic: "jmp", operands: modrm.rmOperand };
      case 5:
        return { mnemonic: "jmp far", operands: modrm.rmOperand };
      case 6:
        return { mnemonic: "push", operands: modrm.rmOperand };
      default:
        return { mnemonic: "db", operands: `0x${opcode.toString(16)}` };
    }
  }
  if (opcode === 244) return { mnemonic: "hlt", operands: "" };
  if (opcode === 248) return { mnemonic: "clc", operands: "" };
  if (opcode === 249) return { mnemonic: "stc", operands: "" };
  if (opcode === 250) return { mnemonic: "cli", operands: "" };
  if (opcode === 251) return { mnemonic: "sti", operands: "" };
  if (opcode === 252) return { mnemonic: "cld", operands: "" };
  if (opcode === 253) return { mnemonic: "std", operands: "" };
  if (opcode === 164) return { mnemonic: "movsb", operands: "" };
  if (opcode === 165) return { mnemonic: s.rexW ? "movsq" : "movsd", operands: "" };
  if (opcode === 166) return { mnemonic: "cmpsb", operands: "" };
  if (opcode === 167) return { mnemonic: s.rexW ? "cmpsq" : "cmpsd", operands: "" };
  if (opcode === 170) return { mnemonic: "stosb", operands: "" };
  if (opcode === 171) return { mnemonic: s.rexW ? "stosq" : "stosd", operands: "" };
  if (opcode === 172) return { mnemonic: "lodsb", operands: "" };
  if (opcode === 173) return { mnemonic: s.rexW ? "lodsq" : "lodsd", operands: "" };
  if (opcode === 174) return { mnemonic: "scasb", operands: "" };
  if (opcode === 175) return { mnemonic: s.rexW ? "scasq" : "scasd", operands: "" };
  if (opcode === 15) {
    const opcode2 = readByte(s);
    if (opcode2 >= 128 && opcode2 <= 143) {
      const cc = CC_NAMES[opcode2 & 15];
      const rel = readImm32Signed(s);
      const target = s.baseAddress + s.pos + rel;
      return { mnemonic: `j${cc}`, operands: `0x${(target >>> 0).toString(16)}` };
    }
    if (opcode2 >= 144 && opcode2 <= 159) {
      const cc = CC_NAMES[opcode2 & 15];
      const modrm = decodeModRM(s, 8);
      return { mnemonic: `set${cc}`, operands: modrm.rmOperand };
    }
    if (opcode2 >= 64 && opcode2 <= 79) {
      const cc = CC_NAMES[opcode2 & 15];
      const modrm = decodeModRM(s, opSize);
      const regStr = getRegName(modrm.regField, opSize, s.hasRex);
      return { mnemonic: `cmov${cc}`, operands: `${regStr}, ${modrm.rmOperand}` };
    }
    if (opcode2 === 182 || opcode2 === 183) {
      const srcSize = opcode2 === 182 ? 8 : 16;
      const modrm = decodeModRM(s, srcSize);
      const regStr = getRegName(modrm.regField, opSize, s.hasRex);
      return { mnemonic: "movzx", operands: `${regStr}, ${modrm.rmOperand}` };
    }
    if (opcode2 === 190 || opcode2 === 191) {
      const srcSize = opcode2 === 190 ? 8 : 16;
      const modrm = decodeModRM(s, srcSize);
      const regStr = getRegName(modrm.regField, opSize, s.hasRex);
      return { mnemonic: "movsx", operands: `${regStr}, ${modrm.rmOperand}` };
    }
    if (opcode2 === 175) {
      const modrm = decodeModRM(s, opSize);
      const regStr = getRegName(modrm.regField, opSize, s.hasRex);
      return { mnemonic: "imul", operands: `${regStr}, ${modrm.rmOperand}` };
    }
    if (opcode2 === 188 || opcode2 === 189) {
      const modrm = decodeModRM(s, opSize);
      const regStr = getRegName(modrm.regField, opSize, s.hasRex);
      const mnemonic = opcode2 === 188 ? "bsf" : "bsr";
      return { mnemonic, operands: `${regStr}, ${modrm.rmOperand}` };
    }
    if (opcode2 >= 200 && opcode2 <= 207) {
      const reg = opcode2 - 200 | (s.rexB ? 8 : 0);
      return { mnemonic: "bswap", operands: getRegName(reg, opSize, s.hasRex) };
    }
    if (opcode2 === 163) {
      const m = decodeModRM(s, opSize);
      return { mnemonic: "bt", operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}` };
    }
    if (opcode2 === 171) {
      const m = decodeModRM(s, opSize);
      return { mnemonic: "bts", operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}` };
    }
    if (opcode2 === 179) {
      const m = decodeModRM(s, opSize);
      return { mnemonic: "btr", operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}` };
    }
    if (opcode2 === 187) {
      const m = decodeModRM(s, opSize);
      return { mnemonic: "btc", operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}` };
    }
    if (opcode2 === 164) {
      const m = decodeModRM(s, opSize);
      const imm = readImm8(s);
      return { mnemonic: "shld", operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}, ${imm}` };
    }
    if (opcode2 === 165) {
      const m = decodeModRM(s, opSize);
      return { mnemonic: "shld", operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}, cl` };
    }
    if (opcode2 === 172) {
      const m = decodeModRM(s, opSize);
      const imm = readImm8(s);
      return { mnemonic: "shrd", operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}, ${imm}` };
    }
    if (opcode2 === 173) {
      const m = decodeModRM(s, opSize);
      return { mnemonic: "shrd", operands: `${m.rmOperand}, ${getRegName(m.regField, opSize, s.hasRex)}, cl` };
    }
    if (opcode2 === 5) return { mnemonic: "syscall", operands: "" };
    if (opcode2 === 7) return { mnemonic: "sysret", operands: "" };
    if (opcode2 === 162) return { mnemonic: "cpuid", operands: "" };
    if (opcode2 === 49) return { mnemonic: "rdtsc", operands: "" };
    if (opcode2 === 11) return { mnemonic: "ud2", operands: "" };
    if (opcode2 === 31) {
      const modrm = decodeModRM(s, opSize);
      return { mnemonic: "nop", operands: modrm.rmOperand };
    }
    return { mnemonic: "db", operands: `0x0f, 0x${opcode2.toString(16)}` };
  }
  if (opcode === 99 && s.is64Mode) {
    const modrm = decodeModRM(s, 32);
    const regStr = getRegName(modrm.regField, s.rexW ? 64 : 32, s.hasRex);
    return { mnemonic: "movsxd", operands: `${regStr}, ${modrm.rmOperand}` };
  }
  if (opcode === 105) {
    const modrm = decodeModRM(s, opSize);
    const regStr = getRegName(modrm.regField, opSize, s.hasRex);
    const imm = s.hasOperandSizeOverride ? readImm16(s) : readImm32(s);
    return { mnemonic: "imul", operands: `${regStr}, ${modrm.rmOperand}, 0x${imm.toString(16)}` };
  }
  if (opcode === 107) {
    const modrm = decodeModRM(s, opSize);
    const regStr = getRegName(modrm.regField, opSize, s.hasRex);
    const imm = readImm8Signed(s);
    return { mnemonic: "imul", operands: `${regStr}, ${modrm.rmOperand}, 0x${(imm & 255).toString(16)}` };
  }
  if (opcode === 200) {
    const imm16 = readImm16(s);
    const imm8 = readImm8(s);
    return { mnemonic: "enter", operands: `0x${imm16.toString(16)}, ${imm8}` };
  }
  return { mnemonic: "db", operands: `0x${opcode.toString(16)}` };
}
function disassemble(data, baseAddress, is64 = true, maxInstructions = 1e3) {
  const s = createState(data instanceof Buffer ? data : Buffer.from(data), baseAddress, is64);
  const instructions = [];
  while (s.pos < s.data.length && instructions.length < maxInstructions) {
    const startOffset = s.pos;
    const address = baseAddress + startOffset;
    try {
      const result = decodeOne(s);
      if (!result) break;
      const size = s.pos - startOffset;
      const bytes = [];
      for (let i = startOffset; i < s.pos; i++) {
        bytes.push(s.data[i]);
      }
      instructions.push({
        address,
        bytes,
        mnemonic: result.mnemonic,
        operands: result.operands,
        size,
        type: classifyInstruction(result.mnemonic)
      });
    } catch {
      instructions.push({
        address,
        bytes: [s.data[startOffset]],
        mnemonic: "db",
        operands: `0x${s.data[startOffset].toString(16)}`,
        size: 1,
        type: InstructionType.Unknown
      });
      s.pos = startOffset + 1;
    }
  }
  return instructions;
}
function registerIpcHandlers() {
  electron.ipcMain.handle("binary:open-dialog", async (event) => {
    const window = electron.BrowserWindow.fromWebContents(event.sender);
    if (!window) return null;
    const result = await electron.dialog.showOpenDialog(window, {
      properties: ["openFile"],
      filters: [
        { name: "Binarios Soportados (*.exe, *.dll, *.elf, *.so, *.bin)", extensions: ["exe", "dll", "elf", "so", "bin", ""] },
        { name: "Todos los archivos", extensions: ["*"] }
      ]
    });
    if (result.canceled || result.filePaths.length === 0) {
      return null;
    }
    const path2 = result.filePaths[0];
    return engineManager.loadBinaryFile(path2);
  });
  electron.ipcMain.handle("binary:load", async (_, { path: path2 }) => {
    return engineManager.loadBinaryFile(path2);
  });
  electron.ipcMain.handle("binary:info", async () => {
    return engineManager.getBinaryInfo();
  });
  electron.ipcMain.handle("disasm:range", async (_, { start, end, baseAddress }) => {
    const size = end - start;
    const bytes = getBytesAtAddress(start, size);
    if (!bytes) return [];
    const is64 = getLoadedInfo()?.architecture === "x64";
    return disassemble(bytes, baseAddress, is64);
  });
  electron.ipcMain.handle("disasm:section", async (_, { sectionName }) => {
    const sec = getSectionByName(sectionName);
    if (!sec) return [];
    const bytes = getSectionBytes(sec);
    if (!bytes) return [];
    const is64 = getLoadedInfo()?.architecture === "x64";
    return disassemble(bytes, sec.virtualAddress, is64);
  });
  electron.ipcMain.handle("vm:step", async () => {
    return engineManager.step();
  });
  electron.ipcMain.handle("vm:step-over", async () => {
    return engineManager.stepOver();
  });
  electron.ipcMain.handle("vm:run", async () => {
    return engineManager.run();
  });
  electron.ipcMain.handle("vm:stop", async () => {
    engineManager.stop();
    return { success: true };
  });
  electron.ipcMain.handle("vm:reset", async () => {
    engineManager.reset();
    return { success: true };
  });
  electron.ipcMain.handle("vm:get-state", async () => {
    return engineManager.getVMModel().state;
  });
  electron.ipcMain.handle("vm:label-handler", async (_, { address, label }) => {
    engineManager.setHandlerLabel(address, label);
    return { success: true };
  });
  electron.ipcMain.handle("vm:set-hypothesis", async (_, { address, hypothesis }) => {
    engineManager.setHandlerHypothesis(address, hypothesis);
    return { success: true };
  });
  electron.ipcMain.handle("bookmark:add", async (_, bookmark) => {
    engineManager.addBookmark(bookmark);
    return { success: true };
  });
  electron.ipcMain.handle("bookmark:remove", async (_, { id }) => {
    engineManager.removeBookmark(id);
    return { success: true };
  });
  electron.ipcMain.handle("bookmark:list", async () => {
    return engineManager.getBookmarks();
  });
  electron.ipcMain.handle("trace:get", async () => {
    return engineManager.getVMModel().trace;
  });
  electron.ipcMain.handle("cfg:get", async () => {
    return engineManager.getVMModel().cfg;
  });
  electron.ipcMain.handle("plugin:list", async () => {
    return getConnectedPlugins();
  });
  electron.ipcMain.handle("plugin:logs", async () => {
    return getPluginLogs();
  });
  electron.ipcMain.handle("plugin:select-folder", async (event) => {
    const window = electron.BrowserWindow.fromWebContents(event.sender);
    if (!window) return { canceled: true };
    const result = await electron.dialog.showOpenDialog(window, {
      properties: ["openDirectory"]
    });
    if (result.canceled || result.filePaths.length === 0) {
      return { canceled: true };
    }
    return { canceled: false, path: result.filePaths[0] };
  });
  electron.ipcMain.handle("plugin:load-folder", async (_, { path: path2 }) => {
    return loadPluginsFromFolder(path2);
  });
  electron.ipcMain.handle("plugin:get-loaded-processes", async () => {
    return getLoadedPluginProcesses();
  });
  electron.ipcMain.handle("plugin:start", async (_, { path: path2 }) => {
    try {
      const info = startPlugin(path2);
      return { success: true, info };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });
  electron.ipcMain.handle("plugin:stop", async (_, { path: path2 }) => {
    try {
      const res = stopPlugin(path2);
      return res;
    } catch (err) {
      return { success: false, error: err.message };
    }
  });
  electron.ipcMain.handle("plugin:install-deps", async (_, { packages }) => {
    try {
      const res = installDeps(packages || ["websocket-client"]);
      return res;
    } catch (err) {
      return { success: false, stdout: "", stderr: err.message };
    }
  });
  electron.ipcMain.handle("plugin:set-auto-install", async (_, { enabled }) => {
    try {
      setAutoInstallDeps(!!enabled);
      return { success: true, enabled: !!enabled };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });
  electron.ipcMain.handle("plugin:get-auto-install", async () => {
    try {
      return { enabled: getAutoInstallDeps() };
    } catch (err) {
      return { enabled: false };
    }
  });
  electron.ipcMain.handle("plugin:set-port", async (_, { port }) => {
    startPluginServer(port);
    return { success: true, port };
  });
}
function createWindow() {
  const mainWindow = new electron.BrowserWindow({
    width: 1400,
    height: 900,
    show: false,
    autoHideMenuBar: false,
    title: "VMTrace — Professional VM Analysis Tool",
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      sandbox: false,
      contextIsolation: true
    }
  });
  engineManager.setMainWindow(mainWindow);
  registerUIForPluginUpdates(mainWindow);
  mainWindow.on("ready-to-show", () => {
    mainWindow.show();
  });
  mainWindow.webContents.setWindowOpenHandler((details) => {
    electron.shell.openExternal(details.url);
    return { action: "deny" };
  });
  if (is.dev && process.env["ELECTRON_RENDERER_URL"]) {
    mainWindow.loadURL(process.env["ELECTRON_RENDERER_URL"]);
  } else {
    mainWindow.loadFile(path.join(__dirname, "../renderer/index.html"));
  }
}
electron.app.whenReady().then(() => {
  electronApp.setAppUserModelId("com.vmtrace");
  electron.app.on("browser-window-created", (_, window) => {
    optimizer.watchWindowShortcuts(window);
  });
  registerIpcHandlers();
  startPluginServer(57130);
  createWindow();
  electron.app.on("activate", function() {
    if (electron.BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});
electron.app.on("window-all-closed", () => {
  stopPluginServer();
  if (process.platform !== "darwin") {
    electron.app.quit();
  }
});
