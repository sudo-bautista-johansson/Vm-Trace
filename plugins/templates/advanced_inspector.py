# ============================================================================
# Advanced ELF Inspector Plugin (Python)
# Conecta al servidor WebSocket de VMTrace y muestra información cuando se carga
# el binario `advanced_vm.elf`. Usa JSON-RPC 2.0 sobre WebSocket.
# Requisitos: pip install websocket-client
# ============================================================================

import json
import time
import threading
from websocket import WebSocketApp

WS_URL = "ws://localhost:57130"
PLUGIN_NAME = "Advanced ELF Inspector"

request_id = 100


def send_request(ws, method, params=None):
    global request_id
    request_id += 1
    msg = {"jsonrpc": "2.0", "method": method, "id": request_id}
    if params is not None:
        msg["params"] = params
    ws.send(json.dumps(msg))
    return request_id


def on_message(ws, message):
    try:
        data = json.loads(message)
    except Exception:
        print("[AdvancedInspector] Mensaje no-JSON recibido:", message)
        return

    # Notificaciones (events)
    if "method" in data and data.get("jsonrpc") == "2.0":
        method = data["method"]
        params = data.get("params", {})
        if method == "event.onBinaryLoaded":
            info = params or {}
            path = info.get('path') or info.get('binaryInfo', {}).get('path') or info.get('file')
            print(f"[AdvancedInspector] Evento: binary loaded -> {path}")

            # Check if it's the advanced ELF we want
            if path and 'advanced_vm.elf' in path:
                print('[AdvancedInspector] Encontrado advanced_vm.elf — solicitando información...')
                # Request binary info
                send_request(ws, 'vm.getBinaryInfo')
                # Request handlers list
                send_request(ws, 'vm.getHandlers')
                # Request CFG
                send_request(ws, 'vm.getCFG')

    # Responses
    if "result" in data and "id" in data:
        rid = data["id"]
        result = data.get("result")
        # Best-effort pretty print
        try:
            pretty = json.dumps(result, indent=2)
        except Exception:
            pretty = str(result)
        print(f"[AdvancedInspector] Response ID={rid}:\n{pretty}")

    if "error" in data:
        print(f"[AdvancedInspector] RPC Error: {data.get('error')}")


def on_open(ws):
    print('[AdvancedInspector] Conectado al servidor VMTrace')
    # Register plugin name
    register = {"jsonrpc": "2.0", "method": "plugin.register", "params": {"name": PLUGIN_NAME}, "id": 1}
    ws.send(json.dumps(register))

    # Subscribe to binary loaded events
    subscribe = {"jsonrpc": "2.0", "method": "plugin.subscribe", "params": {"events": ["event.onBinaryLoaded"]}, "id": 2}
    ws.send(json.dumps(subscribe))


def on_error(ws, err):
    print('[AdvancedInspector] Error WebSocket:', err)


def on_close(ws, code, reason):
    print('[AdvancedInspector] Conexión cerrada', code, reason)


if __name__ == '__main__':
    print(f"[AdvancedInspector] Conectando a {WS_URL} ...")
    ws_app = WebSocketApp(WS_URL,
                          on_open=on_open,
                          on_message=on_message,
                          on_error=on_error,
                          on_close=on_close)

    thr = threading.Thread(target=ws_app.run_forever)
    thr.daemon = True
    thr.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('[AdvancedInspector] Saliendo...')
        ws_app.close()
