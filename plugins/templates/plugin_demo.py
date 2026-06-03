# ============================================================================
# VMTrace Python Plugin Template
# Connects to VMTrace WebSocket API, listens to VM steps, and prints state.
# Requirements: pip install websocket-client
# ============================================================================

import json
import time
import threading
from websocket import create_connection, WebSocketApp

WS_URL = "ws://localhost:57130"
plugin_name = "Python Analyzer Plugin"

def on_message(ws, message):
    data = json.loads(message)
    
    # Check if it is a JSON-RPC notification (event)
    if "method" in data:
        method = data["method"]
        params = data.get("params", {})
        
        if method == "event.onStep":
            state = params.get("state", {})
            trace = params.get("traceEntry", {})
            vip = state.get("vip")
            vsp = state.get("vsp")
            stack = state.get("stack", [])
            
            print(f"\n[EVENT] VM Step executed! VIP: 0x{int(vip):X} | Stack Depth: {len(stack)}")
            if len(stack) > 0:
                print(f" -> Top stack: 0x{int(stack[0]):X}")
                
        elif method == "event.onBinaryLoaded":
            print(f"\n[EVENT] Nuevo binario cargado en VMTrace: {params.get('path')}")
            
    # Check if it is a response to a request
    elif "result" in data:
        print(f"\n[API Response] ID {data.get('id')}: {data['result']}")
    elif "error" in data:
        print(f"\n[API Error] ID {data.get('id')}: {data['error']}")

def on_error(ws, error):
    print("Error:", error)

def on_close(ws, close_status_code, close_msg):
    print("Conexión cerrada.")

def on_open(ws):
    print("Conexión establecida con VMTrace!")
    
    # 1. Register plugin name
    register_msg = {
        "jsonrpc": "2.0",
        "method": "plugin.register",
        "params": {"name": plugin_name},
        "id": 1
    }
    ws.send(json.dumps(register_msg))
    
    # 2. Subscribe to events
    subscribe_msg = {
        "jsonrpc": "2.0",
        "method": "plugin.subscribe",
        "params": {"events": ["event.onStep", "event.onBinaryLoaded"]},
        "id": 2
    }
    ws.send(json.dumps(subscribe_msg))

def start_interactive_console(ws_app):
    # Give it a second to connect
    time.sleep(1.5)
    print("\n--- Consola Interactiva del Plugin ---")
    print("Comandos disponibles:")
    print("  s : Ejecutar un paso (Step)")
    print("  r : Correr ejecución (Run)")
    print("  i : Ver información del binario")
    print("  h : Ver handlers detectados")
    print("  q : Salir")
    
    # Create synchronous connection for sending CLI commands
    try:
        ws = create_connection(WS_URL)
    except Exception as e:
        print(f"\n[Error] No se pudo crear la conexión interactiva: {e}")
        print("Asegúrate de que la aplicación VMTrace esté corriendo (npm run dev).")
        ws_app.close()
        return
    
    cmd_id = 10
    while True:
        cmd = input("\nplugin> ").strip().lower()
        if cmd == 'q':
            ws_app.close()
            break
        elif cmd == 's':
            msg = {"jsonrpc": "2.0", "method": "vm.step", "id": cmd_id}
            ws.send(json.dumps(msg))
        elif cmd == 'r':
            msg = {"jsonrpc": "2.0", "method": "vm.run", "id": cmd_id}
            ws.send(json.dumps(msg))
        elif cmd == 'i':
            msg = {"jsonrpc": "2.0", "method": "vm.getBinaryInfo", "id": cmd_id}
            ws.send(json.dumps(msg))
        elif cmd == 'h':
            msg = {"jsonrpc": "2.0", "method": "vm.getHandlers", "id": cmd_id}
            ws.send(json.dumps(msg))
        else:
            print("Comando desconocido.")
            continue
        
        # Read the immediate response
        try:
            resp = ws.recv()
            data = json.loads(resp)
            print("Respuesta:", json.dumps(data.get("result"), indent=2))
        except Exception as ex:
            print(f"Error al recibir datos: {ex}")
            break
        cmd_id += 1

if __name__ == "__main__":
    print(f"Conectando al servidor VMTrace en {WS_URL}...")
    
    ws_app = WebSocketApp(WS_URL,
                          on_open=on_open,
                          on_message=on_message,
                          on_error=on_error,
                          on_close=on_close)
    
    # Run WS client on background thread
    wst = threading.Thread(target=ws_app.run_forever)
    wst.daemon = True
    wst.start()
    
    try:
        start_interactive_console(ws_app)
    except KeyboardInterrupt:
        print("Saliendo...")
