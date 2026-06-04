# VMTrace Plugins

VMTrace admite plugins externos que se conectan al servidor WebSocket del propio programa para interactuar con el motor de VM y sus datos.

## Lenguajes soportados

VMTrace puede ejecutar plugins en los siguientes formatos:

- Python (`.py`)
- Node.js (`.js`, `.mjs`)
- Java ejecutable (`.jar`)
- Java fuente (`.java`)
- C++ fuente (`.cpp`)
- Ejecutables nativos (`.exe`) y scripts de Windows (`.bat`, `.cmd`)

## Qué puede hacer un plugin

Un plugin puede:

- registrarse como cliente en el servidor de plugins
- suscribirse a eventos de VM
- leer estado de ejecución (`vm.getState`, `vm.getTrace`, `vm.getCFG`, etc.)
- controlar la ejecución de la VM (`vm.step`, `vm.run`, `vm.stop`, `vm.reset`)
- etiquetar handlers desde el exterior (`vm.setHandlerLabel`, `vm.setHandlerHypothesis`)
- trabajar con múltiples plugins en paralelo

## Cómo funciona el servidor de plugins

El servidor WebSocket se inicia automáticamente en:

```
ws://localhost:57130
```

Si la autenticación está habilitada, el plugin debe incluir el token en la URL:

```
ws://localhost:57130?token=TU_TOKEN
```

Esta autenticación se configura mediante la variable de entorno `VMTRACE_PLUGIN_TOKEN` o desde la aplicación si se habilita.

## Cómo crear un plugin paso a paso

### Paso 1: elegir lenguaje

Escoge Python, Node.js, Java o C++ según tu preferencia y disponibilidad de librerías WebSocket.

### Paso 2: conectarse al servidor

Abre una conexión WebSocket hacia `ws://localhost:57130`.

### Paso 3: registrarse

Envía un mensaje JSON-RPC:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "plugin.register",
  "params": { "name": "MiPlugin" }
}
```

El servidor responderá con una ID de cliente y quedará registrado.

### Paso 4: suscribirse a eventos

Si quieres recibir eventos virtuales, suscríbete:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "plugin.subscribe",
  "params": { "events": ["vm.step", "vm.state.changed"] }
}
```

### Paso 5: llamar métodos de VM

Por ejemplo, para pedir el estado actual:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "vm.getState"
}
```

## Métodos JSON-RPC soportados

- `plugin.register`
- `plugin.subscribe`
- `plugin.unsubscribe`
- `vm.step`
- `vm.stepOver`
- `vm.run`
- `vm.stop`
- `vm.reset`
- `vm.getState`
- `vm.setState`
- `vm.getBinaryInfo`
- `vm.getCFG`
- `vm.getTrace`
- `vm.getBytecodeStatistics`
- `vm.findJumpTables`
- `vm.getBytecodeDisassembly`
- `vm.getHandlers`
- `vm.setHandlerLabel`
- `vm.setHandlerHypothesis`

### Nuevos métodos para análisis de bytecode desconocido

- `vm.getBytecodeStatistics`: retorna distribución de bytes y entropía, útil para detectar estructura VM vs datos.
- `vm.findJumpTables`: busca tablas de salto potenciales en el bytecode cargado.
- `vm.getBytecodeDisassembly`: devuelve una descompilación pseudo-ops del bytecode cargado, facilitando la inspección de código oculto.

## Ejemplo mínimo en Python

```python
import json
import websocket

ws = websocket.create_connection('ws://localhost:57130')

ws.send(json.dumps({
    'jsonrpc': '2.0',
    'id': 1,
    'method': 'plugin.register',
    'params': { 'name': 'python-plugin' }
}))

response = ws.recv()
print(response)

ws.send(json.dumps({
    'jsonrpc': '2.0',
    'id': 2,
    'method': 'vm.getState'
}))

print(ws.recv())
ws.close()
```

## Ejemplo mínimo en Node.js

```js
const WebSocket = require('ws')

const ws = new WebSocket('ws://localhost:57130')

ws.on('open', () => {
  ws.send(JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'plugin.register',
    params: { name: 'node-plugin' }
  }))

  ws.send(JSON.stringify({
    jsonrpc: '2.0',
    id: 2,
    method: 'vm.getCFG'
  }))
})

ws.on('message', (message) => {
  console.log('RECEIVED:', message.toString())
})
```

## Java plugins

### Ejecutar `.jar`

Si tienes un JAR listo, coloca el archivo en la carpeta de plugins.

### Ejecutar `.java`

VMTrace compila automáticamente el archivo `*.java` con `javac` y luego ejecuta la clase generada.

El archivo debe tener una clase pública cuyo nombre coincida con el nombre del fichero:

```java
public class PluginMain {
    public static void main(String[] args) {
        // Conexión WebSocket + JSON-RPC aquí
    }
}
```

### Requisitos

- `java` en el PATH
- `javac` en el PATH

## C++ plugins

VMTrace compila archivos `.cpp` con `g++` si está disponible.

El plugin debe ser un ejecutable que use un cliente WebSocket para comunicarse con el servidor.

### Requisitos

- `g++` en el PATH

## Instalación automática de dependencias

VMTrace ofrece instalación automática para Python:

- Instala `websocket-client` cuando es necesario

Para Java y C++, VMTrace detecta la herramienta de compilación y ejecuta el plugin si el entorno está listo.

## Cómo usar la carpeta de plugins

1. Coloca tus plugins en la carpeta de plugins.
2. Abre la pestaña de `Consola Plugins`.
3. Selecciona la carpeta y deja que VMTrace detecte los archivos compatibl
es.
4. Si el plugin se inicia correctamente, debería aparecer en la lista de procesos.

## Nota sobre VMs no conocidas

VMTrace está diseñado para analizar máquinas virtuales custom y puede ayudar a entender VMs nuevas mediante detección de handlers y análisis semántico. Sin embargo, no garantiza soporte para ISAs totalmente inusuales o muy distintos a los patrones de dispatch/handler comunes.
