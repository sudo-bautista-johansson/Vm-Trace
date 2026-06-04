# VM-Trace

VM-Trace es una herramienta de análisis y emulación de máquinas virtuales custom dentro de binarios.

## Qué hace

VM-Trace carga binarios PE y ELF que contienen bytecode de máquinas virtuales internas, emula su ejecución y ofrece datos para ingeniería inversa.

## Para qué sirve

- Analizar VMs usadas por ofuscadores y protectores
- Seguir la ejecución de bytecode paso a paso
- Inspeccionar el estado interno de la VM (pila, registros, flags)
- Generar y revisar el flujo de control de los handlers virtuales
- Exportar trazas de ejecución para análisis posterior

## Qué no es

VM-Trace no emula código nativo estándar, no ejecuta APIs de Windows ni funciona como un emulador x86/x64 general.

## ¿Puede analizar VMs desconocidas?

VM-Trace puede ayudar a analizar VMs arbitrarias mediante detección de dispatchers, handlers y semántica de opcodes. Además, ahora incluye detección de tablas de salto y generación de pseudo-desensamblado de bytecode para que puedas inspeccionar código oculto incluso cuando el dispatcher no es evidente.

Funciona mejor con VMs que siguen patrones de despacho y handlers típicos; no es una garantía para ISAs extremadamente exóticos o personalizados hasta el extremo.

## Por qué usarlo

- Para descubrir cómo funciona una VM custom dentro de un binario
- Para extraer lógica oculta de obfuscadores y protectores
- Para apoyar procesos de devirtualización de código

## Cómo comenzar

1. Abrir un binario PE/ELF con bytecode VM
2. Cargarlo en la herramienta
3. Inspeccionar bytecode y control flow
4. Ejecutar la VM paso a paso o registrar una traza
5. Analizar handlers y estructuras de ejecución

## Ubicación principal del código

- `src/core/analysis/` — análisis de bytecode y detección de handlers
- `src/core/emulator/` — motor de ejecución de la VM
- `src/core/loader/` — parsers de PE y ELF
- `src/renderer/` — interfaz y visualización

---

VM-Trace está diseñado para ingenieros inversos que trabajan con máquinas virtuales personalizadas y necesitan entender su comportamiento interno de manera confiable.- ✅ Stack Management (DUP, SWAP presentes)

**Documentación:** Ver [ADVANCED_VM_BINARY.md](./ADVANCED_VM_BINARY.md) para detalles completos de bytecode

---

## 🚀 Quick Start

### Requisitos
- Node.js 18+
- npm o yarn
- Windows 10+

### Instalación
```bash
# Clonar o descargar el proyecto
cd c:\Users\User\Desktop\VMTrace

# Instalar dependencias
npm install

# Iniciar desarrollo
npm run dev

# Build para producción
npm run build
```

### Uso Básico
1. Presiona **"📂 Cargar Binario"**
2. Selecciona `samples/sample_vm.elf` o tu propio binario
3. Usa **Step (F7)**, **Step Over (F8)**, **Run (F9)**
4. Revisa **CFG Grafo**, **Bytecode Viewer**, **VM State**
5. Inspecciona handlers en **Handler Inspector**

---

## 📊 Estadísticas

| Métrica | Valor |
|---------|-------|
| **Líneas de Código** | ~4000+ |
| **Archivos TS** | 20+ |
| **Opcodes Soportados** | 20+ |
| **Idiomas Soportados** | 2 (EN/ES) |
| **Commits** | Active development |
| **Testing** | Unit + Integration (TODO) |

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Prioridades:

1. **Detección automática**
2. **Bug fixes** y mejoras de estabilidad
3. **Documentación** y ejemplos
4. **Tests** unitarios e integración

### Proceso
1. Fork el repositorio
2. Crea rama: `git checkout -b feature/my-feature`
3. Commit: `git commit -am 'Add my feature'`
4. Push: `git push origin feature/my-feature`
5. PR a `main`

---

## 🐛 Conocidos Issues

- ✅ CFG dinámico ahora incluye bucles detectados a partir de la traza de ejecución.
- ✅ Plugin Server requiere token de conexión para autenticación (`VMTRACE_PLUGIN_TOKEN` o `vmtrace-plugin` por defecto).
- ✅ Soporte de decodificación variable-length habilitado en el ejecutor en tiempo real.
- ✅ El recorder mantiene el límite de `500k` entradas y recicla entradas antiguas automáticamente.

---

## 📚 Documentación Adicional

- [Fixes Applied](./FIXES_APPLIED.md) — Correcciones recientes
- [Architecture](./architecture.md) — Detalles técnicos
- [Plugins](./plugins.md) — Documentación oficial de plugins

---

## 📝 Licencia

MIT License — Libre para usar, modificar y distribuir

---

## 🎓 Casos de Uso

VMTrace es útil para:
- 📖 Aprender análisis de bytecode
- 🔬 Investigación de protección de software
- 🏆 Competencias de CTF (reverse engineering)
- 🎯 Análisis dinámico de VMs custom

---

## 💬 Feedback & Support

- 🐛 **Bugs:** Abrir issue en repositorio
- 💡 **Features:** Discusión en GitHub
- 📧 **Contact:** Contacto en perfil

---

## 🙏 Agradecimientos

- **Cytoscape.js** — CFG visualization
- **Electron** — Cross-platform desktop
- **TypeScript** — Type safety
- **Ghidra** — Inspiración para reverse engineering

---

**Made with ❤️ for reverse engineers and security researchers.**

Last Updated: June 3, 2026 | Status: Active Development ✨

