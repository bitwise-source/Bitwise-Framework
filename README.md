<div align="center">

<img src="docs/banner.png" alt="Bitwise" width="720"/>

# Bitwise

**Framework de ingeniería inversa multi-plataforma y open source**

[![Rust](https://img.shields.io/badge/Rust-2024-orange?logo=rust)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20Windows%20%7C%20macOS-green)](#)
[![Version](https://img.shields.io/badge/version-0.3.5-purple)](#)
[![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?logo=githubactions)](../../actions)

Analiza **binarios** (ELF · PE · Mach-O) y **páginas web** — desensambla,
decompila a pseudo-C, debuggea, emula, y deobfusca JavaScript.

[Instalación](#-instalación) · [Uso](#-uso-rápido) · [Arquitectura](#️-arquitectura) · [Roadmap](#️-roadmap)

*Creado por **k2sy***

</div>

---

## ✨ Características

| Área | Qué hace |
|---|---|
| 📦 **Parsers** | ELF (32/64-bit, LE/BE) · PE (PE32/PE32+) · Mach-O (thin + FAT) |
| 🔧 **Desensamblado** | x86 · x86-64 · ARM32 · AArch64 · MIPS · PowerPC · RISC-V |
| 🧬 **IR propio** | Varnodes + 30 ops P-Code (estilo SLEIGH simplificado) |
| 📝 **Decompilador** | IR → pseudo-C con structuring, type recovery y optimizer |
| 🔍 **Análisis** | Call-graph, CFG, xrefs, strings, DWARF, demangling C++, vtables |
| 🏷️ **Firmas** | Genera y matchea firmas FLIRT-like de funciones conocidas |
| 🐛 **Debugger** | ptrace nativo: breakpoints INT3, registros, memoria, single-step |
| ⚡ **Emulador** | Interpreter x86-64 puro — descifra strings y checks sin ejecutar |
| 🌐 **Recon web** | Endpoints, secrets filtrados, stack, formularios de páginas web |
| 🔓 **JS deobfuscator** | Beautify, renombrado de `_0x..`, decodificación `\xNN`, sourcemaps |
| 🛡️ **Packers** | Detección UPX/ASPack/MPRESS + entropía + parcheo de binarios |
| 🖥️ **TUI** | Interactiva: navega funciones, decompila (`d`), renombra (`r`) |
| 🐚 **Scripting** | Lenguaje `.bws` embebido para automatizar análisis |
| 🤖 **MCP Server** | Expón Bitwise a agentes de IA (Claude, Cursor) vía 8 herramientas |

## 🤖 MCP Server (integración con agentes de IA)

Bitwise se expone vía [Model Context Protocol](https://modelcontextprotocol.io/) para que agentes como Claude o Cursor lo usen directamente. El servidor `bitwise-mcp` corre sobre stdio (JSON-RPC newline-delimited) y ofrece **8 herramientas**:

| Tool | Qué hace |
|---|---|
| `bitwise_info` | Formato, arquitectura, entry point, conteo de secciones/símbolos |
| `bitwise_sections` | Lista secciones con permisos rwx |
| `bitwise_symbols` | Símbolos (funciones/objetos), con filtro |
| `bitwise_disasm` | Desensamblado de una sección |
| `bitwise_strings` | Strings ASCII con grep opcional |
| `bitwise_xrefs` | Xrefs hacia una dirección |
| `bitwise_decompile` | Pseudo-C de funciones |
| `bitwise_analyze` | Detección de funciones + bloques básicos |

**Configuración para Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "bitwise": {
      "command": "/path/to/bitwise/target/release/bitwise-mcp"
    }
  }
}
```

Para otros clientes MCP (Cursor, Zed, etc.) el mismo binario sirve — solo cambia la ruta.

## 🚀 Instalación

```bash
git clone https://github.com/bitwise-source/Bitwise-Framework.git
cd bitwise
./build.sh    # instala Rust automáticamente si falta y compila
```

O manualmente con Rust ya instalado:

```bash
cargo build --release
```

## 📖 Uso rápido

```bash
# Info general del binario
bitwise info /bin/ls

# Desensamblar .text con bytes
bitwise disasm /bin/ls -s .text -n 30 -b

# Decompilar funciones a pseudo-C (usa renombres del proyecto)
bitwise decompile /bin/ls -n 3

# Ver el IR (P-Code)
bitwise ir /bin/ls -s .text -n 20

# Strings, xrefs, hexdump
bitwise strings /bin/ls -n 8 -g "GNU"
bitwise xrefs /bin/ls 0x4970
bitwise hexdump /bin/ls -s .text -n 16

# Detección de funciones (call-graph: funciona en stripped)
bitwise analyze /bin/ls --blocks

# Interfaz interactiva: [5] funciones · [d] decompilar · [r] renombrar
bitwise tui /bin/ls

# Debugger con breakpoint en entry point
bitwise debug /bin/ls

# Emular una función (sin ejecutar el binario)
bitwise emu /bin/ls -f 0x4da4 -n 100

# Renombrar funciones/variables (persiste en .bitwise.json)
bitwise annotate /bin/ls --funcs 0x4da4 main

# Identificar funciones con firmas generadas de libc
bitwise-siggen /lib/x86_64-linux-gnu/libc.so.6 libc_sigs.json
bitwise identify /bin/ls --signatures libc_sigs.json

# Demangling C++ y vtables
bitwise demangle ./app --vtables

# Detección de packers + parcheo con backup
bitwise packer ./malware.exe
bitwise patch ./crackme --at 0x401000 --with 9090 --backup

# Exportar CFG a Graphviz
bitwise cfg-dot /bin/ls -f 0x4da4 > cfg.dot && dot -Tpng cfg.dot -o cfg.png
```

### 🌐 Recon web

```bash
# Analizar una página (endpoints, secrets, stack, formularios)
bitwise web https://ejemplo.com

# Descargar y analizar también los JS externos
bitwise web https://ejemplo.com --deep
```

### 🎭 Análisis dinámico (CDP)

Renderiza la página con un navegador headless real: captura requests XHR/Fetch
invisibles al análisis estático, el DOM post-JS, y ejecuta JS arbitrario.

```bash
# Render + reporte (endpoints dinámicos, scripts, errores de consola)
bitwise web-dyn https://ejemplo.com

# Ejecutar JS arbitrario en la página renderizada
bitwise web-dyn https://ejemplo.com --js "document.querySelectorAll('a').length"

# Screenshot PNG de la página renderizada
bitwise web-dyn https://ejemplo.com --screenshot out.png

# Ambos + tiempo de espera custom (SPA lentas)
bitwise web-dyn https://ejemplo.com -w 5000 -j "localStorage.getItem('token')" -s shot.png
```

Requiere Chrome/Chromium instalado (`chromium`, `google-chrome` o
`chrome-headless-shell` en PATH). Corriendo como root agrega `--no-sandbox`
automáticamente.


### 🔓 Deobfuscar JavaScript

```bash
# Deobfuscado completo: renombra _0x4f2a → v5, decodifica '\x48\x65...' → 'Hello'
bitwise js script_ofuscado.js

# Solo métricas y score de ofuscación
bitwise js script.js --stats

# Solo beautify (sin renombrar)
bitwise js script.js -B

# Desde URL + buscar sourcemaps públicos
bitwise js https://sitio.com/app.js -m
```

### Ejemplo: salida de `decompile`

```c
// Function: func_4da4 (entry: 0x4da4)
void func_4da4() {
    rsp = rsp - 8;
    *(rsp) = rbp;
    rbp = rsp;
    ...
    if (rsi) goto 0x6d03;
    rdi = rbx;
    rax = strrchr();
    ...
}
```

### Scripting (.bws)

```text
# analisis.bws
open "/bin/ls"
info
sections exec
symbols func
eval 0x1000 + 0x10
```

## 🏗️ Arquitectura

```
bitwise/
├── bitwise-core/       # Tipos, parsers (ELF/PE/Mach-O), análisis (CFG, call-graph,
│                       #   xrefs, strings, DWARF, demangling, firmas, annotations,
│                       #   packers, recon web, JS deobfuscator)
├── bitwise-disasm/     # Motor de desensamblado (Capstone, 7 arquitecturas)
├── bitwise-ir/         # IR propio: Varnodes + P-Code ops
├── bitwise-lift/       # Lifters x86-64 / AArch64 → IR
├── bitwise-decomp/     # Decompilador: optimizer + type recovery + structuring
├── bitwise-debug/      # Debugger multi-OS (ptrace funcional, Win/Mac skeleton)
├── bitwise-emu/        # Emulador x86-64 interpreter puro
├── bitwise-tui/        # TUI interactiva + hexdump + export Graphviz
├── bitwise-script/     # Motor de scripting .bws
├── bitwise-mcp/        # Servidor MCP (agentes de IA)
└── bitwise-cli/        # CLI — binario `bitwise` + hardening/siggen/stress
```

## 🗺️ Roadmap

- [x] Parsers ELF / PE / Mach-O
- [x] Desensamblado multi-arquitectura (x86/x64/ARM/AArch64/MIPS/PPC/RISC-V)
- [x] IR propio (P-Code) + lifter x86-64 y AArch64
- [x] Decompilador a pseudo-C con structuring, type recovery y optimizer
- [x] Debugger con breakpoints (Linux) + backends Windows/macOS (skeleton)
- [x] Emulador x86-64 (interpreter puro)
- [x] TUI interactiva: vistas, búsqueda, renombrado (`r`) y decompilado (`d`)
- [x] Scripting embebido (.bws)
- [x] Sistema de firmas FLIRT-like: `siggen` genera, `identify` matchea
- [x] Detección de funciones por call-graph (binarios stripped)
- [x] DWARF debug info + demangling C++ + vtables
- [x] Annotations persistentes (`.bitwise.json`, compartidas CLI/TUI/MCP)
- [x] Detección de packers + parcheo de binarios
- [x] CI multi-plataforma + releases automáticos (GitHub Actions)
- [x] Recon de páginas web: endpoints, secrets, stack, formularios
- [x] JS deobfuscator: beautify, renombrado, decodificación, sourcemaps
- [x] MCP Server (8 herramientas)
- [x] Análisis dinámico web (navegador headless vía CDP — `bitwise web-dyn`)
- [x] Decompilador interactivo: re-tipeo de variables desde la TUI (tecla `t`)
- [x] Lifter AArch64: mul/div, lógica (orr/eor/mvn), ldr/str, br/blr, svc
- [x] Análisis dinámico avanzado (ejecutar JS arbitrario y screenshots vía CDP)

## 🤝 Contribuir

Las PR son bienvenidas. Para compilar y testear:

```bash
./build.sh
cargo test
```

## 📄 Licencia

MIT — ver [LICENSE](LICENSE)

---

<div align="center">

**Bitwise** · hecho con cariño por [**k2sy**](https://discord.gg/TxB4drcSvG)

<br/>

<a href="https://discord.gg/TxB4drcSvG" target="_blank">
  <img src="https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/discord.svg" alt="Discord" width="42" height="42"/>
</a>

<br/>

[💬 Únete a nuestro Discord](https://discord.gg/TxB4drcSvG)

</div>