<div align="center">

<img src="docs/banner.png" alt="Bitwise" width="720"/>

# Bitwise

**Framework de ingeniería inversa multi-plataforma y open source**

[![Rust](https://img.shields.io/badge/Rust-2024-orange?logo=rust)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20Windows%20%7C%20macOS-green)](#)
[![Version](https://img.shields.io/badge/version-0.1.0-purple)](#)

Analiza binarios **ELF** · **PE** · **Mach-O** — desensambla, construye IR propio,
decompila a pseudo-C, debuggea con breakpoints, y automatiza con scripting.

[Instalación](#-instalación) · [Uso](#-uso-rápido) · [Arquitectura](#️-arquitectura) · [Roadmap](#️-roadmap)

*Creado por **k2sy***

</div>

---

## ✨ Características

| Área | Qué hace |
|---|---|
| 📦 **Parsers** | ELF (32/64-bit, LE/BE) · PE (PE32/PE32+) · Mach-O (thin + FAT) |
| 🔧 **Desensamblado** | x86 · x86-64 · ARM32 · AArch64 (Capstone, sintaxis Intel) |
| 🧬 **IR propio** | Varnodes + 30 ops P-Code (estilo SLEIGH simplificado) |
| 📝 **Decompilador** | IR → pseudo-C legible con variables nombradas |
| 🐛 **Debugger** | ptrace nativo: breakpoints INT3, registros, memoria, single-step |
| 🖥️ **TUI** | Interfaz interactiva: disasm/symbols/sections, búsqueda, hexdump |
| 🐚 **Scripting** | Lenguaje `.bws` embebido para automatizar análisis |
| 🤖 **MCP Server** | Expón Bitwise a agentes de IA (Claude, Cursor) vía 8 herramientas |
| 🔍 **Análisis** | Detección de funciones, CFG, xrefs, strings, diff de binarios |

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

# Decompilar funciones a pseudo-C
bitwise decompile /bin/ls -n 3

# Ver el IR (P-Code)
bitwise ir /bin/ls -s .text -n 20

# Strings, xrefs, hexdump
bitwise strings /bin/ls -n 8 -g "GNU"
bitwise xrefs /bin/ls 0x4970
bitwise hexdump /bin/ls -s .text -n 16

# Detección de funciones + bloques básicos
bitwise analyze /bin/ls --blocks

# Interfaz interactiva
bitwise tui /bin/ls

# Debugger con breakpoint en entry point
bitwise debug /bin/ls

# Automatización con scripts
bitwise script analisis.bws

# Comparar dos versiones de un binario
bitwise diff ./app_v1 ./app_v2
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
├── bitwise-core/       # Tipos, parsers (ELF, PE, Mach-O), análisis (CFG, xrefs, strings)
├── bitwise-disasm/     # Motor de desensamblado (Capstone wrapper)
├── bitwise-ir/         # IR propio: Varnodes + P-Code ops
├── bitwise-lift/       # Lifter x86-64 → IR
├── bitwise-decomp/     # Decompilador IR → pseudo-C
├── bitwise-debug/      # Debugger ptrace (Linux) con breakpoints INT3
├── bitwise-tui/        # TUI interactiva (crossterm) + hexdump
├── bitwise-script/     # Motor de scripting .bws (parser + intérprete)
└── bitwise-cli/        # CLI (clap) — binario `bitwise`
```

## 🗺️ Roadmap

- [x] Parsers ELF / PE / Mach-O
- [x] Desensamblado multi-arquitectura
- [x] IR propio (P-Code)
- [x] Decompilador a pseudo-C
- [x] Debugger con breakpoints (Linux)
- [x] TUI interactiva
- [x] Scripting embebido
- [x] Structuring de control flow (if/else/while/do-while con dominadores)
- [x] Type recovery (uint8/16/32/64, int, void*, float, signed/unsigned)
- [x] Lifter AArch64 (stp/ldp/adrp/cbz/b.cond)
- [x] Desensamblado RISC-V / MIPS / PowerPC
- [x] Debugger backends skeleton: Windows (Debug API) y macOS (Mach exceptions)
- [x] Base de datos de firmas de funciones
- [x] Detección de funciones por call-graph (binarios stripped)
- [x] DWARF debug info (nombres de funciones de binarios -g)
- [x] TUI interactiva: vista funciones, renombrado (r) y decompilado (d) integrados
- [x] CI multi-plataforma + releases automáticos (GitHub Actions) 

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
