//! Vistas de la TUI.

/// Modo de vista activo en la TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Disasm,
    Symbols,
    Sections,
    Functions,
    Decomp,
    Help,
}

pub const HELP_TEXT: &str = "\
bitwise — ayuda
──────────────────────────────────────────────
Teclas:
  ↑ / k        subir cursor
  ↓ / j        bajar cursor
  1            vista desensamblado
  2            vista símbolos
  3            vista secciones
  5            vista funciones (call-graph)
  6            vista decompilación
  4            esta ayuda
  /            buscar en símbolos
  r            renombrar función bajo el cursor (vista funciones)
  d            decompilar función bajo el cursor (vista funciones)
  t            re-tipar variable bajo el cursor (vista decomp)
  q / Esc      salir

Vistas:
  disasm     instrucciones nativas (Capstone, sintaxis Intel)
  symbols    símbolos del binario (funciones, objetos)
  sections   secciones con permisos rwx
  functions  funciones detectadas (símbolos + prólogos + call-graph)
  decomp     pseudo-C de la última función decompilada

Annotations:
  Los renombres se guardan en <binario>.bitwise.json y se
  reutilizan en cada decompilación (CLI, TUI y MCP).";