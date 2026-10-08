//! Vistas de la TUI.

/// Modo de vista activo en la TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Disasm,
    Symbols,
    Sections,
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
  4            esta ayuda
  /            buscar en símbolos
  q / Esc      salir

Vistas:
  disasm    instrucciones nativas (Capstone, sintaxis Intel)
  symbols   símbolos del binario (funciones, objetos)
  sections  secciones con permisos rwx
";
