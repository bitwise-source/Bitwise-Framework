#!/usr/bin/env bash
# ============================================================================
#  Bitwise — build automático
#  Creado por k2sy
#
#  Instala automáticamente todos los requisitos (rustup, toolchain Rust)
#  y compila el proyecto en modo release.
#
#  Uso:      ./build.sh
#  Salida:   ./target/release/bitwise
# ============================================================================
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

say()  { echo -e "${CYAN}[bitwise]${RESET} $*"; }
ok()   { echo -e "${GREEN}[ok]${RESET} $*"; }
warn() { echo -e "${YELLOW}[warn]${RESET} $*"; }
fail() { echo -e "${RED}[error]${RESET} $*"; exit 1; }

echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Bitwise — Reverse Engineering Framework ║"
echo "  ║   creado por k2sy                        ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"

cd "$(dirname "$0")"

# ----------------------------------------------------------------------------
# 1. Compilador C (requerido por capstone-sys vía cc)
# ----------------------------------------------------------------------------
say "Verificando compilador C..."
if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
    ok "compilador C presente"
else
    warn "no se encontró compilador C (gcc/clang). Instalando..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y -qq build-essential
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y group "Development Tools"
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm base-devel
    elif command -v apk >/dev/null 2>&1; then
        apk add build-base
    elif command -v xcode-select >/dev/null 2>&1; then
        xcode-select --install || warn "ejecuta 'xcode-select --install' manualmente"
    else
        fail "no pude detectar el gestor de paquetes. Instala gcc/clang manualmente y relanza."
    fi
    ok "compilador C instalado"
fi

# ----------------------------------------------------------------------------
# 2. Rust (rustup + toolchain estable)
# ----------------------------------------------------------------------------
say "Verificando Rust..."
NEED_RUST=0
if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    ok "Rust presente: $(rustc --version)"
else
    NEED_RUST=1
fi

if [ "$NEED_RUST" -eq 1 ]; then
    warn "Rust no encontrado. Instalando rustup automáticamente..."
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    else
        fail "necesitas curl o wget para instalar Rust. Instálalos y relanza."
    fi
    # activar el entorno recién instalado para esta shell
    export PATH="$HOME/.cargo/bin:$PATH"
    ok "Rust instalado: $(rustc --version)"
fi

# ----------------------------------------------------------------------------
# 3. Compilar (release)
# ----------------------------------------------------------------------------
say "Compilando Bitwise (modo release, primera vez tarda unos minutos)..."
cargo build --release
ok "compilación exitosa"

# ----------------------------------------------------------------------------
# 4. Verificación final
# ----------------------------------------------------------------------------
BIN="./target/release/bitwise"
if [ -x "$BIN" ]; then
    echo
    ok "Bitwise listo: ${BIN}"
    "$BIN" --version
    echo
    echo -e "${BOLD}Uso:${RESET}"
    echo "  $BIN --help           # lista de comandos"
    echo "  $BIN info /bin/ls     # analiza un binario"
    echo "  $BIN tui /bin/ls      # interfaz interactiva"
    echo
    echo -e "${GREEN}Bitwise v$("$BIN" --version | awk '{print $2}') listo por k2sy${RESET}"
else
    fail "el binario no se generó; revisa los errores de cargo arriba"
fi
