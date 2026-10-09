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
# 3. cloudflared (túnel público para 'bitwise mirror')
# ----------------------------------------------------------------------------
say "Verificando cloudflared..."
if command -v cloudflared >/dev/null 2>&1; then
    ok "cloudflared presente: $(cloudflared --version 2>/dev/null | head -1)"
else
    warn "cloudflared no encontrado. Instalando..."
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)  CF_ARCH="amd64" ;;
        aarch64|arm64) CF_ARCH="arm64" ;;
        *) fail "arquitectura no soportada para cloudflared: $ARCH" ;;
    esac
    CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}"
    if command -v curl >/dev/null 2>&1; then
        curl -sL --fail "$CF_URL" -o /tmp/cloudflared || fail "descarga de cloudflared falló"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$CF_URL" -O /tmp/cloudflared || fail "descarga de cloudflared falló"
    else
        fail "necesitas curl o wget para instalar cloudflared"
    fi
    chmod +x /tmp/cloudflared
    if [ -w /usr/local/bin ] 2>/dev/null; then
        mv /tmp/cloudflared /usr/local/bin/cloudflared
    else
        sudo mv /tmp/cloudflared /usr/local/bin/cloudflared 2>/dev/null \
            || mkdir -p "$HOME/.local/bin" && mv /tmp/cloudflared "$HOME/.local/bin/cloudflared"
    fi
    ok "cloudflared instalado"
fi

# ----------------------------------------------------------------------------
# 4. Compilar (release)
# ----------------------------------------------------------------------------
say "Compilando Bitwise (modo release, primera vez tarda unos minutos)..."
cargo build --release
ok "compilación exitosa"

# ----------------------------------------------------------------------------
# 5. Verificación final + PATH
# ----------------------------------------------------------------------------
BIN="./target/release/bitwise"
if [ -x "$BIN" ]; then
    # binario disponible en el PATH del usuario (idempotente)
    BIN_DIR="$(cd ./target/release && pwd)"
    case ":$PATH:" in
        *":$BIN_DIR:"*) : ;; # ya está
        *)
            # shellcheck disable=SC2016
            echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.bashrc"
            say "agregado $BIN_DIR al PATH en ~/.bashrc (reinciá la shell o: source ~/.bashrc)"
            ;;
    esac
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
