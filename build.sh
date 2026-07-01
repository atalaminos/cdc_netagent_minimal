#!/usr/bin/env bash
# Compila Netagent en Linux (release), ejecuta los tests y, si el target de
# Windows está instalado, hace una comprobación de compilación cruzada.
#
# Uso:
#   ./build.sh            # release + tests (+ check Windows si está disponible)
#   ./build.sh --debug    # build de debug en vez de release
#   ./build.sh --no-test  # omite los tests
set -euo pipefail
cd "$(dirname "$0")"

PROFILE="--release"
RUN_TESTS=1
for arg in "$@"; do
  case "$arg" in
    --debug)   PROFILE="" ;;
    --no-test) RUN_TESTS=0 ;;
    *) echo "argumento desconocido: $arg"; exit 2 ;;
  esac
done

echo "==> Compilando workspace (Linux) ${PROFILE:-debug}"
cargo build --workspace $PROFILE

if [ "$RUN_TESTS" -eq 1 ]; then
  echo "==> Ejecutando tests"
  cargo test --workspace
fi

# Comprobación de tipos para Windows si el target está instalado (no enlaza).
if command -v rustup >/dev/null 2>&1 && rustup target list --installed 2>/dev/null | grep -q '^x86_64-pc-windows-gnu$'; then
  echo "==> Comprobando compilación para Windows (x86_64-pc-windows-gnu)"
  cargo check --workspace --target x86_64-pc-windows-gnu
else
  echo "==> (omitido) target x86_64-pc-windows-gnu no instalado:"
  echo "    rustup target add x86_64-pc-windows-gnu"
fi

BIN="target/$([ -n "$PROFILE" ] && echo release || echo debug)/netagent"
echo "==> Listo. Binario: $BIN"
