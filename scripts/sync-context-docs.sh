#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# sync-context-docs.sh — Descarga los README.md de los repos relacionados de
# NetEdge a la raíz del repo, para tener a mano su documentación como contexto.
#
# DELIBERADAMENTE separado de `cargo build`: hace red y no debe contaminar la
# compilación (que es offline/air-gap). Ejecútalo a demanda cuando quieras
# refrescar el contexto; los ficheros resultantes están gitignorados.
#
# Uso:
#   scripts/sync-context-docs.sh              # descarga todos
#   GITHUB_TOKEN=ghp_xxx scripts/sync-context-docs.sh   # repos privados / sin rate-limit
#
# Requisitos: curl. Si un repo es privado, exporta GITHUB_TOKEN (scope `repo`).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Repos a sincronizar:  "owner/repo"  →  "fichero-destino.md"
REPOS=(
  "atalaminos/netedge:README_netedge.md"
)

# Raíz del repo (este script vive en scripts/) = destino de los ficheros.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT"

# Cabeceras comunes de la API de GitHub. `raw` devuelve el contenido del README
# directamente (resolviendo su nombre y la rama por defecto sin adivinar).
AUTH=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

fetch_readme() {
  local repo="$1" out="$2"
  local url="https://api.github.com/repos/${repo}/readme"
  local tmp status
  tmp="$(mktemp)"

  status="$(curl -sSL \
    "${AUTH[@]}" \
    -H "Accept: application/vnd.github.raw+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -w '%{http_code}' -o "$tmp" \
    "$url" || true)"

  if [[ "$status" == "200" && -s "$tmp" ]]; then
    # Anteponemos una cabecera de procedencia sin tocar el contenido original.
    {
      echo "<!-- Sincronizado desde https://github.com/${repo} el $(date -u +%Y-%m-%dT%H:%M:%SZ) -->"
      echo "<!-- NO EDITAR A MANO: regenerable con scripts/sync-context-docs.sh -->"
      echo
      cat "$tmp"
    } > "$DEST/$out"
    printf '  ✔ %-30s → %s (%s bytes)\n' "$repo" "$out" "$(wc -c < "$tmp")"
    rm -f "$tmp"
    return 0
  fi

  rm -f "$tmp"
  printf '  [x] %-30s -> HTTP %s (¿repo privado sin GITHUB_TOKEN, o inexistente?)\n' "$repo" "${status:-error}" >&2
  return 1
}

echo "Sincronizando README.md de repos relacionados → raíz del repo ($DEST)"
rc=0
for entry in "${REPOS[@]}"; do
  repo="${entry%%:*}"
  out="${entry##*:}"
  fetch_readme "$repo" "$out" || rc=1
done

if [[ $rc -ne 0 ]]; then
  echo "Algún README no se pudo descargar (ver arriba)." >&2
  exit 1
fi
echo "Hecho."
