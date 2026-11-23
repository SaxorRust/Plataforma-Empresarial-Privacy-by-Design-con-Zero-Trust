#!/usr/bin/env bash
# ==============================================================================
# Instalador idempotente del perfil AppArmor `zt-hospital-api` (MC-01)
# Ejecutar en la VM Ubuntu Server 26.04.1 LTS antes de levantar con AppArmor:
#   sudo ./infra/scripts/install-apparmor-profile.sh
#   docker compose -f docker-compose.yml -f docker-compose.apparmor.yml up -d --build
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROFILE_SRC="${REPO_ROOT}/infra/apparmor/zt-hospital-api"
PROFILE_DST="/etc/apparmor.d/zt-hospital-api"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Error: ejecuta este script con sudo (sudo $0)." >&2
  exit 1
fi

if ! command -v apparmor_parser >/dev/null 2>&1; then
  echo "Error: apparmor_parser no encontrado. Instala 'apparmor' y 'apparmor-utils'." >&2
  exit 2
fi

if [[ ! -f "${PROFILE_SRC}" ]]; then
  echo "Error: no se encontró el perfil fuente en ${PROFILE_SRC}." >&2
  exit 3
fi

echo "[1/3] Copiando perfil a ${PROFILE_DST}..."
install -m 0644 "${PROFILE_SRC}" "${PROFILE_DST}"

echo "[2/3] Cargando y aplicando perfil en modo enforce..."
apparmor_parser -r -W "${PROFILE_DST}"

echo "[3/3] Verificando que 'zt-hospital-api' esté cargado en aa-status..."
if aa-status 2>/dev/null | grep -q "zt-hospital-api"; then
  echo "[PASS] Perfil AppArmor 'zt-hospital-api' activo en modo enforce."
else
  echo "[WARN] El perfil se cargó sin errores, verifica manualmente con 'sudo aa-status'." >&2
fi
