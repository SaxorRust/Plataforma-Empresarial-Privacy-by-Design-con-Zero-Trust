#!/usr/bin/env bash
# ==============================================================================
# Suite de pruebas negativas de confinamiento Seccomp-BPF & AppArmor (MC-01)
# Verifica que `zt-hospital-api` opera normalmente bajo Seccomp default-deny y
# que las llamadas/operaciones prohibidas devuelven `Operation not permitted`
# o `Read-only file system` / `Permission denied`.
#
# Uso: ./infra/scripts/verify-sandboxing-mc01.sh [CONTAINER_NAME]
# ==============================================================================
set -uo pipefail

CONTAINER="${1:-zt-hospital-api}"
PASS=0
WARN=0
FAIL=0

ok()   { echo "[PASS] $1"; PASS=$((PASS + 1)); }
warn() { echo "[WARN] $1"; WARN=$((WARN + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

echo "========================================================================"
echo " Verificación de Confinamiento Seccomp-BPF / AppArmor (MC-01)"
echo " Contenedor: ${CONTAINER}"
echo "========================================================================"

if ! docker inspect "${CONTAINER}" >/dev/null 2>&1; then
  echo "[ERROR] Contenedor '${CONTAINER}' no encontrado. Levanta el stack primero con 'docker compose up -d'." >&2
  exit 1
fi

echo ""
echo "--- 1. Metadatos de endurecimiento del contenedor ---"
READONLY_FS="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "${CONTAINER}")"
if [[ "${READONLY_FS}" == "true" ]]; then
  ok "ReadonlyRootfs=true activo"
else
  fail "ReadonlyRootfs no está activo (${READONLY_FS})"
fi

CAP_DROP="$(docker inspect -f '{{.HostConfig.CapDrop}}' "${CONTAINER}")"
if echo "${CAP_DROP}" | grep -q "ALL"; then
  ok "CapDrop=[ALL] activo"
else
  fail "CapDrop no incluye ALL (${CAP_DROP})"
fi

SEC_OPT="$(docker inspect -f '{{.HostConfig.SecurityOpt}}' "${CONTAINER}")"
if echo "${SEC_OPT}" | grep -q "no-new-privileges:true"; then
  ok "no-new-privileges:true activo"
else
  fail "no-new-privileges:true ausente (${SEC_OPT})"
fi

if echo "${SEC_OPT}" | grep -q "seccomp="; then
  ok "Perfil Seccomp-BPF personalizado cargado en HostConfig.SecurityOpt"
else
  fail "No se detectó perfil Seccomp personalizado en SecurityOpt"
fi

APPARMOR_PROFILE="$(docker inspect -f '{{.AppArmorProfile}}' "${CONTAINER}")"
if [[ "${APPARMOR_PROFILE}" == "zt-hospital-api" ]]; then
  ok "Perfil AppArmor personalizado activo: ${APPARMOR_PROFILE}"
elif [[ -n "${APPARMOR_PROFILE}" ]]; then
  warn "AppArmor activo con perfil '${APPARMOR_PROFILE}' (en Ubuntu VM usa docker-compose.apparmor.yml para 'zt-hospital-api')"
else
  warn "Kernel del host sin AppArmor LSM habilitado (normal fuera de Ubuntu Server VM)"
fi

echo ""
echo "--- 2. Pruebas negativas dentro del contenedor (EPERM / Operation not permitted) ---"

run_negative_python_probe() {
  local label="$1"
  local py_code="$2"
  local expected_regex="$3"
  local out
  out="$(docker exec "${CONTAINER}" python3 -c "${py_code}" 2>&1 || true)"
  if echo "${out}" | grep -Eqi "${expected_regex}"; then
    ok "${label}: bloqueado (${out})"
  else
    fail "${label}: NO fue bloqueado como se esperaba (salida: ${out})"
  fi
}

# 2a. os.fork() bloqueado por Seccomp (clone restringido solo a CLONE_THREAD)
run_negative_python_probe \
  "Seccomp bloquea os.fork()" \
  "import os; os.fork()" \
  "Operation not permitted|Errno 1"

# 2b. subprocess / ejecución de shell bloqueada (sin fork/vfork/posix_spawn)
run_negative_python_probe \
  "Seccomp bloquea subprocess.run(['/bin/sh', '-c', 'id'])" \
  "import subprocess; subprocess.run(['/bin/sh', '-c', 'id'], check=True)" \
  "Operation not permitted|Errno 1|Permission denied"

# 2c. Syscall mount bloqueada por Seccomp (default-deny EPERM)
run_negative_python_probe \
  "Seccomp bloquea syscall mount()" \
  "import ctypes, os; libc=ctypes.CDLL(None, use_errno=True); r=libc.mount(b'none', b'/tmp', b'tmpfs', 0, None); e=ctypes.get_errno(); print(f'rc={r} errno={e} msg={os.strerror(e)}')" \
  "Operation not permitted|errno=1"

# 2d. Syscall unshare (escape de namespaces) bloqueada por Seccomp
run_negative_python_probe \
  "Seccomp bloquea syscall unshare()" \
  "import ctypes, os; libc=ctypes.CDLL(None, use_errno=True); r=libc.unshare(0x10000000); e=ctypes.get_errno(); print(f'rc={r} errno={e} msg={os.strerror(e)}')" \
  "Operation not permitted|errno=1"

# 2e. Syscall ptrace (inyección de procesos) bloqueada por Seccomp
run_negative_python_probe \
  "Seccomp bloquea syscall ptrace()" \
  "import ctypes, os; libc=ctypes.CDLL(None, use_errno=True); r=libc.ptrace(0, 0, 0, 0); e=ctypes.get_errno(); print(f'rc={r} errno={e} msg={os.strerror(e)}')" \
  "Operation not permitted|errno=1"

# 2f. Socket AF_PACKET (raw sniffing) bloqueado por Seccomp
run_negative_python_probe \
  "Seccomp bloquea socket AF_PACKET (raw sniffing)" \
  "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)" \
  "Operation not permitted|Errno 1"

# 2g. Syscall chmod bloqueada por Seccomp
run_negative_python_probe \
  "Seccomp bloquea syscall chmod()" \
  "import os; os.chmod('/tmp', 0o777)" \
  "Operation not permitted|Errno 1"

# 2h. Escritura en /app bloqueada (raíz read-only + AppArmor deny /app/** w)
run_negative_python_probe \
  "RootFS read-only bloquea escritura en /app" \
  "open('/app/malicious.py', 'w').write('x')" \
  "Read-only file system|Permission denied|Operation not permitted"

# 2i. Prueba positiva: /health sigue respondiendo 200 OK bajo confinamiento
echo ""
echo "--- 3. Prueba positiva bajo confinamiento ---"
HEALTH_OUT="$(docker exec "${CONTAINER}" python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())" 2>&1 || true)"
if echo "${HEALTH_OUT}" | grep -q '"status":"ok"'; then
  ok "API FastAPI operativa bajo confinamiento estricto: ${HEALTH_OUT}"
else
  fail "API FastAPI falló prueba positiva /health bajo confinamiento: ${HEALTH_OUT}"
fi

echo ""
echo "========================================================================"
echo " Resumen MC-01 Sandboxing: PASS=${PASS} | WARN=${WARN} | FAIL=${FAIL}"
echo "========================================================================"
[[ "${FAIL}" -eq 0 ]]
