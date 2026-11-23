#!/usr/bin/env bash
# ==============================================================================
# Suite de verificación E2E para Módulo A (MA-01 Autenticación + MA-02 Bóveda Vault)
# Uso: ./infra/scripts/verify-ma01-ma02.sh [BASE_URL]
# Ejemplo local:      ./infra/scripts/verify-ma01-ma02.sh http://127.0.0.1:8000
# Ejemplo producción: ./infra/scripts/verify-ma01-ma02.sh https://tralaleritosmigajeros.uk
# ==============================================================================
set -uo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
BASE_URL="${BASE_URL%/}"
SUFFIX="$(date +%s)_$RANDOM"
PASS=0
FAIL=0

ok()   { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: se requiere '$1' instalado para ejecutar esta verificación." >&2
    exit 2
  fi
}

require_cmd curl
require_cmd jq

echo "========================================================================"
echo " Verificación E2E MA-01 (Argon2id/WebAuthn/JWT) + MA-02 (Vault Transit+KV)"
echo " Objetivo: ${BASE_URL}"
echo "========================================================================"

# 1. Salud base
HEALTH_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${BASE_URL}/health" || echo "000")"
if [[ "${HEALTH_CODE}" == "200" ]]; then
  ok "GET /health respondió HTTP 200"
else
  fail "GET /health falló (HTTP ${HEALTH_CODE})"
  exit 1
fi

register_and_login() {
  local username="$1"
  local role="$2"
  local password="$3"

  local reg_code
  reg_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${username}\",\"password\":\"${password}\",\"role\":\"${role}\"}")"
  if [[ "${reg_code}" != "201" ]]; then
    fail "Registro de ${username} (${role}) devolvió HTTP ${reg_code}"
    return 1
  fi

  local login_body
  login_body="$(curl -s -X POST "${BASE_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${username}\",\"password\":\"${password}\"}")"
  local token
  token="$(echo "${login_body}" | jq -r '.access_token // empty')"
  if [[ -z "${token}" ]]; then
    fail "Login Argon2id de ${username} (${role}) no devolvió access_token"
    return 1
  fi
  echo "${token}"
}

MEDICO_USER="dr_${SUFFIX}"
ANALISTA_USER="ana_${SUFFIX}"
AUDITOR_USER="aud_${SUFFIX}"
ADMIN_USER="adm_${SUFFIX}"
STRONG_PASS="Hospital!2026#ZeroTrust"

echo ""
echo "--- 1. MA-01: Registro Argon2id (salt + pepper), Login JWT y WebAuthn ---"
MEDICO_TOKEN="$(register_and_login "${MEDICO_USER}" "medico" "${STRONG_PASS}")"
[[ -n "${MEDICO_TOKEN}" ]] && ok "Registro y login Argon2id+JWT exitoso para médico (${MEDICO_USER})"

ANALISTA_TOKEN="$(register_and_login "${ANALISTA_USER}" "analista" "${STRONG_PASS}")"
[[ -n "${ANALISTA_TOKEN}" ]] && ok "Registro y login Argon2id+JWT exitoso para analista (${ANALISTA_USER})"

AUDITOR_TOKEN="$(register_and_login "${AUDITOR_USER}" "auditor_arco" "${STRONG_PASS}")"
[[ -n "${AUDITOR_TOKEN}" ]] && ok "Registro y login Argon2id+JWT exitoso para auditor_arco (${AUDITOR_USER})"

ADMIN_TOKEN="$(register_and_login "${ADMIN_USER}" "admin_sec" "${STRONG_PASS}")"
[[ -n "${ADMIN_TOKEN}" ]] && ok "Registro y login Argon2id+JWT exitoso para admin_sec (${ADMIN_USER})"

ME_ROLE="$(curl -s "${BASE_URL}/auth/me" -H "Authorization: Bearer ${MEDICO_TOKEN}" | jq -r '.role // empty')"
if [[ "${ME_ROLE}" == "medico" ]]; then
  ok "GET /auth/me validó JWT Bearer y devolvió role=medico"
else
  fail "GET /auth/me no devolvió role=medico (obtenido: ${ME_ROLE:-vacío})"
fi

WEBAUTHN_CHALLENGE="$(curl -s -X POST "${BASE_URL}/auth/webauthn/register/begin" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}" | jq -r '.options.challenge // empty')"
if [[ -n "${WEBAUTHN_CHALLENGE}" ]]; then
  ok "POST /auth/webauthn/register/begin generó reto FIDO2/WebAuthn"
else
  fail "POST /auth/webauthn/register/begin no devolvió challenge FIDO2"
fi

echo ""
echo "--- 2. MA-02: Bóveda HashiCorp Vault (Transit AEAD + KV v2 + pat_...) ---"
TOK_BODY="$(curl -s -X POST "${BASE_URL}/vault/patients/tokenize" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"full_name":"Juan Carlos Pérez Morales","curp":"PEMJ900115HPLRNS01","nss":"11223344556"}')"
OPAQUE_TOKEN="$(echo "${TOK_BODY}" | jq -r '.opaque_patient_token // empty')"
if [[ "${OPAQUE_TOKEN}" =~ ^pat_[0-9a-f]{32}$ ]]; then
  ok "POST /vault/patients/tokenize aisló PII en Vault y emitió ${OPAQUE_TOKEN}"
else
  fail "POST /vault/patients/tokenize falló: ${TOK_BODY}"
fi

DENY_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/vault/patients/${OPAQUE_TOKEN}" \
  -H "Authorization: Bearer ${ANALISTA_TOKEN}")"
if [[ "${DENY_CODE}" == "403" ]]; then
  ok "Zero Trust RBAC: analista recibió HTTP 403 al intentar detokenizar PII directa"
else
  fail "Zero Trust RBAC falló para analista (esperado 403, obtenido ${DENY_CODE})"
fi

DETOK_CURP="$(curl -s "${BASE_URL}/vault/patients/${OPAQUE_TOKEN}" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}" | jq -r '.curp // empty')"
if [[ "${DETOK_CURP}" == "PEMJ900115HPLRNS01" ]]; then
  ok "GET /vault/patients/${OPAQUE_TOKEN} (médico) descifró PII vía Vault Transit+KV v2"
else
  fail "Detokenización falló para médico (CURP obtenida: ${DETOK_CURP:-vacía})"
fi

VER_BEFORE="$(curl -s "${BASE_URL}/vault/status" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.latest_key_version // 0')"
VER_AFTER="$(curl -s -X POST "${BASE_URL}/vault/keys/rotate" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.latest_key_version // 0')"
if [[ "${VER_AFTER}" -gt "${VER_BEFORE}" ]]; then
  ok "POST /vault/keys/rotate rotó la llave Transit (${VER_BEFORE} -> ${VER_AFTER})"
else
  fail "Rotación de llave Transit falló (${VER_BEFORE} -> ${VER_AFTER})"
fi

DETOK_AFTER_ROT="$(curl -s "${BASE_URL}/vault/patients/${OPAQUE_TOKEN}" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}" | jq -r '.nss // empty')"
if [[ "${DETOK_AFTER_ROT}" == "11223344556" ]]; then
  ok "Token previo sigue descifrando correctamente tras rotación de llave Transit"
else
  fail "Fallo al descifrar token previo tras rotación de llave"
fi

PURGE_STATUS="$(curl -s -X DELETE "${BASE_URL}/vault/patients/${OPAQUE_TOKEN}" \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" | jq -r '.status // empty')"
AFTER_PURGE_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/vault/patients/${OPAQUE_TOKEN}" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}")"
if [[ "${PURGE_STATUS}" == "purged" && "${AFTER_PURGE_CODE}" == "404" ]]; then
  ok "DELETE /vault/patients/${OPAQUE_TOKEN} (auditor_arco) purgó metadatos KV v2 (GET -> 404)"
else
  fail "Purga de bóveda falló (status=${PURGE_STATUS:-vacío}, GET=${AFTER_PURGE_CODE})"
fi

echo ""
echo "--- 3. MA-01: Revocación inmediata de sesión JWT (Logout) ---"
LOGOUT_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/logout" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}")"
REVOKED_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/auth/me" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}")"
if [[ "${LOGOUT_CODE}" == "200" && "${REVOKED_CODE}" == "401" ]]; then
  ok "POST /auth/logout revocó el JWT (GET /auth/me posterior -> HTTP 401)"
else
  fail "Revocación JWT falló (logout=${LOGOUT_CODE}, me=${REVOKED_CODE})"
fi

echo ""
echo "========================================================================"
echo " Resumen E2E MA-01 + MA-02: PASS=${PASS} | FAIL=${FAIL}"
echo "========================================================================"
[[ "${FAIL}" -eq 0 ]]
