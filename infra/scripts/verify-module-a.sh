#!/usr/bin/env bash
# ==============================================================================
# Suite de verificación E2E para Módulo A Completo (MA-02 Segregación Clínica,
# MA-03 Prevención de Function Creep con OPA/ABAC y MA-04 Minimización por Rol)
# Uso: ./infra/scripts/verify-module-a.sh [BASE_URL]
# Ejemplo local:      ./infra/scripts/verify-module-a.sh http://127.0.0.1:8000
# Ejemplo producción: ./infra/scripts/verify-module-a.sh https://tralaleritosmigajeros.uk
# ==============================================================================
set -uo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
BASE_URL="${BASE_URL%/}"
SUFFIX="$(date +%s)_$RANDOM"
PASS=0
FAIL=0

ok()   { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: se requiere '$cmd' instalado." >&2
    exit 2
  fi
done

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

  curl -s -X POST "${BASE_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${username}\",\"password\":\"${password}\"}" | jq -r '.access_token // empty'
}

echo "========================================================================"
echo " Verificación E2E Módulo A: MA-02 Segregación + MA-03 OPA + MA-04 Minimización"
echo " Objetivo: ${BASE_URL}"
echo "========================================================================"

STRONG_PASS="Hospital!2026#ZeroTrust"
MEDICO_TOKEN="$(register_and_login "dr_ma_${SUFFIX}" "medico" "${STRONG_PASS}")"
ENFERMERA_TOKEN="$(register_and_login "enf_ma_${SUFFIX}" "enfermeria" "${STRONG_PASS}")"
ANALISTA_TOKEN="$(register_and_login "ana_ma_${SUFFIX}" "analista" "${STRONG_PASS}")"
AUDITOR_TOKEN="$(register_and_login "aud_ma_${SUFFIX}" "auditor_arco" "${STRONG_PASS}")"
ADMIN_TOKEN="$(register_and_login "adm_ma_${SUFFIX}" "admin_sec" "${STRONG_PASS}")"

echo ""
echo "--- 1. Estado del motor OPA (MA-03) ---"
OPA_STATUS_BODY="$(curl -s "${BASE_URL}/clinical/policy/status" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}")"
OPA_LOADED="$(echo "${OPA_STATUS_BODY}" | jq -r '.policy_loaded // false')"
OPA_VERSION="$(echo "${OPA_STATUS_BODY}" | jq -r '.policy_version // empty')"
if [[ "${OPA_LOADED}" == "true" && "${OPA_VERSION}" == "1.1.0" ]]; then
  ok "GET /clinical/policy/status confirmó OPA operativo y política hospital.authz v${OPA_VERSION} cargada"
else
  fail "OPA no disponible o política desactualizada (loaded=${OPA_LOADED}, version=${OPA_VERSION:-ninguna}). Ejecuta: docker compose up -d --force-recreate opa"
fi

echo ""
echo "--- 2. MA-02: Alta segregada (Vault PII + PostgreSQL Clínico) ---"
CREATE_BODY="$(curl -s -X POST "${BASE_URL}/clinical/records/segregated" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}" \
  -H "X-Purpose: atencion_medica" \
  -H "Content-Type: application/json" \
  -d '{"patient_pii":{"full_name":"Elena Ramos Ortiz","curp":"RAOE890412MPLRNT07","nss":"33445566778"},"clinical_data":{"age_years":37,"zip_prefix":"72000","gender":"F","diagnosis_cie10":"E11.9","diagnosis_summary":"Control ambulatorio diabetes tipo 2","department":"endocrinologia","ttl_hours":720}}')"
OPAQUE_TOKEN="$(echo "${CREATE_BODY}" | jq -r '.opaque_patient_token // empty')"
RECORD_ID="$(echo "${CREATE_BODY}" | jq -r '.record.record_id // empty')"
if [[ "${OPAQUE_TOKEN}" =~ ^pat_[0-9a-f]{32}$ && -n "${RECORD_ID}" ]]; then
  ok "POST /clinical/records/segregated aisló PII en Vault (${OPAQUE_TOKEN}) y creó expediente ${RECORD_ID}"
else
  fail "Alta segregada falló: ${CREATE_BODY}"
fi

echo ""
echo "--- 3. MA-03: Prevención de Function Creep (403 Forbidden) ---"
NO_PURPOSE_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/clinical/records" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}")"
[[ "${NO_PURPOSE_CODE}" == "403" ]] \
  && ok "Consulta sin cabecera X-Purpose bloqueada con HTTP 403" \
  || fail "Se esperaba 403 sin X-Purpose, obtenido ${NO_PURPOSE_CODE}"

MKT_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/clinical/records" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}" \
  -H "X-Purpose: marketing")"
[[ "${MKT_CODE}" == "403" ]] \
  && ok "Médico con X-Purpose: marketing bloqueado con HTTP 403 (Function Creep)" \
  || fail "Se esperaba 403 para marketing, obtenido ${MKT_CODE}"

SINGLE_ANALYST_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/clinical/records/${RECORD_ID}" \
  -H "Authorization: Bearer ${ANALISTA_TOKEN}" \
  -H "X-Purpose: investigacion_estadistica")"
[[ "${SINGLE_ANALYST_CODE}" == "403" ]] \
  && ok "Analista bloqueado al consultar expediente individual (HTTP 403, anti-singularización)" \
  || fail "Se esperaba 403 en lookup individual de analista, obtenido ${SINGLE_ANALYST_CODE}"

ADMIN_CLINICAL_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/clinical/records" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "X-Purpose: atencion_medica")"
[[ "${ADMIN_CLINICAL_CODE}" == "403" ]] \
  && ok "Separación de funciones: admin_sec recibió HTTP 403 en /clinical/records" \
  || fail "Se esperaba 403 para admin_sec, obtenido ${ADMIN_CLINICAL_CODE}"

echo ""
echo "--- 4. MA-04: Minimización cuantitativa y cualitativa por rol ---"
NURSE_REC="$(curl -s "${BASE_URL}/clinical/records/${RECORD_ID}" \
  -H "Authorization: Bearer ${ENFERMERA_TOKEN}" \
  -H "X-Purpose: atencion_medica")"
NURSE_TOKEN_MASK="$(echo "${NURSE_REC}" | jq -r '.record.opaque_patient_token // empty')"
NURSE_HAS_CIE10="$(echo "${NURSE_REC}" | jq -r '(.record != null) and (.record | has("diagnosis_cie10"))')"
if [[ "${NURSE_TOKEN_MASK}" == *"..."* && "${NURSE_HAS_CIE10}" == "false" ]]; then
  ok "Enfermería recibió token enmascarado (${NURSE_TOKEN_MASK}) y sin columna diagnosis_cie10"
else
  fail "Minimización para enfermería incorrecta: ${NURSE_REC}"
fi

ANALYST_REC="$(curl -s "${BASE_URL}/clinical/records?department=endocrinologia" \
  -H "Authorization: Bearer ${ANALISTA_TOKEN}" \
  -H "X-Purpose: investigacion_estadistica")"
ANALYST_AGE="$(echo "${ANALYST_REC}" | jq -r '.records[0].age_range // empty')"
ANALYST_ZIP="$(echo "${ANALYST_REC}" | jq -r '.records[0].zip_generalized // empty')"
ANALYST_HAS_TOKEN="$(echo "${ANALYST_REC}" | jq -r '(.records[0] != null) and (.records[0] | has("opaque_patient_token"))')"
if [[ "${ANALYST_AGE}" == "30-39" && "${ANALYST_ZIP}" == "72***" && "${ANALYST_HAS_TOKEN}" == "false" ]]; then
  ok "Analista recibió datos generalizados (age_range=${ANALYST_AGE}, zip=${ANALYST_ZIP}) sin tokens ni IDs"
else
  fail "Generalización para analista incorrecta: ${ANALYST_REC}"
fi

AUDITOR_REC="$(curl -s "${BASE_URL}/clinical/records/${RECORD_ID}" \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" \
  -H "X-Purpose: ejercicio_arco")"
AUDITOR_HAS_RECORD="$(echo "${AUDITOR_REC}" | jq -r '(.record != null) and (.record | has("is_sanitized"))')"
AUDITOR_HAS_DIAG="$(echo "${AUDITOR_REC}" | jq -r '(.record != null) and (.record | has("diagnosis_summary"))')"
if [[ "${AUDITOR_HAS_RECORD}" == "true" && "${AUDITOR_HAS_DIAG}" == "false" ]]; then
  ok "Auditor ARCO recibió únicamente metadatos de ciclo de vida (sin diagnósticos)"
else
  fail "Auditor ARCO recibió respuesta inesperada o información clínica no permitida: ${AUDITOR_REC}"
fi

echo ""
echo "========================================================================"
echo " Resumen E2E Módulo A: PASS=${PASS} | FAIL=${FAIL}"
echo "========================================================================"
[[ "${FAIL}" -eq 0 ]]
