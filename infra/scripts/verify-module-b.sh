#!/usr/bin/env bash
# ==============================================================================
# Suite de verificación E2E para Módulo B Completo:
#   MB-01 Retención Temporal (TTL)
#   MB-02 Exportación Desidentificada (Safe Harbor + k-anonimato + l-diversidad)
#   MB-03 Derechos ARCO + Sanitización NIST SP 800-88 (Clear/Purge)
#   MB-04 Certificados de Sanitización JSON y PDF firmados con SHA-256
# Uso: ./infra/scripts/verify-module-b.sh [BASE_URL]
# ==============================================================================
set -uo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
BASE_URL="${BASE_URL%/}"
SUFFIX="$(date +%s)_$RANDOM"
PASS=0
FAIL=0

ok()   { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

for cmd in curl jq sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: se requiere '$cmd' instalado." >&2
    exit 2
  fi
done

PROVISION_USER="${PROVISION_USER:-super_admin}"
PROVISION_PASS="${PROVISION_PASS:-SuperAdmin#2026!ZT}"
PROVISION_TOKEN="$(curl -s -X POST "${BASE_URL}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${PROVISION_USER}\",\"password\":\"${PROVISION_PASS}\"}" | jq -r '.access_token // empty')"
if [[ -z "${PROVISION_TOKEN}" ]]; then
  fail "No se pudo autenticar ${PROVISION_USER} para aprovisionar cuentas de prueba"
  exit 1
fi

register_and_login() {
  local username="$1"
  local role="$2"
  local password="$3"

  local reg_code
  reg_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/users" \
    -H "Authorization: Bearer ${PROVISION_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${username}\",\"password\":\"${password}\",\"role\":\"${role}\"}")"
  if [[ "${reg_code}" != "201" ]]; then
    fail "Aprovisionamiento de ${username} (${role}) devolvió HTTP ${reg_code}"
    return 1
  fi

  curl -s -X POST "${BASE_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${username}\",\"password\":\"${password}\"}" | jq -r '.access_token // empty'
}

echo "========================================================================"
echo " Verificación E2E Módulo B: MB-01 TTL + MB-02 Safe Harbor/(k,l) + MB-03/04 NIST 800-88"
echo " Objetivo: ${BASE_URL}"
echo "========================================================================"

STRONG_PASS="Hospital!2026#ZeroTrust"
MEDICO_TOKEN="$(register_and_login "dr_mb_${SUFFIX}" "medico" "${STRONG_PASS}")"
ANALISTA_TOKEN="$(register_and_login "ana_mb_${SUFFIX}" "analista" "${STRONG_PASS}")"
AUDITOR_TOKEN="$(register_and_login "aud_mb_${SUFFIX}" "auditor_arco" "${STRONG_PASS}")"

echo ""
echo "--- 1. MB-01: Estado de scheduler TTL y purga de registro vencido ---"
TTL_RUNNING="$(curl -s "${BASE_URL}/lifecycle/ttl/status" \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" | jq -r '.scheduler_running // false')"
if [[ "${TTL_RUNNING}" == "true" ]]; then
  ok "GET /lifecycle/ttl/status confirmó scheduler TTL activo en segundo plano"
else
  fail "Scheduler TTL no está activo (scheduler_running=${TTL_RUNNING})"
fi

EXPIRED_BODY="$(curl -s -X POST "${BASE_URL}/clinical/records/segregated" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}" \
  -H "X-Purpose: atencion_medica" \
  -H "Content-Type: application/json" \
  -d '{"patient_pii":{"full_name":"Paciente Temporal Vencido","curp":"PTVE900101HPLRNS01","nss":"61000000001"},"clinical_data":{"age_years":33,"zip_prefix":"72000","gender":"M","diagnosis_cie10":"J06.9","diagnosis_summary":"Registro temporal con TTL vencido","department":"urgencias","ttl_expires_at":"2020-01-01T00:00:00Z"}}')"
EXPIRED_TOKEN="$(echo "${EXPIRED_BODY}" | jq -r '.opaque_patient_token // empty')"

SWEEP_BODY="$(curl -s -X POST "${BASE_URL}/lifecycle/ttl/sweep" \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" \
  -H "X-Purpose: ejercicio_arco")"
PURGED_COUNT="$(echo "${SWEEP_BODY}" | jq -r '.purged_records_count // 0')"
VAULT_AFTER_TTL="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/vault/patients/${EXPIRED_TOKEN}" \
  -H "Authorization: Bearer ${MEDICO_TOKEN}")"
if [[ "${PURGED_COUNT}" -ge 1 && "${VAULT_AFTER_TTL}" == "404" ]]; then
  ok "POST /lifecycle/ttl/sweep purgó registro vencido y su token huérfano en Vault (GET -> 404)"
else
  fail "Barrido TTL incompleto (purged=${PURGED_COUNT}, vault_get=${VAULT_AFTER_TTL})"
fi

echo ""
echo "--- 2. MB-02: Exportación Safe Harbor + k-anonimato (k=3) + l-diversidad (l=2) ---"
admit_case() {
  local name="$1" curp="$2" nss="$3" age="$4" zip="$5" gender="$6" cie="$7"
  curl -s -X POST "${BASE_URL}/clinical/records/segregated" \
    -H "Authorization: Bearer ${MEDICO_TOKEN}" \
    -H "X-Purpose: atencion_medica" \
    -H "Content-Type: application/json" \
    -d "{\"patient_pii\":{\"full_name\":\"${name}\",\"curp\":\"${curp}\",\"nss\":\"${nss}\"},\"clinical_data\":{\"age_years\":${age},\"zip_prefix\":\"${zip}\",\"gender\":\"${gender}\",\"diagnosis_cie10\":\"${cie}\",\"diagnosis_summary\":\"Seguimiento estadistico ${cie}\",\"department\":\"epidemiologia\"}}" \
    | jq -r '.opaque_patient_token // empty'
}

ARCO_TARGET_TOKEN="$(admit_case "Ana Lucia Diaz" "DIAA940101MPLRNS01" "71000000001" 32 "72000" "F" "E11.9")"
admit_case "Beatriz Solis" "SOBA920202MPLRNS02" "71000000002" 35 "72010" "F" "I10" >/dev/null
admit_case "Carla Vega" "VECA890303MPLRNS03" "71000000003" 37 "72020" "F" "J45.9" >/dev/null
admit_case "Dolores Cruz" "CRDA320404MPLRNS04" "71000000004" 94 "06600" "F" "I10" >/dev/null
admit_case "Esther Mora" "MOEA300505MPLRNS05" "71000000005" 96 "06610" "F" "E11.9" >/dev/null
admit_case "Fabiola Nunez" "NUFA280606MPLRNS06" "71000000006" 98 "06620" "F" "K21.9" >/dev/null

EXPORT_BODY="$(curl -s -X POST "${BASE_URL}/lifecycle/exports/anonymized" \
  -H "Authorization: Bearer ${ANALISTA_TOKEN}" \
  -H "X-Purpose: investigacion_estadistica" \
  -H "Content-Type: application/json" \
  -d '{"k":3,"l":2,"department":"epidemiologia"}')"
ACHIEVED_K="$(echo "${EXPORT_BODY}" | jq -r '.metrics.achieved_k // 0')"
ACHIEVED_L="$(echo "${EXPORT_BODY}" | jq -r '.metrics.achieved_l // 0')"
SAFE_HARBOR="$(echo "${EXPORT_BODY}" | jq -r '.metrics.safe_harbor_verified // false')"
HAS_90_PLUS="$(echo "${EXPORT_BODY}" | jq -r '[.records[].age_range] | any(. == "90+")')"
if [[ "${ACHIEVED_K}" -ge 3 && "${ACHIEVED_L}" -ge 2 && "${SAFE_HARBOR}" == "true" && "${HAS_90_PLUS}" == "true" ]] && ! echo "${EXPORT_BODY}" | grep -q "pat_"; then
  ok "POST /lifecycle/exports/anonymized verificó Safe Harbor (18 IDs, 90+) + k=${ACHIEVED_K}, l=${ACHIEVED_L}"
else
  fail "Exportación desidentificada falló: ${EXPORT_BODY}"
fi

CSV_STATUS="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/lifecycle/exports/anonymized.csv?k=3&l=2&department=epidemiologia" \
  -H "Authorization: Bearer ${ANALISTA_TOKEN}" \
  -H "X-Purpose: investigacion_estadistica")"
[[ "${CSV_STATUS}" == "200" ]] \
  && ok "GET /lifecycle/exports/anonymized.csv generó exportación estadística CSV (HTTP 200)" \
  || fail "Exportación CSV devolvió HTTP ${CSV_STATUS}"

echo ""
echo "--- 3. MB-03 & MB-04: Derechos ARCO + NIST SP 800-88 PURGE + Certificados JSON/PDF SHA-256 ---"
ERASE_BODY="$(curl -s -X POST "${BASE_URL}/lifecycle/arco/erasure" \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" \
  -H "X-Purpose: ejercicio_arco" \
  -H "Content-Type: application/json" \
  -d "{\"opaque_patient_token\":\"${ARCO_TARGET_TOKEN}\",\"method\":\"NIST_800_88_PURGE\",\"arco_request_folio\":\"ARCO-${SUFFIX}\",\"purge_vault\":true}")"
CERT_ID="$(echo "${ERASE_BODY}" | jq -r '.certificate_id // empty')"
CERT_HASH="$(echo "${ERASE_BODY}" | jq -r '.sha256_hash // empty')"
VAULT_VERIF="$(echo "${ERASE_BODY}" | jq -r '.vault_verification // empty')"
if [[ -n "${CERT_ID}" && "${#CERT_HASH}" -eq 64 && "${VAULT_VERIF}" == "CONFIRMED_NOT_FOUND" ]]; then
  ok "POST /lifecycle/arco/erasure ejecutó NIST SP 800-88 PURGE (cert=${CERT_ID}, sha256=${CERT_HASH:0:12}...)"
else
  fail "Borrado ARCO/NIST falló: ${ERASE_BODY}"
fi

VERIFY_VALID="$(curl -s "${BASE_URL}/lifecycle/certificates/${CERT_ID}/verify" \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" \
  -H "X-Purpose: ejercicio_arco" | jq -r '.valid // false')"
[[ "${VERIFY_VALID}" == "true" ]] \
  && ok "GET /lifecycle/certificates/${CERT_ID}/verify confirmó integridad SHA-256 válida" \
  || fail "Verificación SHA-256 falló (valid=${VERIFY_VALID})"

JSON_HASH_HDR="$(curl -s -D - -o /dev/null "${BASE_URL}/lifecycle/certificates/${CERT_ID}.json" \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" \
  -H "X-Purpose: ejercicio_arco" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-certificate-sha256"{print $2}')"
[[ "${JSON_HASH_HDR}" == "${CERT_HASH}" ]] \
  && ok "GET /lifecycle/certificates/${CERT_ID}.json descargado con sello SHA-256 íntegro" \
  || fail "Descarga JSON de certificado falló (hdr=${JSON_HASH_HDR})"

PDF_TMP="/tmp/cert_${SUFFIX}.pdf"
PDF_CODE="$(curl -s -w '%{http_code}' -o "${PDF_TMP}" "${BASE_URL}/lifecycle/certificates/${CERT_ID}.pdf" \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" \
  -H "X-Purpose: ejercicio_arco")"
if [[ "${PDF_CODE}" == "200" ]] && head -c 5 "${PDF_TMP}" | grep -q "%PDF-"; then
  ok "GET /lifecycle/certificates/${CERT_ID}.pdf generó documento PDF válido ($(wc -c < "${PDF_TMP}") bytes)"
else
  fail "Descarga PDF de certificado falló (HTTP ${PDF_CODE})"
fi
rm -f "${PDF_TMP}"

echo ""
echo "========================================================================"
echo " Resumen E2E Módulo B: PASS=${PASS} | FAIL=${FAIL}"
echo "========================================================================"
[[ "${FAIL}" -eq 0 ]]
