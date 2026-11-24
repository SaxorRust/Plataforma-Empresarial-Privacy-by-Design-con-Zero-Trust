#!/usr/bin/env bash
# ==============================================================================
# Suite de verificación E2E para Módulo C — Auditoría SIEM y SOC:
#   MC-02 Centralización Syslog (RFC 5424) API -> Colector SIEM
#   MC-03 Sanitización Regex en ingesta (tarjetas, CURP, contraseñas, NSS, JWT)
#   MC-04 Reglas de correlación temporal (Fuerza bruta + Consultas masivas CRÍTICA)
# Uso: ./infra/scripts/verify-siem-module-c.sh [API_BASE_URL] [SIEM_BASE_URL]
# ==============================================================================
set -uo pipefail

API_URL="${1:-http://127.0.0.1:8000}"
SIEM_URL="${2:-http://127.0.0.1:8080}"
API_URL="${API_URL%/}"
SIEM_URL="${SIEM_URL%/}"
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

echo "========================================================================"
echo " Verificación E2E Módulo C: MC-02 Syslog RFC 5424 + MC-03 Regex + MC-04 Correlación"
echo " API : ${API_URL}"
echo " SIEM: ${SIEM_URL}"
echo "========================================================================"

echo ""
echo "--- 1. MC-02: Salud del colector SIEM y listeners Syslog UDP/TCP ---"
SIEM_HEALTH="$(curl -s "${SIEM_URL}/health")"
SIEM_STATUS="$(echo "${SIEM_HEALTH}" | jq -r '.status // empty')"
UDP_ACTIVE="$(echo "${SIEM_HEALTH}" | jq -r '.syslog_udp_active // false')"
TCP_ACTIVE="$(echo "${SIEM_HEALTH}" | jq -r '.syslog_tcp_active // false')"

if [[ "${SIEM_STATUS}" == "ok" && "${UDP_ACTIVE}" == "true" && "${TCP_ACTIVE}" == "true" ]]; then
  ok "GET /health confirmó colector SIEM operativo (UDP=true, TCP=true)"
else
  fail "Colector SIEM no operativo o listeners inactivos: ${SIEM_HEALTH}"
fi

RULES_COUNT="$(curl -s "${SIEM_URL}/api/v1/rules" | jq 'length')"
if [[ "${RULES_COUNT}" -ge 2 ]]; then
  ok "GET /api/v1/rules expone ${RULES_COUNT} reglas activas de correlación temporal"
else
  fail "Se esperaban >= 2 reglas de correlación (encontradas=${RULES_COUNT})"
fi

echo ""
echo "--- 2. MC-03: Sanitización Regex en ingesta (Tarjeta, CURP, Contraseña, NSS) ---"
NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RAW_SENSITIVE="<86>1 ${NOW_ISO} verify-host test-probe 9999 AUDIT_SANITIZE_TEST [audit@32473 actor=\"probe_${SUFFIX}\" source_ip=\"198.51.100.10\" password=\"ClaveSecreta99!\"] Pago card=4111-1111-1111-1111 curp=PERJ920514HPLRNS08 nss=45901234567 password=ClaveSecreta99!"

INGEST_PAYLOAD="$(jq -n --arg msg "${RAW_SENSITIVE}" '{raw_message: $msg}')"
INGEST_RESP="$(curl -s -X POST "${SIEM_URL}/api/v1/ingest/syslog" \
  -H "Content-Type: application/json" \
  -d "${INGEST_PAYLOAD}")"

IS_SANITIZED="$(echo "${INGEST_RESP}" | jq -r '.event.sanitized // false')"
STORED_MSG="$(echo "${INGEST_RESP}" | jq -r '.event.message // empty')"
if [[ "${IS_SANITIZED}" == "true" ]] \
  && echo "${STORED_MSG}" | grep -q '\*\*\*' \
  && ! echo "${INGEST_RESP}" | grep -q "4111-1111-1111-1111" \
  && ! echo "${INGEST_RESP}" | grep -q "PERJ920514HPLRNS08" \
  && ! echo "${INGEST_RESP}" | grep -q "ClaveSecreta99!" \
  && ! echo "${INGEST_RESP}" | grep -q "45901234567"; then
  ok "MC-03: Tarjeta, CURP, contraseña y NSS fueron ofuscados con *** antes de persistir"
else
  fail "MC-03 falló sanitización en ingesta: ${INGEST_RESP}"
fi

echo ""
echo "--- 3. MC-04 (Regla 1): Simulación de ataque de fuerza bruta vía API -> SIEM ---"
BF_USER="bf_target_${SUFFIX}"
BF_IP="203.0.113.$(( (RANDOM % 200) + 10 ))"
for _ in 1 2 3 4 5; do
  curl -s -o /dev/null -X POST "${API_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -H "CF-Connecting-IP: ${BF_IP}" \
    -d "{\"username\":\"${BF_USER}\",\"password\":\"Incorrecta!2026\"}"
done
sleep 1

BF_ALERT_COUNT="$(curl -s "${SIEM_URL}/api/v1/alerts?rule_id=RULE-001" \
  | jq --arg ip "${BF_IP}" '[.[] | select(.source_ip == $ip)] | length')"
if [[ "${BF_ALERT_COUNT}" -ge 1 ]]; then
  ok "MC-04 (RULE-001): Alerta de fuerza bruta disparada automáticamente para IP=${BF_IP}"
else
  fail "MC-04 (RULE-001): No se disparó alerta de fuerza bruta para IP=${BF_IP}"
fi

echo ""
echo "--- 4. MC-04 (Regla 2): Simulación de consultas masivas de expedientes -> ALERTA CRÍTICA ---"
MASS_USER="dr_mass_${SUFFIX}"
STRONG_PASS="Hospital!2026#ZeroTrust"
PROVISION_USER="${PROVISION_USER:-admin_sec}"
PROVISION_PASS="${PROVISION_PASS:-AdminSec#2026!ZT}"
PROVISION_TOKEN="$(curl -s -X POST "${API_URL}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${PROVISION_USER}\",\"password\":\"${PROVISION_PASS}\"}" | jq -r '.access_token // empty')"
curl -s -o /dev/null -X POST "${API_URL}/auth/users" \
  -H "Authorization: Bearer ${PROVISION_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${MASS_USER}\",\"password\":\"${STRONG_PASS}\",\"role\":\"medico\"}"

MASS_TOKEN="$(curl -s -X POST "${API_URL}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${MASS_USER}\",\"password\":\"${STRONG_PASS}\"}" | jq -r '.access_token // empty')"

if [[ -z "${MASS_TOKEN}" ]]; then
  fail "No se pudo autenticar usuario de prueba ${MASS_USER} en la API"
else
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -s -o /dev/null "${API_URL}/clinical/records" \
      -H "Authorization: Bearer ${MASS_TOKEN}" \
      -H "X-Purpose: atencion_medica"
  done
  sleep 1

  MASS_ALERT_COUNT="$(curl -s "${SIEM_URL}/api/v1/alerts?rule_id=RULE-002&severity=CRITICAL" \
    | jq --arg actor "${MASS_USER}" '[.[] | select(.actor == $actor)] | length')"
  if [[ "${MASS_ALERT_COUNT}" -ge 1 ]]; then
    ok "MC-04 (RULE-002): Alerta CRÍTICA por consultas masivas disparada para actor=${MASS_USER}"
  else
    fail "MC-04 (RULE-002): No se disparó alerta CRÍTICA para actor=${MASS_USER}"
  fi
fi

echo ""
echo "--- 5. Verificación de consola SOC HTML y trazabilidad de eventos RFC 5424 ---"
DASH_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${SIEM_URL}/")"
RFC_VALID_EVENTS="$(curl -s "${SIEM_URL}/api/v1/stats" | jq -r '.rfc5424_valid_events // 0')"
if [[ "${DASH_CODE}" == "200" && "${RFC_VALID_EVENTS}" -ge 15 ]]; then
  ok "Dashboard SOC operativo (HTTP 200) y ${RFC_VALID_EVENTS} eventos RFC 5424 indexados"
else
  fail "Verificación final falló (dash=${DASH_CODE}, rfc_valid=${RFC_VALID_EVENTS})"
fi

echo ""
echo "========================================================================"
echo " Resumen E2E Módulo C (SIEM/SOC): PASS=${PASS} | FAIL=${FAIL}"
echo "========================================================================"
[[ "${FAIL}" -eq 0 ]]
