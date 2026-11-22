#!/usr/bin/env bash
# ==============================================================================
# Suite de verificación de túnel Cloudflare y endurecimiento de dominio
# Uso: ./infra/scripts/verify-domain-security.sh [dominio]
# Ejemplo: ./infra/scripts/verify-domain-security.sh tralaleritosmigajeros.uk
# ==============================================================================
set -uo pipefail

DOMAIN="${1:-tralaleritosmigajeros.uk}"
PASS=0
WARN=0
FAIL=0

ok()   { echo "[PASS] $1"; PASS=$((PASS + 1)); }
warn() { echo "[WARN] $1"; WARN=$((WARN + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

echo "========================================================================"
echo " Verificación de Seguridad y Conectividad: https://${DOMAIN}"
echo "========================================================================"

echo ""
echo "--- 1. Redirección HTTP -> HTTPS ---"
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${DOMAIN}/health" || echo "000")"
HTTP_LOC="$(curl -s -I --max-time 10 "http://${DOMAIN}/health" | grep -i '^location:' | tr -d '\r' || true)"
if [[ "${HTTP_CODE}" == "301" || "${HTTP_CODE}" == "308" ]] && echo "${HTTP_LOC}" | grep -qi "https://"; then
  ok "HTTP redirige a HTTPS (${HTTP_CODE} -> ${HTTP_LOC})"
else
  fail "HTTP no redirige limpiamente a HTTPS (código=${HTTP_CODE}, ${HTTP_LOC:-sin Location}). Activa 'Always Use HTTPS' en Cloudflare."
fi

echo ""
echo "--- 2. Conectividad HTTPS, Cloudflare Proxy y Salud de API ---"
HEADERS_FILE="$(mktemp)"
BODY_FILE="$(mktemp)"
trap 'rm -f "${HEADERS_FILE}" "${BODY_FILE}"' EXIT

HTTPS_CODE="$(curl -sS -D "${HEADERS_FILE}" -o "${BODY_FILE}" -w '%{http_code}' --max-time 15 "https://${DOMAIN}/health" || echo "000")"
if [[ "${HTTPS_CODE}" == "200" ]]; then
  ok "GET https://${DOMAIN}/health respondió HTTP 200: $(cat "${BODY_FILE}")"
else
  fail "GET https://${DOMAIN}/health falló (HTTP ${HTTPS_CODE}). Revisa 'docker compose ps' y logs de cloudflared."
fi

if grep -qi '^cf-ray:' "${HEADERS_FILE}"; then
  ok "Tráfico pasando por borde de Cloudflare ($(grep -i '^cf-ray:' "${HEADERS_FILE}" | tr -d '\r'))"
else
  fail "No se detectó cabecera CF-Ray (el tráfico no parece estar proxied por Cloudflare)."
fi

EDGE_JSON="$(curl -s --max-time 10 "https://${DOMAIN}/edge-check" || true)"
if echo "${EDGE_JSON}" | grep -q '"via_cloudflare":true'; then
  ok "Endpoint /edge-check confirma Cloudflare Tunnel: ${EDGE_JSON}"
else
  warn "No se pudo confirmar /edge-check (${EDGE_JSON:-vacío}). Asegúrate de desplegar la última versión de la API."
fi

echo ""
echo "--- 3. Cabeceras de Seguridad HTTP (Zero Trust / Privacy-by-Design) ---"
check_header() {
  local name="$1"
  local expected="$2"
  local line
  line="$(grep -i "^${name}:" "${HEADERS_FILE}" | tr -d '\r' || true)"
  if [[ -n "${line}" ]] && echo "${line}" | grep -qi "${expected}"; then
    ok "${line}"
  else
    fail "Cabecera '${name}' ausente o sin '${expected}' (actual: ${line:-ninguna})"
  fi
}

check_header "strict-transport-security" "max-age="
check_header "x-content-type-options" "nosniff"
check_header "x-frame-options" "DENY"
check_header "referrer-policy" "no-referrer"
check_header "content-security-policy" "frame-ancestors"
check_header "cache-control" "no-store"

echo ""
echo "--- 4. Verificación TLS (>= 1.2) ---"
TLS_OUT="$(curl -sI --tlsv1.2 --max-time 10 "https://${DOMAIN}/health" -w '%{ssl_verify_result}' -o /dev/null || echo "err")"
if [[ "${TLS_OUT}" == "0" ]]; then
  ok "Certificado TLS válido (ssl_verify_result=0, TLS >= 1.2)"
else
  fail "Validación TLS falló (ssl_verify_result=${TLS_OUT}). Verifica SSL/TLS 'Full (strict)' en Cloudflare."
fi

echo ""
echo "--- 5. Sondas WAF (Bloqueo de rutas sensibles y payloads maliciosos) ---"
ENV_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://${DOMAIN}/.env" || echo "000")"
if [[ "${ENV_CODE}" == "403" ]]; then
  ok "WAF bloqueó acceso a /.env (HTTP 403)"
else
  warn "Acceso a /.env devolvió HTTP ${ENV_CODE} (esperado 403 desde WAF Custom Rule en Cloudflare)."
fi

SQLI_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://${DOMAIN}/?id=1%27%20OR%20%271%27=%271" || echo "000")"
if [[ "${SQLI_CODE}" == "403" ]]; then
  ok "WAF bloqueó sonda SQLi básica (HTTP 403)"
else
  warn "Sonda SQLi devolvió HTTP ${SQLI_CODE} (esperado 403 tras configurar WAF Custom Rule en Cloudflare)."
fi

echo ""
echo "--- 6. Revisión de exposición del panel SIEM (siem.${DOMAIN}) ---"
SIEM_HEADERS="$(curl -s -D - -o /dev/null --max-time 10 "https://siem.${DOMAIN}/health" || true)"
SIEM_CODE="$(echo "${SIEM_HEADERS}" | awk 'NR==1{print $2}')"
SIEM_LOC="$(echo "${SIEM_HEADERS}" | grep -i '^location:' | tr -d '\r' || true)"
if [[ "${SIEM_CODE}" == "302" ]] && echo "${SIEM_LOC}" | grep -qi "cloudflareaccess.com"; then
  ok "siem.${DOMAIN} protegido con Cloudflare Zero Trust Access (302 -> ${SIEM_LOC})"
elif [[ "${SIEM_CODE}" == "403" || "${SIEM_CODE}" == "401" ]]; then
  ok "siem.${DOMAIN} bloquea acceso anónimo (HTTP ${SIEM_CODE})"
elif [[ "${SIEM_CODE}" == "200" ]]; then
  warn "siem.${DOMAIN}/health responde HTTP 200 públicamente. Configura Cloudflare Zero Trust Access (Email OTP) para restringirlo al equipo."
else
  warn "siem.${DOMAIN} devolvió HTTP ${SIEM_CODE:-000} (verifica DNS/túnel si ya lo activaste)."
fi

echo ""
echo "========================================================================"
echo " RESUMEN: PASS=${PASS} | WARN=${WARN} | FAIL=${FAIL}"
echo "========================================================================"

if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi
