#!/usr/bin/env bash
# ==============================================================================
# Asistente de configuración para Cloudflare Tunnel (`cloudflared`)
# Dominio: tralaleritosmigajeros.uk
# Uso: chmod +x infra/scripts/setup-cloudflared.sh && ./infra/scripts/setup-cloudflared.sh
# ==============================================================================
set -euo pipefail

TUNNEL_NAME="${TUNNEL_NAME:-privacy-zt-tunnel}"
DOMAIN="${DOMAIN:-tralaleritosmigajeros.uk}"
CF_DIR="${HOME}/.cloudflared"
CONFIG_FILE="${CF_DIR}/config.yml"

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "[ERROR] cloudflared no está instalado. Ejecuta primero: ./infra/scripts/setup-ubuntu-vm.sh"
  exit 1
fi

mkdir -p "${CF_DIR}"
chmod 700 "${CF_DIR}"

echo "=== [1/5] Autenticación con Cloudflare (cert.pem) ==="
if [ ! -f "${CF_DIR}/cert.pem" ]; then
  echo "Se generará una URL de autorización. Ábrela en tu navegador y selecciona '${DOMAIN}'."
  cloudflared tunnel login
else
  echo "Certificado existente detectado en ${CF_DIR}/cert.pem (omitido)."
fi

echo "=== [2/5] Creación o reutilización del túnel '${TUNNEL_NAME}' ==="
TUNNEL_ID="$(cloudflared tunnel list -o json | jq -r ".[] | select(.name == \"${TUNNEL_NAME}\") | .id" | head -n 1 || true)"

if [ -z "${TUNNEL_ID}" ]; then
  cloudflared tunnel create "${TUNNEL_NAME}"
  TUNNEL_ID="$(cloudflared tunnel list -o json | jq -r ".[] | select(.name == \"${TUNNEL_NAME}\") | .id" | head -n 1)"
fi

if [ -z "${TUNNEL_ID}" ] || [ ! -f "${CF_DIR}/${TUNNEL_ID}.json" ]; then
  echo "[ERROR] No se pudo localizar el archivo de credenciales ${CF_DIR}/${TUNNEL_ID}.json"
  exit 1
fi

chmod 600 "${CF_DIR}/${TUNNEL_ID}.json"
echo "Túnel activo: ${TUNNEL_NAME} (UUID: ${TUNNEL_ID})"

echo "=== [3/5] Configurando registros DNS (CNAME proxied) en ${DOMAIN} ==="
cloudflared tunnel route dns --overwrite-dns "${TUNNEL_NAME}" "${DOMAIN}"
cloudflared tunnel route dns --overwrite-dns "${TUNNEL_NAME}" "app.${DOMAIN}"
cloudflared tunnel route dns --overwrite-dns "${TUNNEL_NAME}" "siem.${DOMAIN}"

echo "=== [4/5] Generando ${CONFIG_FILE} ==="
cat > "${CONFIG_FILE}" <<EOF
tunnel: ${TUNNEL_ID}
credentials-file: ${CF_DIR}/${TUNNEL_ID}.json
# http2 evita bloqueos de UDP/QUIC en redes universitarias o NAT restrictivos
protocol: http2

ingress:
  - hostname: ${DOMAIN}
    service: http://127.0.0.1:8000
    originRequest:
      connectTimeout: 10s
      noHappyEyeballs: true

  - hostname: app.${DOMAIN}
    service: http://127.0.0.1:8000
    originRequest:
      connectTimeout: 10s
      noHappyEyeballs: true

  # IMPORTANTE: Proteger siem.${DOMAIN} con Cloudflare Zero Trust Access (Email OTP)
  - hostname: siem.${DOMAIN}
    service: http://127.0.0.1:8080
    originRequest:
      connectTimeout: 10s
      noHappyEyeballs: true

  - service: http_status:404
EOF

chmod 600 "${CONFIG_FILE}"

echo "=== [5/5] Validando reglas de ingress ==="
cloudflared tunnel --config "${CONFIG_FILE}" ingress validate

echo ""
echo "========================================================================"
echo " Túnel configurado correctamente para ${DOMAIN}"
echo "------------------------------------------------------------------------"
echo " Opción A — Ejecutar en primer plano (ideal para pruebas y debug):"
echo "   cloudflared tunnel --config ${CONFIG_FILE} run ${TUNNEL_NAME}"
echo ""
echo " Opción B — Instalar como servicio permanente (systemd):"
echo "   sudo mkdir -p /etc/cloudflared"
echo "   sudo cp ${CF_DIR}/${TUNNEL_ID}.json /etc/cloudflared/${TUNNEL_ID}.json"
echo "   sudo sed 's|${CF_DIR}|/etc/cloudflared|g' ${CONFIG_FILE} | sudo tee /etc/cloudflared/config.yml >/dev/null"
echo "   sudo chmod 600 /etc/cloudflared/config.yml /etc/cloudflared/${TUNNEL_ID}.json"
echo "   sudo cloudflared service install"
echo "   sudo systemctl enable --now cloudflared"
echo "   sudo systemctl status cloudflared"
echo "========================================================================"
