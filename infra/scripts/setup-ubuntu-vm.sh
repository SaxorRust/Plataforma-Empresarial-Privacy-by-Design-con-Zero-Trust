#!/usr/bin/env bash
# ==============================================================================
# Aprovisionamiento idempotente para VM Ubuntu Server (24.04 / 26.04.1 LTS)
# Proyecto: Plataforma Empresarial Privacy-by-Design con Zero Trust (BUAP FCC)
# Uso: chmod +x infra/scripts/setup-ubuntu-vm.sh && ./infra/scripts/setup-ubuntu-vm.sh
# ==============================================================================
set -euo pipefail

echo "[1/6] Actualizando índices APT y herramientas base..."
sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  git \
  ufw \
  jq \
  openssl \
  apparmor \
  apparmor-utils \
  systemd-timesyncd

echo "[2/6] Asegurando sincronización horaria NTP (clave para WebAuthn/JWT/TLS)..."
sudo timedatectl set-ntp true || true
sudo systemctl enable --now systemd-timesyncd || true

echo "[3/6] Instalando Docker Engine y Docker Compose v2..."
if ! command -v docker >/dev/null 2>&1; then
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg

  CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-noble}")"
  # Verificar si el codename (ej. Ubuntu 26.04) ya tiene suite en download.docker.com; si no, usar docker.io + docker-compose-v2
  if curl -fsSLI "https://download.docker.com/linux/ubuntu/dists/${CODENAME}/Release" >/dev/null 2>&1; then
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  else
    echo "Repositorio oficial Docker aún sin suite '${CODENAME}'; instalando paquetes nativos Ubuntu (docker.io + docker-compose-v2)..."
    sudo apt-get install -y docker.io docker-compose-v2 docker-buildx
  fi
else
  echo "Docker ya instalado: $(docker --version)"
fi

sudo systemctl enable --now docker
sudo usermod -aG docker "${USER}" || true

echo "[4/6] Verificando estado de AppArmor..."
sudo systemctl enable --now apparmor || true
sudo aa-status | head -n 10 || true

echo "[5/6] Instalando cloudflared..."
if ! command -v cloudflared >/dev/null 2>&1; then
  sudo mkdir -p --mode=0755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" | \
    sudo tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y cloudflared
else
  echo "cloudflared ya instalado: $(cloudflared --version)"
fi

echo "[6/6] Configurando firewall UFW (Zero Trust en host)..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
# Nota: Los puertos 8000 y 8080 de Docker solo escuchan en 127.0.0.1 para cloudflared.
sudo ufw --force enable
sudo ufw status verbose

echo ""
echo "=================================================================="
echo " Aprovisionamiento completado."
echo " IMPORTANTE: Cierra sesión y vuelve a entrar (o ejecuta 'newgrp docker')"
echo " para usar docker sin sudo."
echo "=================================================================="
