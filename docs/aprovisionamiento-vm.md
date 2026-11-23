# Guía de Aprovisionamiento — VM VirtualBox (Ubuntu Server 26.04.1 LTS)

Esta guía prepara la máquina virtual de **Ubuntu Server 26.04.1 LTS** en VirtualBox para ejecutar la plataforma completa con aislamiento Zero Trust, AppArmor, Seccomp-BPF, Docker Compose y el túnel `cloudflared` hacia `tralaleritosmigajeros.uk`.

---

## 1. Configuración recomendada en VirtualBox

- **OS:** Linux → Ubuntu (64-bit) — *Ubuntu Server 26.04.1 LTS*
- **RAM:** 4096 MB (mínimo 3072 MB)
- **CPU:** 2 a 4 vCPUs (habilitar PAE/NX y virtualización anidada si aplica)
- **Disco:** 30 GB VDI dinámico
- **Red (Adaptador 1):** **NAT** con *Reenvío de puertos (Port Forwarding)*:

| Regla | Protocolo | IP Anfitrión | Puerto Anfitrión | IP Invitado | Puerto Invitado | Uso |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `ssh-vm` | TCP | `127.0.0.1` | `2222` | *(vacío)* | `22` | Administración SSH desde Windows |
| `api-local` | TCP | `127.0.0.1` | `8000` | *(vacío)* | `8000` | Plan B local sin internet |
| `siem-local` | TCP | `127.0.0.1` | `8080` | *(vacío)* | `8080` | Plan B local SIEM |

> **Conectar por SSH desde PowerShell en Windows:**
> ```powershell
> ssh -p 2222 <tu_usuario>@127.0.0.1
> ```

---

## 2. Clonar el repositorio y aprovisionar la VM

Dentro de la VM Ubuntu Server:

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/SaxorRust/Plataforma-Empresarial-Privacy-by-Design-con-Zero-Trust.git
cd Plataforma-Empresarial-Privacy-by-Design-con-Zero-Trust
```

Ejecuta el script de aprovisionamiento automático (instala Docker, Docker Compose v2, `apparmor-utils`, `cloudflared`, sincronización NTP y firewall `ufw`):

```bash
chmod +x infra/scripts/setup-ubuntu-vm.sh
./infra/scripts/setup-ubuntu-vm.sh
newgrp docker
```

Verifica versiones instaladas:

```bash
docker --version
docker compose version
sudo aa-status | head -n 8
cloudflared --version
```

---

## 3. Generar secretos locales y archivo `.env`

> **Nunca** subas `.env` a GitHub. Usa valores aleatorios criptográficos:

```bash
cp .env.example .env

# Generar valores seguros de ejemplo en consola para copiarlos a .env:
# Nota: Vault rechaza el prefijo reservado 'hvs.' o puntos en VAULT_DEV_ROOT_TOKEN_ID
echo "POSTGRES_PASSWORD=$(openssl rand -hex 20)"
echo "VAULT_DEV_ROOT_TOKEN_ID=zt-vault-$(openssl rand -hex 16)"
echo "ARGON2_PEPPER=$(openssl rand -hex 32)"
echo "JWT_SECRET_KEY=$(openssl rand -hex 32)"
```

Edita `.env` con `nano .env` y reemplaza todos los campos `CAMBIAR_*`.

---

## 4. Levantar la plataforma base con Docker Compose

```bash
docker compose up --build -d
docker compose ps
```

Verifica que los 5 contenedores (`zt-postgres`, `zt-vault`, `zt-opa`, `zt-siem-collector`, `zt-hospital-api`) estén en estado **`healthy`** o **`running`**:

```bash
curl -s http://127.0.0.1:8000/health | jq
curl -s http://127.0.0.1:8080/health | jq
```

Para ver logs en tiempo real o detener servicios:

```bash
docker compose logs -f api siem-collector
docker compose down
```

---

## 4.1 Activar confinamiento completo Seccomp-BPF + AppArmor (`MC-01`)

El perfil **Seccomp-BPF** (`infra/seccomp/api-seccomp.json`) ya se aplica por defecto en `docker-compose.yml`. Para activar también el perfil **AppArmor** (`zt-hospital-api`) en Ubuntu Server 26.04.1 LTS:

```bash
sudo ./infra/scripts/install-apparmor-profile.sh
docker compose -f docker-compose.yml -f docker-compose.apparmor.yml up -d --build
```

Verifica el confinamiento y los módulos de identidad/bóveda con las suites automatizadas:

```bash
./infra/scripts/verify-sandboxing-mc01.sh
./infra/scripts/verify-ma01-ma02.sh http://127.0.0.1:8000
```

---

## 5. Conectar la VM a `tralaleritosmigajeros.uk` vía `cloudflared`

Sigue los comandos exactos en [infra/cloudflared/README.md](../infra/cloudflared/README.md):

1. `cloudflared tunnel login` (autorizando `tralaleritosmigajeros.uk`).
2. `cloudflared tunnel create privacy-zt-tunnel`.
3. `cloudflared tunnel route dns privacy-zt-tunnel tralaleritosmigajeros.uk`.
4. Configurar `~/.cloudflared/config.yml` apuntando a `http://localhost:8000`.
5. `cloudflared tunnel --protocol http2 run privacy-zt-tunnel` (útil si el Wi-Fi universitario bloquea QUIC/UDP).

---

## 6. Buenas prácticas en VirtualBox antes de pruebas críticas

- **Snapshot previo:** Antes de activar perfiles restrictivos de Seccomp/AppArmor o ejecutar pruebas de borrado NIST SP 800-88, toma un *Snapshot* en VirtualBox (`Máquina → Tomar instantánea`).
- **Verificación de hora:** Si restauras o reanudas una VM pausada, verifica `timedatectl status` para evitar fallos de WebAuthn o tokens JWT por reloj desfasado.
