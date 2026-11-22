# Configuración de Túnel Cloudflare (`cloudflared`) — `tralaleritosmigajeros.uk`

> **Seguridad:** Nunca subas `~/.cloudflared/cert.pem`, `<TUNNEL_UUID>.json` ni `config.yml` con rutas/IDs reales si contienen credenciales privadas al repositorio público. El archivo `.gitignore` ya bloquea `*.pem`, `*.json` y `config.yml` dentro de `infra/cloudflared/`.

---

## 1. Instalar `cloudflared` en Linux (Debian / Ubuntu)

```bash
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install -y cloudflared
cloudflared --version
```

---

## 2. Autenticación y generación del certificado (`cert.pem`)

```bash
cloudflared tunnel login
```

1. Se abrirá una URL en el navegador (o cópiala manualmente si estás en consola SSH).
2. Inicia sesión en Cloudflare y selecciona la zona **`tralaleritosmigajeros.uk`**.
3. Al autorizar, `cloudflared` descargará automáticamente la llave de cuenta en `~/.cloudflared/cert.pem`.

---

## 3. Crear el túnel y generar archivo de llaves (`<TUNNEL_UUID>.json`)

```bash
cloudflared tunnel create privacy-zt-tunnel
```

- Toma nota del **Tunnel UUID** que imprime el comando (ejemplo: `a1b2c3d4-...`).
- Las credenciales del túnel se guardan automáticamente en:
  `~/.cloudflared/<TUNNEL_UUID>.json`.
- Para verificar que quedó creado:

```bash
cloudflared tunnel list
```

---

## 4. Agregar ruteo DNS hacia `tralaleritosmigajeros.uk`

```bash
# Dominio raíz y subdominio principal de la app
cloudflared tunnel route dns privacy-zt-tunnel tralaleritosmigajeros.uk
cloudflared tunnel route dns privacy-zt-tunnel app.tralaleritosmigajeros.uk

# (Opcional) Subdominio para auditoría SIEM (protegido con Cloudflare Access)
cloudflared tunnel route dns privacy-zt-tunnel siem.tralaleritosmigajeros.uk
```

Esto crea automáticamente registros `CNAME` en Cloudflare DNS apuntando a `<TUNNEL_UUID>.cfargotunnel.com` con proxy activado (nube naranja).

> Si algún registro previo en Cloudflare DNS ya existía para `tralaleritosmigajeros.uk`, bórralo primero desde el panel DNS de Cloudflare o usa `--overwrite-dns` (`cloudflared tunnel route dns --overwrite-dns ...`).

---

## 5. Configurar `config.yml` y probar el túnel

```bash
mkdir -p ~/.cloudflared
cp infra/cloudflared/config.yml.example ~/.cloudflared/config.yml
# Edita ~/.cloudflared/config.yml con tu <TUNNEL_UUID> y ruta real a ~/.cloudflared/<TUNNEL_UUID>.json
```

Validar sintaxis y ejecutar en primer plano:

```bash
cloudflared tunnel --config ~/.cloudflared/config.yml ingress validate
cloudflared tunnel --config ~/.cloudflared/config.yml run privacy-zt-tunnel
```

---

## 6. (Opcional) Instalar como servicio `systemd` en Linux

```bash
sudo mkdir -p /etc/cloudflared
sudo cp ~/.cloudflared/config.yml /etc/cloudflared/config.yml
sudo cp ~/.cloudflared/<TUNNEL_UUID>.json /etc/cloudflared/<TUNNEL_UUID>.json
# Asegúrate de que credentials-file en /etc/cloudflared/config.yml apunte a /etc/cloudflared/<TUNNEL_UUID>.json
sudo cloudflared service install
sudo systemctl enable --now cloudflared
sudo systemctl status cloudflared
```

---

## 7. Endurecimiento recomendado en el panel de Cloudflare

1. **SSL/TLS → Overview:** Modo **Full (strict)**.
2. **SSL/TLS → Edge Certificates:** Activar *Always Use HTTPS*, *Automatic HTTPS Rewrites*, TLS mínimo `1.2` y HSTS.
3. **Security → WAF / Rate Limiting:** Regla de límite de peticiones por IP en `/auth/*` (complementa la detección de fuerza bruta en nuestro SIEM).
4. **Zero Trust → Access (opcional para `siem.tralaleritosmigajeros.uk`):** Restringir acceso al dashboard SIEM solo por correo institucional del equipo (`@buap.mx` o correos autorizados).
