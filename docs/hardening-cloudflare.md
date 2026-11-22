# Endurecimiento de Dominio en Cloudflare — `tralaleritosmigajeros.uk`

Guía paso a paso para robustecer el borde perimetral en Cloudflare (compatible con **Cloudflare Free + Zero Trust Free**) y validar el comportamiento junto a `cloudflared` y FastAPI.

---

## 1. SSL/TLS (Cifrado Estricto)

En el panel de Cloudflare → zona **`tralaleritosmigajeros.uk`**:

1. **SSL/TLS → Overview:** Selecciona **Full (strict)** *(con Cloudflare Tunnel el canal túnel↔borde ya viaja autenticado y cifrado vía TLS)*.
2. **SSL/TLS → Edge Certificates:**
   - **Always Use HTTPS:** `ON`
   - **HTTP Strict Transport Security (HSTS):**
     - `Enable HSTS`: `ON`
     - `Max-Age`: `12 months (31536000)`
     - `Apply HSTS policy to subdomains (includeSubDomains)`: `ON`
     - `No-Sniff Header`: `ON`
   - **Minimum TLS Version:** `TLS 1.2`
   - **Opportunistic Encryption:** `ON`
   - **TLS 1.3:** `ON`
   - **Automatic HTTPS Rewrites:** `ON`

---

## 2. DNS y Seguridad de Resolución

En **DNS → Records** y **DNS → Settings**:

1. Verifica que existan los registros `CNAME` creados por `cloudflared` con **Proxy status = Proxied (nube naranja)**:
   - `tralaleritosmigajeros.uk` → `<TUNNEL_UUID>.cfargotunnel.com`
   - `app.tralaleritosmigajeros.uk` → `<TUNNEL_UUID>.cfargotunnel.com`
   - `siem.tralaleritosmigajeros.uk` → `<TUNNEL_UUID>.cfargotunnel.com`
2. **DNS → Settings → DNSSEC:** Activa **Enable DNSSEC** (y registra el `DS record` en tu registrador de dominio `.uk` si tu registrador lo soporta).
3. *(Opcional)* Agrega registros **CAA** restringiendo emisores a Let's Encrypt / Google Trust Services (los que usa Cloudflare Universal SSL).

---

## 3. Reglas WAF Personalizadas (Free Tier: hasta 5 reglas)

En **Security → WAF → Custom rules → Create rule**, agrega estas 4 reglas de alto impacto:

### Regla 1 — Bloqueo de archivos sensibles y escaneos comunes
- **Nombre:** `Block Sensitive Files & Scanners`
- **Action:** `Block`
- **Expression (Edit expression):**
```text
(lower(http.request.uri.path) contains "/.env") or
(lower(http.request.uri.path) contains "/.git") or
(lower(http.request.uri.path) contains "/wp-admin") or
(lower(http.request.uri.path) contains "/wp-login") or
(lower(http.request.uri.path) contains "/phpmyadmin") or
(lower(http.request.uri.path) contains "phpinfo") or
(lower(http.request.uri.path) contains "..")
```

### Regla 2 — Bloqueo de patrones básicos de SQLi / XSS en URI/Query
- **Nombre:** `Block Basic SQLi and XSS Probes`
- **Action:** `Block`
- **Expression:**
```text
(lower(http.request.uri.query) contains "union select") or
(lower(http.request.uri.query) contains "' or '1'='1") or
(lower(http.request.uri.query) contains "<script") or
(lower(http.request.uri.query) contains "javascript:") or
(lower(http.request.uri.query) contains "information_schema")
```

### Regla 3 — Restricción de métodos HTTP permitidos
- **Nombre:** `Allow Only Safe API Methods`
- **Action:** `Block`
- **Expression:**
```text
not (http.request.method in {"GET" "POST" "PUT" "PATCH" "DELETE" "OPTIONS" "HEAD"})
```

### Regla 4 — Bloqueo de bots sin User-Agent
- **Nombre:** `Block Empty User-Agent`
- **Action:** `Block`
- **Expression:**
```text
(http.user_agent eq "")
```

---

## 4. Rate Limiting (Free Tier: 1 regla)

En **Security → WAF → Rate limiting rules → Create rule**:

- **Nombre:** `Protect Auth Endpoints Against Brute Force`
- **If incoming requests match:**
  - `URI Path` `starts with` `/auth/`
- **When rate exceeds:** `10 requests` per `10 seconds`
- **With the same characteristics:** `IP`
- **Then take action:** `Block` (duración: `10 seconds` en Free tier)

> **Nota para pruebas del Módulo C (SIEM):** Cuando Samuel simule ataques de fuerza bruta para disparar la regla de correlación del SIEM en vivo, puedes ajustar el umbral temporalmente o probar desde `127.0.0.1` / con un umbral ligeramente superior al del SIEM (por ejemplo, SIEM alerta en 5 fallos/min y Cloudflare bloquea a partir de 15 req/10s) para demostrar **defensa en profundidad** (ambas capas funcionando sin pisarse).

---

## 5. Bots y Nivel de Seguridad

En **Security → Bots** y **Security → Settings**:
- **Bot Fight Mode:** `ON`
- **Security Level:** `Medium`
- **Browser Integrity Check:** `ON`

---

## 6. Protección Zero Trust para `siem.tralaleritosmigajeros.uk`

El colector SIEM jamás debe quedar abierto al público. En **Zero Trust → Access → Applications → Add an application → Self-hosted**:

1. **Application name:** `Hospital SIEM Collector (BUAP)`
2. **Application domain:** `siem.tralaleritosmigajeros.uk`
3. **Policy name:** `Solo Equipo SOC BUAP`
   - **Action:** `Allow`
   - **Include → Emails:** Agrega únicamente los correos de **Ubaldo**, **Jezreel** y **Samuel**.
4. **Identity provider:** `One-time PIN` (incluido gratis sin configurar IdP externo).

---

## 7. Validación automatizada

Una vez levantados Docker (`docker compose up -d`) y `cloudflared`, ejecuta desde la VM o desde otra máquina:

```bash
chmod +x infra/scripts/verify-domain-security.sh
./infra/scripts/verify-domain-security.sh tralaleritosmigajeros.uk
```

El script reportará `PASS`, `WARN` o `FAIL` para redirección HTTPS, `CF-Ray`, `/edge-check`, cabeceras de seguridad, TLS, WAF (`/.env` y SQLi) y acceso restringido a `siem.tralaleritosmigajeros.uk`.
