# Guía de Defensa Técnica — Ubaldo Edgar Gonzalez Flores
## Rol: Integrante 2 — Ingeniero de Seguridad en Aplicaciones y Sistemas (`role/seguridad-infra`)

- **Asignatura:** Privacidad y Seguridad de los Datos Personales (BUAP FCC — ICSA 252)
- **Fecha de defensa:** 1 de diciembre de 2026
- **Módulos bajo tu responsabilidad:** `F1` (Infraestructura Docker Zero Trust y Ubuntu 26.04.1 LTS), `MA-01` (FIDO2/WebAuthn + Argon2id/Pepper + Portal Zero Trust), `MA-02` (Bóveda HashiCorp Vault Transit AEAD + KV v2), `MC-01` (Sandboxing Seccomp-BPF + AppArmor) y `F5-03`/`F5-04` (Cloudflare Tunnel + Endurecimiento WAF/Rate Limiting/Access).

---

## 1. Tu Discurso Técnico (Resumen en 60 segundos)

> *"Mi responsabilidad fue construir la infraestructura Zero Trust de extremo a extremo: segmentamos 5 servicios en 5 redes Docker aisladas (`internal: true`), implementamos autenticación fuerte **FIDO2/WebAuthn (Passkeys)** con respaldo **Argon2id + Salt + Pepper**, aislamos la PII en **HashiCorp Vault (Transit AEAD + KV v2)** con rotación de llaves, confinamos el contenedor de la API a nivel de kernel con **Seccomp-BPF** y **AppArmor**, y expusimos el servicio sin abrir un solo puerto en el firewall usando **Cloudflare Tunnel**, 4 reglas WAF, Rate Limiting y Cloudflare Zero Trust Access."*

---

## 2. Mapa de Archivos Clave que Debes Dominar

| Archivo | Qué hace exactamente |
| :--- | :--- |
| `docker-compose.yml` y `docker-compose.apparmor.yml` | Orquestación de 5 servicios y 5 redes (`edge_net` + 4 redes `internal: true`), `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, Seccomp y AppArmor. |
| `services/api/app/security/passwords.py` | `Argon2idPasswordService`: parámetros `m=65536, t=3, p=2`, *pepper* vía `HMAC-SHA256` y `verify_dummy()` anti-enumeración por tiempo. |
| `services/api/app/security/webauthn.py` y `routers/auth.py` | Flujo FIDO2/WebAuthn (ECDSA P-256, retos de un solo uso, `sign_count` anti-clonación), JWT `HS256` con revocación por `jti` en `/auth/logout`. |
| `services/api/app/vault/client.py` y `routers/vault.py` | Integración con HashiCorp Vault: cifrado Transit AEAD (`hospital-pii-key`), persistencia en KV v2 con tokens `pat_<32 hex>`, rotación de llaves y purga definitiva. |
| `infra/seccomp/api-seccomp.json` | Perfil Seccomp-BPF default-deny (`EPERM`) que bloquea `fork`, `vfork`, `execve`, `mount`, `unshare`, `ptrace`, `chmod` y sockets `AF_PACKET`. |
| `infra/apparmor/zt-hospital-api` | Perfil AppArmor en modo `enforce` que restringe rutas del sistema de archivos y ejecución de binarios dentro del contenedor API. |
| `services/api/app/middleware.py` | `SecurityHeadersMiddleware`: HSTS, CSP estricto (sin `unsafe-inline`), `X-Frame-Options: DENY`, `Cache-Control: no-store` y `X-Request-ID`. |
| `services/api/app/static/` (`index.html`, `portal.css`, `portal.js`) | Portal clínico con puerta de acceso obligatoria (`#auth-gate`), JWT solo en RAM, visor de contraseña y generador criptográfico Web Crypto API (16 chars). |
| `docs/hardening-cloudflare.md` y `infra/scripts/verify-domain-security.sh` | Configuración de Cloudflare Tunnel (`tralaleritosmigajeros.uk`), 4 reglas WAF, Rate Limiting en `/auth/` y verificación automatizada (`PASS=14 / FAIL=0`). |

---

## 3. Puntos Técnicos Críticos que Te Pueden Preguntar (Q&A de Jurado)

### P1. ¿Cuál es la diferencia entre Salt y Pepper en su implementación de Argon2id?
**Respuesta:** El **Salt** es único y aleatorio por cada usuario y se almacena junto al hash Argon2id en PostgreSQL para derrotar tablas arcoíris y evitar que dos contraseñas iguales produzcan el mismo hash. El **Pepper** (`ARGON2_PEPPER`) es un secreto de aplicación que se aplica mediante `HMAC-SHA256` antes del hash y **nunca se guarda en la base de datos**; así, incluso si un atacante roba PostgreSQL completo, no puede crackear contraseñas offline sin comprometer también los secretos del entorno.

### P2. ¿Cómo mitigan la enumeración de usuarios en el login?
**Respuesta:** Cuando el usuario ingresado no existe, ejecutamos `verify_dummy()` contra un hash Argon2id real precalculado. De esta manera el tiempo de respuesta es prácticamente idéntico para usuarios existentes e inexistentes, y siempre devolvemos el mismo mensaje genérico `401`.

### P3. ¿Por qué FIDO2/WebAuthn es resistente al phishing?
**Respuesta:** Porque la llave privada nunca sale del autenticador del usuario y cada firma ECDSA P-256 está criptográficamente ligada al origen exacto (`rp_id = tralaleritosmigajeros.uk`) y a un reto aleatorio de un solo uso (*anti-replay*). En un sitio de phishing con otro dominio, el navegador ni siquiera libera la credencial. Además validamos `sign_count` monotónico para detectar clonación.

### P4. ¿Por qué no guardan el JWT en `localStorage`?
**Respuesta:** Porque `localStorage` es vulnerable a robo de sesión ante cualquier XSS. En nuestro portal (`portal.js`), el JWT vive exclusivamente en memoria RAM de la pestaña, está protegido por CSP estricto sin `unsafe-inline`, expira en 30 minutos y se revoca inmediatamente por `jti` en `POST /auth/logout`.

### P5. ¿Qué ventaja da usar HashiCorp Vault con Transit AEAD + KV v2 en lugar de cifrar directamente en Python?
**Respuesta:** Con **Transit AEAD** (Encryption-as-a-Service), la llave criptográfica maestra (`hospital-pii-key`) **jamás sale de Vault ni entra a la memoria de la API**. Además permite rotar llaves (`POST /vault/keys/rotate`, ej. versión `1 → 2`) manteniendo descifrables los tokens anteriores sin reescribir la base de datos ni exponer la clave.

### P6. ¿Qué demuestra exactamente su prueba de confinamiento Seccomp-BPF + AppArmor (`MC-01`)?
**Respuesta:** Si un atacante lograra una vulnerabilidad de ejecución de código (RCE) dentro de FastAPI, el kernel Linux bloquea de inmediato (`Errno 1: Operation not permitted`) cualquier intento de abrir una shell (`subprocess`/`execve`), crear procesos (`fork`), escalar privilegios (`mount`, `unshare`, `ptrace`), capturar tráfico (`AF_PACKET`) o escribir en `/app` (`Read-only file system`), mientras la API sigue respondiendo `HTTP 200` normalmente.

### P7. ¿Por qué usan Cloudflare Tunnel (`cloudflared`) en lugar de abrir los puertos 80/443 en el router/VM?
**Respuesta:** Porque `cloudflared` establece conexiones salientes cifradas hacia el borde de Cloudflare (`readyConnections: 4`), por lo que la VM **no expone ninguna IP pública ni puertos entrantes abiertos**, reduciendo drásticamente la superficie de ataque y evitando que alguien se salte el WAF conectándose directo por IP.

### P8. ¿Qué protecciones activaron en Cloudflare para `tralaleritosmigajeros.uk`?
**Respuesta:** TLS Full (Strict) + TLS 1.3 + HSTS 1 año, 4 reglas WAF personalizadas (bloqueo de `/.env`, `/.git`, SQLi/XSS, métodos no permitidos y `User-Agent` vacío), Rate Limiting en `/auth/*` (`10 req / 10 s` por IP) y **Cloudflare Zero Trust Access (Email OTP)** protegiendo `siem.tralaleritosmigajeros.uk`. Todo verificado con `verify-domain-security.sh` (`PASS=14 | WARN=0 | FAIL=0`).

### P9. ¿Por qué desactivaron `Bot Fight Mode` en Cloudflare Free?
**Respuesta:** Porque en el plan Free intercepta clientes legítimos de API (`curl`, scripts de verificación y pruebas automatizadas) con un reto JS `403` sin permitir reglas WAF Skip. En su lugar aplicamos defensa en profundidad con las 4 reglas WAF, Rate Limiting en `/auth/` y las reglas de correlación del SIEM.

### P10. ¿Cómo aseguraron que el generador de contraseñas del portal sea criptográficamente seguro?
**Respuesta:** Usa `window.crypto.getRandomValues` (nunca `Math.random()`), aplica *rejection sampling* para evitar sesgo modular, garantiza al menos 2 caracteres de cada clase OWASP A07 y aplica mezcla Fisher-Yates antes de insertarla en `#reg-password`.

---

## 4. Tu Bloque en la Demo en Vivo (Minutos 2 a 7)

1. Mostrar la puerta de autenticación obligatoria en `https://tralaleritosmigajeros.uk/` (sin sesión no se ve nada de la app).
2. En **Registrar Cuenta**, pulsar **"Generar contraseña segura"** + icono de ojo, crear usuario y mostrar login con Argon2id / Passkey FIDO2.
3. Mostrar en terminal la verificación en vivo de **Seccomp-BPF + AppArmor** (`./infra/scripts/verify-sandboxing-mc01.sh` → `Operation not permitted` en `fork`/`subprocess`/`mount` + `PASS=14`).
4. Mostrar rápidamente una sonda bloqueada por **Cloudflare WAF** (`curl -I https://tralaleritosmigajeros.uk/.env` → `HTTP 403`).
