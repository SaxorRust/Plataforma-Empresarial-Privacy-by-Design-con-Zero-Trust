# Guion de Demostración en Vivo (20 Minutos)
## Plataforma Empresarial Hospitalaria Privacy-by-Design & Zero Trust (BUAP FCC — ICSA 252)

- **Duración total:** 20 minutos exactos (más espacio posterior de preguntas del jurado).
- **URLs productivas:**
  - Portal Clínico y API: `https://tralaleritosmigajeros.uk`
  - Consola SIEM / SOC: `https://siem.tralaleritosmigajeros.uk`
- **Participantes:** **Ubaldo** (Infraestructura, Identidad, Vault, Sandboxing y Cloudflare), **Jezreel** (Privacidad, OPA/ABAC, Minimización, Safe Harbor/$(k,l)$ y ARCO/NIST 800-88), **Samuel** (Syslog RFC 5424, Sanitización Regex, SIEM y Correlación SOC).

---

## 0. Checklist Pre-Demo (5 minutos antes de iniciar)

- [ ] Verificar en la VM Ubuntu que los 5 contenedores estén `Up (healthy)`:
  ```bash
  docker compose -f docker-compose.yml -f docker-compose.apparmor.yml ps
  ```
- [ ] Verificar que el túnel `cloudflared` tenga conexiones activas (`systemctl status cloudflared` o prueba `curl -s https://tralaleritosmigajeros.uk/health`).
- [ ] Tener 3 pestañas abiertas en el navegador:
  1. `https://tralaleritosmigajeros.uk/` (sesión cerrada, mostrando la puerta Zero Trust `#auth-gate`).
  2. `https://siem.tralaleritosmigajeros.uk/` (ya autenticado con OTP en una pestaña, y otra en incógnito para mostrar la barrera Cloudflare Access).
  3. Repositorio GitHub en la pestaña **Actions** (para enseñar los 9/9 checks DevSecOps en verde al cierre).
- [ ] Tener una terminal SSH/VM lista en el directorio del repositorio para ejecutar los comandos cortos de verificación (`verify-sandboxing-mc01.sh` y `curl` WAF).

---

## 1. Cronograma Minuto a Minuto

### Minuto 0:00 – 2:00 | Introducción y Arquitectura Zero Trust *(Todos — inicia Ubaldo)*
- **Qué decir:** Presentar el escenario hospitalario, los 3 módulos exigidos por la rúbrica y la topología de 5 contenedores en 5 redes Docker aisladas (`4 internal: true`), donde PostgreSQL **jamás guarda PII directa**.
- **Qué mostrar:** Diagrama de arquitectura en `docs/DOCUMENTACION_TECNICA.pdf` (Sección 2).

---

### Minuto 2:00 – 7:00 | Bloque Ubaldo — Identidad (`MA-01`), IAM Zero Trust, Sandboxing (`MC-01`) y Cloudflare (`F5`)
1. **Puerta de Autenticación Obligatoria, Auto-registro Mínimo Privilegio e IAM (`02:00 – 03:30`):**
   - Mostrar `https://tralaleritosmigajeros.uk/`: sin JWT válido, toda la aplicación está bloqueada (`#auth-gate`).
   - En **Registrar Cuenta**, destacar que el registro público solo permite el rol **`paciente`** (mínimo privilegio OWASP A01): pulsar **"Generar contraseña segura"** (16 caracteres con Web Crypto API), usar el botón de **visualizar/ocultar contraseña** y crear un paciente de prueba (ej. `pac_demo_vivo`).
   - Cerrar sesión e ingresar con **`admin_sec`** (ver `docs/CREDENCIALES_EQUIPO.md`) para mostrar brevemente la pestaña **6. Gestión de Cuentas** (aprovisionamiento IAM de roles institucionales sin cuenta `super_admin`, y bloqueo `403` si `admin_sec` intenta leer expedientes clínicos) y mencionar el **timeout implícito de 2 minutos por inactividad** en el backend.
   - Cerrar sesión e iniciar con **`medico_demo`** (o demostrar **Passkey FIDO2/WebAuthn** en *1. Mi Sesión & Passkeys* si hay autenticador biométrico/PIN disponible).
2. **Confinamiento Seccomp-BPF + AppArmor (`03:30 – 05:30`):**
   - En la terminal de la VM ejecutar:
     ```bash
     ./infra/scripts/verify-sandboxing-mc01.sh
     ```
   - Señalar en vivo: `ReadonlyRootfs=true`, `CapDrop=[ALL]`, `AppArmor=zt-hospital-api` y el bloqueo `Errno 1: Operation not permitted` al intentar `os.fork()`, `subprocess`, `mount()`, `ptrace()` y `AF_PACKET`, mientras `GET /health` sigue respondiendo `200 OK`.
3. **Endurecimiento Cloudflare (`05:30 – 07:00`):**
   - Ejecutar desde terminal:
     ```bash
     curl -i https://tralaleritosmigajeros.uk/.env
     ```
   - Señalar `HTTP/2 403` bloqueado en el borde por la Regla WAF 1 y mencionar TLS 1.3 Strict + Rate Limiting `/auth/` + `cloudflared` sin puertos abiertos.

---

### Minuto 7:00 – 13:00 | Bloque Jezreel — Segregación (`MA-02`), OPA (`MA-03`), Minimización (`MA-04`) y Ciclo de Vida (`MB-01` a `MB-04`)
1. **Alta Segregada + Detokenización Vault (`07:00 – 08:30`):**
   - Con la sesión activa de **`medico_demo`** (`medico`) en **2. Clínica & Bóveda PII**, hacer clic en **"+ Cargar Cohorte Clínica (6 Pacientes)"**.
   - Señalar que la tabla clínica solo muestra tokens opacos (`pat_...`) sin nombres ni CURP.
   - Pulsar **"Resolver PII (Vault)"** en un registro para demostrar la detokenización auditada vía Vault Transit AEAD + KV v2 (exclusiva del rol `medico`).
2. **Prevención de *Function Creep* con OPA (`08:30 – 09:30`):**
   - En la barra superior cambiar `X-Purpose` a **`marketing_comercial`** y pulsar **"Consultar Expedientes"** → mostrar **`HTTP 403 Forbidden`** devuelto por OPA (`hospital_abac.rego`) en modo Fail-Closed.
3. **Minimización y Exportación Safe Harbor + $(k, l)$ (`09:30 – 11:00`):**
   - Pulsar **"Cerrar Sesión (Revocar JWT)"** (mostrar que la app regresa a `#auth-gate`).
   - Iniciar sesión con **`analista_demo`** (rol `analista`, credenciales en `docs/CREDENCIALES_EQUIPO.md`).
   - En **2. Clínica**, mostrar la **minimización cualitativa y cuantitativa**: edades en rangos (`30-39`, `90+`), CP generalizado (`72***`), cero tokens ni IDs.
   - Ir a **4. Safe Harbor & (k, l)** → exportar con `k=2, l=2` (éxito `200 OK` + descarga CSV) y luego probar `k=10` → demostrar rechazo **Fail-Closed `422`**.
4. **Derechos ARCO + NIST SP 800-88 + Certificado PDF SHA-256 (`11:00 – 13:00`):**
   - Cerrar sesión e iniciar sesión con **`auditor_arco`** (rol `auditor_arco`).
   - En **5. ARCO, TTL & NIST 800-88**, copiar un token `pat_...`, seleccionar **`NIST_800_88_PURGE`** y ejecutar la sanitización.
   - Mostrar en la respuesta: 3 pasadas en PostgreSQL, `memory_buffers_zeroed >= 1`, `vault_verification: CONFIRMED_NOT_FOUND`.
   - En la tabla de certificados, pulsar **"Verificar SHA-256"** (`valid: true`) y descargar/abrir el **Certificado PDF**.

---

### Minuto 13:00 – 18:00 | Bloque Samuel — Syslog RFC 5424 (`MC-02`), Sanitización (`MC-03`) y Correlación SIEM (`MC-04`)
1. **Protección Zero Trust de la Consola SOC (`13:00 – 14:00`):**
   - Mostrar en ventana de incógnito que `https://siem.tralaleritosmigajeros.uk` redirige a **Cloudflare Zero Trust Access (Email OTP restringido a cuentas institucionales BUAP)**.
   - Cambiar a la pestaña ya autenticada de la Consola SOC y destacar la hora local **`America/Mexico_City`** (con selector de zona horaria integrado).
2. **Auditoría RFC 5424 en Vivo (`14:00 – 15:00`):**
   - Recargar la tabla de eventos y señalar las tramas reales recién generadas por Ubaldo y Jezreel (`AUTH_LOGIN_SUCCESS`, `CLINICAL_PII_DETOKENIZE`, `OPA_POLICY_DENIED`, `LIFECYCLE_ARCO_ERASURE`).
3. **Sanitización Regex Pre-Persistencia y Correlación Temporal (`15:00 – 18:00`):**
   - Ejecutar en terminal de la VM:
     ```bash
     ./infra/scripts/verify-siem-module-c.sh
     ```
   - Refrescar la Consola SOC y mostrar:
     - Evento sanitizado donde tarjeta (Luhn), CURP, NSS y contraseña aparecen reemplazados por `***`.
     - Alertas correlacionadas disparadas en tiempo real: **`RULE-001` (`BRUTE_FORCE_LOGIN`, `HIGH`)**, **`RULE-002` (`MASS_RECORD_ACCESS`, `CRITICAL`)** y **`RULE-003` (`REPEATED_POLICY_DENIAL`, `HIGH`)**.
     - Hacer clic en **`ACK`** sobre la alerta crítica para demostrar el flujo de respuesta a incidentes SOC.

---

### Minuto 18:00 – 20:00 | Cierre, DevSecOps y Transición a Q&A *(Todos)*
- Mostrar la pestaña **GitHub Actions** con los **9/9 checks en verde** (`Ruff`, `43/43 Pytest + 82% Cov`, `15/15 OPA`, `ShellCheck`, `Bandit`, `Semgrep`, `Gitleaks`, `Trivy`, `CodeQL`, `pip-audit`).
- Resumir la defensa en profundidad lograda y abrir sesión de preguntas del jurado.

---

## 2. Plan B / Contingencia ante Fallos en Vivo

| Situación Inesperada | Acción Inmediata (Plan B) |
| :--- | :--- |
| Caída temporal de Internet en el aula | Todo funciona de forma idéntica en local sobre `http://127.0.0.1:8000` (API/Portal) y `http://127.0.0.1:8080` (SIEM) en la VM Ubuntu. |
| El equipo de exposición no tiene autenticador WebAuthn/PIN configurado | Usar el flujo **Argon2id + Pepper** en el portal y mostrar `POST /auth/webauthn/register/begin` en `docs/evidencias/evidenciainfra.txt` (`PASS=14 / FAIL=0`). |
| Cloudflare Rate Limiting bloquea durante pruebas rápidas de fuerza bruta | Ejecutar `verify-siem-module-c.sh` contra `127.0.0.1:8000` / `127.0.0.1:8080` y explicar cómo esto demuestra las dos capas complementarias (borde + SIEM). |
| Falta de tiempo en algún bloque | Mostrar directamente las salidas archivadas en `docs/evidencias/` (`evidenciainfra.txt`, `evidenciasROLprivacidad.txt`, `evidenciaTestbashVM.txt` y capturas PNG de Cloudflare). |
