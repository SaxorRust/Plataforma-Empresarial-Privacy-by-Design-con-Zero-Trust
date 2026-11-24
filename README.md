# Plataforma Empresarial Privacy-by-Design con Zero Trust y Auditoría SIEM

Sistema de **Gestión Hospitalaria** diseñado bajo los principios de **Privacidad desde el Diseño (*Privacy-by-Design*)**, arquitectura **Zero Trust** (ABAC con Open Policy Agent), **segregación criptográfica de PII** en HashiCorp Vault, **ciclo de vida / borrado certificado NIST SP 800-88** y **auditoría centralizada SIEM (Syslog RFC 5424)**.

- **Institución:** Benemérita Universidad Autónoma de Puebla (BUAP) — Facultad de Ciencias de la Computación (FCC)
- **Programa Educativo:** Ingeniería en Ciberseguridad · **Asignatura:** Privacidad y Seguridad de los Datos Personales (`ICSA 252`)
- **Equipo:**
  - **Jezreel Pérez Romero** — Arquitecto de Privacidad y Ciclo de Vida (`MA-02`, `MA-03`, `MA-04`, `MB-01`–`MB-04`, DevSecOps)
  - **Ubaldo Edgar Gonzalez Flores** — Ingeniero de Seguridad en Aplicaciones y Sistemas (`F1`, `MA-01`, `MA-02`, `MC-01`, Cloudflare Tunnel/WAF)
  - **Samuel Pérez Rodríguez** — Analista SOC y Auditoría SIEM (`MC-02`, `MC-03`, `MC-04`, Consola SOC y pruebas SIEM)
- **Entorno productivo:** `https://tralaleritosmigajeros.uk` (Portal y API) · `https://siem.tralaleritosmigajeros.uk` (Consola SIEM protegida con Cloudflare Zero Trust Access OTP)

---

## Arquitectura y Módulos Cubiertos

La plataforma aisla **5 contenedores Docker** en **5 redes virtuales segmentadas** (`edge_net` + 4 redes `internal: true` sin acceso a Internet):

| Módulo | Controles Implementados |
| :--- | :--- |
| **Módulo A — Gobernanza, Identidad y ABAC** | `MA-01` FIDO2/WebAuthn (Passkeys ECDSA P-256) + Argon2id (salt único + pepper HMAC-SHA256) + JWT `HS256` con timeout implícito de 2 min; `MA-02` Segregación PII en HashiCorp Vault (`Transit AEAD + KV v2`, tokens `pat_<32 hex>`); `MA-03` Prevención de *Function Creep* con OPA *Fail-Closed* (`hospital_abac.rego`); `MA-04` Minimización cuantitativa y cualitativa por rol. |
| **Módulo B — Ciclo de Vida, Desidentificación y NIST SP 800-88** | `MB-01` Planificador automático TTL (`TTLBackgroundScheduler`); `MB-02` Exportación **HIPAA Safe Harbor** (18 identificadores, tope `90+`) + **$k$-anonimato y $l$-diversidad** *Fail-Closed* (JSON/CSV); `MB-03` Derechos ARCO con sobrescritura multi-pasada `CLEAR`/`PURGE`, limpieza RAM (`secure_zero_buffer`) y purga Vault KV v2; `MB-04` Certificados JSON y PDF sellados con `SHA-256`. |
| **Módulo C — Sandboxing y Auditoría SIEM / SOC** | `MC-01` Confinamiento del contenedor API con **Seccomp-BPF** (*default-deny* `EPERM`), **AppArmor** (`enforce`), `read_only: true`, `cap_drop: [ALL]` y `no-new-privileges`; `MC-02` Centralización **Syslog RFC 5424** (UDP/TCP `:5514`); `MC-03` Sanitización Regex previa a persistencia (tarjetas Luhn, CURP, NSS, JWT, secretos); `MC-04` Motor de correlación temporal (3 reglas activas) y Consola SOC con zona horaria `America/Mexico_City`. |

---

## Despliegue Reproducible (Quick Start)

### Requisitos Previos
- Docker Engine + Docker Compose v2 (Linux recomendado para soporte nativo de Seccomp-BPF y AppArmor; validado en Ubuntu Server 26.04.1 LTS).
- Python 3.11+ (solo si deseas ejecutar la suite de pruebas local fuera de Docker).

### 1. Configurar variables de entorno
```bash
cp .env.example .env
# Edita .env y reemplaza los secretos de desarrollo (POSTGRES_PASSWORD, VAULT_DEV_ROOT_TOKEN_ID, ARGON2_PEPPER, JWT_SECRET_KEY)
```

> **Nota de seguridad (producción vs. evaluación local):** Por conveniencia de evaluación y pruebas locales, `.env.example` incluye `SEED_DEFAULT_ACCOUNTS=true` (precarga las 6 cuentas de demostración documentadas en [`docs/CREDENCIALES_EQUIPO.md`](docs/CREDENCIALES_EQUIPO.md)). En entornos productivos expuestos a Internet se recomienda definir un `SEED_ACCOUNTS_SUFFIX` privado o desactivar la precarga (`SEED_DEFAULT_ACCOUNTS=false`) tras aprovisionar cuentas institucionales con `admin_sec`.

### 2. Levantar la plataforma (con Seccomp-BPF activo)
```bash
docker compose up -d --build
docker compose ps
```

### 3. Activar también AppArmor en Ubuntu Server (opcional pero recomendado)
```bash
sudo ./infra/scripts/install-apparmor-profile.sh
docker compose -f docker-compose.yml -f docker-compose.apparmor.yml up -d --build
```

Accesos locales (vinculados exclusivamente a `127.0.0.1` para publicación controlada vía `cloudflared`):
- **Portal Clínico y API:** `http://127.0.0.1:8000`
- **Consola SIEM / SOC:** `http://127.0.0.1:8080`

---

## Pruebas Automatizadas y Scripts de Verificación E2E

```bash
# Suite unitaria, integración y OWASP Top 10 (43 pruebas Pytest + Ruff)
pip install -r services/api/requirements.txt -r services/siem/requirements.txt pytest pytest-cov ruff
ruff check services tests
pytest -v

# Pruebas unitarias nativas de políticas ABAC en Open Policy Agent (15 pruebas OPA)
opa check --strict infra/opa/policies
opa test -v infra/opa/policies
```

Scripts de verificación end-to-end contra despliegue local o dominio productivo:
- `./infra/scripts/verify-ma01-ma02.sh` — Autenticación Argon2id/JWT/WebAuthn + Bóveda Vault Transit AEAD y KV v2.
- `./infra/scripts/verify-module-a.sh` — OPA *Fail-Closed*, alta segregada, bloqueo de *Function Creep* y minimización por rol.
- `./infra/scripts/verify-module-b.sh` — Barrido TTL, exportación Safe Harbor + $(k, l)$, borrado ARCO NIST SP 800-88 y certificados JSON/PDF `SHA-256`.
- `./infra/scripts/verify-sandboxing-mc01.sh` — Pruebas negativas de confinamiento Seccomp-BPF (`EPERM`) y AppArmor (`enforce`).
- `./infra/scripts/verify-siem-module-c.sh` — Ingesta Syslog RFC 5424, sanitización Regex en SQLite y reglas de correlación SOC.
- `./infra/scripts/verify-domain-security.sh` — TLS Strict, cabeceras Zero Trust, WAF Cloudflare y Access OTP en `siem.`.

---

## Documentación del Proyecto

- **[Documentación Técnica Completa (PDF)](docs/DOCUMENTACION_TECNICA.pdf)** · **[Versión Markdown](docs/DOCUMENTACION_TECNICA.md)**
- **[Matriz de Roles y Permisos (6 roles ABAC Zero Trust)](docs/MATRIZ_ROLES_PERMISOS.md)**
- **[Credenciales Genéricas de Evaluación](docs/CREDENCIALES_EQUIPO.md)**
- **[Guía de Funcionamiento del Sistema](docs/GUIA_FUNCIONAMIENTO.md)**
- **[Checklist Maestro de Trazabilidad](docs/CHECKLIST.md)** · **[Planeación](docs/planeacion.md)**
- **[Aprovisionamiento de VM Ubuntu](docs/aprovisionamiento-vm.md)** · **[Endurecimiento Cloudflare](docs/hardening-cloudflare.md)**
- **Material de Defensa Técnica y Demo en Vivo:** [Guion 20 min](docs/defensa/GUION_DEMO_20MIN.md) · [Guía Jezreel](docs/defensa/GUIA_DEFENSA_JEZREEL.md) · [Guía Ubaldo](docs/defensa/GUIA_DEFENSA_UBALDO.md) · [Guía Samuel](docs/defensa/GUIA_DEFENSA_SAMUEL.md)
