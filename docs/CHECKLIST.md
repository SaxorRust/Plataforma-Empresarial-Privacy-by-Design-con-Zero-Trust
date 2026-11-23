# 📋 Checklist Maestro de Trazabilidad y Avance

- **Institución:** Benemérita Universidad Autónoma de Puebla (BUAP) — Facultad de Ciencias de la Computación (FCC)
- **Carrera:** Ingeniería en Ciberseguridad
- **Asignatura:** Privacidad y Seguridad de los Datos Personales (ICSA 252)
- **Proyecto Final:** Plataforma Empresarial Privacy-by-Design con Zero Trust y Auditoría SIEM
- **Equipo:**
  - **Integrante 1 (Arquitecto de Privacidad y Ciclo de Vida):** Jezreel Pérez Romero (`role/privacidad-ciclo-vida`)
  - **Integrante 2 (Ingeniero de Seguridad en Aplicaciones y Sistemas):** Ubaldo Edgar Gonzalez Flores (`role/seguridad-infra`)
  - **Integrante 3 (Analista SOC y Auditoría SIEM):** Samuel Pérez Rodríguez (`role/siem-soc`)
- **Fecha límite de entrega:** 1 de diciembre de 2026
- **Escenario y Stack:** Sistema de Gestión Hospitalaria · Python (`FastAPI`) + `PostgreSQL` · Docker (Ubuntu Server 26.04.1 LTS en VirtualBox) · WebAuthn/Argon2id + HashiCorp Vault + OPA + Syslog RFC 5424 / SIEM Python
- **Dominio objetivo:** `tralaleritosmigajeros.uk` (vía `cloudflared` tunnel)

---

## 📊 Resumen de Avance Global

> **Fórmula de avance:** Cada ítem tiene un peso asignado. Suma los puntos de los ítems marcados como `[x]` para obtener el **% de avance total** (base 100%).

| Bloque | Peso Total | Completado | Avance del Bloque |
| :--- | :---: | :---: | :---: |
| **Fase 1:** Gobernanza Git, Entorno Base y Planeación | 10% | 10% | `10 / 10` |
| **Módulo A:** Gobernanza, Identidad, Bóveda y ABAC (20% rúbrica) | 20% | 20% | `20 / 20` |
| **Módulo B:** Ciclo de Vida, Desidentificación y NIST SP 800-88 (25% rúbrica) | 22% | 22% | `22 / 22` |
| **Módulo C:** Sandboxing, Syslog RFC 5424 y SIEM (25% rúbrica) | 22% | 22% | `22 / 22` |
| **Fase 5:** Pruebas Automatizadas, GitHub Actions y Cloudflare Tunnel | 12% | 12% | `12 / 12` |
| **Fase 6:** Documentación (MD/PDF) y Defensa Técnica (30% rúbrica) | 14% | 14% | `14 / 14` |
| **TOTAL GLOBAL** | **100%** | **100%** | **`100%`** |

---

## 1. Fase 1 — Gobernanza Git, Entorno Base y Planeación (10%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `F1-01` | [x] | 2% | Confirmar escenario, stack tecnológico y asignación de roles (Jezreel → Int. 1, Ubaldo → Int. 2, Samuel → Int. 3) | `main` / Todos | Definido en `docs/planeacion.md` y `pendientesYscripts/` |
| `F1-02` | [x] | 2% | Definir estructura de ramas por rol y flujo de PR hacia `main` (infra crítica) | `main` | Ramas `role/privacidad-ciclo-vida`, `role/seguridad-infra`, `role/siem-soc` creadas |
| `F1-03` | [x] | 3% | Preparar entorno base reproducible (`docker-compose.yml`, `.env.example`, redes aisladas, guía Ubuntu 26.04.1 LTS) | `main` / Ubaldo | `docker-compose.yml`, `infra/scripts/setup-ubuntu-vm.sh` y `docs/aprovisionamiento-vm.md` |
| `F1-04` | [x] | 3% | Planeación formal del desarrollo (hitos diarios hacia el 1 de diciembre) | `main` / Todos | Cronograma en `docs/planeacion.md` |

---

## 2. Módulo A — Gobernanza, Minimización y Control de Acceso (20%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `MA-01` | [x] | 5% | **Autenticación robusta:** FIDO2/WebAuthn (Passkeys) + respaldo Argon2id con *Salt* único + *Pepper* | `role/seguridad-infra` (Ubaldo) | `/auth/*` operativo (Argon2id `$argon2id$v=19$m=65536,t=3,p=2`, Passkeys ECDSA P-256, JWT+logout); verificado con `pytest` y `verify-ma01-ma02.sh` |
| `MA-02` | [x] | 5% | **Segregación y bóveda (Vault):** Identificadores directos aislados de atributos sensibles | `role/privacidad-ciclo-vida` & `role/seguridad-infra` | Bóveda Vault (`Transit AEAD + KV v2 + pat_...`) integrada con `/clinical/records` y `/clinical/records/segregated` (cero PII directa en PostgreSQL + compensación ante fallo BD); verificado con `pytest` y `verify-module-a.sh` |
| `MA-03` | [x] | 5% | **Prevención de Function Creep (OPA/ABAC):** Validación de propósito declarado por consulta | `role/privacidad-ciclo-vida` (Jezreel) | `OPAClient` fail-closed + `hospital_abac.rego` (13/13 `opa test` + `opa check --strict`); consultas sin `X-Purpose`, fuera de propósito, singularización de analista y `admin_sec` devuelven `403 Forbidden` |
| `MA-04` | [x] | 5% | **Minimización cuantitativa y cualitativa:** Filtrado de columnas y generalización según rol | `role/privacidad-ciclo-vida` (Jezreel) | `apply_minimization` proyecta `allowed_fields`, enmascara token en `enfermeria` (`pat_xxxx...yyyy`), generaliza `age_range` (`30-39`, `90+`) y `zip_generalized` (`72***`) en `analista` y oculta diagnósticos en `auditor_arco` |

---

## 3. Módulo B — Ciclo de Vida, Desidentificación y Borrado Certificado (22%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `MB-01` | [x] | 4% | **Retención temporal (TTL):** Tarea automatizada que purga registros/tokens expirados | `role/privacidad-ciclo-vida` (Jezreel) | `TTLBackgroundScheduler` activo en `lifespan` + `GET /lifecycle/ttl/status` + `POST /lifecycle/ttl/sweep` (sobrescribe y elimina expirados + purga tokens huérfanos en Vault); verificado con `pytest` y `verify-module-b.sh` |
| `MB-02` | [x] | 6% | **Exportación desidentificada:** Método *Safe Harbor* (18 identificadores) + $k$-anonimato agregado con $l$-diversidad | `role/privacidad-ciclo-vida` (Jezreel) | `POST /lifecycle/exports/anonymized` y `GET /lifecycle/exports/anonymized.csv` (18 IDs HIPAA removidos, tope `90+`, retícula adaptativa $(k,l)$ fail-closed); verificado con `pytest` y `verify-module-b.sh` (`k=3, l=3`) |
| `MB-03` | [x] | 6% | **Derechos ARCO + NIST SP 800-88:** Cancelación/Supresión con sobrescritura segura (*Clear/Purge*) y limpieza de buffers en memoria | `role/privacidad-ciclo-vida` (Jezreel) | `POST /lifecycle/arco/erasure` ejecuta sobrescritura multi-pasada en PostgreSQL (`CLEAR` 2 pasadas / `PURGE` 3 pasadas), `secure_zero_buffer` en memoria y purga KV v2 en Vault (`CONFIRMED_NOT_FOUND`) |
| `MB-04` | [x] | 6% | **Certificado de Sanitización:** Emisión automática en JSON y PDF firmado con hash `SHA-256` | `role/privacidad-ciclo-vida` (Jezreel) | Persistido en `compliance.sanitization_certificates`, descargable en `/lifecycle/certificates/{id}.json` y `.pdf` (`reportlab`) con verificación `/verify` en tiempo constante (`hmac.compare_digest`) y detección de tampering |

---

## 4. Módulo C — Sandboxing de Aplicación y Auditoría SIEM (22%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `MC-01` | [x] | 6% | **Confinamiento del sistema:** Perfiles personalizados Seccomp-BPF y AppArmor (ej. bloqueo de `execve`, rutas restringidas) | `role/seguridad-infra` (Ubaldo) | `infra/seccomp/api-seccomp.json` (default-deny EPERM), `infra/apparmor/zt-hospital-api` + `docker-compose.apparmor.yml`, verificado con `verify-sandboxing-mc01.sh` (`Operation not permitted`), `pytest` y CI (`apparmor_parser` + prueba negativa Docker) |
| `MC-02` | [x] | 5% | **Centralización Syslog (RFC 5424):** Envío estructurado de eventos de auditoría al colector SIEM | `role/siem-soc` (Samuel) | `SyslogAuditClient` en `services/api/app/audit/syslog_client.py` (auth, clinical, vault, lifecycle, OPA denials) + colector asíncrono UDP/TCP RFC 5424 (`services/siem/app/syslog_server.py`, `rfc5424.py`, `storage.py`) y endpoints/dashboard SOC en `:8080`; verificado con `pytest` (UDP+TCP real) y `verify-siem-module-c.sh` |
| `MC-03` | [x] | 5% | **Sanitización en ingesta (Regex):** Ofuscación automática de tarjetas, CURP, contraseñas antes de persistir | `role/siem-soc` (Samuel) | `services/siem/app/sanitizer.py` enmascara con `***` tarjetas (Luhn), CURP, contraseñas/secretos, NSS, JWT y claves sensibles de `STRUCTURED-DATA` antes de insertar en SQLite; verificado directo en BD SQLite en `tests/test_siem_module_c.py` |
| `MC-04` | [x] | 6% | **Reglas de correlación temporal (mín. 2):** Detección de fuerza bruta + alerta crítica por consultas masivas | `role/siem-soc` (Samuel) | `TemporalCorrelationEngine` (`services/siem/app/correlator.py`) con 3 reglas activas: `RULE-001` (`BRUTE_FORCE_LOGIN`), `RULE-002` (`MASS_RECORD_ACCESS`, `CRITICAL`) y `RULE-003` (`REPEATED_POLICY_DENIAL`), más `/api/v1/alerts`, `/ack`, `/rules`, `/stats` y consola SOC |

---

## 5. Fase 5 — Pruebas Automatizadas, GitHub Actions y Cloudflare (12%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `F5-01` | [x] | 4% | **Suite de pruebas automatizadas:** Unitarias, integración, políticas ABAC, $k$-anonimato/$l$-diversidad, NIST 800-88 y correlación SIEM | Todos | `pytest` en verde (`38/38 passed`, cobertura 82% global y 90%+ en SIEM): auth, Vault, OPA/ABAC, minimización, TTL, Safe Harbor/$(k,l)$, ARCO/NIST 800-88, OWASP Top 10, Seccomp/AppArmor y SIEM/SOC (`test_siem_module_c.py`) |
| `F5-02` | [x] | 3% | **GitHub Actions (CI):** Pipeline en `.github/workflows/ci.yml` ejecutando linter, tests y validación de seguridad en PRs a `main` | `role/privacidad-ciclo-vida` & `role/seguridad-infra` | 9/9 checks verdes en GitHub Actions (`ci.yml` + `security-owasp.yml` + `dependabot.yml`: Ruff, Pytest+Cov, OPA strict/tests, ShellCheck, pip-audit, Bandit, Semgrep OWASP Top 10, Gitleaks, Trivy, CodeQL v4 y `test_owasp_top10_security.py`) |
| `F5-03` | [x] | 3% | **Túnel `cloudflared`:** Configuración reproducible para exponer la plataforma local hacia `tralaleritosmigajeros.uk` | `role/seguridad-infra` (Ubaldo) | `readyConnections: 4`, 0 errores, `tralaleritosmigajeros.uk` + `app.` + `siem.` operativos |
| `F5-04` | [x] | 2% | **Endurecimiento Cloudflare:** SSL/TLS Strict, reglas WAF/Rate Limiting, cabeceras de seguridad y políticas Zero Trust | Ubaldo & Samuel | `verify-domain-security.sh` → `PASS=14 \| WARN=0 \| FAIL=0` + Access OTP en `siem.` |

---

## 6. Fase 6 — Documentación (MD/PDF) y Defensa Técnica (14%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `F6-01` | [x] | 5% | **Documentación del sistema (Markdown + PDF):** Arquitectura, diagramas, perfiles, evidencias de pruebas y certificados | Todos | Reporte técnico completo en `docs/DOCUMENTACION_TECNICA.md` y versión compilada en `docs/DOCUMENTACION_TECNICA.pdf` (incluye diagrama de arquitectura, evidencias E2E y capturas Cloudflare) |
| `F6-02` | [x] | 5% | **Guías de Defensa Técnica personalizadas:** Material de estudio, flujo end-to-end y Q&A para **Jezreel**, **Samuel** y **Ubaldo** | Todos | Guías por rol en `docs/defensa/GUIA_DEFENSA_JEZREEL.md`, `docs/defensa/GUIA_DEFENSA_UBALDO.md` y `docs/defensa/GUIA_DEFENSA_SAMUEL.md` |
| `F6-03` | [x] | 4% | **Ensayo de demo en vivo (20 min):** Guion paso a paso de demostración de los 3 módulos | Todos | Guion sincronizado minuto a minuto y plan B de contingencia en `docs/defensa/GUION_DEMO_20MIN.md` |

---

## 📝 Registro de Bitácora / Trazas de Avance

| Fecha | ID(s) Completados | Responsable | Commit / PR | Notas |
| :--- | :--- | :--- | :--- | :--- |
| 2026-11-21 | Inicialización | Equipo | `762babe` | Lectura de pliego técnico y `pendientes.txt`. |
| 2026-11-21 | Datos institucionales y stack base | Ubaldo | `93d3217` | Agregados `informacionInstitucional.txt`, `escenarioYtecnologias.txt` y copia PDF inicial. |
| 2026-11-21 | Checklist y guía `cloudflared` | Ubaldo | `5b8a884` | `.gitignore`, `docs/CHECKLIST.md`, `infra/cloudflared/`. |
| 2026-11-21 | `F1-01`, `F1-02`, `F1-03`, `F1-04` | Equipo | `75535bc` | Infraestructura Docker Compose segmentada, esquema SQL, política OPA base, guía Ubuntu 26.04.1 LTS, CI y ramas por rol (**Avance: 10%**). |
| 2026-11-21 | `F5-03`, `F5-04` | Ubaldo | PR #1 | Túnel `cloudflared` (`readyConnections=4`), 4 WAF Custom Rules, Rate Limiting `/auth/`, Zero Trust Access en `siem.` y cabeceras Zero Trust verificados con `PASS=14 / WARN=0 / FAIL=0` (**Avance: 15%**). |
| 2026-11-21 | `MA-01` (+ bóveda `MA-02`) | Ubaldo | `role/seguridad-infra` | Autenticación Argon2id (salt único + HMAC-SHA256 pepper), FIDO2/WebAuthn Passkeys, sesiones JWT con revocación (`/auth/*`) y bóveda HashiCorp Vault Transit AEAD + KV v2 con tokens `pat_...` (`/vault/*`) verificados con `pytest` (11/11) y E2E Docker `verify-ma01-ma02.sh` (`PASS=14 / FAIL=0`) (**Avance: 20%**). |
| 2026-11-22 | `MA-02`, `MA-03`, `MA-04` | Jezreel | `role/privacidad-ciclo-vida` | Integración segregada Vault+PostgreSQL (`/clinical/records`, `/clinical/records/segregated`, `/clinical/records/{id}/patient-identity`), cliente OPA fail-closed y política `hospital_abac.rego` (10/10 `opa test` + `opa check --strict`), motor de minimización cuantitativa/cualitativa por rol y verificación `pytest` (17/17), `ruff`, `verify-ma01-ma02.sh` (`PASS=14/FAIL=0`) y `verify-module-a.sh` (`PASS=9/FAIL=0`) (**Avance: 35%**). |
| 2026-11-22 | `MB-01`, `MB-02`, `MB-03`, `MB-04` | Jezreel | `role/privacidad-ciclo-vida` | Planificador TTL automático (`TTLBackgroundScheduler` + `/lifecycle/ttl/*`), exportador *Safe Harbor* (18 IDs HIPAA, tope `90+`) + $k$-anonimato/$l$-diversidad JSON y CSV (`/lifecycle/exports/*`), borrado ARCO + NIST SP 800-88 (`CLEAR`/`PURGE` multi-pasada, `secure_zero_buffer` en memoria y purga Vault KV v2) y certificados JSON/PDF (`reportlab`) con verificación `SHA-256` (`/lifecycle/certificates/*`); verificado con `opa test` (13/13), `pytest` (21/21), `ruff` y E2E Docker (`verify-ma01-ma02.sh` 14/14, `verify-module-a.sh` 9/9, `verify-module-b.sh` 8/8) (**Avance: 57%**). |
| 2026-11-22 | `F5-02` (DevSecOps & OWASP Top 10) | Jezreel | `role/privacidad-ciclo-vida` | Workflows `ci.yml` y `security-owasp.yml` con SHAs inmutables + `dependabot.yml` (cooldown 7d) + `pyproject.toml` + `test_owasp_top10_security.py` (A01–A10); remediados 40 CVEs en dependencias (`pyjwt`, `starlette`, `pytest`), 9 hallazgos Bandit `B608` (SQL estático parametrizado) y 1 hallazgo Semgrep; **9/9 jobs en verde** en GitHub Actions (`31/31 pytest`, 0 CVEs `pip-audit`, 0 hallazgos Bandit/Semgrep/Trivy/Gitleaks/CodeQL) (**Avance: 60%**). |
| 2026-11-22 | `MC-01` (Seccomp-BPF + AppArmor) | Ubaldo | `role/seguridad-infra` | Perfil Seccomp-BPF default-deny (`infra/seccomp/api-seccomp.json` bloqueando `fork`/`vfork`/`subprocess`/`mount`/`unshare`/`ptrace`/`AF_PACKET`/`chmod` con `EPERM`), perfil AppArmor (`infra/apparmor/zt-hospital-api` + `docker-compose.apparmor.yml`), scripts `install-apparmor-profile.sh` y `verify-sandboxing-mc01.sh`, pruebas `test_sandboxing_mc01.py` y validación CI (`apparmor_parser` + prueba negativa Seccomp Docker) (**Avance: 66%**). |
| 2026-11-23 | `MC-02`, `MC-03`, `MC-04`, `F5-01` | Samuel | `role/siem-soc` | Emisor Syslog RFC 5424 integrado en API (`services/api/app/audit/syslog_client.py` en auth, clinical, vault, lifecycle y denegaciones OPA), colector SIEM UDP/TCP RFC 5424 (`services/siem/app/`), pipeline de sanitización Regex pre-persistencia (tarjetas Luhn, CURP, contraseñas, NSS, JWT), motor de correlación temporal (3 reglas: fuerza bruta `RULE-001`, consultas masivas CRÍTICA `RULE-002` y denegaciones OPA `RULE-003`), consola SOC HTML/API, script `verify-siem-module-c.sh` y pruebas `test_siem_module_c.py` (`38/38 pytest`, `ruff` y `bandit` 0 hallazgos) (**Avance: 86%**). |
| 2026-11-23 | Mejoras Portal Zero Trust UI | Ubaldo | `c8cae75` | Puerta de autenticación obligatoria (`#auth-gate`), botón de visualizar/ocultar contraseña en login y registro, y generador criptográfico de contraseñas (Web Crypto API, 16 chars) con botón de copiado. |
| 2026-11-23 | `F6-01`, `F6-02`, `F6-03` | Equipo | `main` | Documentación técnica completa (`docs/DOCUMENTACION_TECNICA.md` y `docs/DOCUMENTACION_TECNICA.pdf`), guías personalizadas de defensa técnica para Jezreel, Ubaldo y Samuel (`docs/defensa/GUIA_DEFENSA_*.md`) y guion de demo en vivo de 20 minutos (`docs/defensa/GUION_DEMO_20MIN.md`) (**Avance: 100%**). |
