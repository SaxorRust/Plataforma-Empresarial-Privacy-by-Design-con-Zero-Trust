# Guía de Defensa Técnica — Jezreel Pérez Romero
## Rol: Integrante 1 — Arquitecto de Privacidad y Ciclo de Vida (`role/privacidad-ciclo-vida`)

- **Asignatura:** Privacidad y Seguridad de los Datos Personales (BUAP FCC — ICSA 252)
- **Fecha de defensa:** 1 de diciembre de 2026
- **Módulos bajo tu responsabilidad:** `MA-02` (integración segregada), `MA-03` (OPA/ABAC), `MA-04` (Minimización), `MB-01` (TTL), `MB-02` (Safe Harbor + $k,l$), `MB-03` (ARCO + NIST SP 800-88), `MB-04` (Certificados SHA-256) y `F5-02` (Pipeline DevSecOps / OWASP Top 10).

---

## 1. Tu Discurso Técnico (Resumen en 60 segundos)

> *"Mi responsabilidad fue garantizar que los datos clínicos cumplan **Privacy-by-Design** a lo largo de todo su ciclo de vida: desde la ingesta segregada sin PII directa en PostgreSQL, pasando por autorización contextual Fail-Closed en **Open Policy Agent (OPA)** para impedir Function Creep y aplicar minimización por rol, hasta la retención automática (**TTL**), la exportación matemática **Safe Harbor + $k$-anonimato/$l$-diversidad** y el borrado irreversible **ARCO / NIST SP 800-88** respaldado por certificados JSON/PDF sellados con **SHA-256**."*

---

## 2. Mapa de Archivos Clave que Debes Dominar

| Archivo | Qué hace exactamente |
| :--- | :--- |
| `infra/opa/policies/hospital_abac.rego` | Política ABAC en Rego (13/13 pruebas en `hospital_abac_test.rego`). Define `allow`, `reason` y `allowed_fields` por rol, acción y `X-Purpose`. |
| `services/api/app/policy/opa_client.py` | Cliente HTTP hacia `zt-opa` en modo **Fail-Closed** (si OPA falla o no responde, bloquea con `403`). |
| `services/api/app/policy/minimization.py` | Motor `apply_minimization`: proyecta solo `allowed_fields`, enmascara token en `enfermeria` (`pat_xxxx...yyyy`) y generaliza `age_range` (`30-39`, `90+`) + `zip_generalized` (`72***`) en `analista`. |
| `services/api/app/routers/clinical.py` | Alta segregada `POST /clinical/records/segregated` (Regex anti-PII en notas + Vault + PG + compensación si PG falla), consultas minimizadas y detokenización auditada. |
| `services/api/app/lifecycle/ttl_scheduler.py` | `TTLBackgroundScheduler` (ejecución automática en `lifespan`) + barrido manual `POST /lifecycle/ttl/sweep` que purga expirados en PG y tokens huérfanos en Vault. |
| `services/api/app/lifecycle/anonymizer.py` | Exportador **HIPAA Safe Harbor** (18 IDs removidos, tope `90+`) + retícula adaptativa de **$k$-anonimato y $l$-diversidad** en modo Fail-Closed (`HTTP 422` si no cumple). |
| `services/api/app/lifecycle/erasure.py` | Motor **NIST SP 800-88** (`CLEAR` 2 pasadas / `PURGE` 3 pasadas en PG, `secure_zero_buffer` en RAM y purga KV v2 en Vault confirmando `CONFIRMED_NOT_FOUND`). |
| `services/api/app/lifecycle/certificates.py` | Generación de certificados JSON y PDF (`reportlab`) con sello **`SHA-256`** y verificación en tiempo constante (`hmac.compare_digest`). |
| `.github/workflows/security-owasp.yml` | Pipeline DevSecOps: `pip-audit`, `Bandit`, `Semgrep`, `Gitleaks`, `Trivy`, `CodeQL v4` y `tests/test_owasp_top10_security.py`. |

---

## 3. Puntos Técnicos Críticos que Te Pueden Preguntar (Q&A de Jurado)

### P1. ¿Cómo garantizan que si se roba la base de datos PostgreSQL no se filtra la identidad de los pacientes?
**Respuesta:** En `POST /clinical/records/segregated` los identificadores directos (nombre, CURP, NSS, correo) jamás tocan PostgreSQL: primero se envían a **HashiCorp Vault** (cifrado Transit AEAD + KV v2), que devuelve un token opaco `pat_<32 hex>`. En PostgreSQL solo se guarda ese token y los atributos clínicos. Además, validamos por Regex que `diagnosis_summary` no incluya CURP, NSS ni correos (`HTTP 422`), y si falla el `INSERT` en PostgreSQL ejecutamos compensación automática borrando el token en Vault.

### P2. ¿Qué es *Function Creep* y cómo lo previenen técnicamente?
**Respuesta:** Es usar datos recolectados para un fin legítimo (ej. atención médica) en otro fin no autorizado (ej. marketing o investigación sin consentimiento). Lo prevenimos exigiendo la cabecera **`X-Purpose`** en cada consulta y evaluándola en **OPA** (`hospital_abac.rego`). Si un médico envía `X-Purpose: marketing_comercial` o la omite, OPA devuelve `allow: false` y la API responde **`403 Forbidden`**, registrando `OPA_POLICY_DENIED` en el SIEM.

### P3. ¿Qué pasa si el contenedor de OPA se cae o deja de responder?
**Respuesta:** Nuestro `OPAClient` implementa **Fail-Closed** (denegación por defecto). Ante cualquier timeout, error de red o respuesta inválida de OPA, el acceso se rechaza automáticamente con `403`. Nunca se degrada a "permitir".

### P4. ¿Cuál es la diferencia entre minimización cuantitativa y cualitativa en su sistema?
**Respuesta:**
- **Cuantitativa (menos columnas/filas):** `enfermeria` solo recibe 4 columnas (sin edad, CP ni CIE-10); `auditor_arco` solo ve metadatos de ciclo de vida (sin diagnósticos); `admin_sec` recibe `403` en `/clinical/records`.
- **Cualitativa (menor precisión):** `enfermeria` recibe el token enmascarado (`pat_21a0...ae72`) y `analista` recibe la edad en rangos decenales (`30-39`, tope `90+`) y el código postal truncado (`72***`).

### P5. ¿Por qué bloquean al `analista` si intenta consultar `GET /clinical/records/{id}`?
**Respuesta:** Para evitar ataques de **singularización (*singling-out*)**. Un analista solo debe trabajar sobre cohortes agregadas o anonimizadas, nunca sobre el expediente individual de una persona concreta.

### P6. ¿Por qué no basta con HIPAA Safe Harbor y además implementaron $k$-anonimato y $l$-diversidad?
**Respuesta:** Safe Harbor elimina los 18 identificadores directos, pero combinaciones de cuasi-identificadores (edad + CP + género) aún pueden reidentificar a una persona (*linkage attack*). El **$k$-anonimato** garantiza que cada combinación aparezca al menos $k$ veces, y la **$l$-diversidad** evita el ataque de homogeneidad exigiendo al menos $l$ diagnósticos distintos (CIE-10) por clase de equivalencia. Si no se cumple dentro del `suppression_limit`, el sistema falla cerrado (`422`).

### P7. ¿Cómo cumplen exactamente con NIST SP 800-88 en el borrado ARCO?
**Respuesta:** En `POST /lifecycle/arco/erasure` ejecutamos tres capas:
1. Sobrescritura multi-pasada en PostgreSQL (`CLEAR`: 2 pasadas; `PURGE`: 3 pasadas con datos aleatorios y ceros) antes de limpiar el registro.
2. Limpieza de buffers sensibles en memoria RAM mediante `secure_zero_buffer` (`bytearray` puesto en ceros).
3. Purga definitiva de todas las versiones y metadatos en Vault KV v2 verificada con lectura posterior (`CONFIRMED_NOT_FOUND`).

### P8. ¿Cómo prueban que un Certificado de Sanitización no fue alterado después de emitirse?
**Respuesta:** El certificado guarda un hash **`SHA-256`** sobre su carga canónica JSON. El endpoint `GET /lifecycle/certificates/{id}/verify` recalcula el SHA-256 a partir de los datos almacenados y lo compara en tiempo constante usando `hmac.compare_digest`. Si alguien modifica un solo campo en BD, la verificación devuelve `valid: false`.

### P9. ¿Cómo funciona la retención temporal (TTL) sin intervención manual?
**Respuesta:** `TTLBackgroundScheduler` corre como tarea asíncrona dentro del `lifespan` de FastAPI ejecutando barridos periódicos que sobrescriben y eliminan registros con `ttl_expires_at` vencido, además de purgar sus tokens huérfanos en Vault. También puede invocarse manualmente por `admin_sec` o `auditor_arco` en `POST /lifecycle/ttl/sweep`.

### P10. ¿Qué aportó el pipeline de DevSecOps (CI/CD)?
**Respuesta:** Configuramos 9 jobs obligatorios en GitHub Actions (`Ruff`, `Pytest + Cov`, `OPA strict/test`, `ShellCheck`, `pip-audit`, `Bandit`, `Semgrep OWASP Top 10`, `Gitleaks`, `Trivy`, `CodeQL v4`). Gracias a ello remediamos 40 CVEs en dependencias y 9 hallazgos Bandit `B608` antes de llegar a producción.

---

## 4. Tu Bloque en la Demo en Vivo (Minutos 7 a 13)

1. Mostrar alta segregada (`POST /clinical/records/segregated`) y detokenización controlada como `medico`.
2. Cambiar `X-Purpose` a `marketing_comercial` → demostrar **`403 Forbidden`** (Function Creep).
3. Cambiar de sesión a `analista` → mostrar minimización (`30-39`, `72***`) y generar exportación **Safe Harbor + $(k=2, l=2)$** en JSON/CSV + prueba Fail-Closed con `k=10` (`422`).
4. Cambiar de sesión a `auditor_arco` → ejecutar **NIST SP 800-88 `PURGE`**, verificar **`SHA-256`** y abrir el **certificado PDF** descargado.
