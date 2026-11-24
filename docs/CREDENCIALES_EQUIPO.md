# Credenciales Genéricas del Equipo — Acceso por Roles (ABAC + Super Admin)

> **Entorno de uso:** Pruebas, demostraciones y desarrollo del equipo (BUAP FCC — ICSA 252).
> Al iniciar el servicio `api` (`SEED_DEFAULT_ACCOUNTS=true` por defecto), la plataforma **actualiza automáticamente el constraint de `super_admin` en PostgreSQL y crea de forma idempotente las 7 cuentas genéricas** si aún no existen, para que todo el equipo pueda iniciar sesión de inmediato.

---

## 1. Tabla de Credenciales Genéricas Precargadas

Todas las contraseñas cumplen la política **OWASP A07** de la plataforma (mínimo 12 caracteres, mayúscula, minúscula, dígito y carácter especial) y se almacenan con **Argon2id + Salt único + Pepper**.

| Rol (`role`) | Usuario (`username`) | Contraseña (`password`) | Cabecera `X-Purpose` por defecto | Alcance y Módulos Autorizados |
| :--- | :--- | :--- | :--- | :--- |
| **`super_admin`** | `super_admin` | `SuperAdmin#2026!ZT` | `administracion_total` | **Acceso total a todos los módulos:** Clínica/Vault (crear, leer, detokenizar PII, ver sanitizados), OPA/ABAC, Safe Harbor + $(k, l)$, Borrado ARCO NIST SP 800-88, Certificados y TTL. |
| **`medico`** | `medico_demo` | `Medico#2026!ZT` | `atencion_medica` | Alta segregada (Vault + PostgreSQL), lectura/edición de expedientes clínicos completos y detokenización de PII en Vault. |
| **`enfermeria`** | `enfermeria_demo` | `Enfermeria#2026!ZT` | `atencion_medica` | Lectura clínica minimizada (solo 4 columnas: `record_id`, `opaque_patient_token` enmascarado `pat_xxxx...yyyy`, `department`, `diagnosis_summary`). |
| **`analista`** | `analista_demo` | `Analista#2026!ZT` | `investigacion_estadistica` | Listado generalizado (`age_range`, `zip_generalized`) y exportación estadística **HIPAA Safe Harbor + $(k, l)$** en JSON/CSV. Bloqueado para consultas individuales (*anti-singling-out*). |
| **`auditor_arco`** | `auditor_arco` | `AuditorArco#2026!ZT` | `ejercicio_arco` | Auditoría OPA, barrido TTL, borrado certificado **ARCO / NIST SP 800-88** (`CLEAR`/`PURGE`), descarga PDF/JSON y verificación `SHA-256` de certificados. Sin acceso a diagnósticos clínicos. |
| **`admin_sec`** | `admin_sec` | `AdminSec#2026!ZT` | `mantenimiento_ttl` | SecOps: estado y rotación de llave Transit AEAD en HashiCorp Vault, auditoría OPA y barrido TTL. **Separación de funciones:** acceso a expedientes clínicos bloqueado (`403`). |
| **`paciente`** | `paciente_demo` | `Paciente#2026!ZT` | `acceso_titular` | Consulta exclusiva de sus propios registros (`resource_owner_match == true`). |

> **Nota Zero Trust sobre `super_admin`:**
> - **Cuenta única (singleton):** El rol `super_admin` está **bloqueado en el registro público** (`POST /auth/register` devuelve `403 Forbidden` y emite la alerta `AUTH_PRIVILEGE_ESCALATION_BLOCKED` en el SIEM), no aparece en el formulario de registro del portal y está restringido a nivel de PostgreSQL mediante el índice único parcial `uq_single_super_admin` para que **nunca pueda existir más de 1 cuenta `super_admin`**.
> - **Auditoría y prevención de *Function Creep*:** Aunque `super_admin` puede operar todos los módulos y propósitos válidos (`administracion_total`, `atencion_medica`, `investigacion_estadistica`, `ejercicio_arco`, `mantenimiento_ttl`, `acceso_titular`), **sigue auditándose en el SIEM** y sigue siendo bloqueado por OPA si se envía un `X-Purpose` vacío o indebido (ej. `marketing_comercial`).

---

## 2. Cómo Activarlas en tu Servidor / VM

Solo actualiza el repositorio y reconstruye `api` y `opa`:

```bash
git pull origin main
docker compose up -d --build api opa
```

Al arrancar, la API ejecutará automáticamente la migración del constraint `super_admin` y creará las 7 cuentas en PostgreSQL (sin sobrescribir cuentas existentes). Después:

1. Abre **`https://tralaleritosmigajeros.uk/`** (o `http://localhost:8000/`).
2. En la pestaña **Iniciar Sesión**, ingresa cualquiera de los 7 usuarios y contraseñas de la tabla.
3. Opcionalmente, cada integrante puede registrar su propia **Passkey FIDO2/WebAuthn** en *1. Mi Sesión & Passkeys*.

> Para desactivar la precarga automática en un entorno productivo estricto, define `SEED_DEFAULT_ACCOUNTS=false` en tu archivo `.env`.
