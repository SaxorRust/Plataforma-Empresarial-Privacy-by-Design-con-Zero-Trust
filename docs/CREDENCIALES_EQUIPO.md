# Credenciales Genéricas del Equipo — Acceso por Roles (ABAC Zero Trust)

> **Entorno de uso:** Pruebas, demostraciones y desarrollo del equipo (BUAP FCC — ICSA 252).
> Al iniciar el servicio `api` (`SEED_DEFAULT_ACCOUNTS=true` por defecto), la plataforma **elimina automáticamente cualquier cuenta heredada `super_admin`, actualiza el constraint de roles en PostgreSQL y crea de forma idempotente las 6 cuentas genéricas ABAC** si aún no existen, para que todo el equipo pueda iniciar sesión de inmediato.
>
> Para revisar en detalle **qué SÍ hace y qué NO hace cada rol**, consulta la **[Matriz Completa de Roles y Permisos](MATRIZ_ROLES_PERMISOS.md)**.

---

## 1. Tabla de Credenciales Genéricas Precargadas (6 Roles ABAC)

Todas las contraseñas cumplen la política **OWASP A07** de la plataforma (mínimo 12 caracteres, mayúscula, minúscula, dígito y carácter especial) y se almacenan con **Argon2id + Salt único + Pepper**.

| Rol (`role`) | Usuario (`username`) | Contraseña (`password`) | Cabecera `X-Purpose` por defecto | Alcance y Módulos Autorizados |
| :--- | :--- | :--- | :--- | :--- |
| **`admin_sec`** | `admin_sec` | `AdminSec#2026!ZT` | `mantenimiento_ttl` | **SecOps e IAM:** gestión de cuentas y roles (`/auth/users`), estado y rotación de llave Transit AEAD en HashiCorp Vault, auditoría OPA y barrido TTL. **Separación de funciones Zero Trust:** bloqueado (`403`) en datos clínicos, PII, Safe Harbor y ARCO. |
| **`medico`** | `medico_demo` | `Medico#2026!ZT` | `atencion_medica` | Alta segregada (Vault + PostgreSQL), lectura/edición de expedientes clínicos completos y **detokenización exclusiva de PII** en Vault. |
| **`enfermeria`** | `enfermeria_demo` | `Enfermeria#2026!ZT` | `atencion_medica` | Lectura clínica minimizada (solo 4 columnas: `record_id`, `opaque_patient_token` enmascarado `pat_xxxx...yyyy`, `department`, `diagnosis_summary`). |
| **`analista`** | `analista_demo` | `Analista#2026!ZT` | `investigacion_estadistica` | Listado generalizado (`age_range`, `zip_generalized`) y exportación estadística **HIPAA Safe Harbor + $(k, l)$** en JSON/CSV. Bloqueado para consultas individuales (*anti-singling-out*). |
| **`auditor_arco`** | `auditor_arco` | `AuditorArco#2026!ZT` | `ejercicio_arco` | Auditoría OPA, barrido TTL, borrado certificado **ARCO / NIST SP 800-88** (`CLEAR`/`PURGE`), descarga PDF/JSON y verificación `SHA-256` de certificados. Sin acceso a diagnósticos clínicos ni detokenización PII. |
| **`paciente`** | `paciente_demo` | `Paciente#2026!ZT` | `acceso_titular` | Consulta exclusiva de sus propios registros (`resource_owner_match == true`). Único rol permitido en el auto-registro público (`POST /auth/register`). |

> **Nota Zero Trust (Sin cuenta `super_admin`):**
> - Bajo **Mínimo Privilegio (*Least Privilege*)** y **Separación de Funciones (*Separation of Duties*)**, la plataforma **no utiliza ninguna cuenta `super_admin`**.
> - **`admin_sec`** administra identidades y roles institucionales en la pestaña *6. Gestión de Cuentas* (`/auth/users*`) junto con SecOps (Vault/OPA/TTL), mientras que OPA y Vault bloquean (`403 Forbidden`) cualquier acceso de `admin_sec` a expedientes clínicos, PII directa o borrado ARCO.
> - Todas las sesiones expiran de forma **implícita en el backend** tras 2 minutos de inactividad (sin contador visible ni accesible en la interfaz).

---

## 2. Cómo Activarlas en tu Servidor / VM

Solo actualiza el repositorio y reconstruye `api` y `opa`:

```bash
git pull origin main
docker compose -f docker-compose.yml -f docker-compose.apparmor.yml up -d --build api opa
```

Al arrancar, la API ejecutará automáticamente la limpieza de cualquier cuenta `super_admin` previa, aplicará el constraint de los 6 roles ABAC y creará las 6 cuentas en PostgreSQL (sin sobrescribir cuentas existentes). Después:

1. Abre **`https://tralaleritosmigajeros.uk/`** (o `http://localhost:8000/`).
2. En la pestaña **Iniciar Sesión**, ingresa cualquiera de los 6 usuarios y contraseñas de la tabla.
3. Opcionalmente, cada integrante puede registrar su propia **Passkey FIDO2/WebAuthn** en *1. Mi Sesión & Passkeys*.

> Para desactivar la precarga automática en un entorno productivo estricto, define `SEED_DEFAULT_ACCOUNTS=false` en tu archivo `.env`.
