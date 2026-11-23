# Credenciales Genéricas del Equipo — Acceso por Roles (ABAC + Super Admin)

> **Entorno de uso:** Pruebas, demostraciones y desarrollo del equipo (BUAP FCC — ICSA 252).
> La base de datos inicia vacía por diseño **Zero Trust** (sin cuentas hardcodeadas en producción). Utiliza esta guía para registrar y compartir las cuentas estándar del equipo desde el portal web.

---

## 1. Tabla de Credenciales Genéricas Sugeridas

Todas las contraseñas cumplen la política **OWASP A07** de la plataforma (mínimo 12 caracteres, mayúscula, minúscula, dígito y carácter especial) y se protegen con **Argon2id + Salt único + Pepper**.

| Rol (`role`) | Usuario (`username`) | Contraseña (`password`) | Cabecera `X-Purpose` por defecto | Alcance y Módulos Autorizados |
| :--- | :--- | :--- | :--- | :--- |
| **`super_admin`** | `super_admin` | `SuperAdmin#2026!ZT` | `administracion_total` | **Acceso total a todos los módulos:** Clínica/Vault (crear, leer, detokenizar PII, ver sanitizados), OPA/ABAC, Safe Harbor + $(k, l)$, Borrado ARCO NIST SP 800-88, Certificados y TTL. |
| **`medico`** | `medico_demo` | `Medico#2026!ZT` | `atencion_medica` | Alta segregada (Vault + PostgreSQL), lectura/edición de expedientes clínicos completos y detokenización de PII en Vault. |
| **`enfermeria`** | `enfermeria_demo` | `Enfermeria#2026!ZT` | `atencion_medica` | Lectura clínica minimizada (solo 4 columnas: `record_id`, `opaque_patient_token` enmascarado `pat_xxxx...yyyy`, `department`, `diagnosis_summary`). |
| **`analista`** | `analista_demo` | `Analista#2026!ZT` | `investigacion_estadistica` | Listado generalizado (`age_range`, `zip_generalized`) y exportación estadística **HIPAA Safe Harbor + $(k, l)$** en JSON/CSV. Bloqueado para consultas individuales (*anti-singling-out*). |
| **`auditor_arco`** | `auditor_arco` | `AuditorArco#2026!ZT` | `ejercicio_arco` | Auditoría OPA, barrido TTL, borrado certificado **ARCO / NIST SP 800-88** (`CLEAR`/`PURGE`), descarga PDF/JSON y verificación `SHA-256` de certificados. Sin acceso a diagnósticos clínicos. |
| **`admin_sec`** | `admin_sec` | `AdminSec#2026!ZT` | `mantenimiento_ttl` | SecOps: estado y rotación de llave Transit AEAD en HashiCorp Vault, auditoría OPA y barrido TTL. **Separación de funciones:** acceso a expedientes clínicos bloqueado (`403`). |
| **`paciente`** | `paciente_demo` | `Paciente#2026!ZT` | `acceso_titular` | Consulta exclusiva de sus propios registros (`resource_owner_match == true`). |

> **Nota Zero Trust sobre `super_admin`:** Aunque `super_admin` puede operar todos los módulos y propósitos válidos (`administracion_total`, `atencion_medica`, `investigacion_estadistica`, `ejercicio_arco`, `mantenimiento_ttl`, `acceso_titular`), **sigue auditándose en el SIEM** y sigue siendo bloqueado por OPA si se envía un `X-Purpose` vacío o indebido (ej. `marketing_comercial`) para poder demostrar la prevención de *Function Creep*.

---

## 2. Cómo Registrar las Cuentas en el Portal Web

1. Abre el portal en **`https://tralaleritosmigajeros.uk/`** (o `http://localhost:8000/` en entorno local).
2. Selecciona la pestaña **Registrar Cuenta**.
3. Ingresa el **Nombre de usuario**, selecciona el **Rol Institucional (ABAC)** y coloca la **Contraseña** de la tabla anterior.
4. Haz clic en **Crear Cuenta y Autenticar**.
5. Una vez creada, cualquier integrante del equipo puede entrar desde la pestaña **Iniciar Sesión** con ese mismo usuario y contraseña (o vincular su propia **Passkey FIDO2/WebAuthn** en la pestaña *1. Mi Sesión & Passkeys*).

---

## 3. Si tu Servidor Ya Tiene la Base de Datos Inicializada (Migración de `super_admin`)

El archivo `infra/postgres/init.sql` solo se ejecuta cuando el volumen `postgres_data` es nuevo. Si ya tenías contenedores corriendo antes de agregar el rol `super_admin`, actualiza la restricción `CHECK` en PostgreSQL sin perder tus datos existentes:

```bash
docker compose exec postgres psql -U "${POSTGRES_USER:-zt_app_user}" -d "${POSTGRES_DB:-hospital_zt}" -c "
ALTER TABLE auth_identity.users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE auth_identity.users
  ADD CONSTRAINT users_role_check
  CHECK (role IN ('medico', 'enfermeria', 'analista', 'auditor_arco', 'admin_sec', 'paciente', 'super_admin'));
"
```

Después reinicia la API y OPA (si modificaste código o políticas):

```bash
docker compose up -d --build api opa
```
