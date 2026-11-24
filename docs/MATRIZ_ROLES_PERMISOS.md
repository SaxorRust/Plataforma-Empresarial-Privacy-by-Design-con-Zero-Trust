# Documentación de Roles y Matriz de Permisos — Zero Trust (ABAC + OPA)

> **Plataforma Empresarial Hospitalaria Privacy-by-Design & Zero Trust** (BUAP FCC — ICSA 252)  
> Referencia operativa de los **6 roles ABAC** vigentes, sus alcances autorizados (**qué SÍ hace**) y sus restricciones explícitas (**qué NO hace**) bajo el principio de **Mínimo Privilegio (*Least Privilege*)** y **Separación de Funciones (*Separation of Duties*)**.

---

## 1. Principios de Diseño de Roles (Zero Trust)

1. **Sin cuenta `super_admin` (cero "modo Dios"):**  
   La cuenta `super_admin` fue eliminada deliberadamente. En una arquitectura Zero Trust hospitalaria **ningún rol tiene acceso simultáneo a gestión de identidades, criptografía y datos clínicos/PII**. El rol **`admin_sec`** concentra las funciones operativas de seguridad e IAM (gestión de cuentas/roles, llaves Vault, OPA y TTL), pero permanece bloqueado (`HTTP 403`) ante expedientes clínicos, PII y borrado ARCO.
2. **Doble verificación en cada petición (JWT + `X-Purpose`):**  
   Todas las rutas protegidas verifican primero la firma y vigencia del JWT (timeout de **2 minutos de inactividad**) y luego consultan a **Open Policy Agent (OPA)** en modo **Fail-Closed** (`infra/opa/policies/hospital_abac.rego`) validando la tupla `(role, purpose, action, resource_purpose, is_sanitized)`.
3. **Auto-registro público restringido:**  
   `POST /auth/register` únicamente crea cuentas con rol **`paciente`**. Cualquier intento de registrar un rol institucional devuelve `403 Forbidden` y dispara la alerta `AUTH_PRIVILEGE_ESCALATION_BLOCKED` en el SIEM. Solo `admin_sec` puede aprovisionar o cambiar roles en `/auth/users`.
4. **Revocación inmediata en cambios de privilegio:**  
   Cuando `admin_sec` cambia el rol o suspende una cuenta en `PATCH /auth/users/{id}`, todos sus tokens JWT activos se revocan de inmediato.

---

## 2. Resumen Rápido de los 6 Roles

| Rol (`role`) | Cuenta precargada | Contraseña inicial | `X-Purpose` obligatorio | Dominio Principal | Pestañas visibles en `/portal` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`medico`** | `medico_demo` | `Medico#2026!ZT` | `atencion_medica` | Atención clínica integral y resolución PII en Vault | 1. Sesión · 2. Clínica & Bóveda PII |
| **`enfermeria`** | `enfermeria_demo` | `Enfermeria#2026!ZT` | `atencion_medica` | Lectura clínica asistencial minimizada | 1. Sesión · 2. Clínica & Bóveda PII |
| **`analista`** | `analista_demo` | `Analista#2026!ZT` | `investigacion_estadistica` | Analítica poblacional y exportación Safe Harbor + $(k, l)$ | 1. Sesión · 2. Clínica (vista generalizada) · 4. Safe Harbor & $(k, l)$ |
| **`auditor_arco`** | `auditor_arco` | `AuditorArco#2026!ZT` | `ejercicio_arco` | Cumplimiento, derechos ARCO, borrado NIST SP 800-88 y certificados | 1. Sesión · 2. Metadatos · 3. OPA · 5. ARCO, TTL & NIST 800-88 |
| **`admin_sec`** | `admin_sec` | `AdminSec#2026!ZT` | `mantenimiento_ttl` | SecOps e IAM: cuentas/roles, rotación Vault, OPA y barrido TTL | 1. Sesión · 2. Estado/Rotación Vault · 3. OPA · 5. TTL · 6. Gestión de Cuentas |
| **`paciente`** | `paciente_demo` | `Paciente#2026!ZT` | `acceso_titular` | Consulta exclusiva de su propio expediente | 1. Sesión · 2. Mi Expediente |

---

## 3. Ficha Detallada por Rol (Qué SÍ hace y Qué NO hace)

### 3.1 `medico` — Atención Clínica Integral
- **Propósito obligatorio:** `X-Purpose: atencion_medica`
- **Qué SÍ hace:**
  - Inicia sesión con Argon2id o Passkey FIDO2/WebAuthn y gestiona sus propias Passkeys (`/auth/me`, `/auth/webauthn/*`).
  - Da de alta expedientes clínicos segregados (`POST /clinical/records/segregated`): la PII directa se cifra en **HashiCorp Vault** (Transit AEAD + KV v2) y los atributos clínicos se guardan en **PostgreSQL** vinculados solo por `opaque_patient_token` (`pat_...`).
  - Tokeniza PII directa en Vault (`POST /vault/patients/tokenize`) y **detokeniza PII** (`GET /vault/patients/{opaque_patient_token}`) — es el **único rol autorizado** para resolver el nombre, CURP, NSS y correo de un paciente.
  - Consulta listado e historial individual de expedientes activos (`GET /clinical/records`, `GET /clinical/records/{id}`) con proyección completa de 11 columnas (`record_id`, `opaque_patient_token`, `age_years`, `zip_prefix`, `gender`, `diagnosis_cie10`, `diagnosis_summary`, `department`, `purpose_scope`, `ttl_expires_at`, `created_at`).
  - Actualiza diagnósticos y datos clínicos de expedientes (`PATCH /clinical/records/{id}`).
- **Qué NO hace (`403 Forbidden`):**
  - **No** puede consultar expedientes si omite `X-Purpose` o declara un propósito distinto (ej. `marketing_comercial`, `investigacion_estadistica`).
  - **No** puede ver expedientes ya sanitizados por ARCO (`include_sanitized=true` ignorado/bloqueado).
  - **No** puede consultar estado de Vault (`GET /vault/status`) ni rotar llaves Transit (`POST /vault/keys/rotate`).
  - **No** puede exportar datasets estadísticos Safe Harbor (`/lifecycle/anonymized-export`).
  - **No** puede ejecutar borrado certificado ARCO/NIST SP 800-88, consultar/descargar certificados ni ejecutar barridos TTL (`/lifecycle/*`).
  - **No** puede simular ni consultar el motor OPA (`/clinical/policy/*`).
  - **No** puede listar, crear, modificar o suspender cuentas de usuario (`/auth/users*`).

---

### 3.2 `enfermeria` — Asistencia Clínica Minimizada
- **Propósito obligatorio:** `X-Purpose: atencion_medica`
- **Qué SÍ hace:**
  - Gestiona su propia sesión y Passkeys FIDO2/WebAuthn (`/auth/me`, `/auth/webauthn/*`).
  - Consulta expedientes activos en modo **solo lectura minimizada** (`GET /clinical/records`, `GET /clinical/records/{id}`) recibiendo **únicamente 4 columnas**:
    - `record_id`
    - `opaque_patient_token` **enmascarado** (`pat_xxxx...yyyy`)
    - `department`
    - `diagnosis_summary`
  - Opcionalmente puede tokenizar identificadores directos en admisión (`POST /vault/patients/tokenize`) sin recibir PII en respuesta.
- **Qué NO hace (`403 Forbidden`):**
  - **No** puede ver edad exacta (`age_years`), código postal (`zip_prefix`), género ni código `diagnosis_cie10`.
  - **No** puede ver el token opaco completo ni **detokenizar PII** en HashiCorp Vault (`GET /vault/patients/{token}` → `403`).
  - **No** puede crear (`POST /clinical/records/segregated`) ni modificar (`PATCH /clinical/records/{id}`) expedientes clínicos.
  - **No** puede ver registros sanitizados, auditar OPA, exportar datos estadísticos, ejecutar ARCO/TTL ni gestionar cuentas (`/auth/users*`).

---

### 3.3 `analista` — Investigación Estadística y Anonimización
- **Propósito obligatorio:** `X-Purpose: investigacion_estadistica`
- **Qué SÍ hace:**
  - Gestiona su propia sesión y Passkeys FIDO2/WebAuthn (`/auth/me`, `/auth/webauthn/*`).
  - Consulta el listado poblacional de expedientes con alcance compatible (`GET /clinical/records`) bajo **minimización cuantitativa y cualitativa (MA-04)**, recibiendo únicamente **5 columnas generalizadas**:
    - `age_range` (rangos decenales `30-39`, tope `90+`)
    - `zip_generalized` (primeros 2 dígitos + `***`, ej. `72***`)
    - `gender`
    - `diagnosis_cie10`
    - `department`
  - Exporta cohortes anonimizadas bajo **HIPAA Safe Harbor + $(k, l)$-anonimato** en JSON o CSV (`GET /lifecycle/anonymized-export?k=...&l=...&format=json|csv`), con supresión automática de grupos que no alcancen $k$ o $l$-diversidad.
- **Qué NO hace (`403 Forbidden`):**
  - **No** puede consultar un expediente individual (`GET /clinical/records/{id}` → `403`) ni filtrar por token (protección **anti-singularización / *anti-singling-out***).
  - **No** recibe `record_id`, `opaque_patient_token`, `age_years` exacto, `zip_prefix` completo ni `diagnosis_summary`.
  - **No** puede crear ni editar expedientes clínicos.
  - **No** puede tokenizar ni detokenizar PII en Vault, ni consultar/rotar llaves Transit.
  - **No** puede auditar OPA, ejecutar borrados ARCO/TTL, ver certificados ni gestionar cuentas (`/auth/users*`).

---

### 3.4 `auditor_arco` — Cumplimiento Legal, Derechos ARCO y Borrado NIST SP 800-88
- **Propósito obligatorio:** `X-Purpose: ejercicio_arco`
- **Qué SÍ hace:**
  - Gestiona su propia sesión y Passkeys FIDO2/WebAuthn (`/auth/me`, `/auth/webauthn/*`).
  - Consulta únicamente **metadatos de cumplimiento** de expedientes (`GET /clinical/records`, incluso con `include_sanitized=true`) en 6 columnas sin contenido clínico: `record_id`, `opaque_patient_token`, `purpose_scope`, `is_sanitized`, `ttl_expires_at`, `created_at`.
  - Consulta estado y simula decisiones del motor de políticas OPA (`GET /clinical/policy/status`, `POST /clinical/policy/evaluate`).
  - Consulta el estado operativo de HashiCorp Vault (`GET /vault/status`) para verificar el motor criptográfico.
  - Ejecuta el **borrado certificado ARCO conforme a NIST SP 800-88** (`POST /lifecycle/arco/erase`) en modo `CLEAR` (sobrescritura irreversible en PostgreSQL + revocación) o `PURGE` (borrado criptográfico + purga total del token y versiones en Vault KV v2).
  - Ejecuta barridos de retención TTL (`POST /lifecycle/ttl/sweep`).
  - Lista, descarga (PDF y JSON) y verifica la integridad criptográfica `SHA-256` de los certificados de sanitización (`GET /lifecycle/certificates`, `GET /lifecycle/certificates/{id}`, `GET /lifecycle/certificates/{id}/pdf`, `GET /lifecycle/certificates/{id}/verify`).
- **Qué NO hace (`403 Forbidden`):**
  - **No** puede leer diagnósticos (`diagnosis_cie10`, `diagnosis_summary`), edad, código postal ni departamento clínico de ningún paciente.
  - **No** puede crear ni editar expedientes clínicos.
  - **No** puede tokenizar ni **detokenizar PII** en Vault (`GET /vault/patients/{token}` → `403`), ni rotar llaves Transit (`POST /vault/keys/rotate` → `403`).
  - **No** puede exportar datasets estadísticos Safe Harbor (`/lifecycle/anonymized-export`).
  - **No** puede gestionar cuentas de usuario ni cambiar roles (`/auth/users*` → `403`).

---

### 3.5 `admin_sec` — Operaciones de Seguridad (SecOps) y Gestión de Identidades (IAM)
- **Propósito obligatorio:** `X-Purpose: mantenimiento_ttl`
- **Qué SÍ hace:**
  - Gestiona su propia sesión y Passkeys FIDO2/WebAuthn (`/auth/me`, `/auth/webauthn/*`).
  - **Gestión integral de cuentas y roles (IAM — Pestaña 6):**
    - Lista el directorio de cuentas activas y suspendidas (`GET /auth/users`).
    - Aprovisiona nuevas cuentas institucionales asignando cualquiera de los 6 roles ABAC (`POST /auth/users`).
    - Cambia el rol o suspende/reactiva cuentas existentes con **revocación inmediata de sesiones JWT** (`PATCH /auth/users/{user_id}`). *(Por seguridad, no puede desactivar ni degradar su propia cuenta en sesión activa.)*
    - Revoca de forma forzada todas las sesiones JWT de cualquier usuario (`POST /auth/users/{user_id}/revoke-sessions`).
  - **Gestión criptográfica de Vault (sin acceso a PII):**
    - Verifica estado de HashiCorp Vault y versión activa de la llave Transit (`GET /vault/status`).
    - Rota la llave Transit AEAD sin indisponibilidad (`POST /vault/keys/rotate`, exclusivo de `admin_sec`).
  - **Gobernanza y retención:**
    - Verifica estado y ejecuta simulaciones del motor de políticas OPA (`GET /clinical/policy/status`, `POST /clinical/policy/evaluate`).
    - Ejecuta barridos de expiración TTL (`POST /lifecycle/ttl/sweep`).
- **Qué NO hace (`403 Forbidden` — Separación de Funciones Zero Trust):**
  - **No** puede leer, crear ni editar expedientes clínicos (`GET/POST/PATCH /clinical/records*` → `403` por OPA).
  - **No** puede tokenizar ni **detokenizar PII** de pacientes en HashiCorp Vault (`POST /vault/patients/tokenize` y `GET /vault/patients/{token}` → `403`).
  - **No** puede exportar datasets estadísticos Safe Harbor (`/lifecycle/anonymized-export` → `403`).
  - **No** puede ejecutar borrado ARCO ni emitir/descargar certificados de sanitización NIST SP 800-88 (`/lifecycle/arco/erase`, `/lifecycle/certificates*` → `403`).
  - **No** existe ni puede asignar el rol `super_admin` (eliminado del esquema, API y OPA; intento rechazado con `422`).

---

### 3.6 `paciente` — Titular de los Datos (Acceso Propio)
- **Propósito obligatorio:** `X-Purpose: acceso_titular`
- **Qué SÍ hace:**
  - Puede auto-registrarse en el portal público (`POST /auth/register`, único rol permitido).
  - Gestiona su propia sesión y Passkeys FIDO2/WebAuthn (`/auth/me`, `/auth/webauthn/*`).
  - Consulta exclusivamente **sus propios registros** (`resource_owner_match == true`) con proyección limitada a 6 campos: `record_id`, `department`, `diagnosis_summary`, `purpose_scope`, `ttl_expires_at`, `created_at`.
- **Qué NO hace (`403 Forbidden`):**
  - **No** puede consultar, editar ni borrar expedientes de terceros.
  - **No** puede crear ni modificar expedientes clínicos.
  - **No** tiene acceso a Vault (ni tokenización, ni detokenización, ni estado/rotación de llaves).
  - **No** tiene acceso a OPA, exportaciones Safe Harbor, ARCO/TTL ni gestión de cuentas (`/auth/users*`).

---

## 4. Matriz Comparativa Completa (Endpoint / Acción × Rol)

| Módulo | Acción / Endpoint | `medico` | `enfermeria` | `analista` | `auditor_arco` | `admin_sec` | `paciente` |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **MA-01** | Auto-registro público (`POST /auth/register`) | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` | ✅ |
| **MA-01** | Login, `/auth/me`, Logout, Passkeys propias | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **IAM** | Listar / crear / editar / suspender / revocar cuentas (`/auth/users*`) | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` | ✅ | ❌ `403` |
| **MA-02** | Tokenizar PII en Vault (`POST /vault/patients/tokenize`) | ✅ | ✅ | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` |
| **MA-02** | **Detokenizar PII en Vault** (`GET /vault/patients/{token}`) | ✅ | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` |
| **MA-02** | Estado de Vault (`GET /vault/status`) | ❌ `403` | ❌ `403` | ❌ `403` | ✅ | ✅ | ❌ `403` |
| **MA-02** | Rotar llave Transit AEAD (`POST /vault/keys/rotate`) | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` | ✅ | ❌ `403` |
| **MA-03** | Estado y simulador OPA (`/clinical/policy/*`) | ❌ `403` | ❌ `403` | ❌ `403` | ✅ | ✅ | ❌ `403` |
| **MA-04** | Crear expediente segregado (`POST /clinical/records/segregated`) | ✅ | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` |
| **MA-04** | Leer listado clínico (`GET /clinical/records`) | ✅ Completo | ✅ 4 cols (mask) | ✅ 5 cols (gen) | ✅ Metadatos | ❌ `403` | ✅ Propio |
| **MA-04** | Leer expediente individual (`GET /clinical/records/{id}`) | ✅ Completo | ✅ 4 cols (mask) | ❌ `403` | ✅ Metadatos | ❌ `403` | ✅ Propio |
| **MA-04** | Ver expedientes sanitizados (`?include_sanitized=true`) | ❌ | ❌ | ❌ | ✅ | ❌ `403` | ❌ |
| **MA-04** | Actualizar expediente (`PATCH /clinical/records/{id}`) | ✅ | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` | ❌ `403` |
| **MB-02** | Exportar dataset Safe Harbor + $(k, l)$ (`/lifecycle/anonymized-export`) | ❌ `403` | ❌ `403` | ✅ | ❌ `403` | ❌ `403` | ❌ `403` |
| **MB-01** | Ejecutar barrido TTL (`POST /lifecycle/ttl/sweep`) | ❌ `403` | ❌ `403` | ❌ `403` | ✅ | ✅ | ❌ `403` |
| **MB-03/04** | Borrado certificado ARCO NIST SP 800-88 (`POST /lifecycle/arco/erase`) | ❌ `403` | ❌ `403` | ❌ `403` | ✅ | ❌ `403` | ❌ `403` |
| **MB-04** | Listar, descargar PDF/JSON y verificar SHA-256 (`/lifecycle/certificates*`) | ❌ `403` | ❌ `403` | ❌ `403` | ✅ | ❌ `403` | ❌ `403` |

---

## 5. Controles Transversales Aplicados a Todos los Roles

- **Timeout implícito por inactividad (backend):** Si transcurren 120 segundos sin actividad, el servidor revoca y rechaza el JWT (`401`) de forma totalmente implícita (sin contador visible ni manipulable en la interfaz) y el portal bloquea automáticamente la sesión al siguiente intento de operación.
- **Anti-escalación y trazabilidad SIEM (MC-01 a MC-04):** Todo acceso denegado (`403`), intento de *function creep* (propósito vacío o inválido), acceso masivo a expedientes o intento de fuerza bruta genera un evento estructurado **Syslog RFC 5424** (persistido en UTC y visualizado por defecto en **`America/Mexico_City`** con selector de huso horario en la consola SOC).
- **Acceso restringido a la Consola SIEM (`siem.tralaleritosmigajeros.uk`):** La consola SOC externa no utiliza las credenciales JWT del portal clínico; exige autenticación independiente mediante **Cloudflare Zero Trust Access (Email One-Time PIN)** restringida exclusivamente a **cuentas institucionales BUAP** (`@alumno.buap.mx` / `@correo.buap.mx`) autorizadas en la política *Solo Equipo SOC BUAP* (ver [hardening-cloudflare.md](hardening-cloudflare.md)).
- **OpenAPI / Swagger oculto por defecto:** `/docs`, `/redoc` y `/openapi.json` retornan `404` mientras `EXPOSE_OPENAPI_DOCS=false` (OWASP API9:2023).
- **Content Security Policy estricta:** El portal sirve `script-src 'self'; style-src 'self'` sin `unsafe-inline`.
