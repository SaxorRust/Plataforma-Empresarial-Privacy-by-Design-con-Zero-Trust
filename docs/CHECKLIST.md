# 📋 Checklist Maestro de Trazabilidad y Avance

- **Institución:** Benemérita Universidad Autónoma de Puebla (BUAP) — Facultad de Ciencias de la Computación (FCC)
- **Carrera:** Ingeniería en Ciberseguridad
- **Asignatura:** Privacidad y Seguridad de los Datos Personales (ICSA 252)
- **Proyecto Final:** Plataforma Empresarial Privacy-by-Design con Zero Trust y Auditoría SIEM
- **Equipo:** Ubaldo Edgar Gonzalez Flores · Jezreel Pérez Romero · Samuel Pérez Rodríguez
- **Fecha límite de entrega:** 1 de diciembre de 2026
- **Escenario y Stack:** Sistema de Gestión Hospitalaria · Python (`FastAPI`) + `PostgreSQL` · Docker (Linux nativo) · WebAuthn/Argon2id + HashiCorp Vault + OPA + Syslog RFC 5424 / SIEM Python
- **Dominio objetivo:** `tralaleritosmigajeros.uk` (vía `cloudflared` tunnel)

---

## 📊 Resumen de Avance Global

> **Fórmula de avance:** Cada ítem tiene un peso asignado. Suma los puntos de los ítems marcados como `[x]` para obtener el **% de avance total** (base 100%).

| Bloque | Peso Total | Completado | Avance del Bloque |
| :--- | :---: | :---: | :---: |
| **Fase 1:** Gobernanza Git, Entorno Base y Planeación | 10% | 0% | `0 / 10` |
| **Módulo A:** Gobernanza, Identidad, Bóveda y ABAC (20% rúbrica) | 20% | 0% | `0 / 20` |
| **Módulo B:** Ciclo de Vida, Desidentificación y NIST SP 800-88 (25% rúbrica) | 22% | 0% | `0 / 22` |
| **Módulo C:** Sandboxing, Syslog RFC 5424 y SIEM (25% rúbrica) | 22% | 0% | `0 / 22` |
| **Fase 5:** Pruebas Automatizadas, GitHub Actions y Cloudflare Tunnel | 12% | 0% | `0 / 12` |
| **Fase 6:** Documentación (MD/PDF) y Defensa Técnica (30% rúbrica) | 14% | 0% | `0 / 14` |
| **TOTAL GLOBAL** | **100%** | **0%** | **`0%`** |

---

## 1. Fase 1 — Gobernanza Git, Entorno Base y Planeación (10%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `F1-01` | [ ] | 2% | Confirmar escenario, stack tecnológico y asignación de roles (Ubaldo, Jezreel, Samuel → Int. 1, 2, 3) | `main` / Todos | Escenario y stack definidos; pendiente asignación final de roles |
| `F1-02` | [ ] | 2% | Definir estructura de ramas por rol y reglas de protección en `main` (infra crítica) | `main` | Ramas creadas en GitHub + flujo de PR definido |
| `F1-03` | [ ] | 3% | Levantar entorno base reproducible (`docker-compose.yml`, `.env.example`, redes aisladas) | `main` / Int. 2 | `docker compose up` levanta servicios base sin errores |
| `F1-04` | [ ] | 3% | Planeación formal del desarrollo (hitos diarios hacia el 1 de diciembre) | `main` / Todos | Cronograma en `docs/planeacion.md` |

---

## 2. Módulo A — Gobernanza, Minimización y Control de Acceso (20%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `MA-01` | [ ] | 5% | **Autenticación robusta:** FIDO2/WebAuthn (Passkeys) + respaldo Argon2id con *Salt* único + *Pepper* | Int. 2 | Registro y login funcionales; hash verificado en BD |
| `MA-02` | [ ] | 5% | **Segregación y bóveda (Vault):** Identificadores directos aislados de atributos sensibles | Int. 1 & 2 | Esquema segregado + intercambio solo vía tokens opacos |
| `MA-03` | [ ] | 5% | **Prevención de Function Creep (OPA/ABAC):** Validación de propósito declarado por consulta | Int. 1 | Consultas sin propósito válido devuelven `403 Forbidden` |
| `MA-04` | [ ] | 5% | **Minimización cuantitativa y cualitativa:** Filtrado de columnas y generalización según rol | Int. 1 | Respuestas API filtradas/enmascaradas por rol |

---

## 3. Módulo B — Ciclo de Vida, Desidentificación y Borrado Certificado (22%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `MB-01` | [ ] | 4% | **Retención temporal (TTL):** Tarea automatizada que purga registros/tokens expirados | Int. 1 | Job programado ejecutándose y limpiando registros vencidos |
| `MB-02` | [ ] | 6% | **Exportación desidentificada:** Método *Safe Harbor* (18 identificadores) + $k$-anonimato agregado con $l$-diversidad | Int. 1 | Dataset exportado validado sin PII directa y con $k,l$ verificados |
| `MB-03` | [ ] | 6% | **Derechos ARCO + NIST SP 800-88:** Cancelación/Supresión con sobrescritura segura (*Clear/Purge*) y limpieza de buffers en memoria | Int. 1 | Flujo completo de borrado irreversible comprobable en BD/bóveda |
| `MB-04` | [ ] | 6% | **Certificado de Sanitización:** Emisión automática en JSON y PDF firmado con hash `SHA-256` | Int. 1 | Archivos `.json` y `.pdf` generados y hash `SHA-256` verificable |

---

## 4. Módulo C — Sandboxing de Aplicación y Auditoría SIEM (22%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `MC-01` | [ ] | 6% | **Confinamiento del sistema:** Perfiles personalizados Seccomp-BPF y AppArmor (ej. bloqueo de `execve`, rutas restringidas) | Int. 2 | Perfil cargado en contenedor + prueba negativa (`Operation not permitted`) |
| `MC-02` | [ ] | 5% | **Centralización Syslog (RFC 5424):** Envío estructurado de eventos de auditoría al colector SIEM | Int. 3 | Eventos RFC 5424 recibidos e indexados en el SIEM |
| `MC-03` | [ ] | 5% | **Sanitización en ingesta (Regex):** Ofuscación automática de tarjetas, CURP, contraseñas antes de persistir | Int. 3 | Logs almacenados muestran valores enmascarados (`***`) |
| `MC-04` | [ ] | 6% | **Reglas de correlación temporal (mín. 2):** Detección de fuerza bruta + alerta crítica por consultas masivas | Int. 3 | Alertas disparadas y visibles en pruebas simuladas |

---

## 5. Fase 5 — Pruebas Automatizadas, GitHub Actions y Cloudflare (12%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `F5-01` | [ ] | 4% | **Suite de pruebas automatizadas:** Unitarias, integración, políticas ABAC, $k$-anonimato/$l$-diversidad, NIST 800-88 y correlación SIEM | Todos | `pytest` corriendo y en verde (`100% pass`) |
| `F5-02` | [ ] | 3% | **GitHub Actions (CI):** Pipeline en `.github/workflows/` ejecutando linter, tests y validación de seguridad en PRs a `main` | Int. 2 | Checks verdes en GitHub Actions |
| `F5-03` | [ ] | 3% | **Túnel `cloudflared`:** Configuración reproducible para exponer la plataforma local hacia `tralaleritosmigajeros.uk` | Int. 2 | Dominio resolviendo y sirviendo la app vía túnel cifrado |
| `F5-04` | [ ] | 2% | **Endurecimiento Cloudflare:** SSL/TLS Strict, reglas WAF/Rate Limiting, cabeceras de seguridad y políticas Zero Trust | Int. 2 & 3 | Verificación HTTPS, cabeceras y bloqueo de abuso en el dominio |

---

## 6. Fase 6 — Documentación (MD/PDF) y Defensa Técnica (14%)

| ID | Estado | Peso | Elemento / Entregable | Rama / Rol | Evidencia / Criterio de Verificación |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `F6-01` | [ ] | 5% | **Documentación del sistema (Markdown + PDF):** Arquitectura, diagramas, perfiles, evidencias de pruebas y certificados | Todos | Reporte técnico en `docs/` + archivo `.pdf` compilado |
| `F6-02` | [ ] | 5% | **Guías de Defensa Técnica personalizadas:** Material de estudio, flujo end-to-end y Q&A para **Jezreel**, **Samuel** y **Ubaldo** | Todos | Guías listas para repartir antes del 1 de diciembre |
| `F6-03` | [ ] | 4% | **Ensayo de demo en vivo (20 min):** Guion paso a paso de demostración de los 3 módulos | Todos | Simulación completa sin fallos antes del 1 de diciembre |

---

## 📝 Registro de Bitácora / Trazas de Avance

| Fecha | ID(s) Completados | Responsable | Commit / PR | Notas |
| :--- | :--- | :--- | :--- | :--- |
| 2026-11-21 | Inicialización | Equipo | `762babe` | Lectura de pliego técnico y `pendientes.txt`. |
| 2026-11-21 | Datos institucionales y stack base | Ubaldo | `93d3217` | Agregados `informacionInstitucional.txt`, `escenarioYtecnologias.txt` y copia PDF inicial. |
