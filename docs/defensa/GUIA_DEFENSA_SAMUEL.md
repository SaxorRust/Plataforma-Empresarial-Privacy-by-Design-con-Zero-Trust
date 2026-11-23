# Guía de Defensa Técnica — Samuel Pérez Rodríguez
## Rol: Integrante 3 — Analista SOC y Auditoría SIEM (`role/siem-soc`)

- **Asignatura:** Privacidad y Seguridad de los Datos Personales (BUAP FCC — ICSA 252)
- **Fecha de defensa:** 1 de diciembre de 2026
- **Módulos bajo tu responsabilidad:** `MC-02` (Centralización Syslog RFC 5424), `MC-03` (Sanitización Regex pre-persistencia), `MC-04` (Motor de Correlación Temporal y Consola SOC), `F5-01` (pruebas SIEM `test_siem_module_c.py` y `verify-siem-module-c.sh`) y operación SOC protegida por Cloudflare Zero Trust Access.

---

## 1. Tu Discurso Técnico (Resumen en 60 segundos)

> *"Mi responsabilidad fue construir la capa de observabilidad y detección temprana bajo **Zero Trust**: integré un emisor **Syslog RFC 5424** en toda la API hospitalaria conectado al colector SIEM por una red Docker interna aislada (`audit_net`), implementé un pipeline de **sanitización Regex previo a persistencia** para garantizar que jamás se guarden tarjetas (validadas con Luhn), CURP, NSS, contraseñas ni JWT en SQLite, y desarrollé un **motor de correlación temporal** con 3 reglas activas (fuerza bruta, consultas masivas CRÍTICAS y denegaciones reiteradas de OPA) visibles en nuestra Consola SOC protegida con Cloudflare Access OTP."*

---

## 2. Mapa de Archivos Clave que Debes Dominar

| Archivo | Qué hace exactamente |
| :--- | :--- |
| `services/api/app/audit/syslog_client.py` | `SyslogAuditClient`: ensambla tramas **RFC 5424** con `STRUCTURED-DATA` (`[audit@55555 ...]`), sanitiza `\r\n` contra *Log Forging* (CWE-117) y transmite por UDP/TCP a `zt-siem-collector:5514`. |
| `services/siem/app/rfc5424.py` | Parser estricto de mensajes Syslog RFC 5424 (PRI, facility/severity, versión, timestamp ISO-8601, hostname, app-name, procid, msgid, `STRUCTURED-DATA` y mensaje). |
| `services/siem/app/syslog_server.py` | Servidores asíncronos **UDP y TCP** (`asyncio`) escuchando en el puerto `5514` dentro de `audit_net`. |
| `services/siem/app/sanitizer.py` | Pipeline de ofuscación pre-persistencia (`***`): tarjetas bancarias (Regex + **algoritmo de Luhn**), CURP mexicana (18 chars), NSS (11 dígitos), JWT (`eyJ...`) y secretos/contraseñas en mensaje y `STRUCTURED-DATA`. |
| `services/siem/app/correlator.py` | `TemporalCorrelationEngine`: ventanas deslizantes con 3 reglas (`RULE-001` Fuerza Bruta `HIGH`, `RULE-002` Consultas Masivas `CRITICAL`, `RULE-003` Denegaciones OPA `HIGH`). |
| `services/siem/app/storage.py` | Persistencia en SQLite de eventos ya sanitizados y alertas correlacionadas con soporte de reconocimiento (`ACK`). |
| `services/siem/app/dashboard.py` y `main.py` | Consola SOC HTML y API REST (`/api/v1/events`, `/api/v1/alerts`, `/api/v1/alerts/{id}/ack`, `/api/v1/rules`, `/api/v1/stats`). |
| `tests/test_siem_module_c.py` y `infra/scripts/verify-siem-module-c.sh` | Pruebas reales UDP+TCP, inspección directa de la BD SQLite para comprobar ausencia de PII cruda y validación de disparo de las 3 reglas. |

---

## 3. Puntos Técnicos Críticos que Te Pueden Preguntar (Q&A de Jurado)

### P1. ¿Por qué eligieron Syslog RFC 5424 en lugar de texto plano o RFC 3164?
**Respuesta:** Porque **RFC 5424** soporta marcas de tiempo de alta precisión en UTC (ISO-8601), campos bien definidos (`APP-NAME`, `MSGID`) y bloques **`STRUCTURED-DATA`** (`[audit@55555 actor="..." role="..." action="..." outcome="..."]`), lo que permite parseo determinista sin ambigüedades para alimentar el motor de correlación temporal.

### P2. ¿Cómo previenen el ataque de *Log Forging / Log Injection* (CWE-117)?
**Respuesta:** En `SyslogAuditClient` eliminamos/escapamos saltos de línea (`\r`, `\n`), caracteres de control y comillas peligrosas dentro de `STRUCTURED-DATA` antes de construir la trama RFC 5424. Así un atacante no puede inyectar entradas falsas en el log manipulando un nombre de usuario o cabecera.

### P3. ¿Por qué la sanitización Regex ocurre *antes* de escribir en SQLite y no solo al mostrar en pantalla?
**Respuesta:** Por el principio de **Privacy-by-Design**: un log también puede filtrarse o ser inspeccionado por un analista SOC que no debe ver PII ni credenciales. Al sanitizar **en ingesta** (`services/siem/app/pipeline.py` → `sanitizer.py` → `storage.py`), garantizamos que la base de datos SQLite nunca almacena tarjetas, CURP, NSS, contraseñas ni JWT en texto claro (lo verificamos leyendo directamente las filas de SQLite en `test_siem_module_c.py`).

### P4. ¿Por qué validan tarjetas bancarias con el algoritmo de Luhn además de Regex?
**Respuesta:** Para reducir falsos positivos. En un hospital existen números de expediente, teléfonos o identificadores numéricos de 13 a 16 dígitos que no son tarjetas. Validar el dígito verificador de **Luhn** permite enmascarar con precisión números de tarjeta reales sin destruir identificadores operativos benignos.

### P5. Explica cómo funcionan tus 3 reglas de correlación temporal.
**Respuesta:** `TemporalCorrelationEngine` mantiene ventanas deslizantes por actor/origen en memoria:
1. **`RULE-001` (`BRUTE_FORCE_LOGIN`, `HIGH`):** $\ge 5$ eventos `AUTH_LOGIN_FAILED` en 60 segundos.
2. **`RULE-002` (`MASS_RECORD_ACCESS`, `CRITICAL`):** $\ge 10$ consultas clínicas o $\ge 25$ expedientes accedidos en 60 segundos por el mismo usuario (detecta exfiltración masiva).
3. **`RULE-003` (`REPEATED_POLICY_DENIAL`, `HIGH`):** $\ge 5$ eventos `OPA_POLICY_DENIED` en 120 segundos (detecta intentos insistentes de *Function Creep* o escalación).

### P6. ¿Qué ocurre si el SIEM está momentáneamente caído? ¿Se bloquea la atención médica en el hospital?
**Respuesta:** La transmisión Syslog de la API hacia `zt-siem-collector:5514` se realiza con timeout acotado y manejo seguro de excepciones para no tumbar la disponibilidad clínica, mientras que la política de autorización en OPA sí es estrictamente *Fail-Closed*. En paralelo, Docker mantiene `restart: unless-stopped` y healthchecks activos sobre el colector.

### P7. ¿Cómo evitan que un atacante externo acceda a la Consola SOC en `siem.tralaleritosmigajeros.uk`?
**Respuesta:** Con **defensa en profundidad**: el puerto de ingesta Syslog (`5514`) solo existe dentro de la red interna `audit_net` (inaccesible desde Internet), y el panel web (`:8080`) publicado por `cloudflared` está protegido por **Cloudflare Zero Trust Access**, que exige un código **One-Time PIN (OTP)** enviado únicamente a los correos autorizados de Ubaldo, Jezreel y Samuel.

### P8. ¿Qué diferencia hay entre una alerta abierta y una reconocida (`ACK`) en tu consola SOC?
**Respuesta:** Cuando se dispara una correlación, la alerta nace en estado abierto (`acknowledged = false`) destacando su severidad (`HIGH`/`CRITICAL`). El analista SOC puede investigar los eventos asociados y marcarla como atendida mediante `POST /api/v1/alerts/{id}/ack`, dejando trazabilidad del manejo del incidente.

### P9. ¿Cómo conviven el Rate Limiting de Cloudflare en `/auth/` y tu regla `RULE-001` de fuerza bruta?
**Respuesta:** Representan **defensa en profundidad en capas complementarias**: Cloudflare frena ráfagas volumétricas externas en el borde (`10 req / 10 s` por IP), mientras que `RULE-001` en el SIEM detecta intentos distribuidos o sostenidos a ritmo más bajo ($\ge 5$ fallos en 60 s por cuenta/actor) que pasarían por debajo del umbral de borde.

### P10. ¿Qué cobertura de pruebas tiene tu módulo SIEM?
**Respuesta:** `tests/test_siem_module_c.py` supera el **90% de cobertura** en el servicio SIEM, probando transmisión real por sockets UDP y TCP, parseo RFC 5424, enmascaramiento verificado directo en SQLite y disparo + `ACK` de las 3 reglas de correlación.

---

## 4. Tu Bloque en la Demo en Vivo (Minutos 13 a 18)

1. Abrir `https://siem.tralaleritosmigajeros.uk` y destacar la pantalla de **Cloudflare Zero Trust Access (OTP)** antes de entrar.
2. En la Consola SOC, mostrar los **eventos RFC 5424** generados durante los bloques de Ubaldo y Jezreel (`AUTH_LOGIN_SUCCESS`, `CLINICAL_RECORD_CREATED`, `OPA_POLICY_DENIED`, `LIFECYCLE_ARCO_ERASURE`).
3. Ejecutar prueba de **sanitización en ingesta** (o `./infra/scripts/verify-siem-module-c.sh`) demostrando que una CURP, tarjeta Luhn y contraseña enviadas en una trama aparecen como `***` en la consola y en SQLite.
4. Mostrar en vivo las alertas **`RULE-001`**, **`RULE-002` (`CRITICAL`)** y **`RULE-003`** disparadas en la consola y hacer clic en **`ACK`** para cerrar el ciclo de respuesta a incidentes.
