# Planeación de Desarrollo y Gobernanza Git

- **Institución:** BUAP — Facultad de Ciencias de la Computación (Ingeniería en Ciberseguridad)
- **Asignatura:** Privacidad y Seguridad de los Datos Personales (ICSA 252)
- **Fecha de inicio:** 21 de noviembre de 2026
- **Fecha límite de entrega y defensa:** **1 de diciembre de 2026**

---

## 1. Asignación de Roles y Estrategia de Ramas (Git Flow Simplificado)

La rama **`main`** contiene exclusivamente la infraestructura base probada, contratos de integración, perfiles validados y documentación aprobada. Todo desarrollo de módulo entra mediante **Pull Request** con CI en verde.

| Integrante | Rol Asignado | Rama de Trabajo | Responsabilidades Principales |
| :--- | :--- | :--- | :--- |
| **Jezreel Pérez Romero** | **Integrante 1** — Arquitecto de Privacidad y Ciclo de Vida | `role/privacidad-ciclo-vida` | Esquema segregado, motor ABAC/OPA (prevención de *Function Creep* + minimización), TTL automatizado, exportación *Safe Harbor* + $k$-anonimato + $l$-diversidad, flujo ARCO y borrado certificado NIST SP 800-88 (JSON + PDF SHA-256). |
| **Ubaldo Edgar Gonzalez Flores** | **Integrante 2** — Ingeniero de Seguridad en Aplicaciones y Sistemas | `role/seguridad-infra` | Orquestación Docker Zero Trust, aprovisionamiento Ubuntu Server 26.04.1 LTS, autenticación FIDO2/WebAuthn + Argon2id (`salt` + `pepper`), integración HashiCorp Vault (tokenización opaca), perfiles Seccomp-BPF/AppArmor, GitHub Actions y túnel `cloudflared`. |
| **Samuel Pérez Rodríguez** | **Integrante 3** — Analista SOC y Auditoría SIEM | `role/siem-soc` | Transporte Syslog RFC 5424, colector SIEM, pipeline de sanitización regex en ingesta (CURP, tarjetas, contraseñas), reglas de correlación temporal (fuerza bruta y consultas masivas) y suite de validación SOC. |

---

## 2. Cronograma Hito a Hito (21 Nov — 1 Dic 2026)

| Fecha | Fase / Hito | Entregables Clave | Responsables |
| :--- | :--- | :--- | :--- |
| **21–22 Nov** | **Fase 1: Base e Infraestructura** | `docker-compose.yml` segmentado, guía VM Ubuntu 26.04.1 LTS, ramas por rol, CI base en GitHub Actions, túnel `cloudflared` operativo. | Ubaldo (con apoyo de todos) |
| **23–24 Nov** | **Módulo A: Identidad, Bóveda y ABAC** | Registro/login WebAuthn + Argon2id, tokenización opaca con Vault, políticas OPA (`hospital_abac.rego`) con validación de propósito y minimización por rol. | Ubaldo + Jezreel |
| **25–26 Nov** | **Módulo B: Ciclo de Vida, Anonimización y NIST 800-88** | Jobs TTL, exportador *Safe Harbor* + $k$-anonimato + $l$-diversidad, flujo ARCO con sobrescritura segura, limpieza de buffers y certificados JSON/PDF con SHA-256. | Jezreel |
| **27–28 Nov** | **Módulo C: Sandboxing y SIEM** | Perfiles Seccomp-BPF y AppArmor activos en VM, ingesta Syslog RFC 5424 con regex, 2 reglas de correlación temporal activas + dashboard/alertas SIEM. | Ubaldo + Samuel |
| **29 Nov** | **Fase 5: Pruebas Integrales y Endurecimiento** | Suite `pytest` E2E en verde, CI completo, reglas WAF/Rate Limiting/Access en Cloudflare para `tralaleritosmigajeros.uk`. | Todos |
| **30 Nov** | **Fase 6: Documentación PDF y Defensa Técnica** | Reporte técnico completo (MD + PDF), diagramas de arquitectura, evidencias y guías personalizadas de defensa para **Jezreel**, **Samuel** y **Ubaldo** + ensayo de 20 min. | Todos |
| **1 Dic** | **Entrega Final y Demostración en Vivo** | Demo funcional de 20 minutos y defensa técnica del equipo. | **Jezreel, Samuel y Ubaldo** |
