/* ============================================================================
   Hospital Privacy-by-Design & Zero Trust — Client Logic (Vanilla JS)
   BUAP FCC · Ingeniería en Ciberseguridad (ICSA 252)
   Security:
   - Mandatory Zero Trust Authentication Gate (#auth-gate) before #app-shell
   - Zero hardcoded credentials or unauthenticated quick-login backdoors
   - Strict DOM manipulation (textContent / createElement), zero eval/innerHTML
   - Automatic DOM sanitization and lock on logout or HTTP 401
   ============================================================================ */

(function () {
  "use strict";

  const ROLE_DEFAULT_PURPOSE = {
    medico: "atencion_medica",
    enfermeria: "atencion_medica",
    analista: "investigacion_estadistica",
    auditor_arco: "ejercicio_arco",
    admin_sec: "mantenimiento_ttl",
    paciente: "acceso_titular",
    super_admin: "administracion_total",
  };

  const ROLE_DESCRIPTIONS = {
    medico: "Atención clínica completa: alta segregada en Vault+PostgreSQL, lectura/edición de expedientes y resolución PII bajo propósito atencion_medica.",
    enfermeria: "Asistencia clínica minimizada: lectura restringida de departamento y resumen clínico con token opaco enmascarado (pat_xxxx...yyyy).",
    analista: "Analítica poblacional: lecturas generalizadas (rango de edad, CP 2 dígitos) sin acceso individual y exportación HIPAA Safe Harbor + (k, l).",
    auditor_arco: "Cumplimiento y auditoría: evaluación OPA, barrido TTL, borrado certificado ARCO/NIST SP 800-88 y descarga/verificación SHA-256 de certificados.",
    admin_sec: "Operaciones de seguridad (SecOps): gestión de bóveda Vault, evaluación OPA y barrido TTL. Separación de funciones: acceso clínico bloqueado (403).",
    paciente: "Acceso de titular: consulta exclusiva de sus propios registros bajo propósito acceso_titular.",
    super_admin: "Super Administrador (Acceso Total): operación completa en Clínica/Vault, OPA/ABAC, Safe Harbor/(k, l), ARCO/NIST SP 800-88 y TTL con trazabilidad SIEM.",
  };

  const DEMO_COHORT = [
    {
      patient_pii: {
        full_name: "Carlos Mendoza Vega",
        curp: "MEVC850312HPLRNS01",
        nss: "41850312001",
        contact_email: "carlos.mendoza@ejemplo.mx",
      },
      clinical_data: {
        age_years: 34,
        zip_prefix: "72000",
        gender: "M",
        diagnosis_cie10: "I10",
        diagnosis_summary: "Hipertension arterial sistemica en control farmacologico.",
        department: "cardiologia",
        purpose_scope: "atencion_medica",
      },
    },
    {
      patient_pii: {
        full_name: "Roberto Sanchez Luna",
        curp: "SALR830719HPLRNS02",
        nss: "41830719002",
        contact_email: "roberto.sanchez@ejemplo.mx",
      },
      clinical_data: {
        age_years: 37,
        zip_prefix: "72010",
        gender: "M",
        diagnosis_cie10: "E11.9",
        diagnosis_summary: "Diabetes mellitus tipo 2 sin complicaciones agudas.",
        department: "medicina_interna",
        purpose_scope: "atencion_medica",
      },
    },
    {
      patient_pii: {
        full_name: "Miguel Torres Rojas",
        curp: "TORM810925HPLRNS03",
        nss: "41810925003",
        contact_email: "miguel.torres@ejemplo.mx",
      },
      clinical_data: {
        age_years: 32,
        zip_prefix: "72020",
        gender: "M",
        diagnosis_cie10: "J18.9",
        diagnosis_summary: "Neumonia adquirida en la comunidad en remision clinica.",
        department: "urgencias",
        purpose_scope: "atencion_medica",
      },
    },
    {
      patient_pii: {
        full_name: "Ana Sofia Herrera Ruiz",
        curp: "HERA790514MPLRNS04",
        nss: "42790514004",
        contact_email: "ana.herrera@ejemplo.mx",
      },
      clinical_data: {
        age_years: 44,
        zip_prefix: "72100",
        gender: "F",
        diagnosis_cie10: "I10",
        diagnosis_summary: "Monitoreo ambulatorio de presion arterial estable.",
        department: "cardiologia",
        purpose_scope: "atencion_medica",
      },
    },
    {
      patient_pii: {
        full_name: "Laura Patricia Gomez Diaz",
        curp: "GODL761108MPLRNS05",
        nss: "42761108005",
        contact_email: "laura.gomez@ejemplo.mx",
      },
      clinical_data: {
        age_years: 47,
        zip_prefix: "72130",
        gender: "F",
        diagnosis_cie10: "E11.9",
        diagnosis_summary: "Control metabolico trimestral con hemoglobina glucosilada.",
        department: "medicina_interna",
        purpose_scope: "atencion_medica",
      },
    },
    {
      patient_pii: {
        full_name: "Lucia Fernanda Castro Perez",
        curp: "CAPL750220MPLRNS06",
        nss: "42750220006",
        contact_email: "lucia.castro@ejemplo.mx",
      },
      clinical_data: {
        age_years: 41,
        zip_prefix: "72150",
        gender: "F",
        diagnosis_cie10: "G43.9",
        diagnosis_summary: "Cefalea migranosa sin aura en seguimiento neurologico.",
        department: "neurologia",
        purpose_scope: "atencion_medica",
      },
    },
  ];

  // Zero Trust: JWT kept strictly in memory (never in localStorage/sessionStorage)
  const state = {
    accessToken: null,
    user: null,
    amr: [],
    inactivityTimeoutSeconds: 120,
    lastActivityAt: 0,
    lastClinicalCount: 0,
  };

  let idleIntervalId = null;
  let idleWarningShown = false;
  let lastPointerActivityAt = 0;

  // --------------------------------------------------------------------------
  // Base64URL helpers for WebAuthn / FIDO2 ArrayBuffer conversions
  // --------------------------------------------------------------------------
  function base64UrlToUint8Array(base64Url) {
    const padding = "=".repeat((4 - (base64Url.length % 4)) % 4);
    const base64 = (base64Url + padding).replace(/-/g, "+").replace(/_/g, "/");
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
  }

  function arrayBufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  // --------------------------------------------------------------------------
  // DOM & Notification Helpers
  // --------------------------------------------------------------------------
  function byId(id) {
    return document.getElementById(id);
  }

  function showGateToast(message, variant) {
    const banner = byId("gate-toast");
    const textNode = byId("gate-toast-text");
    if (!banner || !textNode) return;
    banner.className = "toast-banner toast-" + (variant || "err");
    textNode.textContent = message;
  }

  function hideGateToast() {
    const banner = byId("gate-toast");
    if (banner) banner.className = "toast-banner hidden";
  }

  function showToast(message, variant) {
    const banner = byId("global-toast");
    const textNode = byId("global-toast-text");
    if (!banner || !textNode) return;
    banner.className = "toast-banner toast-" + (variant || "ok");
    textNode.textContent = message;
  }

  function hideToast() {
    const banner = byId("global-toast");
    if (banner) banner.className = "toast-banner hidden";
  }

  function getSelectedPurpose() {
    const sel = byId("global-purpose-select");
    return sel ? sel.value : "atencion_medica";
  }

  function setSelectedPurpose(purposeValue) {
    const sel = byId("global-purpose-select");
    if (sel) sel.value = purposeValue;
  }

  function logInspector(method, path, status, reqId, payload) {
    const meta = byId("last-request-meta");
    const out = byId("live-response-inspector");
    if (meta) {
      meta.textContent = method + " " + path + " → HTTP " + status + (reqId ? " | X-Request-ID: " + reqId : "");
      meta.className = "badge " + (status >= 200 && status < 300 ? "badge-ok" : status === 403 ? "badge-warn" : "badge-danger");
    }
    if (out) {
      out.textContent = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
    }
  }

  // --------------------------------------------------------------------------
  // Zero Trust Gate Control: Lock / Unlock Workspace & Role-Based UI Filtering
  // --------------------------------------------------------------------------
  function applyRoleVisibility(role) {
    const navButtons = document.querySelectorAll(".nav-btn");
    navButtons.forEach(function (btn) {
      const allowedRoles = (btn.getAttribute("data-roles") || "").split(",");
      const allowed = allowedRoles.includes(role);
      btn.classList.toggle("is-hidden", !allowed);
    });

    const scopeEl = byId("role-scope-summary");
    if (scopeEl) {
      scopeEl.textContent = ROLE_DESCRIPTIONS[role] || "Acceso gobernado por OPA/ABAC.";
    }

    // Role-specific operational panels (Separación de funciones Zero Trust)
    const isSuperAdmin = role === "super_admin";
    const isMedico = role === "medico" || isSuperAdmin;
    const isAdmin = role === "admin_sec" || isSuperAdmin;
    const isAuditor = role === "auditor_arco" || isSuperAdmin;

    const cardSegregated = byId("card-segregated-admission");
    if (cardSegregated) cardSegregated.classList.toggle("is-hidden", !isMedico);

    const btnSeedCohort = byId("btn-seed-clinical-cohort");
    if (btnSeedCohort) btnSeedCohort.classList.toggle("is-hidden", !isMedico);

    const cardVault = byId("card-vault-inspector");
    if (cardVault) cardVault.classList.toggle("is-hidden", !(isMedico || isAdmin || isAuditor));

    // Filtrado granular dentro de Bóveda Vault:
    // - Estado Vault: admin_sec, auditor_arco, super_admin (NO medico)
    // - Rotar Llave Transit: admin_sec, super_admin (NO medico ni auditor_arco)
    // - Detokenizar PII: SOLO medico y super_admin (NO admin_sec ni auditor_arco)
    const btnVaultStatus = byId("btn-vault-status");
    if (btnVaultStatus) btnVaultStatus.classList.toggle("is-hidden", !(isAdmin || isAuditor));

    const btnVaultRotate = byId("btn-vault-rotate");
    if (btnVaultRotate) btnVaultRotate.classList.toggle("is-hidden", !isAdmin);

    const vaultDetokSection = byId("vault-detokenize-section");
    if (vaultDetokSection) vaultDetokSection.classList.toggle("is-hidden", !isMedico);

    const vaultDesc = byId("vault-inspector-desc");
    if (vaultDesc) {
      if (isSuperAdmin) {
        vaultDesc.textContent = "Acceso total de bóveda: estado, rotación Transit AEAD y detokenización PII auditada en SIEM.";
      } else if (role === "medico") {
        vaultDesc.textContent = "Resolución de identidad clínica (detokenización PII) bajo control de rol medico y trazabilidad SIEM.";
      } else if (role === "admin_sec") {
        vaultDesc.textContent = "Operaciones SecOps de bóveda (estado y rotación de llave Transit). Separación de funciones: sin acceso a PII.";
      } else if (role === "auditor_arco") {
        vaultDesc.textContent = "Auditoría de salud de bóveda HashiCorp Vault (solo lectura de estado, sin detokenización PII).";
      }
    }

    const optSuper = byId("opt-admin-role-super");
    if (optSuper) {
      optSuper.disabled = !isSuperAdmin;
      optSuper.hidden = !isSuperAdmin;
    }

    const cardArco = byId("card-arco-erasure");
    if (cardArco) cardArco.classList.toggle("is-hidden", !isAuditor);

    const cardCerts = byId("card-certificates-list");
    if (cardCerts) cardCerts.classList.toggle("is-hidden", !isAuditor);
  }

  function setPasswordVisibility(inputEl, toggleBtn, visible) {
    if (!inputEl || !toggleBtn) return;
    inputEl.type = visible ? "text" : "password";
    toggleBtn.setAttribute("aria-pressed", visible ? "true" : "false");
    const label = visible ? "Ocultar contraseña" : "Mostrar contraseña";
    toggleBtn.setAttribute("aria-label", label);
    toggleBtn.setAttribute("title", label);
    const eyeIcon = toggleBtn.querySelector(".icon-eye");
    const eyeOffIcon = toggleBtn.querySelector(".icon-eye-off");
    if (eyeIcon) eyeIcon.classList.toggle("is-hidden", visible);
    if (eyeOffIcon) eyeOffIcon.classList.toggle("is-hidden", !visible);
  }

  function resetPasswordVisibility() {
    document.querySelectorAll(".password-toggle-btn[data-password-target]").forEach(function (btn) {
      const targetId = btn.getAttribute("data-password-target");
      const inputEl = targetId ? byId(targetId) : null;
      setPasswordVisibility(inputEl, btn, false);
    });
  }

  function cryptoRandomIndex(max) {
    if (max <= 1) return 0;
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    let value;
    do {
      window.crypto.getRandomValues(buf);
      value = buf[0];
    } while (value >= limit);
    return value % max;
  }

  function generateSecurePassword(length) {
    const targetLen = Math.max(12, length || 16);
    const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const lower = "abcdefghijkmnopqrstuvwxyz";
    const digits = "23456789";
    const symbols = "!@#$%^&*()-_=+[]{}?";
    const all = upper + lower + digits + symbols;

    const chars = [];
    // Garantizar al menos 2 caracteres de cada clase exigida por OWASP A07
    for (let i = 0; i < 2; i += 1) {
      chars.push(upper[cryptoRandomIndex(upper.length)]);
      chars.push(lower[cryptoRandomIndex(lower.length)]);
      chars.push(digits[cryptoRandomIndex(digits.length)]);
      chars.push(symbols[cryptoRandomIndex(symbols.length)]);
    }
    while (chars.length < targetLen) {
      chars.push(all[cryptoRandomIndex(all.length)]);
    }
    // Mezcla Fisher-Yates con entropía criptográfica
    for (let i = chars.length - 1; i > 0; i -= 1) {
      const j = cryptoRandomIndex(i + 1);
      const tmp = chars[i];
      chars[i] = chars[j];
      chars[j] = tmp;
    }
    return chars.join("");
  }

  let copyPasswordResetTimer = null;

  function syncRegCopyButtonState() {
    const copyBtn = byId("btn-copy-reg-password");
    const copyLabel = byId("copy-reg-password-label");
    const regInput = byId("reg-password");
    if (!copyBtn || !regInput) return;
    const hasValue = regInput.value.length > 0;
    copyBtn.disabled = !hasValue;
    if (!hasValue && copyLabel) {
      copyLabel.textContent = "Copiar";
    }
  }

  function formatCountdown(seconds) {
    const safe = Math.max(0, Math.floor(seconds));
    const mins = String(Math.floor(safe / 60)).padStart(2, "0");
    const secs = String(safe % 60).padStart(2, "0");
    return mins + ":" + secs;
  }

  function updateIdleTimerBadge(remainingSeconds) {
    const badge = byId("session-idle-timer");
    if (!badge) return;
    badge.textContent = "Inactividad: " + formatCountdown(remainingSeconds);
    if (remainingSeconds <= 30) {
      badge.className = "badge badge-warn";
    } else {
      badge.className = "badge badge-info";
    }
  }

  function recordUserActivity() {
    if (!state.accessToken) return;
    state.lastActivityAt = Date.now();
    idleWarningShown = false;
    updateIdleTimerBadge(state.inactivityTimeoutSeconds);
  }

  function stopInactivityMonitor() {
    if (idleIntervalId !== null) {
      clearInterval(idleIntervalId);
      idleIntervalId = null;
    }
    idleWarningShown = false;
  }

  async function expireSessionByInactivity() {
    stopInactivityMonitor();
    const activeToken = state.accessToken;
    state.accessToken = null;
    if (activeToken) {
      try {
        await fetch("/auth/logout", {
          method: "POST",
          headers: { Authorization: "Bearer " + activeToken },
        });
      } catch (_) {
        // Best-effort revocation; backend also enforces 2-minute inactivity timeout.
      }
    }
    lockWorkspace("Sesión cerrada automáticamente tras 2 minutos de inactividad (Zero Trust).");
  }

  function startInactivityMonitor(timeoutSeconds) {
    stopInactivityMonitor();
    state.inactivityTimeoutSeconds = timeoutSeconds && timeoutSeconds > 0 ? timeoutSeconds : 120;
    state.lastActivityAt = Date.now();
    idleWarningShown = false;
    updateIdleTimerBadge(state.inactivityTimeoutSeconds);

    idleIntervalId = setInterval(function () {
      if (!state.accessToken) {
        stopInactivityMonitor();
        return;
      }
      const elapsedSec = (Date.now() - state.lastActivityAt) / 1000;
      const remainingSec = state.inactivityTimeoutSeconds - elapsedSec;
      if (remainingSec <= 0) {
        expireSessionByInactivity();
        return;
      }
      updateIdleTimerBadge(remainingSec);
      if (remainingSec <= 30 && !idleWarningShown) {
        idleWarningShown = true;
        showToast(
          "Advertencia Zero Trust: tu sesión se cerrará en " + Math.ceil(remainingSec) + "s por inactividad.",
          "warn"
        );
      }
    }, 1000);
  }

  function clearSensitiveDom() {
    byId("auth-me-output").textContent = "";
    byId("vault-inspector-output").textContent = "Sin operaciones activas.";
    byId("opa-decision-output").textContent = "Sin evaluación activa.";
    byId("export-metrics-output").textContent = "Sin exportación activa.";
    byId("ttl-output").textContent = "Sin consulta TTL activa.";
    byId("live-response-inspector").textContent = "Sesión cerrada.";
    byId("clinical-records-tbody").replaceChildren();
    byId("export-records-tbody").replaceChildren();
    byId("certificates-tbody").replaceChildren();
    byId("webauthn-creds-tbody").replaceChildren();
    byId("policy-allowed-fields").replaceChildren();
    const adminUsersBody = byId("admin-users-tbody");
    if (adminUsersBody) adminUsersBody.replaceChildren();
    byId("login-password").value = "";
    byId("reg-password").value = "";
    const adminNewPass = byId("admin-new-password");
    if (adminNewPass) adminNewPass.value = "";
    state.lastClinicalCount = 0;
    resetPasswordVisibility();
    syncRegCopyButtonState();
  }

  async function unlockWorkspace(tokenData) {
    state.accessToken = tokenData.access_token;
    state.user = tokenData.user;
    state.amr = tokenData.amr || ["pwd"];
    const idleSecs = tokenData.inactivity_timeout_seconds || 120;

    // Verify token directly against /auth/me before showing the application shell
    const meRes = await apiRequest("GET", "/auth/me");
    if (!meRes.ok) {
      lockWorkspace("No se pudo verificar la sesión en /auth/me.");
      return false;
    }

    hideGateToast();
    resetPasswordVisibility();
    byId("session-user-label").textContent = state.user.username + " (" + state.amr.join("+") + ")";
    byId("session-role-badge").textContent = state.user.role;
    setSelectedPurpose(ROLE_DEFAULT_PURPOSE[state.user.role] || "atencion_medica");
    applyRoleVisibility(state.user.role);
    startInactivityMonitor(meRes.data.inactivity_timeout_seconds || idleSecs);

    byId("auth-gate").classList.add("is-hidden");
    byId("app-shell").classList.remove("is-hidden");
    switchTab("tab-auth");

    byId("auth-me-output").textContent = JSON.stringify(meRes.data, null, 2);
    await refreshTelemetry();
    await refreshWebAuthnCredentials();
    showToast(
      "Identidad verificada: " + state.user.username + " [rol=" + state.user.role + ", amr=" + state.amr.join("+") + "]",
      "ok"
    );
    return true;
  }

  function lockWorkspace(reasonMessage) {
    stopInactivityMonitor();
    state.accessToken = null;
    state.user = null;
    state.amr = [];
    clearSensitiveDom();
    hideToast();
    byId("app-shell").classList.add("is-hidden");
    byId("auth-gate").classList.remove("is-hidden");
    if (reasonMessage) {
      showGateToast(reasonMessage, "warn");
    }
  }

  // --------------------------------------------------------------------------
  // Unified API Fetch Wrapper (Attaches Bearer JWT + X-Purpose header)
  // --------------------------------------------------------------------------
  async function apiRequest(method, path, options) {
    const opts = options || {};
    const headers = Object.assign({}, opts.headers || {});

    if (state.accessToken && !opts.skipAuth) {
      headers["Authorization"] = "Bearer " + state.accessToken;
      recordUserActivity();
    }

    const purpose = opts.purpose !== undefined ? opts.purpose : getSelectedPurpose();
    if (purpose !== null && purpose !== "") {
      headers["X-Purpose"] = purpose;
    }

    let body = undefined;
    if (opts.json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.json);
    }

    const response = await fetch(path, {
      method: method,
      headers: headers,
      body: body,
    });

    const reqId = response.headers.get("x-request-id") || "";
    const contentType = response.headers.get("content-type") || "";
    let data = null;

    if (response.status !== 204) {
      if (contentType.includes("application/json")) {
        data = await response.json();
      } else {
        data = await response.text();
      }
    }

    logInspector(method, path, response.status, reqId, data || { status: response.status });

    // Zero Trust: if an authenticated call returns 401, immediately lock workspace
    if (response.status === 401 && !opts.skipAuth && state.accessToken) {
      lockWorkspace("Tu sesión JWT expiró o fue revocada. Autentícate nuevamente.");
    }

    return {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      data: data,
    };
  }

  // --------------------------------------------------------------------------
  // Navigation & Telemetry
  // --------------------------------------------------------------------------
  function switchTab(tabId) {
    document.querySelectorAll(".nav-btn").forEach(function (btn) {
      btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
    });
    document.querySelectorAll(".tab-panel").forEach(function (panel) {
      panel.classList.toggle("active", panel.id === tabId);
    });
  }

  function configureSiemLink() {
    const link = byId("link-siem-console");
    if (!link) return;
    const host = window.location.hostname;
    if (host.endsWith("tralaleritosmigajeros.uk")) {
      link.href = "https://siem.tralaleritosmigajeros.uk";
    } else {
      link.href = window.location.protocol + "//" + host + ":8080";
    }
  }

  async function refreshGateHealth() {
    const pill = byId("gate-health-pill");
    if (!pill) return;
    try {
      const resp = await fetch("/health");
      if (resp.ok) {
        pill.textContent = "API ONLINE";
        pill.className = "badge badge-ok";
      } else {
        pill.textContent = "API ERROR";
        pill.className = "badge badge-danger";
      }
    } catch (_err) {
      pill.textContent = "OFFLINE";
      pill.className = "badge badge-danger";
    }
  }

  async function refreshTelemetry() {
    try {
      const [healthResp, edgeResp] = await Promise.all([
        fetch("/health"),
        fetch("/edge-check"),
      ]);
      if (healthResp.ok) {
        const h = await healthResp.json();
        byId("tel-api-status").textContent = h.status.toUpperCase();
        byId("tel-api-env").textContent = h.environment + " · seccomp";
      }
      if (edgeResp.ok) {
        const e = await edgeResp.json();
        const edgeBadge = byId("tel-edge-badge");
        const edgeHost = byId("tel-edge-host");
        if (e.via_cloudflare) {
          edgeBadge.textContent = "CF TUNNEL";
          edgeBadge.className = "badge badge-ok";
          edgeHost.textContent = e.cf_ray || e.host || "cloudflare";
        } else {
          edgeBadge.textContent = "LOOPBACK";
          edgeBadge.className = "badge badge-info";
          edgeHost.textContent = e.host || "127.0.0.1:8000";
        }
      }
    } catch (_err) {
      byId("tel-api-status").textContent = "OFFLINE";
      byId("tel-api-status").className = "badge badge-danger";
    }
  }

  // --------------------------------------------------------------------------
  // Authentication Flows (Argon2id + WebAuthn Passkeys + Logout)
  // --------------------------------------------------------------------------
  async function handlePasswordLogin(username, password) {
    const res = await apiRequest("POST", "/auth/login", {
      json: { username: username, password: password },
      skipAuth: true,
    });

    if (!res.ok) {
      const detail = res.data && res.data.detail ? res.data.detail : "Credenciales inválidas.";
      showGateToast("Acceso denegado (HTTP " + res.status + "): " + detail, "err");
      return false;
    }

    return unlockWorkspace(res.data);
  }

  async function handleLogout() {
    if (state.accessToken) {
      await apiRequest("POST", "/auth/logout");
    }
    lockWorkspace("Sesión cerrada y JWT revocado en el servidor (jti invalidado).");
  }

  async function refreshCurrentUser() {
    const res = await apiRequest("GET", "/auth/me");
    if (res.ok) {
      byId("auth-me-output").textContent = JSON.stringify(res.data, null, 2);
      showToast("Sesión JWT activa y verificada en /auth/me.", "ok");
    }
  }

  async function refreshWebAuthnCredentials() {
    const tbody = byId("webauthn-creds-tbody");
    tbody.replaceChildren();
    if (!state.accessToken) return;

    const res = await apiRequest("GET", "/auth/webauthn/credentials");
    if (!res.ok || !Array.isArray(res.data) || res.data.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.textContent = "No tienes Passkeys FIDO2 registradas todavía.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    res.data.forEach(function (cred) {
      const tr = document.createElement("tr");

      const tdId = document.createElement("td");
      tdId.className = "mono-cell";
      tdId.textContent = cred.credential_id.slice(0, 22) + "...";
      tr.appendChild(tdId);

      const tdCount = document.createElement("td");
      tdCount.className = "mono-cell";
      tdCount.textContent = String(cred.sign_count);
      tr.appendChild(tdCount);

      const tdTrans = document.createElement("td");
      tdTrans.textContent = (cred.transports || []).join(", ") || "internal";
      tr.appendChild(tdTrans);

      const tdAct = document.createElement("td");
      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "btn btn-danger btn-sm";
      delBtn.textContent = "Revocar";
      delBtn.addEventListener("click", async function () {
        const delRes = await apiRequest("DELETE", "/auth/webauthn/credentials/" + encodeURIComponent(cred.credential_id));
        if (delRes.status === 204) {
          showToast("Passkey FIDO2 revocada correctamente.", "ok");
          await refreshWebAuthnCredentials();
        }
      });
      tdAct.appendChild(delBtn);
      tr.appendChild(tdAct);

      tbody.appendChild(tr);
    });
  }

  async function registerWebAuthnPasskey() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      showToast("Tu navegador o contexto actual no soporta WebAuthn (requiere HTTPS o localhost).", "err");
      return;
    }

    const beginRes = await apiRequest("POST", "/auth/webauthn/register/begin");
    if (!beginRes.ok) {
      showToast("Error al iniciar registro WebAuthn: " + JSON.stringify(beginRes.data), "err");
      return;
    }

    const pubKeyOpts = beginRes.data.options;
    pubKeyOpts.challenge = base64UrlToUint8Array(pubKeyOpts.challenge);
    pubKeyOpts.user.id = base64UrlToUint8Array(pubKeyOpts.user.id);
    if (Array.isArray(pubKeyOpts.excludeCredentials)) {
      pubKeyOpts.excludeCredentials = pubKeyOpts.excludeCredentials.map(function (item) {
        return Object.assign({}, item, { id: base64UrlToUint8Array(item.id) });
      });
    }

    try {
      const cred = await navigator.credentials.create({ publicKey: pubKeyOpts });
      const payload = {
        credential: {
          id: cred.id,
          rawId: arrayBufferToBase64Url(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON: arrayBufferToBase64Url(cred.response.clientDataJSON),
            attestationObject: arrayBufferToBase64Url(cred.response.attestationObject),
            transports: cred.response.getTransports ? cred.response.getTransports() : ["internal"],
          },
        },
      };

      const completeRes = await apiRequest("POST", "/auth/webauthn/register/complete", { json: payload });
      if (completeRes.ok) {
        showToast("Passkey FIDO2/WebAuthn registrada con éxito.", "ok");
        await refreshWebAuthnCredentials();
        await refreshCurrentUser();
      } else {
        showToast("Fallo al verificar Passkey: " + (completeRes.data.detail || "Error"), "err");
      }
    } catch (err) {
      showToast("Operación WebAuthn cancelada: " + err.message, "warn");
    }
  }

  async function loginWithWebAuthnPasskey() {
    const username = byId("login-username").value.trim();
    if (!username) {
      showGateToast("Ingresa tu nombre de usuario para solicitar el reto FIDO2.", "warn");
      return;
    }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      showGateToast("WebAuthn no disponible en este contexto (requiere HTTPS o localhost).", "err");
      return;
    }

    const beginRes = await apiRequest("POST", "/auth/webauthn/login/begin", {
      json: { username: username },
      skipAuth: true,
    });
    if (!beginRes.ok) {
      showGateToast(beginRes.data && beginRes.data.detail ? beginRes.data.detail : "Sin Passkeys para este usuario.", "warn");
      return;
    }

    const reqOpts = beginRes.data.options;
    reqOpts.challenge = base64UrlToUint8Array(reqOpts.challenge);
    if (Array.isArray(reqOpts.allowCredentials)) {
      reqOpts.allowCredentials = reqOpts.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: base64UrlToUint8Array(c.id) });
      });
    }

    try {
      const assertion = await navigator.credentials.get({ publicKey: reqOpts });
      const completeRes = await apiRequest("POST", "/auth/webauthn/login/complete", {
        skipAuth: true,
        json: {
          username: username,
          credential: {
            id: assertion.id,
            rawId: arrayBufferToBase64Url(assertion.rawId),
            type: assertion.type,
            response: {
              clientDataJSON: arrayBufferToBase64Url(assertion.response.clientDataJSON),
              authenticatorData: arrayBufferToBase64Url(assertion.response.authenticatorData),
              signature: arrayBufferToBase64Url(assertion.response.signature),
              userHandle: assertion.response.userHandle
                ? arrayBufferToBase64Url(assertion.response.userHandle)
                : null,
            },
          },
        },
      });

      if (completeRes.ok) {
        await unlockWorkspace(completeRes.data);
      } else {
        showGateToast("Fallo en verificación FIDO2: " + (completeRes.data.detail || "Rechazado"), "err");
      }
    } catch (err) {
      showGateToast("Autenticación FIDO2 cancelada: " + err.message, "warn");
    }
  }

  // --------------------------------------------------------------------------
  // TAB 2: Clinical Records, Segregated Vault Admission & Role Minimization
  // --------------------------------------------------------------------------
  function renderPolicyBanner(policy) {
    const summary = byId("policy-meta-summary");
    const pillsWrap = byId("policy-allowed-fields");
    pillsWrap.replaceChildren();

    if (!policy) {
      summary.textContent = "Sin metadatos de política activa.";
      return;
    }

    summary.textContent =
      "rol=" +
      policy.role +
      " | X-Purpose=" +
      policy.purpose +
      " | generalización=" +
      (policy.generalized ? "SÍ (rangos/prefijos)" : "NO") +
      " | token_enmascarado=" +
      (policy.masked_token ? "SÍ" : "NO") +
      " | OPA v" +
      policy.policy_version;

    (policy.allowed_fields || []).forEach(function (field) {
      const span = document.createElement("span");
      span.className = "field-pill";
      span.textContent = field;
      pillsWrap.appendChild(span);
    });
  }

  function renderClinicalTable(records, policy) {
    const thead = byId("clinical-records-thead");
    const tbody = byId("clinical-records-tbody");
    thead.replaceChildren();
    tbody.replaceChildren();

    const cols =
      policy && Array.isArray(policy.allowed_fields) && policy.allowed_fields.length
        ? policy.allowed_fields
        : records.length
        ? Object.keys(records[0])
        : ["record_id", "opaque_patient_token", "department", "diagnosis_cie10"];

    const trHead = document.createElement("tr");
    cols.forEach(function (col) {
      const th = document.createElement("th");
      th.textContent = col;
      trHead.appendChild(th);
    });
    const thActions = document.createElement("th");
    thActions.textContent = "Operaciones Zero Trust";
    trHead.appendChild(thActions);
    thead.appendChild(trHead);

    if (!records.length) {
      const trEmpty = document.createElement("tr");
      const tdEmpty = document.createElement("td");
      tdEmpty.colSpan = cols.length + 1;
      tdEmpty.textContent = "No hay expedientes clínicos visibles para esta consulta.";
      trEmpty.appendChild(tdEmpty);
      tbody.appendChild(trEmpty);
      return;
    }

    records.forEach(function (rec) {
      const tr = document.createElement("tr");
      cols.forEach(function (col) {
        const td = document.createElement("td");
        if (col.includes("id") || col.includes("token") || col.includes("cie10") || col.includes("zip")) {
          td.className = "mono-cell";
        }
        const val = rec[col];
        td.textContent = val === null || val === undefined ? "—" : String(val);
        tr.appendChild(td);
      });

      const tdAct = document.createElement("td");
      const btnWrap = document.createElement("div");
      btnWrap.className = "btn-row btn-row-flush";

      if (rec.record_id && state.user && (state.user.role === "medico" || state.user.role === "super_admin")) {
        const btnPii = document.createElement("button");
        btnPii.type = "button";
        btnPii.className = "btn btn-secondary btn-sm";
        btnPii.textContent = "Resolver PII (Vault)";
        btnPii.addEventListener("click", function () {
          resolveRecordIdentity(rec.record_id, rec.opaque_patient_token);
        });
        btnWrap.appendChild(btnPii);
      }

      if (rec.opaque_patient_token && !String(rec.opaque_patient_token).includes("...") && state.user && (state.user.role === "auditor_arco" || state.user.role === "super_admin")) {
        const btnArco = document.createElement("button");
        btnArco.type = "button";
        btnArco.className = "btn btn-danger btn-sm";
        btnArco.textContent = "Enviar a ARCO";
        btnArco.addEventListener("click", function () {
          byId("arco-token").value = rec.opaque_patient_token;
          switchTab("tab-arco");
          showToast("Token " + rec.opaque_patient_token + " cargado en el formulario de Borrado ARCO NIST SP 800-88.", "ok");
        });
        btnWrap.appendChild(btnArco);
      }

      tdAct.appendChild(btnWrap);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });
  }

  async function loadClinicalRecords() {
    const dept = byId("filter-dept").value.trim();
    const incSan = byId("filter-include-sanitized").checked;
    const params = new URLSearchParams();
    if (dept) params.set("department", dept);
    if (incSan) params.set("include_sanitized", "true");

    const url = "/clinical/records" + (params.toString() ? "?" + params.toString() : "");
    const res = await apiRequest("GET", url);

    if (!res.ok) {
      const detail = res.data && res.data.detail ? res.data.detail : "Acceso denegado";
      showToast("HTTP " + res.status + ": " + detail, res.status === 403 ? "warn" : "err");
      byId("policy-meta-summary").textContent = "DENEGADO POR OPA (HTTP " + res.status + "): " + detail;
      byId("policy-allowed-fields").replaceChildren();
      renderClinicalTable([], null);
      return;
    }

    state.lastClinicalCount = res.data.count || 0;
    renderPolicyBanner(res.data.policy);
    renderClinicalTable(res.data.records || [], res.data.policy);
    showToast("Consulta autorizada por OPA: " + res.data.count + " expedientes proyectados con minimización MA-04.", "ok");
  }

  async function resolveRecordIdentity(recordId, tokenHint) {
    if (tokenHint && !String(tokenHint).includes("...")) {
      byId("vault-inspect-token").value = tokenHint;
    }
    const res = await apiRequest("GET", "/clinical/records/" + encodeURIComponent(recordId) + "/patient-identity");
    byId("vault-inspector-output").textContent = JSON.stringify(res.data, null, 2);
    if (res.ok) {
      showToast("PII detokenizada desde HashiCorp Vault con doble control OPA + Vault.", "ok");
    } else {
      showToast("Detokenización bloqueada (HTTP " + res.status + "): " + (res.data.detail || "No autorizado"), "warn");
    }
  }

  let cohortSeedInProgress = false;

  async function seedClinicalCohort() {
    if (cohortSeedInProgress) return;
    if (state.lastClinicalCount > 0) {
      const proceed = window.confirm(
        "Ya existen " +
          state.lastClinicalCount +
          " expedientes clínicos registrados. ¿Deseas insertar 6 pacientes de demostración adicionales?"
      );
      if (!proceed) return;
    }

    const seedBtn = byId("btn-seed-clinical-cohort");
    cohortSeedInProgress = true;
    if (seedBtn) seedBtn.disabled = true;

    let created = 0;
    try {
      for (let i = 0; i < DEMO_COHORT.length; i++) {
        const res = await apiRequest("POST", "/clinical/records/segregated", {
          json: DEMO_COHORT[i],
          purpose: "atencion_medica",
        });
        if (res.status === 201) {
          created++;
          byId("vault-inspect-token").value = res.data.opaque_patient_token;
        }
      }
      if (created > 0) {
        showToast("Cohorte clínica de " + created + " pacientes creada (PII aislada en Vault + atributos en PostgreSQL).", "ok");
        await loadClinicalRecords();
      } else {
        showToast("No se pudo crear la cohorte (verifica rol medico/super_admin y propósito atencion_medica).", "warn");
      }
    } finally {
      cohortSeedInProgress = false;
      if (seedBtn) seedBtn.disabled = false;
    }
  }

  // --------------------------------------------------------------------------
  // TAB 3: OPA / ABAC Policy Simulator
  // --------------------------------------------------------------------------
  async function runOpaSimulation() {
    const payload = {
      role: byId("opa-sim-role").value,
      purpose: byId("opa-sim-purpose").value,
      action: byId("opa-sim-action").value,
      resource_purpose: byId("opa-sim-res-purpose").value,
      is_sanitized: byId("opa-sim-sanitized").checked,
      resource_owner_match: byId("opa-sim-owner").checked,
    };

    const res = await apiRequest("POST", "/clinical/policy/evaluate", { json: payload });
    const badge = byId("opa-decision-badge");
    const out = byId("opa-decision-output");
    out.textContent = JSON.stringify(res.data, null, 2);

    if (res.ok) {
      if (res.data.allow) {
        badge.textContent = "ALLOW (AUTORIZADO)";
        badge.className = "badge badge-ok";
        showToast("Decisión OPA: ALLOW (" + res.data.allowed_fields.length + " columnas permitidas).", "ok");
      } else {
        badge.textContent = "DENY (BLOQUEADO 403)";
        badge.className = "badge badge-danger";
        showToast("Decisión OPA: DENY — " + res.data.reason, "warn");
      }
    } else {
      badge.textContent = "HTTP " + res.status;
      badge.className = "badge badge-warn";
    }
  }

  // --------------------------------------------------------------------------
  // TAB 4: HIPAA Safe Harbor + k-Anonymity & l-Diversity Export
  // --------------------------------------------------------------------------
  async function handleAnonymizedExportJson(ev) {
    ev.preventDefault();
    const kVal = parseInt(byId("exp-k").value, 10) || 2;
    const lVal = parseInt(byId("exp-l").value, 10) || 2;
    const supVal = parseFloat(byId("exp-suppression").value) || 0.25;
    const deptVal = byId("exp-dept").value.trim() || null;

    const payload = { k: kVal, l: lVal, suppression_limit: supVal };
    if (deptVal) payload.department = deptVal;

    const res = await apiRequest("POST", "/lifecycle/exports/anonymized", { json: payload });
    const out = byId("export-metrics-output");
    const badge = byId("export-metrics-badge");
    const tbody = byId("export-records-tbody");
    tbody.replaceChildren();

    if (!res.ok) {
      out.textContent = JSON.stringify(res.data, null, 2);
      badge.textContent = "FAIL-CLOSED (HTTP " + res.status + ")";
      badge.className = "badge badge-danger";
      showToast("Exportación bloqueada (" + res.status + "): " + (res.data.detail || "No satisfacible"), "warn");
      return;
    }

    badge.textContent = "k=" + res.data.metrics.achieved_k + " | l=" + res.data.metrics.achieved_l + " | Nivel " + res.data.metrics.generalization_level;
    badge.className = "badge badge-ok";
    out.textContent = JSON.stringify(
      { metrics: res.data.metrics, equivalence_classes: res.data.equivalence_classes },
      null,
      2
    );

    (res.data.records || []).forEach(function (row) {
      const tr = document.createElement("tr");
      ["age_range", "zip_generalized", "gender", "diagnosis_cie10", "department", "record_year"].forEach(function (key) {
        const td = document.createElement("td");
        td.className = "mono-cell";
        td.textContent = String(row[key]);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });

    showToast(
      "Exportación Safe Harbor completada: " +
        res.data.metrics.exported_records_count +
        " registros (k=" +
        res.data.metrics.achieved_k +
        ", l=" +
        res.data.metrics.achieved_l +
        ").",
      "ok"
    );
  }

  async function handleAnonymizedExportCsv() {
    const params = new URLSearchParams({
      k: String(parseInt(byId("exp-k").value, 10) || 2),
      l: String(parseInt(byId("exp-l").value, 10) || 2),
      suppression_limit: String(parseFloat(byId("exp-suppression").value) || 0.25),
    });
    const deptVal = byId("exp-dept").value.trim();
    if (deptVal) params.set("department", deptVal);

    const res = await apiRequest("GET", "/lifecycle/exports/anonymized.csv?" + params.toString());
    if (!res.ok) {
      showToast("No fue posible exportar CSV (" + res.status + "): " + (res.data.detail || res.data), "warn");
      return;
    }

    const blob = new Blob([res.data], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "hospital_anonymized_safe_harbor.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast("Archivo CSV Safe Harbor descargado.", "ok");
  }

  // --------------------------------------------------------------------------
  // TAB 5: ARCO Erasure (NIST SP 800-88), TTL & Certificates (SHA-256)
  // --------------------------------------------------------------------------
  async function handleArcoErasure(ev) {
    ev.preventDefault();
    const res = await apiRequest("POST", "/lifecycle/arco/erasure", {
      json: {
        opaque_patient_token: byId("arco-token").value.trim(),
        method: byId("arco-method").value,
        arco_request_folio: byId("arco-folio").value.trim(),
        reason: byId("arco-reason").value.trim(),
        purge_vault: true,
      },
    });

    if (!res.ok) {
      showToast("Error en borrado ARCO (" + res.status + "): " + (res.data.detail || "Rechazado"), "err");
      return;
    }

    showToast(
      "Sanitización " +
        res.data.method +
        " ejecutada (" +
        res.data.overwrite_passes +
        " pasadas, Vault=" +
        res.data.vault_verification +
        "). Certificado SHA-256 emitido.",
      "ok"
    );
    await loadCertificates();
  }

  async function downloadAuthenticatedFile(url, filename) {
    const headers = {};
    if (state.accessToken) headers["Authorization"] = "Bearer " + state.accessToken;
    const purpose = getSelectedPurpose();
    if (purpose) headers["X-Purpose"] = purpose;

    const resp = await fetch(url, { headers: headers });
    if (!resp.ok) {
      showToast("Error al descargar certificado (HTTP " + resp.status + ")", "err");
      return;
    }
    const blob = await resp.blob();
    const objUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = objUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(objUrl);
    showToast("Descargado: " + filename, "ok");
  }

  async function loadCertificates() {
    const tbody = byId("certificates-tbody");
    tbody.replaceChildren();
    const res = await apiRequest("GET", "/lifecycle/certificates");

    if (!res.ok) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.textContent = "Acceso restringido (HTTP " + res.status + ").";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    if (!Array.isArray(res.data) || res.data.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.textContent = "No hay certificados de sanitización emitidos todavía.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    res.data.forEach(function (cert) {
      const tr = document.createElement("tr");

      const tdId = document.createElement("td");
      tdId.className = "mono-cell";
      tdId.textContent = String(cert.certificate_id).slice(0, 13) + "...";
      tr.appendChild(tdId);

      const tdTok = document.createElement("td");
      tdTok.className = "mono-cell";
      tdTok.textContent = cert.opaque_patient_token;
      tr.appendChild(tdTok);

      const tdMethod = document.createElement("td");
      const bMethod = document.createElement("span");
      bMethod.className = "badge badge-danger";
      bMethod.textContent = cert.method;
      tdMethod.appendChild(bMethod);
      tr.appendChild(tdMethod);

      const tdRecs = document.createElement("td");
      tdRecs.textContent = cert.records_sanitized_count + " reg · Vault: " + (cert.vault_purged ? "PURGADO" : "NO");
      tr.appendChild(tdRecs);

      const tdHash = document.createElement("td");
      tdHash.className = "mono-cell";
      tdHash.textContent = String(cert.sha256_hash).slice(0, 18) + "...";
      tr.appendChild(tdHash);

      const tdAct = document.createElement("td");
      const rowBtns = document.createElement("div");
      rowBtns.className = "btn-row btn-row-flush";

      const btnVerify = document.createElement("button");
      btnVerify.type = "button";
      btnVerify.className = "btn btn-primary btn-sm";
      btnVerify.textContent = "Verificar SHA-256";
      btnVerify.addEventListener("click", async function () {
        const vRes = await apiRequest("GET", cert.verify_url);
        if (vRes.ok && vRes.data.valid) {
          showToast("Integridad SHA-256 VERIFICADA: " + vRes.data.stored_sha256, "ok");
        } else {
          showToast("ALERTA: Integridad del certificado comprometida.", "err");
        }
      });
      rowBtns.appendChild(btnVerify);

      const btnJson = document.createElement("button");
      btnJson.type = "button";
      btnJson.className = "btn btn-secondary btn-sm";
      btnJson.textContent = "JSON";
      btnJson.addEventListener("click", function () {
        downloadAuthenticatedFile(cert.json_download_url, "certificado-" + cert.certificate_id + ".json");
      });
      rowBtns.appendChild(btnJson);

      const btnPdf = document.createElement("button");
      btnPdf.type = "button";
      btnPdf.className = "btn btn-secondary btn-sm";
      btnPdf.textContent = "PDF";
      btnPdf.addEventListener("click", function () {
        downloadAuthenticatedFile(cert.pdf_download_url, "certificado-" + cert.certificate_id + ".pdf");
      });
      rowBtns.appendChild(btnPdf);

      tdAct.appendChild(rowBtns);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });
  }

  // --------------------------------------------------------------------------
  // TAB 6: Gestión de Cuentas Institucionales (IAM Zero Trust)
  // --------------------------------------------------------------------------
  const ALL_ROLES = [
    "medico",
    "enfermeria",
    "analista",
    "auditor_arco",
    "admin_sec",
    "paciente",
  ];

  async function loadAdminUsers() {
    const tbody = byId("admin-users-tbody");
    const countBadge = byId("users-count-badge");
    if (!tbody) return;
    tbody.replaceChildren();

    const res = await apiRequest("GET", "/auth/users");
    if (!res.ok) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 5;
      td.textContent = "Acceso denegado (HTTP " + res.status + "): " + (res.data && res.data.detail ? res.data.detail : "Sin permisos");
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    const users = Array.isArray(res.data) ? res.data : [];
    if (countBadge) countBadge.textContent = users.length + " cuentas";

    if (!users.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 5;
      td.textContent = "No hay cuentas registradas.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    const actorIsSuper = state.user && state.user.role === "super_admin";
    const actorUsername = state.user ? state.user.username : "";

    users.forEach(function (u) {
      const tr = document.createElement("tr");

      const tdUser = document.createElement("td");
      tdUser.className = "mono-cell";
      tdUser.textContent = u.username + (u.username === actorUsername ? " (tú)" : "");
      tr.appendChild(tdUser);

      const tdRole = document.createElement("td");
      const canModifyTarget = actorIsSuper || u.role !== "super_admin";
      const isSelf = u.username === actorUsername;

      if (canModifyTarget && !isSelf) {
        const sel = document.createElement("select");
        sel.className = "admin-role-select";
        sel.setAttribute("aria-label", "Rol para " + u.username);
        ALL_ROLES.forEach(function (roleOpt) {
          if (roleOpt === "super_admin" && !actorIsSuper) return;
          const opt = document.createElement("option");
          opt.value = roleOpt;
          opt.textContent = roleOpt;
          if (roleOpt === u.role) opt.selected = true;
          sel.appendChild(opt);
        });
        sel.addEventListener("change", async function () {
          const patchRes = await apiRequest("PATCH", "/auth/users/" + encodeURIComponent(u.id), {
            json: { role: sel.value },
          });
          if (patchRes.ok) {
            showToast("Rol de '" + u.username + "' actualizado a '" + sel.value + "' y sesiones previas revocadas.", "ok");
            await loadAdminUsers();
          } else {
            showToast("Error (" + patchRes.status + "): " + (patchRes.data && patchRes.data.detail ? patchRes.data.detail : "Rechazado"), "warn");
            await loadAdminUsers();
          }
        });
        tdRole.appendChild(sel);
      } else {
        const chip = document.createElement("span");
        chip.className = "role-chip";
        chip.textContent = u.role;
        tdRole.appendChild(chip);
      }
      tr.appendChild(tdRole);

      const tdActive = document.createElement("td");
      const activeBadge = document.createElement("span");
      activeBadge.className = "badge " + (u.is_active ? "badge-ok" : "badge-danger");
      activeBadge.textContent = u.is_active ? "ACTIVA" : "SUSPENDIDA";
      tdActive.appendChild(activeBadge);
      tr.appendChild(tdActive);

      const tdWebAuthn = document.createElement("td");
      tdWebAuthn.textContent = u.webauthn_enabled ? "Habilitada" : "Solo Argon2id";
      tr.appendChild(tdWebAuthn);

      const tdAct = document.createElement("td");
      const btnWrap = document.createElement("div");
      btnWrap.className = "btn-row btn-row-flush";

      if (canModifyTarget && !isSelf) {
        const btnToggle = document.createElement("button");
        btnToggle.type = "button";
        btnToggle.className = "btn " + (u.is_active ? "btn-danger" : "btn-primary") + " btn-sm";
        btnToggle.textContent = u.is_active ? "Suspender" : "Reactivar";
        btnToggle.addEventListener("click", async function () {
          const patchRes = await apiRequest("PATCH", "/auth/users/" + encodeURIComponent(u.id), {
            json: { is_active: !u.is_active },
          });
          if (patchRes.ok) {
            showToast(
              "Cuenta '" + u.username + "' " + (patchRes.data.is_active ? "reactivada" : "suspendida y sesiones revocadas") + ".",
              "ok"
            );
            await loadAdminUsers();
          } else {
            showToast("Error (" + patchRes.status + "): " + (patchRes.data && patchRes.data.detail ? patchRes.data.detail : "Rechazado"), "warn");
          }
        });
        btnWrap.appendChild(btnToggle);
      }

      if (canModifyTarget) {
        const btnRevoke = document.createElement("button");
        btnRevoke.type = "button";
        btnRevoke.className = "btn btn-secondary btn-sm";
        btnRevoke.textContent = "Revocar JWT";
        btnRevoke.addEventListener("click", async function () {
          const revRes = await apiRequest("POST", "/auth/users/" + encodeURIComponent(u.id) + "/revoke-sessions");
          if (revRes.ok) {
            showToast("Sesiones revocadas para '" + u.username + "': " + revRes.data.revoked_sessions + " JWT.", "ok");
          } else {
            showToast("Error (" + revRes.status + "): " + (revRes.data && revRes.data.detail ? revRes.data.detail : "Rechazado"), "warn");
          }
        });
        btnWrap.appendChild(btnRevoke);
      }

      tdAct.appendChild(btnWrap);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });
  }

  // --------------------------------------------------------------------------
  // Wire Event Listeners on DOMContentLoaded
  // --------------------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", function () {
    configureSiemLink();
    refreshGateHealth();

    // Global user activity listeners for 2-minute Zero Trust inactivity timeout
    ["pointerdown", "keydown", "scroll", "touchstart", "click"].forEach(function (evtName) {
      document.addEventListener(evtName, recordUserActivity, { passive: true });
    });
    document.addEventListener(
      "mousemove",
      function () {
        const now = Date.now();
        if (now - lastPointerActivityAt >= 1000) {
          lastPointerActivityAt = now;
          recordUserActivity();
        }
      },
      { passive: true }
    );

    // Gate Login / Register tab switching
    const tabLoginBtn = byId("gate-tab-login");
    const tabRegBtn = byId("gate-tab-register");
    const formLogin = byId("form-login");
    const formRegister = byId("form-register");

    tabLoginBtn.addEventListener("click", function () {
      tabLoginBtn.classList.add("active");
      tabLoginBtn.setAttribute("aria-selected", "true");
      tabRegBtn.classList.remove("active");
      tabRegBtn.setAttribute("aria-selected", "false");
      formLogin.classList.remove("is-hidden");
      formRegister.classList.add("is-hidden");
      resetPasswordVisibility();
      hideGateToast();
    });

    tabRegBtn.addEventListener("click", function () {
      tabRegBtn.classList.add("active");
      tabRegBtn.setAttribute("aria-selected", "true");
      tabLoginBtn.classList.remove("active");
      tabLoginBtn.setAttribute("aria-selected", "false");
      formRegister.classList.remove("is-hidden");
      formLogin.classList.add("is-hidden");
      resetPasswordVisibility();
      hideGateToast();
    });

    document.querySelectorAll(".password-toggle-btn[data-password-target]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const targetId = btn.getAttribute("data-password-target");
        const inputEl = targetId ? byId(targetId) : null;
        if (!inputEl) return;
        const shouldShow = inputEl.type === "password";
        setPasswordVisibility(inputEl, btn, shouldShow);
      });
    });

    const regPasswordInput = byId("reg-password");
    const regPasswordToggle = byId("toggle-reg-password");
    const btnGeneratePassword = byId("btn-generate-password");
    const btnCopyRegPassword = byId("btn-copy-reg-password");
    const copyRegPasswordLabel = byId("copy-reg-password-label");

    if (regPasswordInput) {
      regPasswordInput.addEventListener("input", syncRegCopyButtonState);
    }

    if (btnGeneratePassword && regPasswordInput) {
      btnGeneratePassword.addEventListener("click", function () {
        if (!window.crypto || !window.crypto.getRandomValues) {
          showGateToast("Este navegador no soporta Web Crypto API para generar contraseñas seguras.", "err");
          return;
        }
        regPasswordInput.value = generateSecurePassword(16);
        setPasswordVisibility(regPasswordInput, regPasswordToggle, true);
        syncRegCopyButtonState();
        if (copyRegPasswordLabel) copyRegPasswordLabel.textContent = "Copiar";
        regPasswordInput.focus();
      });
    }

    if (btnCopyRegPassword && regPasswordInput) {
      btnCopyRegPassword.addEventListener("click", async function () {
        const value = regPasswordInput.value;
        if (!value) return;
        let copied = false;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          try {
            await navigator.clipboard.writeText(value);
            copied = true;
          } catch (_) {
            copied = false;
          }
        }
        if (copied && copyRegPasswordLabel) {
          copyRegPasswordLabel.textContent = "Copiada";
          if (copyPasswordResetTimer) clearTimeout(copyPasswordResetTimer);
          copyPasswordResetTimer = setTimeout(function () {
            if (copyRegPasswordLabel) copyRegPasswordLabel.textContent = "Copiar";
          }, 2000);
        } else {
          showGateToast("No se pudo acceder al portapapeles. Copia la contraseña manualmente.", "err");
        }
      });
    }

    // Gate Authentication Handlers
    formLogin.addEventListener("submit", function (ev) {
      ev.preventDefault();
      handlePasswordLogin(byId("login-username").value.trim(), byId("login-password").value);
    });

    byId("btn-webauthn-login").addEventListener("click", loginWithWebAuthnPasskey);

    formRegister.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      const u = byId("reg-username").value.trim();
      const p = byId("reg-password").value;
      const res = await apiRequest("POST", "/auth/register", {
        skipAuth: true,
        json: { username: u, role: "paciente", password: p },
      });
      if (res.status === 201) {
        await handlePasswordLogin(u, p);
      } else {
        const msg = res.data && res.data.detail ? JSON.stringify(res.data.detail) : "Error de validación";
        showGateToast("No se pudo crear la cuenta (" + res.status + "): " + msg, "err");
      }
    });

    // Authenticated Workspace Handlers
    byId("global-toast-close").addEventListener("click", hideToast);
    byId("btn-top-logout").addEventListener("click", handleLogout);

    document.querySelectorAll(".nav-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const targetTab = btn.getAttribute("data-tab");
        switchTab(targetTab);
        if (targetTab === "tab-users") {
          loadAdminUsers();
        }
      });
    });

    byId("btn-webauthn-register").addEventListener("click", registerWebAuthnPasskey);
    byId("btn-refresh-me").addEventListener("click", refreshCurrentUser);

    // Tab 6: Admin User Management
    const btnRefreshUsers = byId("btn-refresh-users");
    if (btnRefreshUsers) btnRefreshUsers.addEventListener("click", loadAdminUsers);

    const btnAdminGenPwd = byId("btn-admin-gen-password");
    const adminNewPwd = byId("admin-new-password");
    const adminPwdToggle = byId("toggle-admin-password");
    if (btnAdminGenPwd && adminNewPwd) {
      btnAdminGenPwd.addEventListener("click", function () {
        adminNewPwd.value = generateSecurePassword(16);
        setPasswordVisibility(adminNewPwd, adminPwdToggle, true);
        adminNewPwd.focus();
      });
    }

    const formAdminCreateUser = byId("form-admin-create-user");
    if (formAdminCreateUser) {
      formAdminCreateUser.addEventListener("submit", async function (ev) {
        ev.preventDefault();
        const u = byId("admin-new-username").value.trim();
        const r = byId("admin-new-role").value;
        const p = byId("admin-new-password").value;
        const res = await apiRequest("POST", "/auth/users", {
          json: { username: u, role: r, password: p },
        });
        if (res.status === 201) {
          byId("admin-new-username").value = "";
          byId("admin-new-password").value = "";
          resetPasswordVisibility();
          showToast("Cuenta institucional '" + res.data.username + "' creada con rol '" + res.data.role + "'.", "ok");
          await loadAdminUsers();
        } else {
          const msg = res.data && res.data.detail ? JSON.stringify(res.data.detail) : "Rechazado";
          showToast("No se pudo crear la cuenta (" + res.status + "): " + msg, "warn");
        }
      });
    }

    // Tab 2: Clinical & Vault
    byId("btn-seed-clinical-cohort").addEventListener("click", seedClinicalCohort);
    byId("btn-refresh-records").addEventListener("click", loadClinicalRecords);

    byId("form-segregated-record").addEventListener("submit", async function (ev) {
      ev.preventDefault();
      const ttlRaw = byId("clin-ttl").value.trim();
      const clinicalData = {
        age_years: parseInt(byId("clin-age").value, 10),
        zip_prefix: byId("clin-zip").value.trim(),
        gender: byId("clin-gender").value,
        diagnosis_cie10: byId("clin-cie10").value.trim().toUpperCase(),
        diagnosis_summary: byId("clin-summary").value.trim(),
        department: byId("clin-dept").value,
        purpose_scope: "atencion_medica",
      };
      if (ttlRaw) clinicalData.ttl_hours = parseInt(ttlRaw, 10);

      const payload = {
        patient_pii: {
          full_name: byId("pii-fullname").value.trim(),
          curp: byId("pii-curp").value.trim().toUpperCase(),
          nss: byId("pii-nss").value.trim(),
          contact_email: byId("pii-email").value.trim() || null,
        },
        clinical_data: clinicalData,
      };

      const res = await apiRequest("POST", "/clinical/records/segregated", { json: payload });
      if (res.status === 201) {
        byId("vault-inspect-token").value = res.data.opaque_patient_token;
        byId("vault-inspector-output").textContent = JSON.stringify(res.data, null, 2);
        showToast("Expediente segregado creado. Token opaco Vault: " + res.data.opaque_patient_token, "ok");
        await loadClinicalRecords();
      } else {
        showToast("Error (" + res.status + "): " + JSON.stringify(res.data.detail || res.data), "err");
      }
    });

    byId("btn-vault-status").addEventListener("click", async function () {
      const res = await apiRequest("GET", "/vault/status");
      byId("vault-inspector-output").textContent = JSON.stringify(res.data, null, 2);
      if (res.ok) {
        byId("tel-vault-key").textContent = res.data.transit_key + " v" + res.data.latest_key_version;
        showToast("HashiCorp Vault operativo (Transit + KV v2).", "ok");
      } else {
        const detail = res.data && res.data.detail ? res.data.detail : "Requiere rol admin_sec, auditor_arco o super_admin.";
        showToast("HTTP " + res.status + ": " + detail, "warn");
      }
    });

    byId("btn-vault-rotate").addEventListener("click", async function () {
      const res = await apiRequest("POST", "/vault/keys/rotate");
      byId("vault-inspector-output").textContent = JSON.stringify(res.data, null, 2);
      if (res.ok) {
        byId("tel-vault-key").textContent = res.data.transit_key + " v" + res.data.latest_key_version;
        showToast("Llave Transit AEAD rotada a versión v" + res.data.latest_key_version, "ok");
      } else {
        const detail = res.data && res.data.detail ? res.data.detail : "Requiere rol admin_sec o super_admin.";
        showToast("HTTP " + res.status + ": " + detail, "warn");
      }
    });

    byId("btn-vault-detokenize").addEventListener("click", async function () {
      const tok = byId("vault-inspect-token").value.trim();
      if (!tok) {
        showToast("Ingresa un token pat_... para detokenizar.", "warn");
        return;
      }
      const res = await apiRequest("GET", "/vault/patients/" + encodeURIComponent(tok));
      byId("vault-inspector-output").textContent = JSON.stringify(res.data, null, 2);
      if (res.ok) {
        showToast("Identificadores directos recuperados desde HashiCorp Vault.", "ok");
      } else {
        showToast("HTTP " + res.status + ": " + (res.data.detail || "No autorizado"), "warn");
      }
    });

    // Tab 3: OPA Simulator & Presets
    byId("form-opa-sim").addEventListener("submit", function (ev) {
      ev.preventDefault();
      runOpaSimulation();
    });

    byId("btn-opa-status").addEventListener("click", async function () {
      const res = await apiRequest("GET", "/clinical/policy/status");
      byId("opa-decision-output").textContent = JSON.stringify(res.data, null, 2);
      if (res.ok) {
        byId("tel-opa-ver").textContent = "v" + (res.data.policy_version || "1.1.0");
        showToast("Motor OPA saludable y política hospital.authz cargada.", "ok");
      }
    });

    byId("preset-opa-medico").addEventListener("click", function () {
      byId("opa-sim-role").value = "medico";
      byId("opa-sim-purpose").value = "atencion_medica";
      byId("opa-sim-action").value = "read_record";
      runOpaSimulation();
    });

    byId("preset-opa-creep").addEventListener("click", function () {
      byId("opa-sim-role").value = "medico";
      byId("opa-sim-purpose").value = "publicidad";
      byId("opa-sim-action").value = "read_record";
      runOpaSimulation();
    });

    byId("preset-opa-singling").addEventListener("click", function () {
      byId("opa-sim-role").value = "analista";
      byId("opa-sim-purpose").value = "investigacion_estadistica";
      byId("opa-sim-action").value = "read_single_record";
      runOpaSimulation();
    });

    byId("preset-opa-admin").addEventListener("click", function () {
      byId("opa-sim-role").value = "admin_sec";
      byId("opa-sim-purpose").value = "atencion_medica";
      byId("opa-sim-action").value = "read_record";
      runOpaSimulation();
    });

    // Tab 4: Safe Harbor Export
    byId("form-anonymized-export").addEventListener("submit", handleAnonymizedExportJson);
    byId("btn-export-csv").addEventListener("click", handleAnonymizedExportCsv);

    // Tab 5: ARCO, NIST SP 800-88 & TTL
    byId("form-arco-erasure").addEventListener("submit", handleArcoErasure);
    byId("btn-refresh-certificates").addEventListener("click", loadCertificates);

    byId("btn-ttl-status").addEventListener("click", async function () {
      const res = await apiRequest("GET", "/lifecycle/ttl/status");
      byId("ttl-output").textContent = JSON.stringify(res.data, null, 2);
      if (res.ok) showToast("Estado del planificador TTL consultado.", "ok");
    });

    byId("btn-ttl-sweep").addEventListener("click", async function () {
      const res = await apiRequest("POST", "/lifecycle/ttl/sweep");
      byId("ttl-output").textContent = JSON.stringify(res.data, null, 2);
      if (res.ok) {
        showToast("Barrido TTL completado: " + res.data.purged_records_count + " registros purgados.", "ok");
      } else {
        showToast("Verifica tu propósito X-Purpose (mantenimiento_ttl o ejercicio_arco).", "warn");
      }
    });
  });
})();
