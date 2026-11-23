/* ============================================================================
   Hospital Privacy-by-Design & Zero Trust — Client Logic (Vanilla JS)
   BUAP FCC · Ingeniería en Ciberseguridad (ICSA 252)
   Security: Strict DOM manipulation (textContent / createElement), zero eval/innerHTML
   ============================================================================ */

(function () {
  "use strict";

  const DEMO_PASSWORD = "Hospital!2026#Secure";
  const DEMO_PERSONAS = {
    medico: { username: "dr_garcia", role: "medico", purpose: "atencion_medica" },
    enfermeria: { username: "enf_martinez", role: "enfermeria", purpose: "atencion_medica" },
    analista: { username: "ana_estadistica", role: "analista", purpose: "investigacion_estadistica" },
    auditor_arco: { username: "aud_arco_buap", role: "auditor_arco", purpose: "ejercicio_arco" },
    admin_sec: { username: "sec_ops_admin", role: "admin_sec", purpose: "mantenimiento_ttl" },
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

  // State kept in memory only (Zero Trust: no permanent storage of clinical PII)
  const state = {
    accessToken: null,
    user: null,
    amr: [],
  };

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
  // UI Helpers & Toast Notifications
  // --------------------------------------------------------------------------
  function byId(id) {
    return document.getElementById(id);
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
    if (banner) {
      banner.className = "toast-banner hidden";
    }
  }

  function getSelectedPurpose() {
    const sel = byId("global-purpose-select");
    return sel ? sel.value : "atencion_medica";
  }

  function setSelectedPurpose(purposeValue) {
    const sel = byId("global-purpose-select");
    if (sel) {
      sel.value = purposeValue;
    }
  }

  function updateSessionHeader() {
    const dot = byId("session-dot");
    const userLabel = byId("session-user-label");
    const roleBadge = byId("session-role-badge");
    const logoutBtn = byId("btn-top-logout");

    if (state.accessToken && state.user) {
      dot.className = "session-dot active";
      userLabel.textContent = state.user.username + " (" + state.amr.join("+") + ")";
      roleBadge.textContent = state.user.role;
      logoutBtn.disabled = false;
    } else {
      dot.className = "session-dot";
      userLabel.textContent = "Sin sesión activa";
      roleBadge.textContent = "anónimo";
      logoutBtn.disabled = true;
    }
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
  // Unified API Fetch Wrapper (Attaches Bearer JWT + X-Purpose header)
  // --------------------------------------------------------------------------
  async function apiRequest(method, path, options) {
    const opts = options || {};
    const headers = Object.assign({}, opts.headers || {});

    if (state.accessToken && !opts.skipAuth) {
      headers["Authorization"] = "Bearer " + state.accessToken;
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
    return {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      data: data,
    };
  }

  // --------------------------------------------------------------------------
  // Tab Navigation & SIEM Link Auto-Configure
  // --------------------------------------------------------------------------
  function switchTab(tabId) {
    const buttons = document.querySelectorAll(".nav-btn");
    buttons.forEach(function (btn) {
      btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
    });
    const panels = document.querySelectorAll(".tab-panel");
    panels.forEach(function (panel) {
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

  // --------------------------------------------------------------------------
  // Telemetry Strip (Health & Edge Check)
  // --------------------------------------------------------------------------
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
  // TAB 1: Authentication (Argon2id + WebAuthn Passkeys + Quick Role Switcher)
  // --------------------------------------------------------------------------
  async function handlePasswordLogin(username, password) {
    const res = await apiRequest("POST", "/auth/login", {
      json: { username: username, password: password },
      skipAuth: true,
    });

    if (!res.ok) {
      showToast("Error de autenticación (" + res.status + "): " + (res.data && res.data.detail ? res.data.detail : "Credenciales inválidas"), "err");
      return false;
    }

    state.accessToken = res.data.access_token;
    state.user = res.data.user;
    state.amr = res.data.amr || ["pwd"];
    updateSessionHeader();
    await refreshCurrentUser();
    await refreshWebAuthnCredentials();
    showToast("Sesión iniciada como " + state.user.username + " [rol=" + state.user.role + "]", "ok");
    return true;
  }

  async function refreshCurrentUser() {
    const out = byId("auth-me-output");
    if (!state.accessToken) {
      out.textContent = "Sin sesión activa.";
      return;
    }
    const res = await apiRequest("GET", "/auth/me");
    if (res.ok) {
      out.textContent = JSON.stringify(res.data, null, 2);
    } else {
      out.textContent = JSON.stringify(res.data, null, 2);
    }
  }

  async function handleLogout() {
    if (!state.accessToken) return;
    const res = await apiRequest("POST", "/auth/logout");
    state.accessToken = null;
    state.user = null;
    state.amr = [];
    updateSessionHeader();
    byId("auth-me-output").textContent = "Sesión JWT revocada explícitamente (jti invalidado).";
    if (res.ok) {
      showToast("Sesión JWT revocada en lista negra Zero Trust (jti=" + res.data.jti + ")", "ok");
    }
  }

  async function ensurePersonaAndLogin(roleKey, customPurpose) {
    const persona = DEMO_PERSONAS[roleKey] || DEMO_PERSONAS.medico;
    setSelectedPurpose(customPurpose !== undefined ? customPurpose : persona.purpose);

    // Try login first; if 401, auto-register the demo user and login
    let res = await apiRequest("POST", "/auth/login", {
      json: { username: persona.username, password: DEMO_PASSWORD },
      skipAuth: true,
    });

    if (res.status === 401) {
      await apiRequest("POST", "/auth/register", {
        json: {
          username: persona.username,
          password: DEMO_PASSWORD,
          role: persona.role,
        },
        skipAuth: true,
      });
      res = await apiRequest("POST", "/auth/login", {
        json: { username: persona.username, password: DEMO_PASSWORD },
        skipAuth: true,
      });
    }

    if (res.ok) {
      state.accessToken = res.data.access_token;
      state.user = res.data.user;
      state.amr = res.data.amr || ["pwd"];
      byId("login-username").value = persona.username;
      updateSessionHeader();
      await refreshCurrentUser();
      await refreshWebAuthnCredentials();
      showToast(
        "Rol activo: " + state.user.role + " (" + state.user.username + ") | X-Purpose: " + (getSelectedPurpose() || "VACÍO"),
        customPurpose === "marketing_comercial" ? "warn" : "ok"
      );
      if (byId("tab-clinical").classList.contains("active")) {
        await loadClinicalRecords();
      }
    } else {
      showToast("No fue posible activar el usuario demo " + persona.username + " (verifica que PostgreSQL esté activo).", "err");
    }
  }

  async function seedAllDemoUsers() {
    let createdCount = 0;
    const keys = Object.keys(DEMO_PERSONAS);
    for (let i = 0; i < keys.length; i++) {
      const p = DEMO_PERSONAS[keys[i]];
      const res = await apiRequest("POST", "/auth/register", {
        json: { username: p.username, password: DEMO_PASSWORD, role: p.role },
        skipAuth: true,
      });
      if (res.status === 201) createdCount++;
    }
    showToast("Inicialización de roles demo completada (" + createdCount + " nuevos, 5 disponibles).", "ok");
  }

  // WebAuthn Passkeys Registration & Login
  async function refreshWebAuthnCredentials() {
    const tbody = byId("webauthn-creds-tbody");
    tbody.replaceChildren();
    if (!state.accessToken) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.textContent = "Autentícate para consultar tus Passkeys FIDO2 registradas.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    const res = await apiRequest("GET", "/auth/webauthn/credentials");
    if (!res.ok || !Array.isArray(res.data) || res.data.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.textContent = "Sin Passkeys FIDO2 registradas para este usuario.";
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
    if (!state.accessToken) {
      showToast("Inicia sesión con Argon2id primero para vincular una Passkey FIDO2.", "warn");
      return;
    }
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
      showToast("Operación WebAuthn cancelada o rechazada por el navegador: " + err.message, "warn");
    }
  }

  async function loginWithWebAuthnPasskey() {
    const username = byId("login-username").value.trim();
    if (!username) {
      showToast("Ingresa tu nombre de usuario para solicitar el reto FIDO2.", "warn");
      return;
    }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      showToast("WebAuthn no disponible en este contexto (usa HTTPS o localhost).", "err");
      return;
    }

    const beginRes = await apiRequest("POST", "/auth/webauthn/login/begin", {
      json: { username: username },
      skipAuth: true,
    });
    if (!beginRes.ok) {
      showToast(beginRes.data && beginRes.data.detail ? beginRes.data.detail : "Sin Passkeys para este usuario.", "warn");
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
        state.accessToken = completeRes.data.access_token;
        state.user = completeRes.data.user;
        state.amr = completeRes.data.amr || ["webauthn", "fido2"];
        updateSessionHeader();
        await refreshCurrentUser();
        await refreshWebAuthnCredentials();
        showToast("Autenticado vía FIDO2/WebAuthn Passkey (amr=webauthn+fido2).", "ok");
      } else {
        showToast("Fallo en verificación FIDO2: " + (completeRes.data.detail || "Rechazado"), "err");
      }
    } catch (err) {
      showToast("Autenticación FIDO2 cancelada: " + err.message, "warn");
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
      btnWrap.className = "btn-row";
      btnWrap.style.marginTop = "0";

      if (rec.record_id) {
        const btnPii = document.createElement("button");
        btnPii.type = "button";
        btnPii.className = "btn btn-secondary btn-sm";
        btnPii.textContent = "Resolver PII (Vault)";
        btnPii.addEventListener("click", function () {
          resolveRecordIdentity(rec.record_id, rec.opaque_patient_token);
        });
        btnWrap.appendChild(btnPii);
      }

      if (rec.opaque_patient_token && !String(rec.opaque_patient_token).includes("...")) {
        const btnArco = document.createElement("button");
        btnArco.type = "button";
        btnArco.className = "btn btn-danger btn-sm";
        btnArco.textContent = "Enviar a ARCO";
        btnArco.addEventListener("click", function () {
          byId("arco-token").value = rec.opaque_patient_token;
          byId("vault-inspect-token").value = rec.opaque_patient_token;
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

    renderPolicyBanner(res.data.policy);
    renderClinicalTable(res.data.records || [], res.data.policy);
    showToast("Consulta autorizada por OPA: " + res.data.count + " expedientes proyectados con minimización MA-04.", "ok");
  }

  async function resolveRecordIdentity(recordId, tokenHint) {
    if (tokenHint && !String(tokenHint).includes("...")) {
      byId("vault-inspect-token").value = tokenHint;
    }
    const res = await apiRequest("GET", "/clinical/records/" + encodeURIComponent(recordId) + "/patient-identity");
    const out = byId("vault-inspector-output");
    out.textContent = JSON.stringify(res.data, null, 2);
    if (res.ok) {
      showToast("PII detokenizada desde HashiCorp Vault con doble control OPA + Vault.", "ok");
    } else {
      showToast("Detokenización bloqueada (HTTP " + res.status + "): " + (res.data.detail || "No autorizado"), "warn");
    }
  }

  async function seedClinicalCohort() {
    if (!state.accessToken || !state.user || state.user.role !== "medico" || getSelectedPurpose() !== "atencion_medica") {
      await ensurePersonaAndLogin("medico", "atencion_medica");
    }
    let created = 0;
    for (let i = 0; i < DEMO_COHORT.length; i++) {
      const item = DEMO_COHORT[i];
      const res = await apiRequest("POST", "/clinical/records/segregated", {
        json: item,
        purpose: "atencion_medica",
      });
      if (res.status === 201) {
        created++;
        byId("vault-inspect-token").value = res.data.opaque_patient_token;
        byId("arco-token").value = res.data.opaque_patient_token;
      }
    }
    showToast("Cohorte clínica de " + created + " pacientes creada (PII aislada en Vault + atributos en PostgreSQL).", "ok");
    await loadClinicalRecords();
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
      showToast("Para usar /clinical/policy/evaluate cambia al rol auditor_arco o admin_sec en la barra lateral.", "warn");
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

    const payload = {
      k: kVal,
      l: lVal,
      suppression_limit: supVal,
    };
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
      {
        metrics: res.data.metrics,
        equivalence_classes: res.data.equivalence_classes,
      },
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
        " registros con k=" +
        res.data.metrics.achieved_k +
        ", l=" +
        res.data.metrics.achieved_l,
      "ok"
    );
  }

  async function handleAnonymizedExportCsv() {
    const kVal = parseInt(byId("exp-k").value, 10) || 2;
    const lVal = parseInt(byId("exp-l").value, 10) || 2;
    const supVal = parseFloat(byId("exp-suppression").value) || 0.25;
    const deptVal = byId("exp-dept").value.trim();

    const params = new URLSearchParams({
      k: String(kVal),
      l: String(lVal),
      suppression_limit: String(supVal),
    });
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
    const token = byId("arco-token").value.trim();
    const method = byId("arco-method").value;
    const folio = byId("arco-folio").value.trim();
    const reason = byId("arco-reason").value.trim();

    const res = await apiRequest("POST", "/lifecycle/arco/erasure", {
      json: {
        opaque_patient_token: token,
        method: method,
        arco_request_folio: folio,
        reason: reason,
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
      td.textContent = "Acceso restringido (HTTP " + res.status + "): requiere rol auditor_arco con propósito ejercicio_arco.";
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
      rowBtns.className = "btn-row";
      rowBtns.style.marginTop = "0";

      const btnVerify = document.createElement("button");
      btnVerify.type = "button";
      btnVerify.className = "btn btn-primary btn-sm";
      btnVerify.textContent = "Verificar SHA-256";
      btnVerify.addEventListener("click", async function () {
        const vRes = await apiRequest("GET", cert.verify_url);
        if (vRes.ok && vRes.data.valid) {
          showToast("Integridad SHA-256 VERIFICADA (hmac.compare_digest válido): " + vRes.data.stored_sha256, "ok");
        } else {
          showToast("ALERTA: Integridad del certificado comprometida o error de verificación.", "err");
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
  // Wire Event Listeners on DOMContentLoaded
  // --------------------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", function () {
    configureSiemLink();
    refreshTelemetry();

    byId("global-toast-close").addEventListener("click", hideToast);
    byId("btn-top-logout").addEventListener("click", handleLogout);

    // Sidebar tab buttons
    document.querySelectorAll(".nav-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        switchTab(btn.getAttribute("data-tab"));
      });
    });

    // Quick Persona Role Switcher buttons
    document.querySelectorAll(".persona-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const role = btn.getAttribute("data-role");
        const purpose = btn.getAttribute("data-purpose");
        ensurePersonaAndLogin(role, purpose);
      });
    });

    // Tab 1: Auth forms
    byId("btn-seed-demo-users").addEventListener("click", seedAllDemoUsers);
    byId("form-login").addEventListener("submit", function (ev) {
      ev.preventDefault();
      handlePasswordLogin(byId("login-username").value.trim(), byId("login-password").value);
    });
    byId("btn-webauthn-login").addEventListener("click", loginWithWebAuthnPasskey);
    byId("btn-webauthn-register").addEventListener("click", registerWebAuthnPasskey);
    byId("btn-refresh-me").addEventListener("click", refreshCurrentUser);

    byId("form-register").addEventListener("submit", async function (ev) {
      ev.preventDefault();
      const u = byId("reg-username").value.trim();
      const r = byId("reg-role").value;
      const p = byId("reg-password").value;
      const res = await apiRequest("POST", "/auth/register", {
        skipAuth: true,
        json: { username: u, role: r, password: p },
      });
      if (res.status === 201) {
        showToast("Usuario " + u + " registrado con rol " + r + ". Iniciando sesión...", "ok");
        await handlePasswordLogin(u, p);
      } else {
        showToast("Error al registrar (" + res.status + "): " + JSON.stringify(res.data.detail || res.data), "err");
      }
    });

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
      if (ttlRaw) {
        clinicalData.ttl_hours = parseInt(ttlRaw, 10);
      }

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
        byId("arco-token").value = res.data.opaque_patient_token;
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
        showToast("Consulta de estado Vault requiere rol admin_sec o auditor_arco.", "warn");
      }
    });

    byId("btn-vault-rotate").addEventListener("click", async function () {
      const res = await apiRequest("POST", "/vault/keys/rotate");
      byId("vault-inspector-output").textContent = JSON.stringify(res.data, null, 2);
      if (res.ok) {
        byId("tel-vault-key").textContent = res.data.transit_key + " v" + res.data.latest_key_version;
        showToast("Llave Transit AEAD rotada a versión v" + res.data.latest_key_version, "ok");
      } else {
        showToast("Rotación de llave requiere rol admin_sec.", "warn");
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
      } else {
        showToast("Para consultar /clinical/policy/status activa el rol auditor_arco o admin_sec.", "warn");
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
      if (res.ok) {
        showToast("Estado del planificador TTL consultado.", "ok");
      } else {
        showToast("Requiere rol auditor_arco o admin_sec.", "warn");
      }
    });

    byId("btn-ttl-sweep").addEventListener("click", async function () {
      const res = await apiRequest("POST", "/lifecycle/ttl/sweep");
      byId("ttl-output").textContent = JSON.stringify(res.data, null, 2);
      if (res.ok) {
        showToast("Barrido TTL completado: " + res.data.purged_records_count + " registros purgados.", "ok");
      } else {
        showToast("Para ejecutar barrido TTL usa rol admin_sec (mantenimiento_ttl) o auditor_arco (ejercicio_arco).", "warn");
      }
    });
  });
})();
