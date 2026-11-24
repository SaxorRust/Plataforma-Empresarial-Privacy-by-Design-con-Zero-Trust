"""Vista HTML interactiva de la Consola SIEM & SOC (sin innerHTML dinámico, prevención XSS)."""

SOC_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description" content="Consola SIEM & SOC — Colector Syslog RFC 5424, Sanitización Regex en Ingesta y Correlación Temporal (BUAP FCC - ICSA 252)." />
  <title>Hospital Zero Trust — Consola SIEM &amp; SOC</title>
  <style>
    :root {
      --bg-canvas: hsl(216, 34%, 7%);
      --bg-elevated: hsl(215, 28%, 11%);
      --bg-panel: hsl(215, 26%, 14%);
      --bg-input: hsl(216, 32%, 9%);
      --border: hsl(215, 22%, 21%);
      --border-strong: hsl(214, 22%, 29%);
      --text: hsl(210, 40%, 96%);
      --text-secondary: hsl(214, 20%, 74%);
      --muted: hsl(215, 16%, 56%);
      --teal: hsl(174, 82%, 44%);
      --teal-soft: hsla(174, 82%, 44%, 0.14);
      --sky: hsl(199, 89%, 56%);
      --sky-soft: hsla(199, 89%, 56%, 0.14);
      --ok: hsl(152, 76%, 44%);
      --ok-soft: hsla(152, 76%, 44%, 0.16);
      --warn: hsl(38, 92%, 54%);
      --warn-soft: hsla(38, 92%, 54%, 0.18);
      --crit: hsl(0, 84%, 62%);
      --crit-soft: hsla(0, 84%, 62%, 0.18);
      --font-sans: "Inter", system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      --font-mono: "JetBrains Mono", "Fira Code", Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg-canvas);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 14.5px;
      line-height: 1.5;
    }
    .topbar {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 14px;
      padding: 14px 26px;
      background: var(--bg-elevated);
      border-bottom: 1px solid var(--border);
    }
    .brand-wrap { display: flex; align-items: center; gap: 12px; }
    .brand-badge {
      width: 38px;
      height: 38px;
      border-radius: 10px;
      background: var(--teal-soft);
      color: var(--teal);
      border: 1px solid hsla(174, 82%, 44%, 0.35);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
      font-weight: 700;
      font-size: 0.85rem;
    }
    h1 { margin: 0; font-size: 1.08rem; font-weight: 700; }
    h2 { margin: 0; font-size: 1.02rem; font-weight: 600; }
    .subtitle { color: var(--muted); font-size: 0.8rem; }
    .toolbar-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
    .container { max-width: 1440px; margin: 0 auto; padding: 22px 26px 48px; }
    .grid-metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 14px;
      margin-bottom: 22px;
    }
    .card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 18px;
    }
    .metric-label {
      color: var(--muted);
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 600;
    }
    .metric-value {
      font-size: 1.75rem;
      font-weight: 700;
      font-family: var(--font-mono);
      margin-top: 6px;
      color: var(--sky);
    }
    .metric-crit { color: var(--crit); }
    .metric-ok { color: var(--ok); }
    .panel-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
      gap: 18px;
      margin-bottom: 22px;
    }
    .section-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
      margin-bottom: 22px;
    }
    .section-head {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 14px;
    }
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
    }
    input[type="text"], select {
      background: var(--bg-input);
      color: var(--text);
      border: 1px solid var(--border-strong);
      border-radius: 6px;
      padding: 7px 11px;
      font-size: 0.83rem;
      font-family: var(--font-sans);
    }
    .mono { font-family: var(--font-mono); font-size: 0.8rem; }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 13px;
      border-radius: 6px;
      border: 1px solid transparent;
      font-weight: 600;
      font-size: 0.82rem;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.15s ease;
    }
    .btn-primary { background: var(--teal); color: hsl(216, 45%, 8%); }
    .btn-primary:hover { background: hsl(174, 82%, 50%); }
    .btn-secondary {
      background: var(--bg-panel);
      color: var(--text);
      border-color: var(--border-strong);
    }
    .btn-secondary:hover { border-color: var(--teal); }
    .btn-danger {
      background: var(--crit-soft);
      color: hsl(0, 92%, 76%);
      border-color: hsla(0, 84%, 62%, 0.4);
    }
    .btn-sm { padding: 4px 9px; font-size: 0.74rem; }
    .table-wrap {
      width: 100%;
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--bg-canvas);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }
    th, td {
      padding: 9px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
      word-break: break-word;
    }
    th {
      background: var(--bg-panel);
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    tr:last-child td { border-bottom: none; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 700;
      font-family: var(--font-mono);
    }
    .badge-CRITICAL { background: var(--crit-soft); color: hsl(0, 95%, 76%); border: 1px solid hsla(0, 84%, 62%, 0.45); }
    .badge-HIGH { background: var(--warn-soft); color: hsl(38, 95%, 72%); border: 1px solid hsla(38, 92%, 54%, 0.45); }
    .badge-OK { background: var(--ok-soft); color: hsl(152, 85%, 68%); border: 1px solid hsla(152, 76%, 44%, 0.45); }
    .badge-INFO { background: var(--sky-soft); color: hsl(199, 92%, 74%); }
    .status-toast {
      padding: 10px 14px;
      border-radius: 8px;
      margin-bottom: 16px;
      font-size: 0.84rem;
      background: var(--teal-soft);
      color: hsl(174, 85%, 76%);
      border: 1px solid hsla(174, 82%, 44%, 0.4);
      display: none;
    }
    .status-toast.visible { display: flex; justify-content: space-between; align-items: center; }
    .tz-control {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      background: var(--bg-panel);
      border: 1px solid var(--border-strong);
      border-radius: 7px;
      padding: 4px 10px;
      font-size: 0.78rem;
      color: var(--text-secondary);
    }
    .tz-control select {
      border: none;
      background: transparent;
      padding: 2px 4px;
      font-size: 0.79rem;
      color: var(--text);
      outline: none;
    }
    .tz-control select option {
      background: var(--bg-elevated);
      color: var(--text);
    }
    .clock-pill {
      font-family: var(--font-mono);
      font-size: 0.78rem;
      color: var(--teal);
      background: var(--teal-soft);
      border: 1px solid hsla(174, 82%, 44%, 0.35);
      border-radius: 999px;
      padding: 4px 11px;
      white-space: nowrap;
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand-wrap">
      <div class="brand-badge">SOC</div>
      <div>
        <h1>Consola SIEM &amp; SOC — Hospital Privacy-by-Design</h1>
        <div class="subtitle">Colector Syslog RFC 5424 (MC-02) · Sanitización Regex en Ingesta (MC-03) · Correlación Temporal (MC-04)</div>
      </div>
    </div>
    <div class="toolbar-actions">
      <span id="soc-clock-badge" class="clock-pill" title="Hora actual en el huso horario seleccionado">--:--:--</span>
      <label class="tz-control" for="timezone-select">
        <span>Huso horario:</span>
        <select id="timezone-select" aria-label="Huso horario de los logs SIEM">
          <option value="America/Mexico_City" selected>CDMX / México Centro (America/Mexico_City)</option>
          <option value="America/Monterrey">Monterrey (America/Monterrey)</option>
          <option value="America/Cancun">Cancún (America/Cancun)</option>
          <option value="America/Chihuahua">Chihuahua (America/Chihuahua)</option>
          <option value="America/Tijuana">Tijuana (America/Tijuana)</option>
          <option value="UTC">UTC (Tiempo Universal Coordinado)</option>
          <option value="America/New_York">Nueva York (America/New_York)</option>
          <option value="America/Los_Angeles">Los Ángeles (America/Los_Angeles)</option>
          <option value="America/Bogota">Bogotá (America/Bogota)</option>
          <option value="America/Argentina/Buenos_Aires">Buenos Aires (America/Argentina/Buenos_Aires)</option>
          <option value="Europe/Madrid">Madrid (Europe/Madrid)</option>
        </select>
      </label>
      <label style="font-size: 0.8rem; color: var(--text-secondary); display: inline-flex; align-items: center; gap: 6px;">
        <input type="checkbox" id="auto-refresh-toggle" checked />
        Auto-actualizar (5s)
      </label>
      <button id="refresh-btn" class="btn btn-primary" type="button">Actualizar Ahora</button>
      <a id="link-clinical-portal" class="btn btn-secondary" href="https://tralaleritosmigajeros.uk/portal">← Portal Clínico (:8000)</a>
    </div>
  </header>

  <main class="container">
    <div id="soc-toast" class="status-toast" role="status">
      <span id="soc-toast-text"></span>
      <button type="button" class="btn btn-secondary btn-sm" id="soc-toast-close">Cerrar</button>
    </div>

    <!-- KPI Metrics -->
    <div class="grid-metrics">
      <div class="card">
        <div class="metric-label">Eventos RFC 5424 Ingeridos</div>
        <div id="m-events" class="metric-value">0</div>
      </div>
      <div class="card">
        <div class="metric-label">Eventos Sanitizados (MC-03)</div>
        <div id="m-sanitized" class="metric-value metric-ok">0</div>
      </div>
      <div class="card">
        <div class="metric-label">Redacciones PII / Secretos (***)</div>
        <div id="m-redactions" class="metric-value metric-ok">0</div>
      </div>
      <div class="card">
        <div class="metric-label">Alertas SOC Abiertas (MC-04)</div>
        <div id="m-alerts" class="metric-value metric-crit">0</div>
      </div>
    </div>

    <!-- Correlation Rules Catalog & Live Syslog Simulator -->
    <div class="panel-grid">
      <div class="section-card" style="margin-bottom: 0;">
        <div class="section-head">
          <h2>Catálogo de Reglas de Correlación Temporal Activas (MC-04)</h2>
          <span class="badge badge-INFO">Tiempo Real</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID Regla</th><th>Nombre</th><th>Severidad</th><th>Umbral / Ventana</th>
              </tr>
            </thead>
            <tbody id="rules-body"></tbody>
          </table>
        </div>
      </div>

      <div class="section-card" style="margin-bottom: 0;">
        <div class="section-head">
          <h2>Simulador SOC de Ingesta Syslog RFC 5424 &amp; Sanitización</h2>
          <span class="badge badge-OK">POST /api/v1/ingest/syslog</span>
        </div>
        <p style="margin: 0 0 12px 0; font-size: 0.82rem; color: var(--text-secondary);">
          Prueba en vivo la ofuscación automática pre-persistencia (MC-03) y el disparo de alertas de correlación temporal (MC-04):
        </p>
        <div class="filter-bar" style="margin-bottom: 12px;">
          <button type="button" class="btn btn-secondary btn-sm" id="sim-pii-leak">
            Simular Fuga PII (Tarjeta Luhn + CURP + Password + JWT)
          </button>
          <button type="button" class="btn btn-danger btn-sm" id="sim-brute-force">
            Simular Fuerza Bruta (5x AUTH_LOGIN_FAILED → RULE-001)
          </button>
          <button type="button" class="btn btn-danger btn-sm" id="sim-mass-access">
            Simular Exfiltración Masiva (30 reg → RULE-002 CRÍTICA)
          </button>
          <button type="button" class="btn btn-secondary btn-sm" id="sim-opa-denial">
            Simular Function Creep (5x OPA_POLICY_DENIED → RULE-003)
          </button>
        </div>
        <div class="filter-bar">
          <input type="text" id="custom-syslog-input" class="mono" style="flex: 1;" value='<86>1 2026-11-23T19:00:00Z hospital-node hospital-privacy-api 4201 AUDIT_TEST [audit@32473 actor="dr_garcia" curp="PERJ920514HPLRNS08"] Intento con tarjeta 4111-1111-1111-1111' />
          <button type="button" class="btn btn-primary btn-sm" id="btn-send-custom-syslog">Ingerir Trama</button>
        </div>
      </div>
    </div>

    <!-- Active Correlation Alerts Table -->
    <section class="section-card">
      <div class="section-head">
        <h2>Alertas de Correlación Temporal Activas (MC-04)</h2>
        <div class="filter-bar">
          <select id="filter-alert-severity">
            <option value="">Todas las severidades</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
          </select>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th><th id="alerts-ts-header">Hora (America/Mexico_City)</th><th>Regla</th><th>Severidad</th><th>Entidad</th><th>Eventos / Umbral</th><th>Ventana</th><th>Resumen</th><th>Estado / Acción SOC</th>
            </tr>
          </thead>
          <tbody id="alerts-body"></tbody>
        </table>
      </div>
    </section>

    <!-- Sanitized RFC 5424 Events Table -->
    <section class="section-card">
      <div class="section-head">
        <h2>Últimos Eventos Syslog RFC 5424 Persistidos (Sanitizados en Ingesta — MC-02 / MC-03)</h2>
        <div class="filter-bar">
          <input type="text" id="filter-event-msgid" class="mono" placeholder="Filtrar MSGID (ej. AUTH_LOGIN_FAILED)" />
          <input type="text" id="filter-event-actor" class="mono" placeholder="Filtrar actor..." />
          <label style="font-size: 0.78rem; color: var(--text-secondary); display: inline-flex; align-items: center; gap: 5px;">
            <input type="checkbox" id="filter-sanitized-only" />
            Solo sanitizados (***)
          </label>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th><th id="events-ts-header">Timestamp (America/Mexico_City)</th><th>MSGID</th><th>Actor</th><th>IP Origen</th><th>Sanitizado (MC-03)</th><th>Mensaje Persistido</th>
            </tr>
          </thead>
          <tbody id="events-body"></tbody>
        </table>
      </div>
    </section>
  </main>

  <script>
    const DEFAULT_TIMEZONE = "America/Mexico_City";
    const TZ_STORAGE_KEY = "siem_display_timezone";
    let currentTimeZone = DEFAULT_TIMEZONE;
    let cachedAlerts = [];
    let cachedEvents = [];

    function initTimezoneSelector() {
      const select = document.getElementById("timezone-select");
      if (!select) return;

      try {
        const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        if (browserTz && !Array.from(select.options).some(function (o) { return o.value === browserTz; })) {
          const opt = document.createElement("option");
          opt.value = browserTz;
          opt.textContent = "Navegador (" + browserTz + ")";
          select.appendChild(opt);
        }
      } catch (_) {
        // Ignore if Intl resolvedOptions is unavailable.
      }

      let saved = DEFAULT_TIMEZONE;
      try {
        const stored = window.localStorage.getItem(TZ_STORAGE_KEY);
        if (stored && Array.from(select.options).some(function (o) { return o.value === stored; })) {
          saved = stored;
        }
      } catch (_) {
        saved = DEFAULT_TIMEZONE;
      }

      currentTimeZone = saved;
      select.value = currentTimeZone;
      updateTimezoneHeaders();
      updateClock();

      select.addEventListener("change", function () {
        currentTimeZone = select.value || DEFAULT_TIMEZONE;
        try {
          window.localStorage.setItem(TZ_STORAGE_KEY, currentTimeZone);
        } catch (_) {
          // Ignore storage restrictions.
        }
        updateTimezoneHeaders();
        updateClock();
        renderAlerts(cachedAlerts);
        renderEvents(cachedEvents);
      });
    }

    function formatTimestamp(isoString, timeZone) {
      if (!isoString) return "-";
      const date = new Date(isoString);
      if (Number.isNaN(date.getTime())) return String(isoString);
      const tz = timeZone || currentTimeZone || DEFAULT_TIMEZONE;
      try {
        const parts = new Intl.DateTimeFormat("en-CA", {
          timeZone: tz,
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hourCycle: "h23",
          timeZoneName: "short",
        }).formatToParts(date);
        const map = {};
        for (const p of parts) {
          map[p.type] = p.value;
        }
        return (
          map.year + "-" + map.month + "-" + map.day + " " +
          map.hour + ":" + map.minute + ":" + map.second +
          (map.timeZoneName ? " " + map.timeZoneName : "")
        );
      } catch (_) {
        return String(isoString);
      }
    }

    function updateTimezoneHeaders() {
      const alertsHdr = document.getElementById("alerts-ts-header");
      const eventsHdr = document.getElementById("events-ts-header");
      if (alertsHdr) alertsHdr.textContent = "Hora (" + currentTimeZone + ")";
      if (eventsHdr) eventsHdr.textContent = "Timestamp (" + currentTimeZone + ")";
    }

    function updateClock() {
      const pill = document.getElementById("soc-clock-badge");
      if (!pill) return;
      pill.textContent = formatTimestamp(new Date().toISOString(), currentTimeZone);
    }

    function showSocToast(msg) {
      const box = document.getElementById("soc-toast");
      const txt = document.getElementById("soc-toast-text");
      txt.textContent = msg;
      box.className = "status-toast visible";
    }

    function addCell(row, text, isMono) {
      const td = document.createElement("td");
      if (isMono) td.className = "mono";
      td.textContent = text === null || text === undefined ? "-" : String(text);
      row.appendChild(td);
      return td;
    }

    function addBadgeCell(row, text, variant) {
      const td = document.createElement("td");
      const span = document.createElement("span");
      span.className = "badge badge-" + variant;
      span.textContent = text;
      td.appendChild(span);
      row.appendChild(td);
    }

    function renderAlerts(alerts) {
      const alertsBody = document.getElementById("alerts-body");
      alertsBody.replaceChildren();
      if (!alerts.length) {
        const tr = document.createElement("tr");
        const td = addCell(tr, "Sin alertas disparadas para el filtro actual.");
        td.colSpan = 9;
        alertsBody.appendChild(tr);
        return;
      }
      for (const a of alerts) {
        const tr = document.createElement("tr");
        addCell(tr, a.id, true);
        const tdTs = addCell(tr, formatTimestamp(a.triggered_at, currentTimeZone), true);
        if (a.triggered_at) tdTs.title = "UTC: " + a.triggered_at;
        addCell(tr, a.rule_id + " (" + a.rule_name + ")", true);
        addBadgeCell(tr, a.severity, a.severity === "CRITICAL" ? "CRITICAL" : "HIGH");
        addCell(tr, a.entity_key, true);
        addCell(tr, a.event_count + " / " + a.threshold, true);
        addCell(tr, a.window_seconds + "s", true);
        addCell(tr, a.summary);

        const tdStatus = document.createElement("td");
        if (a.acknowledged) {
          const span = document.createElement("span");
          span.className = "badge badge-OK";
          span.textContent = "ACK (" + (a.acknowledged_by || "soc") + ")";
          if (a.acknowledged_at) {
            span.title = "Reconocida: " + formatTimestamp(a.acknowledged_at, currentTimeZone) + " (UTC: " + a.acknowledged_at + ")";
          }
          tdStatus.appendChild(span);
        } else {
          const btnAck = document.createElement("button");
          btnAck.type = "button";
          btnAck.className = "btn btn-primary btn-sm";
          btnAck.textContent = "Reconocer (ACK)";
          btnAck.addEventListener("click", function () { acknowledgeAlert(a.id); });
          tdStatus.appendChild(btnAck);
        }
        tr.appendChild(tdStatus);
        alertsBody.appendChild(tr);
      }
    }

    function renderEvents(events) {
      const eventsBody = document.getElementById("events-body");
      eventsBody.replaceChildren();
      if (!events.length) {
        const tr = document.createElement("tr");
        const td = addCell(tr, "Sin eventos recibidos.");
        td.colSpan = 7;
        eventsBody.appendChild(tr);
        return;
      }
      for (const ev of events) {
        const tr = document.createElement("tr");
        addCell(tr, ev.id, true);
        const tdTs = addCell(tr, formatTimestamp(ev.event_timestamp, currentTimeZone), true);
        tdTs.title = "UTC: " + ev.event_timestamp + (ev.received_at ? " | Recibido UTC: " + ev.received_at : "");
        addCell(tr, ev.msg_id, true);
        addCell(tr, ev.actor || "-", true);
        addCell(tr, ev.source_ip || "-", true);
        if (ev.sanitized) {
          addBadgeCell(tr, "SI (" + ev.redacted_categories.join(",") + ")", "OK");
        } else {
          addCell(tr, "NO");
        }
        addCell(tr, ev.message, true);
        eventsBody.appendChild(tr);
      }
    }

    async function acknowledgeAlert(alertId) {
      const resp = await fetch("/api/v1/alerts/" + encodeURIComponent(alertId) + "/ack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ acknowledged_by: "samuel_soc" })
      });
      if (resp.ok) {
        showSocToast("Alerta #" + alertId + " reconocida (ACK) por analista samuel_soc.");
        await refreshDashboard();
      }
    }

    async function ingestFrame(rawMessage) {
      const resp = await fetch("/api/v1/ingest/syslog", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_message: rawMessage })
      });
      return resp.json();
    }

    async function refreshDashboard() {
      const sevFilter = document.getElementById("filter-alert-severity").value;
      const msgIdFilter = document.getElementById("filter-event-msgid").value.trim();
      const actorFilter = document.getElementById("filter-event-actor").value.trim();
      const sanOnly = document.getElementById("filter-sanitized-only").checked;

      const alertParams = new URLSearchParams({ limit: "25" });
      if (sevFilter) alertParams.set("severity", sevFilter);

      const eventParams = new URLSearchParams({ limit: "35" });
      if (msgIdFilter) eventParams.set("msg_id", msgIdFilter);
      if (actorFilter) eventParams.set("actor", actorFilter);
      if (sanOnly) eventParams.set("sanitized_only", "true");

      const [statsResp, rulesResp, alertsResp, eventsResp] = await Promise.all([
        fetch("/api/v1/stats"),
        fetch("/api/v1/rules"),
        fetch("/api/v1/alerts?" + alertParams.toString()),
        fetch("/api/v1/events?" + eventParams.toString())
      ]);
      const stats = await statsResp.json();
      const rules = await rulesResp.json();
      const alerts = await alertsResp.json();
      const events = await eventsResp.json();

      cachedAlerts = Array.isArray(alerts) ? alerts : [];
      cachedEvents = Array.isArray(events) ? events : [];

      document.getElementById("m-events").textContent = String(stats.total_events);
      document.getElementById("m-sanitized").textContent = String(stats.sanitized_events);
      document.getElementById("m-redactions").textContent = String(stats.total_redactions);
      document.getElementById("m-alerts").textContent = String(stats.open_alerts);

      const rulesBody = document.getElementById("rules-body");
      rulesBody.replaceChildren();
      for (const r of rules) {
        const tr = document.createElement("tr");
        addCell(tr, r.rule_id, true);
        addCell(tr, r.rule_name, true);
        addBadgeCell(tr, r.severity, r.severity === "CRITICAL" ? "CRITICAL" : "HIGH");
        addCell(tr, r.threshold + " eventos / " + r.window_seconds + "s", true);
        rulesBody.appendChild(tr);
      }

      renderAlerts(cachedAlerts);
      renderEvents(cachedEvents);
    }

    document.getElementById("refresh-btn").addEventListener("click", refreshDashboard);
    document.getElementById("soc-toast-close").addEventListener("click", function () {
      document.getElementById("soc-toast").className = "status-toast";
    });
    document.getElementById("filter-alert-severity").addEventListener("change", refreshDashboard);
    document.getElementById("filter-event-msgid").addEventListener("input", refreshDashboard);
    document.getElementById("filter-event-actor").addEventListener("input", refreshDashboard);
    document.getElementById("filter-sanitized-only").addEventListener("change", refreshDashboard);

    document.getElementById("btn-send-custom-syslog").addEventListener("click", async function () {
      const raw = document.getElementById("custom-syslog-input").value.trim();
      if (!raw) return;
      const res = await ingestFrame(raw);
      showSocToast("Trama RFC 5424 ingerida (id=" + res.event.id + ", sanitizado=" + res.event.sanitized + ").");
      await refreshDashboard();
    });

    document.getElementById("sim-pii-leak").addEventListener("click", async function () {
      const ts = new Date().toISOString();
      const syntheticJwt = [
        btoa('{"alg":"HS256","typ":"JWT"}').replace(/=+$/, ""),
        btoa('{"sub":"demo_actor"}').replace(/=+$/, ""),
        "demoSignaturePlaceholder000000",
      ].join(".");
      const frame = '<86>1 ' + ts + ' hospital-node hospital-privacy-api 4201 AUDIT_PII_TEST [audit@32473 actor="dr_prueba" password="ClaveSecretaHospital2026!" curp="PERJ920514HPLRNS08"] Pago tarjeta=4111-1111-1111-1111 nss=45901234567 Authorization: Bearer ' + syntheticJwt;
      const res = await ingestFrame(frame);
      showSocToast("Sanitización MC-03 verificada: " + res.event.redaction_count + " secretos/PII enmascarados con *** antes de SQLite.");
      await refreshDashboard();
    });

    document.getElementById("sim-brute-force").addEventListener("click", async function () {
      let triggered = 0;
      for (let i = 0; i < 5; i++) {
        const ts = new Date().toISOString();
        const frame = '<84>1 ' + ts + ' hospital-node hospital-privacy-api 4201 AUTH_LOGIN_FAILED [audit@32473 actor="atacante_bf" action="login_password" outcome="failure" source_ip="203.0.113.99"] Intento fallido #' + (i + 1);
        const r = await ingestFrame(frame);
        if (r.triggered_alerts && r.triggered_alerts.length) triggered += r.triggered_alerts.length;
      }
      showSocToast("Simulación de Fuerza Bruta completada (5 intentos fallidos). Alertas RULE-001 disparadas: " + triggered);
      await refreshDashboard();
    });

    document.getElementById("sim-mass-access").addEventListener("click", async function () {
      const ts = new Date().toISOString();
      const frame = '<86>1 ' + ts + ' hospital-node hospital-privacy-api 4201 CLINICAL_RECORD_LIST [audit@32473 actor="dr_exfiltracion" role="medico" action="read_record" outcome="success" source_ip="198.51.100.77" records_count="30"] Consulta masiva de 30 expedientes clínicos';
      const r = await ingestFrame(frame);
      showSocToast("Simulación de Consulta Masiva completada (30 expedientes). Alerta CRÍTICA RULE-002 disparada: " + (r.triggered_alerts ? r.triggered_alerts.length : 0));
      await refreshDashboard();
    });

    document.getElementById("sim-opa-denial").addEventListener("click", async function () {
      let triggered = 0;
      for (let i = 0; i < 5; i++) {
        const ts = new Date().toISOString();
        const frame = '<84>1 ' + ts + ' hospital-node hospital-privacy-api 4201 OPA_POLICY_DENIED [audit@32473 actor="admin_curioso" role="admin_sec" action="read_record" outcome="denied" source_ip="198.51.100.90"] Denegación ABAC/OPA por Function Creep #' + (i + 1);
        const r = await ingestFrame(frame);
        if (r.triggered_alerts && r.triggered_alerts.length) triggered += r.triggered_alerts.length;
      }
      showSocToast("Simulación de Function Creep completada (5 denegaciones OPA). Alertas RULE-003 disparadas: " + triggered);
      await refreshDashboard();
    });

    (function configurePortalLink() {
      const link = document.getElementById("link-clinical-portal");
      if (!link) return;
      const host = window.location.hostname;
      if (host.endsWith("tralaleritosmigajeros.uk")) {
        link.href = "https://tralaleritosmigajeros.uk/portal";
      } else {
        link.href = window.location.protocol + "//" + host + ":8000/portal";
      }
    })();

    setInterval(updateClock, 1000);
    setInterval(function () {
      const toggle = document.getElementById("auto-refresh-toggle");
      if (toggle && toggle.checked) {
        refreshDashboard();
      }
    }, 5000);

    initTimezoneSelector();
    refreshDashboard();
  </script>
</body>
</html>
"""
