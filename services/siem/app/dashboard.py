"""Vista HTML del panel SOC de solo lectura (sin innerHTML dinámico, prevención XSS)."""

SOC_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Hospital Zero Trust — Consola SIEM &amp; SOC</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --ok: #22c55e;
      --warn: #f59e0b;
      --crit: #ef4444;
      --accent: #38bdf8;
    }
    body {
      margin: 0;
      padding: 24px;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    h1, h2 { margin: 0 0 12px 0; font-weight: 600; }
    .subtitle { color: var(--muted); margin-bottom: 20px; font-size: 0.95rem; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
    }
    .metric-label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; }
    .metric-value { font-size: 1.8rem; font-weight: 700; margin-top: 6px; color: var(--accent); }
    .metric-crit { color: var(--crit); }
    .metric-ok { color: var(--ok); }
    section { margin-bottom: 24px; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      font-size: 0.85rem;
    }
    th, td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      word-break: break-word;
    }
    th { background: #0b1220; color: var(--muted); font-weight: 600; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 700;
    }
    .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--crit); }
    .badge-HIGH { background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid var(--warn); }
    .badge-OK { background: rgba(34, 197, 94, 0.2); color: #86efac; border: 1px solid var(--ok); }
    .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    button {
      background: var(--accent);
      color: #082f49;
      border: none;
      border-radius: 6px;
      padding: 8px 14px;
      font-weight: 600;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="toolbar">
    <div>
      <h1>Consola SIEM &amp; SOC — Hospital Privacy-by-Design</h1>
      <div class="subtitle">Colector Syslog RFC 5424 · Sanitización Regex en Ingesta (MC-03) · Correlación Temporal (MC-04)</div>
    </div>
    <button id="refresh-btn" type="button">Actualizar</button>
  </div>

  <div class="grid">
    <div class="card"><div class="metric-label">Eventos RFC 5424</div><div id="m-events" class="metric-value">0</div></div>
    <div class="card"><div class="metric-label">Eventos Sanitizados</div><div id="m-sanitized" class="metric-value metric-ok">0</div></div>
    <div class="card"><div class="metric-label">Redacciones PII/Secretos</div><div id="m-redactions" class="metric-value metric-ok">0</div></div>
    <div class="card"><div class="metric-label">Alertas Abiertas</div><div id="m-alerts" class="metric-value metric-crit">0</div></div>
  </div>

  <section>
    <h2>Alertas de Correlación Temporal Activas</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th><th>Regla</th><th>Severidad</th><th>Entidad</th><th>Eventos / Umbral</th><th>Ventana</th><th>Resumen</th><th>Estado</th>
        </tr>
      </thead>
      <tbody id="alerts-body"></tbody>
    </table>
  </section>

  <section>
    <h2>Últimos Eventos Syslog RFC 5424 (Sanitizados)</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th><th>Timestamp</th><th>MSGID</th><th>Actor</th><th>IP</th><th>Sanitizado</th><th>Mensaje</th>
        </tr>
      </thead>
      <tbody id="events-body"></tbody>
    </table>
  </section>

  <script>
    function addCell(row, text) {
      const td = document.createElement("td");
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

    async function refreshDashboard() {
      const [statsResp, alertsResp, eventsResp] = await Promise.all([
        fetch("/api/v1/stats"),
        fetch("/api/v1/alerts?limit=25"),
        fetch("/api/v1/events?limit=30")
      ]);
      const stats = await statsResp.json();
      const alerts = await alertsResp.json();
      const events = await eventsResp.json();

      document.getElementById("m-events").textContent = String(stats.total_events);
      document.getElementById("m-sanitized").textContent = String(stats.sanitized_events);
      document.getElementById("m-redactions").textContent = String(stats.total_redactions);
      document.getElementById("m-alerts").textContent = String(stats.open_alerts);

      const alertsBody = document.getElementById("alerts-body");
      alertsBody.replaceChildren();
      if (!alerts.length) {
        const tr = document.createElement("tr");
        const td = addCell(tr, "Sin alertas disparadas.");
        td.colSpan = 8;
        alertsBody.appendChild(tr);
      } else {
        for (const a of alerts) {
          const tr = document.createElement("tr");
          addCell(tr, a.id);
          addCell(tr, a.rule_id + " (" + a.rule_name + ")");
          addBadgeCell(tr, a.severity, a.severity === "CRITICAL" ? "CRITICAL" : "HIGH");
          addCell(tr, a.entity_key);
          addCell(tr, a.event_count + " / " + a.threshold);
          addCell(tr, a.window_seconds + "s");
          addCell(tr, a.summary);
          addCell(tr, a.status);
          alertsBody.appendChild(tr);
        }
      }

      const eventsBody = document.getElementById("events-body");
      eventsBody.replaceChildren();
      if (!events.length) {
        const tr = document.createElement("tr");
        const td = addCell(tr, "Sin eventos recibidos.");
        td.colSpan = 7;
        eventsBody.appendChild(tr);
      } else {
        for (const ev of events) {
          const tr = document.createElement("tr");
          addCell(tr, ev.id);
          addCell(tr, ev.event_timestamp);
          addCell(tr, ev.msg_id);
          addCell(tr, ev.actor || "-");
          addCell(tr, ev.source_ip || "-");
          if (ev.sanitized) {
            addBadgeCell(tr, "SI (" + ev.redacted_categories.join(",") + ")", "OK");
          } else {
            addCell(tr, "NO");
          }
          addCell(tr, ev.message);
          eventsBody.appendChild(tr);
        }
      }
    }

    document.getElementById("refresh-btn").addEventListener("click", refreshDashboard);
    refreshDashboard();
  </script>
</body>
</html>
"""
