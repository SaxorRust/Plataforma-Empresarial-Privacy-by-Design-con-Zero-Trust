from conftest import load_service_client


def test_api_health():
    client = load_service_client("api")
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "hospital-privacy-api"


def test_api_root():
    client = load_service_client("api")
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert "modules" in data
    assert set(data["modules"].keys()) == {"A", "B", "C"}


def test_siem_health():
    client = load_service_client("siem")
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "siem-collector"


def test_api_portal_ui_and_static_assets():
    client = load_service_client("api")

    # 1. Acceso directo al portal HTML (/portal) con puerta de autenticación obligatoria
    portal_resp = client.get("/portal")
    assert portal_resp.status_code == 200
    assert "text/html" in portal_resp.headers["content-type"]
    assert 'id="auth-gate"' in portal_resp.text
    assert 'id="app-shell" class="is-hidden"' in portal_resp.text
    assert 'id="toggle-login-password"' in portal_resp.text
    assert 'id="toggle-reg-password"' in portal_resp.text
    assert 'id="btn-generate-password"' in portal_resp.text
    assert 'id="btn-copy-reg-password"' in portal_resp.text
    assert 'id="session-idle-timer"' not in portal_resp.text
    assert 'id="global-purpose-badge"' in portal_resp.text
    assert 'id="global-purpose-select"' not in portal_resp.text
    assert 'id="card-patient-identity"' in portal_resp.text
    assert 'id="tab-users"' in portal_resp.text
    assert 'id="nav-tab-users" data-tab="tab-users" data-roles="admin_sec"' in portal_resp.text
    assert "super_admin" not in portal_resp.text
    assert 'id="reg-role"' not in portal_resp.text
    assert "script-src 'self'" in portal_resp.headers["content-security-policy"]
    assert "style-src 'self'" in portal_resp.headers["content-security-policy"]
    assert "unsafe-inline" not in portal_resp.headers["content-security-policy"]
    assert 'style="' not in portal_resp.text
    assert "<style" not in portal_resp.text
    assert "<script>" not in portal_resp.text

    # 1b. OpenAPI / Swagger UI deshabilitado por defecto (Zero Trust — OWASP A05/API9)
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404

    # 2. Content negotiation en `/` para navegadores (`Accept: text/html`) vs API (`application/json`)
    browser_root = client.get("/", headers={"Accept": "text/html,application/xhtml+xml"})
    assert browser_root.status_code == 200
    assert "text/html" in browser_root.headers["content-type"]

    json_root = client.get("/?format=json", headers={"Accept": "text/html"})
    assert json_root.status_code == 200
    assert json_root.json()["portal_url"] == "/portal"

    # 3. Archivos estáticos CSS y JS servidos con cabeceras Zero Trust (sin credenciales embebidas)
    css_resp = client.get("/ui/portal.css")
    assert css_resp.status_code == 200
    assert "text/css" in css_resp.headers["content-type"]
    assert "--brand-teal" in css_resp.text
    assert ".password-toggle-btn" in css_resp.text
    assert ".password-actions-row" in css_resp.text

    js_resp = client.get("/ui/portal.js")
    assert js_resp.status_code == 200
    assert "javascript" in js_resp.headers["content-type"]
    assert "/clinical/records/segregated" in js_resp.text
    assert "setPasswordVisibility" in js_resp.text
    assert "generateSecurePassword" in js_resp.text
    assert "global-purpose-badge" in js_resp.text
    assert "inactivityTimeoutSeconds" not in js_resp.text
    assert "recordUserActivity" not in js_resp.text
    assert "DEMO_PASSWORD" not in js_resp.text


def test_siem_dashboard_timezone_selector_defaults_to_mexico_city():
    siem_client = load_service_client("siem")
    resp = siem_client.get("/")
    assert resp.status_code == 200
    assert 'id="timezone-select"' in resp.text
    assert 'value="America/Mexico_City" selected' in resp.text
    assert 'const DEFAULT_TIMEZONE = "America/Mexico_City"' in resp.text
    assert 'value="UTC"' in resp.text

