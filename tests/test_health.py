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
    assert "script-src 'self'" in portal_resp.headers["content-security-policy"]
    assert "unsafe-inline" not in portal_resp.headers["content-security-policy"]

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

    js_resp = client.get("/ui/portal.js")
    assert js_resp.status_code == 200
    assert "javascript" in js_resp.headers["content-type"]
    assert "/clinical/records/segregated" in js_resp.text
    assert "DEMO_PASSWORD" not in js_resp.text

