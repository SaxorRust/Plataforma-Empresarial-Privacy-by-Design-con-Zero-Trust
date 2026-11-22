from conftest import load_service_client


def test_security_headers_present_on_health():
    client = load_service_client("api")
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "max-age=31536000" in resp.headers["strict-transport-security"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "no-store" in resp.headers["cache-control"]
    assert resp.headers.get("x-request-id")


def test_edge_check_detects_cloudflare_headers():
    client = load_service_client("api")
    local_resp = client.get("/edge-check")
    assert local_resp.status_code == 200
    assert local_resp.json()["via_cloudflare"] is False

    cf_resp = client.get(
        "/edge-check",
        headers={
            "CF-Ray": "8a1b2c3d4e5f-MEX",
            "CF-IPCountry": "MX",
            "X-Forwarded-Proto": "https",
        },
    )
    assert cf_resp.status_code == 200
    data = cf_resp.json()
    assert data["via_cloudflare"] is True
    assert data["cf_ray"] == "8a1b2c3d4e5f-MEX"
    assert data["cf_country"] == "MX"
    assert data["forwarded_proto"] == "https"
