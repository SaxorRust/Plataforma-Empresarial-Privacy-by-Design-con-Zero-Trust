import base64
from datetime import datetime, timezone
import json
import secrets
from uuid import uuid4

from conftest import load_service_app
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi.testclient import TestClient
import httpx


class FakeHashiCorpVaultTransport(httpx.BaseTransport):
    """
    Simulador HTTP fiel de HashiCorp Vault (Transit AES-256-GCM96 con derivación por contexto
    + rotación de versiones + KV v2 data/metadata/destroy) para pruebas unitarias e integración
    sin requerir contenedor externo en CI.
    """

    def __init__(self, expected_token: str = "test_vault_token") -> None:
        self.expected_token = expected_token
        self.mounts: dict[str, dict] = {"secret/": {"type": "kv", "options": {"version": "2"}}}
        self.transit_keys: dict[str, dict[int, bytes]] = {}
        self.kv_store: dict[str, dict] = {}

    @staticmethod
    def _derive_key(master_key: bytes, context_b64: str) -> bytes:
        context_bytes = base64.b64decode(context_b64)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"vault-transit-derived:" + context_bytes,
        )
        return hkdf.derive(master_key)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/sys/health":
            return httpx.Response(200, json={"initialized": True, "sealed": False})

        if request.headers.get("X-Vault-Token") != self.expected_token:
            return httpx.Response(403, json={"errors": ["permission denied"]})

        body = json.loads(request.content.decode("utf-8")) if request.content else {}

        if request.method == "GET" and path == "/v1/sys/mounts":
            return httpx.Response(200, json={"data": self.mounts})

        if request.method == "POST" and path.startswith("/v1/sys/mounts/"):
            mount_name = path.removeprefix("/v1/sys/mounts/").strip("/") + "/"
            self.mounts[mount_name] = body
            return httpx.Response(204)

        if path.startswith("/v1/transit/keys/"):
            rest = path.removeprefix("/v1/transit/keys/")
            if request.method == "POST" and rest.endswith("/rotate"):
                key_name = rest.removesuffix("/rotate")
                versions = self.transit_keys[key_name]
                next_ver = max(versions) + 1
                versions[next_ver] = secrets.token_bytes(32)
                return httpx.Response(204)
            if request.method == "POST":
                self.transit_keys.setdefault(rest, {1: secrets.token_bytes(32)})
                return httpx.Response(204)
            if request.method == "GET":
                versions = self.transit_keys.get(rest)
                if not versions:
                    return httpx.Response(404, json={"errors": []})
                return httpx.Response(200, json={"data": {"latest_version": max(versions)}})

        if request.method == "POST" and path.startswith("/v1/transit/encrypt/"):
            key_name = path.removeprefix("/v1/transit/encrypt/")
            versions = self.transit_keys[key_name]
            ver = max(versions)
            derived = self._derive_key(versions[ver], body["context"])
            nonce = secrets.token_bytes(12)
            plaintext = base64.b64decode(body["plaintext"])
            ct = AESGCM(derived).encrypt(nonce, plaintext, None)
            packed = base64.b64encode(nonce + ct).decode("ascii")
            return httpx.Response(
                200,
                json={"data": {"ciphertext": f"vault:v{ver}:{packed}", "key_version": ver}},
            )

        if request.method == "POST" and path.startswith("/v1/transit/decrypt/"):
            key_name = path.removeprefix("/v1/transit/decrypt/")
            versions = self.transit_keys[key_name]
            prefix, ver_str, packed = body["ciphertext"].split(":", 2)
            assert prefix == "vault" and ver_str.startswith("v")
            ver = int(ver_str[1:])
            derived = self._derive_key(versions[ver], body["context"])
            raw = base64.b64decode(packed)
            nonce, ct = raw[:12], raw[12:]
            try:
                pt = AESGCM(derived).decrypt(nonce, ct, None)
            except InvalidTag:
                return httpx.Response(400, json={"errors": ["decryption failed: invalid context"]})
            return httpx.Response(
                200,
                json={"data": {"plaintext": base64.b64encode(pt).decode("ascii")}},
            )

        if path.startswith("/v1/secret/data/"):
            key = path.removeprefix("/v1/secret/data/")
            if request.method == "POST":
                self.kv_store[key] = body["data"]
                return httpx.Response(200, json={"data": {"version": 1}})
            if request.method == "GET":
                stored = self.kv_store.get(key)
                if stored is None:
                    return httpx.Response(404, json={"errors": []})
                return httpx.Response(200, json={"data": {"data": stored}})

        if path.startswith("/v1/secret/metadata/"):
            key = path.removeprefix("/v1/secret/metadata/")
            if request.method == "GET":
                if key not in self.kv_store:
                    return httpx.Response(404, json={"errors": []})
                return httpx.Response(200, json={"data": {"current_version": 1}})
            if request.method == "DELETE":
                self.kv_store.pop(key, None)
                return httpx.Response(204)

        return httpx.Response(404, json={"errors": [f"unhandled {request.method} {path}"]})


def _build_vault_test_env():
    app = load_service_app("api")
    from app.models.auth import UserRecord
    from app.security.dependencies import get_jwt_service, get_vault_service
    from app.security.jwt_auth import JWTService, TokenRevocationStore
    from app.vault.service import VaultPIIVaultService

    vault_transport = FakeHashiCorpVaultTransport(expected_token="test_vault_token")
    vault_service = VaultPIIVaultService(
        vault_addr="http://vault.test:8200",
        vault_token="test_vault_token",
        transit_mount="transit",
        transit_key="hospital-pii-key",
        kv_mount="secret",
        kv_prefix="patients",
        transport=vault_transport,
    )
    jwt_service = JWTService(
        secret_key="test_jwt_secret_key_for_ci_at_least_32_bytes",
        algorithm="HS256",
        expire_minutes=30,
        issuer="Hospital-Privacy-ZeroTrust",
        revocation_store=TokenRevocationStore(),
    )
    app.dependency_overrides[get_vault_service] = lambda: vault_service
    app.dependency_overrides[get_jwt_service] = lambda: jwt_service

    def token_for_role(role: str) -> dict[str, str]:
        user = UserRecord(
            id=uuid4(),
            username=f"user_{role}",
            role=role,  # type: ignore[arg-type]
            password_hash="$argon2id$unused",
            webauthn_enabled=False,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        token, _, _ = jwt_service.create_access_token(user, amr=["pwd"])
        return {"Authorization": f"Bearer {token}"}

    return TestClient(app), vault_transport, vault_service, token_for_role


SAMPLE_PII = {
    "full_name": "María Fernanda Gómez Ruiz",
    "curp": "GORM920514MPLZMR08",
    "nss": "12345678901",
    "contact_email": "maria.gomez@example.org",
    "contact_phone": "+522221234567",
}


def test_vault_tokenize_detokenize_encryption_isolation_and_purge():
    client, vault_transport, _, token_for_role = _build_vault_test_env()

    # Sin JWT -> 401
    assert client.post("/vault/patients/tokenize", json=SAMPLE_PII).status_code == 401

    # Roles sin autoridad clínica (incluyendo admin_sec y super_admin IAM) bloqueados -> 403
    for blocked_tok_role in ("analista", "admin_sec", "auditor_arco", "paciente", "super_admin"):
        assert (
            client.post(
                "/vault/patients/tokenize",
                json=SAMPLE_PII,
                headers=token_for_role(blocked_tok_role),
            ).status_code
            == 403
        )

    # Médico tokeniza identificadores directos -> token opaco pat_...
    tok_resp = client.post(
        "/vault/patients/tokenize",
        json=SAMPLE_PII,
        headers=token_for_role("medico"),
    )
    assert tok_resp.status_code == 201
    tok_data = tok_resp.json()
    opaque_token = tok_data["opaque_patient_token"]
    assert opaque_token.startswith("pat_")
    assert len(opaque_token) == 36
    assert tok_data["vault_engine"] == "transit+kv-v2"
    assert tok_data["key_version"] == 1
    # La respuesta de tokenización NO devuelve PII directa
    assert "curp" not in tok_data
    assert "nss" not in tok_data

    # En KV v2 solo existe el ciphertext Transit (`vault:v1:...`), jamás PII en claro
    kv_entry = vault_transport.kv_store[f"patients/{opaque_token}"]
    assert kv_entry["ciphertext"].startswith("vault:v1:")
    serialized_kv = json.dumps(kv_entry)
    assert SAMPLE_PII["curp"] not in serialized_kv
    assert SAMPLE_PII["nss"] not in serialized_kv
    assert SAMPLE_PII["full_name"] not in serialized_kv

    # Roles sin autoridad clínica (incluyendo admin_sec y super_admin IAM) bloqueados -> 403
    for blocked_role in (
        "enfermeria",
        "analista",
        "paciente",
        "auditor_arco",
        "admin_sec",
        "super_admin",
    ):
        resp = client.get(
            f"/vault/patients/{opaque_token}",
            headers=token_for_role(blocked_role),
        )
        assert resp.status_code == 403

    # Médico detokeniza correctamente -> recupera PII intacta
    detok_resp = client.get(
        f"/vault/patients/{opaque_token}",
        headers=token_for_role("medico"),
    )
    assert detok_resp.status_code == 200
    detok_data = detok_resp.json()
    assert detok_data["opaque_patient_token"] == opaque_token
    assert detok_data["full_name"] == SAMPLE_PII["full_name"]
    assert detok_data["curp"] == SAMPLE_PII["curp"]
    assert detok_data["nss"] == SAMPLE_PII["nss"]

    # Médico NO puede purgar de bóveda -> 403
    deny_purge_resp = client.delete(
        f"/vault/patients/{opaque_token}",
        headers=token_for_role("medico"),
    )
    assert deny_purge_resp.status_code == 403

    # Auditor ARCO ejecuta purga permanente de metadatos KV v2 -> 200
    purge_resp = client.delete(
        f"/vault/patients/{opaque_token}",
        headers=token_for_role("auditor_arco"),
    )
    assert purge_resp.status_code == 200
    assert purge_resp.json()["status"] == "purged"
    assert purge_resp.json()["method"] == "VAULT_KV2_METADATA_DESTROY"

    # Tras purga, el token ya no existe -> 404
    after_purge = client.get(
        f"/vault/patients/{opaque_token}",
        headers=token_for_role("medico"),
    )
    assert after_purge.status_code == 404


def test_vault_key_rotation_and_context_binding_defense():
    client, vault_transport, _, token_for_role = _build_vault_test_env()

    admin_headers = token_for_role("admin_sec")
    medico_headers = token_for_role("medico")

    # Tokenizar paciente A con llave v1
    token_a = client.post(
        "/vault/patients/tokenize",
        json=SAMPLE_PII,
        headers=medico_headers,
    ).json()["opaque_patient_token"]

    # Verificar status y rotar llave Transit a v2
    status_before = client.get("/vault/status", headers=admin_headers)
    assert status_before.status_code == 200
    assert status_before.json()["latest_key_version"] == 1

    rotate_resp = client.post("/vault/keys/rotate", headers=admin_headers)
    assert rotate_resp.status_code == 200
    assert rotate_resp.json()["latest_key_version"] == 2

    # Tokenizar paciente B ahora usa llave v2
    pii_b = {
        "full_name": "Carlos Alberto Mendoza Soto",
        "curp": "MESC881120HPLRNS03",
        "nss": "98765432109",
    }
    tok_b_resp = client.post("/vault/patients/tokenize", json=pii_b, headers=medico_headers)
    assert tok_b_resp.status_code == 201
    assert tok_b_resp.json()["key_version"] == 2
    token_b = tok_b_resp.json()["opaque_patient_token"]

    # Paciente A (v1) y Paciente B (v2) siguen descifrando tras rotación
    assert (
        client.get(f"/vault/patients/{token_a}", headers=medico_headers).json()["curp"]
        == SAMPLE_PII["curp"]
    )
    assert (
        client.get(f"/vault/patients/{token_b}", headers=medico_headers).json()["curp"]
        == pii_b["curp"]
    )

    # Defensa criptográfica: intercambiar el ciphertext de B dentro de la entrada KV de A
    # falla al descifrar porque el `context` derivado está atado a `opaque_patient_token`
    vault_transport.kv_store[f"patients/{token_a}"]["ciphertext"] = vault_transport.kv_store[
        f"patients/{token_b}"
    ]["ciphertext"]
    tampered_resp = client.get(f"/vault/patients/{token_a}", headers=medico_headers)
    assert tampered_resp.status_code == 502


def test_vault_validates_curp_nss_and_blocks_token_path_traversal():
    client, _, _, token_for_role = _build_vault_test_env()
    medico_headers = token_for_role("medico")

    # CURP inválida -> 422
    bad_curp = {**SAMPLE_PII, "curp": "INVALIDA1234567890"}
    assert client.post("/vault/patients/tokenize", json=bad_curp, headers=medico_headers).status_code == 422

    # NSS inválido -> 422
    bad_nss = {**SAMPLE_PII, "nss": "12345"}
    assert client.post("/vault/patients/tokenize", json=bad_nss, headers=medico_headers).status_code == 422

    # Token malformado / intento de path traversal -> 400 (bloqueado antes de contactar Vault)
    for bad_token in ("not_a_token", "pat_short", "pat_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"):
        resp = client.get(f"/vault/patients/{bad_token}", headers=medico_headers)
        assert resp.status_code == 400
