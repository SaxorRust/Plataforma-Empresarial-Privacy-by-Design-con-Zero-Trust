from datetime import datetime, timezone
import hashlib
import json
import secrets
import struct
from uuid import UUID, uuid4

import cbor2
from conftest import load_service_app
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
import jwt
from webauthn.helpers import bytes_to_base64url


class InMemoryUserRepository:
    """Repositorio en memoria que emula el esquema `auth_identity` para pruebas rápidas en CI."""

    def __init__(self) -> None:
        self.users_by_id: dict[UUID, object] = {}
        self.users_by_name: dict[str, UUID] = {}
        self.credentials_by_id: dict[bytes, object] = {}

    def create_user(self, *, username: str, role: str, password_hash: str):
        from app.models.auth import UserRecord
        from app.repositories.auth_repo import DuplicateUsernameError

        if username in self.users_by_name:
            raise DuplicateUsernameError("El nombre de usuario ya se encuentra registrado.")
        record = UserRecord(
            id=uuid4(),
            username=username,
            role=role,  # type: ignore[arg-type]
            password_hash=password_hash,
            webauthn_enabled=False,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        self.users_by_id[record.id] = record
        self.users_by_name[username] = record.id
        return record

    def get_user_by_username(self, username: str):
        uid = self.users_by_name.get(username)
        return self.users_by_id.get(uid) if uid else None

    def get_user_by_id(self, user_id: UUID):
        return self.users_by_id.get(user_id)

    def update_password_hash(self, user_id: UUID, new_password_hash: str) -> None:
        from app.models.auth import UserRecord

        user = self.users_by_id[user_id]
        self.users_by_id[user_id] = UserRecord(
            id=user.id,
            username=user.username,
            role=user.role,
            password_hash=new_password_hash,
            webauthn_enabled=user.webauthn_enabled,
            is_active=user.is_active,
            created_at=user.created_at,
        )

    def add_webauthn_credential(
        self,
        *,
        user_id: UUID,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: list[str],
    ):
        from app.models.auth import UserRecord, WebAuthnCredentialRecord
        from app.repositories.auth_repo import DuplicateCredentialError

        if credential_id in self.credentials_by_id:
            raise DuplicateCredentialError("Credencial duplicada.")
        cred = WebAuthnCredentialRecord(
            id=uuid4(),
            user_id=user_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            transports=list(transports),
            created_at=datetime.now(timezone.utc),
        )
        self.credentials_by_id[credential_id] = cred
        user = self.users_by_id[user_id]
        self.users_by_id[user_id] = UserRecord(
            id=user.id,
            username=user.username,
            role=user.role,
            password_hash=user.password_hash,
            webauthn_enabled=True,
            is_active=user.is_active,
            created_at=user.created_at,
        )
        return cred

    def list_webauthn_credentials(self, user_id: UUID) -> list:
        return [c for c in self.credentials_by_id.values() if c.user_id == user_id]

    def update_webauthn_sign_count(self, credential_id: bytes, new_sign_count: int) -> None:
        from app.models.auth import WebAuthnCredentialRecord

        cred = self.credentials_by_id[credential_id]
        self.credentials_by_id[credential_id] = WebAuthnCredentialRecord(
            id=cred.id,
            user_id=cred.user_id,
            credential_id=cred.credential_id,
            public_key=cred.public_key,
            sign_count=new_sign_count,
            transports=cred.transports,
            created_at=cred.created_at,
        )

    def delete_webauthn_credential(self, user_id: UUID, credential_id: bytes) -> bool:
        from app.models.auth import UserRecord

        cred = self.credentials_by_id.get(credential_id)
        if cred is None or cred.user_id != user_id:
            return False
        del self.credentials_by_id[credential_id]
        still_has_creds = any(c.user_id == user_id for c in self.credentials_by_id.values())
        user = self.users_by_id[user_id]
        self.users_by_id[user_id] = UserRecord(
            id=user.id,
            username=user.username,
            role=user.role,
            password_hash=user.password_hash,
            webauthn_enabled=still_has_creds,
            is_active=user.is_active,
            created_at=user.created_at,
        )
        return True


class VirtualFIDO2Authenticator:
    """Autenticador virtual FIDO2 (ECDSA P-256 / COSE ES256) para pruebas criptográficas reales."""

    def __init__(self, rp_id: str, origin: str) -> None:
        self.rp_id = rp_id
        self.origin = origin
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.sign_count = 0

    def _cose_public_key(self) -> bytes:
        pub_numbers = self.private_key.public_key().public_numbers()
        x_bytes = pub_numbers.x.to_bytes(32, "big")
        y_bytes = pub_numbers.y.to_bytes(32, "big")
        # COSE Key: kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256), x, y
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes})

    def create_registration_credential(self, challenge_b64: str) -> dict:
        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": challenge_b64,
                "origin": self.origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        rp_id_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        # Flags: UP (0x01) | UV (0x04) | AT (0x40) = 0x45
        flags = bytes([0x45])
        sign_count_bytes = struct.pack(">I", self.sign_count)
        aaguid = bytes(16)
        cred_id_len = struct.pack(">H", len(self.credential_id))
        cose_pub = self._cose_public_key()
        auth_data = rp_id_hash + flags + sign_count_bytes + aaguid + cred_id_len + self.credential_id + cose_pub

        attestation_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cred_id_b64 = bytes_to_base64url(self.credential_id)

        return {
            "id": cred_id_b64,
            "rawId": cred_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation_obj),
                "transports": ["internal"],
            },
        }

    def create_assertion_credential(
        self,
        challenge_b64: str,
        *,
        origin_override: str | None = None,
        sign_count_override: int | None = None,
    ) -> dict:
        if sign_count_override is not None:
            current_count = sign_count_override
        else:
            self.sign_count += 1
            current_count = self.sign_count

        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge_b64,
                "origin": origin_override or self.origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        rp_id_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        # Flags: UP (0x01) | UV (0x04) = 0x05
        flags = bytes([0x05])
        sign_count_bytes = struct.pack(">I", current_count)
        auth_data = rp_id_hash + flags + sign_count_bytes

        client_data_hash = hashlib.sha256(client_data).digest()
        signature = self.private_key.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
        cred_id_b64 = bytes_to_base64url(self.credential_id)

        return {
            "id": cred_id_b64,
            "rawId": cred_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
            },
        }


def _build_auth_test_client():
    app = load_service_app("api")
    from app.security.dependencies import (
        get_jwt_service,
        get_password_service,
        get_user_repository,
        get_webauthn_service,
    )
    from app.security.jwt_auth import JWTService, TokenRevocationStore
    from app.security.passwords import Argon2idPasswordService
    from app.security.webauthn_service import WebAuthnChallengeStore, WebAuthnService

    repo = InMemoryUserRepository()
    # Parámetros Argon2id rápidos para pruebas unitarias (manteniendo algoritmo Argon2id + salt + pepper)
    pwd_service = Argon2idPasswordService(
        pepper="test_super_secret_pepper_32chars_min",
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
    )
    jwt_service = JWTService(
        secret_key="test_jwt_secret_key_for_ci_at_least_32_bytes",
        algorithm="HS256",
        expire_minutes=30,
        issuer="Hospital-Privacy-ZeroTrust",
        revocation_store=TokenRevocationStore(),
    )
    webauthn_service = WebAuthnService(
        rp_id="tralaleritosmigajeros.uk",
        rp_name="Hospital Privacy Zero Trust BUAP",
        expected_origins=["https://tralaleritosmigajeros.uk"],
        challenge_store=WebAuthnChallengeStore(ttl_seconds=300),
    )

    app.dependency_overrides[get_user_repository] = lambda: repo
    app.dependency_overrides[get_password_service] = lambda: pwd_service
    app.dependency_overrides[get_jwt_service] = lambda: jwt_service
    app.dependency_overrides[get_webauthn_service] = lambda: webauthn_service
    return TestClient(app), repo, pwd_service, jwt_service


def test_argon2id_unique_salt_and_pepper_binding():
    load_service_app("api")
    from app.security.passwords import Argon2idPasswordService

    svc_a = Argon2idPasswordService(
        pepper="pepper_alpha_secret_12345",
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
    )
    svc_b = Argon2idPasswordService(
        pepper="pepper_bravo_secret_98765",
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
    )

    hash_1 = svc_a.hash_password("Clinica!2026#Seguro")
    hash_2 = svc_a.hash_password("Clinica!2026#Seguro")

    assert hash_1.startswith("$argon2id$")
    assert hash_2.startswith("$argon2id$")
    # Salt único por hash
    assert hash_1 != hash_2
    assert svc_a.verify_password("Clinica!2026#Seguro", hash_1) is True
    assert svc_a.verify_password("Clinica!2026#Seguro", hash_2) is True
    assert svc_a.verify_password("ContrasenaIncorrecta!1", hash_1) is False
    # Sin el pepper correcto, el hash almacenado en BD no puede verificarse
    assert svc_b.verify_password("Clinica!2026#Seguro", hash_1) is False


def test_register_login_jwt_me_and_logout_revocation():
    client, repo, _, _ = _build_auth_test_client()

    # Contraseña débil rechazada
    weak_resp = client.post(
        "/auth/register",
        json={"username": "dr.garcia", "password": "weakpassword", "role": "medico"},
    )
    assert weak_resp.status_code == 422

    # Registro válido
    reg_resp = client.post(
        "/auth/register",
        json={"username": "dr.garcia", "password": "Medico!2026#Strong", "role": "medico"},
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    assert reg_data["username"] == "dr.garcia"
    assert reg_data["role"] == "medico"
    assert reg_data["webauthn_enabled"] is False
    assert "password_hash" not in reg_data

    # El hash persistido en BD es Argon2id (nunca texto plano)
    stored_user = repo.get_user_by_username("dr.garcia")
    assert stored_user is not None
    assert stored_user.password_hash.startswith("$argon2id$")
    assert "Medico!2026#Strong" not in stored_user.password_hash

    # Usuario duplicado -> 409 Conflict
    dup_resp = client.post(
        "/auth/register",
        json={"username": "dr.garcia", "password": "Medico!2026#Strong", "role": "medico"},
    )
    assert dup_resp.status_code == 409

    # Login con contraseña incorrecta -> 401
    bad_login = client.post(
        "/auth/login",
        json={"username": "dr.garcia", "password": "Wrong!2026#Password"},
    )
    assert bad_login.status_code == 401

    # Login exitoso -> JWT con amr=["pwd"]
    login_resp = client.post(
        "/auth/login",
        json={"username": "dr.garcia", "password": "Medico!2026#Strong"},
    )
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert token_data["token_type"] == "bearer"
    assert token_data["amr"] == ["pwd"]
    access_token = token_data["access_token"]

    # Consultar /auth/me autenticado
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["username"] == "dr.garcia"
    assert me_data["role"] == "medico"
    assert me_data["amr"] == ["pwd"]

    # Token forjado con algoritmo 'none' -> 401
    forged_none = jwt.encode({"sub": str(stored_user.id), "role": "admin_sec"}, key="", algorithm="none")
    forged_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {forged_none}"})
    assert forged_resp.status_code == 401

    # Logout revoca inmediatamente el jti
    logout_resp = client.post("/auth/logout", headers={"Authorization": f"Bearer {access_token}"})
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "logged_out"

    # Reutilizar el JWT revocado falla con 401
    revoked_me = client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert revoked_me.status_code == 401


def test_webauthn_passkey_full_flow_anti_phishing_replay_and_cloning():
    client, _, _, _ = _build_auth_test_client()

    # 1. Crear usuario y obtener sesión JWT inicial con Argon2id
    assert (
        client.post(
            "/auth/register",
            json={"username": "dra.lopez", "password": "Doctora!2026#Secure", "role": "medico"},
        ).status_code
        == 201
    )
    jwt_token = client.post(
        "/auth/login",
        json={"username": "dra.lopez", "password": "Doctora!2026#Secure"},
    ).json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {jwt_token}"}

    # 2. Iniciar registro FIDO2/WebAuthn
    begin_reg = client.post("/auth/webauthn/register/begin", headers=auth_headers)
    assert begin_reg.status_code == 200
    reg_options = begin_reg.json()["options"]
    assert reg_options["rp"]["id"] == "tralaleritosmigajeros.uk"

    # 3. Autenticador virtual FIDO2 genera atestación real ECDSA P-256
    authenticator = VirtualFIDO2Authenticator(
        rp_id="tralaleritosmigajeros.uk",
        origin="https://tralaleritosmigajeros.uk",
    )
    reg_credential = authenticator.create_registration_credential(reg_options["challenge"])
    complete_reg = client.post(
        "/auth/webauthn/register/complete",
        headers=auth_headers,
        json={"credential": reg_credential},
    )
    assert complete_reg.status_code == 201
    saved_cred_id = complete_reg.json()["credential_id"]
    assert complete_reg.json()["webauthn_enabled"] is True

    # 4. Listar Passkeys registradas
    list_resp = client.get("/auth/webauthn/credentials", headers=auth_headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1
    assert list_resp.json()[0]["credential_id"] == saved_cred_id

    # 5. Iniciar login sin contraseña con Passkey
    begin_login = client.post("/auth/webauthn/login/begin", json={"username": "dra.lopez"})
    assert begin_login.status_code == 200
    auth_options = begin_login.json()["options"]

    # 6. Prueba anti-phishing: origen falso rechazado con 401
    phishing_assertion = authenticator.create_assertion_credential(
        auth_options["challenge"],
        origin_override="https://evil-phishing-hospital.uk",
        sign_count_override=1,
    )
    phishing_resp = client.post(
        "/auth/webauthn/login/complete",
        json={"username": "dra.lopez", "credential": phishing_assertion},
    )
    assert phishing_resp.status_code == 401

    # 7. Nuevo reto válido -> login FIDO2 exitoso (sign_count=1)
    begin_login_2 = client.post("/auth/webauthn/login/begin", json={"username": "dra.lopez"})
    challenge_2 = begin_login_2.json()["options"]["challenge"]
    valid_assertion = authenticator.create_assertion_credential(challenge_2)
    complete_login = client.post(
        "/auth/webauthn/login/complete",
        json={"username": "dra.lopez", "credential": valid_assertion},
    )
    assert complete_login.status_code == 200
    fido_jwt_data = complete_login.json()
    assert fido_jwt_data["amr"] == ["webauthn", "fido2"]
    assert fido_jwt_data["user"]["webauthn_enabled"] is True

    # 8. Prueba anti-replay: reenviar la misma aserción falla con 401 (reto consumido)
    replay_resp = client.post(
        "/auth/webauthn/login/complete",
        json={"username": "dra.lopez", "credential": valid_assertion},
    )
    assert replay_resp.status_code == 401

    # 9. Prueba anti-clonación: nuevo reto firmado con sign_count estancado (=1) -> 401
    begin_login_3 = client.post("/auth/webauthn/login/begin", json={"username": "dra.lopez"})
    challenge_3 = begin_login_3.json()["options"]["challenge"]
    cloned_assertion = authenticator.create_assertion_credential(
        challenge_3, sign_count_override=1
    )
    cloned_resp = client.post(
        "/auth/webauthn/login/complete",
        json={"username": "dra.lopez", "credential": cloned_assertion},
    )
    assert cloned_resp.status_code == 401

    # 10. Nuevo login legítimo incrementando sign_count (=2) -> 200 OK
    begin_login_4 = client.post("/auth/webauthn/login/begin", json={"username": "dra.lopez"})
    challenge_4 = begin_login_4.json()["options"]["challenge"]
    next_assertion = authenticator.create_assertion_credential(challenge_4)
    assert (
        client.post(
            "/auth/webauthn/login/complete",
            json={"username": "dra.lopez", "credential": next_assertion},
        ).status_code
        == 200
    )

    # 11. Revocar Passkey -> 204 No Content y webauthn_enabled vuelve a False
    del_resp = client.delete(
        f"/auth/webauthn/credentials/{saved_cred_id}",
        headers=auth_headers,
    )
    assert del_resp.status_code == 204
    me_after = client.get("/auth/me", headers=auth_headers).json()
    assert me_after["webauthn_enabled"] is False
