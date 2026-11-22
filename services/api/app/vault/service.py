import base64
from datetime import datetime, timezone
import json
import secrets
from threading import Lock
from typing import Any

import httpx

from app.models.vault import (
    OPAQUE_TOKEN_REGEX,
    DetokenizePatientResponse,
    PatientPIIRequest,
    PurgePatientResponse,
    TokenizePatientResponse,
    VaultRotateKeyResponse,
    VaultStatusResponse,
)


class VaultServiceError(Exception):
    """Error genérico al comunicarse con HashiCorp Vault."""


class VaultUnavailableError(VaultServiceError):
    """HashiCorp Vault no está disponible o está sellado."""


class VaultTokenNotFoundError(VaultServiceError):
    """El token opaco de paciente no existe o fue purgado de la bóveda."""


class InvalidOpaqueTokenError(VaultServiceError):
    """El formato del token opaco no cumple el patrón `pat_<32 hex>`."""


def _zero_bytearray(buffer: bytearray) -> None:
    """Sobrescribe un buffer mutable en memoria para minimizar exposición de PII."""
    for idx in range(len(buffer)):
        buffer[idx] = 0


class VaultPIIVaultService:
    """
    Servicio de Bóveda de Identificadores Directos con HashiCorp Vault (MA-02):
    - Combina **Transit Secrets Engine** (`aes256-gcm96`, derivación de clave por contexto)
      con **KV Secrets Engine v2** para aislamiento en profundidad.
    - Los identificadores directos (nombre completo, CURP, NSS) se cifran con Transit
      ligados criptográficamente a su `opaque_patient_token` (`pat_...`) mediante `context`,
      impidiendo reasignación/intercambio de ciphertexts entre pacientes.
    - La clave de cifrado nunca abandona HashiCorp Vault.
    - Soporta purga definitiva de metadatos y versiones KV v2 (preparado para NIST SP 800-88).
    """

    def __init__(
        self,
        *,
        vault_addr: str,
        vault_token: str,
        transit_mount: str = "transit",
        transit_key: str = "hospital-pii-key",
        kv_mount: str = "secret",
        kv_prefix: str = "patients",
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._vault_addr = vault_addr.rstrip("/")
        self._vault_token = vault_token
        self._transit_mount = transit_mount.strip("/")
        self._transit_key = transit_key.strip("/")
        self._kv_mount = kv_mount.strip("/")
        self._kv_prefix = kv_prefix.strip("/")
        self._timeout = timeout_seconds
        self._transport = transport
        self._initialized = False
        self._init_lock = Lock()

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self._vault_addr,
            headers={"X-Vault-Token": self._vault_token},
            timeout=self._timeout,
            transport=self._transport,
        )

    @staticmethod
    def _validate_opaque_token(opaque_token: str) -> str:
        if not OPAQUE_TOKEN_REGEX.match(opaque_token):
            raise InvalidOpaqueTokenError(
                "Token opaco inválido: debe cumplir el formato `pat_<32 caracteres hex>`."
            )
        return opaque_token

    @staticmethod
    def _encode_context(opaque_token: str) -> str:
        return base64.b64encode(opaque_token.encode("utf-8")).decode("ascii")

    def _request(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        allow_404: bool = False,
    ) -> httpx.Response:
        try:
            response = client.request(method, path, json=json_body)
        except httpx.HTTPError as exc:
            raise VaultUnavailableError(
                "No fue posible comunicarse con HashiCorp Vault."
            ) from exc

        if response.status_code == 404 and allow_404:
            return response
        if response.status_code in (501, 503):
            raise VaultUnavailableError("HashiCorp Vault no inicializado o sellado.")
        if response.status_code >= 400:
            raise VaultServiceError(
                f"Error de HashiCorp Vault (HTTP {response.status_code}) en operación de bóveda."
            )
        return response

    def ensure_initialized(self) -> None:
        """Habilita idempotentemente Transit, KV v2 y la llave AEAD `hospital-pii-key`."""
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            with self._client() as client:
                mounts_resp = self._request(client, "GET", "/v1/sys/mounts")
                mounts_payload = mounts_resp.json()
                mounts = mounts_payload.get("data", mounts_payload)

                if f"{self._transit_mount}/" not in mounts:
                    self._request(
                        client,
                        "POST",
                        f"/v1/sys/mounts/{self._transit_mount}",
                        json_body={"type": "transit"},
                    )

                if f"{self._kv_mount}/" not in mounts:
                    self._request(
                        client,
                        "POST",
                        f"/v1/sys/mounts/{self._kv_mount}",
                        json_body={"type": "kv", "options": {"version": "2"}},
                    )

                # Crear llave AEAD con derivación por contexto (idempotente en Vault)
                self._request(
                    client,
                    "POST",
                    f"/v1/{self._transit_mount}/keys/{self._transit_key}",
                    json_body={
                        "type": "aes256-gcm96",
                        "derived": True,
                        "exportable": False,
                    },
                )
            self._initialized = True

    def tokenize_patient(self, pii: PatientPIIRequest) -> TokenizePatientResponse:
        """
        Aísla los identificadores directos del paciente en HashiCorp Vault:
        1. Genera token opaco aleatorio `pat_<32 hex>` (128 bits de entropía, no reversible).
        2. Cifra el payload PII mediante Vault Transit (`aes256-gcm96` + `context=opaque_token`).
        3. Almacena exclusivamente el ciphertext (`vault:vN:...`) y metadatos en KV v2.
        """
        self.ensure_initialized()
        opaque_token = f"pat_{secrets.token_hex(16)}"
        created_at = datetime.now(timezone.utc)
        context_b64 = self._encode_context(opaque_token)

        pii_payload = {
            "full_name": pii.full_name,
            "curp": pii.curp,
            "nss": pii.nss,
            "contact_email": pii.contact_email,
            "contact_phone": pii.contact_phone,
        }
        raw_buffer = bytearray(json.dumps(pii_payload, separators=(",", ":")).encode("utf-8"))
        try:
            plaintext_b64 = base64.b64encode(bytes(raw_buffer)).decode("ascii")
        finally:
            _zero_bytearray(raw_buffer)

        with self._client() as client:
            enc_resp = self._request(
                client,
                "POST",
                f"/v1/{self._transit_mount}/encrypt/{self._transit_key}",
                json_body={
                    "plaintext": plaintext_b64,
                    "context": context_b64,
                },
            )
            enc_data = enc_resp.json().get("data", {})
            ciphertext = enc_data.get("ciphertext")
            key_version = int(enc_data.get("key_version", 1))
            if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:v"):
                raise VaultServiceError("Respuesta inválida de Vault Transit al cifrar PII.")

            self._request(
                client,
                "POST",
                f"/v1/{self._kv_mount}/data/{self._kv_prefix}/{opaque_token}",
                json_body={
                    "data": {
                        "opaque_patient_token": opaque_token,
                        "ciphertext": ciphertext,
                        "transit_key": self._transit_key,
                        "key_version": key_version,
                        "created_at": created_at.isoformat(),
                    }
                },
            )

        return TokenizePatientResponse(
            opaque_patient_token=opaque_token,
            transit_key=self._transit_key,
            key_version=key_version,
            created_at=created_at,
        )

    def detokenize_patient(self, opaque_token: str) -> DetokenizePatientResponse:
        """
        Resuelve un token opaco `pat_...` recuperando el sobre cifrado de KV v2
        y descifrándolo mediante Vault Transit con validación de `context`.
        """
        token = self._validate_opaque_token(opaque_token)
        self.ensure_initialized()
        context_b64 = self._encode_context(token)

        with self._client() as client:
            kv_resp = self._request(
                client,
                "GET",
                f"/v1/{self._kv_mount}/data/{self._kv_prefix}/{token}",
                allow_404=True,
            )
            if kv_resp.status_code == 404:
                raise VaultTokenNotFoundError("Token opaco no encontrado en la bóveda.")

            kv_outer = kv_resp.json().get("data", {})
            kv_data = kv_outer.get("data")
            if not isinstance(kv_data, dict) or not kv_data.get("ciphertext"):
                raise VaultTokenNotFoundError("Registro de bóveda eliminado o inexistente.")

            ciphertext = str(kv_data["ciphertext"])
            transit_key = str(kv_data.get("transit_key") or self._transit_key)
            created_at_raw = kv_data.get("created_at")

            dec_resp = self._request(
                client,
                "POST",
                f"/v1/{self._transit_mount}/decrypt/{transit_key}",
                json_body={
                    "ciphertext": ciphertext,
                    "context": context_b64,
                },
            )
            plaintext_b64 = dec_resp.json().get("data", {}).get("plaintext")
            if not isinstance(plaintext_b64, str):
                raise VaultServiceError("Respuesta inválida de Vault Transit al descifrar PII.")

        decoded_buffer = bytearray(base64.b64decode(plaintext_b64))
        try:
            pii_payload = json.loads(decoded_buffer.decode("utf-8"))
        finally:
            _zero_bytearray(decoded_buffer)

        created_at = (
            datetime.fromisoformat(created_at_raw)
            if isinstance(created_at_raw, str)
            else datetime.now(timezone.utc)
        )
        return DetokenizePatientResponse(
            opaque_patient_token=token,
            full_name=str(pii_payload["full_name"]),
            curp=str(pii_payload["curp"]),
            nss=str(pii_payload["nss"]),
            contact_email=pii_payload.get("contact_email"),
            contact_phone=pii_payload.get("contact_phone"),
            created_at=created_at,
        )

    def token_exists(self, opaque_token: str) -> bool:
        """
        Verifica si un token opaco `pat_...` existe en KV v2 consultando únicamente
        sus metadatos (sin descifrar ni exponer PII directa), preservando minimización
        al vincular expedientes clínicos segregados (MA-02).
        """
        token = self._validate_opaque_token(opaque_token)
        self.ensure_initialized()

        with self._client() as client:
            meta_resp = self._request(
                client,
                "GET",
                f"/v1/{self._kv_mount}/metadata/{self._kv_prefix}/{token}",
                allow_404=True,
            )
            return meta_resp.status_code == 200

    def purge_patient(self, opaque_token: str) -> PurgePatientResponse:
        """
        Destrucción permanente de TODAS las versiones y metadatos del secreto en KV v2
        (`DELETE /v1/{kv_mount}/metadata/{prefix}/{token}`), compatible con purga
        criptográfica NIST SP 800-88 (Módulo B).
        """
        token = self._validate_opaque_token(opaque_token)
        self.ensure_initialized()

        with self._client() as client:
            meta_resp = self._request(
                client,
                "GET",
                f"/v1/{self._kv_mount}/metadata/{self._kv_prefix}/{token}",
                allow_404=True,
            )
            if meta_resp.status_code == 404:
                raise VaultTokenNotFoundError("Token opaco no encontrado para purga.")

            self._request(
                client,
                "DELETE",
                f"/v1/{self._kv_mount}/metadata/{self._kv_prefix}/{token}",
            )

        return PurgePatientResponse(
            opaque_patient_token=token,
            purged_at=datetime.now(timezone.utc),
        )

    def rotate_transit_key(self) -> VaultRotateKeyResponse:
        """Rota la versión activa de la llave Transit sin interrumpir descifrados previos."""
        self.ensure_initialized()
        with self._client() as client:
            self._request(
                client,
                "POST",
                f"/v1/{self._transit_mount}/keys/{self._transit_key}/rotate",
            )
            key_resp = self._request(
                client,
                "GET",
                f"/v1/{self._transit_mount}/keys/{self._transit_key}",
            )
            latest_version = int(key_resp.json().get("data", {}).get("latest_version", 1))

        return VaultRotateKeyResponse(
            transit_key=self._transit_key,
            latest_key_version=latest_version,
            rotated_at=datetime.now(timezone.utc),
        )

    def get_status(self) -> VaultStatusResponse:
        """Consulta salud de HashiCorp Vault y metadatos de la llave Transit."""
        with self._client() as client:
            try:
                health_resp = client.get("/v1/sys/health")
            except httpx.HTTPError as exc:
                raise VaultUnavailableError(
                    "No fue posible consultar el estado de HashiCorp Vault."
                ) from exc

            health = health_resp.json()
            initialized = bool(health.get("initialized", False))
            sealed = bool(health.get("sealed", True))

        latest_version = 0
        if initialized and not sealed:
            self.ensure_initialized()
            with self._client() as client:
                key_resp = self._request(
                    client,
                    "GET",
                    f"/v1/{self._transit_mount}/keys/{self._transit_key}",
                )
                latest_version = int(key_resp.json().get("data", {}).get("latest_version", 0))

        return VaultStatusResponse(
            reachable=True,
            initialized=initialized,
            sealed=sealed,
            transit_mount=self._transit_mount,
            transit_key=self._transit_key,
            latest_key_version=latest_version,
            kv_mount=self._kv_mount,
        )
