from dataclasses import dataclass
import json
from threading import Lock
import time
from typing import Any, Literal
from uuid import UUID

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.models.auth import UserRecord, WebAuthnCredentialRecord

ChallengeFlow = Literal["registration", "authentication"]


class WebAuthnServiceError(Exception):
    """Error criptográfico o de flujo durante registro/autenticación FIDO2/WebAuthn."""


@dataclass(frozen=True)
class StoredChallenge:
    challenge: bytes
    expires_at: float


@dataclass(frozen=True)
class VerifiedPasskeyRegistration:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: list[str]


@dataclass(frozen=True)
class VerifiedPasskeyAuthentication:
    credential_id: bytes
    new_sign_count: int


class WebAuthnChallengeStore:
    """
    Almacén thread-safe de retos (challenges) WebAuthn de un solo uso con TTL estricto.
    Cada reto queda ligado a `(user_id, flow)` para prevenir ataques de replay o confusión
    entre registro y autenticación.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl_seconds = ttl_seconds
        self._entries: dict[tuple[UUID, ChallengeFlow], StoredChallenge] = {}
        self._lock = Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    def _prune_unlocked(self, now: float) -> None:
        expired_keys = [k for k, v in self._entries.items() if v.expires_at <= now]
        for key in expired_keys:
            del self._entries[key]

    def store(self, user_id: UUID, flow: ChallengeFlow, challenge: bytes) -> None:
        now = time.time()
        with self._lock:
            self._prune_unlocked(now)
            self._entries[(user_id, flow)] = StoredChallenge(
                challenge=challenge,
                expires_at=now + self._ttl_seconds,
            )

    def consume(self, user_id: UUID, flow: ChallengeFlow) -> bytes:
        now = time.time()
        with self._lock:
            self._prune_unlocked(now)
            entry = self._entries.pop((user_id, flow), None)
        if entry is None or entry.expires_at <= now:
            raise WebAuthnServiceError(
                "Reto WebAuthn inexistente o expirado; reinicia el flujo FIDO2."
            )
        return entry.challenge


def _parse_transports(transports: list[str] | None) -> list[AuthenticatorTransport] | None:
    if not transports:
        return None
    valid: list[AuthenticatorTransport] = []
    for item in transports:
        try:
            valid.append(AuthenticatorTransport(item))
        except ValueError:
            continue
    return valid or None


def _extract_transports_from_payload(credential: dict[str, Any]) -> list[str]:
    response = credential.get("response")
    if isinstance(response, dict):
        raw_transports = response.get("transports")
        if isinstance(raw_transports, list):
            return [str(t) for t in raw_transports if isinstance(t, str)]
    return []


class WebAuthnService:
    """
    Servicio FIDO2 / WebAuthn (Passkeys) resistente a phishing (MA-01):
    - Enlaza criptográficamente el origen (`expected_origin`) y Relying Party (`rp_id`).
    - Impide registro duplicado (`exclude_credentials`) y replay de retos (single-use TTL).
    - Valida contador de firmas (`sign_count`) para detectar autenticadores clonados.
    """

    def __init__(
        self,
        *,
        rp_id: str,
        rp_name: str,
        expected_origins: list[str],
        challenge_store: WebAuthnChallengeStore | None = None,
        require_user_verification: bool = False,
    ) -> None:
        self._rp_id = rp_id
        self._rp_name = rp_name
        self._expected_origins = expected_origins
        self._challenge_store = challenge_store or WebAuthnChallengeStore()
        self._require_user_verification = require_user_verification

    @property
    def rp_id(self) -> str:
        return self._rp_id

    @property
    def challenge_ttl_seconds(self) -> int:
        return self._challenge_store.ttl_seconds

    def begin_registration(
        self,
        user: UserRecord,
        existing_credentials: list[WebAuthnCredentialRecord],
    ) -> dict[str, Any]:
        exclude = [
            PublicKeyCredentialDescriptor(
                id=cred.credential_id,
                transports=_parse_transports(cred.transports),
            )
            for cred in existing_credentials
        ]
        options = generate_registration_options(
            rp_id=self._rp_id,
            rp_name=self._rp_name,
            user_id=user.id.bytes,
            user_name=user.username,
            user_display_name=user.username,
            timeout=self._challenge_store.ttl_seconds * 1000,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            exclude_credentials=exclude or None,
        )
        self._challenge_store.store(user.id, "registration", options.challenge)
        return json.loads(options_to_json(options))

    def complete_registration(
        self,
        user: UserRecord,
        credential: dict[str, Any],
    ) -> VerifiedPasskeyRegistration:
        expected_challenge = self._challenge_store.consume(user.id, "registration")
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=self._rp_id,
                expected_origin=self._expected_origins,
                require_user_verification=self._require_user_verification,
            )
        except (InvalidRegistrationResponse, ValueError, KeyError) as exc:
            raise WebAuthnServiceError(
                f"Falló la verificación de registro FIDO2/WebAuthn: {exc}"
            ) from exc

        transports = _extract_transports_from_payload(credential)
        return VerifiedPasskeyRegistration(
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            transports=transports,
        )

    def begin_authentication(
        self,
        user: UserRecord,
        credentials: list[WebAuthnCredentialRecord],
    ) -> dict[str, Any]:
        if not credentials:
            raise WebAuthnServiceError(
                "El usuario no tiene Passkeys FIDO2/WebAuthn registradas."
            )
        allow = [
            PublicKeyCredentialDescriptor(
                id=cred.credential_id,
                transports=_parse_transports(cred.transports),
            )
            for cred in credentials
        ]
        options = generate_authentication_options(
            rp_id=self._rp_id,
            timeout=self._challenge_store.ttl_seconds * 1000,
            allow_credentials=allow,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        self._challenge_store.store(user.id, "authentication", options.challenge)
        return json.loads(options_to_json(options))

    def complete_authentication(
        self,
        user: UserRecord,
        credential: dict[str, Any],
        stored_credentials: list[WebAuthnCredentialRecord],
    ) -> VerifiedPasskeyAuthentication:
        expected_challenge = self._challenge_store.consume(user.id, "authentication")

        raw_id_str = credential.get("rawId") or credential.get("id")
        if not isinstance(raw_id_str, str) or not raw_id_str:
            raise WebAuthnServiceError("Credencial WebAuthn sin identificador `rawId`/`id`.")

        try:
            incoming_cred_id = base64url_to_bytes(raw_id_str)
        except Exception as exc:
            raise WebAuthnServiceError("Identificador de credencial WebAuthn inválido.") from exc

        matched = next(
            (cred for cred in stored_credentials if cred.credential_id == incoming_cred_id),
            None,
        )
        if matched is None:
            raise WebAuthnServiceError("Passkey no registrada para este usuario.")

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=self._rp_id,
                expected_origin=self._expected_origins,
                credential_public_key=matched.public_key,
                credential_current_sign_count=matched.sign_count,
                require_user_verification=self._require_user_verification,
            )
        except (InvalidAuthenticationResponse, ValueError, KeyError) as exc:
            raise WebAuthnServiceError(
                f"Falló la verificación de autenticación FIDO2/WebAuthn: {exc}"
            ) from exc

        # Defensa adicional anti-clonación si el autenticador lleva contador > 0
        if matched.sign_count > 0 and verification.new_sign_count <= matched.sign_count:
            raise WebAuthnServiceError(
                "Anomalía detectada en sign_count (posible autenticador clonado)."
            )

        return VerifiedPasskeyAuthentication(
            credential_id=matched.credential_id,
            new_sign_count=verification.new_sign_count,
        )

    @staticmethod
    def encode_credential_id(credential_id: bytes) -> str:
        return bytes_to_base64url(credential_id)

    @staticmethod
    def decode_credential_id(credential_id_b64: str) -> bytes:
        try:
            return base64url_to_bytes(credential_id_b64)
        except Exception as exc:
            raise WebAuthnServiceError("Formato base64url de credential_id inválido.") from exc
