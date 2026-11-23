from datetime import datetime, timedelta, timezone
from threading import Lock
import time
from uuid import UUID, uuid4

import jwt
from jwt import InvalidTokenError

from app.models.auth import AuthenticatedUser, UserRecord, UserRole

VALID_ROLES: set[str] = {
    "medico",
    "enfermeria",
    "analista",
    "auditor_arco",
    "admin_sec",
    "paciente",
    "super_admin",
}


class TokenAuthenticationError(Exception):
    """Error al validar o decodificar un token JWT de sesión."""


class TokenRevocationStore:
    """
    Lista de revocación de `jti` en memoria con limpieza automática por expiración.
    Permite invalidación inmediata de sesiones en `POST /auth/logout` (Zero Trust).
    """

    def __init__(self) -> None:
        self._revoked: dict[str, float] = {}
        self._lock = Lock()

    def _prune_unlocked(self, now_ts: float) -> None:
        expired = [jti for jti, exp_ts in self._revoked.items() if exp_ts <= now_ts]
        for jti in expired:
            del self._revoked[jti]

    def revoke(self, jti: str, exp: datetime) -> None:
        now_ts = time.time()
        with self._lock:
            self._prune_unlocked(now_ts)
            self._revoked[jti] = exp.timestamp()

    def is_revoked(self, jti: str) -> bool:
        now_ts = time.time()
        with self._lock:
            self._prune_unlocked(now_ts)
            return jti in self._revoked


class JWTService:
    """
    Emisión y validación estricta de sesiones JWT (MA-01):
    - Restringe el algoritmo permitido (bloquea ataques `alg: none` y confusión de algoritmo).
    - Incluye claims `sub`, `username`, `role`, `amr` (RFC 8176), `jti`, `iat`, `nbf`, `exp`, `iss`.
    - Integra verificación de revocación inmediata por `jti`.
    """

    def __init__(
        self,
        *,
        secret_key: str,
        algorithm: str = "HS256",
        expire_minutes: int = 30,
        issuer: str = "Hospital-Privacy-ZeroTrust",
        revocation_store: TokenRevocationStore | None = None,
    ) -> None:
        if not secret_key or len(secret_key) < 16:
            raise ValueError("JWT_SECRET_KEY debe tener al menos 16 caracteres.")
        if algorithm.lower() == "none":
            raise ValueError("El algoritmo JWT 'none' está prohibido por Zero Trust.")
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._expire_minutes = expire_minutes
        self._issuer = issuer
        self._revocation_store = revocation_store or TokenRevocationStore()

    @property
    def expire_seconds(self) -> int:
        return self._expire_minutes * 60

    def create_access_token(
        self,
        user: UserRecord,
        *,
        amr: list[str],
    ) -> tuple[str, str, datetime]:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=self._expire_minutes)
        jti = str(uuid4())

        payload = {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
            "amr": list(amr),
            "jti": jti,
            "iss": self._issuer,
            "type": "access",
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        token = jwt.encode(payload, self._secret_key, algorithm=self._algorithm)
        return token, jti, expires_at

    def verify_access_token(self, token: str) -> AuthenticatedUser:
        try:
            payload = jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                options={"require": ["sub", "username", "role", "amr", "jti", "exp", "iat", "iss"]},
            )
        except InvalidTokenError as exc:
            raise TokenAuthenticationError("Token de sesión inválido o expirado.") from exc

        if payload.get("type") != "access":
            raise TokenAuthenticationError("Tipo de token no autorizado.")

        jti = str(payload["jti"])
        if self._revocation_store.is_revoked(jti):
            raise TokenAuthenticationError("La sesión fue revocada.")

        role = str(payload["role"])
        if role not in VALID_ROLES:
            raise TokenAuthenticationError("Rol incluido en el token no es válido.")

        try:
            user_id = UUID(str(payload["sub"]))
        except ValueError as exc:
            raise TokenAuthenticationError("Identificador de sujeto inválido.") from exc

        raw_amr = payload.get("amr")
        if not isinstance(raw_amr, list) or not all(isinstance(item, str) for item in raw_amr):
            raise TokenAuthenticationError("Claim 'amr' malformado.")

        exp_dt = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)
        typed_role: UserRole = role  # type: ignore[assignment]
        return AuthenticatedUser(
            user_id=user_id,
            username=str(payload["username"]),
            role=typed_role,
            amr=list(raw_amr),
            jti=jti,
            exp=exp_dt,
        )

    def revoke_token(self, user: AuthenticatedUser) -> None:
        self._revocation_store.revoke(user.jti, user.exp)
