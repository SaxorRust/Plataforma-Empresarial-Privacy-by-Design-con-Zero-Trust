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
        inactivity_timeout_seconds: int = 120,
        issuer: str = "Hospital-Privacy-ZeroTrust",
        revocation_store: TokenRevocationStore | None = None,
    ) -> None:
        if not secret_key or len(secret_key) < 16:
            raise ValueError("JWT_SECRET_KEY debe tener al menos 16 caracteres.")
        if algorithm.lower() == "none":
            raise ValueError("El algoritmo JWT 'none' está prohibido por Zero Trust.")
        if inactivity_timeout_seconds < 0:
            raise ValueError("inactivity_timeout_seconds debe ser mayor o igual a 0.")
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._expire_minutes = expire_minutes
        self._inactivity_timeout_seconds = inactivity_timeout_seconds
        self._issuer = issuer
        self._revocation_store = revocation_store or TokenRevocationStore()
        self._activity_lock = Lock()
        self._last_activity: dict[str, float] = {}
        self._session_expiry: dict[str, float] = {}
        self._user_sessions: dict[UUID, set[str]] = {}

    @property
    def expire_seconds(self) -> int:
        return self._expire_minutes * 60

    @property
    def inactivity_timeout_seconds(self) -> int:
        return self._inactivity_timeout_seconds

    def _prune_sessions_unlocked(self, now_ts: float) -> None:
        expired_jtis = [jti for jti, exp_ts in self._session_expiry.items() if exp_ts <= now_ts]
        for jti in expired_jtis:
            self._session_expiry.pop(jti, None)
            self._last_activity.pop(jti, None)
        for uid in list(self._user_sessions):
            self._user_sessions[uid].difference_update(expired_jtis)
            if not self._user_sessions[uid]:
                del self._user_sessions[uid]

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
        now_ts = time.time()
        with self._activity_lock:
            self._prune_sessions_unlocked(now_ts)
            self._last_activity[jti] = now_ts
            self._session_expiry[jti] = expires_at.timestamp()
            self._user_sessions.setdefault(user.id, set()).add(jti)
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
        iat_ts = float(int(payload["iat"]))
        now_ts = time.time()

        if self._inactivity_timeout_seconds > 0:
            with self._activity_lock:
                self._prune_sessions_unlocked(now_ts)
                last_seen = self._last_activity.get(jti, iat_ts)
                if (now_ts - last_seen) > self._inactivity_timeout_seconds:
                    self._last_activity.pop(jti, None)
                    self._session_expiry.pop(jti, None)
                    if user_id in self._user_sessions:
                        self._user_sessions[user_id].discard(jti)
                    self._revocation_store.revoke(jti, exp_dt)
                    raise TokenAuthenticationError(
                        "Sesión expirada por inactividad (2 minutos). Autentícate nuevamente."
                    )
                self._last_activity[jti] = now_ts
                self._session_expiry.setdefault(jti, exp_dt.timestamp())
                self._user_sessions.setdefault(user_id, set()).add(jti)

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
        with self._activity_lock:
            self._last_activity.pop(user.jti, None)
            self._session_expiry.pop(user.jti, None)
            if user.user_id in self._user_sessions:
                self._user_sessions[user.user_id].discard(user.jti)
        self._revocation_store.revoke(user.jti, user.exp)

    def revoke_user_sessions(self, user_id: UUID) -> int:
        """Revoca inmediatamente todas las sesiones JWT activas de un usuario."""
        now_ts = time.time()
        revoked_count = 0
        to_revoke: list[tuple[str, datetime]] = []
        with self._activity_lock:
            self._prune_sessions_unlocked(now_ts)
            jtis = self._user_sessions.pop(user_id, set())
            for jti in jtis:
                exp_ts = self._session_expiry.pop(jti, now_ts + self.expire_seconds)
                self._last_activity.pop(jti, None)
                to_revoke.append((jti, datetime.fromtimestamp(exp_ts, tz=timezone.utc)))
        for jti, exp_dt in to_revoke:
            self._revocation_store.revoke(jti, exp_dt)
            revoked_count += 1
        return revoked_count
