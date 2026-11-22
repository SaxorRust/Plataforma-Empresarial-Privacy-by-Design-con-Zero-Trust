import hashlib
import hmac

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


class Argon2idPasswordService:
    """
    Servicio de derivación y verificación de contraseñas basado en Argon2id (MA-01):
    - Salt criptográfico único por usuario (generado automáticamente por argon2-cffi).
    - Pepper secreto a nivel de aplicación combinado mediante HMAC-SHA256 antes de Argon2id
      (patrón recomendado por OWASP: si se compromete la BD sin el pepper, los hashes
      permanecen inutilizables para fuerza bruta offline).
    - Verificación dummy constante para mitigar enumeración de usuarios por timing.
    """

    def __init__(
        self,
        *,
        pepper: str,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 2,
        hash_len: int = 32,
        salt_len: int = 16,
    ) -> None:
        if not pepper or len(pepper) < 8:
            raise ValueError("ARGON2_PEPPER debe definirse con al menos 8 caracteres.")
        self._pepper = pepper.encode("utf-8")
        self._hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
            type=Type.ID,
        )
        # Hash dummy precalculado para igualar costo computacional cuando el usuario no existe
        self._dummy_hash = self.hash_password("Dummy!Passw0rd#TimingMitigation")

    def _apply_pepper(self, password: str) -> str:
        """Aplica el pepper secreto mediante HMAC-SHA256 antes de Argon2id."""
        digest = hmac.new(
            self._pepper,
            password.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return digest

    def hash_password(self, password: str) -> str:
        peppered = self._apply_pepper(password)
        return self._hasher.hash(peppered)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        if not stored_hash or not stored_hash.startswith("$argon2id$"):
            return False
        peppered = self._apply_pepper(password)
        try:
            return bool(self._hasher.verify(stored_hash, peppered))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def verify_dummy(self, password: str) -> None:
        """Ejecuta una verificación Argon2id real contra un hash dummy (anti-enumeración)."""
        self.verify_password(password, self._dummy_hash)

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            return bool(self._hasher.check_needs_rehash(stored_hash))
        except InvalidHashError:
            return True
