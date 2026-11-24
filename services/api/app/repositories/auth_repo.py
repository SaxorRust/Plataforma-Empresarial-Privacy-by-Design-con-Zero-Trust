from typing import Protocol
from uuid import UUID, uuid4

import psycopg
from psycopg.errors import UniqueViolation

from app.models.auth import UserRecord, UserRole, WebAuthnCredentialRecord


class DatabaseUnavailableError(Exception):
    """Error de conectividad o disponibilidad con PostgreSQL."""


class DuplicateUsernameError(Exception):
    """El nombre de usuario ya existe en `auth_identity.users`."""


class DuplicateCredentialError(Exception):
    """La credencial WebAuthn ya está registrada en el sistema."""


class UserRepository(Protocol):
    """Contrato de persistencia de identidades y credenciales WebAuthn (MA-01)."""

    def create_user(self, *, username: str, role: UserRole, password_hash: str) -> UserRecord: ...

    def get_user_by_username(self, username: str) -> UserRecord | None: ...

    def get_user_by_id(self, user_id: UUID) -> UserRecord | None: ...

    def list_users(self) -> list[UserRecord]: ...

    def update_user(
        self,
        user_id: UUID,
        *,
        role: UserRole | None = None,
        is_active: bool | None = None,
    ) -> UserRecord | None: ...

    def set_user_opaque_patient_token(
        self, user_id: UUID, opaque_patient_token: str | None
    ) -> UserRecord | None: ...

    def update_password_hash(self, user_id: UUID, new_password_hash: str) -> None: ...

    def add_webauthn_credential(
        self,
        *,
        user_id: UUID,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: list[str],
    ) -> WebAuthnCredentialRecord: ...

    def list_webauthn_credentials(self, user_id: UUID) -> list[WebAuthnCredentialRecord]: ...

    def update_webauthn_sign_count(self, credential_id: bytes, new_sign_count: int) -> None: ...

    def delete_webauthn_credential(self, user_id: UUID, credential_id: bytes) -> bool: ...


class PostgresUserRepository:
    """
    Repositorio PostgreSQL para el esquema `auth_identity`:
    - `auth_identity.users` (Argon2id hash, rol, estado WebAuthn, token opaco opcional de titular)
    - `auth_identity.webauthn_credentials` (llaves públicas COSE y sign_count)
    Todas las consultas usan parámetros preparados para prevenir inyección SQL.
    """

    def __init__(self, dsn: str, *, connect_timeout: int = 5) -> None:
        self._dsn = dsn
        self._connect_timeout = connect_timeout

    def _connect(self) -> psycopg.Connection:
        try:
            return psycopg.connect(
                self._dsn,
                connect_timeout=self._connect_timeout,
                autocommit=False,
            )
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "No fue posible conectar con la base de datos de identidades."
            ) from exc

    @staticmethod
    def _row_to_user(row: tuple) -> UserRecord:
        return UserRecord(
            id=row[0],
            username=row[1],
            role=row[2],
            password_hash=row[3],
            webauthn_enabled=bool(row[4]),
            is_active=bool(row[5]),
            created_at=row[6],
            opaque_patient_token=row[7] if len(row) > 7 else None,
        )

    @staticmethod
    def _row_to_credential(row: tuple) -> WebAuthnCredentialRecord:
        return WebAuthnCredentialRecord(
            id=row[0],
            user_id=row[1],
            credential_id=bytes(row[2]),
            public_key=bytes(row[3]),
            sign_count=int(row[4]),
            transports=list(row[5] or []),
            created_at=row[6],
        )

    def ensure_role_constraint(self) -> None:
        """Elimina cuentas `super_admin` heredadas, garantiza columna `opaque_patient_token` y constraint de los 6 roles ABAC."""
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        ALTER TABLE auth_identity.users
                        ADD COLUMN IF NOT EXISTS opaque_patient_token VARCHAR(128)
                        """
                    )
                    cur.execute("DROP INDEX IF EXISTS auth_identity.uq_single_super_admin")
                    cur.execute(
                        """
                        DELETE FROM auth_identity.users
                        WHERE role = 'super_admin' OR username = 'super_admin'
                        """
                    )
                    cur.execute(
                        "ALTER TABLE auth_identity.users DROP CONSTRAINT IF EXISTS users_role_check"
                    )
                    cur.execute(
                        """
                        ALTER TABLE auth_identity.users
                        ADD CONSTRAINT users_role_check
                        CHECK (role IN (
                            'medico', 'enfermeria', 'analista', 'auditor_arco',
                            'admin_sec', 'paciente'
                        ))
                        """
                    )
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al actualizar restricción de roles."
            ) from exc

    def create_user(self, *, username: str, role: UserRole, password_hash: str) -> UserRecord:
        user_id = uuid4()
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO auth_identity.users (id, username, role, password_hash)
                        VALUES (%s, %s, %s, %s)
                        RETURNING id, username, role, password_hash, webauthn_enabled,
                                  is_active, created_at, opaque_patient_token
                        """,
                        (user_id, username, role, password_hash),
                    )
                    row = cur.fetchone()
                conn.commit()
        except UniqueViolation as exc:
            raise DuplicateUsernameError("El nombre de usuario ya se encuentra registrado.") from exc
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al registrar usuario.") from exc

        if row is None:
            raise RuntimeError("PostgreSQL no devolvió la fila del usuario insertado.")
        return self._row_to_user(row)

    def get_user_by_username(self, username: str) -> UserRecord | None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, username, role, password_hash, webauthn_enabled,
                               is_active, created_at, opaque_patient_token
                        FROM auth_identity.users
                        WHERE username = %s
                        """,
                        (username,),
                    )
                    row = cur.fetchone()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al consultar usuario.") from exc

        return self._row_to_user(row) if row else None

    def get_user_by_id(self, user_id: UUID) -> UserRecord | None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, username, role, password_hash, webauthn_enabled,
                               is_active, created_at, opaque_patient_token
                        FROM auth_identity.users
                        WHERE id = %s
                        """,
                        (user_id,),
                    )
                    row = cur.fetchone()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al consultar usuario.") from exc

        return self._row_to_user(row) if row else None

    def list_users(self) -> list[UserRecord]:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, username, role, password_hash, webauthn_enabled,
                               is_active, created_at, opaque_patient_token
                        FROM auth_identity.users
                        ORDER BY created_at ASC, username ASC
                        """
                    )
                    rows = cur.fetchall()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al listar usuarios.") from exc

        return [self._row_to_user(row) for row in rows]

    def update_user(
        self,
        user_id: UUID,
        *,
        role: UserRole | None = None,
        is_active: bool | None = None,
    ) -> UserRecord | None:
        if role is None and is_active is None:
            return self.get_user_by_id(user_id)
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE auth_identity.users
                        SET role = COALESCE(%s, role),
                            is_active = COALESCE(%s, is_active)
                        WHERE id = %s
                        RETURNING id, username, role, password_hash, webauthn_enabled,
                                  is_active, created_at, opaque_patient_token
                        """,
                        (role, is_active, user_id),
                    )
                    row = cur.fetchone()
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al actualizar usuario.") from exc

        return self._row_to_user(row) if row else None

    def set_user_opaque_patient_token(
        self, user_id: UUID, opaque_patient_token: str | None
    ) -> UserRecord | None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE auth_identity.users
                        SET opaque_patient_token = %s
                        WHERE id = %s
                        RETURNING id, username, role, password_hash, webauthn_enabled,
                                  is_active, created_at, opaque_patient_token
                        """,
                        (opaque_patient_token, user_id),
                    )
                    row = cur.fetchone()
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al vincular token opaco de titular."
            ) from exc

        return self._row_to_user(row) if row else None

    def update_password_hash(self, user_id: UUID, new_password_hash: str) -> None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE auth_identity.users
                        SET password_hash = %s
                        WHERE id = %s
                        """,
                        (new_password_hash, user_id),
                    )
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al actualizar hash Argon2id.") from exc

    def add_webauthn_credential(
        self,
        *,
        user_id: UUID,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: list[str],
    ) -> WebAuthnCredentialRecord:
        record_id = uuid4()
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO auth_identity.webauthn_credentials
                            (id, user_id, credential_id, public_key, sign_count, transports)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id, user_id, credential_id, public_key, sign_count,
                                  transports, created_at
                        """,
                        (record_id, user_id, credential_id, public_key, sign_count, transports),
                    )
                    row = cur.fetchone()
                    cur.execute(
                        """
                        UPDATE auth_identity.users
                        SET webauthn_enabled = TRUE
                        WHERE id = %s
                        """,
                        (user_id,),
                    )
                conn.commit()
        except UniqueViolation as exc:
            raise DuplicateCredentialError(
                "Esta credencial Passkey ya fue registrada previamente."
            ) from exc
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al guardar Passkey.") from exc

        if row is None:
            raise RuntimeError("PostgreSQL no devolvió la fila de la credencial WebAuthn.")
        return self._row_to_credential(row)

    def list_webauthn_credentials(self, user_id: UUID) -> list[WebAuthnCredentialRecord]:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, user_id, credential_id, public_key, sign_count,
                               transports, created_at
                        FROM auth_identity.webauthn_credentials
                        WHERE user_id = %s
                        ORDER BY created_at ASC
                        """,
                        (user_id,),
                    )
                    rows = cur.fetchall()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al listar Passkeys.") from exc

        return [self._row_to_credential(row) for row in rows]

    def update_webauthn_sign_count(self, credential_id: bytes, new_sign_count: int) -> None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE auth_identity.webauthn_credentials
                        SET sign_count = %s
                        WHERE credential_id = %s
                        """,
                        (new_sign_count, credential_id),
                    )
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al actualizar sign_count.") from exc

    def delete_webauthn_credential(self, user_id: UUID, credential_id: bytes) -> bool:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        DELETE FROM auth_identity.webauthn_credentials
                        WHERE user_id = %s AND credential_id = %s
                        """,
                        (user_id, credential_id),
                    )
                    deleted = cur.rowcount > 0
                    if deleted:
                        cur.execute(
                            """
                            UPDATE auth_identity.users
                            SET webauthn_enabled = EXISTS (
                                SELECT 1
                                FROM auth_identity.webauthn_credentials
                                WHERE user_id = %s
                            )
                            WHERE id = %s
                            """,
                            (user_id, user_id),
                        )
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError("Error de conexión al revocar Passkey.") from exc

        return deleted
