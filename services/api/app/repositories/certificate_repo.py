from datetime import datetime
import json
from threading import Lock
from typing import Any, Protocol
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from app.models.lifecycle import SanitizationCertificateEntity, SanitizationMethod
from app.repositories.auth_repo import DatabaseUnavailableError


class SanitizationCertificateRepository(Protocol):
    """Contrato de persistencia para `compliance.sanitization_certificates` (MB-04)."""

    def save_certificate(
        self,
        *,
        certificate_id: UUID,
        opaque_patient_token: str,
        method: SanitizationMethod,
        sha256_hash: str,
        requested_by: str,
        executed_at: datetime,
        certificate_json: dict[str, Any],
    ) -> SanitizationCertificateEntity: ...

    def get_certificate_by_id(
        self, certificate_id: UUID
    ) -> SanitizationCertificateEntity | None: ...

    def list_certificates(
        self, *, opaque_patient_token: str | None = None
    ) -> list[SanitizationCertificateEntity]: ...


class InMemorySanitizationCertificateRepository:
    """Repositorio en memoria thread-safe para pruebas unitarias e integración aislada."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._items: dict[UUID, SanitizationCertificateEntity] = {}

    def save_certificate(
        self,
        *,
        certificate_id: UUID,
        opaque_patient_token: str,
        method: SanitizationMethod,
        sha256_hash: str,
        requested_by: str,
        executed_at: datetime,
        certificate_json: dict[str, Any],
    ) -> SanitizationCertificateEntity:
        # Deep copy via JSON round-trip para garantizar inmutabilidad del registro
        cloned_payload = json.loads(json.dumps(certificate_json))
        entity = SanitizationCertificateEntity(
            certificate_id=certificate_id,
            opaque_patient_token=opaque_patient_token,
            method=method,
            sha256_hash=sha256_hash,
            requested_by=requested_by,
            executed_at=executed_at,
            certificate_json=cloned_payload,
        )
        with self._lock:
            self._items[certificate_id] = entity
        return entity

    def get_certificate_by_id(
        self, certificate_id: UUID
    ) -> SanitizationCertificateEntity | None:
        with self._lock:
            return self._items.get(certificate_id)

    def list_certificates(
        self, *, opaque_patient_token: str | None = None
    ) -> list[SanitizationCertificateEntity]:
        with self._lock:
            items = list(self._items.values())
        if opaque_patient_token is not None:
            items = [item for item in items if item.opaque_patient_token == opaque_patient_token]
        items.sort(key=lambda item: item.executed_at, reverse=True)
        return items

    def tamper_certificate_for_test(self, certificate_id: UUID, field: str, new_value: Any) -> None:
        """Auxiliar para probar detección de manipulación en verificación SHA-256."""
        with self._lock:
            existing = self._items.get(certificate_id)
            if existing is None:
                return
            tampered = dict(existing.certificate_json)
            tampered[field] = new_value
            self._items[certificate_id] = SanitizationCertificateEntity(
                certificate_id=existing.certificate_id,
                opaque_patient_token=existing.opaque_patient_token,
                method=existing.method,
                sha256_hash=existing.sha256_hash,
                requested_by=existing.requested_by,
                executed_at=existing.executed_at,
                certificate_json=tampered,
            )


class PostgresSanitizationCertificateRepository:
    """Repositorio PostgreSQL sobre `compliance.sanitization_certificates`."""

    def __init__(self, dsn: str, connect_timeout: int = 5) -> None:
        self._dsn = dsn
        self._connect_timeout = connect_timeout

    def _connect(self) -> psycopg.Connection:
        try:
            return psycopg.connect(self._dsn, connect_timeout=self._connect_timeout)
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "No fue posible conectar con PostgreSQL en `data_net`."
            ) from exc

    @staticmethod
    def _row_to_entity(row: tuple) -> SanitizationCertificateEntity:
        raw_json = row[6]
        cert_dict = json.loads(raw_json) if isinstance(raw_json, str) else dict(raw_json)
        return SanitizationCertificateEntity(
            certificate_id=row[0],
            opaque_patient_token=row[1],
            method=row[2],
            sha256_hash=str(row[3]).strip(),
            requested_by=row[4],
            executed_at=row[5],
            certificate_json=cert_dict,
        )

    def save_certificate(
        self,
        *,
        certificate_id: UUID,
        opaque_patient_token: str,
        method: SanitizationMethod,
        sha256_hash: str,
        requested_by: str,
        executed_at: datetime,
        certificate_json: dict[str, Any],
    ) -> SanitizationCertificateEntity:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO compliance.sanitization_certificates (
                            certificate_id, opaque_patient_token, method, sha256_hash,
                            requested_by, executed_at, certificate_json
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING certificate_id, opaque_patient_token, method, sha256_hash,
                                  requested_by, executed_at, certificate_json
                        """,
                        (
                            certificate_id,
                            opaque_patient_token,
                            method,
                            sha256_hash,
                            requested_by,
                            executed_at,
                            Jsonb(certificate_json),
                        ),
                    )
                    row = cur.fetchone()
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al guardar certificado de sanitización."
            ) from exc

        if row is None:
            raise RuntimeError("PostgreSQL no devolvió la fila del certificado insertado.")
        return self._row_to_entity(row)

    def get_certificate_by_id(
        self, certificate_id: UUID
    ) -> SanitizationCertificateEntity | None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT certificate_id, opaque_patient_token, method, sha256_hash,
                               requested_by, executed_at, certificate_json
                        FROM compliance.sanitization_certificates
                        WHERE certificate_id = %s
                        """,
                        (certificate_id,),
                    )
                    row = cur.fetchone()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al consultar certificado de sanitización."
            ) from exc

        return self._row_to_entity(row) if row else None

    def list_certificates(
        self, *, opaque_patient_token: str | None = None
    ) -> list[SanitizationCertificateEntity]:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    if opaque_patient_token is not None:
                        cur.execute(
                            """
                            SELECT certificate_id, opaque_patient_token, method, sha256_hash,
                                   requested_by, executed_at, certificate_json
                            FROM compliance.sanitization_certificates
                            WHERE opaque_patient_token = %s
                            ORDER BY executed_at DESC
                            """,
                            (opaque_patient_token,),
                        )
                    else:
                        cur.execute(
                            """
                            SELECT certificate_id, opaque_patient_token, method, sha256_hash,
                                   requested_by, executed_at, certificate_json
                            FROM compliance.sanitization_certificates
                            ORDER BY executed_at DESC
                            """
                        )
                    rows = cur.fetchall()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al listar certificados de sanitización."
            ) from exc

        return [self._row_to_entity(row) for row in rows]
