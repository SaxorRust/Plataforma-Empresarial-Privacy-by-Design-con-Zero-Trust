from datetime import datetime, timezone
import secrets
from threading import Lock
from typing import Literal, Protocol
from uuid import UUID, uuid4

import psycopg

from app.models.clinical import MedicalRecordEntity
from app.repositories.auth_repo import DatabaseUnavailableError


class ClinicalRecordRepository(Protocol):
    """Contrato de persistencia segregada para `clinical.medical_records` (sin PII directa)."""

    def create_record(
        self,
        *,
        opaque_patient_token: str,
        age_years: int,
        zip_prefix: str,
        gender: str,
        diagnosis_cie10: str,
        diagnosis_summary: str,
        department: str,
        purpose_scope: str = "atencion_medica",
        ttl_expires_at: datetime | None = None,
    ) -> MedicalRecordEntity: ...

    def get_record_by_id(self, record_id: UUID) -> MedicalRecordEntity | None: ...

    def list_records(
        self,
        *,
        department: str | None = None,
        opaque_patient_token: str | None = None,
        include_sanitized: bool = False,
    ) -> list[MedicalRecordEntity]: ...

    def update_record(
        self,
        record_id: UUID,
        *,
        diagnosis_cie10: str | None = None,
        diagnosis_summary: str | None = None,
        department: str | None = None,
        ttl_expires_at: datetime | None = None,
    ) -> MedicalRecordEntity | None: ...

    def list_expired_records(self, now: datetime) -> list[MedicalRecordEntity]: ...

    def overwrite_and_delete_record(self, record_id: UUID) -> bool: ...

    def count_active_records_for_token(self, opaque_patient_token: str) -> int: ...

    def overwrite_and_sanitize_records_for_token(
        self,
        opaque_patient_token: str,
        *,
        method: Literal["NIST_800_88_CLEAR", "NIST_800_88_PURGE"],
    ) -> tuple[list[UUID], int]: ...


class InMemoryClinicalRecordRepository:
    """Implementación en memoria thread-safe para pruebas unitarias e integración aislada."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._records: dict[UUID, MedicalRecordEntity] = {}

    def create_record(
        self,
        *,
        opaque_patient_token: str,
        age_years: int,
        zip_prefix: str,
        gender: str,
        diagnosis_cie10: str,
        diagnosis_summary: str,
        department: str,
        purpose_scope: str = "atencion_medica",
        ttl_expires_at: datetime | None = None,
    ) -> MedicalRecordEntity:
        record = MedicalRecordEntity(
            record_id=uuid4(),
            opaque_patient_token=opaque_patient_token,
            age_years=age_years,
            zip_prefix=zip_prefix,
            gender=gender,
            diagnosis_cie10=diagnosis_cie10,
            diagnosis_summary=diagnosis_summary,
            department=department,
            purpose_scope=purpose_scope,
            ttl_expires_at=ttl_expires_at,
            is_sanitized=False,
            created_at=datetime.now(timezone.utc),
        )
        with self._lock:
            self._records[record.record_id] = record
        return record

    def get_record_by_id(self, record_id: UUID) -> MedicalRecordEntity | None:
        with self._lock:
            return self._records.get(record_id)

    def list_records(
        self,
        *,
        department: str | None = None,
        opaque_patient_token: str | None = None,
        include_sanitized: bool = False,
    ) -> list[MedicalRecordEntity]:
        with self._lock:
            results = list(self._records.values())

        filtered: list[MedicalRecordEntity] = []
        for rec in results:
            if not include_sanitized and rec.is_sanitized:
                continue
            if department is not None and rec.department != department.lower():
                continue
            if opaque_patient_token is not None and rec.opaque_patient_token != opaque_patient_token:
                continue
            filtered.append(rec)

        filtered.sort(key=lambda r: r.created_at, reverse=True)
        return filtered

    def update_record(
        self,
        record_id: UUID,
        *,
        diagnosis_cie10: str | None = None,
        diagnosis_summary: str | None = None,
        department: str | None = None,
        ttl_expires_at: datetime | None = None,
    ) -> MedicalRecordEntity | None:
        with self._lock:
            existing = self._records.get(record_id)
            if existing is None:
                return None
            updated = MedicalRecordEntity(
                record_id=existing.record_id,
                opaque_patient_token=existing.opaque_patient_token,
                age_years=existing.age_years,
                zip_prefix=existing.zip_prefix,
                gender=existing.gender,
                diagnosis_cie10=(
                    diagnosis_cie10 if diagnosis_cie10 is not None else existing.diagnosis_cie10
                ),
                diagnosis_summary=(
                    diagnosis_summary
                    if diagnosis_summary is not None
                    else existing.diagnosis_summary
                ),
                department=department if department is not None else existing.department,
                purpose_scope=existing.purpose_scope,
                ttl_expires_at=(
                    ttl_expires_at if ttl_expires_at is not None else existing.ttl_expires_at
                ),
                is_sanitized=existing.is_sanitized,
                created_at=existing.created_at,
            )
            self._records[record_id] = updated
            return updated

    def mark_sanitized_for_test(self, record_id: UUID) -> None:
        """Auxiliar para pruebas de políticas sobre registros ya sanitizados."""
        with self._lock:
            existing = self._records.get(record_id)
            if existing is None:
                return
            self._records[record_id] = MedicalRecordEntity(
                record_id=existing.record_id,
                opaque_patient_token=existing.opaque_patient_token,
                age_years=0,
                zip_prefix="00000",
                gender="no_especificado",
                diagnosis_cie10="SANITIZED",
                diagnosis_summary="[NIST SP 800-88 SANITIZED]",
                department="sanitized",
                purpose_scope=existing.purpose_scope,
                ttl_expires_at=existing.ttl_expires_at,
                is_sanitized=True,
                created_at=existing.created_at,
            )

    def list_expired_records(self, now: datetime) -> list[MedicalRecordEntity]:
        with self._lock:
            return [
                rec
                for rec in self._records.values()
                if not rec.is_sanitized
                and rec.ttl_expires_at is not None
                and rec.ttl_expires_at <= now
            ]

    def overwrite_and_delete_record(self, record_id: UUID) -> bool:
        with self._lock:
            existing = self._records.get(record_id)
            if existing is None:
                return False
            # Sobrescritura previa a la eliminación definitiva
            self._records[record_id] = MedicalRecordEntity(
                record_id=existing.record_id,
                opaque_patient_token=existing.opaque_patient_token,
                age_years=0,
                zip_prefix="00000",
                gender="no_especificado",
                diagnosis_cie10="00000000",
                diagnosis_summary="0" * max(16, len(existing.diagnosis_summary)),
                department="00000000",
                purpose_scope=existing.purpose_scope,
                ttl_expires_at=existing.ttl_expires_at,
                is_sanitized=True,
                created_at=existing.created_at,
            )
            del self._records[record_id]
            return True

    def count_active_records_for_token(self, opaque_patient_token: str) -> int:
        with self._lock:
            return sum(
                1
                for rec in self._records.values()
                if rec.opaque_patient_token == opaque_patient_token and not rec.is_sanitized
            )

    def overwrite_and_sanitize_records_for_token(
        self,
        opaque_patient_token: str,
        *,
        method: Literal["NIST_800_88_CLEAR", "NIST_800_88_PURGE"],
    ) -> tuple[list[UUID], int]:
        passes = 3 if method == "NIST_800_88_PURGE" else 2
        tombstone_code = "PURGED" if method == "NIST_800_88_PURGE" else "SANITIZED"
        tombstone_dept = "purged" if method == "NIST_800_88_PURGE" else "sanitized"
        tombstone_summary = (
            "[NIST SP 800-88 PURGE - CRYPTOGRAPHICALLY ERASED]"
            if method == "NIST_800_88_PURGE"
            else "[NIST SP 800-88 CLEAR - OVERWRITTEN]"
        )

        sanitized_ids: list[UUID] = []
        with self._lock:
            targets = [
                rec
                for rec in self._records.values()
                if rec.opaque_patient_token == opaque_patient_token and not rec.is_sanitized
            ]
            for rec in targets:
                if method == "NIST_800_88_PURGE":
                    # Pasada 1: datos pseudoaleatorios criptográficos
                    self._records[rec.record_id] = MedicalRecordEntity(
                        record_id=rec.record_id,
                        opaque_patient_token=rec.opaque_patient_token,
                        age_years=secrets.randbelow(100),
                        zip_prefix=f"{secrets.randbelow(100000):05d}",
                        gender=secrets.token_hex(4),
                        diagnosis_cie10=secrets.token_hex(6),
                        diagnosis_summary=secrets.token_hex(32),
                        department=secrets.token_hex(8),
                        purpose_scope=rec.purpose_scope,
                        ttl_expires_at=rec.ttl_expires_at,
                        is_sanitized=False,
                        created_at=rec.created_at,
                    )
                # Pasada intermedia de ceros
                self._records[rec.record_id] = MedicalRecordEntity(
                    record_id=rec.record_id,
                    opaque_patient_token=rec.opaque_patient_token,
                    age_years=0,
                    zip_prefix="00000",
                    gender="00000000",
                    diagnosis_cie10="00000000",
                    diagnosis_summary="0" * max(32, len(rec.diagnosis_summary)),
                    department="00000000",
                    purpose_scope=rec.purpose_scope,
                    ttl_expires_at=rec.ttl_expires_at,
                    is_sanitized=False,
                    created_at=rec.created_at,
                )
                # Pasada final: marcador canónico NIST SP 800-88 + is_sanitized=TRUE
                self._records[rec.record_id] = MedicalRecordEntity(
                    record_id=rec.record_id,
                    opaque_patient_token=rec.opaque_patient_token,
                    age_years=0,
                    zip_prefix="00000",
                    gender="no_especificado",
                    diagnosis_cie10=tombstone_code,
                    diagnosis_summary=tombstone_summary,
                    department=tombstone_dept,
                    purpose_scope=rec.purpose_scope,
                    ttl_expires_at=rec.ttl_expires_at,
                    is_sanitized=True,
                    created_at=rec.created_at,
                )
                sanitized_ids.append(rec.record_id)

        sanitized_ids.sort()
        return sanitized_ids, passes


class PostgresClinicalRecordRepository:
    """Repositorio PostgreSQL sobre `clinical.medical_records` (red aislada `data_net`)."""

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
    def _row_to_entity(row: tuple) -> MedicalRecordEntity:
        return MedicalRecordEntity(
            record_id=row[0],
            opaque_patient_token=row[1],
            age_years=int(row[2]),
            zip_prefix=row[3],
            gender=row[4],
            diagnosis_cie10=row[5],
            diagnosis_summary=row[6],
            department=row[7],
            purpose_scope=row[8],
            ttl_expires_at=row[9],
            is_sanitized=bool(row[10]),
            created_at=row[11],
        )

    def create_record(
        self,
        *,
        opaque_patient_token: str,
        age_years: int,
        zip_prefix: str,
        gender: str,
        diagnosis_cie10: str,
        diagnosis_summary: str,
        department: str,
        purpose_scope: str = "atencion_medica",
        ttl_expires_at: datetime | None = None,
    ) -> MedicalRecordEntity:
        record_id = uuid4()
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO clinical.medical_records (
                            record_id, opaque_patient_token, age_years, zip_prefix, gender,
                            diagnosis_cie10, diagnosis_summary, department, purpose_scope,
                            ttl_expires_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING record_id, opaque_patient_token, age_years, zip_prefix, gender,
                                  diagnosis_cie10, diagnosis_summary, department, purpose_scope,
                                  ttl_expires_at, is_sanitized, created_at
                        """,
                        (
                            record_id,
                            opaque_patient_token,
                            age_years,
                            zip_prefix,
                            gender,
                            diagnosis_cie10,
                            diagnosis_summary,
                            department,
                            purpose_scope,
                            ttl_expires_at,
                        ),
                    )
                    row = cur.fetchone()
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al persistir expediente clínico."
            ) from exc

        if row is None:
            raise RuntimeError("PostgreSQL no devolvió la fila del expediente insertado.")
        return self._row_to_entity(row)

    def get_record_by_id(self, record_id: UUID) -> MedicalRecordEntity | None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT record_id, opaque_patient_token, age_years, zip_prefix, gender,
                               diagnosis_cie10, diagnosis_summary, department, purpose_scope,
                               ttl_expires_at, is_sanitized, created_at
                        FROM clinical.medical_records
                        WHERE record_id = %s
                        """,
                        (record_id,),
                    )
                    row = cur.fetchone()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al consultar expediente clínico."
            ) from exc

        return self._row_to_entity(row) if row else None

    def list_records(
        self,
        *,
        department: str | None = None,
        opaque_patient_token: str | None = None,
        include_sanitized: bool = False,
    ) -> list[MedicalRecordEntity]:
        dept_filter = department.lower() if department is not None else None
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT record_id, opaque_patient_token, age_years, zip_prefix, gender,
                               diagnosis_cie10, diagnosis_summary, department, purpose_scope,
                               ttl_expires_at, is_sanitized, created_at
                        FROM clinical.medical_records
                        WHERE (%s::boolean OR is_sanitized = FALSE)
                          AND (%s::varchar IS NULL OR department = %s)
                          AND (%s::varchar IS NULL OR opaque_patient_token = %s)
                        ORDER BY created_at DESC
                        """,
                        (
                            include_sanitized,
                            dept_filter,
                            dept_filter,
                            opaque_patient_token,
                            opaque_patient_token,
                        ),
                    )
                    rows = cur.fetchall()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al listar expedientes clínicos."
            ) from exc

        return [self._row_to_entity(row) for row in rows]

    def update_record(
        self,
        record_id: UUID,
        *,
        diagnosis_cie10: str | None = None,
        diagnosis_summary: str | None = None,
        department: str | None = None,
        ttl_expires_at: datetime | None = None,
    ) -> MedicalRecordEntity | None:
        if (
            diagnosis_cie10 is None
            and diagnosis_summary is None
            and department is None
            and ttl_expires_at is None
        ):
            return self.get_record_by_id(record_id)

        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE clinical.medical_records
                        SET diagnosis_cie10 = COALESCE(%s, diagnosis_cie10),
                            diagnosis_summary = COALESCE(%s, diagnosis_summary),
                            department = COALESCE(%s, department),
                            ttl_expires_at = COALESCE(%s, ttl_expires_at)
                        WHERE record_id = %s
                        RETURNING record_id, opaque_patient_token, age_years, zip_prefix, gender,
                                  diagnosis_cie10, diagnosis_summary, department, purpose_scope,
                                  ttl_expires_at, is_sanitized, created_at
                        """,
                        (
                            diagnosis_cie10,
                            diagnosis_summary,
                            department,
                            ttl_expires_at,
                            record_id,
                        ),
                    )
                    row = cur.fetchone()
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al actualizar expediente clínico."
            ) from exc

        return self._row_to_entity(row) if row else None

    def list_expired_records(self, now: datetime) -> list[MedicalRecordEntity]:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT record_id, opaque_patient_token, age_years, zip_prefix, gender,
                               diagnosis_cie10, diagnosis_summary, department, purpose_scope,
                               ttl_expires_at, is_sanitized, created_at
                        FROM clinical.medical_records
                        WHERE is_sanitized = FALSE
                          AND ttl_expires_at IS NOT NULL
                          AND ttl_expires_at <= %s
                        ORDER BY ttl_expires_at ASC
                        """,
                        (now,),
                    )
                    rows = cur.fetchall()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al consultar registros con TTL expirado."
            ) from exc

        return [self._row_to_entity(row) for row in rows]

    def overwrite_and_delete_record(self, record_id: UUID) -> bool:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    # Pasada de sobrescritura segura previa a la eliminación definitiva
                    cur.execute(
                        """
                        UPDATE clinical.medical_records
                        SET age_years = 0,
                            zip_prefix = '00000',
                            gender = 'no_especificado',
                            diagnosis_cie10 = '00000000',
                            diagnosis_summary = %s,
                            department = '00000000',
                            is_sanitized = TRUE
                        WHERE record_id = %s
                        """,
                        ("0" * 64, record_id),
                    )
                conn.commit()
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        DELETE FROM clinical.medical_records
                        WHERE record_id = %s
                        """,
                        (record_id,),
                    )
                    deleted = cur.rowcount > 0
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al purgar registro con TTL expirado."
            ) from exc

        return deleted

    def count_active_records_for_token(self, opaque_patient_token: str) -> int:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT COUNT(*)
                        FROM clinical.medical_records
                        WHERE opaque_patient_token = %s
                          AND is_sanitized = FALSE
                        """,
                        (opaque_patient_token,),
                    )
                    row = cur.fetchone()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al contar registros activos del paciente."
            ) from exc

        return int(row[0]) if row else 0

    def overwrite_and_sanitize_records_for_token(
        self,
        opaque_patient_token: str,
        *,
        method: Literal["NIST_800_88_CLEAR", "NIST_800_88_PURGE"],
    ) -> tuple[list[UUID], int]:
        passes = 3 if method == "NIST_800_88_PURGE" else 2
        tombstone_code = "PURGED" if method == "NIST_800_88_PURGE" else "SANITIZED"
        tombstone_dept = "purged" if method == "NIST_800_88_PURGE" else "sanitized"
        tombstone_summary = (
            "[NIST SP 800-88 PURGE - CRYPTOGRAPHICALLY ERASED]"
            if method == "NIST_800_88_PURGE"
            else "[NIST SP 800-88 CLEAR - OVERWRITTEN]"
        )

        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT record_id
                        FROM clinical.medical_records
                        WHERE opaque_patient_token = %s
                          AND is_sanitized = FALSE
                        ORDER BY record_id ASC
                        """,
                        (opaque_patient_token,),
                    )
                    target_ids = [row[0] for row in cur.fetchall()]

                if not target_ids:
                    return [], passes

                if method == "NIST_800_88_PURGE":
                    # Pasada 1: sobrescritura con bytes pseudoaleatorios criptográficos
                    with conn.cursor() as cur:
                        for rec_id in target_ids:
                            cur.execute(
                                """
                                UPDATE clinical.medical_records
                                SET age_years = %s,
                                    zip_prefix = %s,
                                    gender = %s,
                                    diagnosis_cie10 = %s,
                                    diagnosis_summary = %s,
                                    department = %s
                                WHERE record_id = %s
                                """,
                                (
                                    secrets.randbelow(100),
                                    f"{secrets.randbelow(100000):05d}",
                                    secrets.token_hex(4),
                                    secrets.token_hex(6),
                                    secrets.token_hex(32),
                                    secrets.token_hex(8),
                                    rec_id,
                                ),
                            )
                    conn.commit()

                # Pasada intermedia: sobrescritura uniforme de ceros
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE clinical.medical_records
                        SET age_years = 0,
                            zip_prefix = '00000',
                            gender = '00000000',
                            diagnosis_cie10 = '00000000',
                            diagnosis_summary = %s,
                            department = '00000000'
                        WHERE record_id = ANY(%s)
                        """,
                        ("0" * 64, target_ids),
                    )
                conn.commit()

                # Pasada final: marcador canónico NIST SP 800-88 + bloqueo is_sanitized=TRUE
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE clinical.medical_records
                        SET age_years = 0,
                            zip_prefix = '00000',
                            gender = 'no_especificado',
                            diagnosis_cie10 = %s,
                            diagnosis_summary = %s,
                            department = %s,
                            is_sanitized = TRUE
                        WHERE record_id = ANY(%s)
                        """,
                        (tombstone_code, tombstone_summary, tombstone_dept, target_ids),
                    )
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión durante sobrescritura NIST SP 800-88."
            ) from exc

        return sorted(target_ids), passes
