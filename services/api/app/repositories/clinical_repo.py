from datetime import datetime, timezone
from threading import Lock
from typing import Protocol
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


class PostgresClinicalRecordRepository:
    """Repositorio PostgreSQL sobre `clinical.medical_records` (red aislada `data_net`)."""

    _COLUMNS = (
        "record_id, opaque_patient_token, age_years, zip_prefix, gender, "
        "diagnosis_cie10, diagnosis_summary, department, purpose_scope, "
        "ttl_expires_at, is_sanitized, created_at"
    )

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
                        f"""
                        INSERT INTO clinical.medical_records (
                            record_id, opaque_patient_token, age_years, zip_prefix, gender,
                            diagnosis_cie10, diagnosis_summary, department, purpose_scope,
                            ttl_expires_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING {self._COLUMNS}
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

        assert row is not None
        return self._row_to_entity(row)

    def get_record_by_id(self, record_id: UUID) -> MedicalRecordEntity | None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        SELECT {self._COLUMNS}
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
        clauses: list[str] = []
        params: list[object] = []

        if not include_sanitized:
            clauses.append("is_sanitized = FALSE")
        if department is not None:
            clauses.append("department = %s")
            params.append(department.lower())
        if opaque_patient_token is not None:
            clauses.append("opaque_patient_token = %s")
            params.append(opaque_patient_token)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        SELECT {self._COLUMNS}
                        FROM clinical.medical_records
                        {where_sql}
                        ORDER BY created_at DESC
                        """,
                        params,
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
        assignments: list[str] = []
        params: list[object] = []

        if diagnosis_cie10 is not None:
            assignments.append("diagnosis_cie10 = %s")
            params.append(diagnosis_cie10)
        if diagnosis_summary is not None:
            assignments.append("diagnosis_summary = %s")
            params.append(diagnosis_summary)
        if department is not None:
            assignments.append("department = %s")
            params.append(department)
        if ttl_expires_at is not None:
            assignments.append("ttl_expires_at = %s")
            params.append(ttl_expires_at)

        if not assignments:
            return self.get_record_by_id(record_id)

        params.append(record_id)
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        UPDATE clinical.medical_records
                        SET {', '.join(assignments)}
                        WHERE record_id = %s
                        RETURNING {self._COLUMNS}
                        """,
                        params,
                    )
                    row = cur.fetchone()
                conn.commit()
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Error de conexión al actualizar expediente clínico."
            ) from exc

        return self._row_to_entity(row) if row else None
