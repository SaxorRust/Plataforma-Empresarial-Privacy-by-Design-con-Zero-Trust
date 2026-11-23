from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.vault import OPAQUE_TOKEN_REGEX

SanitizationMethod = Literal["NIST_800_88_CLEAR", "NIST_800_88_PURGE"]
ExportFormat = Literal["json", "csv"]


@dataclass(frozen=True)
class SanitizationCertificateEntity:
    """Representación interna de una fila de `compliance.sanitization_certificates` (MB-04)."""

    certificate_id: UUID
    opaque_patient_token: str
    method: SanitizationMethod
    sha256_hash: str
    requested_by: str
    executed_at: datetime
    certificate_json: dict[str, Any]


# ------------------------------------------------------------------------------
# MB-01: Retención Temporal Automatizada (TTL)
# ------------------------------------------------------------------------------
class TTLSweepResponse(BaseModel):
    triggered_by: str
    executed_at: datetime
    purged_records_count: int
    purged_record_ids: list[UUID]
    purged_vault_tokens_count: int
    purged_vault_tokens: list[str]
    skipped_vault_tokens_with_active_records: list[str]


class TTLStatusResponse(BaseModel):
    enabled: bool
    scheduler_running: bool
    interval_seconds: int
    total_sweeps: int
    total_records_purged: int
    total_vault_tokens_purged: int
    last_run_at: datetime | None = None
    last_error: str | None = None


# ------------------------------------------------------------------------------
# MB-02: Exportación Desidentificada (Safe Harbor + k-Anonimato + l-Diversidad)
# ------------------------------------------------------------------------------
class AnonymizedExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    k: int = Field(
        default=2,
        ge=2,
        le=50,
        description="Parámetro k-anonimato: tamaño mínimo de cada clase de equivalencia.",
    )
    l_diversity: int = Field(
        default=2,
        ge=1,
        le=20,
        alias="l",
        description="Parámetro l-diversidad distinta: mínimo de diagnósticos CIE-10 distintos por clase.",
    )
    suppression_limit: float = Field(
        default=0.25,
        ge=0.0,
        le=0.5,
        description="Fracción máxima de registros que pueden suprimirse para cumplir (k, l).",
    )
    department: str | None = Field(
        default=None,
        min_length=2,
        max_length=64,
        description="Filtro opcional por departamento clínico.",
    )


class EquivalenceClassSummary(BaseModel):
    age_range: str
    zip_generalized: str
    gender: str
    group_size: int
    distinct_diagnoses: int


class AnonymizationMetrics(BaseModel):
    requested_k: int
    achieved_k: int
    requested_l: int
    achieved_l: int
    generalization_level: int
    generalization_description: str
    input_records_count: int
    exported_records_count: int
    suppressed_records_count: int
    suppression_ratio: float
    equivalence_classes_count: int
    safe_harbor_verified: bool
    removed_hipaa_identifiers_count: int
    removed_hipaa_identifiers: list[str]


class AnonymizedRecordRow(BaseModel):
    age_range: str
    zip_generalized: str
    gender: str
    diagnosis_cie10: str
    department: str
    record_year: int


class AnonymizedExportResponse(BaseModel):
    generated_at: datetime
    purpose: str
    metrics: AnonymizationMetrics
    equivalence_classes: list[EquivalenceClassSummary]
    records: list[AnonymizedRecordRow]


# ------------------------------------------------------------------------------
# MB-03 & MB-04: Derechos ARCO + NIST SP 800-88 + Certificado JSON/PDF SHA-256
# ------------------------------------------------------------------------------
class ARCOErasureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    opaque_patient_token: str = Field(
        ...,
        description="Token opaco `pat_<32 hex>` del titular que ejerce Cancelación/Supresión ARCO.",
    )
    method: SanitizationMethod = Field(
        default="NIST_800_88_PURGE",
        description="Método NIST SP 800-88 Rev. 1 (`NIST_800_88_CLEAR` o `NIST_800_88_PURGE`).",
    )
    arco_request_folio: str = Field(
        ...,
        min_length=4,
        max_length=64,
        pattern=r"^[A-Za-z0-9._-]+$",
        description="Folio auditable de la solicitud ARCO (ej. `ARCO-2026-0001`).",
    )
    reason: str = Field(
        default="Ejercicio de derecho ARCO de Cancelación y Supresión (LFPDPPP)",
        min_length=5,
        max_length=300,
        description="Justificación legal/operativa de la supresión.",
    )
    purge_vault: bool = Field(
        default=True,
        description="Destruye todas las versiones y metadatos KV v2 en HashiCorp Vault.",
    )

    @field_validator("opaque_patient_token")
    @classmethod
    def validate_token(cls, value: str) -> str:
        normalized = value.strip()
        if not OPAQUE_TOKEN_REGEX.match(normalized):
            raise ValueError("Token opaco inválido: debe cumplir el formato `pat_<32 hex>`.")
        return normalized


class SanitizationCertificateSummary(BaseModel):
    certificate_id: UUID
    opaque_patient_token: str
    method: SanitizationMethod
    sha256_hash: str
    requested_by: str
    executed_at: datetime
    records_sanitized_count: int
    vault_purged: bool
    json_download_url: str
    pdf_download_url: str
    verify_url: str


class ARCOErasureResponse(BaseModel):
    status: Literal["sanitized"] = "sanitized"
    certificate_id: UUID
    opaque_patient_token: str
    method: SanitizationMethod
    overwrite_passes: int
    memory_buffers_zeroed: int
    records_sanitized_count: int
    sanitized_record_ids: list[UUID]
    vault_purged: bool
    vault_verification: Literal["CONFIRMED_NOT_FOUND", "ALREADY_PURGED", "NOT_REQUESTED"]
    sha256_hash: str
    executed_at: datetime
    certificate: dict[str, Any]
    json_download_url: str
    pdf_download_url: str
    verify_url: str


class CertificateVerificationResponse(BaseModel):
    certificate_id: UUID
    valid: bool
    algorithm: Literal["SHA-256"] = "SHA-256"
    stored_sha256: str
    recomputed_sha256: str
    method: SanitizationMethod
    executed_at: datetime
    verified_at: datetime
