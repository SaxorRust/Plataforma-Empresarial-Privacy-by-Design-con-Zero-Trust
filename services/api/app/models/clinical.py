from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.auth import UserRole
from app.models.vault import OPAQUE_TOKEN_REGEX, PatientPIIRequest

GenderCode = Literal["M", "F", "X", "no_especificado"]
ClinicalPurposeScope = Literal["atencion_medica", "investigacion_estadistica"]

CIE10_REGEX = re.compile(r"^[A-Z]\d{2}(\.[A-Z0-9]{1,4})?$")
ZIP_REGEX = re.compile(r"^\d{5}$")
EMBEDDED_CURP_REGEX = re.compile(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b", re.IGNORECASE)
EMBEDDED_NSS_REGEX = re.compile(r"\b\d{11}\b")
EMBEDDED_EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _validate_no_direct_pii_in_text(value: str) -> str:
    cleaned = " ".join(value.strip().split())
    if len(cleaned) < 3:
        raise ValueError("El resumen clínico debe tener al menos 3 caracteres válidos.")
    if EMBEDDED_CURP_REGEX.search(cleaned):
        raise ValueError(
            "Violación de segregación (MA-02): el resumen clínico no puede contener un CURP."
        )
    if EMBEDDED_NSS_REGEX.search(cleaned):
        raise ValueError(
            "Violación de segregación (MA-02): el resumen clínico no puede contener un NSS."
        )
    if EMBEDDED_EMAIL_REGEX.search(cleaned):
        raise ValueError(
            "Violación de segregación (MA-02): el resumen clínico no puede contener correos."
        )
    return cleaned


@dataclass(frozen=True)
class MedicalRecordEntity:
    """Representación interna de una fila de `clinical.medical_records` (sin PII directa)."""

    record_id: UUID
    opaque_patient_token: str
    age_years: int
    zip_prefix: str
    gender: str
    diagnosis_cie10: str
    diagnosis_summary: str
    department: str
    purpose_scope: str
    ttl_expires_at: datetime | None
    is_sanitized: bool
    created_at: datetime


class _BaseClinicalPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    age_years: int = Field(..., ge=0, le=130, description="Edad en años cumplidos del paciente.")
    zip_prefix: str = Field(..., min_length=5, max_length=5, description="Código postal (5 dígitos).")
    gender: GenderCode = Field(..., description="Género registrado (`M`, `F`, `X`, `no_especificado`).")
    diagnosis_cie10: str = Field(
        ...,
        min_length=3,
        max_length=16,
        description="Código diagnóstico CIE-10 (ej. `E11.9`, `I10`).",
    )
    diagnosis_summary: str = Field(
        ...,
        min_length=3,
        max_length=1000,
        description="Resumen clínico libre de identificadores directos.",
    )
    department: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Área o departamento hospitalario (ej. `cardiologia`, `urgencias`).",
    )
    purpose_scope: ClinicalPurposeScope = Field(
        default="atencion_medica",
        description="Finalidad declarada con la que se recaba el registro.",
    )
    ttl_hours: int | None = Field(
        default=None,
        ge=1,
        le=87600,
        description="Plazo de retención en horas (opcional, usado por TTL del Módulo B).",
    )
    ttl_expires_at: datetime | None = Field(
        default=None,
        description="Marca temporal explícita de expiración TTL (UTC).",
    )

    @field_validator("zip_prefix")
    @classmethod
    def validate_zip(cls, value: str) -> str:
        normalized = value.strip()
        if not ZIP_REGEX.match(normalized):
            raise ValueError("El código postal debe contener exactamente 5 dígitos.")
        return normalized

    @field_validator("diagnosis_cie10")
    @classmethod
    def validate_cie10(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not CIE10_REGEX.match(normalized):
            raise ValueError("Formato CIE-10 inválido (ejemplos válidos: `I10`, `E11.9`, `J18.9`).")
        return normalized

    @field_validator("diagnosis_summary")
    @classmethod
    def validate_summary_no_pii(cls, value: str) -> str:
        return _validate_no_direct_pii_in_text(value)

    @field_validator("department")
    @classmethod
    def normalize_department(cls, value: str) -> str:
        normalized = " ".join(value.strip().split()).lower()
        if len(normalized) < 2:
            raise ValueError("El departamento debe tener al menos 2 caracteres válidos.")
        return normalized

    @model_validator(mode="after")
    def resolve_ttl(self) -> "_BaseClinicalPayload":
        if self.ttl_hours is not None and self.ttl_expires_at is not None:
            raise ValueError("Especifica solo `ttl_hours` o `ttl_expires_at`, no ambos.")
        if self.ttl_hours is not None:
            self.ttl_expires_at = datetime.now(timezone.utc) + timedelta(hours=self.ttl_hours)
        elif self.ttl_expires_at is not None and self.ttl_expires_at.tzinfo is None:
            self.ttl_expires_at = self.ttl_expires_at.replace(tzinfo=timezone.utc)
        return self


class SegregatedClinicalData(_BaseClinicalPayload):
    """Atributos clínicos puros para alta segregada atómica (sin token ni PII directa)."""


class MedicalRecordCreateRequest(_BaseClinicalPayload):
    """Alta de expediente clínico vinculado a un `opaque_patient_token` existente en Vault."""

    opaque_patient_token: str = Field(
        ...,
        description="Token opaco emitido previamente por HashiCorp Vault (`pat_<32 hex>`).",
    )

    @field_validator("opaque_patient_token")
    @classmethod
    def validate_opaque_token(cls, value: str) -> str:
        normalized = value.strip()
        if not OPAQUE_TOKEN_REGEX.match(normalized):
            raise ValueError("Token opaco inválido: debe cumplir el formato `pat_<32 hex>`.")
        return normalized


class SegregatedPatientRecordCreateRequest(BaseModel):
    """
    Alta segregada Privacy-by-Design (MA-02):
    - `patient_pii` se envía exclusivamente a HashiCorp Vault (Transit + KV v2).
    - `clinical_data` se persiste en PostgreSQL vinculado únicamente por `pat_...`.
    """

    model_config = ConfigDict(extra="forbid")

    patient_pii: PatientPIIRequest
    clinical_data: SegregatedClinicalData


class MedicalRecordUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    diagnosis_cie10: str | None = Field(default=None, min_length=3, max_length=16)
    diagnosis_summary: str | None = Field(default=None, min_length=3, max_length=1000)
    department: str | None = Field(default=None, min_length=2, max_length=64)
    ttl_expires_at: datetime | None = None

    @field_validator("diagnosis_cie10")
    @classmethod
    def validate_cie10(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not CIE10_REGEX.match(normalized):
            raise ValueError("Formato CIE-10 inválido (ejemplos válidos: `I10`, `E11.9`).")
        return normalized

    @field_validator("diagnosis_summary")
    @classmethod
    def validate_summary_no_pii(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_no_direct_pii_in_text(value)

    @field_validator("department")
    @classmethod
    def normalize_department(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = " ".join(value.strip().split()).lower()
        if len(normalized) < 2:
            raise ValueError("El departamento debe tener al menos 2 caracteres válidos.")
        return normalized

    @model_validator(mode="after")
    def require_at_least_one_field(self) -> "MedicalRecordUpdateRequest":
        if (
            self.diagnosis_cie10 is None
            and self.diagnosis_summary is None
            and self.department is None
            and self.ttl_expires_at is None
        ):
            raise ValueError("Debe proporcionar al menos un campo clínico para actualizar.")
        if self.ttl_expires_at is not None and self.ttl_expires_at.tzinfo is None:
            self.ttl_expires_at = self.ttl_expires_at.replace(tzinfo=timezone.utc)
        return self


class OPADecision(BaseModel):
    allow: bool
    allowed_fields: list[str] = Field(default_factory=list)
    generalize_fields: bool = False
    mask_token: bool = False
    reason: str
    policy_version: str = "1.1.0"


class MinimizationMetadata(BaseModel):
    role: UserRole
    purpose: str
    action: str
    allowed_fields: list[str]
    generalized: bool
    masked_token: bool
    policy_version: str


class MinimizedRecordResponse(BaseModel):
    record: dict[str, Any]
    policy: MinimizationMetadata


class MinimizedRecordListResponse(BaseModel):
    count: int
    records: list[dict[str, Any]]
    policy: MinimizationMetadata


class SegregatedCreateResponse(BaseModel):
    opaque_patient_token: str = Field(..., pattern=r"^pat_[0-9a-f]{32}$")
    vault_engine: Literal["transit+kv-v2"] = "transit+kv-v2"
    transit_key: str
    key_version: int
    record: dict[str, Any]
    policy: MinimizationMetadata


class OPAStatusResponse(BaseModel):
    reachable: bool
    opa_url: str
    policy_loaded: bool
    policy_version: str | None = None


class PolicyEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: UserRole
    purpose: str = Field(default="", max_length=64)
    action: str = Field(..., min_length=2, max_length=64)
    resource_purpose: str | None = Field(default=None, max_length=64)
    is_sanitized: bool = False
    resource_owner_match: bool = False
