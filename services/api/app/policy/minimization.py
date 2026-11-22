from typing import Any

from app.models.clinical import MedicalRecordEntity, OPADecision


def generalize_age(age_years: int, bucket_size: int = 10) -> str:
    """
    Minimización cualitativa de edad (MA-04 / HIPAA Safe Harbor):
    - Edades >= 90 se agrupan en `"90+"` para evitar singularización de adultos mayores.
    - Resto en intervalos cerrados de `bucket_size` años (ej. `34 -> "30-39"`).
    """
    if age_years >= 90:
        return "90+"
    lower = (age_years // bucket_size) * bucket_size
    upper = min(lower + bucket_size - 1, 89)
    return f"{lower}-{upper}"


def generalize_zip(zip_prefix: str, visible_digits: int = 2) -> str:
    """
    Minimización cualitativa de código postal (MA-04):
    Retiene únicamente los primeros `visible_digits` dígitos y enmascara el resto (`72000 -> 72***`).
    """
    cleaned = zip_prefix.strip()
    if len(cleaned) <= visible_digits:
        return "*" * len(cleaned)
    return f"{cleaned[:visible_digits]}{'*' * (len(cleaned) - visible_digits)}"


def mask_opaque_token(token: str) -> str:
    """
    Enmascaramiento cualitativo del token opaco para perfiles operativos (ej. enfermería):
    `pat_0123456789abcdef0123456789abcdef` -> `pat_0123...cdef`.
    """
    if len(token) <= 12:
        return "pat_***"
    return f"{token[:8]}...{token[-4:]}"


def apply_minimization(
    record: MedicalRecordEntity,
    decision: OPADecision,
) -> dict[str, Any]:
    """
    Aplica minimización cuantitativa y cualitativa estricta (MA-04):
    - **Cuantitativa:** Solo proyecta las claves presentes en `decision.allowed_fields`.
      Ninguna columna no autorizada puede filtrarse en la respuesta HTTP.
    - **Cualitativa:** Si `decision.generalize_fields` está activo, expone `age_range` y
      `zip_generalized` en lugar de valores exactos; si `decision.mask_token` está activo,
      enmascara `opaque_patient_token`.
    """
    if not decision.allow or not decision.allowed_fields:
        return {}

    token_value = (
        mask_opaque_token(record.opaque_patient_token)
        if decision.mask_token
        else record.opaque_patient_token
    )

    candidate_fields: dict[str, Any] = {
        "record_id": str(record.record_id),
        "opaque_patient_token": token_value,
        "age_years": record.age_years,
        "zip_prefix": record.zip_prefix,
        "gender": record.gender,
        "diagnosis_cie10": record.diagnosis_cie10,
        "diagnosis_summary": record.diagnosis_summary,
        "department": record.department,
        "purpose_scope": record.purpose_scope,
        "ttl_expires_at": (
            record.ttl_expires_at.isoformat() if record.ttl_expires_at is not None else None
        ),
        "is_sanitized": record.is_sanitized,
        "created_at": record.created_at.isoformat(),
    }

    if decision.generalize_fields:
        candidate_fields["age_range"] = generalize_age(record.age_years)
        candidate_fields["zip_generalized"] = generalize_zip(record.zip_prefix)
        # Defensa en profundidad: nunca exponer valores exactos si generalización está activa
        candidate_fields.pop("age_years", None)
        candidate_fields.pop("zip_prefix", None)

    return {
        field: candidate_fields[field]
        for field in decision.allowed_fields
        if field in candidate_fields
    }
