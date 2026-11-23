from collections import defaultdict
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import io

from app.models.clinical import (
    EMBEDDED_CURP_REGEX,
    EMBEDDED_EMAIL_REGEX,
    EMBEDDED_NSS_REGEX,
    MedicalRecordEntity,
)
from app.models.lifecycle import (
    AnonymizationMetrics,
    AnonymizedExportResponse,
    AnonymizedRecordRow,
    EquivalenceClassSummary,
)
from app.models.vault import OPAQUE_TOKEN_REGEX

# Los 18 identificadores de HIPAA Safe Harbor (45 CFR § 164.514(b)(2))
HIPAA_SAFE_HARBOR_18_IDENTIFIERS: tuple[str, ...] = (
    "1. Nombres completos",
    "2. Subdivisiones geográficas menores al estado (CP completo / dirección)",
    "3. Fechas exactas (excepto año) y edades > 89 (agrupadas en 90+)",
    "4. Números telefónicos",
    "5. Números de fax",
    "6. Direcciones de correo electrónico",
    "7. Número de Seguridad Social (NSS / SSN)",
    "8. Números de expediente médico (record_id)",
    "9. Números de beneficiario de plan de salud",
    "10. Números de cuenta",
    "11. Números de certificado o licencia",
    "12. Identificadores de vehículos y placas",
    "13. Identificadores y series de dispositivos médicos",
    "14. URLs web",
    "15. Direcciones IP",
    "16. Identificadores biométricos",
    "17. Fotografías faciales completas e imágenes comparables",
    "18. Cualquier otro código identificador único (CURP, opaque_patient_token)",
)


class AnonymizationNotSatisfiableError(Exception):
    """El conjunto de datos no puede satisfacer de forma segura (k, l) sin riesgo de reidentificación."""


@dataclass(frozen=True)
class _GeneralizationLevel:
    level: int
    age_bucket: int | None  # None -> "*"
    zip_digits: int  # 0 -> "*****"
    suppress_gender: bool
    description: str


_GENERALIZATION_LATTICE: tuple[_GeneralizationLevel, ...] = (
    _GeneralizationLevel(0, 10, 3, False, "Safe Harbor fino: edad 10a (90+), CP 3 dígitos, género exacto"),
    _GeneralizationLevel(1, 10, 2, False, "Nivel 1: edad 10a (90+), CP 2 dígitos, género exacto"),
    _GeneralizationLevel(2, 20, 2, False, "Nivel 2: edad 20a (90+), CP 2 dígitos, género exacto"),
    _GeneralizationLevel(3, 20, 1, False, "Nivel 3: edad 20a (90+), CP 1 dígito, género exacto"),
    _GeneralizationLevel(4, 20, 1, True, "Nivel 4: edad 20a (90+), CP 1 dígito, género generalizado (*)"),
    _GeneralizationLevel(5, 30, 0, True, "Nivel 5: edad 30a (90+), CP suprimido (*****), género (*)"),
    _GeneralizationLevel(6, None, 0, True, "Nivel 6 (máximo): cuasi-identificadores globales (*)"),
)


def _generalize_age_safe_harbor(age_years: int, bucket_size: int | None) -> str:
    if bucket_size is None:
        return "*"
    # Regla estricta HIPAA Safe Harbor: edades mayores a 89 siempre se agrupan en "90+"
    if age_years >= 90:
        return "90+"
    lower = (age_years // bucket_size) * bucket_size
    upper = min(lower + bucket_size - 1, 89)
    return f"{lower}-{upper}"


def _generalize_zip_digits(zip_prefix: str, visible_digits: int) -> str:
    cleaned = zip_prefix.strip()
    if visible_digits <= 0:
        return "*****"
    if len(cleaned) <= visible_digits:
        return "*" * len(cleaned)
    return f"{cleaned[:visible_digits]}{'*' * (len(cleaned) - visible_digits)}"


def _verify_safe_harbor_output(rows: list[AnonymizedRecordRow]) -> bool:
    """Verifica post-generación que ninguna fila contenga PII directa ni identificadores prohibidos."""
    for row in rows:
        serialized = (
            f"{row.age_range}|{row.zip_generalized}|{row.gender}|"
            f"{row.diagnosis_cie10}|{row.department}|{row.record_year}"
        )
        if OPAQUE_TOKEN_REGEX.search(serialized):
            return False
        if EMBEDDED_CURP_REGEX.search(serialized):
            return False
        if EMBEDDED_NSS_REGEX.search(serialized):
            return False
        if EMBEDDED_EMAIL_REGEX.search(serialized):
            return False
        # Ningún CP de 5 dígitos sin generalizar permitido en Safe Harbor
        if row.zip_generalized.isdigit() and len(row.zip_generalized) == 5:
            return False
        # Ninguna edad exacta numérica > 89
        if row.age_range.isdigit() and int(row.age_range) >= 90:
            return False
    return True


def build_anonymized_export(
    records: list[MedicalRecordEntity],
    *,
    k: int = 2,
    l_diversity: int = 2,
    suppression_limit: float = 0.25,
    purpose: str = "investigacion_estadistica",
) -> AnonymizedExportResponse:
    """
    Genera un conjunto de datos estadístico desidentificado (MB-02):
    1. Aplica **HIPAA Safe Harbor** eliminando los 18 identificadores directos/pseudónimos
       (`record_id`, `opaque_patient_token`, texto libre `diagnosis_summary`, fechas exactas)
       y agrupando edades >= 90 en `"90+"`.
    2. Recorre una retícula jerárquica de generalización sobre cuasi-identificadores
       (`age_range`, `zip_generalized`, `gender`) hasta satisfacer matemáticamente:
       - **k-anonimato:** cada clase de equivalencia tiene al menos `k` registros.
       - **l-diversidad distinta:** cada clase de equivalencia contiene al menos `l`
         códigos diagnósticos (`diagnosis_cie10`) distintos.
    3. Fail-Closed: si el conjunto de datos no puede satisfacer `(k, l)` dentro del límite
       de supresión permitido, rechaza la exportación para prevenir reidentificación.
    """
    active_records = [rec for rec in records if not rec.is_sanitized]
    total_input = len(active_records)

    if total_input < k:
        raise AnonymizationNotSatisfiableError(
            f"Exportación rechazada (privacidad fail-closed): se requieren al menos k={k} "
            f"registros activos y solo existen {total_input}."
        )

    global_distinct_diagnoses = len({rec.diagnosis_cie10 for rec in active_records})
    if global_distinct_diagnoses < l_diversity:
        raise AnonymizationNotSatisfiableError(
            f"Exportación rechazada (l-diversidad imposible): el conjunto completo solo tiene "
            f"{global_distinct_diagnoses} diagnóstico(s) CIE-10 distinto(s) y se solicitó l={l_diversity}."
        )

    best_candidate: tuple[
        _GeneralizationLevel,
        list[AnonymizedRecordRow],
        list[EquivalenceClassSummary],
        int,
    ] | None = None

    for level in _GENERALIZATION_LATTICE:
        groups: dict[tuple[str, str, str], list[MedicalRecordEntity]] = defaultdict(list)
        for rec in active_records:
            qi_key = (
                _generalize_age_safe_harbor(rec.age_years, level.age_bucket),
                _generalize_zip_digits(rec.zip_prefix, level.zip_digits),
                "*" if level.suppress_gender else rec.gender,
            )
            groups[qi_key].append(rec)

        valid_rows: list[AnonymizedRecordRow] = []
        valid_classes: list[EquivalenceClassSummary] = []
        suppressed_count = 0

        for (age_range, zip_gen, gender_gen), grp in sorted(groups.items()):
            distinct_sa = len({item.diagnosis_cie10 for item in grp})
            if len(grp) >= k and distinct_sa >= l_diversity:
                valid_classes.append(
                    EquivalenceClassSummary(
                        age_range=age_range,
                        zip_generalized=zip_gen,
                        gender=gender_gen,
                        group_size=len(grp),
                        distinct_diagnoses=distinct_sa,
                    )
                )
                for item in grp:
                    valid_rows.append(
                        AnonymizedRecordRow(
                            age_range=age_range,
                            zip_generalized=zip_gen,
                            gender=gender_gen,
                            diagnosis_cie10=item.diagnosis_cie10,
                            department=item.department,
                            record_year=item.created_at.year,
                        )
                    )
            else:
                suppressed_count += len(grp)

        suppression_ratio = suppressed_count / total_input if total_input else 1.0
        if valid_rows and suppression_ratio <= suppression_limit:
            # Preferir nivel más fino con 0 supresión; si hay supresión, continuar buscando
            # si un nivel ligeramente más general evita suprimir registros.
            if suppressed_count == 0:
                best_candidate = (level, valid_rows, valid_classes, suppressed_count)
                break
            if best_candidate is None:
                best_candidate = (level, valid_rows, valid_classes, suppressed_count)

    if best_candidate is None:
        raise AnonymizationNotSatisfiableError(
            f"Exportación rechazada: ningún nivel de generalización satisface k={k} y l={l_diversity} "
            f"dentro del límite de supresión ({suppression_limit:.0%})."
        )

    chosen_level, exported_rows, eq_classes, suppressed_count = best_candidate

    # Orden determinista por cuasi-identificadores para no filtrar orden de inserción original
    exported_rows.sort(
        key=lambda r: (
            r.age_range,
            r.zip_generalized,
            r.gender,
            r.diagnosis_cie10,
            r.department,
            r.record_year,
        )
    )

    safe_harbor_ok = _verify_safe_harbor_output(exported_rows)
    if not safe_harbor_ok:
        raise AnonymizationNotSatisfiableError(
            "Verificación post-exportación Safe Harbor fallida: se detectó patrón de PII residual."
        )

    achieved_k = min(cls.group_size for cls in eq_classes)
    achieved_l = min(cls.distinct_diagnoses for cls in eq_classes)

    metrics = AnonymizationMetrics(
        requested_k=k,
        achieved_k=achieved_k,
        requested_l=l_diversity,
        achieved_l=achieved_l,
        generalization_level=chosen_level.level,
        generalization_description=chosen_level.description,
        input_records_count=total_input,
        exported_records_count=len(exported_rows),
        suppressed_records_count=suppressed_count,
        suppression_ratio=round(suppressed_count / total_input, 4),
        equivalence_classes_count=len(eq_classes),
        safe_harbor_verified=True,
        removed_hipaa_identifiers_count=len(HIPAA_SAFE_HARBOR_18_IDENTIFIERS),
        removed_hipaa_identifiers=list(HIPAA_SAFE_HARBOR_18_IDENTIFIERS),
    )

    return AnonymizedExportResponse(
        generated_at=datetime.now(timezone.utc),
        purpose=purpose,
        metrics=metrics,
        equivalence_classes=eq_classes,
        records=exported_rows,
    )


def render_anonymized_csv(export_result: AnonymizedExportResponse) -> str:
    """Serializa el conjunto de datos desidentificado a CSV listo para análisis estadístico."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "age_range",
            "zip_generalized",
            "gender",
            "diagnosis_cie10",
            "department",
            "record_year",
        ]
    )
    for row in export_result.records:
        writer.writerow(
            [
                row.age_range,
                row.zip_generalized,
                row.gender,
                row.diagnosis_cie10,
                row.department,
                row.record_year,
            ]
        )
    return buffer.getvalue()
