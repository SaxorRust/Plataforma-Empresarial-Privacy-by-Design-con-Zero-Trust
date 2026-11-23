from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
from typing import Any
from uuid import UUID

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models.lifecycle import (
    CertificateVerificationResponse,
    SanitizationCertificateEntity,
    SanitizationCertificateSummary,
)


def canonical_certificate_bytes(certificate_payload: dict[str, Any]) -> bytes:
    """Serialización JSON canónica determinista usada como entrada del sello SHA-256."""
    return json.dumps(
        certificate_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_certificate_sha256(certificate_payload: dict[str, Any]) -> str:
    """Calcula el digest hexadecimal SHA-256 (64 caracteres) del certificado canónico."""
    return hashlib.sha256(canonical_certificate_bytes(certificate_payload)).hexdigest()


def verify_certificate_integrity(
    entity: SanitizationCertificateEntity,
) -> CertificateVerificationResponse:
    """Recalcula SHA-256 sobre `certificate_json` y valida integridad en tiempo constante."""
    recomputed = compute_certificate_sha256(entity.certificate_json)
    is_valid = hmac.compare_digest(entity.sha256_hash.lower(), recomputed.lower())
    return CertificateVerificationResponse(
        certificate_id=entity.certificate_id,
        valid=is_valid,
        stored_sha256=entity.sha256_hash,
        recomputed_sha256=recomputed,
        method=entity.method,
        executed_at=entity.executed_at,
        verified_at=datetime.now(timezone.utc),
    )


def build_certificate_urls(certificate_id: UUID) -> tuple[str, str, str]:
    base = f"/lifecycle/certificates/{certificate_id}"
    return f"{base}.json", f"{base}.pdf", f"{base}/verify"


def entity_to_summary(entity: SanitizationCertificateEntity) -> SanitizationCertificateSummary:
    json_url, pdf_url, verify_url = build_certificate_urls(entity.certificate_id)
    return SanitizationCertificateSummary(
        certificate_id=entity.certificate_id,
        opaque_patient_token=entity.opaque_patient_token,
        method=entity.method,
        sha256_hash=entity.sha256_hash,
        requested_by=entity.requested_by,
        executed_at=entity.executed_at,
        records_sanitized_count=int(entity.certificate_json.get("records_sanitized_count", 0)),
        vault_purged=bool(entity.certificate_json.get("vault_purged", False)),
        json_download_url=json_url,
        pdf_download_url=pdf_url,
        verify_url=verify_url,
    )


def render_certificate_json_document(entity: SanitizationCertificateEntity) -> dict[str, Any]:
    """Documento JSON descargable con payload canónico y firma de integridad SHA-256."""
    return {
        "certificate_id": str(entity.certificate_id),
        "integrity": {
            "algorithm": "SHA-256",
            "sha256_hash": entity.sha256_hash,
            "canonicalization": "JSON sort_keys=True, separators=(',', ':'), UTF-8",
        },
        "certificate": entity.certificate_json,
    }


def render_certificate_pdf(entity: SanitizationCertificateEntity) -> bytes:
    """
    Genera el Certificado Oficial de Sanitización NIST SP 800-88 en PDF (MB-04)
    mediante `reportlab`, incrustando la evidencia técnica y el sello SHA-256 verificable.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
        title=f"Certificado de Sanitizacion NIST SP 800-88 - {entity.certificate_id}",
        author="Hospital Privacy-by-Design Zero Trust (BUAP FCC)",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CertTitle",
        parent=styles["Heading1"],
        fontSize=15,
        leading=20,
        textColor=colors.HexColor("#0F2942"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "CertSubtitle",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#475569"),
        spaceAfter=14,
    )
    section_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0F2942"),
        spaceBefore=12,
        spaceAfter=6,
    )
    mono_style = ParagraphStyle(
        "MonoHash",
        parent=styles["Code"],
        fontName="Courier-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F1F5F9"),
        borderPadding=8,
    )
    footer_style = ParagraphStyle(
        "FooterNote",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#64748B"),
        spaceBefore=14,
    )

    cert = entity.certificate_json
    record_ids = cert.get("sanitized_record_ids", [])
    record_ids_text = ", ".join(str(rid) for rid in record_ids) if record_ids else "Ninguno (solo bóveda)"

    story: list[Any] = [
        Paragraph("CERTIFICADO DE SANITIZACIÓN DE DATOS PERSONALES", title_style),
        Paragraph(
            "Benemérita Universidad Autónoma de Puebla (BUAP) — Facultad de Ciencias de la Computación<br/>"
            "Plataforma Empresarial Privacy-by-Design con Zero Trust · Cumplimiento ARCO &amp; NIST SP 800-88 Rev. 1",
            subtitle_style,
        ),
        Paragraph("1. Identificación de la Solicitud ARCO y Operación", section_style),
    ]

    meta_rows = [
        ["Campo", "Valor Verificado"],
        ["ID de Certificado", str(entity.certificate_id)],
        ["Folio de Solicitud ARCO", str(cert.get("arco_request_folio", "N/A"))],
        ["Derecho Ejercido", str(cert.get("arco_right", "Cancelación / Supresión (ARCO)"))],
        ["Motivo / Justificación", str(cert.get("reason", "N/A"))],
        ["Estándar Técnico", str(cert.get("standard", "NIST SP 800-88 Rev. 1"))],
        ["Método de Sanitización", str(entity.method)],
        ["Fecha de Ejecución (UTC)", entity.executed_at.isoformat()],
        ["Auditor Responsable", f"{entity.requested_by} ({cert.get('requested_by_role', 'auditor_arco')})"],
        ["Token Opaco del Titular", entity.opaque_patient_token],
    ]
    meta_table = Table(meta_rows, colWidths=[2.2 * inch, 4.8 * inch])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F2942")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F8FAFC")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(meta_table)

    story.append(Paragraph("2. Evidencia Técnica de Borrado Seguro (NIST SP 800-88)", section_style))
    tech_rows = [
        ["Control de Sanitización", "Resultado"],
        ["Registros Clínicos Sobrescritos", str(cert.get("records_sanitized_count", 0))],
        ["IDs de Expedientes Sanitizados", Paragraph(record_ids_text, styles["Normal"])],
        ["Pasadas de Sobrescritura en BD", str(cert.get("overwrite_passes", 0))],
        ["Buffers en Memoria Limpiados (Zeroing)", str(cert.get("memory_buffers_zeroed", 0))],
        ["Purga de Bóveda HashiCorp Vault (KV v2)", "SÍ (Destrucción de metadatos)" if cert.get("vault_purged") else "NO"],
        ["Verificación Post-Purga en Vault", str(cert.get("vault_verification", "N/A"))],
    ]
    tech_table = Table(tech_rows, colWidths=[2.6 * inch, 4.4 * inch])
    tech_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F8FAFC")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(tech_table)

    story.append(Paragraph("3. Sello Criptográfico de Integridad (SHA-256)", section_style))
    story.append(
        Paragraph(
            f"SHA-256 (JSON canónico UTF-8):<br/>{entity.sha256_hash}",
            mono_style,
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Nota de Privacidad por Diseño: Este certificado NO contiene identificadores directos "
            "(nombre completo, CURP, NSS, correo o teléfono). Su integridad puede comprobarse en "
            f"cualquier momento mediante el endpoint GET /lifecycle/certificates/{entity.certificate_id}/verify "
            "o recalculando SHA-256 sobre el objeto `certificate` canónico de la versión JSON.",
            footer_style,
        )
    )

    doc.build(story)
    return buffer.getvalue()
