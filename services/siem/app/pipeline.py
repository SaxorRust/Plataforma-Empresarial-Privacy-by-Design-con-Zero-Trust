from datetime import datetime, timezone

from app.config import SIEMSettings
from app.correlator import TemporalCorrelationEngine
from app.models import SyslogIngestResponse
from app.rfc5424 import parse_rfc5424
from app.sanitizer import sanitize_structured_data, sanitize_text
from app.storage import SIEMStorage


def _iso_to_epoch(iso_ts: str) -> float:
    try:
        normalized = iso_ts[:-1] + "+00:00" if iso_ts.endswith("Z") else iso_ts
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return datetime.now(timezone.utc).timestamp()


def _extract_audit_fields(
    structured_data: dict[str, dict[str, str]],
    peer_ip: str | None,
) -> dict[str, object]:
    merged: dict[str, str] = {}
    for params in structured_data.values():
        merged.update(params)

    raw_records = merged.get("records_count", "0")
    try:
        records_count = max(0, int(raw_records))
    except ValueError:
        records_count = 0

    return {
        "actor": merged.get("actor") or None,
        "role": merged.get("role") or None,
        "action": merged.get("action") or None,
        "outcome": merged.get("outcome") or None,
        "purpose": merged.get("purpose") or None,
        "source_ip": merged.get("source_ip") or peer_ip,
        "request_id": merged.get("request_id") or None,
        "records_count": records_count,
    }


class SIEMPipeline:
    """
    Pipeline unificado de ingesta SIEM (MC-02 + MC-03 + MC-04):
    1. Parseo estricto Syslog RFC 5424.
    2. Sanitización regex (tarjetas, CURP, contraseñas, JWT, NSS) ANTES de persistir.
    3. Almacenamiento parametrizado en SQLite.
    4. Evaluación inmediata de reglas de correlación temporal.
    """

    def __init__(self, settings: SIEMSettings, storage: SIEMStorage) -> None:
        self.settings = settings
        self.storage = storage
        self.correlator = TemporalCorrelationEngine(storage=storage, settings=settings)

    def ingest_raw_syslog(
        self,
        raw_message: str,
        *,
        peer_ip: str | None = None,
    ) -> SyslogIngestResponse:
        bounded = raw_message[: self.settings.max_message_bytes]
        parsed = parse_rfc5424(bounded)

        # Sanitización OBLIGATORIA en ingesta antes de tocar SQLite (MC-03)
        msg_san = sanitize_text(parsed.message)
        raw_san = sanitize_text(parsed.raw_message)
        sd_san, sd_cats, sd_count = sanitize_structured_data(parsed.structured_data)

        all_categories = sorted(
            set(msg_san.redacted_categories) | set(raw_san.redacted_categories) | set(sd_cats)
        )
        redaction_count = max(
            raw_san.redaction_count,
            msg_san.redaction_count + sd_count,
        )
        sanitized = redaction_count > 0 or bool(all_categories)

        fields = _extract_audit_fields(sd_san, peer_ip)
        received_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event_epoch = _iso_to_epoch(parsed.event_timestamp)

        stored_event = self.storage.insert_event(
            {
                "received_at": received_at,
                "event_timestamp": parsed.event_timestamp,
                "event_epoch": event_epoch,
                "facility": parsed.facility,
                "severity": parsed.severity,
                "severity_name": parsed.severity_name,
                "hostname": parsed.hostname,
                "app_name": parsed.app_name,
                "proc_id": parsed.proc_id,
                "msg_id": parsed.msg_id,
                "actor": fields["actor"],
                "role": fields["role"],
                "action": fields["action"],
                "outcome": fields["outcome"],
                "purpose": fields["purpose"],
                "source_ip": fields["source_ip"],
                "request_id": fields["request_id"],
                "records_count": fields["records_count"],
                "structured_data": sd_san,
                "message": msg_san.text,
                "raw_sanitized": raw_san.text,
                "rfc5424_valid": parsed.rfc5424_valid,
                "sanitized": sanitized,
                "redacted_categories": all_categories,
                "redaction_count": redaction_count,
            }
        )

        triggered_alerts = self.correlator.evaluate(stored_event, event_epoch=event_epoch)
        return SyslogIngestResponse(event=stored_event, triggered_alerts=triggered_alerts)
