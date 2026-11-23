from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any

from app.models import SIEMAlertResponse, SIEMEventResponse, SIEMStatsResponse

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS siem_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    event_epoch REAL NOT NULL,
    facility INTEGER NOT NULL,
    severity INTEGER NOT NULL,
    severity_name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    app_name TEXT NOT NULL,
    proc_id TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    actor TEXT,
    role TEXT,
    action TEXT,
    outcome TEXT,
    purpose TEXT,
    source_ip TEXT,
    request_id TEXT,
    records_count INTEGER NOT NULL DEFAULT 0,
    structured_data_json TEXT NOT NULL,
    message TEXT NOT NULL,
    raw_sanitized TEXT NOT NULL,
    rfc5424_valid INTEGER NOT NULL,
    sanitized INTEGER NOT NULL,
    redacted_categories_json TEXT NOT NULL,
    redaction_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_siem_events_msg_epoch
    ON siem_events (msg_id, event_epoch);
CREATE INDEX IF NOT EXISTS idx_siem_events_actor_epoch
    ON siem_events (actor, event_epoch);
CREATE INDEX IF NOT EXISTS idx_siem_events_ip_epoch
    ON siem_events (source_ip, event_epoch);

CREATE TABLE IF NOT EXISTS siem_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    triggered_at TEXT NOT NULL,
    triggered_epoch REAL NOT NULL,
    window_seconds INTEGER NOT NULL,
    event_count INTEGER NOT NULL,
    threshold INTEGER NOT NULL,
    entity_key TEXT NOT NULL,
    actor TEXT,
    source_ip TEXT,
    summary TEXT NOT NULL,
    related_event_ids_json TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acknowledged_by TEXT,
    acknowledged_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_siem_alerts_rule_entity
    ON siem_alerts (rule_id, entity_key, triggered_epoch);
"""

_INSERT_EVENT_SQL = """
INSERT INTO siem_events (
    received_at, event_timestamp, event_epoch,
    facility, severity, severity_name,
    hostname, app_name, proc_id, msg_id,
    actor, role, action, outcome, purpose, source_ip, request_id, records_count,
    structured_data_json, message, raw_sanitized,
    rfc5424_valid, sanitized, redacted_categories_json, redaction_count
) VALUES (
    ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?, ?
)
"""

_LIST_EVENTS_SQL = """
SELECT
    id, received_at, event_timestamp, facility, severity, severity_name,
    hostname, app_name, proc_id, msg_id,
    actor, role, action, outcome, purpose, source_ip, request_id, records_count,
    structured_data_json, message, raw_sanitized,
    rfc5424_valid, sanitized, redacted_categories_json, redaction_count
FROM siem_events
WHERE (? IS NULL OR msg_id = ?)
  AND (? IS NULL OR actor = ?)
  AND (? IS NULL OR source_ip = ?)
  AND (? IS NULL OR severity <= ?)
  AND (? = 0 OR sanitized = 1)
ORDER BY id DESC
LIMIT ?
"""

_FETCH_WINDOW_BY_ACTOR_OR_IP_SQL = """
SELECT id, msg_id, actor, source_ip, records_count, event_epoch
FROM siem_events
WHERE event_epoch >= ?
  AND event_epoch <= ?
  AND (
      (? IS NOT NULL AND actor = ?)
      OR (? IS NOT NULL AND source_ip = ?)
  )
ORDER BY id DESC
"""

_INSERT_ALERT_SQL = """
INSERT INTO siem_alerts (
    rule_id, rule_name, severity, status, triggered_at, triggered_epoch,
    window_seconds, event_count, threshold, entity_key,
    actor, source_ip, summary, related_event_ids_json
) VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_RECENT_ALERT_CHECK_SQL = """
SELECT id
FROM siem_alerts
WHERE rule_id = ?
  AND entity_key = ?
  AND triggered_epoch >= ?
ORDER BY id DESC
LIMIT 1
"""

_LIST_ALERTS_SQL = """
SELECT
    id, rule_id, rule_name, severity, status, triggered_at,
    window_seconds, event_count, threshold, entity_key,
    actor, source_ip, summary, related_event_ids_json,
    acknowledged, acknowledged_by, acknowledged_at
FROM siem_alerts
WHERE (? IS NULL OR rule_id = ?)
  AND (? IS NULL OR severity = ?)
  AND (? IS NULL OR acknowledged = ?)
ORDER BY id DESC
LIMIT ?
"""

_ACK_ALERT_SQL = """
UPDATE siem_alerts
SET acknowledged = 1,
    status = 'ACKNOWLEDGED',
    acknowledged_by = ?,
    acknowledged_at = ?
WHERE id = ?
"""

_GET_ALERT_BY_ID_SQL = """
SELECT
    id, rule_id, rule_name, severity, status, triggered_at,
    window_seconds, event_count, threshold, entity_key,
    actor, source_ip, summary, related_event_ids_json,
    acknowledged, acknowledged_by, acknowledged_at
FROM siem_alerts
WHERE id = ?
"""


def _row_to_event(row: sqlite3.Row) -> SIEMEventResponse:
    return SIEMEventResponse(
        id=int(row["id"]),
        received_at=row["received_at"],
        event_timestamp=row["event_timestamp"],
        facility=int(row["facility"]),
        severity=int(row["severity"]),
        severity_name=row["severity_name"],
        hostname=row["hostname"],
        app_name=row["app_name"],
        proc_id=row["proc_id"],
        msg_id=row["msg_id"],
        actor=row["actor"],
        role=row["role"],
        action=row["action"],
        outcome=row["outcome"],
        purpose=row["purpose"],
        source_ip=row["source_ip"],
        request_id=row["request_id"],
        records_count=int(row["records_count"]),
        structured_data=json.loads(row["structured_data_json"]),
        message=row["message"],
        raw_sanitized=row["raw_sanitized"],
        rfc5424_valid=bool(row["rfc5424_valid"]),
        sanitized=bool(row["sanitized"]),
        redacted_categories=json.loads(row["redacted_categories_json"]),
        redaction_count=int(row["redaction_count"]),
    )


def _row_to_alert(row: sqlite3.Row) -> SIEMAlertResponse:
    return SIEMAlertResponse(
        id=int(row["id"]),
        rule_id=row["rule_id"],
        rule_name=row["rule_name"],
        severity=row["severity"],
        status=row["status"],
        triggered_at=row["triggered_at"],
        window_seconds=int(row["window_seconds"]),
        event_count=int(row["event_count"]),
        threshold=int(row["threshold"]),
        entity_key=row["entity_key"],
        actor=row["actor"],
        source_ip=row["source_ip"],
        summary=row["summary"],
        related_event_ids=json.loads(row["related_event_ids_json"]),
        acknowledged=bool(row["acknowledged"]),
        acknowledged_by=row["acknowledged_by"],
        acknowledged_at=row["acknowledged_at"],
    )


class SIEMStorage:
    """Almacén SQLite thread-safe para eventos Syslog sanitizados y alertas SOC."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.executescript(_SCHEMA_SQL)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def insert_event(self, payload: dict[str, Any]) -> SIEMEventResponse:
        with self._lock:
            cursor = self._conn.execute(
                _INSERT_EVENT_SQL,
                (
                    payload["received_at"],
                    payload["event_timestamp"],
                    float(payload["event_epoch"]),
                    int(payload["facility"]),
                    int(payload["severity"]),
                    payload["severity_name"],
                    payload["hostname"],
                    payload["app_name"],
                    payload["proc_id"],
                    payload["msg_id"],
                    payload.get("actor"),
                    payload.get("role"),
                    payload.get("action"),
                    payload.get("outcome"),
                    payload.get("purpose"),
                    payload.get("source_ip"),
                    payload.get("request_id"),
                    int(payload.get("records_count", 0)),
                    json.dumps(payload["structured_data"], ensure_ascii=False),
                    payload["message"],
                    payload["raw_sanitized"],
                    1 if payload["rfc5424_valid"] else 0,
                    1 if payload["sanitized"] else 0,
                    json.dumps(payload["redacted_categories"], ensure_ascii=False),
                    int(payload["redaction_count"]),
                ),
            )
            self._conn.commit()
            event_id = int(cursor.lastrowid or 0)
            row = self._conn.execute(
                "SELECT * FROM siem_events WHERE id = ?",
                (event_id,),
            ).fetchone()
            return _row_to_event(row)

    def list_events(
        self,
        *,
        limit: int = 100,
        msg_id: str | None = None,
        actor: str | None = None,
        source_ip: str | None = None,
        max_severity: int | None = None,
        sanitized_only: bool = False,
    ) -> list[SIEMEventResponse]:
        bounded_limit = max(1, min(limit, 500))
        with self._lock:
            rows = self._conn.execute(
                _LIST_EVENTS_SQL,
                (
                    msg_id,
                    msg_id,
                    actor,
                    actor,
                    source_ip,
                    source_ip,
                    max_severity,
                    max_severity,
                    1 if sanitized_only else 0,
                    bounded_limit,
                ),
            ).fetchall()
        return [_row_to_event(r) for r in rows]

    def fetch_window_events(
        self,
        *,
        start_epoch: float,
        end_epoch: float,
        actor: str | None,
        source_ip: str | None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                _FETCH_WINDOW_BY_ACTOR_OR_IP_SQL,
                (start_epoch, end_epoch, actor, actor, source_ip, source_ip),
            ).fetchall()
        return [dict(r) for r in rows]

    def has_recent_alert(self, *, rule_id: str, entity_key: str, since_epoch: float) -> bool:
        with self._lock:
            row = self._conn.execute(
                _RECENT_ALERT_CHECK_SQL,
                (rule_id, entity_key, since_epoch),
            ).fetchone()
        return row is not None

    def insert_alert(
        self,
        *,
        rule_id: str,
        rule_name: str,
        severity: str,
        triggered_at: str,
        triggered_epoch: float,
        window_seconds: int,
        event_count: int,
        threshold: int,
        entity_key: str,
        actor: str | None,
        source_ip: str | None,
        summary: str,
        related_event_ids: list[int],
    ) -> SIEMAlertResponse:
        with self._lock:
            cursor = self._conn.execute(
                _INSERT_ALERT_SQL,
                (
                    rule_id,
                    rule_name,
                    severity,
                    triggered_at,
                    triggered_epoch,
                    window_seconds,
                    event_count,
                    threshold,
                    entity_key,
                    actor,
                    source_ip,
                    summary,
                    json.dumps(related_event_ids),
                ),
            )
            self._conn.commit()
            alert_id = int(cursor.lastrowid or 0)
            row = self._conn.execute(_GET_ALERT_BY_ID_SQL, (alert_id,)).fetchone()
            return _row_to_alert(row)

    def list_alerts(
        self,
        *,
        limit: int = 100,
        rule_id: str | None = None,
        severity: str | None = None,
        acknowledged: bool | None = None,
    ) -> list[SIEMAlertResponse]:
        bounded_limit = max(1, min(limit, 500))
        ack_param = None if acknowledged is None else (1 if acknowledged else 0)
        with self._lock:
            rows = self._conn.execute(
                _LIST_ALERTS_SQL,
                (
                    rule_id,
                    rule_id,
                    severity,
                    severity,
                    ack_param,
                    ack_param,
                    bounded_limit,
                ),
            ).fetchall()
        return [_row_to_alert(r) for r in rows]

    def acknowledge_alert(self, *, alert_id: int, acknowledged_by: str) -> SIEMAlertResponse | None:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with self._lock:
            cursor = self._conn.execute(_ACK_ALERT_SQL, (acknowledged_by, now_iso, alert_id))
            self._conn.commit()
            if cursor.rowcount == 0:
                return None
            row = self._conn.execute(_GET_ALERT_BY_ID_SQL, (alert_id,)).fetchone()
            return _row_to_alert(row) if row else None

    def get_stats(self) -> SIEMStatsResponse:
        with self._lock:
            ev_row = self._conn.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    COALESCE(SUM(rfc5424_valid), 0) AS rfc5424_valid_events,
                    COALESCE(SUM(sanitized), 0) AS sanitized_events,
                    COALESCE(SUM(redaction_count), 0) AS total_redactions
                FROM siem_events
                """
            ).fetchone()
            cat_rows = self._conn.execute(
                "SELECT redacted_categories_json FROM siem_events WHERE sanitized = 1"
            ).fetchall()
            alert_row = self._conn.execute(
                """
                SELECT
                    COUNT(*) AS total_alerts,
                    COALESCE(SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END), 0) AS open_alerts
                FROM siem_alerts
                """
            ).fetchone()
            sev_rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS cnt FROM siem_alerts GROUP BY severity"
            ).fetchall()
            rule_rows = self._conn.execute(
                "SELECT rule_id, COUNT(*) AS cnt FROM siem_alerts GROUP BY rule_id"
            ).fetchall()

        redactions_by_category: dict[str, int] = {}
        for row in cat_rows:
            for category in json.loads(row["redacted_categories_json"]):
                redactions_by_category[category] = redactions_by_category.get(category, 0) + 1

        return SIEMStatsResponse(
            total_events=int(ev_row["total_events"]),
            rfc5424_valid_events=int(ev_row["rfc5424_valid_events"]),
            sanitized_events=int(ev_row["sanitized_events"]),
            total_redactions=int(ev_row["total_redactions"]),
            redactions_by_category=redactions_by_category,
            total_alerts=int(alert_row["total_alerts"]),
            open_alerts=int(alert_row["open_alerts"]),
            alerts_by_severity={row["severity"]: int(row["cnt"]) for row in sev_rows},
            alerts_by_rule={row["rule_id"]: int(row["cnt"]) for row in rule_rows},
        )
