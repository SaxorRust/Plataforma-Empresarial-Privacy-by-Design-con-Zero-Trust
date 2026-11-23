from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AlertSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class SyslogIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw_message: str = Field(..., min_length=1, max_length=65536)
    source_ip: str | None = Field(default=None, max_length=64)


class AlertAckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    acknowledged_by: str = Field(..., min_length=2, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")


class SIEMEventResponse(BaseModel):
    id: int
    received_at: str
    event_timestamp: str
    facility: int
    severity: int
    severity_name: str
    hostname: str
    app_name: str
    proc_id: str
    msg_id: str
    actor: str | None
    role: str | None
    action: str | None
    outcome: str | None
    purpose: str | None
    source_ip: str | None
    request_id: str | None
    records_count: int
    structured_data: dict[str, dict[str, str]]
    message: str
    raw_sanitized: str
    rfc5424_valid: bool
    sanitized: bool
    redacted_categories: list[str]
    redaction_count: int


class SIEMAlertResponse(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    status: str
    triggered_at: str
    window_seconds: int
    event_count: int
    threshold: int
    entity_key: str
    actor: str | None
    source_ip: str | None
    summary: str
    related_event_ids: list[int]
    acknowledged: bool
    acknowledged_by: str | None
    acknowledged_at: str | None


class SyslogIngestResponse(BaseModel):
    event: SIEMEventResponse
    triggered_alerts: list[SIEMAlertResponse]


class CorrelationRuleInfo(BaseModel):
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    description: str
    threshold: int
    window_seconds: int
    monitored_msg_ids: list[str]


class SIEMStatsResponse(BaseModel):
    total_events: int
    rfc5424_valid_events: int
    sanitized_events: int
    total_redactions: int
    redactions_by_category: dict[str, int]
    total_alerts: int
    open_alerts: int
    alerts_by_severity: dict[str, int]
    alerts_by_rule: dict[str, int]
