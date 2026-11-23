from datetime import datetime, timezone

from app.config import SIEMSettings
from app.models import CorrelationRuleInfo, SIEMAlertResponse, SIEMEventResponse
from app.storage import SIEMStorage

BRUTE_FORCE_MSG_IDS = frozenset({"AUTH_LOGIN_FAILED", "AUTH_WEBAUTHN_FAILED"})
MASS_QUERY_MSG_IDS = frozenset(
    {
        "CLINICAL_RECORD_READ",
        "CLINICAL_RECORD_LIST",
        "CLINICAL_PII_DETOKENIZE",
        "VAULT_DETOKENIZE",
    }
)
POLICY_DENIAL_MSG_IDS = frozenset({"OPA_POLICY_DENIED"})


class TemporalCorrelationEngine:
    """
    Motor de Correlación Temporal SOC (MC-04):
    - RULE-001 (BRUTE_FORCE_LOGIN): Detección de ataques de fuerza bruta por IP o actor.
    - RULE-002 (MASS_RECORD_ACCESS): Alerta CRÍTICA ante consultas masivas de expedientes.
    - RULE-003 (REPEATED_POLICY_DENIAL): Intentos repetidos de Function Creep bloqueados por OPA.
    """

    def __init__(self, storage: SIEMStorage, settings: SIEMSettings) -> None:
        self.storage = storage
        self.settings = settings

    def describe_rules(self) -> list[CorrelationRuleInfo]:
        return [
            CorrelationRuleInfo(
                rule_id="RULE-001",
                rule_name="BRUTE_FORCE_LOGIN",
                severity="HIGH",
                description=(
                    f"Detecta >= {self.settings.brute_force_threshold} intentos fallidos de "
                    f"autenticación en {self.settings.brute_force_window_seconds}s desde la misma IP o usuario."
                ),
                threshold=self.settings.brute_force_threshold,
                window_seconds=self.settings.brute_force_window_seconds,
                monitored_msg_ids=sorted(BRUTE_FORCE_MSG_IDS),
            ),
            CorrelationRuleInfo(
                rule_id="RULE-002",
                rule_name="MASS_RECORD_ACCESS",
                severity="CRITICAL",
                description=(
                    f"Alerta crítica ante >= {self.settings.mass_query_threshold} consultas clínicas "
                    f"o >= {self.settings.mass_records_threshold} expedientes accedidos en "
                    f"{self.settings.mass_query_window_seconds}s por un mismo actor o IP."
                ),
                threshold=self.settings.mass_query_threshold,
                window_seconds=self.settings.mass_query_window_seconds,
                monitored_msg_ids=sorted(MASS_QUERY_MSG_IDS),
            ),
            CorrelationRuleInfo(
                rule_id="RULE-003",
                rule_name="REPEATED_POLICY_DENIAL",
                severity="HIGH",
                description=(
                    f"Detecta >= {self.settings.policy_denial_threshold} denegaciones OPA/ABAC "
                    f"(intento reiterado de Function Creep) en "
                    f"{self.settings.policy_denial_window_seconds}s."
                ),
                threshold=self.settings.policy_denial_threshold,
                window_seconds=self.settings.policy_denial_window_seconds,
                monitored_msg_ids=sorted(POLICY_DENIAL_MSG_IDS),
            ),
        ]

    def evaluate(
        self,
        event: SIEMEventResponse,
        *,
        event_epoch: float,
    ) -> list[SIEMAlertResponse]:
        alerts: list[SIEMAlertResponse] = []

        if event.msg_id in BRUTE_FORCE_MSG_IDS:
            alert = self._evaluate_brute_force(event, event_epoch)
            if alert is not None:
                alerts.append(alert)

        if event.msg_id in MASS_QUERY_MSG_IDS:
            alert = self._evaluate_mass_record_access(event, event_epoch)
            if alert is not None:
                alerts.append(alert)

        if event.msg_id in POLICY_DENIAL_MSG_IDS:
            alert = self._evaluate_policy_denial(event, event_epoch)
            if alert is not None:
                alerts.append(alert)

        return alerts

    def _emit_if_not_in_cooldown(
        self,
        *,
        rule_id: str,
        rule_name: str,
        severity: str,
        event_epoch: float,
        window_seconds: int,
        event_count: int,
        threshold: int,
        entity_key: str,
        actor: str | None,
        source_ip: str | None,
        summary: str,
        related_event_ids: list[int],
    ) -> SIEMAlertResponse | None:
        if self.settings.alert_cooldown_seconds > 0:
            cooldown_since = event_epoch - self.settings.alert_cooldown_seconds
            if self.storage.has_recent_alert(
                rule_id=rule_id,
                entity_key=entity_key,
                since_epoch=cooldown_since,
            ):
                return None

        triggered_at = (
            datetime.fromtimestamp(event_epoch, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        return self.storage.insert_alert(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            triggered_at=triggered_at,
            triggered_epoch=event_epoch,
            window_seconds=window_seconds,
            event_count=event_count,
            threshold=threshold,
            entity_key=entity_key,
            actor=actor,
            source_ip=source_ip,
            summary=summary,
            related_event_ids=related_event_ids[:50],
        )

    def _evaluate_brute_force(
        self,
        event: SIEMEventResponse,
        event_epoch: float,
    ) -> SIEMAlertResponse | None:
        entity_key = event.source_ip or event.actor
        if not entity_key:
            return None

        window = self.settings.brute_force_window_seconds
        rows = self.storage.fetch_window_events(
            start_epoch=event_epoch - window,
            end_epoch=event_epoch,
            actor=event.actor if not event.source_ip else None,
            source_ip=event.source_ip,
        )
        matching = [r for r in rows if r["msg_id"] in BRUTE_FORCE_MSG_IDS]
        if len(matching) < self.settings.brute_force_threshold:
            return None

        severity = (
            "CRITICAL"
            if len(matching) >= self.settings.brute_force_threshold * 2
            else "HIGH"
        )
        return self._emit_if_not_in_cooldown(
            rule_id="RULE-001",
            rule_name="BRUTE_FORCE_LOGIN",
            severity=severity,
            event_epoch=event_epoch,
            window_seconds=window,
            event_count=len(matching),
            threshold=self.settings.brute_force_threshold,
            entity_key=f"bf:{entity_key}",
            actor=event.actor,
            source_ip=event.source_ip,
            summary=(
                f"Posible ataque de fuerza bruta: {len(matching)} intentos de autenticación "
                f"fallidos en {window}s (origen={entity_key}, actor={event.actor or 'N/A'})."
            ),
            related_event_ids=[int(r["id"]) for r in matching],
        )

    def _evaluate_mass_record_access(
        self,
        event: SIEMEventResponse,
        event_epoch: float,
    ) -> SIEMAlertResponse | None:
        entity_key = event.actor or event.source_ip
        if not entity_key:
            return None

        window = self.settings.mass_query_window_seconds
        rows = self.storage.fetch_window_events(
            start_epoch=event_epoch - window,
            end_epoch=event_epoch,
            actor=event.actor,
            source_ip=event.source_ip if not event.actor else None,
        )
        matching = [r for r in rows if r["msg_id"] in MASS_QUERY_MSG_IDS]
        query_count = len(matching)
        total_records = sum(max(1, int(r["records_count"])) for r in matching)

        triggered_by_queries = query_count >= self.settings.mass_query_threshold
        triggered_by_volume = total_records >= self.settings.mass_records_threshold
        if not (triggered_by_queries or triggered_by_volume):
            return None

        metric_value = total_records if triggered_by_volume and not triggered_by_queries else query_count
        threshold_used = (
            self.settings.mass_records_threshold
            if triggered_by_volume and not triggered_by_queries
            else self.settings.mass_query_threshold
        )
        return self._emit_if_not_in_cooldown(
            rule_id="RULE-002",
            rule_name="MASS_RECORD_ACCESS",
            severity="CRITICAL",
            event_epoch=event_epoch,
            window_seconds=window,
            event_count=metric_value,
            threshold=threshold_used,
            entity_key=f"mass:{entity_key}",
            actor=event.actor,
            source_ip=event.source_ip,
            summary=(
                f"ALERTA CRÍTICA — Consultas masivas de expedientes clínicos: {query_count} consultas "
                f"({total_records} expedientes) en {window}s por {entity_key}."
            ),
            related_event_ids=[int(r["id"]) for r in matching],
        )

    def _evaluate_policy_denial(
        self,
        event: SIEMEventResponse,
        event_epoch: float,
    ) -> SIEMAlertResponse | None:
        entity_key = event.actor or event.source_ip
        if not entity_key:
            return None

        window = self.settings.policy_denial_window_seconds
        rows = self.storage.fetch_window_events(
            start_epoch=event_epoch - window,
            end_epoch=event_epoch,
            actor=event.actor,
            source_ip=event.source_ip if not event.actor else None,
        )
        matching = [r for r in rows if r["msg_id"] in POLICY_DENIAL_MSG_IDS]
        if len(matching) < self.settings.policy_denial_threshold:
            return None

        return self._emit_if_not_in_cooldown(
            rule_id="RULE-003",
            rule_name="REPEATED_POLICY_DENIAL",
            severity="HIGH",
            event_epoch=event_epoch,
            window_seconds=window,
            event_count=len(matching),
            threshold=self.settings.policy_denial_threshold,
            entity_key=f"opa:{entity_key}",
            actor=event.actor,
            source_ip=event.source_ip,
            summary=(
                f"Intentos reiterados de Function Creep: {len(matching)} denegaciones OPA/ABAC "
                f"en {window}s para {entity_key}."
            ),
            related_event_ids=[int(r["id"]) for r in matching],
        )
