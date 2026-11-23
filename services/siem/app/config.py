from dataclasses import dataclass
import os


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        parsed = int(raw.strip())
    except ValueError:
        return default
    return max(minimum, parsed)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SIEMSettings:
    """Configuración del Colector SIEM RFC 5424 y Motor de Correlación Temporal (Módulo C)."""

    service_name: str
    syslog_host: str
    syslog_port: int
    enable_syslog_listener: bool
    db_path: str
    max_message_bytes: int
    brute_force_threshold: int
    brute_force_window_seconds: int
    mass_query_threshold: int
    mass_records_threshold: int
    mass_query_window_seconds: int
    policy_denial_threshold: int
    policy_denial_window_seconds: int
    alert_cooldown_seconds: int


def load_siem_settings() -> SIEMSettings:
    default_db = "/data/siem_events.db" if os.path.isdir("/data") else ":memory:"
    return SIEMSettings(
        service_name=os.getenv("SIEM_SERVICE_NAME", "siem-collector"),
        syslog_host=os.getenv("SIEM_SYSLOG_HOST", "127.0.0.1"),
        syslog_port=_env_int("SIEM_SYSLOG_PORT", 5514, minimum=0),
        enable_syslog_listener=_env_bool("SIEM_ENABLE_SYSLOG_LISTENER", True),
        db_path=os.getenv("SIEM_DB_PATH", default_db),
        max_message_bytes=_env_int("SIEM_MAX_MESSAGE_BYTES", 65536, minimum=1024),
        brute_force_threshold=_env_int("SIEM_BRUTE_FORCE_THRESHOLD", 5),
        brute_force_window_seconds=_env_int("SIEM_BRUTE_FORCE_WINDOW_SECONDS", 60),
        mass_query_threshold=_env_int("SIEM_MASS_QUERY_THRESHOLD", 10),
        mass_records_threshold=_env_int("SIEM_MASS_RECORDS_THRESHOLD", 25),
        mass_query_window_seconds=_env_int("SIEM_MASS_QUERY_WINDOW_SECONDS", 60),
        policy_denial_threshold=_env_int("SIEM_POLICY_DENIAL_THRESHOLD", 5),
        policy_denial_window_seconds=_env_int("SIEM_POLICY_DENIAL_WINDOW_SECONDS", 120),
        alert_cooldown_seconds=_env_int("SIEM_ALERT_COOLDOWN_SECONDS", 30, minimum=0),
    )
