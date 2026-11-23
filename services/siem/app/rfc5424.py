from dataclasses import dataclass
from datetime import datetime, timezone
import re

SEVERITY_NAMES: dict[int, str] = {
    0: "EMERG",
    1: "ALERT",
    2: "CRIT",
    3: "ERR",
    4: "WARNING",
    5: "NOTICE",
    6: "INFO",
    7: "DEBUG",
}

# Cabecera RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP REST
_RFC5424_HEADER_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>[1-9]\d{0,2})\s+"
    r"(?P<timestamp>-|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<hostname>\S{1,255})\s+"
    r"(?P<app_name>\S{1,48})\s+"
    r"(?P<proc_id>\S{1,128})\s+"
    r"(?P<msg_id>\S{1,32})"
    r"(?:\s+(?P<rest>.*))?$"
)


@dataclass(frozen=True)
class ParsedRFC5424Message:
    rfc5424_valid: bool
    facility: int
    severity: int
    severity_name: str
    version: int
    event_timestamp: str
    hostname: str
    app_name: str
    proc_id: str
    msg_id: str
    structured_data: dict[str, dict[str, str]]
    message: str
    raw_message: str


def strip_log_control_chars(value: str) -> str:
    """Elimina CR/LF y caracteres de control para prevenir Log Forging (CWE-117)."""
    cleaned = value.replace("\r", " ").replace("\n", " ").replace("\x00", "")
    return "".join(ch if ord(ch) >= 32 or ch == "\t" else " " for ch in cleaned).strip()


def _normalize_timestamp(raw_ts: str) -> str:
    if raw_ts == "-":
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        iso_value = raw_ts[:-1] + "+00:00" if raw_ts.endswith("Z") else raw_ts
        dt = datetime.fromisoformat(iso_value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_sd_params(rest: str, idx: int, length: int) -> tuple[dict[str, str], int]:
    params: dict[str, str] = {}
    while idx < length and rest[idx] != "]":
        while idx < length and rest[idx] == " ":
            idx += 1
        if idx >= length or rest[idx] == "]":
            break
        eq_pos = rest.find("=", idx)
        if eq_pos == -1 or eq_pos + 1 >= length or rest[eq_pos + 1] != '"':
            close_pos = rest.find("]", idx)
            return params, (length if close_pos == -1 else close_pos)
        key = rest[idx:eq_pos].strip()
        idx = eq_pos + 2
        val_chars: list[str] = []
        while idx < length:
            ch = rest[idx]
            if ch == "\\" and idx + 1 < length:
                val_chars.append(rest[idx + 1])
                idx += 2
                continue
            if ch == '"':
                idx += 1
                break
            val_chars.append(ch)
            idx += 1
        if key:
            params[key] = "".join(val_chars)
    return params, idx


def parse_structured_data(rest: str) -> tuple[dict[str, dict[str, str]], str]:
    """Parsea la sección STRUCTURED-DATA de RFC 5424 sin regex anidado (lineal O(n))."""
    if not rest:
        return {}, ""
    if rest == "-":
        return {}, ""
    if rest.startswith("- "):
        return {}, rest[2:].lstrip()
    if not rest.startswith("["):
        return {}, rest

    sd: dict[str, dict[str, str]] = {}
    idx = 0
    length = len(rest)

    while idx < length and rest[idx] == "[":
        idx += 1
        id_start = idx
        while idx < length and rest[idx] not in (" ", "]"):
            idx += 1
        sd_id = rest[id_start:idx].strip()
        params, idx = _parse_sd_params(rest, idx, length)
        if idx < length and rest[idx] == "]":
            idx += 1
        if sd_id:
            sd[sd_id] = params

    msg = rest[idx:].lstrip()
    if msg.startswith("\ufeff"):
        msg = msg[1:]
    return sd, msg


def parse_rfc5424(raw_message: str) -> ParsedRFC5424Message:
    """Parsea una trama Syslog RFC 5424 y retorna estructura normalizada."""
    cleaned_raw = strip_log_control_chars(raw_message)
    match = _RFC5424_HEADER_RE.match(cleaned_raw)
    if not match:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return ParsedRFC5424Message(
            rfc5424_valid=False,
            facility=16,
            severity=6,
            severity_name="INFO",
            version=0,
            event_timestamp=now_iso,
            hostname="-",
            app_name="unknown",
            proc_id="-",
            msg_id="UNSTRUCTURED",
            structured_data={},
            message=cleaned_raw,
            raw_message=cleaned_raw,
        )

    pri = int(match.group("pri"))
    version = int(match.group("version"))
    if pri > 191 or version != 1:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return ParsedRFC5424Message(
            rfc5424_valid=False,
            facility=16,
            severity=6,
            severity_name="INFO",
            version=version,
            event_timestamp=now_iso,
            hostname=match.group("hostname"),
            app_name=match.group("app_name"),
            proc_id=match.group("proc_id"),
            msg_id=match.group("msg_id"),
            structured_data={},
            message=match.group("rest") or "",
            raw_message=cleaned_raw,
        )

    facility = pri // 8
    severity = pri % 8
    sd, msg = parse_structured_data(match.group("rest") or "")

    return ParsedRFC5424Message(
        rfc5424_valid=True,
        facility=facility,
        severity=severity,
        severity_name=SEVERITY_NAMES.get(severity, "INFO"),
        version=version,
        event_timestamp=_normalize_timestamp(match.group("timestamp")),
        hostname=match.group("hostname"),
        app_name=match.group("app_name"),
        proc_id=match.group("proc_id"),
        msg_id=match.group("msg_id"),
        structured_data=sd,
        message=msg,
        raw_message=cleaned_raw,
    )
