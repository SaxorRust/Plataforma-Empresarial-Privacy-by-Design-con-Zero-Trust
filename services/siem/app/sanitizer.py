from dataclasses import dataclass
import re

# ==============================================================================
# Pipeline de Sanitización en Ingesta (MC-03 — Privacy-by-Design)
# Todas las expresiones regulares son lineales (sin cuantificadores anidados)
# para prevenir ataques ReDoS y ofuscan PII/secretos ANTES de persistir.
# ==============================================================================

# 1. Tarjetas bancarias (PAN 13-19 dígitos con espacios o guiones opcionales, validado por Luhn)
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")

# 2. CURP mexicana oficial (18 caracteres)
_CURP_RE = re.compile(
    r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d\b",
    re.IGNORECASE,
)

# 3. Credenciales, contraseñas y secretos en pares clave/valor (form, syslog SD, JSON)
_PASSWORD_KV_RE = re.compile(
    r"(?P<prefix>[\"']?(?:password|passwd|pwd|contrasena|contraseña|secret|api[_-]?key|pepper|client_secret)[\"']?"
    r"\s*(?:=|:)\s*)"
    r"(?P<quote>\"|')?(?P<value>[^\"'\s,;}\]]+)(?P=quote)?",
    re.IGNORECASE,
)

# 4. Cabeceras Authorization Bearer / Basic o tokens explícitos
_AUTH_HEADER_RE = re.compile(
    r"(?P<prefix>(?:authorization\s*[:=]\s*)?(?:bearer|basic)\s+)"
    r"(?P<value>[A-Za-z0-9._\-+/=]{8,})",
    re.IGNORECASE,
)

# 5. Tokens JWT compactos (header.payload.signature)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")

# 6. Hashes Argon2id (evitar exposición accidental en logs)
_ARGON2_RE = re.compile(r"\$argon2id\$[^\s\"';,]+")

# 7. NSS mexicano en contexto etiquetado (11 dígitos)
_NSS_KV_RE = re.compile(
    r"(?P<prefix>[\"']?\bnss[\"']?\s*(?:=|:)\s*)(?P<quote>\"|')?(?P<value>\d{11})(?P=quote)?",
    re.IGNORECASE,
)

# Claves de STRUCTURED-DATA cuyo valor debe ofuscarse siempre por principio de minimización
_SENSITIVE_SD_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "contrasena",
        "secret",
        "pepper",
        "api_key",
        "token",
        "access_token",
        "authorization",
        "curp",
        "nss",
        "card",
        "credit_card",
        "pan",
        "cvv",
    }
)


@dataclass(frozen=True)
class SanitizationResult:
    text: str
    sanitized: bool
    redacted_categories: tuple[str, ...]
    redaction_count: int


def is_valid_luhn(digits: str) -> bool:
    """Valida el dígito verificador Luhn para reducir falsos positivos en números de tarjeta."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    parity = len(digits) % 2
    for idx, ch in enumerate(digits):
        num = int(ch)
        if idx % 2 == parity:
            num *= 2
            if num > 9:
                num -= 9
        total += num
    return total % 10 == 0


def _redact_cards(text: str) -> tuple[str, int]:
    count = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal count
        raw = match.group(0)
        digits = "".join(ch for ch in raw if ch.isdigit())
        if is_valid_luhn(digits):
            count += 1
            return "[REDACTED_CARD:***]"
        return raw

    return _CARD_CANDIDATE_RE.sub(_replace, text), count


def _redact_pattern(
    pattern: re.Pattern[str],
    text: str,
    replacement: str,
    *,
    preserve_prefix: bool = False,
) -> tuple[str, int]:
    count = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        if preserve_prefix:
            quote = match.groupdict().get("quote") or ""
            return f"{match.group('prefix')}{quote}{replacement}{quote}"
        return replacement

    return pattern.sub(_replace, text), count


def sanitize_text(text: str) -> SanitizationResult:
    """Aplica el pipeline de ofuscación regex en orden determinista antes de persistir."""
    if not text:
        return SanitizationResult(text="", sanitized=False, redacted_categories=(), redaction_count=0)

    current = text
    categories: list[str] = []
    total_redactions = 0

    steps = (
        ("jwt", _JWT_RE, "[REDACTED_JWT:***]"),
        ("argon2_hash", _ARGON2_RE, "[REDACTED_HASH:***]"),
        ("curp", _CURP_RE, "[REDACTED_CURP:***]"),
    )
    for cat, pattern, replacement in steps:
        current, hits = _redact_pattern(pattern, current, replacement)
        if hits:
            categories.append(cat)
            total_redactions += hits

    kv_steps = (
        ("password", _PASSWORD_KV_RE, "[REDACTED_PASSWORD:***]"),
        ("auth_token", _AUTH_HEADER_RE, "[REDACTED_TOKEN:***]"),
        ("nss", _NSS_KV_RE, "[REDACTED_NSS:***]"),
    )
    for cat, pattern, replacement in kv_steps:
        current, hits = _redact_pattern(pattern, current, replacement, preserve_prefix=True)
        if hits:
            categories.append(cat)
            total_redactions += hits

    current, card_hits = _redact_cards(current)
    if card_hits:
        categories.append("credit_card")
        total_redactions += card_hits

    return SanitizationResult(
        text=current,
        sanitized=total_redactions > 0,
        redacted_categories=tuple(sorted(set(categories))),
        redaction_count=total_redactions,
    )


def sanitize_structured_data(
    structured_data: dict[str, dict[str, str]],
) -> tuple[dict[str, dict[str, str]], list[str], int]:
    """Sanitiza todos los parámetros STRUCTURED-DATA (por clave sensible y por contenido regex)."""
    sanitized_sd: dict[str, dict[str, str]] = {}
    categories: set[str] = set()
    total_redactions = 0

    for sd_id, params in structured_data.items():
        clean_params: dict[str, str] = {}
        for key, value in params.items():
            lowered_key = key.lower()
            if lowered_key in _SENSITIVE_SD_KEYS:
                clean_params[key] = "***"
                categories.add(f"sd_{lowered_key}")
                total_redactions += 1
                continue
            res = sanitize_text(value)
            clean_params[key] = res.text
            if res.sanitized:
                categories.update(res.redacted_categories)
                total_redactions += res.redaction_count
        sanitized_sd[sd_id] = clean_params

    return sanitized_sd, sorted(categories), total_redactions
