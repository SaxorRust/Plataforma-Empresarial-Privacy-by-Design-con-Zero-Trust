from fastapi import FastAPI

from app.config import settings

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description=(
        "Plataforma Empresarial Privacy-by-Design con Zero Trust y Auditoría SIEM "
        "(Escenario Hospitalario — BUAP FCC)"
    ),
)


@app.get("/health", tags=["infraestructura"])
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "hospital-privacy-api",
        "environment": settings.app_env,
    }


@app.get("/", tags=["infraestructura"])
def root() -> dict[str, object]:
    return {
        "service": settings.app_name,
        "architecture": "Privacy-by-Design & Zero Trust",
        "modules": {
            "A": "Gobernanza, WebAuthn/Argon2id, Vault Tokenization & OPA/ABAC",
            "B": "TTL, Safe Harbor + k-Anonimato/l-Diversidad & NIST SP 800-88",
            "C": "Seccomp/AppArmor, Syslog RFC 5424 & SIEM Correlation",
        },
    }
