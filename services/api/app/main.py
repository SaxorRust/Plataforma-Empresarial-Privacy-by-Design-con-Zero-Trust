from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.lifecycle.ttl_worker import TTLBackgroundScheduler
from app.middleware import SecurityHeadersMiddleware
from app.repositories.auth_repo import DatabaseUnavailableError
from app.routers.auth import router as auth_router
from app.routers.clinical import router as clinical_router
from app.routers.lifecycle import router as lifecycle_router
from app.routers.ui import clinical_portal
from app.routers.ui import router as ui_router
from app.routers.vault import router as vault_router
from app.security.dependencies import (
    get_password_service,
    get_ttl_sweep_service,
    get_user_repository,
)
from app.security.seed_accounts import seed_default_team_accounts

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI):
    if settings.seed_default_accounts:
        repo_provider = application.dependency_overrides.get(
            get_user_repository, get_user_repository
        )
        pwd_provider = application.dependency_overrides.get(
            get_password_service, get_password_service
        )
        try:
            seed_default_team_accounts(
                repo_provider(),
                pwd_provider(),
                suffix=settings.seed_accounts_suffix,
            )
        except DatabaseUnavailableError as exc:
            logger.warning("Se omitió el seed inicial de cuentas (BD no disponible): %s", exc)

    ttl_provider = application.dependency_overrides.get(
        get_ttl_sweep_service, get_ttl_sweep_service
    )
    scheduler = TTLBackgroundScheduler(ttl_provider())
    await scheduler.start()
    try:
        yield
    finally:
        await scheduler.stop()


app = FastAPI(
    title=settings.app_name,
    version="0.5.0",
    description=(
        "Plataforma Empresarial Privacy-by-Design con Zero Trust y Auditoría SIEM "
        "(Escenario Hospitalario — BUAP FCC)"
    ),
    lifespan=lifespan,
)

allowed_origins = [
    settings.webauthn_origin,
    "https://tralaleritosmigajeros.uk",
    "https://app.tralaleritosmigajeros.uk",
]
if settings.app_env == "development":
    allowed_origins.extend(["http://localhost:8000", "http://127.0.0.1:8000"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(set(allowed_origins)),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Purpose", "X-Request-ID"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.include_router(ui_router)
app.include_router(auth_router)
app.include_router(vault_router)
app.include_router(clinical_router)
app.include_router(lifecycle_router)


@app.get("/health", tags=["infraestructura"])
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "hospital-privacy-api",
        "environment": settings.app_env,
    }


@app.get("/edge-check", tags=["infraestructura"])
def edge_check(request: Request) -> dict[str, object]:
    """
    Endpoint de diagnóstico seguro para verificar conectividad a través de
    Cloudflare Tunnel (`CF-Ray`, `CF-IPCountry`, `X-Forwarded-Proto`) sin exponer secretos.
    """
    cf_ray = request.headers.get("cf-ray")
    return {
        "via_cloudflare": bool(cf_ray),
        "cf_ray": cf_ray,
        "cf_country": request.headers.get("cf-ipcountry"),
        "forwarded_proto": request.headers.get("x-forwarded-proto"),
        "host": request.headers.get("host"),
    }


@app.get("/", tags=["infraestructura"])
def root(request: Request, format: str | None = None):
    accept = request.headers.get("accept", "")
    if format != "json" and "text/html" in accept and "application/json" not in accept.split(",")[0]:
        return clinical_portal()
    return {
        "service": settings.app_name,
        "architecture": "Privacy-by-Design & Zero Trust",
        "portal_url": "/portal",
        "modules": {
            "A": "Gobernanza, WebAuthn/Argon2id, Vault Tokenization & OPA/ABAC",
            "B": "TTL, Safe Harbor + k-Anonimato/l-Diversidad & NIST SP 800-88",
            "C": "Seccomp/AppArmor, Syslog RFC 5424 & SIEM Correlation",
        },
    }
