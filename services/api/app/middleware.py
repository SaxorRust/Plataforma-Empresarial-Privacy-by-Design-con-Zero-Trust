import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware Zero Trust / Privacy-by-Design:
    - Inyecta cabeceras HTTP de endurecimiento defensivo en todas las respuestas.
    - Fuerza `Cache-Control: no-store` en endpoints de API para evitar caché de datos
      clínicos sensibles en navegadores o proxies intermedios.
    - Adjunta `X-Request-ID` para trazabilidad con auditoría SIEM.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        response = await call_next(request)

        response.headers["X-Request-ID"] = request_id
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # Evitar almacenamiento en caché de respuestas API con posibles datos clínicos
        if not request.url.path.startswith(DOCS_PATHS):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            )

        return response
