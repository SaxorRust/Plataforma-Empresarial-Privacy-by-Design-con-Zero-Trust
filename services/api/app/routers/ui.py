from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter(tags=["ui-portal"])

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@router.get(
    "/portal",
    response_class=HTMLResponse,
    summary="Portal Web Clínico & Consola de Gobernanza Privacy-by-Design y Zero Trust",
)
def clinical_portal() -> HTMLResponse:
    html_content = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html_content)


@router.get(
    "/ui/portal.css",
    include_in_schema=False,
)
def portal_css() -> FileResponse:
    return FileResponse(STATIC_DIR / "portal.css", media_type="text/css; charset=utf-8")


@router.get(
    "/ui/portal.js",
    include_in_schema=False,
)
def portal_js() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "portal.js",
        media_type="application/javascript; charset=utf-8",
    )
