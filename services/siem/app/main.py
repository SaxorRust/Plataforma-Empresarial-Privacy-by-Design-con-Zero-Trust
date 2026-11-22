import os

from fastapi import FastAPI

app = FastAPI(
    title="Hospital-SIEM-Collector",
    version="0.1.0",
    description="Colector Syslog RFC 5424, sanitización en ingesta y motor de correlación temporal",
)


@app.get("/health", tags=["siem"])
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "siem-collector",
        "syslog_port": os.getenv("SIEM_SYSLOG_PORT", "5514"),
    }
