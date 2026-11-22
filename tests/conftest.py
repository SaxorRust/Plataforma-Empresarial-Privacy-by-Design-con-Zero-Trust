import importlib.util
from pathlib import Path
import sys

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SERVICE_PATHS = {
    "api": str(ROOT / "services" / "api"),
    "siem": str(ROOT / "services" / "siem"),
}


def load_service_app(service_name: str):
    """Carga la instancia FastAPI aislada para `api` o `siem` evitando colisiones de `app`."""
    target_path = SERVICE_PATHS[service_name]

    # Retirar rutas de otros servicios para evitar colisiones de importación `app.*`
    for path in SERVICE_PATHS.values():
        while path in sys.path:
            sys.path.remove(path)
    sys.path.insert(0, target_path)

    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app."):
            del sys.modules[mod]

    spec = importlib.util.spec_from_file_location(
        f"{service_name}_main", ROOT / "services" / service_name / "app" / "main.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


def load_service_client(service_name: str) -> TestClient:
    """Carga un cliente FastAPI aislado para `api` o `siem` evitando colisiones de `app`."""
    return TestClient(load_service_app(service_name))
