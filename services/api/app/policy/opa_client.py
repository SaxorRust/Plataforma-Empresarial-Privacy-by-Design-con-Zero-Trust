from typing import Any
from urllib.parse import urlsplit

import httpx

from app.models.clinical import OPADecision, OPAStatusResponse


class OPAServiceError(Exception):
    """Error genérico al evaluar políticas en Open Policy Agent."""


class OPAUnavailableError(OPAServiceError):
    """OPA no está disponible o devolvió una respuesta inválida (fail-closed)."""


class OPAClient:
    """
    Cliente Zero Trust para Open Policy Agent (MA-03).
    Opera estrictamente en modo **Fail-Closed (Default Deny)**: cualquier error de red,
    timeout o respuesta malformada bloquea el acceso (HTTP 503) en lugar de autorizar.
    """

    def __init__(
        self,
        *,
        opa_url: str,
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._opa_url = opa_url.rstrip("/")
        self._timeout = timeout_seconds
        self._transport = transport

    def _base_url(self) -> str:
        parts = urlsplit(self._opa_url)
        return f"{parts.scheme}://{parts.netloc}"

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=self._timeout,
            transport=self._transport,
        )

    def evaluate(
        self,
        *,
        role: str,
        purpose: str,
        action: str,
        resource_purpose: str | None = None,
        is_sanitized: bool = False,
        resource_owner_match: bool = False,
    ) -> OPADecision:
        """Envía atributos ABAC a OPA y devuelve la decisión estructurada."""
        payload: dict[str, Any] = {
            "input": {
                "role": role,
                "purpose": purpose.strip() if purpose else "",
                "action": action,
                "is_sanitized": bool(is_sanitized),
                "resource_owner_match": bool(resource_owner_match),
            }
        }
        if resource_purpose is not None:
            payload["input"]["resource_purpose"] = resource_purpose

        try:
            with self._client() as client:
                response = client.post(self._opa_url, json=payload)
        except httpx.HTTPError as exc:
            raise OPAUnavailableError(
                "Motor de políticas OPA no disponible (fail-closed: acceso denegado)."
            ) from exc

        if response.status_code >= 500:
            raise OPAUnavailableError(
                f"Error interno del motor OPA (HTTP {response.status_code}, fail-closed)."
            )
        if response.status_code >= 400:
            raise OPAServiceError(
                f"Error al consultar OPA (HTTP {response.status_code})."
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise OPAUnavailableError("Respuesta no-JSON de OPA (fail-closed).") from exc

        result = body.get("result")
        if not isinstance(result, dict) or "allow" not in result:
            raise OPAUnavailableError(
                "Política ABAC no cargada o decisión incompleta en OPA (fail-closed)."
            )

        return OPADecision(
            allow=bool(result.get("allow", False)),
            allowed_fields=[str(f) for f in result.get("allowed_fields", [])],
            generalize_fields=bool(result.get("generalize_fields", False)),
            mask_token=bool(result.get("mask_token", False)),
            reason=str(
                result.get(
                    "reason",
                    "Acceso denegado por política ABAC (prevención de function creep)",
                )
            ),
            policy_version=str(result.get("policy_version", "1.1.0")),
        )

    def get_status(self) -> OPAStatusResponse:
        """Verifica salud de OPA y disponibilidad de la política `hospital.authz`."""
        health_url = f"{self._base_url()}/health"
        try:
            with self._client() as client:
                health_resp = client.get(health_url)
        except httpx.HTTPError as exc:
            raise OPAUnavailableError("No fue posible consultar salud de OPA.") from exc

        reachable = health_resp.status_code == 200
        if not reachable:
            return OPAStatusResponse(
                reachable=False,
                opa_url=self._opa_url,
                policy_loaded=False,
                policy_version=None,
            )

        try:
            probe = self.evaluate(role="admin_sec", purpose="", action="read_record")
            return OPAStatusResponse(
                reachable=True,
                opa_url=self._opa_url,
                policy_loaded=True,
                policy_version=probe.policy_version,
            )
        except OPAServiceError:
            return OPAStatusResponse(
                reachable=True,
                opa_url=self._opa_url,
                policy_loaded=False,
                policy_version=None,
            )
