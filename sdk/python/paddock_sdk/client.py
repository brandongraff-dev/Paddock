"""The public client: generated operations + the hand-written core."""
from __future__ import annotations

from typing import Any

from ._core import BaseClient, NotFound
from ._generated import API_VERSION, OPERATIONS, GeneratedOperations


class PaddockClient(GeneratedOperations, BaseClient):
    """Typed client for the Paddock /v1 API.

    Every API operation is a method (``list_scope``, ``add_scope``,
    ``create_scan``, ``patch_finding``, ...); see ``OPERATIONS`` for the
    full name -> (method, path) index.

    A few endpoints are newer than some servers (exports, integrations); the
    helpers below call them by path and raise :class:`NotFound` with a clear
    message when the server predates them.
    """

    OPERATIONS = OPERATIONS
    SPEC_VERSION = API_VERSION

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return BaseClient._request(self, method, path, **kwargs)

    # -- endpoints that may not exist on every server ---------------------- #
    def _optional(self, method: str, path: str, feature: str, **kwargs: Any) -> Any:
        try:
            return self.request(method, path, **kwargs)
        except NotFound as exc:
            # A 404 whose detail is the stock FastAPI "Not Found" means the
            # route itself is missing, not the object.
            if exc.detail in ("Not Found", None, ""):
                raise NotFound(
                    404,
                    f"this Paddock server does not provide {feature} ({method} {path}); upgrade the server",
                    method=method, url=path,
                ) from exc
            raise

    def export_format(self, fmt: str, **query: Any) -> Any:
        """GET /v1/export/{fmt} -- SARIF / SBOM / OCSF exports."""
        return self._optional("GET", f"/v1/export/{fmt}", f"{fmt} export", query=query)

    def integrations_list(self, **query: Any) -> Any:
        """GET /v1/integrations."""
        return self._optional("GET", "/v1/integrations", "integrations", query=query)

    def scope_verify(self, entry_id: int | str) -> Any:
        """POST /v1/scope/{id}/verify -- proof-of-control check for a scope entry."""
        return self._optional("POST", f"/v1/scope/{entry_id}/verify", "scope verification")
