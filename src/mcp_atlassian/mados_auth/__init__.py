"""Opt-in Mad OS resource-server boundary and memory-only Confluence credentials."""

from __future__ import annotations

import asyncio
import hmac
import json
import math
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

import httpx
from fastmcp.server.dependencies import get_http_request
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp_atlassian.confluence import ConfluenceConfig, ConfluenceFetcher
from mcp_atlassian.utils.env import is_env_ssl_verify, is_env_truthy

UNAVAILABLE = "Mad OS недоступен, попробуйте позже"
ALGORITHMS = ["ES256", "EdDSA", "RS256"]


@dataclass(frozen=True)
class Settings:
    """Validated operator configuration; secret fields never appear in repr."""

    issuer: str
    jwks_url: str
    resource: str
    internal_url: str
    service_token: str = field(repr=False)
    invalidate_token: str = field(repr=False)
    settings_url: str
    confluence_url: str
    pat_ttl: float = 3600

    @classmethod
    def from_env(cls) -> Settings:
        """Load required settings and reject global credential fallback."""
        forbidden = (
            "CONFLUENCE_PERSONAL_TOKEN",
            "CONFLUENCE_API_TOKEN",
            "CONFLUENCE_PERSONAL_TOKEN_COMMAND",
            "CONFLUENCE_API_TOKEN_COMMAND",
            "ATLASSIAN_OAUTH_ACCESS_TOKEN",
            "ATLASSIAN_OAUTH_CLIENT_SECRET",
            "CONFLUENCE_OAUTH_ACCESS_TOKEN",
            "CONFLUENCE_OAUTH_CLIENT_SECRET",
        )
        if is_env_truthy("ALLOW_GLOBAL_CRED_FALLBACK") or any(
            os.getenv(name) for name in forbidden
        ):
            raise ValueError("Mad OS auth forbids global Confluence credentials")

        def required(name: str) -> str:
            value = os.getenv(name, "").strip()
            if not value:
                raise ValueError("Missing Mad OS configuration: " + name)
            return value

        config = cls(
            issuer=required("MADOS_ISSUER"),
            jwks_url=required("MADOS_JWKS_URL"),
            resource=required("MCP_RESOURCE_URL"),
            internal_url=required("MADOS_INTERNAL_URL").rstrip("/"),
            service_token=required("MADOS_SERVICE_TOKEN"),
            invalidate_token=os.getenv("MCP_INVALIDATE_TOKEN", ""),
            settings_url=required("MADOS_CONFLUENCE_SETTINGS_URL"),
            confluence_url=required("CONFLUENCE_URL").rstrip("/"),
            pat_ttl=float(os.getenv("MADOS_PAT_CACHE_TTL_SECONDS", "3600")),
        )
        if not math.isfinite(config.pat_ttl) or config.pat_ttl <= 0:
            raise ValueError("MADOS_PAT_CACHE_TTL_SECONDS must be positive and finite")
        for value in (
            config.issuer,
            config.jwks_url,
            config.resource,
            config.internal_url,
            config.settings_url,
            config.confluence_url,
        ):
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.username
                or parsed.password
                or parsed.fragment
                or parsed.query
                or '"' in value
            ):
                raise ValueError("Invalid Mad OS URL configuration")
        if ConfluenceConfig(url=config.confluence_url, auth_type="pat").is_cloud:
            raise ValueError("Mad OS auth supports Confluence Data Center only")
        return config


class MadOSAuth:
    """ASGI auth boundary with strict JWT verification and bounded memory caches."""

    def __init__(
        self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self.transport = transport
        self._keys: KeySet | None = None
        self._keys_until = 0.0
        self._jwks_lock = asyncio.Lock()
        self._pat_lock = asyncio.Lock()
        self._cache: OrderedDict[str, tuple[float, str | None, str | None]] = (
            OrderedDict()
        )

    async def verify(self, token: str) -> str | None:
        """Verify signature, issuer, resource audience and mandatory lifetime claims."""
        try:
            # Header parsing never authorizes a request; only signed claims do.
            from joserfc.jws import extract_compact

            header = extract_compact(token.encode()).protected
            kid = header.get("kid")
            if header.get("alg") not in ALGORITHMS or not isinstance(kid, str):
                return None
            async with self._jwks_lock:
                known = self._keys is not None and any(
                    key.kid == kid for key in self._keys.keys
                )
                if not known or time.monotonic() >= self._keys_until:
                    async with httpx.AsyncClient(
                        transport=self.transport, timeout=5, follow_redirects=False
                    ) as client:
                        response = await client.get(self.settings.jwks_url)
                        response.raise_for_status()
                        self._keys = KeySet.import_key_set(response.json())
                        self._keys_until = time.monotonic() + 300
                keys = self._keys
            if keys is None:
                return None
            claims = jwt.decode(token, keys, algorithms=ALGORITHMS).claims
            jwt.JWTClaimsRegistry(
                leeway=10,
                iss={"essential": True, "value": self.settings.issuer},
                aud={"essential": True, "value": self.settings.resource},
                exp={"essential": True},
                sub={"essential": True},
            ).validate(claims)
            sub = claims.get("sub")
            exp = claims.get("exp")
            if (
                not isinstance(sub, str)
                or not sub
                or len(sub) > 256
                or not isinstance(exp, int | float)
                or isinstance(exp, bool)
            ):
                return None
            return sub
        except (JoseError, httpx.HTTPError, ValueError, TypeError, KeyError):
            # Never surface token/response-bearing exception text.
            return None

    async def pat(self, profile_id: str) -> str:
        """Resolve a user's PAT; cache 404/403 briefly, never cache outages."""
        # Serializing invalidation with fills prevents an in-flight stale fill from
        # resurrecting a credential after invalidation has returned 204.
        async with self._pat_lock:
            cached = self._cache.get(profile_id)
            if cached is not None and cached[0] > time.monotonic():
                self._cache.move_to_end(profile_id)
                if cached[2]:
                    raise ValueError(cached[2])
                if cached[1] is None:
                    raise ValueError(UNAVAILABLE)
                return cached[1]
            self._cache.pop(profile_id, None)
            error: str | None = None
            pat: str | None = None
            try:
                async with httpx.AsyncClient(
                    transport=self.transport, timeout=5, follow_redirects=False
                ) as client:
                    response = await client.get(
                        self.settings.internal_url
                        + "/internal/confluence/credentials/"
                        + quote(profile_id, safe=""),
                        headers={
                            "Authorization": "Bearer " + self.settings.service_token
                        },
                    )
                if response.status_code == 404:
                    error = (
                        "Confluence не подключён. Подключите свой Personal Access "
                        "Token в Mad OS: " + self.settings.settings_url
                    )
                elif response.status_code == 403:
                    error = "Ваш профиль в Mad OS не активен"
                else:
                    response.raise_for_status()
                    data = response.json()
                    if (
                        data.get("profileId") != profile_id
                        or data.get("baseUrl", "").rstrip("/")
                        != self.settings.confluence_url
                    ):
                        raise ValueError(UNAVAILABLE)
                    pat = data.get("personalAccessToken")
                    if (
                        not isinstance(pat, str)
                        or not pat
                        or any(ord(char) < 33 or ord(char) > 126 for char in pat)
                    ):
                        raise ValueError(UNAVAILABLE)
            except (httpx.HTTPError, ValueError, TypeError, AttributeError):
                raise ValueError(UNAVAILABLE) from None
            ttl = min(30, self.settings.pat_ttl) if error else self.settings.pat_ttl
            self._cache[profile_id] = (time.monotonic() + ttl, pat, error)
            while len(self._cache) > 1024:
                self._cache.popitem(last=False)
            if error:
                raise ValueError(error)
            if pat is None:
                raise ValueError(UNAVAILABLE)
            return pat

    async def fetcher(self) -> ConfluenceFetcher:
        """Build the request-scoped Data Center PAT fetcher from verified identity."""
        request = get_http_request()
        profile_id = getattr(request.state, "mados_sub", None)
        if not profile_id:
            raise ValueError("Mad OS authentication required (HTTP only)")
        cached = getattr(request.state, "confluence_fetcher", None)
        if cached is not None:
            return cached
        pat = await self.pat(profile_id)
        config = ConfluenceConfig(
            url=self.settings.confluence_url,
            auth_type="pat",
            personal_token=pat,
            ssl_verify=is_env_ssl_verify("CONFLUENCE_SSL_VERIFY"),
            **ConfluenceConfig.operator_policy_from_env(),
        )
        fetcher = ConfluenceFetcher(config=config)
        request.state.confluence_fetcher = fetcher
        return fetcher

    def wrap(self, app: ASGIApp, paths: set[str]) -> ASGIApp:
        """Protect MCP paths, serving discovery and service-token invalidation."""
        resource = urlsplit(self.settings.resource)
        origin = f"{resource.scheme}://{resource.netloc}"
        metadata_path = "/.well-known/oauth-protected-resource"

        async def boundary(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] != "http":
                await app(scope, receive, send)
                return
            request = Request(scope, receive)
            path = scope.get("path", "").rstrip("/")
            response: Response | None = None
            if path in {metadata_path, metadata_path + resource.path.rstrip("/")}:
                response = JSONResponse(
                    {
                        "resource": self.settings.resource,
                        "authorization_servers": [self.settings.issuer],
                        "bearer_methods_supported": ["header"],
                        "scopes_supported": [
                            "openid",
                            "profile",
                            "email",
                            "confluence",
                        ],
                    }
                )
            elif path == "/internal/cache/invalidate":
                response = await self._invalidate(request)
            elif any(
                path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/")
                for p in paths
            ):
                authorization = request.headers.get("authorization", "")
                scheme, _, credential = authorization.partition(" ")
                sub = (
                    await self.verify(credential)
                    if scheme.lower() == "bearer"
                    else None
                )
                if sub is None:
                    challenge = f'Bearer resource_metadata="{origin}{metadata_path}"'
                    if authorization:
                        challenge += ', error="invalid_token"'
                    response = JSONResponse(
                        {"error": "unauthorized"},
                        status_code=401,
                        headers={"WWW-Authenticate": challenge},
                    )
                else:
                    scope.setdefault("state", {})["mados_sub"] = sub
            if response is not None:
                await response(scope, receive, send)
            else:
                try:
                    await app(scope, receive, send)
                finally:
                    fetcher = scope.get("state", {}).pop("confluence_fetcher", None)
                    if fetcher is not None:
                        fetcher.close()

        return boundary

    async def _invalidate(self, request: Request) -> Response:
        if not self.settings.invalidate_token:
            return Response(status_code=404)
        expected = "Bearer " + self.settings.invalidate_token
        if not hmac.compare_digest(
            request.headers.get("authorization", "").encode(), expected.encode()
        ):
            return Response(status_code=401)
        if request.method != "POST":
            return Response(status_code=405)
        try:
            data = await request.json()
            profile_id = data.get("profileId")
            if (
                not isinstance(profile_id, str)
                or not profile_id
                or len(profile_id) > 256
            ):
                return Response(status_code=400)
        except (json.JSONDecodeError, AttributeError, UnicodeDecodeError):
            return Response(status_code=400)
        async with self._pat_lock:
            self._cache.pop(profile_id, None)
        return Response(status_code=204)


class MadOSMiddleware:
    """Install the boundary using Starlette's existing middleware hook."""

    def __init__(self, app: ASGIApp, runtime: MadOSAuth, paths: set[str]) -> None:
        self.app = runtime.wrap(app, paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Dispatch an ASGI request."""
        await self.app(scope, receive, send)


_runtime: MadOSAuth | None = None


def get_runtime() -> MadOSAuth | None:
    """Return the process runtime only when explicitly enabled."""
    global _runtime  # noqa: PLW0603
    if not is_env_truthy("MADOS_AUTH_ENABLED"):
        return None
    if _runtime is None:
        _runtime = MadOSAuth(Settings.from_env())
    return _runtime
