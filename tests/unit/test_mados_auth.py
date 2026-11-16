"""Mad OS contract regression tests; all secrets are synthetic."""

import time

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import ECKey, RSAKey
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from mcp_atlassian.mados_auth import MadOSAuth, Settings


@pytest.fixture
def settings(monkeypatch):
    values = {
        "MADOS_AUTH_ENABLED": "true",
        "MADOS_ISSUER": "https://issuer.test/api/auth",
        "MADOS_JWKS_URL": "https://issuer.test/api/auth/jwks",
        "MCP_RESOURCE_URL": "https://mcp.test/mcp",
        "MADOS_INTERNAL_URL": "http://internal.test",
        "MADOS_SERVICE_TOKEN": "synthetic-service",
        "MCP_INVALIDATE_TOKEN": "synthetic-invalidate",
        "MADOS_CONFLUENCE_SETTINGS_URL": "https://web.test/settings/confluence",
        "CONFLUENCE_URL": "https://confluence.test",
        "ALLOW_GLOBAL_CRED_FALLBACK": "false",
    }
    for name in (
        "CONFLUENCE_PERSONAL_TOKEN",
        "CONFLUENCE_API_TOKEN",
        "CONFLUENCE_PERSONAL_TOKEN_COMMAND",
        "CONFLUENCE_API_TOKEN_COMMAND",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return Settings.from_env()


@pytest.fixture(params=["ES256", "RS256", "EdDSA"])
def signing_key(request):
    from joserfc.jwk import OKPKey

    if request.param == "ES256":
        key = ECKey.generate_key("P-256", parameters={"kid": "one"})
    elif request.param == "RS256":
        key = RSAKey.generate_key(2048, parameters={"kid": "one"})
    else:
        key = OKPKey.generate_key("Ed25519", parameters={"kid": "one"})
    return request.param, key


def token(settings, signing_key, **overrides):
    algorithm, key = signing_key
    claims = {
        "iss": settings.issuer,
        "aud": [settings.resource],
        "sub": "alice",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
    }
    claims.update(overrides)
    return jwt.encode(
        {"alg": algorithm, "kid": "one"}, claims, key, algorithms=[algorithm]
    )


def make_auth(settings, signing_key, status=200):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path.endswith("jwks"):
            return httpx.Response(200, json={"keys": [signing_key[1].as_dict()]})
        assert request.headers["authorization"] == "Bearer synthetic-service"
        return httpx.Response(
            status,
            json={
                "profileId": request.url.path.rsplit("/", 1)[-1],
                "baseUrl": settings.confluence_url,
                "personalAccessToken": "synthetic-pat",
                "credentialVersion": "v1",
                "confluenceUsername": "alice",
            },
        )

    return MadOSAuth(settings, transport=httpx.MockTransport(handler)), calls


@pytest.mark.asyncio
async def test_jwt_claims(settings, signing_key):
    auth, _ = make_auth(settings, signing_key)
    assert await auth.verify(token(settings, signing_key)) == "alice"
    for overrides in (
        {"iss": "wrong"},
        {"aud": "wrong"},
        {"exp": time.time() - 60},
        {"nbf": time.time() + 60},
        {"sub": ""},
        {"exp": None},
    ):
        assert await auth.verify(token(settings, signing_key, **overrides)) is None
    assert await auth.verify("malformed") is None


@pytest.mark.asyncio
async def test_http_boundary(settings, signing_key):
    auth, _ = make_auth(settings, signing_key)

    async def endpoint(request):
        return JSONResponse({"sub": getattr(request.state, "mados_sub", None)})

    app = auth.wrap(
        Starlette(
            routes=[
                Route("/mcp", endpoint, methods=["POST"]),
                Route("/healthz", endpoint),
            ]
        ),
        {"/mcp"},
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test"
    ) as client:
        for path in (
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ):
            response = await client.get(path)
            assert response.json()["authorization_servers"] == [settings.issuer]
            assert response.json()["resource"] == settings.resource
        response = await client.post("/mcp")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == (
            'Bearer resource_metadata="https://mcp.test/'
            '.well-known/oauth-protected-resource"'
        )
        response = await client.post("/mcp", headers={"Authorization": "Bearer bad"})
        assert response.status_code == 401
        assert 'error="invalid_token"' in response.headers["www-authenticate"]
        response = await client.post(
            "/mcp", headers={"Authorization": "Bearer " + token(settings, signing_key)}
        )
        assert response.json()["sub"] == "alice"
        assert (await client.get("/healthz")).status_code == 200


@pytest.mark.asyncio
async def test_cache_and_invalidation(settings, signing_key, monkeypatch, caplog):
    auth, calls = make_auth(settings, signing_key)
    now = [100.0]
    monkeypatch.setattr("mcp_atlassian.mados_auth.time.monotonic", lambda: now[0])
    assert await auth.pat("alice") == "synthetic-pat"
    assert await auth.pat("alice") == "synthetic-pat"
    assert len(calls) == 1
    now[0] += 3601
    await auth.pat("alice")
    assert len(calls) == 2
    app = auth.wrap(Starlette(), {"/mcp"})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test"
    ) as client:
        assert (
            await client.post("/internal/cache/invalidate", json={"profileId": "alice"})
        ).status_code == 401
        response = await client.post(
            "/internal/cache/invalidate",
            headers={"Authorization": "Bearer synthetic-invalidate"},
            json={"profileId": "alice"},
        )
        assert response.status_code == 204
        await auth.pat("alice")
        assert len(calls) == 3
    assert "synthetic-pat" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,message",
    [
        (404, "Confluence не подключён"),
        (403, "Ваш профиль в Mad OS не активен"),
        (500, "Mad OS недоступен"),
        (401, "Mad OS недоступен"),
    ],
)
async def test_credential_errors(settings, signing_key, status, message, monkeypatch):
    auth, calls = make_auth(settings, signing_key, status)
    now = [100.0]
    monkeypatch.setattr("mcp_atlassian.mados_auth.time.monotonic", lambda: now[0])
    for _ in range(2):
        with pytest.raises(ValueError, match=message):
            await auth.pat("alice")
    assert len(calls) == (1 if status in (403, 404) else 2)
    now[0] += 31
    with pytest.raises(ValueError, match=message):
        await auth.pat("alice")
    assert len(calls) == (2 if status in (403, 404) else 3)


@pytest.mark.parametrize(
    "name",
    [
        "CONFLUENCE_PERSONAL_TOKEN",
        "CONFLUENCE_API_TOKEN",
        "CONFLUENCE_PERSONAL_TOKEN_COMMAND",
        "ALLOW_GLOBAL_CRED_FALLBACK",
    ],
)
def test_global_credentials_refused(settings, monkeypatch, name):
    monkeypatch.setenv(name, "true")
    with pytest.raises(ValueError):
        Settings.from_env()


@pytest.mark.asyncio
async def test_rotation_and_wrong_signature(settings):
    key1 = ECKey.generate_key("P-256", parameters={"kid": "one"})
    key2 = ECKey.generate_key("P-256", parameters={"kid": "two"})
    keys = [key1.as_dict()]
    count = []

    def handler(request):
        count.append(request)
        return httpx.Response(200, json={"keys": keys})

    auth = MadOSAuth(settings, transport=httpx.MockTransport(handler))
    assert await auth.verify(token(settings, ("ES256", key1))) == "alice"
    claims = {
        "iss": settings.issuer,
        "aud": settings.resource,
        "sub": "bob",
        "exp": int(time.time()) + 100,
    }
    signed = jwt.encode({"alg": "ES256", "kid": "two"}, claims, key2)
    keys.append(key2.as_dict())
    assert await auth.verify(signed) == "bob"
    assert len(count) == 2
    forged = jwt.encode({"alg": "ES256", "kid": "one"}, claims, key2)
    assert await auth.verify(forged) is None


@pytest.mark.asyncio
async def test_fetcher_sends_user_pat(settings, signing_key, monkeypatch, caplog):
    import logging

    from starlette.requests import Request

    from mcp_atlassian.servers.async_utils import run_fetcher_call

    auth, _ = make_auth(settings, signing_key)
    request = Request({"type": "http", "state": {"mados_sub": "alice"}})
    monkeypatch.setattr("mcp_atlassian.mados_auth.get_http_request", lambda: request)
    caplog.set_level(logging.DEBUG)
    fetcher = await auth.fetcher()
    assert await auth.fetcher() is fetcher
    captured = []

    def send(session, prepared, **kwargs):
        from requests import Response

        captured.append(prepared.headers["Authorization"])
        response = Response()
        response.status_code = 200
        response._content = b'{"type":"known", "username":"alice"}'
        response.headers["Content-Type"] = "application/json"
        return response

    monkeypatch.setattr("requests.Session.send", send)
    await run_fetcher_call(fetcher.confluence.get, "rest/api/user/current")
    assert captured == ["Bearer synthetic-pat"]
    assert "synthetic-pat" not in caplog.text
    fetcher.close()


@pytest.mark.asyncio
async def test_disabled_invalidation_and_bad_body(settings, signing_key):
    from dataclasses import replace

    auth, _ = make_auth(settings, signing_key)
    for credential, expected in (("synthetic-invalidate", 400), ("wrong", 401)):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(auth.wrap(Starlette(), {"/mcp"})),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/internal/cache/invalidate",
                content="bad",
                headers={"Authorization": "Bearer " + credential},
            )
            assert response.status_code == expected
    auth = MadOSAuth(replace(settings, invalidate_token=""))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(auth.wrap(Starlette(), {"/mcp"})),
        base_url="http://test",
    ) as client:
        assert (await client.post("/internal/cache/invalidate")).status_code == 404


@pytest.mark.asyncio
async def test_real_server_metadata_and_auth(settings, monkeypatch):
    from mcp_atlassian import mados_auth
    from mcp_atlassian.servers.main import AtlassianMCP

    monkeypatch.setattr(mados_auth, "_runtime", MadOSAuth(settings))
    server = AtlassianMCP("test")
    app = server.http_app(stateless_http=True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test"
    ) as client:
        response = await client.get("/.well-known/oauth-protected-resource")
        assert response.status_code == 200
        assert response.json()["resource"] == settings.resource
        response = await client.post("/mcp")
        assert response.status_code == 401
        assert "resource_metadata=" in response.headers["www-authenticate"]


@pytest.mark.asyncio
async def test_timeout_not_cached_and_no_secret_exception(settings):
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("synthetic-pat must not escape", request=request)

    auth = MadOSAuth(settings, transport=httpx.MockTransport(handler))
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            await auth.pat("alice")
        assert str(error.value) == "Mad OS недоступен, попробуйте позже"
        assert error.value.__suppress_context__
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pat", [" leading", "bad\ntoken", "bad\u0100token", "bad\ttoken"]
)
async def test_unsafe_pat_never_reaches_client(settings, pat):
    def handler(request):
        return httpx.Response(
            200,
            json={
                "profileId": "alice",
                "baseUrl": settings.confluence_url,
                "personalAccessToken": pat,
            },
        )

    auth = MadOSAuth(settings, transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="Mad OS недоступен"):
        await auth.pat("alice")


def test_configurable_long_ttl(settings, monkeypatch):
    monkeypatch.setenv("MADOS_PAT_CACHE_TTL_SECONDS", "172800")
    assert Settings.from_env().pat_ttl == 172800
