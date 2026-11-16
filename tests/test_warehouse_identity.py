import asyncio
import json
import time
from types import SimpleNamespace

import httpx
import pytest
from authlib.jose import JsonWebKey, JsonWebToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lake_mcp import server
from lake_mcp.runtime_security import build_auth

ISSUER = "https://issuer.example"
ALICE_DSN = "lake://alice:synthetic@warehouse.example/alice_db"
BOB_DSN = "lake://bob:synthetic@warehouse.example/bob_db"
INITIALIZE = {
    "protocolVersion": "2025-11-25",
    "capabilities": {},
    "clientInfo": {"name": "test", "version": "1"},
}


@pytest.fixture
def warehouse_map(monkeypatch, tmp_path):
    path = tmp_path / "warehouses.json"
    path.write_text(json.dumps({"alice": ALICE_DSN, "bob": BOB_DSN}))
    path.chmod(0o600)
    monkeypatch.setenv("LAKE_MCP_WAREHOUSE_MAP_FILE", str(path))
    monkeypatch.setenv("LAKE_MCP_AUTH_ISSUER", ISSUER)
    monkeypatch.setenv("LAKE_MCP_AUTH_AUDIENCE", "lake")
    monkeypatch.setenv("LAKE_MCP_AUTH_JWKS_URI", f"{ISSUER}/jwks")
    monkeypatch.delenv("LAKE_MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("LAKE_MCP_AUTH_SUBJECT", raising=False)
    return path


@pytest.mark.parametrize(
    "entries",
    [
        '{"alice":"lake://alice:dummy@warehouse.example/one","alice":"lake://bob:dummy@warehouse.example/two"}',
        json.dumps({"alice": ALICE_DSN, "bob": "lake://alice:other@warehouse.example:443/other?role=limited"}),
        json.dumps({"alice": "lake://alice:dummy@localhost/db?sslmode=disable"}),
        json.dumps({"alice": ALICE_DSN + "?access_token_file=/dummy"}),
        json.dumps({"alice": "lake://warehouse.example/db"}),
    ],
)
def test_warehouse_map_rejects_unsafe_entries(warehouse_map, entries):
    warehouse_map.write_text(entries)
    with pytest.raises(ValueError, match="Invalid warehouse map") as exc:
        build_auth()
    assert "dummy" not in str(exc.value)


@pytest.mark.parametrize("setting", ["LAKE_MCP_AUTH_SUBJECT", "LAKE_MCP_AUTH_TOKEN"])
def test_mapped_mode_rejects_single_owner_auth(warehouse_map, monkeypatch, setting):
    monkeypatch.setenv(setting, "single-owner")
    with pytest.raises(ValueError, match="exactly one subject or warehouse map"):
        build_auth()


@pytest.fixture
def mapped_server(warehouse_map, monkeypatch):
    verifier = build_auth()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = JsonWebKey.import_key(
        private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        {"kty": "RSA"},
    )
    codec = JsonWebToken(["RS256"])

    async def verification_key(_):
        return key

    monkeypatch.setattr(verifier, "_get_verification_key", verification_key)
    monkeypatch.setattr(server.mcp, "auth", verifier)
    monkeypatch.setenv("LAKE_DSN", "lake://fallback:synthetic@warehouse.example/global_db")
    monkeypatch.setenv("LAKE_MCP_SAFE_MODE", "false")
    monkeypatch.delenv("LOCAL_MODE", raising=False)

    def sign(subject, scope="lake", **claims):
        return codec.encode(
            {"alg": "RS256"},
            {"sub": subject, "iss": ISSUER, "aud": "lake", "azp": "shared-app", "scope": scope, "exp": int(time.time()) + 300, **claims},
            key,
        ).decode()

    return sign


def test_mapped_server_requires_network_without_local_fallback(mapped_server, monkeypatch):
    monkeypatch.setattr(server, "create_lake_client", lambda _: pytest.fail("Unexpected warehouse client"))
    assert server._execute_sql("SELECT 1") == {"status": "error", "message": "No warehouse account for this identity"}
    monkeypatch.setenv("LOCAL_MODE", "true")
    with pytest.raises(ValueError, match="requires remote Lake connections"):
        server.mcp.http_app()


@pytest.mark.asyncio
async def test_subject_routing_and_session_authorization(mapped_server, monkeypatch):
    sign = mapped_server
    created = []
    executed = []

    class Result(list):
        def schema(self):
            return SimpleNamespace(fields=lambda: [SimpleNamespace(name="account")])

    def create_client(dsn):
        created.append(dsn)

        def query_iter(sql):
            executed.append((dsn, sql))
            return Result([{"account": dsn.split("://")[1].split(":")[0]}])

        return SimpleNamespace(get_conn=lambda: SimpleNamespace(query_iter=query_iter))

    monkeypatch.setattr(server, "create_lake_client", create_client)
    app = server.mcp.http_app(json_response=True)
    headers = {"Accept": "application/json, text/event-stream"}

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=headers) as client:

            async def rpc(token, method, params=None, session=None):
                request = {"jsonrpc": "2.0", "method": method}
                if method != "notifications/initialized":
                    request["id"] = 1 if method == "initialize" else 2
                if params is not None:
                    request["params"] = params
                request_headers = {"Authorization": f"Bearer {token}"}
                if session:
                    request_headers["Mcp-Session-Id"] = session
                return await client.post("/mcp", json=request, headers=request_headers)

            async def open_session(token):
                response = await rpc(token, "initialize", INITIALIZE)
                response.raise_for_status()
                session = response.headers["Mcp-Session-Id"]
                (await rpc(token, "notifications/initialized", session=session)).raise_for_status()
                return session

            async def tool(token, session, tool_name, **arguments):
                return await rpc(token, "tools/call", {"name": tool_name, "arguments": arguments}, session)

            def result(response):
                response.raise_for_status()
                payload = response.json()["result"]
                assert "structuredContent" in payload, payload
                return payload["structuredContent"]

            alice, bob = sign("alice", "lake lake:write"), sign("bob")
            for token in (sign("unmapped"), sign("alice", "other"), sign("alice", iss="https://wrong.example"), sign("alice", exp=0)):
                assert (await rpc(token, "initialize", INITIALIZE)).status_code == 401
            assert created == []

            alice_session, bob_session = await asyncio.gather(open_session(alice), open_session(bob))
            assert (await tool(bob, alice_session, "execute_sql", sql="SELECT 1")).status_code == 404
            assert executed == []

            writes = {"create_stage", "create_session_sandbox_database"}
            for token, session, can_write in ((alice, alice_session, True), (bob, bob_session, False)):
                listed = (await rpc(token, "tools/list", session=session)).json()["result"]["tools"]
                assert {item["name"] for item in listed} & writes == (writes if can_write else set())
            denied = await tool(bob, bob_session, "create_session_sandbox_database", name="test")
            assert denied.json()["result"]["isError"]
            assert executed == []

            alice_result, bob_result = await asyncio.gather(
                tool(alice, alice_session, "execute_sql", sql="SELECT 1"),
                tool(bob, bob_session, "show_databases"),
            )
            assert result(alice_result)["data"] == [{"account": "alice"}]
            assert result(bob_result)["data"] == [{"account": "bob"}]
            assert result(await tool(bob, bob_session, "list_stage_files", stage_name="example"))["data"] == [{"account": "bob"}]
            assert set(created) == {ALICE_DSN + "?sslmode=require", BOB_DSN + "?sslmode=require"}

            prefix = result(await tool(alice, alice_session, "get_session_sandbox_prefix"))["prefix"]
            assert result(await tool(sign("alice"), alice_session, "execute_sql", sql=f"CREATE DATABASE {prefix}test"))["status"] == "error"
            assert result(await tool(alice, alice_session, "execute_sql", sql=f"CREATE DATABASE {prefix}test"))["status"] == "success"

            # Even lake:write plus local-admin environment flags cannot disable
            # the storage boundary for an authenticated HTTP caller.
            monkeypatch.setenv("LAKE_MCP_ALLOW_STDIO_ADMIN", "1")
            previous = len(executed)
            for sql in (
                f"CREATE STAGE {prefix}s 's3://example.invalid/production/'",
                f"REMOVE @{prefix}s",
                f"CREATE TABLE {prefix}t EXTERNAL_LOCATION='s3://example.invalid/out/' AS SELECT 1",
            ):
                blocked = result(await tool(alice, alice_session, "execute_sql", sql=sql))
                assert blocked["status"] == "error" and "blocked" in blocked["message"]
            blocked = result(await tool(alice, alice_session, "create_stage", name=prefix + "s", url="s3://example.invalid/"))
            assert blocked["status"] == "error"
            assert len(executed) == previous
            assert result(await tool(alice, alice_session, "create_stage", name=prefix + "internal"))["status"] == "success"


@pytest.mark.asyncio
async def test_sse_uses_the_authenticated_warehouse(mapped_server, monkeypatch):
    import socket

    import uvicorn
    from fastmcp import Client
    from fastmcp.client.transports import SSETransport
    from sse_starlette.sse import AppStatus

    # sse-starlette keeps its shutdown event global across pytest event loops.
    monkeypatch.setattr(AppStatus, "should_exit_event", None)
    monkeypatch.setattr(AppStatus, "should_exit", False)

    def query(_sql, *, warehouse_dsn):
        account = "alice" if warehouse_dsn == ALICE_DSN + "?sslmode=require" else "bob"
        assert warehouse_dsn in {ALICE_DSN + "?sslmode=require", BOB_DSN + "?sslmode=require"}
        return [{"account": account}]

    monkeypatch.setattr(server, "execute_lake_query", query)
    # Use a fresh FastMCP instance because its lifespan is bound to the active loop.
    mcp = server.LakeMCP("lake-mcp-sse-test", auth=server.mcp.auth)
    mcp.add_tool(server.Tool.from_function(server.execute_sql))
    monkeypatch.setattr(server, "mcp", mcp)
    app = mcp.http_app(transport="sse")
    async with asyncio.timeout(10):
        with socket.create_server(("127.0.0.1", 0)) as listener:
            url = f"http://127.0.0.1:{listener.getsockname()[1]}/sse"
            listener_server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False))
            task = asyncio.create_task(listener_server.serve(sockets=[listener]))
            try:
                while not listener_server.started and not task.done():
                    await asyncio.sleep(0.01)
                assert listener_server.started

                async def call(subject):
                    async with Client(SSETransport(url, auth=mapped_server(subject))) as client:
                        result = await client.call_tool("execute_sql", {"sql": "SELECT 1"})
                        return result.structured_content["data"]

                assert await asyncio.gather(call("alice"), call("bob")) == [[{"account": "alice"}], [{"account": "bob"}]]
            finally:
                listener_server.should_exit = True
                await task


@pytest.mark.asyncio
async def test_subject_removal_takes_effect_without_restart(warehouse_map, mapped_server):
    verifier = server.mcp.auth
    token = mapped_server("alice")
    verified = await verifier.verify_token(token)
    assert verifier.warehouse_dsn(verified) == ALICE_DSN + "?sslmode=require"
    warehouse_map.write_text(json.dumps({"bob": BOB_DSN}))
    assert await verifier.verify_token(token) is None
    assert verifier.warehouse_dsn(verified) is None


@pytest.mark.asyncio
async def test_file_bearer_rotation(monkeypatch, tmp_path):
    path = tmp_path / "bearer"
    old = "example-old-token-not-for-production"
    new = "example-new-token-not-for-production"
    path.write_text(old)
    path.chmod(0o600)
    monkeypatch.setenv("LAKE_MCP_AUTH_TOKEN_FILE", str(path))
    verifier = build_auth()
    assert await verifier.verify_token(old) is not None
    path.write_text(new)
    assert await verifier.verify_token(old) is None
    assert await verifier.verify_token(new) is not None


def test_warehouse_map_accepts_private_credential_files(warehouse_map, tmp_path):
    credential = tmp_path / "token"
    credential.write_text("fixture credential")
    credential.chmod(0o600)
    warehouse_map.write_text(json.dumps({"alice": f"lake://warehouse.example/db?access_token_file={credential}"}))
    assert build_auth().routes_warehouse_accounts
    credential.chmod(0o644)
    with pytest.raises(ValueError, match="Invalid warehouse map"):
        build_auth()
