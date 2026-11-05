"""Security and compatibility regressions for the FastMCP 3 upgrade."""

import asyncio
from urllib.parse import quote, unquote, urlsplit

import pytest
from fastmcp import Client
from fastmcp.utilities.openapi.director import RequestDirector
from jsonschema_path import SchemaPath

from lake_mcp import server


@pytest.mark.parametrize("value", ["alice", "../../../admin/delete-all?", "..", ".", "a/b", "//other-host/path", "a?b#c", "%2e%2e%2f"])
def test_openapi_path_parameters_remain_literal(value):
    director = RequestDirector(SchemaPath.from_dict({}))
    try:
        url = director._build_url("/api/v1/users/{id}/profile", {"id": value}, "https://backend.example/")
    except ValueError:
        # Newer FastMCP versions reject dot segments instead of encoding them.
        # Both outcomes are safe; ordinary path values must remain usable.
        decoded = unquote(value).replace("\\", "/")
        assert any(part in {".", ".."} for part in decoded.split("/"))
        return

    encoded = quote(value, safe="").replace(".", "%2E")
    assert url == f"https://backend.example/api/v1/users/{encoded}/profile"
    assert urlsplit(url).netloc == "backend.example"
    assert not urlsplit(url).query
    assert not urlsplit(url).fragment


def test_fastmcp_client_can_discover_and_call_lake_tools(monkeypatch):
    # Exercise the actual MCP protocol, not just the underlying Python functions.
    monkeypatch.setattr(server, "execute_lake_query", lambda sql: [{"answer": 42}])

    async def check():
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            assert len(tools) == 13
            assert {"execute_sql", "get_session_sandbox_prefix"} <= {tool.name for tool in tools}
            result = await client.call_tool("execute_sql", {"sql": "SELECT 42 AS answer"})
            assert not result.is_error
            assert result.data == {"status": "success", "data": [{"answer": 42}], "row_count": 1}
            prefix = await client.call_tool("get_session_sandbox_prefix", {})
            assert not prefix.is_error
            assert prefix.data["prefix"] == server.get_session_prefix()

    asyncio.run(check())


@pytest.mark.parametrize(
    ("package", "minimum"),
    [
        ("fastmcp", "3.2.0"),
        ("mcp", "1.28.1"),
        ("pyarrow", "23.0.1"),
        ("sqlparse", "0.6.0"),
        ("cryptography", "50.0.0"),
        ("urllib3", "2.8.0"),
        ("python-multipart", "0.0.30"),
        ("starlette", "1.3.1"),
    ],
)
def test_installed_and_locked_dependencies_meet_security_floors(package, minimum):
    import importlib.metadata
    import tomllib
    from pathlib import Path

    from packaging.version import Version

    assert Version(importlib.metadata.version(package)) >= Version(minimum)
    lock = tomllib.loads((Path(__file__).parents[1] / "uv.lock").read_text())
    versions = [entry["version"] for entry in lock["package"] if entry["name"] == package]
    assert versions, f"{package} missing from lockfile"
    # Check every environment marker branch, not only the current interpreter.
    assert all(Version(version) >= Version(minimum) for version in versions)
