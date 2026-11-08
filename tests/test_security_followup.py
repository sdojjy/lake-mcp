import pytest

from lake_mcp.runtime_security import build_auth, load_config_file
from lake_mcp.safety import check_sql_safety, get_session_prefix


@pytest.mark.parametrize(
    "template",
    [
        "WITH c AS (DELETE FROM production.users RETURNING *) SELECT * FROM c",
        "DELETE FROM production.users WHERE name='CREATE OR REPLACE TABLE {p}t'",
        "UPDATE production.users SET name='REPLACE INTO {p}t'",
        "WITH cte AS (SELECT ')' UNION SELECT 1) DELETE FROM production.users",
        "INSERT INTO production.users SELECT 'grant' FROM {p}db.t",
        "ALTER TABLE {p}db.t SWAP WITH `production`.`users`",
        "ALTER TASK outside_task MODIFY AS ALTER VIEW {p}v AS SELECT 1",
        "ALTER TABLE {p}catalog.prod . users ADD COLUMN probe INT",
        "ALTER TABLE {p}t SWAP WITH {p}catalog.prod . users",
        "ALTER TABLE {p}t SWAP\nWITH production.users",
        "ALTER TASK outside_task MODIFY AS ALTER TABLE {p}db.t SET TAG {p}tag = 'x'",
        "ALTER TABLE {p}db.t SWAP WITH production.users SET TAG {p}tag = 'x'",
        "ALTER TABLE {p}db.t RENAME TO production.pwned SET TAG {p}tag = 'x'",
        "ALTER TABLE {p}db.t SET TAG {p}tag = 'x' RENAME TO production.pwned",
        'ALTER TABLE {p}db.t RENAME TO "production"."users"',
        "INSERT INTO {p}db.t SELECT * FROM `production`.`users`",
        "INSERT INTO {p}db.t SELECT * FROM {p}db.a, production.users",
        "MERGE INTO {p}db.t USING production.users ON 1=1 WHEN MATCHED THEN DELETE",
        "CREATE USER {p}u IDENTIFIED BY 'test' WITH DEFAULT_ROLE='account_admin'",
        "INSERT INTO {p}db.t SELECT * FROM (WITH users AS (SELECT 1) SELECT * FROM users) q, users",
        'CREATE TASK {p}tk AS INSERT INTO {p}db.t SELECT * FROM "production"."users"',
        "WITH users AS (SELECT * FROM users) INSERT INTO {p}db.t SELECT * FROM users",
        "INSERT INTO production.users SELECT $$CREATE OR REPLACE TABLE {p}t$$",
        "DELETE FROM production.users WHERE note = 'quoted -- CREATE OR REPLACE TABLE {p}t'",
    ],
)
def test_bypasses_are_denied(template):
    assert not check_sql_safety(template.format(p=get_session_prefix())).allowed


@pytest.mark.parametrize(
    "template",
    [
        "CREATE TABLE {p}db.t (default_role STRING)",
        "ALTER TABLE {p}db.t ADD COLUMN default_role STRING",
        "ALTER TABLE {p}db.t SET TAG {p}tag = 'SWAP WITH production.users'",
        "ALTER TABLE {p}db.t UNSET TAG {p}tag",
        "INSERT INTO {p}db.t VALUES ('grant', ')', 'CREATE OR REPLACE TABLE production.t')",
        "ALTER TABLE `{p}db`.`t` RENAME TO `t.with.dot`",
        "INSERT INTO `{p}db`.`t` SELECT * FROM `{p}db`.`a`, `{p}db`.`b`",
        "WITH c AS (SELECT ')') INSERT INTO {p}db.t SELECT * FROM c",
        "WITH c AS (SELECT 1) DELETE FROM {p}db.t WHERE a IN (SELECT * FROM c)",
        "MERGE INTO {p}db.t USING {p}db.a ON 1=1 WHEN MATCHED THEN UPDATE SET a=1",
    ],
)
def test_legitimate_sandbox_operations(template):
    assert check_sql_safety(template.format(p=get_session_prefix())).allowed


def test_dotenv_is_explicit(tmp_path, monkeypatch):
    monkeypatch.delenv("LAKE_MCP_ENV_FILE", raising=False)
    monkeypatch.delenv("LAKE_MCP_SAFE_MODE", raising=False)
    (tmp_path / ".env").write_text("LAKE_MCP_SAFE_MODE=false\n")
    monkeypatch.chdir(tmp_path)
    load_config_file()
    import os

    assert "LAKE_MCP_SAFE_MODE" not in os.environ
    monkeypatch.setenv("LAKE_MCP_ENV_FILE", str(tmp_path / ".env"))
    monkeypatch.setenv("LAKE_MCP_SAFE_MODE", "true")
    load_config_file()
    assert os.environ["LAKE_MCP_SAFE_MODE"] == "true"


def test_auth_requires_credentials(monkeypatch):
    monkeypatch.setenv("LAKE_MCP_REQUIRE_AUTH", "true")
    monkeypatch.delenv("LAKE_MCP_AUTH_TOKEN", raising=False)
    with pytest.raises(ValueError, match="requires"):
        build_auth()


def test_token_is_verified(monkeypatch):
    monkeypatch.setenv("LAKE_MCP_AUTH_TOKEN", "local-test-token")
    auth = build_auth()
    import asyncio

    assert asyncio.run(auth.verify_token("wrong")) is None
    assert asyncio.run(auth.verify_token("local-test-token")).client_id == "lake-mcp"


def test_http_authentication_reaches_transport(monkeypatch):
    import asyncio

    import httpx
    from fastmcp import FastMCP

    monkeypatch.setenv("LAKE_MCP_AUTH_TOKEN", "local-test-token")
    mcp = FastMCP("auth-regression", auth=build_auth())

    @mcp.tool
    def ping():
        return "ok"

    async def exercise():
        app = mcp.http_app(stateless_http=True)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
                for token, expected in [(None, 401), ("wrong", 401), ("local-test-token", 200)]:
                    headers = {"Accept": "application/json, text/event-stream"}
                    if token:
                        headers["Authorization"] = "Bearer " + token
                    response = await client.post(
                        "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                    )
                    assert response.status_code == expected
                    if expected == 200:
                        assert "ping" in response.text

    asyncio.run(exercise())
