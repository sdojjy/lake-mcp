from types import SimpleNamespace

import pytest

from lake_mcp.runtime_security import build_auth, network_run_options
from lake_mcp.safety import SESSION_ID, check_sql_safety, get_session_prefix


@pytest.mark.parametrize("kind,options", [("TASK", "WAREHOUSE='wh' SCHEDULE=1 MINUTE"), ("PIPE", ""), ("DYNAMIC TABLE", "")])
def test_decoy_literal_cannot_hide_deferred_sql(kind, options):
    for decoy in ["COMMENT='as of now'", 'COMMENT="as quoted"', "COMMENT=$$as quoted$$"]:
        sql = f"CREATE {kind} {get_session_prefix()}t {options} {decoy} AS DROP TABLE production.users"
        assert not check_sql_safety(sql).allowed


def test_required_body_and_session_entropy():
    assert not check_sql_safety(f"CREATE TASK {get_session_prefix()}t").allowed
    assert len(SESSION_ID) == 32


def test_network_requires_actual_mounted_auth(monkeypatch):
    config = SimpleNamespace(mcp_bind_host="0.0.0.0")
    monkeypatch.delenv("LAKE_MCP_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(ValueError, match="requires"):
        network_run_options(config, None)
    monkeypatch.setenv("LAKE_MCP_AUTH_TOKEN", "test-network-token")
    auth = build_auth()
    assert network_run_options(config, auth)["host"] == "0.0.0.0"
    monkeypatch.setenv("LAKE_MCP_ALLOWED_HOSTS", "*")
    with pytest.raises(ValueError, match="explicit hosts"):
        network_run_options(config, auth)


@pytest.mark.parametrize("host", ["", "0.0.0.0", "::", "192.0.2.1", "local.example", " 127.0.0.1 "])
def test_anonymous_network_rejects_non_loopback_hosts(monkeypatch, host):
    monkeypatch.setenv("LAKE_MCP_ALLOW_INSECURE_HTTP", "true")
    with pytest.raises(ValueError, match="loopback"):
        network_run_options(SimpleNamespace(mcp_bind_host=host), None)


@pytest.mark.parametrize(("host", "expected"), [("localhost", "127.0.0.1"), ("127.0.0.1", "127.0.0.1"), ("::1", "::1")])
def test_anonymous_network_binds_to_loopback(monkeypatch, host, expected):
    monkeypatch.setenv("LAKE_MCP_ALLOW_INSECURE_HTTP", "true")
    assert network_run_options(SimpleNamespace(mcp_bind_host=host), None)["host"] == expected


@pytest.mark.parametrize(
    "statement",
    [
        "GRANT prod_admin TO {p}user",
        "GRANT ROLE {p}role, prod_admin TO {p}user",
        "REVOKE ROLE {p}role, prod_admin FROM {p}user",
        "GRANT ALL ON {p}db.* TO {p}user, prod_admin, root",
        "REVOKE SELECT ON {p}db.* FROM {p}user, root",
        "GRANT ROLE {p}role TO USER '{p}user'@'%', root",
        "GRANT ROLE {p}role TO ROLE prod_admin",
    ],
)
def test_grant_revoke_blocks_unchecked_names(statement):
    assert not check_sql_safety(statement.format(p=get_session_prefix())).allowed


@pytest.mark.parametrize(
    "statement",
    [
        "GRANT ROLE '{p}role' TO USER '{p}user'@'%'",
        "REVOKE ROLE '{p}role' FROM USER '{p}user'@'%'",
        'GRANT SELECT, INSERT ON "{p}db".* TO ROLE "{p}role"',
        "REVOKE SELECT ON {p}db.* FROM ROLE '{p}role'",
    ],
)
def test_grant_revoke_allows_sandbox_names(statement):
    assert check_sql_safety(statement.format(p=get_session_prefix())).allowed
