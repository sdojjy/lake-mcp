from types import SimpleNamespace
import pytest
from lake_mcp.safety import check_sql_safety, get_session_prefix, SESSION_ID
from lake_mcp.runtime_security import build_auth, network_run_options


@pytest.mark.parametrize("kind,options", [("TASK", "WAREHOUSE='wh' SCHEDULE=1 MINUTE"), ("PIPE", ""), ("DYNAMIC TABLE", "")])
def test_decoy_literal_cannot_hide_deferred_sql(kind, options):
    for decoy in ["COMMENT='as of now'", 'COMMENT="as quoted"', "COMMENT=$$as quoted$$"]:
        sql = f"CREATE {kind} {get_session_prefix()}t {options} {decoy} AS DROP TABLE production.users"
        assert not check_sql_safety(sql).allowed


def test_required_body_and_session_entropy():
    assert not check_sql_safety(f"CREATE TASK {get_session_prefix()}t").allowed
    assert len(SESSION_ID) == 32


def test_network_requires_actual_mounted_auth(monkeypatch):
    monkeypatch.delenv("LAKE_MCP_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(ValueError, match="requires"):
        network_run_options(SimpleNamespace(), None)
    monkeypatch.setenv("LAKE_MCP_AUTH_TOKEN", "test-network-token")
    auth = build_auth()
    assert network_run_options(SimpleNamespace(), auth)["middleware"]
    monkeypatch.setenv("LAKE_MCP_ALLOW_INSECURE_HTTP", "true")
    assert network_run_options(SimpleNamespace(), None)
    monkeypatch.setenv("LAKE_MCP_ALLOWED_HOSTS", "*")
    with pytest.raises(ValueError, match="explicit hosts"):
        network_run_options(SimpleNamespace(), auth)
