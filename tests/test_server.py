"""Tests for server safe mode behavior."""

from dataclasses import dataclass

from lake_mcp import server
from lake_mcp.safety import get_session_prefix


@dataclass
class FakeConfig:
    safe_mode: bool
    query_timeout: int = 1


def test_execute_sql_blocks_non_sandbox_write_in_safe_mode(monkeypatch):
    monkeypatch.setattr(server, "get_config", lambda: FakeConfig(safe_mode=True))
    monkeypatch.setattr(server, "execute_lake_query", lambda sql: [])

    result = server._execute_sql("DROP DATABASE production")

    assert result["status"] == "error"
    assert "must start with" in result["message"]


def test_execute_sql_skips_sandbox_validation_when_safe_mode_disabled(monkeypatch):
    executed_sql = []

    monkeypatch.setattr(server, "get_config", lambda: FakeConfig(safe_mode=False))
    monkeypatch.setattr(
        server,
        "execute_lake_query",
        lambda sql: executed_sql.append(sql) or [],
    )

    result = server._execute_sql("DROP DATABASE production")

    assert result == {"status": "success", "data": [], "row_count": 0}
    assert executed_sql == ["DROP DATABASE production"]


def _record_sql(monkeypatch):
    executed = []
    monkeypatch.setattr(
        server,
        "_execute_sql",
        lambda sql: executed.append(sql) or {"status": "success", "data": []},
    )
    return executed


def test_show_tables_rejects_injected_database(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.show_tables(database="mydb; DROP DATABASE production")

    assert result["status"] == "error"
    assert executed == []


def test_show_tables_rejects_injected_filter(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.show_tables(filter="1=1; DROP DATABASE production")

    assert result["status"] == "error"
    assert executed == []


def test_show_tables_rejects_comment_in_filter(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.show_tables(filter="1=1 --")

    assert result["status"] == "error"
    assert executed == []


def test_show_tables_builds_expected_statement(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.show_tables(database="analytics", filter="name like 'test%'")

    assert executed == ["SHOW TABLES FROM analytics WHERE name like 'test%'"]


def test_show_functions_rejects_injected_filter(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.show_functions(filter="1=1; DROP DATABASE production")

    assert result["status"] == "error"
    assert executed == []


def test_describe_table_rejects_injected_table(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.describe_table(table="x; CREATE USER evil IDENTIFIED BY 'p'")

    assert result["status"] == "error"
    assert executed == []


def test_describe_table_rejects_injected_database(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.describe_table(table="users", database="analytics; DROP DATABASE production")

    assert result["status"] == "error"
    assert executed == []


def test_describe_table_builds_expected_statement(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.describe_table(table="users", database="analytics")

    assert executed == ["DESCRIBE TABLE analytics.users"]


def test_list_stage_files_rejects_injected_stage(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.list_stage_files(stage_name="@mystage; DROP DATABASE production")

    assert result["status"] == "error"
    assert executed == []


def test_list_stage_files_rejects_injected_path(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.list_stage_files(stage_name="mystage", path="data/x'; DROP DATABASE production --")

    assert result["status"] == "error"
    assert executed == []


def test_list_stage_files_builds_expected_statement(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.list_stage_files(stage_name="mystage", path="/data/csv/")

    assert executed == ["LIST @mystage/data/csv"]


def test_create_stage_escapes_url_literal(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.create_stage(name="mystage", url="s3://bucket/x'; DROP DATABASE production; --")

    assert executed == [
        "CREATE STAGE mystage URL = 's3://bucket/x''; DROP DATABASE production; --'",
    ]


def test_create_stage_rejects_injected_name(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.create_stage(name="s; DROP DATABASE production", url="s3://bucket")

    assert result["status"] == "error"
    assert executed == []


def test_create_stage_rejects_injected_connection_name(monkeypatch):
    executed = _record_sql(monkeypatch)

    result = server.create_stage(
        name="mystage",
        url="s3://bucket",
        connection_name="c') ; DROP DATABASE production --",
    )

    assert result["status"] == "error"
    assert executed == []


def test_escaped_stage_url_keeps_statement_single(monkeypatch):
    monkeypatch.setattr(server, "get_config", lambda: FakeConfig(safe_mode=True))
    executed = []
    monkeypatch.setattr(
        server,
        "execute_lake_query",
        lambda sql: executed.append(sql) or [],
    )

    prefix = get_session_prefix()
    result = server.create_stage(name=f"{prefix}stage", url="s3://bucket'; DROP DATABASE production --")

    # The quote can no longer close the URL literal, so the injected DDL never
    # becomes its own statement and the sandbox-prefixed CREATE STAGE is allowed.
    assert result["status"] == "success"
    assert executed == [
        f"CREATE STAGE {prefix}stage URL = 's3://bucket''; DROP DATABASE production --'",
    ]
