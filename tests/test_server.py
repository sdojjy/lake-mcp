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


def test_show_tables_allows_comment_markers_inside_filter_literal(monkeypatch):
    """`--` inside a string literal is data, not a comment (compat regression B/R3)."""
    executed = _record_sql(monkeypatch)

    server.show_tables(filter="name = 'a--b'")

    assert executed == ["SHOW TABLES WHERE name = 'a--b'"]


def test_show_tables_allows_semicolon_inside_filter_literal(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.show_tables(filter="name = 'a;b'")

    assert executed == ["SHOW TABLES WHERE name = 'a;b'"]


def test_show_tables_allows_top_level_filter_comment(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.show_tables(filter="1=1 -- trailing")

    assert executed == ["SHOW TABLES WHERE 1=1 -- trailing"]


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


def test_create_stage_escapes_connection_name_literal(monkeypatch):
    """CONNECTION_NAME is a string literal, not an identifier (compat regression B4)."""
    executed = _record_sql(monkeypatch)

    server.create_stage(
        name="mystage",
        url="s3://bucket",
        connection_name="c') ; DROP DATABASE production --",
    )

    assert executed == [
        "CREATE STAGE mystage URL = 's3://bucket' CONNECTION = (CONNECTION_NAME = 'c'') ; DROP DATABASE production --')",
    ]


def test_create_stage_accepts_shell_style_connection_name(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.create_stage(name="mystage", url="s3://bucket", connection_name="my-conn")

    assert executed == [
        "CREATE STAGE mystage URL = 's3://bucket' CONNECTION = (CONNECTION_NAME = 'my-conn')",
    ]


def test_create_stage_accepts_dotted_connection_name(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.create_stage(name="mystage", url="s3://bucket", connection_name="conn.prod")

    assert executed == [
        "CREATE STAGE mystage URL = 's3://bucket' CONNECTION = (CONNECTION_NAME = 'conn.prod')",
    ]


def test_show_tables_accepts_backtick_identifier(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.show_tables(database="`my-db`")

    assert executed == ["SHOW TABLES FROM `my-db`"]


def test_show_tables_accepts_double_quoted_identifier(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.show_tables(database='"my-db"')

    assert executed == ["SHOW TABLES FROM `my-db`"]


def test_show_tables_accepts_dollar_identifier(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.show_tables(database="analytics$prod")

    assert executed == ["SHOW TABLES FROM analytics$prod"]


def test_describe_table_accepts_quoted_names(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.describe_table(table="`my-table`")
    server.describe_table(table="users", database="`analytics`")

    assert executed == [
        "DESCRIBE TABLE `my-table`",
        "DESCRIBE TABLE `analytics`.users",
    ]


def test_describe_table_accepts_dollar_database(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.describe_table(table="orders", database="analytics$prod")

    assert executed == ["DESCRIBE TABLE analytics$prod.orders"]


def test_list_stage_files_accepts_user_stage(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.list_stage_files(stage_name="@~")

    assert executed == ["LIST @~"]


def test_list_stage_files_accepts_table_stage(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.list_stage_files(stage_name="@%t")

    assert executed == ["LIST @%t"]


def test_list_stage_files_accepts_dollar_stage(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.list_stage_files(stage_name="s$1")

    assert executed == ["LIST @s$1"]


def test_list_stage_files_accepts_non_ascii_and_space_in_path(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.list_stage_files(stage_name="@~", path="dir/数据.csv")
    server.list_stage_files(stage_name="mystage", path="dir/a b.csv")

    assert executed == [
        "LIST @~/dir/数据.csv",
        "LIST @mystage/dir/a b.csv",
    ]


def test_create_stage_accepts_dollar_name(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.create_stage(name="stage$1", url="s3://bucket")

    assert executed == ["CREATE STAGE stage$1 URL = 's3://bucket'"]


def test_create_stage_unquotes_simple_quoted_name(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.create_stage(name="`mystage`", url="s3://bucket")

    assert executed == ["CREATE STAGE mystage URL = 's3://bucket'"]


def test_identifier_arguments_still_reject_statement_smuggling(monkeypatch):
    """The relaxed identifier handling must not re-open injection."""
    executed = _record_sql(monkeypatch)

    for kwargs in (
        {"database": "`my-db`; DROP DATABASE production"},
        {"database": "`my-db`\nDROP DATABASE production"},
        {"database": "`my-db` -- x"},
        {"database": "`my-db``; DROP DATABASE production`"},
    ):
        result = server.show_tables(**kwargs)
        assert result["status"] == "error"

    for table in (
        "`my-table`; DROP DATABASE production",
        "x; CREATE USER evil IDENTIFIED BY 'p'",
        "`my-table`\nDROP DATABASE production",
    ):
        result = server.describe_table(table=table)
        assert result["status"] == "error"

    assert executed == []


def test_stage_arguments_still_reject_statement_smuggling(monkeypatch):
    executed = _record_sql(monkeypatch)

    for stage_name in (
        "@~; DROP DATABASE production",
        "@%t; DROP DATABASE production",
        "@mystage`; DROP DATABASE production",
    ):
        result = server.list_stage_files(stage_name=stage_name)
        assert result["status"] == "error"

    for path in (
        "data/x'; DROP DATABASE production --",
        'data/x"; DROP DATABASE production --',
        "data/x`; DROP DATABASE production",
        "data/x\nDROP DATABASE production",
    ):
        result = server.list_stage_files(stage_name="mystage", path=path)
        assert result["status"] == "error"

    assert executed == []


def test_create_stage_still_rejects_smuggled_name(monkeypatch):
    executed = _record_sql(monkeypatch)

    for name in ("s; DROP DATABASE production", "s`; DROP DATABASE production", "s\nDROP"):
        result = server.create_stage(name=name, url="s3://bucket")
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


def test_show_tables_accepts_quoted_non_ascii_identifier(monkeypatch):
    executed = _record_sql(monkeypatch)

    server.show_tables(database="`订单`")
    server.show_tables(database="`my db`")

    assert executed == ["SHOW TABLES FROM `订单`", "SHOW TABLES FROM `my db`"]


def test_quoted_identifier_cannot_escape_with_backslash_or_backtick(monkeypatch):
    """Databend quoted identifiers have no backtick/backslash escape."""
    executed = _record_sql(monkeypatch)

    for database in ("`a\\`", "`a`b`", "`a``b`"):
        result = server.show_tables(database=database)
        assert result["status"] == "error"

    assert executed == []
