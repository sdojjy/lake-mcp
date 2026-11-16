"""Storage ownership must not be inferred from a sandbox object's name."""

from types import SimpleNamespace

import pytest

from lake_mcp import server
from lake_mcp.safety import check_network_sql, check_sql_safety, get_session_prefix


@pytest.mark.parametrize(
    "statement",
    [
        "CREATE STAGE {p}s URL='s3://example.invalid/production/' CONNECTION=(CONNECTION_NAME='prod_conn')",
        "CREATE STAGE {p}s 's3://example.invalid/production/'",
        "CREATE OR REPLACE STAGE {p}s URL='s3://example.invalid/production/'",
        "CREATE /* comment */ STAGE IF NOT EXISTS `{p}s` URL = $$s3://example.invalid/private/$$",
        "ALTER STAGE {p}s SET URL='s3://example.invalid/production/'",
        "CREATE CONNECTION {p}c STORAGE_TYPE='s3' ENDPOINT_URL='https://example.invalid/'",
        "CREATE CATALOG {p}c TYPE=HIVE CONNECTION=(URL='https://example.invalid/')",
        "CREATE DATABASE {p}db OPTIONS (DEFAULT_STORAGE_CONNECTION='prod_conn', DEFAULT_STORAGE_PATH='s3://example.invalid/out/')",
        "ALTER DATABASE {p}db SET OPTIONS (DEFAULT_STORAGE_CONNECTION='prod_conn', DEFAULT_STORAGE_PATH='s3://example.invalid/out/')",
        "ALTER DATABASE {p}db SET OPTIONS (DEFAULT_STORAGE_PATH='s3://example.invalid/out/')",
        "CREATE TABLE {p}t EXTERNAL_LOCATION='s3://example.invalid/out/' AS SELECT * FROM production.users",
        "CREATE OR REPLACE TABLE {p}t (id INT) EXTERNAL_LOCATION='s3://example.invalid/out/' AS SELECT 1",
        "CREATE TABLE {p}t ENGINE=ICEBERG LOCATION='s3://example.invalid/out/' AS SELECT 1",
        "CREATE TABLE {p}t ENGINE=ICEBERG AS SELECT 1",
        "CREATE TABLE {p}t ENGINE=FUSE 's3://example.invalid/out/' AS SELECT 1",
        "CREATE TABLE {p}t (id INT) 'fs:///tmp/out/'",
        "CREATE TABLE {p}t (id INT) `external_location`='s3://example.invalid/out/'",
        'CREATE TABLE {p}t (id INT) "LOCATION" = $$s3://example.invalid/out/$$',
        "CREATE TABLE {p}t (id INT) CONNECTION=(CONNECTION_NAME='prod_conn')",
        "ALTER TABLE {p}t CONNECTION=(CONNECTION_NAME='prod_conn')",
        "ALTER TABLE {p}t SET OPTIONS (external_location='s3://example.invalid/out/')",
        "ALTER TABLE {p}t SET OPTIONS (`storage_prefix`='production/')",
        "CREATE TABLE {p}t (id INT) snapshot_loc='production/snapshot'",
        "CREATE TABLE {p}t (id INT) table_data_uri='s3://example.invalid/production/'",
        "CREATE TASK {p}task AS CREATE STAGE {p}s 's3://example.invalid/production/'",
        "CREATE PIPE {p}pipe AS CREATE TABLE {p}t EXTERNAL_LOCATION='s3://example.invalid/out/' AS SELECT 1",
        "WITH c AS (SELECT 1) CREATE TABLE {p}t EXTERNAL_LOCATION='s3://example.invalid/out/' AS SELECT * FROM c",
        "REMOVE @{p}s",
        "REMOVE @{p}s/production/ PATTERN='.*'",
        'REMOVE @"{p}s"',
        "REMOVE @~/production/",
        "REMOVE @%{p}t",
        "CREATE TASK {p}task AS REMOVE @{p}s",
    ],
)
def test_storage_escape_blocked_in_both_policy_entry_points(statement):
    sql = statement.format(p=get_session_prefix())
    assert not check_sql_safety(sql).allowed
    assert not check_network_sql(sql, allow_write=True).allowed


@pytest.mark.parametrize(
    "statement",
    [
        "CREATE DATABASE {p}db",
        "CREATE DATABASE {p}db ENGINE=DEFAULT",
        "CREATE STAGE {p}s",
        "CREATE STAGE {p}s FILE_FORMAT=(TYPE=CSV FIELD_DELIMITER=',') COMMENT='URL= s3://example.invalid/'",
        "CREATE OR REPLACE STAGE {p}s COMMENTS=$$EXTERNAL_LOCATION='s3://example.invalid/'$$",
        "DROP STAGE {p}s",
        "CREATE TABLE {p}db.t (id INT, location STRING, connection STRING)",
        "CREATE TABLE {p}t (url STRING DEFAULT 's3://example.invalid/data') ENGINE=FUSE",
        "CREATE TABLE {p}t (id INT) ENGINE=MEMORY COMMENT='LOCATION=s3://example.invalid/'",
        "CREATE TABLE {p}t (id INT) ENGINE=FUSE STORAGE_FORMAT='parquet'",
        "CREATE TABLE {p}t ENGINE=NULL AS SELECT 1",
        "CREATE TABLE {p}t AS SELECT 'EXTERNAL_LOCATION=s3://example.invalid/' AS location",
        "CREATE TABLE {p}t AS SELECT * FROM {p}source",
        "CREATE TABLE {p}t AS SELECT * FROM production.users",
        "CREATE VIEW {p}v AS SELECT * FROM production.users",
        "INSERT INTO {p}t VALUES ('s3://example.invalid/', 'CONNECTION')",
        "ALTER TABLE {p}t ADD COLUMN location STRING DEFAULT 's3://example.invalid/'",
        "SELECT * FROM production.users",
        "SHOW CONNECTIONS",
        "LIST @production_stage",
    ],
)
def test_managed_sandbox_and_read_operations_remain_available(statement):
    sql = statement.format(p=get_session_prefix())
    assert check_sql_safety(sql).allowed
    assert check_network_sql(sql, allow_write=True).allowed


def _record_driver(monkeypatch, *, safe_mode=True):
    executed = []
    monkeypatch.setattr(server, "get_config", lambda: SimpleNamespace(safe_mode=safe_mode, query_timeout=1))
    monkeypatch.setattr(server, "execute_lake_query", lambda sql: executed.append(sql) or [])
    return executed


def test_stage_tool_and_raw_sql_rejected_before_driver(monkeypatch):
    executed = _record_driver(monkeypatch)
    p = get_session_prefix()
    assert server.create_stage(f"{p}s", "s3://example.invalid/production/", "prod_conn")["status"] == "error"
    for sql in [
        f"CREATE STAGE {p}s 's3://example.invalid/production/'",
        f"REMOVE @{p}s",
        f"CREATE TABLE {p}t EXTERNAL_LOCATION='s3://example.invalid/out/' AS SELECT * FROM production.users",
    ]:
        assert server.execute_sql(sql)["status"] == "error"
    assert executed == []


def test_internal_stage_tool_executes(monkeypatch):
    executed = _record_driver(monkeypatch)
    name = f"{get_session_prefix()}s"
    assert server.create_stage(name)["status"] == "success"
    assert executed == [f"CREATE STAGE {name}"]


def test_local_admin_explicit_opt_out_retains_external_storage_operations(monkeypatch):
    executed = _record_driver(monkeypatch, safe_mode=False)
    monkeypatch.setenv("LAKE_MCP_ALLOW_STDIO_ADMIN", "1")
    assert server.create_stage("admin_stage", "s3://example.invalid/test/")["status"] == "success"
    assert server.execute_sql("REMOVE @admin_stage")["status"] == "success"
    assert len(executed) == 2
