"""Tests for SQL safety module."""

import pytest

from lake_mcp.safety import (
    SANDBOX_PREFIX,
    SESSION_ID,
    SafetyResult,
    check_sql_safety,
    get_session_prefix,
)


class TestReadOnlyQueries:
    """Read-only queries should always be allowed."""

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM production.users",
            "SHOW DATABASES",
            "SHOW TABLES FROM mydb",
            "DESCRIBE TABLE mydb.users",
            "DESC mydb.orders",
            "EXPLAIN SELECT * FROM t",
            "LIST @mystage",
            "WITH cte AS (SELECT 1) SELECT * FROM cte",
            "SELECT * FROM mcp_sandbox_other_session.table1",  # Can read other sessions
        ],
    )
    def test_read_queries_allowed(self, sql):
        result = check_sql_safety(sql)
        assert result.allowed is True


class TestCurrentSessionSandbox:
    """Write operations on current session sandbox should be allowed."""

    def test_create_database(self):
        sql = f"CREATE DATABASE {get_session_prefix()}mydb"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_create_table(self):
        sql = f"CREATE TABLE {get_session_prefix()}mydb.users (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_insert(self):
        sql = f"INSERT INTO {get_session_prefix()}mydb.users VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_update(self):
        sql = f"UPDATE {get_session_prefix()}mydb.users SET name = 'x'"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_delete(self):
        sql = f"DELETE FROM {get_session_prefix()}mydb.users WHERE id = 1"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_drop_table(self):
        sql = f"DROP TABLE {get_session_prefix()}mydb.users"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_drop_database(self):
        sql = f"DROP DATABASE {get_session_prefix()}mydb"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_truncate(self):
        sql = f"TRUNCATE TABLE {get_session_prefix()}mydb.users"
        result = check_sql_safety(sql)
        assert result.allowed is True


class TestBlockedOperations:
    """Operations that should be blocked."""

    def test_create_or_replace_sandbox_allowed(self):
        sql = f"CREATE OR REPLACE TABLE {get_session_prefix()}mydb.t (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_create_or_replace_view_sandbox_allowed(self):
        sql = f"CREATE OR REPLACE VIEW {get_session_prefix()}mydb.v AS SELECT 1"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_create_or_replace_additional_objects_allowed(self):
        prefix = get_session_prefix()
        sqls = [
            f"CREATE OR REPLACE SEQUENCE {prefix}seq",
            f"CREATE OR REPLACE PROCEDURE {prefix}proc AS $$ SELECT 1 $$",
            f"CREATE OR REPLACE DICTIONARY {prefix}db.dict (id INT) SOURCE(mysql)",
            f"CREATE OR REPLACE FILE FORMAT {prefix}ff TYPE = CSV",
            f"CREATE OR REPLACE NETWORK POLICY {prefix}np ALLOWED_IP_LIST = ('1.1.1.1')",
            f"CREATE OR REPLACE PASSWORD POLICY {prefix}pp PASSWORD_MIN_LENGTH = 8",
            f"CREATE OR REPLACE DYNAMIC TABLE {prefix}db.dt AS SELECT 1",
        ]
        for sql in sqls:
            result = check_sql_safety(sql)
            assert result.allowed is True

    def test_create_or_replace_additional_objects_blocked(self):
        sqls = [
            "CREATE OR REPLACE SEQUENCE seq",
            "CREATE OR REPLACE PROCEDURE proc AS $$ SELECT 1 $$",
            "CREATE OR REPLACE DICTIONARY prod_db.dict (id INT) SOURCE(mysql)",
            "CREATE OR REPLACE FILE FORMAT ff TYPE = CSV",
            "CREATE OR REPLACE NETWORK POLICY np ALLOWED_IP_LIST = ('1.1.1.1')",
            "CREATE OR REPLACE PASSWORD POLICY pp PASSWORD_MIN_LENGTH = 8",
            "CREATE OR REPLACE DYNAMIC TABLE prod_db.dt AS SELECT 1",
        ]
        for sql in sqls:
            result = check_sql_safety(sql)
            assert result.allowed is False

    def test_create_or_replace_non_sandbox_blocked(self):
        sql = "CREATE OR REPLACE TABLE production.users (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "CREATE OR REPLACE" in result.reason

    def test_replace_into_sandbox_allowed(self):
        sql = f"REPLACE INTO {get_session_prefix()}mydb.users VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_replace_into_non_sandbox_blocked(self):
        sql = "REPLACE INTO production.users VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "REPLACE INTO" in result.reason

    def test_non_sandbox_create_table_blocked(self):
        sql = "CREATE TABLE production.test (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "production" in result.reason.lower()

    def test_non_sandbox_insert_blocked(self):
        sql = "INSERT INTO mydb.users VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_non_sandbox_drop_blocked(self):
        sql = "DROP DATABASE important_db"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_non_sandbox_update_blocked(self):
        sql = "UPDATE production.users SET admin = true"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_non_sandbox_delete_blocked(self):
        sql = "DELETE FROM production.logs"
        result = check_sql_safety(sql)
        assert result.allowed is False


class TestSessionIsolation:
    """Session isolation tests."""

    def test_session_prefix_format(self):
        prefix = get_session_prefix()
        assert prefix.startswith(SANDBOX_PREFIX)
        assert prefix.endswith("_")
        assert SESSION_ID in prefix

    def test_different_session_write_blocked(self):
        other_session_prefix = f"{SANDBOX_PREFIX}xyz12345_"
        sql = f"INSERT INTO {other_session_prefix}db.table VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_drop_other_session_sandbox_blocked(self):
        other_session_prefix = f"{SANDBOX_PREFIX}other123_"
        sql = f"DROP DATABASE {other_session_prefix}mydb"
        result = check_sql_safety(sql)
        assert result.allowed is False


class TestNestedSQL:
    """Nested SQL and referenced object checks."""

    def test_task_with_sandbox_sql_allowed(self):
        """TASK with nested SQL writing to sandbox should be allowed."""
        sql = f"CREATE TASK {get_session_prefix()}t AS INSERT INTO {get_session_prefix()}db.t VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_task_with_non_sandbox_sql_blocked(self):
        """TASK with nested SQL writing to non-sandbox should be blocked."""
        sql = f"CREATE TASK {get_session_prefix()}t AS INSERT INTO production.users VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "Referenced object" in result.reason

    def test_pipe_with_non_sandbox_blocked(self):
        """PIPE with COPY INTO non-sandbox should be blocked."""
        sql = f"CREATE PIPE {get_session_prefix()}p AS COPY INTO production.t FROM @stage"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_pipe_with_sandbox_allowed(self):
        """PIPE with COPY INTO sandbox should be allowed."""
        sql = f"CREATE PIPE {get_session_prefix()}p AS COPY INTO {get_session_prefix()}db.t FROM @stage"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_stream_on_sandbox_table_allowed(self):
        """STREAM on sandbox table should be allowed."""
        sql = f"CREATE STREAM {get_session_prefix()}s ON TABLE {get_session_prefix()}db.orders"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_stream_on_non_sandbox_table_blocked(self):
        """STREAM on non-sandbox table should be blocked."""
        sql = f"CREATE STREAM {get_session_prefix()}s ON TABLE production.orders"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "Referenced object" in result.reason

    def test_view_can_reference_any_table(self):
        """VIEW can reference any table (read-only)."""
        # VIEW itself must be in sandbox, but SELECT FROM can read anything
        sql = f"CREATE VIEW {get_session_prefix()}v AS SELECT * FROM production.users"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_dynamic_table_with_sandbox_query_allowed(self):
        prefix = get_session_prefix()
        sql = f"CREATE DYNAMIC TABLE {prefix}db.dt AS SELECT * FROM {prefix}db.t"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_dynamic_table_with_non_sandbox_query_blocked(self):
        prefix = get_session_prefix()
        sql = f"CREATE DYNAMIC TABLE {prefix}db.dt AS SELECT * FROM production.t"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "Referenced object" in result.reason

    def test_index_with_sandbox_query_allowed(self):
        prefix = get_session_prefix()
        sql = f"CREATE AGGREGATING INDEX {prefix}idx AS SELECT * FROM {prefix}db.t"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_index_with_non_sandbox_query_blocked(self):
        prefix = get_session_prefix()
        sql = f"CREATE AGGREGATING INDEX {prefix}idx AS SELECT * FROM production.t"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "Referenced object" in result.reason


class TestGrantRevoke:
    """GRANT/REVOKE privilege operation tests."""

    def test_grant_on_non_sandbox_db_blocked(self):
        """GRANT ON non-sandbox database should be blocked."""
        sql = "GRANT SELECT ON DATABASE production TO user1"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_grant_on_sandbox_db_to_non_sandbox_user_blocked(self):
        """GRANT sandbox db TO non-sandbox user should be blocked."""
        sql = f"GRANT SELECT ON DATABASE {get_session_prefix()}db TO root"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_grant_role_non_sandbox_blocked(self):
        """GRANT non-sandbox ROLE should be blocked."""
        sql = "GRANT ROLE admin TO user1"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_grant_on_sandbox_warehouse_allowed(self):
        """GRANT on sandbox warehouse should be allowed."""
        prefix = get_session_prefix()
        sql = f"GRANT USAGE ON WAREHOUSE {prefix}wh TO {prefix}user"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_grant_on_non_sandbox_warehouse_blocked(self):
        """GRANT on non-sandbox warehouse should be blocked."""
        sql = "GRANT USAGE ON WAREHOUSE prod_wh TO user1"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_grant_on_additional_sandbox_objects_allowed(self):
        """GRANT on additional sandbox objects should be allowed."""
        prefix = get_session_prefix()
        sqls = [
            f"GRANT USAGE ON STAGE {prefix}stage TO {prefix}user",
            f"GRANT USAGE ON UDF {prefix}udf TO {prefix}user",
            f"GRANT USAGE ON CONNECTION {prefix}conn TO {prefix}user",
            f"GRANT USAGE ON SEQUENCE {prefix}seq TO {prefix}user",
            f"GRANT USAGE ON PROCEDURE {prefix}proc TO {prefix}user",
            f"GRANT USAGE ON MASKING POLICY {prefix}mask TO {prefix}user",
            f"GRANT USAGE ON ROW ACCESS POLICY {prefix}rap TO {prefix}user",
        ]
        for sql in sqls:
            result = check_sql_safety(sql)
            assert result.allowed is True

    def test_grant_on_additional_non_sandbox_objects_blocked(self):
        """GRANT on additional non-sandbox objects should be blocked."""
        sqls = [
            "GRANT USAGE ON STAGE stage TO user1",
            "GRANT USAGE ON UDF udf TO user1",
            "GRANT USAGE ON CONNECTION conn TO user1",
            "GRANT USAGE ON SEQUENCE seq TO user1",
            "GRANT USAGE ON PROCEDURE proc TO user1",
            "GRANT USAGE ON MASKING POLICY mask TO user1",
            "GRANT USAGE ON ROW ACCESS POLICY rap TO user1",
        ]
        for sql in sqls:
            result = check_sql_safety(sql)
            assert result.allowed is False

    def test_grant_all_sandbox_allowed(self):
        """GRANT with all sandbox objects should be allowed."""
        prefix = get_session_prefix()
        sql = f"GRANT SELECT ON DATABASE {prefix}db TO {prefix}user"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_revoke_from_non_sandbox_blocked(self):
        """REVOKE FROM non-sandbox user should be blocked."""
        sql = f"REVOKE SELECT ON DATABASE {get_session_prefix()}db FROM admin"
        result = check_sql_safety(sql)
        assert result.allowed is False


class TestAllLakeObjects:
    """Test various TiDB Cloud Lake object types."""

    def test_create_stage_in_sandbox(self):
        sql = f"CREATE STAGE {get_session_prefix()}mystage"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_create_stage_outside_sandbox_blocked(self):
        sql = "CREATE STAGE production_stage"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_create_warehouse_in_sandbox(self):
        sql = f"CREATE WAREHOUSE {get_session_prefix()}wh"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_create_warehouse_outside_sandbox_blocked(self):
        sql = "CREATE WAREHOUSE prod_wh"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_alter_warehouse_in_sandbox(self):
        sql = f"ALTER WAREHOUSE {get_session_prefix()}wh SUSPEND"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_alter_warehouse_outside_sandbox_blocked(self):
        sql = "ALTER WAREHOUSE prod_wh RESUME"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_drop_warehouse_in_sandbox(self):
        sql = f"DROP WAREHOUSE {get_session_prefix()}wh"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_drop_warehouse_outside_sandbox_blocked(self):
        sql = "DROP WAREHOUSE prod_wh"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_create_function_in_sandbox(self):
        sql = f"CREATE FUNCTION {get_session_prefix()}myfunc AS (x) -> x + 1"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_create_user_in_sandbox(self):
        sql = f"CREATE USER {get_session_prefix()}testuser IDENTIFIED BY 'pass'"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_create_user_outside_sandbox_blocked(self):
        sql = "CREATE USER admin IDENTIFIED BY 'pass'"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_alter_table_in_sandbox(self):
        sql = f"ALTER TABLE {get_session_prefix()}db.t ADD COLUMN c INT"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_alter_table_outside_sandbox_blocked(self):
        sql = "ALTER TABLE production.users ADD COLUMN c INT"
        result = check_sql_safety(sql)
        assert result.allowed is False


class TestAdditionalObjects:
    """Additional TiDB Cloud Lake object types."""

    def test_additional_objects_in_sandbox_allowed(self):
        prefix = get_session_prefix()
        sqls = [
            f"CREATE SEQUENCE {prefix}seq",
            f"DROP SEQUENCE {prefix}seq",
            f"CREATE PROCEDURE {prefix}proc AS $$ SELECT 1 $$",
            f"DROP PROCEDURE {prefix}proc",
            f"CREATE DICTIONARY {prefix}db.dict (id INT) SOURCE(mysql)",
            f"DROP DICTIONARY {prefix}db.dict",
            f"CREATE DYNAMIC TABLE {prefix}db.dt AS SELECT 1",
            f"CREATE FILE FORMAT {prefix}ff TYPE = CSV",
            f"DROP FILE FORMAT {prefix}ff",
            f"CREATE NETWORK POLICY {prefix}np ALLOWED_IP_LIST = ('1.1.1.1')",
            f"DROP NETWORK POLICY {prefix}np",
            f"CREATE PASSWORD POLICY {prefix}pp PASSWORD_MIN_LENGTH = 8",
            f"DROP PASSWORD POLICY {prefix}pp",
            f"CREATE MASKING POLICY {prefix}mask AS (val STRING) RETURNS STRING -> val",
            f"DROP MASKING POLICY {prefix}mask",
            f"CREATE ROW ACCESS POLICY {prefix}rap AS (val INT) RETURNS BOOLEAN -> true",
            f"DROP ROW ACCESS POLICY {prefix}rap",
            f"CREATE TAG {prefix}tag",
            f"DROP TAG {prefix}tag",
            f"CREATE NOTIFICATION INTEGRATION {prefix}ni TYPE = WEBHOOK ENABLED = true",
            f"DROP NOTIFICATION INTEGRATION {prefix}ni",
            f"CREATE WORKLOAD GROUP {prefix}wg",
            f"DROP WORKLOAD GROUP {prefix}wg",
            f"CREATE CATALOG {prefix}cat TYPE=HIVE CONNECTION = (a='b')",
            f"DROP CATALOG {prefix}cat",
        ]
        for sql in sqls:
            result = check_sql_safety(sql)
            assert result.allowed is True

    def test_additional_objects_outside_sandbox_blocked(self):
        sqls = [
            "CREATE SEQUENCE seq",
            "DROP SEQUENCE seq",
            "CREATE PROCEDURE proc AS $$ SELECT 1 $$",
            "DROP PROCEDURE proc",
            "CREATE DICTIONARY prod_db.dict (id INT) SOURCE(mysql)",
            "DROP DICTIONARY prod_db.dict",
            "CREATE DYNAMIC TABLE prod_db.dt AS SELECT 1",
            "CREATE FILE FORMAT ff TYPE = CSV",
            "DROP FILE FORMAT ff",
            "CREATE NETWORK POLICY np ALLOWED_IP_LIST = ('1.1.1.1')",
            "DROP NETWORK POLICY np",
            "CREATE PASSWORD POLICY pp PASSWORD_MIN_LENGTH = 8",
            "DROP PASSWORD POLICY pp",
            "CREATE MASKING POLICY mask AS (val STRING) RETURNS STRING -> val",
            "DROP MASKING POLICY mask",
            "CREATE ROW ACCESS POLICY rap AS (val INT) RETURNS BOOLEAN -> true",
            "DROP ROW ACCESS POLICY rap",
            "CREATE TAG tag",
            "DROP TAG tag",
            "CREATE NOTIFICATION INTEGRATION ni TYPE = WEBHOOK ENABLED = true",
            "DROP NOTIFICATION INTEGRATION ni",
            "CREATE WORKLOAD GROUP wg",
            "DROP WORKLOAD GROUP wg",
            "CREATE CATALOG cat TYPE=HIVE CONNECTION = (a='b')",
            "DROP CATALOG cat",
        ]
        for sql in sqls:
            result = check_sql_safety(sql)
            assert result.allowed is False

    def test_alter_additional_objects_in_sandbox_allowed(self):
        prefix = get_session_prefix()
        sqls = [
            f"ALTER VIEW {prefix}db.v AS SELECT 1",
            f"ALTER FUNCTION {prefix}func AS (x) -> x",
            f"ALTER NETWORK POLICY {prefix}np SET ALLOWED_IP_LIST = ('1.1.1.1')",
            f"ALTER PASSWORD POLICY {prefix}pp SET PASSWORD_MIN_LENGTH = 8",
            f"ALTER NOTIFICATION INTEGRATION {prefix}ni SET ENABLED = true",
            f"ALTER WORKLOAD GROUP {prefix}wg SET cpu_quota = '50%'",
        ]
        for sql in sqls:
            result = check_sql_safety(sql)
            assert result.allowed is True

    def test_alter_additional_objects_outside_sandbox_blocked(self):
        sqls = [
            "ALTER VIEW prod_db.v AS SELECT 1",
            "ALTER FUNCTION prod_func AS (x) -> x",
            "ALTER NETWORK POLICY np SET ALLOWED_IP_LIST = ('1.1.1.1')",
            "ALTER PASSWORD POLICY pp SET PASSWORD_MIN_LENGTH = 8",
            "ALTER NOTIFICATION INTEGRATION ni SET ENABLED = true",
            "ALTER WORKLOAD GROUP wg SET cpu_quota = '50%'",
        ]
        for sql in sqls:
            result = check_sql_safety(sql)
            assert result.allowed is False


class TestIndexOperations:
    """Index operation tests."""

    def test_index_on_sandbox_table_allowed(self):
        prefix = get_session_prefix()
        sql = f"CREATE AGGREGATING INDEX {prefix}idx ON {prefix}db.t (c)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_index_on_non_sandbox_table_blocked(self):
        prefix = get_session_prefix()
        sql = f"CREATE AGGREGATING INDEX {prefix}idx ON production.t (c)"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "Referenced object" in result.reason

    def test_create_or_replace_index_allowed(self):
        prefix = get_session_prefix()
        sql = f"CREATE OR REPLACE AGGREGATING INDEX {prefix}idx AS SELECT 1"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_drop_index_in_sandbox_allowed(self):
        prefix = get_session_prefix()
        sql = f"DROP AGGREGATING INDEX {prefix}idx"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_drop_index_outside_sandbox_blocked(self):
        sql = "DROP AGGREGATING INDEX prod_idx"
        result = check_sql_safety(sql)
        assert result.allowed is False


class TestTagOperations:
    """Tag operation tests."""

    def test_set_tag_on_sandbox_object_allowed(self):
        prefix = get_session_prefix()
        sql = f"ALTER TABLE {prefix}db.t SET TAG {prefix}tag = 'x'"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_set_tag_with_non_sandbox_tag_blocked(self):
        prefix = get_session_prefix()
        sql = f"ALTER TABLE {prefix}db.t SET TAG prod_tag = 'x'"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_unset_tag_with_non_sandbox_object_blocked(self):
        prefix = get_session_prefix()
        sql = f"ALTER TABLE prod_db.t UNSET TAG {prefix}tag"
        result = check_sql_safety(sql)
        assert result.allowed is False


class TestEdgeCases:
    """Edge cases and special scenarios."""

    def test_empty_sql(self):
        result = check_sql_safety("")
        assert isinstance(result, SafetyResult)

    def test_whitespace_sql(self):
        result = check_sql_safety("   ")
        assert isinstance(result, SafetyResult)

    def test_multiline_sql(self):
        sql = f"""
        CREATE TABLE {get_session_prefix()}mydb.users (
            id INT,
            name VARCHAR(100)
        )
        """
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_multiline_non_sandbox_blocked(self):
        sql = """
        CREATE TABLE production.users (
            id INT,
            name VARCHAR(100)
        )
        """
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_sql_with_comments(self):
        sql = f"-- This creates a table\nCREATE TABLE {get_session_prefix()}db.users (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_case_insensitive_keywords(self):
        sql = f"create table {get_session_prefix()}db.test (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_case_insensitive_sandbox_prefix(self):
        # Sandbox prefix matching should be case insensitive
        sql = f"CREATE TABLE {get_session_prefix().upper()}DB.test (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_optimize_table_in_sandbox(self):
        sql = f"OPTIMIZE TABLE {get_session_prefix()}db.users"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_optimize_table_outside_sandbox_blocked(self):
        sql = "OPTIMIZE TABLE production.users"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_vacuum_table_in_sandbox(self):
        sql = f"VACUUM TABLE {get_session_prefix()}db.logs"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_vacuum_table_outside_sandbox_blocked(self):
        sql = "VACUUM TABLE production.logs"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_copy_into_sandbox(self):
        sql = f"COPY INTO {get_session_prefix()}db.t FROM @stage/data.csv"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_copy_into_non_sandbox_blocked(self):
        sql = "COPY INTO production.t FROM @stage/data.csv"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_merge_into_sandbox(self):
        sql = f"MERGE INTO {get_session_prefix()}db.target USING {get_session_prefix()}db.source ON target.id = source.id"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_merge_into_non_sandbox_blocked(self):
        sql = f"MERGE INTO production.target USING {get_session_prefix()}db.source ON target.id = source.id"
        result = check_sql_safety(sql)
        assert result.allowed is False


class TestDatabaseTableFormat:
    """Test db.table format handling."""

    def test_insert_db_table_sandbox(self):
        sql = f"INSERT INTO {get_session_prefix()}db.users VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_insert_db_table_non_sandbox_blocked(self):
        sql = "INSERT INTO production.users VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "production" in result.reason

    def test_update_db_table_sandbox(self):
        sql = f"UPDATE {get_session_prefix()}db.users SET name='x'"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_update_db_table_non_sandbox_blocked(self):
        sql = "UPDATE production.users SET name='x'"
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_insert_with_join_non_sandbox_blocked(self):
        sql = f"INSERT INTO {get_session_prefix()}db.t SELECT * FROM production.users"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "non-sandbox" in result.reason

    def test_create_table_db_table_format(self):
        sql = f"CREATE TABLE {get_session_prefix()}db.users (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_create_table_db_table_non_sandbox_blocked(self):
        sql = "CREATE TABLE production.users (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is False


class TestSQLStandardization:
    """Test SQL standardization handles malformed SQL."""

    def test_create_or_replace_with_comments(self):
        sql = f"CREATE/*comment*/OR/*comment*/REPLACE TABLE {get_session_prefix()}t (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_create_or_replace_with_newlines(self):
        sql = f"CREATE\n  OR\n  REPLACE TABLE {get_session_prefix()}t (id INT)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_insert_with_excessive_whitespace(self):
        sql = f"INSERT    INTO    {get_session_prefix()}db.t    VALUES    (1)"
        result = check_sql_safety(sql)
        assert result.allowed is True

    def test_insert_non_sandbox_with_comments(self):
        sql = "INSERT/*comment*/INTO production.users VALUES (1)"
        result = check_sql_safety(sql)
        assert result.allowed is False


class TestStatementBoundaries:
    """A statement must not ride on the approval of another one."""

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 1; DROP DATABASE production",
            "SHOW DATABASES; DROP TABLE production.users",
            "DESC mydb.t; DROP DATABASE production",
            "SELECT 1; SELECT 2",
        ],
    )
    def test_stacked_statements_blocked(self, sql):
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "Multiple SQL statements" in result.reason

    def test_stacked_statement_after_sandbox_write_blocked(self):
        sql = f"INSERT INTO {get_session_prefix()}db.t VALUES (1); DROP DATABASE production"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "Multiple SQL statements" in result.reason

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM production.users;",
            "  SELECT 1 ;  ",
            f"CREATE OR REPLACE PROCEDURE {get_session_prefix()}proc AS $$ SELECT 1; SELECT 2 $$",
        ],
    )
    def test_single_statement_with_trailing_separator_allowed(self, sql):
        assert check_sql_safety(sql).allowed is True

    def test_semicolon_inside_string_is_not_a_separator(self):
        assert check_sql_safety("SELECT * FROM t WHERE c = 'a;b'").allowed is True
        assert check_sql_safety("SELECT * FROM t WHERE c = 'it''s; fine'").allowed is True

    def test_semicolon_inside_comment_is_not_a_separator(self):
        assert check_sql_safety("SELECT 1 -- ; DROP DATABASE production").allowed is True
        assert check_sql_safety("SELECT 1 /* ; DROP DATABASE production */").allowed is True

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 'unterminated",
            "SELECT 1 /* unterminated",
            "SELECT `unterminated",
        ],
    )
    def test_untokenizable_sql_blocked(self, sql):
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "tokenized" in result.reason


class TestReadOnlyPrefixNarrowing:
    """The read-only rule must describe the whole statement, not just a prefix."""

    @pytest.mark.parametrize(
        "sql",
        [
            "EXPLAIN ANALYZE DELETE FROM production.users",
            "EXPLAIN ANALYZE INSERT INTO production.users VALUES (1)",
            "EXPLAIN ANALYZE UPDATE production.users SET admin = true",
            "EXPLAIN DROP DATABASE production",
            "EXPLAIN CREATE USER evil IDENTIFIED BY 'x'",
        ],
    )
    def test_explain_of_write_blocked(self, sql):
        assert check_sql_safety(sql).allowed is False

    @pytest.mark.parametrize(
        "sql",
        [
            "EXPLAIN SELECT * FROM production.users",
            "EXPLAIN ANALYZE SELECT * FROM production.users",
            "EXPLAIN AST SELECT 1",
            "EXPLAIN SYNTAX SELECT 1",
        ],
    )
    def test_explain_of_read_allowed(self, sql):
        assert check_sql_safety(sql).allowed is True

    @pytest.mark.parametrize(
        "sql",
        [
            "WITH cte AS (SELECT 1) DELETE FROM production.users",
            "WITH cte AS (SELECT 1) UPDATE production.users SET admin = true",
            "WITH cte AS (SELECT 1) DROP DATABASE production",
            "WITH RECURSIVE cte AS (SELECT 1) DELETE FROM production.users",
        ],
    )
    def test_cte_write_on_non_sandbox_blocked(self, sql):
        assert check_sql_safety(sql).allowed is False

    def test_cte_select_allowed(self):
        assert check_sql_safety("WITH cte AS (SELECT 1) SELECT * FROM cte").allowed is True

    def test_cte_write_on_sandbox_allowed(self):
        sql = f"WITH cte AS (SELECT 1) DELETE FROM {get_session_prefix()}db.t"
        assert check_sql_safety(sql).allowed is True


class TestGrantWildcard:
    """A wildcard GRANT target must not slip past the identifier checks."""

    @pytest.mark.parametrize(
        "sql",
        [
            "GRANT ALL PRIVILEGES ON *.* TO mcp_sandbox_evil",
            "GRANT ALL ON *.* TO mcp_sandbox_evil WITH GRANT OPTION",
            "GRANT ALL ON *.* TO root",
            "GRANT SELECT ON DATABASE * TO mcp_sandbox_user",
            "REVOKE ALL ON *.* FROM mcp_sandbox_user",
        ],
    )
    def test_global_wildcard_blocked(self, sql):
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_global_wildcard_blocked_for_sandbox_grantee(self):
        """The sandbox prefix on the grantee must not carry a global grant."""
        prefix = get_session_prefix()
        sql = f"GRANT ALL PRIVILEGES ON *.* TO {prefix}evil"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "wildcard" in result.reason

    def test_sandbox_database_wildcard_allowed(self):
        prefix = get_session_prefix()
        sql = f"GRANT SELECT ON {prefix}db.* TO {prefix}user"
        assert check_sql_safety(sql).allowed is True

    def test_non_sandbox_database_wildcard_blocked(self):
        prefix = get_session_prefix()
        sql = f"GRANT SELECT ON production.* TO {prefix}user"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "production" in result.reason

    def test_non_sandbox_grantee_with_sandbox_target_blocked(self):
        prefix = get_session_prefix()
        sql = f"GRANT SELECT ON DATABASE {prefix}db TO root"
        assert check_sql_safety(sql).allowed is False


class TestMultiTargetWriteRules:
    """Write rules must validate every target, not only the first identifier."""

    @pytest.mark.parametrize(
        "statement",
        [
            "DROP TABLE {p}t, production.users",
            "DROP TABLE IF EXISTS {p}a, production.users",
            "DROP VIEW {p}v, production.v2",
            "DROP USER {p}u, production.u",
            "TRUNCATE TABLE {p}t, production.events",
            "TRUNCATE {p}t, production.events",
        ],
    )
    def test_comma_separated_targets_blocked(self, statement):
        sql = statement.format(p=get_session_prefix())
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "production" in result.reason

    @pytest.mark.parametrize(
        "statement",
        [
            "DROP TABLE {p}a, {p}b",
            "TRUNCATE TABLE {p}t, {p}t2",
        ],
    )
    def test_comma_separated_sandbox_targets_allowed(self, statement):
        sql = statement.format(p=get_session_prefix())
        assert check_sql_safety(sql).allowed is True

    @pytest.mark.parametrize(
        "statement",
        [
            "ALTER TABLE {p}db.t RENAME TO production.pwned",
            "ALTER TABLE {p}t SWAP WITH production.users",
            "ALTER DATABASE {p}db RENAME TO production",
            "ALTER WAREHOUSE {p}wh RENAME TO prod_wh",
        ],
    )
    def test_alter_destination_blocked(self, statement):
        sql = statement.format(p=get_session_prefix())
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "ALTER" in result.reason

    def test_alter_rename_inside_sandbox_allowed(self):
        prefix = get_session_prefix()
        sql = f"ALTER TABLE {prefix}db.t RENAME TO {prefix}db.t2"
        assert check_sql_safety(sql).allowed is True

    def test_alter_rename_column_allowed(self):
        prefix = get_session_prefix()
        sql = f"ALTER TABLE {prefix}db.t RENAME COLUMN a TO b"
        assert check_sql_safety(sql).allowed is True


class TestDeferredBodies:
    """TASK/PIPE/DYNAMIC TABLE bodies are validated by the full rule chain."""

    @pytest.mark.parametrize(
        "statement",
        [
            "CREATE TASK {p}t AS DROP TABLE production.users",
            "CREATE TASK {p}t AS TRUNCATE TABLE production.events",
            "CREATE TASK {p}t AS ALTER TABLE production.t DROP COLUMN c",
            "CREATE TASK {p}t AS CREATE USER hacker IDENTIFIED BY 'x'",
            "CREATE TASK {p}t AS GRANT ALL ON *.* TO hacker",
            "CREATE TASK {p}t AS DROP DATABASE production",
            "CREATE OR REPLACE TASK {p}t AS DROP TABLE production.users",
            "CREATE PIPE {p}p AS ALTER TABLE production.t DROP COLUMN c",
            "CREATE DYNAMIC TABLE {p}db.dt AS DROP DATABASE production",
        ],
    )
    def test_non_sandbox_body_blocked(self, statement):
        sql = statement.format(p=get_session_prefix())
        result = check_sql_safety(sql)
        assert result.allowed is False

    @pytest.mark.parametrize(
        "statement",
        [
            "CREATE TASK {p}t AS INSERT INTO {p}db.t VALUES (1)",
            "CREATE TASK {p}t AS SELECT 1",
            "CREATE OR REPLACE TASK {p}t AS INSERT INTO {p}db.t VALUES (1)",
            "CREATE PIPE {p}p AS COPY INTO {p}db.t FROM @stage",
            "CREATE DYNAMIC TABLE {p}db.dt AS SELECT * FROM {p}db.t",
        ],
    )
    def test_sandbox_body_allowed(self, statement):
        sql = statement.format(p=get_session_prefix())
        assert check_sql_safety(sql).allowed is True

    def test_deeply_nested_bodies_blocked(self):
        prefix = get_session_prefix()
        sql = ("CREATE TASK " + prefix + "t AS ") * 6 + "SELECT 1"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "Nested SQL" in result.reason


class TestGrantTargetCoverage:
    """Every object class in an ON clause is checked, not a fixed list of them."""

    @pytest.mark.parametrize(
        "statement",
        [
            "GRANT SELECT ON VIEW production.v TO {p}user",
            "GRANT SELECT ON TAG production.tag TO {p}user",
            "GRANT SELECT ON CATALOG prod_cat TO {p}user",
            "GRANT SELECT ON FILE FORMAT prod_ff TO {p}user",
            'GRANT SELECT ON DATABASE "tables" TO {p}user',
            "GRANT SELECT ON ALL TABLES IN SCHEMA production TO {p}user",
        ],
    )
    def test_any_object_class_checked(self, statement):
        sql = statement.format(p=get_session_prefix())
        result = check_sql_safety(sql)
        assert result.allowed is False

    def test_wildcard_outside_object_reference_blocked(self):
        prefix = get_session_prefix()
        sql = f"GRANT SELECT ON DATABASE {prefix}db TO *"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "wildcard" in result.reason

    @pytest.mark.parametrize(
        "statement",
        [
            "GRANT SELECT ON DATABASE {p}db TO {p}user",
            "GRANT SELECT ON TABLE {p}db.t TO {p}user",
            "GRANT USAGE ON WAREHOUSE {p}wh TO {p}user",
            "GRANT SELECT ON ALL TABLES IN SCHEMA {p}db TO {p}user",
            "GRANT ROLE {p}role TO {p}user",
            "REVOKE SELECT ON DATABASE {p}db FROM {p}user",
        ],
    )
    def test_sandbox_targets_still_allowed(self, statement):
        sql = statement.format(p=get_session_prefix())
        assert check_sql_safety(sql).allowed is True


class TestExplainVariants:
    """Valid Databend EXPLAIN variants must stay read-only (compat regression B5)."""

    @pytest.mark.parametrize(
        "sql",
        [
            "EXPLAIN SELECT * FROM production.users",
            "EXPLAIN ANALYZE SELECT 1",
            "EXPLAIN AST SELECT 1",
            "EXPLAIN SYNTAX SELECT 1",
            "EXPLAIN OPTIMIZED SELECT 1",
            "EXPLAIN MEMO SELECT 1",
            "EXPLAIN PERF SELECT 1",
            "EXPLAIN DECORRELATED SELECT 1",
            "EXPLAIN(LOGICAL) SELECT 1",
            "EXPLAIN(VERBOSE, OPTIMIZED) SELECT 1",
            "EXPLAIN (LOGICAL) SELECT 1",
        ],
    )
    def test_read_explain_variants_allowed(self, sql):
        assert check_sql_safety(sql).allowed is True

    @pytest.mark.parametrize(
        "sql",
        [
            "EXPLAIN DROP DATABASE production",
            "EXPLAIN ANALYZE DELETE FROM production.users",
            "EXPLAIN MEMO DROP TABLE production.users",
            "EXPLAIN(LOGICAL) CREATE USER evil IDENTIFIED BY 'x'",
        ],
    )
    def test_explain_of_write_still_blocked(self, sql):
        assert check_sql_safety(sql).allowed is False


class TestCteWrites:
    """CTE names are aliases, not non-sandbox references (compat regression B6)."""

    def test_cte_insert_into_sandbox_allowed(self):
        prefix = get_session_prefix()
        sql = f"WITH cte AS (SELECT 1) INSERT INTO {prefix}db.t SELECT * FROM cte"
        assert check_sql_safety(sql).allowed is True

    def test_cte_update_sandbox_allowed(self):
        prefix = get_session_prefix()
        sql = f"WITH cte AS (SELECT 2) UPDATE {prefix}db.t SET a = 2 WHERE a IN (SELECT * FROM cte)"
        assert check_sql_safety(sql).allowed is True

    def test_cte_delete_sandbox_allowed(self):
        prefix = get_session_prefix()
        sql = f"WITH cte AS (SELECT 1) DELETE FROM {prefix}db.t WHERE a IN (SELECT * FROM cte)"
        assert check_sql_safety(sql).allowed is True

    def test_multiple_ctes_allowed(self):
        prefix = get_session_prefix()
        sql = f"WITH a AS (SELECT 1), b AS (SELECT * FROM a) INSERT INTO {prefix}db.t SELECT * FROM b"
        assert check_sql_safety(sql).allowed is True

    def test_cte_body_reference_to_non_sandbox_still_blocked(self):
        prefix = get_session_prefix()
        sql = f"WITH cte AS (SELECT * FROM production.users) INSERT INTO {prefix}db.t SELECT * FROM cte"
        result = check_sql_safety(sql)
        assert result.allowed is False
        assert "non-sandbox" in result.reason

    def test_cte_write_on_non_sandbox_target_still_blocked(self):
        sql = "WITH cte AS (SELECT 1) INSERT INTO production.users SELECT * FROM cte"
        assert check_sql_safety(sql).allowed is False


class TestAlterRenameDestinations:
    """Bare RENAME TO / SWAP WITH destinations mean "same database" (compat regression R2)."""

    def test_bare_rename_from_qualified_sandbox_table_allowed(self):
        prefix = get_session_prefix()
        sql = f"ALTER TABLE {prefix}db.t RENAME TO t2"
        assert check_sql_safety(sql).allowed is True

    def test_bare_swap_from_qualified_sandbox_table_allowed(self):
        prefix = get_session_prefix()
        sql = f"ALTER TABLE {prefix}db.t SWAP WITH t3"
        assert check_sql_safety(sql).allowed is True

    def test_bare_rename_from_bare_sandbox_table_blocked(self):
        # Without a database-qualified source the destination cannot be shown to
        # stay inside the sandbox database.
        prefix = get_session_prefix()
        sql = f"ALTER TABLE {prefix}t RENAME TO t2"
        assert check_sql_safety(sql).allowed is False

    def test_prefixed_bare_destination_allowed(self):
        prefix = get_session_prefix()
        sql = f"ALTER TABLE {prefix}t RENAME TO {prefix}t2"
        assert check_sql_safety(sql).allowed is True

    def test_qualified_non_sandbox_destination_blocked(self):
        prefix = get_session_prefix()
        sql = f"ALTER TABLE {prefix}db.t RENAME TO production.pwned"
        assert check_sql_safety(sql).allowed is False

    def test_database_rename_to_non_sandbox_blocked(self):
        prefix = get_session_prefix()
        sql = f"ALTER DATABASE {prefix}db RENAME TO production"
        assert check_sql_safety(sql).allowed is False
