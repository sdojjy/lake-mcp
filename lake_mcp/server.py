import atexit
import concurrent.futures
import logging
import os
import re
import sys
import threading
from typing import Optional

import pyarrow as pa
from fastmcp import FastMCP
from fastmcp.server.auth import AuthContext
from fastmcp.server.dependencies import get_access_token, get_context
from fastmcp.tools import Tool

from .env import TransportType, get_config
from .runtime_security import LakeJWTVerifier, build_auth, get_network_request, load_config_file, network_run_options
from .safety import audit_operation, check_network_sql, check_sql_safety, get_session_id, get_session_prefix

# Constants
SERVER_NAME = "lake-mcp"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(SERVER_NAME)

# Initialize thread pool and cleanup
QUERY_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=10)
atexit.register(lambda: QUERY_EXECUTOR.shutdown(wait=True))

# Load environment variables
load_config_file()


class LakeMCP(FastMCP):
    @property
    def routes_warehouse_accounts(self):
        return isinstance(self.auth, LakeJWTVerifier) and self.auth.routes_warehouse_accounts

    def http_app(self, path=None, middleware=None, **kwargs):
        # Embedded ASGI apps also pass through the same HTTP/SSE policy.
        config = get_config()
        if self.routes_warehouse_accounts and config.local_mode:
            raise ValueError("Warehouse account mapping requires remote Lake connections")
        options = network_run_options(config, self.auth)
        return super().http_app(path=path, middleware=[*options["middleware"], *(middleware or [])], **kwargs)


mcp = LakeMCP(SERVER_NAME, auth=build_auth())

# Single-owner mode retains one client; mapped connections use current credentials per query.
_lake_client = None
_lake_client_lock = threading.Lock()

# Tool arguments are interpolated into SQL text, so they are normalized here
# instead of being pasted in raw: the safety gate sees the finished statement,
# and a `;` smuggled through an argument would otherwise ride on the approval of
# the statement's read-only prefix. Quoted identifiers (`` `my-db` `` or
# `` "my-db" ``) and Databend's `` $ `` identifier character are accepted and
# re-emitted in a canonical, injection-safe form.
_IDENTIFIER_UNQUOTED_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")
_IDENTIFIER_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_STAGE_PATH_FORBIDDEN_RE = re.compile(r"[;'\"`\x00-\x1f\x7f]")


def _invalid_argument(argument: str, expected: str) -> dict:
    """Build the error returned when a tool argument fails validation."""
    return {"status": "error", "message": f"Invalid {argument}: {expected}"}


def _split_identifier_parts(value: str) -> list[tuple[str, bool]] | None:
    """Split ``db.table`` style text into ``(content, was_quoted)`` parts."""
    if not value:
        return None
    parts: list[tuple[str, bool]] = []
    index = 0
    length = len(value)
    while True:
        char = value[index] if index < length else ""
        if char in ("`", '"'):
            quote = char
            index += 1
            content_chars: list[str] = []
            closed = False
            while index < length:
                current = value[index]
                if current == quote:
                    if index + 1 < length and value[index + 1] == quote:
                        content_chars.append(quote)
                        index += 2
                        continue
                    index += 1
                    closed = True
                    break
                content_chars.append(current)
                index += 1
            if not closed:
                return None
            content = "".join(content_chars)
            if not content:
                return None
            parts.append((content, True))
        else:
            start = index
            while index < length and value[index] != ".":
                index += 1
            content = value[start:index]
            if not content:
                return None
            parts.append((content, False))
        if index >= length:
            return parts
        if value[index] != ".":
            return None
        index += 1
        if index >= length:
            return None


def _render_identifier(value: str, *, allow_qualified: bool = True, unquoted_only: bool = False) -> str | None:
    """Return ``value`` as an injection-safe SQL identifier, or None if invalid.

    Unquoted parts must match Databend's plain identifier syntax
    (``[_a-zA-Z][_$a-zA-Z0-9]*``). Quoted parts are re-emitted with backticks
    after rejecting characters that cannot be represented safely there.
    """
    parts = _split_identifier_parts(value.strip())
    if not parts:
        return None
    if not allow_qualified and len(parts) > 1:
        return None
    rendered: list[str] = []
    for content, was_quoted in parts:
        if not was_quoted:
            if not _IDENTIFIER_UNQUOTED_RE.fullmatch(content):
                return None
            rendered.append(content)
            continue
        if unquoted_only:
            # e.g. CREATE STAGE only accepts a plain (unquoted) identifier.
            if not _IDENTIFIER_UNQUOTED_RE.fullmatch(content):
                return None
            rendered.append(content)
            continue
        # Databend quoted identifiers have no escape for a backtick, and a
        # backslash or a second statement separator must never be pasted in.
        if _IDENTIFIER_CONTROL_RE.search(content) or any(char in content for char in (";", "`", "\\")):
            return None
        rendered.append(f"`{content}`")
    return ".".join(rendered)


def _render_stage_reference(stage_name: str) -> str | None:
    """Return an injection-safe ``LIST`` stage reference (``@stage``, ``@~``, ``@%table``)."""
    name = stage_name.strip()
    if name.startswith("@"):
        name = name[1:]
    if not name:
        return None
    if name == "~":
        return "@~"
    if name.startswith("%"):
        table = _render_identifier(name[1:], unquoted_only=True)
        return None if table is None else f"@%{table}"
    stage = _render_identifier(name, unquoted_only=True)
    return None if stage is None else f"@{stage}"


def _escape_sql_literal(value: str) -> str:
    """Escape a value that is placed inside a single-quoted SQL literal."""
    return value.replace("\\", "\\\\").replace("'", "''")


def get_global_lake_client(warehouse_dsn: str | None = None):
    if warehouse_dsn is not None:
        return create_lake_client(warehouse_dsn)

    global _lake_client
    with _lake_client_lock:
        if _lake_client is None:
            _lake_client = create_lake_client()
        return _lake_client


def create_lake_client(warehouse_dsn: str | None = None):
    config = get_config()

    if warehouse_dsn is None and config.local_mode:
        logger.info("Creating local Lake client")
        import databend

        return databend.SessionContext()

    logger.info("Creating remote Lake client")
    from tidbcloudlake_driver import BlockingLakeClient

    return BlockingLakeClient(warehouse_dsn if warehouse_dsn is not None else config.dsn)


def execute_lake_query(sql: str, *, warehouse_dsn: str | None = None) -> list[dict] | dict:
    """Execute SQL with the already selected warehouse connection."""
    try:
        client = get_global_lake_client(warehouse_dsn)
        if warehouse_dsn is None and get_config().local_mode:
            result = client.sql(sql)
            return recordbatches_to_dicts(result.to_py_arrow())

        conn = client.get_conn()
        cursor = conn.query_iter(sql)
        column_names = [field.name for field in cursor.schema().fields()]
        results = [dict(zip(column_names, row.values())) for row in cursor]

        logger.info(f"Query executed successfully, returned {len(results)} rows")
        return results

    except Exception:
        logger.error("Warehouse query failed")
        return {"error": "Warehouse query failed"}


def recordbatches_to_dicts(batches: list[pa.RecordBatch]) -> list[dict]:
    results = []
    for batch in batches:
        columns = batch.schema.names
        columns_data = [batch.column(i).to_pylist() for i in range(batch.num_columns)]
        for row in zip(*columns_data):
            results.append(dict(zip(columns, row)))
    return results


def _execute_sql(sql: str) -> dict:
    logger.info("Executing SQL query")

    config = get_config()

    network = get_network_request() is not None
    try:
        transport = get_context().transport
    except RuntimeError:
        transport = None
    if not network and transport in {"sse", "streamable-http"}:
        return {"status": "error", "message": "HTTP/SSE request context required"}
    token = get_access_token() if network else None
    query_options = {}
    if mcp.routes_warehouse_accounts:
        warehouse_dsn = mcp.auth.warehouse_dsn(token)
        if warehouse_dsn is None:
            return {"status": "error", "message": "No warehouse account for this identity"}
        query_options["warehouse_dsn"] = warehouse_dsn

    local_admin = not network and os.environ.get("LAKE_MCP_ALLOW_STDIO_ADMIN") == "1"
    if network or config.safe_mode or not local_admin:
        if network:
            if mcp.auth is not None and token is None:
                return {"status": "error", "message": "HTTP/SSE authentication required"}
            result = check_network_sql(sql, allow_write=bool(token and "lake:write" in token.scopes))
        elif local_admin:
            result = check_sql_safety(sql)
        else:
            result = check_network_sql(sql, allow_write=True)
        if not result.allowed:
            logger.warning("Query rejected by sandbox policy")
            return {"status": "error", "message": result.reason}
    else:
        logger.warning("LAKE_MCP_SAFE_MODE=false: sandbox safety check is disabled")

    # Record privilege use without emitting SQL, parameters, or credentials.
    if local_admin or not check_network_sql(sql, allow_write=False).allowed:
        principal = (token.subject or token.client_id) if token is not None else f"stdio:{getattr(os, 'geteuid', lambda: 'local')()}"
        logger.info(
            "Warehouse privileged operation requested principal=%r transport=%s action=%s",
            principal,
            "network" if network else "stdio",
            audit_operation(sql),
        )

    try:
        # Submit query to thread pool
        future = QUERY_EXECUTOR.submit(execute_lake_query, sql, **query_options)
        query_timeout = config.query_timeout
        try:
            # Wait for query to complete with timeout
            result = future.result(timeout=query_timeout)

            if isinstance(result, dict) and "error" in result:
                error_msg = f"Query execution failed: {result['error']}"
                logger.warning("Query execution failed")
                return {"status": "error", "message": error_msg}

            # Ensure we always return a dict structure for fastmcp compatibility
            if isinstance(result, list):
                return {"status": "success", "data": result, "row_count": len(result)}
            else:
                return {"status": "success", "data": result}

        except concurrent.futures.TimeoutError:
            error_msg = f"Query timed out after {query_timeout} seconds"
            logger.warning(error_msg)
            future.cancel()
            return {"status": "error", "message": error_msg}

    except Exception:
        logger.error("Unexpected error in query execution")
        return {"status": "error", "message": "Unexpected error in query execution"}


def execute_multi_sql(sqls: list[str]) -> list[dict]:
    """
    Execute multiple SQL queries against the TiDB Cloud Lake database with MCP safe mode protection.

    Safe mode (enabled by default) restricts write operations to the current
    session sandbox. Set LAKE_MCP_SAFE_MODE=false to disable sandbox validation.

    Args:
        sqls: List of SQL query strings to execute

    Returns:
        List of dictionaries containing either query results or error information
    """
    results = []
    for sql in sqls:
        results.append(execute_sql(sql))
    return results


def execute_sql(sql: str) -> dict:
    """
    Execute SQL query against the TiDB Cloud Lake database.

    SAFETY RULES (when LAKE_MCP_SAFE_MODE is enabled):
    - Read operations (SELECT/SHOW/DESCRIBE/EXPLAIN/LIST): allowed on ALL objects
    - Write operations (CREATE/DROP/INSERT/UPDATE/DELETE/...): ONLY allowed on current session's sandbox
    - Current session sandbox prefix: use get_session_sandbox_prefix() to get it
    - Set LAKE_MCP_SAFE_MODE=false to disable sandbox validation

    Args:
        sql: SQL query string to execute

    Returns:
        Dictionary containing query results or error information
    """
    return _execute_sql(sql)


def show_databases():
    """List available TiDB Cloud Lake databases (safe operation, not affected by MCP safe mode)."""
    logger.info("Listing all databases")
    return _execute_sql("SHOW DATABASES")


_FILTER_ATOM = r"(?:'(?:[^'\\]|\\.|'')*'|[+-]?[0-9]+(?:\.[0-9]+)?|TRUE|FALSE|NULL)"
_METADATA_FILTER = re.compile(
    rf"(?P<column>[A-Za-z_][A-Za-z0-9_]*|[0-9]+)\s*"
    rf"(?P<op><>|!=|<=|>=|=|<|>|\s+(?:NOT\s+)?(?:LIKE|ILIKE)\s+)\s*"
    rf"(?P<value>{_FILTER_ATOM})",
    re.IGNORECASE,
)


def _metadata_filter(value):
    # Restrict SHOW predicates to a single metadata column and scalar comparison.
    # The left side and operator are lexical atoms, not arbitrary SQL expressions.
    if len(value) > 4096:
        return None
    match = _METADATA_FILTER.fullmatch(value.strip())
    return match.group(0) if match else None


def show_tables(database: Optional[str] = None, filter: Optional[str] = None):
    """
    List available TiDB Cloud Lake tables in a database (safe operation, not affected by MCP safe mode).
    Args:
        database: The database name
        filter: The filter string, eg: "name like 'test%'"

    Returns:
        Dictionary containing either query results or error information
    """
    logger.info(f"Listing tables in database '{database}'")
    sql = "SHOW TABLES"
    if database is not None:
        rendered = _render_identifier(database)
        if rendered is None:
            return _invalid_argument(
                "database",
                "expected a SQL identifier, e.g. 'analytics', 'analytics.events' or '`my-db`'",
            )
        sql += f" FROM {rendered}"
    if filter is not None:
        predicate = _metadata_filter(filter)
        if predicate is None:
            return _invalid_argument("filter", "expected a metadata column compared with one scalar value")
        sql += f" WHERE {predicate}"
    return _execute_sql(sql)


def show_functions(filter: Optional[str] = None):
    """List available TiDB Cloud Lake functions (safe operation, not affected by MCP safe mode).
    Args:
        filter: The filter string, eg: "name like 'add%'"
    Returns:
        Dictionary containing either query results or error information
    """
    logger.info("Listing all functions")
    sql = "SHOW FUNCTIONS"
    if filter is not None:
        predicate = _metadata_filter(filter)
        if predicate is None:
            return _invalid_argument("filter", "expected a metadata column compared with one scalar value")
        sql += f" WHERE {predicate}"
    return _execute_sql(sql)


def describe_table(table: str, database: Optional[str] = None):
    """
    Describe a TiDB Cloud Lake table (safe operation, not affected by MCP safe mode).
    Args:
        table: The table name
        database: The database name

    Returns:
        Dictionary containing either query results or error information
    """
    rendered_table = _render_identifier(table)
    if rendered_table is None:
        return _invalid_argument("table", "expected a SQL identifier, e.g. 'users', 'analytics.users' or '`my-table`'")
    if database is not None:
        rendered_database = _render_identifier(database)
        if rendered_database is None:
            return _invalid_argument("database", "expected a SQL identifier, e.g. 'analytics' or '`my-db`'")
        rendered_table = f"{rendered_database}.{rendered_table}"
    logger.info(f"Describing table '{rendered_table}'")
    sql = f"DESCRIBE TABLE {rendered_table}"
    return _execute_sql(sql)


def show_stages():
    """List available TiDB Cloud Lake stages (safe operation, not affected by MCP safe mode)."""
    logger.info("Listing all stages")
    return _execute_sql("SHOW STAGES")


def list_stage_files(stage_name: str, path: Optional[str] = None):
    """
    List files in a TiDB Cloud Lake stage (safe operation, not affected by MCP safe mode).
    Args:
        stage_name: The stage name (with @ prefix)
        path: Optional path within the stage

    Returns:
        Dictionary containing either query results or error information
    """
    stage_reference = _render_stage_reference(stage_name)
    if stage_reference is None:
        return _invalid_argument(
            "stage_name",
            "expected a stage name, e.g. 'mystage', '@mystage', '@~' or '@%table'",
        )

    if path:
        path = path.strip()
        if _STAGE_PATH_FORBIDDEN_RE.search(path):
            return _invalid_argument("path", "expected a stage path without ';', quotes or control characters")
        stage_path = f"{stage_reference}/{path.strip('/')}"
    else:
        stage_path = stage_reference

    logger.info(f"Listing files in stage '{stage_path}'")
    sql = f"LIST {stage_path}"
    return _execute_sql(sql)


def show_connections():
    """List available TiDB Cloud Lake connections (safe operation, not affected by MCP safe mode)."""
    logger.info("Listing all connections")
    return _execute_sql("SHOW CONNECTIONS")


def create_stage(name: str, url: Optional[str] = None, connection_name: Optional[str] = None) -> dict:
    """
    Create an internal stage, or an external stage in trusted local admin mode.
    Args:
        name: The stage name
        url: External stage URL; omit for an internal stage (required in safe mode)
        connection_name: Optional connection name to use

    Returns:
        Dictionary containing either query results or error information
    """
    logger.info("Creating stage")

    rendered_name = _render_identifier(name, allow_qualified=False, unquoted_only=True)
    if rendered_name is None:
        return _invalid_argument("name", "expected a stage name, e.g. 'mystage' or 's$1'")
    if url is not None and not url.strip():
        return _invalid_argument("url", "expected a non-empty stage URL, e.g. 's3://bucket-name'")
    if connection_name and url is None:
        return _invalid_argument("connection_name", "an external stage connection requires a URL")

    sql_parts = [f"CREATE STAGE {rendered_name}"]
    if url is not None:
        sql_parts.append(f"URL = '{_escape_sql_literal(url)}'")

    if connection_name:
        # CONNECTION_NAME is a string literal, not an identifier: a connection
        # named `my-conn` / `conn.prod` is valid and must be escaped, not rejected.
        sql_parts.append(f"CONNECTION = (CONNECTION_NAME = '{_escape_sql_literal(connection_name)}')")

    sql = " ".join(sql_parts)
    return _execute_sql(sql)


def get_session_sandbox_prefix() -> dict:
    """
    Get current session's sandbox prefix for writable objects.

    All write operations (CREATE/DROP/INSERT/UPDATE/DELETE/...) are ONLY
    allowed on objects with this prefix. This is enforced by code, not just guidelines.

    Returns:
        Dictionary with session_id and prefix
    """
    prefix = get_session_prefix()
    return {
        "session_id": get_session_id(),
        "prefix": prefix,
        "example_database": f"{prefix}mydb",
        "example_table": f"{prefix}mydb.mytable",
    }


def list_session_sandbox_databases() -> dict:
    """
    List sandbox databases owned by current session.

    Only these databases can be modified. Other databases are read-only.

    Returns:
        Dictionary containing current session's sandbox database list
    """
    prefix = get_session_prefix()
    return _execute_sql(f"SHOW DATABASES LIKE '{prefix}%'")


def create_session_sandbox_database(name: str) -> dict:
    """
    Create a new sandbox database for current session.

    The database name will be automatically prefixed with current session's sandbox prefix.

    Args:
        name: Database name suffix (without prefix)

    Example:
        create_session_sandbox_database('analytics')
        -> Creates 'mcp_sandbox_a1b2c3d4_analytics'

    Returns:
        Dictionary containing result or error
    """
    if not name or not re.match(r"^\w+$", name):
        return {"status": "error", "message": "Invalid database name"}
    db_name = f"{get_session_prefix()}{name}"
    return _execute_sql(f"CREATE DATABASE IF NOT EXISTS {db_name}")


def _can_use_write_tool(context: AuthContext) -> bool:
    if get_network_request() is None:
        return True
    return context.token is not None and "lake:write" in context.token.scopes


# Register all tools
mcp.add_tool(Tool.from_function(execute_sql))
mcp.add_tool(Tool.from_function(execute_multi_sql))
mcp.add_tool(Tool.from_function(show_databases))
mcp.add_tool(Tool.from_function(show_tables))
mcp.add_tool(Tool.from_function(show_functions))
mcp.add_tool(Tool.from_function(describe_table))
mcp.add_tool(Tool.from_function(show_stages))
mcp.add_tool(Tool.from_function(list_stage_files))
mcp.add_tool(Tool.from_function(show_connections))
mcp.add_tool(Tool.from_function(create_stage, auth=_can_use_write_tool))
mcp.add_tool(Tool.from_function(get_session_sandbox_prefix))
mcp.add_tool(Tool.from_function(list_session_sandbox_databases))
mcp.add_tool(Tool.from_function(create_session_sandbox_database, auth=_can_use_write_tool))


def main():
    """Main entry point for the MCP server."""
    try:
        config = get_config()
        transport = config.mcp_server_transport
        if mcp.routes_warehouse_accounts:
            if transport == TransportType.STDIO.value or config.local_mode:
                raise ValueError("Warehouse account mapping requires HTTP/SSE with remote Lake connections")
        elif not config.local_mode:
            _ = config.dsn

        logger.info(f"Starting Lake MCP server with transport: {transport}")

        # For HTTP and SSE transports, we need to specify host and port
        http_transports = [TransportType.HTTP.value, TransportType.SSE.value]
        if transport in http_transports:
            # Use the configured bind host (defaults to 127.0.0.1, can be set to 0.0.0.0)
            # and bind port (defaults to 8001)
            options = network_run_options(config, mcp.auth)
            options.pop("middleware")  # Installed by LakeMCP.http_app.
            mcp.run(
                transport=transport,
                port=config.mcp_bind_port,
                **options,
            )
        else:
            # For stdio transport, no host or port is needed
            mcp.run(transport=transport)
    except KeyboardInterrupt:
        logger.info("Shutting down server by user request")
    except Exception as e:
        logger.error("Server startup failed (%s)", type(e).__name__)
        sys.exit(1)


if __name__ == "__main__":
    main()
