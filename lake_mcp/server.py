import atexit
import concurrent.futures
import logging
import re
import sys
from typing import Optional

import pyarrow as pa
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.tools import Tool

from .env import TransportType, get_config
from .safety import SESSION_ID, check_sql_safety, get_session_prefix

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
load_dotenv()

# Initialize MCP server
mcp = FastMCP(SERVER_NAME)

# Global Lake client singleton
_lake_client = None

# Tool arguments are interpolated into SQL text, so they are validated (or
# escaped) here instead of being pasted in raw: the safety gate sees the
# finished statement, and a `;` smuggled through an argument would otherwise
# ride on the approval of the statement's read-only prefix.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_QUALIFIED_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_STAGE_PATH_RE = re.compile(r"^[A-Za-z0-9_.*?=%+/\-]*$")
_SQL_FRAGMENT_FORBIDDEN_RE = re.compile(r";|--|/\*|\*/")


def _invalid_argument(argument: str, expected: str) -> dict:
    """Build the error returned when a tool argument fails validation."""
    return {"status": "error", "message": f"Invalid {argument}: {expected}"}


def _is_identifier(value: str) -> bool:
    return bool(_IDENTIFIER_RE.match(value))


def _is_qualified_identifier(value: str) -> bool:
    return bool(_QUALIFIED_IDENTIFIER_RE.match(value))


def _escape_sql_literal(value: str) -> str:
    """Escape a value that is placed inside a single-quoted SQL literal."""
    return value.replace("\\", "\\\\").replace("'", "''")


def get_global_lake_client():
    """Get global Lake client instance."""
    global _lake_client
    if _lake_client is None:
        _lake_client = create_lake_client()
    return _lake_client


def create_lake_client():
    """Create and return a Lake client instance."""
    config = get_config()

    if config.local_mode:
        logger.info("Creating local Lake client")
        # Use the local in-memory engine
        import databend

        return databend.SessionContext()
    else:
        logger.info("Creating remote Lake client")
        from tidbcloudlake_driver import BlockingLakeClient

        return BlockingLakeClient(config.dsn)


def execute_lake_query(sql: str) -> list[dict] | dict:
    """
    Execute a SQL query against TiDB Cloud Lake and return results.

    Args:
        sql: SQL query string to execute

    Returns:
        List of dictionaries containing query results or error dictionary
    """
    client = get_global_lake_client()
    config = get_config()

    try:
        if config.local_mode:
            # Handle the local in-memory engine
            result = client.sql(sql)
            df = result.to_py_arrow()
            return recordbatches_to_dicts(df)
        else:
            # Handle remote TiDB Cloud Lake service
            conn = client.get_conn()
            cursor = conn.query_iter(sql)
            column_names = [field.name for field in cursor.schema().fields()]
            results = []

            for row in cursor:
                row_data = dict(zip(column_names, list(row.values())))
                results.append(row_data)

            logger.info(f"Query executed successfully, returned {len(results)} rows")
            return results

    except Exception as err:
        error_msg = f"Error executing query: {str(err)}"
        logger.error(error_msg)
        return {"error": error_msg}


def recordbatches_to_dicts(batches: list[pa.RecordBatch]) -> list[dict]:
    results = []
    for batch in batches:
        columns = batch.schema.names
        columns_data = [batch.column(i).to_pylist() for i in range(batch.num_columns)]
        for row in zip(*columns_data):
            results.append(dict(zip(columns, row)))
    return results


def _execute_sql(sql: str) -> dict:
    logger.info(f"Executing SQL query: {sql}")

    config = get_config()

    if config.safe_mode:
        # Code-enforced safety check - cannot be bypassed while safe mode is enabled
        result = check_sql_safety(sql)
        if not result.allowed:
            logger.warning(f"Query blocked: {result.reason} - SQL: {sql}")
            return {"status": "error", "message": result.reason}
    else:
        logger.warning("LAKE_MCP_SAFE_MODE=false: sandbox safety check is disabled")

    try:
        # Submit query to thread pool
        future = QUERY_EXECUTOR.submit(execute_lake_query, sql)
        query_timeout = config.query_timeout
        try:
            # Wait for query to complete with timeout
            result = future.result(timeout=query_timeout)

            if isinstance(result, dict) and "error" in result:
                error_msg = f"Query execution failed: {result['error']}"
                logger.warning(error_msg)
                return {"status": "error", "message": error_msg}

            # Ensure we always return a dict structure for fastmcp compatibility
            if isinstance(result, list):
                return {"status": "success", "data": result, "row_count": len(result)}
            else:
                return {"status": "success", "data": result}

        except concurrent.futures.TimeoutError:
            error_msg = f"Query timed out after {query_timeout} seconds"
            logger.warning(f"{error_msg}: {sql}")
            future.cancel()
            return {"status": "error", "message": error_msg}

    except Exception as e:
        error_msg = f"Unexpected error in query execution: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}


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
        database = database.strip()
        if not _is_qualified_identifier(database):
            return _invalid_argument("database", "expected a SQL identifier, e.g. 'analytics' or 'analytics.events'")
        sql += f" FROM {database}"
    if filter is not None:
        if not filter.strip() or _SQL_FRAGMENT_FORBIDDEN_RE.search(filter):
            return _invalid_argument("filter", "expected a single SQL expression without ';' or comment markers")
        sql += f" WHERE {filter}"
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
        if not filter.strip() or _SQL_FRAGMENT_FORBIDDEN_RE.search(filter):
            return _invalid_argument("filter", "expected a single SQL expression without ';' or comment markers")
        sql += f" WHERE {filter}"
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
    table = table.strip()
    if not _is_qualified_identifier(table):
        return _invalid_argument("table", "expected a SQL identifier, e.g. 'users' or 'analytics.users'")
    if database is not None:
        database = database.strip()
        if not _is_qualified_identifier(database):
            return _invalid_argument("database", "expected a SQL identifier, e.g. 'analytics'")
        table = f"{database}.{table}"
    logger.info(f"Describing table '{table}'")
    sql = f"DESCRIBE TABLE {table}"
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
    stage_name = stage_name.strip()
    if stage_name.startswith("@"):
        stage_name = stage_name[1:]
    if not _is_qualified_identifier(stage_name):
        return _invalid_argument("stage_name", "expected a stage name, e.g. 'mystage' or '@mystage'")
    stage_name = f"@{stage_name}"

    if path:
        path = path.strip()
        if not _STAGE_PATH_RE.match(path):
            return _invalid_argument("path", "expected a stage path made of letters, digits and _-./*?=%+")
        stage_path = f"{stage_name}/{path.strip('/')}"
    else:
        stage_path = stage_name

    logger.info(f"Listing files in stage '{stage_path}'")
    sql = f"LIST {stage_path}"
    return _execute_sql(sql)


def show_connections():
    """List available TiDB Cloud Lake connections (safe operation, not affected by MCP safe mode)."""
    logger.info("Listing all connections")
    return _execute_sql("SHOW CONNECTIONS")


def create_stage(name: str, url: str, connection_name: Optional[str] = None) -> dict:
    """
    Create a TiDB Cloud Lake stage with a connection.
    Args:
        name: The stage name
        url: The stage URL (e.g., 's3://bucket-name')
        connection_name: Optional connection name to use

    Returns:
        Dictionary containing either query results or error information
    """
    logger.info(f"Creating stage '{name}' with URL '{url}'")

    name = name.strip()
    if not _is_identifier(name):
        return _invalid_argument("name", "expected a stage name, e.g. 'mystage'")
    if not url or not url.strip():
        return _invalid_argument("url", "expected a non-empty stage URL, e.g. 's3://bucket-name'")

    sql_parts = [f"CREATE STAGE {name}", f"URL = '{_escape_sql_literal(url)}'"]

    if connection_name:
        connection_name = connection_name.strip()
        if not _is_identifier(connection_name):
            return _invalid_argument("connection_name", "expected a connection name, e.g. 'myconnection'")
        sql_parts.append(f"CONNECTION = (CONNECTION_NAME = '{connection_name}')")

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
    return {
        "session_id": SESSION_ID,
        "prefix": get_session_prefix(),
        "example_database": f"{get_session_prefix()}mydb",
        "example_table": f"{get_session_prefix()}mydb.mytable",
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
mcp.add_tool(Tool.from_function(create_stage))
mcp.add_tool(Tool.from_function(get_session_sandbox_prefix))
mcp.add_tool(Tool.from_function(list_session_sandbox_databases))
mcp.add_tool(Tool.from_function(create_session_sandbox_database))


def main():
    """Main entry point for the MCP server."""
    try:
        config = get_config()
        transport = config.mcp_server_transport

        logger.info(f"Starting Lake MCP server with transport: {transport}")

        # For HTTP and SSE transports, we need to specify host and port
        http_transports = [TransportType.HTTP.value, TransportType.SSE.value]
        if transport in http_transports:
            # Use the configured bind host (defaults to 127.0.0.1, can be set to 0.0.0.0)
            # and bind port (defaults to 8001)
            mcp.run(
                transport=transport,
                host=config.mcp_bind_host,
                port=config.mcp_bind_port,
            )
        else:
            # For stdio transport, no host or port is needed
            mcp.run(transport=transport)
    except KeyboardInterrupt:
        logger.info("Shutting down server by user request")
    except Exception as e:
        logger.error(f"Server startup failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
