# MCP Server for TiDB Cloud Lake

[![PyPI - Version](https://img.shields.io/pypi/v/tidbcloudlake-mcp)](https://pypi.org/project/tidbcloudlake-mcp)

Connect AI agents to your TiDB Cloud Lake database safely. Session sandbox keeps production read-only while agents experiment. Works with Codex, Cursor, Claude Code, Gemini CLI, and any MCP-compatible client.

## Usage

1. Get your TiDB Cloud Lake DSN.
   Format: `lake://user:password@host:port/database?warehouse=your_warehouse`
   Get it from TiDB Cloud Lake or your project connection settings.
2. Session sandbox safety: writes only to `mcp_sandbox_{session_id}_*`; production stays read-only.
   Use `get_session_sandbox_prefix` to retrieve the live prefix.
3. Configure your MCP client.

**Standard config** works in most tools:

```js
{
  "mcpServers": {
    "lake-mcp": {
      "command": "uv",
      "args": ["tool", "run", "--from", "tidbcloudlake-mcp@latest", "lake-mcp"],
      "env": {
        "LAKE_DSN": "lake://user:password@host:port/database?warehouse=your_warehouse"
      }
    }
  }
}
```

<details>
<summary>Codex</summary>

```bash
codex mcp add lake-mcp \
  --env LAKE_DSN='lake://user:password@host:port/database?warehouse=your_warehouse' \
  -- uv tool run --from tidbcloudlake-mcp@latest lake-mcp
```

</details>

<details>
<summary>Claude Code</summary>

```bash
claude mcp add lake-mcp \
  --env LAKE_DSN='lake://user:password@host:port/database?warehouse=your_warehouse' \
  -- uv tool run --from tidbcloudlake-mcp@latest lake-mcp
```

</details>

<details>
<summary>Cursor</summary>

Add a new MCP server with command `uv tool run --from tidbcloudlake-mcp@latest lake-mcp`, then set `LAKE_DSN` in the env section.

```json
{
  "mcpServers": {
    "lake-mcp": {
      "command": "uv tool run --from tidbcloudlake-mcp@latest lake-mcp",
      "env": {
        "LAKE_DSN": "lake://user:password@host:port/database?warehouse=your_warehouse"
      },
      "args": []
    }
  }
}
```

</details>

<details>
<summary>Gemini CLI</summary>

Add the standard config above to your Gemini CLI `settings.json`.

</details>

## Safety Guarantees

| Scope | Rules |
|-------|-------|
| Read access | `SELECT/SHOW/DESCRIBE/EXPLAIN/LIST` on any object. `EXPLAIN`/`WITH` only stay read-only when the statement they wrap is a read. |
| Statement scope | One statement per call. Stacked `;`-separated statements are rejected; use `execute_multi_sql` for batches. |
| Tool arguments | `database`/`table`/`stage` accept plain identifiers or quoted ones (`` `my-db` ``, `"my-db"`) plus Databend's `$` character; `@~` / `@%table` stages and non-ASCII stage paths are supported. `url` and `connection_name` are escaped as string literals, and `filter` accepts one expression (a `;` is rejected only when it is outside a string literal). Argument validation applies even when `LAKE_MCP_SAFE_MODE=false`. |
| Write access | Only objects prefixed with `mcp_sandbox_{session_id}_*`. |
| Sandbox objects | `CATALOG`, `DATABASE`, `TABLE`, `VIEW`, `STAGE`, `FUNCTION`, `USER`, `ROLE`, `TASK`, `PIPE`, `STREAM`, `CONNECTION`, `WAREHOUSE`, `SEQUENCE`, `PROCEDURE`, `DICTIONARY`, `TAG`, `FILE FORMAT`, `NETWORK POLICY`, `PASSWORD POLICY`, `MASKING POLICY`, `ROW ACCESS POLICY`, `NOTIFICATION INTEGRATION`, `WORKLOAD GROUP`, `DYNAMIC TABLE`, `INDEX` (AGGREGATING/INVERTED/NGRAM/VECTOR). |
| Write rules | `CREATE/CREATE OR REPLACE/DROP/ALTER` on sandbox objects (every DROP/TRUNCATE target - a defensive check, the Databend parser itself rejects multi-target lists; plus `RENAME TO`/`SWAP WITH` destinations, where a bare name means "same database"); DML only on sandbox tables (`INSERT/UPDATE/DELETE/TRUNCATE/COPY/MERGE/REPLACE`); `GRANT/REVOKE` only on sandbox objects/principals and never on global wildcards; `ALTER ... SET|UNSET TAG` requires sandbox tag + target; `CREATE TASK|PIPE|DYNAMIC TABLE|INDEX ... AS` bodies are validated like top-level statements and `CREATE STREAM ... ON TABLE` only sandbox refs; `REMOVE @stage` only sandbox stages. |

## Upgrade notes (0.4.0)

This release is a minor bump because a few calls that used to be accepted are now rejected. Review the points below before upgrading.

- **One statement per call.** `execute_sql` executes exactly one SQL statement; stacked `;`-separated statements are rejected by the gate instead of being forwarded to the engine. Use `execute_multi_sql` (which takes a list of statements) for batches. Scripts that relied on passing several statements in one call must be updated; the multi-statement error is now the gate's "Multiple SQL statements are not allowed in one call" message rather than the engine's `SyntaxException`.
- **Tool arguments are parsed and rebuilt.** `database`, `table` and `stage` arguments accept plain identifiers, quoted identifiers (`` `my-db` ``, `"my-db"`), Databend's `$` character, and non-ASCII/space characters inside quotes. Stage arguments accept `@~` (user stage) and `@%table` (table stage). `filter` accepts a single SQL expression; `;` and `--` are only rejected outside a string literal, so values such as `name = 'a;b'` keep working. Argument validation applies even when `LAKE_MCP_SAFE_MODE=false`.
- **`EXPLAIN` is read-only only when the statement it wraps is a read.** `EXPLAIN SELECT ...`, `EXPLAIN MEMO/PERF/DECORRELATED ...` and `EXPLAIN(...)` forms are allowed; `EXPLAIN ANALYZE DELETE ...` and `EXPLAIN DROP ...` are rejected.
- **`WITH ... <write>` is allowed** as long as the write targets a sandbox object; objects referenced inside the CTE definition bodies are still validated by the same rules.
- **`create_stage(connection_name=...)` is escaped as a string literal** instead of being validated as an identifier, so connection names containing `-`, `.` or `$` work again.

## Available Tools

| Tool | Description |
|------|-------------|
| `execute_sql` | Execute SQL with sandbox validation |
| `execute_multi_sql` | Execute multiple SQL statements |
| `show_databases` | List all databases |
| `show_tables` | List tables in database |
| `describe_table` | Get table schema |
| `get_session_sandbox_prefix` | Get current session prefix |
| `list_session_sandbox_databases` | List sandbox databases |
| `create_session_sandbox_database` | Create sandbox database |
| `show_stages` / `list_stage_files` / `create_stage` | Stage management |
| `show_connections` | List connections |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LAKE_DSN` | - | Connection string |
| `LOCAL_MODE` | `false` | Use the embedded local engine |
| `LAKE_QUERY_TIMEOUT` | `300` | Query timeout (seconds) |
| `LAKE_MCP_SAFE_MODE` | `true` | Enable sandbox validation. Set to `false` to allow all SQL permitted by the configured user. |
| `LAKE_MCP_SERVER_TRANSPORT` | `stdio` | Transport: `stdio`, `http`, `sse` |
| `LAKE_MCP_BIND_HOST` | `127.0.0.1` | Bind host for HTTP/SSE |
| `LAKE_MCP_BIND_PORT` | `8001` | Bind port for HTTP/SSE |

Local mode stores data in `.databend/`.

## Development

```bash
git clone https://github.com/tidbcloud/lake-mcp
cd lake-mcp
uv sync

# Run locally
uv run python -m lake_mcp.main

# Debug
npx @modelcontextprotocol/inspector uv run python -m lake_mcp.main

# Test
uv run pytest
```

### Security configuration

The sandbox gate is an additional client-side guard; the warehouse user still
needs the minimum database grants. A stdio process belongs to its local caller.
A shared HTTP/SSE process does not provide per-user database or tenant isolation.

For HTTP/SSE, set `LAKE_MCP_AUTH_TOKEN` to enable bearer authentication and
`LAKE_MCP_REQUIRE_AUTH=true` to fail startup if it is missing. Clients must send
`Authorization: Bearer <token>`. Keep a plaintext listener on a trusted interface
or use your existing HTTPS endpoint. A shared bearer token authenticates access
to this process; it does not create separate warehouse identities. The legacy
unauthenticated local configuration is preserved unless strict mode is selected.

Environment files are now explicit: set `LAKE_MCP_ENV_FILE` to an absolute file
path when needed. Parent-directory `.env` discovery is disabled so an unrelated
file cannot disable safe mode or redirect the connection. Existing environment
variables retain precedence. Launchers that relied on automatic discovery must
set this path or provide environment variables directly.

SHOW `filter` remains a SQL expression and reads remain available subject to the
warehouse user's grants. Storage connections and stage URLs are also constrained
by warehouse grants and server policy; this client is not an SSRF or multi-user
security boundary. Do not grant an untrusted shared MCP process administrative
or production storage permissions.
