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
| Write access | Only objects prefixed with `mcp_sandbox_{session_id}_*`. |
| Sandbox objects | `CATALOG`, `DATABASE`, `TABLE`, `VIEW`, `STAGE`, `FUNCTION`, `USER`, `ROLE`, `TASK`, `PIPE`, `STREAM`, `CONNECTION`, `WAREHOUSE`, `SEQUENCE`, `PROCEDURE`, `DICTIONARY`, `TAG`, `FILE FORMAT`, `NETWORK POLICY`, `PASSWORD POLICY`, `MASKING POLICY`, `ROW ACCESS POLICY`, `NOTIFICATION INTEGRATION`, `WORKLOAD GROUP`, `DYNAMIC TABLE`, `INDEX` (AGGREGATING/INVERTED/NGRAM/VECTOR). |
| Write rules | `CREATE/CREATE OR REPLACE/DROP/ALTER` on sandbox objects; DML only on sandbox tables (`INSERT/UPDATE/DELETE/TRUNCATE/COPY/MERGE/REPLACE`); `GRANT/REVOKE` only on sandbox objects/principals; `ALTER ... SET|UNSET TAG` requires sandbox tag + target; `CREATE TASK|PIPE|DYNAMIC TABLE|INDEX ... AS` and `CREATE STREAM ... ON TABLE` only sandbox refs; `REMOVE @stage` only sandbox stages. |

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
