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
| Tool arguments | `database`/`table`/`stage` accept plain identifiers or quoted ones (`` `my-db` ``, `"my-db"`) plus Databend's `$` character; `@~` / `@%table` stages and non-ASCII stage paths are supported. `url` and `connection_name` are escaped as string literals, and `filter` accepts a column compared with one scalar literal. Argument validation applies even when `LAKE_MCP_SAFE_MODE=false`. |
| Write access | Only objects prefixed with `mcp_sandbox_{session_id}_*`. |
| Sandbox objects | `DATABASE`, managed `TABLE`, `VIEW`, internal `STAGE`, `FUNCTION`, `USER`, `ROLE`, `TASK`, `PIPE`, `STREAM`, `WAREHOUSE`, `SEQUENCE`, `PROCEDURE`, `DICTIONARY`, `TAG`, `FILE FORMAT`, `NETWORK POLICY`, `PASSWORD POLICY`, `MASKING POLICY`, `ROW ACCESS POLICY`, `NOTIFICATION INTEGRATION`, `WORKLOAD GROUP`, `DYNAMIC TABLE`, `INDEX` (AGGREGATING/INVERTED/NGRAM/VECTOR). |
| Write rules | `CREATE/CREATE OR REPLACE/DROP/ALTER` on sandbox objects (every DROP/TRUNCATE target - a defensive check, the Databend parser itself rejects multi-target lists; plus `RENAME TO`/`SWAP WITH` destinations, where a bare name means "same database"); DML only on sandbox tables (`INSERT/UPDATE/DELETE/TRUNCATE/COPY/MERGE/REPLACE`); `GRANT/REVOKE` only on sandbox objects/principals and never on global wildcards; `ALTER ... SET|UNSET TAG` requires sandbox tag + target; `CREATE TASK|PIPE|DYNAMIC TABLE|INDEX ... AS` bodies are validated like top-level statements and `CREATE STREAM ... ON TABLE` only sandbox refs. |
| Storage boundary | A sandbox name does not establish ownership of its storage. Safe mode rejects external stage creation, connection/catalog configuration, table location/connection overrides and unmanaged table engines. `REMOVE` is rejected even for prefixed stages because an existing stage may point at non-sandbox files. |

### Storage safety changes

- In safe mode, use `create_stage(name)` without a URL or connection to create an internal stage. `CREATE STAGE ... FILE_FORMAT=(...) COMMENT='...'` remains available through `execute_sql`. `create_stage(name, url, connection_name)` retains its arguments for trusted local administration, but safe mode rejects external storage bindings.
- Safe mode allows managed/default tables and explicit `ENGINE=FUSE`, `MEMORY` or `NULL`; `STORAGE_FORMAT` remains available. It rejects storage location/connection overrides, database default storage connection/path changes, attached data or snapshot paths, bare storage URIs and external engines, including `CREATE OR REPLACE` and deferred SQL bodies. Stage configuration changes through `ALTER STAGE` are also restricted to the internal-stage options above.
- `REMOVE` is unavailable in safe mode. A stage's prefix alone cannot prove that deleting its files is safe. Use a separately authorized storage cleanup procedure; do not disable safe mode for an untrusted agent.
- Trusted local administration retains these operations only with both `LAKE_MCP_SAFE_MODE=false` and `LAKE_MCP_ALLOW_STDIO_ADMIN=1`. HTTP/SSE always enforces the sandbox and cannot use this opt-out.

## Upgrade notes (0.4.0)

This release is a minor bump because a few calls that used to be accepted are now rejected. Review the points below before upgrading.

- **One statement per call.** `execute_sql` executes exactly one SQL statement; stacked `;`-separated statements are rejected by the gate instead of being forwarded to the engine. Use `execute_multi_sql` (which takes a list of statements) for batches. Scripts that relied on passing several statements in one call must be updated; the multi-statement error is now the gate's "Multiple SQL statements are not allowed in one call" message rather than the engine's `SyntaxException`.
- **Tool arguments are parsed and rebuilt.** `database`, `table` and `stage` arguments accept plain identifiers, quoted identifiers (`` `my-db` ``, `"my-db"`), Databend's `$` character, and non-ASCII/space characters inside quotes. Stage arguments accept `@~` (user stage) and `@%table` (table stage). `filter` accepts one scalar comparison such as `name LIKE 'test%'` or `name = 'a;b'`. Use `execute_sql` for advanced queries. Argument validation applies even when `LAKE_MCP_SAFE_MODE=false`.
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
| `show_stages` / `list_stage_files` / `create_stage` | Stage reads and internal stage creation in safe mode |
| `show_connections` | List connections |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LAKE_DSN` | - | Connection string for a single-owner instance |
| `LAKE_MCP_WAREHOUSE_MAP_FILE` | - | Absolute path to a JWT subject-to-connection map for shared HTTP/SSE |
| `LOCAL_MODE` | `false` | Use the embedded local engine |
| `LAKE_QUERY_TIMEOUT` | `300` | Query timeout (seconds) |
| `LAKE_MCP_SAFE_MODE` | `true` | Enable sandbox validation. Disabling the sandbox requires an explicit local admin opt-in. |
| `LAKE_MCP_ALLOW_STDIO_ADMIN` | `0` | Set to `1` for trusted local account administration. |
| `LAKE_MCP_AUTH_TOKEN_FILE` | - | Private bearer-token file for a single-owner network listener. |
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

Network clients send an `Authorization: Bearer <token>` header. Use the
listener and credential policies below to configure the transport.

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

### Network listener security

For warehouse connections, provide an explicit `LAKE_DSN` or use
`LOCAL_MODE=true` for the embedded engine. TLS is required for remote DSNs.
Local development may use `sslmode=disable` explicitly on a loopback endpoint.

HTTP/SSE requires a configured bearer token or JWT verification. Use a randomly
generated static token of at least 32 bytes, or set `LAKE_MCP_AUTH_JWKS_URI`
(HTTPS), `LAKE_MCP_AUTH_ISSUER`, `LAKE_MCP_AUTH_AUDIENCE`, and
`LAKE_MCP_AUTH_SUBJECT` for expiring JWTs. The subject identifies the one owner
authorized to use the process's warehouse credentials. JWTs require the `lake`
scope for reads and `lake:write` for sandbox writes.
HTTP/SSE always enforces the sandbox and excludes account/role administration.
In stdio, set `LAKE_MCP_ALLOW_STDIO_ADMIN=1` explicitly to allow account and
role administration. Disabling safe mode also requires that opt-in.
Privileged operations log the principal, transport, and operation type.
Use `LAKE_MCP_AUTH_TOKEN_FILE` instead of the environment token if the
single-owner network listener needs live token rotation.
Stdio remains local and needs no network token. For an intentionally anonymous,
read-only development listener, set `LAKE_MCP_ALLOW_INSECURE_HTTP=true` and
bind to loopback.

Non-loopback listeners require `LAKE_MCP_TLS_CERTFILE` and
`LAKE_MCP_TLS_KEYFILE`. When a trusted proxy terminates TLS, use a loopback
listener where possible. Set `LAKE_MCP_TRUST_TLS_PROXY=1` only when the cleartext
listener is isolated behind that proxy. `LAKE_MCP_ALLOWED_HOSTS` accepts exact
hostnames only.

HTTP and SSE sessions get distinct write sandbox prefixes. In single-owner mode,
share the instance only with clients that should have the same warehouse
permissions. Use stateful HTTP for sandbox writes.

### Shared HTTP/SSE with separate warehouse accounts

To serve users with different warehouse permissions from the same process,
configure `LAKE_MCP_AUTH_JWKS_URI`, `LAKE_MCP_AUTH_ISSUER`, and
`LAKE_MCP_AUTH_AUDIENCE` as above. Set `LAKE_MCP_WAREHOUSE_MAP_FILE` to the
absolute path of a private JSON file. Leave `LAKE_MCP_AUTH_SUBJECT` and
`LAKE_MCP_AUTH_TOKEN` unset. For example, using placeholder credentials:

```json
{
  "alice-subject": "lake://alice:password@warehouse.example:443/alice_db",
  "bob-subject": "lake://bob:password@warehouse.example:443/bob_db"
}
```

Keys are the verified JWT `sub` values. Each entry uses a distinct Lake
account over TLS. Prefer a DSN that references an absolute `access_token_file`
or `private_key_file` path provisioned by your secret manager. Legacy
password DSNs are supported in a private map file. Grant each account only the
databases, tables, and stages that its user should be able to access. The server
uses that account for every query by that subject. Unmapped subjects are
rejected and never use `LAKE_DSN`. The `lake` scope allows reads, and
`lake:write` additionally permits writes in the caller's sandbox where the
warehouse account has the necessary grants. Clients without the write scope
cannot list or call the dedicated write tools.

Restrict credential files and the map to the service owner on POSIX
(for example, mode `0600`). Replace the files atomically when rotating
credentials or removing an identity. The server re-reads the map for new
requests and rejects unavailable or invalid mappings.

Safe mode accepts SQL lambda functions and procedures containing a single
validated read query. Use trusted local stdio for other routine definitions.

A process and its configured bearer token form one owner/trust domain. The
128-bit sandbox prefix prevents accidental name collisions, and is deliberately
public to that owner; it is not an authentication token or a replacement for
warehouse grants. Run separate processes/credentials for untrusted owners.
