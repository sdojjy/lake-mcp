"""SQL Safety module - Code-enforced constraints for AI SQL operations.

Session-level isolation ensures each MCP session can only modify objects
with its unique sandbox prefix: mcp_sandbox_{session_id}_

DEFENSE STRATEGY: Database-level permissions + MCP validation
1. Database user should have LIMITED permissions (only on sandbox databases)
2. MCP validates SQL as additional safety layer
3. Default DENY - only explicitly allowed patterns pass

ARCHITECTURE: Modular rule-based system
- Each rule is independent and can be modified/added/removed easily
- Rules are checked in order, first match wins
"""

import re
import secrets
import threading
from dataclasses import dataclass
from typing import Callable

# Session ID: generated at server startup, constant for process lifetime
SESSION_ID = secrets.token_hex(16)
SANDBOX_PREFIX = "mcp_sandbox_"

# Maximum nesting of deferred statements (TASK/PIPE/DYNAMIC TABLE bodies).
MAX_NESTED_SQL_DEPTH = 3

IDENTIFIER_ATOM = r'(?:`(?:``|[^`])+`|"(?:""|[^"])+"|\w+)'
IDENTIFIER_PATTERN = rf"{IDENTIFIER_ATOM}(?:\s*\.\s*{IDENTIFIER_ATOM})?"
# DROP/TRUNCATE accept comma-separated target lists; every target must be checked.
IDENTIFIER_LIST_PATTERN = rf"{IDENTIFIER_PATTERN}(?:\s*,\s*{IDENTIFIER_PATTERN})*"
INDEX_TYPE_PATTERN = r"(?:AGGREGATING|INVERTED|NGRAM|VECTOR)"
CREATE_OR_REPLACE_OBJECTS = (
    r"(?:TABLE|VIEW|FUNCTION|STAGE|TASK|PIPE|STREAM|WAREHOUSE|SEQUENCE|PROCEDURE|DICTIONARY"
    r"|FILE\s+FORMAT|NETWORK\s+POLICY|PASSWORD\s+POLICY|(?:TRANSIENT\s+)?DYNAMIC\s+TABLE)"
)
CREATE_DROP_OBJECTS = (
    r"(?:CATALOG|DATABASE|TABLE|VIEW|STAGE|FUNCTION|USER|ROLE|TASK|PIPE|STREAM|CONNECTION|WAREHOUSE"
    r"|SEQUENCE|PROCEDURE|DICTIONARY|TAG|FILE\s+FORMAT|NETWORK\s+POLICY|PASSWORD\s+POLICY"
    r"|MASKING\s+POLICY|ROW\s+ACCESS\s+POLICY|NOTIFICATION\s+INTEGRATION|WORKLOAD\s+GROUP"
    r"|(?:TRANSIENT\s+)?DYNAMIC\s+TABLE)"
)
ALTER_OBJECTS = (
    r"(?:TABLE|DATABASE|VIEW|STAGE|USER|ROLE|WAREHOUSE|FUNCTION"
    r"|NETWORK\s+POLICY|PASSWORD\s+POLICY|NOTIFICATION\s+INTEGRATION|WORKLOAD\s+GROUP)"
)
TAG_TARGET_OBJECTS = r"(?:DATABASE|TABLE|STAGE|CONNECTION)"


@dataclass
class SafetyResult:
    """Result of safety check."""

    allowed: bool
    reason: str = ""


def get_session_prefix() -> str:
    """Return current session's sandbox prefix."""
    return f"{SANDBOX_PREFIX}{SESSION_ID}_"


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _normalize_sql(sql: str) -> str:
    """Remove literal data and comments, retaining quoted object identities."""
    return " ".join(t.text for t in _sql_tokens(sql) if t.kind != "literal")


def _standardize_sql(sql: str) -> str:
    """Normalize only SQL syntax; comment markers inside values remain data."""
    tokens = _sql_tokens(sql)
    parts = []
    previous = 0
    for token in tokens:
        gap = sql[previous : token.start]
        parts.append(gap if not gap.strip() else " ")
        parts.append(token.text)
        previous = token.end
    return "".join(parts).strip()


_QUOTE_CHARS = ("'", '"', "`")
_DOLLAR_QUOTE_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


def _skip_quoted(sql: str, start: int) -> int | None:
    """Return the index just past the quoted token starting at `start`, or None if unterminated."""
    quote = sql[start]
    index = start + 1
    length = len(sql)
    while index < length:
        char = sql[index]
        if char == "\\" and quote == "'":
            index += 2
            continue
        if char == quote:
            # Doubled quotes are escapes inside the literal.
            if index + 1 < length and sql[index + 1] == quote:
                index += 2
                continue
            return index + 1
        index += 1
    return None


def _split_sql_statements(sql: str) -> list[str] | None:
    """Split SQL text into statements on top-level semicolons.

    String literals, quoted identifiers, line/block comments and dollar-quoted
    bodies ($$ ... $$) are skipped so a semicolon inside them never starts a new
    statement. Returns None when the input cannot be tokenized unambiguously
    (unterminated quote or block comment); callers must treat that as a denial.
    """
    statements: list[str] = []
    current: list[str] = []
    index = 0
    length = len(sql)

    while index < length:
        char = sql[index]

        if char in _QUOTE_CHARS:
            end = _skip_quoted(sql, index)
            if end is None:
                return None
            current.append(sql[index:end])
            index = end
            continue

        if char == "$":
            dollar_match = _DOLLAR_QUOTE_RE.match(sql, index)
            if dollar_match:
                tag = dollar_match.group(0)
                end = sql.find(tag, dollar_match.end())
                if end == -1:
                    return None
                end += len(tag)
                current.append(sql[index:end])
                index = end
                continue

        if sql.startswith("--", index):
            # Line comment: skip to the end of the line, newline stays in the statement.
            end = sql.find("\n", index)
            index = length if end == -1 else end
            continue

        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            if end == -1:
                return None
            end += 2
            current.append(sql[index:end])
            index = end
            continue

        if char == ";":
            statements.append("".join(current))
            current = []
            index += 1
            continue

        current.append(char)
        index += 1

    statements.append("".join(current))
    return [statement.strip() for statement in statements if statement.strip()]


def has_top_level_separator(sql: str) -> bool:
    """Return True when `sql` contains a ``;`` outside literals and comments.

    Tool arguments that are interpolated as a SQL *expression* (the SHOW
    ``filter``) may legitimately contain ``;``, ``--`` or ``/*`` inside a string
    literal, so callers cannot just search the raw text. Unterminated literals or
    comments count as a separator (fail closed).
    """
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if char in _QUOTE_CHARS:
            end = _skip_quoted(sql, index)
            if end is None:
                return True
            index = end
            continue
        if char == "$":
            dollar_match = _DOLLAR_QUOTE_RE.match(sql, index)
            if dollar_match:
                end = sql.find(dollar_match.group(0), dollar_match.end())
                if end == -1:
                    return True
                index = end + len(dollar_match.group(0))
                continue
        if sql.startswith("--", index):
            end = sql.find("\n", index)
            index = length if end == -1 else end
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            if end == -1:
                return True
            index = end + 2
            continue
        if char == ";":
            return True
        index += 1
    return False


def _extract_identifier(identifier: str, session_prefix: str) -> tuple[str, bool]:
    tokens = _sql_tokens(identifier)
    if not tokens or tokens[0].kind not in ("word", "identifier"):
        return identifier, False
    name = _identifier_value(tokens[0])
    return name, name.lower().startswith(session_prefix.lower())


def _contains_non_sandbox_reference(sql: str, session_prefix: str, cte_names: set[str] | None = None) -> bool:
    """Inspect relation lists and subqueries without erasing quoted names."""
    return _references_outside_sandbox(_sql_tokens(sql), session_prefix, cte_names or set())


def _check_create_or_replace(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: CREATE OR REPLACE must be on sandbox objects."""
    match = _sql_search(
        rf"\bCREATE\s+OR\s+REPLACE\s+({CREATE_OR_REPLACE_OBJECTS})\s+"
        rf"(?:IF\s+(?:NOT\s+)?EXISTS\s+)?({IDENTIFIER_PATTERN})",
        sql,
        re.IGNORECASE,
    )
    if not match:
        return None

    obj_type = match.group(1).upper()
    obj_name = match.group(2)
    name, is_sandbox = _extract_identifier(obj_name, session_prefix)
    if is_sandbox:
        if obj_type in ("TASK", "PIPE") or "DYNAMIC TABLE" in obj_type:
            nested_denial = _check_nested_body(sql, f"CREATE OR REPLACE {obj_type}", session_prefix)
            if nested_denial is not None:
                return nested_denial
        if obj_type == "STREAM":
            on_table_match = _sql_search(
                rf"\bON\s+TABLE\s+({IDENTIFIER_PATTERN})",
                sql,
                re.IGNORECASE,
            )
            if on_table_match:
                table_name = on_table_match.group(1)
                name, is_sandbox = _extract_identifier(table_name, session_prefix)
                if not is_sandbox:
                    return SafetyResult(
                        allowed=False,
                        reason=f"CREATE OR REPLACE STREAM blocked: Referenced object '{name}' must start with {session_prefix}",
                    )
        return SafetyResult(allowed=True)
    return SafetyResult(
        allowed=False,
        reason=f"CREATE OR REPLACE blocked: '{name}' must start with {session_prefix}",
    )


def _check_replace_into(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: REPLACE INTO must be on sandbox objects."""
    match = _sql_search(
        r'\bREPLACE\s+INTO\s+([`\'"]?\w+[`\'"]?(?:\.[`\'"]?\w+[`\'"]?)?)',
        sql,
        re.IGNORECASE,
    )
    if not match:
        return None

    obj_name = match.group(1)
    name, is_sandbox = _extract_identifier(obj_name, session_prefix)
    if is_sandbox:
        return SafetyResult(allowed=True)
    return SafetyResult(
        allowed=False,
        reason=f"REPLACE INTO blocked: '{name}' must start with {session_prefix}",
    )


_STATEMENT_VERBS = frozenset(
    {
        "ALTER",
        "ANALYZE",
        "BEGIN",
        "CALL",
        "COMMIT",
        "COPY",
        "CREATE",
        "DELETE",
        "DESC",
        "DESCRIBE",
        "DROP",
        "EXPLAIN",
        "GRANT",
        "INSERT",
        "LIST",
        "MERGE",
        "OPTIMIZE",
        "PRAGMA",
        "REMOVE",
        "REPLACE",
        "REVOKE",
        "ROLLBACK",
        "SELECT",
        "SET",
        "SHOW",
        "TRUNCATE",
        "UNDROP",
        "UPDATE",
        "USE",
        "VACUUM",
    }
)
# Databend grammar: EXPLAIN ~ ( explain_options | explain_verbose_alias )?
#   ~ ( AST | SYNTAX | PIPELINE | JOIN | GRAPH | FRAGMENTS | RAW | OPTIMIZED
#       | MEMO | DECORRELATED | PERF )? ~ statement
# The option prefix only describes the plan output; what the policy cares about
# is the statement it wraps, so the prefix is skipped and the wrapped statement
# must still be read-only.
_EXPLAIN_OPTION_KEYWORDS = (
    "ANALYZE",
    "AST",
    "SYNTAX",
    "GRAPH",
    "PIPELINE",
    "JOIN",
    "FRAGMENTS",
    "RAW",
    "OPTIMIZED",
    "MEMO",
    "DECORRELATED",
    "PERF",
    "VERBOSE",
    # Accepted historically; harmless synonyms for the plan format.
    "TREE",
    "JSON",
    "FORMAT",
)
_EXPLAIN_OPTION_RE = re.compile(rf"^(?:{'|'.join(_EXPLAIN_OPTION_KEYWORDS)})\b\s*")
_CTE_NAME_RE = re.compile(r"\s*(?:\([^)]*\)\s*)?AS\s*\(", re.IGNORECASE)


def _first_top_level_verb(sql: str, skip_cte_names: bool = False) -> str | None:
    tokens = _sql_tokens(("WITH " if skip_cte_names else "") + sql)
    parsed = _cte_parts(tokens)
    if parsed is None:
        return None
    _, main = parsed
    return tokens[main].text.upper() if main < len(tokens) and tokens[main].kind == "word" else None


def _check_read_only(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: Allow read-only queries on ANY object.

    The read prefix must describe the *whole* statement: ``EXPLAIN ANALYZE
    DELETE ...`` and ``WITH ... DELETE ...`` are not read-only and fall through
    to the write rules below.
    """
    sql_upper = sql.strip().upper()

    if re.match(r"^EXPLAIN\b", sql_upper):
        remainder = sql_upper[len("EXPLAIN") :].lstrip()
        while remainder:
            # Parenthesised option list: EXPLAIN(LOGICAL), EXPLAIN(VERBOSE, OPTIMIZED)
            if remainder.startswith("("):
                depth = 0
                end = -1
                for position, char in enumerate(remainder):
                    if char == "(":
                        depth += 1
                    elif char == ")":
                        depth -= 1
                        if depth == 0:
                            end = position
                            break
                if end == -1:
                    return None
                remainder = remainder[end + 1 :].lstrip()
                continue
            option = _EXPLAIN_OPTION_RE.match(remainder)
            if not option:
                break
            remainder = remainder[option.end() :].lstrip()
        if not remainder:
            return None
        return _check_read_only(remainder, session_prefix)

    if re.match(r"^SELECT\b", sql_upper):
        return SafetyResult(allowed=True)
    if re.match(r"^(?:SHOW|DESCRIBE|DESC)\b", sql_upper):
        return SafetyResult(allowed=True)
    if re.match(r"^LIST\s+@", sql_upper):
        return SafetyResult(allowed=True)
    if re.match(r"^WITH\b", sql_upper):
        if _first_top_level_verb(sql_upper[len("WITH") :], skip_cte_names=True) == "SELECT":
            return SafetyResult(allowed=True)
    return None


def _check_create_drop(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: CREATE/DROP operations must be on sandbox objects."""
    # Support db.table format
    match = _sql_search(
        rf"\b(CREATE|DROP)\s+({CREATE_DROP_OBJECTS})\s+"
        rf"(?:IF\s+(?:NOT\s+)?EXISTS\s+)?({IDENTIFIER_LIST_PATTERN})",
        sql,
        re.IGNORECASE,
    )
    if not match:
        return None

    obj_type = match.group(2).upper()
    obj_names = match.group(3)

    # DROP accepts a comma-separated target list, so every target is checked -
    # approving the statement on the strength of its first (sandbox) name would
    # let "DROP TABLE sandbox.t, production.users" through.
    targets = re.findall(IDENTIFIER_PATTERN, obj_names, re.IGNORECASE) or [obj_names]
    for obj_name in targets:
        name, is_sandbox = _extract_identifier(obj_name, session_prefix)
        if not is_sandbox:
            return SafetyResult(
                allowed=False,
                reason=f"Operation blocked: '{name}' must start with {session_prefix}",
            )

    # For TASK/PIPE/DYNAMIC TABLE, the deferred body must itself be allowed:
    # the body runs later with the DSN principal's rights, so only checking its
    # FROM/JOIN references would let "CREATE TASK t AS DROP TABLE production.x"
    # (or a GRANT) through.
    if obj_type in ("TASK", "PIPE") or "DYNAMIC TABLE" in obj_type:
        nested_denial = _check_nested_body(sql, f"CREATE {obj_type}", session_prefix)
        if nested_denial is not None:
            return nested_denial

    # For STREAM, check ON TABLE reference
    if obj_type == "STREAM":
        on_table_match = _sql_search(
            rf"\bON\s+TABLE\s+({IDENTIFIER_PATTERN})",
            sql,
            re.IGNORECASE,
        )
        if on_table_match:
            table_name = on_table_match.group(1)
            name, is_sandbox = _extract_identifier(table_name, session_prefix)
            if not is_sandbox:
                return SafetyResult(
                    allowed=False,
                    reason=f"CREATE STREAM blocked: Referenced object '{name}' must start with {session_prefix}",
                )

    return SafetyResult(allowed=True)


def _extract_index_on_table(sql: str) -> str | None:
    as_match = _sql_search(r"\bAS\b", sql, re.IGNORECASE)
    sql_prefix = sql if not as_match else sql[: as_match.start()]
    on_match = _sql_search(rf"\bON\s+({IDENTIFIER_PATTERN})", sql_prefix, re.IGNORECASE)
    if on_match:
        return on_match.group(1)
    return None


def _check_index(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: INDEX operations must be on sandbox objects."""
    create_match = _sql_search(
        rf"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:ASYNC\s+)?"
        rf"(?:(?:{INDEX_TYPE_PATTERN})\s+)?INDEX\s+"
        rf"(?:IF\s+(?:NOT\s+)?EXISTS\s+)?({IDENTIFIER_PATTERN})",
        sql,
        re.IGNORECASE,
    )
    if create_match:
        index_name = create_match.group(1)
        name, is_sandbox = _extract_identifier(index_name, session_prefix)
        if not is_sandbox:
            return SafetyResult(
                allowed=False,
                reason=f"CREATE INDEX blocked: '{name}' must start with {session_prefix}",
            )

        on_table = _extract_index_on_table(sql)
        if on_table:
            name, is_sandbox = _extract_identifier(on_table, session_prefix)
            if not is_sandbox:
                return SafetyResult(
                    allowed=False,
                    reason=f"CREATE INDEX blocked: Referenced object '{name}' must start with {session_prefix}",
                )

        nested_denial = _check_nested_body(sql, "CREATE INDEX", session_prefix)
        if nested_denial is not None:
            return nested_denial

        return SafetyResult(allowed=True)

    drop_match = _sql_search(
        rf"\bDROP\s+(?:(?:{INDEX_TYPE_PATTERN})\s+)?INDEX\s+"
        rf"(?:IF\s+EXISTS\s+)?({IDENTIFIER_PATTERN})",
        sql,
        re.IGNORECASE,
    )
    if drop_match:
        index_name = drop_match.group(1)
        name, is_sandbox = _extract_identifier(index_name, session_prefix)
        if not is_sandbox:
            return SafetyResult(
                allowed=False,
                reason=f"DROP INDEX blocked: '{name}' must start with {session_prefix}",
            )

        on_table = _extract_index_on_table(sql)
        if on_table:
            name, is_sandbox = _extract_identifier(on_table, session_prefix)
            if not is_sandbox:
                return SafetyResult(
                    allowed=False,
                    reason=f"DROP INDEX blocked: Referenced object '{name}' must start with {session_prefix}",
                )

        return SafetyResult(allowed=True)

    return None


def _check_tag_actions(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: ALTER ... SET/UNSET TAG must be on sandbox objects and tags."""
    if not _sql_search(r"\b(?:SET|UNSET)\s+TAG\b", sql, re.IGNORECASE):
        return None

    target_match = _sql_search(
        rf"^ALTER\s+({TAG_TARGET_OBJECTS})\s+({IDENTIFIER_PATTERN})\s+(?:SET|UNSET)\s+TAG\s+(.+)$",
        sql,
        re.IGNORECASE,
    )
    if not target_match:
        return SafetyResult(
            allowed=False,
            reason=f"ALTER TAG blocked: target object must start with {session_prefix}",
        )

    target_name = target_match.group(2)
    name, is_sandbox = _extract_identifier(target_name, session_prefix)
    if not is_sandbox:
        return SafetyResult(
            allowed=False,
            reason=f"ALTER TAG blocked: '{name}' must start with {session_prefix}",
        )

    # A tag rule must never short-circuit the destination checks on an ALTER.
    if _sql_search(r"\b(?:RENAME\s+TO|SWAP\s+WITH)\b", sql, re.IGNORECASE):
        return SafetyResult(False, "ALTER TAG blocked: cannot combine tag and object move operations")

    tag_items = [item.strip() for item in target_match.group(3).split(",") if item.strip()]
    if not tag_items:
        return SafetyResult(
            allowed=False,
            reason=f"ALTER TAG blocked: tag names must start with {session_prefix}",
        )

    for item in tag_items:
        tag_name = item.split("=")[0].strip().strip("`'\"")
        name, is_sandbox = _extract_identifier(tag_name, session_prefix)
        if not is_sandbox:
            return SafetyResult(
                allowed=False,
                reason=f"ALTER TAG blocked: '{name}' must start with {session_prefix}",
            )

    return SafetyResult(allowed=True)


def _is_qualified_name(name: str) -> bool:
    """Dots inside quoted names are data; dots between components qualify them."""
    return any(t.text == "." and t.kind == "symbol" for t in _sql_tokens(name))


def _check_alter(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: ALTER operations must be on sandbox objects."""
    # Reject partial matches of unsupported multi-part identifiers.
    target = rf"({IDENTIFIER_PATTERN})(?=\s|$)(?!\s*\.)"
    match = _sql_search(
        rf"^ALTER\s+({ALTER_OBJECTS})\s+{target}",
        sql,
        re.IGNORECASE,
    )
    if not match:
        return None

    obj_type = match.group(1).upper()
    obj_name = match.group(2)
    source_is_qualified = _is_qualified_name(obj_name)

    name, is_sandbox = _extract_identifier(obj_name, session_prefix)
    if not is_sandbox:
        return SafetyResult(
            allowed=False,
            reason=f"ALTER blocked: '{name}' must start with {session_prefix}",
        )

    # RENAME TO / SWAP WITH move or exchange objects, so their destination must
    # stay inside the sandbox: "ALTER TABLE sandbox.t RENAME TO production.pwned"
    # and "ALTER TABLE sandbox.t SWAP WITH production.users" write outside it.
    for keyword in ("RENAME TO", "SWAP WITH"):
        keyword_pattern = r"\s+".join(keyword.split())
        for move in _sql_finditer(rf"\b{keyword_pattern}\b", sql, re.IGNORECASE):
            dest_match = re.match(rf"\s+{target}", sql[move.end() :])
            if dest_match is None:
                return SafetyResult(False, f"ALTER {keyword} blocked: invalid destination")
            destination = dest_match.group(1)
            dest_name, dest_is_sandbox = _extract_identifier(destination, session_prefix)
            if _is_qualified_name(destination):
                if not dest_is_sandbox:
                    return SafetyResult(
                        allowed=False,
                        reason=f"ALTER {keyword} blocked: '{dest_name}' must start with {session_prefix}",
                    )
                continue
            # Databend only accepts a bare destination ("RENAME TO t2"), which
            # stays in the source object's database. That is safe when the
            # destination already carries the prefix, or when the source is
            # database-qualified so its database is the known sandbox one.
            if dest_is_sandbox:
                continue
            if obj_type in ("TABLE", "VIEW") and source_is_qualified:
                continue
            return SafetyResult(
                allowed=False,
                reason=(
                    f"ALTER {keyword} blocked: '{dest_name}' must start with {session_prefix} "
                    f"(or use a database-qualified source so the destination stays in the sandbox database)"
                ),
            )

    return SafetyResult(allowed=True)


def _check_optimize_vacuum(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: OPTIMIZE/VACUUM/ANALYZE must be on sandbox objects."""
    match = _sql_search(
        rf"\b(OPTIMIZE|VACUUM|ANALYZE)\s+TABLE\s+({IDENTIFIER_PATTERN})",
        sql,
        re.IGNORECASE,
    )
    if not match:
        return None

    obj_name = match.group(2)
    name, is_sandbox = _extract_identifier(obj_name, session_prefix)
    if is_sandbox:
        return SafetyResult(allowed=True)
    return SafetyResult(
        allowed=False,
        reason=f"{match.group(1)} blocked: '{name}' must start with {session_prefix}",
    )


_GRANT_TARGET_KEYWORDS = frozenset(
    {
        "ACCESS",
        "ALL",
        "CATALOG",
        "CATALOGS",
        "CONNECTION",
        "CONNECTIONS",
        "DATABASE",
        "DATABASES",
        "FILE",
        "FORMAT",
        "FORMATS",
        "FUTURE",
        "GROUP",
        "GROUPS",
        "IN",
        "INTEGRATION",
        "INTEGRATIONS",
        "MASKING",
        "NETWORK",
        "NOTIFICATION",
        "OBJECTS",
        "ON",
        "PASSWORD",
        "POLICIES",
        "POLICY",
        "PRIVILEGES",
        "PROCEDURE",
        "PROCEDURES",
        "ROW",
        "SCHEMA",
        "SCHEMAS",
        "SEQUENCE",
        "SEQUENCES",
        "STAGE",
        "STAGES",
        "TABLE",
        "TABLES",
        "TAG",
        "TAGS",
        "UDF",
        "UDFS",
        "VIEW",
        "VIEWS",
        "WAREHOUSE",
        "WAREHOUSES",
        "WORKLOAD",
    }
)


def _grant_target_identifiers(target: str) -> list[str] | None:
    """Collect the object identifiers named in a GRANT/REVOKE ``ON`` clause.

    Object-type keywords are skipped; quoted names are always identifiers, so a
    database literally called ``"tables"`` is still checked. Returns None when
    the clause cannot be tokenized.
    """
    identifiers: list[str] = []
    index = 0
    length = len(target)
    while index < length:
        char = target[index]
        if char.isspace() or char == ",":
            index += 1
            continue
        if char in _QUOTE_CHARS:
            end = _skip_quoted(target, index)
            if end is None:
                return None
            identifiers.append(target[index:end])
            index = end
            continue
        if char.isalpha() or char == "_":
            start = index
            end = index
            while end < length and (target[end].isalnum() or target[end] in "_$"):
                end += 1
            token = target[start:end]
            if end < length and target[end] == "." and end + 1 < length and (target[end + 1].isalnum() or target[end + 1] in "_$"):
                tail = _read_qualified_tail(target, end)
                identifiers.append(token + tail)
                index = end + len(tail)
            else:
                if token.upper() not in _GRANT_TARGET_KEYWORDS:
                    identifiers.append(token)
                index = end
            continue
        index += 1
    return identifiers


def _read_qualified_tail(target: str, index: int) -> str:
    """Read the ``.name`` tail of a qualified identifier starting at `index`."""
    tail = ""
    length = len(target)
    while index < length and target[index] == ".":
        tail += "."
        index += 1
        while index < length and (target[index].isalnum() or target[index] in "_$"):
            tail += target[index]
            index += 1
    return tail


def _check_grant_revoke(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: GRANT/REVOKE - all involved objects must be sandbox."""
    if not _sql_search(r"\b(GRANT|REVOKE)\b", sql, re.IGNORECASE):
        return None

    grant_identifiers: list[str] = []

    on_clause = _sql_search(r"\bON\b(.*?)(?:\bTO\b|\bFROM\b|$)", sql, re.IGNORECASE | re.DOTALL)
    if on_clause:
        target = on_clause.group(1)
        # The global wildcard (* / *.*) carries no identifier for the checks
        # below to inspect and would grant authority over the whole warehouse,
        # so it is rejected outright. <db>.* is inspected through its database.
        if "*" in target and not re.fullmatch(r"\s*[`\'\"]?\w+[`\'\"]?\s*\.\s*\*\s*", target):
            return SafetyResult(
                allowed=False,
                reason=f"GRANT/REVOKE blocked: global wildcard target '{target.strip()}' is not allowed",
            )
        on_identifiers = _grant_target_identifiers(target)
        if on_identifiers is None:
            return SafetyResult(
                allowed=False,
                reason="GRANT/REVOKE blocked: ON clause could not be tokenized safely",
            )
        grant_identifiers.extend(on_identifiers)

    # A wildcard outside an object reference ("TO *", "ON *") names no
    # identifier this rule can inspect, so it is rejected.
    for star in _sql_finditer(r"\*", sql):
        if not _sql_search(r"[`'\"]?\w+[`'\"]?\s*\.\s*$", sql[: star.start()]):
            return SafetyResult(
                allowed=False,
                reason="GRANT/REVOKE blocked: wildcard is only supported as '<sandbox_object>.*'",
            )

    # Extract ROLE/TO/FROM patterns
    for pattern in [
        r"\bROLE\s+([`\'\"]?\w+[`\'\"]?)",
        r"\bTO\s+([`\'\"]?\w+[`\'\"]?)",
        r"\bFROM\s+([`\'\"]?\w+[`\'\"]?)",
    ]:
        for match in _sql_finditer(pattern, sql, re.IGNORECASE):
            grant_identifiers.append(match.group(1))

    # Check all extracted identifiers
    for identifier in grant_identifiers:
        name, is_sandbox = _extract_identifier(identifier, session_prefix)
        if not is_sandbox:
            return SafetyResult(
                allowed=False,
                reason=f"GRANT/REVOKE blocked: '{name}' must start with {session_prefix}",
            )

    if grant_identifiers:
        return SafetyResult(allowed=True)
    return None


def _check_dml(sql: str, session_prefix: str, cte_names: set[str] | None = None) -> SafetyResult | None:
    """Rule: DML operations must be on sandbox objects."""
    # Support db.table format
    # TRUNCATE accepts a comma-separated target list, every other DML statement
    # here has a single target.
    dml_patterns = [
        (rf"^INSERT\s+(?:INTO\s+)?({IDENTIFIER_PATTERN})", "INSERT", False),
        (rf"^UPDATE\s+({IDENTIFIER_PATTERN})", "UPDATE", False),
        (rf"^DELETE\s+FROM\s+({IDENTIFIER_PATTERN})", "DELETE", False),
        (rf"^TRUNCATE\s+(?:TABLE\s+)?({IDENTIFIER_LIST_PATTERN})", "TRUNCATE", True),
        (rf"^COPY\s+INTO\s+({IDENTIFIER_PATTERN})", "COPY INTO", False),
        (rf"^MERGE\s+INTO\s+({IDENTIFIER_PATTERN})", "MERGE INTO", False),
    ]

    for pattern, op_name, multiple_targets in dml_patterns:
        match = _sql_search(pattern, sql, re.IGNORECASE)
        if not match:
            continue

        obj_names = match.group(1)
        if multiple_targets:
            targets = re.findall(IDENTIFIER_PATTERN, obj_names, re.IGNORECASE) or [obj_names]
        else:
            targets = [obj_names]

        for obj_name in targets:
            name, is_sandbox = _extract_identifier(obj_name, session_prefix)
            if not is_sandbox:
                return SafetyResult(
                    allowed=False,
                    reason=f"{op_name} blocked: '{name}' must start with {session_prefix}",
                )

        # Check if SQL contains non-sandbox references in FROM/JOIN
        if _contains_non_sandbox_reference(sql, session_prefix, cte_names):
            return SafetyResult(
                allowed=False,
                reason=f"{op_name} blocked: SQL references non-sandbox objects. All objects must start with {session_prefix}",
            )
        return SafetyResult(allowed=True)
    return None


def _check_remove_stage(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: REMOVE @stage must be on sandbox stage."""
    match = _sql_search(r"\bREMOVE\s+@(\w+)", sql, re.IGNORECASE)
    if not match:
        return None

    stage_name = match.group(1)
    if stage_name.lower().startswith(session_prefix.lower()):
        return SafetyResult(allowed=True)
    return SafetyResult(
        allowed=False,
        reason=f"REMOVE blocked: stage '{stage_name}' must start with {session_prefix}",
    )


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

# Rule registry: order matters, first match wins
SAFETY_RULES: list[Callable[[str, str], SafetyResult | None]] = [
    _check_create_or_replace,  # Must be first - always reject
    _check_replace_into,  # Reject REPLACE INTO
    _check_read_only,  # Allow read operations
    _check_index,  # Index operations
    _check_create_drop,  # DDL operations
    _check_tag_actions,  # Tag operations
    _check_alter,  # ALTER operations
    _check_optimize_vacuum,  # Maintenance operations
    _check_grant_revoke,  # Permission operations
    _check_dml,  # Data manipulation
    _check_remove_stage,  # Stage file operations
]


def check_sql_safety(sql: str) -> SafetyResult:
    """
    Check if SQL is safe - STRICT whitelist approach.

    Exactly one statement is accepted per call. Rules are checked in order and
    the first matching rule determines the result; if no rule matches, the
    operation is REJECTED by default. Because the caller forwards the original
    string to the driver, the gate decides on the same statement text that will
    be executed - multiple statements separated by ``;`` are never approved on
    the strength of the first one.

    Args:
        sql: SQL query string

    Returns:
        SafetyResult with allowed status and reason if blocked
    """
    statements = _split_sql_statements(sql)
    if statements is None:
        return SafetyResult(
            allowed=False,
            reason="SQL could not be tokenized safely (unterminated string, quoted identifier or comment)",
        )
    if not statements:
        return SafetyResult(allowed=False, reason="Empty SQL statement")
    if len(statements) > 1:
        return SafetyResult(
            allowed=False,
            reason=(f"Multiple SQL statements are not allowed in one call (found {len(statements)}). Submit each statement separately."),
        )
    try:
        return _check_single_statement(statements[0])
    except ValueError:
        return SafetyResult(False, "SQL could not be tokenized safely")


def _check_single_statement(sql: str) -> SafetyResult:
    sql_std = _standardize_sql(sql)
    tokens = _sql_tokens(sql_std)
    parsed = _cte_parts(tokens)
    if parsed is None or parsed[1] >= len(tokens) or tokens[parsed[1]].kind != "word":
        return SafetyResult(False, "Statement prefix could not be parsed safely")
    bodies, main = parsed
    for _, body in bodies:
        body_parts = _cte_parts(body)
        if body_parts is None or body_parts[1] >= len(body):
            return SafetyResult(False, "CTE body could not be parsed safely")
        body_head = body[body_parts[1]]
        if body_head.kind != "word" or body_head.text.upper() not in {"SELECT", "VALUES"}:
            return SafetyResult(False, "CTE bodies must be read-only queries")
    verb = tokens[main].text.upper()
    statement = sql_std[tokens[main].start :]
    if main:
        # Keep the CTE names visible to the relation validator without letting
        # CTE bodies claim ownership of the main statement's rule.
        if _contains_non_sandbox_reference(sql_std, get_session_prefix()) and verb != "SELECT":
            return SafetyResult(False, "CTE write references non-sandbox objects")
    session_prefix = get_session_prefix()
    # Rules may only claim their real statement type, never a decoy in a value,
    # quoted name, CTE body or deferred statement.
    owners = {
        _check_create_or_replace: {"CREATE"},
        _check_replace_into: {"REPLACE"},
        _check_read_only: {"SELECT", "SHOW", "DESCRIBE", "DESC", "LIST", "EXPLAIN"},
        _check_index: {"CREATE", "DROP"},
        _check_create_drop: {"CREATE", "DROP"},
        _check_tag_actions: {"ALTER"},
        _check_alter: {"ALTER"},
        _check_optimize_vacuum: {"OPTIMIZE", "VACUUM", "ANALYZE"},
        _check_grant_revoke: {"GRANT", "REVOKE"},
        _check_dml: {"INSERT", "UPDATE", "DELETE", "TRUNCATE", "COPY", "MERGE"},
        _check_remove_stage: {"REMOVE"},
    }
    for rule in SAFETY_RULES:
        if verb not in owners[rule]:
            continue
        if main and rule == _check_dml:
            result = _check_dml(statement, session_prefix, {name for name, _ in parsed[0]})
        else:
            result = rule(statement, session_prefix)
        if result is not None:
            if result.allowed and main and verb not in {"SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN"}:
                if _contains_non_sandbox_reference(sql_std, session_prefix):
                    return SafetyResult(False, "CTE write references non-sandbox objects")
            if result.allowed and _sql_search(r"^(?:CREATE|ALTER)\s+USER\b", statement, re.IGNORECASE):
                for i, token in enumerate(tokens):
                    if token.kind != "word" or token.text.upper() != "DEFAULT_ROLE":
                        continue
                    j = i + 1
                    if j < len(tokens) and tokens[j].text == "=":
                        j += 1
                    if j >= len(tokens) or not _identifier_value(tokens[j]).lower().startswith(session_prefix.lower()):
                        return SafetyResult(False, "DEFAULT_ROLE must reference a sandbox role")
            return result
    return SafetyResult(False, f"Operation not allowed. Only read operations and writes to {session_prefix}* objects are permitted.")


_NESTED_STATE = threading.local()


def _check_nested_sql(sql: str) -> SafetyResult:
    """Validate a deferred statement body with the full rule chain."""
    depth = getattr(_NESTED_STATE, "depth", 0)
    if depth >= MAX_NESTED_SQL_DEPTH:
        return SafetyResult(
            allowed=False,
            reason=f"Nested SQL is nested deeper than {MAX_NESTED_SQL_DEPTH} levels",
        )
    _NESTED_STATE.depth = depth + 1
    try:
        return check_sql_safety(sql)
    finally:
        _NESTED_STATE.depth = depth


def _check_nested_body(sql: str, object_label: str, session_prefix: str) -> SafetyResult | None:
    """Validate the ``AS <body>`` statement of CREATE ... AS constructs.

    Returns a denial when the body references non-sandbox objects or is not
    itself allowed by the rule chain (e.g. ``CREATE TASK t AS DROP TABLE prod``).
    """
    # Tokenize first: a greedy regex starting inside a literal can consume
    # the real AS and make the deferred body disappear from validation.
    as_token = None
    depth = 0
    for token in _sql_tokens(sql):
        if token.kind == "symbol" and token.text == "(":
            depth += 1
        elif token.kind == "symbol" and token.text == ")":
            depth -= 1
        elif depth == 0 and token.kind == "word" and token.text.upper() == "AS":
            as_token = token
            break
    if as_token is None:
        if object_label == "CREATE INDEX":
            return None
        return SafetyResult(allowed=False, reason=f"{object_label} blocked: missing AS body")
    nested_sql = sql[as_token.end :].strip()
    if not nested_sql:
        return SafetyResult(allowed=False, reason=f"{object_label} blocked: empty AS body")

    if _contains_non_sandbox_reference(nested_sql, session_prefix):
        return SafetyResult(
            allowed=False,
            reason=f"{object_label} blocked: Referenced object in nested SQL must start with {session_prefix}",
        )

    nested_result = _check_nested_sql(nested_sql)
    if not nested_result.allowed:
        return SafetyResult(
            allowed=False,
            reason=f"{object_label} blocked: nested SQL is not allowed ({nested_result.reason})",
        )
    return None


@dataclass(frozen=True)
class _SQLToken:
    text: str
    kind: str
    start: int
    end: int


def _sql_tokens(sql: str) -> list[_SQLToken]:
    tokens = []
    i = 0
    while i < len(sql):
        start = i
        if sql[i].isspace():
            i += 1
            continue
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            i = len(sql) if end < 0 else end
            continue
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end < 0 or "/*" in sql[i + 2 : end]:
                raise ValueError("Unterminated or nested SQL comment")
            i = end + 2
            continue
        if sql[i] in _QUOTE_CHARS:
            end = _skip_quoted(sql, i)
            if end is None:
                raise ValueError("Unterminated SQL quote")
            kind = "literal" if sql[i] == "'" else "identifier"
            i = end
        elif sql[i] == "$" and (match := _DOLLAR_QUOTE_RE.match(sql, i)):
            end = sql.find(match.group(0), match.end())
            if end < 0:
                raise ValueError("Unterminated SQL dollar quote")
            i = end + len(match.group(0))
            kind = "literal"
        elif sql[i].isalnum() or sql[i] == "_":
            i += 1
            while i < len(sql) and (sql[i].isalnum() or sql[i] in "_$"):
                i += 1
            kind = "word"
        else:
            i += 1
            kind = "symbol"
        tokens.append(_SQLToken(sql[start:i], kind, start, i))
    return tokens


def _sql_finditer(pattern, sql, flags=0):
    protected = [t for t in _sql_tokens(sql) if t.kind in {"literal", "identifier"}]
    index = 0
    for match in re.compile(pattern, flags).finditer(sql):
        while index < len(protected) and protected[index].end <= match.start():
            index += 1
        if index >= len(protected) or match.start() < protected[index].start:
            yield match


def _sql_search(pattern, sql, flags=0):
    return next(_sql_finditer(pattern, sql, flags), None)


def _identifier_value(token: _SQLToken) -> str:
    if token.kind in {"identifier", "literal"}:
        quote = token.text[0]
        return token.text[1:-1].replace(quote + quote, quote)
    return token.text


def _group_end(tokens, start):
    depth = 0
    for i in range(start, len(tokens)):
        if tokens[i].kind != "symbol":
            continue
        if tokens[i].text == "(":
            depth += 1
        elif tokens[i].text == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _cte_parts(tokens):
    """Return (CTE name/body pairs, main-statement index), or fail closed."""
    if not tokens or tokens[0].kind != "word" or tokens[0].text.upper() != "WITH":
        return [], 0
    i = 1
    if i < len(tokens) and tokens[i].text.upper() == "RECURSIVE":
        i += 1
    bodies = []
    while i < len(tokens):
        if tokens[i].kind not in {"word", "identifier"}:
            return None
        name = _identifier_value(tokens[i]).lower()
        i += 1
        if i < len(tokens) and tokens[i].text == "(":
            end = _group_end(tokens, i)
            if end is None:
                return None
            i = end + 1
        if i >= len(tokens) or tokens[i].kind != "word" or tokens[i].text.upper() != "AS":
            return None
        i += 1
        if i >= len(tokens) or tokens[i].text != "(":
            return None
        end = _group_end(tokens, i)
        if end is None:
            return None
        bodies.append((name, tokens[i + 1 : end]))
        i = end + 1
        if i < len(tokens) and tokens[i].text == ",":
            i += 1
            continue
        return bodies, i
    return None


def _references_outside_sandbox(tokens, prefix, inherited, depth=0):
    if depth >= 64:
        return True
    parsed = _cte_parts(tokens)
    if parsed is None:
        return True
    bodies, main = parsed
    scope = set(inherited)
    recursive = len(tokens) > 1 and tokens[1].kind == "word" and tokens[1].text.upper() == "RECURSIVE"
    for name, body in bodies:
        body_scope = scope | {name} if recursive else scope
        if _references_outside_sandbox(body, prefix, body_scope, depth + 1):
            return True
        scope.add(name)
    relation_list = False
    i = main
    while i < len(tokens):
        token = tokens[i]
        word = token.text.upper() if token.kind == "word" else ""
        if token.kind == "symbol" and token.text == "(":
            end = _group_end(tokens, i)
            if end is None or _references_outside_sandbox(tokens[i + 1 : end], prefix, scope, depth + 1):
                return True
            i = end + 1
            continue
        if word in {"WHERE", "GROUP", "ORDER", "HAVING", "QUALIFY", "LIMIT", "UNION", "EXCEPT", "INTERSECT", "SET", "VALUES", "WHEN"}:
            relation_list = False
        reference = word in {"FROM", "JOIN", "INTO", "USING"} or (word == "UPDATE" and i == main)
        if word == "FROM":
            relation_list = True
        if reference or (relation_list and token.kind == "symbol" and token.text == ","):
            j = i + 1
            if j < len(tokens) and tokens[j].kind in {"word", "identifier"}:
                parts = [_identifier_value(tokens[j])]
                j += 1
                while j + 1 < len(tokens) and tokens[j].text == "." and tokens[j + 1].kind in {"word", "identifier"}:
                    parts.append(_identifier_value(tokens[j + 1]))
                    j += 2
                if parts[0].upper() not in {"SELECT", "VALUES", "USING"}:
                    if not (len(parts) == 1 and parts[0].lower() in scope):
                        if not parts[0].lower().startswith(prefix.lower()):
                            return True
                i = j
                continue
        i += 1
    return False
