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
SESSION_ID = secrets.token_hex(4)
SANDBOX_PREFIX = "mcp_sandbox_"

# Maximum nesting of deferred statements (TASK/PIPE/DYNAMIC TABLE bodies).
MAX_NESTED_SQL_DEPTH = 3

IDENTIFIER_PATTERN = r"[`\'\"]?\w+[`\'\"]?(?:\.[`\'\"]?\w+[`\'\"]?)?"
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
    """Remove comments and strings to prevent injection."""
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    sql = re.sub(r"'(?:[^'\\]|\\.)*'", " ", sql)
    sql = re.sub(r'"(?:[^"\\]|\\.)*"', " ", sql)
    sql = re.sub(r"`[^`]*`", " ", sql)
    return sql


def _standardize_sql(sql: str) -> str:
    """Standardize SQL format for reliable pattern matching."""
    # Remove comments
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    # Normalize whitespace (including newlines) to single space
    sql = re.sub(r"\s+", " ", sql)
    return sql.strip()


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


def _extract_identifier(identifier: str, session_prefix: str) -> tuple[str, bool]:
    """Extract identifier and check if it's sandbox.

    Handles: table, db.table, `db`.`table`
    Returns: (name, is_sandbox)
    """
    identifier = identifier.strip("`'\"")

    # Handle db.table format - check database name
    if "." in identifier:
        db_name = identifier.split(".")[0].strip("`'\"")
        return db_name, db_name.lower().startswith(session_prefix.lower())

    return identifier, identifier.lower().startswith(session_prefix.lower())


def _contains_non_sandbox_reference(sql: str, session_prefix: str) -> bool:
    """Check if SQL contains FROM/JOIN/INTO references to non-sandbox objects."""
    sql_clean = _normalize_sql(sql)

    # Support db.table format
    ref_patterns = [
        r'\bFROM\s+([`\'"]?\w+[`\'"]?(?:\.[`\'"]?\w+[`\'"]?)?)',
        r'\bJOIN\s+([`\'"]?\w+[`\'"]?(?:\.[`\'"]?\w+[`\'"]?)?)',
        r'\bINTO\s+([`\'"]?\w+[`\'"]?(?:\.[`\'"]?\w+[`\'"]?)?)',
        r'\bUPDATE\s+([`\'"]?\w+[`\'"]?(?:\.[`\'"]?\w+[`\'"]?)?)',
    ]

    for pattern in ref_patterns:
        for match in re.finditer(pattern, sql_clean, re.IGNORECASE):
            ref = match.group(1)
            if ref.upper() in ("SELECT", "VALUES", "USING"):
                continue
            _, is_sandbox = _extract_identifier(ref, session_prefix)
            if not is_sandbox:
                return True

    return False


# ============================================================================
# RULE CHECKERS - Each function checks one specific rule
# ============================================================================


def _check_create_or_replace(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: CREATE OR REPLACE must be on sandbox objects."""
    match = re.search(
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
            as_match = re.search(r"\bAS\s+(.+)$", sql, re.IGNORECASE | re.DOTALL)
            if as_match:
                nested_sql = as_match.group(1).strip()
                if _contains_non_sandbox_reference(nested_sql, session_prefix):
                    return SafetyResult(
                        allowed=False,
                        reason=f"CREATE OR REPLACE {obj_type} blocked: Referenced object in nested SQL must start with {session_prefix}",
                    )
        if obj_type == "STREAM":
            on_table_match = re.search(
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
    match = re.search(
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
_EXPLAIN_OPTIONS = (
    "ANALYZE",
    "AST",
    "SYNTAX",
    "GRAPH",
    "PIPELINE",
    "JOIN",
    "FRAGMENTS",
    "RAW",
    "OPTIMIZED",
    "TREE",
    "JSON",
    "FORMAT",
)
_EXPLAIN_OPTIONS_RE = re.compile(rf"^(?:{'|'.join(_EXPLAIN_OPTIONS)})\b\s*")
_CTE_NAME_RE = re.compile(r"\s*(?:\([^)]*\)\s*)?AS\s*\(", re.IGNORECASE)


def _first_top_level_verb(sql: str, skip_cte_names: bool = False) -> str | None:
    """Return the first statement verb at parenthesis depth 0, or None.

    With ``skip_cte_names`` tokens followed by ``AS (`` (i.e. CTE names) are
    skipped, so ``WITH cte AS (...) DELETE FROM t`` yields ``DELETE``.
    """
    depth = 0
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and (char.isalpha() or char == "_"):
            end = index + 1
            while end < length and (sql[end].isalnum() or sql[end] == "_"):
                end += 1
            if skip_cte_names and _CTE_NAME_RE.match(sql, end):
                index = end
                continue
            word = sql[index:end].upper()
            if word in _STATEMENT_VERBS:
                return word
            index = end
            continue
        index += 1
    return None


def _check_read_only(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: Allow read-only queries on ANY object.

    The read prefix must describe the *whole* statement: ``EXPLAIN ANALYZE
    DELETE ...`` and ``WITH ... DELETE ...`` are not read-only and fall through
    to the write rules below.
    """
    sql_upper = sql.strip().upper()

    if re.match(r"^EXPLAIN\b", sql_upper):
        remainder = sql_upper[len("EXPLAIN") :].lstrip()
        while True:
            option = _EXPLAIN_OPTIONS_RE.match(remainder)
            if not option:
                break
            remainder = remainder[option.end() :]
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
    match = re.search(
        rf"\b(CREATE|DROP)\s+({CREATE_DROP_OBJECTS})\s+"
        rf"(?:IF\s+(?:NOT\s+)?EXISTS\s+)?({IDENTIFIER_PATTERN})",
        sql,
        re.IGNORECASE,
    )
    if not match:
        return None

    obj_type = match.group(2).upper()
    obj_name = match.group(3)

    # Check object name has sandbox prefix
    name, is_sandbox = _extract_identifier(obj_name, session_prefix)
    if not is_sandbox:
        return SafetyResult(
            allowed=False,
            reason=f"Operation blocked: '{name}' must start with {session_prefix}",
        )

    # For TASK/PIPE, check nested SQL references
    if obj_type in ("TASK", "PIPE"):
        as_match = re.search(r"\bAS\s+(.+)$", sql, re.IGNORECASE | re.DOTALL)
        if as_match:
            nested_sql = as_match.group(1).strip()
            if _contains_non_sandbox_reference(nested_sql, session_prefix):
                return SafetyResult(
                    allowed=False,
                    reason=f"CREATE {obj_type} blocked: Referenced object in nested SQL must start with {session_prefix}",
                )

    if "DYNAMIC TABLE" in obj_type:
        as_match = re.search(r"\bAS\s+(.+)$", sql, re.IGNORECASE | re.DOTALL)
        if as_match:
            nested_sql = as_match.group(1).strip()
            if _contains_non_sandbox_reference(nested_sql, session_prefix):
                return SafetyResult(
                    allowed=False,
                    reason=f"CREATE {obj_type} blocked: Referenced object in nested SQL must start with {session_prefix}",
                )

    # For STREAM, check ON TABLE reference
    if obj_type == "STREAM":
        on_table_match = re.search(
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
    as_match = re.search(r"\bAS\b", sql, re.IGNORECASE)
    sql_prefix = sql if not as_match else sql[: as_match.start()]
    on_match = re.search(rf"\bON\s+({IDENTIFIER_PATTERN})", sql_prefix, re.IGNORECASE)
    if on_match:
        return on_match.group(1)
    return None


def _check_index(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: INDEX operations must be on sandbox objects."""
    create_match = re.search(
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

        as_match = re.search(r"\bAS\s+(.+)$", sql, re.IGNORECASE | re.DOTALL)
        if as_match:
            nested_sql = as_match.group(1).strip()
            if _contains_non_sandbox_reference(nested_sql, session_prefix):
                return SafetyResult(
                    allowed=False,
                    reason=f"CREATE INDEX blocked: Referenced object in nested SQL must start with {session_prefix}",
                )

        return SafetyResult(allowed=True)

    drop_match = re.search(
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
    if not re.search(r"\b(?:SET|UNSET)\s+TAG\b", sql, re.IGNORECASE):
        return None

    target_match = re.search(
        rf"\bALTER\s+({TAG_TARGET_OBJECTS})\s+({IDENTIFIER_PATTERN})",
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

    tags_match = re.search(r"\b(?:SET|UNSET)\s+TAG\s+(.+)$", sql, re.IGNORECASE)
    if not tags_match:
        return SafetyResult(
            allowed=False,
            reason=f"ALTER TAG blocked: tag names must start with {session_prefix}",
        )

    tag_items = [item.strip() for item in tags_match.group(1).split(",") if item.strip()]
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


def _check_alter(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: ALTER operations must be on sandbox objects."""
    match = re.search(
        rf"\bALTER\s+({ALTER_OBJECTS})\s+({IDENTIFIER_PATTERN})",
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
        reason=f"ALTER blocked: '{name}' must start with {session_prefix}",
    )


def _check_optimize_vacuum(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: OPTIMIZE/VACUUM/ANALYZE must be on sandbox objects."""
    match = re.search(
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


def _check_grant_revoke(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: GRANT/REVOKE - all involved objects must be sandbox."""
    if not re.search(r"\b(GRANT|REVOKE)\b", sql, re.IGNORECASE):
        return None

    # The global wildcard (* / *.*) carries no identifier for the checks below
    # to inspect and would grant authority over the whole warehouse, so it is
    # rejected outright. <db>.* stays allowed when <db> is a sandbox database.
    on_clause = re.search(r"\bON\b(.*?)(?:\bTO\b|\bFROM\b|$)", sql, re.IGNORECASE | re.DOTALL)
    if on_clause and "*" in on_clause.group(1):
        target = on_clause.group(1).strip()
        if not re.fullmatch(r"[`\'\"]?\w+[`\'\"]?\s*\.\s*\*", target):
            return SafetyResult(
                allowed=False,
                reason=f"GRANT/REVOKE blocked: global wildcard target '{target}' is not allowed",
            )

    grant_identifiers = []

    # Extract ON DATABASE/TABLE patterns - support db.table
    for pattern in [
        rf"\bON\s+DATABASE\s+({IDENTIFIER_PATTERN})",
        rf"\bON\s+WAREHOUSE\s+({IDENTIFIER_PATTERN})",
        rf"\bON\s+TABLE\s+({IDENTIFIER_PATTERN})",
        rf"\bON\s+STAGE\s+({IDENTIFIER_PATTERN})",
        rf"\bON\s+UDF\s+({IDENTIFIER_PATTERN})",
        rf"\bON\s+CONNECTION\s+({IDENTIFIER_PATTERN})",
        rf"\bON\s+SEQUENCE\s+({IDENTIFIER_PATTERN})",
        rf"\bON\s+PROCEDURE\s+({IDENTIFIER_PATTERN})",
        rf"\bON\s+MASKING\s+POLICY\s+({IDENTIFIER_PATTERN})",
        rf"\bON\s+ROW\s+ACCESS\s+POLICY\s+({IDENTIFIER_PATTERN})",
        r'\bON\s+([`\'"]?\w+[`\'"]?)\.\*',
    ]:
        for match in re.finditer(pattern, sql, re.IGNORECASE):
            grant_identifiers.append(match.group(1))

    # Extract ROLE/TO/FROM patterns
    for pattern in [
        r'\bROLE\s+([`\'"]?\w+[`\'"]?)',
        r'\bTO\s+([`\'"]?\w+[`\'"]?)',
        r'\bFROM\s+([`\'"]?\w+[`\'"]?)',
    ]:
        for match in re.finditer(pattern, sql, re.IGNORECASE):
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


def _check_dml(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: DML operations must be on sandbox objects."""
    # Support db.table format
    dml_patterns = [
        (rf"\bINSERT\s+(?:INTO\s+)?({IDENTIFIER_PATTERN})", "INSERT"),
        (rf"\bUPDATE\s+({IDENTIFIER_PATTERN})", "UPDATE"),
        (rf"\bDELETE\s+FROM\s+({IDENTIFIER_PATTERN})", "DELETE"),
        (rf"\bTRUNCATE\s+(?:TABLE\s+)?({IDENTIFIER_PATTERN})", "TRUNCATE"),
        (rf"\bCOPY\s+INTO\s+({IDENTIFIER_PATTERN})", "COPY INTO"),
        (rf"\bMERGE\s+INTO\s+({IDENTIFIER_PATTERN})", "MERGE INTO"),
    ]

    for pattern, op_name in dml_patterns:
        match = re.search(pattern, sql, re.IGNORECASE)
        if match:
            obj_name = match.group(1)
            name, is_sandbox = _extract_identifier(obj_name, session_prefix)
            if is_sandbox:
                # Check if SQL contains non-sandbox references in FROM/JOIN
                if _contains_non_sandbox_reference(sql, session_prefix):
                    return SafetyResult(
                        allowed=False,
                        reason=f"{op_name} blocked: SQL references non-sandbox objects. All objects must start with {session_prefix}",
                    )
                return SafetyResult(allowed=True)
            return SafetyResult(
                allowed=False,
                reason=f"{op_name} blocked: '{name}' must start with {session_prefix}",
            )
    return None


def _check_remove_stage(sql: str, session_prefix: str) -> SafetyResult | None:
    """Rule: REMOVE @stage must be on sandbox stage."""
    match = re.search(r"\bREMOVE\s+@(\w+)", sql, re.IGNORECASE)
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
            reason=(
                f"Multiple SQL statements are not allowed in one call (found {len(statements)}). "
                "Submit each statement separately."
            ),
        )
    return _check_single_statement(statements[0])


def _check_single_statement(sql: str) -> SafetyResult:
    """Run the rule chain over one statement."""
    # Standardize SQL format first
    sql_std = _standardize_sql(sql)
    session_prefix = get_session_prefix()

    # Check each rule in order
    for rule in SAFETY_RULES:
        result = rule(sql_std, session_prefix)
        if result is not None:
            return result

    # Default: REJECT everything else
    return SafetyResult(
        allowed=False,
        reason=f"Operation not allowed. Only read operations and writes to {session_prefix}* objects are permitted.",
    )


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
    as_match = re.search(r"\bAS\s+(.+)$", sql, re.IGNORECASE | re.DOTALL)
    if not as_match:
        return None
    nested_sql = as_match.group(1).strip()
    if not nested_sql:
        return None

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
