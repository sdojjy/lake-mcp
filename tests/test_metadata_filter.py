"""Metadata filters must retain their grammar without unbounded backtracking."""

import subprocess
import sys

import pytest

from lake_mcp import server


@pytest.mark.parametrize(
    "predicate",
    [
        "name like 'test%'",
        "name ILIKE 'TEST%'",
        "name NOT LIKE 'test%'",
        "name NOT ILIKE 'TEST%'",
        "name\tNOT\nLIKE\t'test%'",
        "name\tLIKE\t'test%'",
        "1=1",
        "rows<>10",
        "rows != -12.5",
        "rows<=+2",
        "rows>=0",
        "rows<2.5",
        "rows>1",
        "enabled=TRUE",
        "enabled != false",
        "name = NULL",
        "name='a''b'",
        r"name='a\'b'",
        r"name='a\\b'",
        "name='; -- LIKE x'",
        "name='数据'",
        "name=''",
    ],
)
@pytest.mark.parametrize("tool,statement", [(server.show_tables, "SHOW TABLES"), (server.show_functions, "SHOW FUNCTIONS")])
def test_supported_filters_reach_query_unchanged(monkeypatch, predicate, tool, statement):
    executed = []
    monkeypatch.setattr(server, "_execute_sql", lambda sql: executed.append(sql) or {"status": "success"})
    assert tool(filter=f"  {predicate}  ")["status"] == "success"
    assert executed == [f"{statement} WHERE {predicate}"]


@pytest.mark.parametrize(
    "predicate",
    [
        "",
        "nameLIKE 'x'",
        "name LIKE'x'",
        "name NOTLIKE 'x'",
        "name LIKE 'x",
        "name LIKE 'x' OR 1=1",
        "name = 'x'; SELECT 1",
        "name LIKE 'x' -- trailing comment",
        "name = 1.2.3",
        "name = 1e2",
        "name = other_column",
        "name = (SELECT 1)",
        "schema.name = 'x'",
        "name = $$x$$",
        "name = 'x'" + " " * 4096,
    ],
)
def test_invalid_filters_never_reach_query(monkeypatch, predicate):
    monkeypatch.setattr(server, "_execute_sql", lambda _: pytest.fail("Invalid filter reached warehouse"))
    for tool in (server.show_tables, server.show_functions):
        assert tool(filter=predicate)["status"] == "error"


def test_max_length_filter_matching_finishes_in_bounded_subprocess():
    # Keep an accidental reintroduction of the old regex from hanging pytest
    # itself. Compile the actual shipped pattern in a clean, killable process;
    # dependency imports and warehouse response times are outside this budget.
    script = r"""
import re
import sys

pattern = re.compile(sys.argv[1], re.IGNORECASE)
malformed = [
    'name' + '\t' * 2039 + 'like' + '\t' * 2039 + "'x",
    'name' + ' ' * 1358 + 'NOT' + ' ' * 1358 + 'LIKE' + ' ' * 1358 + "'x",
    'name' + '\t' * 4080 + '!',
    'name LIKE ' + "'" + '\\' * 4070 + 'x',
    'name=' + '1' * 4080 + '!',
    "name='" + "''" * 2039 + '!',
]
for _ in range(10):
    for value in malformed:
        assert len(value) <= 4096
        assert pattern.fullmatch(value) is None
valid = 'name' + '\t' * 2038 + 'LIKE' + '\t' * 2038 + "'x'"
assert pattern.fullmatch(valid) is not None
"""
    result = subprocess.run(
        [sys.executable, "-c", script, server._METADATA_FILTER.pattern],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr
