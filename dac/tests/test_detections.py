"""
Detection unit tests.

For every case in tests/test_cases.yml:
  1. Convert the Sigma rule to a SQLite query using the Wazuh field-mapping pipeline.
  2. Flatten the sample Wazuh alerts into dotted-key rows and load them into an
     in-memory SQLite table.
  3. Run the query and assert the number of matches.

True-positive samples must match. Benign samples must not. A rule that stops
detecting its own attack, or starts firing on benign traffic, fails CI.
"""

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "test_cases.yml"
PIPELINE = ROOT / "pipelines" / "wazuh_windows.yml"
TABLE = "alerts"


def load_cases():
    cases = yaml.safe_load(MANIFEST.read_text())
    return [
        pytest.param(
            c["rule"],
            c["sample"],
            c["expected_matches"],
            id=f"{Path(c['rule']).stem}::{Path(c['sample']).stem}",
        )
        for c in cases
    ]


def flatten(obj, prefix=""):
    """Wazuh alerts are nested JSON; Sigma queries address dotted paths."""
    flat = {}
    for key, value in obj.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten(value, f"{path}."))
        elif isinstance(value, list):
            flat[path] = " ".join(str(v) for v in value)
        else:
            flat[path] = value
    return flat


def convert(rule_path: Path) -> str:
    result = subprocess.run(
        ["sigma", "convert", "-t", "sqlite", "-p", str(PIPELINE), str(rule_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    queries = [l for l in result.stdout.splitlines() if l.strip().upper().startswith("SELECT")]
    assert queries, f"no query produced for {rule_path}\n{result.stdout}{result.stderr}"
    return queries[0].replace("<TABLE_NAME>", TABLE)


def run_query(query: str, events: list) -> int:
    rows = [flatten(e) for e in events]
    columns = sorted({k for r in rows for k in r})
    quoted = ", ".join(f'"{c}"' for c in columns)
    placeholders = ", ".join("?" * len(columns))

    con = sqlite3.connect(":memory:")
    con.execute(f"CREATE TABLE {TABLE} ({quoted})")
    con.executemany(
        f"INSERT INTO {TABLE} VALUES ({placeholders})",
        [[r.get(c) for c in columns] for r in rows],
    )
    return len(con.execute(query).fetchall())


@pytest.mark.parametrize("rule,sample,expected", load_cases())
def test_detection(rule, sample, expected):
    query = convert(ROOT / rule)
    events = json.loads((ROOT / sample).read_text())
    matches = run_query(query, events)
    assert matches == expected, (
        f"\n  rule:     {rule}"
        f"\n  sample:   {sample}"
        f"\n  expected: {expected} match(es)"
        f"\n  got:      {matches}"
        f"\n  query:    {query}"
    )
