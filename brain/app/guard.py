"""The NL-query safety guard.

This is the hard boundary for the Ask feature. NOTHING runs against the
database unless `validate()` returns ok. It mirrors correlation's
`policy.validate_sql` sqlglot pattern (SELECT-only, reject DDL/DML, reject
multiple statements / semicolons), and then narrows it hard:

  * exactly ONE statement, and it must be a SELECT (no set operations)
  * EVERY table/view referenced must be one of the three ask_* views
    (CTE aliases defined inline are allowed; anything else is refused)
  * no DDL/DML anywhere in the tree (INSERT/UPDATE/DELETE/MERGE/CREATE/
    DROP/ALTER/TRUNCATE/COPY/GRANT/CALL/SELECT INTO ...)
  * no function call on a filesystem/network/time denylist
    (pg_read_file, dblink, lo_*, pg_sleep, ...)

A separate `apply_limit()` enforces/appends a `LIMIT <= MAX_ROWS` so the
caller always runs a bounded query.

The views `ask_assets`, `ask_findings`, `ask_attack_paths` are a safe
projection (schema/009_tier3.sql) that excludes scope secrets, alert
targets and credentials — so even a correct SELECT cannot read those.
"""
from __future__ import annotations

import re
from typing import Iterable

import sqlglot
from sqlglot import exp

# The ONLY tables/views the Ask engine may touch.
ALLOWED_VIEWS: frozenset[str] = frozenset(
    {"ask_assets", "ask_findings", "ask_attack_paths"}
)

MAX_ROWS = 500

# DDL/DML and other mutating / side-effecting statement kinds. Anything of
# these types appearing anywhere in the parse tree is refused.
_FORBIDDEN_EXPR_NAMES = (
    "Create", "Drop", "Alter", "AlterTable", "AlterColumn",
    "Insert", "Update", "Delete", "Merge", "Copy",
    "TruncateTable", "Truncate", "Grant", "Command", "Set", "Use",
    "Into",  # SELECT ... INTO <newtable>
)
_FORBIDDEN_EXPRS: tuple[type, ...] = tuple(
    getattr(exp, n) for n in _FORBIDDEN_EXPR_NAMES if hasattr(exp, n)
)

# Set operations are rejected outright: the contract is a single SELECT.
_SETOP_EXPRS: tuple[type, ...] = tuple(
    e for e in (
        getattr(exp, "SetOperation", None),
        getattr(exp, "Union", None),
        getattr(exp, "Except", None),
        getattr(exp, "Intersect", None),
    ) if e is not None
)

# Function-name denylist (filesystem / network / time / admin side effects).
_DENIED_FUNCS: frozenset[str] = frozenset({
    "pg_read_file", "pg_read_binary_file", "pg_stat_file",
    "pg_ls_dir", "pg_ls_logdir", "pg_ls_waldir", "pg_ls_tmpdir",
    "pg_sleep", "pg_sleep_for", "pg_sleep_until",
    "dblink", "dblink_exec", "dblink_connect", "dblink_open",
    "lo_import", "lo_export", "lo_get", "lo_put", "lo_from_bytea",
    "lo_creat", "lo_create", "lo_unlink",
    "copy", "query_to_xml", "query_to_xml_and_xmlschema",
    "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf",
    "pg_read_server_files", "set_config", "pg_logical_emit_message",
})
_DENIED_FUNC_PREFIXES: tuple[str, ...] = ("pg_read", "pg_ls", "lo_", "dblink")

# Belt-and-suspenders regex backup for the denied functions, in case a
# sqlglot version parses one into a shape the AST walk misses.
_DENIED_FUNC_REGEX = re.compile(
    r"\b(pg_read\w*|pg_ls\w*|pg_stat_file|pg_sleep\w*|dblink\w*|lo_\w+|"
    r"pg_terminate_backend|pg_cancel_backend|pg_reload_conf|set_config|"
    r"query_to_xml\w*|copy)\s*\(",
    re.IGNORECASE,
)


def _walk(root: exp.Expression) -> Iterable[exp.Expression]:
    """Yield every node in the tree, tolerant of sqlglot version differences
    (some versions' `walk()` yields tuples)."""
    for item in root.walk():
        yield item[0] if isinstance(item, tuple) else item


def _cte_names(root: exp.Expression) -> set[str]:
    names: set[str] = set()
    for cte in root.find_all(exp.CTE):
        try:
            names.add(cte.alias_or_name.lower())
        except Exception:  # pragma: no cover - defensive
            pass
    return names


def _func_name(node: exp.Expression) -> str | None:
    if isinstance(node, exp.Anonymous):
        return str(node.name).lower()
    if isinstance(node, exp.Func):
        try:
            return node.sql_name().lower()
        except Exception:  # pragma: no cover - defensive
            return (node.key or "").lower()
    return None


def validate(sql: str) -> tuple[bool, str]:
    """Return ``(ok, reason)``. ``ok`` is True only for a single read-only
    SELECT over the three ask_* views with no denied constructs."""
    if not sql or not sql.strip():
        return False, "empty query"

    # Strip a single trailing semicolon, then refuse any remaining ';':
    # that is the classic "SELECT ...; DROP TABLE ..." stacked-query shape.
    body = sql.strip()
    if body.endswith(";"):
        body = body[:-1].strip()
    if ";" in body:
        return False, "multiple statements are not allowed (';')"

    try:
        statements = [s for s in sqlglot.parse(body, read="postgres") if s is not None]
    except Exception as exc:  # sqlglot.errors.ParseError and friends
        return False, f"query failed to parse: {exc}"

    if len(statements) != 1:
        return False, "query must be exactly one statement"

    root = statements[0]

    if _SETOP_EXPRS and isinstance(root, _SETOP_EXPRS):
        return False, "set operations (UNION/INTERSECT/EXCEPT) are not allowed"

    if not isinstance(root, exp.Select):
        return False, f"query must be a SELECT; got {type(root).__name__}"

    cte_names = _cte_names(root)

    for node in _walk(root):
        # 1. No DDL/DML/side-effecting statement kinds anywhere (also catches
        #    write-CTEs like `WITH x AS (INSERT ... RETURNING ...)`).
        if _FORBIDDEN_EXPRS and isinstance(node, _FORBIDDEN_EXPRS):
            return False, f"disallowed statement kind: {type(node).__name__}"

        # 2. Every real table/view must be an ask_* view (or an inline CTE).
        if isinstance(node, exp.Table):
            name = (node.name or "").lower()
            if not name:
                continue
            if name in cte_names:
                continue
            if name not in ALLOWED_VIEWS:
                return False, (
                    f"table/view '{name}' is not allowed; only "
                    f"{sorted(ALLOWED_VIEWS)} may be queried"
                )

        # 3. No denied function calls (filesystem / network / time / admin).
        fname = _func_name(node)
        if fname is not None:
            if fname in _DENIED_FUNCS or any(
                fname.startswith(p) for p in _DENIED_FUNC_PREFIXES
            ):
                return False, f"disallowed function call: {fname}()"

    # 4. Regex backup for denied functions.
    if _DENIED_FUNC_REGEX.search(body):
        return False, "disallowed function call (denylisted)"

    return True, "ok"


def _current_limit(root: exp.Expression) -> int | None:
    lim = root.args.get("limit")
    if lim is None:
        return None
    target = getattr(lim, "expression", None)
    if isinstance(target, exp.Literal) and target.is_int:
        try:
            return int(target.name)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return None
    return None


def apply_limit(sql: str, max_rows: int = MAX_ROWS) -> str:
    """Return ``sql`` with a bounded ``LIMIT``: appended when absent, capped
    to ``max_rows`` when larger, left alone when already within bounds.

    Call this only on SQL that `validate()` accepted.
    """
    root = sqlglot.parse_one(sql.strip().rstrip(";"), read="postgres")
    cur = _current_limit(root)
    if cur is not None and cur <= max_rows:
        return root.sql(dialect="postgres")
    return root.limit(max_rows).sql(dialect="postgres")
