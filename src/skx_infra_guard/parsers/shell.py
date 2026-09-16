"""Small shared helpers for pulling structured pieces out of a raw shell
command line — the DB-client prefix, an inline SQL payload, etc.

Implements DB_CLIENT detection and extract_sql() into reusable functions 
instead of duplicating the same regex block in every domain module.
"""

from __future__ import annotations

import re
import shlex

_DB_CLIENT_PATTERNS: dict[str, re.Pattern[str]] = {
    "postgresql": re.compile(r"^\s*(psql|pg_dump|pg_restore)\s"),
    "mysql": re.compile(r"^\s*(mysql|mysqldump|mysqlcheck)\s"),
    "sqlite": re.compile(r"^\s*sqlite3\s"),
    # redis-cli is NOT included here on purpose: Redis's command vocabulary
    # (GET/SET/DEL/FLUSHALL...) isn't SQL, and running it through the SQL
    # parser silently misclassified everything — `redis-cli GET foo` came
    # out CRITICAL/BLOCK because the "no WHERE clause" heuristic doesn't
    # mean anything for Redis (found 2026-09-16, fixed by giving Redis its
    # own domain — see parsers/redis.py, domains/redis.py).
}


def detect_db_client(command: str) -> str | None:
    for client, pattern in _DB_CLIENT_PATTERNS.items():
        if pattern.match(command):
            return client
    return None


def extract_inline_sql(command: str) -> str | None:
    """Pulls the SQL text out of `psql -c '...'` / `mysql -e "..."` style
    invocations. Falls back to the raw command if no `-c`/`-e` flag is found
    but the command still looks like it's piping SQL somewhere, matching a
    conservative "analyze the whole command" fallback."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return command

    for flag in ("-c", "-e"):
        if flag in tokens:
            idx = tokens.index(flag)
            if idx + 1 < len(tokens):
                return tokens[idx + 1]

    if "|" in command and re.search(r"\b(psql|mysql|sqlite3)\b", command):
        return command

    return command
