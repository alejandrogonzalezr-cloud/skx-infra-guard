"""Redis command parser.

Redis is its own domain, not "a database that happens to speak SQL"
(docs/policy-model.md #10, Skydropx brief section 15). Running redis-cli 
through a generic SQL parser is broken because concepts like "no WHERE clause"
are not meaningful for a command vocabulary that has no WHERE clause concept 
at all. This module classifies Redis's real vocabulary directly instead.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from skx_infra_guard.core.decision import OperationClass

_READ_COMMANDS = {
    "get", "mget", "exists", "strlen", "scan", "keys", "hget", "hgetall",
    "hmget", "hscan", "hkeys", "hvals", "hlen", "smembers", "sscan",
    "sismember", "scard", "zrange", "zrangebyscore", "zscan", "zscore",
    "zcard", "lrange", "llen", "lindex", "ttl", "pttl", "type", "dbsize",
    "info", "ping", "randomkey", "dump", "object",
}
_CHANGE_COMMANDS = {
    "set", "setex", "psetex", "setnx", "mset", "msetnx", "hset", "hsetnx",
    "hmset", "sadd", "zadd", "lpush", "rpush", "lpushx", "rpushx", "lset",
    "expire", "pexpire", "expireat", "persist", "rename", "renamenx",
    "incr", "incrby", "incrbyfloat", "decr", "decrby", "append", "getset",
    "restore", "copy", "move", "select",
}
_DESTRUCTIVE_COMMANDS = {
    "del", "unlink", "hdel", "srem", "zrem", "lrem", "ltrim", "lpop",
    "rpop", "spop", "zpopmin", "zpopmax",
}
# Always blocked regardless of environment (docs/policy-model.md #10,
# ensuring unconditional FLUSHALL/FLUSHDB protection).
_ALWAYS_BLOCKED_COMMANDS = {"flushall", "flushdb"}

_ALL_COMMANDS = (
    _READ_COMMANDS | _CHANGE_COMMANDS | _DESTRUCTIVE_COMMANDS | _ALWAYS_BLOCKED_COMMANDS
)


@dataclass
class RedisCommand:
    command: str
    operation: OperationClass
    always_blocked: bool
    key_hint: str | None


def is_redis_cli_command(command: str) -> bool:
    return bool(re.match(r"^\s*redis-cli\s", command))


def parse(command: str) -> RedisCommand | None:
    if not is_redis_cli_command(command):
        return None

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    rest = [t for t in tokens[1:] if not t.startswith("-")]
    if not rest:
        return None

    redis_command = rest[0].lower()
    key_hint = rest[1] if len(rest) > 1 else None

    always_blocked = redis_command in _ALWAYS_BLOCKED_COMMANDS
    if always_blocked:
        operation = OperationClass.DESTRUCTIVE
    elif redis_command in _DESTRUCTIVE_COMMANDS:
        operation = OperationClass.DESTRUCTIVE
    elif redis_command in _CHANGE_COMMANDS:
        operation = OperationClass.CHANGE
    elif redis_command in _READ_COMMANDS:
        operation = OperationClass.READ
    else:
        # Unrecognized Redis command (new/obscure verb) — fail-safe, never
        # silently READ.
        operation = OperationClass.CHANGE

    return RedisCommand(
        command=redis_command,
        operation=operation,
        always_blocked=always_blocked,
        key_hint=key_hint,
    )
