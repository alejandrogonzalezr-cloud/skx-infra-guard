"""Command Normalizer.

Prevents bypasses where domain regexes are anchored to the literal start of 
the command string (where a nested execution like `bash -c "kubectl delete namespace production"` 
would slip through untouched).

This module recursively unwraps shell-invocation wrappers (`bash -c`, `sh -c`,
`zsh -c`, `dash -c`, `eval`) to expose the real command(s) underneath, and
splits top-level `;` / `&&` / `||` sequences into separate effective commands
so each part is classified on its own. It deliberately does NOT split on `|`
(pipes) — a piped chain like `curl ... | bash` is dangerous specifically
*because* the two sides are joined, and splitting them apart would hide that.

Also unwraps other common bypasses like an `xargs`-templated command
(`... | xargs -I{} kubectl delete {}`) and a same-line `alias` definition
followed by its use (`alias k=kubectl; k delete namespace production`) which
evade naive domain parsers. Both are resolved by extracting the real command
text so that domain parsers see it unchanged, rather than requiring
every parser to understand xargs/alias syntax individually.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

_SHELL_WRAPPERS = {"bash", "sh", "zsh", "dash", "ksh"}
_MAX_UNWRAP_DEPTH = 8

# xargs flags that consume a separate following token as their value
# (`-I {}`), as opposed to flags whose value is attached (`-I{}`) or that
# take no value at all (`-r`, `-0`, `-t`) — both of the latter are handled
# by simply skipping one token.
_XARGS_VALUE_FLAGS = {"-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"}

@dataclass(frozen=True)
class EffectiveCommand:
    """One command string that should be classified independently."""

    text: str
    unwrapped_from: tuple[str, ...] = ()  # chain of wrappers peeled to get here


def _split_top_level(command: str) -> list[str]:
    """Split on unquoted top-level `;`, `&&`, `||`, slicing the ORIGINAL
    string at the matched positions rather than tokenizing and rejoining.

    Reconstructing "tok1 tok2 tok3" from re-tokenized pieces is lossy in two
    different ways that both matter here: it silently strips quoting (so
    `psql -c 'SELECT ... WHERE id=1'` would lose its quotes and the SQL
    parser downstream would then only see the bare word `SELECT`, misreading
    a filtered query as unfiltered), and inserting whitespace around every
    punctuation token corrupts adjacency-sensitive syntax like the fork-bomb
    pattern `:(){ :|:& };:` (`:()`  requires no space between `:` and `(`).
    Slicing the original string sidesteps both problems entirely.
    """
    quote_char: str | None = None
    depth = 0  # (), {}, [] nesting — don't split inside a subshell/braces
    parts: list[str] = []
    start = 0
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]

        if quote_char:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote_char:
                quote_char = None
            i += 1
            continue

        if ch in ("'", '"'):
            quote_char = ch
            i += 1
            continue

        if ch in "({[":
            depth += 1
            i += 1
            continue
        if ch in ")}]":
            depth = max(0, depth - 1)
            i += 1
            continue

        if depth == 0:
            if ch == ";":
                parts.append(command[start:i])
                i += 1
                start = i
                continue
            if command[i:i + 2] in ("&&", "||"):
                parts.append(command[start:i])
                i += 2
                start = i
                continue

        i += 1

    parts.append(command[start:])
    return [p for p in parts] or [command]


def _extract_wrapped_command(command: str) -> str | None:
    """If `command` is `<shell> -c '<inner>'` or `eval '<inner>'`, return
    <inner>. Returns None if it isn't one of those wrapper forms.
    """
    stripped = command.strip()

    # eval "..."  /  eval $'...'
    m = re.match(r"^eval\s+(.*)$", stripped, re.IGNORECASE | re.DOTALL)
    if m:
        rest = m.group(1).strip()
        try:
            tokens = shlex.split(rest)
        except ValueError:
            return rest
        return " ".join(tokens) if tokens else None

    # <shell> [flags] -c '<inner>' [args...]
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return None
    if not tokens:
        return None

    shell_name = tokens[0].rsplit("/", 1)[-1]
    if shell_name not in _SHELL_WRAPPERS:
        return None
    if "-c" not in tokens:
        return None

    c_index = tokens.index("-c")
    if c_index + 1 >= len(tokens):
        return None
    return tokens[c_index + 1]


def _extract_xargs_template(piece: str) -> str | None:
    """`cmd | xargs [flags] real-command [initial-args] {}` — pull out
    `real-command [initial-args] {}` so it gets classified on its own,
    regardless of what xargs actually substitutes at runtime. The
    substituted value itself can't be known statically; the command
    *template* already reveals the intent and is visible right here.
    """
    m = re.search(r"\bxargs\b(.*)$", piece, re.DOTALL)
    if not m:
        return None
    rest = m.group(1).strip()
    if not rest:
        return None
    try:
        tokens = shlex.split(rest)
    except ValueError:
        tokens = rest.split()

    i = 0
    while i < len(tokens) and tokens[i].startswith("-"):
        i += 1 if tokens[i] not in _XARGS_VALUE_FLAGS else 2

    template_tokens = tokens[i:]
    return " ".join(template_tokens) if template_tokens else None


_ALIAS_DEF_RE = re.compile(r"^alias\s+([A-Za-z_][\w.-]*)=(.*)$")


def _apply_aliases(pieces: list[str]) -> list[str]:
    """`alias k=kubectl; k delete ns prod` — substitute a same-chain alias
    definition into the commands that follow it, left to right, so the
    aliased form gets classified the same as the real command would.
    Aliases from an EARLIER invocation aren't tracked (no persistent shell
    state across separate tool calls) — only same-line definitions count.
    """
    aliases: dict[str, str] = {}
    result: list[str] = []
    for piece in pieces:
        stripped = piece.strip()
        m = _ALIAS_DEF_RE.match(stripped)
        if m:
            name, raw_value = m.group(1), m.group(2)
            try:
                value = " ".join(shlex.split(raw_value))
            except ValueError:
                value = raw_value.strip("'\"")
            if value:
                aliases[name] = value
            result.append(piece)
            continue

        first_word, _, remainder = stripped.partition(" ")
        if first_word in aliases:
            result.append(f"{aliases[first_word]} {remainder}".strip())
        else:
            result.append(piece)
    return result


def normalize(command: str) -> list[EffectiveCommand]:
    """Return every effective command that should be classified.

    Recursively unwraps shell/eval wrappers, splits the innermost text on
    top-level `;`, `&&`, `||`, substitutes same-chain `alias` definitions,
    and adds any `xargs`-templated command as an extra effective command.
    """
    if not command or not command.strip():
        return []

    wrapper_chain: list[str] = []
    current = command
    for _ in range(_MAX_UNWRAP_DEPTH):
        inner = _extract_wrapped_command(current)
        if inner is None:
            break
        wrapper_chain.append(current.strip().split()[0])
        current = inner

    pieces = _apply_aliases(_split_top_level(current))

    effective: list[EffectiveCommand] = []
    for piece in pieces:
        text = piece.strip()
        if not text:
            continue
        effective.append(EffectiveCommand(text=text, unwrapped_from=tuple(wrapper_chain)))

        xargs_template = _extract_xargs_template(text)
        if xargs_template:
            effective.append(
                EffectiveCommand(text=xargs_template, unwrapped_from=tuple(wrapper_chain) + ("xargs",))
            )

    return effective
