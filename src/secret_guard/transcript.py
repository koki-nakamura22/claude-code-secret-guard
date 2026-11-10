"""Mask secrets in Claude Code session logs (``~/.claude/projects/<project>/<session>.jsonl``).

A secret that reached a prompt, a tool call or a reply is written to the session log in plain
text, and resuming the session sends it to the model again. Each secret is overwritten in place
with ``*`` of the same byte length: every line stays valid JSON, and Claude Code, which keeps the
file open and appends to it, is not disturbed.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .detect import find_secrets, redact

_STATE_FILE = "transcript-offsets.json"
_STATE_LIMIT = 500
# Claude Code wraps `!` input and output in tags such as <bash-input>. A tag right before a name hides
# where the name starts, so tags are replaced by spaces before looking for secrets.
_TAG = re.compile(r"</?[A-Za-z][\w-]*>")
_BASH = re.compile(r"<(bash-input|bash-stdout|bash-stderr)>(.*?)</\1>", re.DOTALL)
_PREVIEW_LENGTH = 100


@dataclass(frozen=True)
class TypedSecret:
    """A secret in what the user typed (a prompt or a `!` command), or in the output of a `!` command."""

    kind: str  # "prompt", "bash-input" or "bash-output"
    preview: str  # the text with the secret masked, on one line
    # The values themselves, so that the same value in a `!` command and in its output counts once.
    # Kept out of repr so that they never reach a log or a test failure message.
    secrets: frozenset[str] = field(default=frozenset(), repr=False)


@dataclass
class ScanResult:
    offset: int  # where the next scan starts: after the last complete line
    masked: int = 0
    typed: list[TypedSecret] = field(default_factory=list)


def _strings(value: object) -> list[str]:
    """Return every string in a parsed JSON value, including strings inside JSON-encoded strings."""
    found: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            found.append(item)
            if item[:1] in ("{", "["):
                with contextlib.suppress(ValueError):
                    stack.append(json.loads(item))
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return found


def _encodings(secret: str) -> set[bytes]:
    """The forms a secret can take inside a JSON line: as is, escaped once, and escaped twice."""
    once = json.dumps(secret, ensure_ascii=False)[1:-1]
    twice = json.dumps(once, ensure_ascii=False)[1:-1]
    return {secret.encode(), once.encode(), twice.encode()}


def _is_word_byte(b: int) -> bool:
    return chr(b).isalnum() or b == ord("_") if b < 128 else False


def _mask(line: bytes, form: bytes) -> tuple[bytes, int]:
    """Overwrite each occurrence of ``form`` that is not part of a longer word."""
    count = 0
    start = line.find(form)
    while start != -1:
        end = start + len(form)
        glued_before = start > 0 and _is_word_byte(form[0]) and _is_word_byte(line[start - 1])
        glued_after = end < len(line) and _is_word_byte(form[-1]) and _is_word_byte(line[end])
        if not glued_before and not glued_after:
            line = line[:start] + b"*" * len(form) + line[end:]
            count += 1
        start = line.find(form, end)
    return line, count


def _preview(masked: str) -> str:
    """The line that holds the masked secret, on one line and cut to a short length."""
    lines = [line for line in masked.splitlines() if line.strip()]
    line = next((x for x in lines if "***" in x), lines[0] if lines else "")
    line = " ".join(line.split())
    return line if len(line) <= _PREVIEW_LENGTH else line[: _PREVIEW_LENGTH - 1] + "\u2026"


def typed_secrets(data: object) -> list[TypedSecret]:
    """Secrets in a prompt or a `!` command the user typed, as recorded in one parsed log line.

    Tool results are user lines too, but their content is a list, not a string, so they are skipped,
    as are lines Claude Code writes itself (command output, notes), which start with a tag.
    """
    if not isinstance(data, dict) or data.get("type") != "user" or data.get("isMeta"):
        return []
    message = data.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        return []
    parts = _BASH.findall(content)
    if parts:
        items = [("bash-input" if tag == "bash-input" else "bash-output", body) for tag, body in parts]
    elif content.lstrip().startswith("<"):
        return []
    else:
        items = [("prompt", content)]
    found: list[TypedSecret] = []
    for kind, text in items:
        findings = find_secrets(text)
        if findings:
            values = frozenset(text[f.start : f.end] for f in findings)
            found.append(TypedSecret(kind, _preview(redact(text, findings)), values))
    return found


def mask_line(line: bytes) -> tuple[bytes, int]:
    """Return the line with its secrets masked, and how many places were masked."""
    try:
        data = json.loads(line)
    except ValueError:
        return line, 0
    return _mask_parsed(line, data)


def _mask_parsed(line: bytes, data: object) -> tuple[bytes, int]:
    texts = [_TAG.sub(" ", s) for s in _strings(data)]
    secrets = {t[f.start : f.end] for t in texts for f in find_secrets(t)}
    total = 0
    # Longer first, so that a secret containing a shorter one is masked as a whole.
    for form in sorted({e for s in secrets for e in _encodings(s)}, key=len, reverse=True):
        line, count = _mask(line, form)
        total += count
    return line, total


def redact_file(path: Path, start: int = 0, *, write: bool = True) -> ScanResult:
    """Scan the complete lines of ``path`` from byte ``start``, masking secrets unless ``write`` is false.

    The result tells where the next scan should start, how many places were masked, and the secrets
    the user typed. A line still being written is left for the next scan.
    """
    with path.open("r+b" if write else "rb") as f:
        f.seek(0, os.SEEK_END)
        if start > f.tell():
            start = 0  # the file was replaced or truncated
        f.seek(start)
        chunk = f.read()
        end = chunk.rfind(b"\n") + 1
        result = ScanResult(start + end)
        position = start
        for line in chunk[:end].splitlines(keepends=True):
            try:
                data = json.loads(line)
            except ValueError:
                position += len(line)
                continue
            result.typed.extend(typed_secrets(data))
            if write:
                new, count = _mask_parsed(line, data)
                if count:
                    f.seek(position)
                    f.write(new)
                    result.masked += count
            position += len(line)
    return result


def _load_state(state_path: Path) -> dict[str, int]:
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, int)}


def _save_state(state_path: Path, state: dict[str, int]) -> None:
    # Keep the most recent entries; a forgotten log is simply scanned from the start again.
    items = list(state.items())[-_STATE_LIMIT:]
    tmp = state_path.with_name(f"{state_path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(dict(items)), encoding="utf-8")
    os.replace(tmp, state_path)


def redact_transcript(path: Path, data_dir: Path | None, *, write: bool = True) -> ScanResult:
    """Scan the part of a session log not seen before. ``data_dir`` remembers how far each log was read."""
    state_path = data_dir / _STATE_FILE if data_dir else None
    state = _load_state(state_path) if state_path else {}
    key = str(path)
    result = redact_file(path, state.pop(key, 0), write=write)
    if state_path:
        state[key] = result.offset
        state_path.parent.mkdir(parents=True, exist_ok=True)
        _save_state(state_path, state)
    return result
