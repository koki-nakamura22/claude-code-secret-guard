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
from pathlib import Path

from .detect import find_secrets

_STATE_FILE = "transcript-offsets.json"
_STATE_LIMIT = 500
# Claude Code wraps `!` input and output in tags such as <bash-input>. A tag right before a name hides
# where the name starts, so tags are replaced by spaces before looking for secrets.
_TAG = re.compile(r"</?[A-Za-z][\w-]*>")


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


def mask_line(line: bytes) -> tuple[bytes, int]:
    """Return the line with its secrets masked, and how many places were masked."""
    try:
        data = json.loads(line)
    except ValueError:
        return line, 0
    texts = [_TAG.sub(" ", s) for s in _strings(data)]
    secrets = {t[f.start : f.end] for t in texts for f in find_secrets(t)}
    total = 0
    # Longer first, so that a secret containing a shorter one is masked as a whole.
    for form in sorted({e for s in secrets for e in _encodings(s)}, key=len, reverse=True):
        line, count = _mask(line, form)
        total += count
    return line, total


def redact_file(path: Path, start: int = 0) -> tuple[int, int]:
    """Mask secrets in the complete lines of ``path`` from byte ``start``.

    Return the offset after the last complete line (where the next call should start) and the
    number of places masked. A line still being written is left for the next call.
    """
    with path.open("r+b") as f:
        f.seek(0, os.SEEK_END)
        if start > f.tell():
            start = 0  # the file was replaced or truncated
        f.seek(start)
        chunk = f.read()
        end = chunk.rfind(b"\n") + 1
        masked = 0
        position = start
        for line in chunk[:end].splitlines(keepends=True):
            new, count = mask_line(line)
            if count:
                f.seek(position)
                f.write(new)
                masked += count
            position += len(line)
    return start + end, masked


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


def redact_transcript(path: Path, data_dir: Path | None) -> int:
    """Mask the part of a session log not seen before. ``data_dir`` remembers how far each log was read."""
    state_path = data_dir / _STATE_FILE if data_dir else None
    state = _load_state(state_path) if state_path else {}
    key = str(path)
    offset, masked = redact_file(path, state.pop(key, 0))
    if state_path:
        state[key] = offset
        state_path.parent.mkdir(parents=True, exist_ok=True)
        _save_state(state_path, state)
    return masked
