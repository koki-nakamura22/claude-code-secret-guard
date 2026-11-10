"""Claude Code hook handlers. Each reads the hook input JSON from stdin and writes the output JSON to stdout."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import IO

from .checks import check_repository
from .detect import find_secrets
from .transcript import TypedSecret, redact_transcript

DISABLE_ENV = "SECRET_GUARD_DISABLE"
# Set from the plugin's userConfig option redact_transcripts ("/plugin" > manage). Unset means on.
REDACT_OPTION_ENV = "CLAUDE_PLUGIN_OPTION_REDACT_TRANSCRIPTS"

_REASON = (
    "secret-guard blocked this command because it contains a literal secret:\n"
    "{found}\n"
    "Approved commands can be saved as permission rules in .claude/settings.local.json, "
    "and that file ends up on GitHub more often than you would think. "
    "Never write the secret itself into a command.\n"
    "Instead, reference an environment variable that the user sets outside this session, "
    'e.g. drop `PGPASSWORD=...` and let psql read $PGPASSWORD, or write `mysql -p"$MYSQL_PASSWORD"`, '
    '`curl -H "Authorization: Bearer $API_TOKEN"`, `postgres://user:$DB_PASSWORD@host/db`.\n'
    "If the variable is not set, ask the user to export it (or to use a secret manager such as `op read`) "
    "instead of asking for the value."
)


def pre_tool_use(data: dict[str, object]) -> dict[str, object] | None:
    if data.get("tool_name") != "Bash":
        return None
    tool_input = data.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return None
    findings = find_secrets(command)
    if not findings:
        return None
    found = "\n".join(f"- {f.description} ({f.rule}): {f.masked(command)}" for f in findings)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": _REASON.format(found=found),
        }
    }


# Claude Code puts the bin/ of each plugin on the PATH of its shell, so the short name works there.
_HOW_TO_FIX = "type `! secret-guard fix` in Claude Code, or ask Claude to run it"


def session_start(data: dict[str, object]) -> dict[str, object] | None:
    cwd = data.get("cwd")
    project = os.environ.get("CLAUDE_PROJECT_DIR") or (cwd if isinstance(cwd, str) else None) or os.getcwd()
    issues = check_repository(Path(project), _HOW_TO_FIX)
    if not issues:
        return None
    text = "\n\n".join(i.message for i in issues)
    return {
        "systemMessage": text,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text + "\nTell the user about this at the start of your first reply.",
        },
    }


_PREFIX = {"prompt": "> ", "bash-input": "! ", "bash-output": "output of !: "}


def _typed_message(typed: list[TypedSecret], masked: bool) -> str:
    """Tell the user about a secret they typed (or a `!` command printed), which no hook could stop."""
    # Count values, not lines: `! echo PGPASSWORD=...` shows one value twice, in the command and its output.
    values = {s for t in typed for s in t.secrets}
    typed_values = {s for t in typed if t.kind != "bash-output" for s in t.secrets}
    one = len(values) == 1
    them = "the password or token" if one else "the passwords or tokens"
    by_hand = bool(typed_values)
    if not by_hand:
        headline = f"{'a password or token' if one else 'passwords or tokens'} appeared in the output of a ! command"
    elif typed_values == values:
        headline = (
            f"{'a password or token was' if one else f'{len(values)} passwords or tokens were'} typed in this session"
        )
    else:
        headline = f"{len(values)} passwords or tokens were typed or printed by a ! command in this session"
    shown = "\n".join(f"  {_PREFIX[t.kind]}{t.preview}" for t in typed)
    where = "It was" if one else "They were"
    reason = f"{where} sent to Claude"
    if by_hand:
        reason += ", and your input history (~/.claude/history.jsonl) keeps what you typed in plain text"
    reason += ". " + (
        "This session's log has been masked." if masked else "This session's log was left as it is (masking is off)."
    )
    steps = [f"Change {them}."]
    if by_hand:
        lines = "that line" if sum(t.kind != "bash-output" for t in typed) == 1 else "those lines"
        steps.append(f"After closing Claude Code, delete {lines} from ~/.claude/history.jsonl.")
    numbered = "\n".join(f"  {n}. {step}" for n, step in enumerate(steps, 1))
    return f"secret-guard: {headline}\n{shown}\n{reason}\nWhat to do:\n{numbered}"


def redact(data: dict[str, object]) -> dict[str, object] | None:
    """After each turn (Stop), subagent (SubagentStop) and at SessionEnd, mask secrets in the session log.

    Commands run with `!` reach no hook before they run, so on Stop the user is told about a secret
    they typed (or a `!` command printed) since the last turn.
    """
    write = os.environ.get(REDACT_OPTION_ENV, "").strip().lower() not in ("false", "0")
    event = data.get("hook_event_name")
    key = "agent_transcript_path" if event == "SubagentStop" else "transcript_path"
    path = data.get(key)
    if not isinstance(path, str) or not path:
        return None
    data_dir = os.environ.get("CLAUDE_PLUGIN_DATA")
    try:
        result = redact_transcript(Path(path), Path(data_dir) if data_dir else None, write=write)
    except OSError as e:
        print(f"secret-guard: cannot mask secrets in {path}: {e}", file=sys.stderr)
        return None
    if event != "Stop" or not result.typed:
        return None
    return {"systemMessage": _typed_message(result.typed, write)}


HANDLERS = {"pre-tool-use": pre_tool_use, "session-start": session_start, "redact": redact}


def run(event: str, stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout) -> int:
    if os.environ.get(DISABLE_ENV) == "1":
        return 0
    try:
        data = json.load(stdin)
    except json.JSONDecodeError as e:
        print(f"secret-guard: invalid hook input: {e}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        return 1
    result = HANDLERS[event](data)
    if result is not None:
        json.dump(result, stdout)
    return 0
