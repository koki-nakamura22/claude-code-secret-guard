"""Claude Code hook handlers. Each reads the hook input JSON from stdin and writes the output JSON to stdout."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import IO

from .checks import check_repository
from .detect import find_secrets
from .transcript import redact_transcript

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


def redact(data: dict[str, object]) -> dict[str, object] | None:
    """Mask secrets in the session log after each turn (Stop), subagent (SubagentStop) and at SessionEnd."""
    if os.environ.get(REDACT_OPTION_ENV, "").strip().lower() in ("false", "0"):
        return None
    key = "agent_transcript_path" if data.get("hook_event_name") == "SubagentStop" else "transcript_path"
    path = data.get(key)
    if not isinstance(path, str) or not path:
        return None
    data_dir = os.environ.get("CLAUDE_PLUGIN_DATA")
    try:
        redact_transcript(Path(path), Path(data_dir) if data_dir else None)
    except OSError as e:
        print(f"secret-guard: cannot mask secrets in {path}: {e}", file=sys.stderr)
    return None


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
