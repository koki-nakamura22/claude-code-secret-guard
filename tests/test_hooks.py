from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from conftest import git, write_settings

from secret_guard.hooks import pre_tool_use, redact, run, session_start
from secret_guard.settings import LOCAL_SETTINGS


def bash(command: object) -> dict[str, object]:
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}


def test_pre_tool_use_denies_command_with_secret() -> None:
    """A Bash command with a literal secret is denied, so no prompt is shown and no rule can be saved."""
    # Act
    result = pre_tool_use(bash("PGPASSWORD=Xk7pQ2mZ9vLr psql -h db"))

    # Assert
    assert result is not None
    output = result["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "deny"


def test_pre_tool_use_reason_tells_claude_to_use_a_variable_without_echoing_the_secret() -> None:
    """The reason steers Claude to an environment variable and does not repeat the secret."""
    # Act
    result = pre_tool_use(bash("PGPASSWORD=Xk7pQ2mZ9vLr psql -h db"))

    # Assert
    assert result is not None
    reason = json.dumps(result)
    assert "environment variable" in reason
    assert "Xk7pQ2mZ9vLr" not in reason


@pytest.mark.parametrize(
    "data",
    [
        bash("psql -h db"),
        bash('PGPASSWORD="$PGPASSWORD" psql -h db'),
        bash(None),
        {"tool_name": "Bash", "tool_input": "PGPASSWORD=Xk7pQ2mZ9vLr psql"},
        {"tool_name": "Write", "tool_input": {"command": "PGPASSWORD=Xk7pQ2mZ9vLr psql"}},
        {},
    ],
)
def test_pre_tool_use_lets_everything_else_through(data: dict[str, object]) -> None:
    """Commands without literal secrets, other tools and malformed input get no decision, so normal prompts apply."""
    # Act & Assert
    assert pre_tool_use(data) is None


def test_session_start_warns_about_a_tracked_local_settings_file(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Starting a session in a repository that tracks settings.local.json shows a warning to the user and Claude."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})
    git(repo, "add", "-f", str(LOCAL_SETTINGS))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(repo))

    # Act
    result = session_start({"hook_event_name": "SessionStart"})

    # Assert
    assert result is not None
    assert str(result["systemMessage"]).startswith("secret-guard: .claude/settings.local.json is tracked by git")
    context = result["hookSpecificOutput"]
    assert isinstance(context, dict)
    assert "is tracked by git" in context["additionalContext"]


def test_session_start_is_silent_for_a_safe_repository(repo: Path) -> None:
    """A repository that ignores the file and has no saved secrets produces no output."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": ["Bash(npm test:*)"]}})

    # Act & Assert
    assert session_start({"cwd": str(repo)}) is None


def test_session_start_suggests_the_short_fix_command(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Claude Code puts the plugin's bin/ on its PATH, so the fix is `! secret-guard fix`, not a long path."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": ["Bash(PGPASSWORD=Xk7pQ2mZ9vLr psql:*)"]}})
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", "/plugins/secret-guard")

    # Act
    result = session_start({"cwd": str(repo)})

    # Assert
    assert result is not None
    message = str(result["systemMessage"])
    assert "  1. Remove the saved rule: type `! secret-guard fix` in Claude Code, or ask Claude to run it" in message
    assert "/plugins/secret-guard" not in message


def test_run_writes_hook_output_as_json() -> None:
    """The hook entry point reads the input from stdin and writes the decision as JSON to stdout."""
    # Arrange
    stdin = io.StringIO(json.dumps(bash("PGPASSWORD=Xk7pQ2mZ9vLr psql")))
    stdout = io.StringIO()

    # Act
    code = run("pre-tool-use", stdin, stdout)

    # Assert
    assert code == 0
    assert json.loads(stdout.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_run_writes_nothing_when_there_is_no_decision() -> None:
    """With nothing to report, the hook prints nothing so Claude Code behaves as if it were not installed."""
    # Arrange
    stdout = io.StringIO()

    # Act
    code = run("pre-tool-use", io.StringIO(json.dumps(bash("ls"))), stdout)

    # Assert
    assert (code, stdout.getvalue()) == (0, "")


@pytest.mark.parametrize("payload", ["not json", "[]"])
def test_run_rejects_invalid_input_without_blocking(payload: str) -> None:
    """Invalid input exits with 1, a non-blocking error, instead of denying the tool call."""
    # Arrange
    stdout = io.StringIO()

    # Act
    code = run("pre-tool-use", io.StringIO(payload), stdout)

    # Assert
    assert (code, stdout.getvalue()) == (1, "")


def test_run_does_nothing_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """SECRET_GUARD_DISABLE=1 turns every hook off as an escape hatch."""
    # Arrange
    monkeypatch.setenv("SECRET_GUARD_DISABLE", "1")
    stdout = io.StringIO()

    # Act
    code = run("pre-tool-use", io.StringIO(json.dumps(bash("PGPASSWORD=Xk7pQ2mZ9vLr psql"))), stdout)

    # Assert
    assert (code, stdout.getvalue()) == (0, "")


def transcript(tmp_path: Path, name: str = "session.jsonl") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"type": "user", "message": {"content": "PGPASSWORD=Xk7pQ2mZ9vLr psql"}}) + "\n")
    return path


@pytest.mark.parametrize(
    ("event", "key"),
    [("Stop", "transcript_path"), ("SessionEnd", "transcript_path"), ("SubagentStop", "agent_transcript_path")],
)
def test_redact_masks_the_log_named_by_each_event(tmp_path: Path, event: str, key: str) -> None:
    """Stop and SessionEnd mask the session log; SubagentStop masks the subagent's own log."""
    # Arrange
    path = transcript(tmp_path)
    other = transcript(tmp_path, "other.jsonl")
    data: dict[str, object] = {"hook_event_name": event, "transcript_path": str(other), key: str(path)}

    # Act
    result = redact(data)

    # Assert
    assert result is None
    assert "Xk7pQ2mZ9vLr" not in path.read_text()


def test_redact_keeps_its_place_in_the_plugin_data_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Inside the plugin, how far each log was read is kept in CLAUDE_PLUGIN_DATA."""
    # Arrange
    path = transcript(tmp_path)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))

    # Act
    redact({"hook_event_name": "Stop", "transcript_path": str(path)})

    # Assert
    assert (tmp_path / "data" / "transcript-offsets.json").is_file()


@pytest.mark.parametrize("value", ["false", "0", "False"])
def test_redact_does_nothing_when_turned_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """Turning the redact_transcripts option off leaves the logs untouched."""
    # Arrange
    path = transcript(tmp_path)
    before = path.read_text()
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_REDACT_TRANSCRIPTS", value)

    # Act
    redact({"hook_event_name": "Stop", "transcript_path": str(path)})

    # Assert
    assert path.read_text() == before


def test_redact_is_on_when_the_option_is_true(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The option's default value, true, masks the log."""
    # Arrange
    path = transcript(tmp_path)
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_REDACT_TRANSCRIPTS", "true")

    # Act
    redact({"hook_event_name": "Stop", "transcript_path": str(path)})

    # Assert
    assert "Xk7pQ2mZ9vLr" not in path.read_text()


def test_redact_reports_a_missing_log_without_failing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A log that does not exist (e.g. transcript saving is off) is reported on stderr and the hook still succeeds."""
    # Act
    result = redact({"hook_event_name": "Stop", "transcript_path": str(tmp_path / "missing.jsonl")})

    # Assert
    assert result is None
    assert "cannot mask secrets" in capsys.readouterr().err


def test_redact_ignores_input_without_a_log_path() -> None:
    """Without a path there is nothing to do."""
    # Act & Assert
    assert redact({"hook_event_name": "Stop"}) is None
