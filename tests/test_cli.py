from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import write_settings

from secret_guard.cli import main
from secret_guard.settings import LOCAL_SETTINGS, SHARED_SETTINGS

SECRET_RULE = "Bash(PGPASSWORD=Xk7pQ2mZ9vLr psql:*)"
BIN = Path(__file__).resolve().parent.parent / "bin" / "secret-guard"


def test_check_files_rejects_a_staged_local_settings_file(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """In pre-commit mode, committing settings.local.json fails whatever it contains."""
    # Arrange
    path = write_settings(repo / LOCAL_SETTINGS, {})

    # Act
    code = main(["check", str(path)])

    # Assert
    assert code == 1
    assert "must not be committed" in capsys.readouterr().out


def test_check_files_rejects_shared_settings_with_a_secret(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """In pre-commit mode, a settings.json with a secret fails and the secret is not printed."""
    # Arrange
    path = write_settings(repo / SHARED_SETTINGS, {"permissions": {"allow": [SECRET_RULE]}})

    # Act
    code = main(["check", str(path)])

    # Assert
    out = capsys.readouterr().out
    assert code == 1
    assert "permissions.allow[0]" in out
    assert "Xk7pQ2mZ9vLr" not in out


def test_check_files_rejects_an_unreadable_settings_file(repo: Path) -> None:
    """In pre-commit mode, a broken settings.json fails instead of being skipped."""
    # Arrange
    path = repo / SHARED_SETTINGS
    path.write_text("{")

    # Act & Assert
    assert main(["check", str(path)]) == 1


def test_check_files_accepts_clean_and_deleted_files(repo: Path) -> None:
    """In pre-commit mode, clean files and paths that no longer exist pass."""
    # Arrange
    path = write_settings(repo / SHARED_SETTINGS, {"permissions": {"allow": ["Bash(npm test:*)"]}})

    # Act & Assert
    assert main(["check", str(path), str(repo / "gone" / "settings.json")]) == 0


def test_check_repository_fails_on_error(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without files, check inspects the current repository and fails on errors."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})
    monkeypatch.chdir(repo)

    # Act & Assert
    assert main(["check"]) == 1


def test_check_repository_passes_warnings_unless_strict(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Warnings pass by default and fail with --strict."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": [SECRET_RULE]}})
    monkeypatch.chdir(repo)

    # Act
    default = main(["check"])
    strict = main(["check", "--strict"])

    # Assert
    assert (default, strict) == (0, 1)


def test_check_repository_suggests_the_fix_command_for_a_terminal(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """check runs in the user's terminal, so the fix is offered as the plain `secret-guard fix` command."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": [SECRET_RULE]}})
    monkeypatch.chdir(repo)

    # Act
    main(["check"])

    # Assert
    assert "  1. Remove the saved rule: `secret-guard fix`\n" in capsys.readouterr().out


def test_check_repository_reports_success(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A clean repository passes with a short confirmation."""
    # Arrange
    monkeypatch.chdir(repo)

    # Act
    code = main(["check"])

    # Assert
    assert code == 0
    assert "no problems found" in capsys.readouterr().out


def test_fix_removes_secret_rules_from_the_repository_file(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """fix without arguments cleans the repository's settings.local.json."""
    # Arrange
    path = write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": ["Bash(ls)", SECRET_RULE]}})
    monkeypatch.chdir(repo)

    # Act
    code = main(["fix"])

    # Assert
    assert code == 0
    assert json.loads(path.read_text()) == {"permissions": {"allow": ["Bash(ls)"]}}


def test_fix_without_a_local_settings_file_does_nothing(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """fix in a repository without settings.local.json reports that there is nothing to do."""
    # Arrange
    monkeypatch.chdir(repo)

    # Act
    code = main(["fix"])

    # Assert
    assert code == 0
    assert "no settings.local.json" in capsys.readouterr().out


def test_scan_prints_redacted_lines_with_secrets(capsys: pytest.CaptureFixture[str]) -> None:
    """scan prints only the lines with secrets, redacted, and fails so it can gate scripts."""
    # Act
    code = main(["scan", "PGPASSWORD=Xk7pQ2mZ9vLr psql"])

    # Assert
    assert code == 1
    assert capsys.readouterr().out == "env-assignment\tPGPASSWORD=*** psql\n"


def test_scan_passes_clean_text(capsys: pytest.CaptureFixture[str]) -> None:
    """scan prints nothing and passes when there is no secret."""
    # Act
    code = main(["scan", "psql -h db"])

    # Assert
    assert (code, capsys.readouterr().out) == (0, "")


def test_unknown_command_is_a_usage_error() -> None:
    """An unknown subcommand exits with argparse's usage error."""
    # Act & Assert
    with pytest.raises(SystemExit) as exc:
        main(["nope"])
    assert exc.value.code == 2


def test_plugin_entry_point_runs_without_installation() -> None:
    """The script the plugin hooks call works from a plain checkout with an isolated interpreter."""
    # Arrange
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "PGPASSWORD=Xk7pQ2mZ9vLr psql"}})

    # Act
    proc = subprocess.run(
        [sys.executable, "-I", str(BIN), "hook", "pre-tool-use"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    # Assert
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_fix_cleans_an_explicit_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """fix with a path cleans that file, even outside a repository, and prints what it removed without the secret."""
    # Arrange
    path = write_settings(tmp_path / "custom.json", {"permissions": {"allow": [SECRET_RULE]}})

    # Act
    code = main(["fix", str(path)])

    # Assert
    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(path.read_text()) == {"permissions": {"allow": []}}
    assert "removed permissions.allow[0]" in out
    assert "Xk7pQ2mZ9vLr" not in out
