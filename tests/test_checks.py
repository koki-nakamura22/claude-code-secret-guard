from __future__ import annotations

from pathlib import Path

from conftest import git, write_settings

from secret_guard.checks import check_repository
from secret_guard.settings import LOCAL_SETTINGS, SHARED_SETTINGS

SECRET_RULE = "Bash(PGPASSWORD=Xk7pQ2mZ9vLr psql:*)"


def test_tracked_local_settings_is_an_error(repo: Path) -> None:
    """A tracked settings.local.json leaks on the next push, so it is an error."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})
    git(repo, "add", "-f", str(LOCAL_SETTINGS))

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [i.severity for i in issues] == ["error"]
    assert "rm --cached" in issues[0].message


def test_unignored_local_settings_is_an_error(repo: Path) -> None:
    """A settings.local.json that `git add .` would pick up is an error."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [i.severity for i in issues] == ["error"]
    assert "not ignored" in issues[0].message


def test_local_settings_ignored_only_on_this_machine_is_a_warning(repo: Path) -> None:
    """Ignoring the file only in .git/info/exclude leaves other clones unprotected."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "exclude").write_text(".claude/settings.local.json\n")

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [i.severity for i in issues] == ["warning"]
    assert "other machines" in issues[0].message


def test_secret_in_ignored_local_settings_is_a_warning_with_the_fix_command(repo: Path) -> None:
    """A saved secret is reported even when the file is ignored, with the command that removes it."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": [SECRET_RULE]}})

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [i.severity for i in issues] == ["warning"]
    assert "`fix-it`" in issues[0].message
    assert "Xk7pQ2mZ9vLr" not in issues[0].message


def test_secret_in_shared_settings_is_an_error(repo: Path) -> None:
    """settings.json is committed with the repository, so any secret in it is an error, including env values."""
    # Arrange
    write_settings(repo / SHARED_SETTINGS, {"env": {"API_TOKEN": "abcdef123456"}})

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [i.severity for i in issues] == ["error"]
    assert "env.API_TOKEN" in issues[0].message


def test_safe_repository_has_no_issues(repo: Path) -> None:
    """A repository without settings files, or with safe ones, has nothing to report."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": ["Bash(npm test:*)"]}})
    write_settings(repo / SHARED_SETTINGS, {"env": {"DEBUG": "1"}})

    # Act & Assert
    assert check_repository(repo, "fix-it") == []


def test_outside_git_still_checks_for_saved_secrets(tmp_path: Path) -> None:
    """Outside git, the git checks are skipped but saved secrets are still reported."""
    # Arrange
    write_settings(tmp_path / LOCAL_SETTINGS, {"permissions": {"allow": [SECRET_RULE]}})

    # Act
    issues = check_repository(tmp_path, "fix-it")

    # Assert
    assert [i.severity for i in issues] == ["warning"]
    assert "contain a secret" in issues[0].message
