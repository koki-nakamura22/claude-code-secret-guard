from __future__ import annotations

import re
from pathlib import Path

import pytest
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
    assert "saved in .claude/settings.local.json" in issues[0].message


def test_secret_in_unignored_local_settings_is_one_error_with_every_step(repo: Path) -> None:
    """A saved secret in a file git would commit is one error that lists removing, changing and ignoring, in order."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": [SECRET_RULE]}})

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [i.severity for i in issues] == ["error"]
    steps = re.findall(r"^  \d\. (.*)$", issues[0].message, re.MULTILINE)
    assert len(steps) == 3
    assert "`fix-it`" in steps[0]
    assert "Change the password" in steps[1]
    assert ".gitignore" in steps[2]


def test_first_line_says_what_is_saved_and_where(repo: Path) -> None:
    """The first line alone tells the user that a secret is saved, and in which file."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": [SECRET_RULE]}})

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert issues[0].message.splitlines()[0] == (
        "secret-guard: a password or token is saved in .claude/settings.local.json"
    )


def test_saved_secret_comes_before_warnings_about_git(repo: Path) -> None:
    """A secret saved in the shared settings is reported before the warning that the local file is ignored only here."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "exclude").write_text(".claude/settings.local.json\n")
    write_settings(repo / SHARED_SETTINGS, {"env": {"API_TOKEN": "abcdef123456"}})

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [i.message.splitlines()[0] for i in issues] == [
        "secret-guard: a password or token is saved in .claude/settings.json",
        "secret-guard: .claude/settings.local.json is kept out of git only on this machine",
    ]


def test_messages_name_files_relative_to_the_repository(repo: Path) -> None:
    """Long absolute paths bury the point, so the repository's own files are named by their relative path."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})
    git(repo, "add", "-f", str(LOCAL_SETTINGS))

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert str(repo) not in issues[0].message
    assert "`git rm --cached .claude/settings.local.json`" in issues[0].message


def test_global_excludes_file_is_shown_under_home(repo: Path) -> None:
    """The global excludes file is shown as ~/..., the way people write it, instead of the full home path."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})
    excludes = Path.home() / ".config" / "git" / "ignore"
    excludes.parent.mkdir(parents=True)
    excludes.write_text("**/.claude/settings.local.json\n")

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [i.severity for i in issues] == ["warning"]
    assert "Only ~/.config/git/ignore on this machine" in issues[0].message


def test_main_checkout_of_a_worktree_is_named_by_its_full_path(repo: Path, tmp_path: Path) -> None:
    """From a linked worktree, the main checkout's file is named in full, so it is not mistaken for the worktree's."""
    # Arrange
    (repo / "README").write_text("x")
    git(repo, "add", "README")
    git(repo, "commit", "-q", "-m", "init")
    worktree = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", str(worktree))
    write_settings(repo / LOCAL_SETTINGS, {})
    git(repo, "add", "-f", str(LOCAL_SETTINGS))

    # Act
    issues = check_repository(worktree, "fix-it")

    # Assert
    root = repo.resolve()
    assert issues[0].message.splitlines()[0] == f"secret-guard: {root}/.claude/settings.local.json is tracked by git"
    assert f"`git -C {root} rm --cached .claude/settings.local.json`" in issues[0].message


def test_unreadable_local_settings_says_where_and_what_to_do(repo: Path) -> None:
    """A broken settings.local.json is named by its relative path with a short reason, and may simply be deleted."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    (repo / LOCAL_SETTINGS).write_text("{ not json")

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [(i.severity, i.message) for i in issues] == [
        (
            "warning",
            "secret-guard: cannot read .claude/settings.local.json (not valid JSON: line 1 column 3)\n"
            "What to do: Fix the file by hand, or delete it to start over.",
        )
    ]


def test_unreadable_shared_settings_is_not_suggested_for_deletion(repo: Path) -> None:
    """settings.json is shared with the repository, so the user is told to fix it, not to delete it."""
    # Arrange
    (repo / SHARED_SETTINGS).write_text("[1, 2]")

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert [i.message for i in issues] == [
        "secret-guard: cannot read .claude/settings.json (top level is not a JSON object)\n"
        "What to do: Fix the file by hand."
    ]


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (
            {"permissions": {"allow": [SECRET_RULE]}},
            ["Remove the rule from the file.", "Change the password or token."],
        ),
        (
            {"env": {"API_TOKEN": "abcdef123456", "DB_PASSWORD": "Pa55word"}},
            [
                "Remove the values from the file, and read them from an environment variable instead.",
                "Change the passwords or tokens.",
            ],
        ),
        (
            {"permissions": {"allow": [SECRET_RULE]}, "env": {"API_TOKEN": "abcdef123456"}},
            [
                "Remove the rule from the file.",
                "Remove the value from the file, and read it from an environment variable instead.",
                "Change the passwords or tokens.",
            ],
        ),
    ],
    ids=["rule", "env-values", "rule-and-env"],
)
def test_steps_for_shared_settings_match_what_holds_the_secret(
    repo: Path, settings: dict[str, object], expected: list[str]
) -> None:
    """A saved rule is removed, while an env value is moved to an environment variable; both may appear together."""
    # Arrange
    write_settings(repo / SHARED_SETTINGS, settings)

    # Act
    issues = check_repository(repo, "fix-it")

    # Assert
    assert re.findall(r"^  \d\. (.*)$", issues[0].message, re.MULTILINE) == expected


@pytest.mark.parametrize(
    ("rules", "expected"),
    [
        (
            [SECRET_RULE],
            [
                "If it is ever committed, the password or token goes to GitHub.",
                "Change the password or token. It was stored in plain text on this machine.",
            ],
        ),
        (
            [SECRET_RULE, SECRET_RULE.replace("Xk", "Ab")],
            [
                "If it is ever committed, the passwords or tokens go to GitHub.",
                "Change the passwords or tokens. They were stored in plain text on this machine.",
            ],
        ),
    ],
    ids=["one", "two"],
)
def test_message_speaks_of_one_or_several_secrets_consistently(
    repo: Path, rules: list[str], expected: list[str]
) -> None:
    """The body says "password or token" like the first line, in the singular or plural to match the count."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    write_settings(repo / LOCAL_SETTINGS, {"permissions": {"allow": rules}})

    # Act
    message = check_repository(repo, "fix-it")[0].message

    # Assert
    assert [sentence for sentence in expected if sentence not in message] == []
