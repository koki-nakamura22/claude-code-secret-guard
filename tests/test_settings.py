from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import git, write_settings

from secret_guard.settings import (
    LOCAL_SETTINGS,
    git_toplevels,
    ignore_status,
    is_tracked,
    remove_secret_rules,
    scan_settings,
)

SECRET_RULE = "Bash(PGPASSWORD=Xk7pQ2mZ9vLr psql -h db:*)"


def test_scan_reports_secret_rules_in_every_permission_list(tmp_path: Path) -> None:
    """Secrets are reported wherever a rule is saved (allow, ask and deny), redacted, with their location."""
    # Arrange
    path = write_settings(
        tmp_path / "settings.json",
        {"permissions": {"allow": ["Bash(npm test:*)", SECRET_RULE], "ask": [SECRET_RULE], "deny": [SECRET_RULE]}},
    )

    # Act
    report = scan_settings(path, include_env=False)

    # Assert
    assert [(s.location, s.redacted) for s in report.secrets] == [
        ("permissions.allow[1]", "Bash(PGPASSWORD=*** psql -h db:*)"),
        ("permissions.ask[0]", "Bash(PGPASSWORD=*** psql -h db:*)"),
        ("permissions.deny[0]", "Bash(PGPASSWORD=*** psql -h db:*)"),
    ]


def test_scan_reports_secret_env_values_only_when_asked(tmp_path: Path) -> None:
    """Env values are checked only on request, because env in a local file is a normal place for secrets."""
    # Arrange
    path = write_settings(tmp_path / "settings.json", {"env": {"DB_PASSWORD": "Pa55word", "DEBUG": "1"}})

    # Act
    without_env = scan_settings(path, include_env=False)
    with_env = scan_settings(path, include_env=True)

    # Assert
    assert without_env.secrets == []
    assert [s.location for s in with_env.secrets] == ["env.DB_PASSWORD"]


@pytest.mark.parametrize("value", ["", "$DB_PASSWORD", 1])
def test_scan_ignores_empty_referenced_or_non_string_env_values(tmp_path: Path, value: object) -> None:
    """Env values that are empty, references or not strings hold no secret."""
    # Arrange
    path = write_settings(tmp_path / "settings.json", {"env": {"DB_PASSWORD": value}})

    # Act & Assert
    assert scan_settings(path, include_env=True).secrets == []


@pytest.mark.parametrize(
    "data",
    [{}, {"permissions": "allow"}, {"permissions": {"allow": "Bash(ls)"}}, {"permissions": {"allow": [1, None]}}],
)
def test_scan_tolerates_unexpected_shapes(tmp_path: Path, data: dict[str, object]) -> None:
    """Settings that do not have the expected shape produce no findings and no error."""
    # Arrange
    path = write_settings(tmp_path / "settings.json", data)

    # Act
    report = scan_settings(path, include_env=True)

    # Assert
    assert (report.secrets, report.error) == ([], None)


@pytest.mark.parametrize("content", ["{not json", "[1, 2]"])
def test_scan_reports_unreadable_file_as_error(tmp_path: Path, content: str) -> None:
    """A file that is not a JSON object is reported as an error instead of crashing."""
    # Arrange
    path = tmp_path / "settings.json"
    path.write_text(content)

    # Act
    report = scan_settings(path, include_env=True)

    # Assert
    assert report.error is not None


def test_scan_reports_missing_file_as_error(tmp_path: Path) -> None:
    """A missing file is reported as an error instead of crashing."""
    # Act
    report = scan_settings(tmp_path / "missing.json", include_env=True)

    # Assert
    assert report.error is not None


def test_remove_secret_rules_keeps_other_rules_and_settings(tmp_path: Path) -> None:
    """Fixing removes only the rules with secrets and keeps every other setting."""
    # Arrange
    path = write_settings(
        tmp_path / "settings.local.json",
        {"permissions": {"allow": ["Bash(npm test:*)", SECRET_RULE], "deny": [SECRET_RULE]}, "model": "opus"},
    )

    # Act
    removed = remove_secret_rules(path)

    # Assert
    assert [s.location for s in removed] == ["permissions.allow[1]", "permissions.deny[0]"]
    assert json.loads(path.read_text()) == {"permissions": {"allow": ["Bash(npm test:*)"], "deny": []}, "model": "opus"}


def test_remove_secret_rules_leaves_clean_file_untouched(tmp_path: Path) -> None:
    """A file without secrets is not rewritten, so its formatting is preserved."""
    # Arrange
    path = tmp_path / "settings.local.json"
    original = '{"permissions": {"allow": ["Bash(npm test:*)"]}}'
    path.write_text(original)

    # Act
    removed = remove_secret_rules(path)

    # Assert
    assert removed == []
    assert path.read_text() == original


def test_tracked_file_is_reported_as_tracked(repo: Path) -> None:
    """A committed settings.local.json is recognised as tracked."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})
    git(repo, "add", "-f", str(LOCAL_SETTINGS))

    # Act & Assert
    assert is_tracked(repo, LOCAL_SETTINGS)


def test_untracked_file_is_not_reported_as_tracked(repo: Path) -> None:
    """A file that git does not know about is not tracked."""
    # Arrange
    write_settings(repo / LOCAL_SETTINGS, {})

    # Act & Assert
    assert not is_tracked(repo, LOCAL_SETTINGS)


def test_ignore_by_repository_gitignore_travels_with_the_repository(repo: Path) -> None:
    """An entry in the repository's .gitignore protects every clone."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")

    # Act
    status = ignore_status(repo, LOCAL_SETTINGS)

    # Assert
    assert (status.ignored, status.by_repository) == (True, True)


def test_ignore_by_global_excludes_does_not_travel(repo: Path, isolated_git: Path, tmp_path: Path) -> None:
    """The global excludes Claude Code writes protect only this machine."""
    # Arrange
    excludes = tmp_path / "global-ignore"
    excludes.write_text("**/.claude/settings.local.json\n")
    git(repo, "config", "--file", str(isolated_git), "core.excludesFile", str(excludes))

    # Act
    status = ignore_status(repo, LOCAL_SETTINGS)

    # Assert
    assert (status.ignored, status.by_repository) == (True, False)


def test_ignore_by_info_exclude_does_not_travel(repo: Path) -> None:
    """.git/info/exclude is per clone, so it does not protect other machines."""
    # Arrange
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "exclude").write_text(".claude/settings.local.json\n")

    # Act
    status = ignore_status(repo, LOCAL_SETTINGS)

    # Assert
    assert (status.ignored, status.by_repository) == (True, False)


def test_negated_ignore_rule_means_not_ignored(repo: Path) -> None:
    """A later `!` rule that re-includes the file wins over a broader ignore."""
    # Arrange
    (repo / ".gitignore").write_text(".claude/\n!.claude/\n.claude/*\n!.claude/settings.local.json\n")

    # Act & Assert
    assert not ignore_status(repo, LOCAL_SETTINGS).ignored


def test_file_without_ignore_rule_is_not_ignored(repo: Path) -> None:
    """Without any rule, the file would be picked up by `git add .`."""
    # Act & Assert
    assert not ignore_status(repo, LOCAL_SETTINGS).ignored


def test_linked_worktree_also_returns_main_checkout(repo: Path, tmp_path: Path) -> None:
    """In a linked worktree, the main checkout is checked too, because Claude Code writes the local settings there."""
    # Arrange
    (repo / "README").write_text("x")
    git(repo, "add", "README")
    git(repo, "commit", "-q", "-m", "init")
    worktree = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", str(worktree))

    # Act
    roots = git_toplevels(worktree)

    # Assert
    assert [r.resolve() for r in roots] == [worktree.resolve(), repo.resolve()]


def test_outside_git_returns_no_roots(tmp_path: Path) -> None:
    """Outside a repository there is nothing to check in git."""
    # Arrange
    plain = tmp_path / "plain"
    plain.mkdir()

    # Act & Assert
    assert git_toplevels(plain) == []
