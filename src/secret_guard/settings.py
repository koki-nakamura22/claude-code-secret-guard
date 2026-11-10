"""Inspect Claude Code settings files for saved secrets and git exposure."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .detect import find_secrets, redact

PERMISSION_KEYS = ("allow", "ask", "deny")
LOCAL_SETTINGS = Path(".claude") / "settings.local.json"
SHARED_SETTINGS = Path(".claude") / "settings.json"

_SECRET_ENV_NAME = re.compile(
    r"PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL", re.IGNORECASE
)


@dataclass
class SecretRule:
    location: str  # e.g. "permissions.allow[3]" or "env.DB_PASSWORD"
    redacted: str


@dataclass
class FileReport:
    path: Path
    secrets: list[SecretRule] = field(default_factory=list)
    error: str | None = None


def _load(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("top level is not a JSON object")
    return data


def _permission_lists(data: dict[str, object]) -> list[tuple[str, list[object]]]:
    perms = data.get("permissions")
    if not isinstance(perms, dict):
        return []
    lists: list[tuple[str, list[object]]] = []
    for key in PERMISSION_KEYS:
        rules = perms.get(key)
        if isinstance(rules, list):
            lists.append((key, rules))
    return lists


def scan_settings(path: Path, *, include_env: bool) -> FileReport:
    """Report secrets saved in the permission rules (and, if asked, the env) of a settings file."""
    report = FileReport(path)
    try:
        data = _load(path)
    except (OSError, ValueError) as e:
        report.error = f"cannot read {path}: {e}"
        return report
    for key, rules in _permission_lists(data):
        for i, rule in enumerate(rules):
            if isinstance(rule, str) and find_secrets(rule):
                report.secrets.append(SecretRule(f"permissions.{key}[{i}]", redact(rule)))
    env = data.get("env")
    if include_env and isinstance(env, dict):
        for name, value in env.items():
            if not isinstance(value, str) or not value or value.startswith("$"):
                continue
            if _SECRET_ENV_NAME.search(name) or find_secrets(value):
                report.secrets.append(SecretRule(f"env.{name}", "***"))
    return report


def remove_secret_rules(path: Path) -> list[SecretRule]:
    """Delete permission rules that contain secrets from ``path`` and return what was removed."""
    data = _load(path)
    removed: list[SecretRule] = []
    for key, rules in _permission_lists(data):
        kept: list[object] = []
        for i, rule in enumerate(rules):
            if isinstance(rule, str) and find_secrets(rule):
                removed.append(SecretRule(f"permissions.{key}[{i}]", redact(rule)))
            else:
                kept.append(rule)
        rules[:] = kept
    if removed:
        tmp = path.with_name(path.name + ".secret-guard.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    return removed


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False)


def git_toplevels(start: Path) -> list[Path]:
    """Return the work tree root of ``start`` and, for a linked worktree, the main checkout root.

    Claude Code writes ``settings.local.json`` of a worktree into the main checkout.
    """
    top = _git(start, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return []
    roots = [Path(top.stdout.strip())]
    common = _git(start, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if common.returncode == 0:
        common_dir = Path(common.stdout.strip())
        if common_dir.name == ".git" and common_dir.parent not in roots:
            roots.append(common_dir.parent)
    return roots


def is_tracked(repo: Path, rel: Path) -> bool:
    return _git(repo, "ls-files", "--error-unmatch", "--", str(rel)).returncode == 0


@dataclass
class IgnoreStatus:
    ignored: bool
    by_repository: bool  # ignored by a .gitignore that is committed with the repository
    source: str | None


def ignore_status(repo: Path, rel: Path) -> IgnoreStatus:
    """Tell whether ``rel`` is ignored, and whether the rule travels with the repository.

    Claude Code adds the file to the *global* excludes only, which does not exist on
    another machine, in a container or in CI.
    """
    res = _git(repo, "check-ignore", "-v", "--no-index", "--", str(rel))
    if res.returncode != 0 or not res.stdout.strip():
        return IgnoreStatus(False, False, None)
    m = re.match(r"^(.*?):\d+:(.*?)\t", res.stdout)
    if m is None:
        return IgnoreStatus(False, False, None)
    source, pattern = m.group(1), m.group(2)
    if pattern.startswith("!"):
        return IgnoreStatus(False, False, source)
    src_path = Path(source)
    if not src_path.is_absolute():
        src_path = repo / src_path
    try:
        rel_source = src_path.resolve().relative_to(repo.resolve())
        inside = ".git" not in rel_source.parts
    except (OSError, ValueError):
        inside = False
    return IgnoreStatus(True, inside and src_path.name == ".gitignore", source)


def staged_files(repo: Path) -> list[str]:
    res = _git(repo, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    return [line for line in res.stdout.splitlines() if line]
