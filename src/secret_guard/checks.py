"""Repository-level checks shared by the SessionStart hook and the CLI.

Each issue is written for someone who has never heard of this tool: the first line says what is
wrong, then why it matters, then numbered steps.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .settings import (
    LOCAL_SETTINGS,
    SHARED_SETTINGS,
    IgnoreStatus,
    SecretRule,
    git_toplevels,
    ignore_status,
    is_tracked,
    scan_settings,
)


@dataclass
class Issue:
    severity: str  # "error": can leak through git now; "warning": a secret is saved locally
    message: str


_KEEPS_APPROVALS = 'This file keeps the commands you approved with "Yes, and don\'t ask again".'


def _home_relative(path: str) -> str:
    home = str(Path.home())
    return "~" + path[len(home) :] if path.startswith(home + "/") else path


def _steps(steps: list[str]) -> str:
    if len(steps) == 1:
        return f"What to do: {steps[0]}"
    return "What to do:\n" + "\n".join(f"  {n}. {step}" for n, step in enumerate(steps, 1))


def _rules(secrets: list[SecretRule]) -> str:
    # An env value is redacted to *** entirely, so its name is what tells the user which one it is.
    return "\n".join(f"  {s.location}" if s.location.startswith("env.") else f"  {s.redacted}" for s in secrets)


def _saved_secret(name: str, secrets: list[SecretRule]) -> str:
    what = "a password or token is" if len(secrets) == 1 else f"{len(secrets)} passwords or tokens are"
    return f"secret-guard: {what} saved in {name}\n{_rules(secrets)}"


def _them(count: int) -> str:
    return "the password or token" if count == 1 else "the passwords or tokens"


def _shared_steps(secrets: list[SecretRule]) -> list[str]:
    rules = sum(not s.location.startswith("env.") for s in secrets)
    values = len(secrets) - rules
    steps: list[str] = []
    if rules:
        steps.append(f"Remove the {'rule' if rules == 1 else 'rules'} from the file.")
    if values:
        value, it = ("value", "it") if values == 1 else ("values", "them")
        steps.append(f"Remove the {value} from the file, and read {it} from an environment variable instead.")
    steps.append(f"Change {_them(len(secrets))}.")
    return steps


def _unreadable(name: str, reason: str, *, local: bool) -> Issue:
    # settings.local.json holds only this machine's approvals, so starting over is safe; settings.json is shared.
    step = "Fix the file by hand, or delete it to start over." if local else "Fix the file by hand."
    return Issue("warning", f"secret-guard: cannot read {name} ({reason})\n{_steps([step])}")


def _local_issue(
    name: str, git_c: str, tracked: bool, status: IgnoreStatus | None, secrets: list[SecretRule], fix_command: str
) -> Issue | None:
    """Describe settings.local.json: the saved secrets first, then what keeps the file out of git."""
    gitignore_step = f"Add `{LOCAL_SETTINGS}` to .gitignore."
    them = _them(len(secrets))
    goes = "goes" if len(secrets) == 1 else "go"
    if tracked:
        severity = "error"
        leak = f"It is tracked by git, so your next push puts {them} on GitHub."
        risk = "It is tracked by git, so your next push puts it on GitHub."
        git_steps = [f"Stop tracking it: `git{git_c} rm --cached {LOCAL_SETTINGS}`", gitignore_step]
    elif status is not None and not status.ignored:
        severity = "error"
        leak = f"It is not ignored by git, so `git add .` would commit it and put {them} on GitHub."
        risk = "It is not ignored by git, so `git add .` would commit it and put it on GitHub."
        git_steps = [gitignore_step]
    elif status is not None and not status.by_repository:
        severity = "warning"
        only_here = (
            f"Only {_home_relative(status.source or '')} on this machine keeps it out of git; "
            "other machines, containers and CI do not have that file."
        )
        leak = f"If it is committed, {them} {goes} to GitHub. {only_here}"
        risk = f"{only_here} A commit from there would include it."
        git_steps = [gitignore_step]
    else:
        severity = "warning"
        leak = f"If it is ever committed, {them} {goes} to GitHub."
        risk = ""
        git_steps = []

    if secrets:
        steps = [
            f"Remove the saved {'rule' if len(secrets) == 1 else 'rules'}: `{fix_command}`",
            f"Change {them}. {'It was' if len(secrets) == 1 else 'They were'} stored in plain text on this machine.",
            *git_steps,
        ]
        return Issue(severity, f"{_saved_secret(name, secrets)}\n{_KEEPS_APPROVALS} {leak}\n{_steps(steps)}")

    if not git_steps:
        return None
    if tracked:
        headline = f"{name} is tracked by git"
        git_steps.append("If it was ever pushed, change every password or token it contained.")
    elif severity == "error":
        headline = f"{name} is not ignored by git"
    else:
        headline = f"{name} is kept out of git only on this machine"
    reason = f"{_KEEPS_APPROVALS} They can contain passwords or tokens. {risk}"
    return Issue(severity, f"secret-guard: {headline}\n{reason}\n{_steps(git_steps)}")


def check_repository(start: Path, fix_command: str) -> list[Issue]:
    """Check the settings files of the repository that contains ``start``."""
    # The saved secrets matter most, so they come before the warnings about git.
    saved: list[Issue] = []
    others: list[Issue] = []
    roots = git_toplevels(start)
    for index, root in enumerate(roots or [start]):
        in_git = bool(roots)
        # The second root is the main checkout of a linked worktree; a bare relative path would be ambiguous.
        prefix = "" if index == 0 else f"{root}/"
        git_c = "" if index == 0 and root.resolve() == start.resolve() else f" -C {root}"
        local = root / LOCAL_SETTINGS
        shared = root / SHARED_SETTINGS
        if local.is_file():
            tracked = in_git and is_tracked(root, LOCAL_SETTINGS)
            status = ignore_status(root, LOCAL_SETTINGS) if in_git and not tracked else None
            report = scan_settings(local, include_env=False)
            if report.error:
                others.append(_unreadable(f"{prefix}{LOCAL_SETTINGS}", report.error, local=True))
            issue = _local_issue(f"{prefix}{LOCAL_SETTINGS}", git_c, tracked, status, report.secrets, fix_command)
            if issue is not None:
                (saved if report.secrets else others).append(issue)
        if shared.is_file():
            report = scan_settings(shared, include_env=True)
            if report.error:
                others.append(_unreadable(f"{prefix}{SHARED_SETTINGS}", report.error, local=False))
            if report.secrets:
                is_ = "is" if len(report.secrets) == 1 else "are"
                reason = (
                    f"This file is committed with the repository, so {_them(len(report.secrets))} {is_} on GitHub "
                    "or soon will be."
                )
                steps = _shared_steps(report.secrets)
                message = f"{_saved_secret(f'{prefix}{SHARED_SETTINGS}', report.secrets)}\n{reason}\n{_steps(steps)}"
                saved.append(Issue("error", message))
    return saved + others
