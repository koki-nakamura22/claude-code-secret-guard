"""Repository-level checks shared by the SessionStart hook and the CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .settings import (
    LOCAL_SETTINGS,
    SHARED_SETTINGS,
    git_toplevels,
    ignore_status,
    is_tracked,
    scan_settings,
)


@dataclass
class Issue:
    severity: str  # "error": can leak through git now; "warning": a secret is saved locally
    message: str


def _secret_lines(report_secrets: list[tuple[str, str]]) -> str:
    return "\n".join(f"  - {loc}: {text}" for loc, text in report_secrets)


def check_repository(start: Path, fix_command: str) -> list[Issue]:
    """Check the settings files of the repository that contains ``start``."""
    issues: list[Issue] = []
    roots = git_toplevels(start)
    for root in roots or [start]:
        in_git = bool(roots)
        local = root / LOCAL_SETTINGS
        shared = root / SHARED_SETTINGS
        if local.is_file():
            if in_git and is_tracked(root, LOCAL_SETTINGS):
                issues.append(
                    Issue(
                        "error",
                        f"{local} is tracked by git. Untrack it with "
                        f"`git -C {root} rm --cached {LOCAL_SETTINGS}` and add `{LOCAL_SETTINGS}` to .gitignore. "
                        "If it was ever pushed, rotate every secret it contains.",
                    )
                )
            elif in_git:
                status = ignore_status(root, LOCAL_SETTINGS)
                if not status.ignored:
                    gitignore = root / ".gitignore"
                    message = f"{local} is not ignored by git. Add `{LOCAL_SETTINGS}` to {gitignore}."
                    issues.append(Issue("error", message))
                elif not status.by_repository:
                    issues.append(
                        Issue(
                            "warning",
                            f"{local} is ignored only by {status.source}, which other machines, containers and CI "
                            f"do not have. Add `{LOCAL_SETTINGS}` to {root / '.gitignore'}.",
                        )
                    )
            report = scan_settings(local, include_env=False)
            if report.error:
                issues.append(Issue("warning", report.error))
            if report.secrets:
                lines = _secret_lines([(s.location, s.redacted) for s in report.secrets])
                issues.append(
                    Issue(
                        "warning",
                        f"{len(report.secrets)} permission rule(s) in {local} contain a secret:\n{lines}\n"
                        f"Remove them with `{fix_command}` and rotate the secrets.",
                    )
                )
        if shared.is_file():
            report = scan_settings(shared, include_env=True)
            if report.error:
                issues.append(Issue("warning", report.error))
            if report.secrets:
                lines = _secret_lines([(s.location, s.redacted) for s in report.secrets])
                issues.append(
                    Issue(
                        "error",
                        f"{shared} is shared with the repository and contains a secret:\n{lines}\n"
                        "Move secrets out of it and rotate them.",
                    )
                )
    return issues
