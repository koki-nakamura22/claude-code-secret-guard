"""Command-line interface: ``secret-guard check | fix | scan | hook``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, hooks
from .checks import check_repository
from .detect import find_secrets, redact
from .settings import LOCAL_SETTINGS, git_toplevels, remove_secret_rules, scan_settings


def _is_local_settings(path: Path) -> bool:
    return path.name == LOCAL_SETTINGS.name and path.parent.name == LOCAL_SETTINGS.parent.name


def _check_files(paths: list[Path]) -> int:
    """Pre-commit mode: the given files are about to be committed."""
    status = 0
    for path in paths:
        if _is_local_settings(path):
            print(
                f"{path}: personal Claude Code settings must not be committed. "
                f"Run `git rm --cached {path}` and add `{LOCAL_SETTINGS}` to .gitignore."
            )
            status = 1
            continue
        if not path.is_file():
            continue
        report = scan_settings(path, include_env=True)
        if report.error:
            print(report.error)
            status = 1
        for s in report.secrets:
            print(f"{path}: {s.location} contains a secret: {s.redacted}")
            status = 1
    return status


def cmd_check(args: argparse.Namespace) -> int:
    if args.files:
        return _check_files([Path(f) for f in args.files])
    issues = check_repository(Path.cwd(), "secret-guard fix")
    if not issues:
        print("secret-guard: no problems found")
        return 0
    print("\n\n".join(i.message for i in issues))
    if any(i.severity == "error" for i in issues):
        return 1
    return 1 if args.strict else 0


def cmd_fix(args: argparse.Namespace) -> int:
    if args.file:
        targets = [Path(args.file)]
    else:
        roots = git_toplevels(Path.cwd()) or [Path.cwd()]
        targets = [r / LOCAL_SETTINGS for r in roots if (r / LOCAL_SETTINGS).is_file()]
    if not targets:
        print("secret-guard: no settings.local.json found")
        return 0
    for target in targets:
        removed = remove_secret_rules(target)
        for s in removed:
            print(f"{target}: removed {s.location}: {s.redacted}")
        if not removed:
            print(f"{target}: no rules with secrets")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Print the secrets found in each line of the input. Exit 1 if any were found."""
    text = " ".join(args.text) if args.text else sys.stdin.read()
    found = False
    for line in text.splitlines() or [text]:
        findings = find_secrets(line)
        if findings:
            found = True
            print(f"{', '.join(f.rule for f in findings)}\t{redact(line, findings)}")
    return 1 if found else 0


def cmd_hook(args: argparse.Namespace) -> int:
    return hooks.run(args.event)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-guard", description="Keep secrets out of Claude Code permission rules and out of git."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="check the repository, or the given files before a commit")
    p.add_argument("files", nargs="*", help="files about to be committed (pre-commit mode)")
    p.add_argument("--strict", action="store_true", help="also fail on warnings")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("fix", help="remove permission rules that contain secrets from settings.local.json")
    p.add_argument("file", nargs="?", help="settings file (default: .claude/settings.local.json of this repository)")
    p.set_defaults(func=cmd_fix)

    p = sub.add_parser("scan", help="print secrets found in text (arguments, or stdin line by line)")
    p.add_argument("text", nargs="*")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("hook", help="run as a Claude Code hook")
    p.add_argument("event", choices=sorted(hooks.HANDLERS))
    p.set_defaults(func=cmd_hook)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))
