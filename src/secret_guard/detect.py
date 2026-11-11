"""Find literal secrets in shell commands and permission rules.

The detectors target secrets that have no fixed shape (plain passwords after
``PGPASSWORD=``, ``mysql -p``, ``--password=`` and so on) as well as a few key
formats that do. A value that references a variable (``$DB_PASSWORD``) or is an
obvious placeholder is not reported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule: str
    description: str
    start: int
    end: int

    def masked(self, text: str) -> str:
        """Return the matched secret with all but the first two characters hidden."""
        value = text[self.start : self.end]
        return value[:2] + "***" if len(value) > 4 else "***"


_SECRET_NAME = (
    r"(?:[A-Za-z_][A-Za-z0-9_]*?)?"
    r"(?:PASSWORD|PASSWD|PASS|PWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)"
    r"[A-Za-z0-9_]*"
)
# Names that look like secrets but hold something else.
_NOT_SECRET_NAME = re.compile(
    r"^(?:OLD)?PWD$|TOKENS|TOKENIZER"
    r"|[_-](?:FILE|PATH|DIR|CMD|COMMAND|URL|URI|HOST|PORT|USER|USERNAME|NAME|ID|COUNT|LIMIT|SIZE|TTL"
    r"|EXPIRY|EXPIRES|LENGTH|LEN|TYPE|MODE|ENABLED|ENV|PROMPT|POLICY|PATTERN|REGEX|FORMAT|STRATEGY|STDIN)$",
    re.IGNORECASE,
)

# A shell word: double-quoted, single-quoted, or bare.
_WORD = r"""(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<bare>[^\s;&|<>()'"`]+))"""

_PLACEHOLDER = re.compile(
    r"""^(?:
        [*xX.\-_]+                      # ***, xxx, ...
      | (?:\\\*)+                       # \*\*\*, a *** escaped for grep
      | <[^>]*>                         # <password>
      | \{\{[^}]*\}\}                   # {{ password }}
      | \{[^{}]*\}(?:\\[nrt])*          # {password} of str.format and f-strings, maybe before "\n"
      | \[[^\]]*\]                      # [password]
      | (?:your|my)[_-]?\w*             # your_password
      | (?:password|passwd|secret|token|changeme|redacted|dummy|example|placeholder|none|null|true|false)
    )$""",
    re.IGNORECASE | re.VERBOSE,
)

# Commands that search for secrets write a pattern where the value goes: TOKEN=[a-f0-9]{32}, API_KEY=\S+.
# Only a value that starts with a character class or escape and a quantifier counts, because real
# passwords can contain [, { and \ too.
_REGEX_VALUE = re.compile(r"^(?:\[[^\]]+\]|\\[A-Za-z]|\.)(?:[*+?]|\{\d+(?:,\d*)?\})")

_MIN_SECRET_LENGTH = 3


def _is_reference(value: str) -> bool:
    return value.startswith(("$", "`")) or "$(" in value or "${" in value


def _is_literal_secret(value: str) -> bool:
    if len(value) < _MIN_SECRET_LENGTH:
        return False
    if _is_reference(value) or value.startswith("-"):
        return False
    return not _PLACEHOLDER.match(value) and not _REGEX_VALUE.match(value)


def _word_span(m: re.Match[str]) -> tuple[str, int, int] | None:
    for group in ("dq", "sq", "bare"):
        if m.group(group) is not None:
            return m.group(group), m.start(group), m.end(group)
    return None


@dataclass(frozen=True)
class _Detector:
    rule: str
    description: str
    pattern: re.Pattern[str]
    group: str | None = None  # None: use the shell word groups (dq/sq/bare)
    name_group: str | None = None


_DETECTORS: tuple[_Detector, ...] = (
    _Detector(
        "env-assignment",
        "secret assigned to an environment variable",
        # After an opening quote ('password=...' of curl -d), a quote right after = closes the string
        # (grep "DB_PASSWORD=" .), so the value there must be bare.
        re.compile(
            rf"(?:^|(?<=[\s;&|(=,?])|(?<=(?P<quote>['\"])))(?:export\s+)?(?P<name>{_SECRET_NAME})="
            rf"(?(quote)(?!['\"])){_WORD}",
            re.IGNORECASE,
        ),
        name_group="name",
    ),
    _Detector(
        "mysql-password",
        "password passed to a MySQL client with -p",
        re.compile(rf"\b(?:mysql\w*|mariadb\w*)\b[^;&|\n]*?\s-p{_WORD}"),
    ),
    _Detector(
        "sshpass",
        "password passed to sshpass -p",
        re.compile(rf"\bsshpass\b[^;&|\n]*?\s-p\s*{_WORD}"),
    ),
    _Detector(
        "redis-cli",
        "password passed to redis-cli -a",
        re.compile(rf"\bredis-cli\b[^;&|\n]*?\s-a\s+{_WORD}"),
    ),
    _Detector(
        "docker-login",
        "password passed to docker login -p",
        re.compile(rf"\b(?:docker|podman|nerdctl)\s+login\b[^;&|\n]*?\s-p\s+{_WORD}"),
    ),
    _Detector(
        "password-option",
        "secret passed as a command-line option",
        re.compile(
            rf"(?<![\w-])--?(?P<name>[a-z0-9-]*(?:password|passwd|secret|token|api-?key|access-key|private-key))(?:=|\s+){_WORD}",
            re.IGNORECASE,
        ),
        name_group="name",
    ),
    _Detector(
        "basic-auth-option",
        "user:password passed to -u/--user",
        re.compile(r"\b(?:curl|wget|http)\b[^;&|\n]*?\s(?:-u|--user)(?:=|\s*)['\"]?[^\s:'\"]+:(?P<value>[^\s'\"]+)"),
        group="value",
    ),
    _Detector(
        "url-userinfo",
        "password in the userinfo of a URL",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@'\"]*:(?P<value>[^\s/@'\"]+)@", re.IGNORECASE),
        group="value",
    ),
    _Detector(
        "auth-header",
        "credential in an HTTP header",
        re.compile(
            r"\b(?:Authorization|Proxy-Authorization)\s*:\s*(?:Bearer|Basic|Token|Bot|Digest)\s+(?P<value>[^\s'\"\\]+)",
            re.IGNORECASE,
        ),
        group="value",
    ),
    _Detector(
        "api-key-header",
        "credential in an HTTP header",
        re.compile(
            r"\b(?:X-API-Key|X-Auth-Token|X-Access-Token|Api-Key|Private-Token|X-Vault-Token)\s*:\s*(?P<value>[^\s'\"\\]+)",
            re.IGNORECASE,
        ),
        group="value",
    ),
    _Detector(
        "known-key",
        "token with a known key format",
        re.compile(
            r"""(?P<value>
                (?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}
              | github_pat_[A-Za-z0-9_]{22,}
              | glpat-[A-Za-z0-9_-]{20,}
              | (?:AKIA|ASIA)[0-9A-Z]{16}
              | sk-ant-[A-Za-z0-9_-]{20,}
              | sk-(?:proj-)?[A-Za-z0-9_-]{32,}
              | (?:sk|rk)_live_[A-Za-z0-9]{20,}
              | xox[abposr]-[A-Za-z0-9-]{10,}
              | AIza[0-9A-Za-z_-]{35}
              | npm_[A-Za-z0-9]{36}
              | hooks\.slack\.com/services/[A-Za-z0-9/]{20,}
              | eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}
              | -----BEGIN[ A-Z]*PRIVATE\ KEY-----
            )""",
            re.VERBOSE,
        ),
        group="value",
    ),
)


def find_secrets(text: str) -> list[Finding]:
    """Return literal secrets found in ``text``, ordered by position, without overlaps."""
    found: list[Finding] = []
    for detector in _DETECTORS:
        for m in detector.pattern.finditer(text):
            if detector.name_group and _NOT_SECRET_NAME.search(m.group(detector.name_group)):
                continue
            if detector.group is not None:
                value, start, end = m.group(detector.group), m.start(detector.group), m.end(detector.group)
            else:
                span = _word_span(m)
                if span is None:
                    continue
                value, start, end = span
            if detector.rule != "known-key" and not _is_literal_secret(value):
                continue
            found.append(Finding(detector.rule, detector.description, start, end))
    found.sort(key=lambda f: (f.start, -(f.end - f.start)))
    result: list[Finding] = []
    for f in found:
        if result and f.start < result[-1].end:
            continue
        result.append(f)
    return result


def redact(text: str, findings: list[Finding] | None = None) -> str:
    """Return ``text`` with every finding replaced by ``***``."""
    if findings is None:
        findings = find_secrets(text)
    out = text
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        out = out[: f.start] + "***" + out[f.end :]
    return out
