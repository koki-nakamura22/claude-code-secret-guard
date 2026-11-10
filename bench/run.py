"""Compare secret-guard with gitleaks and TruffleHog on fake settings.local.json rules.

Every secret here is fake. Tokens with a known shape are assembled at run time so that
the repository itself never contains a string that looks like a real token.

    python3 bench/run.py            # print a Markdown table
    python3 bench/run.py --json     # machine-readable results
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secret_guard.detect import find_secrets


def _token(prefix: str, body: str, length: int) -> str:
    return prefix + (body * length)[:length]


SLACK_WEBHOOK = (
    "https://hooks.slack.com/services/"
    + _token("T0", "8X4K2M9P", 9)
    + "/"
    + _token("B0", "7Q3W5E1R", 9)
    + "/"
    + _token("", "a1B2c3D4e5F6g7H8i9J0k1L2", 24)
)

# (category, command, has_secret)
CASES: list[tuple[str, str, bool]] = [
    ("env", "PGPASSWORD=Xk7pQ2mZ9vLr psql -h db.internal -U app -d shop", True),
    ("env", "MYSQL_PWD=Tr0ub4dor3 mysql -u root shop", True),
    ("env", "DB_PASSWORD=pa55w0rd-prod ./manage.py migrate", True),
    ("env", "REDIS_PASSWORD=Qw3rty778 redis-cli ping", True),
    ("env", "export API_TOKEN=c0ffee15b4d4ndl0ng && ./deploy.sh", True),
    ("env", "kubectl create secret generic db --from-literal=password=Sup3rSecret9", True),
    ("cli", "mysql -h db.internal -u root -pHunter2xx shop", True),
    ("cli", "mysqldump -u backup -p'B4ckup!2026' --all-databases", True),
    ("cli", "sshpass -p 'Tr0ub4dor&3' ssh deploy@10.0.0.5", True),
    ("cli", "redis-cli -h cache.internal -a S3cretRedis ping", True),
    ("cli", "docker login -u ci -p Regi5tryPass registry.example.com", True),
    ("cli", "pg_dump --dbname=shop --password=Sup3rSecret db.internal", True),
    ("cli", "some-cli --api-key 4f9a8b7c6d5e4f3a2b1c run", True),
    ("url", "psql postgres://app:Pa55word@db.example.com:5432/shop", True),
    ("url", "mongosh mongodb://admin:M0ng0Pass@mongo.internal:27017/admin", True),
    ("url", "curl -u admin:Pa55word123 https://jenkins.internal/api/json", True),
    ("header", 'curl -H "Authorization: Bearer abcDEF123456ghiJKL" https://api.example.com/v1/me', True),
    ("header", "curl -H 'Authorization: Basic YWRtaW46UGE1NXdvcmQ=' https://api.example.com", True),
    ("header", "curl -H 'X-API-Key: 9d8c7b6a5f4e3d2c1b0a' https://api.example.com", True),
    ("known", "gh api user -H 'Authorization: token " + _token("ghp_", "A1b2C3d4E5f6G7h8I9j0", 36) + "'", True),
    ("known", "AWS_ACCESS_KEY_ID=" + _token("AKIA", "Q7W3E6R2T5Y4U3I2", 16) + " aws s3 ls", True),
    ("known", "curl -X POST " + SLACK_WEBHOOK, True),
    ("known", "ANTHROPIC_API_KEY=" + _token("sk-ant-api03-", "Zx9Yw8Vu7Ts6Rq5Po4", 93) + "AA" + " claude -p hi", True),
    # Secrets in positions secret-guard does not know about yet.
    ("other", "htpasswd -b -c .htpasswd admin Adm1nPass", True),
    ("other", "openssl pkcs12 -in cert.p12 -passin pass:P12Secret -nokeys", True),
    ("other", "echo 'SudoPa55' | sudo -S apt-get update", True),
    # Harmless commands: anything reported here is a false positive.
    ("clean", 'PGPASSWORD="$DB_PASSWORD" psql -h db.internal -U app', False),
    ("clean", "mysql -u root -p shop", False),
    ("clean", 'curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com', False),
    ("clean", "psql postgres://app:${DB_PASSWORD}@db:5432/shop", False),
    ("clean", 'echo "$REGISTRY_PASSWORD" | docker login --password-stdin registry.example.com', False),
    ("clean", "npm test -- --max-tokens 4096", False),
    ("clean", "git clone https://github.com/org/repo.git", False),
    ("clean", "TOKENIZERS_PARALLELISM=false python train.py", False),
    ("clean", "op run --env-file=.env -- ./deploy.sh", False),
    ("clean", "aws s3 ls --profile prod", False),
]


def write_fixture(directory: Path) -> tuple[Path, dict[int, int]]:
    """Write one settings.local.json with one rule per line. Return it and a map from line number to case index."""
    path = directory / ".claude" / "settings.local.json"
    path.parent.mkdir(parents=True)
    lines = ["{", '  "permissions": {', '    "allow": [']
    line_to_case: dict[int, int] = {}
    for i, (_, command, _) in enumerate(CASES):
        comma = "," if i < len(CASES) - 1 else ""
        lines.append(f"      {json.dumps(f'Bash({command}:*)')}{comma}")
        line_to_case[len(lines)] = i
    lines += ["    ]", "  }", "}"]
    path.write_text("\n".join(lines) + "\n")
    return path, line_to_case


def run_secret_guard() -> set[int]:
    return {i for i, (_, command, _) in enumerate(CASES) if find_secrets(f"Bash({command}:*)")}


def run_gitleaks(directory: Path, line_to_case: dict[int, int]) -> set[int] | None:
    exe = shutil.which("gitleaks")
    if exe is None:
        return None
    report = directory / "gitleaks.json"
    subprocess.run(
        [exe, "dir", str(directory / ".claude"), "--no-banner", "--report-format=json", f"--report-path={report}"],
        capture_output=True,
        check=False,
    )
    findings = json.loads(report.read_text() or "[]")
    return {line_to_case[f["StartLine"]] for f in findings if f["StartLine"] in line_to_case}


def run_trufflehog(directory: Path, line_to_case: dict[int, int]) -> set[int] | None:
    exe = shutil.which("trufflehog")
    if exe is None:
        return None
    proc = subprocess.run(
        [exe, "filesystem", str(directory / ".claude"), "--json", "--no-verification", "--no-update"],
        capture_output=True,
        text=True,
        check=False,
    )
    hits: set[int] = set()
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        number = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line")
        if number in line_to_case:
            hits.add(line_to_case[number])
    return hits


def version(exe: str, *args: str) -> str:
    path = shutil.which(exe)
    if path is None:
        return "not installed"
    proc = subprocess.run([path, *args], capture_output=True, text=True, check=False)
    return (proc.stdout or proc.stderr).strip().splitlines()[-1] if (proc.stdout or proc.stderr) else "unknown"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        _, line_to_case = write_fixture(directory)
        results: dict[str, set[int] | None] = {
            "secret-guard": run_secret_guard(),
            "gitleaks": run_gitleaks(directory, line_to_case),
            "trufflehog": run_trufflehog(directory, line_to_case),
        }
    versions = {"gitleaks": version("gitleaks", "version"), "trufflehog": version("trufflehog", "--version")}

    positives = [i for i, c in enumerate(CASES) if c[2]]
    negatives = [i for i, c in enumerate(CASES) if not c[2]]
    if args.json:
        out = {
            "versions": versions,
            "cases": [
                {"category": c[0], "has_secret": c[2], **{k: (v is not None and i in v) for k, v in results.items()}}
                for i, c in enumerate(CASES)
            ],
        }
        print(json.dumps(out, indent=2))
        return 0

    categories = sorted({c[0] for c in CASES if c[2]})
    names = list(results)
    print("| category | cases | " + " | ".join(names) + " |")
    print("|---|---|" + "---|" * len(names))
    for cat in [*categories, "clean"]:
        idx = [i for i, c in enumerate(CASES) if c[0] == cat]
        cells = []
        for name in names:
            hits = results[name]
            cells.append("n/a" if hits is None else str(len(hits.intersection(idx))))
        label = f"{cat} (false positives)" if cat == "clean" else cat
        print(f"| {label} | {len(idx)} | " + " | ".join(cells) + " |")
    cells = []
    for name in names:
        hits = results[name]
        cells.append("n/a" if hits is None else f"{len(hits.intersection(positives))}/{len(positives)}")
    print("| **detected** | | " + " | ".join(cells) + " |")
    print(f"\nnegatives: {len(negatives)}; gitleaks: {versions['gitleaks']}; trufflehog: {versions['trufflehog']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
