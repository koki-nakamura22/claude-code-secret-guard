from __future__ import annotations

import pytest
from conftest import FAKE_AWS_KEY_ID, FAKE_GITHUB_TOKEN

from secret_guard.detect import Finding, find_secrets, redact


@pytest.mark.parametrize(
    ("command", "rule", "secret"),
    [
        ("PGPASSWORD=Xk7pQ2mZ9vLr psql -h db -U app", "env-assignment", "Xk7pQ2mZ9vLr"),
        ("export MYSQL_PWD='s3cr3t-Pa55' && mysql -u root", "env-assignment", "s3cr3t-Pa55"),
        ('cd /srv && DB_PASSWORD="Pa55 word" ./migrate', "env-assignment", "Pa55 word"),
        ("password=hunter22", "env-assignment", "hunter22"),
        ("kubectl create secret generic db --from-literal=password=Sup3rSecret", "env-assignment", "Sup3rSecret"),
        ("mysql -u root -pHunter2xx shop", "mysql-password", "Hunter2xx"),
        ("mysqldump -u root -p'Hunter2xx' shop", "mysql-password", "Hunter2xx"),
        ("sshpass -p 'Tr0ub4dor&3' ssh deploy@host", "sshpass", "Tr0ub4dor&3"),
        ("redis-cli -h cache -a S3cretRedis ping", "redis-cli", "S3cretRedis"),
        ("docker login -u me -p Sup3rSecret registry.example.com", "docker-login", "Sup3rSecret"),
        ("mysqldump --password=Sup3rSecret db", "password-option", "Sup3rSecret"),
        ("some-cli --api-key abcdef0123456789 run", "password-option", "abcdef0123456789"),
        ("curl -u admin:Pa55word123 https://example.com", "basic-auth-option", "Pa55word123"),
        ("psql postgres://app:Pa55word@db.example.com:5432/shop", "url-userinfo", "Pa55word"),
        ('curl -H "Authorization: Bearer abcDEF123456ghi" https://api.example.com', "auth-header", "abcDEF123456ghi"),
        ("curl -H 'PRIVATE-TOKEN: glxyz0123456789' https://gitlab.example.com", "api-key-header", "glxyz0123456789"),
        (f"gh api user -H 'X-Note: {FAKE_GITHUB_TOKEN}'", "known-key", FAKE_GITHUB_TOKEN),
        (f"echo {FAKE_AWS_KEY_ID}", "known-key", FAKE_AWS_KEY_ID),
    ],
)
def test_literal_secret_is_found(command: str, rule: str, secret: str) -> None:
    """Each supported way of writing a secret into a command is detected, and the span is the secret itself."""
    # Act
    findings = find_secrets(command)

    # Assert
    assert [(f.rule, command[f.start : f.end]) for f in findings] == [(rule, secret)]


@pytest.mark.parametrize(
    "command",
    [
        'PGPASSWORD="$DB_PASSWORD" psql -h db',
        "PGPASSWORD=${DB_PASSWORD} psql -h db",
        "PGPASSWORD=$(op read op://vault/db/password) psql",
        "psql -h db -U app",
        "mysql -u root -p shop",
        'mysql -u root -P 3306 -p"$MYSQL_PASSWORD"',
        'curl -H "Authorization: Bearer $TOKEN" https://api.example.com',
        "psql postgres://app:$DB_PASSWORD@db:5432/shop",
        "git clone https://github.com/org/repo.git",
        "git clone git@github.com:org/repo.git",
        "echo pass | docker login --password-stdin",
        "some-cli --token-file ~/.token",
        "some-cli --password --verbose",
        "some-cli --max-tokens 4096",
        "MAX_TOKENS=4096 python app.py",
        "TOKENIZERS_PARALLELISM=false python x.py",
        "DB_PASSWORD_FILE=/run/secrets/db app",
        "PWD=/tmp ls",
        "npm test -- --password=<password>",
        "API_TOKEN=xxx curl https://example.com",
        "API_TOKEN=your_token curl https://example.com",
        "PASSWORD=*** ./run",
        "PASSWORD=ab ./run",
        "",
    ],
)
def test_reference_placeholder_or_harmless_text_is_not_found(command: str) -> None:
    """Variables, placeholders, very short values and look-alike names are not reported, so work is not blocked."""
    # Act & Assert
    assert find_secrets(command) == []


def test_three_character_value_is_found() -> None:
    """Three characters is the shortest value treated as a secret (two or fewer are too ambiguous)."""
    # Act & Assert
    assert [f.rule for f in find_secrets("PASSWORD=abc ./run")] == ["env-assignment"]


def test_every_secret_in_a_compound_command_is_found_in_order() -> None:
    """A compound command reports each secret once, ordered by position."""
    # Arrange
    command = "PGPASSWORD=Xk7pQ2mZ9vLr psql -h db && mysql -u root -pHunter2xx shop"

    # Act
    findings = find_secrets(command)

    # Assert
    assert [command[f.start : f.end] for f in findings] == ["Xk7pQ2mZ9vLr", "Hunter2xx"]


def test_secret_matched_by_two_detectors_is_reported_once() -> None:
    """A known token assigned to a secret variable is reported once, not once per detector."""
    # Arrange
    command = f"GITHUB_TOKEN={FAKE_GITHUB_TOKEN} gh api user"

    # Act
    findings = find_secrets(command)

    # Assert
    assert len(findings) == 1


def test_redact_replaces_only_the_secrets() -> None:
    """Redaction keeps the command readable and removes every secret."""
    # Arrange
    command = "PGPASSWORD=Xk7pQ2mZ9vLr psql postgres://app:Pa55word@db/shop"

    # Act
    redacted = redact(command)

    # Assert
    assert redacted == "PGPASSWORD=*** psql postgres://app:***@db/shop"


def test_redact_without_secrets_returns_text_unchanged() -> None:
    """Text without secrets is returned as is."""
    # Act & Assert
    assert redact("psql -h db") == "psql -h db"


@pytest.mark.parametrize(
    ("value", "expected"),
    [("Xk7pQ2mZ9vLr", "Xk***"), ("abcde", "ab***"), ("abcd", "***"), ("abc", "***")],
)
def test_masked_shows_at_most_two_characters(value: str, expected: str) -> None:
    """A masked preview never reveals more than two characters, and none for short values."""
    # Arrange
    text = f"PASSWORD={value}"
    finding = Finding("env-assignment", "", len("PASSWORD="), len(text))

    # Act & Assert
    assert finding.masked(text) == expected
