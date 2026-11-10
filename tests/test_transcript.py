from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import FAKE_GITHUB_TOKEN

from secret_guard.transcript import TypedSecret, mask_line, redact_file, redact_transcript, typed_secrets

SECRET = "Xk7pQ2mZ9vLr"


def jsonl(*records: object) -> bytes:
    return b"".join(json.dumps(r, ensure_ascii=False).encode() + b"\n" for r in records)


def user_line(text: str) -> bytes:
    return jsonl({"type": "user", "message": {"role": "user", "content": text}})


@pytest.mark.parametrize(
    "record",
    [
        {"type": "user", "message": {"content": f"PGPASSWORD={SECRET} psql -h db"}},
        {"type": "user", "message": {"content": f"<bash-input>PGPASSWORD={SECRET} psql</bash-input>"}},
        {
            "type": "assistant",
            "message": {"content": [{"type": "tool_use", "input": {"command": f"PGPASSWORD={SECRET} psql"}}]},
        },
        {"type": "last-prompt", "lastPrompt": f"PGPASSWORD={SECRET} psql"},
        {"type": "api-request-blob", "content": json.dumps({"messages": [f"PGPASSWORD={SECRET} psql"]})},
    ],
    ids=["prompt", "bash-input", "tool-use", "last-prompt", "json-inside-a-string"],
)
def test_secret_is_masked_wherever_it_sits_in_the_line(record: dict[str, object]) -> None:
    """Prompts, `!` input, tool calls, the last prompt and JSON nested in a string are all masked."""
    # Arrange
    line = jsonl(record)

    # Act
    masked, count = mask_line(line)

    # Assert
    assert SECRET.encode() not in masked
    assert count >= 1
    assert b"*" * len(SECRET) in masked


@pytest.mark.parametrize(
    "text",
    [
        f'export DB_PASSWORD="{SECRET} x" && ./migrate',
        "PASSWORD=pä55wörd123 ./run",
        f"token {FAKE_GITHUB_TOKEN} here",
    ],
    ids=["escaped-quotes", "multibyte", "known-key"],
)
def test_masked_line_keeps_its_byte_length_and_stays_valid_json(text: str) -> None:
    """The line is overwritten in place, so it must keep its length and remain valid JSON, even with escapes."""
    # Arrange
    line = user_line(text)

    # Act
    masked, count = mask_line(line)

    # Assert
    assert count >= 1
    assert len(masked) == len(line)
    assert json.loads(masked)["type"] == "user"


def test_line_without_secrets_is_returned_unchanged() -> None:
    """Ordinary conversation is left as it is."""
    # Arrange
    line = user_line('PGPASSWORD="$DB_PASSWORD" psql -h db')

    # Act & Assert
    assert mask_line(line) == (line, 0)


def test_line_that_is_not_json_is_left_alone() -> None:
    """A line being written, or anything that is not JSON, is not touched."""
    # Arrange
    line = b'{"type": "user", "message": {"content": "PGPASSWORD=' + SECRET.encode()

    # Act & Assert
    assert mask_line(line) == (line, 0)


def test_secret_repeated_elsewhere_in_the_line_is_masked_too() -> None:
    """Once found, the same secret is masked where it appears without its name, e.g. in a reply that repeats it."""
    # Arrange
    line = user_line(f"PGPASSWORD={SECRET} psql; the password was {SECRET}.")

    # Act
    masked, count = mask_line(line)

    # Assert
    assert count == 2
    assert SECRET.encode() not in masked


def test_secret_inside_a_longer_word_is_not_masked() -> None:
    """A short secret is not masked inside an unrelated longer word, so the rest of the log stays readable."""
    # Arrange
    line = user_line("PASSWORD=app ./run; see the application log")

    # Act
    masked, _ = mask_line(line)

    # Assert
    assert b"the application log" in masked
    assert b"PASSWORD=*** ./run" in masked


def test_redact_file_masks_complete_lines_and_returns_where_to_continue(tmp_path: Path) -> None:
    """The returned offset is the end of the last complete line; a half-written last line is left for later."""
    # Arrange
    complete = user_line(f"PGPASSWORD={SECRET} psql")
    partial = b'{"type": "user", "message": {"content": "PGPASSWORD=' + SECRET.encode()
    path = tmp_path / "s.jsonl"
    path.write_bytes(complete + partial)

    # Act
    result = redact_file(path)

    # Assert
    assert (result.offset, result.masked) == (len(complete), 1)
    assert path.read_bytes() == mask_line(complete)[0] + partial


def test_redact_file_starts_at_the_given_offset(tmp_path: Path) -> None:
    """Lines before the offset were handled before and are not read again."""
    # Arrange
    first = user_line(f"PGPASSWORD={SECRET} psql")
    second = user_line(f"MYSQL_PWD={SECRET}9 mysql")
    path = tmp_path / "s.jsonl"
    path.write_bytes(first + second)

    # Act
    result = redact_file(path, start=len(first))

    # Assert
    assert (result.offset, result.masked) == (len(first) + len(second), 1)
    assert path.read_bytes().startswith(first)


def test_redact_file_starts_over_when_the_file_shrank(tmp_path: Path) -> None:
    """An offset past the end means the file was replaced, so it is read from the start."""
    # Arrange
    path = tmp_path / "s.jsonl"
    path.write_bytes(user_line(f"PGPASSWORD={SECRET} psql"))

    # Act
    result = redact_file(path, start=10_000)

    # Assert
    assert result.masked == 1


def test_redact_transcript_remembers_how_far_it_read(tmp_path: Path) -> None:
    """With a data folder, the next call reads only what was appended, and appended secrets are masked."""
    # Arrange
    path = tmp_path / "s.jsonl"
    data_dir = tmp_path / "data"
    path.write_bytes(user_line(f"PGPASSWORD={SECRET} psql"))
    redact_transcript(path, data_dir)
    with path.open("ab") as f:
        f.write(user_line(f"MYSQL_PWD={SECRET}9 mysql"))

    # Act
    result = redact_transcript(path, data_dir)

    # Assert
    assert result.masked == 1
    assert SECRET.encode() not in path.read_bytes()
    state = json.loads((data_dir / "transcript-offsets.json").read_text())
    assert state == {str(path): path.stat().st_size}


def test_redact_transcript_without_a_data_folder_reads_the_whole_file(tmp_path: Path) -> None:
    """Without a data folder (outside the plugin) the whole file is scanned each time."""
    # Arrange
    path = tmp_path / "s.jsonl"
    path.write_bytes(user_line(f"PGPASSWORD={SECRET} psql"))

    # Act & Assert
    assert redact_transcript(path, None).masked == 1


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (f"PGPASSWORD={SECRET} psql", [TypedSecret("prompt", "PGPASSWORD=*** psql")]),
        (f"<bash-input>PGPASSWORD={SECRET} psql</bash-input>", [TypedSecret("bash-input", "PGPASSWORD=*** psql")]),
        (
            f"<bash-stdout>DB_PASSWORD={SECRET}</bash-stdout><bash-stderr></bash-stderr>",
            [TypedSecret("bash-output", "DB_PASSWORD=***")],
        ),
        (f"first line\n  PGPASSWORD={SECRET}   psql  ", [TypedSecret("prompt", "PGPASSWORD=*** psql")]),
    ],
    ids=["prompt", "bash-input", "bash-output", "line-with-the-secret"],
)
def test_typed_secrets_finds_what_the_user_typed_or_a_bash_command_printed(
    content: str, expected: list[TypedSecret]
) -> None:
    """Prompts and `!` input and output are reported with the secret masked, on one line."""
    # Act & Assert
    assert typed_secrets({"type": "user", "message": {"content": content}}) == expected


@pytest.mark.parametrize(
    "record",
    [
        {"type": "user", "message": {"content": [{"type": "tool_result", "content": f"PGPASSWORD={SECRET}"}]}},
        {"type": "user", "isMeta": True, "message": {"content": f"PGPASSWORD={SECRET}"}},
        {"type": "user", "message": {"content": f"<local-command-stdout>PGPASSWORD={SECRET}</local-command-stdout>"}},
        {"type": "assistant", "message": {"content": f"PGPASSWORD={SECRET}"}},
        {"type": "user", "message": {"content": 'PGPASSWORD="$DB_PASSWORD" psql'}},
        "not a record",
    ],
    ids=["tool-result", "meta", "command-output", "assistant", "no-secret", "not-a-dict"],
)
def test_typed_secrets_ignores_what_the_user_did_not_type(record: object) -> None:
    """Tool results, lines Claude Code writes itself and Claude's replies are not reported as typed."""
    # Act & Assert
    assert typed_secrets(record) == []


def test_long_preview_is_shortened() -> None:
    """A long prompt is cut so the notice stays short."""
    # Arrange
    content = f"PGPASSWORD={SECRET} " + "x" * 300

    # Act
    [found] = typed_secrets({"type": "user", "message": {"content": content}})

    # Assert
    assert len(found.preview) == 100
    assert found.preview.endswith("\u2026")


def test_scan_without_writing_reports_but_leaves_the_file(tmp_path: Path) -> None:
    """With masking off, typed secrets are still found and the file is not opened for writing."""
    # Arrange
    path = tmp_path / "s.jsonl"
    path.write_bytes(user_line(f"PGPASSWORD={SECRET} psql"))
    before = path.read_bytes()

    # Act
    result = redact_file(path, write=False)

    # Assert
    assert (result.masked, len(result.typed)) == (0, 1)
    assert path.read_bytes() == before
