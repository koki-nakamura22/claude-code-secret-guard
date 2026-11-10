from __future__ import annotations

import re
from pathlib import Path

import pytest

from secret_guard.detect import find_secrets

ROOT = Path(__file__).resolve().parent.parent
READMES = [ROOT / "README.md", ROOT / "README.ja.md"]


def section(readme: Path, name: str) -> str:
    text = readme.read_text(encoding="utf-8")
    match = re.search(rf"<!-- {name}:start -->(.*?)<!-- {name}:end -->", text, re.DOTALL)
    assert match, f"{readme.name} has no {name} section"
    return match.group(1)


def code(cell: str) -> str:
    match = re.fullmatch(r"\s*`(.*)`\s*", cell)
    assert match, f"not a code cell: {cell!r}"
    return match.group(1).replace("\\|", "|")


def catalog_rows(readme: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in section(readme, "catalog").splitlines():
        cells = re.split(r"(?<!\\)\|", line)[1:-1]
        if len(cells) != 3 or "`" not in cells[1]:
            continue
        rows.append((code(cells[1]), code(cells[2])))
    return rows


@pytest.mark.parametrize("readme", READMES, ids=lambda p: p.name)
def test_both_readmes_show_the_same_examples(readme: Path) -> None:
    """The English and Japanese catalogs list the same commands, so neither drifts from the other."""
    # Act & Assert
    assert catalog_rows(readme) == catalog_rows(READMES[0])


@pytest.mark.parametrize("readme", READMES, ids=lambda p: p.name)
def test_every_blocked_example_is_detected(readme: Path) -> None:
    """Each command the README says is blocked really contains a secret the detector finds."""
    # Arrange
    rows = catalog_rows(readme)

    # Act
    missed = [blocked for blocked, _ in rows if not find_secrets(blocked)]

    # Assert
    assert rows
    assert missed == []


@pytest.mark.parametrize("readme", READMES, ids=lambda p: p.name)
def test_every_not_blocked_example_passes(readme: Path) -> None:
    """Each command the README says is not blocked passes the detector."""
    # Arrange
    rows = catalog_rows(readme)

    # Act
    blocked = [allowed for _, allowed in rows if find_secrets(allowed)]

    # Assert
    assert blocked == []


@pytest.mark.parametrize("readme", READMES, ids=lambda p: p.name)
def test_every_missed_example_is_really_missed(readme: Path) -> None:
    """The README's list of known misses stays honest: if the detector learns one, the README must be updated."""
    # Arrange
    examples = re.findall(r"^- `(.*)`$", section(readme, "missed"), re.MULTILINE)

    # Act
    found = [example for example in examples if find_secrets(example)]

    # Assert
    assert len(examples) == 3
    assert found == []
