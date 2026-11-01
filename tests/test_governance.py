"""Checks that the persistent governance ledger covers blueprint identifiers."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_required_governance_files_exist() -> None:
    required = (
        "AGENTS.md",
        "docs/BUILD_LEDGER.md",
        "docs/adr/0001-python-environment-and-packaging.md",
        "README.md",
        ".gitignore",
        ".python-version",
        "pyproject.toml",
    )

    assert all((ROOT / path).is_file() for path in required)


def test_ledger_covers_all_required_identifiers_without_false_verification() -> None:
    ledger = (ROOT / "docs/BUILD_LEDGER.md").read_text(encoding="utf-8")

    expected_ids = [
        *(f"F{number:02d}" for number in range(1, 47)),
        *(f"CR{number}" for number in range(10)),
        *(f"P{number:02d}" for number in range(18)),
        *(f"AB{number:02d}" for number in range(1, 19)),
    ]
    assert all(identifier in ledger for identifier in expected_ids)
    assert "F43 |" in ledger and "IN_PROGRESS" in ledger
    assert "F46 |" in ledger and "IN_PROGRESS" in ledger
    assert "NOT_STARTED | VERIFIED" not in ledger
