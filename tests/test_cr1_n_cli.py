from __future__ import annotations

import json

from typer.testing import CliRunner

import sentinel.readers.local_search as local_search
from sentinel.cli import app
from sentinel.readers import LocalTextError, LocalTextErrorCode

runner = CliRunner()


def test_search_command_is_nested_and_preserves_inspect_file() -> None:
    source_help = runner.invoke(app, ["source", "--help"])
    search_help = runner.invoke(app, ["source", "search-files", "--help"])
    inspect_help = runner.invoke(app, ["source", "inspect-file", "--help"])

    assert source_help.exit_code == 0
    assert "search-files" in source_help.output
    assert search_help.exit_code == 0
    assert all(
        value in search_help.output
        for value in ("--allow-root", "--file", "--query", "--show-snippets", "--format")
    )
    assert inspect_help.exit_code == 0
    assert "--start-byte" in inspect_help.output


def test_text_json_agree_and_query_is_not_emitted_by_default(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    first = root / "first.txt"
    second = root / "second.md"
    first.write_text("deadline deadline", encoding="utf-8")
    second.write_text("none", encoding="utf-8")
    common = [
        "source",
        "search-files",
        "--allow-root",
        str(root),
        "--file",
        str(first),
        "--file",
        str(second),
        "--query",
        "deadline",
    ]

    text_result = runner.invoke(app, common + ["--format", "text"])
    json_result = runner.invoke(app, common + ["--format", "json"])

    assert text_result.exit_code == json_result.exit_code == 0
    assert "deadline" not in text_result.stdout
    assert "deadline" not in json_result.stdout
    assert str(root) not in text_result.stdout
    assert str(root) not in json_result.stdout
    assert "File 1" in text_result.stdout and "File 2" in text_result.stdout
    document = json.loads(json_result.stdout)
    assert document["schema_version"] == "sentinel.local-file-search.v1"
    assert document["total_match_count"] == 2
    assert document["files"][1]["match_count"] == 0
    assert len(document["files"][0]["matches"]) == 2


def test_snippets_are_explicit_and_late_file_failure_has_no_partial_stdout(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    first = root / "first.txt"
    first.write_text("before target after", encoding="utf-8")
    missing = root / "missing.txt"
    common = [
        "source",
        "search-files",
        "--allow-root",
        str(root),
        "--file",
        str(first),
        "--file",
        str(missing),
        "--query",
        "target",
    ]

    failed = runner.invoke(app, common + ["--format", "json"])
    assert failed.exit_code != 0
    assert failed.stdout == ""
    assert str(root) not in failed.stderr
    assert "target" not in failed.stderr
    assert "Traceback" not in failed.stderr

    shown = runner.invoke(
        app,
        [
            "source",
            "search-files",
            "--allow-root",
            str(root),
            "--file",
            str(first),
            "--query",
            "target",
            "--show-snippets",
            "--format",
            "json",
        ],
    )
    assert shown.exit_code == 0
    assert (
        json.loads(shown.stdout)["files"][0]["matches"][0]["preview"]["cited_text"]
        == "before target after"
    )


def test_too_many_matches_and_late_preview_failure_emit_no_stdout(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "many.txt"
    selected.write_bytes(b"x" * 33)
    excessive = runner.invoke(
        app,
        [
            "source",
            "search-files",
            "--allow-root",
            str(root),
            "--file",
            str(selected),
            "--query",
            "x",
            "--format",
            "json",
        ],
    )
    assert excessive.exit_code != 0
    assert excessive.stdout == ""
    assert str(root) not in excessive.stderr

    selected.write_text("context x context", encoding="utf-8")
    original = local_search.verify_local_text_span
    count = 0

    def fail_preview(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 2:
            raise LocalTextError(LocalTextErrorCode.INVALID_CITATION)
        return original(*args, **kwargs)

    monkeypatch.setattr(local_search, "verify_local_text_span", fail_preview)
    failed_preview = runner.invoke(
        app,
        [
            "source",
            "search-files",
            "--allow-root",
            str(root),
            "--file",
            str(selected),
            "--query",
            "x",
            "--show-snippets",
            "--format",
            "json",
        ],
    )
    assert failed_preview.exit_code != 0
    assert failed_preview.stdout == ""
    assert str(root) not in failed_preview.stderr
    assert "context" not in failed_preview.stderr


def test_invalid_format_and_missing_required_options_emit_no_success_output(
    tmp_path, monkeypatch
) -> None:
    def forbidden(**_kwargs):
        raise AssertionError("invalid CLI arguments must fail before file access")

    monkeypatch.setattr("sentinel.cli.search_selected_local_text_files", forbidden)
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    selected.write_text("query", encoding="utf-8")
    invalid_format = runner.invoke(
        app,
        [
            "source",
            "search-files",
            "--allow-root",
            str(root),
            "--file",
            str(selected),
            "--query",
            "query",
            "--format",
            "xml",
        ],
    )
    missing_query = runner.invoke(
        app,
        ["source", "search-files", "--allow-root", str(root), "--file", str(selected)],
    )

    assert invalid_format.exit_code != 0
    assert invalid_format.stdout == ""
    assert str(root) not in invalid_format.stderr
    assert "query" not in invalid_format.stderr
    assert missing_query.exit_code != 0
    assert missing_query.stdout == ""
    assert str(root) not in missing_query.stderr
