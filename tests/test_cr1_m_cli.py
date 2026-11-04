from __future__ import annotations

import json

from typer.testing import CliRunner

import sentinel.cli as sentinel_cli
from sentinel.cli import app

runner = CliRunner()


def test_source_inspect_file_is_nested_and_existing_commands_remain(tmp_path) -> None:
    root_help = runner.invoke(app, ["--help"])
    source_help = runner.invoke(app, ["source", "--help"])
    command_help = runner.invoke(app, ["source", "inspect-file", "--help"])

    assert root_help.exit_code == 0
    assert all(
        name in root_help.output
        for name in ("version", "init", "doctor", "demo", "brief", "task", "fixture-sync", "source")
    )
    assert source_help.exit_code == 0
    assert "inspect-file" in source_help.output
    assert command_help.exit_code == 0
    assert "--allow-root" in command_help.output
    assert "--file" in command_help.output
    assert "--format" in command_help.output


def test_default_cli_output_is_metadata_only_and_json_is_deterministic(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    selected = root / "secret-note.txt"
    body = "PRIVATE-CANARY\r\n\U0001f9ed".encode()
    selected.write_bytes(body)
    common = ["source", "inspect-file", "--allow-root", str(root), "--file", str(selected)]

    text_result = runner.invoke(app, common + ["--format", "text"])
    json_first = runner.invoke(app, common + ["--format", "json"])
    json_second = runner.invoke(app, common + ["--format", "json"])

    assert text_result.exit_code == 0
    assert "local text file" in text_result.output.lower()
    assert "T4 EXTERNAL" in text_result.output
    assert "PRIVATE" in text_result.output
    assert "PRIVATE-CANARY" not in text_result.output
    assert str(root) not in text_result.output
    assert json_first.exit_code == json_second.exit_code == 0
    assert json_first.output == json_second.output
    payload = json.loads(json_first.output)
    assert payload["schema_version"] == "sentinel.local-file-inspection.v1"
    assert payload["byte_length"] == len(body)
    assert "PRIVATE-CANARY" not in json_first.output
    assert str(root) not in json_first.output


def test_explicit_citation_displays_only_escaped_requested_excerpt(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "data.md"
    body = b"hidden\x1b[31m\x07\r\nvisible\x00\x08" + "\u202e".encode() + b"tail"
    selected.write_bytes(body)
    start = body.index(b"\x1b")
    end = body.index(b"tail")
    result = runner.invoke(
        app,
        [
            "source",
            "inspect-file",
            "--allow-root",
            str(root),
            "--file",
            str(selected),
            "--start-byte",
            str(start),
            "--end-byte",
            str(end),
            "--format",
            "text",
        ],
    )

    assert result.exit_code == 0
    assert "hidden" not in result.output
    assert "\\x1b" in result.output
    assert "\\x07" in result.output
    assert "\\r\\n" in result.output
    assert "\\x00" in result.output
    assert "\\x08" in result.output
    assert "\\u202e" in result.output
    assert "visible" in result.output


def test_failure_has_empty_stdout_and_does_not_leak_path_or_body(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    canary = "PRIVATE-SOURCE-CANARY"
    selected = root / "note.txt"
    selected.write_text(canary, encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "source",
            "inspect-file",
            "--allow-root",
            str(root),
            "--file",
            str(selected),
            "--start-byte",
            "0",
            "--format",
            "json",
        ],
    )

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(root) not in result.stderr
    assert canary not in result.stderr
    assert "Traceback" not in result.stderr


def test_command_requires_explicit_paths_and_paired_offsets() -> None:
    result = runner.invoke(app, ["source", "inspect-file", "--format", "text"])

    assert result.exit_code != 0
    assert result.stdout == ""


def test_invalid_format_fails_before_opening_source(tmp_path, monkeypatch) -> None:
    def forbidden_read(**_kwargs):
        raise AssertionError("reader must not run for an invalid output format")

    monkeypatch.setattr(sentinel_cli, "read_allowlisted_local_text", forbidden_read)
    root = tmp_path / "root"
    result = runner.invoke(
        app,
        [
            "source",
            "inspect-file",
            "--allow-root",
            str(root),
            "--file",
            str(root / "x.txt"),
            "--format",
            str(root),
        ],
    )

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(root) not in result.stderr
    assert "output format must be text or json" in result.stderr


def test_invalid_utf8_cli_failure_is_bounded_and_has_no_partial_output(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "PRIVATE-PATH-CANARY.txt"
    selected.write_bytes(b"PRIVATE-BODY-CANARY\xff")
    result = runner.invoke(
        app,
        ["source", "inspect-file", "--allow-root", str(root), "--file", str(selected)],
    )

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(root) not in result.stderr
    assert selected.name not in result.stderr
    assert "PRIVATE-BODY-CANARY" not in result.stderr
    assert "Traceback" not in result.stderr


def test_late_invalid_citation_has_no_success_output(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    selected.write_text("PRIVATE-LATE-CITATION-CANARY", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "source",
            "inspect-file",
            "--allow-root",
            str(root),
            "--file",
            str(selected),
            "--start-byte",
            "0",
            "--end-byte",
            "999",
            "--format",
            "json",
        ],
    )

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(root) not in result.stderr
    assert "PRIVATE-LATE-CITATION-CANARY" not in result.stderr
