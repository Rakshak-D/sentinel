from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
import urllib.request

from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.readers.notes_registry import (
    LOCAL_NOTES_REGISTRY_SCHEMA_VERSION,
    build_local_notes_registry,
    format_json_local_notes_registry,
)


def test_notes_registry_commands_are_nested_under_source() -> None:
    runner = CliRunner()
    source_help = runner.invoke(app, ["source", "--help"])
    group_help = runner.invoke(app, ["source", "notes-registry", "--help"])
    build_help = runner.invoke(app, ["source", "notes-registry", "build", "--help"])
    verify_help = runner.invoke(app, ["source", "notes-registry", "verify", "--help"])
    assert source_help.exit_code == group_help.exit_code == 0
    assert "notes-registry" in source_help.stdout
    assert "build" in group_help.stdout and "verify" in group_help.stdout
    assert all(flag in build_help.stdout for flag in ("--allow-root", "--file"))
    assert all(flag in verify_help.stdout for flag in ("--allow-root", "--registry", "--format"))


def test_cli_builds_then_verifies_saved_registry_and_reports_changes(tmp_path) -> None:
    runner = CliRunner()
    root = tmp_path / "notes"
    root.mkdir()
    note = root / "note.txt"
    note.write_bytes(b"private note canary")
    built = runner.invoke(
        app,
        [
            "source",
            "notes-registry",
            "build",
            "--allow-root",
            str(root),
            "--file",
            str(note),
        ],
    )
    assert built.exit_code == 0
    assert built.stderr == ""
    document = json.loads(built.stdout)
    assert document["schema_version"] == LOCAL_NOTES_REGISTRY_SCHEMA_VERSION
    assert "private note canary" not in built.stdout
    registry = root / "baseline.txt"
    registry.write_bytes(built.stdout.encode("utf-8"))
    verify_args = [
        "source",
        "notes-registry",
        "verify",
        "--allow-root",
        str(root),
        "--registry",
        str(registry),
        "--format",
        "json",
    ]
    unchanged = runner.invoke(app, verify_args)
    assert unchanged.exit_code == 0
    assert json.loads(unchanged.stdout)["overall_status"] == "UNCHANGED"
    unchanged_text = runner.invoke(app, verify_args[:-1] + ["text"])
    assert unchanged_text.exit_code == 0
    assert "Overall status: UNCHANGED" in unchanged_text.stdout
    assert "note.txt" not in unchanged_text.stdout
    note.write_bytes(b"changed note canary!")
    changed = runner.invoke(app, verify_args)
    assert changed.exit_code == 1
    assert json.loads(changed.stdout)["changed_count"] == 1
    assert "changed note canary" not in changed.stdout
    assert str(root) not in changed.stdout


def test_cli_late_missing_file_fails_without_output_or_path_leak(tmp_path) -> None:
    runner = CliRunner()
    root = tmp_path / "notes"
    root.mkdir()
    first = root / "note.txt"
    first.write_text("private body canary", encoding="utf-8")
    registry = root / "baseline.txt"
    registry.write_text(
        format_json_local_notes_registry(
            build_local_notes_registry(allowed_root=root, file_paths=(first,))
        ),
        encoding="utf-8",
    )
    first.unlink()
    result = runner.invoke(
        app,
        [
            "source",
            "notes-registry",
            "verify",
            "--allow-root",
            str(root),
            "--registry",
            str(registry),
            "--format",
            "text",
        ],
    )
    assert result.exit_code == 1
    assert result.stdout == ""
    assert str(root) not in result.stderr
    assert "private body canary" not in result.stderr
    assert "Traceback" not in result.stderr


def test_invalid_format_is_rejected_before_registry_or_file_reads(monkeypatch, tmp_path) -> None:
    import sentinel.cli as cli

    def forbidden(**_kwargs):
        raise AssertionError("format validation must happen before a registry read")

    monkeypatch.setattr(cli, "verify_local_notes_registry", forbidden)
    result = CliRunner().invoke(
        app,
        [
            "source",
            "notes-registry",
            "verify",
            "--allow-root",
            str(tmp_path),
            "--registry",
            str(tmp_path / "baseline.txt"),
            "--format",
            "yaml",
        ],
    )
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "text or json" in result.stderr
    assert "Traceback" not in result.stderr


def test_registry_read_path_has_no_database_network_or_process_side_effects(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    note = root / "note.txt"
    note.write_text("ordinary note", encoding="utf-8")
    registry = root / "baseline.txt"
    registry.write_text(
        format_json_local_notes_registry(
            build_local_notes_registry(allowed_root=root, file_paths=(note,))
        ),
        encoding="utf-8",
    )
    before_files = sorted(path.name for path in root.iterdir())
    before_note = note.read_bytes()
    before_registry = registry.read_bytes()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("read-only registry verification must not perform external effects")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    verified = CliRunner().invoke(
        app,
        [
            "source",
            "notes-registry",
            "verify",
            "--allow-root",
            str(root),
            "--registry",
            str(registry),
            "--format",
            "json",
        ],
    )

    assert verified.exit_code == 0
    assert sorted(path.name for path in root.iterdir()) == before_files
    assert note.read_bytes() == before_note
    assert registry.read_bytes() == before_registry
