"""Entry point scaffold for the fixed offline F42-D0 diagnostic."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from sentinel.policy.canonical import policy_sha256

MANIFEST_DOMAIN = b"sentinel.f42-d0-scenario-manifest.v1\x00"
REPORT_DOMAIN = b"sentinel.f42-d0-diagnostic-report.v1\x00"
REPORT_SCHEMA_VERSION = "sentinel.f42-d0-diagnostic-report.v1"
PINNED_MANIFEST_SHA256 = "d9817d20bf92855eeb6d89123d87ac8872bb860840c6e02736a7dc250534e8bd"


class DiagnosticFailure(RuntimeError):
    """A bounded failure code that is safe for diagnostic stderr."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def manifest_sha256(payload: object) -> str:
    return hashlib.sha256(MANIFEST_DOMAIN + canonical_json_bytes(payload)).hexdigest()


def load_manifest_document() -> dict[str, Any]:
    path = Path(__file__).with_name("scenario_manifest.json")
    return json.loads(path.read_bytes().decode("utf-8", errors="strict"))


def validate_manifest_document(payload: object) -> dict[str, Any]:
    if type(payload) is not dict or manifest_sha256(payload) != PINNED_MANIFEST_SHA256:
        raise DiagnosticFailure("MANIFEST_PIN_MISMATCH")
    return payload


def run_diagnostic() -> dict[str, Any]:
    """Return the versioned fixed diagnostic report."""
    return {}


def main() -> int:
    try:
        report = run_diagnostic()
        sys.stdout.write(canonical_json_bytes(report).decode("utf-8") + "\n")
        return 0
    except DiagnosticFailure as exc:
        sys.stderr.write(f"F42_D0_FAILED {exc.code}\n")
        return 2

