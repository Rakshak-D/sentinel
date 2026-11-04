"""Shared complete-state checks for the fixed GitHub blob integration."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, Literal, NoReturn

from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST, ExpectedItem
from sentinel.ingestion.types import (
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
)

if TYPE_CHECKING:
    from sentinel.ingestion.github_fixture import _PreparedFixture

CONTENT_REF_PREFIX = "sentinel-public-blob-v1:sha256:"


def fail(code: GithubBlobIntegrationErrorCode) -> NoReturn:
    raise GithubBlobIntegrationError(code) from None


def fixture_ref(item: ExpectedItem) -> str:
    return str(item.values[5])


def blob_ref(item: ExpectedItem) -> str:
    return f"{CONTENT_REF_PREFIX}{item.content_sha256}"


def verify_fixture_matches_manifest(prepared: _PreparedFixture) -> None:
    """Bind promotion input to the pinned metadata-only readback contract."""

    try:
        fixture = prepared.fixture
        registry = prepared.registry
        items = prepared.items
        if (
            fixture.fixture_version != EXPECTED_MANIFEST.fixture_version
            or fixture.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
            or registry.principal_values != EXPECTED_MANIFEST.principal_row
            or registry.plugin_values != EXPECTED_MANIFEST.plugin_row
            or registry.source_values != EXPECTED_MANIFEST.source_row
            or len(items) != len(EXPECTED_MANIFEST.items)
        ):
            fail(GithubBlobIntegrationErrorCode.PROMOTION_INCOMPLETE)
        for actual, expected in zip(items, EXPECTED_MANIFEST.items, strict=True):
            if (
                actual.values != expected.values
                or actual.item_id != expected.item_id
                or actual.issue.source_id != expected.source_envelope_id
                or len(actual.spans) != len(expected.spans)
            ):
                fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)
            for actual_span, expected_span in zip(actual.spans, expected.spans, strict=True):
                if (
                    actual_span.values != expected_span.values
                    or actual_span.citation.source_id != expected_span.source_id
                    or actual_span.citation.content_sha256 != expected_span.content_sha256
                    or actual_span.citation.span.span_id != expected_span.in_memory_span_id
                ):
                    fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)
    except GithubBlobIntegrationError:
        raise
    except Exception:
        fail(GithubBlobIntegrationErrorCode.PROMOTION_INCOMPLETE)


def verify_registration(connection: sqlite3.Connection) -> None:
    checks = (
        (
            "SELECT principal_id, kind, display_name, os_binding, created_at, revoked_at "
            "FROM principals WHERE principal_id = ?",
            (EXPECTED_MANIFEST.principal_row[0],),
            EXPECTED_MANIFEST.principal_row,
        ),
        (
            "SELECT plugin_id, plugin_version, manifest_ref, manifest_sha256, origin, "
            "capability_json, trust, sensitivity, host_allowlist_json, fixture_set_sha256, "
            "enabled, registered_at FROM plugin_manifests WHERE plugin_id = ? "
            "AND plugin_version = ?",
            EXPECTED_MANIFEST.plugin_row[:2],
            EXPECTED_MANIFEST.plugin_row,
        ),
        (
            "SELECT source_id, plugin_id, plugin_version, principal_id, source_type, "
            "account_alias, scope_json, host_allowlist_json, trust, default_sensitivity, "
            "enabled, created_at FROM sources WHERE source_id = ?",
            (EXPECTED_MANIFEST.source_row[0],),
            EXPECTED_MANIFEST.source_row,
        ),
    )
    try:
        for query, parameters, expected in checks:
            row = connection.execute(query, parameters).fetchone()
            if row is None or tuple(row) != expected:
                fail(GithubBlobIntegrationErrorCode.REGISTRATION_CONFLICT)
    except GithubBlobIntegrationError:
        raise
    except sqlite3.Error:
        fail(GithubBlobIntegrationErrorCode.INTEGRITY_FAILURE)


def verify_items(
    connection: sqlite3.Connection,
    *,
    accepted_states: tuple[Literal["fixture", "blob"], ...],
) -> Literal["fixture", "blob"]:
    """Compare the exact fixed-source item set; unrelated sources are untouched."""

    try:
        rows = connection.execute(
            "SELECT item_id, source_id, provider_item_id, provider_revision, canonical_uri, "
            "content_ref, content_sha256, trust, sensitivity, observed_at, source_at, "
            "deleted_at, metadata_json FROM source_items WHERE source_id = ? "
            "ORDER BY provider_item_id, content_sha256, item_id LIMIT ?",
            (EXPECTED_MANIFEST.source_row[0], len(EXPECTED_MANIFEST.items) + 1),
        ).fetchall()
    except sqlite3.Error:
        fail(GithubBlobIntegrationErrorCode.INTEGRITY_FAILURE)
    if len(rows) != len(EXPECTED_MANIFEST.items):
        fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)

    expected_by_id = {str(item.item_id): item for item in EXPECTED_MANIFEST.items}
    seen: set[str] = set()
    states: set[str] = set()
    for row in rows:
        item_id = str(row[0])
        expected = expected_by_id.get(item_id)
        if expected is None or item_id in seen:
            fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)
        seen.add(item_id)
        actual = tuple(row)
        if actual[5] == fixture_ref(expected):
            state = "fixture"
        elif actual[5] == blob_ref(expected):
            state = "blob"
        else:
            fail(GithubBlobIntegrationErrorCode.CONTENT_REF_INVALID)
        if actual != expected.values_with_ref(str(actual[5])):
            fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)
        states.add(state)

    if seen != set(expected_by_id):
        fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)
    if len(states) != 1:
        fail(GithubBlobIntegrationErrorCode.PROMOTION_INCOMPLETE)
    state = next(iter(states))
    if state == "fixture":
        if "fixture" not in accepted_states:
            fail(GithubBlobIntegrationErrorCode.CONTENT_REF_INVALID)
        return "fixture"
    if "blob" not in accepted_states:
        fail(GithubBlobIntegrationErrorCode.CONTENT_REF_INVALID)
    return "blob"


def verify_spans(connection: sqlite3.Connection) -> None:
    """Compare exact per-item span sets and global persisted span identities."""

    try:
        for item in EXPECTED_MANIFEST.items:
            rows = connection.execute(
                "SELECT span_id, item_id, start_byte, end_byte, text_sha256, context_ref, "
                "derived_by_boundary_id FROM source_spans WHERE item_id = ? "
                "ORDER BY span_id LIMIT ?",
                (str(item.item_id), len(item.spans) + 1),
            ).fetchall()
            if len(rows) != len(item.spans):
                fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)
            expected_by_id = {str(span.span_id): span for span in item.spans}
            seen: set[str] = set()
            for row in rows:
                span_id = str(row[0])
                expected = expected_by_id.get(span_id)
                if expected is None or span_id in seen or tuple(row) != expected.values:
                    fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)
                seen.add(span_id)
            if seen != set(expected_by_id):
                fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)
            for span in item.spans:
                row = connection.execute(
                    "SELECT span_id, item_id, start_byte, end_byte, text_sha256, context_ref, "
                    "derived_by_boundary_id FROM source_spans WHERE span_id = ?",
                    (str(span.span_id),),
                ).fetchone()
                if row is None or tuple(row) != span.values:
                    fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)
    except GithubBlobIntegrationError:
        raise
    except sqlite3.Error:
        fail(GithubBlobIntegrationErrorCode.INTEGRITY_FAILURE)


__all__ = [
    "CONTENT_REF_PREFIX",
    "blob_ref",
    "fail",
    "fixture_ref",
    "verify_fixture_matches_manifest",
    "verify_items",
    "verify_registration",
    "verify_spans",
]
