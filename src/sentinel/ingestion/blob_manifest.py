"""Pinned, body-free expectations for promoted GitHub fixture rows.

This manifest is generated from the accepted CR1-G contract and intentionally
contains identifiers, hashes, timestamps and byte offsets only. It contains no
issue title, body, or raw source content.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Final, cast
from uuid import UUID

MANIFEST_VERSION: Final = "sentinel.github-fixture-persistence-manifest.v1"
FIXTURE_VERSION: Final = "sentinel.github-issues-fixture.v1"
FIXTURE_SHA256: Final = "7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1"
EXPECTED_MANIFEST_SHA256: Final = "645aecaedd14d8e6c6071b9d8c32a5d91f664c715799191303eac315d6f9c08f"
OBSERVED_AT: Final = "2026-11-03T12:00:00+00:00"

PRINCIPAL_ROW: Final[tuple[object, ...]] = (
    "cb58c343-adb2-5823-82f0-a05e5fcdc9f5",
    "synthetic-fixture",
    "Synthetic GitHub fixture principal",
    "synthetic:fixture-only",
    OBSERVED_AT,
    None,
)
PLUGIN_ROW: Final[tuple[object, ...]] = (
    "github.fixture",
    "1.0.0",
    "package-resource:sentinel.readers/fixtures/github-issues-v1.json",
    "bd82ab9afa04391043de9f30301b91d5ffc8679fa8f41d9e672f1c6da69a2864",
    "bundled-synthetic-fixture",
    '["read_synthetic_fixture"]',
    "T4 EXTERNAL",
    "PUBLIC",
    "[]",
    FIXTURE_SHA256,
    0,
    OBSERVED_AT,
)
SOURCE_ROW: Final[tuple[object, ...]] = (
    "9338577b-4f6d-5507-9422-598c6ffc16bd",
    "github.fixture",
    "1.0.0",
    "cb58c343-adb2-5823-82f0-a05e5fcdc9f5",
    "github_issue_fixture",
    "example-owner/fixture-project",
    '{"fixture_sha256":"7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1","fixture_version":"sentinel.github-issues-fixture.v1","repository":"example-owner/fixture-project"}',
    "[]",
    "T4 EXTERNAL",
    "PUBLIC",
    1,
    OBSERVED_AT,
)

# Each item tuple is the complete CR1-G source_items row in column order.
_ITEM_ROWS: Final = (
    (
        (
            "26fcc66d-1857-5ba9-abf3-c8d062ad3826",
            SOURCE_ROW[0],
            "example-owner/fixture-project#101",
            None,
            None,
            "fixture:sentinel.github-issues-fixture.v1:example-owner/fixture-project#101",
            "4ed9123596eda8d6095d288d39f3ee267faef342e515da10d22cd2013a9509b2",
            "T4 EXTERNAL",
            "PUBLIC",
            OBSERVED_AT,
            "2026-11-02T10:30:00+00:00",
            None,
            '{"encoding":"utf-8","fixture_sha256":"7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1","fixture_version":"sentinel.github-issues-fixture.v1","in_memory_source_id":"73f3a57e-43c9-5aa3-b792-310a0b9a1e5c","issue_number":101,"repository":"example-owner/fixture-project","source_updated_at":"2026-11-02T10:30:00+00:00"}',
        ),
        "73f3a57e-43c9-5aa3-b792-310a0b9a1e5c",
        (
            (
                (
                    "6831d403-30b9-5eff-9bf3-1369f764bab2",
                    "26fcc66d-1857-5ba9-abf3-c8d062ad3826",
                    17,
                    31,
                    "c1c359805d43a94850877d653ef94fa2f86f8e743587bc92e6814c1df63a78f8",
                    None,
                    None,
                ),
                "0b0c7b75-0c56-4b9a-8274-7aa9e7b34420",
            ),
            (
                (
                    "1642a959-c379-52ab-9755-273fe16247a9",
                    "26fcc66d-1857-5ba9-abf3-c8d062ad3826",
                    68,
                    72,
                    "a4c3ed04a95a3da14a9d235c83d868bed7c0f45cf7f3faa751ee8f50598d2211",
                    None,
                    None,
                ),
                "2755b3b9-4e54-4e0a-b565-683d70aacd3c",
            ),
            (
                (
                    "d5db02e7-6cab-5074-95e3-f562c05072b2",
                    "26fcc66d-1857-5ba9-abf3-c8d062ad3826",
                    74,
                    78,
                    "a4c3ed04a95a3da14a9d235c83d868bed7c0f45cf7f3faa751ee8f50598d2211",
                    None,
                    None,
                ),
                "400ac51b-d472-4b64-8e4f-44c7dbf4f67a",
            ),
        ),
    ),
    (
        (
            "222b3311-95e4-5031-8992-25b249c349bd",
            SOURCE_ROW[0],
            "example-owner/fixture-project#102",
            None,
            None,
            "fixture:sentinel.github-issues-fixture.v1:example-owner/fixture-project#102",
            "58485f7f640572778e5938f992eb20b4ae23481b35dcb7b94c714856727876d3",
            "T4 EXTERNAL",
            "PUBLIC",
            OBSERVED_AT,
            "2026-11-02T10:31:00+05:30",
            None,
            '{"encoding":"utf-8","fixture_sha256":"7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1","fixture_version":"sentinel.github-issues-fixture.v1","in_memory_source_id":"58c40621-9c97-5e18-ba79-fa66c26052ee","issue_number":102,"repository":"example-owner/fixture-project","source_updated_at":"2026-11-02T10:31:00+05:30"}',
        ),
        "58c40621-9c97-5e18-ba79-fa66c26052ee",
        (
            (
                (
                    "8dde28db-7337-5493-8a7f-0d6eadd89688",
                    "222b3311-95e4-5031-8992-25b249c349bd",
                    23,
                    27,
                    "d06f1525f791397809f9bc98682b5c13318eca4c3123433467fd4dffda44fd14",
                    None,
                    None,
                ),
                "50e0a266-8165-4b2e-9fb5-eab4479d1a8b",
            ),
            (
                (
                    "402d95a0-d63d-5c87-a548-f2e3843a2030",
                    "222b3311-95e4-5031-8992-25b249c349bd",
                    32,
                    41,
                    "77710aedc74ecfa33685e33a6c7df5cc83004da1bdcef7fb280f5c2b2e97e0a5",
                    None,
                    None,
                ),
                "aa2670a9-268b-42e1-aafc-032d6e0dd6bf",
            ),
            (
                (
                    "a12db338-d9e3-5458-8352-39310204e87c",
                    "222b3311-95e4-5031-8992-25b249c349bd",
                    42,
                    44,
                    "7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6",
                    None,
                    None,
                ),
                "f1394391-3900-464c-9a62-d5ae2e9d8b93",
            ),
            (
                (
                    "0848f643-3426-558a-b203-3772dd418a3b",
                    "222b3311-95e4-5031-8992-25b249c349bd",
                    61,
                    63,
                    "4cd0e21a9a0795a14ec9aa5f0e7d1abff0492565770e43eafdf1e3e8afed1f33",
                    None,
                    None,
                ),
                "21391c2f-8f49-4505-9323-115276acec77",
            ),
            (
                (
                    "7c09cb87-1faa-566e-89bf-aafe58285f9e",
                    "222b3311-95e4-5031-8992-25b249c349bd",
                    66,
                    68,
                    "4cd0e21a9a0795a14ec9aa5f0e7d1abff0492565770e43eafdf1e3e8afed1f33",
                    None,
                    None,
                ),
                "c60ceeb4-b5b8-4364-8c11-794a006c4931",
            ),
        ),
    ),
    (
        (
            "59baf4e0-02fb-5785-a5be-d49a433920b0",
            SOURCE_ROW[0],
            "example-owner/fixture-project#103",
            None,
            None,
            "fixture:sentinel.github-issues-fixture.v1:example-owner/fixture-project#103",
            "0d8f518b261850fb65ac0ec792b60e3abb3407659410a84fd390196c978e2ef2",
            "T4 EXTERNAL",
            "PUBLIC",
            OBSERVED_AT,
            "2026-11-02T10:32:00+00:00",
            None,
            '{"encoding":"utf-8","fixture_sha256":"7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1","fixture_version":"sentinel.github-issues-fixture.v1","in_memory_source_id":"6bfb1b55-3221-5950-bce9-d05b9848d3a5","issue_number":103,"repository":"example-owner/fixture-project","source_updated_at":"2026-11-02T10:32:00+00:00"}',
        ),
        "6bfb1b55-3221-5950-bce9-d05b9848d3a5",
        (
            (
                (
                    "4fa2fd51-8462-5eca-b868-a4852d929729",
                    "59baf4e0-02fb-5785-a5be-d49a433920b0",
                    16,
                    41,
                    "adca399ddf6a0c2e9be3462738ccb4315230e32fbd285287352fce1f66d89bb7",
                    None,
                    None,
                ),
                "a47a880d-e09a-48c7-b50c-b2d3b0e8a0e1",
            ),
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class ExpectedSpan:
    values: tuple[object, ...]
    in_memory_span_id: UUID
    source_id: UUID
    content_sha256: str

    @property
    def span_id(self) -> UUID:
        return UUID(str(self.values[0]))

    @property
    def start_byte(self) -> int:
        return cast(int, self.values[2])

    @property
    def end_byte(self) -> int:
        return cast(int, self.values[3])

    @property
    def text_sha256(self) -> str:
        return cast(str, self.values[4])


@dataclass(frozen=True, slots=True)
class ExpectedItem:
    values: tuple[object, ...]
    source_envelope_id: UUID
    spans: tuple[ExpectedSpan, ...]

    @property
    def item_id(self) -> UUID:
        return UUID(str(self.values[0]))

    @property
    def provider_item_id(self) -> str:
        return str(self.values[2])

    @property
    def content_sha256(self) -> str:
        return str(self.values[6])

    def values_with_ref(self, content_ref: str) -> tuple[object, ...]:
        values = list(self.values)
        values[5] = content_ref
        return tuple(values)


@dataclass(frozen=True, slots=True)
class ExpectedManifest:
    version: str
    fixture_version: str
    fixture_sha256: str
    observed_at: str
    principal_row: tuple[object, ...]
    plugin_row: tuple[object, ...]
    source_row: tuple[object, ...]
    items: tuple[ExpectedItem, ...]
    sha256: str


def _canonical_manifest_data() -> dict[str, object]:
    return {
        "version": MANIFEST_VERSION,
        "fixture_version": FIXTURE_VERSION,
        "fixture_sha256": FIXTURE_SHA256,
        "observed_at": OBSERVED_AT,
        "registry": {
            "principal": PRINCIPAL_ROW,
            "plugin": PLUGIN_ROW,
            "source": SOURCE_ROW,
        },
        "items": [
            {
                "values": values,
                "source_envelope_id": source_id,
                "spans": [
                    {
                        "values": span_values,
                        "in_memory_span_id": in_memory_span_id,
                        "source_id": source_id,
                        "content_sha256": str(values[6]),
                    }
                    for span_values, in_memory_span_id in span_rows
                ],
            }
            for values, source_id, span_rows in _ITEM_ROWS
        ],
    }


def load_expected_manifest() -> ExpectedManifest:
    """Return immutable expectations after checking their independently pinned hash."""

    try:
        canonical = json.dumps(
            _canonical_manifest_data(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ValueError("trusted persistence manifest is invalid") from None
    digest = hashlib.sha256(canonical).hexdigest()
    if digest != EXPECTED_MANIFEST_SHA256:
        raise ValueError("trusted persistence manifest integrity failed")

    items: list[ExpectedItem] = []
    for values, source_id, raw_spans in _ITEM_ROWS:
        spans = tuple(
            ExpectedSpan(
                values=span_values,
                in_memory_span_id=UUID(in_memory_span_id),
                source_id=UUID(source_id),
                content_sha256=str(values[6]),
            )
            for span_values, in_memory_span_id in raw_spans
        )
        items.append(
            ExpectedItem(
                values=values,
                source_envelope_id=UUID(source_id),
                spans=spans,
            )
        )
    return ExpectedManifest(
        version=MANIFEST_VERSION,
        fixture_version=FIXTURE_VERSION,
        fixture_sha256=FIXTURE_SHA256,
        observed_at=OBSERVED_AT,
        principal_row=PRINCIPAL_ROW,
        plugin_row=PLUGIN_ROW,
        source_row=SOURCE_ROW,
        items=tuple(items),
        sha256=digest,
    )


EXPECTED_MANIFEST: Final = load_expected_manifest()


__all__ = [
    "EXPECTED_MANIFEST",
    "EXPECTED_MANIFEST_SHA256",
    "ExpectedItem",
    "ExpectedManifest",
    "ExpectedSpan",
    "FIXTURE_SHA256",
    "FIXTURE_VERSION",
    "MANIFEST_VERSION",
    "OBSERVED_AT",
]
