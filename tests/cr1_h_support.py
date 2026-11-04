"""Shared synthetic helpers for CR1-H content-store tests."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

from sentinel.content import initialize_public_fixture_store, store_packaged_github_public_bodies

BLOB_MAGIC = b"SENTINEL-PUBLIC-FIXTURE-BLOB\n"
EXPECTED_BODY_DIGESTS = {
    "4ed9123596eda8d6095d288d39f3ee267faef342e515da10d22cd2013a9509b2",
    "58485f7f640572778e5938f992eb20b4ae23481b35dcb7b94c714856727876d3",
    "0d8f518b261850fb65ac0ec792b60e3abb3407659410a84fd390196c978e2ef2",
}


def prepare_store(root: Path) -> tuple[Path, Any]:
    initialize_public_fixture_store(root)
    return root, store_packaged_github_public_bodies(root)


def blob_path(root: Path, digest: str) -> Path:
    return root / "public-v1" / "sha256" / f"{digest}.blob"


def split_blob(path: Path) -> tuple[dict[str, object], bytes, bytes]:
    raw = path.read_bytes()
    assert raw.startswith(BLOB_MAGIC)
    size_offset = len(BLOB_MAGIC)
    metadata_size = struct.unpack(">I", raw[size_offset : size_offset + 4])[0]
    metadata_start = size_offset + 4
    metadata_end = metadata_start + metadata_size
    metadata_bytes = raw[metadata_start:metadata_end]
    metadata = json.loads(metadata_bytes.decode("utf-8"))
    return metadata, raw[:metadata_start], raw[metadata_start:metadata_end]


def encode_blob(metadata: dict[str, object], payload: bytes) -> bytes:
    metadata_bytes = json.dumps(
        metadata,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return BLOB_MAGIC + struct.pack(">I", len(metadata_bytes)) + metadata_bytes + payload


def rewrite_blob(path: Path, mutate: Any, payload: bytes | None = None) -> None:
    metadata, prefix, _metadata_bytes = split_blob(path)
    original_payload = path.read_bytes()[len(prefix) + len(_metadata_bytes) :]
    changed = mutate(metadata)
    path.write_bytes(encode_blob(changed, original_payload if payload is None else payload))
