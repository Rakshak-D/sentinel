"""Write-once storage for the pinned PUBLIC GitHub fixture bodies.

This is deliberately not a general source-content store. The write operation
accepts bytes only through the trusted packaged fixture reader; readback is
content-addressed and does not consult that fixture resource.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import stat
import struct
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, NoReturn

from sentinel.content.types import PublicFixtureBlob, PublicFixtureStoreReport
from sentinel.contracts.envelopes import SourceEnvelope
from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization.types import NormalizedPlainTextSource
from sentinel.readers.github_fixture import (
    FIXTURE_SCHEMA_VERSION,
    FIXTURE_SHA256,
    MAX_BODY_BYTES,
    GithubFixtureIssue,
    GithubFixtureRead,
    read_packaged_github_fixture,
)

STORE_FORMAT_VERSION: Final = "sentinel.public-fixture-store.v1"
BLOB_FORMAT_VERSION: Final = "sentinel.public-fixture-blob.v1"
MAX_BLOB_BYTES: Final = MAX_BODY_BYTES
MAX_HEADER_BYTES: Final = 1024
MAX_STORE_ROOT_PATH_CHARS: Final = 160

_STORE_MARKER_NAME: Final = "store-format-v1.json"
_PUBLIC_DIRECTORY: Final = "public-v1"
_HASH_DIRECTORY: Final = "sha256"
_STORE_MARKER: Final = (
    b'{"format_version":"sentinel.public-fixture-store.v1"}\n'
)
_BLOB_MAGIC: Final = b"SENTINEL-PUBLIC-FIXTURE-BLOB\n"
_LENGTH_PREFIX_BYTES: Final = 4
_MAX_BLOB_FILE_BYTES: Final = (
    len(_BLOB_MAGIC) + _LENGTH_PREFIX_BYTES + MAX_HEADER_BYTES + MAX_BLOB_BYTES
)
_MAX_MARKER_BYTES: Final = 128
_MAX_DIRECTORY_ENTRIES: Final = 24
_DIGEST_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
_TEMP_NAME_PATTERN: Final = re.compile(r"^\.tmp-[0-9a-f]{32}\.part$")

# These are the only payload identities writable or readable through this
# release-scope API. They are hashes of exact UTF-8 body bytes, not JSON bytes.
_FIXTURE_BODY_DIGESTS: Final = frozenset(
    {
        "4ed9123596eda8d6095d288d39f3ee267faef342e515da10d22cd2013a9509b2",
        "58485f7f640572778e5938f992eb20b4ae23481b35dcb7b94c714856727876d3",
        "0d8f518b261850fb65ac0ec792b60e3abb3407659410a84fd390196c978e2ef2",
    }
)
_BLOB_METADATA_FIELDS: Final = frozenset(
    {
        "content_sha256",
        "fixture_sha256",
        "fixture_version",
        "format_version",
        "payload_byte_length",
        "retention_class",
        "sensitivity",
        "trust_provenance",
    }
)


class PublicFixtureStoreErrorCode(StrEnum):
    """Fixed public failure categories; values never contain paths or content."""

    INVALID_ROOT = "invalid_root"
    UNSUPPORTED_FILESYSTEM = "unsupported_filesystem"
    STORE_UNINITIALIZED = "store_uninitialized"
    STORE_INVALID = "store_invalid"
    INVALID_DIGEST = "invalid_digest"
    BLOB_NOT_FOUND = "blob_not_found"
    BLOB_INVALID = "blob_invalid"
    FIXTURE_INVALID = "fixture_invalid"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    FILESYSTEM_FAILURE = "filesystem_failure"


_ERROR_MESSAGES: Final[dict[PublicFixtureStoreErrorCode, str]] = {
    PublicFixtureStoreErrorCode.INVALID_ROOT: (
        "An explicit absolute local store root is required."
    ),
    PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM: (
        "The selected store root is not on a supported local filesystem."
    ),
    PublicFixtureStoreErrorCode.STORE_UNINITIALIZED: (
        "The selected public fixture store is not initialized."
    ),
    PublicFixtureStoreErrorCode.STORE_INVALID: (
        "The selected public fixture store failed format verification."
    ),
    PublicFixtureStoreErrorCode.INVALID_DIGEST: (
        "Content digest must be a lowercase SHA-256 value."
    ),
    PublicFixtureStoreErrorCode.BLOB_NOT_FOUND: (
        "The requested public fixture blob is unavailable."
    ),
    PublicFixtureStoreErrorCode.BLOB_INVALID: (
        "The requested public fixture blob failed integrity verification."
    ),
    PublicFixtureStoreErrorCode.FIXTURE_INVALID: (
        "The pinned public GitHub fixture could not be verified."
    ),
    PublicFixtureStoreErrorCode.PAYLOAD_TOO_LARGE: (
        "Public fixture payload exceeds the configured size limit."
    ),
    PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE: (
        "Public fixture storage operation failed."
    ),
}


class PublicFixtureStoreError(RuntimeError):
    """Bounded storage failure with no filesystem or source-content details."""

    def __init__(self, code: PublicFixtureStoreErrorCode) -> None:
        if type(code) is not PublicFixtureStoreErrorCode:
            raise TypeError("storage error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


def _raise(code: PublicFixtureStoreErrorCode) -> NoReturn:
    raise PublicFixtureStoreError(code) from None


def _windows_drive_type(anchor: str) -> int:
    try:
        kernel32 = ctypes.windll.kernel32
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        return int(get_drive_type(anchor))
    except Exception:
        _raise(PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM)


def _is_reparse_point(path: Path) -> bool:
    """Detect Windows reparse points, including junctions, where supported."""

    if path.is_symlink():
        return True
    if os.name != "nt":
        return False
    kernel32 = ctypes.windll.kernel32
    get_attributes = kernel32.GetFileAttributesW
    get_attributes.argtypes = [ctypes.c_wchar_p]
    get_attributes.restype = ctypes.c_uint32
    attributes = int(get_attributes(str(path)))
    if attributes == 0xFFFFFFFF:
        raise OSError("file attributes are unavailable")
    return bool(attributes & 0x00000400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _coerce_root(root: str | Path) -> Path:
    if type(root) is str:
        raw_path = root
        try:
            path = Path(root)
        except (TypeError, ValueError):
            _raise(PublicFixtureStoreErrorCode.INVALID_ROOT)
    elif type(root) is type(Path()):
        path = root
        raw_path = str(root)
    else:
        _raise(PublicFixtureStoreErrorCode.INVALID_ROOT)

    if (
        not raw_path
        or "\x00" in raw_path
        or len(raw_path) > MAX_STORE_ROOT_PATH_CHARS
        or not path.is_absolute()
        or ".." in path.parts
    ):
        _raise(PublicFixtureStoreErrorCode.INVALID_ROOT)

    if os.name != "nt":
        _raise(PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM)
    if raw_path.startswith(("\\\\", "//")) or raw_path.startswith("\\\\?\\"):
        _raise(PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM)
    if not path.anchor or _windows_drive_type(path.anchor) != 3:  # DRIVE_FIXED
        _raise(PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM)
    return path


def _path_components(path: Path) -> tuple[Path, ...]:
    if not path.anchor:
        _raise(PublicFixtureStoreErrorCode.INVALID_ROOT)
    current = Path(path.anchor)
    components = [current]
    for part in path.parts[1:]:
        current = current / part
        components.append(current)
    return tuple(components)


def _walk_path(
    path: Path,
    *,
    leaf_kind: str,
    allow_missing_leaf: bool,
    error_code: PublicFixtureStoreErrorCode,
) -> os.stat_result | None:
    components = _path_components(path)
    for index, component in enumerate(components):
        is_leaf = index == len(components) - 1
        try:
            info = component.lstat()
        except FileNotFoundError:
            if is_leaf and allow_missing_leaf:
                return None
            _raise(error_code)
        except OSError:
            _raise(error_code)
        try:
            is_reparse = _is_reparse_point(component)
        except OSError:
            _raise(error_code)
        if is_reparse:
            _raise(error_code)
        if not is_leaf or leaf_kind == "directory":
            if not stat.S_ISDIR(info.st_mode):
                _raise(error_code)
        elif not stat.S_ISREG(info.st_mode):
            _raise(error_code)
    return info


def _directory_entries(path: Path, error_code: PublicFixtureStoreErrorCode) -> list[Path]:
    try:
        entries: list[Path] = []
        for entry in path.iterdir():
            entries.append(entry)
            if len(entries) > _MAX_DIRECTORY_ENTRIES:
                _raise(error_code)
    except OSError:
        _raise(error_code)
    return entries


def _ensure_directory(path: Path, error_code: PublicFixtureStoreErrorCode) -> None:
    state = _walk_path(
        path,
        leaf_kind="directory",
        allow_missing_leaf=True,
        error_code=error_code,
    )
    if state is None:
        try:
            os.mkdir(path)
        except FileExistsError:
            pass
        except OSError:
            _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
        _walk_path(
            path,
            leaf_kind="directory",
            allow_missing_leaf=False,
            error_code=error_code,
        )


def _file_identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


@dataclass(frozen=True, slots=True)
class _TemporaryIdentity:
    file: tuple[int, int]
    directory: tuple[int, int]


def _remove_owned_temporary(path: Path, identity: _TemporaryIdentity | None) -> None:
    if identity is None:
        return
    try:
        directory_info = _walk_path(
            path.parent,
            leaf_kind="directory",
            allow_missing_leaf=False,
            error_code=PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE,
        )
        if directory_info is None or _file_identity(directory_info) != identity.directory:
            return
        info = path.lstat()
        if (
            stat.S_ISREG(info.st_mode)
            and _file_identity(info) == identity.file
            and not _is_reparse_point(path)
        ):
            path.unlink()
    except (OSError, PublicFixtureStoreError):
        # Cleanup is best-effort and is limited to the exact inode opened by
        # this operation. A leftover temporary file is not a committed blob.
        return


def _write_temporary(directory: Path, contents: bytes) -> tuple[Path, _TemporaryIdentity]:
    directory_info = _walk_path(
        directory,
        leaf_kind="directory",
        allow_missing_leaf=False,
        error_code=PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE,
    )
    if directory_info is None:
        _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    temporary: Path | None = None
    descriptor: int | None = None
    identity: _TemporaryIdentity | None = None
    for _attempt in range(3):
        candidate = directory / f".tmp-{uuid.uuid4().hex}.part"
        try:
            descriptor = os.open(candidate, flags, 0o600)
            temporary = candidate
            identity = _TemporaryIdentity(
                file=_file_identity(os.fstat(descriptor)),
                directory=_file_identity(directory_info),
            )
            break
        except FileExistsError:
            continue
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
    if descriptor is None or temporary is None or identity is None:
        _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)

    try:
        offset = 0
        while offset < len(contents):
            written = os.write(descriptor, contents[offset:])
            if written <= 0:
                _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
            offset += written
        os.fsync(descriptor)
    except PublicFixtureStoreError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        _remove_owned_temporary(temporary, identity)
        raise
    except OSError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        _remove_owned_temporary(temporary, identity)
        _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
    else:
        try:
            os.close(descriptor)
        except OSError:
            _remove_owned_temporary(temporary, identity)
            _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
    return temporary, identity


def _publish_no_clobber(
    temporary: Path,
    final: Path,
    identity: _TemporaryIdentity,
) -> bool:
    """Atomically publish on the verified Windows target without replacement."""

    if os.name != "nt":
        _raise(PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM)
    if temporary.parent != final.parent:
        _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
    directory_info = _walk_path(
        temporary.parent,
        leaf_kind="directory",
        allow_missing_leaf=False,
        error_code=PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE,
    )
    if directory_info is None or _file_identity(directory_info) != identity.directory:
        _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
    temporary_info = _walk_path(
        temporary,
        leaf_kind="file",
        allow_missing_leaf=False,
        error_code=PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE,
    )
    if temporary_info is None or _file_identity(temporary_info) != identity.file:
        _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
    try:
        # On Windows, os.rename uses MoveFileW without MOVEFILE_REPLACE_EXISTING;
        # an existing destination raises FileExistsError. Tests exercise this
        # behavior on the target NTFS volume.
        os.rename(temporary, final)
    except FileExistsError:
        return False
    except OSError:
        _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
    return True


def _canonical_json(value: dict[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)


def _make_blob_metadata(content_sha256: str, payload_byte_length: int) -> dict[str, object]:
    return {
        "content_sha256": content_sha256,
        "fixture_sha256": FIXTURE_SHA256,
        "fixture_version": FIXTURE_SCHEMA_VERSION,
        "format_version": BLOB_FORMAT_VERSION,
        "payload_byte_length": payload_byte_length,
        "retention_class": "fixture_public",
        "sensitivity": SensitivityLabel.PUBLIC.value,
        "trust_provenance": TrustLabel.T4_EXTERNAL.value,
    }


def _encode_blob(content_sha256: str, payload: bytes) -> bytes:
    metadata = _make_blob_metadata(content_sha256, len(payload))
    encoded_metadata = _canonical_json(metadata)
    if len(encoded_metadata) > MAX_HEADER_BYTES:
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
    return (
        _BLOB_MAGIC
        + struct.pack(">I", len(encoded_metadata))
        + encoded_metadata
        + payload
    )


def _read_bounded_file(
    path: Path,
    *,
    maximum_bytes: int,
    error_code: PublicFixtureStoreErrorCode,
    missing_code: PublicFixtureStoreErrorCode | None = None,
) -> bytes:
    info = _walk_path(
        path,
        leaf_kind="file",
        allow_missing_leaf=missing_code is not None,
        error_code=error_code,
    )
    if info is None:
        if missing_code is None:
            _raise(error_code)
        _raise(missing_code)
    if info.st_nlink != 1 or info.st_size < 0 or info.st_size > maximum_bytes:
        _raise(error_code)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_info.st_mode)
            or opened_info.st_nlink != 1
            or _file_identity(opened_info) != _file_identity(info)
            or opened_info.st_size != info.st_size
        ):
            _raise(error_code)
        content = bytearray()
        while len(content) <= maximum_bytes:
            remaining = maximum_bytes + 1 - len(content)
            chunk = os.read(descriptor, min(8192, remaining))
            if not chunk:
                break
            content.extend(chunk)
        after_info = os.fstat(descriptor)
        current_info = path.lstat()
        if (
            len(content) > maximum_bytes
            or len(content) != opened_info.st_size
            or _file_identity(after_info) != _file_identity(opened_info)
            or after_info.st_size != opened_info.st_size
            or _file_identity(current_info) != _file_identity(opened_info)
            or _is_reparse_point(path)
        ):
            _raise(error_code)
        return bytes(content)
    except PublicFixtureStoreError:
        raise
    except OSError:
        _raise(error_code)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                _raise(error_code)


def _verify_marker(root: Path, *, absent_allowed: bool) -> bool:
    marker = root / _STORE_MARKER_NAME
    marker_bytes = _read_bounded_file(
        marker,
        maximum_bytes=_MAX_MARKER_BYTES,
        error_code=PublicFixtureStoreErrorCode.STORE_INVALID,
        missing_code=(
            PublicFixtureStoreErrorCode.STORE_UNINITIALIZED if absent_allowed else None
        ),
    )
    if marker_bytes != _STORE_MARKER:
        _raise(PublicFixtureStoreErrorCode.STORE_INVALID)
    return True


def _validate_store_layout(root: Path) -> None:
    root_state = _walk_path(
        root,
        leaf_kind="directory",
        allow_missing_leaf=True,
        error_code=PublicFixtureStoreErrorCode.STORE_INVALID,
    )
    if root_state is None:
        _raise(PublicFixtureStoreErrorCode.STORE_UNINITIALIZED)
    _verify_marker(root, absent_allowed=True)

    public_dir = root / _PUBLIC_DIRECTORY
    hash_dir = public_dir / _HASH_DIRECTORY
    _walk_path(
        public_dir,
        leaf_kind="directory",
        allow_missing_leaf=False,
        error_code=PublicFixtureStoreErrorCode.STORE_INVALID,
    )
    _walk_path(
        hash_dir,
        leaf_kind="directory",
        allow_missing_leaf=False,
        error_code=PublicFixtureStoreErrorCode.STORE_INVALID,
    )

    root_entries = _directory_entries(root, PublicFixtureStoreErrorCode.STORE_INVALID)
    if {entry.name for entry in root_entries} != {_STORE_MARKER_NAME, _PUBLIC_DIRECTORY}:
        _raise(PublicFixtureStoreErrorCode.STORE_INVALID)
    public_entries = _directory_entries(public_dir, PublicFixtureStoreErrorCode.STORE_INVALID)
    if {entry.name for entry in public_entries} != {_HASH_DIRECTORY}:
        _raise(PublicFixtureStoreErrorCode.STORE_INVALID)
    hash_entries = _directory_entries(hash_dir, PublicFixtureStoreErrorCode.STORE_INVALID)
    for entry in hash_entries:
        if entry.name.endswith(".blob"):
            digest = entry.name[:-5]
            if digest not in _FIXTURE_BODY_DIGESTS:
                _raise(PublicFixtureStoreErrorCode.STORE_INVALID)
            _walk_path(
                entry,
                leaf_kind="file",
                allow_missing_leaf=False,
                error_code=PublicFixtureStoreErrorCode.STORE_INVALID,
            )
        elif _TEMP_NAME_PATTERN.fullmatch(entry.name) is not None:
            _walk_path(
                entry,
                leaf_kind="file",
                allow_missing_leaf=False,
                error_code=PublicFixtureStoreErrorCode.STORE_INVALID,
            )
        else:
            _raise(PublicFixtureStoreErrorCode.STORE_INVALID)


def _create_marker(root: Path) -> None:
    temporary, identity = _write_temporary(root, _STORE_MARKER)
    marker = root / _STORE_MARKER_NAME
    published = False
    try:
        published = _publish_no_clobber(temporary, marker, identity)
    except PublicFixtureStoreError:
        _remove_owned_temporary(temporary, identity)
        raise
    if not published:
        _remove_owned_temporary(temporary, identity)
        _verify_marker(root, absent_allowed=False)


def initialize_public_fixture_store(root: str | Path) -> None:
    """Create the selected store layout; parent directories must already exist.

    Calling this function never initializes SQLite or creates a default path.
    An unrecognized or partially initialized nonempty directory is rejected,
    not repaired.
    """

    selected_root = _coerce_root(root)
    root_state = _walk_path(
        selected_root,
        leaf_kind="directory",
        allow_missing_leaf=True,
        error_code=PublicFixtureStoreErrorCode.INVALID_ROOT,
    )
    if root_state is None:
        _walk_path(
            selected_root.parent,
            leaf_kind="directory",
            allow_missing_leaf=False,
            error_code=PublicFixtureStoreErrorCode.INVALID_ROOT,
        )
        try:
            os.mkdir(selected_root)
        except FileExistsError:
            pass
        except OSError:
            _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
        _walk_path(
            selected_root,
            leaf_kind="directory",
            allow_missing_leaf=False,
            error_code=PublicFixtureStoreErrorCode.INVALID_ROOT,
        )

    marker = selected_root / _STORE_MARKER_NAME
    marker_state = _walk_path(
        marker,
        leaf_kind="file",
        allow_missing_leaf=True,
        error_code=PublicFixtureStoreErrorCode.STORE_INVALID,
    )
    if marker_state is not None:
        _validate_store_layout(selected_root)
        return

    if _directory_entries(selected_root, PublicFixtureStoreErrorCode.STORE_INVALID):
        _raise(PublicFixtureStoreErrorCode.STORE_INVALID)

    public_dir = selected_root / _PUBLIC_DIRECTORY
    hash_dir = public_dir / _HASH_DIRECTORY
    _ensure_directory(public_dir, PublicFixtureStoreErrorCode.STORE_INVALID)
    _ensure_directory(hash_dir, PublicFixtureStoreErrorCode.STORE_INVALID)
    _create_marker(selected_root)
    _validate_store_layout(selected_root)


def _require_store(root: str | Path) -> Path:
    selected_root = _coerce_root(root)
    _validate_store_layout(selected_root)
    return selected_root


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("non-standard JSON constant")


def _parse_blob(raw: bytes, requested_digest: str) -> bytes:
    if len(raw) < len(_BLOB_MAGIC) + _LENGTH_PREFIX_BYTES:
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
    if not raw.startswith(_BLOB_MAGIC):
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
    length_start = len(_BLOB_MAGIC)
    length_end = length_start + _LENGTH_PREFIX_BYTES
    metadata_length = struct.unpack(">I", raw[length_start:length_end])[0]
    if not 1 <= metadata_length <= MAX_HEADER_BYTES:
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
    metadata_start = length_start + _LENGTH_PREFIX_BYTES
    payload_start = metadata_start + metadata_length
    if payload_start > len(raw):
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
    metadata_bytes = raw[metadata_start:payload_start]
    payload = raw[payload_start:]
    try:
        metadata_text = metadata_bytes.decode("utf-8", errors="strict")
        metadata_value = json.loads(
            metadata_text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
    if type(metadata_value) is not dict or set(metadata_value) != _BLOB_METADATA_FIELDS:
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)

    metadata = metadata_value
    if (
        any(
            type(metadata[field]) is not str
            for field in _BLOB_METADATA_FIELDS - {"payload_byte_length"}
        )
        or type(metadata["payload_byte_length"]) is not int
        or not 0 <= metadata["payload_byte_length"] <= MAX_BLOB_BYTES
        or metadata["format_version"] != BLOB_FORMAT_VERSION
        or metadata["fixture_version"] != FIXTURE_SCHEMA_VERSION
        or metadata["fixture_sha256"] != FIXTURE_SHA256
        or metadata["sensitivity"] != SensitivityLabel.PUBLIC.value
        or metadata["retention_class"] != "fixture_public"
        or metadata["trust_provenance"] != TrustLabel.T4_EXTERNAL.value
        or metadata["content_sha256"] != requested_digest
        or requested_digest not in _FIXTURE_BODY_DIGESTS
        or _canonical_json(metadata) != metadata_bytes
        or metadata["payload_byte_length"] != len(payload)
        or hashlib.sha256(payload).hexdigest() != requested_digest
    ):
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
    return payload


def _blob_path(root: Path, content_sha256: str) -> Path:
    return root / _PUBLIC_DIRECTORY / _HASH_DIRECTORY / f"{content_sha256}.blob"


def _read_blob(root: Path, content_sha256: str) -> bytes:
    if type(content_sha256) is not str or _DIGEST_PATTERN.fullmatch(content_sha256) is None:
        _raise(PublicFixtureStoreErrorCode.INVALID_DIGEST)
    if content_sha256 not in _FIXTURE_BODY_DIGESTS:
        _raise(PublicFixtureStoreErrorCode.BLOB_NOT_FOUND)
    path = _blob_path(root, content_sha256)
    raw = _read_bounded_file(
        path,
        maximum_bytes=_MAX_BLOB_FILE_BYTES,
        error_code=PublicFixtureStoreErrorCode.BLOB_INVALID,
        missing_code=PublicFixtureStoreErrorCode.BLOB_NOT_FOUND,
    )
    return _parse_blob(raw, content_sha256)


def read_public_fixture_blob(root: str | Path, *, content_sha256: str) -> bytes:
    """Return exact verified PUBLIC payload bytes without reading the fixture.

    The digest must be one of the three fixed GitHub fixture body identities.
    The returned byte sequence is intended for trusted internal callers.
    """

    selected_root = _require_store(root)
    if type(content_sha256) is not str or _DIGEST_PATTERN.fullmatch(content_sha256) is None:
        _raise(PublicFixtureStoreErrorCode.INVALID_DIGEST)
    if content_sha256 not in _FIXTURE_BODY_DIGESTS:
        _raise(PublicFixtureStoreErrorCode.BLOB_NOT_FOUND)
    return _read_blob(selected_root, content_sha256)


def _fixture_bodies() -> tuple[tuple[str, bytes], ...]:
    try:
        fixture = read_packaged_github_fixture()
        if (
            type(fixture) is not GithubFixtureRead
            or fixture.fixture_version != FIXTURE_SCHEMA_VERSION
            or fixture.fixture_sha256 != FIXTURE_SHA256
            or type(fixture.issues) is not tuple
            or len(fixture.issues) != 3
        ):
            _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)

        bodies: list[tuple[str, bytes]] = []
        for issue in fixture.issues:
            if type(issue) is not GithubFixtureIssue:
                _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)
            normalized = issue.normalized_source
            if type(normalized) is not NormalizedPlainTextSource:
                _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)
            envelope = normalized.envelope
            if type(envelope) is not SourceEnvelope:
                _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)
            checked_envelope = SourceEnvelope.model_validate(envelope.model_dump(mode="python"))
            payload = normalized.original_bytes
            text = normalized.text
            if (
                type(payload) is not bytes
                or type(text) is not str
                or len(payload) > MAX_BLOB_BYTES
                or text.encode("utf-8", errors="strict") != payload
                or hashlib.sha256(payload).hexdigest() != checked_envelope.content_sha256
                or checked_envelope.provider_id != "github.fixture"
                or checked_envelope.trust is not TrustLabel.T4_EXTERNAL
                or checked_envelope.sensitivity is not SensitivityLabel.PUBLIC
            ):
                _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)
            digest = hashlib.sha256(payload).hexdigest()
            if digest not in _FIXTURE_BODY_DIGESTS:
                _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)
            bodies.append((digest, payload))

        if {digest for digest, _payload in bodies} != _FIXTURE_BODY_DIGESTS:
            _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)
        if len({digest for digest, _payload in bodies}) != len(bodies):
            _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)
        return tuple(bodies)
    except PublicFixtureStoreError:
        raise
    except Exception:
        _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)


def _store_one(root: Path, digest: str, payload: bytes) -> bool:
    final = _blob_path(root, digest)
    existing = _walk_path(
        final,
        leaf_kind="file",
        allow_missing_leaf=True,
        error_code=PublicFixtureStoreErrorCode.BLOB_INVALID,
    )
    if existing is not None:
        if _read_blob(root, digest) != payload:
            _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
        return False

    encoded = _encode_blob(digest, payload)
    temporary, identity = _write_temporary(final.parent, encoded)
    try:
        published = _publish_no_clobber(temporary, final, identity)
    except PublicFixtureStoreError:
        _remove_owned_temporary(temporary, identity)
        raise
    except OSError:
        _remove_owned_temporary(temporary, identity)
        _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)
    if not published:
        _remove_owned_temporary(temporary, identity)
        if _read_blob(root, digest) != payload:
            _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
        return False
    if _read_blob(root, digest) != payload:
        _raise(PublicFixtureStoreErrorCode.BLOB_INVALID)
    return True


def store_packaged_github_public_bodies(root: str | Path) -> PublicFixtureStoreReport:
    """Persist only the three exact PUBLIC bodies from the fixed GitHub fixture.

    The store must have been explicitly initialized. Each file is independently
    flushed, atomically published without replacement, then read back and
    verified. The collection of three files is not one atomic transaction.
    """

    try:
        selected_root = _require_store(root)
        bodies = _fixture_bodies()
        blobs: list[PublicFixtureBlob] = []
        inserted_count = 0
        existing_count = 0
        for digest, payload in bodies:
            if len(payload) > MAX_BLOB_BYTES:
                _raise(PublicFixtureStoreErrorCode.PAYLOAD_TOO_LARGE)
            was_inserted = _store_one(selected_root, digest, payload)
            if was_inserted:
                inserted_count += 1
            else:
                existing_count += 1
            blobs.append(PublicFixtureBlob(content_sha256=digest, payload_byte_length=len(payload)))
        if inserted_count + existing_count != 3:
            _raise(PublicFixtureStoreErrorCode.FIXTURE_INVALID)
        return PublicFixtureStoreReport(
            format_version=STORE_FORMAT_VERSION,
            fixture_version=FIXTURE_SCHEMA_VERSION,
            fixture_sha256=FIXTURE_SHA256,
            inserted_count=inserted_count,
            existing_count=existing_count,
            blobs=tuple(blobs),
        )
    except PublicFixtureStoreError:
        raise
    except OSError:
        _raise(PublicFixtureStoreErrorCode.FILESYSTEM_FAILURE)


__all__ = [
    "BLOB_FORMAT_VERSION",
    "MAX_BLOB_BYTES",
    "MAX_HEADER_BYTES",
    "MAX_STORE_ROOT_PATH_CHARS",
    "STORE_FORMAT_VERSION",
    "PublicFixtureStoreError",
    "PublicFixtureStoreErrorCode",
    "initialize_public_fixture_store",
    "read_public_fixture_blob",
    "store_packaged_github_public_bodies",
]
