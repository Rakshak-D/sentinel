"""One explicitly selected, bounded Windows local text-file adapter."""

from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import re
import stat
from ctypes import wintypes
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import (
    MAX_PLAIN_TEXT_BYTES,
    NormalizationError,
    NormalizedPlainTextSource,
    PlainTextSourceDescriptor,
    add_citation,
    bind_citation,
    normalize_plain_text,
    verify_bound_citation,
)
from sentinel.readers.local_text_types import (
    LocalFileMetadata,
    LocalTextCitation,
    LocalTextError,
    LocalTextErrorCode,
    LocalTextFormat,
    LocalTextRead,
)

_MAX_PATH_CHARS = 32760
_REPARSE_POINT = 0x0400
_FILE_ATTRIBUTE_DIRECTORY = 0x0010
_FILE_ATTRIBUTE_DEVICE = 0x0040
_GENERIC_READ = 0x80000000
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_TYPE_DISK = 1
_DRIVE_FIXED = 3
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_RESERVED_BASES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
        *(f"COM{digit}" for digit in "¹²³"),
        *(f"LPT{digit}" for digit in "¹²³"),
    }
)
_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:$")


class _FileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("creation_time", _FileTime),
        ("last_access_time", _FileTime),
        ("last_write_time", _FileTime),
        ("volume_serial", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    ]


def _raise(code: LocalTextErrorCode) -> NoReturn:
    raise LocalTextError(code) from None


def _utc_now() -> datetime:
    """Trusted local observation clock; tests replace this private seam."""
    return datetime.now(UTC)


def _path_text(value: str | Path, *, root: bool) -> tuple[str, Path]:
    if type(value) is str:
        raw = value
    elif type(value) is type(Path()):
        raw = str(value)
    else:
        _raise(LocalTextErrorCode.INVALID_PATH)
    if (
        not raw
        or len(raw) > _MAX_PATH_CHARS
        or "\x00" in raw
        or "/" in raw
        or raw.startswith(("\\\\", "\\\\?\\", "\\\\.\\", "\\??\\"))
        or not raw[0:2].endswith(":")
    ):
        _raise(LocalTextErrorCode.INVALID_PATH)
    drive, tail = ntpath.splitdrive(raw)
    if _DRIVE_PATTERN.fullmatch(drive) is None or not tail.startswith("\\"):
        _raise(LocalTextErrorCode.INVALID_PATH)
    if ":" in tail:
        _raise(LocalTextErrorCode.INVALID_PATH)
    if tail.endswith("\\") and not root:
        _raise(LocalTextErrorCode.INVALID_PATH)
    components = tail[1:].split("\\")
    if root and components[-1] == "":
        components.pop()
    for component in components:
        if not component or component in {".", ".."} or component.endswith((".", " ")):
            _raise(LocalTextErrorCode.INVALID_PATH)
        if any(character in component for character in ("<", ">", '"', "|", "?", "*")):
            _raise(LocalTextErrorCode.INVALID_PATH)
        if component.split(".", 1)[0].rstrip(" .").upper() in _RESERVED_BASES:
            _raise(LocalTextErrorCode.INVALID_PATH)
    if os.name != "nt":
        _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = (wintypes.LPCWSTR,)
        get_drive_type.restype = wintypes.UINT
        if int(get_drive_type(f"{drive}\\")) != _DRIVE_FIXED:
            _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)
        path = Path(raw)
    except LocalTextError:
        raise
    except Exception:
        _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)
    if not path.is_absolute():
        _raise(LocalTextErrorCode.INVALID_PATH)
    return raw, path


def _commonpath_contains(root: str, target: str) -> bool:
    try:
        common = ntpath.commonpath((root, target))
    except (ValueError, OSError):
        return False
    return ntpath.normcase(common) == ntpath.normcase(root) and ntpath.normcase(
        target
    ) != ntpath.normcase(root)


def _components(path: Path) -> tuple[Path, ...]:
    drive, tail = ntpath.splitdrive(str(path))
    current = Path(f"{drive}\\")
    result = [current]
    for component in tail[1:].rstrip("\\").split("\\"):
        if component:
            current = current / component
            result.append(current)
    return tuple(result)


def _has_reparse_attribute(path: Path) -> bool:
    try:
        info = path.lstat()
    except (OSError, RuntimeError, ValueError, TypeError):
        _raise(LocalTextErrorCode.FILE_UNAVAILABLE)
    attributes = int(getattr(info, "st_file_attributes", 0))
    if stat.S_ISLNK(info.st_mode) or attributes & _REPARSE_POINT:
        return True
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_attributes = kernel32.GetFileAttributesW
        get_attributes.argtypes = (wintypes.LPCWSTR,)
        get_attributes.restype = wintypes.DWORD
        value = int(get_attributes(str(path)))
        if value == 0xFFFFFFFF:
            _raise(LocalTextErrorCode.FILE_UNAVAILABLE)
        return bool(value & _REPARSE_POINT)
    except LocalTextError:
        raise
    except Exception:
        _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)


def _checked_stat(path: Path) -> os.stat_result:
    if _has_reparse_attribute(path):
        _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
    try:
        return path.stat()
    except (OSError, RuntimeError, ValueError, TypeError):
        _raise(LocalTextErrorCode.FILE_UNAVAILABLE)


def _check_components(path: Path, *, expect_directory: bool) -> os.stat_result:
    chain = _components(path)
    last: os.stat_result | None = None
    for component in chain:
        last = _checked_stat(component)
        if component != chain[-1] and not stat.S_ISDIR(last.st_mode):
            _raise(LocalTextErrorCode.NOT_REGULAR_FILE)
    if last is None:
        _raise(LocalTextErrorCode.INVALID_PATH)
    if expect_directory:
        if not stat.S_ISDIR(last.st_mode):
            _raise(LocalTextErrorCode.FILE_UNAVAILABLE)
    elif not stat.S_ISREG(last.st_mode):
        _raise(LocalTextErrorCode.NOT_REGULAR_FILE)
    return last


def _identity_from_stat(info: os.stat_result) -> tuple[int, int, int, int, int]:
    values = (
        getattr(info, "st_dev", None),
        getattr(info, "st_ino", None),
        getattr(info, "st_nlink", None),
        getattr(info, "st_size", None),
        getattr(info, "st_mtime_ns", None),
    )
    if any(type(value) is not int for value in values) or values[1] == 0:
        _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)
    device, inode, links, size, modified_ns = (cast(int, value) for value in values)
    if links > 1:
        _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
    return device, inode, links, size, modified_ns


def _kernel32() -> object:
    try:
        return ctypes.WinDLL("kernel32", use_last_error=True)
    except Exception:
        _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)


def _create_file_handle(path: Path, *, directory: bool) -> int:
    kernel = _kernel32()
    create_file = kernel.CreateFileW  # type: ignore[attr-defined]
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    desired_access = _FILE_READ_ATTRIBUTES if directory else _GENERIC_READ | _FILE_READ_ATTRIBUTES
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    else:
        flags |= _FILE_FLAG_SEQUENTIAL_SCAN
    raw_handle = create_file(
        str(path), desired_access, _FILE_SHARE_READ, None, _OPEN_EXISTING, flags, None
    )
    handle = int(raw_handle) if raw_handle is not None else int(_INVALID_HANDLE_VALUE or -1)
    if handle == _INVALID_HANDLE_VALUE or handle == 0:
        _raise(LocalTextErrorCode.FILE_UNAVAILABLE)
    try:
        set_handle_info = kernel.SetHandleInformation  # type: ignore[attr-defined]
        set_handle_info.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD)
        set_handle_info.restype = wintypes.BOOL
        succeeded = bool(set_handle_info(wintypes.HANDLE(handle), 1, 0))
    except Exception:
        kernel.CloseHandle(wintypes.HANDLE(handle))  # type: ignore[attr-defined]
        _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)
    if not succeeded:
        kernel.CloseHandle(wintypes.HANDLE(handle))  # type: ignore[attr-defined]
        _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)
    return handle


def _file_information(handle: int) -> _ByHandleFileInformation:
    kernel = _kernel32()
    get_type = kernel.GetFileType  # type: ignore[attr-defined]
    get_type.argtypes = (wintypes.HANDLE,)
    get_type.restype = wintypes.DWORD
    if int(get_type(wintypes.HANDLE(handle))) != _FILE_TYPE_DISK:
        _raise(LocalTextErrorCode.NOT_REGULAR_FILE)
    info = _ByHandleFileInformation()
    get_info = kernel.GetFileInformationByHandle  # type: ignore[attr-defined]
    get_info.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation))
    get_info.restype = wintypes.BOOL
    if not get_info(wintypes.HANDLE(handle), ctypes.byref(info)):
        _raise(LocalTextErrorCode.FILE_UNAVAILABLE)
    return info


def _raw_handle_identity(info: _ByHandleFileInformation) -> tuple[int, int, int, int, int, int]:
    size = (int(info.file_size_high) << 32) | int(info.file_size_low)
    index = (int(info.file_index_high) << 32) | int(info.file_index_low)
    modified = (int(info.last_write_time.high) << 32) | int(info.last_write_time.low)
    return (
        int(info.volume_serial),
        index,
        int(info.number_of_links),
        size,
        modified,
        int(info.attributes),
    )


def _handle_identity(info: _ByHandleFileInformation) -> tuple[int, int, int, int, int, int]:
    identity = _raw_handle_identity(info)
    if info.attributes & _REPARSE_POINT:
        _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
    if info.attributes & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_DEVICE):
        _raise(LocalTextErrorCode.NOT_REGULAR_FILE)
    if info.number_of_links != 1 or identity[1] == 0:
        _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
    return identity


def _opened_final_path(handle: int) -> str:
    kernel = _kernel32()
    get_final = kernel.GetFinalPathNameByHandleW  # type: ignore[attr-defined]
    get_final.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    get_final.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(_MAX_PATH_CHARS + 1)
    count = int(get_final(wintypes.HANDLE(handle), buffer, len(buffer), 0))
    if count == 0 or count >= len(buffer):
        _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)
    result = buffer.value
    if result.startswith("\\\\?\\"):
        result = result[4:]
    if not ntpath.splitdrive(result)[0]:
        _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)
    return ntpath.normpath(result)


def _close_handle(handle: int) -> None:
    try:
        _kernel32().CloseHandle(wintypes.HANDLE(handle))  # type: ignore[attr-defined]
    except Exception:
        pass


def _open_directory_guards(root: Path, target_parent: Path) -> tuple[list[int], int, str]:
    handles: list[int] = []
    root_key = ntpath.normcase(ntpath.normpath(str(root)))
    root_handle = 0
    root_final = ""
    try:
        for component in _components(target_parent):
            _checked_stat(component)
            handle = _create_file_handle(component, directory=True)
            handles.append(handle)
            info = _file_information(handle)
            if info.attributes & _REPARSE_POINT:
                _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
            if not (info.attributes & _FILE_ATTRIBUTE_DIRECTORY):
                _raise(LocalTextErrorCode.NOT_REGULAR_FILE)
            final = _opened_final_path(handle)
            if ntpath.normcase(final) == root_key:
                root_handle = handle
                root_final = final
        if not root_handle:
            _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
        return handles, root_handle, root_final
    except Exception:
        for handle in reversed(handles):
            _close_handle(handle)
        raise


def read_allowlisted_local_text(
    *,
    allowed_root: str | Path,
    file_path: str | Path,
) -> LocalTextRead:
    """Read one exact UTF-8 `.txt` or `.md` file beneath an explicit root.

    Windows path checks are repeated around a non-inheritable handle read. The
    opened target's file ID and final path are checked against the selected root.
    This is a cooperative filesystem boundary, not isolation from a malicious
    same-user process with directory access.
    """

    _, root = _path_text(allowed_root, root=True)
    _, target = _path_text(file_path, root=False)
    if ntpath.normcase(str(root.drive)) != ntpath.normcase(str(target.drive)):
        _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
    if not _commonpath_contains(str(root), str(target)):
        _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
    suffix = target.suffix.lower()
    if suffix not in {".txt", ".md"}:
        _raise(LocalTextErrorCode.UNSUPPORTED_FORMAT)

    root_stat = _check_components(root, expect_directory=True)
    before_stat = _check_components(target, expect_directory=False)
    before_identity = _identity_from_stat(before_stat)
    if before_stat.st_size > MAX_PLAIN_TEXT_BYTES:
        _raise(LocalTextErrorCode.TOO_LARGE)
    directory_handles: list[int] = []
    target_handle: int | None = None
    descriptor: int | None = None
    try:
        import msvcrt

        directory_handles, opened_root_handle, opened_root_path = _open_directory_guards(
            root, target.parent
        )
        opened_root_info = _file_information(opened_root_handle)
        root_identity = _raw_handle_identity(opened_root_info)
        if (
            int(root_stat.st_dev) != root_identity[0]
            or int(root_stat.st_ino) != root_identity[1]
            or not (opened_root_info.attributes & _FILE_ATTRIBUTE_DIRECTORY)
        ):
            _raise(LocalTextErrorCode.FILE_CHANGED)

        target_handle = _create_file_handle(target, directory=False)
        target_info = _file_information(target_handle)
        opened_identity = _handle_identity(target_info)
        if (
            before_identity[0] != opened_identity[0]
            or before_identity[1] != opened_identity[1]
            or before_identity[3] != opened_identity[3]
            or opened_identity[0] != root_identity[0]
        ):
            _raise(LocalTextErrorCode.FILE_CHANGED)
        if opened_identity[3] > MAX_PLAIN_TEXT_BYTES:
            _raise(LocalTextErrorCode.TOO_LARGE)
        opened_path = _opened_final_path(target_handle)
        if not _commonpath_contains(opened_root_path, opened_path):
            _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
        descriptor, target_handle = (
            msvcrt.open_osfhandle(target_handle, os.O_RDONLY | os.O_BINARY),
            None,
        )
        os.set_inheritable(descriptor, False)
        content = bytearray()
        while len(content) < MAX_PLAIN_TEXT_BYTES + 1:
            remaining = MAX_PLAIN_TEXT_BYTES + 1 - len(content)
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > MAX_PLAIN_TEXT_BYTES:
            _raise(LocalTextErrorCode.TOO_LARGE)
        raw_content = bytes(content)

        # Validate both the still-open handle and the path after the bounded read.
        after_info = _file_information(msvcrt.get_osfhandle(descriptor))
        after_identity = _handle_identity(after_info)
        after_stat = _check_components(target, expect_directory=False)
        after_path_identity = _identity_from_stat(after_stat)
        if (
            opened_identity != after_identity
            or before_identity != after_path_identity
            or after_path_identity[0] != opened_identity[0]
            or after_path_identity[1] != opened_identity[1]
            or after_path_identity[3] != len(raw_content)
            or len(raw_content) != opened_identity[3]
        ):
            _raise(LocalTextErrorCode.FILE_CHANGED)

        try:
            observed_at = _utc_now()
            if (
                type(observed_at) is not datetime
                or observed_at.tzinfo is None
                or observed_at.utcoffset() is None
            ):
                _raise(LocalTextErrorCode.INVALID_SOURCE)
            observed_at = observed_at.astimezone(UTC)
            relative_identity = ntpath.relpath(opened_path, opened_root_path).replace("\\", "/")
            if relative_identity.startswith("../") or relative_identity == "..":
                _raise(LocalTextErrorCode.PATH_NOT_ALLOWED)
            content_sha256 = hashlib.sha256(raw_content).hexdigest()
            source_id = uuid5(
                NAMESPACE_URL,
                f"sentinel:local-text:v1:{relative_identity}:{content_sha256}",
            )
            descriptor_value = PlainTextSourceDescriptor(
                source_id=source_id,
                provider_id="local.file",
                observed_at=observed_at,
                trust=TrustLabel.T4_EXTERNAL,
                sensitivity=SensitivityLabel.PRIVATE,
            )
            normalized = normalize_plain_text(
                descriptor_value,
                raw_content,
                "text/plain; charset=utf-8",
            )
        except LocalTextError:
            raise
        except NormalizationError as exc:
            if getattr(exc, "code", None) is not None and exc.code.value == "invalid_utf8":
                _raise(LocalTextErrorCode.INVALID_UTF8)
            if getattr(exc, "code", None) is not None and exc.code.value == "too_large":
                _raise(LocalTextErrorCode.TOO_LARGE)
            _raise(LocalTextErrorCode.INVALID_SOURCE)
        except Exception:
            _raise(LocalTextErrorCode.INVALID_SOURCE)

        try:
            modified_at = datetime.fromtimestamp(after_stat.st_mtime, UTC)
        except (OverflowError, OSError, ValueError):
            _raise(LocalTextErrorCode.UNSUPPORTED_FILESYSTEM)
        return LocalTextRead(
            normalized_source=normalized,
            source_id=source_id,
            provider_id="local.file",
            byte_length=len(raw_content),
            content_sha256=content_sha256,
            trust=TrustLabel.T4_EXTERNAL,
            sensitivity=SensitivityLabel.PRIVATE,
            source_format=LocalTextFormat(suffix),
            file_metadata=LocalFileMetadata(
                byte_length=len(raw_content),
                source_format=LocalTextFormat(suffix),
                modified_at_utc=modified_at,
            ),
            _relative_identity=relative_identity,
        )
    except LocalTextError:
        raise
    except OSError:
        _raise(LocalTextErrorCode.FILE_CHANGED)
    except Exception:
        _raise(LocalTextErrorCode.FILE_UNAVAILABLE)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if target_handle is not None:
            _close_handle(target_handle)
        for handle in reversed(directory_handles):
            _close_handle(handle)


def verify_local_text_span(
    source: LocalTextRead,
    *,
    start_byte: int,
    end_byte: int,
    expected_text: str | None = None,
) -> LocalTextCitation:
    """Create one verified, source-bound half-open UTF-8 byte citation."""

    if (
        type(source) is not LocalTextRead
        or type(start_byte) is not int
        or type(end_byte) is not int
        or (expected_text is not None and type(expected_text) is not str)
    ):
        _raise(LocalTextErrorCode.INVALID_CITATION)
    normalized = source.normalized_source
    if type(normalized) is not NormalizedPlainTextSource:
        _raise(LocalTextErrorCode.INVALID_SOURCE)
    try:
        envelope = normalized.envelope
        if (
            type(source.source_id) is not UUID
            or type(source.content_sha256) is not str
            or type(source.byte_length) is not int
            or type(source.source_format) is not LocalTextFormat
            or type(source.file_metadata) is not LocalFileMetadata
            or type(source.file_metadata.byte_length) is not int
            or source.file_metadata.byte_length != source.byte_length
            or source.file_metadata.source_format is not source.source_format
            or type(source.file_metadata.modified_at_utc) is not datetime
            or source.file_metadata.modified_at_utc.tzinfo is None
            or source.file_metadata.modified_at_utc.utcoffset() is None
            or type(source._relative_identity) is not str
            or not source._relative_identity
            or "\\" in source._relative_identity
            or ":" in source._relative_identity
            or source._relative_identity.startswith("/")
            or any(part in {"", ".", ".."} for part in source._relative_identity.split("/"))
            or source.source_format.value
            != ("." + source._relative_identity.rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower())
        ):
            _raise(LocalTextErrorCode.INVALID_SOURCE)
        if (
            envelope.source_id != source.source_id
            or envelope.content_sha256 != source.content_sha256
            or envelope.provider_id != "local.file"
            or envelope.trust is not TrustLabel.T4_EXTERNAL
            or envelope.sensitivity is not SensitivityLabel.PRIVATE
            or source.provider_id != "local.file"
            or source.trust is not TrustLabel.T4_EXTERNAL
            or source.sensitivity is not SensitivityLabel.PRIVATE
            or source.byte_length != len(normalized.original_bytes)
            or normalized.declared_mime_type != "text/plain; charset=utf-8"
            or normalized.mime_type != "text/plain; charset=utf-8"
            or normalized.charset != "utf-8"
            or normalized.citations
            or hashlib.sha256(normalized.original_bytes).hexdigest() != source.content_sha256
            or source.source_id
            != uuid5(
                NAMESPACE_URL,
                f"sentinel:local-text:v1:{source._relative_identity}:{source.content_sha256}",
            )
        ):
            _raise(LocalTextErrorCode.INVALID_SOURCE)
        span_id = uuid5(
            NAMESPACE_URL,
            f"sentinel:local-text:span:v1:{source.source_id}:{start_byte}:{end_byte}",
        )
        cited_source = add_citation(
            normalized,
            span_id=span_id,
            start_byte=start_byte,
            end_byte=end_byte,
            expected_text=expected_text,
        )
        span = cited_source.citations[-1]
        bound = bind_citation(cited_source, span)
        cited_text = verify_bound_citation(
            cited_source,
            bound,
            original_bytes=normalized.original_bytes,
            expected_text=expected_text,
        )
        return LocalTextCitation(bound_citation=bound, cited_text=cited_text)
    except LocalTextError:
        raise
    except NormalizationError:
        _raise(LocalTextErrorCode.INVALID_CITATION)
    except Exception:
        _raise(LocalTextErrorCode.INVALID_SOURCE)


__all__ = ["read_allowlisted_local_text", "verify_local_text_span"]
