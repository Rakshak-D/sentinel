"""Disposable Windows-only probes for the CR2-G-B2 Actions laboratory.

This helper has no production entry point. File, service, and pipe targets are
fixed to the synthetic B2 lab contract; it does not accept arbitrary paths,
commands, SQL, or authorization claims.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    _LAB_APP_ROOT = str(Path(__file__).resolve().parents[2])
    if _LAB_APP_ROOT not in sys.path:
        sys.path.insert(0, _LAB_APP_ROOT)

from tools.cr2_g_b1.protocol import MAX_FRAME_BYTES, encode_request
from tools.cr2_g_b1.service_host import SERVICE_NAME, SERVICE_ROOT, _service_sid
from tools.cr2_g_b1.store import CanaryStore
from tools.cr2_g_b1.windows_pipe import (
    _CLIENT_PIPE_ACCESS,
    _PIPE_AUDITOR_ACCESS,
    BrokerPipeError,
    request_pipe,
)
from tools.cr2_g_b1.windows_pipe import _require_windows as _require_windows_pipe

_ERROR_ACCESS_DENIED = 5
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_OPEN_EXISTING = 3
_CREATE_NEW = 1
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x00010000
_READ_CONTROL = 0x00020000
_DACL_SECURITY_INFORMATION = 0x00000004
_SE_FILE_OBJECT = 1
_SERVICE_CHANGE_CONFIG = 0x0002
_SERVICE_QUERY_CONFIG = 0x0001
_SERVICE_CONFIG_SERVICE_SID_INFO = 5
_SERVICE_SID_TYPE_RESTRICTED = 3
_SC_MANAGER_CONNECT = 0x0001
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_GROUPS = 2
_TOKEN_RESTRICTED_SIDS = 11
_TOKEN_ELEVATION = 20
_ERROR_INSUFFICIENT_BUFFER = 122
_FILE_READ_DATA = 0x0001
_FILE_WRITE_DATA = 0x0002
_FILE_CREATE_PIPE_INSTANCE = 0x0004
_FILE_READ_ATTRIBUTES = 0x0080
_SYNCHRONIZE = 0x00100000
_EXPECTED_CLIENT_MASK = (
    _FILE_READ_DATA | _FILE_WRITE_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
)
_EXPECTED_ADMIN_MASK = _EXPECTED_CLIENT_MASK | _READ_CONTROL
_PIPE_ACCESS_DUPLEX = 0x00000003
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_PIPE_TYPE_BYTE = 0
_PIPE_READMODE_BYTE = 0
_PIPE_WAIT = 0
_MOVEFILE_REPLACE_EXISTING = 0x00000001
_PIPE_NAME_PREFIX = r"\\.\pipe\SentinelCR2GB2-"
_PIPE_NAME_RE = re.compile(r"\\\\\.\\pipe\\SentinelCR2GB2-[A-Za-z0-9-]{1,64}\Z", re.ASCII)
_FULL_FILE_ACCESS = 0x001F01FF
_SERVICE_READ_EXECUTE = 0x001200A9
_CLIENT_ROOT_NAME = re.compile(r"SentinelCR2GB2-client-[0-9a-f]{32}\Z", re.ASCII)


class LabProbeError(RuntimeError):
    """Fixed-code error; messages never include caller data or OS text."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _require_exact_aces(
    entries: list[tuple[str, int]],
    expected: dict[str, int],
    *,
    reason: str,
) -> dict[str, int]:
    """Reject duplicate, unexpected, or altered access-allowed ACEs."""
    masks = dict(entries)
    if len(entries) != len(expected) or len(masks) != len(entries) or masks != expected:
        raise LabProbeError(reason)
    return masks


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class _ServiceSidInfo(ctypes.Structure):
    _fields_ = [("dwServiceSidType", wintypes.DWORD)]


class _QueryServiceConfig(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwStartType", wintypes.DWORD),
        ("dwErrorControl", wintypes.DWORD),
        ("lpBinaryPathName", wintypes.LPWSTR),
        ("lpLoadOrderGroup", wintypes.LPWSTR),
        ("dwTagId", wintypes.DWORD),
        ("lpDependencies", wintypes.LPWSTR),
        ("lpServiceStartName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
    ]


def _emit(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _require_windows() -> tuple[Any, Any]:
    if os.name != "nt":
        raise LabProbeError("WINDOWS_ONLY")
    return _require_windows_pipe()


def _token_information(advapi32: Any, token: wintypes.HANDLE, kind: int) -> ctypes.Array[Any]:
    needed = wintypes.DWORD()
    advapi32.GetTokenInformation(token, kind, None, 0, ctypes.byref(needed))
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or needed.value == 0:
        raise LabProbeError("TOKEN_QUERY_FAILED")
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetTokenInformation(
        token, kind, buffer, needed.value, ctypes.byref(needed)
    ):
        raise LabProbeError("TOKEN_QUERY_FAILED")
    return buffer


def _sid_string(advapi32: Any, kernel32: Any, sid: wintypes.LPVOID) -> str:
    value = wintypes.LPWSTR()
    try:
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
            raise LabProbeError("TOKEN_QUERY_FAILED")
        if not value.value or not value.value.startswith("S-1-"):
            raise LabProbeError("TOKEN_QUERY_FAILED")
        return value.value
    finally:
        if value:
            kernel32.LocalFree(ctypes.cast(value, wintypes.HLOCAL))


def _token_sids(advapi32: Any, kernel32: Any, token: wintypes.HANDLE, kind: int) -> set[str]:
    buffer = _token_information(advapi32, token, kind)
    count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    offset = (ctypes.sizeof(wintypes.DWORD) + ctypes.alignment(_SidAndAttributes) - 1) & ~(
        ctypes.alignment(_SidAndAttributes) - 1
    )
    entries = ctypes.cast(
        ctypes.addressof(buffer) + offset,
        ctypes.POINTER(_SidAndAttributes * count),
    ).contents
    return {_sid_string(advapi32, kernel32, item.Sid) for item in entries}


def _enabled_token_sids(
    advapi32: Any, kernel32: Any, token: wintypes.HANDLE
) -> set[str]:
    buffer = _token_information(advapi32, token, _TOKEN_GROUPS)
    count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    offset = (ctypes.sizeof(wintypes.DWORD) + ctypes.alignment(_SidAndAttributes) - 1) & ~(
        ctypes.alignment(_SidAndAttributes) - 1
    )
    entries = ctypes.cast(
        ctypes.addressof(buffer) + offset,
        ctypes.POINTER(_SidAndAttributes * count),
    ).contents
    return {
        _sid_string(advapi32, kernel32, item.Sid)
        for item in entries
        if item.Attributes & 0x00000004 and not item.Attributes & 0x00000010
    }


def _current_token_facts() -> dict[str, object]:
    kernel32, advapi32 = _require_windows()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
    kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.CheckTokenMembership.restype = wintypes.BOOL
    advapi32.CheckTokenMembership.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise LabProbeError("TOKEN_QUERY_FAILED")
    try:
        user = ctypes.cast(
            _token_information(advapi32, token, _TOKEN_USER),
            ctypes.POINTER(_TokenUser),
        ).contents
        user_sid = _sid_string(advapi32, kernel32, user.User.Sid)
        elevation = ctypes.cast(
            _token_information(advapi32, token, _TOKEN_ELEVATION),
            ctypes.POINTER(wintypes.DWORD),
        ).contents.value
        admin_sid = wintypes.LPVOID()
        if not advapi32.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(admin_sid)):
            raise LabProbeError("TOKEN_QUERY_FAILED")
        try:
            is_admin = wintypes.BOOL()
            if not advapi32.CheckTokenMembership(None, admin_sid, ctypes.byref(is_admin)):
                raise LabProbeError("TOKEN_QUERY_FAILED")
        finally:
            kernel32.LocalFree(ctypes.cast(admin_sid, wintypes.HLOCAL))
        session_id = wintypes.DWORD()
        if not kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id)):
            raise LabProbeError("TOKEN_QUERY_FAILED")
        return {
            "user_sid": user_sid,
            "elevated": elevation != 0,
            "administrator": bool(is_admin.value),
            "session_id": int(session_id.value),
        }
    finally:
        kernel32.CloseHandle(token)


def _process_token_facts(pid: int, expected_service_sid: str) -> dict[str, object]:
    kernel32, advapi32 = _require_windows()
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]

    process = kernel32.OpenProcess(0x1000, False, pid)
    if not process:
        raise LabProbeError("SERVICE_PROCESS_UNAVAILABLE")
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
            raise LabProbeError("SERVICE_TOKEN_UNAVAILABLE")
        try:
            user = ctypes.cast(
                _token_information(advapi32, token, _TOKEN_USER),
                ctypes.POINTER(_TokenUser),
            ).contents
            groups = _enabled_token_sids(advapi32, kernel32, token)
            restricted = _token_sids(advapi32, kernel32, token, _TOKEN_RESTRICTED_SIDS)
            elevation = ctypes.cast(
                _token_information(advapi32, token, _TOKEN_ELEVATION),
                ctypes.POINTER(wintypes.DWORD),
            ).contents.value
            return {
                "user_sid": _sid_string(advapi32, kernel32, user.User.Sid),
                "service_sid_enabled": expected_service_sid in groups,
                "service_sid_restricting": expected_service_sid in restricted,
                "administrator_group_present": "S-1-5-32-544" in groups,
                "elevated": elevation != 0,
            }
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(process)


def _read_live_pipe_aces(pipe_name: str) -> list[tuple[str, int]]:
    if not _PIPE_NAME_RE.fullmatch(pipe_name):
        raise LabProbeError("PIPE_NAME_INVALID")
    kernel32, advapi32 = _require_windows()
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]

    deadline = time.monotonic() + 10.0
    handle = wintypes.HANDLE()
    while time.monotonic() < deadline:
        kernel32.WaitNamedPipeW(pipe_name, 100)
        handle = kernel32.CreateFileW(
            pipe_name,
            _PIPE_AUDITOR_ACCESS,
            0,
            None,
            _OPEN_EXISTING,
            0,
            None,
        )
        if handle and ctypes.cast(handle, ctypes.c_void_p).value != _INVALID_HANDLE:
            break
        if kernel32.GetLastError() not in {2, 231, 121}:
            raise LabProbeError("PIPE_ACL_INSPECTION_OPEN_FAILED")
    else:
        raise LabProbeError("PIPE_ACL_INSPECTION_TIMEOUT")

    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    try:
        error = advapi32.GetSecurityInfo(
            handle,
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION,
            None,
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if error != 0:
            raise LabProbeError("PIPE_ACL_QUERY_FAILED")
        acl_size = ctypes.create_string_buffer(12)
        if not advapi32.GetAclInformation(dacl, acl_size, 12, 2):
            raise LabProbeError("PIPE_ACL_QUERY_FAILED")
        ace_count = ctypes.cast(acl_size, ctypes.POINTER(wintypes.DWORD)).contents.value
        entries: list[tuple[str, int]] = []
        for index in range(ace_count):
            ace = wintypes.LPVOID()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                raise LabProbeError("PIPE_ACL_QUERY_FAILED")
            header = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))
            if header[0] != 0:
                raise LabProbeError("PIPE_ACE_TYPE_UNSUPPORTED")
            words = ctypes.cast(ace, ctypes.POINTER(wintypes.DWORD))
            sid_pointer = ctypes.c_void_p(ctypes.cast(ace, ctypes.c_void_p).value + 8)
            sid_text = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_text)):
                raise LabProbeError("PIPE_ACL_QUERY_FAILED")
            try:
                if sid_text.value:
                    entries.append((sid_text.value, int(words[1])))
            finally:
                kernel32.LocalFree(ctypes.cast(sid_text, wintypes.HLOCAL))
        return entries
    finally:
        if descriptor:
            kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))
        kernel32.CloseHandle(handle)


def _read_file_acl(path: Path) -> tuple[str, list[tuple[str, int]]]:
    kernel32, advapi32 = _require_windows()
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    error = advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        0x00000001 | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if error != 0:
        raise LabProbeError("STORAGE_ACL_QUERY_FAILED")
    try:
        size_info = ctypes.create_string_buffer(12)
        if not advapi32.GetAclInformation(dacl, size_info, 12, 2):
            raise LabProbeError("STORAGE_ACL_QUERY_FAILED")
        count = ctypes.cast(size_info, ctypes.POINTER(wintypes.DWORD)).contents.value
        entries: list[tuple[str, int]] = []
        for index in range(count):
            ace = wintypes.LPVOID()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                raise LabProbeError("STORAGE_ACL_QUERY_FAILED")
            if ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))[0] != 0:
                raise LabProbeError("STORAGE_ACE_TYPE_UNSUPPORTED")
            words = ctypes.cast(ace, ctypes.POINTER(wintypes.DWORD))
            sid_pointer = ctypes.c_void_p(ctypes.cast(ace, ctypes.c_void_p).value + 8)
            sid_text = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_text)):
                raise LabProbeError("STORAGE_ACL_QUERY_FAILED")
            try:
                if sid_text.value:
                    entries.append((sid_text.value, int(words[1])))
            finally:
                kernel32.LocalFree(ctypes.cast(sid_text, wintypes.HLOCAL))
        owner_text = _sid_string(advapi32, kernel32, owner)
        return owner_text, entries
    finally:
        if descriptor:
            kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))


def _verify_storage_acls(service_sid: str, client_sid: str) -> None:
    targets = {
        "root": SERVICE_ROOT,
        "application": SERVICE_ROOT / "app",
        "python_runtime": SERVICE_ROOT / "app" / "python" / "python.exe",
        "service_module": SERVICE_ROOT / "app" / "tools" / "cr2_g_b1" / "service_host.py",
        "configuration": SERVICE_ROOT / "config" / "service.json",
        "canary_directory": SERVICE_ROOT / "data",
        "canary_database": SERVICE_ROOT / "data" / "canary.sqlite",
    }
    summaries: dict[str, dict[str, object]] = {}
    for label, path in targets.items():
        owner_sid, entries = _read_file_acl(path)
        masks = _require_exact_aces(
            entries,
            {
                service_sid: _SERVICE_READ_EXECUTE,
                "S-1-5-18": _FULL_FILE_ACCESS,
                "S-1-5-32-544": _FULL_FILE_ACCESS,
            },
            reason="STORAGE_ACL_MISMATCH",
        )
        if (
            owner_sid != "S-1-5-18"
            or client_sid in masks
        ):
            raise LabProbeError("STORAGE_ACL_MISMATCH")
        summaries[label] = {
            "owner_sid": owner_sid,
            "service_sid_mask": masks[service_sid],
            "system_mask": masks["S-1-5-18"],
            "administrator_mask": masks["S-1-5-32-544"],
        }
    _emit({"storage_acl_summary": summaries})


def _verify_client_acls(root: Path) -> None:
    public_root = Path(os.environ.get("PUBLIC", r"C:\Users\Public")).resolve(strict=True)
    if (
        not root.is_absolute()
        or root.parent.resolve(strict=True) != public_root
        or not _CLIENT_ROOT_NAME.fullmatch(root.name)
        or root.is_symlink()
    ):
        raise LabProbeError("PUBLIC_CLIENT_ROOT_INVALID")
    expected = {
        "S-1-5-18": _FULL_FILE_ACCESS,
        "S-1-5-32-544": _FULL_FILE_ACCESS,
        "S-1-5-32-545": _SERVICE_READ_EXECUTE,
    }
    targets = (
        root,
        root / "python" / "python.exe",
        root / "tools" / "cr2_g_b1" / "windows_service_lab.py",
    )
    for target in targets:
        if not target.exists() or target.is_symlink():
            raise LabProbeError("PUBLIC_CLIENT_TARGET_INVALID")
        owner, entries = _read_file_acl(target)
        if owner != "S-1-5-18":
            raise LabProbeError("PUBLIC_CLIENT_OWNER_MISMATCH")
        _require_exact_aces(entries, expected, reason="PUBLIC_CLIENT_ACL_MISMATCH")
    _emit({"public_client_acl": "READ_EXECUTE_ONLY", "targets_checked": len(targets)})


def _expect_access_denied(path: Path, desired: int, *, label: str, directory: bool = False) -> None:
    kernel32, _ = _require_windows()
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    attributes = _FILE_FLAG_BACKUP_SEMANTICS if directory else 0
    handle = kernel32.CreateFileW(
        str(path), desired, 0x00000007, None, _OPEN_EXISTING, attributes, None
    )
    if handle and ctypes.cast(handle, ctypes.c_void_p).value != _INVALID_HANDLE:
        kernel32.CloseHandle(handle)
        raise LabProbeError(f"UNEXPECTED_{label}_ACCESS")
    error = kernel32.GetLastError()
    if error != _ERROR_ACCESS_DENIED:
        raise LabProbeError(f"{label}_NOT_DENIED_BY_DACL")


def _expect_move_denied(source: Path, destination: Path, *, replace: bool) -> None:
    kernel32, _ = _require_windows()
    kernel32.MoveFileExW.restype = wintypes.BOOL
    kernel32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []
    flags = _MOVEFILE_REPLACE_EXISTING if replace else 0
    if kernel32.MoveFileExW(str(source), str(destination), flags):
        raise LabProbeError("UNEXPECTED_RENAME_ACCESS")
    if kernel32.GetLastError() != _ERROR_ACCESS_DENIED:
        raise LabProbeError("RENAME_NOT_DENIED_BY_DACL")


def _expect_delete_denied(path: Path) -> None:
    kernel32, _ = _require_windows()
    kernel32.DeleteFileW.restype = wintypes.BOOL
    kernel32.DeleteFileW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []
    if kernel32.DeleteFileW(str(path)):
        raise LabProbeError("UNEXPECTED_DELETE_ACCESS")
    if kernel32.GetLastError() != _ERROR_ACCESS_DENIED:
        raise LabProbeError("DELETE_NOT_DENIED_BY_DACL")


def _expect_acl_change_denied(path: Path) -> None:
    kernel32, advapi32 = _require_windows()
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    error = advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    try:
        if error == _ERROR_ACCESS_DENIED:
            return
        if error != 0:
            raise LabProbeError("ACL_QUERY_FAILED")
        # Attempt to set the exact existing DACL. Success is an ACL-write
        # permission failure even though the descriptor contents are unchanged.
        error = advapi32.SetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if error != _ERROR_ACCESS_DENIED:
            raise LabProbeError("ACL_CHANGE_NOT_DENIED")
    finally:
        if descriptor:
            kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))


def _probe_storage() -> None:
    facts = _current_token_facts()
    if facts["elevated"] or facts["administrator"]:
        raise LabProbeError("TEST_IDENTITY_IS_PRIVILEGED")
    root = SERVICE_ROOT
    file_paths = {
        "python_runtime": root / "app" / "python" / "python.exe",
        "service_module": root / "app" / "tools" / "cr2_g_b1" / "service_host.py",
        "service_config": root / "config" / "service.json",
        "canary_database": root / "data" / "canary.sqlite",
    }
    for label, path in file_paths.items():
        _expect_access_denied(path, _GENERIC_READ, label=f"{label}_READ")
        _expect_access_denied(path, _GENERIC_WRITE, label=f"{label}_WRITE")
        _expect_access_denied(path, _DELETE, label=f"{label}_DELETE")
        _expect_acl_change_denied(path)

    for label, directory in (
        ("root", root),
        ("app", root / "app"),
        ("config", root / "config"),
        ("data", root / "data"),
    ):
        _expect_access_denied(
            directory,
            _GENERIC_READ,
            label=f"{label}_DIRECTORY_READ",
            directory=True,
        )
        _expect_access_denied(
            directory,
            _GENERIC_WRITE,
            label=f"{label}_DIRECTORY_WRITE",
            directory=True,
        )
        _expect_access_denied(
            directory,
            _DELETE,
            label=f"{label}_DIRECTORY_DELETE",
            directory=True,
        )
        _expect_acl_change_denied(directory)

    scratch = Path(os.environ.get("TEMP", r"C:\Windows\Temp"))
    replacement = scratch / "sgb2-replacement-synthetic.bin"
    replacement.write_bytes(b"synthetic replacement probe")
    try:
        for path in file_paths.values():
            _expect_move_denied(
                path,
                path.with_name(path.name + ".renamed"),
                replace=False,
            )
            _expect_move_denied(replacement, path, replace=True)
        for label in ("app", "config", "data"):
            marker = root / label / "access-marker.bin"
            _expect_delete_denied(marker)
            _expect_move_denied(marker, marker.with_suffix(".renamed"), replace=False)
            _expect_move_denied(replacement, marker, replace=True)
    finally:
        replacement.unlink(missing_ok=True)

    kernel32, advapi32 = _require_windows()
    advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenServiceW.restype = wintypes.HANDLE
    advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []
    manager = advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not manager:
        raise LabProbeError("SCM_QUERY_FAILED")
    try:
        service = advapi32.OpenServiceW(manager, SERVICE_NAME, _SERVICE_CHANGE_CONFIG)
        if service:
            kernel32.CloseHandle(service)
            raise LabProbeError("SERVICE_CONFIG_CHANGE_ALLOWED")
        if kernel32.GetLastError() != _ERROR_ACCESS_DENIED:
            raise LabProbeError("SERVICE_CONFIG_CHANGE_NOT_DENIED")
    finally:
        kernel32.CloseHandle(manager)
    _emit(
        {
            "identity": facts,
            "storage_denials": "ACCESS_DENIED",
            "file_targets_checked": len(file_paths),
            "directory_targets_checked": 4,
            "service_config_change": "ACCESS_DENIED",
        }
    )


def _decode_response(frame: bytes) -> dict[str, object]:
    if len(frame) < 5 or struct.unpack(">I", frame[:4])[0] != len(frame) - 4:
        raise LabProbeError("RESPONSE_INVALID")
    value = json.loads(frame[4:].decode("utf-8", errors="strict"))
    if not isinstance(value, dict):
        raise LabProbeError("RESPONSE_INVALID")
    return value


def _request(
    pipe_name: str,
    command: str,
    *,
    request_id: str = "lab-request",
) -> dict[str, object]:
    if command not in {"health", "canary_status", "enroll", "approve", "unknown"}:
        raise LabProbeError("COMMAND_NOT_ALLOWED")
    frame = encode_request(request_id, command)
    return _decode_response(request_pipe(pipe_name, frame, timeout_ms=5000))


def _raw_frame_parts(payload: bytes | None, *, declared: int | None = None) -> list[bytes]:
    length = len(payload) if declared is None and payload is not None else declared
    if length is None or not 0 <= length <= 0xFFFFFFFF:
        raise LabProbeError("RAW_FRAME_INVALID")
    parts = [struct.pack(">I", length)]
    if payload is not None:
        parts.append(payload)
    return parts


def _parallel_health(pipe_name: str) -> None:
    if not _PIPE_NAME_RE.fullmatch(pipe_name):
        raise LabProbeError("PIPE_NAME_INVALID")
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(_request, pipe_name, "health", request_id=f"parallel-{index}")
            for index in range(4)
        ]
        responses = [future.result(timeout=8) for future in futures]
    if any(response.get("status") != "OK" for response in responses):
        raise LabProbeError("CONCURRENT_PIPE_REQUEST_FAILED")
    _emit({"parallel_health_requests": len(responses), "all_ok": True})


def _raw_disconnect(pipe_name: str, payload: bytes | None, *, declared: int | None = None) -> None:
    if not _PIPE_NAME_RE.fullmatch(pipe_name):
        raise LabProbeError("PIPE_NAME_INVALID")
    kernel32, _ = _require_windows()
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []
    kernel32.PeekNamedPipe.restype = wintypes.BOOL
    kernel32.PeekNamedPipe.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.Sleep.restype = None
    kernel32.Sleep.argtypes = [wintypes.DWORD]
    deadline = time.monotonic() + 5
    handle = wintypes.HANDLE()
    while time.monotonic() < deadline:
        kernel32.WaitNamedPipeW(pipe_name, 100)
        handle = kernel32.CreateFileW(
            pipe_name,
            _CLIENT_PIPE_ACCESS,
            0,
            None,
            _OPEN_EXISTING,
            0,
            None,
        )
        if handle and ctypes.cast(handle, ctypes.c_void_p).value != _INVALID_HANDLE:
            break
        if kernel32.GetLastError() not in {2, 231, 121}:
            raise LabProbeError("RAW_PIPE_CONNECT_FAILED")
    else:
        raise LabProbeError("RAW_PIPE_CONNECT_TIMEOUT")
    try:
        for part in _raw_frame_parts(payload, declared=declared):
            buffer = ctypes.create_string_buffer(part)
            written = wintypes.DWORD()
            if not kernel32.WriteFile(
                handle, buffer, len(part), ctypes.byref(written), None
            ) or written.value != len(part):
                raise LabProbeError("RAW_PIPE_WRITE_FAILED")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            available = wintypes.DWORD()
            if not kernel32.PeekNamedPipe(
                handle, None, 0, None, ctypes.byref(available), None
            ):
                if kernel32.GetLastError() in {109, 232, 233}:
                    break
                raise LabProbeError("INVALID_FRAME_PIPE_CHECK_FAILED")
            if available.value:
                raise LabProbeError("INVALID_FRAME_RECEIVED_RESPONSE")
            kernel32.Sleep(10)
        else:
            raise LabProbeError("INVALID_FRAME_NOT_CLOSED")
    finally:
        kernel32.CloseHandle(handle)


def _raw_tests(pipe_name: str) -> None:
    valid_prefix = (
        b'{"schema_version":"sentinel.cr2-g-b1-request.v1",'
        b'"request_id":"bad","command":"health","arguments":{}}'
    )
    cases = [
        ("oversized", None, MAX_FRAME_BYTES + 1),
        (
            "duplicate_key",
            b'{"schema_version":"sentinel.cr2-g-b1-request.v1",'
            b'"schema_version":"sentinel.cr2-g-b1-request.v1",'
            b'"request_id":"bad","command":"health","arguments":{}}',
            None,
        ),
        (
            "authority_flag",
            valid_prefix[:-1] + b',"owner_verified":true}',
            None,
        ),
    ]
    for _, payload, declared in cases:
        _raw_disconnect(pipe_name, payload, declared=declared)
    for command, reason in (("enroll", "COMMAND_DISABLED"), ("approve", "COMMAND_DISABLED")):
        response = _request(pipe_name, command)
        if response.get("status") != "DENIED" or response.get("reason_code") != reason:
            raise LabProbeError("DISABLED_COMMAND_ACCEPTED")
    unknown = _request(pipe_name, "unknown")
    if unknown.get("status") != "DENIED" or unknown.get("reason_code") != "UNKNOWN_COMMAND":
        raise LabProbeError("UNKNOWN_COMMAND_ACCEPTED")
    _emit({"invalid_frames": "DISCONNECTED", "authority_flag": "DISCONNECTED", "disabled": 2})


def _precreate(pipe_name: str, seconds: int) -> None:
    if not 1 <= seconds <= 30:
        raise LabProbeError("PRECREATE_TIMEOUT_INVALID")
    if not pipe_name.startswith(_PIPE_NAME_PREFIX):
        raise LabProbeError("PIPE_NAME_INVALID")
    kernel32, _ = _require_windows()
    kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.CreateNamedPipeW(
        pipe_name,
        _PIPE_ACCESS_DUPLEX | _FILE_FLAG_FIRST_PIPE_INSTANCE,
        _PIPE_TYPE_BYTE | _PIPE_READMODE_BYTE | _PIPE_WAIT,
        1,
        MAX_FRAME_BYTES + 4,
        MAX_FRAME_BYTES + 4,
        1000,
        None,
    )
    if not handle or ctypes.cast(handle, ctypes.c_void_p).value == _INVALID_HANDLE:
        raise LabProbeError("PIPE_PRECREATE_FAILED")
    try:
        _emit({"pipe_precreated": True})
        time.sleep(seconds)
    finally:
        kernel32.CloseHandle(handle)


def _partial_client(pipe_name: str, seconds: int) -> None:
    if not _PIPE_NAME_RE.fullmatch(pipe_name) or not 1 <= seconds <= 30:
        raise LabProbeError("PARTIAL_CLIENT_ARGUMENTS_INVALID")
    kernel32, _ = _require_windows()
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []
    deadline = time.monotonic() + 5
    handle = wintypes.HANDLE()
    while time.monotonic() < deadline:
        kernel32.WaitNamedPipeW(pipe_name, 100)
        handle = kernel32.CreateFileW(
            pipe_name,
            _CLIENT_PIPE_ACCESS,
            0,
            None,
            _OPEN_EXISTING,
            0,
            None,
        )
        if handle and ctypes.cast(handle, ctypes.c_void_p).value != _INVALID_HANDLE:
            break
        if kernel32.GetLastError() not in {2, 231, 121}:
            raise LabProbeError("PARTIAL_CLIENT_CONNECT_FAILED")
    else:
        raise LabProbeError("PARTIAL_CLIENT_CONNECT_TIMEOUT")
    try:
        one_byte = ctypes.create_string_buffer(b"\x00")
        written = wintypes.DWORD()
        if not kernel32.WriteFile(handle, one_byte, 1, ctypes.byref(written), None):
            raise LabProbeError("PARTIAL_CLIENT_WRITE_FAILED")
        if written.value != 1:
            raise LabProbeError("PARTIAL_CLIENT_WRITE_FAILED")
        _emit({"partial_request_open": True})
        time.sleep(seconds)
    finally:
        kernel32.CloseHandle(handle)


def _service_configuration() -> dict[str, object]:
    kernel32, advapi32 = _require_windows()
    advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenServiceW.restype = wintypes.HANDLE
    advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.QueryServiceConfig2W.restype = wintypes.BOOL
    advapi32.QueryServiceConfig2W.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.QueryServiceConfigW.restype = wintypes.BOOL
    advapi32.QueryServiceConfigW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []
    manager = advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not manager:
        raise LabProbeError("SCM_QUERY_FAILED")
    service = wintypes.HANDLE()
    try:
        service = advapi32.OpenServiceW(manager, SERVICE_NAME, _SERVICE_QUERY_CONFIG)
        if not service:
            raise LabProbeError("SERVICE_CONFIG_QUERY_FAILED")
        sid_info = _ServiceSidInfo()
        needed = wintypes.DWORD()
        if not advapi32.QueryServiceConfig2W(
            service,
            _SERVICE_CONFIG_SERVICE_SID_INFO,
            ctypes.byref(sid_info),
            ctypes.sizeof(sid_info),
            ctypes.byref(needed),
        ):
            raise LabProbeError("SERVICE_SID_TYPE_QUERY_FAILED")
        config_size = wintypes.DWORD()
        advapi32.QueryServiceConfigW(service, None, 0, ctypes.byref(config_size))
        if kernel32.GetLastError() != _ERROR_INSUFFICIENT_BUFFER or not config_size.value:
            raise LabProbeError("SERVICE_CONFIG_QUERY_FAILED")
        config_buffer = ctypes.create_string_buffer(config_size.value)
        if not advapi32.QueryServiceConfigW(
            service, config_buffer, config_size.value, ctypes.byref(config_size)
        ):
            raise LabProbeError("SERVICE_CONFIG_QUERY_FAILED")
        config = ctypes.cast(
            config_buffer, ctypes.POINTER(_QueryServiceConfig)
        ).contents
        start_name = config.lpServiceStartName
        result = {
            "service_sid_type": int(sid_info.dwServiceSidType),
            "service_account": start_name,
        }
        if (
            sid_info.dwServiceSidType != _SERVICE_SID_TYPE_RESTRICTED
            or start_name != r"NT AUTHORITY\LocalService"
        ):
            raise LabProbeError("SERVICE_CONFIGURATION_MISMATCH")
        return result
    finally:
        if service:
            kernel32.CloseHandle(service)
        kernel32.CloseHandle(manager)


def _service_sid_value() -> str:
    kernel32, advapi32 = _require_windows()
    return _service_sid(advapi32, kernel32)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=(
            "identity",
            "probe-storage",
            "request",
            "parallel-health",
            "denied-request",
            "raw-tests",
            "pipe-acl",
            "storage-acls",
            "service-token",
            "precreate",
            "init-store",
            "service-config",
            "service-sid",
            "partial-client",
            "client-acls",
        ),
    )
    parser.add_argument("--pipe")
    parser.add_argument("--command")
    parser.add_argument("--client-sid")
    parser.add_argument("--service-sid")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--seconds", type=int, default=10)
    args = parser.parse_args()
    try:
        if args.mode == "identity":
            _emit(_current_token_facts())
        elif args.mode == "probe-storage":
            _probe_storage()
        elif args.mode == "request":
            if args.pipe is None or args.command is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            _emit(_request(args.pipe, args.command))
        elif args.mode == "denied-request":
            if args.pipe is None or args.command is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            try:
                _request(args.pipe, args.command)
            except BrokerPipeError as exc:
                if exc.reason_code != "PIPE_ACCESS_DENIED":
                    raise
                _emit({"denial": exc.reason_code})
            else:
                raise LabProbeError("DISALLOWED_CLIENT_CONNECTED")
        elif args.mode == "parallel-health":
            if args.pipe is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            _parallel_health(args.pipe)
        elif args.mode == "raw-tests":
            if args.pipe is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            _raw_tests(args.pipe)
        elif args.mode == "pipe-acl":
            if args.pipe is None or args.service_sid is None or args.client_sid is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            entries = _read_live_pipe_aces(args.pipe)
            client_sid = args.client_sid
            required = {
                client_sid: _EXPECTED_CLIENT_MASK,
                "S-1-5-32-544": _EXPECTED_ADMIN_MASK,
                args.service_sid: 0x10000000,
                "S-1-5-18": 0x10000000,
            }
            masks = _require_exact_aces(entries, required, reason="PIPE_ACE_MISMATCH")
            if masks[client_sid] & _FILE_CREATE_PIPE_INSTANCE:
                raise LabProbeError("CLIENT_CAN_CREATE_PIPE_INSTANCE")
            _emit({"ace_masks": masks, "client_mask": masks[client_sid]})
        elif args.mode == "storage-acls":
            if args.service_sid is None or args.client_sid is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            _verify_storage_acls(args.service_sid, args.client_sid)
        elif args.mode == "client-acls":
            if args.root is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            _verify_client_acls(args.root)
        elif args.mode == "service-token":
            if args.pid is None or args.service_sid is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            facts = _process_token_facts(args.pid, args.service_sid)
            if (
                facts["user_sid"] != "S-1-5-19"
                or facts["service_sid_enabled"] is not True
                or facts["service_sid_restricting"] is not True
            ):
                raise LabProbeError("SERVICE_TOKEN_MISMATCH")
            _emit(facts)
        elif args.mode == "precreate":
            if args.pipe is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            _precreate(args.pipe, args.seconds)
        elif args.mode == "partial-client":
            if args.pipe is None:
                raise LabProbeError("REQUEST_ARGUMENTS_INVALID")
            _partial_client(args.pipe, args.seconds)
        elif args.mode == "init-store":
            (SERVICE_ROOT / "data").mkdir(parents=True, exist_ok=True)
            CanaryStore.initialize(SERVICE_ROOT / "data" / "canary.sqlite")
            _emit({"canary_store": "SYNTHETIC_ONLY"})
        elif args.mode == "service-config":
            _emit(_service_configuration())
        elif args.mode == "service-sid":
            _emit({"service_sid": _service_sid_value()})
        return 0
    except Exception as exc:
        reason = getattr(exc, "reason_code", getattr(exc, "reason", "LAB_PROBE_FAILED"))
        sys.stderr.write(str(reason)[:64] + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
