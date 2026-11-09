"""Genuine SCM dispatcher host for the CR2-G-B2 ephemeral lab only.

This module is copied under a protected guest-only directory and registered as
an own-process Windows service. It is deliberately not imported by Sentinel's
production package or wired into its authentication/effect paths.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    # SCM starts the service with its working directory outside the copied
    # laboratory package. Resolve only the fixed package parent of this trusted
    # service script; no IPC value controls imports or paths.
    _LAB_APP_ROOT = str(Path(__file__).resolve().parents[2])
    if _LAB_APP_ROOT not in sys.path:
        sys.path.insert(0, _LAB_APP_ROOT)

from tools.cr2_g_b1.store import CanaryStore, CanaryStoreError
from tools.cr2_g_b1.windows_pipe import BrokerPipeError, serve_one_request

SERVICE_NAME = "SentinelCR2GB2Lab"
SERVICE_CONFIG_SCHEMA = "sentinel.cr2-g-b2-service-config.v1"
SERVICE_ROOT = Path(r"C:\ProgramData\SentinelCR2GB2")
SERVICE_CONFIG_PATH = SERVICE_ROOT / "config" / "service.json"
SERVICE_DATABASE_PATH = SERVICE_ROOT / "data" / "canary.sqlite"
SERVICE_PIPE_TIMEOUT_MS = 1000
SERVICE_JOIN_TIMEOUT_SECONDS = 5
_MAX_CONFIG_BYTES = 4096
_PIPE_NAME = re.compile(r"\\\\\.\\pipe\\SentinelCR2GB2-[A-Za-z0-9-]{1,64}\Z", re.ASCII)
_SID = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\Z", re.ASCII)
_LOCAL_TEST_USER_SID = re.compile(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\Z", re.ASCII)

_SERVICE_WIN32_OWN_PROCESS = 0x00000010
_SERVICE_START_PENDING = 0x00000002
_SERVICE_STOP_PENDING = 0x00000003
_SERVICE_RUNNING = 0x00000004
_SERVICE_STOPPED = 0x00000001
_SERVICE_ACCEPT_STOP = 0x00000001
_SERVICE_ACCEPT_SHUTDOWN = 0x00000004
_SERVICE_CONTROL_STOP = 0x00000001
_SERVICE_CONTROL_INTERROGATE = 0x00000004
_SERVICE_CONTROL_SHUTDOWN = 0x00000005
_ERROR_CALL_NOT_IMPLEMENTED = 120
_ERROR_SERVICE_SPECIFIC_ERROR = 1066
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_GROUPS = 2
_TOKEN_RESTRICTED_SIDS = 11
_ERROR_INSUFFICIENT_BUFFER = 122

_BENIGN_REQUEST_ERRORS = frozenset(
    {
        "PIPE_TIMEOUT",
        "PIPE_EOF",
        "FRAME_SIZE",
        "CALLER_NOT_ALLOWED",
        "RESPONSE_ACK_INVALID",
        "DUPLICATE_JSON_KEY",
        "NONFINITE_JSON_NUMBER",
        "INVALID_UTF8",
        "NESTING_LIMIT",
        "INVALID_JSON",
        "REQUEST_FIELDS",
        "UNSUPPORTED_VERSION",
        "INVALID_REQUEST_ID",
        "INVALID_COMMAND",
        "ARGUMENTS_NOT_ALLOWED",
    }
)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ServiceLabError("SERVICE_CONFIG_INVALID")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise ServiceLabError("SERVICE_CONFIG_INVALID")


class ServiceLabError(ValueError):
    """Fixed-code lab configuration or state-machine error."""


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    """Fixed-scope configuration accepted by the isolated lab service."""

    pipe_name: str
    allowed_client_sid: str
    database_path: Path


class ServiceState(StrEnum):
    STOPPED = "STOPPED"
    START_PENDING = "START_PENDING"
    RUNNING = "RUNNING"
    STOP_PENDING = "STOP_PENDING"


def parse_service_config(payload: bytes, *, root: Path = SERVICE_ROOT) -> ServiceConfig:
    """Parse exact-schema JSON and pin every path to the lab-only root."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= _MAX_CONFIG_BYTES:
        raise ServiceLabError("SERVICE_CONFIG_INVALID")
    try:
        data = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        root_path = Path(root)
        if not root_path.is_absolute() or not isinstance(data, dict):
            raise ServiceLabError("SERVICE_CONFIG_INVALID")
        if set(data) != {
            "schema_version",
            "service_name",
            "pipe_name",
            "allowed_client_sid",
            "database_path",
        }:
            raise ServiceLabError("SERVICE_CONFIG_INVALID")
        if data["schema_version"] != SERVICE_CONFIG_SCHEMA:
            raise ServiceLabError("SERVICE_CONFIG_INVALID")
        if data["service_name"] != SERVICE_NAME:
            raise ServiceLabError("SERVICE_CONFIG_INVALID")
        pipe_name = data["pipe_name"]
        client_sid = data["allowed_client_sid"]
        database_path = data["database_path"]
        if not isinstance(pipe_name, str) or not _PIPE_NAME.fullmatch(pipe_name):
            raise ServiceLabError("SERVICE_CONFIG_INVALID")
        if not isinstance(client_sid, str) or not _LOCAL_TEST_USER_SID.fullmatch(client_sid):
            raise ServiceLabError("SERVICE_CONFIG_INVALID")
        expected_path = root_path / "data" / "canary.sqlite"
        if not isinstance(database_path, str) or database_path != str(expected_path):
            raise ServiceLabError("SERVICE_CONFIG_INVALID")
        return ServiceConfig(pipe_name, client_sid, expected_path)
    except ServiceLabError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        OSError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise ServiceLabError("SERVICE_CONFIG_INVALID") from exc


def next_service_state(state: ServiceState, event: str) -> ServiceState:
    """Apply one legal SCM lifecycle event."""
    transitions = {
        (ServiceState.STOPPED, "START"): ServiceState.START_PENDING,
        (ServiceState.START_PENDING, "READY"): ServiceState.RUNNING,
        (ServiceState.START_PENDING, "FAIL"): ServiceState.STOPPED,
        (ServiceState.RUNNING, "STOP"): ServiceState.STOP_PENDING,
        (ServiceState.RUNNING, "FAIL"): ServiceState.STOP_PENDING,
        (ServiceState.STOP_PENDING, "EXIT"): ServiceState.STOPPED,
    }
    try:
        return transitions[(state, event)]
    except (KeyError, TypeError) as exc:
        raise ServiceLabError("SERVICE_STATE_INVALID") from exc


class _ServiceStatus(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


_CALLBACK_FACTORY = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
_ServiceMainCallback = _CALLBACK_FACTORY(
    None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR)
)
_ServiceHandlerCallback = _CALLBACK_FACTORY(
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
)


class _ServiceTableEntry(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", _ServiceMainCallback)]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


_status_handle: wintypes.HANDLE | None = None
_stop_event = threading.Event()
_worker_failure = threading.Event()
_worker_ready = threading.Event()
_status_lock = threading.Lock()
_status_checkpoint = 0
_last_status: _ServiceStatus | None = None


def _win32() -> tuple[Any, Any]:
    if os.name != "nt":
        raise ServiceLabError("WINDOWS_ONLY")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
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
    advapi32.LookupAccountNameW.restype = wintypes.BOOL
    advapi32.LookupAccountNameW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    advapi32.RevertToSelf.restype = wintypes.BOOL
    advapi32.RevertToSelf.argtypes = []
    advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    advapi32.RegisterServiceCtrlHandlerExW.argtypes = [
        wintypes.LPCWSTR,
        _ServiceHandlerCallback,
        wintypes.LPVOID,
    ]
    advapi32.SetServiceStatus.restype = wintypes.BOOL
    advapi32.SetServiceStatus.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ServiceStatus),
    ]
    advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
    advapi32.StartServiceCtrlDispatcherW.argtypes = [
        ctypes.POINTER(_ServiceTableEntry)
    ]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel32, advapi32


def _token_sid_sets(advapi32: Any, kernel32: Any) -> tuple[str, set[str], set[str]]:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise ServiceLabError("SERVICE_TOKEN_INVALID")

    def information(token_class: int) -> ctypes.Array[ctypes.c_char]:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(token, token_class, None, 0, ctypes.byref(required))
        if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or required.value == 0:
            raise ServiceLabError("SERVICE_TOKEN_INVALID")
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token, token_class, buffer, required.value, ctypes.byref(required)
        ):
            raise ServiceLabError("SERVICE_TOKEN_INVALID")
        return buffer

    def sid_string(sid: wintypes.LPVOID) -> str:
        value = wintypes.LPWSTR()
        try:
            if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
                raise ServiceLabError("SERVICE_TOKEN_INVALID")
            if value.value is None or not _SID.fullmatch(value.value):
                raise ServiceLabError("SERVICE_TOKEN_INVALID")
            return value.value
        finally:
            if value:
                kernel32.LocalFree(ctypes.cast(value, wintypes.HLOCAL))

    def group_sids(token_class: int, *, require_enabled: bool) -> set[str]:
        buffer = information(token_class)
        count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
        offset = (ctypes.sizeof(wintypes.DWORD) + ctypes.alignment(_SidAndAttributes) - 1) & ~(
            ctypes.alignment(_SidAndAttributes) - 1
        )
        group_array = ctypes.cast(
            ctypes.addressof(buffer) + offset,
            ctypes.POINTER(_SidAndAttributes * count),
        ).contents
        result: set[str] = set()
        for group in group_array:
            if require_enabled and not group.Attributes & 0x00000004:
                continue
            if require_enabled and group.Attributes & 0x00000010:
                continue
            result.add(sid_string(group.Sid))
        return result

    try:
        user_buffer = information(_TOKEN_USER)
        user = ctypes.cast(user_buffer, ctypes.POINTER(_TokenUser)).contents
        user_sid = sid_string(user.User.Sid)
        return (
            user_sid,
            group_sids(_TOKEN_GROUPS, require_enabled=True),
            group_sids(_TOKEN_RESTRICTED_SIDS, require_enabled=False),
        )
    finally:
        kernel32.CloseHandle(token)


def _service_sid(advapi32: Any, kernel32: Any) -> str:
    sid_size = wintypes.DWORD()
    domain_size = wintypes.DWORD()
    use = wintypes.DWORD()
    account = rf"NT SERVICE\{SERVICE_NAME}"
    advapi32.LookupAccountNameW(
        None,
        account,
        None,
        ctypes.byref(sid_size),
        None,
        ctypes.byref(domain_size),
        ctypes.byref(use),
    )
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
        raise ServiceLabError("SERVICE_SID_UNAVAILABLE")
    sid_buffer = ctypes.create_string_buffer(sid_size.value)
    domain_buffer = ctypes.create_unicode_buffer(domain_size.value)
    if not advapi32.LookupAccountNameW(
        None,
        account,
        sid_buffer,
        ctypes.byref(sid_size),
        domain_buffer,
        ctypes.byref(domain_size),
        ctypes.byref(use),
    ):
        raise ServiceLabError("SERVICE_SID_UNAVAILABLE")
    sid_string = wintypes.LPWSTR()
    try:
        if not advapi32.ConvertSidToStringSidW(sid_buffer, ctypes.byref(sid_string)):
            raise ServiceLabError("SERVICE_SID_UNAVAILABLE")
        result = sid_string.value
        if result is None or not _SID.fullmatch(result):
            raise ServiceLabError("SERVICE_SID_UNAVAILABLE")
        return result
    finally:
        if sid_string:
            kernel32.LocalFree(ctypes.cast(sid_string, wintypes.HLOCAL))


def _publish_status(
    advapi32: Any,
    state: ServiceState,
    *,
    exit_code: int = 0,
    service_exit_code: int = 0,
) -> None:
    global _status_checkpoint, _last_status
    win_state = {
        ServiceState.STOPPED: _SERVICE_STOPPED,
        ServiceState.START_PENDING: _SERVICE_START_PENDING,
        ServiceState.RUNNING: _SERVICE_RUNNING,
        ServiceState.STOP_PENDING: _SERVICE_STOP_PENDING,
    }[state]
    with _status_lock:
        if state in {ServiceState.START_PENDING, ServiceState.STOP_PENDING}:
            _status_checkpoint += 1
        status = _ServiceStatus(
            _SERVICE_WIN32_OWN_PROCESS,
            win_state,
            (_SERVICE_ACCEPT_STOP | _SERVICE_ACCEPT_SHUTDOWN)
            if state is ServiceState.RUNNING
            else 0,
            exit_code,
            service_exit_code,
            _status_checkpoint,
            5000 if state in {ServiceState.START_PENDING, ServiceState.STOP_PENDING} else 0,
        )
        _last_status = status
        handle = _status_handle
        if handle and not advapi32.SetServiceStatus(handle, ctypes.byref(status)):
            raise ServiceLabError("SERVICE_STATUS_UPDATE_FAILED")


def _serve_loop(config: ServiceConfig, server_sid: str) -> None:
    try:
        store = CanaryStore.open_existing(config.database_path)
        _worker_ready.set()
        while not _stop_event.is_set():
            try:
                serve_one_request(
                    pipe_name=config.pipe_name,
                    allowed_client_sid=config.allowed_client_sid,
                    server_sid=server_sid,
                    store=store,
                    timeout_ms=SERVICE_PIPE_TIMEOUT_MS,
                )
            except BrokerPipeError as exc:
                if exc.reason_code in _BENIGN_REQUEST_ERRORS:
                    continue
                raise
    except BrokerPipeError as exc:
        if exc.reason_code in _BENIGN_REQUEST_ERRORS:
            return
        _worker_failure.set()
        _stop_event.set()
        _worker_ready.set()
    except CanaryStoreError:
        _worker_failure.set()
        _stop_event.set()
        _worker_ready.set()
    except Exception:
        _worker_failure.set()
        _stop_event.set()
        _worker_ready.set()


def _service_handler(
    control: int,
    _: int,
    __: wintypes.LPVOID,
    ___: wintypes.LPVOID,
) -> int:
    if control == _SERVICE_CONTROL_INTERROGATE:
        return 0
    if control in {_SERVICE_CONTROL_STOP, _SERVICE_CONTROL_SHUTDOWN}:
        try:
            _stop_event.set()
            return 0
        except Exception:
            return _ERROR_CALL_NOT_IMPLEMENTED
    return _ERROR_CALL_NOT_IMPLEMENTED


def _service_main(_: int, __: ctypes.POINTER(wintypes.LPWSTR)) -> None:
    global _status_handle
    kernel32, advapi32 = _win32()
    _stop_event.clear()
    _worker_failure.clear()
    _worker_ready.clear()
    try:
        _status_handle = advapi32.RegisterServiceCtrlHandlerExW(
            SERVICE_NAME,
            _handler_callback,
            None,
        )
        if not _status_handle:
            return
        _publish_status(advapi32, ServiceState.START_PENDING)
        config = parse_service_config(SERVICE_CONFIG_PATH.read_bytes())
        user_sid, groups, restricted_sids = _token_sid_sets(advapi32, kernel32)
        service_sid = _service_sid(advapi32, kernel32)
        if (
            user_sid != "S-1-5-19"
            or service_sid not in groups
            or service_sid not in restricted_sids
        ):
            raise ServiceLabError("SERVICE_TOKEN_INVALID")
        worker = threading.Thread(
            target=_serve_loop,
            args=(config, service_sid),
            name="cr2-g-b2-canary-pipe",
            daemon=True,
        )
        worker.start()
        if not _worker_ready.wait(SERVICE_JOIN_TIMEOUT_SECONDS) or _worker_failure.is_set():
            _stop_event.set()
            worker.join(SERVICE_JOIN_TIMEOUT_SECONDS)
            raise ServiceLabError("SERVICE_WORKER_START_FAILED")
        _publish_status(advapi32, ServiceState.RUNNING)
        while not _stop_event.wait(0.1):
            if _worker_failure.is_set():
                break
        _publish_status(advapi32, ServiceState.STOP_PENDING)
        worker.join(SERVICE_JOIN_TIMEOUT_SECONDS)
        failed = worker.is_alive() or _worker_failure.is_set()
        _publish_status(
            advapi32,
            ServiceState.STOPPED,
            exit_code=_ERROR_SERVICE_SPECIFIC_ERROR if failed else 0,
            service_exit_code=1 if failed else 0,
        )
    except Exception:
        _stop_event.set()
        try:
            _publish_status(
                advapi32,
                ServiceState.STOPPED,
                exit_code=_ERROR_SERVICE_SPECIFIC_ERROR,
                service_exit_code=2,
            )
        except Exception:
            return


_handler_callback = _ServiceHandlerCallback(_service_handler)
_service_main_callback = _ServiceMainCallback(_service_main)


def run_scm_service() -> int:
    """Connect this process to SCM; console-mode fallback is intentionally absent."""
    _, advapi32 = _win32()
    table = (_ServiceTableEntry * 2)()
    table[0] = _ServiceTableEntry(SERVICE_NAME, _service_main_callback)
    table[1] = _ServiceTableEntry(None, _ServiceMainCallback())
    if not advapi32.StartServiceCtrlDispatcherW(table):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run_scm_service())
