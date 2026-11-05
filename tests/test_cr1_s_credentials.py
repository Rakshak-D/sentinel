from __future__ import annotations

import socket

from sentinel.credentials import CredentialBroker
from sentinel.readers.source_status import build_source_status_report, is_source_status_healthy
from sentinel.readers.source_status_types import (
    CredentialBackendState,
    SourceCapabilityId,
)


def test_source_status_reports_backend_without_checking_references(monkeypatch) -> None:
    def forbidden_reference_check(self, reference):
        del self, reference
        raise AssertionError("source status must not probe credential references")

    monkeypatch.setattr(CredentialBroker, "status", forbidden_reference_check)
    report = build_source_status_report()
    capabilities = {item.capability_id: item for item in report.capabilities}
    assert (
        capabilities[SourceCapabilityId.PRODUCTION_CREDENTIAL_BACKEND].credential_backend_state
        is CredentialBackendState.UNAVAILABLE
    )
    assert all(
        item.credential_check_state.value in {"NOT_REQUIRED", "NOT_CHECKED"}
        for item in report.capabilities
    )
    assert all(item.account_check_state.value != "PRESENT" for item in report.capabilities)


def test_source_status_does_not_open_a_network_socket(monkeypatch) -> None:
    def forbidden_socket(*_args, **_kwargs):
        raise AssertionError("source status attempted a network operation")

    monkeypatch.setattr(socket, "create_connection", forbidden_socket)
    report = build_source_status_report()
    assert is_source_status_healthy(report) is True
