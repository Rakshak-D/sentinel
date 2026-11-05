from __future__ import annotations

import pytest

from sentinel.readers import source_status
from sentinel.readers.source_status import build_source_status_report, is_source_status_healthy
from sentinel.readers.source_status_types import (
    SourceCapabilityId,
    SourceReadinessCode,
)


@pytest.mark.parametrize(
    ("module", "reader_name", "capability_id"),
    (
        ("gmail_fixture", "read_packaged_gmail_fixture", SourceCapabilityId.GMAIL_FIXTURE),
        ("github_fixture", "read_packaged_github_fixture", SourceCapabilityId.GITHUB_FIXTURE),
        ("calendar_fixture", "read_packaged_calendar_fixture", SourceCapabilityId.CALENDAR_FIXTURE),
    ),
)
def test_any_broken_fixture_is_invalid_in_the_complete_inventory(
    monkeypatch, module, reader_name, capability_id
) -> None:
    fixture_module = getattr(source_status, module)

    def broken_reader():
        raise FileNotFoundError(r"C:\sensitive\source.json")

    monkeypatch.setattr(fixture_module, reader_name, broken_reader)
    report = build_source_status_report()
    capabilities = {item.capability_id: item for item in report.capabilities}
    assert capabilities[capability_id].readiness is SourceReadinessCode.FIXTURE_INVALID
    assert len(report.capabilities) == 14
    assert is_source_status_healthy(report) is False


def test_each_fixed_packaged_reader_is_actually_invoked(monkeypatch) -> None:
    calls = {"gmail": 0, "github": 0, "calendar": 0}
    readers = (
        ("gmail", source_status.gmail_fixture, "read_packaged_gmail_fixture"),
        ("github", source_status.github_fixture, "read_packaged_github_fixture"),
        ("calendar", source_status.calendar_fixture, "read_packaged_calendar_fixture"),
    )
    originals = {name: getattr(module, attribute) for name, module, attribute in readers}
    for name, module, attribute in readers:
        original = originals[name]

        def counted(original=original, name=name):
            calls[name] += 1
            return original()

        monkeypatch.setattr(module, attribute, counted)

    report = build_source_status_report()
    assert calls == {"gmail": 1, "github": 1, "calendar": 1}
    assert all(
        item.readiness is SourceReadinessCode.FIXTURE_READY for item in report.capabilities[:3]
    )


def test_broken_packaged_fixture_is_not_reported_ready(monkeypatch) -> None:
    def broken_reader():
        raise RuntimeError("private body and absolute path must not escape")

    monkeypatch.setattr(
        source_status.calendar_fixture, "read_packaged_calendar_fixture", broken_reader
    )
    report = build_source_status_report()
    capabilities = {item.capability_id: item for item in report.capabilities}
    assert capabilities[SourceCapabilityId.CALENDAR_FIXTURE].readiness is (
        SourceReadinessCode.FIXTURE_INVALID
    )
    assert is_source_status_healthy(report) is False
