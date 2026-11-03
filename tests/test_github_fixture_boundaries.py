"""Strict schema, bounded errors and no-effects tests for the fixture reader."""

import json
import socket
import sqlite3
import subprocess
import urllib.request

import pytest

from sentinel.credentials.broker import CredentialBroker
from sentinel.gateways.model import ModelGateway
from sentinel.gateways.tool import ToolGateway
from sentinel.readers import (
    FIXTURE_OBSERVED_AT,
    GithubFixtureError,
    GithubFixtureErrorCode,
    read_packaged_github_fixture,
)
from sentinel.readers import github_fixture as reader_impl


def _valid_document() -> dict[str, object]:
    return {
        "fixture_version": reader_impl.FIXTURE_SCHEMA_VERSION,
        "issues": [
            {
                "repository": "example-owner/fixture-project",
                "issue_number": 101,
                "updated_at": "2026-11-02T10:30:00Z",
                "title": "Synthetic issue title",
                "body": "Synthetic issue body contains a note.",
                "evidence_spans": [
                    {
                        "span_id": "d767cdd2-90cb-45d6-9291-95d0c8aa0d09",
                        "start_byte": 16,
                        "end_byte": 26,
                        "expected_text": "body conta",
                    }
                ],
            }
        ],
    }


def _raw(document: dict[str, object] | None = None) -> bytes:
    return json.dumps(
        document if document is not None else _valid_document(),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _parse(raw_json: bytes):
    return reader_impl._parse_fixture_bytes(raw_json, observed_at=FIXTURE_OBSERVED_AT)


def _mutate_issue(mutator) -> bytes:
    document = _valid_document()
    issue = document["issues"][0]  # type: ignore[index]
    assert isinstance(issue, dict)
    mutator(issue)
    return _raw(document)


@pytest.mark.parametrize(
    "mutated",
    [
        lambda document: document.update(fixture_version="sentinel.github-issues-fixture.v999"),
        lambda document: document.update(unexpected="synthetic body canary"),
        lambda document: document["issues"][0].update(extra="synthetic body canary"),
        lambda document: document["issues"][0].update(repository="Bad/Repo"),
        lambda document: document["issues"][0].update(repository="https://example.invalid/repo"),
        lambda document: document["issues"][0].update(issue_number=True),
        lambda document: document["issues"][0].update(issue_number=0),
        lambda document: document["issues"][0].update(updated_at="2026-11-02T10:30:00"),
        lambda document: document["issues"][0].update(updated_at="not-a-time"),
        lambda document: document["issues"][0].update(trust="T1_OWNER_INTENT"),
        lambda document: document["issues"][0].update(api_token="synthetic credential canary"),
    ],
)
def test_unknown_version_fields_and_invalid_metadata_fail_closed(mutated) -> None:
    document = _valid_document()
    mutated(document)

    with pytest.raises(GithubFixtureError) as error:
        _parse(_raw(document))
    assert error.value.code is GithubFixtureErrorCode.INVALID_FIXTURE
    assert "synthetic body canary" not in str(error.value)


def test_invalid_utf8_duplicate_json_keys_and_nonstandard_nan_rejected() -> None:
    with pytest.raises(GithubFixtureError):
        _parse(b"\xff")
    with pytest.raises(GithubFixtureError):
        _parse(
            b'{"fixture_version":"sentinel.github-issues-fixture.v1",'
            b'"fixture_version":"sentinel.github-issues-fixture.v1","issues":[]}'
        )
    nonstandard = _raw().replace(b'"issue_number":101', b'"issue_number":NaN')
    with pytest.raises(GithubFixtureError):
        _parse(nonstandard)

    document = _valid_document()
    issue = document["issues"][0]  # type: ignore[index]
    assert isinstance(issue, dict)
    issue["body"] = "isolated surrogate: \ud800"
    escaped_surrogate = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode(
        "utf-8"
    )
    with pytest.raises(GithubFixtureError):
        _parse(escaped_surrogate)


def test_missing_required_fields_invalid_span_uuid_and_coercion_are_rejected() -> None:
    with pytest.raises(GithubFixtureError):
        _parse(_mutate_issue(lambda issue: issue.pop("title")))
    with pytest.raises(GithubFixtureError):
        _parse(_mutate_issue(lambda issue: issue.update(issue_number="101")))
    with pytest.raises(GithubFixtureError):
        _parse(
            _mutate_issue(
                lambda issue: issue["evidence_spans"][0].update(span_id="not-a-uuid")
            )
        )


def test_duplicate_issue_identity_and_duplicate_span_ids_rejected() -> None:
    document = _valid_document()
    duplicate = json.loads(json.dumps(document["issues"][0]))  # type: ignore[index]
    document["issues"].append(duplicate)  # type: ignore[union-attr]
    with pytest.raises(GithubFixtureError):
        _parse(_raw(document))

    document = _valid_document()
    issue = document["issues"][0]  # type: ignore[index]
    assert isinstance(issue, dict)
    duplicate_span = json.loads(json.dumps(issue["evidence_spans"][0]))
    issue["evidence_spans"].append(duplicate_span)
    with pytest.raises(GithubFixtureError):
        _parse(_raw(document))


def test_fixture_body_byte_limit_and_total_fixture_limit_are_enforced() -> None:
    with pytest.raises(GithubFixtureError) as fixture_size_error:
        _parse(b" " * (reader_impl.MAX_FIXTURE_BYTES + 1))
    assert fixture_size_error.value.code is GithubFixtureErrorCode.INVALID_FIXTURE

    raw_json = _mutate_issue(
        lambda issue: issue.update(body="x" * (reader_impl.MAX_BODY_BYTES + 1), evidence_spans=[])
    )
    with pytest.raises(GithubFixtureError):
        _parse(raw_json)


@pytest.mark.parametrize(
    "body,start,end,expected",
    [
        ("synthetic issue body", -1, 3, "syn"),
        ("synthetic issue body", 0, 100, "synthetic issue body"),
        ("é", 0, 1, ""),
        ("synthetic issue body", 0, 3, "wrong"),
    ],
)
def test_invalid_byte_ranges_codepoint_splits_and_expected_text_rejected(
    body: str, start: int, end: int, expected: str
) -> None:
    document = _valid_document()
    issue = document["issues"][0]  # type: ignore[index]
    assert isinstance(issue, dict)
    issue["body"] = body
    issue["evidence_spans"] = [
        {
            "span_id": "ca456074-86b6-42f6-9e3f-0831a268df68",
            "start_byte": start,
            "end_byte": end,
            "expected_text": expected,
        }
    ]
    with pytest.raises(GithubFixtureError) as error:
        _parse(_raw(document))
    assert error.value.code in {
        GithubFixtureErrorCode.INVALID_FIXTURE,
        GithubFixtureErrorCode.INVALID_CITATION,
    }


def test_malformed_fixture_body_canary_is_not_exposed_in_errors_or_logs(caplog) -> None:
    canary = "SYNTHETIC_CREDENTIAL_BODY_CANARY"

    def mutate(issue: dict[str, object]) -> None:
        issue["body"] = canary
        issue["evidence_spans"] = [
            {
                "span_id": "f8da783e-6b88-4d4a-ab76-5476ca196cbe",
                "start_byte": 0,
                "end_byte": len(canary),
                "expected_text": "wrong synthetic body",
            }
        ]

    raw_json = _mutate_issue(mutate)

    with pytest.raises(GithubFixtureError) as error:
        _parse(raw_json)
    assert canary not in str(error.value)
    assert canary not in repr(error.value)
    assert canary not in caplog.text
    assert caplog.records == []


def test_reader_performs_no_network_database_subprocess_credential_or_gateway_call(
    monkeypatch, tmp_path
) -> None:
    calls: list[str] = []

    def forbidden(name: str):
        def fail(*args, **kwargs):
            calls.append(name)
            raise AssertionError(f"unexpected {name} operation")

        return fail

    monkeypatch.setattr(socket, "create_connection", forbidden("network"))
    monkeypatch.setattr(socket, "socket", forbidden("socket"))
    monkeypatch.setattr(urllib.request, "urlopen", forbidden("urlopen"))
    monkeypatch.setattr(sqlite3, "connect", forbidden("sqlite"))
    monkeypatch.setattr(subprocess, "Popen", forbidden("subprocess"))
    monkeypatch.setattr(subprocess, "run", forbidden("subprocess.run"))
    monkeypatch.setattr(CredentialBroker, "resolve_for_test", forbidden("credential"))
    monkeypatch.setattr(CredentialBroker, "status", forbidden("credential status"))
    monkeypatch.setattr(ModelGateway, "generate", forbidden("model"))
    monkeypatch.setattr(ToolGateway, "call", forbidden("tool"))
    monkeypatch.chdir(tmp_path)

    result = read_packaged_github_fixture()

    assert len(result.issues) == 3
    assert calls == []
    assert list(tmp_path.iterdir()) == []
