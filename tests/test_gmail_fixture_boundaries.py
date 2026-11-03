"""Fail-closed schema, privacy, and no-effects tests for the Gmail fixture."""

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
    GMAIL_FIXTURE_OBSERVED_AT,
    GmailFixtureError,
    GmailFixtureErrorCode,
    read_packaged_gmail_fixture,
)
from sentinel.readers import gmail_fixture as reader_impl


def _document():
    return json.loads(reader_impl._read_gmail_fixture_resource())


def _raw(document):
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _parse(document):
    return reader_impl._parse_fixture_bytes(_raw(document))


def test_missing_or_tampered_packaged_resource_fails_with_fixed_category(monkeypatch) -> None:
    original = _raw(_document())

    def missing():
        raise FileNotFoundError("SYNTHETIC_PATH_CANARY")

    monkeypatch.setattr(reader_impl, "_read_gmail_fixture_resource", missing)
    with pytest.raises(GmailFixtureError) as error:
        read_packaged_gmail_fixture()
    assert error.value.code is GmailFixtureErrorCode.FIXTURE_UNAVAILABLE
    assert "SYNTHETIC_PATH_CANARY" not in str(error.value)

    monkeypatch.setattr(reader_impl, "_read_gmail_fixture_resource", lambda: original + b" ")
    with pytest.raises(GmailFixtureError) as error:
        read_packaged_gmail_fixture()
    assert error.value.code is GmailFixtureErrorCode.FIXTURE_HASH_MISMATCH


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update(fixture_version="sentinel.gmail-messages-fixture.v999"),
        lambda doc: doc.update(unexpected="SYNTHETIC_BODY_CANARY"),
        lambda doc: doc["messages"][0].update(extra="SYNTHETIC_BODY_CANARY"),
        lambda doc: doc["messages"][0]["message"].update(labelIds=["T1_OWNER_INTENT"]),
        lambda doc: doc["messages"][0]["message"].update(id=""),
        lambda doc: doc["messages"][0]["message"].update(id="not a valid id"),
        lambda doc: doc["messages"][0]["message"].update(internalDate="not-a-date"),
        lambda doc: doc["messages"][0]["message"].update(internalDate="-1"),
        lambda doc: doc["messages"][0]["message"].update(internalDate=1793527200000),
        lambda doc: doc["messages"][0]["message"]["payload"].update(mimeType="text/html"),
        lambda doc: doc["messages"][0]["message"]["payload"].update(filename="attachment.txt"),
        lambda doc: doc["messages"][0]["message"]["payload"].update(parts=[]),
        lambda doc: doc["messages"][0]["message"]["payload"].update(parts=[{}]),
        lambda doc: doc["messages"][0]["message"]["payload"]["headers"][1].update(
            value="text/html"
        ),
        lambda doc: doc["messages"][0]["message"]["payload"]["headers"][1].update(
            value="text/plain; charset=iso-8859-1"
        ),
        lambda doc: doc["messages"][0]["message"]["payload"]["body"].update(
            attachmentId="synthetic-attachment"
        ),
        lambda doc: doc["messages"][0]["message"]["payload"]["headers"].append(
            {"name": "Content-Type", "value": "text/html; charset=utf-8"}
        ),
    ],
)
def test_unsupported_or_unknown_fixture_shapes_fail_closed(mutate) -> None:
    document = _document()
    mutate(document)
    with pytest.raises(GmailFixtureError):
        _parse(document)


def test_duplicate_keys_invalid_utf8_and_nonstandard_json_constants_fail() -> None:
    with pytest.raises(GmailFixtureError):
        reader_impl._parse_fixture_bytes(b"\xff")
    with pytest.raises(GmailFixtureError):
        reader_impl._parse_fixture_bytes(
            b'{"fixture_version":"sentinel.gmail-messages-fixture.v1",'
            b'"fixture_version":"sentinel.gmail-messages-fixture.v1",'
            b'"mailbox_alias":"synthetic-inbox","messages":[]}'
        )
    with pytest.raises(GmailFixtureError):
        reader_impl._parse_fixture_bytes(
            b'{"fixture_version":"sentinel.gmail-messages-fixture.v1",'
            b'"mailbox_alias":"synthetic-inbox","messages":[],"value":NaN}'
        )


def test_duplicate_message_identity_and_bad_mailbox_alias_are_rejected() -> None:
    document = _document()
    document["messages"].append(json.loads(json.dumps(document["messages"][0])))
    with pytest.raises(GmailFixtureError):
        _parse(document)


def test_fixture_size_message_count_header_and_strict_numeric_bounds_are_enforced() -> None:
    with pytest.raises(GmailFixtureError):
        reader_impl._parse_fixture_bytes(b" " * (reader_impl.MAX_GMAIL_FIXTURE_BYTES + 1))

    document = _document()
    document["messages"] = [document["messages"][0]] * (reader_impl.MAX_GMAIL_MESSAGES + 1)
    with pytest.raises(GmailFixtureError):
        _parse(document)

    document = _document()
    document["messages"][0]["message"]["payload"]["headers"][0]["value"] = (
        "S" * (reader_impl.MAX_GMAIL_SUBJECT_BYTES + 1)
    )
    with pytest.raises(GmailFixtureError):
        _parse(document)

    document = _document()
    document["messages"][0]["message"]["payload"]["body"]["size"] = True
    with pytest.raises(GmailFixtureError):
        _parse(document)


@pytest.mark.parametrize(
    "change",
    [
        lambda spans: spans[0].update(start_byte=-1),
        lambda spans: spans[0].update(end_byte=999999),
        lambda spans: spans[0].update(expected_text="wrong cited text"),
        lambda spans: spans[1].update(span_id=spans[0]["span_id"]),
    ],
)
def test_invalid_or_duplicate_citation_annotations_reject_the_entire_fixture(change) -> None:
    document = _document()
    spans = document["messages"][0]["evidence_spans"]
    change(spans)
    with pytest.raises(GmailFixtureError):
        _parse(document)


def test_utf8_codepoint_splitting_in_citation_is_rejected() -> None:
    document = _document()
    emoji = document["messages"][1]["evidence_spans"][1]
    emoji["start_byte"] += 1
    with pytest.raises(GmailFixtureError):
        _parse(document)

    document = _document()
    document["mailbox_alias"] = "real@example.com"
    with pytest.raises(GmailFixtureError):
        _parse(document)


def test_naive_observation_timestamp_and_hostile_input_fail_without_stringification() -> None:
    document = _document()
    with pytest.raises(GmailFixtureError) as error:
        reader_impl._parse_fixture_bytes(
            _raw(document), observed_at=GMAIL_FIXTURE_OBSERVED_AT.replace(tzinfo=None)
        )
    assert error.value.code is GmailFixtureErrorCode.INVALID_OBSERVED_AT

    class Hostile:
        calls = 0

        def __str__(self):
            self.calls += 1
            raise AssertionError("unexpected conversion")

        def __repr__(self):
            self.calls += 1
            raise AssertionError("unexpected repr")

    hostile = Hostile()
    with pytest.raises(GmailFixtureError):
        reader_impl._parse_fixture_bytes(hostile)  # type: ignore[arg-type]
    assert hostile.calls == 0


def test_prompt_injection_does_not_change_labels_or_reader_capabilities() -> None:
    result = read_packaged_gmail_fixture()
    message = result.messages[2]

    assert "ignore previous instructions" in message.body_text
    assert message.normalized_source.envelope.trust.value == "T4 EXTERNAL"
    assert message.normalized_source.envelope.sensitivity.value == "PRIVATE"


def test_private_subject_and_body_canaries_never_enter_errors_or_logs(caplog) -> None:
    document = _document()
    document["messages"][0]["message"]["payload"]["headers"][0]["value"] = (
        "SYNTHETIC_PRIVATE_SUBJECT_CANARY"
    )
    body = document["messages"][0]["message"]["payload"]["body"]
    body["size"] += 1
    with pytest.raises(GmailFixtureError) as error:
        _parse(document)

    assert "SYNTHETIC_PRIVATE_SUBJECT_CANARY" not in str(error.value)
    assert "SYNTHETIC_PRIVATE_BODY_CANARY" not in str(error.value)
    assert caplog.records == []
    assert caplog.text == ""


def test_reader_has_no_network_database_subprocess_credential_or_gateway_effects(
    monkeypatch, tmp_path
) -> None:
    calls: list[str] = []

    def forbidden(name: str):
        def fail(*args, **kwargs):
            calls.append(name)
            raise AssertionError("unexpected operation")

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

    result = read_packaged_gmail_fixture()
    assert len(result.messages) == 3
    assert calls == []
    assert list(tmp_path.iterdir()) == []
