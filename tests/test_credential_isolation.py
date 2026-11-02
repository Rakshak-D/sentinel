import socket
import subprocess
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from sentinel.config import load_bundled_defaults
from sentinel.contracts import BoundaryEnvelope
from sentinel.credentials.broker import CredentialBroker, CredentialBrokerError
from sentinel.credentials.types import (
    SecretRef,
    SecretReferenceValidationError,
)
from sentinel.gateways.types import ModelRequest, ToolRequest
from sentinel.observability.events import (
    DiagnosticEvent,
    DiagnosticEventCode,
    DiagnosticOutcome,
    DiagnosticSeverity,
    DiagnosticValidationError,
)


def make_reference(**overrides: object) -> SecretRef:
    fields: dict[str, object] = {
        "secret_ref_id": "secret.synthetic.primary",
        "provider": "gmail",
        "keychain_locator": "sentinel:gmail/primary",
        "scope_manifest_sha256": "a" * 64,
        "os_owner_binding": "windows-owner:synthetic",
        "created_at": datetime(2026, 11, 2, 12, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        "revoked_at": None,
    }
    fields.update(overrides)
    return SecretRef(**fields)  # type: ignore[arg-type]


def test_secret_canary_is_absent_from_reference_json_failures_and_public_results() -> None:
    canary = "SYNTHETIC_ACCESS_TOKEN_CANARY"
    reference = make_reference()
    broker = CredentialBroker()

    assert canary not in reference.model_dump_json()
    with pytest.raises(SecretReferenceValidationError):
        SecretRef.model_validate({**reference.model_dump(), "access_token": canary})
    with pytest.raises(CredentialBrokerError) as caught:
        broker.resolve_for_test(reference)
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)


def test_diagnostic_event_rejects_credential_fields_without_emitting_them() -> None:
    canary = "SYNTHETIC_BEARER_CANARY"

    with pytest.raises(DiagnosticValidationError) as caught:
        DiagnosticEvent(
            event_code=DiagnosticEventCode.DIAGNOSTIC_FAILURE,
            severity=DiagnosticSeverity.ERROR,
            outcome=DiagnosticOutcome.FAILURE,
            access_token=canary,
        )
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)


@pytest.mark.parametrize("contract", [ModelRequest, ToolRequest, BoundaryEnvelope])
def test_existing_boundary_contracts_do_not_expose_credential_fields(contract: type) -> None:
    credential_fields = {
        "access_token",
        "refresh_token",
        "password",
        "secret_value",
        "keychain_locator",
        "secret_ref_id",
        "authorization",
        "cookie",
    }
    assert not credential_fields.intersection(contract.model_fields)


def test_no_environment_or_plaintext_file_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    canary = "SYNTHETIC_ENV_CREDENTIAL_CANARY"
    monkeypatch.setenv("SENTINEL_GMAIL_ACCESS_TOKEN", canary)
    monkeypatch.setenv("GOOGLE_ACCESS_TOKEN", canary)
    monkeypatch.setenv("OPENAI_API_KEY", canary)
    monkeypatch.chdir(tmp_path)

    status = CredentialBroker().status(make_reference())

    assert status.backend.value == "UNAVAILABLE"
    assert list(tmp_path.iterdir()) == []


def test_synthetic_credentials_never_appear_in_stdout_or_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    reference = make_reference()
    canary = b"SYNTHETIC_STDOUT_STDERR_CANARY"
    broker = CredentialBroker.for_tests()
    broker.put_for_test(reference, canary)
    access = broker.resolve_for_test(reference)
    failure = CredentialBroker()
    with pytest.raises(CredentialBrokerError):
        failure.resolve_for_test(reference)

    captured = capsys.readouterr()
    assert canary.decode("ascii") not in captured.out
    assert canary.decode("ascii") not in captured.err
    assert canary.decode("ascii") not in repr(access)


def test_credential_types_are_not_added_to_configuration_or_boundary_json() -> None:
    config = load_bundled_defaults()
    reference = make_reference()
    envelope = BoundaryEnvelope(
        boundary_id=uuid4(),
        run_id=uuid4(),
        seq=1,
        kind="tool",
        adapter_id="synthetic.reader",
        request_ref="sha256:" + "a" * 64,
        response_ref=None,
        request_sha256="a" * 64,
        response_sha256=None,
        sensitivity="PUBLIC",
        source_ids=(),
        replay_injected=False,
        error_code=None,
        created_at=datetime(2026, 11, 2, tzinfo=UTC),
    )
    assert "credentials" not in type(config).model_fields
    assert not {"access_token", "refresh_token", "password"}.intersection(
        type(config).model_fields
    )

    serialized_models = (
        config.model_dump_json(),
        envelope.model_dump_json(),
        reference.model_dump_json(),
    )
    for serialized in serialized_models:
        assert "access_token" not in serialized
        assert "secret_value" not in serialized


def test_synthetic_backend_does_not_use_network_or_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unexpected external operation")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    reference = make_reference()
    broker = CredentialBroker.for_tests()
    broker.put_for_test(reference, b"synthetic")

    assert broker.status(reference).reference.value == "PRESENT"
    assert broker.resolve_for_test(reference).reveal_for_test() == b"synthetic"
