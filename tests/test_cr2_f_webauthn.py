from __future__ import annotations

import base64
import hashlib
import inspect
import json
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.proposals import save_github_fixture_proposal
from sentinel.storage.migrations import initialize_storage
from tests.test_cr1_i_support import promoted_case

_RP_ID = "sentinel.test"
_ORIGIN = "https://sentinel.test"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _register_test_credential(database: Path, private_key: Any) -> str:
    credential_bytes = b"cr2f-synthetic-credential-001"
    credential_id = _b64url(credential_bytes)
    public_numbers = private_key.public_key().public_numbers()
    cose_public_key = cbor2.dumps(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            """INSERT INTO owner_proof_credentials
               (credential_id, owner_association, cose_public_key, rp_id,
                expected_origin, sign_count, registration_state, revoked, created_at)
               VALUES (?, ?, ?, ?, ?, 0, 'SYNTHETIC_TEST_ONLY', 0, ?)""",
            (
                credential_id,
                "synthetic-test-owner",
                cose_public_key,
                _RP_ID,
                _ORIGIN,
                datetime.now(UTC).isoformat(timespec="microseconds"),
            ),
        )
    return credential_id


def _replace_immutable_challenge_value(
    database: Path,
    *,
    challenge_id: str,
    column: str,
    value: object,
) -> None:
    from sentinel.storage.schema import OWNER_PROOF_CHALLENGES_UPDATE_GUARD_DDL

    allowed_columns = {
        "proposal_snapshot_sha256",
        "source_set_sha256",
        "source_item_id",
        "source_envelope_id",
        "source_content_sha256",
        "citation_bindings_json",
        "citation_bindings_sha256",
        "policy_request_sha256",
        "policy_sha256",
        "registry_sha256",
        "config_sha256",
    }
    assert column in allowed_columns
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER owner_proof_challenges_update_guard")
        connection.execute(
            f"UPDATE owner_proof_challenges SET {column} = ? WHERE challenge_id = ?",
            (value, challenge_id),
        )
        connection.execute(OWNER_PROOF_CHALLENGES_UPDATE_GUARD_DDL)


def _replace_immutable_credential_value(
    database: Path,
    *,
    credential_id: str,
    column: str,
    value: object,
) -> None:
    from sentinel.storage.schema import OWNER_PROOF_CREDENTIALS_UPDATE_GUARD_DDL

    assert column in {"cose_public_key", "revoked"}
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER owner_proof_credentials_update_guard")
        connection.execute(
            f"UPDATE owner_proof_credentials SET {column} = ? WHERE credential_id = ?",
            (value, credential_id),
        )
        connection.execute(OWNER_PROOF_CREDENTIALS_UPDATE_GUARD_DDL)


def _signed_assertion(
    *,
    options_json: str,
    credential_id: str,
    credential_bytes: bytes,
    private_key: Any,
    sign_count: int = 1,
    flags: int = 0x05,
    authenticator_rp_id: str = _RP_ID,
    client_origin: str = _ORIGIN,
    client_data_json: bytes | None = None,
) -> bytes:
    options = json.loads(options_json)
    client_data = (
        client_data_json
        if client_data_json is not None
        else json.dumps(
            {
                "type": "webauthn.get",
                "challenge": options["challenge"],
                "origin": client_origin,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    authenticator_data = (
        hashlib.sha256(authenticator_rp_id.encode("utf-8")).digest()
        + bytes([flags])
        + sign_count.to_bytes(4, "big")
    )
    signature = private_key.sign(
        authenticator_data + hashlib.sha256(client_data).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    payload = {
        "id": credential_id,
        "rawId": _b64url(credential_bytes),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64url(client_data),
            "authenticatorData": _b64url(authenticator_data),
            "signature": _b64url(signature),
            "userHandle": None,
        },
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _setup_assertion_case(
    tmp_path: Path,
    *,
    name: str,
    issue: int = 101,
    private_key: Any | None = None,
):
    import sentinel.owner_proof as owner_proof

    database, store_root = promoted_case(tmp_path, name=name)
    saved = save_github_fixture_proposal(database, store_root=store_root, issue_number=issue)
    key = private_key or ec.generate_private_key(ec.SECP256R1())
    credential_id = _register_test_credential(database, key)
    issued = owner_proof.issue_synthetic_assertion_options(
        database,
        store_root=store_root,
        proposal_id=saved.proposal.proposal_id,
        credential_id=credential_id,
    )
    return database, store_root, saved.proposal, key, credential_id, issued


def _verify_in_fresh_process(
    database: Path,
    store_root: Path,
    challenge_id: str,
    assertion_json: bytes,
) -> subprocess.CompletedProcess[str]:
    script = """
import sys
from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion
try:
    report = verify_synthetic_assertion(
        sys.argv[1], store_root=sys.argv[2], challenge_id=sys.argv[3],
        assertion_json=bytes.fromhex(sys.argv[4]),
    )
    print(report.outcome)
except OwnerProofError as error:
    print(error.code.value)
    sys.exit(1)
"""
    return subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(database),
            str(store_root),
            challenge_id,
            assertion_json.hex(),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )


def _issue_in_fresh_process(
    database: Path,
    store_root: Path,
    proposal_id: str,
    credential_id: str,
) -> subprocess.CompletedProcess[str]:
    script = """
import json
import sys
from sentinel.owner_proof import issue_synthetic_assertion_options
result = issue_synthetic_assertion_options(
    sys.argv[1], store_root=sys.argv[2], proposal_id=sys.argv[3],
    credential_id=sys.argv[4],
)
print(json.dumps({"challenge_id": result.challenge_id, "options_json": result.options_json}))
"""
    return subprocess.run(
        [sys.executable, "-c", script, str(database), str(store_root), proposal_id, credential_id],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )


def test_auth_status_is_a_read_only_unavailable_report_for_existing_database(tmp_path) -> None:
    database = tmp_path / "auth-status.sqlite3"
    initialize_storage(database, create=True)

    result = CliRunner().invoke(
        app,
        ["auth", "status", "--database", str(database), "--format", "json"],
    )
    repeated = CliRunner().invoke(
        app,
        ["auth", "status", "--database", str(database), "--format", "json"],
    )

    assert result.exit_code == 0, result.stderr
    assert result.stderr == ""
    assert repeated.exit_code == 0
    assert repeated.stdout == result.stdout
    report = json.loads(result.stdout)
    assert report["schema_version"] == "sentinel.owner-proof-status.v1"
    assert report["production_owner_verification"] == "UNAVAILABLE"
    assert report["synthetic_test_credentials"] == 0
    assert report["executable"] is False


def test_genuine_signed_synthetic_assertion_is_verified_once(tmp_path, monkeypatch) -> None:
    import sentinel.owner_proof as owner_proof

    database, store_root = promoted_case(tmp_path, name="cr2-f-signed-assertion")
    saved = save_github_fixture_proposal(database, store_root=store_root, issue_number=101)
    before_proposal = saved.proposal
    private_key = ec.generate_private_key(ec.SECP256R1())
    credential_bytes = b"cr2f-synthetic-credential-001"
    credential_id = _register_test_credential(database, private_key)

    issue = getattr(owner_proof, "issue_synthetic_assertion_options", None)
    verify = getattr(owner_proof, "verify_synthetic_assertion", None)
    assert callable(issue), "synthetic WebAuthn option issuance API must exist"
    assert callable(verify), "synthetic WebAuthn assertion verification API must exist"

    issued = issue(
        database,
        store_root=store_root,
        proposal_id=saved.proposal.proposal_id,
        credential_id=credential_id,
    )
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=credential_bytes,
        private_key=private_key,
    )
    import socket

    def forbidden_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("owner-proof verification attempted network access")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    verified = verify(
        database,
        store_root=store_root,
        challenge_id=issued.challenge_id,
        assertion_json=assertion,
    )

    assert verified.outcome == "SYNTHETIC_ASSERTION_VERIFIED"
    assert verified.owner_verified is False
    assert verified.executable is False
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM owner_proof_challenge_consumptions"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()[0]
            == 1
        )
        assert connection.execute("SELECT count(*) FROM tasks").fetchone()[0] == 0
    from sentinel.proposals import get_github_fixture_proposal

    after_proposal = get_github_fixture_proposal(
        database,
        proposal_id=before_proposal.proposal_id,
    )
    assert after_proposal == before_proposal


def test_unregistered_credential_cannot_receive_options_or_create_a_challenge(tmp_path) -> None:
    import sentinel.owner_proof as owner_proof

    database, store_root = promoted_case(tmp_path, name="cr2-f-unknown-credential")
    proposal = save_github_fixture_proposal(
        database, store_root=store_root, issue_number=101
    ).proposal
    parameters = inspect.signature(owner_proof.issue_synthetic_assertion_options).parameters
    assert "public_key" not in parameters
    assert "rp_id" not in parameters
    assert "expected_origin" not in parameters
    with pytest.raises(owner_proof.OwnerProofError):
        owner_proof.issue_synthetic_assertion_options(
            database,
            store_root=store_root,
            proposal_id=proposal.proposal_id,
            credential_id=_b64url(b"not-a-registered-credential"),
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM owner_proof_challenges").fetchone() == (
            0,
        )


def test_invalid_signature_consumes_challenge_without_advancing_counter(tmp_path) -> None:
    from sentinel.owner_proof import OwnerProofError

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-invalid-signature"
    )
    assertion = json.loads(
        _signed_assertion(
            options_json=issued.options_json,
            credential_id=credential_id,
            credential_bytes=b"cr2f-synthetic-credential-001",
            private_key=key,
        )
    )
    signature = bytearray(base64.urlsafe_b64decode(assertion["response"]["signature"] + "==="))
    signature[-1] ^= 1
    assertion["response"]["signature"] = _b64url(bytes(signature))

    with pytest.raises(OwnerProofError):
        import sentinel.owner_proof as owner_proof

        owner_proof.verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=json.dumps(assertion, separators=(",", ":")).encode("utf-8"),
        )

    with sqlite3.connect(database) as connection:
        consumption = connection.execute(
            "SELECT outcome, reason_code, verified_sign_count "
            "FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone()
        counter = connection.execute(
            "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone()[0]
    assert consumption == ("FAILED", "ASSERTION_REJECTED", None)
    assert counter == 0


def test_malformed_assertion_consumes_only_the_identified_challenge(tmp_path) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, _key, credential_id, issued = _setup_assertion_case(
        tmp_path,
        name="cr2-f-malformed-assertion",
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=b"not-json",
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)
        assert connection.execute(
            "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("proposal_snapshot_sha256", "f" * 64),
        ("source_set_sha256", "f" * 64),
        ("source_item_id", "00000000-0000-0000-0000-000000000001"),
        ("source_envelope_id", "00000000-0000-0000-0000-000000000001"),
        ("source_content_sha256", "f" * 64),
        ("citation_bindings_json", "[]"),
        ("citation_bindings_sha256", "f" * 64),
        ("policy_request_sha256", "f" * 64),
        ("policy_sha256", "f" * 64),
        ("registry_sha256", "f" * 64),
        ("config_sha256", "f" * 64),
    ],
)
def test_challenge_proposal_source_and_policy_bindings_are_rechecked(
    tmp_path,
    column: str,
    value: object,
) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path,
        name=f"cr2-f-binding-{column}",
    )
    _replace_immutable_challenge_value(
        database,
        challenge_id=issued.challenge_id,
        column=column,
        value=value,
    )
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=assertion,
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)
        assert connection.execute(
            "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone() == (0,)


@pytest.mark.parametrize("tamper", ["cose_public_key", "revoked", "counter"])
def test_credential_registration_and_counter_are_rechecked(tmp_path, tamper: str) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path,
        name=f"cr2-f-credential-{tamper}",
    )
    if tamper == "cose_public_key":
        other_key = ec.generate_private_key(ec.SECP256R1())
        numbers = other_key.public_key().public_numbers()
        replacement = cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )
        _replace_immutable_credential_value(
            database,
            credential_id=credential_id,
            column="cose_public_key",
            value=replacement,
        )
    elif tamper == "revoked":
        _replace_immutable_credential_value(
            database,
            credential_id=credential_id,
            column="revoked",
            value=1,
        )
    else:
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE owner_proof_credentials SET sign_count = 1 WHERE credential_id = ?",
                (credential_id,),
            )
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
        sign_count=1,
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=assertion,
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)


@pytest.mark.parametrize(
    ("client_data", "origin", "auth_rp_id", "flags"),
    [
        (
            b'{"type":"webauthn.get","challenge":"bad","origin":"https://sentinel.test"}',
            _ORIGIN,
            _RP_ID,
            0x05,
        ),
        (None, "https://attacker.invalid", _RP_ID, 0x05),
        (None, _ORIGIN, "attacker.invalid", 0x05),
        (None, _ORIGIN, _RP_ID, 0x01),
        (None, _ORIGIN, _RP_ID, 0x04),
    ],
)
def test_assertion_context_mismatches_are_rejected(
    tmp_path,
    client_data: bytes | None,
    origin: str,
    auth_rp_id: str,
    flags: int,
) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name=f"cr2-f-context-{flags}-{len(origin)}-{len(auth_rp_id)}"
    )
    if client_data == b"":
        options = json.loads(issued.options_json)
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": options["challenge"],
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
        client_origin=origin,
        authenticator_rp_id=auth_rp_id,
        flags=flags,
        client_data_json=client_data,
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=assertion,
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)
        assert (
            connection.execute(
                "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    "client_data",
    [
        b'{"type":"webauthn.get","type":"webauthn.create","challenge":"x","origin":"https://sentinel.test"}',
        b'{"type":"webauthn.get","challenge":"x","origin":"https://sentinel.test","crossOrigin":true}',
        b'{"type":"webauthn.get","challenge":"x","origin":"https://sentinel.test","crossOrigin":"false"}',
        b'{"type":"webauthn.get","challenge":"x","origin":"https://sentinel.test","topOrigin":"https://sentinel.test"}',
    ],
)
def test_ambiguous_or_cross_origin_client_data_fails_closed(tmp_path, client_data: bytes) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name=f"cr2-f-client-data-{hashlib.sha256(client_data).hexdigest()[:8]}"
    )
    options = json.loads(issued.options_json)
    # Keep the authenticator signature valid for these exact ambiguous bytes. The
    # strict precheck must reject before the WebAuthn parser can coerce them.
    client_data = client_data.replace(b'"x"', json.dumps(options["challenge"]).encode())
    client_data = client_data.replace(b'"x"', json.dumps(_ORIGIN).encode())
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
        client_data_json=client_data,
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=assertion,
        )


def test_explicit_cross_origin_false_is_accepted_as_signed_client_data(tmp_path) -> None:
    from sentinel.owner_proof import verify_synthetic_assertion

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path,
        name="cr2-f-cross-origin-false",
    )
    options = json.loads(issued.options_json)
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": options["challenge"],
            "origin": _ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
        client_data_json=client_data,
    )
    result = verify_synthetic_assertion(
        database,
        store_root=store_root,
        challenge_id=issued.challenge_id,
        assertion_json=assertion,
    )
    assert result.outcome == "SYNTHETIC_ASSERTION_VERIFIED"


def test_wrong_key_and_wrong_credential_identity_are_rejected(tmp_path) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, _key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-wrong-key"
    )
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=wrong_key,
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=assertion,
        )


def test_mismatched_credential_id_and_raw_id_are_rejected(tmp_path) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-mismatched-credential-identity"
    )
    assertion = json.loads(
        _signed_assertion(
            options_json=issued.options_json,
            credential_id=credential_id,
            credential_bytes=b"cr2f-synthetic-credential-001",
            private_key=key,
        )
    )
    assertion["rawId"] = _b64url(b"different-credential-id")
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=json.dumps(assertion, separators=(",", ":")).encode("utf-8"),
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)
        assert connection.execute(
            "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone() == (0,)


def test_challenge_for_one_proposal_cannot_be_rebound_to_another(tmp_path) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, proposal_a, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-cross-proposal"
    )
    proposal_b = save_github_fixture_proposal(
        database, store_root=store_root, issue_number=102
    ).proposal
    assert proposal_a.proposal_id != proposal_b.proposal_id
    from sentinel.storage.schema import OWNER_PROOF_CHALLENGES_UPDATE_GUARD_DDL

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER owner_proof_challenges_update_guard")
        connection.execute(
            "UPDATE owner_proof_challenges SET proposal_id = ? WHERE challenge_id = ?",
            (proposal_b.proposal_id, issued.challenge_id),
        )
        connection.execute(OWNER_PROOF_CHALLENGES_UPDATE_GUARD_DDL)
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=_signed_assertion(
                options_json=issued.options_json,
                credential_id=credential_id,
                credential_bytes=b"cr2f-synthetic-credential-001",
                private_key=key,
            ),
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)
        assert connection.execute(
            "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    "invalid_assertion",
    [
        b"\xff",
        b'{"id":"x","id":"x","rawId":"eA","type":"public-key","response":{}}',
        b" " * 16_385,
    ],
)
def test_malformed_duplicate_and_oversized_assertions_consume_known_challenge(
    tmp_path,
    invalid_assertion: bytes,
) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, _key, _credential_id, issued = _setup_assertion_case(
        tmp_path,
        name=f"cr2-f-invalid-envelope-{hashlib.sha256(invalid_assertion).hexdigest()[:8]}",
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=invalid_assertion,
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)

    database2, store_root2, _proposal2, key2, credential_id2, issued2 = _setup_assertion_case(
        tmp_path, name="cr2-f-wrong-id"
    )
    forged_id = _b64url(b"another-credential")
    assertion2 = _signed_assertion(
        options_json=issued2.options_json,
        credential_id=forged_id,
        credential_bytes=b"another-credential",
        private_key=key2,
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database2,
            store_root=store_root2,
            challenge_id=issued2.challenge_id,
            assertion_json=assertion2,
        )


def test_counter_rollback_and_zero_counter_credentials_remain_replay_safe(tmp_path) -> None:
    from sentinel.owner_proof import (
        OwnerProofError,
        issue_synthetic_assertion_options,
        verify_synthetic_assertion,
    )

    database, store_root, proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-counter-rollback"
    )
    valid = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
        sign_count=2,
    )
    verify_synthetic_assertion(
        database, store_root=store_root, challenge_id=issued.challenge_id, assertion_json=valid
    )
    next_issued = issue_synthetic_assertion_options(
        database,
        store_root=store_root,
        proposal_id=proposal.proposal_id,
        credential_id=credential_id,
    )
    rollback = _signed_assertion(
        options_json=next_issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
        sign_count=2,
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=next_issued.challenge_id,
            assertion_json=rollback,
        )
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()[0]
            == 2
        )

    database_zero, store_zero, proposal_zero, key_zero, cred_zero, issued_zero = (
        _setup_assertion_case(tmp_path, name="cr2-f-zero-counter")
    )
    zero = _signed_assertion(
        options_json=issued_zero.options_json,
        credential_id=cred_zero,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key_zero,
        sign_count=0,
    )
    verify_synthetic_assertion(
        database_zero,
        store_root=store_zero,
        challenge_id=issued_zero.challenge_id,
        assertion_json=zero,
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database_zero,
            store_root=store_zero,
            challenge_id=issued_zero.challenge_id,
            assertion_json=zero,
        )
    next_zero = issue_synthetic_assertion_options(
        database_zero,
        store_root=store_zero,
        proposal_id=proposal_zero.proposal_id,
        credential_id=cred_zero,
    )
    second_zero = _signed_assertion(
        options_json=next_zero.options_json,
        credential_id=cred_zero,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key_zero,
        sign_count=0,
    )
    verify_synthetic_assertion(
        database_zero,
        store_root=store_zero,
        challenge_id=next_zero.challenge_id,
        assertion_json=second_zero,
    )


def test_malformed_identity_does_not_consume_an_unrelated_challenge(tmp_path) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, _key, _credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-malformed-id"
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id="../bad",
            assertion_json=b"{}",
        )
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM owner_proof_challenge_consumptions"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM owner_proof_challenges WHERE challenge_id = ?",
                (issued.challenge_id,),
            ).fetchone()[0]
            == 1
        )


def test_challenge_bytes_are_random_and_never_derived_from_proposal_identity(tmp_path) -> None:
    from sentinel.owner_proof import issue_synthetic_assertion_options

    database, store_root = promoted_case(tmp_path, name="cr2-f-random-challenges")
    saved = save_github_fixture_proposal(database, store_root=store_root, issue_number=101)
    key = ec.generate_private_key(ec.SECP256R1())
    credential_id = _register_test_credential(database, key)
    results = [
        issue_synthetic_assertion_options(
            database,
            store_root=store_root,
            proposal_id=saved.proposal.proposal_id,
            credential_id=credential_id,
        )
        for _ in range(20)
    ]
    challenge_ids = {item.challenge_id for item in results}
    challenges = {json.loads(item.options_json)["challenge"] for item in results}
    assert len(challenge_ids) == 20
    assert len(challenges) == 20
    assert all(len(base64.urlsafe_b64decode(value + "=")) == 32 for value in challenges)
    assert saved.proposal.proposal_id not in challenges


def test_challenge_expiry_boundary_and_future_clock_fail_closed(tmp_path, monkeypatch) -> None:
    import sentinel.owner_proof.service as service
    import sentinel.proposals.review as review
    from sentinel.owner_proof import OwnerProofError

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-expiry-boundary"
    )
    with sqlite3.connect(database) as connection:
        expires_value = connection.execute(
            "SELECT expires_at FROM owner_proof_challenges WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone()[0]
    expires_at = datetime.fromisoformat(expires_value)
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )
    with monkeypatch.context() as clock:
        clock.setattr(review, "_utc_now", lambda: expires_at - timedelta(seconds=1))
        clock.setattr(service, "_capture_utc_now", lambda: expires_at)
        with pytest.raises(OwnerProofError):
            service.verify_synthetic_assertion(
                database,
                store_root=store_root,
                challenge_id=issued.challenge_id,
                assertion_json=assertion,
            )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)
        assert connection.execute(
            "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone() == (0,)

    database2, store_root2, _proposal2, key2, credential_id2, issued2 = _setup_assertion_case(
        tmp_path, name="cr2-f-future-clock"
    )
    with sqlite3.connect(database2) as connection:
        created_value = connection.execute(
            "SELECT created_at FROM owner_proof_challenges WHERE challenge_id = ?",
            (issued2.challenge_id,),
        ).fetchone()[0]
    created_at = datetime.fromisoformat(created_value)
    with monkeypatch.context() as clock:
        clock.setattr(review, "_utc_now", lambda: created_at + timedelta(seconds=1))
        clock.setattr(service, "_capture_utc_now", lambda: created_at - timedelta(microseconds=1))
        with pytest.raises(OwnerProofError):
            service.verify_synthetic_assertion(
                database2,
                store_root=store_root2,
                challenge_id=issued2.challenge_id,
                assertion_json=_signed_assertion(
                    options_json=issued2.options_json,
                    credential_id=credential_id2,
                    credential_bytes=b"cr2f-synthetic-credential-001",
                    private_key=key2,
                ),
            )


def test_proposal_expiry_boundary_limits_or_rejects_challenge_issuance(
    tmp_path,
    monkeypatch,
) -> None:
    import sentinel.owner_proof.service as service
    from sentinel.owner_proof import OwnerProofError

    before_database, before_store = promoted_case(tmp_path, name="cr2-f-proposal-expiry-before")
    before_proposal = save_github_fixture_proposal(
        before_database,
        store_root=before_store,
        issue_number=101,
    ).proposal
    before_key = ec.generate_private_key(ec.SECP256R1())
    before_credential = _register_test_credential(before_database, before_key)
    before_expiry = before_proposal.expires_at - timedelta(microseconds=1)
    with monkeypatch.context() as clock:
        clock.setattr(service, "_capture_utc_now", lambda: before_expiry)
        before_options = service.issue_synthetic_assertion_options(
            before_database,
            store_root=before_store,
            proposal_id=before_proposal.proposal_id,
            credential_id=before_credential,
        )
    before_json = json.loads(before_options.options_json)
    assert before_json["timeout"] == 1
    with sqlite3.connect(before_database) as connection:
        assert connection.execute(
            "SELECT expires_at FROM owner_proof_challenges WHERE challenge_id = ?",
            (before_options.challenge_id,),
        ).fetchone() == (before_proposal.expires_at.isoformat(timespec="microseconds"),)

    exact_database, exact_store = promoted_case(tmp_path, name="cr2-f-proposal-expiry-exact")
    exact_proposal = save_github_fixture_proposal(
        exact_database,
        store_root=exact_store,
        issue_number=101,
    ).proposal
    exact_credential = _register_test_credential(
        exact_database,
        ec.generate_private_key(ec.SECP256R1()),
    )
    with monkeypatch.context() as clock:
        clock.setattr(service, "_capture_utc_now", lambda: exact_proposal.expires_at)
        with pytest.raises(OwnerProofError):
            service.issue_synthetic_assertion_options(
                exact_database,
                store_root=exact_store,
                proposal_id=exact_proposal.proposal_id,
                credential_id=exact_credential,
            )
    with sqlite3.connect(exact_database) as connection:
        assert connection.execute("SELECT count(*) FROM owner_proof_challenges").fetchone() == (0,)


def test_tampered_proposal_status_cannot_be_used_for_owner_proof(tmp_path) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path,
        name="cr2-f-proposal-status-tamper",
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE action_proposals SET status = 'APPROVED' WHERE proposal_id = ?",
            (proposal.proposal_id,),
        )
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=assertion,
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status FROM action_proposals WHERE proposal_id = ?",
            (proposal.proposal_id,),
        ).fetchone() == ("APPROVED",)
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)
        assert connection.execute("SELECT count(*) FROM tasks").fetchone() == (0,)


def test_post_crypto_transaction_failure_rolls_back_consumption_and_counter(
    tmp_path, monkeypatch
) -> None:
    import sentinel.owner_proof.service as service
    from sentinel.owner_proof import OwnerProofError

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-post-crypto-rollback"
    )
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )

    def fail_after_staged_writes(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected commit-path failure")

    monkeypatch.setattr(service, "_verify_attempt_writes", fail_after_staged_writes)
    with pytest.raises(OwnerProofError):
        service.verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=assertion,
        )
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
                (issued.challenge_id,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()[0]
            == 0
        )


def test_actual_sqlite_commit_failure_cannot_return_success_or_leave_partial_state(
    tmp_path,
    monkeypatch,
) -> None:
    import sentinel.storage.writer as writer
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path,
        name="cr2-f-commit-failure",
    )
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )
    original = writer._execute_transaction_control
    commit_attempted = False

    def fail_commit(connection, state, statement: str) -> None:
        nonlocal commit_attempted
        if statement == "COMMIT":
            commit_attempted = True
            raise sqlite3.OperationalError("synthetic commit failure")
        original(connection, state, statement)

    monkeypatch.setattr(writer, "_execute_transaction_control", fail_commit)
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=assertion,
        )
    assert commit_attempted
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone() == (0,)


def test_proposal_and_credential_records_are_rechecked_on_writer_transaction(
    tmp_path,
    monkeypatch,
) -> None:
    import sentinel.owner_proof.service as service

    database, store_root, proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path,
        name="cr2-f-transactional-recheck",
    )
    proposal_reader = service.get_github_fixture_proposal_in_transaction
    credential_reader = service._read_credential
    proposal_transactions: list[bool] = []
    credential_transactions: list[bool] = []

    def check_proposal(connection, *, proposal_id):
        proposal_transactions.append(connection.in_transaction)
        return proposal_reader(connection, proposal_id=proposal_id)

    def check_credential(connection, credential: str):
        credential_transactions.append(connection.in_transaction)
        return credential_reader(connection, credential)

    monkeypatch.setattr(service, "get_github_fixture_proposal_in_transaction", check_proposal)
    monkeypatch.setattr(service, "_read_credential", check_credential)
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )
    result = service.verify_synthetic_assertion(
        database,
        store_root=store_root,
        challenge_id=issued.challenge_id,
        assertion_json=assertion,
    )
    assert result.owner_verified is False
    assert len(proposal_transactions) >= 2
    assert all(proposal_transactions)
    assert len(credential_transactions) == 2
    assert all(credential_transactions)
    from sentinel.proposals import get_github_fixture_proposal

    assert get_github_fixture_proposal(database, proposal_id=proposal.proposal_id).status == (
        "PENDING_REVIEW"
    )


def test_process_restart_persists_consumption_and_replay_denial(tmp_path) -> None:
    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-process-restart"
    )
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )
    first = _verify_in_fresh_process(database, store_root, issued.challenge_id, assertion)
    second = _verify_in_fresh_process(database, store_root, issued.challenge_id, assertion)
    assert first.returncode == 0
    assert first.stdout.strip() == "SYNTHETIC_ASSERTION_VERIFIED"
    assert second.returncode != 0
    assert second.stdout.strip() == "replay_rejected"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("VERIFIED_SYNTHETIC_ONLY",)
        assert (
            connection.execute(
                "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()[0]
            == 1
        )


def test_independent_process_issues_then_verifies_and_replays_challenge(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-f-process-issue")
    saved = save_github_fixture_proposal(database, store_root=store_root, issue_number=102)
    key = ec.generate_private_key(ec.SECP256R1())
    credential_id = _register_test_credential(database, key)
    issued_process = _issue_in_fresh_process(
        database,
        store_root,
        saved.proposal.proposal_id,
        credential_id,
    )
    assert issued_process.returncode == 0, issued_process.stderr
    issued = json.loads(issued_process.stdout)
    assertion = _signed_assertion(
        options_json=issued["options_json"],
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )
    verified = _verify_in_fresh_process(
        database,
        store_root,
        issued["challenge_id"],
        assertion,
    )
    replay = _verify_in_fresh_process(
        database,
        store_root,
        issued["challenge_id"],
        assertion,
    )
    assert verified.returncode == 0
    assert verified.stdout.strip() == "SYNTHETIC_ASSERTION_VERIFIED"
    assert replay.returncode == 1
    assert replay.stdout.strip() == "replay_rejected"


def test_two_independent_processes_cannot_both_consume_one_challenge(tmp_path) -> None:
    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-concurrent-consumption"
    )
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )
    command = [
        sys.executable,
        "-c",
        """
import sys
from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion
try:
    result = verify_synthetic_assertion(
        sys.argv[1], store_root=sys.argv[2], challenge_id=sys.argv[3],
        assertion_json=bytes.fromhex(sys.argv[4]),
    )
    print(result.outcome)
except OwnerProofError as error:
    print(error.code.value)
    sys.exit(1)
""",
        str(database),
        str(store_root),
        issued.challenge_id,
        assertion.hex(),
    ]
    first = subprocess.Popen(
        command,
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    second = subprocess.Popen(
        command,
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    first_out, first_err = first.communicate(timeout=45)
    second_out, second_err = second.communicate(timeout=45)
    assert first_err == ""
    assert second_err == ""
    assert sum(process.returncode == 0 for process in (first, second)) == 1, (first_out, second_out)
    assert sorted((first.returncode, second.returncode)) == [0, 1]
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
                (issued.challenge_id,),
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()[0]
            == 1
        )


def test_current_source_or_proposal_change_denies_and_consumes_attempt(tmp_path) -> None:
    from sentinel.content.public_fixture_store import _blob_path
    from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-changed-source"
    )
    expected_digest = str(EXPECTED_MANIFEST.items[0].content_sha256)
    blob = _blob_path(store_root, expected_digest)
    original = blob.read_bytes()
    try:
        blob.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with pytest.raises(OwnerProofError):
            verify_synthetic_assertion(
                database,
                store_root=store_root,
                challenge_id=issued.challenge_id,
                assertion_json=_signed_assertion(
                    options_json=issued.options_json,
                    credential_id=credential_id,
                    credential_bytes=b"cr2f-synthetic-credential-001",
                    private_key=key,
                ),
            )
    finally:
        blob.write_bytes(original)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)
        assert (
            connection.execute(
                "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()[0]
            == 0
        )


def test_source_change_during_crypto_verification_is_rechecked_before_commit(
    tmp_path,
    monkeypatch,
) -> None:
    import sentinel.owner_proof.service as service
    from sentinel.content.public_fixture_store import _blob_path
    from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
    from sentinel.owner_proof import OwnerProofError

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path,
        name="cr2-f-source-changed-during-verification",
    )
    expected_digest = str(EXPECTED_MANIFEST.items[0].content_sha256)
    blob = _blob_path(store_root, expected_digest)
    original_bytes = blob.read_bytes()
    original_loader = service._load_webauthn
    api = original_loader()
    real_verify = api[1]

    def verify_then_tamper(**kwargs: object):
        verified = real_verify(**kwargs)
        blob.write_bytes(original_bytes[:-1] + bytes([original_bytes[-1] ^ 1]))
        return verified

    monkeypatch.setattr(service, "_load_webauthn", lambda: (api[0], verify_then_tamper, *api[2:]))
    assertion = _signed_assertion(
        options_json=issued.options_json,
        credential_id=credential_id,
        credential_bytes=b"cr2f-synthetic-credential-001",
        private_key=key,
    )
    try:
        with pytest.raises(OwnerProofError):
            service.verify_synthetic_assertion(
                database,
                store_root=store_root,
                challenge_id=issued.challenge_id,
                assertion_json=assertion,
            )
    finally:
        blob.write_bytes(original_bytes)

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT outcome FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
            (issued.challenge_id,),
        ).fetchone() == ("FAILED",)
        assert connection.execute(
            "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone() == (0,)


def test_status_is_read_only_and_never_reports_production_owner_verification(tmp_path) -> None:
    import sentinel.owner_proof as owner_proof

    database, store_root, _proposal, _key, credential_id, _issued = _setup_assertion_case(
        tmp_path, name="cr2-f-status-read-only"
    )
    with sqlite3.connect(database) as connection:
        before = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT credential_id, owner_association, sign_count, registration_state "
                "FROM owner_proof_credentials"
            )
        )
    status = owner_proof.build_owner_proof_status(database)
    assert status.production_owner_verification == "UNAVAILABLE"
    assert status.credential_state == "SYNTHETIC_TEST_ONLY"
    assert status.synthetic_test_credentials == 1
    assert status.owner_verified is False
    assert status.executable is False
    assert "private_key" not in repr(status).casefold()
    assert credential_id not in repr(status)
    assert "cose_public_key" not in repr(status).casefold()
    with sqlite3.connect(database) as connection:
        after = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT credential_id, owner_association, sign_count, registration_state "
                "FROM owner_proof_credentials"
            )
        )
    assert before == after
    assert credential_id in before[0]


def test_missing_optional_webauthn_dependency_is_explicit_and_fail_closed(
    tmp_path, monkeypatch
) -> None:
    import sentinel.owner_proof.service as service

    database, _store_root = promoted_case(tmp_path, name="cr2-f-missing-dependency")
    original_import = service.importlib.import_module

    def without_webauthn(name: str, package: str | None = None):
        if name == "webauthn":
            raise ImportError("test-only unavailable")
        return original_import(name, package)

    monkeypatch.setattr(service.importlib, "import_module", without_webauthn)
    status = service.build_owner_proof_status(database)
    assert status.backend_state == "MISSING_DEPENDENCY"
    assert status.production_owner_verification == "UNAVAILABLE"


def test_missing_optional_dependency_cannot_create_or_consume_challenges(
    tmp_path,
    monkeypatch,
) -> None:
    import sentinel.owner_proof.service as service
    from sentinel.owner_proof import OwnerProofError

    database, store_root, _proposal, _key, credential_id, issued = _setup_assertion_case(
        tmp_path,
        name="cr2-f-dependency-unavailable",
    )

    def unavailable() -> None:
        raise OwnerProofError(service.OwnerProofErrorCode.DEPENDENCY_UNAVAILABLE)

    monkeypatch.setattr(service, "_load_webauthn", unavailable)
    with pytest.raises(OwnerProofError):
        service.verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=b"{}",
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM owner_proof_challenge_consumptions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT sign_count FROM owner_proof_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone() == (0,)


def test_valid_cr2e_database_remains_readable_without_auth_migration(tmp_path) -> None:
    import sentinel.owner_proof as owner_proof
    from sentinel.briefing import build_github_fixture_brief
    from sentinel.proposals import list_github_fixture_proposals

    database, store_root, proposal, _key, _credential_id, _issued = _setup_assertion_case(
        tmp_path, name="cr2-f-old-schema-read"
    )
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE owner_proof_challenge_consumptions")
        connection.execute("DROP TABLE owner_proof_challenges")
        connection.execute("DROP TABLE owner_proof_credentials")
        connection.execute(
            "DELETE FROM schema_migrations WHERE migration_id = 'cr2-f-0006-owner-proof-challenges'"
        )
    status = owner_proof.build_owner_proof_status(database)
    assert status.schema_state == "MIGRATION_REQUIRED"
    with pytest.raises(owner_proof.OwnerProofError):
        owner_proof.issue_synthetic_assertion_options(
            database,
            store_root=store_root,
            proposal_id=proposal.proposal_id,
            credential_id="c2NyMmYtc3ludGhldGljLWNyZWRlbnRpYWwtMDAx",
        )
    listed = list_github_fixture_proposals(database)
    assert listed.proposal_count == 1
    assert listed.proposals[0].proposal_id == proposal.proposal_id
    assert len(build_github_fixture_brief(database, store_root=store_root).items) == 3
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE name = 'owner_proof_challenges'"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT count(*) FROM schema_migrations").fetchone() == (5,)
    assert initialize_storage(database) == ("cr2-f-0006-owner-proof-challenges",)
    assert owner_proof.build_owner_proof_status(database).schema_state == "CURRENT"
    assert list_github_fixture_proposals(database).proposal_count == 1


def test_corrupt_migration_history_denies_status_without_repair(tmp_path) -> None:
    import sentinel.owner_proof as owner_proof

    database = tmp_path / "cr2-f-corrupt-history.sqlite3"
    initialize_storage(database, create=True)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET artifact_sha256 = ? "
            "WHERE migration_id = 'cr2-f-0006-owner-proof-challenges'",
            ("f" * 64,),
        )
    with pytest.raises(owner_proof.OwnerProofError):
        owner_proof.build_owner_proof_status(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT artifact_sha256 FROM schema_migrations "
            "WHERE migration_id = 'cr2-f-0006-owner-proof-challenges'"
        ).fetchone() == ("f" * 64,)


def test_assertion_cannot_set_owner_authority_and_status_cli_has_no_ceremony_command(
    tmp_path,
) -> None:
    from sentinel.owner_proof import OwnerProofError, verify_synthetic_assertion

    database, store_root, _proposal, key, credential_id, issued = _setup_assertion_case(
        tmp_path, name="cr2-f-owner-claim"
    )
    assertion = json.loads(
        _signed_assertion(
            options_json=issued.options_json,
            credential_id=credential_id,
            credential_bytes=b"cr2f-synthetic-credential-001",
            private_key=key,
        )
    )
    assertion["owner_verified"] = True
    with pytest.raises(OwnerProofError):
        verify_synthetic_assertion(
            database,
            store_root=store_root,
            challenge_id=issued.challenge_id,
            assertion_json=json.dumps(assertion, separators=(",", ":")).encode("utf-8"),
        )
    help_result = CliRunner().invoke(app, ["auth", "--help"])
    assert help_result.exit_code == 0
    assert "status" in help_result.stdout
    assert "issue" not in help_result.stdout
    assert "verify" not in help_result.stdout
