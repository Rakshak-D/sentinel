"""Durable, synthetic-only WebAuthn challenge issuance and assertion verification.

This module verifies signatures for test credentials. It never creates trusted owner
authority, approvals, grants, tasks, or executable receipts.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib
import json
import re
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, NoReturn
from uuid import UUID, uuid4

from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.owner_proof.types import (
    AuthenticationChallengeOptions,
    OwnerProofChallenge,
    OwnerProofError,
    OwnerProofErrorCode,
    OwnerProofStatus,
    SyntheticAssertionVerification,
)
from sentinel.policy.source_binding import (
    PublicReadBindingError,
    PublicSourceBinding,
    VerifiedGithubPublicRead,
    resolve_github_fixture_public_read,
    validate_verified_github_public_read,
)
from sentinel.proposals.persistence import (
    ProposalPersistenceError,
    get_github_fixture_proposal_in_transaction,
)
from sentinel.proposals.persistence_types import SyntheticPendingProposal
from sentinel.storage.connection import DatabaseOpenError, readonly_database_connection
from sentinel.storage.migrations import (
    MigrationIntegrityError,
    inspect_migration_state_readonly,
    verify_integrity,
)
from sentinel.storage.writer import WriterLeaseError, acquire_writer_lease

_CHALLENGE_LIFETIME = timedelta(seconds=120)
_MAX_CHALLENGES = 10_000
_MAX_ASSERTION_BYTES = 16_384
_MAX_CLIENT_DATA_BYTES = 4096
_MAX_AUTHENTICATOR_DATA_BYTES = 4096
_MAX_SIGNATURE_BYTES = 1024
_MAX_CREDENTIAL_ID_BYTES = 512
_RP_ID: Final[Literal["sentinel.test"]] = "sentinel.test"
_ORIGIN: Final[Literal["https://sentinel.test"]] = "https://sentinel.test"
_OWNER_ASSOCIATION: Final[Literal["synthetic-test-owner"]] = "synthetic-test-owner"
_PURPOSE: Final[Literal["sentinel.pending-proposal-review.webauthn-get.v1"]] = (
    "sentinel.pending-proposal-review.webauthn-get.v1"
)
_SCOPE: Final[Literal["SYNTHETIC_TEST_ONLY_NON_EXECUTABLE"]] = "SYNTHETIC_TEST_ONLY_NON_EXECUTABLE"
_AUTH_MIGRATION_ID = "cr2-f-0006-owner-proof-challenges"
_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_B64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_CITATION_DOMAIN = b"sentinel.owner-proof-selected-citations.v1\x00"
_PROPOSAL_DOMAIN = b"sentinel.owner-proof-proposal-snapshot.v1\x00"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _domain_sha256(domain: bytes, payload: bytes) -> str:
    return hashlib.sha256(domain + payload).hexdigest()


def _proposal_digest(proposal: SyntheticPendingProposal) -> str:
    checked = SyntheticPendingProposal.model_validate(
        proposal.model_dump(mode="python"), strict=True
    )
    if checked != proposal:
        raise OwnerProofError(OwnerProofErrorCode.PROPOSAL_UNAVAILABLE)
    return _domain_sha256(_PROPOSAL_DOMAIN, _canonical_json(checked.model_dump(mode="json")))


def _citation_material(source: PublicSourceBinding) -> str:
    return _canonical_json(
        [
            {
                "end_byte": citation.end_byte,
                "span_id": str(citation.span_id),
                "start_byte": citation.start_byte,
                "text_sha256": citation.text_sha256,
            }
            for citation in source.citations
        ]
    ).decode("utf-8", errors="strict")


def _citation_digest(citation_json: str) -> str:
    return _domain_sha256(_CITATION_DOMAIN, citation_json.encode("utf-8", errors="strict"))


def _load_webauthn() -> tuple[Any, ...]:
    """Load only fixed public WebAuthn APIs; keep the core import optional."""
    try:
        root = importlib.import_module("webauthn")
        helpers = importlib.import_module("webauthn.helpers")
        structs = importlib.import_module("webauthn.helpers.structs")
        return (
            root.generate_authentication_options,
            root.verify_authentication_response,
            helpers.options_to_json,
            structs.PublicKeyCredentialDescriptor,
            structs.UserVerificationRequirement,
            structs.AuthenticationCredential,
            structs.AuthenticatorAssertionResponse,
            structs.PublicKeyCredentialType,
        )
    except Exception:
        raise OwnerProofError(OwnerProofErrorCode.DEPENDENCY_UNAVAILABLE) from None


def _capture_utc_now() -> datetime:
    value = datetime.now(UTC)
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED)
    return value.astimezone(UTC)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_b64url(value: object, *, maximum: int) -> bytes:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum * 2
        or not _B64URL_PATTERN.fullmatch(value)
        or len(value) % 4 == 1
    ):
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (binascii.Error, ValueError):
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED) from None
    if not raw or len(raw) > maximum or _b64url(raw) != value:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    return raw


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite JSON number")


def _strict_object(raw: bytes, *, maximum: int) -> dict[str, object]:
    if not raw or len(raw) > maximum:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED) from None
    if type(value) is not dict:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    return value


def _current_context(
    database: str | Path,
    *,
    connection: sqlite3.Connection,
    store_root: str | Path,
    proposal_id: str,
) -> tuple[SyntheticPendingProposal, VerifiedGithubPublicRead, PublicSourceBinding]:
    try:
        proposal = get_github_fixture_proposal_in_transaction(
            connection,
            proposal_id=proposal_id,
        )
        verified = resolve_github_fixture_public_read(database, store_root=store_root)
        if type(verified) is not VerifiedGithubPublicRead or not (
            validate_verified_github_public_read(verified)
        ):
            raise OwnerProofError(OwnerProofErrorCode.PROPOSAL_UNAVAILABLE)
        binding = verified.binding
        source_matches = tuple(
            item for item in binding.sources if item.item_id == proposal.source_item_id
        )
        if (
            len(binding.sources) != 3
            or len(source_matches) != 1
            or binding.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
            or binding.manifest_sha256 != EXPECTED_MANIFEST.sha256
            or binding.source_set_sha256 != proposal.source_binding_sha256
            or proposal.source_manifest_sha256 != binding.manifest_sha256
        ):
            raise OwnerProofError(OwnerProofErrorCode.PROPOSAL_UNAVAILABLE)
        source = source_matches[0]
        if (
            source.source_id != proposal.source_envelope_id
            or source.content_sha256 != proposal.source_content_sha256
            or tuple(item.span_id for item in source.citations) != proposal.evidence_span_ids
            or source.trust.value != "T4 EXTERNAL"
            or source.sensitivity.value != "PUBLIC"
        ):
            raise OwnerProofError(OwnerProofErrorCode.PROPOSAL_UNAVAILABLE)
        return proposal, verified, source
    except OwnerProofError:
        raise
    except (ProposalPersistenceError, PublicReadBindingError):
        raise OwnerProofError(OwnerProofErrorCode.PROPOSAL_UNAVAILABLE) from None
    except Exception:
        raise OwnerProofError(OwnerProofErrorCode.PROPOSAL_UNAVAILABLE) from None


def _read_credential(connection: sqlite3.Connection, credential_id: str) -> tuple[bytes, int]:
    row = connection.execute(
        """SELECT owner_association, cose_public_key, rp_id, expected_origin,
                  sign_count, registration_state, revoked
           FROM owner_proof_credentials WHERE credential_id = ?""",
        (credential_id,),
    ).fetchone()
    if row is None:
        raise OwnerProofError(OwnerProofErrorCode.CREDENTIAL_UNAVAILABLE)
    owner_association, public_key, rp_id, expected_origin, counter, state, revoked = row
    if (
        owner_association != _OWNER_ASSOCIATION
        or type(public_key) is not bytes
        or not 1 <= len(public_key) <= 4096
        or rp_id != _RP_ID
        or expected_origin != _ORIGIN
        or type(counter) is not int
        or not 0 <= counter <= 4_294_967_295
        or state != "SYNTHETIC_TEST_ONLY"
        or revoked != 0
    ):
        raise OwnerProofError(OwnerProofErrorCode.CREDENTIAL_UNAVAILABLE)
    return public_key, counter


def _challenge_from_row(row: tuple[object, ...]) -> OwnerProofChallenge:
    columns = (
        "challenge_id",
        "schema_version",
        "challenge_b64url",
        "proposal_id",
        "proposal_snapshot_sha256",
        "fixture_sha256",
        "manifest_sha256",
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
        "credential_id",
        "owner_association",
        "rp_id",
        "expected_origin",
        "created_at",
        "expires_at",
        "purpose",
        "scope",
    )
    if len(row) != len(columns):
        raise OwnerProofError(OwnerProofErrorCode.CHALLENGE_UNAVAILABLE)
    values = dict(zip(columns, row, strict=True))
    try:
        values["source_item_id"] = UUID(str(values["source_item_id"]))
        values["source_envelope_id"] = UUID(str(values["source_envelope_id"]))
        values["created_at"] = datetime.fromisoformat(str(values["created_at"]))
        values["expires_at"] = datetime.fromisoformat(str(values["expires_at"]))
        challenge = OwnerProofChallenge.model_validate(values, strict=True)
        if challenge.created_at.isoformat(timespec="microseconds") != str(row[21]):
            raise ValueError
        if challenge.expires_at.isoformat(timespec="microseconds") != str(row[22]):
            raise ValueError
        decoded = _decode_b64url(challenge.challenge_b64url, maximum=32)
        if len(decoded) != 32:
            raise ValueError
        return challenge
    except Exception:
        raise OwnerProofError(OwnerProofErrorCode.CHALLENGE_UNAVAILABLE) from None


def _validate_saved_binding(
    challenge: OwnerProofChallenge,
    proposal: SyntheticPendingProposal,
    verified: VerifiedGithubPublicRead,
    source: PublicSourceBinding,
    *,
    now: datetime,
) -> None:
    binding = verified.binding
    citation_json = _citation_material(source)
    if (
        now < challenge.created_at
        or now >= challenge.expires_at
        or now >= proposal.expires_at
        or challenge.expires_at > proposal.expires_at
        or _proposal_digest(proposal) != challenge.proposal_snapshot_sha256
        or proposal.proposal_id != challenge.proposal_id
        or binding.fixture_sha256 != challenge.fixture_sha256
        or binding.manifest_sha256 != challenge.manifest_sha256
        or binding.source_set_sha256 != challenge.source_set_sha256
        or source.item_id != challenge.source_item_id
        or source.source_id != challenge.source_envelope_id
        or source.content_sha256 != challenge.source_content_sha256
        or _citation_digest(citation_json) != challenge.citation_bindings_sha256
        or citation_json != challenge.citation_bindings_json
        or proposal.policy_request_sha256 != challenge.policy_request_sha256
        or proposal.policy_sha256 != challenge.policy_sha256
        or proposal.registry_sha256 != challenge.registry_sha256
        or proposal.config_sha256 != challenge.config_sha256
        or proposal.status != "PENDING_REVIEW"
        or proposal.owner_intent_id is not None
        or proposal.credential_alias is not None
        or proposal.executable
    ):
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)


def _verify_attempt_writes(
    connection: sqlite3.Connection,
    *,
    challenge_id: str,
    outcome: str,
    counter: int | None,
) -> None:
    """Check the complete transaction-local consumption/counter result before commit."""
    row = connection.execute(
        """SELECT outcome, verified_sign_count
           FROM owner_proof_challenge_consumptions WHERE challenge_id = ?""",
        (challenge_id,),
    ).fetchone()
    if row is None or row[0] != outcome:
        raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED)
    if outcome == "VERIFIED_SYNTHETIC_ONLY":
        credential_row = connection.execute(
            """SELECT sign_count FROM owner_proof_credentials
               WHERE credential_id = (
                   SELECT credential_id FROM owner_proof_challenges WHERE challenge_id = ?
               )""",
            (challenge_id,),
        ).fetchone()
        if (
            counter is None
            or row[1] != counter
            or credential_row is None
            or credential_row[0] != counter
        ):
            raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED)
    elif counter is not None:
        credential_row = connection.execute(
            """SELECT sign_count FROM owner_proof_credentials
               WHERE credential_id = (
                   SELECT credential_id FROM owner_proof_challenges WHERE challenge_id = ?
               )""",
            (challenge_id,),
        ).fetchone()
        if credential_row is None or credential_row[0] != counter:
            raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED)


def issue_synthetic_assertion_options(
    database: str | Path,
    *,
    store_root: str | Path,
    proposal_id: str,
    credential_id: str,
) -> AuthenticationChallengeOptions:
    """Persist a short-lived challenge for an explicitly selected pending proposal.

    This API is intended for isolated synthetic test credentials. It does not
    create an enrollment record or owner-authority evidence.
    """
    if (
        type(proposal_id) is not str
        or len(proposal_id) != 64
        or any(character not in "0123456789abcdef" for character in proposal_id)
        or type(credential_id) is not str
        or not _B64URL_PATTERN.fullmatch(credential_id)
        or len(credential_id) > 684
    ):
        raise OwnerProofError(OwnerProofErrorCode.INVALID_INPUT)
    (
        generate_options,
        _verify,
        options_to_json,
        descriptor_type,
        uv_type,
        *_rest,
    ) = _load_webauthn()
    try:
        with acquire_writer_lease(database) as lease:
            with lease.transaction() as connection:
                proposal, verified, source = _current_context(
                    database,
                    connection=connection,
                    store_root=store_root,
                    proposal_id=proposal_id,
                )
                _read_credential(connection, credential_id)
                now = _capture_utc_now()
                if now >= proposal.expires_at or now < proposal.created_at:
                    raise OwnerProofError(OwnerProofErrorCode.PROPOSAL_UNAVAILABLE)
                if (
                    connection.execute(
                        "SELECT count(*) FROM tasks WHERE proposal_id = ?",
                        (proposal.proposal_id,),
                    ).fetchone()[0]
                    != 0
                ):
                    raise OwnerProofError(OwnerProofErrorCode.PROPOSAL_UNAVAILABLE)
                challenge_bytes = secrets.token_bytes(32)
                if type(challenge_bytes) is not bytes or len(challenge_bytes) != 32:
                    raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED)
                challenge_id = uuid4().hex
                challenge_b64url = _b64url(challenge_bytes)
                expires_at = min(now + _CHALLENGE_LIFETIME, proposal.expires_at)
                if expires_at <= now:
                    raise OwnerProofError(OwnerProofErrorCode.PROPOSAL_UNAVAILABLE)
                timeout_ms = min(
                    120_000,
                    max(1, int((expires_at - now).total_seconds() * 1000)),
                )
                citation_json = _citation_material(source)
                challenge = OwnerProofChallenge(
                    challenge_id=challenge_id,
                    challenge_b64url=challenge_b64url,
                    proposal_id=proposal.proposal_id,
                    proposal_snapshot_sha256=_proposal_digest(proposal),
                    fixture_sha256=verified.binding.fixture_sha256,
                    manifest_sha256=verified.binding.manifest_sha256,
                    source_set_sha256=verified.binding.source_set_sha256,
                    source_item_id=source.item_id,
                    source_envelope_id=source.source_id,
                    source_content_sha256=source.content_sha256,
                    citation_bindings_json=citation_json,
                    citation_bindings_sha256=_citation_digest(citation_json),
                    policy_request_sha256=proposal.policy_request_sha256,
                    policy_sha256=proposal.policy_sha256,
                    registry_sha256=proposal.registry_sha256,
                    config_sha256=proposal.config_sha256,
                    credential_id=credential_id,
                    owner_association=_OWNER_ASSOCIATION,
                    rp_id=_RP_ID,
                    expected_origin=_ORIGIN,
                    created_at=now,
                    expires_at=expires_at,
                    purpose=_PURPOSE,
                    scope=_SCOPE,
                )
                raw_credential_id = _decode_b64url(credential_id, maximum=_MAX_CREDENTIAL_ID_BYTES)
                options = generate_options(
                    rp_id=_RP_ID,
                    challenge=challenge_bytes,
                    timeout=timeout_ms,
                    allow_credentials=[descriptor_type(id=raw_credential_id)],
                    user_verification=uv_type.REQUIRED,
                )
                options_json = options_to_json(options)
                options_doc = json.loads(options_json)
                if (
                    type(options_doc) is not dict
                    or options_doc.get("challenge") != challenge_b64url
                    or options_doc.get("userVerification") != "required"
                    or len(options_json.encode("utf-8")) > 8192
                ):
                    raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED)
                connection.execute(
                    """INSERT INTO owner_proof_challenges (
                       challenge_id, schema_version, challenge_b64url, proposal_id,
                       proposal_snapshot_sha256, fixture_sha256, manifest_sha256,
                       source_set_sha256, source_item_id, source_envelope_id,
                       source_content_sha256, citation_bindings_json,
                       citation_bindings_sha256, policy_request_sha256, policy_sha256,
                       registry_sha256, config_sha256, credential_id, owner_association,
                       rp_id, expected_origin, created_at, expires_at, purpose, scope
                       ) VALUES (
                       ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?
                       )""",
                    (
                        challenge.challenge_id,
                        challenge.schema_version,
                        challenge.challenge_b64url,
                        challenge.proposal_id,
                        challenge.proposal_snapshot_sha256,
                        challenge.fixture_sha256,
                        challenge.manifest_sha256,
                        challenge.source_set_sha256,
                        str(challenge.source_item_id),
                        str(challenge.source_envelope_id),
                        challenge.source_content_sha256,
                        challenge.citation_bindings_json,
                        challenge.citation_bindings_sha256,
                        challenge.policy_request_sha256,
                        challenge.policy_sha256,
                        challenge.registry_sha256,
                        challenge.config_sha256,
                        challenge.credential_id,
                        challenge.owner_association,
                        challenge.rp_id,
                        challenge.expected_origin,
                        challenge.created_at.isoformat(timespec="microseconds"),
                        challenge.expires_at.isoformat(timespec="microseconds"),
                        challenge.purpose,
                        challenge.scope,
                    ),
                )
                total = int(
                    connection.execute("SELECT count(*) FROM owner_proof_challenges").fetchone()[0]
                )
                if total > _MAX_CHALLENGES:
                    raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED)
        return AuthenticationChallengeOptions(
            challenge_id=challenge_id,
            options_json=options_json,
        )
    except OwnerProofError:
        raise
    except (WriterLeaseError, DatabaseOpenError, MigrationIntegrityError, sqlite3.Error):
        raise OwnerProofError(OwnerProofErrorCode.DATABASE_UNAVAILABLE) from None
    except Exception:
        raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED) from None


def _parse_assertion(raw: bytes, credential_id: str, challenge_b64url: str) -> Any:
    if type(raw) is not bytes:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    payload = _strict_object(raw, maximum=_MAX_ASSERTION_BYTES)
    if set(payload) != {"id", "rawId", "type", "response"}:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    if payload.get("type") != "public-key" or payload.get("id") != credential_id:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    raw_id = _decode_b64url(payload.get("rawId"), maximum=_MAX_CREDENTIAL_ID_BYTES)
    if _b64url(raw_id) != credential_id:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    response = payload.get("response")
    if type(response) is not dict or set(response) - {
        "clientDataJSON",
        "authenticatorData",
        "signature",
        "userHandle",
    }:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    if not {"clientDataJSON", "authenticatorData", "signature"}.issubset(response):
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    client_data = _decode_b64url(response["clientDataJSON"], maximum=_MAX_CLIENT_DATA_BYTES)
    authenticator_data = _decode_b64url(
        response["authenticatorData"], maximum=_MAX_AUTHENTICATOR_DATA_BYTES
    )
    signature = _decode_b64url(response["signature"], maximum=_MAX_SIGNATURE_BYTES)
    if "userHandle" in response:
        user_handle_value = response["userHandle"]
        if user_handle_value is None:
            user_handle = None
        else:
            user_handle = _decode_b64url(user_handle_value, maximum=1024)
    else:
        user_handle = None
    client_doc = _strict_object(client_data, maximum=_MAX_CLIENT_DATA_BYTES)
    if set(client_doc) - {"type", "challenge", "origin", "crossOrigin"}:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    if (
        client_doc.get("type") != "webauthn.get"
        or client_doc.get("challenge") != challenge_b64url
        or client_doc.get("origin") != _ORIGIN
        or ("crossOrigin" in client_doc and client_doc["crossOrigin"] is not False)
        or "topOrigin" in client_doc
    ):
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
    (
        _generate,
        _verify,
        _options_json,
        _descriptor,
        _uv,
        credential_type,
        response_type,
        public_type,
    ) = _load_webauthn()
    try:
        return credential_type(
            id=credential_id,
            raw_id=raw_id,
            response=response_type(
                client_data_json=client_data,
                authenticator_data=authenticator_data,
                signature=signature,
                user_handle=user_handle,
            ),
            type=public_type.PUBLIC_KEY,
        )
    except Exception:
        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED) from None


def _challenge_select(
    connection: sqlite3.Connection, challenge_id: str
) -> tuple[object, ...] | None:
    row = connection.execute(
        """SELECT challenge_id, schema_version, challenge_b64url, proposal_id,
                  proposal_snapshot_sha256, fixture_sha256, manifest_sha256,
                  source_set_sha256, source_item_id, source_envelope_id,
                  source_content_sha256, citation_bindings_json,
                  citation_bindings_sha256, policy_request_sha256, policy_sha256,
                  registry_sha256, config_sha256, credential_id, owner_association,
                  rp_id, expected_origin, created_at, expires_at, purpose, scope
           FROM owner_proof_challenges WHERE challenge_id = ?""",
        (challenge_id,),
    ).fetchone()
    return None if row is None else tuple(row)


def verify_synthetic_assertion(
    database: str | Path,
    *,
    store_root: str | Path,
    challenge_id: str,
    assertion_json: bytes,
) -> SyntheticAssertionVerification:
    """Verify and consume one assertion in a single writer-lease transaction.

    A parseable challenge ID for an existing unconsumed challenge is consumed on
    an invalid assertion. Transaction/storage failures roll back consumption and
    counter updates together.
    """
    if type(challenge_id) is not str or not _ID_PATTERN.fullmatch(challenge_id):
        raise OwnerProofError(OwnerProofErrorCode.INVALID_INPUT)
    _generate, verify_response, _options_json, _descriptor, _uv, *_ = _load_webauthn()
    try:
        with acquire_writer_lease(database) as lease:
            failure = False
            verified_count = 0
            consumed_at: str | None = None
            challenge: OwnerProofChallenge | None = None
            original_counter: int | None = None
            final_decision_time: datetime | None = None
            with lease.transaction() as connection:
                raw_row = _challenge_select(connection, challenge_id)
                if raw_row is None:
                    raise OwnerProofError(OwnerProofErrorCode.CHALLENGE_UNAVAILABLE)
                existing = connection.execute(
                    "SELECT 1 FROM owner_proof_challenge_consumptions WHERE challenge_id = ?",
                    (challenge_id,),
                ).fetchone()
                if existing is not None:
                    raise OwnerProofError(OwnerProofErrorCode.REPLAY_REJECTED)
                try:
                    challenge = _challenge_from_row(raw_row)
                    if challenge.challenge_id != challenge_id:
                        raise OwnerProofError(OwnerProofErrorCode.CHALLENGE_UNAVAILABLE)
                    public_key, counter = _read_credential(connection, challenge.credential_id)
                    original_counter = counter
                    proposal, verified_source, source = _current_context(
                        database,
                        connection=connection,
                        store_root=store_root,
                        proposal_id=challenge.proposal_id,
                    )
                    initial_time = _capture_utc_now()
                    _validate_saved_binding(
                        challenge,
                        proposal,
                        verified_source,
                        source,
                        now=initial_time,
                    )
                    if (
                        proposal.created_at > initial_time
                        or proposal.expires_at <= initial_time
                        or connection.execute(
                            "SELECT count(*) FROM tasks WHERE proposal_id = ?",
                            (proposal.proposal_id,),
                        ).fetchone()[0]
                        != 0
                    ):
                        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
                    credential = _parse_assertion(
                        assertion_json,
                        challenge.credential_id,
                        challenge.challenge_b64url,
                    )
                    raw_credential_id = _decode_b64url(
                        challenge.credential_id,
                        maximum=_MAX_CREDENTIAL_ID_BYTES,
                    )
                    result = verify_response(
                        credential=credential,
                        expected_challenge=_decode_b64url(
                            challenge.challenge_b64url,
                            maximum=32,
                        ),
                        expected_rp_id=challenge.rp_id,
                        expected_origin=challenge.expected_origin,
                        credential_public_key=public_key,
                        credential_current_sign_count=counter,
                        require_user_verification=True,
                    )
                    if (
                        result.credential_id != raw_credential_id
                        or result.user_verified is not True
                        or (counter > 0 and result.new_sign_count <= counter)
                    ):
                        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
                    verified_count = int(result.new_sign_count)
                    if not 0 <= verified_count <= 4_294_967_295:
                        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
                    # Filesystem blobs do not participate in SQLite's transaction.
                    # Resolve them again immediately before staging the committed
                    # result so a detectable replacement during signature checking
                    # cannot be accepted. This is a second validation point, not an
                    # atomic snapshot against same-user or ABA filesystem races.
                    proposal_recheck, source_recheck, selected_source_recheck = _current_context(
                        database,
                        connection=connection,
                        store_root=store_root,
                        proposal_id=challenge.proposal_id,
                    )
                    current_key, current_counter = _read_credential(
                        connection,
                        challenge.credential_id,
                    )
                    if (
                        _proposal_digest(proposal_recheck) != challenge.proposal_snapshot_sha256
                        or current_key != public_key
                        or current_counter != counter
                    ):
                        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
                    final_decision_time = _capture_utc_now()
                    if final_decision_time < initial_time:
                        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
                    _validate_saved_binding(
                        challenge,
                        proposal_recheck,
                        source_recheck,
                        selected_source_recheck,
                        now=final_decision_time,
                    )
                    if proposal_recheck.created_at > final_decision_time:
                        raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
                    consumed_at = final_decision_time.isoformat(timespec="microseconds")
                except OwnerProofError:
                    failure = True
                    decision_time = (
                        final_decision_time
                        if final_decision_time is not None
                        else _capture_utc_now()
                    )
                    consumed_at = decision_time.isoformat(timespec="microseconds")
                except Exception:
                    failure = True
                    decision_time = (
                        final_decision_time
                        if final_decision_time is not None
                        else _capture_utc_now()
                    )
                    consumed_at = decision_time.isoformat(timespec="microseconds")

                if consumed_at is None or challenge is None:
                    raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED)
                if failure:
                    connection.execute(
                        """INSERT INTO owner_proof_challenge_consumptions
                           (challenge_id, consumed_at, outcome, reason_code, verified_sign_count)
                           VALUES (?, ?, 'FAILED', 'ASSERTION_REJECTED', NULL)""",
                        (challenge_id, consumed_at),
                    )
                else:
                    connection.execute(
                        """INSERT INTO owner_proof_challenge_consumptions
                           (challenge_id, consumed_at, outcome, reason_code, verified_sign_count)
                           VALUES (?, ?, 'VERIFIED_SYNTHETIC_ONLY', 'ASSERTION_VERIFIED', ?)""",
                        (challenge_id, consumed_at, verified_count),
                    )
                    update = connection.execute(
                        """UPDATE owner_proof_credentials SET sign_count = ?
                           WHERE credential_id = ?""",
                        (verified_count, challenge.credential_id),
                    )
                    if update.rowcount != 1:
                        raise OwnerProofError(OwnerProofErrorCode.CREDENTIAL_UNAVAILABLE)
                _verify_attempt_writes(
                    connection,
                    challenge_id=challenge_id,
                    outcome=("FAILED" if failure else "VERIFIED_SYNTHETIC_ONLY"),
                    counter=(original_counter if failure else verified_count),
                )
            if failure:
                raise OwnerProofError(OwnerProofErrorCode.ASSERTION_REJECTED)
            return SyntheticAssertionVerification(
                challenge_id=challenge_id,
                new_sign_count=verified_count,
            )
    except OwnerProofError:
        raise
    except (WriterLeaseError, DatabaseOpenError, MigrationIntegrityError, sqlite3.Error):
        raise OwnerProofError(OwnerProofErrorCode.DATABASE_UNAVAILABLE) from None
    except Exception:
        raise OwnerProofError(OwnerProofErrorCode.OPERATION_FAILED) from None


def build_owner_proof_status(database: str | Path) -> OwnerProofStatus:
    """Read validated schema and synthetic-only credential counts without mutation."""
    backend_state: Literal["AVAILABLE", "MISSING_DEPENDENCY"]
    try:
        _load_webauthn()
        backend_state = "AVAILABLE"
    except OwnerProofError as error:
        if error.code is not OwnerProofErrorCode.DEPENDENCY_UNAVAILABLE:
            raise
        backend_state = "MISSING_DEPENDENCY"
    try:
        with readonly_database_connection(database) as connection:
            state = inspect_migration_state_readonly(connection)
            verify_integrity(connection)
            auth_applied = _AUTH_MIGRATION_ID in state.applied_migration_ids
            count = 0
            if auth_applied:
                count_value = connection.execute(
                    """SELECT count(*) FROM owner_proof_credentials
                       WHERE registration_state = 'SYNTHETIC_TEST_ONLY'"""
                ).fetchone()[0]
                if type(count_value) is not int or not 0 <= count_value <= 1000:
                    raise OwnerProofError(OwnerProofErrorCode.DATABASE_UNAVAILABLE)
                count = count_value
            return OwnerProofStatus(
                backend_state=backend_state,
                schema_state="CURRENT" if auth_applied else "MIGRATION_REQUIRED",
                credential_state=("SYNTHETIC_TEST_ONLY" if count else "NO_PROTECTED_ENROLLMENT"),
                synthetic_test_credentials=count,
            )
    except OwnerProofError:
        raise
    except (DatabaseOpenError, MigrationIntegrityError, sqlite3.Error, OSError, ValueError):
        raise OwnerProofError(OwnerProofErrorCode.DATABASE_UNAVAILABLE) from None
    except Exception:
        raise OwnerProofError(OwnerProofErrorCode.DATABASE_UNAVAILABLE) from None


__all__ = [
    "build_owner_proof_status",
    "issue_synthetic_assertion_options",
    "verify_synthetic_assertion",
]
