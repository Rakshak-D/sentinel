"""Run fixed synthetic policy checks without persistent or external effects."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import UUID

from sentinel.config import CONFIG_SCHEMA_VERSION, config_sha256, load_bundled_defaults
from sentinel.content import initialize_public_fixture_store
from sentinel.contracts import SensitivityLabel, SourceEnvelope, TrustLabel
from sentinel.gateways.types import ExecutionMode
from sentinel.ingestion import (
    ingest_packaged_github_fixture,
    promote_github_fixture_to_public_blobs,
)
from sentinel.ingestion.blob_manifest import (
    EXPECTED_MANIFEST,
    FIXTURE_SHA256,
    MANIFEST_VERSION,
)
from sentinel.policy import (
    BUILTIN_REGISTRY,
    POLICY_ID,
    POLICY_VERSION,
    REGISTRY_ID,
    REGISTRY_VERSION,
    ArgumentKind,
    Capability,
    EffectClass,
    ExecutionBoundary,
    PolicyContext,
    PolicyDecision,
    PolicyRequest,
    build_policy_context,
    build_proposal_persistence_policy_request,
    builtin_registry_sha256,
    evaluate_policy,
    policy_sha256,
)
from sentinel.policy.evaluator import (
    build_verified_proposal_preview_policy_input,
    build_verified_public_read_policy_input,
)
from sentinel.policy.identities import proposal_preview_identity
from sentinel.policy.source_binding import (
    VerifiedGithubPublicRead,
    resolve_github_fixture_public_read,
)
from sentinel.storage.migrations import initialize_storage

MANIFEST_DOMAIN = b"sentinel.f42-d0-scenario-manifest.v1\x00"
ORACLE_DOMAIN = b"sentinel.f42-d0-policy-decision-oracle.v1\x00"
REPORT_DOMAIN = b"sentinel.f42-d0-diagnostic-report.v1\x00"
REPORT_SCHEMA_VERSION = "sentinel.f42-d0-diagnostic-report.v1"
PINNED_MANIFEST_SHA256 = "832414dee819bcc5e0d4312b7e37e7772c99709eedf812e95c421bf69cc3830e"
PINNED_ORACLE_SHA256 = "1e78c28b2e39f274e785865afb6028e9258ef738898be9322ac79704f2e9b18a"
MAX_MANIFEST_BYTES = 32 * 1024
MAX_ORACLE_BYTES = 128 * 1024
MAX_REPORT_BYTES = 64 * 1024
_SAFE_FAILURE_CODES = frozenset(
    {
        "MANIFEST_PIN_MISMATCH",
        "MANIFEST_INVALID",
        "ORACLE_PIN_MISMATCH",
        "ORACLE_INVALID",
        "ORACLE_CASE_MISSING",
        "FIXTURE_BINDING_MISMATCH",
        "FIXTURE_VERIFICATION_FAILED",
        "SCENARIO_UNAVAILABLE",
        "POLICY_EVALUATION_FAILED",
        "ORACLE_EXPECTATION_MISMATCH",
        "SYNTHETIC_WORKSPACE_MUTATED",
        "POLICY_FINGERPRINT_MISMATCH",
        "REPORT_TOO_LARGE",
        "DIAGNOSTIC_INTERNAL_FAILURE",
        "ARGUMENTS_UNSUPPORTED",
    }
)

_EFFECT_BY_CAPABILITY = {
    Capability.C0_READ_PUBLIC: EffectClass.READ_ONLY,
    Capability.C1_READ_PRIVATE: EffectClass.READ_ONLY,
    Capability.C2_WRITE_LOCAL_PROPOSAL: EffectClass.LOCAL_PROPOSAL,
    Capability.C3_WRITE_LOCAL_ACCEPTED: EffectClass.LOCAL_ACCEPTED,
    Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB: EffectClass.EXTERNAL_DRAFT_OR_GITHUB,
    Capability.C5_SEND_EXTERNAL_EMAIL: EffectClass.EXTERNAL_SEND,
    Capability.C6_ACCESS_SECRET: EffectClass.SECRET_ACCESS,
}


class DiagnosticFailure(RuntimeError):
    """A fixed, bounded failure category safe to display in terminal output."""

    def __init__(self, code: str) -> None:
        safe_code = (
            code
            if type(code) is str and code in _SAFE_FAILURE_CODES
            else "DIAGNOSTIC_INTERNAL_FAILURE"
        )
        super().__init__(safe_code)
        self.code = safe_code


def canonical_json_bytes(payload: object) -> bytes:
    """Serialize bounded report data deterministically as canonical UTF-8 JSON."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def manifest_sha256(payload: object) -> str:
    """Return the domain-separated identity of canonical manifest content."""
    return hashlib.sha256(MANIFEST_DOMAIN + canonical_json_bytes(payload)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _strict_json_loads(raw: bytes) -> object:
    return json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid JSON number")),
    )


def load_manifest_document() -> dict[str, Any]:
    """Read only the fixed repository manifest; no path is user-selectable."""
    path = Path(__file__).with_name("scenario_manifest.json")
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_MANIFEST_BYTES:
            raise DiagnosticFailure("MANIFEST_INVALID")
        value = _strict_json_loads(raw)
        if type(value) is not dict:
            raise DiagnosticFailure("MANIFEST_INVALID")
        return value
    except DiagnosticFailure:
        raise
    except Exception:
        raise DiagnosticFailure("MANIFEST_INVALID") from None


def validate_manifest_document(payload: object) -> dict[str, Any]:
    """Reject any manifest not matching the independently pinned content ID."""
    if type(payload) is not dict:
        raise DiagnosticFailure("MANIFEST_PIN_MISMATCH")
    try:
        if manifest_sha256(payload) != PINNED_MANIFEST_SHA256:
            raise DiagnosticFailure("MANIFEST_PIN_MISMATCH")
        if payload.get("schema_version") != "sentinel.f42-d0-scenario-manifest.v1":
            raise DiagnosticFailure("MANIFEST_INVALID")
        if payload.get("manifest_version") != "f42-d0.1":
            raise DiagnosticFailure("MANIFEST_INVALID")
        if set(payload) != {
            "schema_version",
            "manifest_version",
            "baseline",
            "fixture",
            "decision_oracle",
            "scenarios",
        }:
            raise DiagnosticFailure("MANIFEST_INVALID")
        baseline = payload.get("baseline")
        if type(baseline) is not dict or set(baseline) != {
            "policy_sha256",
            "registry_sha256",
            "config_sha256",
        }:
            raise DiagnosticFailure("MANIFEST_INVALID")
        for value in baseline.values():
            if (
                type(value) is not str
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise DiagnosticFailure("MANIFEST_INVALID")
        fixture = payload.get("fixture")
        if type(fixture) is not dict or set(fixture) != {
            "fixture_id",
            "fixture_sha256",
            "manifest_version",
            "manifest_sha256",
            "source_set_sha256",
            "source_count",
            "citation_count",
        }:
            raise DiagnosticFailure("MANIFEST_INVALID")
        if fixture != {
            "fixture_id": "example-owner/fixture-project",
            "fixture_sha256": FIXTURE_SHA256,
            "manifest_version": MANIFEST_VERSION,
            "manifest_sha256": EXPECTED_MANIFEST.sha256,
            "source_set_sha256": "603c7bdf5a58702292b2b0966f9d67cf90f06c8a671d9ef76831fc43d8ccf69f",
            "source_count": 3,
            "citation_count": 9,
        }:
            raise DiagnosticFailure("MANIFEST_INVALID")
        oracle = payload.get("decision_oracle")
        if type(oracle) is not dict or oracle != {
            "oracle_id": "r2-a-pre-refactor-policy-decision-snapshots.v1",
            "sha256": PINNED_ORACLE_SHA256,
        }:
            raise DiagnosticFailure("MANIFEST_INVALID")
        scenarios = payload.get("scenarios")
        if type(scenarios) is not list or len(scenarios) != 16:
            raise DiagnosticFailure("MANIFEST_INVALID")
        identifiers: set[str] = set()
        oracle_cases: set[str] = set()
        for scenario in scenarios:
            if type(scenario) is not dict or set(scenario) != {"id", "oracle_case", "expected"}:
                raise DiagnosticFailure("MANIFEST_INVALID")
            scenario_id = scenario.get("id")
            oracle_case = scenario.get("oracle_case")
            expected = scenario.get("expected")
            if (
                type(scenario_id) is not str
                or not scenario_id
                or type(oracle_case) is not str
                or not oracle_case
                or scenario_id in identifiers
                or oracle_case in oracle_cases
            ):
                raise DiagnosticFailure("MANIFEST_INVALID")
            if type(expected) is not dict or set(expected) != {
                "outcome",
                "rule_id",
                "reason_code",
                "executable",
            }:
                raise DiagnosticFailure("MANIFEST_INVALID")
            if (
                expected.get("outcome") not in {"ALLOW", "DENY"}
                or type(expected.get("rule_id")) is not str
                or type(expected.get("reason_code")) is not str
                or expected.get("executable") is not False
            ):
                raise DiagnosticFailure("MANIFEST_INVALID")
            identifiers.add(scenario_id)
            oracle_cases.add(oracle_case)
        return payload
    except DiagnosticFailure:
        raise
    except Exception:
        raise DiagnosticFailure("MANIFEST_INVALID") from None


def _load_oracle() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    path = root / "tests" / "r2_a_policy_decision_snapshots.json"
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_ORACLE_BYTES:
            raise DiagnosticFailure("ORACLE_PIN_MISMATCH")
        value = _strict_json_loads(raw)
        if type(value) is not dict:
            raise DiagnosticFailure("ORACLE_INVALID")
        oracle_digest = hashlib.sha256(ORACLE_DOMAIN + canonical_json_bytes(value)).hexdigest()
        if oracle_digest != PINNED_ORACLE_SHA256:
            raise DiagnosticFailure("ORACLE_PIN_MISMATCH")
        return value
    except DiagnosticFailure:
        raise
    except Exception:
        raise DiagnosticFailure("ORACLE_INVALID") from None


def _make_source(
    *,
    trust: TrustLabel = TrustLabel.T4_EXTERNAL,
    sensitivity: SensitivityLabel = SensitivityLabel.PRIVATE,
) -> SourceEnvelope:
    return SourceEnvelope(
        source_id=UUID(int=101),
        provider_id="sentinel.cr2-test-source",
        content_sha256="a" * 64,
        observed_at=datetime(2026, 11, 6, tzinfo=UTC),
        trust=trust,
        sensitivity=sensitivity,
        parent_ids=(),
        byte_spans=(),
    )


def _make_context(source: SourceEnvelope | None = None) -> PolicyContext:
    return build_policy_context(sources=() if source is None else (source,))


def _make_request(
    *,
    capability: Capability = Capability.C0_READ_PUBLIC,
    operation_id: str | None = None,
    source: SourceEnvelope | None = None,
    source_ids: tuple[UUID, ...] | None = None,
    execution_mode: ExecutionMode = ExecutionMode.LIVE,
    execution_boundary: ExecutionBoundary = ExecutionBoundary.CORE,
    declared_sensitivity: SensitivityLabel | None = SensitivityLabel.PRIVATE,
) -> PolicyRequest:
    selected_operation = operation_id or next(
        entry.operation_id
        for entry in BUILTIN_REGISTRY.entries
        if entry.capability_id is capability
    )
    registration = BUILTIN_REGISTRY.find_operation(selected_operation)
    if registration is None:
        arguments: tuple[tuple[str, str | int | bool], ...] = (("resource_id", "synthetic-item"),)
    else:
        defaults: dict[ArgumentKind, str | int | bool] = {
            ArgumentKind.TEXT: "synthetic-item",
            ArgumentKind.INTEGER: 1,
            ArgumentKind.BOOLEAN: True,
        }
        arguments = tuple(
            (spec.name, defaults[spec.value_kind]) for spec in registration.argument_schema
        )
    source_value = source or _make_source()
    context = _make_context(source_value)
    return PolicyRequest(
        request_id=UUID(int=202),
        operation_id=selected_operation,
        capability=capability,
        execution_mode=execution_mode,
        execution_boundary=execution_boundary,
        arguments=arguments,
        source_ids=(source_value.source_id,) if source_ids is None else source_ids,
        declared_sensitivity=declared_sensitivity,
        registry_id=REGISTRY_ID,
        registry_version=REGISTRY_VERSION,
        registry_sha256=builtin_registry_sha256(),
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        policy_sha256=policy_sha256(),
        config_version=context.config_version,
        config_sha256=context.config_sha256,
        requested_effect_class=(
            _EFFECT_BY_CAPABILITY[capability] if registration is None else registration.effect_class
        ),
    )


def _prepare_verified_fixture(workspace: Path) -> VerifiedGithubPublicRead:
    database = workspace / "diagnostic.sqlite3"
    store_root = workspace / "public-store"
    try:
        initialize_storage(database, create=True)
        ingest_packaged_github_fixture(database)
        initialize_public_fixture_store(store_root)
        promote_github_fixture_to_public_blobs(database, store_root=store_root)
        verified = resolve_github_fixture_public_read(database, store_root=store_root)
        if (
            verified.binding.fixture_sha256 != FIXTURE_SHA256
            or verified.binding.manifest_sha256 != EXPECTED_MANIFEST.sha256
            or verified.binding.source_set_sha256
            != "603c7bdf5a58702292b2b0966f9d67cf90f06c8a671d9ef76831fc43d8ccf69f"
            or len(verified.binding.sources) != 3
            or sum(len(source.citations) for source in verified.binding.sources) != 9
        ):
            raise DiagnosticFailure("FIXTURE_BINDING_MISMATCH")
        return verified
    except DiagnosticFailure:
        raise
    except Exception:
        raise DiagnosticFailure("FIXTURE_VERIFICATION_FAILED") from None


def _snapshot_workspace(workspace: Path) -> dict[str, str]:
    return {
        path.relative_to(workspace).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }


def _build_scenario_inputs(
    verified: VerifiedGithubPublicRead,
) -> dict[str, tuple[PolicyRequest, PolicyContext, VerifiedGithubPublicRead | None]]:
    source = _make_source()
    context = _make_context(source)
    request = _make_request(source=source)
    inputs: dict[str, tuple[PolicyRequest, PolicyContext, VerifiedGithubPublicRead | None]] = {}

    unknown_operation = _make_request(source=source, operation_id="sentinel.unknown.operation")
    inputs["p00_operation_unknown"] = (unknown_operation, _make_context(source), None)

    mismatch = _make_request(
        capability=Capability.C1_READ_PRIVATE,
        operation_id="sentinel.synthetic.read.public",
        source=source,
    )
    inputs["p00_capability_mismatch"] = (mismatch, _make_context(source), None)

    unknown_source = _make_source(trust=TrustLabel.T5_UNKNOWN)
    inputs["p00_source_t5"] = (
        _make_request(source=unknown_source),
        _make_context(unknown_source),
        None,
    )

    replay = _make_request(
        capability=Capability.C2_WRITE_LOCAL_PROPOSAL,
        source=source,
        execution_mode=ExecutionMode.REPLAY,
    )
    inputs["p01_replay"] = (replay, context, None)

    priority_p00 = request.model_copy(
        update={
            "registry_sha256": "0" * 64,
            "execution_boundary": ExecutionBoundary.BYPASS_GATEWAY,
        }
    )
    inputs["priority_p00_before_p01"] = (priority_p00, context, None)

    priority_p01 = _make_request(
        capability=Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
        source=source,
        execution_boundary=ExecutionBoundary.BYPASS_GATEWAY,
    )
    inputs["priority_p01_before_p02"] = (priority_p01, context, None)

    external = _make_request(
        capability=Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
        source=source,
    )
    inputs["p02_c4"] = (external, context, None)

    secret_source = _make_source(sensitivity=SensitivityLabel.SECRET)
    secret_model = _make_request(
        source=secret_source,
        execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
        declared_sensitivity=SensitivityLabel.SECRET,
    )
    inputs["p03_secret"] = (secret_model, _make_context(secret_source), None)

    secret_capability = _make_request(
        capability=Capability.C6_ACCESS_SECRET,
        source=secret_source,
        execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
        declared_sensitivity=SensitivityLabel.SECRET,
    )
    inputs["priority_p03_before_p17"] = (
        secret_capability,
        _make_context(secret_source),
        None,
    )

    secret_access = _make_request(capability=Capability.C6_ACCESS_SECRET, source=source)
    inputs["p17_c6"] = (secret_access, context, None)

    missing_binding = _make_request(
        capability=Capability.C2_WRITE_LOCAL_PROPOSAL,
        source=source,
    )
    inputs["p09_binding_missing"] = (missing_binding, context, None)

    public_request, public_context = build_verified_public_read_policy_input(verified)
    wrong_digest = public_request.model_copy(update={"source_binding_sha256": "f" * 64})
    inputs["p09_wrong_binding_digest"] = (wrong_digest, public_context, verified)
    wrong_citations = public_request.model_copy(
        update={"evidence_span_ids": public_request.evidence_span_ids[:-1]}
    )
    inputs["p09_wrong_citation_set"] = (wrong_citations, public_context, verified)
    inputs["p04_public_read_allow"] = (public_request, public_context, verified)

    preview_request, preview_context = build_verified_proposal_preview_policy_input(
        verified, issue_number=101
    )
    inputs["p06_preview_allow"] = (preview_request, preview_context, verified)

    selected = next(
        item for item in verified.binding.sources if item.provider_item_id.endswith("#101")
    )
    preview_id = proposal_preview_identity(selected.item_id, verified.binding.source_set_sha256)
    persistence_request = build_proposal_persistence_policy_request(
        binding=verified.binding,
        issue_number=101,
        preview_id=preview_id,
    )
    persistence_context = build_policy_context(
        sources=verified.source_envelopes,
        source_binding_sha256=verified.binding.source_set_sha256,
    )
    inputs["p06_persistence_allow"] = (persistence_request, persistence_context, verified)
    return inputs


def _decision_projection(decision: dict[str, Any]) -> dict[str, object]:
    return {
        "outcome": decision.get("outcome"),
        "rule_id": decision.get("rule_id"),
        "reason_code": decision.get("reason_code"),
        "executable": decision.get("executable"),
    }


def _coverage_inventory(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    rule_results: dict[str, list[bool]] = {}
    for result in results:
        rule_id = result["expected_decision"]["rule_id"]
        rule_results.setdefault(rule_id, []).append(result["status"] == "PASS")
    inventory = [
        {
            "requirement_id": "P00",
            "status": "VERIFIED_IN_BOUNDED_DIAGNOSTIC",
            "reason_code": "FIXED_CASES_MATCHED",
        },
        {
            "requirement_id": "P01",
            "status": "VERIFIED_IN_BOUNDED_DIAGNOSTIC",
            "reason_code": "FIXED_CASES_MATCHED",
        },
        {
            "requirement_id": "P02",
            "status": "VERIFIED_IN_BOUNDED_DIAGNOSTIC",
            "reason_code": "FIXED_CASES_MATCHED",
        },
        {
            "requirement_id": "P03",
            "status": "VERIFIED_IN_BOUNDED_DIAGNOSTIC",
            "reason_code": "FIXED_CASES_MATCHED",
        },
        {
            "requirement_id": "P04",
            "status": "VERIFIED_IN_BOUNDED_DIAGNOSTIC",
            "reason_code": "SYNTHETIC_FIXTURE_ROUTE_ONLY",
        },
        {
            "requirement_id": "P06",
            "status": "VERIFIED_IN_BOUNDED_DIAGNOSTIC",
            "reason_code": "SYNTHETIC_PROPOSAL_ROUTES_ONLY",
        },
        {
            "requirement_id": "P09",
            "status": "VERIFIED_IN_BOUNDED_DIAGNOSTIC",
            "reason_code": "FIXED_BINDING_CASES_MATCHED",
        },
        {
            "requirement_id": "P12",
            "status": "NOT_EVALUATED",
            "reason_code": "UNREACHABLE_WITH_FIXED_TRUSTED_REGISTRY",
        },
        {
            "requirement_id": "P17",
            "status": "VERIFIED_IN_BOUNDED_DIAGNOSTIC",
            "reason_code": "FIXED_SECRET_DENIAL_CASES_MATCHED",
        },
        {
            "requirement_id": "P05_P07_P08_P10_P13_P14_P15_P16",
            "status": "NOT_IMPLEMENTED",
            "reason_code": "OUTSIDE_CURRENT_IMPLEMENTATION",
        },
        {
            "requirement_id": "P11",
            "status": "BLOCKED",
            "reason_code": "OWNER_VERIFICATION_UNAVAILABLE",
        },
        {
            "requirement_id": "F42_BLUEPRINT_48_SCENARIOS",
            "status": "NOT_IMPLEMENTED",
            "reason_code": "D0_IS_A_BOUNDED_DIAGNOSTIC",
        },
        {
            "requirement_id": "PRODUCTION_OWNER_VERIFICATION",
            "status": "BLOCKED",
            "reason_code": "NOT_AVAILABLE",
        },
        {
            "requirement_id": "WINDOWS_SERVICE_ISOLATION",
            "status": "BLOCKED",
            "reason_code": "LAB_ROOT_CAUSE_UNRESOLVED",
        },
    ]
    for item in inventory:
        rule_id = item["requirement_id"]
        if rule_id in rule_results and not all(rule_results[rule_id]):
            item["status"] = "FAILED_IN_BOUNDED_DIAGNOSTIC"
            item["reason_code"] = "DECISION_MISMATCH"
    return inventory


def _build_report() -> dict[str, Any]:
    manifest = validate_manifest_document(load_manifest_document())
    policy_digest = policy_sha256()
    registry_digest = builtin_registry_sha256()
    config_digest = config_sha256(load_bundled_defaults())
    expected_baseline = manifest["baseline"]
    if (
        policy_digest != expected_baseline["policy_sha256"]
        or registry_digest != expected_baseline["registry_sha256"]
        or config_digest != expected_baseline["config_sha256"]
    ):
        raise DiagnosticFailure("POLICY_FINGERPRINT_MISMATCH")

    oracle = _load_oracle()
    oracle_keys = set(oracle)
    scenarios = manifest["scenarios"]
    if any(item["oracle_case"] not in oracle_keys for item in scenarios):
        raise DiagnosticFailure("ORACLE_CASE_MISSING")

    with TemporaryDirectory(prefix="sentinel-f42-d0-") as temp_name:
        workspace = Path(temp_name)
        verified = _prepare_verified_fixture(workspace)
        before = _snapshot_workspace(workspace)
        inputs = _build_scenario_inputs(verified)
        results: list[dict[str, Any]] = []
        for scenario in scenarios:
            scenario_id = scenario["id"]
            oracle_case = scenario["oracle_case"]
            if oracle_case not in inputs:
                raise DiagnosticFailure("SCENARIO_UNAVAILABLE")
            request, context, binding = inputs[oracle_case]
            try:
                decision: PolicyDecision = evaluate_policy(
                    request=request,
                    context=context,
                    evidence_binding=binding,
                )
                actual = decision.model_dump(mode="json")
            except Exception:
                raise DiagnosticFailure("POLICY_EVALUATION_FAILED") from None
            expected = oracle[oracle_case]
            expected_projection = scenario["expected"]
            if _decision_projection(expected) != expected_projection:
                raise DiagnosticFailure("ORACLE_EXPECTATION_MISMATCH")
            passed = actual == expected
            results.append(
                {
                    "id": scenario_id,
                    "oracle_case": oracle_case,
                    "status": "PASS" if passed else "FAIL",
                    "expected_decision": expected,
                    "actual_decision": actual,
                }
            )
        after = _snapshot_workspace(workspace)
        if before != after:
            raise DiagnosticFailure("SYNTHETIC_WORKSPACE_MUTATED")
        fixture_binding = verified.binding
        fixture_summary = {
            "fixture_id": "example-owner/fixture-project",
            "fixture_version": fixture_binding.fixture_version,
            "fixture_sha256": fixture_binding.fixture_sha256,
            "manifest_version": fixture_binding.manifest_version,
            "manifest_sha256": fixture_binding.manifest_sha256,
            "source_set_sha256": fixture_binding.source_set_sha256,
            "source_count": len(fixture_binding.sources),
            "citation_count": sum(len(item.citations) for item in fixture_binding.sources),
            "sources": [
                {
                    "source_id": str(source.source_id),
                    "item_id": str(source.item_id),
                    "provider_item_id": source.provider_item_id,
                    "content_sha256": source.content_sha256,
                    "trust": source.trust.value,
                    "sensitivity": source.sensitivity.value,
                    "citations": [
                        {
                            "span_id": str(citation.span_id),
                            "start_byte": citation.start_byte,
                            "end_byte": citation.end_byte,
                            "text_sha256": citation.text_sha256,
                        }
                        for citation in source.citations
                    ],
                }
                for source in fixture_binding.sources
            ],
        }

    passed_count = sum(item["status"] == "PASS" for item in results)
    failed_count = len(results) - passed_count
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "manifest_version": manifest["manifest_version"],
        "manifest_sha256": PINNED_MANIFEST_SHA256,
        "decision_oracle_sha256": PINNED_ORACLE_SHA256,
        "policy_sha256": policy_digest,
        "registry_sha256": registry_digest,
        "config_version": CONFIG_SCHEMA_VERSION,
        "config_sha256": config_digest,
        "fixture": fixture_summary,
        "scenario_count": len(results),
        "scenarios": results,
        "coverage": _coverage_inventory(results),
        "summary": {"executed": len(results), "passed": passed_count, "failed": failed_count},
        "readiness": {
            "diagnostic_only": True,
            "complete_f42": False,
            "cr2_release_complete": False,
            "production_activation_eligible": False,
            "owner_verification_available": False,
            "os_isolation_verified": False,
            "external_effects_enabled": False,
        },
    }
    report["report_sha256"] = hashlib.sha256(
        REPORT_DOMAIN + canonical_json_bytes(report)
    ).hexdigest()
    return report


def run_diagnostic() -> dict[str, Any]:
    """Evaluate the fixed local cases and return a deterministic report object."""
    try:
        report = _build_report()
        if len(canonical_json_bytes(report)) > MAX_REPORT_BYTES:
            raise DiagnosticFailure("REPORT_TOO_LARGE")
        return report
    except DiagnosticFailure:
        raise
    except Exception:
        raise DiagnosticFailure("DIAGNOSTIC_INTERNAL_FAILURE") from None


def main(argv: Sequence[str] | None = None) -> int:
    """Write one complete report, or emit a fixed error with empty stdout."""
    try:
        if tuple(sys.argv[1:] if argv is None else argv):
            raise DiagnosticFailure("ARGUMENTS_UNSUPPORTED")
        report = run_diagnostic()
        encoded = canonical_json_bytes(report)
        if len(encoded) > MAX_REPORT_BYTES:
            raise DiagnosticFailure("REPORT_TOO_LARGE")
        sys.stdout.write(encoded.decode("utf-8", errors="strict") + "\n")
        return 0 if report["summary"]["failed"] == 0 else 1
    except DiagnosticFailure as exc:
        sys.stderr.write(f"F42_D0_FAILED {exc.code}\n")
        return 2
    except Exception:
        sys.stderr.write("F42_D0_FAILED DIAGNOSTIC_INTERNAL_FAILURE\n")
        return 2
