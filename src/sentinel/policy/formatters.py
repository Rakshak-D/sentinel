"""Deterministic text and JSON presentations for read-only policy status."""

from __future__ import annotations

import json

from sentinel.policy.types import (
    Capability,
    PolicyStatusReport,
)

_CAPABILITY_LABELS: dict[Capability, str] = {
    Capability.C0_READ_PUBLIC: "Read public",
    Capability.C1_READ_PRIVATE: "Read private",
    Capability.C2_WRITE_LOCAL_PROPOSAL: "Write local proposal",
    Capability.C3_WRITE_LOCAL_ACCEPTED: "Write local accepted",
    Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB: "Write external draft/GitHub",
    Capability.C5_SEND_EXTERNAL_EMAIL: "Send external email",
    Capability.C6_ACCESS_SECRET: "Access secret",
}


def _validate_report(report: PolicyStatusReport) -> PolicyStatusReport:
    if type(report) is not PolicyStatusReport:
        raise TypeError("policy status formatter requires a validated status report")
    return PolicyStatusReport.model_validate(report.model_dump(mode="python"), strict=True)


def format_json_policy_status(report: PolicyStatusReport) -> str:
    """Return compact deterministic JSON without private request material."""
    validated = _validate_report(report)
    return json.dumps(
        validated.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def format_text_policy_status(report: PolicyStatusReport) -> str:
    """Return compact source-free policy status text."""
    validated = _validate_report(report)
    lines = [
        "Sentinel policy status",
        f"Schema: {validated.schema_version}",
        f"Policy: {validated.policy_id} ({validated.policy_version})",
        f"Policy SHA-256: {validated.policy_sha256}",
        f"Registry: {validated.registry_id} ({validated.registry_version})",
        f"Registry SHA-256: {validated.registry_sha256}",
        "Capabilities:",
    ]
    for item in validated.capabilities:
        state = "OFF" if item.registration_state.value == "OFF" else "DENY_ONLY"
        lines.append(
            f"  {item.capability_id.value}  {_CAPABILITY_LABELS[item.capability_id]}  {state}"
        )
    lines.extend(
        (
            "Active denial order: "
            + " -> ".join(rule.value for rule in validated.active_denial_rules),
            f"Default decision: {validated.default_outcome.value}",
            f"Approval verifier: {validated.approval_verifier}",
            f"Live effect execution: {validated.live_effect_execution}",
            f"Enforcement integration: {validated.enforcement_integration}",
            "Policy decisions are metadata only and never authorize execution.",
        )
    )
    return "\n".join(lines)


__all__ = ["format_json_policy_status", "format_text_policy_status"]
