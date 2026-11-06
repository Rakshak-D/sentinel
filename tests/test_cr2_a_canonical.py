import hashlib
import json

from cr2_a_policy_cases import make_request, make_source

from sentinel.policy import (
    BUILTIN_REGISTRY,
    build_policy_context,
    builtin_registry_sha256,
    canonical_policy_bytes,
    evaluate_policy,
    policy_sha256,
    registration_sha256,
    registry_sha256,
    request_sha256,
)


def test_canonical_request_serialization_is_stable_utf8_and_versioned() -> None:
    request = make_request()
    encoded = canonical_policy_bytes(request)
    assert encoded == canonical_policy_bytes(request)
    assert encoded.startswith(b'{"arguments":')
    assert b'"schema_version":"sentinel.policy-request.v2"' in encoded
    assert json.loads(encoded.decode("utf-8"))["operation_id"] == "sentinel.synthetic.read.public"
    assert request_sha256(request) == request_sha256(request)
    assert len(request_sha256(request)) == 64


def test_policy_and_registry_digests_are_domain_separated_and_stable() -> None:
    registration = BUILTIN_REGISTRY.entries[0]
    expected_registry = hashlib.sha256(
        b"sentinel.capability-registry.v2\x00" + canonical_policy_bytes(BUILTIN_REGISTRY)
    ).hexdigest()
    expected_registration = hashlib.sha256(
        b"sentinel.capability-registration.v1\x00" + canonical_policy_bytes(registration)
    ).hexdigest()
    assert registry_sha256(BUILTIN_REGISTRY) == expected_registry
    assert builtin_registry_sha256() == expected_registry
    assert registration_sha256(registration) == expected_registration
    assert policy_sha256() == policy_sha256()
    assert len(policy_sha256()) == 64


def test_policy_canonicalization_excludes_clock_and_repeated_decisions_are_stable() -> None:
    source_a = make_source()
    source_b = make_source(observed_at=source_a.observed_at.replace(year=2027))
    request = make_request(source=source_a)
    context_a = build_policy_context(sources=(source_a,))
    context_b = build_policy_context(sources=(source_b,))
    first = evaluate_policy(request=request, context=context_a)
    second = evaluate_policy(request=request, context=context_b)
    assert first == second
    assert first.outcome.value == "DENY"
    assert first.request_sha256 == request_sha256(request)
