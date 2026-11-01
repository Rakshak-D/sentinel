"""Trust and sensitivity label contract tests using synthetic values only."""

import pytest
from pydantic import TypeAdapter, ValidationError

from sentinel.contracts.labels import SensitivityLabel, TrustLabel


def test_trust_labels_match_the_master_blueprint_exactly() -> None:
    assert [label.value for label in TrustLabel] == [
        "T0 POLICY",
        "T1 OWNER_INTENT",
        "T2 AUTH_METADATA",
        "T3 DERIVED",
        "T4 EXTERNAL",
        "T5 UNKNOWN",
    ]


@pytest.mark.parametrize("value", ["T6 TRUSTED", "OWNER_INTENT", "T1", "external"])
def test_unknown_trust_labels_are_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(TrustLabel).validate_python(value)


def test_sensitivity_labels_match_the_master_blueprint_exactly() -> None:
    assert [label.value for label in SensitivityLabel] == [
        "PUBLIC",
        "INTERNAL",
        "PRIVATE",
        "SECRET",
    ]


@pytest.mark.parametrize("value", ["UNKNOWN", "", None, "public"])
def test_unknown_sensitivity_is_rejected(value: object) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(SensitivityLabel).validate_python(value)
