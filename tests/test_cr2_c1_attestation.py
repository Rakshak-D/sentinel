from __future__ import annotations

from copy import deepcopy
from uuid import NAMESPACE_URL, uuid5

import pytest
from pydantic import ValidationError

from sentinel.proposals.formatters import (
    format_json_proposal_preview,
    format_text_proposal_preview,
)
from sentinel.proposals.preview import build_github_issue_proposal_preview
from sentinel.proposals.types import SyntheticProposalPreview
from tests.test_cr1_i_support import promoted_case


@pytest.fixture
def verified_preview(tmp_path) -> SyntheticProposalPreview:
    database, store_root = promoted_case(tmp_path, name="cr2-c1-attestation")
    return build_github_issue_proposal_preview(
        database,
        store_root=store_root,
        issue_number=101,
    )


def _assert_both_formatters_reject(preview: SyntheticProposalPreview) -> None:
    accepted: list[str] = []
    for formatter in (format_json_proposal_preview, format_text_proposal_preview):
        try:
            formatter(preview)
        except ValueError as error:
            assert "verified preview" in str(error)
        else:
            accepted.append(formatter.__name__)
    assert not accepted, f"formatters accepted an unverified preview: {accepted}"


def test_legitimate_preview_still_formats(verified_preview: SyntheticProposalPreview) -> None:
    assert '"status":"PREVIEW_ONLY"' in format_json_proposal_preview(verified_preview)
    assert "Synthetic GitHub proposal preview" in format_text_proposal_preview(verified_preview)


@pytest.mark.parametrize(
    "field_name",
    [
        "source_content_sha256",
        "preview_id",
        "source_item_id",
        "evidence_span_ids",
        "policy_request_sha256",
        "policy_sha256",
        "registry_sha256",
    ],
)
def test_model_copy_update_cannot_retain_formatter_eligibility(
    verified_preview: SyntheticProposalPreview,
    field_name: str,
) -> None:
    current = getattr(verified_preview, field_name)
    if field_name.endswith("sha256") or field_name == "preview_id":
        replacement = "f" * 64 if current != "f" * 64 else "e" * 64
    elif field_name == "source_item_id":
        replacement = uuid5(NAMESPACE_URL, "cr2-c1-replaced-source")
    else:
        replacement = (uuid5(NAMESPACE_URL, "cr2-c1-replaced-span"), *current[1:])

    altered = verified_preview.model_copy(update={field_name: replacement})
    _assert_both_formatters_reject(altered)


def test_plain_model_copy_and_deepcopy_are_not_verified(
    verified_preview: SyntheticProposalPreview,
) -> None:
    _assert_both_formatters_reject(verified_preview.model_copy())
    _assert_both_formatters_reject(deepcopy(verified_preview))


def test_model_reconstruction_and_fabricated_private_attribute_are_not_verified(
    verified_preview: SyntheticProposalPreview,
) -> None:
    fields = verified_preview.model_dump(mode="python")
    reconstructed = SyntheticProposalPreview.model_validate(fields, strict=True)
    _assert_both_formatters_reject(reconstructed)

    constructed = SyntheticProposalPreview.model_construct(**fields)
    _assert_both_formatters_reject(constructed)

    forged = SyntheticProposalPreview.model_construct(**fields)
    forged._verification_attestation = object()
    _assert_both_formatters_reject(forged)

    copied_attestation = SyntheticProposalPreview.model_construct(**fields)
    copied_attestation._verification_attestation = verified_preview._verification_attestation
    _assert_both_formatters_reject(copied_attestation)

    directly_constructed = SyntheticProposalPreview(**fields)
    _assert_both_formatters_reject(directly_constructed)

    with pytest.raises(ValidationError):
        SyntheticProposalPreview(**fields, _verification_attestation=object())


def test_low_level_mutation_of_original_fails_integrity_check(
    verified_preview: SyntheticProposalPreview,
) -> None:
    replacement = "f" * 64 if verified_preview.source_content_sha256 != "f" * 64 else "e" * 64
    object.__setattr__(verified_preview, "source_content_sha256", replacement)
    _assert_both_formatters_reject(verified_preview)
