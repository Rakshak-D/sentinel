"""Citation tests assert byte offsets against the original UTF-8 payload."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID

import pytest

from sentinel.contracts.envelopes import ByteSpan
from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import (
    NormalizationError,
    NormalizationErrorCode,
    PlainTextSourceDescriptor,
    SourceBoundCitation,
    add_citation,
    bind_citation,
    normalize_plain_text,
    verify_bound_citation,
    verify_citation,
)

SOURCE_ID = UUID("36e2f511-a7b5-4e60-a147-c2d1e11a22d5")
SPAN_1 = UUID("1a1e8c19-1093-4cb5-a5d8-82b7e00e6d72")
SPAN_2 = UUID("70c21b75-1924-4a59-92e3-2a47504d5461")


def source(raw: bytes):
    descriptor = PlainTextSourceDescriptor(
        source_id=SOURCE_ID,
        provider_id="synthetic-reader",
        observed_at=datetime(2026, 11, 3, tzinfo=UTC),
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=SensitivityLabel.PUBLIC,
    )
    return normalize_plain_text(descriptor, raw, "text/plain; charset=utf-8")


def source_with_id(raw: bytes, source_id: UUID):
    descriptor = PlainTextSourceDescriptor(
        source_id=source_id,
        provider_id="synthetic-reader",
        observed_at=datetime(2026, 11, 3, tzinfo=UTC),
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=SensitivityLabel.PUBLIC,
    )
    return normalize_plain_text(descriptor, raw, "text/plain; charset=utf-8")


def test_ascii_citation_uses_explicit_half_open_byte_offsets() -> None:
    normalized = source(b"alpha beta")
    cited = add_citation(
        normalized, span_id=SPAN_1, start_byte=6, end_byte=10, expected_text="beta"
    )

    assert (cited.citations[0].start_byte, cited.citations[0].end_byte) == (6, 10)
    assert verify_citation(cited, cited.citations[0]) == "beta"


def test_multibyte_unicode_offsets_are_utf8_bytes_not_character_indexes() -> None:
    raw = "é🙂界".encode()
    normalized = source(raw)
    cited = add_citation(normalized, span_id=SPAN_1, start_byte=2, end_byte=6, expected_text="🙂")
    final = add_citation(cited, span_id=SPAN_2, start_byte=6, end_byte=9, expected_text="界")

    assert [(span.start_byte, span.end_byte) for span in final.citations] == [(2, 6), (6, 9)]
    assert verify_citation(final, final.citations[0]) == "🙂"
    assert verify_citation(final, final.citations[1]) == "界"


def test_crlf_and_lf_offsets_are_preserved_exactly() -> None:
    normalized = source(b"a\r\nb\nc")
    cited = add_citation(normalized, span_id=SPAN_1, start_byte=3, end_byte=4, expected_text="b")

    assert cited.text == "a\r\nb\nc"
    assert verify_citation(cited, cited.citations[0]) == "b"


def test_repeated_words_at_different_offsets_are_distinct_citations() -> None:
    normalized = source(b"go stop go")
    first = add_citation(normalized, span_id=SPAN_1, start_byte=0, end_byte=2, expected_text="go")
    both = add_citation(first, span_id=SPAN_2, start_byte=8, end_byte=10, expected_text="go")

    assert both.citations[0].span_id != both.citations[1].span_id
    assert both.citations[0].start_byte == 0
    assert both.citations[1].start_byte == 8
    assert all(verify_citation(both, span, expected_text="go") == "go" for span in both.citations)


@pytest.mark.parametrize(
    "start,end",
    [(-1, 1), (2, 2), (3, 2), (0, 11), (True, 2)],
)
def test_invalid_citation_offsets_are_rejected(start: int, end: int) -> None:
    with pytest.raises(NormalizationError):
        add_citation(source(b"abc"), span_id=SPAN_1, start_byte=start, end_byte=end)


@pytest.mark.parametrize("start,end", [(0, 1), (1, 2), (2, 3), (5, 6)])
def test_citation_may_not_split_utf8_code_points(start: int, end: int) -> None:
    with pytest.raises(NormalizationError) as error:
        add_citation(source("é🙂".encode()), span_id=SPAN_1, start_byte=start, end_byte=end)
    assert error.value.code is NormalizationErrorCode.INVALID_CITATION


def test_wrong_original_source_bytes_fail_the_source_digest_check() -> None:
    normalized = source(b"alpha beta")
    cited = add_citation(normalized, span_id=SPAN_1, start_byte=6, end_byte=10)

    with pytest.raises(NormalizationError) as error:
        verify_citation(cited, cited.citations[0], original_bytes=b"alpha zeta")
    assert error.value.code is NormalizationErrorCode.SOURCE_DIGEST_MISMATCH


def test_tampered_retained_source_bytes_fail_the_source_digest_check() -> None:
    normalized = add_citation(source(b"alpha beta"), span_id=SPAN_1, start_byte=6, end_byte=10)
    object.__setattr__(normalized, "_original_bytes", b"alpha zeta")

    with pytest.raises(NormalizationError) as error:
        verify_citation(normalized, normalized.citations[0])
    assert error.value.code is NormalizationErrorCode.SOURCE_DIGEST_MISMATCH


def test_modified_citation_digest_and_expected_text_fail_verification() -> None:
    normalized = source(b"alpha beta")
    cited = add_citation(normalized, span_id=SPAN_1, start_byte=6, end_byte=10)
    data = cited.citations[0].model_dump(mode="python")
    data["text_sha256"] = "0" * 64
    tampered_span = ByteSpan.model_validate(data)

    with pytest.raises(NormalizationError) as error:
        verify_citation(cited, tampered_span)
    assert error.value.code is NormalizationErrorCode.CITATION_SOURCE_MISMATCH
    with pytest.raises(NormalizationError) as mismatch:
        verify_citation(cited, cited.citations[0], expected_text="other")
    assert mismatch.value.code is NormalizationErrorCode.CITED_TEXT_MISMATCH


def test_invalid_span_identifier_is_rejected_without_echoing_input() -> None:
    with pytest.raises(NormalizationError):
        add_citation(source(b"abc"), span_id="bad-id", start_byte=0, end_byte=1)  # type: ignore[arg-type]


def test_citation_cannot_be_verified_against_another_source() -> None:
    first = add_citation(source(b"alpha"), span_id=SPAN_1, start_byte=0, end_byte=5)
    other = source(b"alpha")

    with pytest.raises(NormalizationError) as error:
        verify_citation(other, first.citations[0])
    assert error.value.code is NormalizationErrorCode.CITATION_SOURCE_MISMATCH


SOURCE_A_ID = UUID("08a35075-fc8f-4d7a-9825-b06c3704e9cb")
SOURCE_B_ID = UUID("6481174b-84cc-4f17-b57f-629822f857a4")
REUSED_SPAN_ID = UUID("f5ae0ef3-f695-47d8-9a94-33d109286628")


def test_pre_correction_unbound_span_is_interchangeable_across_equal_sources() -> None:
    source_a = add_citation(
        source_with_id(b"alpha", SOURCE_A_ID),
        span_id=REUSED_SPAN_ID,
        start_byte=0,
        end_byte=5,
    )
    source_b = add_citation(
        source_with_id(b"alpha", SOURCE_B_ID),
        span_id=REUSED_SPAN_ID,
        start_byte=0,
        end_byte=5,
    )

    assert source_a.envelope.source_id != source_b.envelope.source_id
    assert source_a.envelope.content_sha256 == source_b.envelope.content_sha256
    assert source_a.citations[0] == source_b.citations[0]
    assert verify_citation(source_b, source_a.citations[0]) == "alpha"


def test_bound_citation_preserves_source_digest_and_span_and_verifies() -> None:
    normalized = add_citation(
        source_with_id(b"alpha", SOURCE_A_ID),
        span_id=REUSED_SPAN_ID,
        start_byte=0,
        end_byte=5,
        expected_text="alpha",
    )
    citation = normalized.citations[0]

    bound = bind_citation(normalized, citation)

    assert bound.source_id == normalized.envelope.source_id
    assert bound.content_sha256 == normalized.envelope.content_sha256
    assert bound.span == citation
    assert bound.content_sha256 == hashlib.sha256(normalized.original_bytes).hexdigest()
    assert bound.span.text_sha256 == hashlib.sha256(
        normalized.original_bytes[bound.span.start_byte : bound.span.end_byte]
    ).hexdigest()
    assert verify_bound_citation(normalized, bound, expected_text="alpha") == "alpha"


@pytest.mark.parametrize(
    "raw,start,end,text",
    [
        (b"alpha beta", 6, 10, "beta"),
        ("é🙂界".encode(), 2, 6, "🙂"),
        (b"a\r\nb\nc", 3, 4, "b"),
    ],
)
def test_bound_citation_verifies_ascii_unicode_and_crlf_ranges(
    raw: bytes, start: int, end: int, text: str
) -> None:
    normalized = add_citation(
        source_with_id(raw, SOURCE_A_ID),
        span_id=SPAN_1,
        start_byte=start,
        end_byte=end,
        expected_text=text,
    )
    bound = bind_citation(normalized, normalized.citations[0])

    assert verify_bound_citation(normalized, bound, expected_text=text) == text


def test_bound_repeated_text_keeps_distinct_byte_ranges() -> None:
    normalized = source_with_id(b"go stop go", SOURCE_A_ID)
    first = add_citation(normalized, span_id=SPAN_1, start_byte=0, end_byte=2, expected_text="go")
    both = add_citation(first, span_id=SPAN_2, start_byte=8, end_byte=10, expected_text="go")
    bound = [bind_citation(both, span) for span in both.citations]

    assert [(item.span.start_byte, item.span.end_byte) for item in bound] == [(0, 2), (8, 10)]
    assert [verify_bound_citation(both, item) for item in bound] == ["go", "go"]


def test_cross_source_bound_citation_rejects_identical_content_and_span() -> None:
    source_a = add_citation(
        source_with_id(b"alpha", SOURCE_A_ID),
        span_id=REUSED_SPAN_ID,
        start_byte=0,
        end_byte=5,
    )
    source_b = add_citation(
        source_with_id(b"alpha", SOURCE_B_ID),
        span_id=REUSED_SPAN_ID,
        start_byte=0,
        end_byte=5,
    )
    bound_from_a = bind_citation(source_a, source_a.citations[0])

    with pytest.raises(NormalizationError) as error:
        verify_bound_citation(source_b, bound_from_a)
    assert error.value.code is NormalizationErrorCode.CITATION_SOURCE_MISMATCH


def test_same_source_id_with_different_content_digest_is_rejected() -> None:
    source_a = add_citation(
        source_with_id(b"alpha", SOURCE_A_ID),
        span_id=SPAN_1,
        start_byte=0,
        end_byte=5,
    )
    source_changed = add_citation(
        source_with_id(b"alpha!", SOURCE_A_ID),
        span_id=SPAN_1,
        start_byte=0,
        end_byte=5,
    )
    bound = bind_citation(source_a, source_a.citations[0])

    with pytest.raises(NormalizationError) as error:
        verify_bound_citation(source_changed, bound)
    assert error.value.code is NormalizationErrorCode.SOURCE_DIGEST_MISMATCH


def test_bound_verifier_rejects_wrong_or_altered_original_bytes() -> None:
    normalized = add_citation(
        source_with_id(b"alpha", SOURCE_A_ID),
        span_id=SPAN_1,
        start_byte=0,
        end_byte=5,
    )
    bound = bind_citation(normalized, normalized.citations[0])

    with pytest.raises(NormalizationError) as wrong_source:
        verify_bound_citation(normalized, bound, original_bytes=b"omega")
    assert wrong_source.value.code is NormalizationErrorCode.SOURCE_DIGEST_MISMATCH

    tampered = bound.model_copy(
        update={"span": bound.span.model_copy(update={"text_sha256": "0" * 64})}
    )
    with pytest.raises(NormalizationError):
        verify_bound_citation(normalized, tampered)


@pytest.mark.parametrize(
    "updates,expected_code",
    [
        ({"source_id": SOURCE_B_ID}, NormalizationErrorCode.CITATION_SOURCE_MISMATCH),
        ({"content_sha256": "0" * 64}, NormalizationErrorCode.SOURCE_DIGEST_MISMATCH),
    ],
)
def test_bound_verifier_revalidates_unchecked_model_copies(
    updates: dict[str, object], expected_code: NormalizationErrorCode
) -> None:
    normalized = add_citation(
        source_with_id(b"alpha", SOURCE_A_ID),
        span_id=SPAN_1,
        start_byte=0,
        end_byte=5,
    )
    bound = bind_citation(normalized, normalized.citations[0])
    tampered = bound.model_copy(update=updates)

    with pytest.raises(NormalizationError) as error:
        verify_bound_citation(normalized, tampered)
    assert error.value.code is expected_code


def test_bound_verifier_rejects_malformed_nested_span_and_expected_text() -> None:
    normalized = add_citation(
        source_with_id(b"alpha", SOURCE_A_ID),
        span_id=SPAN_1,
        start_byte=0,
        end_byte=5,
    )
    bound = bind_citation(normalized, normalized.citations[0])
    malformed_span = bound.span.model_copy(update={"start_byte": -1})
    malformed_bound = bound.model_copy(update={"span": malformed_span})

    with pytest.raises(NormalizationError):
        verify_bound_citation(normalized, malformed_bound)
    with pytest.raises(NormalizationError) as error:
        verify_bound_citation(normalized, bound, expected_text="omega")
    assert error.value.code is NormalizationErrorCode.CITED_TEXT_MISMATCH


def test_bound_reference_rejects_missing_unknown_and_malformed_fields() -> None:
    span = ByteSpan.model_validate(
        {
            "span_id": SPAN_1,
            "start_byte": 0,
            "end_byte": 5,
            "text_sha256": "2c1743a391305fbf367df8e4f069f9f9bdbbfd8d62f8f7f07e07a2c178a1e2e5",
        }
    )
    valid = {
        "source_id": SOURCE_A_ID,
        "content_sha256": "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8",
        "span": span,
    }

    with pytest.raises(ValueError):
        SourceBoundCitation(source_id=SOURCE_A_ID, span=span)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        SourceBoundCitation(**valid, unexpected="synthetic-extra-canary")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        SourceBoundCitation(**{**valid, "source_id": "bad-uuid"})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        SourceBoundCitation(**{**valid, "content_sha256": "bad-digest"})


def test_bound_reference_serialization_is_stable_and_contains_no_body() -> None:
    canary = "synthetic-private-source-canary"
    normalized = add_citation(
        source_with_id(canary.encode(), SOURCE_A_ID),
        span_id=SPAN_1,
        start_byte=0,
        end_byte=len(canary.encode()),
    )
    bound = bind_citation(normalized, normalized.citations[0])
    equivalent = type(bound).model_validate(
        {
            "span": bound.span.model_dump(mode="python"),
            "content_sha256": bound.content_sha256,
            "source_id": bound.source_id,
        }
    )

    assert bound.model_dump_json() == equivalent.model_dump_json()
    assert canary not in bound.model_dump_json()
    with pytest.raises(ValueError):
        bound.source_id = SOURCE_B_ID  # type: ignore[misc]
    with pytest.raises(ValueError):
        bound.span.start_byte = 1  # type: ignore[misc]


def test_bound_reference_validation_errors_do_not_expose_hostile_values() -> None:
    class Hostile:
        string_calls = 0
        repr_calls = 0

        def __str__(self) -> str:
            self.string_calls += 1
            raise AssertionError("__str__ must not be called")

        def __repr__(self) -> str:
            self.repr_calls += 1
            raise AssertionError("__repr__ must not be called")

    hostile = Hostile()
    with pytest.raises(ValueError) as error:
        SourceBoundCitation(source_id=SOURCE_A_ID, content_sha256=hostile, span=object())
    assert str(error.value) == "Source-bound citation is invalid."
    assert hostile.string_calls == 0
    assert hostile.repr_calls == 0


def test_unchecked_envelope_copy_is_revalidated_before_citation_verification() -> None:
    normalized = add_citation(source(b"alpha"), span_id=SPAN_1, start_byte=0, end_byte=5)
    malformed_envelope = normalized.envelope.model_copy(update={"content_sha256": "invalid"})
    object.__setattr__(normalized, "_envelope", malformed_envelope)

    with pytest.raises(NormalizationError) as error:
        verify_citation(normalized, normalized.citations[0])
    assert error.value.code is NormalizationErrorCode.INVALID_NORMALIZED_SOURCE
