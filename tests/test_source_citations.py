"""Citation tests assert byte offsets against the original UTF-8 payload."""

from datetime import UTC, datetime
from uuid import UUID

import pytest

from sentinel.contracts.envelopes import ByteSpan
from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import (
    NormalizationError,
    NormalizationErrorCode,
    PlainTextSourceDescriptor,
    add_citation,
    normalize_plain_text,
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


def test_unchecked_envelope_copy_is_revalidated_before_citation_verification() -> None:
    normalized = add_citation(source(b"alpha"), span_id=SPAN_1, start_byte=0, end_byte=5)
    malformed_envelope = normalized.envelope.model_copy(update={"content_sha256": "invalid"})
    object.__setattr__(normalized, "_envelope", malformed_envelope)

    with pytest.raises(NormalizationError) as error:
        verify_citation(normalized, normalized.citations[0])
    assert error.value.code is NormalizationErrorCode.INVALID_NORMALIZED_SOURCE
