"""Synthetic immutable Gmail message constructor for CR1-O tests only."""

from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import PlainTextSourceDescriptor, normalize_plain_text
from sentinel.readers.types import GmailFixtureMessage


def gmail_message(
    body: str,
    *,
    message_id: str = "test-alert-001",
    subject: str = "Unused subject",
) -> GmailFixtureMessage:
    raw = body.encode("utf-8", errors="strict")
    source_id = uuid5(NAMESPACE_URL, f"sentinel:gmail.fixture:synthetic-test#{message_id}")
    normalized = normalize_plain_text(
        PlainTextSourceDescriptor(
            source_id=source_id,
            provider_id="gmail.fixture",
            observed_at=datetime(2026, 11, 5, tzinfo=UTC),
            trust=TrustLabel.T4_EXTERNAL,
            sensitivity=SensitivityLabel.PRIVATE,
        ),
        raw,
        "text/plain; charset=utf-8",
    )
    return GmailFixtureMessage(
        mailbox_alias="synthetic-test",
        message_id=message_id,
        thread_id="thread-" + message_id,
        internal_date=datetime(2026, 11, 4, tzinfo=UTC),
        subject=subject,
        normalized_source=normalized,
        citations=(),
    )
