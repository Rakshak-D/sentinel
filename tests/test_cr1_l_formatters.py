import json
from dataclasses import replace
from uuid import UUID

from sentinel.overview import (
    LocalOverviewTask,
    build_local_overview,
    format_json_local_overview,
    format_text_local_overview,
)
from sentinel.tasks.types import TaskStatus
from tests.cr1_l_support import AS_OF, overview_case


def test_task_title_controls_and_bidi_marks_are_escaped_in_both_formats(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="format-controls")
    overview = build_local_overview(database, store_root=store_root, as_of=AS_OF)
    original = overview.task_sections[3]
    hostile = LocalOverviewTask(
        task_id=UUID("14172fa3-efde-5596-9b22-32d93d73bbbd"),
        title="quote\" slash\\ CR\r LF\n tab\t NUL\x00 ESC\x1b BEL\x07 bidi\u202e end",
        status=TaskStatus.OPEN,
        revision=1,
        due_at=None,
        created_at=AS_OF,
        completed_at=None,
    )
    sections = list(overview.task_sections)
    sections[3] = replace(original, tasks=(hostile,))
    modified = replace(overview, task_sections=tuple(sections))

    text = format_text_local_overview(modified)
    encoded = format_json_local_overview(modified)
    title = json.loads(encoded)["task_sections"][3]["tasks"][0]["title"]

    assert 'CR\\r LF\\n tab\\t NUL\\x00 ESC\\x1b BEL\\x07 bidi\\u202e end' in text
    assert "\x1b" not in text and "\x07" not in text and "\x00" not in text
    assert r"\u202e" in text
    assert "\x1b" not in title and "\x07" not in title and "\x00" not in title
    assert r"\r" in title and r"\n" in title and r"\u202e" in title
    assert "ignore prior instructions" in text


def test_json_preserves_existing_evidence_contract_and_deterministic_counts(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="json-evidence")
    overview = build_local_overview(database, store_root=store_root, as_of=AS_OF)

    first = format_json_local_overview(overview)
    second = format_json_local_overview(overview)
    document = json.loads(first)

    assert first == second
    assert (
        document["synthetic_evidence"]["schema_version"]
        == "sentinel.synthetic-evidence-brief.v1"
    )
    assert document["synthetic_evidence"]["item_count"] == 3
    assert document["synthetic_evidence"]["citation_count"] == 9
    assert [len(item["citations"]) for item in document["synthetic_evidence"]["items"]] == [5, 3, 1]
    assert "database" not in first.lower()
    assert "store_root" not in first.lower()
