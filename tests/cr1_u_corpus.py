"""Hash-pinned CR1-U fictional evaluation corpus and labels."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

CORPUS_DIRECTORY = Path(__file__).parent / "fixtures" / "cr1_u"
CORPUS_SHA256 = {
    "development": "13e4374e7cee04a1d08d9987376dc6d764eb737b63f1965ca756964fa0e820b5",
    "holdout": "645bdaf8a2725e4228de49490b568ef92bcc37b4352b73e8ff3d439d026d47ba",
}
EXPECTED_LABELS_SHA256 = "482008fb933808175d4ab1847d6c055b772dcb7a13abc388b2f941dabcbc2e79"
CORPUS_SCHEMA_VERSION = "sentinel.job-alert-triage-evaluation-corpus.v1"
LABEL_SCHEMA_VERSION = "sentinel.job-alert-triage-label-manifest.v1"
EVALUATION_VERSION = "cr1-u-job-alert-triage-v1"


def _read_pinned_json(path: Path, expected_sha256: str) -> dict[str, Any]:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise AssertionError(f"pinned CR1-U evaluation resource changed: {path.name}")
    value = json.loads(raw.decode("utf-8", errors="strict"))
    if type(value) is not dict:
        raise AssertionError("pinned CR1-U evaluation resource is invalid")
    return value


def load_cr1_u_corpus() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest = _read_pinned_json(
        CORPUS_DIRECTORY / "expected-labels-v1.json", EXPECTED_LABELS_SHA256
    )
    if (
        manifest.get("schema_version") != LABEL_SCHEMA_VERSION
        or manifest.get("corpus_schema_version") != CORPUS_SCHEMA_VERSION
        or manifest.get("evaluation_version") != EVALUATION_VERSION
    ):
        raise AssertionError("pinned CR1-U evaluation manifest has an unsupported version")
    datasets: dict[str, dict[str, Any]] = {}
    for dataset_name in ("development", "holdout"):
        corpus = _read_pinned_json(
            CORPUS_DIRECTORY / f"{dataset_name}-v1.json", CORPUS_SHA256[dataset_name]
        )
        if (
            corpus.get("schema_version") != CORPUS_SCHEMA_VERSION
            or corpus.get("dataset_id") != dataset_name
            or type(corpus.get("cases")) is not list
        ):
            raise AssertionError("pinned CR1-U case corpus has an unsupported shape")
        cases = corpus["cases"]
        labels = manifest.get(dataset_name)
        if (
            type(labels) is not list
            or len(cases) != len(labels)
            or len({case.get("case_id") for case in cases if type(case) is dict}) != len(cases)
            or [case.get("case_id") for case in cases] != [label.get("case_id") for label in labels]
        ):
            raise AssertionError("pinned CR1-U labels do not match the ordered cases")
        datasets[dataset_name] = corpus
    if len(datasets["development"]["cases"]) != 24 or len(datasets["holdout"]["cases"]) != 30:
        raise AssertionError("pinned CR1-U evaluation case counts changed")
    return datasets["development"], datasets["holdout"], manifest


def decode_corpus_case(case: dict[str, Any]) -> bytes:
    spec = case["input"]
    if type(spec) is not dict:
        raise AssertionError("corpus input specification is invalid")
    encoding = spec.get("encoding")
    if encoding == "utf8":
        body = spec.get("body")
        if type(body) is not str:
            raise AssertionError("UTF-8 corpus body is invalid")
        return body.encode("utf-8", errors="strict")
    if encoding == "base64":
        data = spec.get("data")
        if type(data) is not str:
            raise AssertionError("base64 corpus body is invalid")
        return base64.b64decode(data, validate=True)
    if encoding == "repeat_ascii":
        prefix, character, count, suffix = (
            spec.get("prefix"),
            spec.get("character"),
            spec.get("count"),
            spec.get("suffix"),
        )
        if (
            type(prefix) is not str
            or type(character) is not str
            or len(character) != 1
            or type(count) is not int
            or type(suffix) is not str
            or not character.isascii()
        ):
            raise AssertionError("repeat corpus body is invalid")
        return (prefix + character * count + suffix).encode("ascii", errors="strict")
    if encoding == "repeat_line":
        line, count = spec.get("line"), spec.get("count")
        if type(line) is not str or type(count) is not int:
            raise AssertionError("repeat-line corpus body is invalid")
        return (line * count).encode("utf-8", errors="strict")
    raise AssertionError("unknown pinned corpus encoding")
