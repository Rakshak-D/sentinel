"""Package-resource and wheel package-data tests for the Gmail fixture."""

import hashlib
import importlib.resources
import tomllib
from pathlib import Path

from sentinel.readers import GMAIL_FIXTURE_SHA256


def test_fixture_resource_is_readable_outside_checkout_and_declared_as_package_data(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    resource = importlib.resources.files("sentinel.readers").joinpath(
        "fixtures", "gmail-messages-v1.json"
    )

    assert resource.is_file()
    raw = resource.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == GMAIL_FIXTURE_SHA256

    project = Path(__file__).resolve().parents[1]
    package_data = tomllib.loads((project / "pyproject.toml").read_text("utf-8"))[
        "tool"
    ]["setuptools"]["package-data"]
    assert package_data["sentinel.readers"] == ["fixtures/*.json"]
