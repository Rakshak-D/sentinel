"""Package resource and setuptools data configuration tests."""

import hashlib
import importlib.resources
import tomllib
from pathlib import Path

from sentinel.readers import FIXTURE_SHA256


def test_fixture_is_resource_accessible_outside_checkout_and_package_data_is_configured(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    resource = importlib.resources.files("sentinel.readers").joinpath(
        "fixtures", "github-issues-v1.json"
    )

    assert resource.is_file()
    raw = resource.read_bytes()
    assert raw.startswith(b"{")
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256

    project = Path(__file__).resolve().parents[1]
    configuration = tomllib.loads((project / "pyproject.toml").read_text("utf-8"))
    package_data = configuration["tool"]["setuptools"]["package-data"]
    assert package_data["sentinel.readers"] == ["fixtures/*.json"]
