"""Packaged demo-resource access and package-data configuration tests."""

import importlib.resources
import tomllib
from pathlib import Path


def test_fixture_is_a_package_resource_and_package_data_is_configured(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    resource = importlib.resources.files("sentinel.demo").joinpath(
        "fixtures", "demo-v1.json"
    )
    assert resource.is_file()
    assert resource.read_bytes().startswith(b"{")

    project = Path(__file__).resolve().parents[1]
    configuration = tomllib.loads((project / "pyproject.toml").read_text("utf-8"))
    package_data = configuration["tool"]["setuptools"]["package-data"]
    assert package_data["sentinel.demo"] == ["fixtures/*.json"]
