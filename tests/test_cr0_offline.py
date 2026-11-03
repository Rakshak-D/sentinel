from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tools.verify_cr0_offline import OfflineVerificationError, install_offline


def _make_wheel(wheelhouse: Path) -> tuple[Path, str]:
    version = "1.0.0"
    dist_info = "sentinel-1.0.0.dist-info"
    files = {
        "sentinel/__init__.py": b"VALUE = 'installed-from-local-wheel'\n",
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            "Name: sentinel\n"
            f"Version: {version}\n"
            "Requires-Python: >=3.11\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: sentinel-test\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n\n"
        ),
    }
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for filename, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
        writer.writerow((filename, f"sha256={digest}", str(len(data))))
    writer.writerow((f"{dist_info}/RECORD", "", ""))
    files[f"{dist_info}/RECORD"] = record.getvalue().encode("utf-8")

    wheel = wheelhouse / "sentinel-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for filename, data in sorted(files.items()):
            info = zipfile.ZipInfo(filename, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    return wheel, digest


def _write_lock(path: Path, digest: str) -> None:
    path.write_text(
        f"sentinel==1.0.0 --hash=sha256:{digest}\n",
        encoding="utf-8",
    )


def _base_python() -> Path:
    executable = "python.exe" if os.name == "nt" else "python"
    path = Path(sys.base_prefix) / executable
    assert path.is_file(), f"expected base Python executable at {path}"
    return path


def test_offline_install_uses_local_hash_pinned_wheel_and_isolates_imports(
    tmp_path: Path,
) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _, digest = _make_wheel(wheelhouse)
    lock = tmp_path / "requirements.lock"
    _write_lock(lock, digest)

    installed = install_offline(_base_python(), wheelhouse, lock, tmp_path / "isolated-install")

    assert installed.python.is_file()
    assert installed.pip_version.startswith("pip ")
    probe = subprocess.run(
        [
            str(installed.python),
            "-c",
            "import sentinel; print(sentinel.VALUE); print(sentinel.__file__)",
        ],
        cwd=installed.root / "work",
        check=True,
        capture_output=True,
        text=True,
    )
    assert probe.stdout.splitlines()[0] == "installed-from-local-wheel"
    assert Path(probe.stdout.splitlines()[1]).resolve().is_relative_to(installed.root.resolve())
    assert Path(probe.stdout.splitlines()[1]).resolve() == installed.installed_location.resolve()


def test_offline_install_fails_when_required_wheel_is_missing(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "empty-wheelhouse"
    wheelhouse.mkdir()
    lock = tmp_path / "requirements.lock"
    _write_lock(lock, "0" * 64)

    with pytest.raises(OfflineVerificationError, match="No matching distribution") as exc_info:
        install_offline(_base_python(), wheelhouse, lock, tmp_path / "missing-install")

    assert "No matching distribution" in str(exc_info.value)


def test_offline_install_rejects_tampered_wheel_hash(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel, digest = _make_wheel(wheelhouse)
    _write_lock(tmp_path / "requirements.lock", digest)
    wheel.write_bytes(wheel.read_bytes() + b"tampered")

    with pytest.raises(OfflineVerificationError, match="hash mismatch") as exc_info:
        install_offline(
            _base_python(),
            wheelhouse,
            tmp_path / "requirements.lock",
            tmp_path / "tampered-install",
        )

    assert "hash" in str(exc_info.value).lower()


def test_offline_install_rejects_invalid_pinned_hash(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _make_wheel(wheelhouse)
    _write_lock(tmp_path / "requirements.lock", "0" * 64)

    with pytest.raises(OfflineVerificationError, match="hash mismatch") as exc_info:
        install_offline(
            _base_python(),
            wheelhouse,
            tmp_path / "requirements.lock",
            tmp_path / "bad-lock-install",
        )

    assert "hash" in str(exc_info.value).lower()
