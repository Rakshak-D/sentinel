"""Install and smoke-test Sentinel from a hash-pinned local Windows wheelhouse."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FOUNDATION_MIGRATION_ID = "cr0-c-0001-schema-migrations"
FOUNDATION_ARTIFACT_SHA256 = "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217"
_REQUIREMENT_PATTERN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)"
    r"\s+(--hash=sha256:[0-9a-f]{64}(?:\s+--hash=sha256:[0-9a-f]{64})*)$"
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class OfflineVerificationError(RuntimeError):
    """A bounded verification failure, with subprocess output when useful."""


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    hashes: tuple[str, ...]


@dataclass(frozen=True)
class InstalledEnvironment:
    root: Path
    venv: Path
    python: Path
    work_directory: Path
    pip_version: str
    bootstrap_packages: tuple[str, ...]
    installed_packages: tuple[str, ...]
    python_identity: str
    installed_location: Path
    pip_install_output: str
    pip_check_output: str
    artifact_inventory: tuple[str, ...]


def _normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _validate_external_path(path: Path, label: str, *, must_exist: bool) -> Path:
    resolved = path.resolve(strict=must_exist)
    if _is_within(resolved, REPOSITORY_ROOT):
        raise OfflineVerificationError(f"{label} must be outside the source checkout")
    return resolved


def _parse_requirements(path: Path) -> tuple[LockedRequirement, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        raise OfflineVerificationError("requirements lock is unavailable or invalid") from None

    requirements: list[LockedRequirement] = []
    seen_names: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _REQUIREMENT_PATTERN.fullmatch(stripped)
        if match is None:
            raise OfflineVerificationError(
                f"requirements lock line {line_number} must use an exact pin and SHA-256 hash"
            )
        name, version, hash_text = match.groups()
        canonical_name = _normalized_name(name)
        if canonical_name in seen_names:
            raise OfflineVerificationError("requirements lock contains a duplicate package")
        seen_names.add(canonical_name)
        hashes = tuple(item.removeprefix("--hash=sha256:") for item in hash_text.split())
        if any(_SHA256_PATTERN.fullmatch(value) is None for value in hashes):
            raise OfflineVerificationError("requirements lock contains an invalid SHA-256 hash")
        requirements.append(LockedRequirement(name, version, hashes))
    if not requirements:
        raise OfflineVerificationError("requirements lock contains no package pins")
    return tuple(requirements)


def _clean_environment() -> dict[str, str]:
    env = os.environ.copy()
    sensitive_fragments = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH", "COOKIE")
    for key in tuple(env):
        upper_key = key.upper()
        if (
            upper_key.startswith("PIP_")
            or upper_key in {"PYTHONHOME", "PYTHONPATH"}
            or any(fragment in upper_key for fragment in sensitive_fragments)
        ):
            env.pop(key, None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONSAFEPATH"] = "1"
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_NO_INDEX"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    label: str,
    timeout: int = 300,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise OfflineVerificationError(f"{label} could not be completed") from None


def _output(result: subprocess.CompletedProcess[bytes]) -> str:
    return (result.stdout + result.stderr).decode("utf-8", errors="replace")


def _require_success(
    result: subprocess.CompletedProcess[bytes], label: str
) -> subprocess.CompletedProcess[bytes]:
    if result.returncode != 0:
        raise OfflineVerificationError(
            f"{label} failed with exit code {result.returncode}:\n{_output(result)}"
        )
    return result


def _python_identity(python_exe: Path, *, cwd: Path, env: dict[str, str]) -> dict[str, str]:
    code = (
        "import json, platform, sys; "
        "print(json.dumps({'implementation':sys.implementation.name,'version':platform.python_version(),"
        "'platform':sys.platform,'machine':platform.machine(),'prefix':sys.prefix,"
        "'base_prefix':sys.base_prefix}))"
    )
    result = _require_success(
        _run([str(python_exe), "-c", code], cwd=cwd, env=env, label="Python version check"),
        "Python version check",
    )
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise OfflineVerificationError("Python version check returned invalid data") from None
    if type(payload) is not dict or any(type(value) is not str for value in payload.values()):
        raise OfflineVerificationError("Python version check returned invalid data")
    identity = {str(key): str(value) for key, value in payload.items()}
    if (
        identity.get("implementation") != "cpython"
        or identity.get("version") != "3.11.7"
        or identity.get("platform") != "win32"
        or identity.get("machine", "").lower() not in {"amd64", "x86_64"}
        or identity.get("prefix") != identity.get("base_prefix")
    ):
        raise OfflineVerificationError(
            "base interpreter must be a non-venv CPython 3.11.7 Windows x64 installation"
        )
    return identity


def _inspect_wheelhouse(
    wheel_dir: Path,
    requirements: tuple[LockedRequirement, ...],
) -> tuple[str, ...]:
    expected = {_normalized_name(item.name): item for item in requirements}
    artifacts: dict[str, tuple[str, str, str, Path, tuple[str, ...], Message]] = {}
    entries = tuple(wheel_dir.iterdir())
    wheel_files = tuple(
        sorted(path for path in entries if path.is_file() and path.suffix.lower() == ".whl")
    )
    if len(wheel_files) != len(entries):
        raise OfflineVerificationError("wheelhouse must contain only the locked wheel artifacts")

    for wheel in wheel_files:
        try:
            with zipfile.ZipFile(wheel) as archive:
                names = tuple(archive.namelist())
                metadata_files = [name for name in names if name.endswith(".dist-info/METADATA")]
                if len(metadata_files) != 1:
                    raise OfflineVerificationError("wheel metadata is missing or ambiguous")
                metadata = BytesParser().parsebytes(archive.read(metadata_files[0]))
                package_name = metadata.get("Name")
                package_version = metadata.get("Version")
                if not package_name or not package_version:
                    raise OfflineVerificationError("wheel metadata has no package name or version")
                normalized = _normalized_name(package_name)
                if normalized in artifacts:
                    raise OfflineVerificationError(
                        "wheelhouse has multiple artifacts for one package"
                    )
                if any(name.lower().endswith(".pth") for name in names):
                    raise OfflineVerificationError(
                        "wheelhouse contains a Python path-injection file"
                    )
                digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
                artifacts[normalized] = (
                    package_name,
                    package_version,
                    digest,
                    wheel,
                    names,
                    metadata,
                )
        except (OSError, zipfile.BadZipFile, KeyError):
            raise OfflineVerificationError(
                "wheelhouse contains an unreadable wheel artifact"
            ) from None

    inventory: list[str] = []
    for normalized, lock_item in expected.items():
        artifact = artifacts.get(normalized)
        if artifact is None:
            raise OfflineVerificationError(
                f"No matching distribution for locked package {lock_item.name}"
            )
        package_name, version, digest, _, _, _ = artifact
        if version != lock_item.version:
            raise OfflineVerificationError(
                f"wheel version does not match the exact pin for {lock_item.name}"
            )
        if digest not in lock_item.hashes:
            raise OfflineVerificationError(
                f"SHA-256 artifact hash mismatch for {lock_item.name}=={lock_item.version}"
            )
        inventory.append(f"{package_name}=={version} sha256:{digest} ({artifact[3].name})")

    if set(artifacts) != set(expected):
        raise OfflineVerificationError("wheelhouse contains an artifact absent from the lock")

    sentinel = artifacts.get("sentinel")
    if sentinel is not None and sentinel[1] == "0.1.0":
        required_contents = {
            "sentinel/__init__.py",
            "sentinel/cli.py",
            "sentinel/config/__init__.py",
            "sentinel/config/defaults.py",
            "sentinel/config/fingerprint.py",
            "sentinel/config/schema.py",
            "sentinel/storage/__init__.py",
            "sentinel/storage/connection.py",
            "sentinel/storage/migrations.py",
            "sentinel/storage/schema.py",
            "sentinel/observability/__init__.py",
            "sentinel/observability/events.py",
            "sentinel/observability/logging.py",
            "sentinel/credentials/__init__.py",
            "sentinel/credentials/backends.py",
            "sentinel/credentials/broker.py",
            "sentinel/credentials/types.py",
            "sentinel/gateways/__init__.py",
            "sentinel/gateways/model.py",
            "sentinel/gateways/registry.py",
            "sentinel/gateways/tool.py",
            "sentinel/gateways/types.py",
            "sentinel/bootstrap/__init__.py",
            "sentinel/bootstrap/init.py",
            "sentinel/bootstrap/doctor.py",
            "sentinel/demo/__init__.py",
            "sentinel/demo/runner.py",
            "sentinel/demo/fixtures/demo-v1.json",
        }
        if not required_contents.issubset(set(sentinel[4])):
            raise OfflineVerificationError(
                "Sentinel wheel is missing required modules or the demo fixture"
            )
        entry_point_files = [
            name for name in sentinel[4] if name.endswith(".dist-info/entry_points.txt")
        ]
        if len(entry_point_files) != 1:
            raise OfflineVerificationError("Sentinel wheel console entry point metadata is missing")
        try:
            with zipfile.ZipFile(sentinel[3]) as archive:
                entry_points = archive.read(entry_point_files[0]).decode("utf-8")
        except (OSError, UnicodeError, zipfile.BadZipFile, KeyError):
            raise OfflineVerificationError(
                "Sentinel wheel entry point metadata is invalid"
            ) from None
        if (
            "[console_scripts]" not in entry_points
            or "sentinel = sentinel.cli:app" not in entry_points
        ):
            raise OfflineVerificationError("Sentinel wheel console entry point is invalid")
        metadata = sentinel[5]
        if metadata.get("Requires-Python") != "<3.12,>=3.11":
            raise OfflineVerificationError(
                "Sentinel wheel Python compatibility metadata is unexpected"
            )
        dependencies = set(metadata.get_all("Requires-Dist", []))
        if not {"pydantic<3,>=2", "typer<1.0,>=0.12"}.issubset(dependencies):
            raise OfflineVerificationError(
                "Sentinel wheel runtime dependency metadata is incomplete"
            )

    pydantic_core = artifacts.get("pydantic-core")
    if pydantic_core is not None and not pydantic_core[3].name.endswith(
        "-cp311-cp311-win_amd64.whl"
    ):
        raise OfflineVerificationError(
            "pydantic-core wheel does not target CPython 3.11 Windows x64"
        )

    return tuple(sorted(inventory, key=lambda row: row.split("==", 1)[0].lower()))


def _installed_location(python: Path, *, cwd: Path, env: dict[str, str], venv: Path) -> Path:
    repo_literal = json.dumps(str(REPOSITORY_ROOT.resolve()))
    code = (
        "import importlib, json, os, site, sys; from pathlib import Path; "
        "import importlib.metadata as md; "
        "repo=Path(" + repo_literal + ").resolve(); "
        "direct=md.distribution('sentinel').read_text('direct_url.json'); "
        "assert direct is None or not json.loads(direct).get('dir_info',{}).get('editable',False); "
        "assert direct is None or str(repo).casefold() not in direct.casefold(); "
        "module=importlib.import_module('sentinel'); "
        "origin=Path(module.__file__).resolve(); "
        "sites=[Path(p).resolve() for p in site.getsitepackages()]; "
        "sys_paths=[Path(p or os.getcwd()).resolve() for p in sys.path]; "
        "assert any(origin == p or p in origin.parents for p in sites); "
        "assert all(not (p == repo or repo in p.parents) for p in sys_paths); "
        "print(json.dumps({'origin':str(origin)}))"
    )
    result = _require_success(
        _run([str(python), "-c", code], cwd=cwd, env=env, label="installed import isolation check"),
        "installed import isolation check",
    )
    try:
        origin = Path(json.loads(result.stdout.decode("utf-8"))["origin"]).resolve()
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        raise OfflineVerificationError(
            "installed import isolation check returned invalid data"
        ) from None
    if not _is_within(origin, venv):
        raise OfflineVerificationError("Sentinel did not import from the disposable environment")

    site_packages = next(
        (candidate for candidate in (venv / "Lib" / "site-packages",) if candidate.is_dir()),
        None,
    )
    if site_packages is None:
        raise OfflineVerificationError("disposable environment has no Windows site-packages")
    for pth_file in site_packages.glob("*.pth"):
        try:
            contents = pth_file.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            raise OfflineVerificationError(
                "site-packages path configuration could not be inspected"
            ) from None
        if str(REPOSITORY_ROOT.resolve()).casefold() in contents.casefold():
            raise OfflineVerificationError("site-packages contains a source-checkout path link")
    return origin


def _installed_distributions(
    python: Path,
    *,
    cwd: Path,
    env: dict[str, str],
    requirements: tuple[LockedRequirement, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    result = _require_success(
        _run(
            [str(python), "-m", "pip", "list", "--format=json"],
            cwd=cwd,
            env=env,
            label="installed package inventory check",
        ),
        "installed package inventory check",
    )
    try:
        installed = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OfflineVerificationError("installed package inventory is invalid") from None
    if type(installed) is not list:
        raise OfflineVerificationError("installed package inventory is invalid")

    actual: dict[str, tuple[str, str]] = {}
    for item in installed:
        if (
            type(item) is not dict
            or type(item.get("name")) is not str
            or type(item.get("version")) is not str
        ):
            raise OfflineVerificationError("installed package inventory is invalid")
        actual[_normalized_name(item["name"])] = (item["name"], item["version"])

    expected = {_normalized_name(item.name): item for item in requirements}
    for normalized, lock_item in expected.items():
        if normalized not in actual or actual[normalized][1] != lock_item.version:
            raise OfflineVerificationError("installed package versions do not match the lock")

    bootstrap = tuple(
        f"{name}=={version}"
        for normalized, (name, version) in sorted(actual.items())
        if normalized in {"pip", "setuptools"}
    )
    unexpected = set(actual) - set(expected) - {"pip", "setuptools"}
    if unexpected:
        raise OfflineVerificationError(
            "unexpected packages are installed in the disposable environment"
        )
    locked_versions = tuple(f"{actual[name][0]}=={actual[name][1]}" for name in sorted(expected))
    return bootstrap, locked_versions


def install_offline(
    python_exe: Path,
    wheelhouse: Path,
    requirements: Path,
    install_root: Path,
) -> InstalledEnvironment:
    """Create a fresh Windows CPython 3.11.7 venv and install a strict wheel lock."""

    base_python = _validate_external_path(Path(python_exe), "Python executable", must_exist=True)
    wheel_dir = _validate_external_path(Path(wheelhouse), "wheelhouse", must_exist=True)
    lock_path = Path(requirements).resolve(strict=True)
    if not base_python.is_file() or not wheel_dir.is_dir() or not lock_path.is_file():
        raise OfflineVerificationError("Python executable, wheelhouse, or lock is invalid")
    requirements_list = _parse_requirements(lock_path)
    artifact_inventory = _inspect_wheelhouse(wheel_dir, requirements_list)

    install_path = Path(install_root).resolve()
    if _is_within(install_path, REPOSITORY_ROOT):
        raise OfflineVerificationError("installation root must be outside the source checkout")
    if install_path.exists():
        raise OfflineVerificationError("installation root must be a new disposable path")
    if not install_path.parent.is_dir():
        raise OfflineVerificationError("installation root parent must already exist")

    env = _clean_environment()
    identity = _python_identity(base_python, cwd=install_path.parent, env=env)
    install_path.mkdir()
    work_directory = install_path / "work"
    work_directory.mkdir()
    venv_path = install_path / "venv"
    create_venv = _run(
        [str(base_python), "-m", "venv", "--without-pip", str(venv_path)],
        cwd=work_directory,
        env=env,
        label="fresh virtual environment creation",
    )
    _require_success(create_venv, "fresh virtual environment creation")
    venv_python = venv_path / "Scripts" / "python.exe"

    ensure_pip = _run(
        [str(venv_python), "-m", "ensurepip", "--default-pip"],
        cwd=work_directory,
        env=env,
        label="local ensurepip bootstrap",
    )
    _require_success(ensure_pip, "local ensurepip bootstrap")

    pip_version_result = _require_success(
        _run(
            [str(venv_python), "-m", "pip", "--version"],
            cwd=work_directory,
            env=env,
            label="isolated pip version check",
        ),
        "isolated pip version check",
    )
    pip_version_output = pip_version_result.stdout.decode("utf-8", errors="replace").strip()
    version_match = re.match(r"^(pip\s+\S+)", pip_version_output)
    if version_match is None:
        raise OfflineVerificationError("isolated pip version check returned invalid data")
    pip_version = version_match.group(1)

    install_command = [
        str(venv_python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--find-links",
        str(wheel_dir),
        "--require-hashes",
        "--no-cache-dir",
        "--only-binary=:all:",
        "-r",
        str(lock_path),
    ]
    install_result = _run(
        install_command,
        cwd=work_directory,
        env=env,
        label="offline pip installation",
    )
    _require_success(install_result, "offline pip installation")

    pip_check_result = _require_success(
        _run(
            [str(venv_python), "-m", "pip", "check"],
            cwd=work_directory,
            env=env,
            label="isolated pip check",
        ),
        "isolated pip check",
    )
    bootstrap_packages, installed_packages = _installed_distributions(
        venv_python,
        cwd=work_directory,
        env=env,
        requirements=requirements_list,
    )
    location = _installed_location(venv_python, cwd=work_directory, env=env, venv=venv_path)
    return InstalledEnvironment(
        root=install_path,
        venv=venv_path,
        python=venv_python,
        work_directory=work_directory,
        pip_version=pip_version,
        bootstrap_packages=bootstrap_packages,
        installed_packages=installed_packages,
        python_identity=identity["implementation"] + " " + identity["version"],
        installed_location=location,
        pip_install_output=_output(install_result),
        pip_check_output=_output(pip_check_result),
        artifact_inventory=artifact_inventory,
    )


def _run_app(
    environment: InstalledEnvironment,
    arguments: Sequence[str],
    env: dict[str, str],
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    executable = environment.venv / "Scripts" / "sentinel.exe"
    if not executable.is_file():
        raise OfflineVerificationError("installed Sentinel console entry point is missing")
    return _run(
        [str(executable), *arguments],
        cwd=environment.work_directory,
        env=env,
        label=label,
        timeout=90,
    )


def _require_cli_success(
    environment: InstalledEnvironment,
    arguments: Sequence[str],
    env: dict[str, str],
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    return _require_success(_run_app(environment, arguments, env, label), label)


def _validate_demo_report(
    output: bytes, expected_fixture_sha: str, expected_config_sha: str
) -> dict[str, object]:
    try:
        document = json.loads(output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OfflineVerificationError("demo did not emit one valid UTF-8 JSON document") from None
    if type(document) is not dict or output.strip() == b"":
        raise OfflineVerificationError("demo did not emit one valid JSON object")
    if output.strip().count(b"\n") != 0:
        raise OfflineVerificationError("demo output contains more than one line")
    expected_fields: dict[str, object] = {
        "schema_version": "sentinel.demo.v1",
        "fixture_version": "sentinel.demo-fixture.v1",
        "fixture_sha256": expected_fixture_sha,
        "config_sha256": expected_config_sha,
        "execution_mode": "DEMO",
        "profile": "local-only",
        "credentials_used": False,
        "external_effects": False,
        "production_readiness": False,
    }
    if any(document.get(key) != value for key, value in expected_fields.items()):
        raise OfflineVerificationError(
            "demo report does not match the trusted fixture/configuration"
        )
    for result_name in ("model", "tool"):
        result = document.get(result_name)
        if type(result) is not dict or result.get("status") != "SUCCESS":
            raise OfflineVerificationError("demo gateway result was not successful")
        for digest_name in ("request_sha256", "response_sha256"):
            digest = result.get(digest_name)
            if type(digest) is not str or _SHA256_PATTERN.fullmatch(digest) is None:
                raise OfflineVerificationError("demo boundary digest is invalid")
    denials = document.get("negative_probes")
    expected_denials = {
        "unknown_model",
        "secret_model",
        "private_model",
        "unknown_tool",
        "external_write_tool",
        "approval_tool",
    }
    if type(denials) is not dict or set(denials) != expected_denials:
        raise OfflineVerificationError("demo denial probe set is incomplete")
    if any(value != "DENIED" for value in denials.values()):
        raise OfflineVerificationError("demo reported an unauthorized execution probe")
    return document


def _installed_fingerprints(
    environment: InstalledEnvironment, env: dict[str, str]
) -> tuple[str, str]:
    code = (
        "import hashlib, json; from importlib.resources import files; "
        "from sentinel.config import config_sha256, load_bundled_defaults; "
        "from sentinel.demo.runner import FIXTURE_SHA256, FIXTURE_VERSION; "
        "raw=files('sentinel.demo').joinpath('fixtures').joinpath('demo-v1.json').read_bytes(); "
        "actual=hashlib.sha256(raw).hexdigest(); "
        "assert actual == FIXTURE_SHA256; "
        "print(json.dumps({'fixture_sha256':actual,'fixture_version':FIXTURE_VERSION,"
        "'config_sha256':config_sha256(load_bundled_defaults())}))"
    )
    result = _require_success(
        _run(
            [str(environment.python), "-c", code],
            cwd=environment.work_directory,
            env=env,
            label="installed fixture/config fingerprint check",
        ),
        "installed fixture/config fingerprint check",
    )
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
        if payload.get("fixture_version") != "sentinel.demo-fixture.v1":
            raise ValueError
        return str(payload["fixture_sha256"]), str(payload["config_sha256"])
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        raise OfflineVerificationError(
            "installed fixture/config fingerprint check failed"
        ) from None


def _verify_initialized_database(
    environment: InstalledEnvironment,
    database_path: Path,
    env: dict[str, str],
) -> None:
    code = f"""
from pathlib import Path
import sqlite3
import sys
path = Path(sys.argv[1])
con = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
integrity = con.execute('PRAGMA integrity_check').fetchone()[0]
rows = con.execute(
    'SELECT migration_id, artifact_sha256, success FROM schema_migrations'
).fetchall()
objects = con.execute(
    \"SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name\"
).fetchall()
fk = con.execute('PRAGMA foreign_key_check').fetchall()
con.close()
expected = [({FOUNDATION_MIGRATION_ID!r}, {FOUNDATION_ARTIFACT_SHA256!r}, 1)]
expected_objects = [
    ('index', 'schema_migrations_applied_at_idx'),
    ('table', 'schema_migrations'),
]
assert integrity == 'ok' and rows == expected and objects == expected_objects and not fk
print('foundation migration, digest, schema, and SQLite integrity verified')
"""
    result = _run(
        [str(environment.python), "-c", code, str(database_path)],
        cwd=environment.work_directory,
        env=env,
        label="initialized database verification",
    )
    _require_success(result, "initialized database verification")


def _verify_doctor_failures(
    environment: InstalledEnvironment,
    env: dict[str, str],
) -> tuple[tuple[int, str], tuple[int, str]]:
    missing = environment.root / "missing.sqlite3"
    malformed = environment.root / "malformed.sqlite3"
    malformed.write_bytes(b"synthetic non-SQLite bytes")
    before = malformed.read_bytes()

    missing_result = _run_app(
        environment,
        ["doctor", "--database", str(missing)],
        env,
        "doctor missing-database probe",
    )
    malformed_result = _run_app(
        environment,
        ["doctor", "--database", str(malformed)],
        env,
        "doctor malformed-database probe",
    )
    for label, path, result in (
        ("missing", missing, missing_result),
        ("malformed", malformed, malformed_result),
    ):
        output = result.stdout + result.stderr
        if result.returncode == 0 or str(path).encode() in output:
            raise OfflineVerificationError(f"doctor {label}-database failure contract was violated")
    if missing.exists() or malformed.read_bytes() != before:
        raise OfflineVerificationError("doctor modified a missing or malformed database target")
    return (
        (
            missing_result.returncode,
            (missing_result.stdout + missing_result.stderr).decode("utf-8", errors="replace"),
        ),
        (
            malformed_result.returncode,
            (malformed_result.stdout + malformed_result.stderr).decode("utf-8", errors="replace"),
        ),
    )


def run_smoke_tests(environment: InstalledEnvironment) -> None:
    """Run the installed-wheel CLI and database smoke checks outside the checkout."""

    env = _clean_environment()
    print(f"Target environment: {environment.python_identity} on Windows x64")
    print(f"Bootstrapped pip: {environment.pip_version}")
    print("Import origin: Sentinel imported from disposable venv site-packages")
    print("Installed runtime versions:")
    for package in environment.installed_packages:
        print(f"  {package}")
    print("Local ensurepip bootstrap packages:")
    for package in environment.bootstrap_packages:
        print(f"  {package}")
    print("Verified pinned wheel inventory:")
    for artifact in environment.artifact_inventory:
        print(f"  {artifact}")
    print("Offline pip install output:")
    sys.stdout.write(environment.pip_install_output)
    if environment.pip_install_output and not environment.pip_install_output.endswith("\n"):
        print()
    print("Offline pip check output:")
    sys.stdout.write(environment.pip_check_output)
    if environment.pip_check_output and not environment.pip_check_output.endswith("\n"):
        print()

    version = _require_cli_success(environment, ["version"], env, "sentinel version")
    version_text = version.stdout.decode("utf-8", errors="replace").strip()
    if version_text != "0.1.0" or version.stderr:
        raise OfflineVerificationError("installed sentinel version result is unexpected")
    print(f"sentinel version (exit {version.returncode}): {version_text}")

    help_result = _require_cli_success(environment, ["--help"], env, "sentinel --help")
    help_text = help_result.stdout.decode("utf-8", errors="replace")
    if any(command not in help_text for command in ("init", "doctor", "demo", "version")):
        raise OfflineVerificationError("installed CLI help is missing a required command")
    print(f"sentinel --help (exit {help_result.returncode}): init, doctor, demo, version found")

    fixture_sha, config_sha = _installed_fingerprints(environment, env)
    demo_one = _require_cli_success(environment, ["demo"], env, "sentinel demo")
    demo_two = _require_cli_success(environment, ["demo"], env, "sentinel demo repeat")
    if demo_one.stdout != demo_two.stdout or demo_one.stderr or demo_two.stderr:
        raise OfflineVerificationError("repeated demo output was not byte-identical and clean")
    _validate_demo_report(demo_one.stdout, fixture_sha, config_sha)
    print(f"sentinel demo (exit {demo_one.returncode}; byte-identical repeat):")
    sys.stdout.write(demo_one.stdout.decode("utf-8"))
    print("" if demo_one.stdout.endswith(b"\n") else "")

    database = environment.root / "cr0-disposable.sqlite3"
    init_result = _require_cli_success(
        environment,
        ["init", "--database", str(database)],
        env,
        "sentinel init",
    )
    if not database.is_file() or str(database).encode() in init_result.stdout + init_result.stderr:
        raise OfflineVerificationError("installed init did not create a path-safe database")
    print(f"sentinel init (exit {init_result.returncode}):")
    sys.stdout.write(init_result.stdout.decode("utf-8", errors="replace"))
    _verify_initialized_database(environment, database, env)

    doctor = _require_cli_success(
        environment,
        ["doctor", "--database", str(database)],
        env,
        "sentinel doctor",
    )
    doctor_output = doctor.stdout.decode("utf-8", errors="replace")
    required = (
        "PASS database.read_only",
        "PASS database.wal",
        "PASS database.integrity",
        "PASS storage.migration_history",
        "PASS storage.schema_checkpoint",
        "PASS config.validation",
        "PASS config.fingerprint",
        "UNAVAILABLE credential.backend",
        "UNAVAILABLE capability.os_keychain",
        "NOT_IMPLEMENTED capability.policy_engine",
        "NOT_IMPLEMENTED capability.mcp_smoke",
    )
    if (
        any(marker not in doctor_output for marker in required)
        or "production readiness result" not in doctor_output
        or str(database) in doctor_output
        or doctor.stderr
    ):
        raise OfflineVerificationError(
            "doctor did not report the expected supported/unavailable states"
        )
    print(f"sentinel doctor (exit {doctor.returncode}):")
    sys.stdout.write(doctor.stdout.decode("utf-8", errors="replace"))

    (missing_exit, missing_output), (malformed_exit, malformed_output) = _verify_doctor_failures(
        environment, env
    )
    print(f"sentinel doctor missing database (exit {missing_exit}):")
    sys.stdout.write(missing_output)
    if missing_output and not missing_output.endswith("\n"):
        print()
    print(f"sentinel doctor malformed database (exit {malformed_exit}):")
    sys.stdout.write(malformed_output)
    if malformed_output and not malformed_output.endswith("\n"):
        print()
    print("Database verification: foundation migration digest and exact schema verified")
    print(
        "Network/index mode: pip index access disabled; "
        "operating-system network sandbox not applied"
    )
    print("Credentials: none supplied or required; external effects: false for the demo")


def _parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python-exe", type=Path, required=True, help="pyenv CPython 3.11.7 executable"
    )
    parser.add_argument(
        "--wheelhouse", type=Path, required=True, help="external directory containing pinned wheels"
    )
    parser.add_argument(
        "--requirements", type=Path, required=True, help="committed hash-pinned runtime lock"
    )
    parser.add_argument(
        "--install-root", type=Path, required=True, help="new disposable root outside the checkout"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parse_arguments(argv)
        environment = install_offline(
            args.python_exe,
            args.wheelhouse,
            args.requirements,
            args.install_root,
        )
        run_smoke_tests(environment)
    except OfflineVerificationError as error:
        print(f"CR0-K OFFLINE VERIFICATION FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
