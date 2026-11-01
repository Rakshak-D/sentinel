# ADR-0001: Python environment and packaging

- Status: Accepted for CR0-A
- Date: 2026-11-02
- Decision owners: Sentinel project

## Context

The Master Blueprint (2026-11-01) names Python 3.11+ as a candidate target and treats its exact patch and the dependency graph as unverified until a clean install is demonstrated. It lists uv as an alternative for tooling and locking, but does not establish a successful uv lock or install. The repository owner uses Windows, pyenv, pip, and a project-local virtual environment.

## Decision

Use pyenv-win to select Python 3.11.7, `python -m venv .venv` to isolate the project, pip invoked only through `.venv\Scripts\python.exe`, and a `pyproject.toml` with a standard setuptools build backend. The CLI is exposed as the `sentinel` console script and uses Typer.

uv is not required for this first slice. Adding a second environment and installer tool would not improve the minimal bootstrap enough to justify an additional toolchain dependency. This is an implementation choice consistent with the blueprint's alternative-tooling allowance, not a change to product architecture.

## Reproducibility and release plan

Before CR0 exits, resolve dependencies against the live package registry in a clean environment; record exact selected versions; generate and review a deterministic, hash-pinned dependency lock; download wheels for the supported Windows/Python target; install those wheels with network access disabled in a clean environment; and verify the built wheel, CLI commands, and test suite from that clean install. Any incompatible resolution must be recorded and resolved with documented exact pins. This ADR does not claim that a lockfile, wheelhouse, offline installation, or cross-platform compatibility has passed.

## Impact

The local venv prevents project dependencies from being installed globally. Pip resolution without a committed lock is not yet reproducible across time or machines. The CR0-A evidence establishes only a real registry-backed local install on the selected interpreter; it does not establish an offline or clean-machine install. Restricting this slice to Typer and development tools reduces supply-chain surface while avoiding provider, model, MCP, and frontend dependencies.

## Revisit conditions

Revisit this choice before CR0 exit if lock generation, hash pinning, wheelhouse creation, or offline installation is unreliable with pip, or if the supported OS matrix requires a stronger single-command resolver workflow. Revisit the Python patch when the supported interpreter matrix is validated or a security fix requires an upgrade. Any changed packaging preference or unsupported compatibility claim must be recorded with evidence.
