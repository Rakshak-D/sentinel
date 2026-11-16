# Sentinel

Sentinel is a local-first personal automation agent with a policy engine in front of actions. This pre-release repository currently provides bounded offline workflows built around synthetic fixtures and test-only integrations.

## Status

The Windows CLI can run a synthetic demo, read fixture-backed cited evidence, build a local overview, manage manually entered tasks, and inspect bounded synthetic proposals.

Production owner verification remains unavailable. Live Gmail, GitHub, and Calendar integrations, live job-feed access, executable approvals, general provider automation, and external effects are not available.

The hosted Windows service-isolation laboratory failed twice. The second run stopped during host preflight with an I/O error at line 321. Its root cause remains unresolved. Windows service isolation has not been verified.

## Requirements

- Windows is the supported platform today.
- Python `>=3.11,<3.12`.
- Linux is not supported. Linux testing exposes platform-specific failures; fixing them is outside this round.

## Install and try it

Run these commands in PowerShell from the repository root. They create a virtual environment, install the development extra, and run local help, version, and synthetic demo commands.

```powershell
python -m venv .venv-sentinel
.\.venv-sentinel\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv-sentinel\Scripts\sentinel.exe --help
.\.venv-sentinel\Scripts\sentinel.exe version
.\.venv-sentinel\Scripts\sentinel.exe demo
```

## Commands

The installed CLI exposes these command groups:

- `version` — print the installed package version.
- `init` — initialize a new database at an explicitly selected path.
- `doctor` — run read-only diagnostics on an explicitly selected database.
- `demo` — run the deterministic synthetic demo.
- `brief` — read verified, source-cited evidence.
- `source` — inspect and work with explicitly selected local files or fixed fixtures; live provider readers are unavailable.
- `task` — manage manually entered local tasks.
- `fixture-sync` — replay the fixed synthetic GitHub issue fixture.
- `fixture-workspace` — prepare or verify the bounded offline synthetic workspace.
- `policy` — inspect the deterministic policy status and supported boundaries.
- `auth` — inspect the synthetic WebAuthn verification foundation; production owner verification is unavailable.
- `proposal` — preview, save, list, or check bounded synthetic proposals; pending review does not authorize execution.

## How it is built

- `sentinel.contracts` and `sentinel.normalization` define typed source labels, envelopes, and citation validation.
- `sentinel.readers`, `sentinel.ingestion`, and `sentinel.sync` handle bounded local or synthetic fixture inputs and their registered metadata.
- `sentinel.storage` owns SQLite schemas, migrations, integrity checks, and the Windows writer lease.
- `sentinel.briefing`, `sentinel.overview`, and `sentinel.workspace` assemble read-only cited output and synthetic workspace views.
- `sentinel.triage` and `sentinel.extraction` provide bounded deterministic review of selected content.
- `sentinel.policy` and `sentinel.proposals` implement deny-by-default policy foundations and narrow synthetic proposal paths; they are not a system-wide reference monitor.
- `sentinel.gateways`, `sentinel.credentials`, and `sentinel.owner_proof` keep demo gateways and test-only verification separated from unavailable production capabilities.
- See the [documentation index](docs/README.md) and [owner-authentication architecture record](docs/adr/0005-cr2-g-a-owner-authentication-trust-root.md).

## Safety limits

- Source labels and citations describe bounded synthetic or selected local inputs; they do not authenticate a real provider or the author of its content.
- Production owner verification is unavailable. CR2-F WebAuthn verification is synthetic-only. The current ModelGateway is demo-only.
- Pending proposals are review material. No owner approval, accepted-task conversion, executable grant, or general external effect is available.
- The Windows broker and service-isolation experiment is non-authorizing and has not demonstrated a protected service boundary. See [ADR-0005](docs/adr/0005-cr2-g-a-owner-authentication-trust-root.md) and [ADR-0004](docs/adr/0004-cr1-j-task-request-receipts.md).

## Development

Use the supported Windows Python 3.11 environment:

```powershell
.\.venv-sentinel\Scripts\python.exe -m ruff check .
.\.venv-sentinel\Scripts\python.exe -m mypy src/sentinel
.\.venv-sentinel\Scripts\python.exe -m pytest -q
```

Read the [contributor instructions](AGENTS.md) before changing the repository.

## Project history

- [Changelog](CHANGELOG.md)
- [Build ledger](docs/BUILD_LEDGER.md)
- [Archived slice history](docs/history/slice-log.md)
