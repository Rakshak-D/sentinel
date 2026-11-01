# Sentinel

Sentinel is a planned local-first personal automation application. Its authoritative design is [the Sentinel Master Blueprint](docs/spec/Sentinel%20Master%20Blueprint.pdf); [the build ledger](docs/BUILD_LEDGER.md) tracks implementation evidence and remaining gates. The architecture separates untrusted source content, model access through `ModelGateway`, tool effects through `ToolGateway`, and a deterministic policy reference monitor.

## CR0-A scope

This slice establishes the repository rules, a Python package, and an installable CLI with `sentinel --help` and `sentinel version`. The CLI reports package metadata. These commands are package scaffolding only; they do not implement F43 or F46 and do not complete CR0.

There is no agent, model adapter, MCP worker, policy engine, approval system, provider integration, database, daemon, or frontend. `init`, `doctor`, and `demo` are not available. No model, HTTP provider, MCP, or external-tool calls are made. External writes are unavailable. The CLI bootstrap does not demonstrate later security invariants.

## CR0-B contract API

`sentinel.contracts` exports the immutable `SourceEnvelope`, `ByteSpan`, and `BoundaryEnvelope` models, their `TrustLabel`, `SensitivityLabel`, and `BoundaryKind` enums, and `canonical_json_bytes` / `canonical_sha256` helpers. The models use UUID identifiers, timezone-aware UTC-normalized timestamps, lowercase 64-character SHA-256 hex digests, `sha256:<hex>` content references, tuples for nested collections, and reject undeclared fields.

```python
from datetime import UTC, datetime
from uuid import uuid4

from sentinel.contracts import SensitivityLabel, SourceEnvelope, TrustLabel

source = SourceEnvelope(
    source_id=uuid4(),
    provider_id="synthetic-source",
    content_sha256="a" * 64,
    observed_at=datetime.now(UTC),
    trust=TrustLabel.T4_EXTERNAL,
    sensitivity=SensitivityLabel.PRIVATE,
    parent_ids=(),
    byte_spans=(),
)
```

`BoundaryEnvelope.kind` classifies `model` or `tool`. Request and response payloads are represented by content references and matching digests, not embedded bodies. Optional response reference/digest and error code fields must be supplied explicitly as a value or `None`. Byte spans enforce `0 <= start_byte < end_byte`; because the source body length is not part of the blueprint's SourceEnvelope schema, the envelope cannot validate an upper bound against that body.

These contracts validate shape only. A `T1 OWNER_INTENT` value is a declaration, not proof of owner authentication; callers must not accept T0/T1 labels from untrusted source content. No generic external-payload factory is provided. The contracts do not authorize or execute actions. Canonical JSON is limited to exact contract types and is not the future approval digest or audit-chain algorithm.

## Windows PowerShell setup

Install pyenv-win and Python 3.11.7 if not already available, then from the repository root:

```powershell
pyenv local 3.11.7
python --version
python -m venv .venv
```

Use the explicit virtual-environment interpreter for every package operation:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pip check
```

Do not install project packages with a global or ambiguous `pip` command. Run the supported CLI and checks with:

```powershell
.\.venv\Scripts\sentinel.exe --help
.\.venv\Scripts\sentinel.exe version
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src/sentinel
.\.venv\Scripts\python.exe -m build --wheel
```

The initial development install is registry-resolved and not yet hash-locked. See ADR-0001 and the ledger for the actual selected versions and the remaining clean offline installation gate.

## Security limitations

This bootstrap is not a security certification and does not implement the blueprint's P00-P17 policy rules or AB01-AB18 bypass tests. It has no credentials or personal-data fixtures. All consequential external capabilities remain unavailable pending their release gates. Use synthetic fixtures only in future tests.
