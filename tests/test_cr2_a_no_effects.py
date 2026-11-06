import os
import socket
import sqlite3
import subprocess
from pathlib import Path

from cr2_a_policy_cases import make_context, make_request, make_source

from sentinel.policy import build_policy_status_report, evaluate_policy


def test_policy_evaluation_and_status_do_not_access_effectful_services(
    monkeypatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("unexpected external or persistent effect")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    source = make_source()
    request = make_request(source=source)
    context = make_context(source)
    monkeypatch.setenv("SENTINEL_CR2_PRIVATE_CANARY", "never-read")
    result = evaluate_policy(request=request, context=context)
    status = build_policy_status_report()
    assert result.outcome.value == "DENY"
    assert status.default_outcome.value == "DENY"
    assert os.environ["SENTINEL_CR2_PRIVATE_CANARY"] == "never-read"
