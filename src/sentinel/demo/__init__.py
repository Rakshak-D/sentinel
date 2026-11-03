"""Synthetic, credential-free demo flow through Sentinel's existing gateways."""

from sentinel.demo.runner import (
    DEMO_OUTPUT_SCHEMA_VERSION,
    FIXTURE_SHA256,
    FIXTURE_VERSION,
    DemoExecutionError,
    DemoFixture,
    DemoReport,
    load_packaged_fixture,
    parse_fixture_document,
    run_demo,
)

__all__ = [
    "DEMO_OUTPUT_SCHEMA_VERSION",
    "FIXTURE_SHA256",
    "FIXTURE_VERSION",
    "DemoExecutionError",
    "DemoFixture",
    "DemoReport",
    "load_packaged_fixture",
    "parse_fixture_document",
    "run_demo",
]
