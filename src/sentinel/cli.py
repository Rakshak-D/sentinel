"""Minimal command-line entry point for the Sentinel package."""

import sys
from pathlib import Path
from typing import Annotated, Literal

import typer

from sentinel import __version__
from sentinel.bootstrap.doctor import DoctorReport, run_doctor
from sentinel.bootstrap.init import BootstrapInitError, initialize_new_database
from sentinel.briefing import build_github_fixture_brief, format_json_brief, format_text_brief
from sentinel.briefing.types import BriefingError
from sentinel.demo import run_demo
from sentinel.ingestion.types import GithubBlobIntegrationError

app = typer.Typer(no_args_is_help=True, help="Sentinel local-first automation CLI.")
brief_app = typer.Typer(no_args_is_help=True, help="Read verified, source-cited evidence.")


def _write_brief_stdout(output: str) -> None:
    """Write one complete UTF-8 record after evidence and rendering succeed."""

    payload = (output + "\n").encode("utf-8", errors="strict")
    stream_buffer = getattr(sys.stdout, "buffer", None)
    if stream_buffer is not None:
        stream_buffer.write(payload)
        stream_buffer.flush()
    else:
        typer.echo(output)


@app.callback()
def main(ctx: typer.Context) -> None:
    """Show command help when no subcommand is selected."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@app.command()
def version() -> None:
    """Print the installed Sentinel package version."""
    typer.echo(__version__)


@app.command()
def init(
    database: Annotated[
        Path,
        typer.Option(
            "--database",
            help="Absolute path for a new database; existing paths are refused.",
        ),
    ],
) -> None:
    """Initialize one new database at the explicitly selected path."""
    try:
        initialize_new_database(database)
    except BootstrapInitError as exc:
        typer.echo(f"Initialization failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo("Initialized new Sentinel database; migration and integrity checks passed.")


@app.command()
def doctor(
    database: Annotated[
        Path,
        typer.Option(
            "--database",
            help="Absolute path to an existing Sentinel database; never created or modified.",
        ),
    ],
) -> None:
    """Run read-only diagnostics on one explicitly selected existing database."""
    try:
        report: DoctorReport = run_doctor(database)
    except Exception:
        typer.echo("Doctor failed: diagnostic execution failed.", err=True)
        raise typer.Exit(code=1) from None

    typer.echo("A passing Sentinel diagnostic is not a production readiness result.")
    for check in report.checks:
        typer.echo(f"{check.status.value} {check.check_id.value}: {check.message}")
    if not report.successful:
        raise typer.Exit(code=1)


@app.command()
def demo() -> None:
    """Run the deterministic credential-free synthetic DEMO flow."""
    try:
        report = run_demo()
        output = report.to_json_bytes().decode("utf-8", errors="strict")
    except Exception:
        typer.echo("Demo failed: synthetic execution could not be verified.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(output)


@brief_app.command("github-fixture")
def github_fixture_brief(
    database: Annotated[
        Path,
        typer.Option("--database", help="Existing current Sentinel database."),
    ],
    store_root: Annotated[
        Path,
        typer.Option("--store-root", help="Initialized PUBLIC blob store."),
    ],
    output_format: Annotated[
        Literal["text", "json"],
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
) -> None:
    """Display verified evidence from the fixed synthetic GitHub fixture."""

    try:
        briefing = build_github_fixture_brief(database, store_root=store_root)
        output = (
            format_text_brief(briefing)
            if output_format == "text"
            else format_json_brief(briefing)
        )
    except (BriefingError, GithubBlobIntegrationError):
        typer.echo("Brief failed: verified synthetic evidence is unavailable.", err=True)
        raise typer.Exit(code=1) from None
    except Exception:
        typer.echo("Brief failed: verified synthetic evidence is unavailable.", err=True)
        raise typer.Exit(code=1) from None
    _write_brief_stdout(output)


app.add_typer(brief_app, name="brief")


if __name__ == "__main__":
    app()
