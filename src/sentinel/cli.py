"""Minimal command-line entry point for the Sentinel package."""

from pathlib import Path
from typing import Annotated

import typer

from sentinel import __version__
from sentinel.bootstrap.doctor import DoctorReport, run_doctor
from sentinel.bootstrap.init import BootstrapInitError, initialize_new_database

app = typer.Typer(no_args_is_help=True, help="Sentinel local-first automation CLI.")


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


if __name__ == "__main__":
    app()
