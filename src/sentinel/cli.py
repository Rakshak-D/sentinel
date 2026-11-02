"""Minimal command-line entry point for the Sentinel package."""

from pathlib import Path
from typing import Annotated

import typer

from sentinel import __version__
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


if __name__ == "__main__":
    app()
