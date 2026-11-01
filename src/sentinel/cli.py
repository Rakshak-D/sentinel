"""Minimal command-line entry point for the Sentinel package."""

import typer

from sentinel import __version__

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


if __name__ == "__main__":
    app()
