import typer

app = typer.Typer(
    name="llmbuster",
    help="Terminal-based (TUI) security scanner for OWASP Top 10 for LLMs assessments.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    pass


if __name__ == "__main__":
    app()
