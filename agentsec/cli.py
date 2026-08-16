"""Interfaz de linea de comandos de AgentSec (typer)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from agentsec.models import ScanOptions
from agentsec.payloads import ProbeConfig, Prober, load_payloads
from agentsec.reporter import render_by_format
from agentsec.scanner import exit_code_for, run_scan

app = typer.Typer(
    name="agentsec",
    help="Auditor shift-left de seguridad para agentes de IA "
    "(LangChain, CrewAI y asistentes de codigo agenciicos).",
    no_args_is_help=True,
)


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Ruta al proyecto con configs de agentes.")],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Formato de salida: text|json|sarif|html"),
    ] = "text",
    threshold: Annotated[
        float,
        typer.Option("--threshold", help="Umbral de puntaje para FAIL (default 60)."),
    ] = 60.0,
    allow: Annotated[
        list[str] | None,
        typer.Option("--allow", "-a", help="Reglas a ignorar (repetible)."),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Escribir reporte a archivo en vez de stdout."),
    ] = None,
) -> None:
    """Ejecuta analisis estatico de seguridad sobre configs de agentes."""
    options = ScanOptions(
        path=str(path),
        formats=[format],
        allow=allow or [],
        threshold=threshold,
    )
    try:
        result = run_scan(options)
    except FileNotFoundError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=3) from exc

    content = render_by_format(result, format if format != "html" else "html")

    if out is not None:
        out.write_text(content, encoding="utf-8")
        typer.echo(f"Reporte {format} escrito en {out}")
    else:
        typer.echo(content)

    code = exit_code_for(result, threshold)
    typer.secho(
        f"Puntaje: {result.score:.1f}/100 | hallazgos: {len(result.findings)} | exit: {code}",
        fg=typer.colors.GREEN
        if code == 0
        else typer.colors.YELLOW
        if code == 1
        else typer.colors.RED,
    )
    raise typer.Exit(code)


@app.command()
def probe(
    target: Annotated[str, typer.Argument(help="URL del endpoint del agente (POST).")],
    suite: Annotated[
        str,
        typer.Option("--suite", "-s", help="Suite de payloads: indirect (default)."),
    ] = "indirect",
    field: Annotated[
        str,
        typer.Option("--field", help="Campo JSON donde se inyecta el dato (default query)."),
    ] = "query",
    timeout: Annotated[float, typer.Option("--timeout", help="Timeout por request (s).")] = 10.0,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Prueba un endpoint con payloads de inyeccion de prompt indirecta."""
    config = ProbeConfig(target=target, suite=suite, request_field=field, timeout=timeout)
    prober = Prober(config)
    payloads = load_payloads(suite=suite)
    with prober.client:
        results = prober.run(payloads)

    triggered = [r for r in results if r.triggered]
    failed = [r for r in results if r.server_error and not r.triggered]

    typer.echo(f"Payloads probados: {len(results)} ({suite})")
    typer.echo(f"Detonados: {len(triggered)} | Errores de conexion: {len(failed)}")
    for result in results:
        status = "DETONADO" if result.triggered else ("ERROR" if result.server_error else "limpio")
        color = (
            typer.colors.RED
            if result.triggered
            else (typer.colors.YELLOW if result.server_error else typer.colors.GREEN)
        )
        line = f"  [{result.payload.id}] {status:8} {result.payload.name}"
        if result.triggered or verbose:
            typer.secho(line, fg=color)
            if result.triggered:
                typer.echo(f"      motivo: {result.reason}")
                typer.echo(f"      respuesta: {result.response_snippet[:120]}")
            if result.server_error:
                typer.echo(f"      error: {result.server_error}")
        else:
            typer.echo(line)

    if failed:
        raise typer.Exit(3)
    raise typer.Exit(2 if triggered else 0)


@app.command()
def version() -> None:
    """Muestra la version instalada."""
    from agentsec import __version__

    typer.echo(f"AgentSec {__version__}")


def main() -> int:
    return app()


if __name__ == "__main__":
    sys.exit(main())
