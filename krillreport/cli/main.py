"""KrillReport command-line interface (Click).

Subcommands:

* ``generate``  — ingest inputs and render branded PDF/DOCX reports.
* ``inspect``   — dry-run: ingest + normalize and print what was found (no rendering).
* ``templates`` — manage branding templates (list / add / show / remove).
* ``serve``     — launch the web UI / API.
* ``version``   — print the version.

The CLI is intentionally thin: it parses options, resolves the template and LLM
settings, and delegates to :func:`krillreport.pipeline.run_pipeline`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import click

from .. import __version__
from ..config import LLMSettings, Settings, get_settings
from ..ingestion import ingest_paths
from ..logging_config import configure_logging
from ..models import Severity
from ..normalization import collect_warnings, normalize
from ..pipeline import PipelineResult, run_pipeline
from ..template_engine import SUPPORTED_TEMPLATE_EXTENSIONS, TemplateManager


# --------------------------------------------------------------------------- #
# Root group
# --------------------------------------------------------------------------- #


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="krillreport")
@click.option("--data-dir", type=click.Path(file_okay=False), default=None, help="Base data directory.")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Path to a YAML config file.")
@click.option("--log-level", default=None, help="Logging level (DEBUG, INFO, WARNING, ERROR).")
@click.pass_context
def cli(ctx: click.Context, data_dir: Optional[str], config_path: Optional[str], log_level: Optional[str]) -> None:
    """Generate branded pentest / red-team reports from security-tool output."""
    if config_path:
        os.environ["KRILLREPORT_CONFIG"] = config_path
    overrides = {}
    if data_dir:
        overrides["data_dir"] = Path(data_dir)
    if log_level:
        overrides["log_level"] = log_level
    settings = get_settings(reload=True, **overrides)
    configure_logging(settings.log_level)
    settings.ensure_dirs()
    ctx.obj = settings


# --------------------------------------------------------------------------- #
# generate
# --------------------------------------------------------------------------- #


@cli.command()
@click.argument("inputs", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output-dir", type=click.Path(file_okay=False), default=None,
              help="Where to write reports (default: <data-dir>/output).")
@click.option("-t", "--template", default="default", help="Branding template name.")
@click.option("-f", "--format", "formats", multiple=True, type=click.Choice(["pdf", "docx"]),
              help="Output format(s); repeatable. Default: both.")
@click.option("--name", default=None, help="Output filename stem.")
@click.option("--attach", "attachments", multiple=True,
              type=click.Path(exists=True, dir_okay=False),
              help="File to attach as an appendix — a script/config reproduced verbatim, "
                   "or an image embedded as a picture; repeatable.")
@click.option("--layout-template", "layout_template", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="A .docx to render the DOCX report into (layout fidelity; see 'templates scaffold').")
@click.option("--css", "css_file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="CSS file appended to the PDF stylesheet (restyle without LibreOffice).")
@click.option("--logo", "logo_file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Logo image to use for this run (overrides the template's logo).")
@click.option("--client", default=None, help="Override client name.")
@click.option("--project", default=None, help="Override project name.")
@click.option("--report-title", default=None, help="Override report title.")
@click.option("--engagement-type", default=None, help="Override engagement type (e.g. 'Red Team').")
@click.option("--classification", default=None, help="Override classification banner.")
@click.option("--provider", default=None, type=click.Choice(["offline", "anthropic", "openai", "ollama"]),
              help="Override LLM provider for narrative enhancement.")
@click.option("--model", default=None, help="Override LLM model.")
@click.option("--no-enhance", is_flag=True, help="Skip narrative enhancement entirely.")
@click.pass_obj
def generate(
    settings: Settings,
    inputs,
    output_dir,
    template,
    formats,
    name,
    attachments,
    layout_template,
    css_file,
    logo_file,
    client,
    project,
    report_title,
    engagement_type,
    classification,
    provider,
    model,
    no_enhance,
) -> None:
    """Ingest INPUTS and render branded report(s)."""
    formats = list(formats) or ["pdf", "docx"]
    out_dir = Path(output_dir) if output_dir else settings.output_dir

    manager = TemplateManager(settings.templates_dir)
    branding = manager.get(template)
    if template not in (None, "default") and not manager.exists(template):
        click.secho(f"Template '{template}' not found; using default branding.", fg="yellow")
    if css_file:
        extra = Path(css_file).read_text(encoding="utf-8")
        branding.custom_css = (branding.custom_css + "\n" + extra).strip()
    if logo_file:
        branding.logo_path = str(Path(logo_file))  # ad-hoc logo for this run

    overrides = _metadata_overrides(client, project, report_title, engagement_type, classification)
    llm_settings = _llm_settings(settings.llm, provider, model)

    attach_note = f" (+{len(attachments)} attachment(s))" if attachments else ""
    click.echo(f"Ingesting {len(inputs)} file(s){attach_note}…")
    result = run_pipeline(
        [Path(p) for p in inputs],
        output_dir=out_dir,
        branding=branding,
        basename=name,
        formats=formats,
        metadata_overrides=overrides,
        llm_settings=llm_settings,
        enhance=not no_enhance,
        attachments=[Path(p) for p in attachments],
        layout_template=Path(layout_template) if layout_template else None,
    )
    _print_result(result, branding.display_name)


# --------------------------------------------------------------------------- #
# inspect
# --------------------------------------------------------------------------- #


@cli.command()
@click.argument("inputs", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.pass_obj
def inspect(settings: Settings, inputs) -> None:
    """Ingest + normalize INPUTS and print a summary without rendering."""
    parse_results = ingest_paths([Path(p) for p in inputs])
    report = normalize(parse_results)

    md = report.metadata
    click.secho("\nEngagement", bold=True)
    click.echo(f"  Client      : {md.client_name or '—'}")
    click.echo(f"  Title       : {md.report_title}")
    click.echo(f"  Type        : {md.engagement_type.value}")
    click.echo(f"  Window      : {md.start_date or '—'} → {md.end_date or '—'}")

    summary = report.summary()
    click.secho(f"\nFindings ({summary.total_findings})", bold=True)
    for row in summary.by_severity:
        bar = "█" * row.count
        click.echo(f"  {_sev_style(row.severity, row.severity.value.ljust(13))} {row.count:>3}  {bar}")

    click.secho("\nFindings detail", bold=True)
    for idx, finding in enumerate(report.sorted_findings(), 1):
        click.echo(
            f"  {idx:>2}. {_sev_style(finding.severity, '['+finding.severity.value+']'):<22} "
            f"{finding.title}"
        )

    if report.hosts:
        click.secho(f"\nHosts ({len(report.hosts)})", bold=True)
        for host in report.hosts:
            click.echo(f"  {host.identifier:<26} {len(host.services)} service(s)")

    warnings = collect_warnings(parse_results)
    if warnings:
        click.secho(f"\nWarnings ({len(warnings)})", fg="yellow", bold=True)
        for warning in warnings:
            click.secho(f"  • {warning}", fg="yellow")
    click.echo()


# --------------------------------------------------------------------------- #
# templates
# --------------------------------------------------------------------------- #


@cli.group()
def templates() -> None:
    """Manage branding templates."""


@templates.command("list")
@click.pass_obj
def templates_list(settings: Settings) -> None:
    """List available branding templates."""
    manager = TemplateManager(settings.templates_dir)
    for branding in manager.list_templates():
        logo = "logo" if branding.logo_path else "no-logo"
        click.echo(
            f"  {branding.name:<20} {branding.display_name:<26} "
            f"primary={branding.primary_color}  font={branding.heading_font}  {logo}"
        )


@templates.command("scaffold")
@click.option("-o", "--out", default="krill_layout_template.docx",
              type=click.Path(dir_okay=False), help="Where to write the starter template.")
def templates_scaffold(out: str) -> None:
    """Write a starter .docx layout template (anchors + styles) to customise in Word."""
    from ..template_engine.scaffold import build_scaffold_template

    path = build_scaffold_template(Path(out))
    click.secho(f"Wrote layout template: {path}", fg="green")
    click.echo("Style it in Word, then: krillreport generate <inputs> --layout-template "
               f"{path}")


@templates.command("add")
@click.argument("sample", type=click.Path(exists=True, dir_okay=False))
@click.option("--name", default=None, help="Template name (default: sample filename).")
@click.option("--primary", default=None, help="Override primary colour (#RRGGBB).")
@click.option("--logo", "logo_file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Logo image to use (overrides auto-extraction).")
@click.option("--css", "css_file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="CSS file to bake into the template (appended to the PDF stylesheet).")
@click.pass_obj
def templates_add(settings: Settings, sample: str, name: Optional[str],
                  primary: Optional[str], logo_file: Optional[str], css_file: Optional[str]) -> None:
    """Create a branding template from a sample .docx or PDF."""
    sample_path = Path(sample)
    if sample_path.suffix.lower() not in SUPPORTED_TEMPLATE_EXTENSIONS:
        click.secho(
            f"Note: {sample_path.suffix} is not a supported sample type "
            f"({', '.join(sorted(SUPPORTED_TEMPLATE_EXTENSIONS))}); defaults will be used.",
            fg="yellow",
        )
    manager = TemplateManager(settings.templates_dir)
    overrides = {"primary_color": primary} if primary else None
    branding = manager.create_from_sample(sample_path, name=name, overrides=overrides)
    if logo_file:
        branding.logo_path = str(manager.set_logo(branding.name, Path(logo_file)))
        click.echo(f"  set logo from {Path(logo_file).name}")
    if css_file:
        manager.write_custom_css(branding.name, Path(css_file).read_text(encoding="utf-8"))
        click.echo(f"  baked custom CSS from {Path(css_file).name}")
    click.secho(f"Created template '{branding.name}'", fg="green")
    click.echo(f"  primary={branding.primary_color} heading={branding.heading_font} "
               f"logo={'yes' if branding.logo_path else 'no'}")


@templates.command("show")
@click.argument("name")
@click.pass_obj
def templates_show(settings: Settings, name: str) -> None:
    """Print a template's branding as JSON."""
    manager = TemplateManager(settings.templates_dir)
    click.echo(manager.get(name).model_dump_json(indent=2))


@templates.command("remove")
@click.argument("name")
@click.pass_obj
def templates_remove(settings: Settings, name: str) -> None:
    """Delete a branding template."""
    manager = TemplateManager(settings.templates_dir)
    if manager.delete(name):
        click.secho(f"Removed template '{name}'", fg="green")
    else:
        click.secho(f"Template '{name}' not found.", fg="yellow")


# --------------------------------------------------------------------------- #
# serve
# --------------------------------------------------------------------------- #


@cli.command()
@click.option("--host", default=None, help="Bind host (default from config).")
@click.option("--port", default=None, type=int, help="Bind port (default from config).")
@click.option("--reload", is_flag=True, help="Auto-reload (development).")
@click.pass_obj
def serve(settings: Settings, host: Optional[str], port: Optional[int], reload: bool) -> None:
    """Launch the web UI / API server."""
    import uvicorn

    bind_host = host or settings.host
    bind_port = port or settings.port
    click.secho(f"Starting KrillReport web UI on http://{bind_host}:{bind_port}", fg="green")
    uvicorn.run("krillreport.api:app", host=bind_host, port=bind_port, reload=reload)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_SEV_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "bright_red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFORMATIONAL: "blue",
}


def _sev_style(severity: Severity, text: str) -> str:
    return click.style(text, fg=_SEV_COLORS.get(severity, "white"))


def _metadata_overrides(client, project, report_title, engagement_type, classification) -> dict:
    overrides = {
        "client_name": client,
        "project_name": project,
        "report_title": report_title,
        "engagement_type": engagement_type,
        "classification": classification,
    }
    return {k: v for k, v in overrides.items() if v}


def _llm_settings(base: LLMSettings, provider: Optional[str], model: Optional[str]) -> LLMSettings:
    """Return LLM settings with optional CLI overrides applied (re-resolving the model)."""
    if not provider and not model:
        return base
    return LLMSettings(
        provider=provider or base.provider,
        model=model or "",  # blank -> validator picks the provider default
        api_key=base.api_key,
        base_url=base.base_url,
        max_tokens=base.max_tokens,
        temperature=base.temperature,
        timeout=base.timeout,
        enabled=base.enabled,
    )


def _print_result(result: PipelineResult, template_name: str) -> None:
    report = result.report
    summary = report.summary()
    click.secho("\n✓ Report generated", fg="green", bold=True)
    click.echo(f"  Title       : {report.metadata.report_title}")
    click.echo(f"  Template    : {template_name}")
    click.echo(f"  Enhancement : {result.enhancement_mode}")
    click.echo(f"  Findings    : {summary.total_findings}  (highest: {summary.highest_severity.value})")
    counts = "  ".join(
        f"{_sev_style(r.severity, r.severity.value)}:{r.count}"
        for r in summary.by_severity
        if r.count
    )
    if counts:
        click.echo(f"  Breakdown   : {counts}")
    click.echo(f"  Hosts       : {len(report.hosts)}")

    click.secho("\n  Outputs:", bold=True)
    for fmt, path in result.outputs.items():
        click.echo(f"    {fmt.upper():4} → {path}")

    if result.warnings:
        click.secho(f"\n  Warnings ({len(result.warnings)}):", fg="yellow")
        for warning in result.warnings:
            click.secho(f"    • {warning}", fg="yellow")
    click.echo()


if __name__ == "__main__":
    cli()
