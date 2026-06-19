#!/usr/bin/env python3
"""End-to-end KrillReport demo: ingest every sample input and render reports.

Run from the repo root::

    python examples/make_sample_template.py   # optional: creates a branded template
    python examples/generate_demo.py

Reports are written to ``<data-dir>/output/`` (``./krilldata/output`` by default).
"""

from __future__ import annotations

from pathlib import Path

from krillreport.config import get_settings
from krillreport.logging_config import configure_logging
from krillreport.pipeline import run_pipeline
from krillreport.template_engine import TemplateManager, default_branding

HERE = Path(__file__).resolve().parent
INPUTS = sorted(p for p in (HERE / "sample_inputs").iterdir() if p.is_file())


def main() -> None:
    configure_logging("INFO")
    settings = get_settings()
    settings.ensure_dirs()

    # Use the "acme-corp" template if it has been created, otherwise the built-in default.
    manager = TemplateManager(settings.templates_dir)
    branding = manager.get("acme-corp") if manager.exists("acme-corp") else default_branding()

    result = run_pipeline(
        INPUTS,
        output_dir=settings.output_dir,
        branding=branding,
        basename="demo_engagement",
    )

    summary = result.report.summary()
    print("\n" + "=" * 60)
    print(f"Template     : {branding.display_name}")
    print(f"Enhancement  : {result.enhancement_mode}")
    print(f"Findings     : {summary.total_findings} (highest: {summary.highest_severity.value})")
    print(f"Hosts        : {summary.total_hosts}")
    for fmt, path in result.outputs.items():
        print(f"  {fmt.upper():4} -> {path}")
    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")
    print("=" * 60)


if __name__ == "__main__":
    main()
