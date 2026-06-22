"""End-to-end orchestration: ingest -> normalize -> enhance -> render.

Both the CLI and the web API call :func:`run_pipeline`, so the full workflow lives in
exactly one place. The pieces are also individually importable for callers that want
finer control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .config import LLMSettings
from .ingestion import ParseResult, build_attachments, ingest_paths
from .llm_enhancer import Enhancer
from .logging_config import get_logger
from .models import NormalizedReport
from .normalization import collect_warnings, normalize
from .report_renderer import render_reports
from .template_engine import Branding, default_branding
from .utils import safe_filename

logger = get_logger(__name__)


@dataclass
class PipelineResult:
    """Outcome of a full report-generation run."""

    report: NormalizedReport
    outputs: Dict[str, Path] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    enhancement_mode: str = "disabled"
    parse_results: List[ParseResult] = field(default_factory=list)


def run_pipeline(
    input_paths: Iterable[Path],
    *,
    output_dir: Path,
    branding: Optional[Branding] = None,
    basename: Optional[str] = None,
    formats: Iterable[str] = ("pdf", "docx"),
    metadata_overrides: Optional[Dict[str, Any]] = None,
    llm_settings: Optional[LLMSettings] = None,
    enhance: bool = True,
    attachments: Optional[Iterable[Path]] = None,
) -> PipelineResult:
    """Run the complete pipeline and return a :class:`PipelineResult`.

    Parameters
    ----------
    input_paths:
        Files to ingest (any supported format).
    output_dir:
        Directory to write the rendered reports into.
    branding:
        Template branding to apply; defaults to the built-in default.
    basename:
        Output filename stem; derived from the report title if omitted.
    formats:
        Which outputs to produce — any of ``"pdf"`` / ``"docx"``.
    metadata_overrides:
        Engagement-metadata fields supplied by the operator (highest precedence).
    llm_settings:
        LLM configuration; falls back to global settings when ``None``.
    enhance:
        When False, the narrative is left exactly as ingested.
    attachments:
        Files to reproduce verbatim as appendices (e.g. engagement scripts); never
        parsed as findings.
    """
    input_paths = [Path(p) for p in input_paths]
    branding = branding or default_branding()

    logger.info("Pipeline: ingesting %d file(s)", len(input_paths))
    parse_results = ingest_paths(input_paths)

    report = normalize(parse_results, overrides=metadata_overrides)

    if attachments:
        report.appendices.extend(build_attachments([Path(p) for p in attachments]))

    mode = "disabled"
    if enhance:
        enhancer = Enhancer(llm_settings)
        enhancer.enhance_report(report)
        mode = enhancer.mode

    if not basename:
        basename = safe_filename(report.metadata.report_title or "security-report")

    outputs = render_reports(report, branding, Path(output_dir), basename, formats)

    return PipelineResult(
        report=report,
        outputs=outputs,
        warnings=collect_warnings(parse_results),
        enhancement_mode=mode,
        parse_results=parse_results,
    )
