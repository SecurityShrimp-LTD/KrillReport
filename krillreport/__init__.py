"""KrillReport — pentest & red team engagement report generation toolkit.

KrillReport ingests the output of many security tools and data formats, normalizes
them into a single internal data model, and renders professionally branded
penetration-test / red-team reports in both PDF and DOCX. Narrative sections can be
enhanced with a configurable LLM provider.

The package is deliberately split into small, single-responsibility sub-packages:

* :mod:`krillreport.models`        — the unified normalized data model
* :mod:`krillreport.ingestion`     — per-format parsers + format dispatcher
* :mod:`krillreport.normalization` — merge / dedupe / group / risk-rate findings
* :mod:`krillreport.template_engine` — branding extraction + template management
* :mod:`krillreport.report_renderer` — DOCX + PDF rendering
* :mod:`krillreport.llm_enhancer`  — pluggable LLM narrative enhancement
* :mod:`krillreport.cli`           — command line interface
* :mod:`krillreport.api`           — FastAPI web backend + browser UI
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "1.0.0"
