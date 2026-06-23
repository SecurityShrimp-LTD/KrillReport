"""Tests for verbatim file attachments (engagement scripts) → report appendices."""

from pathlib import Path

import io

from PIL import Image

from krillreport.ingestion.attachments import (
    build_attachment,
    build_attachments,
    is_image,
    language_for,
)
from krillreport.pipeline import run_pipeline


def _write_png(path: Path) -> Path:
    Image.new("RGB", (40, 20), (12, 80, 200)).save(path, format="PNG")
    return path

SAMPLE_MD = Path(__file__).resolve().parents[1] / "examples" / "sample_inputs" / "manual_findings.md"


def test_language_inference():
    assert language_for(Path("x.sh")) == "bash"
    assert language_for(Path("x.ps1")) == "powershell"
    assert language_for(Path("x.py")) == "python"
    assert language_for(Path("x.unknown")) == "text"  # still rendered verbatim


def test_build_attachment_preserves_content(tmp_path):
    script = tmp_path / "poc.sh"
    script.write_text("#!/bin/bash\n# do not parse me as a heading\necho hi\n")
    ap = build_attachment(script)
    assert ap.title == "poc.sh"
    assert ap.language == "bash"
    assert "# do not parse me as a heading" in ap.content  # comment kept, not a Markdown H1


def test_build_attachments_skips_missing(tmp_path):
    good = tmp_path / "a.sh"
    good.write_text("echo a\n")
    result = build_attachments([good, tmp_path / "missing.sh"])
    assert [a.title for a in result] == ["a.sh"]


def test_image_attachment_becomes_image_appendix(tmp_path):
    img = _write_png(tmp_path / "screenshot.png")
    assert is_image(img)
    ap = build_attachment(img)
    assert ap.title == "screenshot.png"
    assert ap.image_path == str(img)
    assert ap.language == ""  # not a verbatim code block
    assert ap.content == ""   # binary not read as text


def test_pipeline_embeds_image_attachment(tmp_path):
    img = _write_png(tmp_path / "evidence.png")
    result = run_pipeline(
        [SAMPLE_MD],
        output_dir=tmp_path / "out",
        formats=["pdf", "docx"],
        enhance=False,
        attachments=[img],
    )
    images = [a for a in result.report.appendices if a.image_path]
    assert len(images) == 1
    assert images[0].image_path == str(img)
    assert list((tmp_path / "out").glob("*.pdf"))
    assert list((tmp_path / "out").glob("*.docx"))


def test_pipeline_appends_attachments_as_appendices(tmp_path):
    script = tmp_path / "harness.sh"
    script.write_text("#!/usr/bin/env bash\narp-scan -I wlan0 10.0.0.0/22\n")
    result = run_pipeline(
        [SAMPLE_MD],
        output_dir=tmp_path / "out",
        formats=["pdf"],
        enhance=False,
        attachments=[script],
    )
    scripts = [a for a in result.report.appendices if a.language]
    assert len(scripts) == 1
    assert scripts[0].title == "harness.sh"
    assert scripts[0].language == "bash"
    assert "arp-scan" in scripts[0].content
    assert (tmp_path / "out").glob("*.pdf")  # report still rendered
