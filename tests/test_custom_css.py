"""Custom-CSS PDF restyling (no LibreOffice): injection + template baking."""

from pathlib import Path

from krillreport.ingestion.dispatcher import ingest_paths
from krillreport.normalization.normalizer import normalize
from krillreport.report_renderer.pdf_renderer import PdfRenderer
from krillreport.template_engine import default_branding
from krillreport.template_engine.manager import TemplateManager

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample_inputs" / "manual_findings.md"


def _report():
    return normalize(ingest_paths([SAMPLE]))


def test_custom_css_injected_after_builtin_styles():
    branding = default_branding()
    branding.custom_css = ".cover-band { background: #6A1B9A !important; }"
    html = PdfRenderer().render_html(_report(), branding)
    assert "#6A1B9A" in html
    # User CSS must come last in the cascade so it overrides the defaults.
    assert html.index("Operator custom CSS") > html.index("table.md-table")
    assert html.index("#6A1B9A") > html.index(".cover-band {")  # after the built-in rule


def test_no_custom_css_leaves_no_marker_noise():
    html = PdfRenderer().render_html(_report(), default_branding())
    # Renders fine and the injection block is empty when no custom CSS is set.
    assert "%PDF" not in html  # sanity: it's HTML
    assert "#6A1B9A" not in html


def test_template_loads_custom_css_file(tmp_path):
    mgr = TemplateManager(tmp_path / "templates")
    mgr.create("HousePDF")
    css_path = mgr.write_custom_css("HousePDF", "h2 { color: #123456; }")
    assert css_path.exists()
    # A standalone custom.css in the template dir is picked up on load.
    loaded = mgr.get("HousePDF")
    assert "h2 { color: #123456; }" in loaded.custom_css


def test_custom_css_file_overrides_branding_json(tmp_path):
    mgr = TemplateManager(tmp_path / "templates")
    b = mgr.create("T")
    b.custom_css = "p { color: red; }"
    mgr.save(b)                                  # branding.json has the red rule
    mgr.write_custom_css("T", "p { color: green; }")  # the file says green
    assert "green" in mgr.get("T").custom_css    # file wins


def test_set_logo_override_replaces_extracted_logo(tmp_path):
    from PIL import Image

    mgr = TemplateManager(tmp_path / "templates")
    b = mgr.create("T")
    # Pretend an earlier logo.jpg was extracted.
    (tmp_path / "templates" / "t" / "logo.jpg").write_bytes(b"old-jpeg-bytes")
    b.logo_path = str(tmp_path / "templates" / "t" / "logo.jpg")
    mgr.save(b)

    override = tmp_path / "brand.png"
    Image.new("RGB", (120, 40), (0, 128, 255)).save(override)
    dest = mgr.set_logo("T", override)

    assert dest.name == "logo.png"
    # The old extracted logo is gone; only the override remains.
    assert sorted(p.name for p in (tmp_path / "templates" / "t").glob("logo.*")) == ["logo.png"]
    reloaded = mgr.get("T")
    assert Path(reloaded.logo_path).read_bytes() == override.read_bytes()
