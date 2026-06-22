"""Smoke tests for the web UI's accumulating file-upload enhancement."""

from pathlib import Path

from fastapi.testclient import TestClient

from krillreport.api import app

client = TestClient(app)


def test_index_marks_file_inputs_for_accumulation():
    html = client.get("/").text
    # Both the data-files and attachments inputs opt into JS accumulation.
    assert html.count("data-accumulate") == 2
    assert '/static/upload.js' in html


def test_add_template_with_logo_override(tmp_path):
    import io
    import json
    from PIL import Image
    from docx import Document
    from krillreport.api.app import create_app
    from krillreport.config import get_settings

    # Isolated app so the created template doesn't touch the real data dir.
    iso = TestClient(create_app(get_settings(reload=True, data_dir=tmp_path)))
    assert 'name="logo"' in iso.get("/").text  # the add-template form exposes the field

    sbuf = io.BytesIO()
    Document().save(sbuf)  # a sample with no usable logo
    lbuf = io.BytesIO()
    Image.new("RGB", (160, 50), (10, 90, 200)).save(lbuf, format="PNG")
    r = iso.post(
        "/templates",
        files=[
            ("sample", ("brand.docx", sbuf.getvalue(),
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document")),
            ("logo", ("logo.png", lbuf.getvalue(), "image/png")),
        ],
        data={"name": "LogoTest"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    branding = json.loads((tmp_path / "templates" / "logotest" / "branding.json").read_text())
    assert branding["logo_path"].endswith("logo.png")
    assert Path(branding["logo_path"]).read_bytes() == lbuf.getvalue()


def test_health_and_footer_report_libreoffice_status():
    health = client.get("/api/health").json()
    assert "libreoffice" in health and isinstance(health["libreoffice"], bool)
    footer = client.get("/").text
    assert ("LibreOffice (exact)" in footer) or ("built-in layout" in footer)


def test_upload_js_and_styles_served():
    js = client.get("/static/upload.js")
    assert js.status_code == 200
    assert "DataTransfer" in js.text  # the accumulation mechanism
    css = client.get("/static/style.css")
    assert ".filelist" in css.text  # styles for the accumulated-file chips


def test_multiple_files_still_post_in_one_request():
    # The server already accepts many files in one multipart request (what the
    # accumulated FileList submits); guard that contract.
    md = b"# T\n## Exec Summary\nx\n## SQLi\nSeverity: High\nbad\n"
    csv = b"host,ip,os,port\nweb01,10.0.0.1,Linux,443\n"
    r = client.post(
        "/generate",
        files=[
            ("files", ("a.md", md, "text/markdown")),
            ("files", ("b.csv", csv, "text/csv")),
        ],
        data={"formats": ["pdf"], "enhance": "off"},
    )
    assert r.status_code == 200
