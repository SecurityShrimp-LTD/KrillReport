"""Tests for the shared Markdown rendering layer used by both report renderers."""

from krillreport.report_renderer.markdown_render import (
    inline_segments,
    parse_blocks,
    to_html,
)


def test_inline_bold_italic_code_link():
    segs = inline_segments("a **b** and *c* and `d` and [e](http://x)")
    bolds = [s.text for s in segs if s.bold]
    italics = [s.text for s in segs if s.italic]
    codes = [s.text for s in segs if s.code]
    links = [(s.text, s.href) for s in segs if s.href]
    assert bolds == ["b"]
    assert italics == ["c"]
    assert codes == ["d"]
    assert links == [("e", "http://x")]


def test_underscore_identifiers_not_italicised():
    # Intraword underscores (identifiers) must survive verbatim.
    segs = inline_segments("set risk_factor and some_user_name now")
    assert not any(s.italic for s in segs)
    assert "".join(s.text for s in segs) == "set risk_factor and some_user_name now"


def test_html_escapes_and_formats():
    html = str(to_html("Use **bold** & `<tag>` here"))
    assert "<strong>bold</strong>" in html
    assert "<code>&lt;tag&gt;</code>" in html
    assert "&amp;" in html  # ampersand escaped, not literal


def test_pipe_table_parsed_to_table_block():
    md = (
        "| Component | Detail |\n"
        "|---|---|\n"
        "| Enterprise CA | `firstbusey-CA` |\n"
        "| Domain | `firstbusey.corp` |\n"
    )
    blocks = parse_blocks(md)
    assert len(blocks) == 1
    table = blocks[0]
    assert table["kind"] == "table"
    assert table["header"] == ["Component", "Detail"]
    assert len(table["rows"]) == 2
    assert table["rows"][0][0] == "Enterprise CA"
    html = str(to_html(md))
    assert "<table" in html and "<th>Component</th>" in html


def test_table_cell_soft_wraps_across_lines():
    # A single outer-pipe row whose second cell wraps over three physical lines.
    md = (
        "| Templates | Notes |\n"
        "|---|---|\n"
        "| ESC1 | `IntuneWirelessUser`, `IntuneVPNUser`\n"
        "— each: `Domain Users` enroll,\n"
        "**EnrolleeSuppliesSubject** |\n"
    )
    table = parse_blocks(md)[0]
    assert table["kind"] == "table"
    assert len(table["rows"]) == 1
    cell = table["rows"][0][1]
    assert "IntuneWirelessUser" in cell
    assert "EnrolleeSuppliesSubject" in cell  # the wrapped tail is kept in the cell
    # And the wrapped row does not leak into a second bogus row.
    assert table["rows"][0][0] == "ESC1"


def test_lists_and_code_fence():
    md = "- one\n- two\n\n```\ncode here\n```\n"
    blocks = parse_blocks(md)
    kinds = [b["kind"] for b in blocks]
    assert kinds == ["ulist", "code"]
    assert blocks[0]["items"] == ["one", "two"]
    assert blocks[1]["text"] == "code here"
    html = str(to_html(md))
    assert "<ul" in html and "<li>one</li>" in html
    assert "<pre" in html


def test_plain_prose_passes_through_as_paragraphs():
    blocks = parse_blocks("First line.\n\nSecond paragraph.")
    assert [b["kind"] for b in blocks] == ["para", "para"]
    assert blocks[0]["text"] == "First line."
