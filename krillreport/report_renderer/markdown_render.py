"""Lightweight Markdown rendering shared by the PDF and DOCX renderers.

Finding prose (description/impact/remediation), narrative sections, and imported
appendices frequently arrive as Markdown — especially from ``.md`` source files, where
authors lean on **bold**, ``code``, pipe tables, and bullet lists. The renderers used to
emit that text verbatim, so a table showed up as raw ``| a | b |`` lines and ``**x**``
kept its asterisks. This module parses a pragmatic Markdown subset *once* into a neutral
block model, so both renderers format it the same way — only the emission differs (HTML
for WeasyPrint, python-docx elements for Word).

Scope is deliberately bounded to what pentest reports actually use: ATX headings, GFM
pipe tables (including outer-pipe rows whose cells soft-wrap across lines), ordered and
unordered lists, fenced code, block quotes, paragraphs, and inline **bold** / *italic* /
``code`` / ``[links](url)``. Underscore emphasis requires word boundaries so identifiers
like ``risk_factor`` or ``some_user_name`` are never mangled into italics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape as _esc
from typing import Dict, List, Optional

from markupsafe import Markup

# --------------------------------------------------------------------------- #
# Inline parsing
# --------------------------------------------------------------------------- #


@dataclass
class Seg:
    """An inline text run carrying its active emphasis flags."""

    text: str
    bold: bool = False
    italic: bool = False
    code: bool = False
    href: Optional[str] = None


_CODE_RE = re.compile(r"`([^`]+)`")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(\s*([^)\s]+)[^)]*\)")
# Underscore variants require non-word neighbours so ``a_b_c`` is left untouched.
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*|(?<!\w)__(.+?)__(?!\w)", re.DOTALL)
_ITALIC_RE = re.compile(
    r"\*(?![\s*])(.+?)(?<![\s*])\*|(?<!\w)_(?![\s_])(.+?)(?<![\s_])_(?!\w)", re.DOTALL
)


def _emph(text: str, bold: bool = False, italic: bool = False, href: Optional[str] = None) -> List[Seg]:
    """Recursively resolve link/bold/italic spans into flat styled segments."""
    if not text:
        return []
    best = None  # (kind, match) of the earliest-starting marker
    for kind, rx in (("link", _LINK_RE), ("bold", _BOLD_RE), ("italic", _ITALIC_RE)):
        m = rx.search(text)
        if m and (best is None or m.start() < best[1].start()):
            best = (kind, m)
    if best is None:
        return [Seg(text, bold, italic, False, href)]

    kind, m = best
    segs: List[Seg] = []
    if m.start() > 0:  # literal text before the marker has no further markers
        segs.append(Seg(text[: m.start()], bold, italic, False, href))
    inner = next((g for g in m.groups()[: 2 if kind != "link" else 1] if g is not None), "")
    if kind == "link":
        segs.extend(_emph(m.group(1), bold, italic, m.group(2)))
    elif kind == "bold":
        segs.extend(_emph(inner, True, italic, href))
    else:
        segs.extend(_emph(inner, bold, True, href))
    if m.end() < len(text):
        segs.extend(_emph(text[m.end():], bold, italic, href))
    return segs


def inline_segments(text: str) -> List[Seg]:
    """Split inline text into styled segments; code spans suppress other emphasis."""
    segs: List[Seg] = []
    pos = 0
    for m in _CODE_RE.finditer(text):
        if m.start() > pos:
            segs.extend(_emph(text[pos:m.start()]))
        segs.append(Seg(m.group(1), code=True))
        pos = m.end()
    if pos < len(text):
        segs.extend(_emph(text[pos:]))
    return segs


# --------------------------------------------------------------------------- #
# Block parsing
# --------------------------------------------------------------------------- #

Block = Dict[str, object]

_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*\S)\s*#*\s*$")
_ULI_RE = re.compile(r"^(\s*)[-*+]\s+(.*)$")
_OLI_RE = re.compile(r"^(\s*)\d+[.)]\s+(.*)$")
_FENCE_RE = re.compile(r"^\s*(```|~~~)")
# A table-delimiter row: dashes/colons separated by pipes (a pipe is required so a bare
# ``---`` horizontal rule is not mistaken for one).
_SEP_RE = re.compile(r"^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$")
_QUOTE_RE = re.compile(r"^\s*>\s?(.*)$")


def _split_cells(line: str) -> List[str]:
    """Split one logical table row into cell strings, honouring ``\\|`` and code spans."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    cells: List[str] = []
    buf: List[str] = []
    in_code = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            buf.append("|")
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
            buf.append(ch)
        elif ch == "|" and not in_code:
            cells.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    cells.append("".join(buf).strip())
    return cells


def _is_table_header(lines: List[str], i: int) -> bool:
    return (
        "|" in lines[i]
        and i + 1 < len(lines)
        and "|" in lines[i + 1]
        and bool(_SEP_RE.match(lines[i + 1]))
    )


def _gather_rows(lines: List[str], i: int, header_line: str):
    """Collect table body rows from ``i``; returns ``(rows, next_index)``.

    When the header uses outer pipes, a row is considered complete only once the
    accumulated text ends with ``|`` — this lets a single cell soft-wrap across several
    physical lines (a common shape in hand-written Markdown) without splitting the row.
    """
    multiline = header_line.lstrip().startswith("|") and header_line.rstrip().endswith("|")
    rows: List[List[str]] = []
    buf: Optional[str] = None
    n = len(lines)
    while i < n:
        ln = lines[i]
        if not ln.strip():
            break
        if multiline:
            if buf is None and not ln.lstrip().startswith("|"):
                break
            buf = ln if buf is None else buf + "\n" + ln
            if buf.rstrip().endswith("|"):
                rows.append(_split_cells(buf))
                buf = None
            i += 1
        else:
            if "|" not in ln:
                break
            rows.append(_split_cells(ln))
            i += 1
    if buf is not None:
        rows.append(_split_cells(buf))
    return rows, i


def _is_block_start(lines: List[str], i: int) -> bool:
    ln = lines[i]
    if not ln.strip():
        return True
    if _HEADING_RE.match(ln) or _FENCE_RE.match(ln):
        return True
    if _ULI_RE.match(ln) or _OLI_RE.match(ln):
        return True
    if ln.lstrip().startswith(">"):
        return True
    return _is_table_header(lines, i)


def _gather_list(lines: List[str], i: int, ordered: bool):
    """Collect consecutive list items (with indented continuations); returns items + index."""
    items: List[str] = []
    marker = _OLI_RE if ordered else _ULI_RE
    other = _ULI_RE if ordered else _OLI_RE
    n = len(lines)
    while i < n:
        ln = lines[i]
        if not ln.strip():
            break
        m = marker.match(ln)
        if m:
            items.append(m.group(2).strip())
        elif other.match(ln) or _HEADING_RE.match(ln) or _FENCE_RE.match(ln) or ln.lstrip().startswith(">"):
            break
        elif ln.startswith((" ", "\t")) and items:
            items[-1] += "\n" + ln.strip()
        else:
            break
        i += 1
    return items, i


def parse_blocks(text: str) -> List[Block]:
    """Parse Markdown into an ordered list of neutral block dicts."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    blocks: List[Block] = []
    i, n = 0, len(lines)
    while i < n:
        ln = lines[i]
        if not ln.strip():
            i += 1
            continue

        fence = _FENCE_RE.match(ln)
        if fence:
            token = fence.group(1)
            buf: List[str] = []
            i += 1
            while i < n and not lines[i].lstrip().startswith(token):
                buf.append(lines[i])
                i += 1
            i += 1  # consume closing fence (if any)
            blocks.append({"kind": "code", "text": "\n".join(buf)})
            continue

        hm = _HEADING_RE.match(ln)
        if hm:
            blocks.append({"kind": "heading", "level": len(hm.group(1)), "text": hm.group(2)})
            i += 1
            continue

        if _is_table_header(lines, i):
            header = _split_cells(ln)
            rows, i = _gather_rows(lines, i + 2, ln)
            ncol = len(header)
            norm = [(r + [""] * ncol)[:ncol] for r in rows]
            blocks.append({"kind": "table", "header": header, "rows": norm})
            continue

        if ln.lstrip().startswith(">"):
            buf = []
            while i < n and lines[i].lstrip().startswith(">"):
                buf.append(_QUOTE_RE.match(lines[i]).group(1))
                i += 1
            blocks.append({"kind": "quote", "text": "\n".join(buf)})
            continue

        if _ULI_RE.match(ln) or _OLI_RE.match(ln):
            ordered = bool(_OLI_RE.match(ln))
            items, i = _gather_list(lines, i, ordered)
            blocks.append({"kind": "olist" if ordered else "ulist", "items": items})
            continue

        buf = [ln]
        i += 1
        while i < n and not _is_block_start(lines, i):
            buf.append(lines[i])
            i += 1
        blocks.append({"kind": "para", "text": "\n".join(buf)})
    return blocks


# --------------------------------------------------------------------------- #
# HTML emission (PDF)
# --------------------------------------------------------------------------- #


def _inline_html(text: str) -> str:
    out: List[str] = []
    for seg in inline_segments(text):
        if seg.code:
            out.append(f"<code>{_esc(seg.text)}</code>")
            continue
        piece = _esc(seg.text).replace("\n", "<br>")
        if seg.bold:
            piece = f"<strong>{piece}</strong>"
        if seg.italic:
            piece = f"<em>{piece}</em>"
        if seg.href:
            piece = f'<a href="{_esc(seg.href, quote=True)}">{piece}</a>'
        out.append(piece)
    return "".join(out)


def to_html(text: Optional[str]) -> Markup:
    """Render a Markdown string to safe HTML for the PDF template."""
    if not text or not text.strip():
        return Markup("")
    parts: List[str] = []
    for block in parse_blocks(text):
        kind = block["kind"]
        if kind == "heading":
            parts.append(f'<p class="md-h">{_inline_html(block["text"])}</p>')
        elif kind == "para":
            parts.append(f"<p>{_inline_html(block['text'])}</p>")
        elif kind == "code":
            parts.append(f'<pre class="md-code">{_esc(block["text"])}</pre>')
        elif kind == "quote":
            parts.append(f'<blockquote class="md-quote">{_inline_html(block["text"])}</blockquote>')
        elif kind in ("ulist", "olist"):
            tag = "ol" if kind == "olist" else "ul"
            items = "".join(f"<li>{_inline_html(it)}</li>" for it in block["items"])
            parts.append(f'<{tag} class="md-list">{items}</{tag}>')
        elif kind == "table":
            head = "".join(f"<th>{_inline_html(c)}</th>" for c in block["header"])
            body = "".join(
                "<tr>" + "".join(f"<td>{_inline_html(c)}</td>" for c in row) + "</tr>"
                for row in block["rows"]
            )
            parts.append(
                f'<table class="md-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'
            )
    return Markup("".join(parts))
