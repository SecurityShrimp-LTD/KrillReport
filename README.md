# 🦐 KrillReport

**Ingest the output of many security tools, normalize it into one data model, and
generate professionally branded penetration-test / red-team reports in both PDF and
DOCX — with optional LLM narrative enhancement.**

KrillReport takes the messy, heterogeneous artifacts produced during an engagement
(scanner exports, CSVs of hosts, hand-written Markdown findings, prior PDF reports) and
turns them into a single, consistent, client-ready report that matches your house style.

---

## Highlights

- **Many input formats** — JSON, CSV/TSV, XML (Nessus, Burp, OpenVAS, Nmap, generic),
  Nmap grepable (`.gnmap`), YAML, plain text, Markdown, and PDF. Tool-specific field
  names are mapped automatically into one model.
- **Smart normalization** — findings are de-duplicated across sources (by CVE or
  normalized title), affected assets/evidence are merged, severities are reconciled with
  CVSS, and hosts are consolidated.
- **Branding templates** — upload a sample branded `.docx` or PDF; KrillReport extracts
  fonts, colours, logo, and header/footer text, and applies them to every generated
  report. Pick a template from a list, or override values manually.
- **Two outputs, one model** — branded **PDF** (HTML/CSS via WeasyPrint) and **DOCX**
  (python-docx), both following standard pentest structure: cover, exec summary, scope,
  methodology, findings summary, detailed findings (severity/CVSS/evidence/remediation),
  asset inventory, conclusion, appendices.
- **LLM narrative enhancement** — structured data fills the fields; an LLM improves the
  prose in executive summaries, finding descriptions, and recommendations. Pluggable
  providers: **Anthropic**, **OpenAI**, **Ollama**, or a deterministic **offline** mode
  (the default) that needs no API key or network.
- **Two interfaces** — a **CLI** and a **FastAPI web UI** for upload → select template →
  generate → download.

---

## Architecture

Modular packages with clear separation of concerns:

```
krillreport/
├── models.py            # the unified normalized data model (Finding, Host, …)
├── config.py            # layered configuration (env > .env > YAML > defaults)
├── pipeline.py          # ingest → normalize → enhance → render orchestration
├── ingestion/           # per-format parsers + format-detecting dispatcher
│   ├── common.py        #   arbitrary tool record -> Finding/Host field mapping
│   ├── json_parser.py  csv_parser.py  xml_parser.py  yaml_parser.py
│   ├── text_parser.py  markdown_parser.py  pdf_parser.py
│   └── dispatcher.py
├── normalization/       # merge / dedupe / group findings, reconcile severity
├── template_engine/     # Branding model + DOCX/PDF branding extraction + manager
├── report_renderer/     # DOCX (python-docx) + PDF (Jinja2 + WeasyPrint)
├── llm_enhancer/        # provider abstraction + Anthropic/OpenAI/Ollama/offline
├── cli/                 # Click command-line interface
└── api/                 # FastAPI backend + server-rendered browser UI
```

Every parser maps into `models.py`; everything downstream is format-agnostic.

---

## Installation

KrillReport needs **Python 3.10+**. The PDF renderer (WeasyPrint) needs a few native
libraries (Pango/Cairo).

```bash
# 1. System libraries for WeasyPrint (Debian/Ubuntu example)
sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 libffi-dev libcairo2
#   macOS:  brew install pango cairo gdk-pixbuf libffi

# 2. Create a virtual environment and install
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .          # installs the `krillreport` command

# The LLM SDKs are optional — install only what you use:
#   pip install anthropic     # provider: anthropic
#   pip install openai        # provider: openai / OpenAI-compatible
#   pip install httpx         # provider: ollama (usually already present)
```

> The default `offline` LLM provider needs none of the SDKs, no API key, and no network.

---

## Quick start — CLI

The repo ships ready-made example inputs under `examples/sample_inputs/`.

```bash
# Generate a sample branding template from a sample branded .docx (one-time):
python examples/make_sample_template.py
krillreport templates add examples/sample_templates/acme_brand.docx --name "ACME Corp"

# Inspect what would be ingested (dry run — no rendering):
krillreport inspect examples/sample_inputs/*

# Generate branded PDF + DOCX from every example input, using the ACME template:
krillreport generate examples/sample_inputs/* \
    --template acme-corp \
    --client "ACME Corporation" \
    --engagement-type "Penetration Test" \
    --name acme_engagement

# Outputs land in ./krilldata/output/ by default:
#   acme_engagement.pdf   acme_engagement.docx
```

Other useful commands:

```bash
krillreport templates list                      # list available templates
krillreport templates show acme-corp            # print a template's branding as JSON
krillreport generate report.json -f pdf         # PDF only
krillreport generate findings.md --attach poc.sh --attach setup.sh   # scripts → appendices
krillreport templates scaffold -o layout.docx   # starter layout template (edit in Word)
krillreport generate findings.md --layout-template layout.docx       # render DOCX into it
krillreport generate findings.md --css house.css                     # restyle the PDF (no LibreOffice)
krillreport generate report.json --no-enhance   # skip narrative enhancement
krillreport generate report.json --provider anthropic   # use Claude for prose
krillreport --help                              # full help
```

### Key `generate` options

| Option | Description |
|---|---|
| `-t, --template` | Branding template name (default: `default`). |
| `-f, --format` | `pdf` and/or `docx` (repeatable; default both). |
| `-o, --output-dir` | Output directory (default `<data-dir>/output`). |
| `--name` | Output filename stem. |
| `--attach` | File reproduced verbatim as an appendix (e.g. an engagement script); repeatable. |
| `--layout-template` | A `.docx` to render the DOCX report into for layout fidelity (see `templates scaffold`). |
| `--css` | A CSS file appended to the PDF stylesheet to restyle it (no LibreOffice needed). |
| `--logo` | A logo image to use for this run (overrides the template's logo). |
| `--client` / `--project` / `--report-title` | Metadata overrides. |
| `--engagement-type` | e.g. `"Red Team"`, `"Penetration Test"`. |
| `--classification` | Cover/header classification banner. |
| `--provider` / `--model` | LLM provider/model override for this run. |
| `--no-enhance` | Leave narrative exactly as ingested. |

---

## Quick start — Web UI

```bash
krillreport serve            # http://127.0.0.1:8000
#   or: uvicorn krillreport.api:app --reload
```

**Walkthrough**

1. Open `http://127.0.0.1:8000`.
2. **Branding templates** card → *Add template from a branded sample*: upload a branded
   `.docx` or PDF and give it a name. Its colours, fonts and logo are extracted and it
   appears in the template list.
3. **Generate a report** card:
   - Upload one or more tool-output files — browse repeatedly or drag & drop to gather
     files from several folders; selections accumulate and can be removed individually.
   - Optionally add **Attachments** (scripts/configs) to include verbatim as appendices.
   - Optionally add a **Layout template** (`.docx`) to render the DOCX into for layout fidelity.
   - Choose a branding template and output format(s).
   - Optionally expand *Engagement details* to set client/project/title/etc.
   - Optionally expand *Narrative enhancement* to pick an LLM provider (default `offline`).
   - Click **Generate report**.
4. On the result page, review the findings summary and **download** the PDF / DOCX.

JSON endpoints are also available: `GET /api/health`, `GET /api/templates`.

---

## Supported input formats

| Format | Extensions | Notes |
|---|---|---|
| JSON | `.json` | Objects, arrays, JSON Lines; nested tool structures auto-discovered. |
| CSV / TSV | `.csv`, `.tsv` | Auto-detects findings vs host inventories from columns. |
| XML | `.xml`, `.nessus` | Nessus `ReportItem`, Burp `issue`, OpenVAS `result`, Nmap hosts, generic. |
| Nmap grepable | `.gnmap` | `nmap -oG` output → host inventory (open ports, services, OS). |
| YAML | `.yaml`, `.yml` | Same structure handling as JSON; multi-document supported. |
| Text | `.txt`, `.text`, `.log` | `Key: Value` blocks, `[Severity]` markers, narrative sections. |
| Markdown | `.md`, `.markdown` | `#` title, `##`/`###` finding headings, labelled fields, code fences as evidence. |
| PDF | `.pdf` | Tables + body text; falls back to an appendix when unstructured. |

Findings, hosts, engagement metadata, scope, severity, CVSS/CVE/CWE, evidence and
references are all extracted where present, and anything unrecognized is preserved as an
appendix rather than dropped.

---

## Branding & templates

Upload a sample branded report and KrillReport approximates its house style:

- **DOCX samples** — extracts body/heading fonts, the strongest brand colours, the first
  embedded image as a logo, and header/footer text.
- **PDF samples** — infers dominant colours and fonts and the page size (logo extraction
  from PDF is intentionally skipped as unreliable).

Anything not detected falls back to clean defaults, and you can override any value
(`krillreport templates add … --primary "#0E7C7B"`, or edit the saved
`branding.json`). Templates live under `<data-dir>/templates/<name>/`.

The logo is the largest embedded image (EMF/WMF logos are converted via LibreOffice when
available). If your sample's "logo" is WordArt/live text — or extraction picks the wrong
image — supply one explicitly: `templates add brand.docx --logo logo.png`, a one-off
`generate … --logo logo.png`, the **Logo (optional)** field on the web *Add template* form,
or drop a `logo.<ext>` into the template folder.

Branding is a *skin* applied to KrillReport's own layout. For **layout fidelity** — your
cover, headers/footers, fonts and section structure — use a **layout template** instead:

```bash
krillreport templates scaffold -o layout.docx          # starter template with anchors
# …style layout.docx in Word: cover art, fonts, headers/footers, etc…
krillreport generate inputs/* --layout-template layout.docx -f docx
```

The DOCX is rendered *into* your template: scalar tokens (`{{report_title}}`, `{{client}}`,
`{{date}}`, …) are replaced inline, and block anchors (`{{executive_summary}}`,
`{{findings}}`, `{{asset_inventory}}`, …) — each alone on its own line — expand into the
generated section using your template's styles. A template with **no** anchors still works:
the full report is appended after its content.

For a **template-faithful PDF**, install **LibreOffice** (`soffice` on `PATH`): in
layout-template mode the PDF is produced by converting the filled DOCX, so both outputs
match. Without LibreOffice the PDF falls back to the built-in layout (a warning is logged).

### Custom PDF styling (no LibreOffice)

To restyle the built-in PDF to your house style without LibreOffice, append your own CSS —
it is added after the built-in stylesheet, so your rules win:

```bash
krillreport generate inputs/* --css house.css          # ad-hoc for one run
krillreport templates add brand.docx --name Acme --css house.css   # bake into a template
```

You can also drop a `custom.css` into a template folder
(`<data-dir>/templates/<name>/custom.css`) and edit it directly, or upload one in the web
UI. Useful selectors: `.cover-band` / `.cover-title` / `.cover-sub` (cover), `h2`, `h3`,
`h4` (section headings), `table.grid` / `table.grid th` (summary & asset tables),
`.meta-table` (finding metadata), `.finding` (a finding card), `.badge` (severity pills),
`pre.evidence` (evidence blocks), `table.md-table` / `pre.md-code` (rendered Markdown),
and `@page` (margins/size).

---

## LLM narrative enhancement

Configure via `.env` (copy `.env.example`) or `config.yaml` (copy `config.example.yaml`):

```bash
KRILLREPORT_LLM__PROVIDER=anthropic      # offline | anthropic | openai | ollama
KRILLREPORT_LLM__MODEL=                  # blank = provider default
ANTHROPIC_API_KEY=sk-ant-...             # provider-native key (or KRILLREPORT_LLM__API_KEY)
```

- **offline** (default) — deterministic, template-based prose. Fills only *missing*
  narrative; never overwrites text you supplied. No key, no network — always works.
- **anthropic** — Claude (default model `claude-opus-4-8`). Needs `anthropic` + `ANTHROPIC_API_KEY`.
- **openai** — GPT (default `gpt-4o`); set `KRILLREPORT_LLM__BASE_URL` for OpenAI-compatible gateways.
- **ollama** — local models via `http://localhost:11434` (override with `BASE_URL`).

If a selected provider is unavailable or a call fails, KrillReport automatically falls
back to the offline templates so a report is always produced.

---

## Configuration

Settings resolve in order of precedence: **CLI flags → environment variables → `.env`
→ YAML config (`config.yaml`, or `$KRILLREPORT_CONFIG`) → defaults**.

| Setting | Env var | Default |
|---|---|---|
| Data directory | `KRILLREPORT_DATA_DIR` | `krilldata` |
| Web host / port | `KRILLREPORT_HOST` / `KRILLREPORT_PORT` | `127.0.0.1` / `8000` |
| Log level | `KRILLREPORT_LOG_LEVEL` | `INFO` |
| LLM provider | `KRILLREPORT_LLM__PROVIDER` | `offline` |

Templates, uploads and outputs default to sub-directories of the data directory.

---

## Examples directory

```
examples/
├── make_sample_template.py     # generates a branded sample .docx for templating
├── generate_demo.py            # end-to-end demo script (ingest → render)
└── sample_inputs/              # one file per supported format
    ├── scanner_findings.json   web_findings.csv   host_inventory.csv
    ├── nessus_scan.nessus      nmap_scan.xml      redteam_findings.yaml
    ├── manual_findings.md      consultant_notes.txt
```

Run the full demo:

```bash
python examples/make_sample_template.py
python examples/generate_demo.py        # writes reports to ./krilldata/output/
```

---

## Development & tests

```bash
pip install -e ".[all]" pytest
pytest -q
```

Tests under `tests/` cover ingestion mapping, normalization/dedup, and the full
render pipeline (with the offline provider, so they run without credentials).

---

## Notes

- KrillReport is a reporting tool for **authorized** security engagements. It processes
  the data you give it and does not perform any scanning or testing itself.
- Generated DOCX files include a Word table-of-contents *field*; open the document and
  choose **Update Field** (or print) to populate page numbers.
- The web UI ships without authentication — run it locally or behind your own
  authenticating reverse proxy; do not expose it directly to untrusted networks.
