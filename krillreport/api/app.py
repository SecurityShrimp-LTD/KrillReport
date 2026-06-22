"""FastAPI web backend + server-rendered browser UI.

Endpoints
---------
* ``GET  /``                       — the UI: upload form, template selection, options.
* ``POST /generate``               — ingest uploads, run the pipeline, show results.
* ``GET  /download/{run}/{file}``  — download a generated report.
* ``POST /templates``              — create a branding template from an uploaded sample.
* ``POST /templates/{name}/delete``— delete a template.
* ``GET  /api/health``             — JSON health check.
* ``GET  /api/templates``          — JSON list of templates.

The UI is intentionally a small, dependency-free server-rendered app (Jinja2 + a single
CSS file) so it runs anywhere the package does. All heavy lifting is delegated to
:func:`krillreport.pipeline.run_pipeline`.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..config import LLMSettings, Settings, get_settings
from ..ingestion import supported_extensions
from ..logging_config import configure_logging, get_logger
from ..pipeline import run_pipeline
from ..template_engine import SUPPORTED_TEMPLATE_EXTENSIONS, TemplateManager

logger = get_logger(__name__)

_HERE = Path(__file__).resolve().parent
_TEMPLATES_DIR = _HERE / "templates"
_STATIC_DIR = _HERE / "static"

_RUN_ID_RE = re.compile(r"^[0-9a-f]{8,32}$")
_PROVIDERS = ["offline", "anthropic", "openai", "ollama"]


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """Application factory."""
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    settings.ensure_dirs()

    app = FastAPI(title="KrillReport", version=__version__)
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    def template_manager() -> TemplateManager:
        return TemplateManager(settings.templates_dir)

    def _ui_context(request: Request, **extra) -> dict:
        manager = template_manager()
        context = {
            "request": request,
            "version": __version__,
            "templates": manager.list_templates(),
            "supported_extensions": sorted(supported_extensions()),
            "template_extensions": sorted(SUPPORTED_TEMPLATE_EXTENSIONS),
            "providers": _PROVIDERS,
            "current_provider": settings.llm.provider,
            "llm_enabled": settings.llm.enabled,
        }
        context.update(extra)
        return context

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "index.html", _ui_context(request))

    @app.post("/generate", response_class=HTMLResponse)
    async def generate(
        request: Request,
        files: List[UploadFile] = File(...),
        attachments: List[UploadFile] = File([]),
        layout_template: List[UploadFile] = File([]),
        custom_css: List[UploadFile] = File([]),
        template: str = Form("default"),
        formats: List[str] = Form([]),
        client: str = Form(""),
        project: str = Form(""),
        report_title: str = Form(""),
        engagement_type: str = Form(""),
        classification: str = Form(""),
        provider: str = Form(""),
        model: str = Form(""),
        enhance: str = Form("on"),
    ) -> HTMLResponse:
        formats = [f for f in formats if f in ("pdf", "docx")] or ["pdf", "docx"]
        run_id = uuid.uuid4().hex[:16]

        upload_dir = settings.upload_dir / run_id
        upload_dir.mkdir(parents=True, exist_ok=True)
        saved_paths = await _save_uploads(files, upload_dir)
        if not saved_paths:
            return templates.TemplateResponse(
                request,
                "index.html",
                _ui_context(request, error="No files were uploaded."),
                status_code=400,
            )
        attach_dir = upload_dir / "attachments"
        attach_dir.mkdir(exist_ok=True)
        attachment_paths = await _save_uploads(attachments, attach_dir)
        layout_dir = upload_dir / "layout"
        layout_dir.mkdir(exist_ok=True)
        layout_paths = await _save_uploads(layout_template, layout_dir)

        branding = template_manager().get(template)
        css_paths = await _save_uploads(custom_css, upload_dir / "css")
        if css_paths:
            extra = css_paths[0].read_text(encoding="utf-8", errors="replace")
            branding.custom_css = (branding.custom_css + "\n" + extra).strip()
        overrides = {
            k: v
            for k, v in {
                "client_name": client.strip(),
                "project_name": project.strip(),
                "report_title": report_title.strip(),
                "engagement_type": engagement_type.strip(),
                "classification": classification.strip(),
            }.items()
            if v
        }
        llm_settings = _resolve_llm_settings(settings.llm, provider, model)

        try:
            result = run_pipeline(
                saved_paths,
                output_dir=settings.output_dir / run_id,
                branding=branding,
                formats=formats,
                metadata_overrides=overrides,
                llm_settings=llm_settings,
                enhance=(enhance == "on"),
                attachments=attachment_paths,
                layout_template=layout_paths[0] if layout_paths else None,
            )
        except Exception as exc:  # surface a friendly error rather than a 500 page
            logger.exception("Report generation failed")
            return templates.TemplateResponse(
                request,
                "index.html",
                _ui_context(request, error=f"Report generation failed: {exc}"),
                status_code=500,
            )

        summary = result.report.summary()
        downloads = [
            {"format": fmt.upper(), "url": f"/download/{run_id}/{path.name}", "name": path.name}
            for fmt, path in result.outputs.items()
        ]
        return templates.TemplateResponse(
            request,
            "result.html",
            _ui_context(
                request,
                report=result.report,
                summary=summary,
                downloads=downloads,
                warnings=result.warnings,
                enhancement_mode=result.enhancement_mode,
                template_name=branding.display_name,
                input_count=len(saved_paths),
            ),
        )

    @app.get("/download/{run_id}/{filename}")
    def download(run_id: str, filename: str) -> FileResponse:
        # Validate both path components to prevent traversal.
        if not _RUN_ID_RE.match(run_id) or "/" in filename or "\\" in filename or ".." in filename:
            raise HTTPException(status_code=400, detail="Invalid download path.")
        path = (settings.output_dir / run_id / filename).resolve()
        output_root = settings.output_dir.resolve()
        if output_root not in path.parents or not path.is_file():
            raise HTTPException(status_code=404, detail="File not found.")
        return FileResponse(str(path), filename=filename)

    @app.post("/templates")
    async def create_template(
        sample: UploadFile = File(...),
        name: str = Form(""),
    ) -> RedirectResponse:
        suffix = Path(sample.filename or "").suffix.lower()
        tmp_dir = settings.upload_dir / f"tmpl_{uuid.uuid4().hex[:12]}"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        sample_path = tmp_dir / (Path(sample.filename or "sample").name or f"sample{suffix}")
        sample_path.write_bytes(await sample.read())
        manager = template_manager()
        manager.create_from_sample(sample_path, name=name.strip() or None)
        return RedirectResponse(url="/", status_code=303)

    @app.post("/templates/{name}/delete")
    def delete_template(name: str) -> RedirectResponse:
        template_manager().delete(name)
        return RedirectResponse(url="/", status_code=303)

    # ------------------------------------------------------------------ #
    # JSON API
    # ------------------------------------------------------------------ #

    @app.get("/api/health")
    def health() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "version": __version__,
                "llm_provider": settings.llm.provider,
                "llm_enabled": settings.llm.enabled,
            }
        )

    @app.get("/api/templates")
    def api_templates() -> JSONResponse:
        return JSONResponse([b.model_dump() for b in template_manager().list_templates()])

    return app


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


async def _save_uploads(files: List[UploadFile], dest_dir: Path) -> List[Path]:
    saved: List[Path] = []
    for upload in files:
        if not upload.filename:
            continue
        safe_name = Path(upload.filename).name  # strip any directory component
        target = dest_dir / safe_name
        content = await upload.read()
        if not content:
            continue
        target.write_bytes(content)
        saved.append(target)
    return saved


def _resolve_llm_settings(base: LLMSettings, provider: str, model: str) -> LLMSettings:
    provider = (provider or "").strip()
    model = (model or "").strip()
    if not provider and not model:
        return base
    return LLMSettings(
        provider=provider or base.provider,
        model=model or "",
        api_key=base.api_key,
        base_url=base.base_url,
        max_tokens=base.max_tokens,
        temperature=base.temperature,
        timeout=base.timeout,
        enabled=base.enabled,
    )


# Module-level app for `uvicorn krillreport.api:app` and the CLI `serve` command.
app = create_app()
