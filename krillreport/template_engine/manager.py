"""Template storage and selection.

Each template lives in its own directory under ``templates_dir``::

    templates_dir/
      acme-corp/
        branding.json     # serialized Branding
        logo.png          # extracted logo (optional)
        sample.docx       # the uploaded sample, kept for reference (optional)

The built-in ``default`` template is always available and is not stored on disk.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logging_config import get_logger
from .branding import Branding, default_branding, make_template_id
from .extractor import SUPPORTED_TEMPLATE_EXTENSIONS, extract_branding

logger = get_logger(__name__)

_BRANDING_FILE = "branding.json"
_CUSTOM_CSS_FILE = "custom.css"
DEFAULT_TEMPLATE_NAME = "default"


class TemplateManager:
    """Create, list, fetch and delete report branding templates."""

    def __init__(self, templates_dir: Path):
        self.templates_dir = Path(templates_dir).resolve()
        self.templates_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Query
    # ------------------------------------------------------------------ #

    def list_templates(self) -> List[Branding]:
        """Return all templates, with the built-in default first."""
        templates: List[Branding] = [default_branding()]
        for entry in sorted(self.templates_dir.iterdir()):
            if not entry.is_dir():
                continue
            branding = self._load(entry)
            if branding is not None:
                templates.append(branding)
        return templates

    def list_names(self) -> List[str]:
        return [b.name for b in self.list_templates()]

    def get(self, name: Optional[str]) -> Branding:
        """Fetch a template by name, falling back to the default if missing/None."""
        if not name or name == DEFAULT_TEMPLATE_NAME:
            return default_branding()
        slug = make_template_id(name)
        branding = self._load(self.templates_dir / slug)
        if branding is None:
            logger.warning("Template %r not found; using default branding.", name)
            return default_branding()
        return branding

    def exists(self, name: str) -> bool:
        slug = make_template_id(name)
        return (self.templates_dir / slug / _BRANDING_FILE).exists()

    # ------------------------------------------------------------------ #
    # Mutate
    # ------------------------------------------------------------------ #

    def create_from_sample(
        self,
        sample_path: Path,
        *,
        name: Optional[str] = None,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Branding:
        """Create (or overwrite) a template by extracting branding from a sample doc."""
        sample_path = Path(sample_path)
        if sample_path.suffix.lower() not in SUPPORTED_TEMPLATE_EXTENSIONS:
            logger.warning(
                "Sample %s has unsupported extension; extraction will use defaults.",
                sample_path.name,
            )
        display = name or sample_path.stem
        slug = make_template_id(display)
        template_dir = self.templates_dir / slug
        template_dir.mkdir(parents=True, exist_ok=True)

        branding = extract_branding(
            sample_path, template_dir, name=display, overrides=overrides
        )

        # Keep a copy of the original sample for reference / re-extraction.
        try:
            shutil.copy2(sample_path, template_dir / f"sample{sample_path.suffix.lower()}")
        except OSError as exc:  # pragma: no cover
            logger.debug("Could not copy sample into template dir: %s", exc)

        self.save(branding)
        logger.info("Created template %r from %s", slug, sample_path.name)
        return branding

    def write_custom_css(self, name: str, css_text: str) -> Path:
        """Write ``custom.css`` into a template dir (the editable PDF-restyle source)."""
        template_dir = self.templates_dir / make_template_id(name)
        template_dir.mkdir(parents=True, exist_ok=True)
        path = template_dir / _CUSTOM_CSS_FILE
        path.write_text(css_text, encoding="utf-8")
        return path

    def set_logo(self, name: str, logo_source: Path) -> Path:
        """Copy an explicit logo into a template, overriding auto-extraction."""
        logo_source = Path(logo_source)
        template_dir = self.templates_dir / make_template_id(name)
        template_dir.mkdir(parents=True, exist_ok=True)
        # Remove any previously-extracted logo so logo_path is unambiguous.
        for existing in template_dir.glob("logo.*"):
            existing.unlink()
        ext = logo_source.suffix.lower() or ".png"
        dest = template_dir / f"logo{ext}"
        shutil.copy2(logo_source, dest)
        branding = self._load(template_dir)
        if branding is not None:
            branding.logo_path = str(dest)
            self.save(branding)
        return dest

    def create(self, name: str, branding: Optional[Branding] = None, **overrides: Any) -> Branding:
        """Create a template directly from a Branding object or field overrides."""
        slug = make_template_id(name)
        if branding is None:
            base = default_branding().model_dump()
            base.update({k: v for k, v in overrides.items() if v not in (None, "")})
            base["name"] = slug
            base["display_name"] = name
            branding = Branding(**base)
        else:
            branding = branding.model_copy(update={"name": slug, "display_name": name})
        (self.templates_dir / slug).mkdir(parents=True, exist_ok=True)
        self.save(branding)
        return branding

    def save(self, branding: Branding) -> None:
        """Persist a Branding to its template directory."""
        template_dir = self.templates_dir / branding.name
        template_dir.mkdir(parents=True, exist_ok=True)
        path = template_dir / _BRANDING_FILE
        path.write_text(branding.model_dump_json(indent=2), encoding="utf-8")

    def delete(self, name: str) -> bool:
        """Delete a template directory. Returns True if it existed."""
        if name == DEFAULT_TEMPLATE_NAME:
            logger.warning("Refusing to delete the built-in default template.")
            return False
        slug = make_template_id(name)
        template_dir = self.templates_dir / slug
        if template_dir.exists():
            shutil.rmtree(template_dir, ignore_errors=True)
            logger.info("Deleted template %r", slug)
            return True
        return False

    # ------------------------------------------------------------------ #

    def _load(self, template_dir: Path) -> Optional[Branding]:
        path = template_dir / _BRANDING_FILE
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            branding = Branding(**data)
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            logger.warning("Could not load template at %s: %s", template_dir, exc)
            return None
        # A standalone custom.css in the template dir is the editable source of truth for
        # PDF restyling — if present it overrides whatever is stored in branding.json.
        css_path = template_dir / _CUSTOM_CSS_FILE
        if css_path.exists():
            try:
                branding.custom_css = css_path.read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning("Could not read %s: %s", css_path, exc)
        return branding
