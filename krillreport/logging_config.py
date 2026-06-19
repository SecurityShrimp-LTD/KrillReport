"""Centralized logging configuration for KrillReport.

Every module obtains its logger via :func:`get_logger`, and the application entry
points (CLI / API) call :func:`configure_logging` exactly once at start-up. Keeping
the configuration in one place means library code never calls ``logging.basicConfig``
itself (which would clobber a host application's logging setup).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional, Union

_CONFIGURED = False

# A compact, human-readable format. Timestamps are second-resolution because report
# generation is not a high-frequency operation and finer resolution adds noise.
_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def configure_logging(
    level: Union[str, int] = "INFO",
    *,
    log_file: Optional[Union[str, Path]] = None,
    force: bool = False,
) -> None:
    """Configure the root ``krillreport`` logger.

    Parameters
    ----------
    level:
        Logging level, either a name (``"DEBUG"``) or numeric value.
    log_file:
        Optional path to additionally write logs to. The parent directory is
        created if it does not already exist.
    force:
        Re-apply configuration even if it was already configured this process.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    if isinstance(level, str):
        level = logging.getLevelName(level.upper())

    logger = logging.getLogger("krillreport")
    logger.setLevel(level)
    # Drop any handlers left from a previous (forced) configuration so we do not
    # emit duplicate lines.
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    stream_handler = logging.StreamHandler(stream=sys.stderr)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if log_file is not None:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger of the ``krillreport`` root logger.

    ``name`` is typically ``__name__``; the leading ``krillreport.`` is preserved so
    the hierarchy lines up with the package layout.
    """
    if name == "krillreport" or name.startswith("krillreport."):
        return logging.getLogger(name)
    return logging.getLogger(f"krillreport.{name}")
