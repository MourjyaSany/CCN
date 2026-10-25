"""Centralised logging configuration.

A single :func:`setup_logging` call configures the root logger for console
output and, optionally, a rotating run log under ``results/logs``.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from .paths import ensure_dir

_DEFAULT_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)-28s | %(message)s"
_CONFIGURED = False


class _ColourFormatter(logging.Formatter):
    """Formatter that adds ANSI colour when the stream is a TTY."""

    _COLOURS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[1;31m",
    }
    _RESET = "\033[0m"

    def __init__(self, fmt: str, use_colour: bool) -> None:
        super().__init__(fmt, datefmt="%H:%M:%S")
        self.use_colour = use_colour

    def format(self, record: logging.LogRecord) -> str:  # noqa: D102
        text = super().format(record)
        if self.use_colour:
            colour = self._COLOURS.get(record.levelname, "")
            if colour:
                text = f"{colour}{text}{self._RESET}"
        return text


def setup_logging(
    level: str = "INFO",
    fmt: str = _DEFAULT_FORMAT,
    log_file: str | Path | None = None,
    force: bool = False,
) -> logging.Logger:
    """Configure the root logger once per process.

    Args:
        level: Logging level name (``"DEBUG"``, ``"INFO"``, ...).
        fmt: ``logging`` format string.
        log_file: Optional path for a plain-text copy of the log.
        force: Reconfigure even if logging was already set up.

    Returns:
        The configured root logger.
    """
    global _CONFIGURED
    root = logging.getLogger()
    if _CONFIGURED and not force:
        return root

    for handler in list(root.handlers):
        root.removeHandler(handler)

    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    console = logging.StreamHandler(stream=sys.stdout)
    console.setFormatter(_ColourFormatter(fmt, use_colour=sys.stdout.isatty()))
    root.addHandler(console)

    if log_file is not None:
        path = Path(log_file)
        ensure_dir(path.parent)
        file_handler = logging.FileHandler(path, mode="a", encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(fmt))
        root.addHandler(file_handler)

    # Third-party noise reduction.
    for noisy in ("matplotlib", "PIL", "asyncio", "urllib3", "watchfiles"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True
    return root


def get_logger(name: str) -> logging.Logger:
    """Return a module logger, configuring logging lazily if needed."""
    if not _CONFIGURED:
        setup_logging()
    return logging.getLogger(name)
