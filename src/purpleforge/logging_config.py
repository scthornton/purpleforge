"""Logging setup for the CLI and a per-run log file."""

from __future__ import annotations

import logging
from pathlib import Path

PACKAGE_LOGGER = "purpleforge"
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure the package logger level and a console handler.

    DEBUG when verbose, WARNING when quiet, INFO otherwise. Quiet wins when both
    are set. Safe to call more than once; it does not stack console handlers.
    """
    level = logging.INFO
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG

    logger = logging.getLogger(PACKAGE_LOGGER)
    logger.setLevel(level)
    logger.propagate = False

    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
            handler.setLevel(level)
            break
    else:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        logger.addHandler(console_handler)


def add_run_log_handler(log_path: Path) -> logging.FileHandler:
    """Attach a file handler that records the package logger into a run's run.log."""
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    logging.getLogger(PACKAGE_LOGGER).addHandler(handler)
    return handler


def remove_run_log_handler(handler: logging.FileHandler) -> None:
    """Detach and close a run log handler so handlers do not leak across runs."""
    logging.getLogger(PACKAGE_LOGGER).removeHandler(handler)
    handler.close()
