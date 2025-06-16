"""Logging utilities used across the framework."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import time
from typing import Optional

from termcolor import colored
from components.ingestor import createfile_nocollision
from oberon_framework import log_banner

_LOGGER_NAME = "oberon"


def configure_logging(log_dir: str = "logs", level: int = logging.INFO) -> Path:
    """Configure the framework logger.

    Parameters
    ----------
    log_dir:
        Directory where log files should be stored.
    level:
        Default logging level.

    Returns
    -------
    Path
        Path to the log file that will receive log entries.
    """

    Path(log_dir).mkdir(parents=True, exist_ok=True)

    from components.ingestor import createfile_nocollision

    current_date = time.strftime("%d-%m-%Y", time.localtime())

    log_filename = createfile_nocollision(f"log_{current_date}", ".log")
    log_path = Path(log_dir) / log_filename

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    with open(log_path, "w") as file_log:
        file_log.write(log_banner())

    return log_path


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a logger with the given name bound to the framework root logger."""

    if name is None:
        name = _LOGGER_NAME
    return logging.getLogger(name)


def log_activity(audit_message: str, log_level: str = "info") -> None:
    """Write a message to the framework log.

    Parameters
    ----------
    audit_message:
        The message to be logged.
    log_level:
        The level at which to log the message. Defaults to ``"info"``.
    """

    logger = logging.getLogger(_LOGGER_NAME)
    try:
        log_func = getattr(logger, log_level.lower())
    except AttributeError:
        logger.error(audit_message)
    else:
        log_func(audit_message)
