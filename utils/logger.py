"""
CipherGuard — Logging Configuration
Centralized logging setup for all modules.
"""

import logging
import os
from config import LOG_PATH


def setup_logger(name: str = "CipherGuard", level: int = logging.INFO) -> logging.Logger:
    """
    Set up and return a configured logger.

    Args:
        name: Logger name (default: 'CipherGuard').
        level: Logging level (default: INFO).

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # File handler — logs everything to file
    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_format)

    # Console handler — logs warnings and above to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_format = logging.Formatter(
        "[%(levelname)s] %(message)s"
    )
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
