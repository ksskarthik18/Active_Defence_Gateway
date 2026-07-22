"""
utils.py

Common utility functions for the Active Defense Gateway (ADG).
This module should remain generic and contain reusable helper
functions only. Do NOT place policy or controller logic here.
"""

import logging
import re
from datetime import datetime


# -------------------------------
# Logging
# -------------------------------

def get_logger(name: str) -> logging.Logger:
    """
    Create or return a configured logger.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s :: %(message)s",
            datefmt="%H:%M:%S",
        )

        handler = logging.StreamHandler()
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    return logger


# -------------------------------
# Time
# -------------------------------

def timestamp() -> str:
    """Return current timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# -------------------------------
# Validation
# -------------------------------

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def is_valid_mac(mac: str) -> bool:
    """Validate MAC address."""
    return bool(MAC_REGEX.match(mac))


# -------------------------------
# Formatting
# -------------------------------

def format_packet(src: str, dst: str, in_port: int) -> str:
    """
    Pretty-print packet metadata.
    """
    return (
        f"SRC={src} | "
        f"DST={dst} | "
        f"PORT={in_port}"
    )


def divider(title: str = "") -> str:
    """
    Create a readable divider for logs.
    """
    if title:
        return f"\n========== {title} =========="
    return "\n=============================="


# -------------------------------
# Debug
# -------------------------------

def debug_packet(logger, src, dst, port):
    """
    Log packet information.
    """
    logger.info(format_packet(src, dst, port))