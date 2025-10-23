"""
Safe utility helpers: parsing, reporting, logging setup.
These functions perform only local, non-invasive tasks.
"""

import logging
import json
from datetime import datetime
from urllib.parse import urlparse

DEFAULT_TIMEOUT = 5

def setup_logging(log_file="anish_scanner.log"):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.info("Logging initialized.")

def parse_target_url(user_input: str):
    """
    Normalize user input into a URL string and return (url, domain).
    This function does not perform network IO.
    """
    if not user_input:
        raise ValueError("Target URL required")
    if "://" not in user_input:
        user_input = "https://" + user_input
    parsed = urlparse(user_input)
    domain = parsed.netloc.split(":")[0]
    return user_input, domain

def write_report(data: dict, filename: str = "anish_scanner_report.json"):
    data.setdefault("generated_at", datetime.utcnow().isoformat() + "Z")
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    logging.info(f"Report written to {filename}")
