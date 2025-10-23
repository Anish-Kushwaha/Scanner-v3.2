"""
Web scanning helpers (SAFE STUBS).
This module does not perform injection tests or attempts to exploit vulnerabilities.
It only contains parsing/analysis helpers and a 'simulate' function for demo purposes.
"""

from typing import List, Dict
from urllib.parse import urljoin

def analyze_page_stub(html_text: str, headers: Dict[str, str]) -> Dict:
    """
    Safe analyzer that extracts title and meta tags from provided HTML (no network IO here).
    Use this to test report generation in offline mode or with saved HTML.
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_text or "<html></html>", "html.parser")
    title = soup.title.string.strip() if soup.title else "No title"
    meta_tags = {m.get("name"): m.get("content") for m in soup.find_all("meta") if m.get("name")}
    return {"title": title, "meta": meta_tags, "headers": headers}
