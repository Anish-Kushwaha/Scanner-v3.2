"""
Network module (SAFE STUBS).
This file intentionally DOES NOT implement live network scanning.
Fill in implementations only for authorized testing environments (VMs / lab targets).
"""

from typing import List, Tuple

def detect_ports_from_url(url: str) -> Tuple[str, int]:
    """
    Parse URL and return (domain, port).
    Default port is left as 8443 for admin panels (convention only).
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]
    port = parsed.port or 8443
    return domain, port

def run_network_scan_stub(ip: str, ports: List[int]) -> List[Tuple[int, str, str]]:
    """
    STUB: returns a simulated scan result list of tuples (port, banner, vuln_info).
    DO NOT replace this stub with live scanning code unless you have explicit permission.
    """
    # Example simulated output (for tests / demos)
    fake_results = []
    for p in ports:
        fake_results.append((p, "SIMULATED_BANNER", "No known vulnerabilities detected"))
    return fake_results
