"""
Core runner for Anish Scanner (SAFE).
This module coordinates parsing, simulated scans, and report generation.
It will NOT run live network scans by default.
"""

from .utils import setup_logging, parse_target_url, write_report
from .network import detect_ports_from_url, run_network_scan_stub
from .webscan import analyze_page_stub

def run_safe_demo(target_input: str):
    """
    High-level demo flow that only uses safe stubs.
    Use this for README examples or CI checks.
    """
    setup_logging()
    url, domain = parse_target_url(target_input)
    domain, port = detect_ports_from_url(url)

    # Simulated network scan
    ports_to_test = [80, 443, 8443]
    net_results = run_network_scan_stub(domain, ports_to_test)

    # Simulated web analysis (supply a saved HTML for real parsing)
    sample_html = "<html><head><title>Demo</title></head><body></body></html>"
    web_info = analyze_page_stub(sample_html, {"Server": "SIMULATED"})

    report = {
        "target_url": url,
        "domain": domain,
        "detected_port": port,
        "network_results": net_results,
        "web_analysis": web_info
    }
    write_report(report)
    return report

if __name__ == "__main__":
    # Example safe invocation (only uses stubs)
    run_safe_demo("example.com")
