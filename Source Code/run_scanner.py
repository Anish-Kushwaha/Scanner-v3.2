#!/usr/bin/env python3
"""
Runner script that requires explicit authorization environment variable before running any real code.
By default, it runs the safe demo (no network IO).
To allow real scans (NOT recommended in this repo), set AUTHORIZED=1 in the environment first,
and ensure you understand legal responsibilities.
"""

import os
from src.anish_scanner.core import run_safe_demo

def main():
    auth = os.getenv("AUTHORIZED", "0")
    if auth != "1":
        print("[!] AUTHORIZATION not present. Running safe demo only.")
        run_safe_demo("example.com")
    else:
        print("[!] AUTHORIZED=1 detected. THIS REPO DOES NOT INCLUDE live scanning code. Implement responsibly.")

if __name__ == "__main__":
    main()
