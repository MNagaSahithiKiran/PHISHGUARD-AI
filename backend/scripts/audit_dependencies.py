#!/usr/bin/env python3
"""PhishGuard AI - Dependency Security Auditor
Audits Python and JavaScript dependencies across backend, frontend, and browser extension.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

KNOWN_VULNERABLE_PACKAGES = {
    "pycrypto": "Deprecated cryptographic library with known vulnerabilities. Use cryptography or bcrypt.",
    "telnetlib": "Insecure unencrypted protocol.",
    "pickle5": "Deserialization hazard.",
    "eventlet": "Known vulnerabilities in older eventlet versions.",
}


def audit_backend_requirements():
    req_file = ROOT / "backend" / "requirements.txt"
    if not req_file.exists():
        return []

    issues = []
    with open(req_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            pkg_match = re.match(r"^([a-zA-Z0-9_\-\[\]]+)", line)
            if pkg_match:
                pkg = pkg_match.group(1).lower().split("[")[0]
                if pkg in KNOWN_VULNERABLE_PACKAGES:
                    issues.append(f"Backend: {pkg} is flagged: {KNOWN_VULNERABLE_PACKAGES[pkg]}")

    return issues


def audit_npm_package(pkg_path: Path, component_name: str):
    if not pkg_path.exists():
        return []

    issues = []
    try:
        with open(pkg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

            for pkg, ver in deps.items():
                if pkg in KNOWN_VULNERABLE_PACKAGES:
                    issues.append(f"{component_name}: {pkg} flagged: {KNOWN_VULNERABLE_PACKAGES[pkg]}")
                if ver == "*" or ver == "latest":
                    issues.append(f"{component_name}: Unpinned wildcard version '{ver}' for {pkg}")
    except Exception as e:
        issues.append(f"{component_name}: Failed to read package.json: {e}")

    return issues


def main():
    print("=" * 70)
    print("PHISHGUARD AI - DEPENDENCY SECURITY AUDIT")
    print("=" * 70)

    issues = []
    issues.extend(audit_backend_requirements())
    issues.extend(audit_npm_package(ROOT / "frontend" / "package.json", "Frontend Web"))
    issues.extend(audit_npm_package(ROOT / "browser-extension" / "package.json", "Browser Extension"))

    print(f"Backend requirements: {ROOT / 'backend' / 'requirements.txt'}")
    print(f"Frontend dependencies: {ROOT / 'frontend' / 'package.json'}")
    print(f"Extension dependencies: {ROOT / 'browser-extension' / 'package.json'}")

    print("\nAudit Summary:")
    if not issues:
        print("[SUCCESS] All dependencies audited. Zero high-risk or banned packages detected.")
        sys.exit(0)
    else:
        print(f"[WARNING] Found {len(issues)} dependency issue(s):")
        for iss in issues:
            print(f"  - {iss}")
        sys.exit(1)


if __name__ == "__main__":
    main()
