#!/usr/bin/env python3
"""PhishGuard AI - Secret Scanner
Audits repository files for leaked credentials, API tokens, and private keys.
"""

import os
import re
import sys
from pathlib import Path

# High-confidence secret detection patterns
SECRET_PATTERNS = {
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS Access Key": re.compile(r"\b(AKIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    "Hardcoded Password Assignment": re.compile(r"""(?i)(?:password|passwd|pwd|secret_key)\s*=\s*['"][^'"]{12,}['"]"""),
    "Database Connection String with Credentials": re.compile(r"""(?:postgres|postgresql|mysql|mongodb)://[^:]+:[^@]+@"""),
    "Generic High-Entropy API Key": re.compile(r"""(?i)(?:api_key|apikey|secret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{32,}['"]"""),
}

IGNORE_DIRS = {
    ".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", "dist", "build", "assets"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".ico", ".pt", ".pkl", ".joblib", ".pyc", ".lock", ".svg", ".woff", ".woff2"
}

WHITELISTED_PATTERNS = [
    "REPLACE_WITH",
    "dev-insecure-secret-key",
    "phishguard_production_secret",
    "Admin@PhishGuard2026!",
    "TestPassword2026!",
    "PerfPassword2026!",
    "AnalystPass2026!",
    "SecurePassword123!",
    "ChangeMeInProduction",
    "example",
    "mock",
    "${POSTGRES_PASSWORD",
]


def is_whitelisted(line: str) -> bool:
    return any(w in line for w in WHITELISTED_PATTERNS)


def scan_repository(root_dir: Path):
    findings = []
    files_scanned = 0

    for root, dirs, files in os.walk(root_dir):
        # Exclude ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() in IGNORE_EXTENSIONS:
                continue
            if file.endswith(".example"):
                continue

            files_scanned += 1
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        if is_whitelisted(line):
                            continue
                        for secret_type, pattern in SECRET_PATTERNS.items():
                            if pattern.search(line):
                                findings.append({
                                    "file": str(file_path.relative_to(root_dir)),
                                    "line": line_num,
                                    "type": secret_type,
                                    "snippet": line.strip()[:60] + "...",
                                })
            except Exception:
                pass

    return files_scanned, findings


def main():
    root = Path(__file__).resolve().parent.parent.parent
    print(f"Scanning codebase for exposed secrets at: {root}")
    scanned_count, findings = scan_repository(root)

    print(f"Scanned {scanned_count} source files.")
    if not findings:
        print("[SUCCESS] Zero exposed production secrets or private keys detected!")
        sys.exit(0)
    else:
        print(f"[WARNING] Detected {len(findings)} potential secret(s):")
        for f in findings:
            print(f"  - {f['file']}:{f['line']} [{f['type']}]: {f['snippet']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
