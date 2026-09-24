"""
PhishGuard AI - Security Header Analyzer
Passive inspection of HTTP response security headers.
NOTE: Missing security headers alone MUST NOT trigger a phishing classification,
as many benign sites have incomplete configurations. Headers provide defense-in-depth telemetry.
"""

from typing import Any, Dict, Optional


class HeaderAnalysisResult:
    def __init__(
        self,
        hsts_present: bool,
        hsts_max_age: Optional[int],
        hsts_includes_subdomains: bool,
        hsts_preload: bool,
        csp_present: bool,
        csp_has_default_src: bool,
        csp_has_frame_ancestors: bool,
        x_frame_options: Optional[str],
        x_content_type_options: Optional[str],
        referrer_policy: Optional[str],
        permissions_policy_present: bool,
        server_banner: Optional[str],
        x_powered_by: Optional[str],
        security_header_score: float,
        raw_headers: Dict[str, str],
    ):
        self.hsts_present = hsts_present
        self.hsts_max_age = hsts_max_age
        self.hsts_includes_subdomains = hsts_includes_subdomains
        self.hsts_preload = hsts_preload
        self.csp_present = csp_present
        self.csp_has_default_src = csp_has_default_src
        self.csp_has_frame_ancestors = csp_has_frame_ancestors
        self.x_frame_options = x_frame_options
        self.x_content_type_options = x_content_type_options
        self.referrer_policy = referrer_policy
        self.permissions_policy_present = permissions_policy_present
        self.server_banner = server_banner
        self.x_powered_by = x_powered_by
        self.security_header_score = security_header_score
        self.raw_headers = raw_headers

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hsts_present": self.hsts_present,
            "hsts_max_age": self.hsts_max_age,
            "hsts_includes_subdomains": self.hsts_includes_subdomains,
            "hsts_preload": self.hsts_preload,
            "csp_present": self.csp_present,
            "csp_has_default_src": self.csp_has_default_src,
            "csp_has_frame_ancestors": self.csp_has_frame_ancestors,
            "x_frame_options": self.x_frame_options,
            "x_content_type_options": self.x_content_type_options,
            "referrer_policy": self.referrer_policy,
            "permissions_policy_present": self.permissions_policy_present,
            "server_banner": self.server_banner,
            "x_powered_by": self.x_powered_by,
            "security_header_score": round(self.security_header_score, 2),
            "raw_headers": self.raw_headers,
        }


def analyze_security_headers(headers: Dict[str, str]) -> HeaderAnalysisResult:
    """
    Parses and evaluates HTTP security headers.
    Headers dictionary is normalized to lowercase keys.
    """
    norm = {k.lower(): v for k, v in headers.items()}

    # HSTS
    hsts_val = norm.get("strict-transport-security")
    hsts_present = hsts_val is not None
    hsts_max_age = None
    hsts_includes_sub = False
    hsts_preload = False
    if hsts_present and hsts_val:
        parts = [p.strip() for p in hsts_val.split(";")]
        for part in parts:
            if part.lower().startswith("max-age="):
                try:
                    hsts_max_age = int(part.split("=")[1])
                except (ValueError, IndexError):
                    pass
            elif part.lower() == "includesubdomains":
                hsts_includes_sub = True
            elif part.lower() == "preload":
                hsts_preload = True

    # CSP
    csp_val = norm.get("content-security-policy")
    csp_present = csp_val is not None
    csp_has_default_src = False
    csp_has_frame_ancestors = False
    if csp_present and csp_val:
        directives = [d.strip().lower() for d in csp_val.split(";")]
        for d in directives:
            if d.startswith("default-src"):
                csp_has_default_src = True
            elif d.startswith("frame-ancestors"):
                csp_has_frame_ancestors = True

    # X-Frame-Options
    xfo = norm.get("x-frame-options")
    # X-Content-Type-Options
    xcto = norm.get("x-content-type-options")
    # Referrer-Policy
    referrer_policy = norm.get("referrer-policy")
    # Permissions-Policy or Feature-Policy
    perm_policy = norm.get("permissions-policy") or norm.get("feature-policy")
    permissions_policy_present = perm_policy is not None

    # Server disclosures
    server_banner = norm.get("server")
    x_powered_by = norm.get("x-powered-by")

    # Defense-in-depth posture score (0.0 to 1.0)
    score_points = 0
    total_points = 5
    if hsts_present:
        score_points += 1
    if csp_present:
        score_points += 1
    if xfo:
        score_points += 1
    if xcto and "nosniff" in xcto.lower():
        score_points += 1
    if referrer_policy:
        score_points += 1

    security_header_score = score_points / total_points

    # Only include selected safe headers in raw_headers to prevent bloating
    safe_header_names = {
        "content-type",
        "server",
        "x-powered-by",
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "date",
    }
    filtered_headers = {k: v for k, v in norm.items() if k in safe_header_names}

    return HeaderAnalysisResult(
        hsts_present=hsts_present,
        hsts_max_age=hsts_max_age,
        hsts_includes_subdomains=hsts_includes_sub,
        hsts_preload=hsts_preload,
        csp_present=csp_present,
        csp_has_default_src=csp_has_default_src,
        csp_has_frame_ancestors=csp_has_frame_ancestors,
        x_frame_options=xfo,
        x_content_type_options=xcto,
        referrer_policy=referrer_policy,
        permissions_policy_present=permissions_policy_present,
        server_banner=server_banner,
        x_powered_by=x_powered_by,
        security_header_score=security_header_score,
        raw_headers=filtered_headers,
    )
