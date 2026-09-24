"""
PhishGuard AI - Evidence Generation Service
Produces factual, auditable, structured security evidence records from website telemetry.
Adheres strictly to the principle of evidence-based security:
Never fabricates facts, and treats missing optional headers merely as defense-in-depth posture telemetry.
"""

from typing import Any, Dict, List


class EvidenceItem:
    def __init__(
        self,
        category: str,
        severity: str,
        title: str,
        detail: str,
        recommendation: str = "",
    ):
        self.category = category
        self.severity = severity  # "info", "low", "medium", "high", "critical"
        self.title = title
        self.detail = detail
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


def generate_website_evidence(
    http_data: Dict[str, Any],
    redirect_data: Dict[str, Any],
    html_data: Dict[str, Any],
    dom_data: Dict[str, Any],
    form_data: Dict[str, Any],
    link_data: Dict[str, Any],
    script_data: Dict[str, Any],
    iframe_data: Dict[str, Any],
    resource_data: Dict[str, Any],
    header_data: Dict[str, Any],
) -> List[EvidenceItem]:
    """
    Evaluates raw telemetry across all vectors and generates traceable evidence items.
    """
    evidence: List[EvidenceItem] = []

    # 1. HTTP / Network Checks
    error = http_data.get("error")
    if error:
        if "security reasons" in error.lower() or "blocked" in error.lower():
            evidence.append(
                EvidenceItem(
                    category="network",
                    severity="critical",
                    title="SSRF Protection Triggered",
                    detail=f"Target URL resolved to a restricted IP address or scheme: {error}",
                    recommendation="Destination target violates network security policy.",
                )
            )
        else:
            evidence.append(
                EvidenceItem(
                    category="network",
                    severity="medium",
                    title="HTTP Connection Failure",
                    detail=f"Connection could not be established: {error}",
                    recommendation="Verify host reachability and network configurations.",
                )
            )

    # 2. Redirect Chain Checks
    hops = redirect_data.get("total_hops", 0)
    if hops >= 3:
        evidence.append(
            EvidenceItem(
                category="redirects",
                severity="medium" if hops >= 4 else "low",
                title="Excessive Redirect Hops",
                detail=f"The website executed {hops} redirect hops before reaching final destination.",
                recommendation="Investigate destination stability; phishers often chain redirects through open redirectors.",
            )
        )

    if redirect_data.get("protocol_downgrades", 0) > 0:
        evidence.append(
            EvidenceItem(
                category="redirects",
                severity="high",
                title="Insecure Protocol Downgrade in Redirect Chain",
                detail="Redirect flow traversed from an encrypted HTTPS URL to an unencrypted HTTP endpoint.",
                recommendation="Ensure end-to-end transport encryption with strict HTTPS enforcement.",
            )
        )

    if redirect_data.get("cross_domain_redirects", 0) > 0:
        evidence.append(
            EvidenceItem(
                category="redirects",
                severity="medium",
                title="Cross-Domain Redirect Observed",
                detail=f"The request traversed across multiple distinct domains: {hops} hops.",
                recommendation="Audit domain ownership across redirect intermediates.",
            )
        )

    # 3. Form & Credential Theft Checks
    forms = form_data.get("forms", [])
    has_pwd = form_data.get("has_password_field", False)
    final_url = http_data.get("final_url", "")
    is_final_https = final_url.lower().startswith("https://")

    if has_pwd and not is_final_https:
        evidence.append(
            EvidenceItem(
                category="forms",
                severity="high",
                title="Unencrypted Password Submission Field",
                detail="Website contains authentication credentials inputs on an unencrypted HTTP connection.",
                recommendation="All credential ingestion forms must be served and submitted over TLS/HTTPS.",
            )
        )

    if form_data.get("external_action_count", 0) > 0:
        ext_forms = [f for f in forms if f.get("is_external_action")]
        target_domains = {f.get("action_domain") for f in ext_forms if f.get("action_domain")}
        severity = "critical" if any(f.get("has_password") for f in ext_forms) else "high"
        evidence.append(
            EvidenceItem(
                category="forms",
                severity=severity,
                title="Form Action Points to External Domain",
                detail=f"Form submissions are routed to external domains: {', '.join(target_domains) or 'cross-domain targets'}.",
                recommendation="Verify legitimate data egress destination; high correlation with phishing credential harvesting drop zones.",
            )
        )

    if form_data.get("empty_action_count", 0) > 0 and has_pwd:
        evidence.append(
            EvidenceItem(
                category="forms",
                severity="medium",
                title="Credential Form with Blank/Fragment Action",
                detail="Form containing credentials submits to empty action or Javascript hook rather than standard endpoint.",
                recommendation="Audit client-side script listeners handling form submission.",
            )
        )

    # 4. Link Distribution Checks
    null_ratio = link_data.get("null_link_ratio", 0.0)
    total_links = link_data.get("total_links", 0)
    if total_links >= 10 and null_ratio > 0.40:
        evidence.append(
            EvidenceItem(
                category="links",
                severity="medium",
                title="High Percentage of Dummy Navigation Links",
                detail=f"{round(null_ratio * 100, 1)}% of all links point to '#', 'javascript:void(0)', or are blank.",
                recommendation="Phishing kits often replicate visual navbars using dead links.",
            )
        )

    # 5. Iframe Checks
    hidden_iframes = iframe_data.get("hidden_iframes", 0)
    if hidden_iframes > 0:
        evidence.append(
            EvidenceItem(
                category="iframes",
                severity="medium",
                title="Hidden Iframes Detected",
                detail=f"Found {hidden_iframes} iframe element(s) with zero dimensions or display:none styling.",
                recommendation="Inspect hidden frame targets for unauthorized tracking or silent redirection.",
            )
        )

    if iframe_data.get("suspicious_fullpage_iframes", 0) > 0:
        evidence.append(
            EvidenceItem(
                category="iframes",
                severity="high",
                title="Full-Page Framing Overlay Detected",
                detail="Detected 100% viewport coverage iframe that may disguise the true host identity.",
                recommendation="Verify whether page employs legitimate embedded single-page architecture or frame phishing.",
            )
        )

    # 6. Resource Dependency Checks
    ext_res_ratio = resource_data.get("external_resource_ratio", 0.0)
    total_res = resource_data.get("total_resources", 0)
    if total_res >= 5 and ext_res_ratio > 0.85:
        evidence.append(
            EvidenceItem(
                category="resources",
                severity="medium",
                title="Heavy External Asset Dependency",
                detail=f"{round(ext_res_ratio * 100, 1)}% of assets (images, stylesheets) are hotlinked from external origins.",
                recommendation="Phishers frequently load logos and styles directly from impersonated brand servers.",
            )
        )

    # 7. Security Header Telemetry (Defense-in-depth, not false alarm)
    if is_final_https and not header_data.get("hsts_present", False):
        evidence.append(
            EvidenceItem(
                category="headers",
                severity="info",
                title="HSTS Header Missing",
                detail="HTTP Strict Transport Security is not declared on this HTTPS endpoint.",
                recommendation="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        )

    if not header_data.get("csp_present", False):
        evidence.append(
            EvidenceItem(
                category="headers",
                severity="info",
                title="Content-Security-Policy Missing",
                detail="No Content-Security-Policy header provided to restrict resource execution origins.",
                recommendation="Implement a robust CSP policy limiting script-src and form-action destinations.",
            )
        )

    if not header_data.get("x_frame_options") and not header_data.get("csp_has_frame_ancestors"):
        evidence.append(
            EvidenceItem(
                category="headers",
                severity="low",
                title="Missing Framing Protection",
                detail="Neither X-Frame-Options nor CSP frame-ancestors is configured; page is susceptible to clickjacking.",
                recommendation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
            )
        )

    return evidence
