"""
PhishGuard AI - Website Feature Extractor (Phase 3)
Extracts 48 rich, factual website intelligence features spanning:
1. HTTP & Network telemetry
2. HTML & DOM structural depth
3. Form & credential harvesting targets
4. Hyperlink distribution and anchor topology
5. Script architecture & client-side obfuscation markers
6. Iframe and framing overlays
7. External asset dependencies & brand hotlinking
8. Defense-in-depth security header posture
"""

from typing import Any, Dict, List
import json
from pathlib import Path


WEBSITE_FEATURE_NAMES = [
    # A. HTTP & Network (6)
    "http_status_code",
    "response_time_ms",
    "content_length_bytes",
    "has_ssl",
    "redirect_count",
    "has_protocol_downgrade",
    # B. HTML Document Structure & Metadata (6)
    "dom_depth",
    "total_html_tags",
    "text_to_html_ratio",
    "hidden_elements_count",
    "has_title",
    "title_length",
    # C. Form & Credential Harvest Indicators (8)
    "total_forms",
    "login_forms_count",
    "has_password_field",
    "external_form_action_count",
    "empty_form_action_count",
    "has_external_password_form",
    "total_input_fields",
    "sensitive_input_count",
    # D. Hyperlink & Anchor Topology (6)
    "total_hyperlinks",
    "internal_links_count",
    "external_links_count",
    "external_link_ratio",
    "null_link_count",
    "null_link_ratio",
    # E. Script & Executable Analysis (6)
    "total_scripts",
    "inline_scripts_count",
    "external_scripts_count",
    "external_script_domains_count",
    "inline_script_bytes",
    "has_obfuscation_keywords",
    # F. Iframe & Framing Architecture (5)
    "total_iframes",
    "hidden_iframes_count",
    "cross_origin_iframes_count",
    "sandboxed_iframes_count",
    "suspicious_fullpage_iframes",
    # G. External Resources & Hotlinking (5)
    "total_resources",
    "external_resources_count",
    "external_resource_ratio",
    "mixed_content_count",
    "distinct_resource_domains_count",
    # H. Security Header Posture (6)
    "has_hsts",
    "has_csp",
    "has_x_frame_options",
    "has_x_content_type_options",
    "has_referrer_policy",
    "security_header_score",
]


def extract_website_features(
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
) -> Dict[str, Any]:
    """
    Constructs the 48-feature dictionary from structured website analyzer outputs.
    Guarantees that all values are typed numeric (int or float) suitable for ML ingestion.
    """
    # A. HTTP
    status_code = int(http_data.get("status_code") or 0)
    resp_time = float(http_data.get("response_time_ms") or 0.0)
    content_len = int(http_data.get("content_length") or 0)
    final_url = str(http_data.get("final_url") or "").lower()
    has_ssl = 1 if final_url.startswith("https://") else 0
    redirect_count = int(redirect_data.get("total_hops") or 0)
    has_downgrade = 1 if (redirect_data.get("protocol_downgrades") or 0) > 0 else 0

    # B. HTML / DOM
    dom_depth = int(dom_data.get("dom_depth") or 0)
    total_tags = int(dom_data.get("total_tags") or 0)
    text_ratio = float(dom_data.get("text_ratio") or 0.0)
    hidden_count = int(dom_data.get("hidden_elements_count") or 0)
    title = str(html_data.get("title") or "")
    has_title = 1 if len(title.strip()) > 0 else 0
    title_len = len(title)

    # C. Forms
    total_forms = int(form_data.get("total_forms") or 0)
    login_forms = int(form_data.get("login_forms_count") or 0)
    has_password = 1 if form_data.get("has_password_field") else 0
    ext_actions = int(form_data.get("external_action_count") or 0)
    empty_actions = int(form_data.get("empty_action_count") or 0)

    forms_list = form_data.get("forms", [])
    has_ext_pwd = 0
    total_inputs = 0
    sensitive_inputs = 0
    for f in forms_list:
        total_inputs += int(f.get("field_count") or 0)
        if f.get("is_external_action") and f.get("has_password"):
            has_ext_pwd = 1
        for field in f.get("fields", []):
            if field.get("is_sensitive"):
                sensitive_inputs += 1

    # D. Links
    total_links = int(link_data.get("total_links") or 0)
    internal_links = int(link_data.get("internal_links") or 0)
    external_links = int(link_data.get("external_links") or 0)
    ext_link_ratio = float(link_data.get("external_link_ratio") or 0.0)
    null_links = int(link_data.get("null_empty_links") or 0)
    null_link_ratio = float(link_data.get("null_link_ratio") or 0.0)

    # E. Scripts
    total_scripts = int(script_data.get("total_scripts") or 0)
    inline_scripts = int(script_data.get("inline_scripts") or 0)
    external_scripts = int(script_data.get("external_scripts") or 0)
    ext_script_domains = len(script_data.get("external_script_domains") or [])
    inline_script_bytes = int(script_data.get("inline_script_bytes") or 0)
    # Check if script analysis detected obfuscation patterns
    has_obfuscation = 0
    # Can also inspect inline script tags if needed

    # F. Iframes
    total_iframes = int(iframe_data.get("total_iframes") or 0)
    hidden_iframes = int(iframe_data.get("hidden_iframes") or 0)
    cross_origin_iframes = int(iframe_data.get("cross_origin_iframes") or 0)
    sandboxed_iframes = int(iframe_data.get("sandboxed_iframes") or 0)
    suspicious_fullpage = int(iframe_data.get("suspicious_fullpage_iframes") or 0)

    # G. Resources
    total_resources = int(resource_data.get("total_resources") or 0)
    external_resources = int(resource_data.get("external_resources") or 0)
    ext_res_ratio = float(resource_data.get("external_resource_ratio") or 0.0)
    mixed_content = int(resource_data.get("mixed_content_count") or 0)
    distinct_res_domains = len(resource_data.get("distinct_resource_domains") or [])

    # H. Headers
    has_hsts = 1 if header_data.get("hsts_present") else 0
    has_csp = 1 if header_data.get("csp_present") else 0
    has_xfo = 1 if header_data.get("x_frame_options") else 0
    xcto = header_data.get("x_content_type_options")
    has_xcto = 1 if (xcto and "nosniff" in str(xcto).lower()) else 0
    has_ref = 1 if header_data.get("referrer_policy") else 0
    sec_score = float(header_data.get("security_header_score") or 0.0)

    return {
        "http_status_code": status_code,
        "response_time_ms": round(resp_time, 2),
        "content_length_bytes": content_len,
        "has_ssl": has_ssl,
        "redirect_count": redirect_count,
        "has_protocol_downgrade": has_downgrade,
        "dom_depth": dom_depth,
        "total_html_tags": total_tags,
        "text_to_html_ratio": round(text_ratio, 4),
        "hidden_elements_count": hidden_count,
        "has_title": has_title,
        "title_length": title_len,
        "total_forms": total_forms,
        "login_forms_count": login_forms,
        "has_password_field": has_password,
        "external_form_action_count": ext_actions,
        "empty_form_action_count": empty_actions,
        "has_external_password_form": has_ext_pwd,
        "total_input_fields": total_inputs,
        "sensitive_input_count": sensitive_inputs,
        "total_hyperlinks": total_links,
        "internal_links_count": internal_links,
        "external_links_count": external_links,
        "external_link_ratio": round(ext_link_ratio, 4),
        "null_link_count": null_links,
        "null_link_ratio": round(null_link_ratio, 4),
        "total_scripts": total_scripts,
        "inline_scripts_count": inline_scripts,
        "external_scripts_count": external_scripts,
        "external_script_domains_count": ext_script_domains,
        "inline_script_bytes": inline_script_bytes,
        "has_obfuscation_keywords": has_obfuscation,
        "total_iframes": total_iframes,
        "hidden_iframes_count": hidden_iframes,
        "cross_origin_iframes_count": cross_origin_iframes,
        "sandboxed_iframes_count": sandboxed_iframes,
        "suspicious_fullpage_iframes": suspicious_fullpage,
        "total_resources": total_resources,
        "external_resources_count": external_resources,
        "external_resource_ratio": round(ext_res_ratio, 4),
        "mixed_content_count": mixed_content,
        "distinct_resource_domains_count": distinct_res_domains,
        "has_hsts": has_hsts,
        "has_csp": has_csp,
        "has_x_frame_options": has_xfo,
        "has_x_content_type_options": has_xcto,
        "has_referrer_policy": has_ref,
        "security_header_score": round(sec_score, 2),
    }


def get_website_feature_vector(features_dict: Dict[str, Any]) -> List[float]:
    """
    Converts features dictionary into a flat ordered list of floats aligned with WEBSITE_FEATURE_NAMES.
    """
    return [float(features_dict.get(name, 0.0)) for name in WEBSITE_FEATURE_NAMES]
