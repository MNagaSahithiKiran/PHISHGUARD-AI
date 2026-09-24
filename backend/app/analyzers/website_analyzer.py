"""
PhishGuard AI - Master Website Analyzer
Coordinates all safe, passive HTML, DOM, form, link, script, iframe, resource,
header, and redirect analysis pipelines.
Never executes JS, never submits forms, never performs recursive crawls.
"""

from typing import Any, Dict, Optional
from bs4 import BeautifulSoup

from app.analyzers.http_analyzer import safe_http_fetch, SafeFetchResult
from app.analyzers.redirect_analyzer import analyze_redirect_chain
from app.analyzers.html_analyzer import parse_html_safely, extract_meta_tags
from app.analyzers.dom_analyzer import analyze_dom
from app.analyzers.form_analyzer import analyze_forms
from app.analyzers.link_analyzer import analyze_links
from app.analyzers.script_analyzer import analyze_scripts
from app.analyzers.iframe_analyzer import analyze_iframes
from app.analyzers.resource_analyzer import analyze_resources
from app.analyzers.header_analyzer import analyze_security_headers


class WebsiteAnalysisResult:
    def __init__(
        self,
        fetch_result: SafeFetchResult,
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
        dom_snapshot_hash: str = "",
    ):
        self.fetch_result = fetch_result
        self.http_data = http_data
        self.redirect_data = redirect_data
        self.html_data = html_data
        self.dom_data = dom_data
        self.form_data = form_data
        self.link_data = link_data
        self.script_data = script_data
        self.iframe_data = iframe_data
        self.resource_data = resource_data
        self.header_data = header_data
        self.dom_snapshot_hash = dom_snapshot_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "http": self.http_data,
            "redirects": self.redirect_data,
            "html": self.html_data,
            "dom": self.dom_data,
            "forms": self.form_data,
            "links": self.link_data,
            "scripts": self.script_data,
            "iframes": self.iframe_data,
            "resources": self.resource_data,
            "headers": self.header_data,
            "dom_snapshot_hash": self.dom_snapshot_hash,
        }



async def analyze_website(url: str) -> WebsiteAnalysisResult:
    """
    Performs full, controlled website analysis on an untrusted target URL:
    1. Safe network fetch with SSRF protection, redirect tracking, size/timeout limits.
    2. Parsing HTML safely with BeautifulSoup (html.parser).
    3. Running all domain, structure, content, form, script, iframe, resource, and header analyzers.
    """
    # 1. Safe HTTP fetch
    fetch_res = await safe_http_fetch(url)

    final_url = fetch_res.final_url or url
    status_code = fetch_res.status_code
    headers = fetch_res.headers or {}

    http_data = {
        "initial_url": url,
        "final_url": final_url,
        "status_code": status_code,
        "content_length": fetch_res.content_length,
        "response_time_ms": fetch_res.response_time_ms,
        "error": fetch_res.error,
        "truncated": fetch_res.truncated,
        "ip_address": fetch_res.ip_address,
        "content_type": headers.get("content-type", ""),
    }

    # 2. Redirect chain analysis
    redirect_analysis = analyze_redirect_chain(fetch_res.redirect_chain)
    redirect_data = redirect_analysis.to_dict()

    # If fetch failed completely (e.g. DNS failure, connection refused, or SSRF blocked)
    if not fetch_res.html_content and fetch_res.error:
        empty_html = {"title": "", "language": "", "charset": "", "meta_tags": {}, "body_byte_length": 0}
        empty_dom = {"total_tags": 0, "dom_depth": 0, "text_ratio": 0.0, "hidden_elements_count": 0, "tag_frequencies": {}}
        empty_form = {"total_forms": 0, "login_forms_count": 0, "has_password_field": False, "external_action_count": 0, "empty_action_count": 0, "forms": []}
        empty_link = {"total_links": 0, "internal_links": 0, "external_links": 0, "null_empty_links": 0, "external_link_ratio": 0.0, "null_link_ratio": 0.0, "distinct_external_domains": []}
        empty_script = {"total_scripts": 0, "inline_scripts": 0, "external_scripts": 0, "external_script_domains": [], "inline_script_bytes": 0}
        empty_iframe = {"total_iframes": 0, "hidden_iframes": 0, "cross_origin_iframes": 0, "sandboxed_iframes": 0, "suspicious_fullpage_iframes": 0, "iframe_sources": []}
        empty_res = {"total_resources": 0, "external_resources": 0, "external_resource_ratio": 0.0, "mixed_content_count": 0, "distinct_resource_domains": [], "stylesheet_count": 0, "external_stylesheets": 0, "image_count": 0, "external_images": 0}
        empty_head = analyze_security_headers(headers).to_dict()

        from app.intelligence.reproducibility import compute_snapshot_hash
        dom_hash = compute_snapshot_hash(fetch_res.html_content) if fetch_res.html_content else ""

        return WebsiteAnalysisResult(
            fetch_result=fetch_res,
            http_data=http_data,
            redirect_data=redirect_data,
            html_data=empty_html,
            dom_data=empty_dom,
            form_data=empty_form,
            link_data=empty_link,
            script_data=empty_script,
            iframe_data=empty_iframe,
            resource_data=empty_res,
            header_data=empty_head,
            dom_snapshot_hash=dom_hash,
        )

    # 3. Parse HTML
    soup = parse_html_safely(fetch_res.html_content)

    # 4. Run analyzers
    html_info = {
        "title": soup.title.string.strip() if soup.title and soup.title.string else "",
        "language": (soup.html.get("lang") or "").strip() if soup.html else "",
        "charset": (soup.meta.get("charset") or "").strip() if soup.meta and soup.meta.has_attr("charset") else "",
        "meta_tags": extract_meta_tags(soup),
        "body_byte_length": len(fetch_res.html_content.encode("utf-8", errors="replace")),
    }
    dom_data = analyze_dom(soup).to_dict()
    form_data = analyze_forms(soup, final_url).to_dict()
    link_data = analyze_links(soup, final_url).to_dict()
    script_data = analyze_scripts(soup, final_url).to_dict()
    iframe_data = analyze_iframes(soup, final_url).to_dict()
    resource_data = analyze_resources(soup, final_url).to_dict()
    header_data = analyze_security_headers(headers).to_dict()

    from app.intelligence.reproducibility import compute_snapshot_hash
    dom_hash = compute_snapshot_hash(fetch_res.html_content)

    return WebsiteAnalysisResult(
        fetch_result=fetch_res,
        http_data=http_data,
        redirect_data=redirect_data,
        html_data=html_info,
        dom_data=dom_data,
        form_data=form_data,
        link_data=link_data,
        script_data=script_data,
        iframe_data=iframe_data,
        resource_data=resource_data,
        header_data=header_data,
        dom_snapshot_hash=dom_hash,
    )

