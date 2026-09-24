"""
PhishGuard AI - Form & Authentication Target Analyzer.
Inspects <form> elements, input configurations, and target action domains.
STRICT DEFENSE: NEVER submits forms or collects credentials.
"""

from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import tldextract


class FormAnalysisResult:
    def __init__(
        self,
        total_forms: int,
        login_forms_count: int,
        has_password_field: bool,
        external_action_count: int,
        empty_action_count: int,
        forms: List[Dict[str, Any]],
    ):
        self.total_forms = total_forms
        self.login_forms_count = login_forms_count
        self.has_password_field = has_password_field
        self.external_action_count = external_action_count
        self.empty_action_count = empty_action_count
        self.forms = forms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_forms": self.total_forms,
            "login_forms_count": self.login_forms_count,
            "has_password_field": self.has_password_field,
            "external_action_count": self.external_action_count,
            "empty_action_count": self.empty_action_count,
            "forms": self.forms,
        }


def analyze_forms(soup: BeautifulSoup, page_url: str) -> FormAnalysisResult:
    if not soup:
        return FormAnalysisResult(0, 0, False, 0, 0, [])

    parsed_page = urlparse(page_url)
    page_host = (parsed_page.hostname or "").lower()
    page_ext = tldextract.extract(page_host)
    page_domain = f"{page_ext.domain}.{page_ext.suffix}" if page_ext.suffix else page_ext.domain

    forms = soup.find_all("form")
    form_details: List[Dict[str, Any]] = []

    total_forms = len(forms)
    login_forms = 0
    external_action_count = 0
    empty_action_count = 0
    has_any_password = False

    for idx, f in enumerate(forms):
        raw_action = (f.get("action") or "").strip()
        method = (f.get("method", "get") or "get").lower()
        form_id = f.get("id") or ""
        form_name = f.get("name") or ""

        is_empty_action = not raw_action or raw_action in ["#", "#!"] or raw_action.lower().startswith("javascript:")
        if is_empty_action:
            empty_action_count += 1

        resolved_action = urljoin(page_url, raw_action)
        action_parsed = urlparse(resolved_action)
        action_host = (action_parsed.hostname or "").lower()

        action_ext = tldextract.extract(action_host)
        action_domain = f"{action_ext.domain}.{action_ext.suffix}" if action_ext.suffix else action_ext.domain

        is_same_host = (action_host == page_host) or (not action_host)
        is_same_domain = (action_domain == page_domain) or (not action_domain)
        is_external_action = not is_same_host and bool(action_host)

        if is_external_action:
            external_action_count += 1

        inputs = f.find_all(["input", "textarea", "select"])
        has_password = False
        fields_list = []

        for inp in inputs:
            inp_type = (inp.get("type", "text") or "text").lower()
            inp_name = (inp.get("name", "") or "").lower()
            is_sensitive = inp_type == "password" or any(s in inp_name for s in ["pass", "pwd", "ssn", "creditcard", "pin", "cvv"])
            if inp_type == "password" or "pass" in inp_name:
                has_password = True
                has_any_password = True

            fields_list.append({
                "name": inp_name,
                "type": inp_type,
                "is_sensitive": is_sensitive,
            })

        is_login = has_password or any(s in form_name.lower() or s in form_id.lower() for s in ["login", "signin", "auth"])
        if is_login:
            login_forms += 1

        form_details.append({
            "id": form_id,
            "name": form_name,
            "action": raw_action,
            "action_domain": action_domain,
            "method": method,
            "is_login_form": is_login,
            "is_external_action": is_external_action,
            "is_empty_action": is_empty_action,
            "field_count": len(inputs),
            "has_password": has_password,
            "fields": fields_list[:20],
        })

    return FormAnalysisResult(
        total_forms=total_forms,
        login_forms_count=login_forms,
        has_password_field=has_any_password,
        external_action_count=external_action_count,
        empty_action_count=empty_action_count,
        forms=form_details,
    )


class FormAnalyzer:
    @staticmethod
    def analyze_forms(soup: BeautifulSoup, page_url: str) -> Dict[str, Any]:
        res = analyze_forms(soup, page_url)
        return {
            "total_forms": res.total_forms,
            "login_forms_count": res.login_forms_count,
            "external_action_forms_count": res.external_action_count,
            "cross_domain_forms_count": res.external_action_count,
            "password_field_count": 1 if res.has_password_field else 0,
            "forms": res.forms,
        }
