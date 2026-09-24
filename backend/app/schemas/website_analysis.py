from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class WebsiteAnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target website URL to analyze", min_length=4, max_length=2048)


class RedirectHopSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    hop_number: int
    source_url: str
    target_url: str
    status_code: int


class EvidenceSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    category: str
    severity: str
    title: str
    detail: str
    recommendation: Optional[str] = None


class HTTPAnalysisSchema(BaseModel):
    initial_url: str
    final_url: str
    status_code: Optional[int] = None
    content_length: int = 0
    response_time_ms: float = 0.0
    error: Optional[str] = None
    truncated: bool = False
    ip_address: Optional[str] = None
    content_type: str = ""


class HTMLAnalysisSchema(BaseModel):
    title: str = ""
    language: str = ""
    charset: str = ""
    meta_tags: Dict[str, str] = {}
    body_byte_length: int = 0


class DOMAnalysisSchema(BaseModel):
    total_tags: int = 0
    dom_depth: int = 0
    text_ratio: float = 0.0
    hidden_elements_count: int = 0
    tag_frequencies: Dict[str, int] = {}


class FormFieldSchema(BaseModel):
    name: str = ""
    type: str = ""
    is_sensitive: bool = False


class FormDetailSchema(BaseModel):
    id: str = ""
    name: str = ""
    action: str = ""
    action_domain: str = ""
    method: str = "get"
    is_login_form: bool = False
    is_external_action: bool = False
    is_empty_action: bool = False
    field_count: int = 0
    has_password: bool = False
    fields: List[FormFieldSchema] = []


class FormAnalysisSchema(BaseModel):
    total_forms: int = 0
    login_forms_count: int = 0
    has_password_field: bool = False
    external_action_count: int = 0
    empty_action_count: int = 0
    forms: List[FormDetailSchema] = []


class LinkAnalysisSchema(BaseModel):
    total_links: int = 0
    internal_links: int = 0
    external_links: int = 0
    null_empty_links: int = 0
    external_link_ratio: float = 0.0
    null_link_ratio: float = 0.0
    distinct_external_domains: List[str] = []


class ScriptAnalysisSchema(BaseModel):
    total_scripts: int = 0
    inline_scripts: int = 0
    external_scripts: int = 0
    external_script_domains: List[str] = []
    inline_script_bytes: int = 0


class IframeSourceSchema(BaseModel):
    src: str = ""
    domain: str = ""
    is_hidden: bool = False
    is_cross_origin: bool = False
    is_sandboxed: bool = False
    is_fullpage: bool = False


class IframeAnalysisSchema(BaseModel):
    total_iframes: int = 0
    hidden_iframes: int = 0
    cross_origin_iframes: int = 0
    sandboxed_iframes: int = 0
    suspicious_fullpage_iframes: int = 0
    iframe_sources: List[IframeSourceSchema] = []


class ResourceAnalysisSchema(BaseModel):
    total_resources: int = 0
    external_resources: int = 0
    external_resource_ratio: float = 0.0
    mixed_content_count: int = 0
    distinct_resource_domains: List[str] = []
    stylesheet_count: int = 0
    external_stylesheets: int = 0
    image_count: int = 0
    external_images: int = 0


class HeaderAnalysisSchema(BaseModel):
    hsts_present: bool = False
    hsts_max_age: Optional[int] = None
    hsts_includes_subdomains: bool = False
    hsts_preload: bool = False
    csp_present: bool = False
    csp_has_default_src: bool = False
    csp_has_frame_ancestors: bool = False
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy_present: bool = False
    server_banner: Optional[str] = None
    x_powered_by: Optional[str] = None
    security_header_score: float = 0.0
    raw_headers: Dict[str, str] = {}


class WebsiteAnalyzeResponse(BaseModel):
    scan_id: str
    status: str  # "completed", "failed", "blocked"
    url: str
    final_url: str
    http: HTTPAnalysisSchema
    redirects: Dict[str, Any]
    html: HTMLAnalysisSchema
    dom: DOMAnalysisSchema
    forms: FormAnalysisSchema
    links: LinkAnalysisSchema
    scripts: ScriptAnalysisSchema
    iframes: IframeAnalysisSchema
    resources: ResourceAnalysisSchema
    headers: HeaderAnalysisSchema
    evidence: List[EvidenceSchema] = []
    screenshot_url: Optional[str] = None
    url_model: Optional[Dict[str, Any]] = None
    website_model: Dict[str, Any] = Field(
        default_factory=lambda: {
            "status": "not_available",
            "message": "Dedicated multimodal website model will be trained once live HTML/DOM dataset is accumulated.",
        }
    )
    visual_model: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "status": "not_available",
            "message": "Visual analysis can be triggered via /api/v1/visual-analysis.",
        }
    )
