# PHISHGUARD AI — Website Feature Engineering & Telemetry Specification (Phase 3)

## 1. Feature Vector Overview
While Phase 2 implemented a 34-feature URL lexical extractor, Phase 3 defines a comprehensive **48-feature numeric vector** derived from safe, passive inspection of website structure, DOM topology, authentication targets, external asset hotlinking, and security configurations.

The schema is formally registered in [`ml/feature_engineering/website_feature_schema.json`](file:///C:/Users/dilee/.gemini/antigravity/scratch/phishguard-ai/ml/feature_engineering/website_feature_schema.json) (v1.0.0).

---

## 2. Feature Taxonomies & Security Rationale

### Category A: HTTP & Network Telemetry (6 Features)
| Feature Name | Type | Rationale |
|:---|:---|:---|
| `http_status_code` | int | 200 vs 404/500 indicates site liveness and evasion techniques. |
| `response_time_ms` | float | Network latency; bulletproof hosts and transient phishing servers exhibit anomalous timing. |
| `content_length_bytes` | int | Phishing pages are often lightweight landing pages compared to complex corporate apps. |
| `has_ssl` | int | TLS encryption status. |
| `redirect_count` | int | Excessive redirection chains correlate with evasive link shorteners and traffic distribution systems (TDS). |
| `has_protocol_downgrade` | int | Redirecting from HTTPS to unencrypted HTTP is a severe anomaly in legitimate authentication flows. |

### Category B: HTML & DOM Structural Metrics (6 Features)
| Feature Name | Type | Rationale |
|:---|:---|:---|
| `dom_depth` | int | Maximum DOM nesting depth; clone sites frequently feature shallow, un-nested structures. |
| `total_html_tags` | int | Total node count reflecting document complexity. |
| `text_to_html_ratio` | float | Phishing pages often have very low visible text relative to boilerplate HTML code. |
| `hidden_elements_count` | int | Count of elements with `display:none` or `visibility:hidden`, used for cloaking or stealth forms. |
| `has_title` | int | Binary flag indicating if `<title>` tag is non-empty. |
| `title_length` | int | Character length of document title. |

### Category C: Form & Credential Theft Targets (8 Features)
| Feature Name | Type | Rationale |
|:---|:---|:---|
| `total_forms` | int | Total `<form>` elements on page. |
| `login_forms_count` | int | Semantic detection of login/authentication dialogs. |
| `has_password_field` | int | Presence of `<input type="password">`. |
| `external_form_action_count` | int | Forms whose action destination points to an external registered domain. |
| `empty_form_action_count` | int | Forms with action `#`, `javascript:void(0)`, or blank action. |
| `has_external_password_form` | int | High-severity phishing indicator: credentials submitted to external destination. |
| `total_input_fields` | int | Cumulative count of input fields across all forms. |
| `sensitive_input_count` | int | Inputs targeting PINs, SSNs, credit cards, or passwords. |

### Category D: Hyperlink & Anchor Topology (6 Features)
| Feature Name | Type | Rationale |
|:---|:---|:---|
| `total_hyperlinks` | int | Total anchor `<a>` tags with `href`. |
| `internal_links_count` | int | Links pointing to same registered domain. |
| `external_links_count` | int | Links referencing third-party domains. |
| `external_link_ratio` | float | Proportion of external links to total links. |
| `null_link_count` | int | Dead navigation links (`#`, `javascript:void(0)`). |
| `null_link_ratio` | float | Cloned navigation bars typically have 40–80% dead null links. |

### Category E: Script & Executable Analysis (6 Features)
| Feature Name | Type | Rationale |
|:---|:---|:---|
| `total_scripts` | int | Total `<script>` elements. |
| `inline_scripts_count` | int | Scripts defined directly within the page body. |
| `external_scripts_count` | int | Scripts loaded from remote URLs. |
| `external_script_domains_count` | int | Count of distinct domains supplying scripts. |
| `inline_script_bytes` | int | Total byte length of inline JavaScript. |
| `has_obfuscation_keywords` | int | Presence of `eval`, `unescape`, or `fromCharCode` strings. |

### Category F: Iframe & Framing Overlays (5 Features)
| Feature Name | Type | Rationale |
|:---|:---|:---|
| `total_iframes` | int | Total `<iframe>` tags. |
| `hidden_iframes_count` | int | Zero-dimension or invisible iframes used for drive-by drops or silent analytics. |
| `cross_origin_iframes_count` | int | Iframes loading cross-origin resources. |
| `sandboxed_iframes_count` | int | Iframes using HTML5 sandbox attributes. |
| `suspicious_fullpage_iframes` | int | 100% viewport iframe overlays used in reverse proxy/credential interception attacks. |

### Category G: External Resource Hotlinking (5 Features)
| Feature Name | Type | Rationale |
|:---|:---|:---|
| `total_resources` | int | Total embedded images, stylesheets, and media. |
| `external_resources_count` | int | Assets loaded from external domains. |
| `external_resource_ratio` | float | Hotlinking: phishers often load 90%+ of images directly from the victim brand. |
| `mixed_content_count` | int | HTTP assets requested over HTTPS. |
| `distinct_resource_domains_count` | int | Unique external domains supplying page assets. |

### Category H: Security Header Hardening (6 Features)
| Feature Name | Type | Rationale |
|:---|:---|:---|
| `has_hsts` | int | Binary indicator for Strict-Transport-Security. |
| `has_csp` | int | Binary indicator for Content-Security-Policy. |
| `has_x_frame_options` | int | Binary indicator for X-Frame-Options (clickjacking defense). |
| `has_x_content_type_options` | int | Binary indicator for X-Content-Type-Options: nosniff. |
| `has_referrer_policy` | int | Binary indicator for Referrer-Policy. |
| `security_header_score` | float | Composite score [0.0 - 1.0] representing baseline defense-in-depth posture. |

---

## 3. Strict Machine Learning Integrity
In Phase 3:
- URL-level prediction is actively powered by the Phase 2 trained Random Forest model (`url_model`).
- The multi-modal website model output is declared as:
  ```json
  "website_model": {
    "status": "not_available",
    "message": "Phase 2 evaluated URL-based models. Dedicated multimodal website model will be trained in Phase 4 once live dataset is accumulated."
  }
  ```
- No artificial accuracies, confusion matrices, or simulated ML predictions are fabricated for the website model until a full multi-modal dataset is collected and trained in Phase 4.
