# PhishGuard AI - Feature Engineering Specification

**Document Version**: 2.0.0  
**Feature Count**: 34 Features  
**Module**: `ml/feature_engineering/`  

---

## 1. Feature Taxonomy

The 34 features extracted by PhishGuard AI are organized into five orthogonal categories:

1. **Dimensional & Length Metrics** (5 features)
2. **Syntactic & Delimiter Distributions** (11 features)
3. **Statistical Ratios & Entropies** (5 features)
4. **Structural & Domain Topology** (7 features)
5. **Security Obfuscation & Heuristic Flags** (6 features)

---

## 2. Complete Feature Catalog

| Index | Feature Identifier | Mathematical / Algorithmic Definition | Scientific Rationale |
| :---: | :--- | :--- | :--- |
| 1 | `url_length` | $|S_{\text{url}}|$ | Phishing URLs are frequently lengthened to embed tokens or deceive preview bars. |
| 2 | `hostname_length` | $|S_{\text{host}}|$ | Impersonation attacks often elongate hostnames with multiple brand tokens. |
| 3 | `path_length` | $|S_{\text{path}}|$ | Compromised content management systems often host phishing in deep subdirectory paths. |
| 4 | `query_length` | $|S_{\text{query}}|$ | Base64-encoded credential parameters expand query string length. |
| 5 | `fragment_length` | $|S_{\text{fragment}}|$ | Client-side redirects frequently utilize fragments (`#`). |
| 6 | `count_dots` | $\sum \mathbf{1}_{\{c = '.'\}}$ | Multiple dots indicate subdomain nesting or IP representations. |
| 7 | `count_hyphens` | $\sum \mathbf{1}_{\{c = '-' \}}$ | Hyphens are widely used in typosquatting and deceptive brand pairing (`paypal-update`). |
| 8 | `count_underscores` | $\sum \mathbf{1}_{\{c = '\_' \}}$ | Less common in standard hostnames; frequent in automated attack scripts. |
| 9 | `count_slashes` | $\sum \mathbf{1}_{\{c = '/' \}}$ | Excessive directory nesting. |
| 10 | `count_question_marks`| $\sum \mathbf{1}_{\{c = '?' \}}$ | Query delimiters. |
| 11 | `count_equals` | $\sum \mathbf{1}_{\{c = '=' \}}$ | Parameter assignment count. |
| 12 | `count_ampersands` | $\sum \mathbf{1}_{\{c = '\&' \}}$ | Multiple parameter chaining. |
| 13 | `count_percent` | $\sum \mathbf{1}_{\{c = '\%' \}}$ | URL hex encoding indicator (used to obfuscate malicious path strings). |
| 14 | `count_digits` | $\sum \mathbf{1}_{\{c \in [0-9]\}}$ | Numerical character volume. |
| 15 | `count_letters` | $\sum \mathbf{1}_{\{c \in [a-zA-Z]\}}$ | Alphabetical character volume. |
| 16 | `count_special_chars` | $\sum \mathbf{1}_{\{c \notin [a-zA-Z0-9/.:]\}}$ | Obfuscation symbol count. |
| 17 | `ratio_digits_url` | $\frac{\text{count\_digits}}{\text{url\_length}}$ | Automated domain generators and phishing hashes exhibit elevated digit ratios. |
| 18 | `ratio_special_chars` | $\frac{\text{count\_special}}{\text{url\_length}}$ | Special character density. |
| 19 | `count_subdomains` | $|S_{\text{subdomains}}| - 2$ | Subdomain hierarchies designed to mimic legitimate domain structures. |
| 20 | `has_ip_address` | $\mathbf{1}_{\{\text{host} \in \text{IPv4} \cup \text{IPv6}\}}$ | Direct IP access bypasses domain reputation and WHOIS attribution. |
| 21 | `has_at_symbol` | $\mathbf{1}_{\{'@' \in S_{\text{url}}\}}$ | Basic authentication delimiter used to obscure the true landing hostname. |
| 22 | `has_shortener` | $\mathbf{1}_{\{\text{host} \in \mathcal{K}_{\text{shorteners}}\}}$ | URL shorteners conceal landing destinations. |
| 23 | `has_https` | $\mathbf{1}_{\{\text{scheme} = 'https' \}}$ | Protocol security indicator. Modern phishing increasingly uses free TLS certificates. |
| 24 | `suspicious_keyword_count` | $\sum_{k \in \mathcal{K}_{\text{sec}}} \mathbf{1}_{\{k \in S_{\text{url}}\}}$ | Matches against credential keywords (`login`, `verify`, `banking`, `wallet`). |
| 25 | `hostname_entropy` | $-\sum P(x) \log_2 P(x)$ on hostname | Measures randomness in hostnames; flags DGA domains. |
| 26 | `url_entropy` | $-\sum P(x) \log_2 P(x)$ on full URL | Measures total lexical randomness. |
| 27 | `path_token_count` | Number of segments split by `/` | Granular structural depth indicator. |
| 28 | `query_param_count` | Number of query key-value pairs | Data exfiltration indicator. |
| 29 | `is_suspicious_tld` | $\mathbf{1}_{\{\text{tld} \in \mathcal{T}_{\text{abuse}}\}}$ | Matches high-abuse TLDs (`.xyz`, `.top`, `.click`, `.loan`, etc.). |
| 30 | `has_punycode` | $\mathbf{1}_{\{'xn--' \in \text{host}\}}$ | Identifies internationalized domain name (IDN) homograph spoofing attempts. |
| 31 | `has_encoded_chars` | $\mathbf{1}_{\{'\%' \in S_{\text{url}}\}}$ | Percent-encoding flag. |
| 32 | `hostname_path_ratio` | $\frac{\text{hostname\_length}}{\max(1, \text{path\_length})}$ | Distinguishes deep landing scripts from root benign domains. |
| 33 | `repeated_char_max` | $\max_{c} (\text{consecutive run of } c)$ | Catches typosquatting repetitions (`goooogle.com`). |
| 34 | `suspicious_brand_token` | $\sum_{b \in \mathcal{B}} \mathbf{1}_{\{b \in S_{\text{url}}\}}$ | Brand names in third-party or subdomained URLs (`paypal`, `chase`, `meta`). |
