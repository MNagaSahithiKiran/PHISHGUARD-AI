# PHISHGUARD AI — Server-Side Request Forgery (SSRF) Protection Specification

## 1. Threat Model & SSRF Risks
In an automated phishing analysis platform, attackers submit URLs for scanning with the intent of exploiting backend HTTP fetching services to:
- Port-scan internal VPC subnets and private infrastructure.
- Access cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`) to steal IAM credentials or instance tokens.
- Pivot to local loopback administrative interfaces (`localhost:8000`, `127.0.0.1:5432`).
- Trigger denial-of-service via huge payloads (decompression/memory bombs) or infinite redirect loops.

## 2. Multi-Layer Defensive Controls

### Layer 1: Protocol & URI Scheme Whitelisting
- Only `http://` and `https://` schemes are permitted.
- High-risk schemes (`file://`, `gopher://`, `ftp://`, `ldap://`, `dict://`, `javascript:`, `data:`, `ws://`) are rejected immediately before DNS resolution.

### Layer 2: IP Range & Cloud Metadata Validation
Before any TCP socket connection is established, the target host is evaluated against IPv4 and IPv6 restricted ranges using `ipaddress`:
- **Loopback**: `127.0.0.0/8`, `::1`
- **RFC 1918 Private**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Link-Local & Cloud Metadata**: `169.254.0.0/16`, `169.254.169.254`, `fe80::/10`, `fd00:ec2::254`
- **Unique Local IPv6**: `fc00::/7`
- **Zero / Broadcast / Reserved**: `0.0.0.0/8`, `255.255.255.255`
- **IPv4-Mapped IPv6**: Unwrapped and validated against IPv4 rules (e.g., `::ffff:127.0.0.1`).

### Layer 3: DNS Pre-Resolution & Rebinding Protection
Hostnames are resolved using `socket.getaddrinfo`. Every resolved IP in the A and AAAA records is evaluated against the IP restriction engine. If any resolved address belongs to restricted space, the request is blocked.

### Layer 4: Per-Hop Redirect Interception
Standard HTTP clients (e.g. `follow_redirects=True`) automatically follow redirects without re-checking DNS, exposing the scanner to "open redirect to internal IP" attacks.
PhishGuard AI enforces:
- `follow_redirects=False`
- Manual inspection of each `Location` header
- Re-running the full SSRF Guard on the resolved target URL before the next connection
- Strict cap of **5 maximum redirect hops**

### Layer 5: Resource & Timeout Caps
- **Stream Body Cap**: 5 MB maximum body size read in chunks via `client.stream`. If exceeded, streaming terminates safely.
- **Connection Timeout**: 5.0 seconds
- **Total Request Timeout**: 10.0 seconds

### Layer 6: Sanitized Error Responses
When SSRF or network policy violations occur, the API returns a generic sanitized error message:
`"Analysis blocked for security reasons."`
This prevents adversaries from measuring timing or error responses to conduct reconnaissance on internal subnet architecture.
