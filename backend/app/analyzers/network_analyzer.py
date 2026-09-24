"""
PhishGuard AI - Network & Domain Infrastructure Analyzer
Performs genuine, passive network probing:
1. Genuine DNS resolution (A/AAAA records, nameservers, or DNS_FAILED).
2. Genuine TLS handshake & certificate inspection (issuer, validity dates, SANs).
3. Genuine Registration Data Access Protocol (RDAP) lookup (registrar, creation/expiration dates, domain age).
Zero synthetic data: Returns explicit NOT_AVAILABLE or DNS_FAILED states on missing or failed probes.
"""

import socket
import ssl
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx
from app.core.logging import logger
from app.models.features import DomainInformation


class NetworkAnalyzer:
    @staticmethod
    def resolve_dns(hostname: str) -> Dict[str, Any]:
        """
        Performs genuine passive DNS resolution for the target hostname.
        Never mocks or fabricates IP addresses.
        """
        try:
            addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            resolved_ips = list(set(item[4][0] for item in addr_info if item[4]))
            return {
                "status": "RESOLVED",
                "resolved_ips": sorted(resolved_ips),
                "error": None,
            }
        except socket.gaierror as e:
            return {
                "status": "DNS_FAILED",
                "resolved_ips": [],
                "error": f"DNS resolution failed: {e.strerror or str(e)}",
            }
        except Exception as e:
            return {
                "status": "DNS_FAILED",
                "resolved_ips": [],
                "error": f"DNS lookup error: {str(e)}",
            }

    @staticmethod
    def inspect_tls_certificate(hostname: str, port: int = 443, timeout_seconds: float = 3.5) -> Dict[str, Any]:
        """
        Establishes a passive TLS handshake to extract genuine certificate parameters.
        """
        try:
            context = ssl.create_default_context()
            # Non-blocking / timeout-bounded socket connection
            with socket.create_connection((hostname, port), timeout=timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()

                    # Extract Subject and Issuer
                    subject_dict = dict(x[0] for x in cert.get("subject", ()))
                    issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                    issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"

                    # Parse dates
                    not_before_str = cert.get("notBefore")
                    not_after_str = cert.get("notAfter")
                    not_before = None
                    not_after = None
                    if not_before_str:
                        try:
                            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        except Exception:
                            pass
                    if not_after_str:
                        try:
                            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        except Exception:
                            pass

                    # Extract SANs
                    sans = [item[1] for item in cert.get("subjectAltName", ()) if item[0] == "DNS"]

                    now = datetime.now(timezone.utc)
                    is_valid = True
                    if not_after and now > not_after:
                        is_valid = False
                    if not_before and now < not_before:
                        is_valid = False

                    return {
                        "status": "VALID" if is_valid else "EXPIRED",
                        "has_valid_ssl": is_valid,
                        "issuer": issuer_org,
                        "subject": subject_dict.get("commonName"),
                        "valid_from": not_before.isoformat() if not_before else None,
                        "valid_until": not_after.isoformat() if not_after else None,
                        "san_count": len(sans),
                        "sans": sans[:10],
                        "tls_version": tls_version,
                        "cipher": cipher[0] if cipher else None,
                        "error": None,
                    }
        except ssl.SSLCertVerificationError as e:
            return {
                "status": "INVALID_CERT",
                "has_valid_ssl": False,
                "issuer": None,
                "subject": None,
                "valid_from": None,
                "valid_until": None,
                "san_count": 0,
                "sans": [],
                "tls_version": None,
                "cipher": None,
                "error": f"TLS Certificate Verification Error: {str(e)}",
            }
        except (socket.timeout, TimeoutError):
            return {
                "status": "TIMEOUT",
                "has_valid_ssl": None,
                "issuer": None,
                "subject": None,
                "valid_from": None,
                "valid_until": None,
                "san_count": 0,
                "sans": [],
                "tls_version": None,
                "cipher": None,
                "error": f"TLS handshake timed out after {timeout_seconds}s",
            }
        except Exception as e:
            return {
                "status": "NOT_AVAILABLE",
                "has_valid_ssl": None,
                "issuer": None,
                "subject": None,
                "valid_from": None,
                "valid_until": None,
                "san_count": 0,
                "sans": [],
                "tls_version": None,
                "cipher": None,
                "error": str(e),
            }

    @staticmethod
    async def query_rdap(domain: str, timeout_seconds: float = 3.5) -> Dict[str, Any]:
        """
        Queries official public RDAP endpoints (rdap.org) for genuine domain registration information.
        Never fabricates or guesses domain age.
        """
        rdap_url = f"https://rdap.org/domain/{domain.strip().lower()}"
        try:
            async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
                resp = await client.get(
                    rdap_url,
                    headers={"Accept": "application/rdap+json, application/json", "User-Agent": "PhishGuard-AI/2.0"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    events = data.get("events", [])
                    creation_dt: Optional[datetime] = None
                    expiration_dt: Optional[datetime] = None

                    for ev in events:
                        action = ev.get("eventAction")
                        ev_date = ev.get("eventDate")
                        if not ev_date:
                            continue
                        try:
                            clean_date = ev_date.replace("Z", "+00:00")
                            parsed_dt = datetime.fromisoformat(clean_date)
                            if action in ["registration", "created"]:
                                creation_dt = parsed_dt
                            elif action in ["expiration"]:
                                expiration_dt = parsed_dt
                        except Exception:
                            continue

                    # Extract registrar name
                    registrar_name = None
                    for entity in data.get("entities", []):
                        roles = entity.get("roles", [])
                        if "registrar" in roles:
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1 and isinstance(vcard[1], list):
                                for item in vcard[1]:
                                    if item and item[0] == "fn":
                                        registrar_name = item[3]
                                        break
                            if not registrar_name:
                                registrar_name = entity.get("handle")

                    # Extract nameservers
                    nameservers = []
                    for ns in data.get("nameservers", []):
                        ldh = ns.get("ldhName")
                        if ldh:
                            nameservers.append(ldh)

                    # Compute genuine domain age in days
                    domain_age_days = None
                    if creation_dt:
                        now = datetime.now(timezone.utc)
                        domain_age_days = max(0, (now - creation_dt).days)

                    return {
                        "status": "RECORD_FOUND",
                        "registrar": registrar_name,
                        "creation_date": creation_dt,
                        "expiration_date": expiration_dt,
                        "domain_age_days": domain_age_days,
                        "nameservers": nameservers,
                        "error": None,
                    }
                else:
                    return {
                        "status": "NOT_AVAILABLE",
                        "registrar": None,
                        "creation_date": None,
                        "expiration_date": None,
                        "domain_age_days": None,
                        "nameservers": [],
                        "error": f"RDAP service returned status {resp.status_code}",
                    }
        except Exception as e:
            return {
                "status": "NOT_AVAILABLE",
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
                "domain_age_days": None,
                "nameservers": [],
                "error": f"RDAP query error: {str(e)}",
            }

    @classmethod
    async def analyze(
        cls,
        domain: str,
        hostname: str,
        scheme: str = "https",
        port: int = 443,
    ) -> Dict[str, Any]:
        """
        Executes passive network probes concurrently:
        DNS resolution, TLS certificate inspection, and RDAP registration lookup.
        """
        loop = asyncio.get_running_loop()

        # Run socket DNS and TLS in executor to prevent event loop blocking
        dns_future = loop.run_in_executor(None, cls.resolve_dns, hostname)
        tls_future = (
            loop.run_in_executor(None, cls.inspect_tls_certificate, hostname, port, 3.5)
            if scheme == "https"
            else asyncio.sleep(0, result={"status": "HTTP_ONLY", "has_valid_ssl": False, "issuer": None, "error": None})
        )
        rdap_future = cls.query_rdap(domain, timeout_seconds=3.5)

        dns_res, tls_res, rdap_res = await asyncio.gather(dns_future, tls_future, rdap_future, return_exceptions=True)

        if isinstance(dns_res, Exception):
            dns_res = {"status": "DNS_FAILED", "resolved_ips": [], "error": str(dns_res)}
        if isinstance(tls_res, Exception):
            tls_res = {"status": "NOT_AVAILABLE", "has_valid_ssl": None, "issuer": None, "error": str(tls_res)}
        if isinstance(rdap_res, Exception):
            rdap_res = {"status": "NOT_AVAILABLE", "registrar": None, "creation_date": None, "domain_age_days": None, "error": str(rdap_res)}

        nameservers_str = ", ".join(rdap_res.get("nameservers", [])) if rdap_res.get("nameservers") else None

        return {
            "dns": dns_res,
            "tls": tls_res,
            "rdap": rdap_res,
            "domain_info": {
                "registrar": rdap_res.get("registrar"),
                "creation_date": rdap_res.get("creation_date"),
                "expiration_date": rdap_res.get("expiration_date"),
                "domain_age_days": rdap_res.get("domain_age_days"),
                "dnssec": None,
                "has_valid_ssl": tls_res.get("has_valid_ssl"),
                "ssl_issuer": tls_res.get("issuer"),
                "nameservers": nameservers_str,
            }
        }
