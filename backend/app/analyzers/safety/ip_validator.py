"""
PhishGuard AI - IP Address Validation & SSRF Guard.
Strictly evaluates whether an IP address belongs to:
- Loopback (127.0.0.0/8, ::1)
- RFC 1918 Private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- IPv6 Unique Local (fc00::/7)
- Link-Local (169.254.0.0/16, fe80::/10)
- Cloud Provider Metadata (169.254.169.254, metadata.google.internal)
- Unspecified / Broadcast / Multicast
- IPv4-Mapped IPv6
"""

import ipaddress
from typing import Union

CLOUD_METADATA_IPS = {
    "169.254.169.254",
    "fd00:ec2::254",
    "100.100.100.200",  # Alibaba Cloud metadata
}


def is_ip_restricted(ip_str: str) -> bool:
    """
    Evaluates whether an IP address string belongs to restricted/private/internal space.
    Returns True if the IP is dangerous for server-side outbound requests.
    """
    if not ip_str or not isinstance(ip_str, str):
        return True

    clean_ip = ip_str.strip()

    # Direct cloud metadata check
    if clean_ip in CLOUD_METADATA_IPS:
        return True

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return True

    # Check for IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return True

    # Explicit check for 0.0.0.0/8
    if isinstance(ip_obj, ipaddress.IPv4Address):
        if ip_obj in ipaddress.IPv4Network("0.0.0.0/8"):
            return True
        if str(ip_obj) == "255.255.255.255":
            return True

    return False


class IPValidator:
    @staticmethod
    def is_ip_private(ip_str: str) -> bool:
        return is_ip_restricted(ip_str)

    @staticmethod
    def is_ip_restricted(ip_str: str) -> bool:
        return is_ip_restricted(ip_str)
