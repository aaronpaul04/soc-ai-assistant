"""
IOC (Indicator of Compromise) extractor.
Pulls IPs, domains, hashes, URLs, and emails out of raw alert text.
"""

import re
from typing import Dict, List

# Regex patterns
PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b"
    ),
    "url": re.compile(
        r"https?://[^\s<>\"'()]+",
        re.IGNORECASE,
    ),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|us|uk|de|cn|ru|tk|ml|ga|cf|info|biz|xyz|top|club|online|site|app|dev|tech|ai|me|ly|gov|edu|mil|int)\b",
        re.IGNORECASE,
    ),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    "email": re.compile(
        r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b",
        re.IGNORECASE,
    ),
}

# IP ranges to filter out (private, multicast, broadcast, etc)
PRIVATE_IP_PREFIXES = (
    "10.", "192.168.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "0.0.0.0", "255.255.255.255",
)


def is_public_ip(ip: str) -> bool:
    """Filter out private/internal IPs that won't have threat intel."""
    return not ip.startswith(PRIVATE_IP_PREFIXES)


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Pull all IOCs from a block of text. Returns dedup'd lists per type."""
    if not isinstance(text, str):
        text = str(text)

    iocs = {}
    for name, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        # Dedupe while preserving order
        seen = set()
        unique = []
        for m in matches:
            m = m.lower() if name in ("domain", "email", "md5", "sha1", "sha256") else m
            if m not in seen:
                seen.add(m)
                unique.append(m)
        iocs[name] = unique

    # Filter private IPs out
    iocs["ipv4"] = [ip for ip in iocs["ipv4"] if is_public_ip(ip)]

    # Domains often overlap with URLs; remove domains that are inside URLs
    url_text = " ".join(iocs["url"])
    iocs["domain"] = [d for d in iocs["domain"] if d not in url_text]

    return iocs


if __name__ == "__main__":
    sample_alert = """
    Suspicious PowerShell execution detected on host WIN-DC-01.
    Source IP: 192.168.1.50 connecting to external IP 185.220.101.42
    Downloaded file hash (SHA256): a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
    URL contacted: http://malicious-domain.tk/payload.exe
    Email: attacker@evil-domain.com
    MD5 of payload: 5d41402abc4b2a76b9719d911017c592
    """

    iocs = extract_iocs(sample_alert)
    for category, items in iocs.items():
        print(f"{category}: {items}")