"""
Threat intel enrichment via VirusTotal and AbuseIPDB.
"""

import os
import time
import base64
import requests
from typing import Dict, Optional
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


def _vt_get(endpoint: str) -> Optional[dict]:
    """Helper for VirusTotal GET requests with error handling."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured"}
    try:
        r = requests.get(
            f"{VT_BASE}/{endpoint}",
            headers={"x-apikey": VT_API_KEY},
            timeout=15,
        )
        if r.status_code == 404:
            return {"error": "not_found"}
        if r.status_code == 429:
            return {"error": "rate_limited"}
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def _summarize_vt(data: dict) -> dict:
    """Pull out the useful bits from a VT response."""
    if not data or "error" in data:
        return data or {"error": "no_data"}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "reputation": attrs.get("reputation"),
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
        "tags": attrs.get("tags", [])[:5],
    }


def enrich_ip_vt(ip: str) -> dict:
    return _summarize_vt(_vt_get(f"ip_addresses/{ip}"))


def enrich_domain_vt(domain: str) -> dict:
    return _summarize_vt(_vt_get(f"domains/{domain}"))


def enrich_hash_vt(file_hash: str) -> dict:
    data = _vt_get(f"files/{file_hash}")
    if not data or "error" in data:
        return data or {"error": "no_data"}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "type_description": attrs.get("type_description"),
        "meaningful_name": attrs.get("meaningful_name"),
        "popular_threat_classification": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
    }


def enrich_url_vt(url: str) -> dict:
    # VT requires URLs to be base64url encoded with no padding
    encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return _summarize_vt(_vt_get(f"urls/{encoded}"))


def enrich_ip_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not configured"}
    try:
        r = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "abuse_confidence": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
            "is_tor": data.get("isTor"),
        }
    except Exception as e:
        return {"error": str(e)}


def enrich_iocs(iocs: Dict[str, list]) -> Dict[str, list]:
    """
    Take the IOC dict from extractor and enrich each item.
    Returns the same structure but values are list of {ioc, enrichment} dicts.
    """
    result = {}

    # IPs: both VT and AbuseIPDB
    result["ipv4"] = []
    for ip in iocs.get("ipv4", [])[:5]:  # limit to first 5 to respect free tier
        result["ipv4"].append({
            "ioc": ip,
            "virustotal": enrich_ip_vt(ip),
            "abuseipdb": enrich_ip_abuseipdb(ip),
        })
        time.sleep(16)  # VT free tier: 4/min, so wait 16s between calls

    # Hashes: VT
    result["hashes"] = []
    all_hashes = iocs.get("md5", []) + iocs.get("sha1", []) + iocs.get("sha256", [])
    for h in all_hashes[:5]:
        result["hashes"].append({
            "ioc": h,
            "virustotal": enrich_hash_vt(h),
        })
        time.sleep(16)

    # Domains: VT
    result["domains"] = []
    for d in iocs.get("domain", [])[:5]:
        result["domains"].append({
            "ioc": d,
            "virustotal": enrich_domain_vt(d),
        })
        time.sleep(16)

    # URLs: VT
    result["urls"] = []
    for u in iocs.get("url", [])[:5]:
        result["urls"].append({
            "ioc": u,
            "virustotal": enrich_url_vt(u),
        })
        time.sleep(16)

    return result


if __name__ == "__main__":
    # Quick test with one known-malicious IOC
    print("Testing AbuseIPDB on a known scanner IP (185.220.101.42 = Tor exit)...")
    print(enrich_ip_abuseipdb("185.220.101.42"))
    print()
    print("Testing VirusTotal on the same IP...")
    print(enrich_ip_vt("185.220.101.42"))