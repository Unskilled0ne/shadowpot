import ipaddress
import logging
import time
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger("shadowpot.threat_intel")

_CACHE: Dict[str, Dict[str, Any]] = {}

def is_private_or_special_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return True

def enrich_ip(ip_str: str) -> Dict[str, Any]:
    """
    Enriches an IP address with GeoIP, Country, City, and ASN info.
    Includes in-memory cache and private IP detection.
    """
    if not ip_str:
        return {"country": "Unknown", "city": "Unknown", "org": "Unknown", "is_private": True}

    if is_private_or_special_ip(ip_str):
        return {
            "country": "Local/Private",
            "country_code": "LAN",
            "city": "Internal",
            "org": "Private Network",
            "is_private": True
        }

    now = time.time()
    if ip_str in _CACHE:
        cached = _CACHE[ip_str]
        if now - cached.get("_cached_at", 0) < 86400:
            return cached

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,city,org,as",
            timeout=2.0
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "XX"),
                    "city": data.get("city", "Unknown"),
                    "org": data.get("org", data.get("as", "Unknown")),
                    "is_private": False,
                    "_cached_at": now
                }
                _CACHE[ip_str] = result
                return result
    except Exception as e:
        logger.debug(f"GeoIP resolution failed for {ip_str}: {e}")

    fallback = {
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "org": "Unknown",
        "is_private": False,
        "_cached_at": now
    }
    _CACHE[ip_str] = fallback
    return fallback
