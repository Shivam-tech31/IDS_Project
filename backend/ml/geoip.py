"""
GeoIP lookup using ip-api.com (free, no key, 45 req/min).
"""

import httpx
import ipaddress

_cache: dict = {}

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

async def geoip_lookup(ip: str) -> dict | None:
    if _is_private(ip):
        return None
    if ip in _cache:
        return _cache[ip]
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp")
            data = r.json()
            if data.get("status") == "success":
                result = {
                    "country":      data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region":       data.get("regionName"),
                    "city":         data.get("city"),
                    "lat":          data.get("lat"),
                    "lon":          data.get("lon"),
                    "isp":          data.get("isp"),
                }
                _cache[ip] = result
                return result
    except Exception:
        pass
    return None
