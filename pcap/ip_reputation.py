"""
IP Reputation Checker - Verifica reputación de IPs usando AbuseIPDB

APIs gratuitas disponibles:
- AbuseIPDB ( gratuito hasta 1000 requests/dia)
- Shodan (limitado)
- VirusTotal (limitado)

Este modulo usa AbuseIPDB: https://www.abuseipdb.com/
"""

import os
import logging
import requests
from typing import Dict, List, Optional
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

logger = logging.getLogger(__name__)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
REPUTATION_THRESHOLD = int(os.getenv("IP_REPUTATION_THRESHOLD", "50"))

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_reputation(ip: str) -> Optional[Dict]:
    """Verifica la reputación de una IP en AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        logger.debug("AbuseIPDB API key no configurada")
        return None

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": ip,
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "country_code": data.get("countryCode", ""),
                "iso_country_code": data.get("isoCountryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "usage_type": data.get("usageType", ""),
                "category": data.get("category", []),
                "last_reported_at": data.get("lastReportedAt", ""),
                "public": data.get("isPublic", True),
                "ip_version": data.get("ipVersion", 4),
                "status": data.get("status", "unknown")
            }
        elif response.status_code == 429:
            logger.warning("AbuseIPDB rate limit excedido")
        elif response.status_code == 401:
            logger.error("AbuseIPDB API key invalida")
        else:
            logger.debug(f"AbuseIPDB error: {response.status_code}")

    except requests.RequestException as e:
        logger.debug(f"Error checking IP {ip}: {e}")

    return None


def check_batch_ips(ips: List[str], max_requests: int = 5) -> Dict[str, Dict]:
    """Verifica múltiples IPs con rate limiting."""
    results = {}

    for i, ip in enumerate(set(ips)):
        if i >= max_requests:
            logger.warning(f"Rate limit: solo verificando {max_requests} IPs")
            break

        if not ip or ip.startswith(("10.", "192.168.", "172.", "127.", "224.")):
            continue

        result = check_ip_reputation(ip)
        if result:
            results[ip] = result
            logger.info(f"Checked {ip}: score={result.get('abuse_confidence')}")

    return results


def is_malicious(ip: str) -> bool:
    """Verifica rápidamente si una IP es maliciosa."""
    result = check_ip_reputation(ip)
    if result:
        return result.get("abuse_confidence", 0) >= REPUTATION_THRESHOLD
    return False


def get_ip_summary(ip: str) -> str:
    """Retorna resumen simple de reputación."""
    if not ABUSEIPDB_API_KEY:
        return "API no configurada"

    result = check_ip_reputation(ip)
    if not result:
        return "No disponible"

    score = result.get("abuse_confidence", 0)
    if score >= 80:
        return f"MALICIOSA ({score}%)"
    elif score >= 50:
        return f"Sospechosa ({score}%)"
    else:
        return f"Limpia ({score}%)"


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1:
        ip = sys.argv[1]
    else:
        ip = "8.8.8.8"

    print(f"Checking {ip}...")
    result = check_ip_reputation(ip)
    if result:
        print(f"Confidence: {result['abuse_confidence']}%")
        print(f"Reports: {result['total_reports']}")
        print(f"ISP: {result['isp']}")
        print(f"Country: {result['country_code']}")
        print(f"Domain: {result['domain']}")
    else:
        print("No se pudo verificar")