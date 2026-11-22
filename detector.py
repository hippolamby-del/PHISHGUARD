
from urllib.parse import urlparse
import ipaddress
import re

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification",
    "account", "secure", "update", "password",
    "payment", "wallet", "billing", "confirm"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "cutt.ly", "is.gd", "rb.gy"
}


def analyze_url(url: str) -> dict:
    """Analyze a URL using simple defensive heuristics."""

    url = url.strip()

    if not url:
        return {
            "score": 100,
            "risk": "High",
            "host": "",
            "findings": ["No URL was provided."]
        }

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    findings = []
    score = 0

    if not host:
        return {
            "score": 100,
            "risk": "High",
            "host": "",
            "findings": ["Invalid or unrecognized URL."]
        }

    # Detect raw IP addresses
    try:
        ipaddress.ip_address(host)
        findings.append("URL uses an IP address instead of a domain.")
        score += 25
    except ValueError:
        pass

    # Check HTTPS
    if parsed.scheme.lower() != "https":
        findings.append("URL does not use HTTPS.")
        score += 10

    # Detect deceptive user information in URLs
    if parsed.username or parsed.password:
        findings.append("URL contains misleading user information.")
        score += 25

    # Detect punycode domains
    if "xn--" in host:
        findings.append("Domain contains encoded characters.")
        score += 20

    # Detect unusually long hostnames
    if len(host) > 50:
        findings.append("Hostname is unusually long.")
        score += 15

    # Detect excessive subdomains
    if len(host.split(".")) > 4:
        findings.append("Domain contains many subdomains.")
        score += 10

    # Detect URL shorteners
    if host in URL_SHORTENERS:
        findings.append("URL uses a shortening service.")
        score += 15

    # Detect suspicious keywords
    text_to_check = (host + parsed.path + parsed.query).lower()

    matches = [
        keyword for keyword in SUSPICIOUS_KEYWORDS
        if keyword in text_to_check
    ]

    if matches:
        findings.append(
            "Suspicious keywords detected: " + ", ".join(matches)
        )
        score += min(len(matches) * 5, 20)

    # Detect PayPal impersonation indicators
    if "paypal" in host:
        official = (
            host == "paypal.com"
            or host.endswith(".paypal.com")
        )

        if not official:
            findings.append(
                "PayPal name detected in a non-official domain."
            )
            score += 35

    score = min(score, 100)

    if score >= 50:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append(
            "No common warning signs detected by this basic analysis."
        )

    return {
        "score": score,
        "risk": risk,
        "host": host,
        "findings": findings
    }
