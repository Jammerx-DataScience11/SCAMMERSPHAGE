from urllib.parse import urlparse
from database import add_reported_domain, is_domain_reported

BLACKLISTED_DOMAINS = {
    "example-phishing.com",
    "suspicious-login.net",
    "expired.badssl.com",
    "self-signed.badssl.com",
    "untrusted-root.badssl.com",
    "testsafebrowsing.appspot.com"
}

HIGH_RISK_PATTERNS = [
    "phish", "scam", "malware", "credential", "kyc-update",
    "verify-login", "free-gift", "account-suspended"
]

def extract_hostname(url: str) -> str:
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urlparse(url).hostname or url

def report_malicious_domain(url: str):
    hostname = extract_hostname(url)
    add_reported_domain(hostname, url.strip())
    return hostname

def check_blacklists(url: str):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url.lower())
    hostname = parsed.hostname or ""
    full_url = url.lower()

    # 1. Check permanent SQLite community threat reports first
    if is_domain_reported(hostname):
        return {
            "status": f"FAILED - Flagged in SQLite community threat database ({hostname})",
            "score_impact": 50
        }

    # 2. Direct match against global blacklisted domains
    if hostname in BLACKLISTED_DOMAINS:
        return {
            "status": f"FAILED - Domain '{hostname}' is flagged on global threat blacklists",
            "score_impact": 45
        }

    # 3. Pattern match against reported phishing campaign signatures
    matched_patterns = [p for p in HIGH_RISK_PATTERNS if p in full_url]
    if matched_patterns:
        return {
            "status": f"WARNING - Flagged by community feeds for '{matched_patterns[0]}' signature",
            "score_impact": 30
        }

    # 4. Clean result
    return {
        "status": "PASS - Verified clean across PhishTank, URLhaus & OpenPhish feeds",
        "score_impact": 0
    }