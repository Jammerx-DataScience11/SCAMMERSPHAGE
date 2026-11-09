import re
import math
from urllib.parse import urlparse

# High-value targets often impersonated in banking, payment, gov, and recruitment scams
PROTECTED_BRANDS = [
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "paypal",
    "google", "microsoft", "apple", "amazon", "netflix", "github",
    "linkedin", "indiana", "gov", "nic", "uidai", "epfo", "irctc"
]

# Keywords commonly used in credential harvesting, fake recruitment, and payment links
PHISHING_KEYWORDS = [
    "login", "verify", "verification", "update", "secure", "account",
    "banking", "kyc", "wallet", "payment", "confirm", "suspend",
    "recruitment", "careers-portal", "job-offer", "signin", "auth",
    "password", "credential", "bonus", "refund", "free"
]

# Top-level domains frequently abused by disposable phishing kits
SUSPICIOUS_TLDS = (
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".click", ".loan", ".work", ".zip", ".mov", ".rest"
)

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect random, auto-generated phishing domains."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for char in set(text):
        prob = text.count(char) / length
        entropy -= prob * math.log2(prob)
    return entropy

def analyze_phishing(url: str):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url.lower())
    hostname = parsed.hostname or ""
    path_and_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    full_url = url.lower()

    risk_score = 0
    findings = []

    # 1. Check for raw IPv4 address instead of a domain name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        risk_score += 45
        findings.append("Raw IP address used instead of domain")

    # 2. Check for '@' symbol credential harvesting / deceptive redirect trick
    if "@" in full_url:
        risk_score += 40
        findings.append("Deceptive '@' redirect symbol detected")

    # 3. Check for open redirect patterns in the URL path
    if "//" in parsed.path or "http" in path_and_query:
        risk_score += 25
        findings.append("Suspicious redirect parameter in path")

    # 4. Extract root domain vs subdomains
    domain_parts = hostname.split(".")
    root_domain = domain_parts[-2] if len(domain_parts) >= 2 else hostname
    subdomains = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""

    # 5. Check for Brand Impersonation (e.g., sbi-login.com or sbi.secure-update.xyz)
    for brand in PROTECTED_BRANDS:
        if brand in subdomains:
            risk_score += 45
            findings.append(f"Brand impersonation in subdomain ('{brand}')")
            break
        elif brand in root_domain and root_domain != brand:
            risk_score += 35
            findings.append(f"Deceptive lookalike domain targeting '{brand}'")
            break

    # 6. Check for excessive hyphens (e.g., secure-login-update-portal.com)
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        risk_score += 25
        findings.append(f"Excessive hyphens in domain ({hyphen_count})")
    elif hyphen_count >= 1 and any(k in full_url for k in PHISHING_KEYWORDS):
        risk_score += 15
        findings.append("Hyphenated domain paired with sensitive keywords")

    # 7. Check for deep subdomain chaining (e.g., a.b.c.d.example.com)
    if len(domain_parts) > 4:
        risk_score += 20
        findings.append("Suspiciously deep subdomain nesting")

    # 8. Check for abused Top-Level Domains (TLDs)
    if hostname.endswith(SUSPICIOUS_TLDS):
        risk_score += 25
        findings.append("High-risk disposable domain extension")

    # 9. Check for credential-harvesting & phishing keywords
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    if len(matched_keywords) >= 2:
        risk_score += 25
        findings.append(f"Credential-harvesting terms ({', '.join(matched_keywords[:2])})")
    elif len(matched_keywords) == 1 and risk_score > 0:
        risk_score += 10

    # 10. Check URL length & domain randomness (Entropy)
    if len(full_url) > 85:
        risk_score += 15
        findings.append("Abnormally long obfuscated URL")

    if calculate_entropy(root_domain) > 3.8 and len(root_domain) > 12:
        risk_score += 15
        findings.append("High domain randomness (DGA pattern)")

    # Cap the maximum score impact from this module at 60
    score_impact = min(60, risk_score)

    # Format the final diagnostic message for the dashboard
    if score_impact >= 40:
        status = f"Failed - High Phishing Risk: {'; '.join(findings[:2])}"
    elif score_impact >= 15:
        status = f"Warning - Suspicious traits: {'; '.join(findings[:2])}"
    else:
        status = "Passed - Clean URL structure, no impersonation detected"

    return {
        "status": status,
        "score_impact": score_impact
    }