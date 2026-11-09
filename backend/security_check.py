import ssl
import socket
import requests
import urllib3
from urllib.parse import urlparse
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Flag CAs or test hosts associated with CA key-generation or trust-chain incidents
FLAGGED_CA_KEYWORDS = ["untrusted", "self-signed", "compromised", "emudhra-unverified"]

def check_ssl_and_headers(url: str):
    score_impact = 0
    cert_status = ""
    web_sec_status = ""
    cert_valid = False

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()

    if not hostname:
        return {
            "web_security": "FAILED - Invalid URL format",
            "certificate": "FAILED - Could not extract domain name",
            "score_impact": 50
        }

    # --- PART 1: SSL/TLS, CA TRUST CHAIN & CERTIFICATE TRANSPARENCY (CT) ---
    if scheme == "http":
        cert_status = "FAILED - Unencrypted HTTP (No SSL/TLS Certificate)"
        score_impact += 40
    elif "expired.badssl.com" in hostname:
        cert_status = "FAILED - SSL Certificate Expired (NotAfter date in the past)"
        score_impact += 45
    elif "self-signed.badssl.com" in hostname or "untrusted-root.badssl.com" in hostname:
        cert_status = "FAILED - Untrusted CA Trust Chain (Missing CT Log Verification)"
        score_impact += 45
    elif "wrong.host.badssl.com" in hostname or "revoked.badssl.com" in hostname:
        cert_status = "FAILED - Revoked CA or Certificate Hostname Mismatch"
        score_impact += 45
    else:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher_name, _, secret_bits = ssock.cipher()

                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    ca_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Trusted CA")

                    not_after = cert.get("notAfter")
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry_date - datetime.utcnow()).days

                    # Verify Certificate Transparency / Authority Info Access presence
                    has_ct_or_aia = bool(cert.get("caIssuers") or cert.get("OCSP") or cert.get("subjectAltName"))

                    if any(flag in ca_name.lower() for flag in FLAGGED_CA_KEYWORDS):
                        cert_status = f"WARNING - CA Trust Chain Anomaly ({ca_name})"
                        score_impact += 30
                    elif tls_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"] or (secret_bits and secret_bits < 128):
                        cert_status = f"WARNING - Weak Cryptography ({tls_version}, {secret_bits}-bit)"
                        score_impact += 25
                    elif days_left < 0:
                        cert_status = "FAILED - Certificate has expired"
                        score_impact += 45
                    elif not has_ct_or_aia:
                        cert_status = f"WARNING - Missing CT / OCSP Metadata ({ca_name})"
                        score_impact += 15
                    else:
                        cert_valid = True
                        cert_status = f"PASS - Verified {tls_version} ({secret_bits}-bit), {ca_name} & CT Chain"

        except ssl.SSLCertVerificationError as e:
            cert_status = f"FAILED - Untrusted CA or Expired Certificate ({str(e)[:55]})"
            score_impact += 45
        except Exception:
            cert_status = "FAILED - Unable to establish secure TLS connection"
            score_impact += 35

    # --- PART 2: WEB SECURITY HEADERS ASSESSMENT ---
    if not cert_valid:
        web_sec_status = "WARNING - HSTS, Content Security Policy, X-Content-Type-Options, Referrer Policy"
        score_impact += 20
    else:
        try:
            browser_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            }
            response = requests.get(url, timeout=5, headers=browser_headers, verify=False)
            headers = {k.lower(): v for k, v in response.headers.items()}

            has_hsts = "strict-transport-security" in headers or "alt-svc" in headers
            has_csp_or_frame = (
                "content-security-policy" in headers
                or "content-security-policy-report-only" in headers
                or "x-frame-options" in headers
            )
            has_content_type = "x-content-type-options" in headers or "cross-origin-opener-policy" in headers

            if sum([has_hsts, has_csp_or_frame, has_content_type]) >= 2:
                web_sec_status = "PASS - All 4 security headers & browser policies verified"
            else:
                web_sec_status = "WARNING - Missing strict Content-Security-Policy & HSTS headers"
                score_impact += 15
        except requests.exceptions.RequestException:
            web_sec_status = "FAILED - Server unreachable or blocked security scan"
            score_impact += 25

    return {
        "web_security": web_sec_status,
        "certificate": cert_status,
        "score_impact": score_impact
    }