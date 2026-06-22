#region Imports
import csv
from dataclasses import dataclass
import re
import subprocess
import time
from typing import Optional
import certifi
from OpenSSL import crypto
import ssl
import socket
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, NameOID
import dns.resolver
from urllib.parse import urlparse
import tldextract
#endregion

#region Data classes
@dataclass
class CAResult:
    website: str
    ca_name: Optional[str] = None
    ca_url: Optional[str] = None
    ca_type: str = "unknown"           # "private" / "third" / "unknown"
    ocsp_stapling: bool = False
    critical_dependency: bool = False  # True if third-party CA AND no OCSP stapling
#endregion

# ---------------------------------------------------------------------------
# Corporate family table
# ---------------------------------------------------------------------------
# Maps every known subsidiary / product domain to a canonical owner token.
# Add rows freely — the token strings just need to match within a family.
# Keys are registered domains (eTLD+1); values are arbitrary owner labels.
 
CORPORATE_FAMILY: dict[str, str] = {
    # Google / Alphabet
    "google.com":       "google",
    "googleapis.com":   "google",
    "gstatic.com":      "google",
    "googleusercontent.com": "google",
    "googlevideo.com":  "google",
    "goog":             "google",
    "pki.goog":         "google",
    "youtube.com":      "google",
    "youtu.be":         "google",
    "gmail.com":        "google",
    "googlemail.com":   "google",
    "googlesyndication.com": "google",
    "googletagmanager.com":  "google",
    "doubleclick.net":  "google",
    "ggpht.com":        "google",
    "chromium.org":     "google",
 
    # Meta / Facebook
    "facebook.com":     "meta",
    "fb.com":           "meta",
    "fbcdn.net":        "meta",
    "instagram.com":    "meta",
    "whatsapp.com":     "meta",
    "whatsapp.net":     "meta",
    "messenger.com":    "meta",
    "oculus.com":       "meta",
 
    # Microsoft
    "microsoft.com":    "microsoft",
    "microsoftonline.com": "microsoft",
    "azure.com":        "microsoft",
    "azureedge.net":    "microsoft",
    "msecnd.net":       "microsoft",
    "windows.net":      "microsoft",
    "msftconnecttest.com": "microsoft",
    "office.com":       "microsoft",
    "office365.com":    "microsoft",
    "live.com":         "microsoft",
    "hotmail.com":      "microsoft",
    "outlook.com":      "microsoft",
    "sharepoint.com":   "microsoft",
    "skype.com":        "microsoft",
    "xbox.com":         "microsoft",
    "linkedin.com":     "microsoft",  # acquired 2016
 
    # Amazon / AWS
    "amazon.com":       "amazon",
    "amazonaws.com":    "amazon",
    "aws.amazon.com":   "amazon",
    "cloudfront.net":   "amazon",
    "awsstatic.com":    "amazon",
    "amazonvideo.com":  "amazon",
    "primevideo.com":   "amazon",
    "audible.com":      "amazon",
    "imdb.com":         "amazon",
    "twitch.tv":        "amazon",   # acquired 2014
    "goodreads.com":    "amazon",
 
    # Apple
    "apple.com":        "apple",
    "icloud.com":       "apple",
    "me.com":           "apple",
    "mac.com":          "apple",
    "mzstatic.com":     "apple",
    "apple-dns.net":    "apple",
    "aaplimg.com":      "apple",
 
    # Cloudflare
    "cloudflare.com":   "cloudflare",
    "cloudflare.net":   "cloudflare",
    "cloudflarestorage.com": "cloudflare",
    "1dot1dot1dot1.cloudflare-dns.com": "cloudflare",
 
    # Yahoo / Oath / Verizon Media
    "yahoo.com":        "yahoo",
    "yimg.com":         "yahoo",
    "yahooapis.com":    "yahoo",
    "oath.com":         "yahoo",
    "aol.com":          "yahoo",
    "tumblr.com":       "yahoo",
 
    # Alibaba
    "alibaba.com":      "alibaba",
    "alicdn.com":       "alibaba",
    "alibabadns.com":   "alibaba",
    "aliyun.com":       "alibaba",
    "alikunlun.com":    "alibaba",
    "taobao.com":       "alibaba",
    "tmall.com":        "alibaba",
 
    # Tencent
    "tencent.com":      "tencent",
    "qq.com":           "tencent",
    "wechat.com":       "tencent",
    "weixin.qq.com":    "tencent",
    "qcloud.com":       "tencent",
 
    # Twitter / X
    "twitter.com":      "twitter",
    "x.com":            "twitter",
    "twimg.com":        "twitter",
    "t.co":             "twitter",
 
    # Spotify
    "spotify.com":      "spotify",
    "scdn.co":          "spotify",
    "spotifycdn.com":   "spotify",
 
    # Netflix
    "netflix.com":      "netflix",
    "nflximg.com":      "netflix",
    "nflxvideo.net":    "netflix",
    "nflxext.com":      "netflix",
    "fast.com":         "netflix",
 
    # Adobe
    "adobe.com":        "adobe",
    "adobedtm.com":     "adobe",
    "2o7.net":          "adobe",
    "omtrdc.net":       "adobe",
    "scene7.com":       "adobe",
 
    # Salesforce
    "salesforce.com":   "salesforce",
    "force.com":        "salesforce",
    "exacttarget.com":  "salesforce",
    "pardot.com":       "salesforce",
 
    # WordPress / Automattic
    "wordpress.com":    "automattic",
    "wordpress.org":    "automattic",
    "wp.com":           "automattic",
    "gravatar.com":     "automattic",
}

def get_tld(hostname: str) -> str:
    """Return the registered domain (eTLD+1) for a hostname."""
    try:
        ext = tldextract.TLDExtract(cache_dir=None)(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return hostname
    except Exception:
        parts = hostname.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
 
 
def owner_of(domain: str) -> Optional[str]:
    """
    Return the corporate owner token for *domain*, or None if unknown.
    Checks the exact registered domain first, then walks up suffix variants
    so that e.g. 'ocsp.pki.goog' → registered domain 'pki.goog' → 'google'.
    """
    tld = get_tld(domain.lower().lstrip("*."))
    return CORPORATE_FAMILY.get(tld)
 
 
def same_corporate_family(domain_a: str, domain_b: str) -> bool:
    """
    Return True if both domains belong to the same corporate family,
    e.g. same_corporate_family('googleapis.com', 'google.com') → True.
    """
    owner_a = owner_of(domain_a)
    owner_b = owner_of(domain_b)
    # Both must be known and identical
    return bool(owner_a and owner_b and owner_a == owner_b)
    
# ---------------------------------------------------------------------------
# Public CA keyword list (unchanged from your original)
# ---------------------------------------------------------------------------
 
PUBLIC_CA_KEYWORDS = [
    "digicert",
    "let's encrypt",
    "letsencrypt",
    "sectigo",
    "globalsign",
    "global sign",
    "geotrust",
    "rapidssl",
    "comodo",
    "thawte",
    "symantec",
    "ssl corp",
    "starfield",
    "quovadis",
    "trustwave",
    "amazon trust",
    "google trust services",
    "certum",
    "buypass",
    "zerossl",
    "entrust",
]

def is_https(domain: str, retries: int = 2, timeout: int = 10) -> bool:
    """Return True if the domain responds on HTTPS (port 443)."""
    for attempt in range(retries + 1):  # +1 so retries=2 means 3 total attempts
        try:
            ctx = ssl.create_default_context()
            conn = socket.create_connection((domain, 443), timeout=timeout)
            with ctx.wrap_socket(conn, server_hostname=domain):
                return True
        except (ConnectionResetError, BrokenPipeError):
            if attempt < retries:
                time.sleep(1)
            continue
        except Exception:
            return False  # non-transient error, don't retry
    return False

def get_san_tlds(domain: str, retries: int = 2, timeout: int = 10) -> set[str]:
    """Return registered domains from TLS SAN for `domain`."""
    sans: set[str] = set()
    for attempt in range(retries + 1):  # +1 so retries=2 means 3 total attempts
        try:
            ctx = ssl.create_default_context()
            conn = socket.create_connection((domain, 443), timeout=timeout)
            with ctx.wrap_socket(conn, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                for kind, value in cert.get("subjectAltName", []):
                    if kind == "DNS":
                        clean = value.lstrip("*.")
                        sans.add(get_tld(clean))
                return sans  # success — exit early
        except (ConnectionResetError, BrokenPipeError):
            if attempt < retries:
                time.sleep(1)
            continue  # transient — retry
        except Exception:
            break  # permanent failure (no HTTPS, bad cert, etc.) — don't retry
    return sans

def dig_ns(domain: str, timeout: int = 5) -> list[str]:
    """Return nameserver hostnames for *domain* via DNS query."""
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=timeout)
        return [str(r.target).rstrip(".").lower() for r in answers]
    except Exception:
        return []

# ---------------------------------------------------------------------------
# SOA helper (kept local so this module is self-contained)
# ---------------------------------------------------------------------------
 
def _dig_soa(domain: str, timeout: int = 5) -> Optional[str]:
    try:
        answers = dns.resolver.resolve(domain, "SOA", lifetime=timeout)
        return str(answers[0].mname).rstrip(".").lower()
    except Exception:
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            candidate = ".".join(parts[i:])
            try:
                answers = dns.resolver.resolve(candidate, "SOA", lifetime=timeout)
                return str(answers[0].mname).rstrip(".").lower()
            except Exception:
                continue
        return None
    
def is_public_ca_name(ca_name: str) -> bool:
    name = (ca_name or "").lower()
    return any(kw in name for kw in PUBLIC_CA_KEYWORDS)

def dig_cname(domain: str, timeout: int = 5) -> Optional[str]:
    """Return the first CNAME target for *domain*."""
    try:
        answers = dns.resolver.resolve(domain, "CNAME", lifetime=timeout)
        return str(answers[0].target).rstrip(".").lower()
    except Exception:
        return None
#endregion

#region CA Helpers
def getCA(domain):
    context = ssl.create_default_context()

    with socket.create_connection((domain, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()

    issuer = {}

    for rdn in cert["issuer"]:
        for key, value in rdn:
            issuer[key] = value

    return f"{issuer.get('organizationName')} + {issuer.get('commonName')}"

def getCA_URL(domain: str):
    context = ssl.create_default_context()

    with socket.create_connection((domain, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as tls:
            cert_der = tls.getpeercert(binary_form=True)

    cert = x509.load_der_x509_certificate(cert_der)

    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value

        for desc in aia:
            if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                parsed = urlparse(desc.access_location.value)
                host = parsed.hostname or desc.access_location.value
                return host

    except x509.ExtensionNotFound:
        return None

    return None

def get_ssl_info(domain: str, timeout: int = 10) -> dict:
    """
    Fetch the SSL certificate for *domain* and extract:
      - SAN list (subject alternate names as eTLD+1 values)
      - CA issuer common name
      - OCSP URLs
      - CRL distribution points
      - Whether OCSP stapling is active
    Returns a dict; empty dict on failure.
    """
    result = {
        "san_tlds": [],
        "ca_name": None,
        "ca_url": None,
        "ocsp_urls": [],
        "crl_urls": [],
        "ocsp_stapled": False,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der is None:
                    return result

                x509_cert = x509.load_der_x509_certificate(cert_der)

                # SANs
                try:
                    san_ext = x509_cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    ).value
                    result["san_tlds"] = list({
                        get_tld(re.sub(r"^\\*\\.", "", name))
                        for name in san_ext.get_values_for_type(x509.DNSName)
                    })
                except x509.ExtensionNotFound:
                    result["san_tlds"] = []

                # Issuer / CA name
                issuer = x509_cert.issuer
                org_name = None
                common_name = None
                org_unit = None
                for attribute in issuer:
                    if attribute.oid == NameOID.ORGANIZATION_NAME and not org_name:
                        org_name = attribute.value
                    elif attribute.oid == NameOID.COMMON_NAME and not common_name:
                        common_name = attribute.value
                    elif attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME and not org_unit:
                        org_unit = attribute.value

                result["ca_name"] = org_name or common_name or org_unit or ""

                # Try to resolve the CA issuer location from the certificate's AIA extension.
                if not result["ca_url"]:
                    result["ca_url"] = getCA_URL(domain)

                # OCSP / CRL from caIssuers / OCSP extension (not always in stdlib cert dict)
                # Use openssl CLI for richer extension data
    except Exception:
        pass

    # Supplement with openssl for OCSP stapling check
    try:
        cmd = [
            "openssl", "s_client", "-connect", f"{domain}:443",
            "-status", "-servername", domain,
        ]
        proc = subprocess.run(
            cmd, input=b"", capture_output=True, timeout=timeout + 5
        )
        output = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")

        if "OCSP response:" in output and "no response sent" not in output.lower():
            result["ocsp_stapled"] = True

        # Extract OCSP URL
        for line in output.splitlines():
            if "OCSP - URI:" in line:
                url = line.split("URI:")[-1].strip()
                result["ocsp_urls"].append(url)
                if not result["ca_url"]:
                    host = re.sub(r"https?://", "", url).split("/")[0]
                    result["ca_url"] = get_tld(host)
            if "CRL - URI:" in line or ("URI:" in line and ".crl" in line.lower()):
                url = line.split("URI:")[-1].strip()
                result["crl_urls"].append(url)
    except Exception:
        pass

    return result
#endregion

#region Put it all together

PUBLIC_CA_KEYWORDS = [
    "digicert",
    "let's encrypt",
    "letsencrypt",
    "sectigo",
    "globalsign",
    "global sign",
    "geotrust",
    "rapidssl",
    "comodo",
    "thawte",
    "symantec",
    "ssl corp",
    "starfield",
    "quovadis",
    "trustwave",
    "amazon trust",
    "google trust services",
    "certum",
    "buypass",
]

def is_public_ca_name(ca_name: str) -> bool:
    name = (ca_name or "").lower()
    return any(keyword in name for keyword in PUBLIC_CA_KEYWORDS)


# ---------------------------------------------------------------------------
# classify_ca — updated with corporate-family check
# ---------------------------------------------------------------------------
 
def classify_ca(
    ca_url: str,
    website: str,
    san_tlds: list[str],
    ca_name: str = "",
) -> str:
    """
    Classify a CA as 'private', 'third', or 'unknown'.
 
    Priority order (stops at first conclusive result):
      1. Known public CA name keyword                     → third
      2. Corporate family match on ca_url vs website      → private  ← NEW
      3. Company name in CA name string                   → private
      4. TLD match (ca_url == website registered domain)  → private
      5. CA TLD in website SAN list                       → private
      6. SOA mismatch between ca_url and website          → third
      7. ca_url doesn't contain website TLD               → third
      8. Fallback                                         → unknown
    """
    ca_name_lower = (ca_name or "").lower()
    w_tld = get_tld(website)
    domain_root = w_tld.split(".")[0]  # e.g. "google" from "google.com"
 
    # 1. Definitively public CA by name — check first so well-known CAs are
    #    never accidentally classified as private (e.g. "Google Trust Services"
    #    for a non-Google site).
    if is_public_ca_name(ca_name_lower):
        # Exception: if the public CA is actually owned by the same company
        # (e.g. Google Trust Services for google.com) treat as private.
        if ca_url and same_corporate_family(ca_url, website):
            return "private"
        if ca_url and owner_of(website) and owner_of(website) in ca_name_lower:
            return "private"
        return "third"
 
    # 2. Corporate family match on the CA issuer URL.
    #    Catches googleapis.com, gstatic.com, fbcdn.net, etc.
    if ca_url and same_corporate_family(ca_url, website):
        return "private"
 
    # 3. Company/domain name appears inside the CA name string.
    if domain_root and domain_root in ca_name_lower:
        return "private"
    if w_tld and w_tld in ca_name_lower:
        return "private"
    if ca_url and w_tld and w_tld in ca_url.lower():
        return "private"
 
    # 4. Exact TLD match.
    if ca_url:
        ca_tld = get_tld(ca_url)
        if ca_tld and ca_tld == w_tld:
            return "private"
 
        # 5. CA TLD found in the website's SAN list.
        if ca_tld in san_tlds:
            return "private"
 
        # 6. SOA mismatch → different DNS authority → third-party.
        ca_soa = _dig_soa(ca_url)
        w_soa = _dig_soa(website)
        if ca_soa and w_soa and ca_soa != w_soa:
            return "third"
 
        # 7. ca_url doesn't mention the website's registered domain at all.
        if w_tld and w_tld not in ca_url.lower():
            return "third"
 
    return "unknown"

def measure_ca(website: str) -> CAResult:
    result = CAResult(website=website)
    ssl_info = get_ssl_info(website)
    if not ssl_info:
        return result

    result.ca_name = ssl_info.get("ca_name", "")
    result.ca_url = ssl_info.get("ca_url", "")
    result.ocsp_stapling = ssl_info.get("ocsp_stapled", False)

    san_tlds = ssl_info.get("san_tlds", [])
    result.ca_type = classify_ca(result.ca_url or "", website, san_tlds, result.ca_name)

    # Critical dependency: third-party CA AND no OCSP stapling
    result.critical_dependency = (result.ca_type == "third") and not result.ocsp_stapling

    return result

def main():
    input_path  = "src/Source_Data/Cloudflare_Top100_Domains.csv"
    output_path = "src/Source_Data/ca_results.csv"
 
    rows = []
 
    with open(input_path, "r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
 
        for row in reader:
            domain_name = row["domain"].strip()
            description = row.get("description", "").strip()
 
            ca_result = measure_ca(domain_name)
 
            print(
                f"Domain:  {domain_name}\n"
                f"CA Name: {ca_result.ca_name}\n"
                f"Type:    {ca_result.ca_type}\n"
            )
            rows.append({
                "domain":      domain_name,
                "CA Name":     ca_result.ca_name,
                "type":        ca_result.ca_type,
            })
            
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "CA Name", "type"])
        writer.writeheader()
        writer.writerows(rows)

if __name__ == "__main__":
    main()
#endregion