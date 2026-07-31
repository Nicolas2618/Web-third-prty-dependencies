#region Imports
#########################################################################################################################################
#Imports
########################################################################################################################################
import re
import ssl
import csv
import time
import socket
import circlify
import subprocess
import tldextract
import numpy as np
import dns.resolver
import pandas as pa
from OpenSSL import crypto
from typing import Optional
from cryptography import x509
from dataclasses import dataclass
from urllib.parse import urlparse
from domains import CORPORATE_FAMILY
import matplotlib.patches as mpatches
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, NameOID
import pandas as pd
#endregion

#region Data classes
########################################################################################################################################
#Data Classes
########################################################################################################################################

@dataclass
class CAResult:
    website: str
    ca_name: Optional[str] = None
    ca_url: Optional[str] = None
    ca_type: str = "unknown"                 # "private" / "third" / "unknown" / "infrastructure"
    ocsp_stapling: Optional[bool] = None      # True / False / None = undetermined
    critical_dependency: bool = False         # True only if ca_type == "third" AND ocsp_stapling is False
    ssl_error: Optional[str] = None
    ssl_or_tls: str = "unknown"
    https_enabled: bool = False
#region Basic helpers
########################################################################################################################################
#Basic Helpers
########################################################################################################################################
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
    "gts",
    "amazon rsa",
    "amazon ecc",
    "amazon trust services",
    "we1",
    "we2",
    "wr1",
    "wr2",
]

def is_https(domain: str, retries: int = 2, timeout: int = 10) -> bool:
    """Return True if the domain completes a TLS handshake on port 443.
    Tries the bare domain first, then falls back to www.<domain>,
    matching the fallback behavior used in measure_ca()/get_ssl_info().
    """
    def _attempt(host: str) -> bool:
        for attempt in range(retries + 1):
            conn = None
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = socket.create_connection((host, 443), timeout=timeout)
                with ctx.wrap_socket(conn, server_hostname=host):
                    return True
            except (ConnectionResetError, BrokenPipeError, socket.timeout):
                if conn:
                    conn.close()
                if attempt < retries:
                    time.sleep(1)
                continue
            except Exception:
                if conn:
                    conn.close()
                return False
        return False

    if _attempt(domain):
        return True
    return _attempt(f"www.{domain}")

INFRASTRUCTURE_KEYWORDS = [
    "cloudfront",
    "akadns",
    "akamai",
    "apple-dns",
    "cdn",
]

def is_infrastructure_domain(domain: str) -> bool:
    """
    Returns true if and only if the domain in lowercase contains any of the keywords in the infrastructure keywords
    list, just to revise if it is in the correct infrastructre.
    """
    d = domain.lower()

    return any(k in d for k in INFRASTRUCTURE_KEYWORDS)

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
    """
    After obtaining the Certificate Authority name, it checks for containment in the public CA keywords shown above.
    """
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
#########################################################################################################################################
#CA Helpers
#########################################################################################################################################
def getCA(domain) -> str:
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
      - SAN list, CA issuer name, OCSP/CRL URLs, and OCSP stapling status.
    """

    result = {
        "san_tlds": [],
        "ca_name": None,
        "ca_url": None,
        "tls_or_ssl": None,
        "ocsp_urls": [],
        "crl_urls": [],
        "ocsp_stapled": None, 
    }
    
    # 1. Initial Handshake to get Certificate Data
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["tls_or_ssl"] = f"{ssock.version()}"
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    x509_cert = x509.load_der_x509_certificate(cert_der)
                    # (SAN and Issuer extraction logic remains the same as your original)
                    issuer = x509_cert.issuer
                    org = next((a.value for a in issuer if a.oid == NameOID.ORGANIZATION_NAME), None)
                    cn = next((a.value for a in issuer if a.oid == NameOID.COMMON_NAME), None)
                    result["ca_name"] = f"{org} {cn}" if org and cn else (org or cn)
    except Exception as e:
        print(f"[SSL ERROR] {domain}: {e}")

    # 2. OCSP Stapling Check (The part that was failing)
    try:
        cmd = ["openssl", "s_client", "-connect", f"{domain}:443", "-status", "-servername", domain]
        proc = subprocess.run(cmd, input=b"Q\n", capture_output=True, timeout=timeout + 5)

        output = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
        output_l = output.lower()

        if "ocsp response: no response sent" in output_l or "no ocsp response received" in output_l:
            result["ocsp_stapled"] = False
        elif "ocsp response:" in output_l or "ocsp response data:" in output_l:
            result["ocsp_stapled"] = True

        for line in output.splitlines():
            if "OCSP - URI:" in line:
                result["ocsp_urls"].append(line.split("URI:")[-1].strip())
            if "CRL - URI:" in line or (".crl" in line.lower() and "URI:" in line):
                result["crl_urls"].append(line.split("URI:")[-1].strip())

    except subprocess.TimeoutExpired:
        print(f"[OCSP TIMEOUT] {domain}")
    except FileNotFoundError:
        print(f"[OCSP ERROR] {domain}: 'openssl' binary not found on PATH")
    except Exception as e:
        print(f"[OCSP ERROR] {domain}: {type(e).__name__}: {e}")

    return result

def check_ocsp_stapling(hostname, port=443, timeout=10):
    """
    Checks if a website supports OCSP Stapling using OpenSSL safely.
    Returns True, False, or None (undetermined).
    """
    cmd = [
        "openssl", "s_client", "-connect", f"{hostname}:{port}",
        "-status", "-servername", hostname
    ]
    try:
        result = subprocess.run(
            cmd,
            input=b"Q\n",
            capture_output=True,
            timeout=timeout
        )
        output = (
            result.stdout.decode(errors="replace")
            + result.stderr.decode(errors="replace")
        )
        # Normalize to lowercase ONCE to avoid case-sensitivity bugs
        output_l = output.lower()

        # Check for explicit "no stapling" signals first
        if (
            "ocsp response: no response sent" in output_l
            or "no ocsp response received" in output_l
            or "ocsp response: no response" in output_l
        ):
            return False

        # Then check for positive stapling signals
        if (
            "ocsp response data:" in output_l
            or "ocsp response:" in output_l
            or "successful (0x0)" in output_l  # OCSP status success indicator
        ):
            return True

        return None

    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

def is_public_ca_name(ca_name: str) -> bool:
    name = (ca_name or "").lower()
    return any(keyword in name for keyword in PUBLIC_CA_KEYWORDS)
#endregion

#region Classify CA
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Classify_CA
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
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
        if owner_of(website) and owner_of(website) in ca_name_lower:
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
        if ca_soa and w_soa and ca_soa == w_soa:
            return "third"
 
        # 7. ca_url doesn't mention the website's registered domain at all.
        if w_tld and w_tld not in ca_url.lower():
            return "third"
        
    # NEW — catches cases where ca_url extraction failed but the CA name
    # still identifies the domain's own parent company (e.g. bing.com issued
    # by "Microsoft Corporation", icloud.com issued by "Apple Inc.").
    owner = owner_of(website)
    if owner and owner in ca_name_lower:
        return "private"

    return "unknown"
 
#endregion

#region Measure CA
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Measure CA
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#

def measure_ca(website: str) -> CAResult:
    result = CAResult(website=website)
 
    # Short-circuit for CDN/DNS infrastructure domains that don't serve
    # a real HTTPS endpoint of their own (e.g. akadns.net, cloudfront.net).
    if is_infrastructure_domain(website):
        result.ca_name = "infrastructure"
        result.ca_type = "infrastructure"
        result.https_enabled = False
        return result
 
    ssl_info = get_ssl_info(website)
 
    if not ssl_info.get("ca_name"):
        ssl_info = get_ssl_info(f"www.{website}")
 
    result.ca_name = ssl_info.get("ca_name") or "unknown"
    result.ca_url = ssl_info.get("ca_url") or ""
    result.ssl_or_tls = ssl_info.get("tls_or_ssl") or "unknown"
 
    # Keep the real tri-state result (True / False / None) instead of
    # coercing None into a falsy bool.
    result.ocsp_stapling = ssl_info.get("ocsp_stapled")
 
    result.https_enabled = bool(ssl_info.get("tls_or_ssl"))
 
    san_tlds = ssl_info.get("san_tlds", [])
    result.ca_type = classify_ca(result.ca_url or "", website, san_tlds, result.ca_name)
 
    # Critical dependency: third-party CA AND stapling CONFIRMED absent.
    # (ocsp_stapling is None -> undetermined -> not a confirmed critical dependency)
    result.critical_dependency = (
        result.ca_type == "third" and result.ocsp_stapling is False
    )
 
    if result.ca_type == "unknown":
        print(
            f"""
    UNKNOWN DOMAIN
    --------------
    Website: {website}
    CA Name: {result.ca_name}
    CA URL: {result.ca_url}
    SANs: {san_tlds}
    OCSP Stapled: {result.ocsp_stapling}
    """
        )
 
    return result
#endregion

#region Main
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Main
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
def main():
    input_path  = "src/Source_Data/top_domains/top-1000-domains.csv"
    output_path = "src/Source_Data/ca_results/ca_results_1000.csv"
 
    rows = []
 
    with open(input_path, "r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
 
        for row in reader:
            domain_name = row["domain"].strip()
 
            ca_result = measure_ca(domain_name)
 
            print(
                f"Domain:  {domain_name}\n"
                f"CA Name: {ca_result.ca_name}\n"
                f"Type:    {ca_result.ca_type}\n"
                f"Stapled: {ca_result.ocsp_stapling}"
            )
            rows.append({
                "domain":       domain_name,
                "CA Name":      ca_result.ca_name,
                "type":         ca_result.ca_type,
                "Stapled":      str(ca_result.ocsp_stapling) if ca_result.ocsp_stapling is not None else "Undetermined",
                "TLS":          ca_result.ssl_or_tls,
                "HTTPS Enabled": ca_result.https_enabled,
            })
            
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "CA Name", "type", "Stapled", "TLS", "HTTPS Enabled"])
        writer.writeheader()
        writer.writerows(rows)

    return output_path
#endregion

def extract_provider_domains(input_path, output_path):
    """
    Reads a results CSV and returns a new CSV containing 
    the unique CA provider names found across all domains.
    """
    df = pd.read_csv(input_path)

    # Use a set for efficient deduplication
    ca_set = set()

    # Check if the column exists (case-sensitive check)
    column_to_use = 'CA Name' 
    if column_to_use not in df.columns:
        print(f"❌ Error: Column '{column_to_use}' not found.")
        print(f"Available columns are: {list(df.columns)}")
        return

    for index, row in df.iterrows():
        ca = row[column_to_use]
        if pd.notna(ca):
            ca_stripped = str(ca).strip() # Remove whitespace
            if ca_stripped:               # Skip empty strings
                ca_set.add(ca_stripped)

    # Convert to sorted DataFrame for clean output
    # Changed column name to 'ca_provider' to match the context
    provider_df = pd.DataFrame({'ca_provider': sorted(ca_set)})

    # Save the file
    provider_df.to_csv(output_path, index=False)

    print(f"✅ Extraction Complete:")
    print(f"Total domains analyzed: {len(df)}")
    print(f"Unique CA providers found: {len(provider_df)}")
    print(f"Saved to: {output_path}")


#region Starter
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Starter
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
if __name__ == "__main__":
    #main()
    extract_provider_domains("src/Source_Data/ca_results/ca_results_100000.csv", 
                               "src/Source_Data/ca_results/only_ca_providers.csv")

#endregion