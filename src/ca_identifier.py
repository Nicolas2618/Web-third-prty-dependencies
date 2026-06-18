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

#region Already Made Helpers
def get_tld(hostname: str) -> str:
    """
    Return the registered domain (eTLD+1). 
    e.g. 'ns1.example.com' → 'example.com' 'ns1.cloudflare.com' → 'cloudflare.com'
    """
    try:
        # Use tldextract to get the public suffix / registered domain. Passing cache_dir=None avoids creating a cache file 
        # and prevents permission errors in environments where the package install path is read-only.
        ext = tldextract.TLDExtract(cache_dir=None)(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return hostname
    except ImportError:
        parts = hostname.rstrip(".").split(".")
        # For this exception it returns the las two parts of the domain and suffix. e.g domain.com 
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

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

def get_soa(hostname: str) -> Optional[str]:
    """
    Return the SOA MNAME (primary nameserver) for the zone that hosts
    `hostname`, or None on failure.
    """
    try:
        answers = dns.resolver.resolve(hostname, "SOA")
        return str(answers[0].mname).rstrip(".")
    except Exception:
        # Walk up the tree: try the domain itself, then parent zones
        parts = hostname.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            try:
                answers = dns.resolver.resolve(candidate, "SOA")
                return str(answers[0].mname).rstrip(".")
            except Exception:
                continue
        return None

def dig_ns(domain: str, timeout: int = 5) -> list[str]:
    """Return nameserver hostnames for *domain* via DNS query."""
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=timeout)
        return [str(r.target).rstrip(".").lower() for r in answers]
    except Exception:
        return []


def dig_soa(domain: str, timeout: int = 5) -> Optional[str]:
    """Return the SOA MNAME (master nameserver) for *domain*."""
    try:
        answers = dns.resolver.resolve(domain, "SOA", lifetime=timeout)
        for r in answers:
            return str(r.mname).rstrip(".").lower()
    except Exception:
        return None


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


def classify_ca(ca_url: str, website: str, san_tlds: list[str], ca_name: str = "") -> str:
    """Classify a CA as 'private' or 'third'."""
    if not ca_url and not ca_name:
        return "unknown"

    ca_tld = get_tld(ca_url) if ca_url else ""
    w_tld = get_tld(website)
    website_root = w_tld.lower()
    ca_name_lower = (ca_name or "").lower()

    # Extract company/domain name (e.g. "google" from "google.com")
    domain_parts = website_root.split(".")
    company_name = domain_parts[0] if domain_parts else ""

    # Check if CA name contains domain company name (e.g. "Google Trust Services" for google.com)
    if company_name and company_name in ca_name_lower:
        return "private"

    if website_root and website_root in ca_name_lower:
        return "private"

    if ca_url and website_root and website_root in ca_url.lower():
        return "private"

    if is_public_ca_name(ca_name_lower):
        return "third"

    if ca_url:
        ca_host = ca_url.lower()
        if any(keyword in ca_host for keyword in PUBLIC_CA_KEYWORDS):
            return "third"

    if ca_tld and ca_tld == w_tld:
        return "private"

    if ca_tld in san_tlds:
        return "private"

    if ca_url:
        ca_soa = dig_soa(ca_url)
        w_soa = dig_soa(website)
        if ca_soa and w_soa and ca_soa != w_soa:
            return "third"

        ca_url_lower = ca_url.lower()
        if ca_url_lower and w_tld and w_tld not in ca_url_lower:
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