#region Imports
import re
import subprocess
import time
from typing import Optional
import certifi
from OpenSSL import crypto
import ssl
import socket
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
import dns.resolver
import tldextract
#endregion

#region Already Made Helpers
def get_tld(domain: str) -> str:
    """Return the registered domain (eTLD+1) for a hostname."""
    ext = tldextract.TLDExtract(cache_dir=None)(domain)
    return f"{ext.domain}.{ext.suffix}" if ext.domain else ""

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

    return f"{issuer.get("organizationName")} + {issuer.get("commonName")}"

def getCA_URL(CA : str, domain : str):
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
                return desc.access_location.value

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
                cert = ssock.getpeercert(binary_form=False)
                if cert is None:
                    return result

                # SANs
                san_raw = cert.get("subjectAltName", [])
                result["san_tlds"] = list({
                    get_tld(v) for t, v in san_raw if t == "DNS" and v
                })

                # Issuer / CA name
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["ca_name"] = issuer.get("organizationName", "")

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
                    result["ca_url"] = tldextract.extract(
                        re.sub(r"https?://", "", url).split("/")[0]
                    )
                    result["ca_url"] = get_tld(
                        re.sub(r"https?://", "", url).split("/")[0]
                    )
            if "CRL - URI:" in line or "URI:" in line and ".crl" in line.lower():
                url = line.split("URI:")[-1].strip()
                result["crl_urls"].append(url)
    except Exception:
        pass

    return result
#endregion

#region Put it all together
def main_algo(domain : str):
    ca_info = getCA(domain)
    print(ca_info)
    ca_url = getCA_URL(ca_info, domain)
    print(ca_url)
    ca_type = "unknown"
    ca_url_tld = get_tld(ca_url)
    ca_tld = get_tld(domain)
    w_sans = get_san_tlds(domain)
    w_https = is_https(domain)
    if (ca_url_tld == ca_tld):
        ca_type = "private"
        return ca_type
    elif w_https and ca_url_tld in w_sans:
        ca_type = "private"
        return ca_type
    elif get_soa(ca_url) != get_soa(domain):
        ca_type = "third"
        return ca_type
    ca_type = "unknown"
    return ca_type

def classify_ca(ca_url: str, website: str, san_tlds: list[str]) -> str:
    """Classify a CA as 'private' or 'third'. Algorithm 2 from paper."""
    if not ca_url:
        return "unknown"

    ca_tld = get_tld(ca_url)
    w_tld = get_tld(website)

    if ca_tld == w_tld:
        return "private"

    if ca_tld in san_tlds:
        return "private"

    ca_soa = dig_soa(ca_url)
    w_soa = dig_soa(website)
    if ca_soa and w_soa and ca_soa != w_soa:
        return "third"

    return "unknown"



if __name__ == "__main__":
    print(main_algo("google.com"))
#endregion