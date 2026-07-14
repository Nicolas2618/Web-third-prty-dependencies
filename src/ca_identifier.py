#region Imports
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Imports
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
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
import numpy as np
import tldextract
from domains import CORPORATE_FAMILY
import matplotlib.pyplot as plt
import pandas as pa
import circlify
import matplotlib.patches as mpatches
#endregion





#region Data classes
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Data Classes
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
@dataclass
class CAResult:
    website: str
    ca_name: Optional[str] = None
    ca_url: Optional[str] = None
    ca_type: str = "unknown"           # "private" / "third" / "unknown"
    ocsp_stapling: bool = False
    critical_dependency: bool = False  # True if third-party CA AND no OCSP stapling
    ssl_error: Optional[str] = None
    ssl_or_tls: str = "unknown"
#endregion





#region Basic helpers
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Basic Helpers
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
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

INFRASTRUCTURE_KEYWORDS = [
    "cloudfront",
    "akadns",
    "akamai",
    "apple-dns",
    "cdn",
]

def is_infrastructure_domain(domain: str) -> bool:
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
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#CA Helpers
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
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
        "tls_or_ssl": None,
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
                #print(f"Negotiated Protocol Version: {ssock.version()}")
                result["tls_or_ssl"] = f"{ssock.version()}"
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

                # Prefer Organization Name (O), then Common Name (CN), then Organizational Unit (OU).
                ca_name = None
                for attribute in issuer:
                    if attribute.oid == NameOID.ORGANIZATION_NAME and attribute.value:
                        ca_name = attribute.value
                        break
                if not ca_name:
                    for attribute in issuer:
                        if attribute.oid == NameOID.COMMON_NAME and attribute.value:
                            ca_name = attribute.value
                            break
                if not ca_name:
                    for attribute in issuer:
                        if attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME and attribute.value:
                            ca_name = attribute.value
                            break

                # Fallback: join any available issuer attribute values (previous behaviour).
                if not ca_name:
                    parts = [attr.value for attr in issuer if getattr(attr, "value", None)]
                    ca_name = " | ".join(parts)

                result["ca_name"] = ca_name

                # Try to resolve the CA issuer location from the certificate's AIA extension.
                if not result["ca_url"]:
                    result["ca_url"] = getCA_URL(domain)

                # OCSP / CRL from caIssuers / OCSP extension (not always in stdlib cert dict)
                # Use openssl CLI for richer extension data
    except Exception as e:
        print(f"[SSL ERROR] {domain}: {type(e).__name__}: {e}. Except 1")

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
    except Exception as e:
        pass

    return result

def check_ocsp_stapling(hostname, port=443):
    """
    Checks if a website supports OCSP Stapling using OpenSSL.
    """
    command = f"echo | openssl s_client -connect {hostname}:{port} -status"
    
    try:
        # Run the command and capture the output
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        output = result.stdout + result.stderr
        
        # Look for the OCSP response block
        if "OCSP response: no response sent" in output:
            print(f"[{hostname}] OCSP Stapling is NOT enabled.")
            return False
        elif "OCSP Response Data:" in output:
            print(f"[{hostname}] OCSP Stapling IS enabled!")
            
            # (Optional) Extract the validation status
            match = re.search(r"Cert Status: (.+)", output)
            if match:
                print(f"Certificate Status: {match.group(1)}")
            return True
        else:
            #print(f"[{hostname}] Could not determine OCSP status (Handshake may have failed).")
            return None
            
    except subprocess.TimeoutExpired:
        print("Command timed out.")
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
        if ca_soa and w_soa and ca_soa == w_soa:
            return "third"
 
        # 7. ca_url doesn't mention the website's registered domain at all.
        if w_tld and w_tld not in ca_url.lower():
            return "third"
 
    return "unknown"
#endregion





#region Measure CA
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Measure CA
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
def measure_ca(website: str) -> CAResult:
    result = CAResult(website=website)
    ssl_info = get_ssl_info(website)

    if not ssl_info.get("ca_name"):
        ssl_info = get_ssl_info(f"www.{website}")

    result.ca_name = ssl_info.get("ca_name", "")
    if result.ca_name == None:
        result.ca_name = "unknown"
    result.ca_url = ssl_info.get("ca_url", "")
    result.ssl_or_tls = ssl_info.get("tls_or_ssl", "")
    if result.ssl_or_tls == None:
        result.ssl_or_tls = "unknown"
    result.ocsp_stapling = check_ocsp_stapling(website)

    san_tlds = ssl_info.get("san_tlds", [])
    result.ca_type = classify_ca(result.ca_url or "", website, san_tlds, result.ca_name)

    # Critical dependency: third-party CA AND no OCSP stapling
    result.critical_dependency = (result.ca_type == "third") and not result.ocsp_stapling

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
    input_path  = "src/Source_Data/top-100000-domains.csv"
    output_path = "src/Source_Data/ca_results_100000.csv"
 
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
                "domain":      domain_name,
                "CA Name":     ca_result.ca_name,
                "type":        ca_result.ca_type,
                "Stapled": ca_result.ocsp_stapling,
                "SSL or TLS": ca_result.ssl_or_tls
            })
            
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "CA Name", "type", "Stapled", "SSL or TLS"])
        writer.writeheader()
        writer.writerows(rows)

    return output_path
#endregion





#region Data Visualization
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Data Visualization
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
def data_vis(input_file):
    df = pa.read_csv(input_file)

    # # ----- Type pie -----
    # plt.figure(figsize=(8, 8))

    # df["type"].value_counts().plot.pie(
    #     autopct="%1.1f%%",
    #     ylabel="",
    #     fontsize = 22
    # )

    # plt.title("CA Type Distribution", fontsize=26)
    # plt.show()

    # # ----- CA Name pie -----
    # ca_counts = (
    # df["CA Name"]
    # .fillna("Unknown")
    # .replace("", "Unknown")
    # .value_counts())

    # top_n = 100

    # if len(ca_counts) > top_n:
    #     other = ca_counts.iloc[top_n:].sum()
    #     ca_counts = pa.concat([
    #         ca_counts.iloc[:top_n],
    #         pa.Series({"Other": other})
    #     ])

    # plt.figure(figsize=(10, 10))

    # ca_counts.plot.pie(
    #     autopct="%1.1f%%",
    #     ylabel=""
    # )

    # plt.title("Certificate Authority Distribution")
    
    # #Making a bar chart showing the exact counts of types
    # plt.figure(figsize=(10, 6))
    # df["type"].value_counts().plot(kind="bar")
    # plt.title("CA Type Distribution")
    # plt.xlabel("Type")
    # plt.ylabel("Count")

    # #Pie chart for TLS/SSL
    # plt.figure(figsize=(8, 8))
    # df["SSL or TLS"].value_counts().plot.pie(
    #     autopct="%1.1f%%",
    #     ylabel=""
    # )
    # plt.title("TLS/SSL Distribution")

    # --- Proportional Area / Bubble Chart for CA Name ---
    ca_counts = (
        df["CA Name"]
        .fillna("Unknown")
        .replace("", "Unknown")
        .value_counts()
    )

    # Split into top 5 and "Other"
    top5 = ca_counts.head(5)
    other_count = ca_counts.iloc[5:].sum()

    # Combine into final series
    if other_count > 0:
        import pandas as pd
        ca_counts = pd.concat([top5, pd.Series({"Other": other_count})])
    else:
        ca_counts = top5

    labels = ca_counts.index.tolist()
    values = ca_counts.values.tolist()

    # circlify expects values sorted descending
    sorted_pairs = sorted(zip(values, labels), reverse=True)
    sorted_values, sorted_labels = zip(*sorted_pairs)

    # Compute packed circle layout
    circles = circlify.circlify(
        list(sorted_values),
        show_enclosure=False,
        target_enclosure=circlify.Circle(x=0, y=0, r=1)  # adjust as needed
    )

    # Reverse so largest circle matches first label
    circles = circles[::-1]

    fig, ax = plt.subplots(figsize=(12, 12))
    ax.set_aspect("equal")
    ax.axis("off")
    fig.patch.set_facecolor("#F5F6FA")
    ax.set_facecolor("#F5F6FA")

    DARK_BLUE = "#070BE7"
    TEAL      = "#5FB6E9"
    WHITE     = "#FFFFFF"

    max_val = sorted_values[0]

    for circle, label, value in zip(circles, sorted_labels, sorted_values):
        x, y, r = circle.x, circle.y, circle.r
        color = DARK_BLUE if value == max_val else TEAL

        patch = plt.Circle((x, y), r, color=color, alpha=0.92, zorder=2)
        ax.add_patch(patch)

        # Label sizing based on circle radius
        fontsize = 24

        # Only label if circle is large enough
        if r > 0.04:
            # Truncate long names
            short_label = label if len(label) <= 18 else label[:16] + "…"
            ax.text(
                x, y + r * 0.12,
                short_label,
                ha="center", va="center",
                fontsize=fontsize,
                color=WHITE,
                fontweight="bold",
                zorder=3,
                wrap=False
            )
            ax.text(
                x, y - r * 0.28,
                f"{value:,}",
                ha="center", va="center",
                fontsize=fontsize * 0.85,
                color=WHITE,
                alpha=0.85,
                zorder=3
            )

    # Fit axes tightly around packed circles
    lim = max(abs(c.x) + c.r for c in circles) * 1.05
    ax.set_xlim(-lim, lim)
    ax.set_ylim(-lim, lim)

    plt.title(
        "Certificate Authority Distribution",
        fontsize=26,
        fontweight="bold",
        pad=16,
        color="#060E77"
    )
    plt.tight_layout()

    plt.show()
#endregion





#region Starter
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
#Starter
#--------------------------------------------------------------------------------------------------------------------------------------------------------------#
if __name__ == "__main__":
    #full thing
    # output = main()
    # data_vis(output)
    
    # quick vis
    data_vis("src/Source_Data/ca_results_100000.csv")

#endregion

