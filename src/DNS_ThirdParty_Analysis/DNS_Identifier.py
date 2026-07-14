import re
import csv
import ssl
import time
import socket
import tldextract
import dns.resolver
import pandas as pa
from typing import Optional
from dataclasses import dataclass, field

"""
Nameserver Classifier
Reads a CSV file with columns: rank, domain, description
Classifies each domain's nameservers as 'private', 'third', or 'unknown' based on the algorithm from 
the paper:
    1. If the Top Level Domain (TLD) of the nameserver is equal to the website's domain, we check for private.
    2. Else if HTTPS and TLD is contained in the SAN, we also check for private.
    3. Else if There is a different Start of Authority (SOA) record, We check for third-party.
    4. Else if the concentration is >= 50, we check for third party.
    5. Finally, we check for unknown. 
"""

# ---------------------------------------------------------------------------
# Data structures we are going to use, for the first one we are setting the nameserver to be empty or 'unknown'
# that way we can manipulate the data. The second method indicates the data types of the results.
# ---------------------------------------------------------------------------
@dataclass
class NameserverResult:
    """ Sets the nameserver values into base, unknown values so that we are able to manipulate them as 
        veritication continues. """
    ns: str
    ns_type: str = "unknown"
    reason: str = ""
@dataclass
class DomainResult:
    """ This are the parameters of how it would appear un the csv file after factoring all of the results 
        and checking for all of the websites. """
    domain: str
    description: str
    nameservers: list[NameserverResult] = field(default_factory=list)
    error: Optional[str] = None
    dependency: str = "" 

# --------------------------------------------------------------------------------------------
# Helper Functions that would help us develop the overall part of the algorithm (DNS Helpers).
# --------------------------------------------------------------------------------------------

def get_ns(domain: str) -> list[str]:
    """
    Gets the nameservers for a specific domain. Uses the dns library installed through a virtual environment that would 
    help us to internally store it for our specific usage. 
    """
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [str(rdata).rstrip('.').lower() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return []
    except dns.resolver.NoNameservers:  
        return []

def clean_provider(value: str) -> str:
    '''
    This is a method with the objective of cleaning the provider name: For example, if the provider result is 
    awsdns-32, it would use the regular expressions library to strip and only get the aws, which is the provider 
    name we need of the dns.
    '''

    # Checks for possible empty values in domains/nameserver data. 
    if pa.isna(value):
        return value
    
    value = str(value).strip().lower()
    value = value.rstrip('.')
    
    # Remove TLD suffixes (.com, .net, .org, etc.)
    value = re.sub(r'\.(com|net|org|info|co\.uk)$', '', value)
    
    # Remove trailing hyphens and numbers (e.g. 'awsdns-05' → 'awsdns')
    value = re.sub(r'[-_]\d+$', '', value)

    # Remove common DNS noise words
    value = re.sub(r'[-_]?(dns|ns)$', '', value)
    
    return value
    
def get_soa(domain: str) -> dict:
    """
    Gets the SOA record for a specific domain.
    Returns a dict with mname and rname, or None if unavailable.
    """
    try:
        # USes DNS resolver library to just get the SOA. 
        answers = dns.resolver.resolve(domain, 'SOA')
        for rdata in answers:
            return {
                "mname": str(rdata.mname).rstrip('.').lower(),
                "rname": str(rdata.rname).rstrip('.').lower(),
            }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return None
    except dns.resolver.NoNameservers: 
        return None
    
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
    
# ---------------------------------------------------------------------------
# HTTPS / TLS helpers
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Provider name extraction
# ---------------------------------------------------------------------------

def extract_provider(nameserver: str) -> str:
    ns = nameserver.rstrip('.').lower()
    parts = ns.split('.')
    
    # If it ends in a standard TLD like .com, .net, .org (e.g., cloudflare.com)
    # parts[-1] = 'com', parts[-2] = 'cloudflare'
    if len(parts) >= 2:
        # Handle common double TLDs if necessary (e.g., co.uk)
        if parts[-1] == 'uk' and parts[-2] == 'co':
            return parts[-3] if len(parts) >= 3 else None
        else:
            raw = parts[-2]

        return clean_provider(raw) if raw else None
        
    return None

# ---------------------------------------------------------------------------
# Dictionary that contains some of the somains that are corporate owned 
# ---------------------------------------------------------------------------

# Maps a nameserver's registered domain → the parent company's registered domains.
# If a website's domain TLD resolves to the same parent, it's private.
CORPORATE_NS_OWNERS: dict[str, set[str]] = {
    "cloudns.net":          {"3gppnetwork.org"},
    "cloudns.uk":           {"3gppnetwork.org"},
    "google.com":           {"gmail.com", "youtube.com"},
    "awsdns-01.com":        {"amazon.com", "amazonaws.com"},
    "awsdns-01.net":        {"amazon.com", "amazonaws.com"},
    "awsdns-01.org":        {"amazon.com", "amazonaws.com"},
    "awsdns-01.co.uk":      {"amazon.com", "amazonaws.com"},
    "awsdns-56.net":        {"amazon.com", "amazonaws.com"},
    "awsdns-37.org":        {"amazon.com", "amazonaws.com"},
    "awsdns-16.co.uk":      {"amazon.com", "amazonaws.com"},
    "awsdns-03.com":        {"amazon.com", "amazonaws.com"},
    "awsdns-33.com":        {"amazon.com", "amazonaws.com"},
    "awsdns-52.org":        {"amazon.com", "amazonaws.com"},
    "awsdns-21.co.uk":      {"amazon.com", "amazonaws.com"},
    "googledomains.com":    {"google.com", "alphabet.com"},
    "apple.com":            {"aaplimg.com", "apple.com", "icloud.com"},
    "p-ns.facebook.com":    {"facebook.com", "meta.com", "fb.com", "fbcdn.com", "fbsbx.com", },
    "azure-dns.com":        {"microsoft.com", "outlook.com", "gamepass.com", "microsoftonline.com", "cloud.microsoft"},
    "azure-dns.net":        {"microsoft.com", "outlook.com", "gamepass.com", "microsoftonline.com", "cloud.microsoft"},
    "azure-dns.org":        {"microsoft.com", "outlook.com", "gamepass.com", "microsoftonline.com", "cloud.microsoft"},
    "azure-dns.info":       {"microsoft.com", "outlook.com", "gamepass.com", "microsoftonline.com", "cloud.microsoft"},
}

def get_ns_parent(ns_tld: str) -> set[str]:
    """Return the set of corporate parent domains for a known NS TLD, or empty set."""
    return CORPORATE_NS_OWNERS.get(ns_tld, set())

def _extract_name_token(hostname: str) -> Optional[str]:
    """
    Pull the meaningful brand token out of a hostname.
    'googledomains.com' → 'googledomains'
    'ns1.google.com'    → 'google'
    'azure-dns.org'     → 'azure'   (stops at the hyphen)
    """
    ext = tldextract.TLDExtract(cache_dir=None)(hostname)
    token = ext.domain.lower()  # e.g. 'googledomains', 'google', 'azure'
    if not token or len(token) <= 2:
        return None
    return token

def name_recognition(domain: str, ns: str):
    """ 
    This is a checker for containment, it will extract the name as tokens for comparison.
    it will check if the domain name or token is inside the the Nameserver name, and also it will check 
    if the whole word is inside the domain. 
    """
    domain_token = _extract_name_token(domain)
    ns_token     = _extract_name_token(ns)

    if not domain_token or not ns_token:
        return False

    # Exact match — same token on both sides (e.g. azure / azure)
    if domain_token == ns_token:
        return True

    def whole_word(needle: str, haystack: str) -> bool:
        pattern = rf'(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])'
        return bool(re.search(pattern, haystack))

    if domain_token in ns_token:
        return True
    # Direction A: domain token as whole word inside NS hostname
    # 'azure' inside 'ns3-39.azure-dns.org' → True
    if whole_word(domain_token, ns):
        return True

    # Direction B: NS token as substring inside domain token
    # 'google' inside 'googleapis' → True  (substring, not whole-word)
    if ns_token in domain_token:
        return True

    # Direction C: NS token as whole word inside full domain hostname
    # 'google' inside 'google-domains.com' → True
    if whole_word(ns_token, domain):
        return True
    

    return False

# ---------------------------------------------------------------------------
# Concentration score
# ---------------------------------------------------------------------------

# Simple in-process cache so the same NS TLD is not re-queried.
_concentration_cache: dict[str, float] = {}
 
# Replace with a full dataset in production.
SAMPLE_DOMAINS: list[str] = []
 
def concentration(ns: str) -> float:
    """
    Return an estimated concentration score (0–100) for a nameserver.
    Score = percentage of SAMPLE_DOMAINS whose NS TLD matches this NS's TLD.
    """
    ns_tld = get_tld(ns)
    if ns_tld in _concentration_cache:
        return _concentration_cache[ns_tld]
 
    total = len(SAMPLE_DOMAINS)
    if total == 0:
        return 0.0
 
    matches = sum(
        1
        for sample in SAMPLE_DOMAINS
        if any(get_tld(s) == ns_tld for s in get_ns(sample))
    )

    score = (matches / total) * 100
    _concentration_cache[ns_tld] = score
    return score

# ---------------------------------------------------------------------------
# SOA-based classification
# ---------------------------------------------------------------------------

def classify_by_soa(domain: str, soa: Optional[dict], ns: str = "") -> tuple[str, str]:
    """
    Classify a domain as private or third-party using SOA mname and rname.
    """
    if soa is None:
        return "unknown", "no SOA record"

    domain_tld = get_tld(domain)
    mname_tld  = get_tld(soa["mname"])
    rname_tld  = get_tld(soa["rname"])
    ns_tld     = get_tld(ns) if ns else None
    
    # Both point to the same owner — definitely private
    if mname_tld == domain_tld and rname_tld == domain_tld:
        return "private", f"SOA mname and rname both match domain"
    
    
    if ns_tld and mname_tld == ns_tld:
        return "unknown", f"SOA mname matches NS provider ({mname_tld}); no independent ownership signal"

    # mname is third party — strongest signal
    if mname_tld != domain_tld:
        provider = extract_provider(soa["mname"])
        return "third", f"SOA mname points to third party: {provider}"
    
    if rname_tld != domain_tld:
        provider = extract_provider(soa["rname"])
        return "third", f"SOA rname points to: {provider}"
    
    # was: return "no rule matched"  ← only one value, crashes on unpack
    return "unknown", "SOA present but no rule matched"

def extract_provider_from_reason(reason: str, nameserver: str = "", domain: str = "") -> Optional[str]:
    # "SOA Mnama/rname points to third party: google"
    if "points to third party:" in reason:
        match = re.search(r':\s*(\S+)$', reason)
        return match.group(1) if match else None
    
    # Checker for subsidiary (From the dictionary).
    if "known subsidiary of" in reason:
        match = re.search(r'known subsidiary of\s+(\S+)$', reason)
        return match.group(1) if match else None
    
    # "NS TLD matches domain TLD"
    if "NS TLD matches domain TLD" in reason:
        return get_tld(domain)
    
    # If Domain name is contained in the nameserver.
    if "contained in the nameserver" in reason:
        return get_tld(nameserver)
    
    return None

def dependency_classification(nameservers: list[NameserverResult]) -> str:
    """
    Determines whether a domain has a critical single-provider DNS dependency.
    Checks unique providers across already-classified nameservers rather than
    re-querying DNS.
    """
    # Extract the provider from each NS result's reason
    providers = set()
    for ns_result in nameservers:
        raw_provider = extract_provider(ns_result.ns)
        if raw_provider:
            providers.add(raw_provider)

    if len(providers) > 1:
        return "No critical dependency"
    else:
        return "Critical dependency"
# ---------------------------------------------------------------------------
# Per-nameserver classification  (the 5-step algorithm)
# ---------------------------------------------------------------------------

def classify_name_server(ns: str, domain: str, domain_tld: str, soa: Optional[dict], https_enabled: bool,
    san_tlds: set[str],) -> NameserverResult:
    """
    Classify a single nameserver for the given domain using the 5-step algorithm. All expensive lookups (SOA, HTTPS, SAN) 
    are pre-computed and passed in so they are not repeated for each NS of the same domain.
    """
    result = NameserverResult(ns=ns)
    ns_tld = get_tld(ns)

    # Step 1 — NS TLD matches the domain itself
    if ns_tld == domain_tld:
        result.ns_type = "private"
        result.reason  = "NS TLD matches domain TLD"
        return result
    
    # Step 1.5a - Domain name is contained in the nameserver.
    if name_recognition(domain, ns):
        result.ns_type = "private"
        result.reason = f'Domanin name is contained in the nameserver, signaling ownership'
        return result
    
    # Step 1.5b — NS belongs to a known corporate subsidiary of the domain owner
    parent_domains = get_ns_parent(ns_tld)
    if domain_tld in parent_domains:
        result.ns_type = "private"
        result.reason  = f"NS TLD {ns_tld} is a known subsidiary of {domain_tld}"
        return result
    
    # Step 2 — Domain uses HTTPS and NS TLD appears in its SAN
    if https_enabled and ns_tld in san_tlds: 
        result.ns_type = "private"
        result.reason = "Domain has HTTPS and NS TLD is contained in SAN"
        return result
    
    # Step 2.5?? - Domain before the tld is contained in the nameserver
    if domain in ns:
        result.ns_type = "private"
        result.reason = " Hosts the same name."
        return result
    
    # Step 3 — SOA record indicates a different owner
    soa_type, soa_reason = classify_by_soa(domain, soa)
    if soa_type != "unknown":
        result.ns_type = soa_type
        result.reason  = soa_reason
        return result
    
    # Step 4 — NS is widely shared (high concentration → third-party provider)
    if concentration(ns) >= 50:
        result.ns_type = "third"
        result.reason  = f"NS concentration >= 50 for {get_tld(ns)}"
        return result
 
    # Step 5 — Could not determine
    result.ns_type = "unknown"
    result.reason  = "no rule matched"
    return result

# ---------------------------------------------------------------------------
# Per-Domain classification  (the 5-step algorithm)
# ---------------------------------------------------------------------------

def classify_domain(domain: str, description: str = "") -> DomainResult:
    """
    Run all lookups for a domain once, then classify each of its nameservers.
    Returns a DomainResult with one NameserverResult per NS.
    """
    result = DomainResult(domain=domain, description=description)
    # We get the tld of the domain.
    domain_tld = get_tld(domain)
    
    # Here we get the nameservers based on the domain
    name_servers = get_ns(domain)
    if not name_servers:
        result.error = "no nameservers found"
        return result
 
    # Expensive lookups happen once per domain, not once per NS
    soa          = get_soa(domain)
    https_active = is_https(domain)
    san_tlds     = get_san_tlds(domain) if https_active else set()
 
    # Here we make the specific lookup of the individual nameservers based on the domain. 
    for ns in name_servers:
        ns_result = classify_name_server(ns=ns, domain=domain, domain_tld=domain_tld, soa=soa, https_enabled=https_active,
                                         san_tlds=san_tlds,)
        result.nameservers.append(ns_result)
 
    # Checks for dependency classification.
    result.dependency = dependency_classification(result.nameservers)

    return result

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

 
def main():
    input_path  = "src/Source_Data/Domain_Robustness_Results.csv"
    output_path = "src/Source_Data/DNS_Identifier_Results.csv"

    rows = []

    input_df = pa.read_csv(input_path)

    for _, row in input_df.iterrows():
        domain_name = str(row["domain"]).strip()
        description = str(row.get("description", "")).strip()

        domain_result = classify_domain(domain_name, description)

        if domain_result.error:
            print(f"[{domain_name}] ERROR: {domain_result.error}")
            continue

        for ns_result in domain_result.nameservers:
            print(
                f"Domain:  {domain_name}\n"
                f"  NS:    {ns_result.ns}\n"
                f"  Type:  {ns_result.ns_type}\n"
                f"  Why:   {ns_result.reason}\n"
                f"{'-' * 40}"
            )
            rows.append({
                "domain":      domain_name,
                "nameserver":  ns_result.ns,
                "type":        ns_result.ns_type,
                "reason":      ns_result.reason,
                "provider":    extract_provider_from_reason(ns_result.reason, ns_result.ns, domain_name),
                "dependency":  domain_result.dependency,
            })

    output_df = pa.DataFrame(rows, columns=["domain", "nameserver", "type", "reason", "provider", "dependency"])

    # Readability formatting
    output_df = output_df.sort_values(by=["domain", "type"])
    output_df = output_df.fillna("N/A")
    output_df.columns = [col.upper() for col in output_df.columns]

    output_df.to_csv(output_path, index=False)

    # Console summary
    type_col = "TYPE"
    print(f"\n{'='*40}")
    print(f"Results written to {output_path}")
    print(f"Total nameservers classified: {len(output_df)}")
    print(f"Unique domains processed:     {output_df['DOMAIN'].nunique()}")
    print(f"\nClassification breakdown:")
    print(output_df[type_col].value_counts().to_string())
    print(f"\nDependency breakdown:")
    print(output_df.drop_duplicates(subset="DOMAIN")["DEPENDENCY"].value_counts().to_string())
 
if __name__ == "__main__":
    main()