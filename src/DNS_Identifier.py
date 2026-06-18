import re
import csv
import ssl
import time
import json
import socket
import urllib.request
import tldextract
import urllib.parse
import numpy as np
import dns.resolver
import pandas as pa
from typing import Optional, Any
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
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    
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
    """Extract provider name from a nameserver string. e.g google.com would return google as their nameserver. """
    # Remove trailing dot
    ns = nameserver.rstrip('.')
    # Splits the nameserver by parts, most of the time the nameserver is located in the second part of the dns. 
    nameserver_parts = ns.split('.')

    # Examples: 'awsdns-43' -> 'awsdns', 'apple' -> 'apple', 'google' -> 'google'
    for part in nameserver_parts:
        match = re.search(r'([a-z]+)', part)
        # if else statements to get the appropriate nameserver, in some scenarios it is not at the second position, so it 
        # accounts for that. 
        if match:
            token = match.group(1)
            if token == "ns" or len(token) <= 2 or token == "dns":
                continue
            return token
    # Returns nothing in case there is no nameserver. 
    return None

# ---------------------------------------------------------------------------
# Dictionary that contains some of the somains that are corporate owned 
# ---------------------------------------------------------------------------

# Maps a nameserver's registered domain → the parent company's registered domains.
# If a website's domain TLD resolves to the same parent, it's private.
CORPORATE_NS_OWNERS: dict[str, set[str]] = {
    "azure-dns.com":    {"microsoft.com"},
    "azure-dns.net":    {"microsoft.com"},
    "azure-dns.org":    {"microsoft.com"},
    "azure-dns.info":   {"microsoft.com"},
    "awsdns-01.com":    {"amazon.com", "amazonaws.com"},
    "awsdns-01.net":    {"amazon.com", "amazonaws.com"},
    "awsdns-01.org":    {"amazon.com", "amazonaws.com"},
    "awsdns-01.co.uk":  {"amazon.com", "amazonaws.com"},
    "awsdns-56.net":    {"amazon.com", "amazonaws.com"},
    "awsdns-37.org":    {"amazon.com", "amazonaws.com"},
    "googledomains.com":{"google.com", "alphabet.com"},
    "p-ns.facebook.com":{"facebook.com", "meta.com"},
    "cloudflare.com":   set(),  # pure third-party CDN, never private
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

    # Direction A: domain token inside the NS hostname
    # 'azure' inside 'ns3-39.azure-dns.org' → True
    if whole_word(domain_token, ns):
        return True

    # Direction B: NS token inside the domain hostname
    # 'google' inside 'googledomains.com' → True
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

def classify_by_soa(domain: str, soa: dict) -> tuple[str, str]:
    """
    Classify a domain as private or third-party using SOA mname and rname.
    """
    if soa is None:
        return "unknown", "no SOA record"

    domain_tld = get_tld(domain)
    mname_tld  = get_tld(soa["mname"])
    rname_tld  = get_tld(soa["rname"])
    
    # Both point to the same owner — definitely private
    if mname_tld == domain_tld and rname_tld == domain_tld:
        return "private", f"SOA mname and rname both match domain"

    # mname is third party — strongest signal
    if mname_tld != domain_tld:
        provider = extract_provider(soa["mname"])
        return "third", f"SOA mname points to third party: {provider}"
    
    if rname_tld != domain_tld:
        provider = extract_provider(soa["rname"])
        return "third", f"SOA rname points to: {provider}"
    
    return "no rule matched"

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
        result.reason = f'DOmanin name is contained in the nameserver, signaling ownership'
        return result
    
    # Step 1.5b — NS belongs to a known corporate subsidiary of the domain owner
    parent_domains = get_ns_parent(ns_tld)
    if domain_tld in parent_domains:
        result.ns_type = "private"
        result.reason  = f"NS TLD {ns_tld} is a known subsidiary of {domain_tld}"
        return result
    
    # Step 2 — Domain uses HTTPS and NS TLD appears in its SAN
    if https_enabled and domain_tld in san_tlds:
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
 
    return result

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    input_path  = "src/Source_Data/Cloudflare_Top100_Domains.csv"
    output_path = "src/Source_Data/DNS_Identifier_Results.csv"
 
    rows = []
 
    with open(input_path, "r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
 
        for row in reader:
            domain_name = row["domain"].strip()
            description = row.get("description", "").strip()
 
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
                })
 
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "nameserver", "type", "reason"])
        writer.writeheader()
        writer.writerows(rows)
 
    print(f"\nDone. Results written to {output_path}")
 
 
if __name__ == "__main__":
    main()