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
import re
import csv
import ssl
import time
import json
import socket
import urllib.request
import urllib.parse
import numpy as np
import dns.resolver
import pandas as pa
from typing import Optional, Any
try:
    from . import PriorityDictionary as pd
except ImportError:
    import PriorityDictionary as pd
from PriorityDictionary import classify_by_soa
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Data structures
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

# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def dig_ns(domain: str) -> list[str]:
    """Return list of nameserver hostnames for domain."""
    try:
        answers = dns.resolver.resolve(domain, "NS")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception as e:
        raise RuntimeError(f"NS lookup failed for {domain}: {e}")
    
def get_auth_ns_set(domain: str) -> frozenset[str]:
    """Return the set of authoritative NS TLDs for a domain."""
    try:
        answers = dns.resolver.resolve(domain, "NS")
        return frozenset(get_tld(str(r.target).rstrip(".")) for r in answers)
    except Exception:
        return frozenset()
    
def get_tld(hostname: str) -> str:
    """
    Return the registered domain (eTLD+1) as a rough TLD proxy.
    e.g. 'ns1.example.com' → 'example.com'
         'ns1.cloudflare.com' → 'cloudflare.com'
    Falls back to the last two labels if tldextract is unavailable.
    """
    try:
        # Use tldextract to get the public suffix / registered domain.
        # Passing cache_dir=None avoids creating a cache file and prevents
        # permission errors in environments where the package install path is read-only.
        import tldextract
        ext = tldextract.TLDExtract(cache_dir=None)(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return hostname
    except ImportError:
        parts = hostname.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

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
    
def regular_expression_nameserver(retrieved_SOA: str) -> str:
    '''we get the nameserver domain based on the SOA expression we obtain from the get_soa function, 
    so that we can trail the information and match elements later on. '''
    if get_soa(retrieved_SOA):
        # we inherit form the priority dictionary
        nameserver = pd.extract_provider(retrieved_SOA)
        return nameserver
    return None
    
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
# Concentration: fraction of Alexa/common domains sharing this nameserver
# expressed as a percentage (0–100).  Without a real dataset we approximate
# by querying how many of a sample of the Alexa top-1000 share the same
# nameserver TLD.  In production, replace this with a precomputed lookup.
# ---------------------------------------------------------------------------

# Simple in-process cache so we don't re-query for the same NS repeatedly.
_concentration_cache: dict[str, float] = {}

# A small representative sample – replace with a full dataset in production.
SAMPLE_DOMAINS: list[str] = []

def concentration(ns: str) -> float:
    """
    Return an estimated concentration score (0-100) for a nameserver.
    Score = percentage of sample domains whose NS TLD matches ns's TLD.
    """
    ns_tld = get_tld(ns)
    if ns_tld in _concentration_cache:
        return _concentration_cache[ns_tld]

    matches = 0
    total = len(SAMPLE_DOMAINS)
    for sample in SAMPLE_DOMAINS:
        try:
            sample_ns_list = dig_ns(sample)
            if any(get_tld(s) == ns_tld for s in sample_ns_list):
                matches += 1
        except Exception:
            pass

    score = (matches / total) * 100 if total else 0.0
    _concentration_cache[ns_tld] = score
    return score

def get_soa(domain: str) -> dict:
    """
    Gets the SOA record for a specific domain.
    Returns a dict with mname and rname, or None if unavailable.
    """
    try:
        answers = dns.resolver.resolve(domain, 'SOA')
        for rdata in answers:
            return {
                "mname": str(rdata.mname).rstrip('.').lower(),
                "rname": str(rdata.rname).rstrip('.').lower(),
            }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

# ---------------------------------------------------------------------------
# Core classification algorithm
# ---------------------------------------------------------------------------

def classify_soa(ns: str, domain: str) -> tuple[str, str]:
    
    domain_tld = get_tld(domain)
    domain_https = is_https(domain)
    domain_san = get_san_tlds(domain) if domain_https else set()
    domain_soa = get_soa(domain)
    
    ns_tld = get_tld(ns)
    ns_soa = get_soa(ns)
    
    # Rule 1: same TLD
    if ns_tld == domain_tld:
        return "private", f"same TLD as domain (domain={domain_soa}, ns={ns_soa})"

    # Rule 2: HTTPS + SAN
    if domain_https and ns_tld in domain_san:
        return "private", f"ns TLD found in domain's TLS SAN (domain={domain_soa}, ns={ns_soa})"
    
    soa_result = classify_by_soa(domain, domain_soa)
    if (soa_result != "no rule matched"):
        return soa_result
    
    # Rule 5: concentration
    conc = concentration(ns)
    if conc >= 50:
        return "third", f"high concentration score ({conc:.1f}%) (domain={domain_soa}, ns={ns_soa})"    

    return "unknown", "no rule matched"

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    input_path  = "src/Source_Data/Cloudflare_Top100_Domains.csv"
    output_path = "src/Source_Data/soa_results.csv"

    results = []

    with open(input_path, "r", newline='') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            domain_name = row["domain"].strip()
            soa = get_soa(domain_name)

            try:
                ns_list = dig_ns(domain_name)
            except RuntimeError as e:
                print(f"Domain:  {domain_name}")
                print(f"  Error:  {e}")
                print("-" * 40)
                results.append({
                    "domain_name": domain_name,
                    "mname":       soa["mname"] if soa else None,
                    "rname":       soa["rname"] if soa else None,
                    "type":        None,
                    "reason":      str(e),
                })
                continue

            for ns in ns_list:
                ns_type, reason = classify_soa(ns, domain_name)

                print(f"Domain:  {domain_name}")
                print(f"  NS:     {ns}")
                print(f"  Mname:  {soa['mname'] if soa else 'N/A'}")
                print(f"  Rname:  {soa['rname'] if soa else 'N/A'}")
                print(f"  Type:   {ns_type}")
                print(f"  Reason: {reason}")
                print("-" * 40)

                results.append({
                    "domain_name": domain_name,
                    "mname":       soa["mname"] if soa else None,
                    "rname":       soa["rname"] if soa else None,
                    "type":        ns_type,
                    "reason":      reason,
                })

    # Write output
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain_name", "mname", "rname", "type", "reason"])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nDone. Results written to {output_path}")

if __name__ == "__main__":
    main()

