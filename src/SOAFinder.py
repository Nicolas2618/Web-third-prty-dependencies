"""
Nameserver Classifier
Reads a CSV with columns: domain, description
Classifies each domain's nameservers as 'private', 'third', or 'unknown'
using the algorithm:
  1. Same TLD as domain → private
  2. HTTPS cert SAN contains ns TLD → private
  3. Different SOA → third
  4. Concentration >= 50 → third
  5. Otherwise → unknown
"""

import csv
import sys
import ssl
import socket
import dns.resolver
import dns.query
import dns.zone
import dns.name
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class NameserverResult:
    ns: str
    ns_type: str = "unknown"
    reason: str = ""


@dataclass
class DomainResult:
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


def get_tld(hostname: str) -> str:
    """
    Return the registered domain (eTLD+1) as a rough TLD proxy.
    e.g. 'ns1.example.com' → 'example.com'
         'ns1.cloudflare.com' → 'cloudflare.com'
    Falls back to the last two labels if tldextract is unavailable.
    """
    try:
        import tldextract
        ext = tldextract.extract(hostname)
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


def is_https(domain: str) -> bool:
    """Return True if the domain responds on HTTPS (port 443)."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=5),
            server_hostname=domain,
        ):
            return True
    except Exception:
        return False


def get_san_tlds(domain: str) -> set[str]:
    """
    Return the set of registered domains found in the TLS certificate's
    Subject Alternative Names for `domain`.
    """
    sans: set[str] = set()
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=5),
            server_hostname=domain,
        ) as ssock:
            cert = ssock.getpeercert()
            for kind, value in cert.get("subjectAltName", []):
                if kind == "DNS":
                    clean = value.lstrip("*.")
                    sans.add(get_tld(clean))
    except Exception:
        pass
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
SAMPLE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "amazon.com", "wikipedia.org", "instagram.com", "linkedin.com",
    "reddit.com", "netflix.com", "microsoft.com", "apple.com",
    "github.com", "stackoverflow.com", "wordpress.com",
]


def concentration(ns: str) -> float:
    """
    Return an estimated concentration score (0–100) for a nameserver.
    Score = percentage of sample domains whose NS TLD matches ns's TLD.
    """
    ns_tld = get_tld(ns)
    if ns_tld in _concentration_cache:
        return _concentration_cache[ns_tld]

    matches = 0
    for sample in SAMPLE_DOMAINS:
        try:
            sample_ns_list = dig_ns(sample)
            if any(get_tld(s) == ns_tld for s in sample_ns_list):
                matches += 1
        except Exception:
            pass

    score = (matches / len(SAMPLE_DOMAINS)) * 100
    _concentration_cache[ns_tld] = score
    return score


# ---------------------------------------------------------------------------
# Core classification algorithm
# ---------------------------------------------------------------------------

def classify_ns(ns: str, domain: str, domain_tld: str,
                domain_https: bool, domain_san: set[str],
                domain_soa: Optional[str]) -> tuple[str, str]:
    """
    Apply the classification algorithm to a single nameserver.
    Returns (type, reason).
    """
    ns_tld = get_tld(ns)

    # Rule 1: same TLD
    if ns_tld == domain_tld:
        return "private", "same TLD as domain"

    # Rule 2: HTTPS + SAN
    if domain_https and ns_tld in domain_san:
        return "private", "ns TLD found in domain's TLS SAN"

    # Rule 3: different SOA
    ns_soa = get_soa(ns)
    if ns_soa is not None and domain_soa is not None and ns_soa != domain_soa:
        return "third", f"different SOA (domain={domain_soa}, ns={ns_soa})"

    # Rule 4: concentration
    conc = concentration(ns)
    if conc >= 50:
        return "third", f"high concentration score ({conc:.1f}%)"

    return "unknown", "no rule matched"


def classify_domain(domain: str, description: str) -> DomainResult:
    result = DomainResult(domain=domain, description=description)

    # --- gather domain-level data once ---
    try:
        ns_list = dig_ns(domain)
    except RuntimeError as e:
        result.error = str(e)
        return result

    domain_tld = get_tld(domain)
    domain_https = is_https(domain)
    domain_san = get_san_tlds(domain) if domain_https else set()
    domain_soa = get_soa(domain)

    for ns in ns_list:
        ns_type, reason = classify_ns(
            ns, domain, domain_tld, domain_https, domain_san, domain_soa
        )
        result.nameservers.append(NameserverResult(ns=ns, ns_type=ns_type, reason=reason))

    return result


# ---------------------------------------------------------------------------
# CSV I/O
# ---------------------------------------------------------------------------

def process_csv(input_path: str, output_path: str,
                domain_col: str = "domain",
                desc_col: str = "categories") -> None:
    results: list[DomainResult] = []

    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    total = len(rows)
    for i, row in enumerate(rows, 1):
        domain = row.get(domain_col, "").strip()
        description = row.get(desc_col, "").strip()
        if not domain:
            continue
        print(f"[{i}/{total}] Classifying {domain} …", flush=True)
        results.append(classify_domain(domain, description))

    # Write output
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "description", "nameserver", "type", "reason", "error"])
        for r in results:
            if r.error:
                writer.writerow([r.domain, r.description, "", "", "", r.error])
            elif not r.nameservers:
                writer.writerow([r.domain, r.description, "", "unknown", "no NS records", ""])
            else:
                for ns in r.nameservers:
                    writer.writerow([r.domain, r.description, ns.ns, ns.ns_type, ns.reason, ""])

    print(f"\nDone. Results written to {output_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print("Usage: python ns_classifier.py <input.csv>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = "ns_results.csv"
    process_csv(input_path, output_path)


if __name__ == "__main__":
    main()
