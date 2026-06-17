"""
Claude's implementation

Not going to uuse in it's entirety just going to reference to see if we can improve our own code


Recreating: "Analyzing Third Party Service Dependencies in Modern Web Services:
Have We Learned from the Mirai-Dyn Incident?"
Kashaf, Sekar, Agarwal — IMC 2020

This script replicates the methodology for measuring DNS, CDN, and CA
third-party dependencies for top websites, and analyzing concentration,
critical dependency, and redundancy.

Requirements:
    pip install dnspython requests tldextract cryptography pyOpenSSL
"""

import dns.resolver
import dns.query
import dns.zone
import tldextract
import subprocess
import ssl
import socket
import json
import csv
import re
import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DNSResult:
    website: str
    nameservers: list[str] = field(default_factory=list)
    ns_types: dict[str, str] = field(default_factory=dict)   # ns -> "private"/"third"/"unknown"
    soa_record: Optional[str] = None
    san_list: list[str] = field(default_factory=list)
    uses_third_party: bool = False
    critical_dependency: bool = False   # True if ALL ns are third-party (no redundancy with private)
    redundant: bool = False             # True if uses >1 distinct provider

@dataclass
class CAResult:
    website: str
    ca_name: Optional[str] = None
    ca_url: Optional[str] = None
    ca_type: str = "unknown"           # "private" / "third" / "unknown"
    ocsp_stapling: bool = False
    critical_dependency: bool = False  # True if third-party CA AND no OCSP stapling

@dataclass
class CDNResult:
    website: str
    cdns: list[str] = field(default_factory=list)
    cdn_types: dict[str, str] = field(default_factory=dict)
    uses_third_party: bool = False
    critical_dependency: bool = False
    redundant: bool = False


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def get_tld(domain: str) -> str:
    """Return the registered domain (eTLD+1) for a hostname."""
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}" if ext.domain else ""


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


# ---------------------------------------------------------------------------
# Third-party classification heuristics (Algorithm 1 & 2 from paper)
# ---------------------------------------------------------------------------

def classify_ns(ns: str, website: str, san_tlds: list[str],
                concentration_map: dict[str, int]) -> str:
    """
    Classify a nameserver as 'private' or 'third' (or 'unknown').
    Implements the paper's combined TLD + SAN + SOA + concentration heuristic.
    """
    ns_tld = get_tld(ns)
    w_tld = get_tld(website)

    # Rule 1: TLD match → private
    if ns_tld and ns_tld == w_tld:
        return "private"

    # Rule 2: NS TLD in website's SAN list → private
    if ns_tld and ns_tld in san_tlds:
        return "private"

    # Rule 3: SOA mismatch → third-party
    ns_soa = dig_soa(ns)
    w_soa = dig_soa(website)
    if ns_soa and w_soa and ns_soa != w_soa:
        return "third"

    # Rule 4: High concentration → likely third-party provider
    count = concentration_map.get(ns_tld, 0)
    if count >= 50:
        return "third"

    return "unknown"


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


def classify_cdn(cname: str, website: str, san_tlds: list[str]) -> str:
    """Classify a CDN CNAME as 'private' or 'third'. Section 3.3 heuristic."""
    if not cname:
        return "unknown"

    cname_tld = get_tld(cname)
    w_tld = get_tld(website)

    if cname_tld == w_tld:
        return "private"
    if cname_tld in san_tlds:
        return "private"

    cname_soa = dig_soa(cname)
    w_soa = dig_soa(website)
    if cname_soa and w_soa and cname_soa != w_soa:
        return "third"

    return "unknown"


# ---------------------------------------------------------------------------
# CNAME-to-CDN map (self-populated subset from paper; extend as needed)
# ---------------------------------------------------------------------------

CDN_CNAME_PATTERNS = {
    "akamai": ["akamaiedge.net", "akamai.net", "akamaitechnologies.com",
               "akamaized.net", "edgesuite.net", "edgekey.net"],
    "cloudfront": ["cloudfront.net"],
    "cloudflare": ["cloudflare.net", "cloudflare.com"],
    "fastly": ["fastly.net", "fastlylb.net"],
    "incapsula": ["incapdns.net", "impervadns.net"],
    "maxcdn": ["netdna-cdn.com", "stackpathdns.com"],
    "limelight": ["llnwd.net", "llnw.net"],
    "edgecast": ["edgecastcdn.net", "edgecastdns.com"],
    "level3": ["fpbns.net", "footprint.net"],
    "alibaba": ["alikunlun.com", "alicdn.com"],
    "azure": ["azureedge.net", "msecnd.net", "trafficmanager.net"],
    "google": ["googlevideo.com", "googleusercontent.com", "gvt1.com"],
    "wordpress": ["wordpress.com"],
    "sucuri": ["sucuri.net"],
    "cachefly": ["cachefly.net"],
    "highwinds": ["hwcdn.net"],
}


def detect_cdn_from_cname(cname: str) -> Optional[str]:
    """Map a CNAME to a CDN name using the pattern table."""
    cname_lower = cname.lower()
    for cdn_name, patterns in CDN_CNAME_PATTERNS.items():
        for pat in patterns:
            if cname_lower.endswith(pat) or pat in cname_lower:
                return cdn_name
    return None


def get_cdn_cnames(domain: str, depth: int = 5) -> list[tuple[str, str]]:
    """
    Follow CNAME chain for *domain* and return list of (cname, cdn_name) tuples
    for any CDN-matching entries found.
    """
    results = []
    target = domain
    for _ in range(depth):
        cname = dig_cname(target)
        if not cname:
            break
        cdn = detect_cdn_from_cname(cname)
        if cdn:
            results.append((cname, cdn))
        target = cname
    return results


# ---------------------------------------------------------------------------
# Per-website measurement functions
# ---------------------------------------------------------------------------

def measure_dns(website: str, concentration_map: dict[str, int]) -> DNSResult:
    result = DNSResult(website=website)
    nameservers = dig_ns(website)
    result.nameservers = nameservers
    if not nameservers:
        return result

    ssl_info = get_ssl_info(website)
    san_tlds = ssl_info.get("san_tlds", [])
    result.san_list = san_tlds

    result.soa_record = dig_soa(website)

    for ns in nameservers:
        ns_type = classify_ns(ns, website, san_tlds, concentration_map)
        result.ns_types[ns] = ns_type

    types = list(result.ns_types.values())
    has_third = "third" in types
    has_private = "private" in types

    result.uses_third_party = has_third

    # Critical dependency: website has NO private NS (entirely reliant on third-party)
    result.critical_dependency = has_third and not has_private

    # Redundancy: uses nameservers from >1 distinct provider
    third_tlds = {get_tld(ns) for ns, t in result.ns_types.items() if t == "third"}
    result.redundant = len(third_tlds) > 1 or (has_third and has_private)

    return result


def measure_ca(website: str) -> CAResult:
    result = CAResult(website=website)
    ssl_info = get_ssl_info(website)
    if not ssl_info:
        return result

    result.ca_name = ssl_info.get("ca_name", "")
    result.ca_url = ssl_info.get("ca_url", "")
    result.ocsp_stapling = ssl_info.get("ocsp_stapled", False)

    san_tlds = ssl_info.get("san_tlds", [])
    result.ca_type = classify_ca(result.ca_url or "", website, san_tlds)

    # Critical dependency: third-party CA AND no OCSP stapling
    result.critical_dependency = (result.ca_type == "third") and not result.ocsp_stapling

    return result


def measure_cdn(website: str) -> CDNResult:
    result = CDNResult(website=website)

    ssl_info = get_ssl_info(website)
    san_tlds = ssl_info.get("san_tlds", [])

    # Probe www subdomain and apex
    probes = [website, f"www.{website}"]
    seen_cdns: dict[str, str] = {}  # cdn_name -> cname

    for probe in probes:
        for cname, cdn in get_cdn_cnames(probe):
            if cdn not in seen_cdns:
                seen_cdns[cdn] = cname

    result.cdns = list(seen_cdns.keys())
    for cdn_name, cname in seen_cdns.items():
        cdn_type = classify_cdn(cname, website, san_tlds)
        result.cdn_types[cdn_name] = cdn_type

    types = list(result.cdn_types.values())
    has_third = "third" in types

    result.uses_third_party = has_third
    # Critical: uses CDN and all are third-party (no private CDN fallback)
    result.critical_dependency = has_third and "private" not in types
    # Redundant: more than one distinct CDN provider
    result.redundant = len({c for c, t in result.cdn_types.items() if t == "third"}) > 1

    return result


# ---------------------------------------------------------------------------
# Provider concentration + impact metrics (Section 2.2)
# ---------------------------------------------------------------------------

def compute_concentration_and_impact(
    provider_to_websites: dict[str, set[str]],
    critical_map: dict[str, bool],
    total_websites: int,
) -> dict[str, dict]:
    """
    For each provider compute:
      concentration = |websites using provider| / total_websites * 100
      impact        = |websites critically dependent on provider| / total_websites * 100
    """
    stats = {}
    for provider, sites in provider_to_websites.items():
        concentration = len(sites) / total_websites * 100
        critically_dependent = {s for s in sites if critical_map.get(s, False)}
        impact = len(critically_dependent) / total_websites * 100
        stats[provider] = {
            "concentration": round(concentration, 2),
            "impact": round(impact, 2),
            "website_count": len(sites),
            "critical_count": len(critically_dependent),
        }
    return dict(sorted(stats.items(), key=lambda x: -x[1]["concentration"]))


# ---------------------------------------------------------------------------
# Inter-service dependency measurements (Section 3.4 / Section 5)
# ---------------------------------------------------------------------------

def measure_cdn_to_dns(cdn_cname: str, concentration_map: dict[str, int]) -> dict:
    """Measure CDN → DNS dependency by finding NS of CDN's CNAME domain."""
    ns_list = dig_ns(cdn_cname)
    results = {}
    for ns in ns_list:
        ns_type = classify_ns(ns, cdn_cname, [], concentration_map)
        results[ns] = ns_type
    return results


def measure_ca_to_dns(ocsp_url: str, concentration_map: dict[str, int]) -> dict:
    """Measure CA → DNS dependency by finding NS of the CA's OCSP server domain."""
    domain = re.sub(r"https?://", "", ocsp_url).split("/")[0]
    ns_list = dig_ns(domain)
    results = {}
    for ns in ns_list:
        ns_type = classify_ns(ns, domain, [], concentration_map)
        results[ns] = ns_type
    return results


def measure_ca_to_cdn(ocsp_url: str) -> dict:
    """Measure CA → CDN dependency by checking if OCSP server uses a CDN."""
    domain = re.sub(r"https?://", "", ocsp_url).split("/")[0]
    cdns = get_cdn_cnames(domain)
    return {cdn: cname for cname, cdn in cdns}


# ---------------------------------------------------------------------------
# Study orchestration
# ---------------------------------------------------------------------------

class DependencyStudy:
    """
    Orchestrates the full measurement pipeline for a list of websites.

    Usage:
        study = DependencyStudy(websites, workers=20)
        results = study.run()
        study.print_summary(results)
        study.save_results(results, "output.json")
    """

    def __init__(self, websites: list[str], workers: int = 10, delay: float = 0.5):
        self.websites = websites
        self.workers = workers
        self.delay = delay
        self._concentration_map: dict[str, int] = {}

    def _build_concentration_map(self) -> dict[str, int]:
        """
        First-pass: collect all nameservers to build a concentration map
        (number of websites served by each NS TLD). Used by the heuristic to
        identify commercial DNS providers (concentration >= 50).
        """
        log.info("Building NS concentration map (pass 1) ...")
        ns_counts: dict[str, int] = defaultdict(int)
        for website in self.websites:
            for ns in dig_ns(website):
                ns_tld = get_tld(ns)
                if ns_tld:
                    ns_counts[ns_tld] += 1
        return dict(ns_counts)

    def _measure_one(self, website: str) -> dict:
        time.sleep(self.delay)
        log.info(f"Measuring {website}")
        dns_r = measure_dns(website, self._concentration_map)
        ca_r = measure_ca(website)
        cdn_r = measure_cdn(website)
        return {
            "website": website,
            "dns": dns_r.__dict__,
            "ca": ca_r.__dict__,
            "cdn": cdn_r.__dict__,
        }

    def run(self) -> list[dict]:
        self._concentration_map = self._build_concentration_map()
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(self._measure_one, w): w for w in self.websites}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    log.warning(f"Error measuring {futures[fut]}: {e}")
        return results

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    @staticmethod
    def summarize(results: list[dict]) -> dict:
        total = len(results)
        if total == 0:
            return {}

        # DNS
        dns_third = sum(1 for r in results if r["dns"]["uses_third_party"])
        dns_critical = sum(1 for r in results if r["dns"]["critical_dependency"])
        dns_redundant = sum(1 for r in results if r["dns"]["redundant"])

        # CDN
        cdn_users = [r for r in results if r["cdn"]["cdns"]]
        cdn_third = sum(1 for r in cdn_users if r["cdn"]["uses_third_party"])
        cdn_critical = sum(1 for r in cdn_users if r["cdn"]["critical_dependency"])
        cdn_redundant = sum(1 for r in cdn_users if r["cdn"]["redundant"])

        # CA
        ca_results = [r for r in results if r["ca"]["ca_name"]]
        ca_third = sum(1 for r in ca_results if r["ca"]["ca_type"] == "third")
        ca_critical = sum(1 for r in ca_results if r["ca"]["critical_dependency"])
        ocsp_stapling = sum(1 for r in ca_results if r["ca"]["ocsp_stapling"])

        # Provider concentration maps
        dns_provider_sites: dict[str, set] = defaultdict(set)
        for r in results:
            for ns, t in r["dns"]["ns_types"].items():
                if t == "third":
                    dns_provider_sites[get_tld(ns)].add(r["website"])

        cdn_provider_sites: dict[str, set] = defaultdict(set)
        for r in cdn_users:
            for cdn, t in r["cdn"]["cdn_types"].items():
                if t == "third":
                    cdn_provider_sites[cdn].add(r["website"])

        ca_provider_sites: dict[str, set] = defaultdict(set)
        for r in ca_results:
            if r["ca"]["ca_type"] == "third" and r["ca"]["ca_name"]:
                ca_provider_sites[r["ca"]["ca_name"]].add(r["website"])

        dns_critical_map = {r["website"]: r["dns"]["critical_dependency"] for r in results}
        cdn_critical_map = {r["website"]: r["cdn"]["critical_dependency"] for r in results}
        ca_critical_map = {r["website"]: r["ca"]["critical_dependency"] for r in results}

        dns_conc = compute_concentration_and_impact(dns_provider_sites, dns_critical_map, total)
        cdn_conc = compute_concentration_and_impact(cdn_provider_sites, cdn_critical_map, total)
        ca_conc = compute_concentration_and_impact(ca_provider_sites, ca_critical_map, total)

        return {
            "total_websites": total,
            "dns": {
                "third_party_pct": round(dns_third / total * 100, 1),
                "critical_pct": round(dns_critical / total * 100, 1),
                "redundant_pct": round(dns_redundant / total * 100, 1),
                "top_providers": list(dns_conc.items())[:10],
            },
            "cdn": {
                "users": len(cdn_users),
                "users_pct": round(len(cdn_users) / total * 100, 1),
                "third_party_pct": round(cdn_third / len(cdn_users) * 100, 1) if cdn_users else 0,
                "critical_pct": round(cdn_critical / len(cdn_users) * 100, 1) if cdn_users else 0,
                "redundant_pct": round(cdn_redundant / len(cdn_users) * 100, 1) if cdn_users else 0,
                "top_providers": list(cdn_conc.items())[:10],
            },
            "ca": {
                "https_websites": len(ca_results),
                "https_pct": round(len(ca_results) / total * 100, 1),
                "third_party_pct": round(ca_third / len(ca_results) * 100, 1) if ca_results else 0,
                "critical_pct": round(ca_critical / len(ca_results) * 100, 1) if ca_results else 0,
                "ocsp_stapling_pct": round(ocsp_stapling / len(ca_results) * 100, 1) if ca_results else 0,
                "top_providers": list(ca_conc.items())[:10],
            },
        }

    @staticmethod
    def print_summary(results: list[dict]) -> None:
        s = DependencyStudy.summarize(results)
        print("\n" + "=" * 60)
        print(f"  IMC 2020 Dependency Study — Summary ({s['total_websites']} websites)")
        print("=" * 60)

        print("\n── DNS Direct Dependencies ──────────────────────────────────")
        d = s["dns"]
        print(f"  Third-party DNS:    {d['third_party_pct']}%")
        print(f"  Critical dep.:      {d['critical_pct']}%")
        print(f"  Redundant:          {d['redundant_pct']}%")
        print("  Top DNS providers (by concentration):")
        for prov, stats in d["top_providers"][:5]:
            print(f"    {prov:25s}  conc={stats['concentration']:.1f}%  impact={stats['impact']:.1f}%")

        print("\n── CDN Direct Dependencies ──────────────────────────────────")
        c = s["cdn"]
        print(f"  Sites using CDN:    {c['users_pct']}% ({c['users']} sites)")
        print(f"  Third-party CDN:    {c['third_party_pct']}% of CDN users")
        print(f"  Critical dep.:      {c['critical_pct']}% of CDN users")
        print(f"  Redundant:          {c['redundant_pct']}% of CDN users")
        print("  Top CDN providers:")
        for prov, stats in c["top_providers"][:5]:
            print(f"    {prov:25s}  conc={stats['concentration']:.1f}%  impact={stats['impact']:.1f}%")

        print("\n── CA Direct Dependencies ───────────────────────────────────")
        a = s["ca"]
        print(f"  Sites with HTTPS:   {a['https_pct']}% ({a['https_websites']} sites)")
        print(f"  Third-party CA:     {a['third_party_pct']}% of HTTPS sites")
        print(f"  OCSP stapling:      {a['ocsp_stapling_pct']}% of HTTPS sites")
        print(f"  Critical dep.:      {a['critical_pct']}% of HTTPS sites")
        print("  Top CA providers:")
        for prov, stats in a["top_providers"][:5]:
            print(f"    {prov:30s}  conc={stats['concentration']:.1f}%  impact={stats['impact']:.1f}%")

        print("\n" + "=" * 60)

    @staticmethod
    def save_results(results: list[dict], path: str) -> None:
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
        log.info(f"Results saved to {path}")

    @staticmethod
    def save_summary_csv(results: list[dict], path: str) -> None:
        """Save per-website summary rows to CSV."""
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "website",
                "dns_third_party", "dns_critical", "dns_redundant",
                "cdn_uses", "cdn_third_party", "cdn_critical", "cdn_redundant",
                "https", "ca_type", "ocsp_stapling", "ca_critical",
            ])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "website": r["website"],
                    "dns_third_party": r["dns"]["uses_third_party"],
                    "dns_critical": r["dns"]["critical_dependency"],
                    "dns_redundant": r["dns"]["redundant"],
                    "cdn_uses": bool(r["cdn"]["cdns"]),
                    "cdn_third_party": r["cdn"]["uses_third_party"],
                    "cdn_critical": r["cdn"]["critical_dependency"],
                    "cdn_redundant": r["cdn"]["redundant"],
                    "https": bool(r["ca"]["ca_name"]),
                    "ca_type": r["ca"]["ca_type"],
                    "ocsp_stapling": r["ca"]["ocsp_stapling"],
                    "ca_critical": r["ca"]["critical_dependency"],
                })
        log.info(f"CSV saved to {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def load_alexa_top_n(n: int = 100) -> list[str]:
    """
    Returns a small hardcoded sample from the Alexa top-100K list.
    In the full study, the authors use the actual Alexa CSV.
    Replace this with: pd.read_csv("alexa_top1m.csv")["domain"].head(n).tolist()
    """
    sample = [
        "google.com", "youtube.com", "facebook.com", "twitter.com",
        "instagram.com", "linkedin.com", "wikipedia.org", "reddit.com",
        "amazon.com", "netflix.com", "github.com", "stackoverflow.com",
        "medium.com", "nytimes.com", "bbc.com", "cnn.com",
        "apple.com", "microsoft.com", "dropbox.com", "zoom.us",
        "paypal.com", "ebay.com", "shopify.com", "wordpress.com",
        "cloudflare.com", "akamai.com", "fastly.com", "twitch.tv",
        "espn.com", "spotify.com",
    ]
    return sample[:n]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IMC 2020 DNS/CDN/CA dependency replication")
    parser.add_argument("--websites", nargs="+", help="Domains to measure (overrides sample)")
    parser.add_argument("--n", type=int, default=10, help="Number of sample sites to use")
    parser.add_argument("--workers", type=int, default=5, help="Parallel workers")
    parser.add_argument("--out-json", default="dependency_results.json")
    parser.add_argument("--out-csv", default="dependency_results.csv")
    args = parser.parse_args()

    sites = args.websites if args.websites else load_alexa_top_n(args.n)
    print(f"Running dependency analysis on {len(sites)} websites ...")

    study = DependencyStudy(sites, workers=args.workers)
    results = study.run()

    study.print_summary(results)
    study.save_results(results, args.out_json)
    study.save_summary_csv(results, args.out_csv)