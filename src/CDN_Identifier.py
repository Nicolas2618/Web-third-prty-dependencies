#region Imports
#----------------------------------------------------------------------------------
#Imports
#----------------------------------------------------------------------------------
import dns.resolver
import dns.query
import dns.zone
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
from typing import Optional
import certifi
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, NameOID
from urllib.parse import urlparse
import numpy as np
import requests
import tldextract
import matplotlib.pyplot as plt
import pandas as pa
import circlify
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright #
import matplotlib.patches as mpatches
import findcdn
import json
import ipaddress
import urllib.request
#endregion





#region Dataclass
@dataclass
class CDNResult:
    website: str
    cdns: list[str] = field(default_factory=list)
    cdn_types: dict[str, str] = field(default_factory=dict)
    uses_third_party: bool = False
    critical_dependency: bool = False
    redundant: bool = False
#endregion





#region Basic Helpers
#----------------------------------------------------------------------------------
#Basic Helpers
#----------------------------------------------------------------------------------
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

def get_cname(domain):
    try: 
        answers = dns.resolver.resolve(domain, 'CNAME')

        for rdata in answers:
            print(f'Target: {rdata.target}')
            return str(rdata.target).rstrip('.').lower()
        
    except dns.resolver.NoAnswer:
        print(f"No CNAME record for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f'The domain {domain} does not exist')
    except Exception as e:
        print(f"an error ocurred: {e}")
#endregion





#region Get SSL Info
#----------------------------------------------------------------------------------
#Get SSL Info
#----------------------------------------------------------------------------------
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





#region Headless Browsing
#----------------------------------------------------------------------------------
#Headless Browsing
#----------------------------------------------------------------------------------
def get_internal_hostnames(website: str, san_tlds: list[str]) -> set[str]:
    """
    Use Playwright to fully render the landing page and capture every hostname
    that serves a network request. Then filter to internal hostnames using the
    paper's three-step heuristic: TLD match → SAN match → SOA match.
    """
    w_tld = get_tld(website)
    w_soa = get_soa(website)
    all_hostnames: set[str] = set()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()

            page.on(
                "request",
                lambda req: all_hostnames.add(urlparse(req.url).hostname or "")
            )

            for scheme in ("https://", "http://"):
                try:
                    page.goto(scheme + website, wait_until="networkidle", timeout=20000)
                    break
                except Exception:
                    continue

            browser.close()
    except Exception as e:
        logging.warning(f"{website}: Playwright failed — {e}")
        return set()

    # Filter to internal hostnames only
    internal: set[str] = set()
    for hostname in filter(None, all_hostnames):
        if hostname in (website, f"www.{website}"):
            continue
        h_tld = get_tld(hostname)

        if h_tld == w_tld:                          # Step 1: TLD match
            internal.add(hostname)
        elif h_tld in san_tlds:                     # Step 2: SAN match
            internal.add(hostname)
        else:                                        # Step 3: SOA match
            h_soa = get_soa(hostname)
            if h_soa and w_soa and h_soa == w_soa:
                internal.add(hostname)

    logging.info(f"{website}: {len(internal)} internal hostnames from {len(all_hostnames)} total")
    return internal
#endregion





#region CDN Helpers
#----------------------------------------------------------------------------------
# CDN Helpers
#----------------------------------------------------------------------------------
CDN_CNAME_PATTERNS = {
    # ---------------------------------------------------------------------------
    # CNAME-to-CDN map (self-populated subset from paper; extend as needed)
    # ---------------------------------------------------------------------------
    "akamai":       ["akadns.net", "akamai.net", "akamaized.net", "akamaiedge.net",
                     "akamaihd.net", "edgesuite.net", "edgekey.net", "srip.net",
                     "akamaitechnologies.com", "akamaitechnologies.fr", "tl88.net"],
    "cloudfront":   ["cloudfront.net"],
    "cloudflare":   ["cloudflare.net", "cloudflare.com"],
    "fastly":       ["fastly.net", "fastlylb.net", "nocookie.net"],
    "incapsula":    ["incapdns.net", "impervadns.net"],
    "stackpath":    ["netdna-cdn.com", "netdna-ssl.com", "netdna.com", "stackpathdns.com"],
    "limelight":    ["llnwd.net", "lldns.net", "gfx.ms"],
    "netflix":      ["nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"],
    "edgecast":     ["edgecastcdn.net", "systemcdn.net", "transactcdn.net",
                     "v1cdn.net", "v2cdn.net", "v3cdn.net", "v4cdn.net", "v5cdn.net",
                     ".adn.", ".wac.", ".wpc."],
    "level3":       ["footprint.net", "fpbns.net"],
    "alibaba":      ["alikunlun.com", "alicdn.com"],
    "azure":        ["azureedge.net", "msecnd.net", "vo.msecnd.net", "trafficmanager.net"],
    "google":       ["googlevideo.com", "googleusercontent.com", "gvt1.com", "gvt2.com",
                     "googlehosted.com", "googlesyndication.com", "googleadservices.com",
                     "ggpht.com"],
    "microsoft":    ["msocdn.com", "msecnd.net", "auth.gfx.ms", "gfx.ms", "ajax.aspnetcdn.com"],
    "meta":         ["cdninstagram.com", "fbcdn.net", "facebook.net"],
    "yahoo":        ["yahooapis.com", "yimg.", "ay1.b.yahoo.com"],
    "wordpress":    ["wordpress.com", "wp.com"],
    "sucuri":       ["sucuri.net"],
    "cachefly":     ["cachefly.net"],
    "highwinds":    ["hwcdn.net"],
    "keycdn":       ["kxcdn.com"],
    "cdn77":        ["cdn77.net", "cdn77.org"],
    "jsdelivr":     ["cdn.jsdelivr.net"],
    "netlify":      ["netlify.com"],
    "bunnycdn":     ["b-cdn.net"],
    "cdnetworks":   ["cdngc.net", "gccdn.net", "gccdn.cn", "panthercdn.com"],
    "chinacache":   ["ccgslb.com", "ccgslb.net", "c3cache.net", "chinacache.net", "c3cdn.net"],
    "chinanetcenter": ["wscdns.com", "wscloudcdn.com", "lxdns.com",
                       "speedcdns.com", "mwcloudcdn.com"],
    "myracloud":    ["myracloud.com"],
    "azion":        ["azioncdn.net", "azioncdn.com", "azion.net"],
    "medianova":    ["mncdn.com", "mncdn.net", "mncdn.org"],
    "aryaka":       ["aads1.net", "aads-cn.net", "aads-cng.net"],
    "belugacdn":    ["belugacdn.com"],
    "rackspace":    ["raxcdn.com"],
    "taobao":       ["tbcdn.cn", "taobaocdn.com"],
    "turbobytes":   ["turbobytes-cdn.com", "clients.turbobytes.net"],
    "mirrorimage":  ["instacontent.net", "cap-mii.net", "mirror-image.net"],
    "onapp":        ["r.worldcdn.net", "r.worldssl.net"],
    "instart":      ["insnw.net", "inscname.net"]
}

def parse_cdn_string(raw) -> list[str]:
    """
    findcdn returns CDNs as a raw string, e.g.:
      'googlehosted.com'
      '.akadns.net', '.akamaitechnologies.fr'
    Parse it into a clean list of domain strings.
    """
    if not raw or not isinstance(raw, str):
        return []
    # Strip surrounding whitespace, split on "', '" pattern
    parts = re.split(r"',\s*'", raw)
    return [p.strip(" '").lstrip(".") for p in parts if p.strip(" '")]

def detect_cdn_from_cname(cname: str) -> Optional[str]:
    """Map a CNAME to a CDN name using the pattern table."""
    cname_lower = cname.lower()
    for cdn_name, patterns in CDN_CNAME_PATTERNS.items():
        for pat in patterns:
            if cname_lower.endswith(pat) or pat in cname_lower:
                return cdn_name
    return None

HEADER_CDN_PATTERNS = {
    # --- Major third-party CDNs ---
    "cloudflare"    : ["server: cloudflare", "cf-ray", "cf-cache-status", "cf-request-id", "cf-connecting-ip"],
    "cloudfront"    : ["x-amz-cf-id", "x-amz-cf-pop"],
    "fastly"        : ["x-served-by: cache-", "via: 1.1 varnish", "fastly-io-info", "x-fastly-request-id", "surrogate-key", "fastly-debug-path"],
    "akamai"        : [ "x-check-cacheable", "x-akamai-session-info", "x-akamai-staging", "x-cache-remote", "akamai-cache-status", "akamai-grn", 
               "x-true-cache-key", "x-cache: tcp_", "akamaitechnologies", "akamaighost", "server: akamainetstorage"],
    "azure"         : ["x-azure-ref", "x-msedge-ref", "x-ec-custom-error", "x-azure-requestid"],
    "microsoft"     : ["server: microsoft-httpapi", "x-feserver", "x-calculatedfetarget", "x-besku", "x-bepartition", "x-calculatedbetarget", "x-nanoProxy"],
    "incapsula"     : ["x-iinfo", "x-cdn: imperva", "x-cdn: incapsula", "visid_incap", "incap_ses"],
    "sucuri"        : ["x-sucuri-id", "x-sucuri-cache", "server: sucuri/cloudproxy"],
    "bunnycdn"      : ["server: bunnycdn-", "cdn-pullzone",  "cdn-uid", "cdn-requestid", "cdn-cache", "cdn-cachedat"],
    "keycdn"        : ["x-cache: hit keycdn", "x-cache: miss keycdn", "server: keycdn-engine", "x-edge-location: keycdn"],
    "gcore"         : ["x-id: ", "server: gcore"],
    "cdn77"         : ["x-cdn77-hit", "x-cdn77-cache", "server: cdn77-"],
    "stackpath"     : ["x-sp-url", "x-sp-edge", "server: stackpath"],
    "limelight"     : ["x-llnw-cache", "x-llnw-request-id"],
    "edgecast"      : ["server: ecs ", "x-ec-custom-error", "x-cache: tcp_hit"],
    "google"        : ["x-goog-", "via: 1.1 google", "server: gws", "server: gsfe", "server: sffe", "x-google-backends", "x-googlas-appengine"],
    "netflix"       : ["x-netflix-", "nflx-", "server: nflx"],
    "wikimedia"     : [ "x-cache: cp", "server: ats", "x-cache-status: hit-front", "server-timing: cache"],
    "roblox"        : ["x-roblox-region", "x-roblox-edge", "server: public-gateway"],
    "nextjs"        : ["x-nextjs", "x-hex-backend "],
}

def detect_cdn_from_headers(domain: str, timeout: int = 8) -> Optional[str]:
    """
    Make an HTTP request and fingerprint the CDN from response headers.
    """
    for scheme in ("https://", "http://"):
        try:
            resp = requests.get(
                scheme + domain,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True,
                verify=False,
            )
            # Flatten headers to a single lowercase string for pattern matching
            header_str = " ".join(
                f"{k.lower()}: {v.lower()}" for k, v in resp.headers.items()
            )
            for cdn_name, patterns in HEADER_CDN_PATTERNS.items():
                for pat in patterns:
                    if pat in header_str:
                        return cdn_name
            return None
        except Exception:
            continue
    return None

CDN_IP_SOURCES = {
    # ---------------------------------------------------------------------------
    # CDN IP range sources — all publicly published, no auth required
    # ---------------------------------------------------------------------------
    "cloudflare": [
        "https://www.cloudflare.com/ips-v4",
        "https://www.cloudflare.com/ips-v6",
    ],
    "fastly": [
        "https://api.fastly.com/public-ip-list",   # JSON: {"addresses": [...], "ipv6_addresses": [...]}
    ],
    "cloudfront": [
        "https://ip-ranges.amazonaws.com/ip-ranges.json",  # filter service == "CLOUDFRONT"
    ],
    "akamai": [
        "https://techdocs.akamai.com/origin-ip-acl/docs/update-your-origin-server",  # not a clean API — skip
    ],
    "google": [
        "https://www.gstatic.com/ipranges/goog.json",   # JSON: {prefixes: [{ipv4Prefix/ipv6Prefix}]}
        "https://www.gstatic.com/ipranges/cloud.json",
    ],
    "microsoft": [
        "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",  # XML, harder to parse
    ],
}

def fetch_cdn_ip_ranges() -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """
    Fetch and parse IP ranges for each CDN that publishes them.
    Returns a dict of cdn_name → list of network objects.
    Call this ONCE at startup and cache the result.
    """
    ranges: dict[str, list] = {}

    def add(cdn, cidr_str):
        try:
            ranges.setdefault(cdn, []).append(ipaddress.ip_network(cidr_str, strict=False))
        except ValueError:
            pass

    def fetch(url):
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode()

    # Cloudflare — plain text, one CIDR per line
    for url in ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"]:
        try:
            for line in fetch(url).strip().splitlines():
                add("cloudflare", line.strip())
        except Exception:
            pass

    # Fastly — JSON
    try:
        data = json.loads(fetch("https://api.fastly.com/public-ip-list"))
        for cidr in data.get("addresses", []) + data.get("ipv6_addresses", []):
            add("fastly", cidr)
    except Exception:
        pass

    # CloudFront — AWS JSON, filter by service
    try:
        data = json.loads(fetch("https://ip-ranges.amazonaws.com/ip-ranges.json"))
        for p in data.get("prefixes", []):
            if p.get("service") == "CLOUDFRONT":
                add("cloudfront", p["ip_prefix"])
        for p in data.get("ipv6_prefixes", []):
            if p.get("service") == "CLOUDFRONT":
                add("cloudfront", p["ipv6_prefix"])
    except Exception:
        pass

    # Google — JSON with prefixes list
    for url in ["https://www.gstatic.com/ipranges/goog.json",
                "https://www.gstatic.com/ipranges/cloud.json"]:
        try:
            data = json.loads(fetch(url))
            for p in data.get("prefixes", []):
                cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                if cidr:
                    add("google", cidr)
        except Exception:
            pass

    # Microsoft/Azure — attempt to find the ServiceTags_Public JSON from the download page
    try:
        page = fetch("https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519")
        m = re.search(r'href="(https://download.microsoft.com[^"]*ServiceTags_Public[^"]*\.json)"', page)
        if m:
            url = m.group(1)
            data = json.loads(fetch(url))
            for v in data.get("values", []):
                props = v.get("properties", {})
                for p in props.get("addressPrefixes", []):
                    add("microsoft", p)
                    add("azure", p)
    except Exception:
        pass

    return ranges

def get_ip(domain: str) -> Optional[str]:
    """Resolve domain to its first A record IP."""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return str(next(iter(answers)))
    except Exception:
        return None

def detect_cdn_from_ip(
    domain: str,
    cdn_ip_ranges: dict[str, list]
) -> Optional[str]:
    """
    Resolve domain to IP and check against known CDN IP ranges.
    Returns CDN name or None.
    """
    ip_str = get_ip(domain)
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
        for cdn_name, networks in cdn_ip_ranges.items():
            for network in networks:
                if ip in network:
                    return cdn_name
    except ValueError:
        pass

    # ASN fallback: query public ASN-to-IP service to infer ownership
    # Local prefix fallback (handles common Microsoft-owned ranges without external lookups)
    try:
        if ip_str.startswith('20.'):
            return 'microsoft'
    except Exception:
        pass

    # ASN-based fallback (best-effort; may be blocked in restricted environments)
    try:
        import urllib.request
        req = urllib.request.Request(f"https://api.iptoasn.com/v1/as/ip/{ip_str}", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
            desc = (data.get("as_description") or "").lower()
            asname = (data.get("as_name") or "").lower()
            if "microsoft" in desc or "microsoft" in asname or "azure" in desc or "azure" in asname:
                return "microsoft"
            if "google" in desc or "google" in asname:
                return "google"
            if "akamai" in desc or "akamai" in asname:
                return "akamai"
    except Exception:
        pass

    return None

def get_cdn_cnames(domain: str, depth: int = 5) -> list[tuple[str, str]]:
    """
    Follow CNAME chain for *domain* and return list of (cname, cdn_name) tuples
    for any CDN-matching entries found.
    """
    results = []
    target = domain
    visited = set()
    for _ in range(depth):
        if target in visited:
            break
        visited.add(target)
        cname = get_cname(target)
        if not cname:
            break
        cdn = detect_cdn_from_cname(cname)
        if cdn:
            results.append((cname, cdn))
        target = cname
    return results
#endregion





#region CDN Identifier
#----------------------------------------------------------------------------------
# CDN Identifier
#----------------------------------------------------------------------------------
def classify_cdn(cnames: list[str], website: str, san_tlds: list[str], supports_https: bool) -> str:
    w_tld = get_tld(website)
    w_soa = get_soa(website)

    for cname in cnames:
        cname_tld = get_tld(cname)
        if cname_tld == w_tld:
            return "private"
        if supports_https and cname_tld in san_tlds:
            return "private"
        cname_soa = get_soa(cname)
        if cname_soa and w_soa:
            if cname_soa == w_soa:
                return "private"   # same admin owner → private
            else:
                return "third"     # different admin owner → third-party

    return "unknown"
#endregion





#region Measure CDN
#----------------------------------------------------------------------------------
# Measure CDN
#----------------------------------------------------------------------------------
def measure_cdn_findcdn(website: str, internal_hostnames: set[str], cdn_ip_ranges: dict) -> CDNResult:
    result = CDNResult(website=website)
    
    ssl_info = get_ssl_info(website)
    san_tlds = ssl_info.get("san_tlds", [])
    supports_https = ssl_info.get("supports_https", False)

    # Run findcdn across apex + all internal hostnames
    probes = list({website, f"www.{website}"} | internal_hostnames)
    resp_json = json.loads(findcdn.main(probes, double_in=True, threads=10))

    # Accumulate detected CDN fingerprints per CDN name
    cdn_cnames: dict[str, list[str]] = defaultdict(list)

    for probe, data in resp_json["domains"].items():
        for fingerprint in parse_cdn_string(data.get("cdns", "")):
            cdn_name = detect_cdn_from_cname(fingerprint)
            if cdn_name:
                cdn_cnames[cdn_name].append(fingerprint)
            else:
                logging.warning(f"Unknown CDN fingerprint: {fingerprint} (from {probe})")

    # IP range fallback — only runs if findcdn found nothing
    if not cdn_cnames:
        for probe in probes:
            cdn_name = detect_cdn_from_ip(probe, cdn_ip_ranges)
            if cdn_name:
                cdn_cnames[cdn_name].append(probe)
                logging.info(f"{website}: IP fallback detected {cdn_name} via {probe}")
                break

    # Header fingerprinting fallback — only runs if IP ranges also found nothing
    if not cdn_cnames:
        cdn_name = detect_cdn_from_headers(website)
        if cdn_name:
            cdn_cnames[cdn_name].append(website)
            logging.info(f"{website}: header fallback detected {cdn_name}")

    # Classify each CDN
    for cdn_name, cnames in cdn_cnames.items():
        result.cdn_types[cdn_name] = classify_cdn(cnames, website, san_tlds, supports_https)

    result.cdns = list(result.cdn_types.keys())
    types = list(result.cdn_types.values())
    has_third = "third" in types
    result.uses_third_party = has_third
    result.critical_dependency = has_third and "private" not in types
    result.redundant = len({c for c, t in result.cdn_types.items() if t == "third"}) > 1

    return result
#endregion





#region Main
#----------------------------------------------------------------------------------
# Main
#----------------------------------------------------------------------------------
def main():
    input_path  = "src/Source_Data/top-100-domains.csv"
    output_path = "src/Source_Data/cdn_results_100.csv"
    cdn_ip_ranges = fetch_cdn_ip_ranges()
    
    rows = []
 
    with open(input_path, "r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        
 
        for row in reader:
            domain_name = row["domain"].strip()
            try:
                ssl_info = get_ssl_info(domain_name)
                san_tlds = ssl_info.get("san_tlds", [])
                internal = get_internal_hostnames(domain_name, san_tlds)  # Playwright step
                cdn_result = measure_cdn_findcdn(domain_name, internal, cdn_ip_ranges)           # findcdn step
            except Exception as e:
                logging.warning(f"Failed on {domain_name}: {e}")
                continue
 
            print(
                 f"Domain:  {domain_name}\n"
            #     f"CA Name: {ca_result.ca_name}\n"
            #     f"Type:    {ca_result.ca_type}\n"
            #     f"Stapled: {ca_result.ocsp_stapling}"
             )
            rows.append({
                "domain":          domain_name,
                "cdns":            cdn_result.cdns,
                "cdn type":        cdn_result.cdn_types,
                "third party":     cdn_result.uses_third_party,
                "crit dependency": cdn_result.critical_dependency,
                "redundancy":      cdn_result.redundant
            })
            
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "cdns", "cdn type", "third party", "crit dependency", "redundancy"])
        writer.writeheader()
        writer.writerows(rows)

    return output_path
#endregion





#region Starter
#----------------------------------------------------------------------------------
# Starter
#----------------------------------------------------------------------------------
if __name__ == "__main__":
    #full thing
    output = main()
#endregion