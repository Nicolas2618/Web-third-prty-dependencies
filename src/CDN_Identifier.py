#region Imports
#----------------------------------------------------------------------------------
#Imports
#----------------------------------------------------------------------------------
import sys

import aiodns
import asyncio
import subprocess
import aiohttp
import aiodns
import ssl
import socket
import dns.resolver
import json
import csv
import re
import logging
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional
import requests
import tldextract
import findcdn
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import circlify
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright
import urllib
#endregion

# Fix for Windows ProactorEventLoop "ConnectionResetError"
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

#region Dataclass
@dataclass
class CDNResult:
    website: str
    cdns: list[str] = field(default_factory=list)
    cdn_types: dict[str, str] = field(default_factory=dict)
    uses_third_party: bool = False
    critical_dependency: bool = False
    redundant: bool = False
    step_ids: str = ""
#endregion

#region Basic Helpers
#----------------------------------------------------------------------------------
#Basic Helpers
#----------------------------------------------------------------------------------

async def get_soa_async(resolver: aiodns.DNSResolver, domain: str) -> dict:
    try:
        # Modern method as requested
        result = await resolver.query_dns(domain, 'SOA')
        return {
            "mname": (result.mname or "").rstrip('.').lower(),
            "rname": (result.rname or "").rstrip('.').lower(),
        }
    except Exception as e:
        logging.debug(f"SOA lookup failed for {domain}: {e}")
        return None

async def get_cnames_async(resolver: aiodns.DNSResolver, domain: str) -> list[str]:
    cnames = []
    current = domain
    try:
        for _ in range(10):
            result = await resolver.query_dns(current, 'CNAME')
            cname = result.cname.rstrip('.')
            cnames.append(cname)
            current = cname
    except Exception:
        pass
    return cnames

async def resolve_a_async(resolver: aiodns.DNSResolver, domain: str) -> list[str]:
    try:
        result = await resolver.query_dns(domain, 'A')
        return [r.host for r in result]
    except Exception as e:
        logging.debug(f"A lookup failed for {domain}: {e}")
        return []

async def get_ptr_async(resolver, ip):
    try:
        reversal = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        # Updated to query_dns
        result = await resolver.query_dns(reversal, 'PTR')
        if result and result[0].name:
            return result[0].name.lower()
        return None
    except Exception:
        return None
    
async def get_asn_info_async(session: aiohttp.ClientSession, ip: str, retries: int = 2) -> Optional[str]:
    # Use rdap.org for global coverage (catches US-based Microsoft/Apple IPs)
    url = f"https://rdap.org/ip/{ip}"
    for attempt in range(retries + 1):
        try:
            async with session.get(url, timeout=5, allow_redirects=True) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    owner_str = json.dumps(data).lower()
                    
                    # Map infrastructure keywords to CDN identities
                    identity = identity_from_text(owner_str)
                    if identity:
                        return identity

                    return None
        except:
            if attempt < retries: await asyncio.sleep(0.5)
    return None

async def get_domain_org_async(session: aiohttp.ClientSession, domain: str) -> Optional[str]:
    """
    Safer RDAP lookup with better error handling and vcard parsing.
    """
    try:
        tld = get_tld(domain)
        url = f"https://rdap.org/domain/{tld}"
        async with session.get(url, timeout=5) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                for entity in data.get("entities", []):
                    vcard = entity.get("vcardArray")
                    # Ensure vcard exists and has the expected structure
                    if vcard and isinstance(vcard, list) and len(vcard) > 1:
                        for entry in vcard[1]:
                            if isinstance(entry, list) and entry[0] == "fn":
                                # Ensure the value exists before calling .lower()
                                val = entry[3]
                                return val.lower() if val else None
    except Exception:
        pass
    return None
    
async def resolve_aaaa_async(resolver: aiodns.DNSResolver, domain: str) -> list[str]:
    """Async AAAA (IPv6) record resolution."""
    try:
        result = await resolver.query_dns(domain, 'AAAA')
        return [r.host for r in result]
    except aiodns.error.DNSError:
        return []
    
async def get_ns_async(resolver: aiodns.DNSResolver, domain: str) -> list[str]:
    try:
        result = await resolver.query_dns(domain, "NS")
        return [
            r.host.rstrip(".").lower()
            for r in result
            if getattr(r, "host", None)
        ]
    except Exception:
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
    "15cdn":        ["15cdn.com", "tzcdn.cn"],
    "360":          ["360anyu.com", "360cdn.com", "360cloudwaf.com", "360safedns.com", "360wzws.com", "qh-cdn.com", "qhcdn.com", "qihucdn.com"],
    "adobe":        ["2o7.net", "adobedtm.com", "demdex.net", "omtrdc.net", "scene7.com"],
    "akamai":       ["akadns.net", "akamai.com", "akamai.net", "akamaiedge-staging.net", "akamaiedge.net", "akamaihd.net", "akamaiorigin.net", "akamaistream.net", "akamaitech.net", "akamaitechnologies.com", "akamaized.net", "edgekey.net", "edgesuite.net", "srip.net", "tl88.net", "ytcdn.net"],
    "alibaba":      ["alicdn.com", "aligaofang.com", "alikunlun.com", "alikunlun.net", "aliyun-inc.com", "aliyun.com", "aliyuncs.com", "cdngslb.com", "kunlun*.com", "taobaocdn.com", "tbcache.com", "tbcdn.cn", "yundunddos.com"],
    "amazon":       ["amazonaws.com", "awsglobalaccelerator.com", "cloudfront.net", "images-amazon.com", "media-amazon.com", "ssl-images-amazon.com"],
    "apple":        ["aaplimg.com", "apple-dns.net", "cdn-apple.com", "icloud-content.com", "mzstatic.com"],
    "aryaka":       ["aads1.net", "aryaka.com"],
    "azion":        ["azion.com", "azion.net", "azioncdn.net"],
    "baidu":        ["baidubce.com", "bcebos.com", "bdstatic.com", "bdydns.com", "shifen.com", "yunjiasu-cdn.net"],
    "baishan":      ["bsclink.cn", "bsgslb.cn", "qingcdn.com", "trpcdn.net"],
    "belugacdn":    ["belugacdn.com"],
    "bilibili":     ["biliapi.com", "hdslb.com", "hdslb.net"],
    "bunnycdn":     ["b-cdn.net", "bunny.net", "bunnycdn.com"],
    "bytedance":    ["byteacctimg.com", "bytecdn.cn", "bytedance.com", "byteimg.com", "ibyteimg.com", "muscdn.com", "sgsnssdk.com", "tiktokcdn.com", "tiktokv.com", "ttwstatic.com"],
    "cachefly":     ["cachefly.com", "cachefly.net"],
    "cdn77":        ["cdn77.com", "cdn77.net", "cdn77.org"],
    "cdnetworks":   ["cdnetworks.com", "cdnetworks.net", "cdnga.net", "cdngc.net", "cdnnetworks.com", "gccdn.cn", "gccdn.net", "panthercdn.com", "txcdn.cn", "txnetworks.cn"],
    "cdnify":       ["cdnify.io"],
    "cdnsun":       ["cdnsun.net"],
    "cdnunion":     ["cdnunion.com", "cdnunion.net"],
    "cdnvideo":     ["cdnvideo.net", "cdnvideo.ru"],
    "chinacache":   ["c3cache.net", "c3dns.net", "ccgslb.com", "ccgslb.com.cn", "ccgslb.net", "chinacache.net", "xgslb.net"],
    "cedexis":      ["cedexis.net", "cdxcn.cn"],
    "chuangcache":  ["aocde.com", "chuangcdn.com"],
    "cloudflare":   ["cloudflare-dns.com", "cloudflare.com", "cloudflare.net", "pages.dev", "r2.dev", "trycloudflare.com", "workers.dev"],
    "cloudinary":   ["cloudinary.com", "cloudinary.net"],
    "conversant":   ["swiftserve.com"],
    "criteo":       ["criteo.com", "criteo.net"],
    "ctyun":        ["ctxcdn.cn"],
    "dailymotion":  ["dmcdn.net"],
    "digitalocean": ["digitalocean.com", "digitaloceanspaces.com"],
    "discord":      ["discordapp.com", "discordapp.net"],
    "dnion":        ["dlgslb.cn", "dnion.com", "ewcache.com", "fastcdn.com", "flxdns.com", "globalcdn.cn", "tlgslb.com"],
    "eleme":        ["elemecdn.com"],
    "fastly":       ["fastly-edge.com", "fastly.com", "fastly.net", "fastlylb.net", "nocookie.net"],
    "fastweb":      ["cachecn.com", "cloudcdn.net", "cloudglb.com", "fastweb.com", "fastwebcdn.com", "fwcdn.com", "fwdns.net", "hacdn.net", "hadns.net"],
    "firebase":     ["firebaseapp.com", "web.app"],
    "fly":          ["fly.dev", "fly.io"],
    "gcore":        ["gc.onl", "gcdn.co", "gcore.com", "gcorelabs.com"],
    "github":       ["github.io", "githubassets.com", "githubusercontent.com"],
    "gitlab":       ["gitlab.io"],
    "google":       ["1e100.net", "ampproject.org", "appspot.com", "ggpht.com", "google-analytics.com", "google.com", "googleadservices.com", "googleapis.com",
                      "googlehosted.com", "googlesyndication.com", "googletagmanager.com", "googletagservices.com", "googleusercontent.com", "googlevideo.com",
                      "gstatic.com", "gvt1.com", "gvt2.com", "gvt3.com", "youtube-nocookie.com", "ytimg.com"],
    "gosun":        ["gosuncdn.com", "mmtrixopt.com"],
    "gravatar":     ["gravatar.com"],
    "heroku":       ["heroku.com", "herokuapp.com", "herokussl.com"],
    "huawei":       ["cdnhwc1.com", "cdnhwc2.com", "cdnhwc3.com", "hicloud.com", "huaweicloud.com"],
    "hubspot":      ["hs-banner.com", "hs-sites.com", "hsappstatic.net", "hubspot.com", "hubspotemail.net"],
    "imageengine":  ["imgeng.in"],
    "imagekit":     ["imagekit.io"],
    "imgix":        ["imgix.com", "imgix.net"],
    "imperva":      ["imperva.com", "impervadns.net", "incapdns.net", "incapsula.com"],
    "jd":           ["jcloud-cdn.com", "jcloudcs.com", "jcloudlb.com", "jdcdn.com", "qianxun.com"],
    "jsdelivr":     ["jsdelivr.com", "jsdelivr.net"],
    "jwplayer":     ["jwpcdn.com"],
    "kakao":        ["kakaocdn.net"],
    "keycdn":       ["keycdn.com", "kxcdn.com"],
    "kingsoft":     ["ks-cdn.com", "ksyuncdn-k1.com", "ksyuncdn.com"],
    "leaseweb":     ["lswcdn.net"],
    "lecloud":      ["cdnle.com"],
    "limelight":    ["lldns.net", "llnwd.net", "llnwi.net", "unud.net"],
    "line":         ["line-scdn.net"],
    "linkedin":     ["licdn.com"],
    "maoyun":       ["maoyun.tv", "maoyundns.com"],
    "medianova":    ["medianova.com", "mncdn.com", "mncdn.net", "mncdn.org"],
    "mediavine":    ["mediavine.com"],
    "meituan":      ["mtyun.com", "sankuai.com"],
    "meta":         ["cdninstagram.com", "facebook.net", "fb.com", "fb.me", "fbcdn.net", "fbsbx.com"],
    "microsoft":    ["ax-msedge.net", "azure.com", "azureedge.net", "azurefd.net", "azurewebsites.net", "azurewebsites.windows.net", "chinacloudsites.cn", 
                     "cloudapp.net", "gfx.ms", "mschcdn.com", "msecnd.net", "msftconnecttest.com", "msftncsi.com", "msocdn.com", "trafficmanager.net", "v0cdn.net"],
    "myracloud":    ["myracloud.com"],
    "naver":        ["pstatic.net"],
    "netease":      ["126.net", "163jiasu.com"],
    "netflix":      ["nflxext.com", "nflximg.com", "nflximg.net", "nflxso.net", "nflxvideo.net"],
    "netlify":      ["netlify.app", "netlify.com"],
    "newdefend":    ["anquan.io", "newdefend.cn"],
    "ngenix":       ["ngenix.net"],
    "nsfocus":      ["nscloudwaf.com"],
    "onapp":        ["worldcdn.net", "worldssl.net"],
    "opera":        ["opera.com", "operacdn.com"],
    "oracle":       ["oraclecloud.com"],
    "ovh":          ["ovh.com", "ovh.net", "ovhcloud.com"],
    "perfops":      ["flexbalancer.net"],
    "pinterest":    ["pinimg.com"],
    "powercdn":     ["powercdn.cn"],
    "qingcloud":    ["frontwize.com", "qingcache.com", "qingcloud.com"],
    "quantserve":   ["quantcount.com", "quantserve.com"],
    "quic":         ["quic.cloud"],
    "qiniu":        ["qbox.me", "qiniu.com", "qiniudns.com"],
    "rackspace":    ["rackcdn.com", "raxcdn.com"],
    "render":       ["onrender.com", "render.com"],
    "salesforce":   ["exacttarget.com", "salesforceliveagent.com", "sfdcstatic.com"],
    "sangfor":      ["sangfordns.com"],
    "section":      ["section.io"],
    "sendgrid":     ["sendgrid.net"],
    "shopify":      ["myshopify.com", "shopify.com", "shopifycdn.com"],
    "sina":         ["sina.com.cn", "sinacdn.com", "sinaedge.com", "sinajs.cn", "sinasws.com"],
    "snapchat":     ["sc-cdn.net"],
    "speedycloud":  ["speedycloud.cc", "xundayun.cn", "xundayun.com"],
    "spotify":      ["sndcdn.com", "spotifycdn.com"],
    "sqspcdn":      ["sqspcdn.com"],
    "stackpath":    ["bootstrapcdn.com", "hwcdn.net", "maxcdn.com", "netdna-cdn.com", "netdna-ssl.com", "netdna.com", "stackpathcdn.com", "stackpathdns.com"],
    "statically":   ["statically.io"],
    "sucuri":       ["sucuri.net"],
    "tata":         ["bitgravity.com", "zenedge.net"],
    "telegram":     ["t.me", "telegra.ph"],
    "tencent":      ["cdntip.com", "dayugslb.com", "dnsv1.com", "gtimg.cn", "gtimg.com", "myqcloud.com", "qcloudcdn.com", "qlogo.cn", "qpic.cn", "qq.com", 
                     "tcdnvod.com", "tdnsv5.com", "tencdns.net", "tencent-cloud.net", "tencentcos.cn"],
    "twitch":       ["jtvnw.net"],
    "twitter":      ["t.co", "twimg.com"],
    "ucloud":       ["cdndo.com", "ucloud.cn", "ucloud.com.cn", "ucloudgda.com"],
    "unpkg":        ["unpkg.com"],
    "upyun":        ["aicdn.com"],
    "vangen":       ["cdnudns.com", "mygslb.com", "sprycdn.com"],
    "vercel":       ["now.sh", "vercel-dns.com", "vercel.app", "vercel.com"],
    "verizon":      ["alphacdn.net", "edgecastcdn.net", "mucdn.net", "nucdn.net", "systemcdn.net", "zetacdn.net"],
    "verycloud":    ["verycdn.net", "verycloud.cn", "verygslb.com"],
    "vimeo":        ["vimeocdn.com"],
    "wangsu":       ["51cdn.com", "chinanetcenter.com", "customcdn.cn", "customcdn.com.cn", "lxdns.com", "mwcloudcdn.com", "mwcname.com", "speedcdns.com", 
                     "wscdns.com", "wscloudcdn.com", "wsdvs.com", "wsglb0.com", "wsssec.com", "wswebcdn.com", "wswebpic.com", "wtxcdn.com"],
    "weibo":        ["sinaimg.cn", "weibocdn.com"],
    "west":         ["800cdn.com", "vhostgo.com"],
    "wikimedia":    ["wmfusercontent.org"],
    "wix":          ["parastorage.com", "wix.com", "wixsite.com", "wixstatic.com"],
    "wordpress":    ["wordpress.com", "wp.com", "wpengine.com", "wpenginepowered.com"],
    "xycloud":      ["00cdn.com", "p2cdn.com"],
    "yahoo":        ["yahooapis.com", "yimg.com", "yimg.jp"],
    "yandex":       ["yandex.net", "yandex.ru", "yandexcloud.net", "yastatic.net"],
    "yundun":       ["jsd.cc"],
    "yandex":       ["yandex.net", "yandex.ru", "yandexcloud.net", "yastatic.net"],
    "yunaq":        ["jiashule.com", "jiasule.org", "365cyd.cn"],
    "zendesk":      ["zdassets.com", "zendesk.com"],
    "zenlayer":     ["ogslb.com", "uxengine.net", "zenlogic.net"],
    "zscaler":      ["zscaler.com", "zscaler.net", "zscalerone.net", "zscalerthree.net", "zscalertwo.net", "zscloud.net"],
}


CDN_ALIASES = {
    "azure": "microsoft",
    "cloudfront": "amazon",
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
    "cloudflare":   ["server: cloudflare", "cf-ray", "cf-cache-status", "cf-request-id", "cf-connecting-ip"],
    "amazon":       ["x-amz-cf-id", "x-amz-cf-pop"],
    "fastly":       ["x-served-by: cache-", "via: 1.1 varnish", "fastly-io-info", "x-fastly-request-id", "surrogate-key", "fastly-debug-path"],
    "microsoft":    ["server: fbs", "x-msedge-ref", "x-azure-ref", "x-ms-ref", "x-calculatedfetarget", "x-feserver", "server: microsoft-httpapi", 
                        "x-nanoproxy", "x-azure-ref", "x-azure-requestid", "x-msedge-ref", "x-ms-request-id", "x-ms-session-id", "x-ms-routing-name"],
    "akamai":       ["x-check-cacheable", "x-akamai-session-info", "x-akamai-staging", "x-cache-remote", "akamai-cache-status", "akamai-grn", 
                        "x-true-cache-key", "x-cache: tcp_", "akamaitechnologies", "akamaighost", "server: akamainetstorage", "x-akamai-transformed"],
    "sucuri":       ["x-sucuri-id", "x-sucuri-cache", "server: sucuri/cloudproxy"],
    "bunnycdn":     ["server: bunnycdn-", "cdn-pullzone",  "cdn-uid", "cdn-requestid", "cdn-cache", "cdn-cachedat"],
    "keycdn":       ["x-cache: hit keycdn", "x-cache: miss keycdn", "server: keycdn-engine", "x-edge-location: keycdn"],
    "gcore":        ["x-id: ", "server: gcore"],
    "cdn77":        ["x-cdn77-hit", "x-cdn77-cache", "server: cdn77-"],
    "stackpath":    ["x-sp-url", "x-sp-edge", "server: stackpath"],
    "limelight":    ["x-llnw-cache", "x-llnw-request-id"],
    "edgecast":     ["server: ecs ", "x-ec-custom-error", "x-cache: tcp_hit"],
    "google":       ["x-goog-", "via: 1.1 google", "server: gws", "server: gsfe", "server: sffe", "x-google-backends", "x-googlas-appengine"],
    "netflix":      ["x-netflix-", "nflx-", "server: nflx", "x-originating-url"],
    "wikimedia":    ["x-cache: cp", "server: ats", "x-cache-status: hit-front"],
    "roblox":       ["x-roblox-region", "x-roblox-edge", "server: public-gateway"],
    "nextjs":       ["x-nextjs", "x-hex-backend "],
    "google":       ["x-goog-", "via: 1.1 google", "server: gws", "server: gsfe", "server: sffe"],
    "meta":         ["x-fb-debug", "x-fb-trip-id", "server: fbs"],
    "apple":        ["server: applehttp", "x-apple-jingle-", "x-apple-application-site-association", "x-apple-request-uuid"],
    "opera":        ["server: opera"],
    "telegram":     ["server: telegram"],
}

def detect_cdn_from_headers(headers: dict) -> Optional[str]:
    """
    Pure function — takes already-fetched headers dict, no network calls.
    """
    if not headers:
        return None
    header_str = " ".join(
        f"{str(k).lower()}: {str(v).lower()}" for k, v in headers.items()
    )
    for cdn_name, patterns in HEADER_CDN_PATTERNS.items():
        for pat in patterns:
            if pat in header_str:
                return cdn_name
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

def identity_from_text(text: str) -> Optional[str]:
    if not text:
        return None

    text = text.lower()

    identity_keywords = {
        "microsoft": "microsoft", "azure": "microsoft", "msft": "microsoft", "msedge": "microsoft", "msn": "microsoft", "bing": "microsoft", 
            "office365": "microsoft", "skype" : "microsoft", "live" : "microsoft", "google": "google", "googledomains": "google", 
            "googlehosted": "google", "googleusercontent": "google", "gstatic": "google", "1e100": "google", "youtube": "google", 
            "gmail": "google", "doubleclick": "google", "ggpht": "google", "android": "google", "facebook": "meta", "meta platforms": "meta", 
            "fbcdn": "meta", "tfbnw": "meta", "instagram": "meta", "whatsapp": "meta", "fb.me": "meta", "amazon": "amazon", "aws": "amazon", 
            "amzn": "amazon", "cloudfront": "amazon", "apple": "apple", "icloud": "apple", "aaplimg": "apple", "itunes": "apple", 
            "netflix": "netflix", "nflx": "netflix", "wikimedia": "wikimedia", "wikipedia": "wikimedia", "yahoo": "yahoo", "yimg": "yahoo", 
            "tiktok": "tiktok", "bytedance": "tiktok", "roblox": "roblox", "digicert": "digicert", "avast": "avast", "sucuri": "sucuri", 
            "incapsula": "incapsula", "imperva": "incapsula", "cloudflare": "cloudflare", "akamai": "akamai", "edgesuite": "akamai", 
            "edgekey": "akamai", "fastly": "fastly"
    }

    for keyword, identity in identity_keywords.items():
        if keyword in text:
            return identity

    return None

async def fetch_cdn_ip_ranges_async(session: aiohttp.ClientSession) -> dict:
    """Async replacement for fetch_cdn_ip_ranges() — call ONCE at startup"""
    ranges = defaultdict(list)

    def add(cdn, cidr):
        try:
            ranges[cdn].append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass

    # Cloudflare
    try:
        text = await fetch_url_async(session, "https://www.cloudflare.com/ips-v4")
        for line in text.strip().splitlines():
            add("cloudflare", line.strip())
        text = await fetch_url_async(session, "https://www.cloudflare.com/ips-v6")
        for line in text.strip().splitlines():
            add("cloudflare", line.strip())
    except Exception:
        pass

    # CloudFront
    try:
        text = await fetch_url_async(session, "https://ip-ranges.amazonaws.com/ip-ranges.json")
        data = json.loads(text)
        for p in data.get("prefixes", []):
            if p.get("service") == "CLOUDFRONT":
                add("cloudfront", p["ip_prefix"])
        for p in data.get("ipv6_prefixes", []):
            if p.get("service") == "CLOUDFRONT":
                add("cloudfront", p["ipv6_prefix"])
    except Exception:
        pass

    # Google
    for url in ["https://www.gstatic.com/ipranges/goog.json",
                "https://www.gstatic.com/ipranges/cloud.json"]:
        try:
            text = await fetch_url_async(session, url)
            data = json.loads(text)
            for p in data.get("prefixes", []):
                cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                if cidr:
                    add("google", cidr)
        except Exception:
            pass

    return dict(ranges)

def get_ip(domain: str) -> Optional[str]:
    """Resolve domain to its first A record IP."""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return str(next(iter(answers)))
    except Exception:
        return None

def detect_cdn_from_ip(
    ips: list[str],
    cdn_ip_ranges: dict
) -> Optional[str]:
    """
    Pure function — takes already-resolved list of IPs, no DNS calls.
    """
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
            for cdn_name, networks in cdn_ip_ranges.items():
                for network in networks:
                    if ip in network:
                        return cdn_name
        except ValueError:
            continue
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
# CDN owner names as they appear in RDAP records
CDN_ORG_NAMES = {
    "google":     ["google llc", "google inc", "alphabet"],
    "meta":       ["meta platforms", "facebook inc"],
    "microsoft":  ["microsoft corporation"],
    "amazon":     ["amazon technologies", "amazon.com inc"],
    "apple":      ["apple inc"],
    "cloudflare": ["cloudflare inc"],
    "fastly":     ["fastly inc"],
    "akamai":     ["akamai technologies"],
    "netflix":    ["netflix streaming", "netflix inc"],
    "wikimedia":  ["wikimedia foundation"],
}

async def classify_cdn_dynamic(
    cdn_name: str,
    website: str,
    cnames: list[str],
    san_tlds: list[str],
    resolver: aiodns.DNSResolver,
    session: aiohttp.ClientSession,
    website_soa: dict = None,
    website_org: str = None,
    website_ns: list[str] = None
) -> str:
    w_tld = get_tld(website).lower()
    cdn_name_lower = cdn_name.lower()
    
    # Resolve the "Parent Identity" (e.g., 'azure' -> 'microsoft')
    parent_identity = CDN_ALIASES.get(cdn_name_lower, cdn_name_lower)
    
    # 1. Domain/TLD Match (e.g., 'google.com' or 'dns.google')
    if parent_identity in w_tld:
        return "private"

    # 2. Administrative Consensus (The "Android/Gmail" Fix)
    # Check if the detected CDN identity appears in the Website's NS, SOA, or Org record
    ns_text = " ".join(website_ns or []).lower()
    soa_text = json.dumps(website_soa or {}).lower()
    org_text = (website_org or "").lower()
    
    # Combine all ownership signals
    ownership_signals = f"{ns_text} {soa_text} {org_text}"
    
    # If the parent identity (e.g., 'google') is found in the ownership signals, it's private
    if parent_identity in ownership_signals:
        return "private"
    
    # 3. CNAME Suffix Match (Self-hosting check)
    for cname in cnames:
        if get_tld(cname).lower() == w_tld:
            return "private"

    # 4. SAN Match
    if w_tld in san_tlds:
        return "private"

    return "third"
#endregion

#region Measure CDN
#----------------------------------------------------------------------------------
# Measure CDN
#----------------------------------------------------------------------------------
def measure_cdn_findcdn(
    website: str,
    internal_hostnames: set[str],
    cdn_ip_ranges: dict
) -> CDNResult:
    """
    Pure version — only processes findcdn JSON output.
    Classification is handled upstream by process_domain_async.
    Returns CDNResult with cdn_types values set to "findcdn" 
    so the caller knows to reclassify them.
    """
    result = CDNResult(website=website)

    ssl_info     = get_ssl_info(website)
    supports_https = ssl_info.get("supports_https", False) if ssl_info else False

    probes = list({website, f"www.{website}"} | internal_hostnames)

    try:
        resp_json = json.loads(findcdn.main(probes, double_in=True, threads=10))
    except Exception as e:
        logging.warning(f"{website}: findcdn failed — {e}")
        return result

    cdn_cnames: dict[str, list[str]] = defaultdict(list)

    for probe, data in resp_json.get("domains", {}).items():
        for fingerprint in parse_cdn_string(data.get("cdns", "")):
            cdn_name = detect_cdn_from_cname(fingerprint)
            if cdn_name:
                cdn_cnames[cdn_name].append(fingerprint)
            else:
                logging.warning(
                    f"Unknown CDN fingerprint: {fingerprint} (from {probe})"
                )

    # Tag as "findcdn" — process_domain_async will reclassify
    for cdn_name in cdn_cnames:
        result.cdn_types[cdn_name] = "findcdn"

    result.cdns = list(result.cdn_types.keys())
    return result

async def measure_cdn_findcdn_async(domain, internal, cdn_ip_ranges):
    return await asyncio.to_thread(
        measure_cdn_findcdn, domain, internal, cdn_ip_ranges
    )
#endregion

#region async
async def fetch_headers_async(
    session: aiohttp.ClientSession, 
    domain: str, 
    timeout: int = 10
) -> dict:
    """Async replacement for your requests-based header fetch"""
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            async with session.head(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
                ssl=False  # Skip SSL verification for speed at scale
            ) as response:
                return dict(response.headers)
        except Exception:
            continue
    return {}

async def fetch_url_async(
    session: aiohttp.ClientSession, 
    url: str
) -> str:
    """Async replacement for urllib.request.urlopen() — used in fetch_cdn_ip_ranges()"""
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
        return await response.text()
    
async def process_domain_async(session, resolver, domain, cdn_ip_ranges):
    try:
        # --- TIER 1: FAST ASYNC CHECK ---
        cnames_apex, cnames_www, ips_v4, ips_v6, soa, ns_records = await asyncio.gather(
            get_cnames_async(resolver, domain),
            get_cnames_async(resolver, f"www.{domain}"),
            resolve_a_async(resolver, domain),
            resolve_aaaa_async(resolver, domain),
            get_soa_async(resolver, domain),
            get_ns_async(resolver, domain),
            return_exceptions=True
        )

        ips = (ips_v4 if isinstance(ips_v4, list) else []) + (ips_v6 if isinstance(ips_v6, list) else [])
        cnames = list(set((cnames_apex if isinstance(cnames_apex, list) else []) + (cnames_www if isinstance(cnames_www, list) else [])))
        soa = soa if isinstance(soa, dict) else None
        ns_records = ns_records if isinstance(ns_records, list) else []

        headers  = await fetch_headers_async(session, domain)
        ssl_info = await asyncio.to_thread(get_ssl_info, domain)
        san_tlds = ssl_info.get("san_tlds", []) if ssl_info else []
        website_org = await get_domain_org_async(session, domain)

        detected_cdns = {}
        step_id = ""

        # --- STEP 0: INFRASTRUCTURE TLD & KEYWORD CHECK (The "dns.google" Fix) ---
        # If the domain ends in .google, .apple, etc., it is private infra.
        infra_tlds = {".google": "google", ".apple": "apple", ".microsoft": "microsoft", ".netflix": "netflix"}
        for tld, identity in infra_tlds.items():
            if domain.lower().endswith(tld):
                detected_cdns[identity] = "private"
                step_id += "step 0, "

        # If not caught by TLD, check if the domain name itself contains the identity
        if not detected_cdns:
            domain_identity = identity_from_text(domain)
            if domain_identity:
                detected_cdns[domain_identity] = "private"
                step_id += "step 0, "

        # --- STEP 0.25: DOMAIN KEYWORD CHECK ---
        # If the domain name itself contains a known identity, mark it private.
        domain_id = identity_from_text(domain)
        if domain_id:
            detected_cdns[domain_id] = "private"
            step_id += "step .25, "

        # --- STEP 0.5: RDAP ORG CHECK ---
        if website_org:
            org_id = identity_from_text(website_org)
            if org_id and org_id not in detected_cdns:
                detected_cdns[org_id] = await classify_cdn_dynamic(
                    org_id, domain, cnames, san_tlds, resolver, session, 
                    website_soa=soa, website_org=website_org, website_ns=ns_records
                )
                step_id += "step .5, "

        # --- STEP 0.75: NAMESERVER IDENTITY CHECK ---
        ns_id = identity_from_text(" ".join(ns_records))
        if ns_id and ns_id not in detected_cdns:
            detected_cdns[ns_id] = await classify_cdn_dynamic(
                ns_id, domain, cnames, san_tlds, resolver, session, 
                website_soa=soa, website_org=website_org, website_ns=ns_records
            )
            step_id += "step .75, "

        # --- RULES 1-3: CNAME, HEADERS, IP RANGES ---
        for cname in cnames:
            cdn = detect_cdn_from_cname(cname)
            if cdn and cdn not in detected_cdns:
                detected_cdns[cdn] = await classify_cdn_dynamic(
                    cdn, domain, cnames, san_tlds, resolver, session, 
                    website_soa=soa, website_org=website_org, website_ns=ns_records
                )
                step_id += "step 1, "

        cdn = detect_cdn_from_headers(headers)
        if cdn and cdn not in detected_cdns:
            detected_cdns[cdn] = await classify_cdn_dynamic(
                cdn, domain, cnames, san_tlds, resolver, session, 
                website_soa=soa, website_org=website_org, website_ns=ns_records
            )
            step_id += "step 2, "

        cdn = detect_cdn_from_ip(ips, cdn_ip_ranges)
        if cdn and cdn not in detected_cdns:
            detected_cdns[cdn] = await classify_cdn_dynamic(
                cdn, domain, cnames, san_tlds, resolver, session, 
                website_soa=soa, website_org=website_org, website_ns=ns_records
            )
            step_id += "step 3, "

        # --- STEP 4: ASN & PTR ---
        if ips:
            ips_to_check = ips if not detected_cdns else ips[:3]
            for ip in ips_to_check:
                infra_identity = await get_asn_info_async(session, ip)
                if not infra_identity:
                    ptr_name = await get_ptr_async(resolver, ip)
                    infra_identity = identity_from_text(ptr_name) if ptr_name else None

                if infra_identity and infra_identity not in detected_cdns:
                    detected_cdns[infra_identity] = await classify_cdn_dynamic(
                        infra_identity, domain, cnames, san_tlds, resolver, session, 
                        website_soa=soa, website_org=website_org, website_ns=ns_records
                    )
                    step_id += "step 4, "
                    break 

        # --- FINAL RESULT CALCULATION ---
        third_party_cdns = [name for name, c_type in detected_cdns.items() if c_type == "third"]
        private_cdns     = [name for name, c_type in detected_cdns.items() if c_type == "private"]
        
        return CDNResult(
            website=domain,
            cdns=list(detected_cdns.keys()),
            cdn_types=detected_cdns,
            uses_third_party=len(third_party_cdns) > 0,
            critical_dependency=len(third_party_cdns) > 0 and len(private_cdns) == 0,
            redundant=len(detected_cdns) > 1,
            step_ids=step_id
        )

    except Exception as e:
        logging.warning(f"{domain}: failed — {e}")
        return None
#endregion

#region async main
async def main_async():
    input_path  = "src/Source_Data/top-100000-domains.csv"
    output_path = "src/Source_Data/cdn_results_100000.csv"

    with open(input_path, "r", newline="") as f:
        domains = [row["domain"].strip() for row in csv.DictReader(f)]

    connector = aiohttp.TCPConnector(limit=100, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        
        # Fetch IP ranges once at startup
        print("Fetching CDN IP ranges...")
        cdn_ip_ranges = await fetch_cdn_ip_ranges_async(session)
        
        resolver = aiodns.DNSResolver(nameservers=['8.8.8.8', '1.1.1.1'])
        results  = []
        failed   = []

        # Process in batches of 100
        batch_size = 100
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            tasks = [
                process_domain_async(session, resolver, d, cdn_ip_ranges)
                for d in batch
            ]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for domain, result in zip(batch, batch_results):
                if isinstance(result, Exception) or result is None:
                    failed.append(domain)
                else:
                    results.append(result)

            print(f"✅ Batch {i // batch_size + 1} done — "
                  f"{len(results)} succeeded, {len(failed)} failed")
            
            await asyncio.sleep(0.2)  # Brief pause between batches

    # Write results
    with open(output_path, "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["website", "cdns", "cdn_types",
                         "uses_third_party", "critical_dependency", "redundant", "step_id"])
        for r in results:
            writer.writerow([
                r.website,
                "|".join(r.cdns),
                json.dumps(r.cdn_types),
                r.uses_third_party,
                r.critical_dependency,
                r.redundant,
                r.step_ids
            ])

    if failed:
        with open("src/Source_Data/failed_domains.txt", "w") as f:
            f.write("\n".join(failed))

    print(f"\n✅ Complete — {len(results)} processed, {len(failed)} failed")
#endregion

def datavis():
    df = pd.read_csv('src/Source_Data/cdn_results_10000.csv')

    cdns_detected = df[df['cdns'].notna()]['cdns'].str.split(',').explode().str.strip().value_counts()
    print("CDN Detection Summary:")
    print(f"Total Domains: {len(df)}")
    print(f"Domains with CDN Detected: {df['cdns'].notna().sum()}")
    print(f"Domains with NO CDN Detected: {df['cdns'].isna().sum()}")
    print(f"\nTop 15 CDNs by Frequency:")
    print(cdns_detected.head(15))

    # Boolean flags
    print(f"\n--- Boolean Flags ---")
    print(f"Uses Third-Party CDN: {df['uses_third_party'].sum()} ({df['uses_third_party'].sum()/len(df)*100:.1f}%)")
    print(f"Critical Dependency: {df['critical_dependency'].sum()} ({df['critical_dependency'].sum()/len(df)*100:.1f}%)")
    print(f"Redundant CDN: {df['redundant'].sum()} ({df['redundant'].sum()/len(df)*100:.1f}%)")

    # Parse cdn_types (appears to be JSON)
    cdn_type_counts = Counter()
    for val in df['cdn_types']:
        if pd.notna(val) and val != 'null':
            try:
                parsed = json.loads(val.replace("'", '"'))
                for key in parsed.keys():
                    cdn_type_counts[key] += 1
            except:
                pass

    print(f"\n--- CDN Types Distribution ---")
    print(dict(cdn_type_counts.most_common(10)))

    # Create comprehensive visualizations
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('CDN Analysis: 10,000 Domains', fontsize=16, fontweight='bold', y=0.995)

    # --- 1. CDN Detection Rate (Pie Chart) ---
    ax1 = axes[0, 0]
    detected_counts = [df['cdns'].notna().sum(), df['cdns'].isna().sum()]
    colors = ['#2ecc71', '#e74c3c']
    wedges, texts, autotexts = ax1.pie(detected_counts, labels=['CDN Detected', 'No CDN'], 
                                        autopct='%1.1f%%', colors=colors, startangle=90, textprops={'fontsize': 11})
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
    ax1.set_title('CDN Detection Rate', fontsize=12, fontweight='bold', pad=10)

    # --- 2. Top 12 CDNs (Bar Chart) ---
    ax2 = axes[0, 1]
    top_cdns = cdns_detected.head(12)
    bars = ax2.barh(range(len(top_cdns)), top_cdns.values, color='#3498db')
    ax2.set_yticks(range(len(top_cdns)))
    ax2.set_yticklabels(top_cdns.index)
    ax2.set_xlabel('Number of Domains', fontsize=10, fontweight='bold')
    ax2.set_title('Top 12 CDNs by Frequency', fontsize=12, fontweight='bold', pad=10)
    ax2.invert_yaxis()
    for i, (bar, val) in enumerate(zip(bars, top_cdns.values)):
        ax2.text(val + 20, i, str(val), va='center', fontweight='bold', fontsize=9)
    ax2.grid(axis='x', alpha=0.3)

    # --- 3. Critical Infrastructure Dependencies ---
    ax3 = axes[1, 0]
    dep_labels = ['Critical\nDependency', 'No Critical\nDependency']
    dep_counts = [df['critical_dependency'].sum(), (~df['critical_dependency']).sum()]
    colors_dep = ['#e67e22', '#95a5a6']
    bars3 = ax3.bar(dep_labels, dep_counts, color=colors_dep, width=0.6)
    ax3.set_ylabel('Number of Domains', fontsize=10, fontweight='bold')
    ax3.set_title('Critical Dependency Analysis', fontsize=12, fontweight='bold', pad=10)
    ax3.set_ylim(0, max(dep_counts) * 1.15)
    for bar, val in zip(bars3, dep_counts):
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height + 100,
                f'{val}\n({val/len(df)*100:.1f}%)', ha='center', va='bottom', fontweight='bold', fontsize=10)
    ax3.grid(axis='y', alpha=0.3)

    # --- 4. Third-Party vs Redundancy ---
    ax4 = axes[1, 1]
    categories = ['Uses Third-Party', 'Has Redundancy', 'Both']
    third_party = df['uses_third_party'].sum()
    redundant = df['redundant'].sum()
    both = ((df['uses_third_party']) & (df['redundant'])).sum()
    counts_comp = [third_party, redundant, both]
    colors_comp = ['#9b59b6', '#1abc9c', '#f39c12']
    bars4 = ax4.bar(categories, counts_comp, color=colors_comp, width=0.6)
    ax4.set_ylabel('Number of Domains', fontsize=10, fontweight='bold')
    ax4.set_title('Third-Party CDN & Redundancy Metrics', fontsize=12, fontweight='bold', pad=10)
    ax4.set_ylim(0, max(counts_comp) * 1.15)
    for bar, val in zip(bars4, counts_comp):
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 100,
                f'{val}\n({val/len(df)*100:.1f}%)', ha='center', va='bottom', fontweight='bold', fontsize=10)
    ax4.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('src/Source_Data/cdn_analysis_overview.png', dpi=300, bbox_inches='tight')
    print("✓ Chart 1 saved: cdn_analysis_overview.png")
    plt.close()

if __name__ == "__main__":
    asyncio.run(main_async())
    #datavis("src/Source_Data/cdn_results_10000.csv")

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
#if __name__ == "__main__":
    #full thing
    #output = main()

#endregion