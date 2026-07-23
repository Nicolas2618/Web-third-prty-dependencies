#region Imports
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# Imports
#---------------------------------------------------------------------------------------------------------------------------------------------------#
import sys
import aiodns
import asyncio
import subprocess
import aiohttp
import ssl
import socket
import json
import csv
import re
import logging
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional
import tldextract
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
#endregion

# Fix for Windows ProactorEventLoop "ConnectionResetError"
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

#region Data Classes
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# Data Classes
#---------------------------------------------------------------------------------------------------------------------------------------------------#
@dataclass
class CDNResult:
    website: str
    cdns: list[str] = field(default_factory=list)
    cdn_types: dict[str, str] = field(default_factory=dict)
    uses_third_party: bool = False
    critical_dependency: bool = False
    redundant: bool = False
    multiple_third: bool = False
    step_ids: str = ""
#endregion

#region Async Helpers
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# Async Helpers
#---------------------------------------------------------------------------------------------------------------------------------------------------#
async def _query_record(resolver, domain: str, record_type: str):
    if hasattr(resolver, "query_dns"):
        return await resolver.query_dns(domain, record_type)
    if hasattr(resolver, "query"):
        return await resolver.query(domain, record_type)
    raise AttributeError("DNS resolver does not support query_dns() or query()")


def _normalise_answer(result) -> list:
    if result is None:
        return []
    if hasattr(result, "answer"):
        return list(result.answer or [])
    if isinstance(result, list):
        return result
    return [result]


async def get_soa_async(resolver: aiodns.DNSResolver, domain: str) -> dict:
    try:
        res = await _query_record(resolver, domain, 'SOA')
        records = _normalise_answer(res)
        if not records:
            return None
        data = getattr(records[0], "data", None)
        if data is None:
            return None
        return {
            "mname": (getattr(data, "mname", None) or "").rstrip('.').lower(),
            "rname": (getattr(data, "rname", None) or "").rstrip('.').lower(),
        }
    except Exception:
        return None

async def get_cnames_async(resolver: aiodns.DNSResolver, domain: str) -> list[str]:
    cnames = []
    current = domain
    try:
        for _ in range(10):
            res = await _query_record(resolver, current, 'CNAME')
            records = _normalise_answer(res)
            if not records:
                break
            record = records[0]
            data = getattr(record, "data", None)
            cname = getattr(data, "cname", None) or getattr(record, "cname", None)
            if not cname:
                break
            cname = cname.rstrip('.')
            cnames.append(cname)
            current = cname
    except Exception:
        pass
    return cnames

async def resolve_a_async(resolver: aiodns.DNSResolver, domain: str) -> list[str]:
    try:
        res = await _query_record(resolver, domain, 'A')
        records = _normalise_answer(res)
        return [
            getattr(getattr(r, "data", None), "address", None) or getattr(r, "host", None)
            for r in records
            if getattr(getattr(r, "data", None), "address", None) or getattr(r, "host", None)
        ]
    except Exception as e:
        if "returned answer with no data" not in str(e) and "not found" not in str(e):
            print(f"[DNS ERROR] {domain}: {e}")
        return []

async def resolve_aaaa_async(resolver: aiodns.DNSResolver, domain: str) -> list[str]:
    try:
        res = await _query_record(resolver, domain, 'AAAA')
        records = _normalise_answer(res)
        return [
            getattr(getattr(r, "data", None), "address", None) or getattr(r, "host", None)
            for r in records
            if getattr(getattr(r, "data", None), "address", None) or getattr(r, "host", None)
        ]
    except Exception:
        return []

async def get_ns_async(resolver: aiodns.DNSResolver, domain: str) -> list[str]:
    try:
        res = await _query_record(resolver, domain, "NS")
        records = _normalise_answer(res)
        return [
            (getattr(getattr(r, "data", None), "host", None) or getattr(r, "host", None) or "").rstrip(".").lower()
            for r in records
            if (getattr(getattr(r, "data", None), "host", None) or getattr(r, "host", None))
        ]
    except Exception:
        return []

async def get_ptr_async(resolver, ip):
    try:
        reversal = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        res = await _query_record(resolver, reversal, 'PTR')
        records = _normalise_answer(res)
        if not records:
            return None
        data = getattr(records[0], "data", None)
        ptrname = getattr(data, "ptrname", None) or getattr(records[0], "ptrname", None)
        return ptrname.lower() if ptrname else None
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
                    if vcard and isinstance(vcard, list) and len(vcard) > 1:
                        for entry in vcard[1]:
                            if isinstance(entry, list):
                                # Check both 'fn' (Full Name) and 'org' (Organization)
                                if entry[0] in ["fn", "org"]:
                                    val = entry[3]
                                    if val: return val.lower()
                    
                    # Fallback: Check top-level entity remarks or roles if vcard is missing
                    if "remarks" in entity:
                        return json.dumps(entity["remarks"]).lower()
    except Exception:
        pass
    return None

async def fetch_headers_async(
    session: aiohttp.ClientSession, 
    domain: str, 
    timeout: int = 10
) -> dict:
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            # Using GET but with a short timeout and no body download if possible
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
                ssl=False
            ) as response:
                # We only need the headers, so we don't await response.text()
                return dict(response.headers)
        except Exception:
            continue
    return {}

async def fetch_url_async(session: aiohttp.ClientSession, url: str) -> str:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
        "Accept-Encoding": "identity" 
    }
    try:
        # Ensure 'headers=headers' is inside this call
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
            if response.status != 200:
                return ""
            return await response.text()
    except Exception:
        return ""
#endregion

#region Basic Helpers
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# Basic Helpers
#---------------------------------------------------------------------------------------------------------------------------------------------------#
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

#region CDN Constants
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# CDN Constants
#---------------------------------------------------------------------------------------------------------------------------------------------------#
CDN_CNAME_PATTERNS = {
    # ---------------------------------------------------------------------------
    # CNAME-to-CDN map
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
    "bunnycdn":     ["server: bunnycdn-", "cdn-pullzone",  "cdn-uid", "cdn-requestid", "cdn-cache", "cdn-cachedat", "server: bunnycdn", "x-b-cache", "x-b-edge"],
    "keycdn":       ["x-cache: hit keycdn", "x-cache: miss keycdn", "server: keycdn-engine", "x-edge-location: keycdn"],
    "gcore":        ["x-id: ", "server: gcore"],
    "cdn77":        ["x-cdn77-hit", "x-cdn77-cache", "server: cdn77-"],
    "stackpath":    ["x-sp-url", "x-sp-edge", "server: stackpath"],
    "limelight":    ["x-llnw-cache", "x-llnw-request-id"],
    "edgecast":     ["server: ecs ", "x-ec-custom-error", "x-cache: tcp_hit", "server: ecd"],
    "google":       ["x-goog-", "via: 1.1 google", "server: gws", "server: gsfe", "server: sffe", "x-google-backends", "x-googlas-appengine", "server: upload-gws"],
    "netflix":      ["x-netflix-", "nflx-", "server: nflx", "x-originating-url", "via: 1.1 nflx"],
    "bunnycdn":     [],
    "wikimedia":    ["x-cache: cp", "server: ats", "x-cache-status: hit-front"],
    "roblox":       ["x-roblox-region", "x-roblox-edge", "server: public-gateway"],
    "nextjs":       ["x-nextjs", "x-hex-backend "],
    "google":       ["x-goog-", "via: 1.1 google", "server: gws", "server: gsfe", "server: sffe"],
    "meta":         ["x-fb-debug", "x-fb-trip-id", "server: fbs"],
    "apple":        ["server: applehttp", "x-apple-jingle-", "x-apple-application-site-association", "x-apple-request-uuid"],
    "opera":        ["server: opera"],
    "telegram":     ["server: telegram"],
}

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
#endregion

#region CDN Helpers
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# CDN Helpers
#---------------------------------------------------------------------------------------------------------------------------------------------------#
def detect_cdn_from_cname(cname: str) -> Optional[str]:
    """Map a CNAME to a CDN name using the pattern table."""
    cname_lower = cname.lower()
    for cdn_name, patterns in CDN_CNAME_PATTERNS.items():
        for pat in patterns:
            if cname_lower.endswith(pat) or pat in cname_lower:
                return cdn_name
    return None

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

def detect_cdn_from_ns(ns_records: list[str]) -> Optional[str]:
    """Map Nameserver hostnames to CDN providers."""
    if not ns_records:
        return None
    
    ns_str = " ".join(ns_records).lower()
    
    # Specific NS patterns that indicate CDN/Managed Infra
    ns_patterns = {
        "cloudflare": ["cloudflare.com"],
        "amazon":     ["awsdns", "cloudfront.net"],
        "akamai":     ["akamai.net", "akadns.net", "edgesuite.net"],
        "google":     ["googledomains.com", "google.com"],
        "microsoft":  ["azure-dns", "msedge.net"],
        "fastly":     ["fastly.net"],
        "oracle":     ["dynect.net"],
        "verisign":   ["verisign-grs.com"],
    }
    
    for cdn, patterns in ns_patterns.items():
        for pat in patterns:
            if pat in ns_str:
                return cdn
    return None

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
        "edgekey": "akamai", "fastly": "fastly", "edgecast": "edgecast", "verizon": "edgecast", "bunny": "bunnycdn", "gcore": "gcore",
        "leaseweb": "leaseweb", "stackpath": "stackpath", "highwinds": "edgecast", "llnw": "limelight", "limelight": "limelight"
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

    #Microsoft
    if "microsoft" not in ranges:
        # Common Azure/Microsoft Edge ranges to ensure Rule 3 works
        msft_seeds = ["13.64.0.0/11", "40.74.0.0/15", "52.145.0.0/16", "104.40.0.0/13"]
        for cidr in msft_seeds:
            add("microsoft", cidr)

    return dict(ranges)

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
#endregion

#region CDN Classifier
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# CDN Classifier
#---------------------------------------------------------------------------------------------------------------------------------------------------#
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
    
    # 2. Reverse Pattern Match (e.g., is 'facebook.com' a known domain for 'meta'?)
    if parent_identity in CDN_CNAME_PATTERNS:
        for pat in CDN_CNAME_PATTERNS[parent_identity]:
            if pat in w_tld or w_tld in pat:
                return "private"

    # 3. Ownership Verification
    if website_org:
        org_text = website_org.lower()
        # Check against known official owner names
        if parent_identity in CDN_ORG_NAMES:
            for official_name in CDN_ORG_NAMES[parent_identity]:
                if official_name in org_text:
                    return "private"
        
        # Fallback: If the parent identity keyword is in the Org name (e.g., "Google" in "Google LLC")
        if parent_identity in org_text:
            return "private"
    
    # 4. CNAME Suffix Match (Self-hosting check)
    for cname in cnames:
        if get_tld(cname).lower() == w_tld:
            return "private"

    # 5. SAN Match
    if w_tld in san_tlds:
        return "private"

    return "third"
#endregion

#region Process Domain
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# Process Domain
#---------------------------------------------------------------------------------------------------------------------------------------------------#
async def process_domain_async(session, resolver, domain, cdn_ip_ranges):
    base_domain = domain[4:] if domain.lower().startswith("www.") else domain
    
    try:
        # --- TIER 1: FAST ASYNC CHECK ---
        # Use base_domain here to ensure we check apex and www correctly
        cnames_apex, cnames_www, ips_v4, ips_v6, soa, ns_records = await asyncio.gather(
            get_cnames_async(resolver, base_domain),
            get_cnames_async(resolver, f"www.{base_domain}"),
            resolve_a_async(resolver, base_domain),
            resolve_aaaa_async(resolver, base_domain),
            get_soa_async(resolver, base_domain),
            get_ns_async(resolver, base_domain),
            return_exceptions=True
        )
        step_id = ""

        ips = (ips_v4 if isinstance(ips_v4, list) else []) + (ips_v6 if isinstance(ips_v6, list) else [])
        cnames = list(set((cnames_apex if isinstance(cnames_apex, list) else []) + (cnames_www if isinstance(cnames_www, list) else [])))
        soa = soa if isinstance(soa, dict) else None
        ns_records = ns_records if isinstance(ns_records, list) else []

        headers  = await fetch_headers_async(session, domain)
        ssl_info = await asyncio.to_thread(get_ssl_info, domain)
        san_tlds = ssl_info.get("san_tlds", []) if ssl_info else []
        ca_name  = ssl_info.get("ca_name", "") if ssl_info else ""
        website_org = await get_domain_org_async(session, domain)

        detected_cdns = {}
        
        # --- STEP 1: TRUE OWNERSHIP CHECK (TLD & Domain Name) ---
        # Only mark as private here if the domain itself is a known infrastructure domain.
        infra_tlds = {".google": "google", ".apple": "apple", ".microsoft": "microsoft", ".netflix": "netflix"}
        
        for tld, identity in infra_tlds.items():
            if domain.lower().endswith(tld):
                detected_cdns[identity] = "private"
                step_id += "step 1, "
                break
        
        # --- STEP 2: Check if the domain is a known CDN-owned domain (e.g., fbcdn.net) ---
        if not detected_cdns:
            for cdn_id, patterns in CDN_CNAME_PATTERNS.items():
                if any(pat == base_domain for pat in patterns):
                    detected_cdns[cdn_id] = "private"
                    step_id += "step 2, "
                    break

        # --- STEP 3: DOMAIN KEYWORD CLASSIFICATION ---
        domain_id = identity_from_text(domain)
        if domain_id and domain_id not in detected_cdns:
            detected_cdns[domain_id] = await classify_cdn_dynamic(
                domain_id, domain, cnames, san_tlds, resolver, session, 
                website_soa=soa, website_org=website_org, website_ns=ns_records
            )
            step_id += "step 3, "

        # --- STEP 4: NAMESERVER PATTERN CHECK ---
        # Check NS records for specific CDN patterns
        ns_cdn = detect_cdn_from_ns(ns_records)
        if ns_cdn and ns_cdn not in detected_cdns:
            detected_cdns[ns_cdn] = await classify_cdn_dynamic(
                ns_cdn, domain, cnames, san_tlds, resolver, session, 
                website_soa=soa, website_org=website_org, website_ns=ns_records
            )
            step_id += "step 4 (NS), "

        # --- STEP 5: SOA PATTERN CHECK ---
        # Check SOA Mname (Primary Master) for CDN identity
        if soa and soa.get("mname"):
            soa_id = identity_from_text(soa["mname"])
            if soa_id and soa_id not in detected_cdns:
                detected_cdns[soa_id] = await classify_cdn_dynamic(
                    soa_id, domain, cnames, san_tlds, resolver, session, 
                    website_soa=soa, website_org=website_org, website_ns=ns_records
                )
                step_id += "step 5 (SOA), "

        # --- RULES 6: CNAME ---
        # In process_domain_async, replace your Step 1 loop with this:
        for cname in cnames:
            cname_clean = cname.rstrip(".")  # DNS trailing dot fix
            cdn = detect_cdn_from_cname(cname_clean)
            if cdn and cdn not in detected_cdns:
                detected_cdns[cdn] = await classify_cdn_dynamic(
                    cdn, domain, cnames, san_tlds, resolver, session,
                    website_soa=soa, website_org=website_org, website_ns=ns_records
                )
                step_id += "step 6, "

        # --- RULES 7: HEADERS ---
        cdn = detect_cdn_from_headers(headers)
        if cdn and cdn not in detected_cdns:
            detected_cdns[cdn] = await classify_cdn_dynamic(
                cdn, domain, cnames, san_tlds, resolver, session, 
                website_soa=soa, website_org=website_org, website_ns=ns_records
            )
            step_id += "step 7, "

        # --- RULES 8: IP RANGES ---
        cdn = detect_cdn_from_ip(ips, cdn_ip_ranges)
        if cdn and cdn not in detected_cdns:
            detected_cdns[cdn] = await classify_cdn_dynamic(
                cdn, domain, cnames, san_tlds, resolver, session, 
                website_soa=soa, website_org=website_org, website_ns=ns_records
            )
            step_id += "step 8, "

        # --- STEP 9: ASN & PTR ---
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
                    step_id += "step 9, "
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
            multiple_third = len(third_party_cdns) > 1,
            step_ids=step_id
        )

    except Exception as e:
        logging.warning(f"{domain}: failed — {e}")
        return None
#endregion

#region Main
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# Main
#---------------------------------------------------------------------------------------------------------------------------------------------------#
async def main_async():
    input_path  = "src/Source_Data/top_domains/top-100000-domains.csv" 
    output_path = "src/Source_Data/cdn_results/cdn_results_100000.csv"

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
                         "uses_third_party", "critical_dependency", "redundant", "mult_third", "step_id"])
        for r in results:
            writer.writerow([
                r.website,
                "|".join(r.cdns),
                json.dumps(r.cdn_types),
                r.uses_third_party,
                r.critical_dependency,
                r.redundant,
                r.multiple_third,
                r.step_ids
            ])

    if failed:
        with open("src/Source_Data/failed_domains.txt", "w") as f:
            f.write("\n".join(failed))

    print(f"\n✅ Complete — {len(results)} processed, {len(failed)} failed")
#endregion

#region Data Visualization
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# Data Visualization
#---------------------------------------------------------------------------------------------------------------------------------------------------#
def four_corners_graph():
    df = pd.read_csv('src/Source_Data/cdn_results_1000 2.csv')

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
    fig.suptitle('CDN Analysis: 1,000 Domains', fontsize=25, fontweight='bold', y=0.995)

    # --- 1. CDN Detection Rate (Pie Chart) ---
    ax1 = axes[0, 0]
    detected_counts = [df['cdns'].notna().sum(), df['cdns'].isna().sum()]
    colors = ['#2ecc71', '#e74c3c']
    wedges, texts, autotexts = ax1.pie(detected_counts, labels=['CDN Detected', 'No CDN'], 
                                        autopct='%1.1f%%', colors=colors, startangle=90, textprops={'fontsize': 18})
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
    ax1.set_title('CDN Detection Rate', fontsize=20, fontweight='bold', pad=10)

    # --- 2. Top 12 CDNs (Bar Chart) ---
    ax2 = axes[0, 1]
    top_cdns = cdns_detected.head(12)
    bars = ax2.barh(range(len(top_cdns)), top_cdns.values, color='#3498db')
    ax2.set_yticks(range(len(top_cdns)))
    ax2.set_yticklabels(top_cdns.index, fontsize=15)
    ax2.set_xlabel('Number of Domains', fontsize=15, fontweight='bold')
    ax2.set_title('Top 12 CDNs by Frequency', fontsize=18, fontweight='bold', pad=10)
    ax2.invert_yaxis()
    for i, (bar, val) in enumerate(zip(bars, top_cdns.values)):
        ax2.text(val + 20, i, str(val), va='center', fontweight='bold', fontsize=15)
    ax2.grid(axis='x', alpha=0.3)

    # --- 3. Critical Infrastructure Dependencies ---
    ax3 = axes[1, 0]
    dep_labels = ['Critical\nDependency', 'No Critical\nDependency']
    dep_counts = [df['critical_dependency'].sum(), (~df['critical_dependency']).sum()]
    colors_dep = ['#e67e22', '#95a5a6']
    bars3 = ax3.bar(dep_labels, dep_counts, color=colors_dep, width=0.6)
    ax3.tick_params(axis='x', labelsize=14)
    ax3.set_ylabel('Number of Domains', fontsize=15, fontweight='bold')
    ax3.set_title('Critical Dependency Analysis', fontsize=18, fontweight='bold', pad=10)
    ax3.set_ylim(0, max(dep_counts) * 1.15)
    for bar, val in zip(bars3, dep_counts):
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height - 100,
                f'{val}\n({val/len(df)*100:.1f}%)', ha='center', va='bottom', fontweight='bold', fontsize=20)
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
    ax4.tick_params(axis='x', labelsize=14)
    ax4.set_ylabel('Number of Domains', fontsize=15, fontweight='bold')
    ax4.set_title('Third-Party CDN & Redundancy Metrics', fontsize=18, fontweight='bold', pad=10)
    ax4.set_ylim(0, max(counts_comp) * 1.15)
    for bar, val in zip(bars4, counts_comp):
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height - 100,
                f'{val}\n({val/len(df)*100:.1f}%)', ha='center', va='bottom', fontweight='bold', fontsize=20)
    ax4.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('src/Source_Data/cdn_datavis/cdn_1000_analysis_overview.png', dpi=300, bbox_inches='tight')
    print("✓ Chart 1 saved: cdn_analysis_overview.png")
    plt.close()

def four_bar_cdn():
    dfs = [
        pd.read_csv("src/Source_Data/cdn_results/cdn_results_100.csv"),
        pd.read_csv("src/Source_Data/cdn_results/cdn_results_1000.csv"),
        pd.read_csv("src/Source_Data/cdn_results/cdn_results_10000.csv"),
        pd.read_csv("src/Source_Data/cdn_results/cdn_results_100000.csv")
    ]

    ranks = ["100", "1000", "10000", "100000"]

    third_party = []
    critical = []
    redundancy = []
    multiple = []

    for df in dfs:
        n = len(df)

        # Percentages
        third_party.append(df["uses_third_party"].mean() * 100)
        critical.append(df["critical_dependency"].mean() * 100)
        redundancy.append(df["redundant"].mean() * 100)
        multiple.append(df["mult_third"].mean() * 100)

    x = np.arange(len(ranks))
    width = 0.18

    fig, ax = plt.subplots(figsize=(8,6))

    b1 = ax.bar(x - 1.5*width, third_party, width,
                label="3rd Party Dependency",
                hatch="///",
                edgecolor="black",
                color="white")

    b2 = ax.bar(x - 0.5*width, critical, width,
                label="Critical Dependency",
                hatch="\\\\\\\\",
                edgecolor="black",
                color="white")

    b3 = ax.bar(x + 0.5*width, redundancy, width,
                label="Redundancy",
                hatch="++",
                edgecolor="black",
                color="white")

    b4 = ax.bar(x + 1.5*width, multiple, width,
                label="Multiple 3rd",
                hatch="....",
                edgecolor="black",
                color="white")

    ax.set_xticks(x)
    ax.set_xticklabels(ranks)
    ax.set_xlabel("Cloudflare Rank", fontsize=12)
    ax.set_ylabel("Percentage of Websites", fontsize=12)
    ax.set_ylim(0, 100)

    ax.legend(loc="upper left", ncol=2)

    # Add values above bars
    for bars in [b1, b2, b3, b4]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2,
                    h + 1,
                    f"{h:.1f}",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                    rotation=90)

    plt.tight_layout()
    plt.savefig("src/Source_Data/cdn_datavis/cdn_four_bar.png", dpi=300)
    plt.show()
#endregion

#region Runner
#---------------------------------------------------------------------------------------------------------------------------------------------------#
# Runner
#---------------------------------------------------------------------------------------------------------------------------------------------------#
if __name__ == "__main__":
    #asyncio.run(main_async())
    #four_corners_graph()
    four_bar_cdn()
#endregion