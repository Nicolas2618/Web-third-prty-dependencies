import dns.resolver
import re
def get_ns(domain: str) -> list[str]:
    """Get the nameservers for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []

def extract_provider(domain_name : str) -> str:
    """ extract the provider name (e.g apple, aws, google, etc.)"""
    ns = domain_name.rstrip('.')

    match = re.search(r'([a-z]+)', ns.split('.')[1])

    return match.group(1) if match else None




def get_ns_lst():
    dns_lst = ["google.com", "github.com", "googleapis.com", "cloudflare.com", "gstatic.com", "apple.com", "microsoft.com",
    "facebook.com", "amazonaws.com", "googlevideo.com", "fbcdn.net", "amazon.com", "youtube.com", "instagram.com", "whatsapp.net",
    "live.com", "doubleclick.net", "bing.com", "apple-dns.net", "netflix.com", "akadns.net", "ntp.org", "googleusercontent.com",
    "icloud.com", "googlesyndication.com", "cdninstagram.com", "chatgpt.com", "cloudflare-dns.com", "akamai.net", "aaplimg.com",
    "tiktokcdn.com", "tiktokv.com", "cloudfront.net", "ui.com", "ytimg.com", "akamaiedge.net", "edgcdn.net", "yahoo.com",
    "gvt2.com", "spotify.com", "fastly.net", "samsung.com", "roblox.com", "baidu.com", "office.com", "sentry.io",
    "wikipedia.org", "criteo.com", "app-analytics-services.com", "app-measurement.com", "gvt1.com", "prodregistryv2.org",
    "steamserver.net", "dns.google", "one.one", "google-analytics.com", "msftncsi.com", "snapchat.com", "applovin.com",
    "3gppnetwork.org", "appsflyersdk.com", "trafficmanager.net", "azure.com", "whatsapp.com", "googletagmanager.com",
    "windows.com", "amazon-adsystem.com", "msn.com", "googleadservices.com", "ggpht.com", "oxylabs.io", "amazon.dev",
    "linkedin.com", "windows.net", "unity3d.com", "microsoftonline.com", "a2z.com", "adtrafficquality.google", "xiaomi.com",
    "playstation.net", "skype.com", "rubiconproject.com", "capcutapi.com", "vungle.com", "msftconnecttest.com",
    "taboola.com", "windowsupdate.com", "digicert.com", "gmail.com", "cloud.microsoft", "qq.com", "tiktok.com", "aws.dev",
    "miui.com", "cdn-apple.com", "pubmatic.com", "adsrvr.org", "avast.com", "avsxappcaptiveportal.com", "android.com",
    "reddit.com",]

    results = {}
    for domain in dns_lst:
        ns_records = get_ns(domain)
        results[domain] = ns_records
        print(f"{domain}: {ns_records}")

    return results