import dns.resolver
import re

def get_ns(domain: str) -> list[str]:
    """
    gets the nameservers for a specific domain. Uses the dns library installed through a virtual environment that would 
    help us to internally store it for our specific usage. """
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        answers_lst = [str(rdata) for rdata in answers]
        return answers_lst
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
        
def extract_provider(nameserver: str) -> str:
    """Extract provider name from a nameserver string."""
    # Remove trailing dot
    ns = nameserver.rstrip('.')

    nameserver_parts = ns.split('.')

    # Examples: 'awsdns-43' -> 'awsdns', 'apple' -> 'apple', 'google' -> 'google'
    for part in nameserver_parts:
        match = re.search(r'([a-z]+)', part)

        if match:
            token = match.group(1)
            if token == "ns" or len(token) <= 2 or token == "dns":
                continue
            return token

    return None

######################################################## Example Usage ##########################################

def get_ns_lst_with_providers():
    """Get DNS records and extract provider names for each domain."""

    dns_lst = ['netflix.com']
    
    '''dns_lst = ["google.com", "github.com", "googleapis.com", "cloudflare.com", "gstatic.com",
    "apple.com", "microsoft.com", "facebook.com", "amazonaws.com", "googlevideo.com",
    "fbcdn.net", "amazon.com", "youtube.com", "instagram.com", "whatsapp.net",
    "live.com", "doubleclick.net", "bing.com", "apple-dns.net", "netflix.com",
    "akadns.net", "ntp.org", "googleusercontent.com", "icloud.com", "googlesyndication.com",
    "cdninstagram.com", "chatgpt.com", "cloudflare-dns.com", "akamai.net", "aaplimg.com",
    "tiktokcdn.com", "tiktokv.com", "cloudfront.net", "ui.com", "ytimg.com",
    "akamaiedge.net", "edgcdn.net", "yahoo.com", "gvt2.com"]'''
    
    results = {}
    for domain in dns_lst:
        ns_records = get_ns(domain)
        providers = [extract_provider(ns) for ns in ns_records if ns]
        results[domain] = {
            'nameservers': ns_records,
            'providers': providers
        }
        print(f"{domain}:\n")
        print(f"  Nameservers: {ns_records}\n")
        print(f"  Providers: {providers}\n")
    
    return results


# Example usage
if __name__ == "__main__":
    results = get_ns_lst_with_providers()
    print("Final Results:", results)


   