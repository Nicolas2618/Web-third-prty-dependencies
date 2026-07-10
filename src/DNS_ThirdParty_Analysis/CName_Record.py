import csv
import pandas as pd
import dns.resolver

def get_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoNameservers:
        return None
    except Exception:
        return None

def get_mx_records(domain) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [f"{rdata.preference}:{str(rdata.exchange).rstrip('.')}" for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoNameservers:
        return []
    except Exception:
        return []

def get_txt_records(domain) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        return [rdata.to_text().strip('"') for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoNameservers:
        return []
    except Exception:
        return []


def check_domain_robustness(domain) -> bool:
    # Starts with null values and no data. 
    has_ipv4 = False
    has_ipv6 = False
    ipv4 = None
    ipv6 = None

    print(f"\n--- Checking DNS for: {domain} ---")

    # First searches for the IPv4 addresses, which are the most common. Also 
    try:
        ipv4_records = dns.resolver.resolve(domain, 'A')
        for ip in ipv4_records:
            print(f"  IPv4 Address: {ip.to_text()}")
        ipv4 = ipv4_records[0].to_text()
        has_ipv4 = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print("  IPv4 address not found")
    except Exception as e:
        print(f"  Error fetching IPv4: {e}")

    try:
        ipv6_records = dns.resolver.resolve(domain, 'AAAA')
        for ip in ipv6_records:
            print(f"  IPv6 Address: {ip.to_text()}")
        ipv6 = ipv6_records[0].to_text()
        has_ipv6 = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print("  IPv6 address not found")
    except Exception as e:
        print(f"  Error fetching IPv6: {e}")

    if has_ipv4 and has_ipv6:
        classification = "High Robustness"
    elif has_ipv4:
        classification = "Old robustness - low"
    elif has_ipv6:
        classification = "New robustness - low"
    else:
        classification = "CNAME Enabled"

    print(f"  Result: {classification}")
    return {"ipv4": ipv4, "ipv6": ipv6, "classification": classification}


domain = 'www.msftncsi.com.edgesuite.net'
print(check_domain_robustness(domain))