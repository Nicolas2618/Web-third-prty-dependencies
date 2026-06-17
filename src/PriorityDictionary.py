import re
import csv
import tldextract
import pandas as pd
import dns.resolver

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
        ext = tldextract.TLDExtract(cache_dir=None)(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return hostname
    except ImportError:
        parts = hostname.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    

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
        return "managed by third party", f"SOA rname points to: {provider}"
    
    return "no rule matched"



def main():
    input_path  = "src/Source_Data/Cloudflare_Top100_Domains.csv"
    output_path = "src/Source_Data/soa_results.csv"

    results = []

    with open(input_path, "r", newline='') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            domain_name = row["domain"].strip()
            soa         = get_soa(domain_name)
            ns_type, reason = classify_by_soa(domain_name, soa)

            print(f"Domain:  {domain_name}")
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
    
