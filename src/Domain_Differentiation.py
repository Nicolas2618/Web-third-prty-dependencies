import re
import csv
import whois
import dns.resolver

# Gets the nameserver of the domain.
def get_ns(domain: str) -> list[str]:
    """
    Gets the nameservers for a specific domain. Uses the dns library installed through a virtual environment that would 
    help us to internally store it for our specific usage. 
    """
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [str(rdata).rstrip('.').lower() for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []

# Gets the provider from the nameserver obtained previously.
def extract_provider(nameserver: str) -> str:
    """
    Extract provider name from a nameserver string. e.g google.com would return google as their provider name.
    """
    # Remove trailing dot and lowercase
    ns = nameserver.rstrip('.').lower()
    nameserver_parts = ns.split('.')

    for part in nameserver_parts:
        match = re.search(r'([a-z]+)', part)
        if match:
            token = match.group(1)
            if token == "ns" or len(token) <= 2 or token == "dns":
                continue
            return token
    return None

def lookup_domain(domain_name: str):
    try:
        domain_info = whois.whois(domain_name)

        # Normalize domain_name — can be a list
        name = domain_info.domain_name
        if isinstance(name, list):
            name = name[0]

        # Normalize creation_date — can be a list
        date = domain_info.creation_date
        if isinstance(date, list):
            date = date[0]

        return {
            "domain_name": name,
            "creation_date": date,
            "name_servers": domain_info.name_servers,
        }

    except Exception as e:
        print(f'Error retrieving WHOIS data for {domain_name}: {e}')
        return None


def main():
    input_path = "src/Source_Data/Cloudflare_Top100_Domains.csv"
    output_path = "src/Source_Data/whois_results.csv"
    
    results = []

    with open(input_path, "r", newline='') as csvfile:
        reader = csv.DictReader(csvfile)  # use DictReader to avoid fragile row[1]

        for row in reader:
            domain_name = row["domain"].strip()
            result = lookup_domain(domain_name)

            # Use DNS for nameservers — more reliable than WHOIS
            name_servers = get_ns(domain_name)

            providers = [extract_provider(ns) for ns in name_servers if ns]

            if result is not None:
                result["name_servers"] = name_servers
                result["provider"] = providers
                results.append(result)
            else:
                results.append({
                    "domain_name": domain_name,
                    "creation_date": None,
                    "name_servers": name_servers,
                    "provider": providers,
                })

    # Write output
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain_name", "creation_date", "name_servers", "org", "provider"])
        for r in results:
            writer.writerow([
                r["domain_name"],
                r["creation_date"],
                ", ".join(str(ns) for ns in r["name_servers"] if ns) if r["name_servers"] else "",
                ", ".join(p for p in r["provider"] if p),
            ])

    print(f"\nDone. Results written to {output_path}")

if __name__ == "__main__":
    main()