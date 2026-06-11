import dns.resolver
import re
import csv

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

    # gets the information from the uploaded csv file with all the domains. 
    with open("src/Source_Data/Cloudflare_Top100_Domains.csv", "r", newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)

        #for row in reader:
            #print(row)
        
        results = {}
        for row in reader:
            domain_name = row[1]

            ns_records = get_ns(domain_name)

            providers = [extract_provider(ns) for ns in ns_records if ns]
            #print(f'{providers}')
            results[domain_name] = {
            'nameservers': ns_records,
            'providers': providers
        }

            print(f"{domain_name}:\n")
            print(f"  Nameservers: {ns_records}\n")
            print(f"  Providers: {providers}\n")
    
    return results

if __name__ == "__main__":
    results = get_ns_lst_with_providers()
    print("Final Results:", results)

def get_lst_of_dns_providers():
    results = []
    with open("src/Source_Data/Cloudflare_Top100_Domains.csv", "r", newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            domain_name = row[1]
            ns_records = get_ns(domain_name)
            providers = [extract_provider(ns) for ns in ns_records if ns]
            results.append(providers)
    return results
            
if __name__ == "__main__":
    results = get_lst_of_dns_providers()
    print("Final Results:", results)

def get_big_lst_of_providers_and_counts():
    """Get a list of dns providers and their counts from the csv file."""
    providernestedlist = get_lst_of_dns_providers()
    provider_counts = {}

    for providerlst in providernestedlist:
        for provider in providerlst:
            if provider in provider_counts:
                provider_counts[provider] += 1
            else:
                provider_counts[provider] = 1

    return provider_counts

if __name__ == "__main__":
    results = get_big_lst_of_providers_and_counts()
    print("Final Results:", results)