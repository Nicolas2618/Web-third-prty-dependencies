import dns.resolver
import re
import csv
import gsan
import gsan

def get_ns(domain: str) -> list[str]:
    """
    gets the nameservers for a specific domain. Uses the dns library installed through a virtual environment that would 
    help us to internally store it for our specific usage. """
    try:
        # Uses the DNS library so that we can get the desired 
        answers = dns.resolver.resolve(domain, 'NS')
        answers_lst = [str(rdata) for rdata in answers]
        return answers_lst
    # returns an empty list if there is not domain available or there are no more DNS to take from.
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
        
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


def get_ns_lst_with_providers():
    """Get DNS records and extract provider names for each domain. It is a function that just calls the """

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

            #print(f"{domain_name}:\n")
            #print(f"  Nameservers: {ns_records}\n")
            #print(f"  Providers: {providers}\n")
    
    return results

def get_lst_of_dns_providers() -> list[str]:
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
    results1 = get_ns_lst_with_providers()
    results2 = get_lst_of_dns_providers()
    results3 = get_big_lst_of_providers_and_counts()
    print("Final Results:", results3)