import csv
import dns.resolver

def get_cname(domain):

    try: 
        answers = dns.resolver.resolve(domain, 'CNAME')

        for rdata in answers:
            print(f'Target: {rdata.target}')
            return str(rdata.target)
        
    except dns.resolver.NoAnswer:
        print(f"No CNAME record for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f'The domain {domain} does not exist')
    except Exception as e:
        print(f"an error ocurred: {e}")


def process_domains_from_file(filepath):
    results = {}
    private = []

    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        domains = [row['domain'] for row in reader]

    for domain in domains:
        print(f"\nLooking up: {domain}")
        cname = get_cname(f'www.{domain}')

        if cname is None:
            private.append(domain)

        results[domain] = cname

    print(f'{private}')
    return results


results = process_domains_from_file("src/Source_Data/Cloudflare_Top100_Domains.csv")