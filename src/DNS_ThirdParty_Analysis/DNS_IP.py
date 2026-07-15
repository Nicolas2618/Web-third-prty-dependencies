import csv
import requests
import whoisit
import dns.resolver


# Path to your CSV file
CSV_FILE_PATH = "src/Source_Data/top_10000_domains.csv"
OUTPUT_FILE_PATH = "src/Source_Data/Domain_Robustness_Results.csv"

######################################################################################################################
# Checks for the AS and data processing.
######################################################################################################################
whoisit.bootstrap()
RIR_REGION = {
    'arin':    'US/Canada/Caribbean',
    'ripe':    'Europe/Middle East',
    'apnic':   'Asia Pacific',
    'lacnic':  'Latin America',
    'afrinic': 'Africa',
}

def lookup_AS_and_data(ip_address: str) -> dict:
    '''
    Uses te Whoisit library, as well as the requests library to get the entities and who is registered to the specified IP
    address. It gets the organization, the region is the IP located, the notwork address in CIDR Notation '''
    try:
        response = whoisit.ip(ip_address)
        entities = response.get('entities', {})
        registrant = entities.get('registrant', [{}])[0]

        # Try address country first, then org-level country, then give up     
        rir = response.get('rir', '')
        region = registrant.get('address', {}).get('country') or RIR_REGION.get(rir, '')

        # We need to extract the ASN from the network or entities
        # Get the information from the url of stat.ripe.net 
        url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip_address}"
        
        # It uses the requests library from python 
        data = requests.get(url, verify=True).json()
        asns = data.get("data", {}).get("asns", [])
        asn = f"AS{asns[0]['asn']}" if asns else "ASN Not Found"
        
        return {
            "org":     registrant.get('name'),
            "country": region,
            "network": str(response.get('network', '')),
            "rir":     response.get('rir'),
            "asn":     asn,
            }

    # A series of exceptions based on not being supported or simple lookup error. 
    except whoisit.errors.UnsupportedError as e:
        return {"error": f"Unsupported: {e}"}
    except Exception as e:
        return {"error": str(e)}
    
######################################################################################################################
# Checks for domain robustness (both IPv4 and IPv6) addresses.
######################################################################################################################
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
        classification = "Low Robustness"
    elif has_ipv6:
        classification = "Low Robustness"
    else:
        classification = "CNAME Enabled"

    print(f"  Result: {classification}")
    return {"ipv4": ipv4, "ipv6": ipv6, "classification": classification}

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


def obtain_domain_IP():
    rows_to_save = []
    try:
        with open(CSV_FILE_PATH, mode='r', newline='', encoding='utf-8') as file:
            csv_reader = csv.reader(file)

            try:
                next(csv_reader)
            except StopIteration:
                print("Error: The source CSV file is empty.")
                return
            for row in csv_reader:
                if not row or not row[0].strip():
                    continue
            
                domain = row[0].strip()

                dns_result = check_domain_robustness(domain)
                cname = get_cname(f'www.{domain}')

                # Skip domains that don't resolve to any IP address
                if not dns_result['ipv4'] and not dns_result['ipv6'] and not cname:
                    continue

                # This is a binding condition. If the domain contains an IPv4 or IPv6 address, we can search for more information. 
                whois_result = lookup_AS_and_data(dns_result['ipv4']) if dns_result['ipv4'] else {}
                

                rows_to_save.append({
                    "domain":         domain,
                    "ipv4":           dns_result['ipv4'],
                    "ipv6":           dns_result['ipv6'],
                    "classification": dns_result['classification'],
                    "org":            whois_result.get('org'),
                    "region":         whois_result.get('country'),
                    "network":        whois_result.get('network'),
                    "ASN":            whois_result.get('asn'),
                    "CNAME":          cname,
                })

    except FileNotFoundError:
        print(f"Error: The source file '{CSV_FILE_PATH}' was not found.")
        return

    print(f"\n[#] Analysis Complete. Exporting records to: {OUTPUT_FILE_PATH}")
    try:
        fieldnames = ["domain", "ipv4", "ipv6", "classification", "org", "region", "network", "ASN", "CNAME"]
        with open(OUTPUT_FILE_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows_to_save)
        print(f"[✓] Successfully wrote {len(rows_to_save)} rows to the output file.")
    except IOError as e:
        print(f"[✗] File writing error: {e}")

if __name__ == "__main__":
    obtain_domain_IP()