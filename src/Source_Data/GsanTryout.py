import dns.resolver
import ssl
import OpenSSL
import re

def get_soa_record(tld_domain):
    try:
        # Resolve the SOA record for the given domain/TLD
        answers = dns.resolver.resolve(tld_domain, 'SOA')
        
        for rdata in answers:
            print(f"Primary Name Server: {rdata.mname}")
            print(f"Hostmaster: {rdata.rname}")
            print(f"Serial Number: {rdata.serial}")
            print(f"Refresh: {rdata.refresh}")
            print(f"Retry: {rdata.retry}")
            print(f"Expire: {rdata.expire}")
            print(f"Minimum TTL: {rdata.minimum}")
            print("-" * 35)
            
    except dns.resolver.NXDOMAIN:
        print(f"Error: The domain {tld_domain} does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example: Checking the SOA for the .com TLD
get_soa_record("net")


def get_ssl_info(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        expiredate = str(x509.get_notAfter())
        date = f"{expiredate[4:6]}-{expiredate[6:8]}-{expiredate[:4]}"  # Format to MM-DD-YYYY
        issuer = str(x509.get_issuer())
        issuer = re.search("CN=[a-zA-Z0-9\s'-]+", issuer).group(0).replace("'", "") if issuer else "n/a"
        return date, issuer
    except Exception as e:
        return "n/a", str(e)

