'''import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("src/Source_Data/Cloudflare_Top100_Domains.csv")
# Automatically assign index to the 
#print(df.to_string())

new = df["categories"].value_counts()

top_categories = new.head()

#print(f'{new}')

top_categories.plot()

plt.show()'''

import whois

def normalize_whois_string(value) -> Optional[str]:
    if isinstance(value, (list, tuple)):
        for item in value:
            normalized = normalize_whois_string(item)
            if normalized:
                return normalized
        return None
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    text = re.sub(r"[^a-z0-9]+", " ", text).strip()
    return text if text else None

def extract_org(info) -> Optional[str]:
    return normalize_whois_string(getattr(info, "org", None))

# Terms that are too generic to use for reliable WHOIS ownership matching.
# This helps avoid false positive token matches like "Inc", "LLC", or "Registrar".
WHOIS_STOP_WORDS = {
    "inc", "ltd", "llc", "corp", "corporation", "company", "co", "limited",
    "the", "domain", "registrar", "name", "tag", "department", "legal",
    "services", "service", "group", "incorporated", "technology", "systems",
}

def whois_identity_keys(info) -> set[str]:
    # Collect normalized WHOIS owner fields as exact identity strings.
    # These are used for a strict match when both sides expose the same normalized value.
    keys: set[str] = set()
    for field_name in ("org", "name", "registrar"):
        value = normalize_whois_string(getattr(info, field_name, None))
        if value:
            keys.add(value)
    return keys

def whois_identity_terms(info) -> set[str]:
    # Collect normalized WHOIS tokens from owner fields.
    # This supports partial token overlap when exact WHOIS strings are absent.
    terms: set[str] = set()
    for field_name in ("org", "name", "registrar"):
        value = normalize_whois_string(getattr(info, field_name, None))
        if not value:
            continue
        for token in value.split():
            if len(token) < 3 or token in WHOIS_STOP_WORDS:
                continue
            terms.add(token)
    return terms

def classify_ns(ns: str, domain: str, domain_tld: str,
                domain_https: bool, domain_san: set[str],
                domain_soa: Optional[str]) -> tuple[str, str]:
    ns_tld = get_tld(ns)

    # Rule 1: same TLD
    if ns_tld == domain_tld:
        return "private", "same TLD as domain"

    # Rule 2: HTTPS + SAN
    if domain_https and ns_tld in domain_san:
        return "private", "ns TLD found in domain's TLS SAN"
    
    # Rule 3: WHOIS identity match (last resort, slow)
    try:
        dn_info = whois.whois(domain)
        dn_keys = whois_identity_keys(dn_info)
        dn_terms = whois_identity_terms(dn_info)

        # First try WHOIS on the TLD extracted from the nameserver.
        ms_info = whois.whois(ns_tld)
        ms_keys = whois_identity_keys(ms_info)
        ms_terms = whois_identity_terms(ms_info)

        # If the NS-TLD lookup returned no identity fields, fall back to the raw NS hostname.
        if not ms_terms:
            ms_info = whois.whois(ns)
            ms_keys = whois_identity_keys(ms_info)
            ms_terms = whois_identity_terms(ms_info)

        # Match either exact normalized WHOIS values or overlapping identity tokens.
        if (dn_keys and ms_keys and dn_keys & ms_keys) or (dn_terms and ms_terms and dn_terms & ms_terms):
            return "private", "same organization in whois"
    except Exception:
        pass

    # Rule 3.5: shared authoritative nameservers
    domain_auth_ns = get_auth_ns_set(domain)
    ns_auth_ns = get_auth_ns_set(ns_tld)
    if domain_auth_ns and ns_auth_ns and domain_auth_ns == ns_auth_ns:
        return "private", "same authoritative nameservers"

    # Rule 4: different SOA
    ns_soa = get_soa(ns)

    if ns_soa is not None and domain_soa is not None and ns_soa != domain_soa:
        # ↓ Add this block before returning "third"
        ns_provider = regular_expression_nameserver(ns_soa)
        domain_provider = regular_expression_nameserver(domain_soa)
        if ns_provider and domain_provider and ns_provider == domain_provider:
            return "private", "same nameserver provider despite different SOA"
        return "third", f"different SOA (domain={domain_soa}, ns={ns_soa})"

    # Rule 5: concentration
    conc = concentration(ns)
    if conc >= 50:
        return "third", f"high concentration score ({conc:.1f}%)"    

    return "unknown", "no rule matched"




















# Perform a WHOIS lookup
domain_info = whois.whois("google.com")

# Print the entire response
print(f'{domain_info.name_servers}')
print(f'{domain_info.org}')

# Extract specific details
#print(f"Registrar: {domain_info.registrar}")
#print(f"Creation Date: {domain_info.creation_date}")
#print(f"Expiration Date: {domain_info.expiration_date}")