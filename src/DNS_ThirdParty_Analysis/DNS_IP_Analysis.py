
import dns.resolver
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("src/Source_Data/Domain_Robustness_Results_100k.csv")

######################################################################################################################
# For rows where classification == "CNAME Enabled", the domain itself had no A/AAAA record, but a CNAME target
# was found. This mirrors check_domain_robustness()'s exact rule, applied to the CNAME target instead of the
# domain, so a CNAME-enabled row ends up classified the same way a directly-resolvable domain would be:
#   has_ipv4 AND has_ipv6  -> High Robustness
#   has_ipv4 OR  has_ipv6  -> Low Robustness
#   neither                -> Unresolved  (target itself doesn't resolve either -- rare, but possible)
######################################################################################################################

RESOLVER = dns.resolver.Resolver()
RESOLVER.timeout = 3
RESOLVER.lifetime = 3


def resolve_cname_target(cname_domain: str) -> dict:
    """Look up A/AAAA for the CNAME target and classify it with the same rule as check_domain_robustness()."""
    ipv4 = None
    ipv6 = None

    try:
        ipv4_records = RESOLVER.resolve(cname_domain, 'A')
        ipv4 = ipv4_records[0].to_text()
    except Exception:
        pass

    try:
        ipv6_records = RESOLVER.resolve(cname_domain, 'AAAA')
        ipv6 = ipv6_records[0].to_text()
    except Exception:
        pass

    if ipv4 and ipv6:
        classification = "High Robustness"
    elif ipv4 or ipv6:
        classification = "Low Robustness"
    else:
        classification = "Unresolved"

    return {"ipv4": ipv4, "ipv6": ipv6, "classification": classification}


cname_mask = df['classification'] == 'CNAME Enabled'
cname_rows = df.loc[cname_mask]
print(f"Resolving {len(cname_rows)} CNAME-enabled domains...")

# Resolve each CNAME target one at a time and collect the results in plain lists,
# instead of using .apply() with a lambda.
resolved_ipv4 = []
resolved_ipv6 = []
resolved_classification = []

for cname_target in cname_rows['CNAME']:
    result = resolve_cname_target(cname_target)
    resolved_ipv4.append(result['ipv4'])
    resolved_ipv6.append(result['ipv6'])
    resolved_classification.append(result['classification'])

# Fill in the ipv4/ipv6/classification columns for those rows using the resolved values,
# instead of leaving them empty or lumped under "CNAME Enabled".
df.loc[cname_mask, 'ipv4'] = resolved_ipv4
df.loc[cname_mask, 'ipv6'] = resolved_ipv6
df.loc[cname_mask, 'classification'] = resolved_classification

still_unresolved = (df['classification'] == 'Unresolved').sum()
print(f"{still_unresolved} CNAME-enabled domain(s) still didn't resolve after following the CNAME.")

# Optional: save the corrected dataframe so you don't have to re-resolve every time you replot
df.to_csv("src/Source_Data/Domain_Robustness_Results_resolved_100K.csv", index=False)

######################################################################################################################
# From here on, df['classification'] now reflects High/Low Robustness for the previously CNAME-enabled rows too,
# so the value_counts() feeding your ASN pie chart already includes them correctly.
######################################################################################################################
asn_counts = df['classification'].value_counts()
total_domains = asn_counts.sum() - asn_counts.get('Unresolved', 0)
print(f"Total classified domains: {total_domains}")

##################################################################################################################
# We get a data frame with the DNS classification value counts, so that we can make a pie chart comparing the most used
# classifications, with the idea of understanding which categories are the most used around the world. 
##################################################################################################################

dns_classification_counts = df['classification'].value_counts()
print(dns_classification_counts)

top_n = 2
top = asn_counts.head(top_n)

# Map the raw classification values to whatever display names you want
LABEL_MAP = {
    'High Robustness': 'Hosts IPv4 & IPv6',   # <- change these values to whatever you want shown
    'Low Robustness': 'Only Hosts IPv4 Exclusively',
}
display_labels = [LABEL_MAP.get(label, label) for label in top.index]

colors = ['#008000', '#1baf7a']

fig, ax = plt.subplots(figsize=(14, 12))

wedges, texts, autotexts = ax.pie(
    top.values,
    labels=display_labels,
    autopct=lambda p: f'{p:.1f}%' if p >= 3 else '',
    colors=colors[:len(top)],
    startangle=140,
    pctdistance=0.75,
    wedgeprops=dict(linewidth=2, edgecolor='white'),
)

for text in texts:
    text.set_fontsize(20)
for autotext in autotexts:
    autotext.set_fontsize(30)
    autotext.set_color('white')

fig.suptitle('IP Robustness from 100K Domains', fontsize=30, y=0.98)
ax.set_title(f'{total_domains} classified domains', fontsize=20, pad=20, y=0.95)

plt.tight_layout()
plt.show()



