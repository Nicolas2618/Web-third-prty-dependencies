import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

#################################################################################################################################
# This is one of the graphs that would help us with our analysis and comparison. 
#################################################################################################################################


def compute_metrics(csv_path):
    df = pd.read_csv(csv_path)

    total_domains = df['DOMAIN'].nunique()

    # Third-Party Dependency: A domain counts as 'third-party dependent' if any of its nameservers is third party.

    third_party_domains = df.groupby("DOMAIN")["TYPE"].apply(lambda types: (types == 'third').any())
    third_party_pct = third_party_domains.mean() * 100

    # Critical dependency and redundancy; they are already constant per domain, so just grab one row per domain. 

    domain_level = df.drop_duplicates(subset = 'DOMAIN')

    critical_pct = (domain_level['DEPENDENCY'] == 'Critical dependency').mean() * 100
    redundant_pct = (domain_level['REDUNDANT'] == True).mean() * 100

    return third_party_pct, critical_pct, redundant_pct, total_domains

# Here it reads the three files of interest.
files = {
            '100 Domains': 'src/Source_Data/DNS_Identifier_Results_100_domains.csv',
            '1,000 Domains': 'src/Source_Data/DNS_Identifier_Results_1k_domains.csv',
            '10,000 Domains': 'src/Source_Data/DNS_Identifier_Results_10k_domains.csv',
        }


library = []
Third_Party_Dependency = []
Critical_Dependency = []
Redundancy = []

for label, path in files.items():
    third_party, critical, redundancy, n = compute_metrics(path)

    library.append(label)
    Third_Party_Dependency.append(round(third_party, 2))
    Critical_Dependency.append(round(critical,2))
    Redundancy.append(round(redundancy, 2))

    print(f"{label}: n = {n}, third_party = {third_party:.1f}%, critical = {critical:.1f}%, redundancy = {redundancy:.1f}%,")


bar_width = 0.2
x_label = np.arange(len(library))

bars1 = plt.bar(x_label - 1.5*bar_width, Third_Party_Dependency, bar_width, label='3rd Party Dependency', color='forestgreen')
bars2 = plt.bar(x_label - 0.5*bar_width, Critical_Dependency, bar_width, label='Critical Dependency', color='teal')
bars3 = plt.bar(x_label + 0.5*bar_width, Redundancy, bar_width, label='Redundancy', color='purple')

plt.bar_label(bars1, padding=3, fontsize=12)
plt.bar_label(bars2, padding=3, fontsize=12)
plt.bar_label(bars3, padding=3, fontsize=12)

plt.xlabel('Cloudflare Top Rank')
plt.ylabel('Percentage of Websites')
plt.title('DNS Third-Party Analysis')
plt.xticks(x_label, library)
plt.legend(title='Regions')
plt.show()