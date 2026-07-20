import dns.resolver 
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("src/Source_Data/Domain_Robustness_Results_100k.csv")













##################################################################################################################
# We get a data frame with the DNS classification value counts, so that we can make a pie chart comparing the most used
# classifications, with the idea of understanding which categories are the most used around the world. 
##################################################################################################################

dns_classification_counts = df['classification'].value_counts()
print(dns_classification_counts)

# Group smaller slices into "Other" to keep the chart readable
top_n = 6
top = dns_classification_counts.head(top_n)
other_count = dns_classification_counts.iloc[top_n:].sum()

if other_count > 0:
    top['Other'] = other_count

colors = ['#008000', '#1baf7a', '#005500', '#00CF00', '#800080', '#400080', '#001C00']

fig, ax = plt.subplots(figsize=(14, 12))

wedges, texts, autotexts = ax.pie(
    top.values,
    labels=top.index,
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
    #autotext.set_fontweight('bold')

ax.set_title('IP robustness from 100k domains', fontsize=30, pad=40)

plt.tight_layout()
#plt.savefig("src/Source_Data/asn_pie_chart.png", dpi=150, bbox_inches='tight')
#print("Chart saved to src/Source_Data/asn_pie_chart.png")
plt.show()


######################################################################################################################
# This is a pie chart that would analyze the region distribution  of the domains and the location.
######################################################################################################################

region_organization = df['region'].value_counts()

top = region_organization.head()

colors = ["#000980", "#095590", "#0F97B6", "#6F4C94"]


fig, ax = plt.subplots(figsize=(14, 12))

wedges, arguments, autotexts = ax.pie(
    top.values,
    labels=top.index,
    autopct=lambda p: f'{p:.1f}%' if p >= 3 else '',
    colors=colors[:len(top)],
    startangle=90,
    pctdistance=0.75,
    wedgeprops=dict(linewidth=2, edgecolor='white'),
)

for text in arguments:
    text.set_fontsize(20)
for autotext in autotexts:
    autotext.set_fontsize(30)
    autotext.set_color('white')

ax.set_title('IP location concentration from 100k domains', fontsize=30, pad=20)

plt.tight_layout()
plt.show()


