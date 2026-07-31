import pandas as pd
import matplotlib.pyplot as plt

# 1. Load the already resolved file
df = pd.read_csv("src/Source_Data/Domain_Robustness_Results_resolved_100K.csv")

# 2. Calculate classification counts
asn_counts = df['classification'].value_counts()
total_domains = asn_counts.sum() - asn_counts.get('Unresolved', 0)

# 3. Prepare data for the pie chart
top_n = 2
top = asn_counts.head(top_n)

LABEL_MAP = {
    'High Robustness': 'Hosts IPv4 & IPv6',
    'Low Robustness': 'Only Hosts IPv4 Exclusively',
}
display_labels = [LABEL_MAP.get(label, label) for label in top.index]

# ⭐ Use white fill so the hatch pattern is the visible distinguisher
colors = ['white', 'white']
hatches = ['///', '...']   # different pattern for each wedge

# 4. Create the figure
fig, ax = plt.subplots(figsize=(14, 8))

wedges, texts, autotexts = ax.pie(
    top.values,
    labels=display_labels,
    autopct=lambda p: f'{p:.1f}%' if p >= 3 else '',
    colors=colors[:len(top)],
    startangle=140,
    pctdistance=0.75,
    wedgeprops=dict(linewidth=2, edgecolor='black'),  # black edge for visibility
)

# ⭐ Apply hatch patterns to each wedge
for wedge, hatch in zip(wedges, hatches):
    wedge.set_hatch(hatch)

# 5. Styling
for text in texts:
    text.set_fontsize(20)
for autotext in autotexts:
    autotext.set_fontsize(30)
    autotext.set_color('black')   # ⭐ changed from white — needs to be visible on white fill

fig.suptitle('IP Robustness from 100K Domains', fontsize=30, y=0.98)
ax.set_title(f'{total_domains} classified domains', fontsize=20, pad=20, y=0.95)

# 6. Legend
'''plt.legend(
    title='Metric',
    loc='upper center',
    bbox_to_anchor=(0.5, -0.1),
    ncol=2,
    fontsize=18,
    title_fontsize=18,
    borderaxespad=0
)'''
plt.savefig('DNS_IP_PIE.png', dpi=300, bbox_inches='tight')
plt.tight_layout()
plt.show()



