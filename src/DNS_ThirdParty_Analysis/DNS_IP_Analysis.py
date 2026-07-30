import pandas as pd
import matplotlib.pyplot as plt

# 1. Load the already resolved file
# This skips the time-consuming DNS resolution step
df = pd.read_csv("src/Source_Data/Domain_Robustness_Results_resolved_100K.csv")

# 2. Calculate classification counts
asn_counts = df['classification'].value_counts()
total_domains = asn_counts.sum() - asn_counts.get('Unresolved', 0)

# 3. Prepare data for the pie chart (Top 2: High and Low Robustness)
top_n = 2
top = asn_counts.head(top_n)

# Map the raw classification values to display names
LABEL_MAP = {
    'High Robustness': 'Hosts IPv4 & IPv6',
    'Low Robustness': 'Only Hosts IPv4 Exclusively',
}
display_labels = [LABEL_MAP.get(label, label) for label in top.index]

colors = ['#008000', '#1baf7a']

# 4. Create the figure
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

# 5. Styling
for text in texts:
    text.set_fontsize(20)
for autotext in autotexts:
    autotext.set_fontsize(30)
    autotext.set_color('white')

fig.suptitle('IP Robustness from 100K Domains', fontsize=30, y=0.98)
ax.set_title(f'{total_domains} classified domains', fontsize=20, pad=20, y=0.95)

# 6. Legend (Positioned lower using the fix from our previous turn)
plt.legend(
    title='Metric',
    loc='upper center',
    bbox_to_anchor=(0.5, -0.1),  # Adjust this value (e.g., -0.15) to move it even lower
    ncol=2,
    fontsize=18,
    title_fontsize=18,
    borderaxespad=0
)

plt.tight_layout()
plt.show()



