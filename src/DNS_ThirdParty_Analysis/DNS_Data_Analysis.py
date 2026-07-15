import re
import circlify
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt  
import matplotlib.patches as mpatches
from DNS_Identifier import main

#################################################################################################################
# Runs the analysis and writes the CSV file from the original file.
#################################################################################################################

PROVIDER_ALIASES = {
    # Akamai family
    "akam": "akamai",
    "akamai": "akamai",
    "akamaitech": "akamai",
    "akamaiedge": "akamai",
    "akamaistream": "akamai",
    "aka": "akamai",

    # Google family
    "google": "google",
    "googledomai": "google",
    "zdns.google": "google",
}


def normalize_provider(name):
    """Fold known provider name variants into one canonical label."""
    if pd.isna(name):
        return name
    key = str(name).strip().lower()
    return PROVIDER_ALIASES.get(key, name)
#DNS_Identifier.main() 

df = pd.read_csv("src/Source_Data/DNS_Identifier_Results_10k_domains.csv")

#################################################################################################################
# This would run the analysis only comparing between Third-party and Provate dependencies. 
#################################################################################################################
# Get the value counts for the 'type' column
data_subset_piechart = df['TYPE'].value_counts().head(2)

# Fixed: Added a clean layout, shadow, and adjusted colors if desired
plt.pie(
    data_subset_piechart, 
    labels=data_subset_piechart.index, 
    startangle=90, 
    autopct='%.1f%%',
    wedgeprops={'edgecolor': 'white', 'linewidth': 1.5} # Cleaner look
)

plt.title('Third party vs Private Infrastructure', fontsize=16)

# Optional: Adjust legend position so it doesn't overlap the pie chart
plt.legend(loc="upper right", bbox_to_anchor=(1.2, 1))

plt.tight_layout()
plt.show()


#################################################################################################################
# This would be for data analysis regarding the most used dns providers.
#################################################################################################################

def clean_provider(value: str) -> str:
    '''
    This is a method with the objective of cleaning the provider name: For example, if the provider result is 
    awsdns-32, it would use the regular expressions library to strip and only get the aws, which is the provider 
    name we need of the dns.
    '''

    # Checks for possible empty values in domains/nameserver data. 
    if pd.isna(value):
        return value
    
    value = str(value).strip().lower()
    value = value.rstrip('.')
    
    # Remove TLD suffixes (.com, .net, .org, etc.)
    value = re.sub(r'\.(com|net|org|info|co\.uk)$', '', value)
    
    # Remove trailing hyphens and numbers (e.g. 'awsdns-05' → 'awsdns')
    value = re.sub(r'[-_]\d+$', '', value)

    # Remove common DNS noise words
    value = re.sub(r'[-_]?(dns|ns)$', '', value)
    
    return value


domain_col = "DOMAIN"

df['provider_clean'] = df['PROVIDER'].apply(clean_provider)
df['provider_clean'] = df['provider_clean'].apply(normalize_provider)

df_known = df[df['provider_clean'].notna() & (df['provider_clean'] != "")]
total_domains = df_known[domain_col].nunique()

# Dedupe on the DataFrame so each domain only counts once per provider,
# no matter how many nameservers it has there
domain_provider_pairs = df_known.drop_duplicates(subset=[domain_col, "provider_clean"])

# Count ALL rows, then take the top N most common
top_n = 5  # adjust as needed
counts = domain_provider_pairs['provider_clean'].value_counts().head(top_n)
print(counts.to_string())

plt.figure(figsize=(10, 6))
plt.bar(counts.index, counts.values, color="darkgreen", edgecolor="black")
plt.title(f"Top {top_n} DNS Providers by Domain Count", fontsize=16)
plt.xlabel("Providers", fontsize=14)
plt.ylabel("Domains", fontsize=14)
plt.xticks(rotation=30, ha='right')
plt.tight_layout()
plt.show()

#################################################################################################################
# This would encase the bubble style graph we saw on the Certificate Authority analysis.
#################################################################################################################
# Map provider name variants onto a single canonical name.
# Add more entries here any time you spot another split (e.g. "amazon" vs "aws").
def bubble_data_vis(input_file, domain_col="DOMAIN"):
    df = pd.read_csv(input_file)

    df["provider_clean"] = df["PROVIDER"].apply(clean_provider)
    df["provider_clean"] = df["provider_clean"].apply(normalize_provider)
    df["provider_clean"] = df["provider_clean"].fillna("Unknown").replace("", "Unknown")

    # Drop Unknown before ranking, same as before
    df_known = df[df["provider_clean"] != "Unknown"]

    total_domains = df_known[domain_col].nunique()

    # --- KEY CHANGE ---
    # Collapse to one row per (domain, provider) pair, so a domain with
    # 4 AWS nameservers only counts once for AWS. Then count how many
    # UNIQUE DOMAINS each provider appears in (their "reach"), not how
    # many nameserver rows they own.
    domain_provider_pairs = df_known.drop_duplicates(subset=[domain_col, "provider_clean"])
    ca_counts = domain_provider_pairs["provider_clean"].value_counts().head(10)

    labels = ca_counts.index.tolist()
    values = ca_counts.values.tolist()

    sorted_pairs = sorted(zip(values, labels), reverse=True)
    sorted_values, sorted_labels = zip(*sorted_pairs)

    circles = circlify.circlify(
        list(sorted_values),
        show_enclosure=False,
        target_enclosure=circlify.Circle(x=0, y=0, r=1)
    )
    circles = circles[::-1]

    # --- Style ---
    BG        = "#63676F"
    PALETTE   = [
        "#1B2C72", "#2E86C1", "#300F42",
        "#0E222EA6", "#05281790", "#16395239",
        "#1A5276", "#154360", "#21618C", "#0B3957"
    ]
    TEXT_DARK  = "#DAE0E6"
    TEXT_LIGHT = "#FDFEFEDD"

    fig, ax = plt.subplots(figsize=(16, 16))
    ax.set_aspect("equal")
    ax.axis("off")
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    for i, (circle, label, value) in enumerate(zip(circles, sorted_labels, sorted_values)):
        x, y, r = circle.x, circle.y, circle.r
        color = PALETTE[i % len(PALETTE)]

        patch = plt.Circle((x, y), r, color=color, alpha=0.93, zorder=2)
        edge  = plt.Circle((x, y), r, fill=False, edgecolor="white", linewidth=1.2, alpha=0.4, zorder=3)
        ax.add_patch(patch)
        ax.add_patch(edge)

        if r > 0.04:
            fontsize   = max(20, min(13, r * 30))
            text_color = TEXT_LIGHT

            short_label = label.upper() if len(label) <= 14 else label[:13].upper() + "…"

            ax.text(
                x, y + r * 0.15,
                short_label,
                ha="center", va="center",
                fontsize=fontsize,
                fontweight="bold",
                color=text_color,
                zorder=4,
            )
            # --- LABEL CHANGE: domains, not nameservers ---
            ax.text(
                x, y - r * 0.22,
                f"{value:,} domains",
                ha="center", va="center",
                fontsize=fontsize * 0.78,
                color=text_color,
                alpha=0.88,
                zorder=4,
            )

            if r > 0.12:
                # --- PERCENT CHANGE: share of total domains, not sum of bubble values ---
                pct = value / total_domains * 100
                ax.text(
                    x, y - r * 0.52,
                    f"({pct:.1f}%)",
                    ha="center", va="center",
                    fontsize=fontsize * 0.68,
                    color=text_color,
                    alpha=0.72,
                    zorder=4,
                )

    lim = max(abs(c.x) + c.r for c in circles) * 1.08
    ax.set_xlim(-lim, lim)
    ax.set_ylim(-lim, lim)

    fig.text(
        0.5, 0.97,
        "Top DNS Providers by Domain Reach",
        ha="center", va="top",
        fontsize=20, fontweight="bold",
        color=TEXT_DARK,
    )
    fig.text(
        0.5, 0.93,
        f"Top 10 providers across {total_domains:,} domains "
        f"({len(df_known):,} nameservers analysed)",
        ha="center", va="top",
        fontsize=12, color="#DDE2E8",
    )

    plt.tight_layout(rect=[0, 0, 1, 0.93])
    plt.savefig("dns_bubble_chart_by_domain.png", dpi=180, bbox_inches="tight", facecolor=BG)
    plt.show()


if __name__ == "__main__":
    bubble_data_vis("src/Source_Data/DNS_Identifier_Results_10k_domains.csv", domain_col="DOMAIN")


#####################################################################################################################################
# This is to create a graph for our analysis, with the list of domains that have a third party dependency and a private dependency. 
# I did it here considering that the information is obtained when we append it to the csv of the results, therefore 
#####################################################################################################################################
 
def plot_dependency_breakdown(csv_path="src/Source_Data/DNS_Identifier_Results_100_domains.csv", save_path=None):
    """
    Reads the DNS identifier results and plots a bar chart of
    unique domains by dependency type (e.g. third-party vs private).
    """
    df = pd.read_csv(csv_path)
    
    unique_domains = df.drop_duplicates(subset="DOMAIN")


    filtered_domains = unique_domains[unique_domains["TYPE"].str.lower() != "private"]

    dependency_counts = filtered_domains["DEPENDENCY"].value_counts()


    plt.figure(figsize=(8, 6))
    plt.bar(dependency_counts.index, dependency_counts.values, color="skyblue", edgecolor="black")
    plt.title("Domain Dependency Breakdown", fontsize=16)
    plt.xlabel("Dependency", fontsize=14)
    plt.ylabel("Number of Domains", fontsize=14)
    plt.xticks(rotation=30, ha='right')

    for i, v in enumerate(dependency_counts.values):
        plt.text(i, v + 0.5, str(v), ha='center', fontsize=11)

    plt.tight_layout()

    plt.show()

    redundant_counts = unique_domains["REDUNDANT"].value_counts()

    plt.figure(figsize=(8, 6))
    plt.bar(redundant_counts.index.astype(str), redundant_counts.values, color="green", edgecolor="black")
    plt.title("Domain Redundancy Breakdown", fontsize=16)
    plt.xlabel("Redundancy", fontsize=14)
    plt.ylabel("Number of Domains", fontsize=14)
    plt.xticks(rotation=30, ha='right')

    for i, v in enumerate(redundant_counts.values):
        plt.text(i, v + 0.5, str(v), ha='center', fontsize=11)

    plt.tight_layout()
    plt.show()




if __name__ == "__main__":
    plot_dependency_breakdown()