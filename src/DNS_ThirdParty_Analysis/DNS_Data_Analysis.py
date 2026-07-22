"""
DNS Third-Party Dependency Analysis
------------------------------------
One consistent pipeline for all charts, across the 100 / 1,000 / 10,000
domain samples.

Why this file is structured this way:
The raw CSVs are one row per NAMESERVER. DEPENDENCY, REDUNDANT, and
ENTITY_COUNT are domain-level facts that just get repeated on every
nameserver row for that domain. Every chart that reports a percentage
of *domains* (not nameservers) needs to first collapse to one row per
DOMAIN -- that collapse logic lives in ONE place (domain_level_summary)
so every chart agrees with every other chart.

Sections:
  1. Config
  2. Data loading & provider-name cleaning (shared by every chart)
  3. Domain-level metrics (shared by every chart)
  4. Chart functions (each takes an already-loaded dataframe)
  5. main()
"""

import re
import circlify
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# ------------------------------------------------------------------
# 1. CONFIG
# ------------------------------------------------------------------

FILES = {
    "100 Domains": "src/Source_Data/DNS_Identifier_Results_100_domains.csv",
    "1,000 Domains": "src/Source_Data/DNS_Identifier_Results_1k_domains.csv",
    "10,000 Domains": "src/Source_Data/DNS_Identifier_Results_10k_domains.csv",
}

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


# ------------------------------------------------------------------
# 2. DATA LOADING & CLEANING (shared by every chart)
# ------------------------------------------------------------------

def clean_provider(value: str) -> str:
    """Strip TLD suffixes, trailing numbers, and dns/ns noise from a provider string.
    e.g. 'awsdns-32' -> 'aws'
    """
    if pd.isna(value):
        return value
    value = str(value).strip().lower().rstrip('.')
    value = re.sub(r'\.(com|net|org|info|co\.uk)$', '', value)
    value = re.sub(r'[-_]\d+$', '', value)
    value = re.sub(r'[-_]?(dns|ns)$', '', value)
    return value


def normalize_provider(name: str) -> str:
    """Fold known provider name variants (akamai, google, etc.) into one canonical label."""
    if pd.isna(name):
        return name
    key = str(name).strip().lower()
    return PROVIDER_ALIASES.get(key, name)


def load_data(csv_path: str) -> pd.DataFrame:
    """Load a DNS_Identifier results CSV and attach cleaned/normalized provider columns."""
    df = pd.read_csv(csv_path)
    df["provider_clean"] = df["PROVIDER"].apply(clean_provider).apply(normalize_provider)
    df["provider_clean"] = df["provider_clean"].fillna("Unknown").replace("", "Unknown")
    return df


# ------------------------------------------------------------------
# 3. DOMAIN-LEVEL METRICS
# ------------------------------------------------------------------
# The raw CSV is one row per NAMESERVER -> collapse to one row per DOMAIN
# before computing any percentage, so a domain with 6 nameservers doesn't
# get counted 6 times, and so "does this domain use a third party" reflects
# ALL of its nameservers, not just whichever row happened to come first.

def domain_level_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Collapse a nameserver-level dataframe into one row per DOMAIN with:
      - has_third_party : True if ANY nameserver for that domain is TYPE == 'third'
      - dependency       : DEPENDENCY value (constant per domain)
      - redundant        : REDUNDANT value  (constant per domain)
      - entity_count     : ENTITY_COUNT value (constant per domain)
    """
    has_third_party = df.groupby("DOMAIN")["TYPE"].apply(lambda t: (t == "third").any())

    # DEPENDENCY / REDUNDANT are supposed to be identical across every
    # nameserver row for a given domain. Verify that rather than assume it.
    inconsistent = df.groupby("DOMAIN")[["DEPENDENCY", "REDUNDANT"]].nunique()
    bad = inconsistent[(inconsistent["DEPENDENCY"] > 1) | (inconsistent["REDUNDANT"] > 1)]
    if len(bad):
        print(f"Warning: {len(bad)} domain(s) have inconsistent DEPENDENCY/REDUNDANT "
              f"values across their nameserver rows: {bad.index.tolist()}")

    first_row = df.drop_duplicates(subset="DOMAIN").set_index("DOMAIN")

    summary = pd.DataFrame({
        "has_third_party": has_third_party,
        "dependency": first_row["DEPENDENCY"],
        "redundant": first_row["REDUNDANT"],
        "entity_count": first_row["ENTITY_COUNT"],
    })
    return summary.reset_index()


def compute_metrics(csv_path: str) -> dict:
    """Return headline percentages for one CSV.
    - third_party_pct : % of ALL domains
    - critical_pct    : % of THIRD-PARTY domains only
    - redundant_pct   : % of ALL domains
    """
    df = load_data(csv_path)
    summary = domain_level_summary(df)

    n = len(summary)
    third_party_domains = summary[summary["has_third_party"]]
    n_third_party = len(third_party_domains)

    return {
        "n_domains": n,
        "n_third_party": n_third_party,
        "third_party_pct": summary["has_third_party"].mean() * 100,
        "critical_pct": (third_party_domains["dependency"] == "Critical dependency").mean() * 100 if n_third_party else 0,
        "redundant_pct": (summary["redundant"] == True).mean() * 100,
    }


# ------------------------------------------------------------------
# 4. CHARTS
# ------------------------------------------------------------------

def plot_summary_comparison(files: dict = FILES):
    """100 / 1k / 10k grouped bar chart -- percentages computed live from the CSVs."""
    labels, third_party, critical, redundant = [], [], [], []

    for label, path in files.items():
        m = compute_metrics(path)
        labels.append(label)
        third_party.append(round(m["third_party_pct"], 1))
        critical.append(round(m["critical_pct"], 1))
        redundant.append(round(m["redundant_pct"], 1))
        print(f"{label}: n={m['n_domains']} (third-party n={m['n_third_party']}), "
              f"third_party={m['third_party_pct']:.1f}%, "
              f"critical={m['critical_pct']:.1f}% of third-party, "
              f"redundant={m['redundant_pct']:.1f}%")

    bar_width = 0.2
    x = np.arange(len(labels))

    plt.figure(figsize=(10, 6))
    b1 = plt.bar(x - 1.5 * bar_width, third_party, bar_width, label='3rd Party Dependency', color='forestgreen')
    b2 = plt.bar(x - 0.5 * bar_width, critical, bar_width, label='Critical Dependency', color='teal')
    b3 = plt.bar(x + 0.5 * bar_width, redundant, bar_width, label='Redundancy', color='purple')
    plt.bar_label(b1, padding=3, fontsize=12)
    plt.bar_label(b2, padding=3, fontsize=12)
    plt.bar_label(b3, padding=3, fontsize=12)

    plt.xlabel('Cloudflare Top Rank')
    plt.ylabel('Percentage of Domains')
    plt.title('DNS Third-Party Analysis')
    plt.xticks(x, labels)
    plt.legend(title='Metric')
    plt.tight_layout()
    plt.show()


def plot_type_pie(df: pd.DataFrame):
    """
    Third-party vs private nameserver split (nameserver-level, not domain-level).
    """

    counts = df['TYPE'].value_counts().head(2)
    
    fig, ax = plt.subplots()
    wedges, texts, autotexts = ax.pie(
        counts,
        labels=counts.index,
        startangle=90,
        autopct='%.1f%%',
        textprops={'fontsize': 16},
        wedgeprops={'edgecolor': 'white', 'linewidth': 1.5},
    )
    for autotext in autotexts:
        autotext.set_fontsize(18)
        autotext.set_fontweight('bold')
        autotext.set_color('white')

    ax.set_title('Third Party vs Private Infrastructure', fontsize=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.2, 1), fontsize=12)
    plt.tight_layout()
    plt.show()


def plot_top_providers(df: pd.DataFrame, top_n: int = 5):
    """Top N DNS providers, counted once per domain (not once per nameserver row)."""
    df_known = df[(df['provider_clean'].notna()) & (df['provider_clean'] != "Unknown")]
    domain_provider_pairs = df_known.drop_duplicates(subset=["DOMAIN", "provider_clean"])
    counts = domain_provider_pairs['provider_clean'].value_counts().head(top_n)
    print(counts.to_string())

    plt.figure(figsize=(12, 10))
    plt.bar(counts.index, counts.values, color="darkgreen", edgecolor="black")
    plt.title(f"Top {top_n} DNS Providers by Domain Count", fontsize=18)
    plt.xlabel("Providers", fontsize=16)
    plt.ylabel("Domains", fontsize=16)
    plt.xticks(rotation=30, ha='right')
    plt.tight_layout()
    plt.show()
    return counts


def plot_provider_bubble(df: pd.DataFrame, save_path: str = "dns_bubble_chart_by_domain.png"):
    """Bubble chart of the top 10 providers by unique-domain reach."""
    df_known = df[df["provider_clean"] != "Unknown"]
    total_domains = df_known["DOMAIN"].nunique()

    domain_provider_pairs = df_known.drop_duplicates(subset=["DOMAIN", "provider_clean"])
    ca_counts = domain_provider_pairs["provider_clean"].value_counts().head(10)

    sorted_pairs = sorted(zip(ca_counts.values.tolist(), ca_counts.index.tolist()), reverse=True)
    sorted_values, sorted_labels = zip(*sorted_pairs)

    circles = circlify.circlify(
        list(sorted_values),
        show_enclosure=False,
        target_enclosure=circlify.Circle(x=0, y=0, r=1)
    )[::-1]

    BG = "#63676F"
    PALETTE = [
        "#1B2C72", "#2E86C1", "#300F42",
        "#0E222EA6", "#05281790", "#16395239",
        "#1A5276", "#154360", "#21618C", "#0B3957"
    ]
    TEXT_LIGHT = "#FDFEFEDD"

    fig, ax = plt.subplots(figsize=(16, 16))
    ax.set_aspect("equal")
    ax.axis("off")
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    for i, (circle, label, value) in enumerate(zip(circles, sorted_labels, sorted_values)):
        x, y, r = circle.x, circle.y, circle.r
        color = PALETTE[i % len(PALETTE)]
        ax.add_patch(plt.Circle((x, y), r, color=color, alpha=0.93, zorder=2))
        ax.add_patch(plt.Circle((x, y), r, fill=False, edgecolor="white", linewidth=1.2, alpha=0.4, zorder=3))

        if r > 0.04:
            fontsize = max(20, min(13, r * 30))
            short_label = label.upper() if len(label) <= 14 else label[:13].upper() + "…"
            ax.text(x, y + r * 0.15, short_label, ha="center", va="center",
                    fontsize=fontsize, fontweight="bold", color=TEXT_LIGHT, zorder=4)
            ax.text(x, y - r * 0.22, f"{value:,} domains", ha="center", va="center",
                    fontsize=fontsize * 0.78, color=TEXT_LIGHT, alpha=0.88, zorder=4)
            if r > 0.12:
                pct = value / total_domains * 100
                ax.text(x, y - r * 0.52, f"({pct:.1f}%)", ha="center", va="center",
                        fontsize=fontsize * 0.68, color=TEXT_LIGHT, alpha=0.72, zorder=4)

    lim = max(abs(c.x) + c.r for c in circles) * 1.08
    ax.set_xlim(-lim, lim)
    ax.set_ylim(-lim, lim)

    fig.text(0.5, 0.97, "Top DNS Providers by Domain Reach", ha="center", va="top",
              fontsize=20, fontweight="bold", color="#DAE0E6")
    fig.text(0.5, 0.93, f"Top 10 providers across {total_domains:,} domains "
                         f"({len(df_known):,} nameservers analysed)",
              ha="center", va="top", fontsize=12, color="#DDE2E8")

    plt.tight_layout(rect=[0, 0, 1, 0.93])
    plt.savefig(save_path, dpi=180, bbox_inches="tight", facecolor=BG)
    plt.show()


def plot_dependency_breakdown(df: pd.DataFrame):
    """
    Domain-level dependency & redundancy breakdown.
    Uses domain_level_summary() so a domain's dependency status reflects
    ALL of its nameservers, not just whichever row happened to be first
    (this is the bug fix vs. the previous version, which used
    drop_duplicates(subset='DOMAIN') directly).
    """
    summary = domain_level_summary(df)

    # Only domains that actually have at least one third-party nameserver
    third_party_domains = summary[summary["has_third_party"]]
    dependency_counts = third_party_domains["dependency"].value_counts()

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

    redundant_counts = summary["redundant"].value_counts()
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


# ------------------------------------------------------------------
# 5. MAIN
# ------------------------------------------------------------------

def main():
    # Cross-file summary (100 / 1k / 10k) -- one consistent set of computed metrics
    plot_summary_comparison(FILES)

    # Detailed charts on a single sample (change the key below to switch files)
    df = load_data(FILES["10,000 Domains"])
    plot_type_pie(df)
    plot_top_providers(df, top_n=5)
    plot_provider_bubble(df)
    plot_dependency_breakdown(df)


if __name__ == "__main__":
    main()