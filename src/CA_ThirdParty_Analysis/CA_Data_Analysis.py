"""
visualize_ca_results.py

Visualization suite for ca_results_*.csv output.

Organized as one function per chart so any single chart can be
regenerated on its own, plus a main() that runs the full suite.

Changes made vs. the original script:
  - Removed the unrelated IT/ECE/CSE "students passed" bar chart
    (hardcoded placeholder data with no connection to CA/TLS analysis).
  - Fixed OCSP stapling % to correctly separate "confirmed stapled",
    "confirmed not stapled", and "undetermined" (Stapled can be
    True / False / None) instead of collapsing False and None together.
  - Removed the commented-out dead code block in the CA-name chart.
  - Consolidated to a single pandas import (no pd/pa aliasing).
  - Wrapped everything in functions + a main() guard so importing this
    module doesn't immediately pop up five plot windows.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import circlify


DEFAULT_INPUT_PATH = "src/Source_Data/ca_results/ca_results_100000.csv"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_data(input_path: str = DEFAULT_INPUT_PATH) -> pd.DataFrame:
    return pd.read_csv(input_path)


def filter_classified(df: pd.DataFrame) -> pd.DataFrame:
    """
    Drop rows where type is 'unknown' or 'infrastructure'.

    These aren't classified CA relationships -- 'unknown' means the
    classifier couldn't determine ownership, and 'infrastructure' means
    the domain isn't a first-party HTTPS endpoint at all (CDN/DNS
    backend). Including them in charts about CA type, HTTPS support, or
    TLS adoption would mix "not applicable / not resolved" rows in with
    real measurements. Prints the excluded rate so it's visible, even
    though it's no longer plotted.
    """
    total = len(df)
    unknown_pct = (df["type"] == "unknown").mean() * 100
    infrastructure_pct = (df["type"] == "infrastructure").mean() * 100
    print(f"Excluded from all charts -- Unknown: {unknown_pct:.1f}%, "
          f"Infrastructure: {infrastructure_pct:.1f}% "
          f"(of {total} total domains)")

    return df[~df["type"].isin(["unknown", "infrastructure"])].copy()


# ---------------------------------------------------------------------------
# Chart 1: CA type distribution (pie)
# ---------------------------------------------------------------------------
def plot_ca_type_distribution(df: pd.DataFrame) -> None:
    """df is expected to already be filtered to classified rows only
    (see filter_classified / run_all) -- this function just plots it."""
    counts = df["type"].value_counts()

    plt.figure(figsize=(10, 8))
    plt.pie(
        counts,
        labels=counts.index,
        autopct="%1.1f%%",
        startangle=180,
        textprops={"fontsize": 16},
    )
    plt.title("Distribution of Certificate Authority Type", fontsize=20)
    plt.axis("equal")
    plt.tight_layout()
    plt.show()


# ---------------------------------------------------------------------------
# Chart 2: HTTPS enabled distribution (pie)
# ---------------------------------------------------------------------------
def plot_https_distribution(df: pd.DataFrame) -> None:
    https_counts = df["HTTPS Enabled"].value_counts()

    label_map = {True: "Has HTTPS Support", False: "No HTTPS Support"}
    display_labels = [label_map.get(label, label) for label in https_counts.index]

    plt.figure(figsize=(12, 10))
    plt.pie(
        https_counts,
        labels=display_labels,
        autopct="%1.1f%%",
        startangle=185,
        textprops={"fontsize": 20},
    )
    plt.title("HTTPS Enabled Distribution", fontsize=24)
    plt.tight_layout()
    plt.show()


# ---------------------------------------------------------------------------
# Chart 3: TLS / SSL version distribution (bar)
# ---------------------------------------------------------------------------
def plot_tls_distribution(df: pd.DataFrame) -> None:
    tls_counts = df["TLS"].value_counts()

    plt.figure(figsize=(10, 8))
    bars = plt.bar(tls_counts.index, tls_counts.values, color="#033819", edgecolor="#FFFFFF")
    plt.bar_label(bars, padding=3, fontsize=12)

    plt.title("TLS Version Distribution", fontsize=16, fontweight="bold")
    plt.xlabel("Type of TLS", fontsize=14)
    plt.ylabel("Count", fontsize=14)
    plt.tight_layout()
    plt.show()

#----------------------------------------------------------------------------
# Chart 4: CA third-party dependency and TLS adoption across different sample sizes (bar)
#----------------------------------------------------------------------------
def compute_four_bar():
    dfs = [
        pd.read_csv("src/Source_Data/ca_results/ca_results_100.csv"),
        pd.read_csv("src/Source_Data/ca_results/ca_results_1000.csv"),
        pd.read_csv("src/Source_Data/ca_results/ca_results_10000.csv"),
        pd.read_csv("src/Source_Data/ca_results/ca_results_100000.csv")
    ]

    ranks = ["100 Domains", "1,000 Domains", "10,000 Domains", "100,000 Domains"]

    third_party = []
    tls13 = []
    tls12 = []

    for df in dfs:
        third_party.append((df["type"] == "third").mean() * 100)
        tls13.append((df["TLS"] == "TLSv1.3").mean() * 100)
        tls12.append((df["TLS"] == "TLSv1.2").mean() * 100)

    x = np.arange(len(ranks))
    bar_width = 0.2

    fig, ax = plt.subplots(figsize=(14, 8))

    b1 = ax.bar(x - 1.5 * bar_width, third_party, bar_width,
                label = "Third-Party Dependency CA",
                hatch = "///",
                edgecolor = "black",
                color = "white")

    btwo = ax.bar(x - 0.5 * bar_width, tls13, bar_width,
                    label = "TLS v1.3 Adoption",
                    hatch = "\\\\",
                    edgecolor = "black",
                    color = "white")

    b3 = ax.bar(x + 0.5 * bar_width, tls12, bar_width,
                    label = "TLS v1.2 Adoption",
                    hatch = "++",
                    edgecolor = "black",
                    color = "white")

    
    ax.set_xticks(x)
    ax.set_xticklabels(ranks)
    ax.set_ylabel("Percentage of Domains (%)", fontweight="bold", fontsize=15)
    ax.set_xlabel("Cloudflare Top Rank", fontweight="bold", fontsize=15)
    ax.set_title("CA Third-Party Dependency and TLS Adoption Across Different Sample Sizes", fontweight="bold", fontsize=20)
    ax.set_ylim(0, 115)

    ax.legend(loc = "upper left", fontsize=12)

    # Add percentage labels on top of each bar
    for bars in [b1, btwo, b3]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 1, f"{h:.1f}%", ha='center', va='bottom', fontsize=10)

    plt.tight_layout()
    plt.show()

# ---------------------------------------------------------------------------
# Chart 5: CA name bubble / proportional-area chart
# ---------------------------------------------------------------------------
def plot_ca_name_bubble_chart(df: pd.DataFrame, top_n: int = 5) -> None:
    """
    Groups CA names by parent brand (e.g., all 'Amazon RSA 2048 MXX' 
    become 'Amazon') and renders them as a proportional bubble chart.
    """

    # 1. Define a helper to normalize CA names into parent brands
    def simplify_ca(name):
        if pd.isna(name) or name.strip() == "":
            return "Unknown"
        name = name.strip()
        # Special multi-word brands that shouldn't be split on the first word
        if "Let's Encrypt" in name:
            return "Let's Encrypt"
        if "Google Trust" in name or name.startswith("Google"):
            return "Google"
        if "DigiCert" in name:
            return "DigiCert"
        if "Amazon" in name:
            return "Amazon"
        if "Sectigo" in name:
            return "Sectigo"
        if "GlobalSign" in name:
            return "GlobalSign"
        if "GoDaddy" in name or "Starfield" in name:
            return "GoDaddy"
        if "Microsoft" in name:
            return "Microsoft"
        if "Cloudflare" in name:
            return "Cloudflare"
        # Fallback: take the first word as the brand
        return name.split()[0]

    # 2. Apply the simplification, then count
    ca_counts = df["CA Name"].apply(simplify_ca).value_counts()

    # 3. Keep only the top N brands (no "Other" bucket)
    ca_counts = ca_counts.head(top_n)
    print(f"Top {top_n} Grouped CAs by count:\n{ca_counts}\n")

    labels = ca_counts.index.tolist()
    values = ca_counts.values.tolist()

    # circlify expects values sorted descending
    sorted_pairs = sorted(zip(values, labels), reverse=True)
    sorted_values, sorted_labels = zip(*sorted_pairs)

    circles = circlify.circlify(
        list(sorted_values),
        show_enclosure=False,
        target_enclosure=circlify.Circle(x=0, y=0, r=1),
    )
    circles = circles[::-1]  # largest circle matches first label

    fig, ax = plt.subplots(figsize=(12, 12))
    ax.set_aspect("equal")
    ax.axis("off")
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    DARK_BLUE = "#B5B682"
    TEAL = "#FEDC97"
    WHITE = "black"
    max_val = sorted_values[0]

    for circle, label, value in zip(circles, sorted_labels, sorted_values):
        x, y, r = circle.x, circle.y, circle.r
        color = DARK_BLUE if value == max_val else TEAL

        ax.add_patch(plt.Circle((x, y), r, color=color, alpha=0.92, zorder=2))

        if r > 0.04:  # only label circles large enough to read
            short_label = label if len(label) <= 18 else label[:16] + "…"
            ax.text(
                x, y + r * 0.12, short_label,
                ha="center", va="center",
                fontsize=r * 85,          # ← scales text to bubble size
                color=WHITE, fontweight="bold", zorder=3,
            )
            ax.text(
                x, y - r * 0.28, f"{value:,}",
                ha="center", va="center",
                fontsize=r * 70,          # ← scales count text too
                color=WHITE, alpha=0.85, zorder=3,
            )

    lim = max(abs(c.x) + c.r for c in circles) * 1.05
    ax.set_xlim(-lim, lim)
    ax.set_ylim(-lim, lim)

    plt.title(
        "Certificate Authority Distribution",
        fontsize=26, fontweight="bold", pad=10, color="#060E77",
    )
    plt.tight_layout()
    plt.show()
#----------------------------------------------------------------------------
# Chart 4: Comparative Metrics across Sample Sizes
#----------------------------------------------------------------------------
def plot_comparative_metrics():
    """
    Compares Third-Party Dependency and TLS adoption across different 
    Cloudflare rank samples (100, 1k, 10k). 
    
    Applies filter_classified to each to ensure percentages are consistent 
    with the individual charts.
    """
    file_configs = [
        ("src/Source_Data/ca_results/ca_results_100.csv", "Top 100"),
        ("src/Source_Data/ca_results/ca_results_1000.csv", "Top 1,000"),
        ("src/Source_Data/ca_results/ca_results_10000.csv", "Top 10,000"),
        ("src/Source_Data/ca_results/ca_results_100000.csv", "Top 100,000")
    ]

    ranks = []
    third_party = []
    tls13 = []
    tls12 = []

    for path, label in file_configs:
        try:
            # Load and apply the same filter used in other charts for consistency
            df_raw = pd.read_csv(path)
            df = filter_classified(df_raw)
            
            ranks.append(label)
            third_party.append((df["type"] == "third").mean() * 100)
            tls13.append((df["TLS"] == "TLSv1.3").mean() * 100)
            tls12.append((df["TLS"] == "TLSv1.2").mean() * 100)
        except FileNotFoundError:
            print(f"Warning: Could not find {path}, skipping in comparison.")

    if not ranks:
        return

    x = np.arange(len(ranks))
    bar_width = 0.20

    fig, ax = plt.subplots(figsize=(14, 8))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    # Using the color palette from your other charts (Teal and Blues)
    b1 = ax.bar(x - bar_width, third_party, bar_width,
                label="Third-Party Dependency",
                hatch="//", edgecolor="black", color="white")

    b2 = ax.bar(x, tls13, bar_width,
                label="TLS v1.3 Adoption",
                hatch="||", edgecolor="black", color="white")

    b3 = ax.bar(x + bar_width, tls12, bar_width,
                label="TLS v1.2 Adoption",
                hatch="++", edgecolor="black", color="white")

    # Formatting
    ax.set_xticks(x)
    ax.set_xticklabels(ranks, fontsize=12, fontweight="bold")
    ax.set_xlabel("Cloudflare Top Rank", fontweight="bold", fontsize=14)
    ax.set_ylabel("Percentage of Classified Domains (%)", fontweight="bold", fontsize=14)
    ax.set_title("CA Dependency and TLS Adoption by Sample Size", 
                 fontweight="bold", fontsize=20, pad=20, color="black")
    ax.set_ylim(0, 130) # Extra room for labels
    ax.legend(loc="upper left", frameon=True, fontsize=18)

    # Add values above bars
    for bars in [b1, b2, b3]:
        for bar in bars:
            h = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2,
                    h + 1,
                    f"{h:.1f}",
                    ha="center",
                    va="bottom",
                    fontsize=18,
                    rotation=90)

    plt.tight_layout()
    plt.savefig('CA_four_bar_comparison.png', dpi=300, bbox_inches='tight')
    plt.show()


# ---------------------------------------------------------------------------
# Run the full suite
# ---------------------------------------------------------------------------
def run_all(input_path: str = DEFAULT_INPUT_PATH) -> None:
    #df = load_data(input_path)
    #df = filter_classified(df)
    #plot_ca_type_distribution(df)
    #plot_https_distribution(df)
    #plot_tls_distribution(df)
    #compute_four_bar()
    #plot_ca_name_bubble_chart(df)
    plot_comparative_metrics()
if __name__ == "__main__":
    run_all()