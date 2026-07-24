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


DEFAULT_INPUT_PATH = "src/Source_Data/ca_results/ca_results_1000.csv"


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
    tls_counts = df["SSL or TLS"].value_counts()

    plt.figure(figsize=(10, 8))
    bars = plt.bar(tls_counts.index, tls_counts.values, color="#033819", edgecolor="#FFFFFF")
    plt.bar_label(bars, padding=3, fontsize=12)

    plt.title("TLS Version Distribution", fontsize=16, fontweight="bold")
    plt.xlabel("Type of TLS", fontsize=14)
    plt.ylabel("Count", fontsize=14)
    plt.tight_layout()
    plt.show()


# ---------------------------------------------------------------------------
# Chart 4: Summary metrics across the whole sample (bar)
# ---------------------------------------------------------------------------
def plot_summary_metrics(df: pd.DataFrame) -> None:
    total = len(df)

    #https_pct = (df["HTTPS Enabled"] == True).mean() * 100          
    third_party_pct = (df["type"] == "third").mean() * 100
    tls_pct = (df["SSL or TLS"] != "unknown").mean() * 100

    # Stapled is tri-state: True / False / None (undetermined). After a
    # CSV round-trip, pandas may read these back as bool, string
    # ("True"/"False"), or NaN depending on dtype inference -- so compare
    # against the string form of True rather than the Python bool, to
    # avoid silently under-counting confirmed-stapled rows.
    stapled_col = df["Stapled"].astype(str).str.strip().str.lower()
    ocsp_stapling_pct = (stapled_col == "true").mean() * 100

    categories = ["Third-Party CA", "TLS Usage", "OCSP Use"]
    percentages = [third_party_pct, tls_pct, ocsp_stapling_pct]
    colors = ["#056686", "#07A69E", "#4056B9", "#3CCAA1"]

    fig, ax = plt.subplots(figsize=(10, 8))
    bars = ax.bar(categories, percentages, color=colors, edgecolor="black", width=0.5)
    ax.bar_label(bars, fmt="%.1f%%", padding=3, fontsize=12)

    ax.set_xlabel("Metric", fontweight="bold", fontsize=15)
    ax.set_ylabel("Percentage of Domains (%)", fontweight="bold", fontsize=15)
    ax.set_title(
        f"Certificate & TLS Adoption ({total} Domains)",
        fontweight="bold",
        fontsize=14,
    )
    ax.set_ylim(0, 100)
    plt.tight_layout()
    plt.show()


# ---------------------------------------------------------------------------
# Chart 5: CA name bubble / proportional-area chart
# ---------------------------------------------------------------------------
def plot_ca_name_bubble_chart(df: pd.DataFrame, top_n: int = 5) -> None:
    ca_counts = df["CA Name"].fillna("Unknown").replace("", "Unknown").value_counts()

    top = ca_counts.head(top_n)
    other_count = ca_counts.iloc[top_n:].sum()
    ca_counts = pd.concat([top, pd.Series({"Other": other_count})]) if other_count > 0 else top

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
    fig.patch.set_facecolor("#F5F6FA")
    ax.set_facecolor("#F5F6FA")

    DARK_BLUE = "#070BE7"
    TEAL = "#5FB6E9"
    WHITE = "#FFFFFF"
    max_val = sorted_values[0]

    for circle, label, value in zip(circles, sorted_labels, sorted_values):
        x, y, r = circle.x, circle.y, circle.r
        color = DARK_BLUE if value == max_val else TEAL

        ax.add_patch(plt.Circle((x, y), r, color=color, alpha=0.92, zorder=2))

        if r > 0.04:  # only label circles large enough to read
            short_label = label if len(label) <= 18 else label[:16] + "…"
            ax.text(
                x, y + r * 0.12, short_label,
                ha="center", va="center", fontsize=24,
                color=WHITE, fontweight="bold", zorder=3,
            )
            ax.text(
                x, y - r * 0.28, f"{value:,}",
                ha="center", va="center", fontsize=24 * 0.85,
                color=WHITE, alpha=0.85, zorder=3,
            )

    lim = max(abs(c.x) + c.r for c in circles) * 1.05
    ax.set_xlim(-lim, lim)
    ax.set_ylim(-lim, lim)

    plt.title(
        "Certificate Authority Distribution",
        fontsize=26, fontweight="bold", pad=16, color="#060E77",
    )
    plt.tight_layout()
    plt.show()


# ---------------------------------------------------------------------------
# Run the full suite
# ---------------------------------------------------------------------------
def run_all(input_path: str = DEFAULT_INPUT_PATH) -> None:
    df = load_data(input_path)
    df = filter_classified(df)
    plot_ca_type_distribution(df)
    plot_https_distribution(df)
    plot_tls_distribution(df)
    plot_summary_metrics(df)
    plot_ca_name_bubble_chart(df)


if __name__ == "__main__":
    run_all()