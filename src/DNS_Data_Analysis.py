import re
import pandas as pd
import matplotlib.pyplot as plt  # Fixed: Added .pyplot

# Runs the analysis and writes the CSV file from the original file. 
#DNS_Identifier.main() 

df = pd.read_csv("src/Source_Data/DNS_Identifier_Results.csv")

# Get the value counts for the 'type' column
data_subset = df['type'].value_counts()



def clean_provider(value: str) -> str:
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

df['provider_clean'] = df['provider'].apply(clean_provider)

print(df['provider_clean'].value_counts().to_string())
# Create the figure to ensure proper layout
'''plt.figure(figsize=(8, 6))

# Fixed: Added a clean layout, shadow, and adjusted colors if desired
plt.pie(
    data_subset, 
    labels=data_subset.index, 
    startangle=90, 
    autopct='%.1f%%',
    wedgeprops={'edgecolor': 'white', 'linewidth': 1.5} # Cleaner look
)

plt.title('Third party vs Private Infrastructure')

# Optional: Adjust legend position so it doesn't overlap the pie chart
plt.legend(loc="upper right", bbox_to_anchor=(1.2, 1))

plt.tight_layout()
plt.show()'''