'''import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("src/Source_Data/Cloudflare_Top100_Domains.csv")
# Automatically assign index to the 
#print(df.to_string())

new = df["categories"].value_counts()

top_categories = new.head()

#print(f'{new}')

top_categories.plot()

plt.show()'''

import whois
# Perform a WHOIS lookup
domain_info = whois.whois("google.com")

# Print the entire response
print(f'{domain_info.name_servers}')
print(f'{domain_info.org}')

# Extract specific details
#print(f"Registrar: {domain_info.registrar}")
#print(f"Creation Date: {domain_info.creation_date}")
#print(f"Expiration Date: {domain_info.expiration_date}")