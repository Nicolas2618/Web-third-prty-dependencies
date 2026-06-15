import pandas as pd

df = pd.read_csv("src/Source_Data/Cloudflare_Top100_Domains.csv")
# Automatically assign index to the 
#print(df)

new = df["categories"].value_counts()

print(f'{new}')