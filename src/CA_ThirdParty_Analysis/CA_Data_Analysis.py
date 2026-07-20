import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('src/Source_Data/ca_results_1000.csv')

df_type = df[df['type'] != 'unknown']

counts = df_type['type'].value_counts()

print(counts)

plt.figure(figsize=(10, 8))
plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=180)
plt.title('Distribution of Certificate Authority Type')
plt.axis('equal') 
plt.tight_layout()
plt.show()

######################################################################################################################################
# This is a graph that would help us understand the amount that are HTTPS enabled.
######################################################################################################################################

df_HTTPS = df['HTTPS Enabled'].value_counts()

plt.figure(figsize = (12, 10))
plt.pie(df_HTTPS, labels=df_HTTPS.index, autopct='%1.1f%%', startangle=185)
plt.title('HTTPS Enabled distribrution', fontsize=20)
plt.tight_layout()
plt.show()