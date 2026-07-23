import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('src/Source_Data/ca_results_100.csv')

third_pct = (df['type'] == 'third').mean() * 100
unknown_pct = (df['type'] == 'unknown').mean() * 100

print(f"Third-party CA: {third_pct:.1f}%")
print(f"Unknown CA: {unknown_pct:.1f}%")

counts = df['type'].value_counts()  # keep 'unknown' in the pie this time

plt.figure(figsize=(10, 8))
plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=180, textprops={'fontsize': 16})
plt.title('Distribution of Certificate Authority Type', fontsize=20)
plt.axis('equal')
plt.tight_layout()
plt.show()

######################################################################################################################################
# This is a graph that would help us understand the amount that are HTTPS enabled.
######################################################################################################################################

df_HTTPS = df['HTTPS Enabled'].value_counts()

LABEL_MAP = {
    True: "Has HTTPS Support",
    False: "No HTTPS Support"
}
display_info = [LABEL_MAP.get(label, label) for label in df_HTTPS.index]

plt.figure(figsize=(12, 10))
plt.pie(df_HTTPS, labels=display_info, autopct='%1.1f%%', startangle=185, textprops={'fontsize': 20})
plt.title('HTTPS Enabled Distribution', fontsize=24)
plt.tight_layout()
plt.show()

#########################################################################################################################
# This is a graph that would represent if it hosts a TLS, it would emphasize on the version of the TLS or wether is 
# is unknown. This is the new OCSP stapling. 
#########################################################################################################################

# Define the data categories and their corresponding values. 
TLS_categories = df['SSL or TLS'].value_counts()

# Set up the figure size (width, heigh in inches)
plt.figure(figsize=(10, 8))

# Create the vertical bar chart with a custom color.
bars = plt.bar(TLS_categories.index, TLS_categories.values, color = "#033819", edgecolor = "#FFFFFF")

plt.bar_label(bars, padding=3, fontsize=12)

# Add a title and labels for the axes. 
plt.title('TLS (New OCSP Distribution)', fontsize = 16, fontweight = 'bold') 
plt.xlabel('Type of TLS', fontsize = 14)
plt.ylabel('Count', fontsize = 14)

# Display the graph on the screen
plt.show() 

###########################################################################################################################
# Final graph for analysis of 3 main aspects for certificate authorities (CA): It would measure the HTTPS Support, the 
# third-party dependency and the support of transport layer protocol (TLS) and encryption needs.
###########################################################################################################################

bar_width = 0.25
fig, ax = plt.subplots(figsize=(12, 8))

IT = [12, 30, 1, 8, 22]
ECE = [28, 6, 16, 5, 10]
CSE = [29, 3, 24, 25, 17]

br1 = np.arange(len(IT))
br2 = [x + bar_width for x in br1]
br3 = [x + bar_width for x in br2]

plt.bar(br1, IT, color="#056686", width=bar_width, edgecolor='black', label="IT")
plt.bar(br2, ECE, color="#07A69E", width=bar_width, edgecolor='black', label="ECE")
plt.bar(br3, CSE, color="#4056B9", width=bar_width, edgecolor='black', label="CSE")

plt.xlabel('BRANCH', fontweight='bold', fontsize=15)
plt.ylabel('STUDENTS PASSED', fontweight='bold', fontsize=15)
plt.xticks([r + bar_width for r in range(len(IT))], ['2015', '2016', '2017', '2018', '2019'])

plt.legend()
plt.show()



#######################################################################################################################
# This graph wouyld help us for comparison across all of the samples. 

total = len(df)

# HTTPS Support: % of domains where HTTPS Enabled == True
https_pct = (df['HTTPS Enabled'] == True).mean() * 100

# Third-Party CA Dependency: % of domains where 'type' == 'third'
third_party_pct = (df['type'] == 'third').mean() * 100

# OCSP Stapling use: % of domains where 'stapling' == True
OCSP_stapling = (df['Stapled'] == True).mean() * 100

# TLS Usage: % of domains with a known TLS version (i.e. not 'unknown')
tls_pct = (df['SSL or TLS'] != 'unknown').mean() * 100

categories = ['HTTPS Support', 'Third-Party CA', 'TLS Usage', 'OCSP Use']
percentages = [https_pct, third_party_pct, tls_pct, OCSP_stapling]
colors = ["#056686", "#07A69E", "#4056B9", "#3CCAA1"]

fig, ax = plt.subplots(figsize=(10, 8))
bars = ax.bar(categories, percentages, color=colors, edgecolor='black', width=0.5)

ax.bar_label(bars, fmt='%.1f%%', padding=3, fontsize=12)

ax.set_xlabel('Metric', fontweight='bold', fontsize=15)
ax.set_ylabel('Percentage of Domains (%)', fontweight='bold', fontsize=15)
ax.set_title(f'Certificate & TLS Adoption ({total} Domains)', fontweight='bold', fontsize=16)
ax.set_ylim(0, 100)

plt.tight_layout()
plt.show()