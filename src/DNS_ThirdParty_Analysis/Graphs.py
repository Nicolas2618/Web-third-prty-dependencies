import numpy as np
import matplotlib.pyplot as plt

#################################################################################################################################
# This is one of the graphs that would help us with our analysis and comparison. 
#################################################################################################################################

library = ['100', '1,000', '10,000']

Third_Party_Dependency = [60.2, 0, 84.3]
Critical_Dependency = [33, 0, 56]
Redundancy = [0,0,0]


bar_width = 0.2
x_label = np.arange(len(library))

plt.bar(x_label - 1.5*bar_width, Third_Party_Dependency, bar_width, label='3rd Party Dependency', color='forestgreen')
plt.bar(x_label - 0.5*bar_width, Critical_Dependency, bar_width, label='Critical Dependency', color='teal')
plt.bar(x_label + 0.5*bar_width, Redundancy, bar_width, label='Redundancy', color='purple')


plt.xlabel('Cloudflare Rank')
plt.ylabel('Percentage of Websites')
plt.title('Regional Preferences for Visualization Libraries (Grouped)')
plt.xticks(x_label, library)
plt.legend(title='Regions')
plt.show()