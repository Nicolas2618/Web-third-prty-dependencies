import numpy as np
import matplotlib.pyplot as plt

#################################################################################################################################
# This is one of the graphs that would help us with our analysis and comparison. 
#################################################################################################################################

library = ['100', '1,000', '10,000']

Third_Party_Dependency = [60.2, 80.5, 84.3]
Critical_Dependency = [33, 46, 56]
Redundancy = [7.6,6.2,5.3]


bar_width = 0.2
x_label = np.arange(len(library))

bars1 = plt.bar(x_label - 1.5*bar_width, Third_Party_Dependency, bar_width, label='3rd Party Dependency', color='forestgreen')
bars2 = plt.bar(x_label - 0.5*bar_width, Critical_Dependency, bar_width, label='Critical Dependency', color='teal')
bars3 = plt.bar(x_label + 0.5*bar_width, Redundancy, bar_width, label='Redundancy', color='purple')

plt.bar_label(bars1, padding=3, fontsize=12)
plt.bar_label(bars2, padding=3, fontsize=12)
plt.bar_label(bars3, padding=3, fontsize=12)

plt.xlabel('Cloudflare Rank')
plt.ylabel('Percentage of Websites')
plt.title('DNS Third-Party Analysis')
plt.xticks(x_label, library)
plt.legend(title='Regions')
plt.show()