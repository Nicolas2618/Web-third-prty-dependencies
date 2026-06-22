import pandas as pd
import DNS_Identifier
import Source_Data

# Runs the analysis and writes the CSV file from the original file. 
#DNS_Identifier.main() 

df = pd.read_csv("src/Source_Data/Domain_Robustness_Results.csv")

#print(df.to_string())

print(df['robustness_classification'].value_counts().to_string())
