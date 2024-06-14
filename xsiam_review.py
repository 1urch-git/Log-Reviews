import pandas as pd
import re

# Define the excel file path
file_path = "your_log_file.xlsx"

# Read the excel file into a pandas DataFrame
df = pd.read_excel(file_path)

######## XSIAM Data ####### 
### This section counts the number of unique values in ech column ###
# Count unique types
type_counts = df['Type'].value_counts()
print("\n")
print(f"Unique Types and their counts:")
print(type_counts)
print("\n")

# Count unique source types
source_counts = df['Sources'].value_counts()
print("\n")
print(f"Unique source types and their counts:")
print(source_counts)
print("\n")

# Count unique providers
provider_counts = df['Externally Detected Providers'].value_counts()
print("\n")
print(f"Unique providers and their counts:")
print(provider_counts)
print("\n")

# Count unique services
services_counts = df['Active External Services Types'].value_counts()
print("\n")
print(f"Unique services and their counts:")
print(services_counts)
print("\n")

######## Review domains, IPs ################
#### This code will return a count and list of unique domains, IPs etc. from the Name column
#### It will also provide uncommon entries, removing IPv6, IPv4, and domain names

# Unique names and count
unique_names = df['name'].unique()
unique_count = len(unique_names)
print(f"List of unique names: {unique_names}")
print(f"Count of unique names: {unique_count}")

# Find names without "." or ":" character (using regular expressions)
names_no_dot_colon = df[~df['name'].str.contains(r'[.:]')]['name'].tolist()
print(f"Names without '.' or ':' character: {names_no_dot_colon}")
print("\n")

# Ensure "IP Addresses" are strings
df['IP Addresses'] = df['IP Addresses'].astype(str)

# View entries with "Externally inferred CVEs" and corresponding score
cve_df = df[df["Externally inferred CVEs"].notnull()]
sorted_cve_df = cve_df.sort_values(by="Externally Inferred Vulnerability Score", ascending=False)
print(f"Entries with Externally inferred CVEs:")
print(cve_df[["Name","Externally inferred CVEs", "Externally Inferred Vulnerability Score"]])
print("\n")

# Consolidate "Name" entries with comma-separated "IP Addresses"
grouped_df = df.groupby("name")["IP Addresses"].agg(", ".join)
print(f"Consolidated Names with comma-separated IP Addresses:")
print(grouped_df)


# Close the excel file (not directly supported by pandas)
# Consider saving the DataFrame to a new file if needed.
