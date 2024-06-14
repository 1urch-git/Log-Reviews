import pandas as pd

# Define the excel file path
file_path = "your_log_file.xlsx"

# Read the excel file into a pandas DataFrame
df = pd.read_excel(file_path)

# View entries filtered by unique source type
source_types = df["sources"].unique()

for source_type in source_types:
  filtered_df = df[df["sources"] == source_type]
  print(f"Entries from source: {source_type}")
  print(filtered_df)
  print("\n")

# View entries with "Externally inferred CVEs" and corresponding score
cve_df = df[df["Externally inferred CVEs"].notnull()]
print(f"Entries with Externally inferred CVEs:")
print(cve_df[["Externally inferred CVEs", "Externally Inferred Vulnerability Score"]])
print("\n")

# Consolidate "Name" entries with comma-separated "IP Addresses"
grouped_df = df.groupby("name")["IP Addresses"].agg(", ".join)
print(f"Consolidated Names with comma-separated IP Addresses:")
print(grouped_df)

# Close the excel file (not directly supported by pandas)
# Consider saving the DataFrame to a new file if needed.
