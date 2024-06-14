"""
This python file is used to review the XSIAM data and provide insights inot what is there.
As long as the header values remain consistent, this should analyze all data in the provided excel file.
"""

import pandas as pd
from pandas.api.types import is_numeric_dtype
import re
import matplotlib.pyplot as plt
from datetime import datetime

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

### Activity Chart ###

# Function to convert date string to datetime
def convert_date_string(date_str):
  try:
    # Assuming format "Month Dayth Year Hour:Minute:Second"
      if not pd.api.types.is_string_dtype(date_str):
        return None
    return datetime.strptime(date_str, '%b %dth %Y %H:%M:%S')
  except ValueError:
    # Handle potential parsing errors
    return None

# Function to calculate cumulative activity for the full date range
def calculate_cumulative_activity(df):
  # Assuming "First Observed" is the date column for activity
  df['First Observed'] = df['First Observed'].apply(convert_date_string)
  min_date = df['First Observed'].min()
  max_date = df['First Observed'].max()
  if min_date is None or max_date is None:
    # Handle empty DataFrames or parsing errors
    return pd.Series(dtype=int)  # Return an empty Series
  date_range = pd.date_range(start=min_date, end=max_date)
  # Count occurrences for each date in the range
  daily_activity = df['First Observed'].dt.date.value_counts(normalize=False).sort_index(ascending=True)
  # Reindex with full date range to ensure all dates are included (filling with zeros)
  daily_activity = daily_activity.reindex(date_range, fill_value=0)
  # Calculate cumulative sum
  daily_activity = daily_activity.cumsum()
  return daily_activity

# Calculate daily activity across all records
daily_activity = calculate_cumulative_activity(df.copy())  # Avoid modifying original DataFrame

# Plot the cumulative activity
daily_activity.plot(kind='area', alpha=0.4, colormap='viridis')  # Adjust alpha and colormap as needed
plt.xlabel("Date")
plt.ylabel("Cumulative Activity")
plt.title("Cumulative Activity Over Full Date Range")
plt.xticks(rotation=45)  # Rotate x-axis labels for better readability
plt.tight_layout()
plt.show()



# Close the excel file (not directly supported by pandas)
# Consider saving the DataFrame to a new file if needed.
