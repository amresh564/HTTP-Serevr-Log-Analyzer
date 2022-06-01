import re
import pandas as pd
import numpy as np

# Define the headers for the DataFrame
headers = ['domain', 'path', 'size', 'ip', 'foo', 'bar', 'datetime', 'request', 'status', 'size2', 'referer', 'user_agent']

# Define the regular expression pattern to match and extract log file entries
regex = r'(?:(.*?) (.*) (\d+?|-) )?(\d+\.\d+\.\d+\.\d+|-) (.*?) (.*?) \[(.*?)\] "(.*?[^\\])" (.*?) (\d+?|-)(?: "(.*?)" "(.*?)")?$'

# Create an empty list to store the extracted log values
array = []

# Initialize a line counter
line_number = 0

# Open the log file and iterate over each line
with open("httpd-access.log","r") as file:
    for line in file:
        # Create an empty list to store the values for the current log entry
        values = []
        
        # Check if the line matches the regular expression pattern
        if re.match(regex, line) is not None:
            m = re.match(regex, line)
            
            # Iterate over the captured groups and append the values to the list
            for i in range(1, 13):
                if m.group(i) is not None:
                    values.append(m.group(i))
                else:
                    values.append('None')
        
        # If the line does not match the pattern, print the line number
        else:
            print(line_number + 1)
        
        # Append the list of values to the array
        array.append(values)
        
        # Increment the line counter
        line_number += 1

# Create a DataFrame from the array of log values, using the headers as column names
df = pd.DataFrame(array, columns=headers)

# Clean the data

# Convert the "datetime" column to datetime format
from datetime import datetime
datetime_format = '%d/%b/%Y:%H:%M:%S %z'
time_conv = lambda x: datetime.strptime(x, datetime_format)
df['datetime'] = df['datetime'].apply(time_conv)

# Convert selected columns to numeric format
df[['size', 'size2', 'status']] = df[['size', 'size2', 'status']].apply(pd.to_numeric, errors="coerce")

# Create a new column "bot_or_not" based on whether the "user_agent" contains the word "bot"
df['bot_or_not'] = df['user_agent'].str.contains('bot')

# Calculate the time difference from the earliest timestamp and store it in a new column "delta_t"
df['delta_t'] = df['datetime'] - np.min(df['datetime'])

# Remove unnecessary columns
df = df.drop(columns=['foo', 'bar', 'size2'])

# Split the "request" column into three separate columns: "request_method", "request_content", and "request_version"
regex_request = r'(?:(?:(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|TRACE))?(?: ?)(?:(.*))?(?: ))?(?:(.*))?'
request_method, request_content, request_version = [], [], []

for item in df['request']:
    if re.match(regex_request, item) is not None:
        rq = re.match(regex_request, item)
        request_method.append(rq.group(1))
        request_content.append(rq.group(2))
        request_version.append(rq.group(3))
    else:
        request_method.append(None)
        request_content.append(None)
        request_version.append(None)

df['request_method'] = request_method
df['request_content'] = request_content
df['request_version'] = request_version

# Analyze XML-RPC requests

# Create a new column "xmlrpc" based on the presence of "xmlrpc.php" in the "request_content"
df['xmlrpc'] = df['request_content'].str.contains('xmlrpc.php')

# Check for suspicious XML-RPC requests by combining "xmlrpc" requests with status code 404
xmlrpc_serious = []
for index, value in enumerate(df['xmlrpc']):
    if value and df["status"].iloc[index] == 404:
        xmlrpc_serious.append(True)
    else:
        xmlrpc_serious.append(False)
df['xmlrpc_serious'] = xmlrpc_serious

# Check for XML-RPC requests with status code 200
xmlrpc_warning = []
for index, value in enumerate(df['xmlrpc']):
    if value and df["status"].iloc[index] == 200:
        xmlrpc_warning.append(True)
    else:
        xmlrpc_warning.append(False)
df['xmlrpc_warning'] = xmlrpc_warning

# Search for various types of injections

# Define regular expressions for injection patterns
regex_sql = '/(\')|(\%27)|(\-\-)|(#)|(\%23)/ix'
regex_sql2 = "/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix"
regex_xss = "/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/ix"
regrex_login = 'pass|password|Password|Pass|pswd|pwd|username|Username'
regex_sudo = 'sudo'
regex_cd = '\/\.\./'
regex_groups = 'etc\/groups'
regex_sql_to_shell = '/exec(\s|\+)+(s|x)p\w+/ix'
regex_remote_file = '/(https?|ftp|php|data):/i'

# Create columns for different types of injections based on the presence of corresponding patterns
df['SQL'] = df['request_content'].str.extract(regex_sql).notna()
df['SQL2'] = df['request_content'].str.extract(regex_sql2).notna()
df['xss'] = df['request_content'].str.extract(regex_xss).notna()
df['sql_shell'] = df['request_content'].str.extract(regex_sql_to_shell).notna()
df['remote_file'] = df['request_content'].str.extract(regex_remote_file).notna()
df['login'] = df['request_content'].str.contains(regrex_login)
df['cd'] = df['request_content'].str.contains(regex_cd)
df['groups'] = df['request_content'].str.contains(regex_groups)

# Display the first few rows of the DataFrame
df.head()
