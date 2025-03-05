import yara
import sys
from collections import defaultdict

# Define the path to the YARA file and the sample file
yara_file = "test.yara"
sample_file = sys.argv[1]

def run_yara_on_sample(yara_file, sample_file):
    # Compile the YARA rules
    rules = yara.compile(filepath=yara_file)
    
    # Dictionary to store the rules and their corresponding matched strings
    rule_to_strings = defaultdict(set)
    
    # Open the sample file and scan it with the YARA rules
    with open(sample_file, 'rb') as f:
        matches = rules.match(data=f.read())
    
    # Process the YARA matches
    for match in matches:
        signature = match.rule
        for string_match in match.strings:
            matched_string = string_match[2].decode('utf-8')  # Extract the matched string
            rule_to_strings[signature].add(matched_string)
    
    return rule_to_strings

# Run the function and collect the distinct strings hit in the YARA rules
rule_to_strings = run_yara_on_sample(yara_file, sample_file)
malicious = []
result = []

# Check if there are any malicious matches and update the result list
for rule, strings in rule_to_strings.items():
    if len(rule) > 0:
        result.append("Malicious: Yes")
        malicious.extend(strings)

# If no matches were found, set the result to "Malicious: No"
if len(malicious) > 0:
    result.append("Matched Strings: " + str(list(set(malicious))))
else:
    result.append("Malicious: No")
    result.append("Matched Strings: []")
    
result = "\n".join(result)

# Print the result
print(result)
