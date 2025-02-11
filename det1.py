import yara
import sys
from collections import defaultdict

# Define the path to the YARA file and the sample file
yara_file = "test.yara"
sample_file = sys.argv[1]

def run_yara_on_sample(yara_file, sample_file):
    # Compile the YARA rules
    try:
        rules = yara.compile(filepath=yara_file)
    except yara.SyntaxError as e:
        print(f"YARA Syntax Error: {e}")
        sys.exit(1)
    
    # Scan the sample file
    try:
        matches = rules.match(sample_file)
    except yara.Error as e:
        print(f"YARA Error: {e}")
        sys.exit(1)

    # Dictionary to store the rules and their corresponding matched strings
    rule_to_strings = defaultdict(set)

    for match in matches:
        rule_name = match.rule  # Get the rule name
        matched_strings = [str(data[2]) for data in match.strings]  # Extract matched string values
        rule_to_strings[rule_name].update(matched_strings)

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
