import subprocess
import sys
from collections import defaultdict

# Define the path to the YARA file and the sample file
yara_file = "test.yara"
sample_file = sys.argv[1]

def run_yara_on_sample(yara_file, sample_file):
    # Run YARA on the single sample with the -rs option to capture both the rule and the matched strings
    result = subprocess.run(["./yara64.exe", "-s", yara_file, sample_file], capture_output=True, text=True)
    
    # Parse the YARA output
    yara_output = result.stdout.strip().split("\n")
    
    # Dictionary to store the rules and their corresponding matched strings
    rule_to_strings = defaultdict(set)
    i = 0
    
    # Process the YARA output
    for line in yara_output:
        if line:
            parts = line.split()
            if i == 0:
                signature = parts[0]
                i += 1
            else:
                matched_string = " ".join(parts[1:])  # Matched string
                # Store the matched string under the corresponding rule
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
    
result= "\n".join(result)

# Print the result
print(result)
