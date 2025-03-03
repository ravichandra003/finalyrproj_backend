import yara
import sys
from collections import defaultdict

# Define the path to the YARA file and the sample file
yara_file = "test.yara"
sample_file = sys.argv[1]

def run_yara_on_sample(yara_file, sample_file):
    try:
        # Compile the YARA rules
        rules = yara.compile(filepath=yara_file)
        
        # Scan the file with YARA
        matches = rules.match(sample_file)

        # Dictionary to store rules and matched strings
        rule_to_strings = defaultdict(set)
        
        # Process matches
        for match in matches:
            rule_name = match.rule
            for string_match in match.strings:
                _, _, matched_string = string_match
                rule_to_strings[rule_name].add(matched_string)

        return rule_to_strings

    except Exception as e:
        return {"error": str(e)}

# Run the function and collect matched strings
rule_to_strings = run_yara_on_sample(yara_file, sample_file)
malicious = []
result = []

# Check if there are malicious matches
if rule_to_strings and "error" not in rule_to_strings:
    for rule, strings in rule_to_strings.items():
        if len(rule) > 0:
            result.append("Malicious: Yes")
            malicious.extend(strings)

# If no matches were found, set the result to "Malicious: No"
if malicious:
    result.append("Matched Strings: " + str(list(set(malicious))))
else:
    result.append("Malicious: No")
    result.append("Matched Strings: []")
    
result = "\n".join(result)

# Print the result
print(result)
