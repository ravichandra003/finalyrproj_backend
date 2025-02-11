import yara
import sys
import json
from collections import defaultdict

# Define the path to the YARA file and the sample file
yara_file = "test.yara"
sample_file = sys.argv[1]

def run_yara_on_sample(yara_file, sample_file):
    try:
        # Compile the YARA rules
        rules = yara.compile(filepath=yara_file)
        
        # Scan the sample file
        matches = rules.match(sample_file)

        # Dictionary to store the rules and their corresponding matched strings
        rule_to_strings = defaultdict(set)

        for match in matches:
            rule_name = match.rule  # Get the rule name
            matched_strings = [str(data[2]) for data in match.strings]  # Extract matched string values
            rule_to_strings[rule_name].update(matched_strings)

        return rule_to_strings

    except yara.SyntaxError as e:
        return {"error": f"YARA Syntax Error: {e}"}
    except yara.Error as e:
        return {"error": f"YARA Processing Error: {e}"}
    except Exception as e:
        return {"error": f"Unexpected Error: {e}"}

# Run the function and collect results
rule_to_strings = run_yara_on_sample(yara_file, sample_file)

# If an error occurred, print it and exit
if isinstance(rule_to_strings, dict) and "error" in rule_to_strings:
    print(json.dumps(rule_to_strings))
    sys.exit(1)

# Process results
malicious = bool(rule_to_strings)  # True if any rule matched
result = {
    "Malicious": "Yes" if malicious else "No",
    "Matched Strings": {rule: list(strings) for rule, strings in rule_to_strings.items()}
}

# Print JSON result
print(json.dumps(result, indent=2))
