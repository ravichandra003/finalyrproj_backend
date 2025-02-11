import yara
import sys
import json
from collections import defaultdict

# Ensure correct argument count
if len(sys.argv) < 2:
    print(json.dumps({"error": "No file path provided"}))
    sys.exit(1)

yara_file = "test.yara"
sample_file = sys.argv[1]

def run_yara_on_sample(yara_file, sample_file):
    try:
        # Compile YARA rules
        rules = yara.compile(filepath=yara_file)
        
        # Scan the file with YARA
        matches = rules.match(sample_file)
        
        # Dictionary to store the rules and their corresponding matched strings
        rule_to_strings = defaultdict(set)
        rules_triggered_without_strings = []

        for match in matches:
            rule_name = match.rule
            matched_strings = [data[2].decode('utf-8', 'ignore') for data in match.strings if isinstance(data[2], bytes)]
            
            if matched_strings:
                rule_to_strings[rule_name].update(matched_strings)
            else:
                rules_triggered_without_strings.append(rule_name)

        return rule_to_strings, rules_triggered_without_strings

    except yara.Error as e:
        return {"error": f"YARA Error: {str(e)}"}

# Run the function and collect matched strings
rule_to_strings, rules_triggered_without_strings = run_yara_on_sample(yara_file, sample_file)

response = {
    "Malicious": "Yes" if rule_to_strings or rules_triggered_without_strings else "No",
    "Matched Strings": {rule: list(strings) for rule, strings in rule_to_strings.items()},
    "Rules Triggered Without Strings": rules_triggered_without_strings
}

# Print JSON response for Flask app
print(json.dumps(response))
