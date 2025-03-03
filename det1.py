import yara
import sys

# Define the path to the YARA rule file
yara_file = "test.yara"
sample_file = sys.argv[1]

def run_yara_on_sample(yara_file, sample_file):
    try:
        # Compile YARA rules
        rules = yara.compile(filepath=yara_file)
        
        # Scan the sample file
        matches = rules.match(sample_file)

        # Extract matched strings
        rule_to_strings = {match.rule: [s[2].decode('utf-8', 'ignore') for s in match.strings] for match in matches}

        return rule_to_strings

    except yara.Error as e:
        return {"error": str(e)}

# Run the function and collect matched strings
rule_to_strings = run_yara_on_sample(yara_file, sample_file)

# Prepare response
if rule_to_strings:
    result = {
        "Malicious": "Yes" if rule_to_strings else "No",
        "Matched Strings": rule_to_strings if rule_to_strings else []
    }
else:
    result = {"Malicious": "No", "Matched Strings": []}

return result
