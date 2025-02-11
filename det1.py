import yara
import sys
from collections import defaultdict
import json

def run_yara_on_sample(yara_file, sample_file):
    try:
        rules = yara.compile(filepath=yara_file)
    except yara.SyntaxError as e:
        return {"error": f"YARA Syntax Error: {e}"}
    
    try:
        matches = rules.match(sample_file)
    except yara.Error as e:
        return {"error": f"YARA Error: {e}"}

    rule_to_strings = {}
    rules_triggered_without_strings = []

    for match in matches:
        rule_name = match.rule
        matched_strings = [str(data[2]) for data in match.strings]

        if matched_strings:
            rule_to_strings[rule_name] = matched_strings
        else:
            rules_triggered_without_strings.append(rule_name)

    # Determine malicious status
    is_malicious = bool(matches)

    # Prepare the final JSON result
    result = {
        "Malicious": "Yes" if is_malicious else "No",
        "Matched Strings": rule_to_strings
    }

    # Include rules that triggered without strings
    if rules_triggered_without_strings:
        result["Rules Triggered Without Strings"] = rules_triggered_without_strings

    return result

# Only run if executed directly
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 det1.py <sample_file>")
        sys.exit(1)

    yara_file = "test.yara"
    sample_file = sys.argv[1]
    result = run_yara_on_sample(yara_file, sample_file)

    # Ensure proper JSON formatting
    print(json.dumps(result, indent=2))
