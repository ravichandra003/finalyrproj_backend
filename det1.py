import yara
import sys
from collections import defaultdict

def run_yara_on_sample(yara_file, sample_file):
    try:
        rules = yara.compile(filepath=yara_file)
    except yara.SyntaxError as e:
        return {"error": f"YARA Syntax Error: {e}"}
    
    try:
        matches = rules.match(sample_file)
    except yara.Error as e:
        return {"error": f"YARA Error: {e}"}

    rule_to_strings = defaultdict(set)

    for match in matches:
        rule_name = match.rule
        matched_strings = [str(data[2]) for data in match.strings]
        rule_to_strings[rule_name].update(matched_strings)

    return rule_to_strings

# Only run if executed directly, not when imported
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 det1.py <sample_file>")
        sys.exit(1)

    yara_file = "test.yara"
    sample_file = sys.argv[1]
    result = run_yara_on_sample(yara_file, sample_file)
    print(result)
