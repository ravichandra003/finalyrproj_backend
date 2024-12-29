
import os
import ppdeep
import yara
import argparse

# Constants
YARA_LOW_THRESHOLD = 1
YARA_MEDIUM_THRESHOLD = 10
FUZZY_HASH_LOW_THRESHOLD = 20
FUZZY_HASH_MEDIUM_THRESHOLD = 50

# Static file paths for fuzzy hashes and YARA rules
KNOWN_FUZZY_HASHES_FILE = "malwareFuzzyHashes.txt"
YARA_RULES_FILE = "test.yara"

# Function to assess likelihood based on thresholds
def assess_likelihood(yara_string_count, fuzzy_hash_similarity):
    if yara_string_count < YARA_LOW_THRESHOLD and fuzzy_hash_similarity < FUZZY_HASH_LOW_THRESHOLD:
        return "Malicious: Less Likely (YARA matches < threshold, Fuzzy hash < threshold)"
    elif yara_string_count >= YARA_MEDIUM_THRESHOLD or fuzzy_hash_similarity >= FUZZY_HASH_MEDIUM_THRESHOLD:
        return "Malicious: Most Likely (YARA or Fuzzy hash >= high threshold)"
    elif yara_string_count >= YARA_LOW_THRESHOLD or fuzzy_hash_similarity >= FUZZY_HASH_LOW_THRESHOLD:
        return "Malicious: Likely (YARA or Fuzzy hash >= low threshold)"
    return "Malicious: Unknown (No clear threshold exceeded)"

# Function to load known fuzzy hashes from a file
def load_known_fuzzy_hashes(file_path):
    known_fuzzy_hashes = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    parts = line.split(',')
                    if len(parts) == 2:
                        fuzzy_hash_part = parts[0]
                        known_fuzzy_hashes[fuzzy_hash_part] = parts[1].strip().strip('"')
    except Exception as e:
        print(f"Error loading known fuzzy hashes from {file_path}: {str(e)}")
    return known_fuzzy_hashes

# Function to process a single sample and compute likelihood
def process_sample(sample_path, known_fuzzy_hashes, yara_rules):
    sample_name = os.path.basename(sample_path)

    if not os.path.exists(sample_path):
        return f"Sample {sample_name} does not exist."

    try:
        with open(sample_path, 'rb') as file:
            sample_data = file.read()
    except Exception as e:
        return f"Error reading sample {sample_name}: {str(e)}"

    yara_matches = yara_rules.match(data=sample_data)
    sample_fuzzy_hash = ppdeep.hash(sample_data)

    total_string_matches = sum(len(match.strings) for match in yara_matches)
    highest_fuzzy_similarity = max(
        (ppdeep.compare(sample_fuzzy_hash, known_hash) for known_hash in known_fuzzy_hashes),
        default=0
    )

    # Assess likelihood
    likelihood = assess_likelihood(total_string_matches, highest_fuzzy_similarity)

    return sample_name, total_string_matches, highest_fuzzy_similarity, likelihood

# Driver code
if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Malware analysis using YARA rules and fuzzy hashing.")
    parser.add_argument("sample_file", help="Path to the malware file to analyze.")
    args = parser.parse_args()

    sample_file = args.sample_file

    # Validate input
    if not os.path.isfile(sample_file):
        print(f"Error: {sample_file} is not a valid file.")
        exit(1)
    if not os.path.isfile(KNOWN_FUZZY_HASHES_FILE):
        print(f"Error: {KNOWN_FUZZY_HASHES_FILE} is not a valid file.")
        exit(1)
    if not os.path.isfile(YARA_RULES_FILE):
        print(f"Error: {YARA_RULES_FILE} is not a valid file.")
        exit(1)

    # Load fuzzy hashes and compile YARA rules
    known_fuzzy_hashes = load_known_fuzzy_hashes(KNOWN_FUZZY_HASHES_FILE)
    yara_rules = yara.compile(filepath=YARA_RULES_FILE)

    # Process the sample file
    result = process_sample(sample_file, known_fuzzy_hashes, yara_rules)

    # Print result
    if isinstance(result, str):
        # Error message
        print(result)
    else:
        sample_name, total_string_matches, highest_fuzzy_similarity, likelihood = result
        print(f"Sample: {sample_name}")
        print(f"Analysis: {likelihood}")
        print(f"YARA Matches: {total_string_matches}")
        print(f"Fuzzy Hash Similarity: {highest_fuzzy_similarity}%")
