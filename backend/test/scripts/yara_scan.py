import yara
import os

RULES_DIR = "rules"

def load_yara_rules():
    rule_files = [os.path.join(RULES_DIR, f) for f in os.listdir(RULES_DIR) if f.endswith(".yar")]
    return yara.compile(filepaths={str(i): rule for i, rule in enumerate(rule_files)})

def scan_file(file_path, rules):
    matches = rules.match(file_path)
    return matches

if __name__ == "__main__":
    rules = load_yara_rules()
    sample_file = "samples/test.exe"
    matches = scan_file(sample_file, rules)
    print(f"YARA Matches: {matches}")
