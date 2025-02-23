import os
import json
from pe_analysis import analyze_pe
from entropy_check import check_entropy
from yara_scan import load_yara_rules, scan_file

SAMPLES_DIR = "samples"
REPORTS_DIR = "reports"

def scan_directory():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)  # Ensure reports directory exists

    rules = load_yara_rules()
    results = []

    for filename in os.listdir(SAMPLES_DIR):
        file_path = os.path.join(SAMPLES_DIR, filename)

        if filename.endswith(".exe"):
            print(f"\n[*] Scanning: {filename}")

            # Run YARA scan
            yara_matches = scan_file(file_path, rules)

            # Run PE Analysis
            analyze_pe(file_path)

            # Run Entropy Check
            high_entropy_sections = check_entropy(file_path)

            # Determine if file is malware
            is_malicious = len(yara_matches) > 0 or len(high_entropy_sections) > 0

            # Categorize result
            if len(yara_matches) > 0:
                status = "MALICIOUS"
            elif len(high_entropy_sections) > 0:
                status = "SUSPICIOUS"
            else:
                status = "BENIGN"

            print(f"[*] Scan Result: {status}")

            # Save report
            report = {
                "filename": filename,
                "status": status,
                "yara_matches": [str(match) for match in yara_matches],
                "high_entropy_sections": high_entropy_sections
            }
            results.append(report)

    # Save report to JSON file
    report_path = os.path.join(REPORTS_DIR, "scan_report.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[✔] Scan completed. Report saved to {report_path}")

if __name__ == "__main__":
    scan_directory()
