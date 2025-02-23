import pefile
import math
import os
import sys

def calculate_entropy(data):
    """Calculate Shannon entropy of given data."""
    if not data:
        return 0

    entropy = 0
    length = len(data)
    freq = [0] * 256

    for byte in data:
        freq[byte] += 1

    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)

    return entropy

def check_entropy(file_path):
    """Check PE file for high entropy sections (possible packed sections)."""
    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return []

    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        print(f"[ERROR] Invalid or corrupted PE file: {file_path}")
        return []
    except Exception as e:
        print(f"[ERROR] Unexpected error while loading PE file: {str(e)}")
        return []

    high_entropy_sections = []

    for section in pe.sections:
        try:
            entropy = calculate_entropy(section.get_data())
            section_name = section.Name.decode(errors='ignore').strip()
            if entropy > 7.0:
                high_entropy_sections.append((section_name, entropy))
        except Exception as e:
            print(f"[WARNING] Failed to analyze section: {str(e)}")

    return high_entropy_sections

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_exe>")
        sys.exit(1)

    sample_file = sys.argv[1]  # Get file path from command line
    suspicious_sections = check_entropy(sample_file)

    if suspicious_sections:
        print("\n[*] High Entropy Sections (Potential Packing/Obfuscation Detected):")
        for section, entropy in suspicious_sections:
            print(f"  - {section}: Entropy = {entropy:.2f}")
    else:
        print("\n[*] No high entropy sections detected.")
