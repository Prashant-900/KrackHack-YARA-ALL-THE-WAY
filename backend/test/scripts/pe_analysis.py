import pefile
import os

def analyze_pe(file_path):
    # Ensure the file exists
    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return

    # Ensure the file is not empty
    if os.path.getsize(file_path) < 512:  # PE files are usually >512 bytes
        print(f"[ERROR] File too small to be a valid PE: {file_path}")
        return

    try:
        pe = pefile.PE(file_path)

        print(f"[*] Analyzing: {file_path}")
        print(f"[*] Timestamp: {hex(pe.FILE_HEADER.TimeDateStamp)}")
        print(f"[*] Sections: {len(pe.sections)}")

        # Analyze sections
        for section in pe.sections:
            try:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
            except:
                section_name = "<Unknown>"
            print(f"  - {section_name}: Entropy {section.get_entropy():.2f}")

        # Analyze Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("[*] Imports:")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors='ignore') if entry.dll else "<Unknown DLL>"
                print(f"  - {dll_name}")
                for imp in entry.imports:
                    func_name = imp.name.decode(errors='ignore') if imp.name else f"Ordinal {imp.ordinal}"
                    print(f"    {hex(imp.address)} {func_name}")
        else:
            print("[*] No import table found!")

    except pefile.PEFormatError:
        print(f"[ERROR] Invalid or corrupted PE file: {file_path}")

if __name__ == "__main__":
    sample_file = "samples/test.exe"
    analyze_pe(sample_file)
