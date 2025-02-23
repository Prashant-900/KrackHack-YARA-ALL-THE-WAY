import "pe"

rule Suspicious_API_Calls
{
    meta:
        author = "Prashant Suthar"
        description = "Detects PE files using suspicious Windows API calls"
        date = "2025-02-22"

    strings:
        $inj1 = "VirtualAlloc" ascii
        $inj2 = "WriteProcessMemory" ascii
        $inj3 = "CreateRemoteThread" ascii

    condition:
        uint16(0) == 0x5A4D and  // Must be a PE file
        (any of ($inj*) and pe.number_of_sections > 3) // Reduce false positives
}
