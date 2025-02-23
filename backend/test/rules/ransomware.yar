import "pe"

rule Ransomware_Detection
{
    meta:
        author = "Prashant Suthar"
        description = "Detects ransomware based on encryption-related API calls"
        date = "2025-02-22"

    strings:
        $encrypt1 = "CryptEncrypt" ascii
        $encrypt2 = "CryptAcquireContextA" ascii
        $encrypt3 = "CryptGenKey" ascii
        $encrypt4 = "CryptImportKey" ascii
        $encrypt5 = "CreateFileA" ascii
        $ransom_note = "Your files are encrypted" ascii

    condition:
        uint16(0) == 0x5A4D and
        (any of ($encrypt*) or $ransom_note)
}
