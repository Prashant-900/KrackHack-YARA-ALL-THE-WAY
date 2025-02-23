import "pe"

rule Rootkit_Detection
{
    meta:
        author = "Prashant Suthar"
        description = "Detects rootkits that hide processes or manipulate system calls"
        date = "2025-02-22"

    strings:
        $hook1 = "NtQuerySystemInformation" ascii
        $hook2 = "ZwQuerySystemInformation" ascii
        $hook3 = "NtQueryDirectoryFile" ascii
        $hook4 = "ZwQueryDirectoryFile" ascii

        $stealth1 = "SetFileAttributesA" ascii
        $stealth2 = "FindFirstFileA" ascii
        $stealth3 = "FindNextFileA" ascii

    condition:
        uint16(0) == 0x5A4D and   // PE file
        (any of ($hook*) or any of ($stealth*))
}
