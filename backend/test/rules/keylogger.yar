import "pe"

rule Keylogger_Detection
{
    meta:
        author = "Prashant Suthar"
        description = "Detects keyloggers that record user keystrokes"
        date = "2025-02-22"

    strings:
        $hook = "SetWindowsHookExA" ascii
        $record = "GetAsyncKeyState" ascii
        $logfile = ".log" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($hook, $record, $logfile)
}
