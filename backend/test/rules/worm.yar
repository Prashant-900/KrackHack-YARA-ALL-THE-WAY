import "pe"

rule Worm_Detection
{
    meta:
        author = "Prashant Suthar"
        description = "Detects worms that spread via network shares or USB"
        date = "2025-02-22"

    strings:
        $copy = "CopyFileA" ascii
        $autostart = "autorun.inf" ascii
        $netspread1 = "NetShareAdd" ascii
        $netspread2 = "NetUserAdd" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($copy, $autostart, $netspread1, $netspread2)
}
