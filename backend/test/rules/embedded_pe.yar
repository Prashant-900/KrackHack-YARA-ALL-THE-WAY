import "pe"

rule Embedded_PE
{
    meta:
        author = "Prashant Suthar"
        description = "Detects embedded PE files inside another PE (possible droppers)"
        date = "2025-02-22"

    strings:
        $mz = "MZ" nocase
        $pe = "PE" nocase

    condition:
        uint16(0) == 0x5A4D and
        @mz != 0 and @pe != 0 and @mz != @pe
}
