import "pe"
import "math"

rule Packed_PE_File
{
    meta:
        author = "Prashant Suthar"
        description = "Detects packed or encrypted PE files"
        date = "2025-02-22"

    condition:
        uint16(0) == 0x5A4D and   // PE file check
        for any i in (0..pe.number_of_sections) : (pe.sections[i].entropy > 7.0) or
        pe.number_of_sections > 10 or 
        pe.overlay.offset > 0
}
