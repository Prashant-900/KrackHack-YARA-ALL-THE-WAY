import "pe"

rule InfoStealer_Malware
{
    meta:
        author = "Prashant Suthar"
        description = "Detects malware that steals stored passwords, cookies, and banking details"
        date = "2025-02-22"

    strings:
        $chrome = "Chrome Safe Storage" ascii
        $firefox = "signons.sqlite" ascii
        $bank1 = "creditcard" ascii
        $bank2 = "bankaccount" ascii
        $keyfile = "id_rsa" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($chrome, $firefox, $bank1, $bank2, $keyfile)
}
