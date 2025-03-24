rule win32_dcrat {
    meta:
        author = "Reedus0"
        description = "Rule for detecting DCRat malware"
        date = "2024-03-24"
        yarahub_reference_md5 = "cf40b5e2332d76b97a1a1a18f89b68ef"
        yarahub_uuid = "4c367ccc-f8a1-4d33-8ec1-9fd83b366ee5"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.dcrat"
        version = "1"
    strings:
        $string_0 = "DCRat" wide
        $string_1 = "(\\w\\W.+)Telegram.exe" wide
        $string_2 = "@echo off\r\nchcp 65001" wide
        $string_3 = "ping -n 10 localhost > nul" wide
        $string_4 = "w32tm /stripchart /computer:localhost /period:5 /dataonly /samples:2 > nul" wide
        $string_5 = "SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')" wide
    condition:
        uint16(0) == 0x5A4D and (($string_0) or 4 of them)
}