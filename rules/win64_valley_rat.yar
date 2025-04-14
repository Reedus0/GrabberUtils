rule win64_valley_rat {
    meta:
        author = "Reedus0"
        description = "Rule for detecting ValleyRAT malware"
        date = "2024-04-14"
        yarahub_reference_md5 = "08778fc09ac8ff3af6f21a0e7a27fafc"
        yarahub_uuid = "ff16a44f-f146-42ba-81aa-9f837f453f31"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.valley_rat"
        version = "1"
    strings:
        $string_0 = { ( 70 | 6F | 74 ) 00 ( 31 | 32 | 33 ) 00 3A 00 00 00 }
        $string_1 = "Windows\\System32\\tracerpt.exe"
        $string_2 = "denglupeizhi"
        $string_3 = "[RO] %ld bytes"
        $string_4 = "[RI] %d bytes"
        $string_5 = "!analyze -v"
    condition:
        uint16(0) == 0x5A4D and #string_0 >= 4 and 3 of them
}