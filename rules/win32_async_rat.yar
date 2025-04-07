rule win32_async_rat {
    meta:
        author = "Reedus0"
        description = "Rule for detecting AsyncRAT malware"
        date = "2024-04-07"
        yarahub_reference_md5 = "f76702fa423ce2b2b4b0fdcf547b0789"
        yarahub_uuid = "275e3906-ce43-429d-8b51-23838cdbad93"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.asyncrat"
        version = "1"
    strings:
        $string_0 = { 16 0A 38 ?? ?? ?? ?? 20 E8 03 00 00 28 ?? ?? ?? ?? 06 17 58 0A 06 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 32 ?? }
        $string_1 = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide
        $string_2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $string_3 = "@echo off" wide
        $string_4 = "timeout 3 > NUL" wide
    condition:
        uint16(0) == 0x5A4D and ($string_0 or 4 of them)
}