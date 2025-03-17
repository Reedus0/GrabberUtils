rule win32_xworm {
    meta:
        author = "Reedus0"
        description = "Rule for detecting XWorm malware"
        date = "2024-01-29"
        yarahub_reference_md5 = "C0D9BE7234912E8A19D5BA31A4AAA324"
        yarahub_uuid = "407232ed-d7fb-4440-a061-25572f9a9b29"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.xworm"
        version = "1"
    strings:
        $string_0 = { 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 08
        72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 08 }
        $string_1 = "@echo off" wide
        $string_2 = "timeout 3 > NUL" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}