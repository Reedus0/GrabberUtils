import "pe"

rule win32_dotnet_obfuscate{
    meta:
        author = "Reedus0"
        description = "Rule for detecting .NET obfuscated malware"
        date = "2025-02-14"
        yarahub_reference_md5 = "9e7c6c00ffd9d6501586ff6e3a87ff47"
        yarahub_uuid = "ba2170cb-29c8-4645-996f-9b99425d89d6"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = { 2B 09 28 ?? ?? ?? ?? 14 16 9A 26 16 2D F9 28 13 12 00 06 00 7E 24 01 00 04 }
        $string_1 = { 73 ?? ?? ?? ?? 26 14 14 73 BC 00 00 06 28 72 00 00 06 }
        $string_2 = { 20 ?? ?? ?? ?? FE 0E 00 00 38 00 00 00 00 FE 0C 00 00 45 ?? ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and 1 of them
}    