rule win32_dotnet_form_obfuscate {
    meta:
        author = "Reedus0"
        description = "Rule for detecting .NET form obfuscate malware"
        date = "2024-01-29"
        yarahub_reference_md5 = "24a04c8ba1c202b443c237c014c9721c"
        yarahub_uuid = "37809a30-6293-4dd0-8964-5e44bccd2fc2"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = { 28 ?? ?? ?? 0? [0-1] 16 [0-1] 28 ?? ?? ?? 0? [0-1] 73 ?? ?? ?? 06 28 ?? ?? ?? 0? }
    condition:
        uint16(0) == 0x5A4D and $string_0
}