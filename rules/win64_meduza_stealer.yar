rule win64_meduza_stealer {
    meta:
        author = "Reedus0"
        description = "Rule for detecting Meduza Stealer malware"
        date = "2024-04-02"
        yarahub_reference_md5 = "40d39e1426b624e504f616d225b8e410"
        yarahub_uuid = "334ec875-a5f8-42dd-82f7-c204bcdee458"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.meduza"
        version = "1"
    strings:
        $string_0 = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 4C 24 ?? }
        $string_1 = "<discarded>"
        $string_2 = "invalid UTF-8 byte at index"
        $string_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        $string_4 = "temp_directory_path"
        $string_5 = "SeDebugPrivilege"
    condition:
        uint16(0) == 0x5A4D and (#string_0 > 15) and 4 of them
}