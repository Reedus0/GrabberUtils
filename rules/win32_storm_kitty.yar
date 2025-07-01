rule win32_storm_kitty {
    meta:
        author = "Reedus0"
        description = "Rule for detecting StormKitty malware"
        date = "2024-06-09"
        yarahub_reference_md5 = "310c1b76fbf1b164cc59a158949d24f3"
        yarahub_uuid = "8e643456-7dee-4255-93d8-a40002b4f147"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "StormKitty"
    condition:
        uint16(0) == 0x5A4D and ($string_0 or 1 of them)
}