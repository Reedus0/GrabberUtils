rule win32_safengine {
    meta:
        author = "Reedus0"
        description = "Rule for detecting safengine packer"
        date = "2025-02-12"
        yarahub_reference_md5 = "0c93cdb7a0be26411401c05267f51d8b"
        yarahub_uuid = "e5d75527-948f-4e4b-9a46-181fa2e2a8ed"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "Safengine Shielden v2.4.0.0"
        $string_1 = ".sedata"
    condition:
        uint16(0) == 0x5A4D and $string_0 and #string_1 >= 2
}    