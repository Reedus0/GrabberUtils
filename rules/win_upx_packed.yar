rule win_upx_packed {
    meta:
        author = "Reedus0"
        description = "Rule for detecting UPX packed malware"
        date = "2024-04-14"
        yarahub_reference_md5 = "c9f7d1e7579b0791f8391bfa27962e45"
        yarahub_uuid = "a2f4f650-02ce-435c-a27a-4aa17afb457e"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $upx1 = { 55 50 58 30 00 00 00 }
        $upx2 = { 55 50 58 31 00 00 00 }
        $upx_sig = "UPX!"
    condition:
        uint16(0) == 0x5A4D and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024)
}