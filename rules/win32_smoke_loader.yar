import "pe"

rule win32_smoke_loader {
    meta:
        author = "Reedus0"
        description = "Rule for detecting SmokeLoader malware"
        date = "2024-01-29"
        yarahub_reference_md5 = "3863A31031F20C75A411FC8893B36177"
        yarahub_uuid = "9591d18a-1eae-4cfd-bac8-77c2269b420a"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.smokeloader"
        version = "1"
    strings:
        $string_0 = { E8 00 00 00 00 75 ?? 74 ?? }
    condition:
        uint16(0) == 0x5A4D and #string_0 >= 2 and pe.image_base == 0x400000
}