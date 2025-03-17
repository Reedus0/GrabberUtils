import "pe"

rule win32_lumma_stealer {
    meta:
        author = "Reedus0"
        description = "Rule for detecting LummaStealer malware"
        date = "2024-02-13"
        yarahub_reference_md5 = "9a675f29e768c405bf4705890fa9d2ba"
        yarahub_uuid = "46ec8e39-d171-43cc-bcc5-d77caafc723a"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.lumma"
        version = "2"
    strings:
        $string_0 = { 68 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 08 A3 ?? ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and #string_0 >= 5
}