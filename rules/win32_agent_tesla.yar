rule win32_agent_tesla {
    meta:
        author = "Reedus0"
        description = "Rule for detecting AgentTesla malware"
        date = "2024-03-06"
        yarahub_reference_md5 = "a943bea8997dec969ba9cff3286ef6e2"
        yarahub_uuid = "af3452ab-ae29-470c-920f-7835dd3d845e"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.agent_tesla"
        version = "1"
    strings:
        $string_0 = { 06 91 06 61 20 ?? ?? ?? 00 61 D2 9C 06 17 58 0A 06 }
    condition:
        uint16(0) == 0x5A4D and all of them
}