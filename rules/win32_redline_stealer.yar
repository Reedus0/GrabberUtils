rule win32_redline_stealer {
    meta:
        author = "Reedus0"
        description = "Rule for detecting RedLine Stealer malware"
        date = "2024-03-03"
        yarahub_reference_md5 = "5b0363ac5b831b9c3c07eeacd8ce0dff"
        yarahub_uuid = "dd11687f-5692-4b4b-800a-704e63cf52c6"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.redline_stealer"
        version = "1"
    strings:
        $string_0 = "UNKNOWN" wide
        $string_1 = "*wallet*" wide
        $string_2 = "https://api.ip.sb/ip" wide
        $string_3 = "windows-1251" wide
        $string_4 = "{0}{1}{2}" wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}