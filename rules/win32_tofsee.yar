rule win32_tofsee {
    meta:
        author = "Reedus0"
        description = "Rule for detecting Tofsee malware"
        date = "2024-03-24"
        yarahub_reference_md5 = "a210bfb226c6249565877fec47501485"
        yarahub_uuid = "51fde6a6-5c2f-4bdf-84d6-ebca9beafc61"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "rcpt to:<%s>"
        $string_1 = "mail from:<%s>"
        $string_2 = "%04x%08.8lx$%08.8lx$%08x@%s"
        $string_3 = "SMTP"
        $string_4 = "helo %s"
        $string_5 = "ehlo %s"
        $string_6 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u"
    condition:
        uint16(0) == 0x5A4D and 5 of them
}