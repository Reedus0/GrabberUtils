rule win32_vulcan_keylogger {
    meta:
        author = "Reedus0"
        description = "Rule for detecting Vulcan Keylogger malware"
        date = "2024-03-24"
        yarahub_reference_md5 = "b58a0a4b950f9614aaed929e83733d8c"
        yarahub_uuid = "29930789-f37a-469a-aa24-aaa5b0549a46"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "2"
    strings:
        $string_0 = "[Vulcan " wide
        $string_1 = "]: New Infection" wide
        $string_2 = "New Infection!!!" wide 
        $string_3 = "smtp.gmail.com" wide
        $string_4 = "]: Program Is Off Now" wide
        $string_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
    condition:
        uint16(0) == 0x5A4D and 5 of them
}