rule win32_njrat {
    meta:
        author = "Reedus0"
        description = "Rule for detecting njrat malware"
        date = "2025-02-01"
        yarahub_uuid = "882404f2-e440-4c51-8530-69a5d482eddd"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        yarahub_reference_md5 = "337cabfce35dc84645dbad617b58a418"
        version = "1"
    strings:
        $string_0 = "cmd.exe /C Y /N /D Y /T 1 & Del" wide
        $string_1 = "cmd.exe /k ping 0 & del" wide
        $string_2 = "netsh firewall add allowedprogram" wide
        $string_3 = "/C choice /C Y /N /D Y /T 5 & Del" wide
        $string_4 = "schtasks /delete /tn" wide
        $string_5 = "SEE_MASK_NOZONECHECKS" wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}