rule win32_salat_stealer {
    meta:
        author = "Reedus0"
        description = "Rule for detecting SalatStealer malware"
        date = "2024-03-24"
        yarahub_reference_md5 = "55e9fcfb5c2ead956109341d5f66cc97"
        yarahub_uuid = "a4481c04-bbbb-45b4-8c32-4ca4200ffdbc"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" 
        $string_1 = "57776f6749434167496d563463477876636d56794c6d56345a534973436941674"
        $string_2 = "select TotalPhysicalMemory from Win32_ComputerSystem"
        $string_3 = "create process as user: %s"
        $string_4 = "UserInformation.txt"
        $string_5 = "$appdata"
        $string_6 = "winsta0\\default"
    condition:
        uint16(0) == 0x5A4D and 5 of them
}